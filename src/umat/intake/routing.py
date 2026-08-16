from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath

from fastapi import HTTPException, status


def is_structurally_valid_apk(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > 100_000:
                return False
            names: set[str] = set()
            total_uncompressed = 0
            for info in infos:
                name = PurePosixPath(info.filename)
                if name.is_absolute() or ".." in name.parts or "\\" in info.filename:
                    return False
                total_uncompressed += info.file_size
                if total_uncompressed > 4 * 1024 * 1024 * 1024:
                    return False
                if info.compress_size and info.file_size / info.compress_size > 1000:
                    return False
                names.add(info.filename)
            return "AndroidManifest.xml" in names and any(
                name.startswith("classes") and name.endswith(".dex") for name in names
            )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return False


# Container formats that have no executable form. A submission matching one of
# these is a package around the sample, never the sample itself.
_CONTAINER_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "gzip archive"),
    (b"\xfd7zXZ\x00", "XZ archive"),
    (b"BZh", "bzip2 archive"),
    (b"MSCF", "Microsoft Cabinet archive"),
)

# ZIP entries that make a ZIP an executable artifact in its own right rather
# than a container. A JAR runs; an APK runs; a bag of files does not.
_EXECUTABLE_ZIP_MARKERS = ("META-INF/MANIFEST.MF", "AndroidManifest.xml")


def container_archive_kind(path: Path) -> str | None:
    """Name the container format when a submission is a package, else None.

    Detection is by MAGIC BYTES, never by file extension, because the extension
    is routinely wrong — often deliberately. The Remcos sample that prompted
    this arrived as ``MDRHZBOL2503407N2 CIPL.7z`` and was a ZIP archive; the
    campaign used the mismatch to slip past mail filtering, and Windows
    extracted it anyway.

    Why this matters at intake: create_case routes anything that is not a valid
    APK to Platform.WINDOWS, so an archive was accepted as a Windows executable
    and handed to CAPE. CAPE detonated the container -- Explorer or 7-Zip
    opening a file -- which produces a technically successful run with no
    malware behaviour in it. The officer receives an empty report for a sample
    that is in fact malicious, which is worse than an error, because nothing
    signals that the analysis never reached the payload.

    A ZIP carrying META-INF/MANIFEST.MF (a JAR) or AndroidManifest.xml (an APK)
    is executable in its own right and is NOT reported as a container. Nothing
    else is filtered here: scripts, documents, shortcuts, installers and PE
    files all remain valid submissions.
    """
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
    except OSError:
        return None
    if not header:
        return None

    for magic, label in _CONTAINER_MAGIC:
        if header.startswith(magic):
            return label

    if not header.startswith(b"PK\x03\x04"):
        return None
    # A ZIP. Executable only if it declares itself as one.
    try:
        with zipfile.ZipFile(path) as archive:
            names = {info.filename for info in archive.infolist()[:100_000]}
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        # Unreadable or encrypted: still a container, and one nobody can
        # analyse without the password. Say so rather than detonating it.
        return "ZIP archive"
    if any(marker in names for marker in _EXECUTABLE_ZIP_MARKERS):
        return None
    return "ZIP archive"


def reject_container_submission(path: Path, filename: str) -> None:
    """Refuse a package, and say what to submit instead.

    Rejecting rather than unpacking is deliberate. Extracting an untrusted
    archive means parsing attacker-controlled structure inside the control
    plane, which is the one component in this system that must never handle
    malware -- it holds the database credentials, the session secrets and the
    executor enrolment material, and every other path keeps samples in
    quarantine or inside a disposable worker. Choosing which member to detonate
    is also a policy decision, not a parsing one: a real archive can hold a
    decoy document, several droppers, and the payload.

    Refusing with instructions costs the officer one extra step. Accepting the
    archive costs them a clean report on malicious software, which is the
    outcome this system exists to prevent.
    """
    kind = container_archive_kind(path)
    if kind is None:
        return
    raise HTTPException(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        f"'{filename}' is a {kind}, not a program. Analysing it would only "
        f"observe the archive being opened and would report no malicious "
        f"activity even if the contents are malicious. Extract the archive and "
        f"submit the file inside it -- usually the executable, script or "
        f"document. Note that the file extension can be wrong: this check reads "
        f"the file's contents, not its name.",
    )
