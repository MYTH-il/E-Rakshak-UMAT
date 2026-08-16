"""Container submissions must be refused, not silently analysed as programs.

create_case routes anything that is not a structurally valid APK to
Platform.WINDOWS, so an archive was accepted as a Windows executable and handed
to CAPE. CAPE then detonated the container -- Explorer or 7-Zip opening a file --
which is a technically successful run containing no malware behaviour. The
officer received an empty report for a sample that was in fact malicious, with
nothing to indicate the analysis never reached the payload.

Observed on a real Remcos RAT case: the email attachment
``MDRHZBOL2503407N2 CIPL.7z`` is a ZIP archive despite the extension -- the
campaign used that mismatch to evade mail filtering -- and analysing it produced
no C2, no persistence and no keylogger evidence, none of which were in the
container to begin with.
"""

import io
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException

from umat.intake import container_archive_kind, reject_container_submission


def _zip(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, b"fixture")
    return path


class TestContainerDetection:
    def test_zip_wearing_a_7z_extension_is_still_a_zip(self, tmp_path: Path) -> None:
        """The exact Remcos attachment. Detection must read content, not name."""
        sample = _zip(tmp_path / "MDRHZBOL2503407N2 CIPL.7z", ["CIPL.bat"])
        assert container_archive_kind(sample) == "ZIP archive"

    @pytest.mark.parametrize(
        ("name", "magic", "expected"),
        [
            ("real.7z", b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
            ("bundle.rar", b"Rar!\x1a\x07\x00", "RAR archive"),
            ("payload.gz", b"\x1f\x8b\x08", "gzip archive"),
            ("payload.xz", b"\xfd7zXZ\x00", "XZ archive"),
            ("payload.bz2", b"BZh9", "bzip2 archive"),
            ("driver.cab", b"MSCF\x00\x00", "Microsoft Cabinet archive"),
        ],
    )
    def test_container_formats_by_magic(
        self, tmp_path: Path, name: str, magic: bytes, expected: str
    ) -> None:
        sample = tmp_path / name
        sample.write_bytes(magic + b"\x00" * 64)
        assert container_archive_kind(sample) == expected

    def test_unreadable_or_encrypted_zip_is_still_a_container(self, tmp_path: Path) -> None:
        """A password-protected archive is one nobody can analyse. Say so rather
        than detonating it and reporting nothing."""
        sample = tmp_path / "locked.zip"
        sample.write_bytes(b"PK\x03\x04" + b"\xff" * 64)
        assert container_archive_kind(sample) == "ZIP archive"

    def test_empty_file_is_not_reported_as_a_container(self, tmp_path: Path) -> None:
        sample = tmp_path / "empty.bin"
        sample.write_bytes(b"")
        assert container_archive_kind(sample) is None


class TestExecutableSubmissionsStillPass:
    """The filter must catch containers and nothing else. A false rejection here
    blocks a legitimate investigation."""

    def test_jar_is_executable_not_a_container(self, tmp_path: Path) -> None:
        sample = _zip(tmp_path / "tool.jar", ["META-INF/MANIFEST.MF", "Main.class"])
        assert container_archive_kind(sample) is None

    def test_apk_is_executable_not_a_container(self, tmp_path: Path) -> None:
        sample = _zip(tmp_path / "app.apk", ["AndroidManifest.xml", "classes.dex"])
        assert container_archive_kind(sample) is None

    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("payload.exe", b"MZ\x90\x00" + b"\x00" * 64),
            ("dropper.bat", b"@echo off\r\nstart evil\r\n"),
            ("stage.ps1", b"IEX (New-Object Net.WebClient)\r\n"),
            ("lure.lnk", b"L\x00\x00\x00\x01\x14\x02\x00"),
            ("macro.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
        ],
    )
    def test_non_archive_submissions_are_accepted(
        self, tmp_path: Path, name: str, content: bytes
    ) -> None:
        sample = tmp_path / name
        sample.write_bytes(content)
        assert container_archive_kind(sample) is None
        reject_container_submission(sample, name)   # must not raise


class TestRejectionResponse:
    def test_container_raises_422_naming_the_format(self, tmp_path: Path) -> None:
        sample = _zip(tmp_path / "attachment.7z", ["invoice.bat"])
        with pytest.raises(HTTPException) as caught:
            reject_container_submission(sample, "attachment.7z")
        assert caught.value.status_code == 422
        detail = caught.value.detail
        assert "ZIP archive" in detail
        assert "attachment.7z" in detail

    def test_message_tells_the_officer_what_to_do(self, tmp_path: Path) -> None:
        """A refusal that does not say how to proceed just moves the dead end."""
        sample = _zip(tmp_path / "mail.zip", ["doc.bat"])
        with pytest.raises(HTTPException) as caught:
            reject_container_submission(sample, "mail.zip")
        detail = caught.value.detail.lower()
        assert "extract" in detail
        assert "extension" in detail        # warns the name may be misleading
