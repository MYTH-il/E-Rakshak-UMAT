from __future__ import annotations

import zipfile
from pathlib import Path, PurePosixPath


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
