from __future__ import annotations

import hashlib
import os
import shutil
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path

from fastapi import UploadFile


class UploadTooLargeError(ValueError):
    pass


class DigestMismatchError(ValueError):
    pass


@dataclass(frozen=True)
class StoredObject:
    sha256: str
    size_bytes: int
    object_key: str
    path: Path


@dataclass(frozen=True)
class QuarantinedObject:
    sha256: str
    size_bytes: int
    path: Path


class LocalArtifactStore:
    def __init__(self, quarantine_root: Path, artifact_root: Path) -> None:
        self.quarantine_root = quarantine_root.resolve()
        self.artifact_root = artifact_root.resolve()
        self.quarantine_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)

    async def quarantine_upload(self, upload: UploadFile, max_bytes: int) -> QuarantinedObject:
        path = self.quarantine_root / f"upload-{uuid.uuid4().hex}.part"
        digest = hashlib.sha256()
        total = 0
        try:
            with path.open("xb") as destination:
                os.chmod(path, 0o600)
                while chunk := await upload.read(1024 * 1024):
                    total += len(chunk)
                    if total > max_bytes:
                        raise UploadTooLargeError(f"upload exceeds {max_bytes} bytes")
                    digest.update(chunk)
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())
            return QuarantinedObject(digest.hexdigest(), total, path)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def object_key(self, sha256: str) -> str:
        return f"objects/sha256/{sha256[:2]}/{sha256[2:]}"

    def promote(self, quarantined: QuarantinedObject) -> StoredObject:
        key = self.object_key(quarantined.sha256)
        destination = self.artifact_root / key
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if destination.exists():
            if self.digest(destination) != quarantined.sha256:
                raise DigestMismatchError("existing content-addressed object has the wrong digest")
            quarantined.path.unlink(missing_ok=True)
        else:
            os.replace(quarantined.path, destination)
            os.chmod(destination, stat.S_IRUSR | stat.S_IRGRP)
        return StoredObject(quarantined.sha256, quarantined.size_bytes, key, destination)

    def store_file(self, source: Path, expected_sha256: str, expected_size: int) -> StoredObject:
        if source.stat().st_size != expected_size or self.digest(source) != expected_sha256:
            raise DigestMismatchError("uploaded artifact identity does not match its envelope")
        destination = self.artifact_root / self.object_key(expected_sha256)
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not destination.exists():
            temporary = destination.with_suffix(f".tmp-{uuid.uuid4().hex}")
            shutil.copyfile(source, temporary)
            os.chmod(temporary, 0o440)
            os.replace(temporary, destination)
        return StoredObject(
            expected_sha256, expected_size, self.object_key(expected_sha256), destination
        )

    def resolve(self, object_key: str) -> Path:
        path = (self.artifact_root / object_key).resolve()
        if self.artifact_root not in path.parents:
            raise ValueError("invalid object key")
        return path

    @staticmethod
    def digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def verify(self, object_key: str, expected_sha256: str) -> Path:
        path = self.resolve(object_key)
        if not path.is_file() or self.digest(path) != expected_sha256:
            raise DigestMismatchError("artifact digest verification failed")
        return path

    def cleanup_temporary(self) -> int:
        removed = 0
        for path in self.quarantine_root.glob("*.part"):
            path.unlink(missing_ok=True)
            removed += 1
        return removed
