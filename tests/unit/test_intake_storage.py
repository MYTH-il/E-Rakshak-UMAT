import io
import zipfile
from pathlib import Path

import pytest
from fastapi import UploadFile

from umat.intake import is_structurally_valid_apk
from umat.storage.local import DigestMismatchError, LocalArtifactStore, UploadTooLargeError


def apk(path: Path, names: list[str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in names:
            archive.writestr(name, b"fixture")


def test_apk_content_routing_ignores_extension(tmp_path: Path) -> None:
    valid = tmp_path / "sample.bin"
    apk(valid, ["AndroidManifest.xml", "classes.dex"])
    assert is_structurally_valid_apk(valid)
    malformed = tmp_path / "fake.apk"
    malformed.write_bytes(b"not a zip")
    assert not is_structurally_valid_apk(malformed)


def test_apk_rejects_traversal(tmp_path: Path) -> None:
    hostile = tmp_path / "hostile.apk"
    apk(hostile, ["AndroidManifest.xml", "classes.dex", "../escape"])
    assert not is_structurally_valid_apk(hostile)


@pytest.mark.asyncio
async def test_stream_promote_deduplicate_and_verify(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "q", tmp_path / "a")
    first = await store.quarantine_upload(UploadFile(file=io.BytesIO(b"evidence"), filename="../../x"), 100)
    stored = store.promote(first)
    assert store.verify(stored.object_key, stored.sha256) == stored.path
    second = await store.quarantine_upload(UploadFile(file=io.BytesIO(b"evidence")), 100)
    assert store.promote(second).path == stored.path
    stored.path.chmod(0o600)
    stored.path.write_bytes(b"tampered")
    with pytest.raises(DigestMismatchError):
        store.verify(stored.object_key, stored.sha256)


@pytest.mark.asyncio
async def test_oversize_upload_is_removed(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "q", tmp_path / "a")
    with pytest.raises(UploadTooLargeError):
        await store.quarantine_upload(UploadFile(file=io.BytesIO(b"too large")), 2)
    assert list((tmp_path / "q").iterdir()) == []


def test_object_key_cannot_escape_root(tmp_path: Path) -> None:
    store = LocalArtifactStore(tmp_path / "q", tmp_path / "a")
    with pytest.raises(ValueError):
        store.resolve("../../escape")
