import hashlib
import json
from pathlib import Path

import pytest

from umat.operations.offline import (
    OfflineBundleError,
    create_offline_manifest,
    verify_offline_bundle,
)


def _bundle(root: Path) -> str:
    files = []
    for name, value in (("pyproject.toml", b"project"), ("uv.lock", b"lock")):
        path = root / name
        path.write_bytes(value)
        path.chmod(0o444)
        files.append(
            {"path": name, "sha256": hashlib.sha256(value).hexdigest(), "size_bytes": len(value)}
        )
    manifest = root / "offline-manifest.json"
    manifest.write_text(json.dumps({"schema_version": "1.0", "files": files}))
    return hashlib.sha256(manifest.read_bytes()).hexdigest()


def test_offline_bundle_requires_out_of_band_digest_and_read_only_files(tmp_path: Path) -> None:
    digest = _bundle(tmp_path)
    assert len(verify_offline_bundle(tmp_path, digest)["files"]) == 2
    with pytest.raises(OfflineBundleError, match="digest mismatch"):
        verify_offline_bundle(tmp_path, "0" * 64)


def test_offline_bundle_rejects_inventory_changes(tmp_path: Path) -> None:
    digest = _bundle(tmp_path)
    (tmp_path / "uv.lock").chmod(0o644)
    (tmp_path / "uv.lock").write_text("changed")
    with pytest.raises(OfflineBundleError, match="inventory mismatch"):
        verify_offline_bundle(tmp_path, digest)


def test_offline_bundle_can_be_sealed_then_verified(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("project")
    (tmp_path / "uv.lock").write_text("lock")
    manifest, digest = create_offline_manifest(tmp_path)
    assert manifest.stat().st_mode & 0o222 == 0
    assert len(verify_offline_bundle(tmp_path, digest)["files"]) == 2
