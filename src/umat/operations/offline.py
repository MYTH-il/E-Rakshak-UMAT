from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any, cast

from umat.contracts.canonical import canonical_json
from umat.operations.backup import sha256_file


class OfflineBundleError(RuntimeError):
    pass


def create_offline_manifest(root: Path) -> tuple[Path, str]:
    root = root.expanduser().resolve()
    manifest_path = root / "offline-manifest.json"
    if manifest_path.exists():
        raise OfflineBundleError("offline manifest already exists")
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise OfflineBundleError(f"offline bundle contains a symbolic link: {path}")
        if path.is_file():
            path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    present = {item["path"] for item in files}
    if not {"uv.lock", "pyproject.toml"}.issubset(present):
        raise OfflineBundleError("offline bundle requires pyproject.toml and uv.lock")
    manifest_path.write_bytes(canonical_json({"schema_version": "1.0", "files": files}) + b"\n")
    manifest_path.chmod(0o444)
    return manifest_path, sha256_file(manifest_path)


def verify_offline_bundle(root: Path, expected_manifest_sha256: str) -> dict[str, Any]:
    root = root.expanduser().resolve()
    manifest_path = root / "offline-manifest.json"
    if not expected_manifest_sha256 or len(expected_manifest_sha256) != 64:
        raise OfflineBundleError("an independently transported manifest SHA-256 is required")
    if not manifest_path.is_file() or sha256_file(manifest_path) != expected_manifest_sha256:
        raise OfflineBundleError("offline manifest digest mismatch")
    try:
        manifest = cast(dict[str, Any], json.loads(manifest_path.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        raise OfflineBundleError("offline manifest is invalid") from exc
    if manifest.get("schema_version") != "1.0":
        raise OfflineBundleError("unsupported offline manifest version")
    expected = manifest.get("files")
    if not isinstance(expected, list):
        raise OfflineBundleError("offline manifest file inventory is invalid")
    observed: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        if path == manifest_path:
            continue
        if path.is_symlink():
            raise OfflineBundleError(f"offline bundle contains a symbolic link: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        observed.append(
            {"path": relative, "sha256": sha256_file(path), "size_bytes": path.stat().st_size}
        )
    if observed != expected:
        raise OfflineBundleError("offline bundle inventory mismatch")
    required = {"uv.lock", "pyproject.toml"}
    present = {item["path"] for item in observed}
    missing = required - present
    if missing:
        raise OfflineBundleError(f"offline bundle omits required files: {sorted(missing)}")
    # Verification must never make staged content executable as a side effect.
    if any((root / item["path"]).stat().st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) for item in observed):
        raise OfflineBundleError("offline bundle files must be read-only before verification")
    return manifest
