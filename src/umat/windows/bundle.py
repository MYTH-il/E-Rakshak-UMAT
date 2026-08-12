from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import stat
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from umat.contracts import ContractError, validate_contract
from umat.contracts.canonical import canonical_json
from umat.contracts.validator import validate_pinned_native_schema

WINSTDT_COMMIT = "7bc74765e9d38d7ba6df3f2115db67761cb4cbd8"
HANDOFF_DIGEST = "16cbce2d8ac4db7f2db9d986df75dc6a45d092fc4f7a608ebc0443ffb104fd1f"
ACCESS_DIGEST = "4a47282985e412ee9c061db517bd460dd06db7e560f8a801b4cf7a83c97dbd1a"
SAMPLE_META_DIGEST = "fe36e4893e689c9570ffede487707002c0af91b183e91aa3ffc873ab2004c8d6"


class WindowsBundleError(ContractError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WindowsBundleError(f"invalid JSON file: {path.name}") from exc
    if not isinstance(value, dict):
        raise WindowsBundleError(f"{path.name} must contain an object")
    return cast(dict[str, Any], value)


@dataclass(frozen=True)
class BuiltWindowsBundle:
    root: Path
    archive_path: Path
    manifest: dict[str, Any]


class NativeWindowsValidator:
    def __init__(self, schema_root: Path) -> None:
        self.schema_root = schema_root.resolve()

    def validate(self, root: Path, sample_sha256: str, cape_task_id: int) -> dict[str, Any]:
        handoff = _load_object(root / "manifest.json")
        validate_pinned_native_schema(
            document=handoff,
            schema_path=self.schema_root / "handoff_manifest.schema.json",
            expected_sha256=HANDOFF_DIGEST,
        )
        if str(handoff.get("sample_sha256", "")).lower() != sample_sha256:
            raise WindowsBundleError("WinST/DT sample identity mismatch")
        if handoff.get("cape_task_id") != cape_task_id:
            raise WindowsBundleError("WinST/DT CAPE task identity mismatch")
        sample_meta = root / "sample.meta.json"
        if sample_meta.is_file():
            meta = _load_object(sample_meta)
            validate_pinned_native_schema(
                document=meta,
                schema_path=self.schema_root / "sample_meta.schema.json",
                expected_sha256=SAMPLE_META_DIGEST,
            )
            if str(meta.get("sample_sha256", "")).lower() != sample_sha256:
                raise WindowsBundleError("sample metadata identity mismatch")
        access = root / "behavior/access_events.json"
        if access.is_file():
            try:
                document = json.loads(access.read_text())
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise WindowsBundleError("invalid access-events JSON") from exc
            validate_pinned_native_schema(
                document=document,
                schema_path=self.schema_root / "access_events.schema.json",
                expected_sha256=ACCESS_DIGEST,
            )
        verified_paths = self._verify_native_hashes(root)
        artifact_paths = handoff.get("artifact_paths")
        if not isinstance(artifact_paths, dict) or not isinstance(artifact_paths.get("pcap"), str):
            raise WindowsBundleError("WinST/DT handoff does not declare a PCAP artifact")
        for kind, relative in artifact_paths.items():
            if not isinstance(relative, str):
                raise WindowsBundleError(f"invalid WinST/DT artifact path for {kind}")
            path = (root / relative).resolve()
            if root.resolve() not in path.parents or not path.is_file():
                raise WindowsBundleError(f"missing WinST/DT artifact: {kind}")
            if relative not in verified_paths:
                raise WindowsBundleError(f"unhashed WinST/DT artifact: {kind}")
        declared_hashes = (handoff.get("integrity") or {}).get("hash_manifest_sha256")
        if declared_hashes and sha256_file(root / "hashes.sha256") != str(declared_hashes).lower():
            raise WindowsBundleError("WinST/DT hash-manifest identity mismatch")
        return handoff

    @staticmethod
    def _verify_native_hashes(root: Path) -> set[str]:
        hashes = root / "hashes.sha256"
        if not hashes.is_file():
            raise WindowsBundleError("WinST/DT bundle has no hashes.sha256")
        verified: set[str] = set()
        for line in hashes.read_text().splitlines():
            try:
                expected, relative = line.split("  ", 1)
            except ValueError as exc:
                raise WindowsBundleError("invalid WinST/DT hash manifest") from exc
            path = (root / relative).resolve()
            if root.resolve() not in path.parents or not path.is_file():
                raise WindowsBundleError(f"invalid WinST/DT artifact path: {relative}")
            if sha256_file(path) != expected.lower():
                raise WindowsBundleError(f"WinST/DT artifact hash mismatch: {relative}")
            if relative in verified:
                raise WindowsBundleError(f"duplicate WinST/DT artifact hash: {relative}")
            verified.add(relative)
        observed = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "hashes.sha256"}
        }
        if observed != verified:
            raise WindowsBundleError("WinST/DT hash manifest does not cover every artifact")
        return verified


class WindowsBundleBuilder:
    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        key_id: str,
        native_validator: NativeWindowsValidator,
    ) -> None:
        self.signing_key = signing_key
        self.key_id = key_id
        self.native_validator = native_validator

    def build(
        self,
        *,
        analysis_run_id: UUID,
        sample_sha256: str,
        cape_task_id: int,
        cape_package: str | None,
        detected_type: str | None,
        profile_snapshot: dict[str, Any],
        native_root: Path,
        destination: Path,
        cape_evidence: dict[str, Any] | None = None,
    ) -> BuiltWindowsBundle:
        handoff = self.native_validator.validate(native_root, sample_sha256, cape_task_id)
        if destination.exists():
            raise WindowsBundleError("Windows bundle destination already exists")
        native_destination = destination / "native"
        shutil.copytree(native_root, native_destination)
        if cape_evidence is not None:
            (destination / "cape-evidence.json").write_text(
                json.dumps(cape_evidence, sort_keys=True, separators=(",", ":"))
            )
        descriptors = [
            {
                "path": path.relative_to(destination).as_posix(),
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
            for path in sorted(destination.rglob("*"))
            if path.is_file()
        ]
        unsigned = {
            "schema_version": "1.0",
            "analysis_run_id": str(analysis_run_id),
            "sample_sha256": sample_sha256,
            "platform": "windows",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "producer": {"name": "winstdt", "commit": WINSTDT_COMMIT},
            "native_contract": {
                "schema_version": "1.0",
                "source_commit": WINSTDT_COMMIT,
                "schema_path": "schemas/handoff_manifest.schema.json",
                "schema_sha256": HANDOFF_DIGEST,
            },
            "handoff_manifest": handoff,
            "cape": {
                "task_id": cape_task_id,
                "package": cape_package,
                "detected_type": detected_type,
            },
            "selected_profile": profile_snapshot,
            "artifacts": descriptors,
            "caveats": self._caveats(handoff, profile_snapshot),
        }
        signature = base64.b64encode(self.signing_key.sign(canonical_json(unsigned))).decode()
        manifest = unsigned | {
            "signature": {"key_id": self.key_id, "algorithm": "Ed25519", "value": signature}
        }
        validate_contract("windows/windows-import.schema.json", manifest)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "umat-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        for path in destination.rglob("*"):
            if path.is_file():
                os.chmod(path, stat.S_IRUSR | stat.S_IRGRP)
        archive = destination.with_suffix(".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            for path in sorted(destination.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(destination).as_posix())
        os.chmod(archive, stat.S_IRUSR | stat.S_IRGRP)
        return BuiltWindowsBundle(destination, archive, manifest)

    @staticmethod
    def _caveats(handoff: dict[str, Any], profile_snapshot: dict[str, Any]) -> list[str]:
        caveats: list[str] = []
        authoritative_mode = profile_snapshot.get("network_mode")
        if authoritative_mode == "isolated_simulated" or (
            authoritative_mode != "real_world_egress"
            and handoff.get("network_mode") == "simulated_inetsim"
        ):
            caveats.append("network_responses_simulated")
        if (handoff.get("telemetry") or {}).get("telemetry_degraded"):
            caveats.append("host_telemetry_degraded")
        if not (handoff.get("correlation") or {}).get("host_network_correlation_enabled", False):
            caveats.append("host_network_correlation_unavailable")
        return caveats


def safe_extract_windows_bundle(archive: Path, destination: Path, max_bytes: int) -> Path:
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    with zipfile.ZipFile(archive) as bundle:
        if sum(info.file_size for info in bundle.infolist()) > max_bytes:
            raise WindowsBundleError("Windows bundle exceeds uncompressed size limit")
        for info in bundle.infolist():
            relative = Path(info.filename)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or stat.S_ISLNK(info.external_attr >> 16)
            ):
                raise WindowsBundleError("unsafe Windows bundle member")
            if info.is_dir():
                continue
            target = (destination / relative).resolve()
            if destination.resolve() not in target.parents:
                raise WindowsBundleError("Windows bundle member escapes destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
    return destination


def verify_windows_bundle(
    root: Path,
    public_key: Ed25519PublicKey,
    native_validator: NativeWindowsValidator,
) -> dict[str, Any]:
    manifest = _load_object(root / "umat-manifest.json")
    validate_contract("windows/windows-import.schema.json", manifest)
    signature = manifest["signature"]
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    try:
        public_key.verify(
            base64.b64decode(signature["value"], validate=True), canonical_json(unsigned)
        )
    except (ValueError, InvalidSignature) as exc:
        raise WindowsBundleError("Windows bundle signature verification failed") from exc
    observed = {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file() and path.name != "umat-manifest.json"
    }
    descriptors = {item["path"]: item for item in manifest["artifacts"]}
    if set(observed) != set(descriptors):
        raise WindowsBundleError("Windows bundle artifact member set mismatch")
    for relative, path in observed.items():
        item = descriptors[relative]
        if item["sha256"] != sha256_file(path) or item["size_bytes"] != path.stat().st_size:
            raise WindowsBundleError(f"Windows bundle artifact mismatch: {relative}")
    native_validator.validate(
        root / "native", manifest["sample_sha256"], int(manifest["cape"]["task_id"])
    )
    return manifest
