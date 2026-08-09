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

ANDROID_COMMIT = "6462901d1aaa0b090b867934ea5a01a82d31bc03"
MOBSF_VERSION = "4.5.1"


class AndroidBundleError(ContractError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AndroidBundleError(f"invalid JSON file: {path.name}") from exc
    if not isinstance(value, dict):
        raise AndroidBundleError(f"{path.name} must contain an object")
    return cast(dict[str, Any], value)


@dataclass(frozen=True)
class BuiltAndroidBundle:
    root: Path
    archive_path: Path
    manifest: dict[str, Any]


class AndroidBundleBuilder:
    def __init__(self, signing_key: Ed25519PrivateKey, key_id: str) -> None:
        self.signing_key = signing_key
        self.key_id = key_id

    def build(
        self,
        *,
        analysis_run_id: UUID,
        sample_sha256: str,
        scan_hash: str,
        analysis_started_at: datetime,
        analysis_ended_at: datetime,
        emulator: dict[str, Any],
        static_report: Path,
        dynamic_report: Path | None,
        evidence: dict[str, Path],
        stimulation: dict[str, Any],
        caveats: list[str],
        destination: Path,
    ) -> BuiltAndroidBundle:
        if destination.exists():
            raise AndroidBundleError("Android bundle destination already exists")
        destination.mkdir(parents=True, mode=0o700)
        sources = {"mobsf_static_report": static_report, **evidence}
        if dynamic_report is not None:
            sources["mobsf_dynamic_report"] = dynamic_report
        descriptors: dict[str, dict[str, Any]] = {}
        for kind, source in sorted(sources.items()):
            if not source.is_file():
                raise AndroidBundleError(f"missing Android evidence: {kind}")
            target = destination / "evidence" / f"{kind}{source.suffix or '.bin'}"
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            descriptors[kind] = {
                "kind": kind,
                "path": target.relative_to(destination).as_posix(),
                "sha256": sha256_file(target),
                "size_bytes": target.stat().st_size,
            }
        unsigned = {
            "schema_version": "1.0",
            "analysis_run_id": str(analysis_run_id),
            "sample_sha256": sample_sha256,
            "platform": "android",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "producer": {
                "name": "android-erakshak",
                "commit": ANDROID_COMMIT,
                "mobsf_version": MOBSF_VERSION,
            },
            "native_contract": {
                "api_version": "v1",
                "source_commit": ANDROID_COMMIT,
                "static_report_endpoint": "/api/v1/report_json",
                "dynamic_report_endpoint": "/api/v1/dynamic/report_json",
            },
            "analysis_window": {
                "started_at": analysis_started_at.astimezone(timezone.utc).isoformat(),
                "ended_at": analysis_ended_at.astimezone(timezone.utc).isoformat(),
            },
            "emulator": emulator,
            "mobsf_reports": {
                "scan_hash": scan_hash,
                "static": descriptors["mobsf_static_report"],
                "dynamic": descriptors.get("mobsf_dynamic_report"),
            },
            "artifacts": list(descriptors.values()),
            "stimulation": stimulation,
            "caveats": sorted(set(caveats)),
        }
        signature = base64.b64encode(self.signing_key.sign(canonical_json(unsigned))).decode()
        manifest = unsigned | {
            "signature": {"key_id": self.key_id, "algorithm": "Ed25519", "value": signature}
        }
        validate_contract("android/android-bundle.schema.json", manifest)
        (destination / "umat-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        archive = destination.with_suffix(".zip")
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            for path in sorted(destination.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(destination).as_posix())
                    os.chmod(path, stat.S_IRUSR | stat.S_IRGRP)
        os.chmod(archive, stat.S_IRUSR | stat.S_IRGRP)
        return BuiltAndroidBundle(destination, archive, manifest)


def safe_extract_android_bundle(archive: Path, destination: Path, max_bytes: int) -> Path:
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    with zipfile.ZipFile(archive) as bundle:
        members = bundle.infolist()
        if sum(item.file_size for item in members) > max_bytes:
            raise AndroidBundleError("Android bundle exceeds uncompressed size limit")
        for item in members:
            relative = Path(item.filename)
            if relative.is_absolute() or ".." in relative.parts or stat.S_ISLNK(item.external_attr >> 16):
                raise AndroidBundleError("unsafe Android bundle member")
            if item.is_dir():
                continue
            target = (destination / relative).resolve()
            if destination.resolve() not in target.parents:
                raise AndroidBundleError("Android bundle member escapes destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as source, target.open("xb") as output:
                shutil.copyfileobj(source, output)
    return destination


def verify_android_bundle(root: Path, public_key: Ed25519PublicKey) -> dict[str, Any]:
    manifest = _object(root / "umat-manifest.json")
    validate_contract("android/android-bundle.schema.json", manifest)
    signature = manifest["signature"]
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    try:
        public_key.verify(base64.b64decode(signature["value"], validate=True), canonical_json(unsigned))
    except (ValueError, InvalidSignature) as exc:
        raise AndroidBundleError("Android bundle signature verification failed") from exc
    observed = {
        path.relative_to(root).as_posix(): path
        for path in root.rglob("*")
        if path.is_file() and path.name != "umat-manifest.json"
    }
    descriptors = {item["path"]: item for item in manifest["artifacts"]}
    if len(descriptors) != len(manifest["artifacts"]) or set(observed) != set(descriptors):
        raise AndroidBundleError("Android bundle artifact member set mismatch")
    for relative, path in observed.items():
        item = descriptors[relative]
        if item["sha256"] != sha256_file(path) or item["size_bytes"] != path.stat().st_size:
            raise AndroidBundleError(f"Android bundle artifact mismatch: {relative}")
    return manifest
