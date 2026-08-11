from __future__ import annotations

import base64
import csv
import hashlib
import json
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from umat.c2.models import C2AnalysisContext, NativeC2Result
from umat.contracts import ContractError, validate_contract
from umat.contracts.canonical import canonical_json


class C2BundleError(ContractError):
    pass


@dataclass(frozen=True)
class BuiltBundle:
    root: Path
    manifest_path: Path
    archive_path: Path
    manifest: dict[str, Any]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ResultBundleBuilder:
    def __init__(self, signing_key: Ed25519PrivateKey, key_id: str) -> None:
        self.signing_key = signing_key
        self.key_id = key_id

    def build(
        self,
        context: C2AnalysisContext,
        native: NativeC2Result,
        destination: Path,
    ) -> BuiltBundle:
        if destination.exists() and any(destination.iterdir()):
            raise C2BundleError("result destination is not empty")
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        ioc_dir = destination / "iocs"
        integrity_dir = destination / "integrity"
        ioc_dir.mkdir(mode=0o700)
        integrity_dir.mkdir(mode=0o700)

        events, root_hash, tip_hash = self._normalize_events(context, native.events)
        self._write_json(destination / "network-events.json", events)
        self._write_json(
            destination / "exfil-events.json",
            [event for event in events if event["finding_kind"] in {"exfil", "correlation"}],
        )
        self._write_json(destination / "attribution.json", native.attribution)
        self._write_json(destination / "provenance.json", native.provenance)
        self._write_json(destination / "timeline.json", native.timeline)
        self._write_json(
            destination / "analysis-notes.json",
            {
                "notes": native.notes,
                "caveats": context.caveats,
                "runtime_identity": native.runtime_identity,
            },
        )
        self._write_iocs(ioc_dir / "iocs.csv", native.iocs, events)
        self._write_json(ioc_dir / "iocs-stix.json", [])

        result_files = [
            destination / "network-events.json",
            destination / "exfil-events.json",
            destination / "attribution.json",
            destination / "provenance.json",
            destination / "timeline.json",
            destination / "analysis-notes.json",
            ioc_dir / "iocs.csv",
            ioc_dir / "iocs-stix.json",
        ]
        artifacts = [self._descriptor(destination, path) for path in result_files]
        unsigned = {
            "schema_version": "1.0",
            "native_event_schema_version": "1.3",
            "analysis_run_id": str(context.analysis_run_id),
            "sample_sha256": context.sample_sha256,
            "platform": context.platform,
            "created_at": context.analysis_ended_at.isoformat(),
            "producer": {
                "name": "c2-exfil",
                "runtime_identity": native.runtime_identity,
                "tool_versions": native.tool_versions,
            },
            "pcap_sha256": context.pcap.sha256,
            "platform_manifest_sha256": context.platform_manifest.sha256,
            "analysis_window": {
                "started_at": context.analysis_started_at.isoformat(),
                "ended_at": context.analysis_ended_at.isoformat(),
            },
            "guest_ip": context.guest_ip,
            "correlation_mode": "host_network" if context.correlation_eligible else "network_only",
            "network_events": events,
            "artifacts": artifacts,
            "caveats": sorted(set(context.caveats)),
            "evidence_chain": {"root": root_hash, "tip": tip_hash},
        }
        signature_value = base64.b64encode(self.signing_key.sign(canonical_json(unsigned))).decode()
        manifest = unsigned | {
            "signature": {
                "algorithm": "Ed25519",
                "key_id": self.key_id,
                "value": signature_value,
            }
        }
        validate_contract("c2/c2-result.schema.json", manifest)
        manifest_path = destination / "manifest.json"
        self._write_json(manifest_path, manifest)
        hashes = result_files + [manifest_path]
        (destination / "hashes.sha256").write_text(
            "".join(
                f"{sha256_file(path)}  {path.relative_to(destination).as_posix()}\n"
                for path in hashes
            )
        )
        (integrity_dir / "signature").write_text(signature_value + "\n")
        for path in destination.rglob("*"):
            if path.is_file():
                os.chmod(path, stat.S_IRUSR | stat.S_IRGRP)
        archive = destination.with_suffix(".zip")
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(destination.rglob("*")):
                if path.is_file():
                    bundle.write(path, path.relative_to(destination).as_posix())
        os.chmod(archive, stat.S_IRUSR | stat.S_IRGRP)
        return BuiltBundle(destination, manifest_path, archive, manifest)

    @staticmethod
    def _normalize_events(
        context: C2AnalysisContext, native_events: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], str, str]:
        root = context.platform_manifest.sha256
        previous = root
        normalized: list[dict[str, Any]] = []
        for native in native_events:
            destination = (
                native.get("destination_domain") or native.get("destination_ip") or "unknown"
            )
            data_type = native.get("data_type_accessed")
            if context.platform == "android":
                data_type = None
            kind = native.get("finding_kind") or ResultBundleBuilder._finding_kind(
                native, bool(data_type)
            )
            plain = native.get("plain_language") or (
                f"The sample communicated with {destination}."
                if not data_type
                else f"Access to {data_type.replace('_', ' ')} was linked to {destination}."
            )
            evidence_refs = native.get("evidence_refs") or []
            evidence_refs = [
                item if isinstance(item, dict) else {"reference": str(item)}
                for item in evidence_refs
            ]
            row: dict[str, Any] = {
                "event_id": str(native.get("event_id") or uuid4()),
                "sample_id": context.sample_sha256,
                "session_id": native.get("session_id"),
                "cape_task_id": native.get("cape_task_id"),
                "platform": context.platform,
                "timestamp": str(
                    native.get("timestamp") or context.analysis_started_at.isoformat()
                ),
                "data_type_accessed": data_type,
                "access_api_call": native.get("access_api_call")
                if context.platform == "windows"
                else None,
                "destination_ip": native.get("destination_ip"),
                "destination_port": native.get("destination_port"),
                "destination_domain": native.get("destination_domain"),
                "asn": native.get("asn"),
                "asn_org": native.get("asn_org"),
                "geo_country": native.get("geo_country"),
                "reputation_score": native.get("reputation_score"),
                "reputation_note": native.get("reputation_note"),
                "reputation_source": native.get("reputation_source"),
                "ja3_hash": native.get("ja3_hash"),
                "plaintext_available": native.get("plaintext_available"),
                "confidence_score": native.get("confidence_score"),
                "confidence_tier": native.get("confidence_tier", "unconfirmed"),
                "mitre_technique_id": native.get("mitre_technique_id"),
                "manifest_sha256": root if not normalized else None,
                "case_id": str(context.analysis_run_id),
                "finding_kind": kind,
                "plain_language": str(plain),
                "capped_by_caveat": native.get("capped_by_caveat")
                or ("c2_network_only" if context.platform == "android" else None),
                "evidence_refs": evidence_refs,
            }
            row["evidence_hash"] = hashlib.sha256(
                previous.encode("ascii") + canonical_json(row)
            ).hexdigest()
            previous = row["evidence_hash"]
            normalized.append(row)
        return normalized, root, previous

    @staticmethod
    def _finding_kind(native: dict[str, Any], correlated: bool) -> str:
        if correlated:
            return "correlation"
        technique = str(native.get("mitre_technique_id") or "")
        if technique == "T1071.004" or native.get("destination_port") == 53:
            return "dns"
        if technique in {"T1048", "T1048.003", "T1567", "T1567.002"}:
            return "exfil"
        if technique in {"T1572", "T1573"}:
            return "covert_channel"
        if (native.get("reputation_score") or 0) > 0:
            return "reputation"
        return "beacon"

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _descriptor(root: Path, path: Path) -> dict[str, Any]:
        return {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
            "size_bytes": path.stat().st_size,
        }

    @staticmethod
    def _write_iocs(
        path: Path, native_iocs: list[dict[str, Any]], events: list[dict[str, Any]]
    ) -> None:
        rows = native_iocs or [
            {
                "type": "domain" if event.get("destination_domain") else "ip",
                "value": event.get("destination_domain") or event.get("destination_ip"),
                "confidence": event["confidence_tier"],
                "source_event_id": event["event_id"],
            }
            for event in events
            if event.get("destination_domain") or event.get("destination_ip")
        ]
        fields = ["type", "value", "confidence", "source_event_id"]
        with path.open("w", newline="") as destination:
            writer = csv.DictWriter(destination, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)


def verify_result_bundle(root: Path, public_key: Ed25519PublicKey) -> dict[str, Any]:
    expected_files = {
        "manifest.json",
        "hashes.sha256",
        "integrity/signature",
        "network-events.json",
        "exfil-events.json",
        "attribution.json",
        "provenance.json",
        "timeline.json",
        "analysis-notes.json",
        "iocs/iocs.csv",
        "iocs/iocs-stix.json",
    }
    observed_files = {
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    }
    if observed_files != expected_files:
        raise C2BundleError(
            f"result bundle member set mismatch: {sorted(observed_files ^ expected_files)}"
        )
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text())
        validate_contract("c2/c2-result.schema.json", manifest)
    except (OSError, json.JSONDecodeError, ContractError) as exc:
        raise C2BundleError(f"invalid result manifest: {exc}") from exc
    signature = manifest["signature"]
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    try:
        public_key.verify(
            base64.b64decode(signature["value"], validate=True), canonical_json(unsigned)
        )
    except (ValueError, InvalidSignature) as exc:
        raise C2BundleError("result signature verification failed") from exc
    if (root / "integrity/signature").read_text().strip() != signature["value"]:
        raise C2BundleError("detached result signature mismatch")
    expected_hashes: dict[str, str] = {}
    try:
        for line in (root / "hashes.sha256").read_text().splitlines():
            digest, relative = line.split("  ", 1)
            if relative in expected_hashes or len(digest) != 64:
                raise ValueError
            expected_hashes[relative] = digest
    except (OSError, ValueError) as exc:
        raise C2BundleError("invalid result hash manifest") from exc
    hashed_files = expected_files - {"hashes.sha256", "integrity/signature"}
    if set(expected_hashes) != hashed_files:
        raise C2BundleError("result hash manifest member set mismatch")
    for relative, expected in expected_hashes.items():
        path = (root / relative).resolve()
        if root.resolve() not in path.parents or sha256_file(path) != expected:
            raise C2BundleError(f"result artifact hash mismatch: {relative}")
    descriptors = {item["path"]: item for item in manifest["artifacts"]}
    result_files = hashed_files - {"manifest.json"}
    if set(descriptors) != result_files:
        raise C2BundleError("result artifact descriptor set mismatch")
    for relative, descriptor in descriptors.items():
        path = root / relative
        if (
            descriptor["sha256"] != sha256_file(path)
            or descriptor["size_bytes"] != path.stat().st_size
        ):
            raise C2BundleError(f"result artifact descriptor mismatch: {relative}")
    previous = manifest["evidence_chain"]["root"]
    for event in manifest["network_events"]:
        content = {key: value for key, value in event.items() if key != "evidence_hash"}
        expected = hashlib.sha256(previous.encode("ascii") + canonical_json(content)).hexdigest()
        if event["evidence_hash"] != expected:
            raise C2BundleError(f"event evidence chain failed at {event['event_id']}")
        previous = expected
    if previous != manifest["evidence_chain"]["tip"]:
        raise C2BundleError("event evidence-chain tip mismatch")
    return cast(dict[str, Any], manifest)


def safe_extract_bundle(
    archive: Path, destination: Path, max_uncompressed_bytes: int = 1024 * 1024 * 1024
) -> Path:
    destination.mkdir(parents=True, exist_ok=False, mode=0o700)
    with zipfile.ZipFile(archive) as bundle:
        if sum(info.file_size for info in bundle.infolist()) > max_uncompressed_bytes:
            raise C2BundleError("result bundle exceeds uncompressed size limit")
        for info in bundle.infolist():
            relative = Path(info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise C2BundleError("result bundle contains a symbolic link")
            if relative.is_absolute() or ".." in relative.parts or info.is_dir():
                if info.is_dir():
                    continue
                raise C2BundleError("unsafe result bundle member")
            target = (destination / relative).resolve()
            if destination.resolve() not in target.parents:
                raise C2BundleError("result bundle member escapes destination")
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, target.open("xb") as output:
                output.write(source.read())
    return destination
