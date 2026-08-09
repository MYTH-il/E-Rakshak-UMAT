from __future__ import annotations

import json
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from umat.android.bundle import (
    AndroidBundleBuilder,
    AndroidBundleError,
    safe_extract_android_bundle,
    verify_android_bundle,
)


def test_android_bundle_round_trip_and_tamper_detection(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    static = tmp_path / "static.json"
    dynamic = tmp_path / "dynamic.json"
    pcap = tmp_path / "capture.pcap"
    static.write_text(json.dumps({"package_name": "test.app"}))
    dynamic.write_text(json.dumps({"domains": ["example.test"]}))
    pcap.write_bytes(b"pcap fixture")
    started = datetime.now(timezone.utc)
    built = AndroidBundleBuilder(key, "executor-key").build(
        analysis_run_id=uuid4(),
        sample_sha256="a" * 64,
        scan_hash="b" * 32,
        analysis_started_at=started,
        analysis_ended_at=started + timedelta(seconds=30),
        emulator={"api_level": 30, "avd_name": "umat-test", "guest_ip": "10.0.2.15"},
        static_report=static,
        dynamic_report=dynamic,
        evidence={"pcap": pcap},
        stimulation={"strategy": "deterministic_adb_v1", "actions_completed": 5},
        caveats=["c2_network_only"],
        destination=tmp_path / "bundle",
    )
    extracted = safe_extract_android_bundle(built.archive_path, tmp_path / "extracted", 1024 * 1024)
    manifest = verify_android_bundle(extracted, key.public_key())
    assert manifest["producer"]["mobsf_version"] == "4.5.1"
    assert manifest["mobsf_reports"]["dynamic"] is not None

    (extracted / "evidence" / "pcap.pcap").write_bytes(b"modified")
    with pytest.raises(AndroidBundleError, match="artifact mismatch"):
        verify_android_bundle(extracted, key.public_key())


def test_android_bundle_rejects_traversal_and_size_limit(tmp_path: Path) -> None:
    malicious = tmp_path / "malicious.zip"
    with zipfile.ZipFile(malicious, "w") as archive:
        archive.writestr("../escape", b"bad")
    with pytest.raises(AndroidBundleError, match="unsafe"):
        safe_extract_android_bundle(malicious, tmp_path / "unsafe", 1024)

    oversized = tmp_path / "oversized.zip"
    with zipfile.ZipFile(oversized, "w") as archive:
        archive.writestr("large", b"x" * 32)
    with pytest.raises(AndroidBundleError, match="size limit"):
        safe_extract_android_bundle(oversized, tmp_path / "large", 16)
