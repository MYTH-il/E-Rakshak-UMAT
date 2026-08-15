import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from umat.c2.bundle import (
    C2BundleError,
    ResultBundleBuilder,
    safe_extract_bundle,
    verify_result_bundle,
)
from umat.c2.input_builder import C2InputBuilder, C2InputError
from umat.c2.models import InputArtifact
from umat.c2.runtime import FixtureC2Runtime, SubprocessC2Runtime

RUN_ID = UUID("0198fd40-1111-7000-8000-000000000001")
SAMPLE_HASH = "a" * 64


def artifact(path: Path, kind: str, content: bytes, source: str = "platform_analysis") -> InputArtifact:
    path.write_bytes(content)
    return InputArtifact(
        artifact_id=uuid4(),
        kind=kind,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        media_type="application/json" if kind != "pcap" else "application/vnd.tcpdump.pcap",
        source_stage_type=source,
        local_path=path,
    )


def android_inputs(root: Path) -> list[InputArtifact]:
    manifest = {
        "analysis_window": {
            "started_at": "2026-08-08T12:00:00Z",
            "ended_at": "2026-08-08T12:05:00Z",
        },
        "emulator": {"guest_ip": "10.0.2.15"},
        "caveats": ["encrypted_traffic"],
    }
    return [
        artifact(root / "android.pcap", "pcap", b"same-pcap-fixture"),
        artifact(root / "android-manifest.json", "platform_manifest", json.dumps(manifest).encode()),
    ]


def windows_inputs(root: Path) -> list[InputArtifact]:
    manifest = {
        "handoff_manifest": {
            "detonation_start_utc": "2026-08-08T12:00:00Z",
            "detonation_end_utc": "2026-08-08T12:05:00Z",
            "guest_vm_identity": {"guest_ip": "192.0.2.10"},
            "correlation": {"host_network_correlation_enabled": True},
        }
    }
    return [
        artifact(root / "windows.pcap", "pcap", b"same-pcap-fixture"),
        artifact(root / "windows-manifest.json", "platform_manifest", json.dumps(manifest).encode()),
        artifact(root / "access.json", "access_events", b"[]"),
    ]


def test_android_is_network_only_and_bundle_verifies(tmp_path: Path) -> None:
    context = C2InputBuilder().build(
        analysis_run_id=RUN_ID,
        platform="android",
        sample_sha256=SAMPLE_HASH,
        artifacts=android_inputs(tmp_path),
    )
    assert not context.correlation_eligible
    assert context.access_events is None
    assert "c2_network_only" in context.caveats

    private = Ed25519PrivateKey.generate()
    native = FixtureC2Runtime().run(context, tmp_path / "runtime")
    built = ResultBundleBuilder(private, str(uuid4())).build(context, native, tmp_path / "result")
    extracted = safe_extract_bundle(built.archive_path, tmp_path / "extracted")
    manifest = verify_result_bundle(extracted, private.public_key())
    assert manifest["native_event_schema_version"] == "1.3"
    assert manifest["correlation_mode"] == "network_only"
    assert all(event["data_type_accessed"] is None for event in manifest["network_events"])


def test_android_proxy_observations_are_available_to_c2(tmp_path: Path) -> None:
    inputs = android_inputs(tmp_path)
    inputs.append(artifact(
        tmp_path / "network-activity.json",
        "network_activity",
        json.dumps({"observations": [{
            "observed_at": "2026-08-08T12:01:00Z",
            "destination_domain": "runtime.example",
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "source": "mobsf_dynamic_proxy",
        }]}).encode(),
    ))
    context = C2InputBuilder().build(
        analysis_run_id=RUN_ID,
        platform="android",
        sample_sha256=SAMPLE_HASH,
        artifacts=inputs,
    )
    events = SubprocessC2Runtime._proxy_network_events(context)  # noqa: SLF001
    assert events[0]["destination_domain"] == "runtime.example"
    assert events[0]["finding_kind"] == "beacon"
    assert events[0]["capped_by_caveat"] == "c2_network_only"


def test_android_access_events_enable_review_grade_temporal_correlation(
    tmp_path: Path,
) -> None:
    inputs = android_inputs(tmp_path)
    access_document = {
        "schema_version": "1.0",
        "platform": "android",
        "package_name": "com.example.spy",
        "analysis_window": {
            "started_at": "2026-08-08T12:00:00Z",
            "ended_at": "2026-08-08T12:05:00Z",
        },
        "clock": {
            "basis": "executor_utc_first_observation",
            "quality_acceptable": True,
            "maximum_uncertainty_ms": 1000,
        },
        "sources": [{"source": "frida_api_monitor"}],
        "events": [
            {
                "event_id": "0198fd40-1111-7000-8000-000000000020",
                "timestamp": "2026-08-08T12:01:00Z",
                "timestamp_uncertainty_ms": 1000,
                "source": "frida_api_monitor",
                "package_name": "com.example.spy",
                "process_ids": [1234],
                "data_type": "contacts",
                "api_call": "android.content.ContentResolver.query",
                "operation": "query",
                "object_reference": "content://com.android.contacts/contacts",
                "called_from": "com.example.spy.Collector.run(Collector.java:42)",
                "source_event_sha256": "d" * 64,
            }
        ],
    }
    inputs.append(
        artifact(
            tmp_path / "android-access-events.json",
            "access_events",
            json.dumps(access_document).encode(),
        )
    )
    context = C2InputBuilder().build(
        analysis_run_id=RUN_ID,
        platform="android",
        sample_sha256=SAMPLE_HASH,
        artifacts=inputs,
    )
    assert context.correlation_eligible is True
    assert context.access_events is not None
    assert "c2_network_only" not in context.caveats
    assert "android_temporal_correlation_only" in context.caveats
    assert context.contract_document()["access_events"]["source"] == "android_telemetry"

    network = {
        "timestamp": "2026-08-08T12:01:02Z",
        "destination_ip": "198.51.100.20",
        "destination_port": 443,
        "destination_domain": "spy.example",
        "confidence_score": 0.8,
        "confidence_tier": "strong",
        "finding_kind": "beacon",
        "evidence_refs": [{"source": "immutable_guest_pcap"}],
    }
    correlations = SubprocessC2Runtime._correlate_android_access(  # noqa: SLF001
        context, [network]
    )
    assert len(correlations) == 1
    correlation = correlations[0]
    assert correlation["data_type_accessed"] == "contacts"
    assert correlation["confidence_tier"] == "weak"
    assert correlation["capped_by_caveat"] == "android_temporal_correlation_only"
    assert correlation["evidence_refs"][-1]["package_name"] == "com.example.spy"

    private = Ed25519PrivateKey.generate()
    native = FixtureC2Runtime().run(context, tmp_path / "runtime")
    native.events.extend(correlations)
    built = ResultBundleBuilder(private, str(uuid4())).build(
        context, native, tmp_path / "correlated-result"
    )
    manifest = verify_result_bundle(
        safe_extract_bundle(built.archive_path, tmp_path / "correlated-extracted"),
        private.public_key(),
    )
    assert manifest["correlation_mode"] == "temporal"
    correlated = next(
        event for event in manifest["network_events"] if event["finding_kind"] == "correlation"
    )
    assert correlated["data_type_accessed"] == "contacts"
    assert correlated["access_api_call"] == "android.content.ContentResolver.query"


def test_same_pcap_has_same_network_observation_across_platforms(tmp_path: Path) -> None:
    android_root = tmp_path / "android"
    windows_root = tmp_path / "windows"
    android_root.mkdir()
    windows_root.mkdir()
    builder = C2InputBuilder()
    android = builder.build(
        analysis_run_id=RUN_ID,
        platform="android",
        sample_sha256=SAMPLE_HASH,
        artifacts=android_inputs(android_root),
    )
    windows = builder.build(
        analysis_run_id=RUN_ID,
        platform="windows",
        sample_sha256=SAMPLE_HASH,
        artifacts=windows_inputs(windows_root),
    )
    runtime = FixtureC2Runtime()
    android_event = runtime.run(android, tmp_path / "runtime-a").events[0]
    windows_event = runtime.run(windows, tmp_path / "runtime-w").events[0]
    fields = ("destination_ip", "destination_port", "destination_domain", "timestamp")
    assert {field: android_event[field] for field in fields} == {
        field: windows_event[field] for field in fields
    }
    assert "data_type_accessed" not in android_event
    assert windows_event["data_type_accessed"] == "browser_credentials"


def test_bundle_signature_and_member_hash_tampering_fails(tmp_path: Path) -> None:
    context = C2InputBuilder().build(
        analysis_run_id=RUN_ID,
        platform="android",
        sample_sha256=SAMPLE_HASH,
        artifacts=android_inputs(tmp_path),
    )
    private = Ed25519PrivateKey.generate()
    built = ResultBundleBuilder(private, str(uuid4())).build(
        context, FixtureC2Runtime().run(context, tmp_path / "runtime"), tmp_path / "result"
    )
    extracted = safe_extract_bundle(built.archive_path, tmp_path / "extracted")
    events = extracted / "network-events.json"
    events.write_text(events.read_text().replace("fixture.invalid", "tampered.invalid"))
    with pytest.raises(C2BundleError, match="hash mismatch"):
        verify_result_bundle(extracted, private.public_key())


def test_missing_required_artifact_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(C2InputError, match="platform_manifest"):
        C2InputBuilder().build(
            analysis_run_id=RUN_ID,
            platform="android",
            sample_sha256=SAMPLE_HASH,
            artifacts=[artifact(tmp_path / "only.pcap", "pcap", b"pcap")],
        )


def test_analysis_window_rejects_naive_time(tmp_path: Path) -> None:
    manifest = {
        "analysis_window": {
            "started_at": datetime.now().isoformat(),
            "ended_at": datetime.now(timezone.utc).isoformat(),
        }
    }
    artifacts = [
        artifact(tmp_path / "capture.pcap", "pcap", b"pcap"),
        artifact(tmp_path / "manifest.json", "platform_manifest", json.dumps(manifest).encode()),
    ]
    with pytest.raises(C2InputError, match="timezone-aware"):
        C2InputBuilder().build(
            analysis_run_id=RUN_ID,
            platform="android",
            sample_sha256=SAMPLE_HASH,
            artifacts=artifacts,
        )
