from __future__ import annotations

import json
import subprocess
from datetime import datetime
from typing import Any
from uuid import uuid4

from umat.android.access_events import AndroidAccessEventCollector
from umat.android.adapter import AndroidAdapter
from umat.android.executor import AndroidExecutor
from umat.db.models import AndroidCapability, AndroidFinding, StaticIOC


class RecordingSession:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    def add(self, value: Any) -> None:
        self.rows.append(value)


def test_android_normalization_separates_declared_and_observed_evidence() -> None:
    session = RecordingSession()
    adaptation_id, run_id = uuid4(), uuid4()
    static = {
        "permissions": {
            "android.permission.READ_CONTACTS": {"status": "dangerous"},
            "android.permission.CAMERA": {"status": "dangerous"},
        },
        "manifest_analysis": [
            {"rule": "exported_activity", "severity": "high", "title": "Exported activity"}
        ],
        "urls": ["https://api.example.test/path"],
    }
    dynamic = {"api_monitor": [{"class": "ContactsContract", "method": "query"}]}
    AndroidAdapter._findings(session, adaptation_id, run_id, static, dynamic)  # type: ignore[arg-type]
    AndroidAdapter._capabilities(session, adaptation_id, run_id, static, dynamic)  # type: ignore[arg-type]
    AndroidAdapter._iocs(session, adaptation_id, run_id, static, dynamic)  # type: ignore[arg-type]

    findings = [item for item in session.rows if isinstance(item, AndroidFinding)]
    capabilities = [item for item in session.rows if isinstance(item, AndroidCapability)]
    iocs = [item for item in session.rows if isinstance(item, StaticIOC)]
    assert findings[0].confidence == "strong"
    assert {(item.data_type, item.evidence_level) for item in capabilities} == {
        ("contacts", "observed"),
        ("camera", "declared"),
    }
    assert ("domain", "api.example.test") in {(item.ioc_type, item.value) for item in iocs}


def test_android_imports_mobsf_security_and_behavior_mappings() -> None:
    session = RecordingSession()
    AndroidAdapter._findings(  # noqa: SLF001
        session,
        uuid4(),
        uuid4(),
        {
            "code_analysis": {
                "findings": {
                    "android_hardcoded": {
                        "files": {"Example.java": "10"},
                        "metadata": {
                            "description": "Hardcoded secret",
                            "severity": "warning",
                            "masvs": "MSTG-STORAGE-14",
                            "owasp-mobile": "M9: Reverse Engineering",
                            "cwe": "CWE-312: Cleartext Storage of Sensitive Information",
                        },
                    }
                }
            },
            "behaviour": {
                "00030": {
                    "files": {"Example.java": "20"},
                    "metadata": {
                        "description": "Connect to a remote server",
                        "severity": "info",
                        "label": ["network"],
                    },
                }
            },
        },
        {},
    )
    findings = [item for item in session.rows if isinstance(item, AndroidFinding)]
    assert len(findings) == 2
    code = next(item for item in findings if item.category == "code")
    assert code.kind == "android_hardcoded"
    assert code.details["security_mappings"] == [
        "CWE-312: Cleartext Storage of Sensitive Information",
        "OWASP MASVS/MSTG: MSTG-STORAGE-14",
        "OWASP Mobile: M9: Reverse Engineering",
    ]
    behavior = next(item for item in findings if item.category == "behavior")
    assert behavior.details["security_mappings"] == ["MobSF behavior: network"]


def test_android_ioc_normalization_drops_tool_references_and_placeholders() -> None:
    session = RecordingSession()
    AndroidAdapter._iocs(  # noqa: SLF001
        session,
        uuid4(),
        uuid4(),
        {
            "urls": [
                "https://uklivemy.gq/USK/rat.php",
                "https://github.com/MobSF/owasp-mstg/blob/main/reference.md",
                "https://%s/%s/%s",
                "https://invalid-url/",
            ]
        },
        {"domains": {"uklivemy.gq": {}}},
    )
    iocs = [item for item in session.rows if isinstance(item, StaticIOC)]
    assert {(item.ioc_type, item.value) for item in iocs} == {
        ("domain", "uklivemy.gq"),
        ("url", "https://uklivemy.gq/USK/rat.php"),
    }
    assert all(item.seen_in_traffic for item in iocs)


def test_dynamic_quality_rejects_android_baseline_only_traffic(tmp_path: Any) -> None:
    quality = AndroidExecutor._dynamic_quality(  # noqa: SLF001
        {"domains": {"www.google.com": {}}, "clipboard": [], "sqlite": []},
        {},
        {"frida": {"status": "ok"}, "stimulation": {"package_process_ids": ["123"]}},
    )
    assert quality["package_process_observed"] is True
    assert quality["runtime_behavior_observed"] is False


def test_dynamic_quality_accepts_api_monitor_events(tmp_path: Any) -> None:
    monitor = tmp_path / "api.json"
    monitor.write_text('{"data":[{"class":"android.content.ContentResolver"}]}')
    quality = AndroidExecutor._dynamic_quality(  # noqa: SLF001
        {"domains": {}},
        {"api_monitor": monitor},
        {"frida": {"status": "ok"}, "stimulation": {"package_process_ids": ["123"]}},
    )
    assert quality["api_monitor_event_count"] == 1
    assert quality["runtime_behavior_observed"] is True


def test_access_event_collector_normalizes_sensitive_frida_rows(tmp_path: Any) -> None:
    collector = AndroidAccessEventCollector(
        lambda: {
            "data": [
                {
                    "name": "Device Data",
                    "class": "android.content.ContentResolver",
                    "method": "query",
                    "arguments": ["content://com.android.contacts/contacts"],
                    "calledFrom": "com.example.spy.Collector.run(Collector.java:42)",
                },
                {
                    "name": "Crypto",
                    "class": "javax.crypto.Cipher",
                    "method": "doFinal",
                    "arguments": [],
                },
            ]
        },
        package_name="com.example.spy",
        process_ids=["1234"],
        started_at=datetime.fromisoformat("2026-08-08T12:00:00+00:00"),
        poll_interval_seconds=0.1,
    )
    collector.start()
    destination = tmp_path / "access-events.json"
    document = collector.stop(
        destination, ended_at=datetime.fromisoformat("2026-08-08T12:05:00+00:00")
    )
    assert destination.is_file()
    assert len(document["events"]) == 1
    assert document["events"][0]["data_type"] == "contacts"
    assert document["events"][0]["api_call"] == "android.content.ContentResolver.query"
    assert document["events"][0]["process_ids"] == [1234]


def test_access_event_collector_distinguishes_empty_monitor_from_failure(tmp_path: Any) -> None:
    collector = AndroidAccessEventCollector(
        lambda: {"status": "waiting", "data": []},
        package_name="com.example.quiet",
        process_ids=["42"],
        started_at=datetime.fromisoformat("2026-08-08T12:00:00+00:00"),
        poll_interval_seconds=0.1,
    )
    collector.start()
    document = collector.stop(tmp_path / "access-events.json")

    assert document["events"] == []
    assert document["clock"]["quality_acceptable"] is True
    assert document["sources"][0]["poll_errors"] == 0


def test_dynamic_quality_accepts_ready_empty_api_monitor(tmp_path: Any) -> None:
    monitor = tmp_path / "api.json"
    monitor.write_text('{"status":"waiting","data":[]}')
    quality = AndroidExecutor._dynamic_quality(  # noqa: SLF001
        {"domains": {}},
        {"api_monitor": monitor},
        {
            "frida": {"status": "ok", "hook_ready": True},
            "stimulation": {"package_process_ids": ["123"]},
        },
    )

    assert quality["api_monitor_available"] is True
    assert quality["api_monitor_event_count"] == 0
    assert quality["instrumentation_evidence_observed"] is True


def test_network_summary_merges_proxy_checkpoint_when_final_report_is_empty(
    tmp_path: Any,
    monkeypatch: Any,
) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"immutable-pcap")
    destination = tmp_path / "network.json"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, b"", b""),
    )
    AndroidExecutor._network_summary(  # noqa: SLF001
        object.__new__(AndroidExecutor),
        pcap,
        "172.30.0.2",
        destination,
        {"domains": {}, "urls": []},
        {
            "checkpoints": [
                {
                    "status": "ok",
                    "captured_at": "2026-08-10T12:00:00Z",
                    "reason": "before_tls_test",
                    "domains": {"api.example.test": {"geolocation": {"ip": "203.0.113.8"}}},
                    "urls": ["https://api.example.test/path"],
                }
            ]
        },
    )
    document = json.loads(destination.read_text())
    assert document["proxy_checkpoint_count"] == 2
    assert document["observations"][0]["destination_domain"] == "api.example.test"
    assert document["observations"][0]["source"] == "mobsf_proxy_checkpoint"
    assert document["observations"][0]["provenance"]["checkpoint_reason"] == "before_tls_test"


def test_network_summary_merges_isolated_mitmproxy_events(tmp_path: Any, monkeypatch: Any) -> None:
    pcap = tmp_path / "capture.pcap"
    pcap.write_bytes(b"immutable-pcap")
    sidecar = tmp_path / "mitmproxy"
    sidecar.mkdir()
    (sidecar / "events.jsonl").write_text(
        json.dumps(
            {
                "event": "request",
                "observed_at": "2026-08-11T11:00:00Z",
                "scheme": "https",
                "host": "c2.example.test",
                "port": 443,
            }
        )
        + "\n"
    )
    destination = tmp_path / "network.json"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, b"", b""),
    )
    AndroidExecutor._network_summary(  # noqa: SLF001
        object.__new__(AndroidExecutor), pcap, "172.30.0.2", destination
    )
    observation = json.loads(destination.read_text())["observations"][0]
    assert observation["destination_domain"] == "c2.example.test"
    assert observation["source"] == "mitmproxy_sidecar"
    assert observation["provenance"]["upstream"] == "none"
