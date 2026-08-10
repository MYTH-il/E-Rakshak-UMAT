from __future__ import annotations

from typing import Any
from uuid import uuid4

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
        "manifest_analysis": [{"rule": "exported_activity", "severity": "high", "title": "Exported activity"}],
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


def test_android_ioc_normalization_drops_tool_references_and_placeholders() -> None:
    session = RecordingSession()
    AndroidAdapter._iocs(  # noqa: SLF001
        session, uuid4(), uuid4(),
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
        ("domain", "uklivemy.gq"), ("url", "https://uklivemy.gq/USK/rat.php")
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
        {"domains": {}}, {"api_monitor": monitor},
        {"frida": {"status": "ok"}, "stimulation": {"package_process_ids": ["123"]}},
    )
    assert quality["api_monitor_event_count"] == 1
    assert quality["runtime_behavior_observed"] is True
