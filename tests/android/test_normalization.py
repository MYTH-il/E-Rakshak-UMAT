from __future__ import annotations

from typing import Any
from uuid import uuid4

from umat.android.adapter import AndroidAdapter
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
