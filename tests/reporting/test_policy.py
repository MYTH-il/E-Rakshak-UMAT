from __future__ import annotations

from types import SimpleNamespace

from umat.db.models import Platform, StageState, StageType, Verdict
from umat.reporting.aggregator import CaseAggregator, filter_report_for_roles
from umat.reporting.exports import ReportExporter


def test_android_network_only_never_promotes_data_access() -> None:
    event = SimpleNamespace(data_type_accessed="contacts", confidence="confirmed")
    assert CaseAggregator._capabilities([], [event], Platform.ANDROID) == []


def test_android_network_only_rewrites_causal_provenance() -> None:
    link = SimpleNamespace(
        statement="Contacts were stolen.",
        item_type="contacts",
        destination="example.invalid",
        source_event_id="event-1",
    )
    result = CaseAggregator._provenance([link], Platform.ANDROID)
    assert result[0]["item_type"] is None
    assert "not linked to a specific Android data item" in result[0]["statement"]
    assert "stolen" not in result[0]["statement"]


def test_verdict_policy_never_emits_safe() -> None:
    verdict = CaseAggregator._verdict(
        [
            {
                "confidence": "confirmed",
                "kind": "exfil",
                "details": {},
            }
        ],
        [],
        [],
        True,
        True,
    )
    assert verdict == Verdict.MALICIOUS
    assert "safe" not in {item.value for item in Verdict}


def test_isolated_verdict_does_not_require_c2_stages() -> None:
    stages = [
        SimpleNamespace(stage_type=StageType.PLATFORM_ANALYSIS, state=StageState.COMPLETED),
        SimpleNamespace(stage_type=StageType.PLATFORM_ADAPTATION, state=StageState.COMPLETED),
    ]
    verdict = CaseAggregator._verdict([], [], stages, True, False, requires_c2=False)
    assert verdict == Verdict.NO_MALICIOUS_ACTIVITY_OBSERVED


def test_officer_filter_removes_technical_and_restricted_artifacts() -> None:
    report = {
        "technical": {"findings": [{"summary": "analyst detail"}]},
        "artifacts": [
            {"artifact_id": "one", "access_tier": "officer"},
            {"artifact_id": "two", "access_tier": "analyst"},
        ],
    }
    filtered = filter_report_for_roles(report, frozenset({"officer"}))
    assert "technical" not in filtered
    assert [item["artifact_id"] for item in filtered["artifacts"]] == ["one"]


def test_csv_formula_injection_is_neutralized() -> None:
    content = ReportExporter._csv(
        {
            "technical": {
                "iocs": [
                    {
                        "type": "domain",
                        "value": '=HYPERLINK("bad")',
                        "confidence": "strong",
                        "source": "fixture",
                        "seen_in_traffic": True,
                    }
                ],
                "findings": [],
            }
        }
    ).decode()
    assert "'=HYPERLINK" in content
