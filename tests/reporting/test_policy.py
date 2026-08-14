from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from umat.db.models import Platform, StageState, StageType, Verdict
from umat.reporting.aggregator import CaseAggregator, filter_report_for_roles
from umat.reporting.exports import ReportExporter


def test_c2_timeline_confidence_tier_survives_report_aggregation() -> None:
    event = SimpleNamespace(
        occurred_at=datetime(2026, 8, 14, tzinfo=timezone.utc),
        actor="network",
        description="C2 beacon observed.",
        mitre_technique_id="T1071.001",
        # The native C2 timeline.json schema emits the tier at the top level;
        # the adapter retains the complete item in TimelineEvent.details.
        details={"tier": "strong"},
    )
    assert CaseAggregator._timeline([event])[0]["confidence"] == "strong"


def test_legacy_c2_timeline_confidence_tier_survives_report_aggregation() -> None:
    event = SimpleNamespace(
        occurred_at=datetime(2026, 8, 14, tzinfo=timezone.utc),
        actor="network",
        description="C2 beacon observed.",
        mitre_technique_id="T1071.001",
        details={"confidence_tier": "confirmed"},
    )
    assert CaseAggregator._timeline([event])[0]["confidence"] == "confirmed"


def test_unknown_timeline_confidence_fails_closed() -> None:
    event = SimpleNamespace(
        occurred_at=datetime(2026, 8, 14, tzinfo=timezone.utc),
        actor="network",
        description="C2 event.",
        mitre_technique_id=None,
        details={"confidence_tier": "certain-ish"},
    )
    assert CaseAggregator._timeline([event])[0]["confidence"] == "unconfirmed"


def test_report_coalesces_legacy_duplicate_network_observations() -> None:
    base = {
        "analysis_run_id": "run",
        "stage_id": "stage",
        "platform": "windows",
        "source": "c2",
        "kind": "network_observation",
        "category": "network",
        "confidence": "weak",
        "evidence_level": "observed",
        "summary": "Network traffic was observed without attribution.",
        "mitre_technique_ids": [],
        "security_mappings": [],
        "evidence_artifact_ids": ["pcap"],
        "caveats": ["network_process_not_sample"],
    }
    details = {
        "timestamp": "2026-08-11T12:00:02Z",
        "destination_domain": "go.microsoft.com",
        "destination_ip": "198.51.100.10",
        "destination_port": 443,
        "protocol": "TCP",
    }
    findings = [
        {
            **base,
            "finding_id": "one",
            "details": {**details, "evidence_refs": [{"type": "host_access", "id": "a"}]},
        },
        {
            **base,
            "finding_id": "two",
            "details": {
                **details,
                "destination_ip": "203.0.113.20",
                "evidence_refs": [{"type": "host_access", "id": "b"}],
            },
        },
    ]

    result = CaseAggregator._coalesce_network_findings(findings)

    assert len(result) == 1
    assert result[0]["details"]["observation_count"] == 2
    assert result[0]["details"]["observed_destination_ips"] == [
        "198.51.100.10",
        "203.0.113.20",
    ]
    assert result[0]["details"]["source_finding_ids"] == ["one", "two"]
    assert {ref["id"] for ref in result[0]["details"]["evidence_refs"]} == {"a", "b"}


def test_ioc_projection_merges_duplicate_confidence_and_observation_state() -> None:
    iocs = [
        SimpleNamespace(
            ioc_type="domain",
            value="cdn.onenote.net",
            confidence="weak",
            source="c2-runtime",
            seen_in_traffic=False,
        ),
        SimpleNamespace(
            ioc_type="domain",
            value="cdn.onenote.net",
            confidence="confirmed",
            source="c2-runtime",
            seen_in_traffic=True,
        ),
    ]
    assert CaseAggregator._iocs(iocs, {("domain", "cdn.onenote.net")}) == [
        {
            "type": "domain",
            "value": "cdn.onenote.net",
            "confidence": "confirmed",
            "source": "c2-runtime",
            "seen_in_traffic": True,
        }
    ]


def test_ioc_projection_sorts_actionable_before_allowlisted() -> None:
    iocs = [
        SimpleNamespace(
            ioc_type="domain",
            value="update.example",
            confidence="allowlisted",
            source="c2-runtime",
            seen_in_traffic=True,
        ),
        SimpleNamespace(
            ioc_type="domain",
            value="weak.example",
            confidence="weak",
            source="c2-runtime",
            seen_in_traffic=True,
        ),
        SimpleNamespace(
            ioc_type="domain",
            value="confirmed.example",
            confidence="confirmed",
            source="c2-runtime",
            seen_in_traffic=True,
        ),
    ]

    assert [item["confidence"] for item in CaseAggregator._iocs(iocs)] == [
        "confirmed",
        "weak",
        "allowlisted",
    ]


def test_report_destinations_fill_missing_geolite_fields(monkeypatch) -> None:
    monkeypatch.setattr(
        "umat.reporting.aggregator.lookup_ip",
        lambda value: ("US", "AS15169", "Google LLC"),
    )
    observation = SimpleNamespace(
        destination_domain=None,
        destination_ip="8.8.8.8",
        destination_port=443,
        protocol="tcp",
        observed_at=datetime(2026, 8, 14, tzinfo=timezone.utc),
        details={
            "geo_country": None,
            "asn": None,
            "asn_org": None,
            "reputation_score": 0.0,
        },
    )

    destination = CaseAggregator._destinations([observation])[0]

    assert destination["geo_country"] == "US"
    assert destination["asn"] == "AS15169"
    assert destination["asn_org"] == "Google LLC"


def test_android_network_only_never_promotes_data_access() -> None:
    event = SimpleNamespace(data_type_accessed="contacts", confidence="confirmed")
    assert CaseAggregator._capabilities([], [event], Platform.ANDROID) == []


def test_windows_capability_preserves_accessed_file_context() -> None:
    capability = SimpleNamespace(
        capability="file_access",
        confidence="confirmed",
        details={
            "events": [
                {
                    "object_name": "Login Data",
                    "object_path": r"C:\Users\Analyst\Edge\Login Data",
                    "access_operation": "FILE_READ_DATA",
                    "process_path": r"C:\Temp\sample.exe",
                    "process_id": 4242,
                }
            ]
        },
    )
    result = CaseAggregator._capabilities([capability], [], Platform.WINDOWS)
    assert result[0]["observed_objects"] == [
        {
            "name": "Login Data",
            "path": r"C:\Users\Analyst\Edge\Login Data",
            "operation": "FILE_READ_DATA",
            "process": r"C:\Temp\sample.exe",
            "process_id": 4242,
        }
    ]


def test_windows_access_event_projection_keeps_action_object_and_provenance() -> None:
    capability = SimpleNamespace(
        capability="file_access",
        details={
            "events": [
                {
                    "timestamp": "2026-08-11T22:40:07Z",
                    "data_type": "file_access",
                    "api_call": "NtCreateFile",
                    "access_operation": "FILE_READ_DATA|FILE_OPEN",
                    "object_name": "Login Data",
                    "object_path": r"C:\Users\Analyst\Edge\Login Data",
                    "process": "sample.exe",
                    "process_path": r"C:\Temp\sample.exe",
                    "process_id": 4242,
                    "parent_process_id": 1000,
                    "source_call_id": "3349",
                }
            ]
        },
    )
    assert CaseAggregator._access_events([capability]) == [
        {
            "timestamp": "2026-08-11T22:40:07Z",
            "data_type": "file_access",
            "action": "FILE_READ_DATA|FILE_OPEN",
            "api_call": "NtCreateFile",
            "object_name": "Login Data",
            "object_path": r"C:\Users\Analyst\Edge\Login Data",
            "process": "sample.exe",
            "process_path": r"C:\Temp\sample.exe",
            "process_id": 4242,
            "parent_process_id": 1000,
            "source_call_id": "3349",
            "source": "winstdt_access_events",
        }
    ]


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


def test_officer_headline_does_not_claim_destination_received_data() -> None:
    headline = CaseAggregator._headline(
        Verdict.MALICIOUS,
        [],
        Platform.WINDOWS,
        [{"data_type": "documents", "evidence_level": "observed", "confidence": "strong"}],
        [{"value": "example.invalid"}],
    )
    assert headline == "This sample accessed personal documents and contacted example.invalid."
    assert "sent data" not in headline


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
