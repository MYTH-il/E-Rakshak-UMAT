from __future__ import annotations

from pathlib import Path

import httpx

from umat.windows.cape import (
    CapeClient,
    cape_filename_for_package,
    cape_package_for_sample,
    cape_static_prior,
    normalize_cape_evidence,
)


def test_profile_management_uses_separate_authenticated_gateway() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            201,
            json={
                "operation_id": "0198a04b-8a7a-7000-8000-000000000002",
                "machine_label": "umat-office-1234abcd",
            },
        )

    client = CapeClient(
        "http://cape.invalid",
        management_url="http://gateway.invalid",
        management_token="gateway-secret",  # noqa: S106 - non-secret test fixture
    )
    client.management = httpx.Client(
        base_url="http://gateway.invalid", transport=httpx.MockTransport(handler)
    )
    operation, label = client.create_machine({"profile_id": "profile-1"})
    assert (operation, label) == (
        "0198a04b-8a7a-7000-8000-000000000002",
        "umat-office-1234abcd",
    )
    assert requests[0].url == httpx.URL("http://gateway.invalid/api/v1/machines")


def test_cape_status_accepts_native_string_response() -> None:
    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"error": False, "data": "reported"})
        ),
    )
    assert client.status(42) == {"status": "reported"}


def test_task_machine_resolves_cape_assigned_machine() -> None:
    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"data": {"task": {"machine": "winstdt-win10-22h2"}}}
            )
        ),
    )
    assert client.task_machine(42) == "winstdt-win10-22h2"


def test_cape_analysis_timeout_is_never_shorter_than_ten_minutes() -> None:
    assert CapeClient("http://cape.invalid").analysis_timeout_seconds == 600
    assert CapeClient(
        "http://cape.invalid", analysis_timeout_seconds=180
    ).analysis_timeout_seconds == 600
    assert CapeClient(
        "http://cape.invalid", analysis_timeout_seconds=1200
    ).analysis_timeout_seconds == 1200


def test_open_console_uses_authenticated_management_gateway() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/tasks/42/console"
        assert request.headers["authorization"] == "Bearer gateway-secret"
        return httpx.Response(
            200,
            json={
                "console_url": "ws://127.0.0.1:8091/api/v1/console/token",
                "machine_label": "umat-office-1234abcd",
            },
        )

    client = CapeClient(
        "http://cape.invalid",
        management_url="http://gateway.invalid",
        management_token="gateway-secret",  # noqa: S106
    )
    client.management = httpx.Client(
        base_url="http://gateway.invalid",
        headers={"Authorization": "Bearer gateway-secret"},
        transport=httpx.MockTransport(handler),
    )
    assert client.open_console(42, "umat-office-1234abcd")["console_url"].endswith("/token")


def test_finish_uses_task_state_when_cape_returns_contradictory_error(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    responses = iter(
        [
            httpx.Response(
                200,
                json={"error": True, "data": '{"message":"Successfully created directory"}'},
            ),
            httpx.Response(200, json={"data": {"status": "reported"}}),
        ]
    )
    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid",
        transport=httpx.MockTransport(lambda request: next(responses)),
    )
    monkeypatch.setattr("umat.windows.cape.time.sleep", lambda _seconds: None)
    client.cancel(42)


def test_submit_never_uses_original_filename(tmp_path: Path) -> None:
    sample = tmp_path / "attacker-name.exe"
    sample.write_bytes(b"harmless fixture")

    def handler(request: httpx.Request) -> httpx.Response:
        assert b"attacker-name.exe" not in request.content
        assert b'name="file"; filename="sample.bin"' in request.content
        assert b'name="timeout"' in request.content
        assert b"600" in request.content
        assert b'name="enforce_timeout"' in request.content
        return httpx.Response(200, json={"data": {"task_ids": [7]}})

    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid", transport=httpx.MockTransport(handler)
    )
    assert client.submit(sample, {"analysis_profile": "standard"}) == 7


def test_manual_windows_submission_disables_cape_human_automation(tmp_path: Path) -> None:
    sample = tmp_path / "benign.exe"
    sample.write_bytes(b"harmless fixture")

    def handler(request: httpx.Request) -> httpx.Response:
        assert b"nohuman=1" in request.content
        return httpx.Response(200, json={"data": {"task_ids": [9]}})

    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid", transport=httpx.MockTransport(handler)
    )
    assert client.submit(sample, {"windows_interactive": True}) == 9


def test_cape_package_for_native_pe(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    image = bytearray(128)
    image[:2] = b"MZ"
    image[60:64] = (64).to_bytes(4, "little")
    image[64:68] = b"PE\0\0"
    sample.write_bytes(image)
    assert cape_package_for_sample(sample) == "exe"

    image[64 + 22 : 64 + 24] = (0x2000).to_bytes(2, "little")
    sample.write_bytes(image)
    assert cape_package_for_sample(sample) == "dll"

    sample.write_bytes(b"PK\x03\x04not-a-pe")
    assert cape_package_for_sample(sample) == "zip"


def test_lnk_signature_wins_over_embedded_zip_overlay(tmp_path: Path) -> None:
    sample = tmp_path / "misleading.zip"
    sample.write_bytes(
        bytes.fromhex("4c0000000114020000000000c000000000000046")
        + b"payload"
        + b"PK\x03\x04embedded-archive"
    )
    assert cape_package_for_sample(sample) == "lnk"
    assert cape_filename_for_package("lnk") == "sample.lnk"

    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"data": {"task_ids": [8]}})

    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid", transport=httpx.MockTransport(handler)
    )
    assert client.submit(sample, {"analysis_profile": "standard"}) == 8
    assert b'name="package"' in requests[0].content
    assert b"lnk" in requests[0].content
    assert b'filename="sample.lnk"' in requests[0].content


def test_cape_evidence_has_bounded_projections_and_lossless_source() -> None:
    report = {
        "malscore": 10.0,
        "signatures": [{"name": f"signature-{index}"} for index in range(1005)],
        "behavior": {"summary": {"files": ["one"]}, "processes": [{"calls": [1]}]},
        "network": {"hosts": ["198.51.100.1"], "domains": [{"domain": "example.test"}]},
        "suricata": {"alerts": [{"signature": "test alert"}]},
        "dropped": [{"sha256": "a" * 64}],
    }
    evidence = normalize_cape_evidence(report)
    assert evidence["malscore"] == 10.0
    assert len(evidence["signatures"]) == 1000
    assert "processes" not in evidence["behavior"]
    assert evidence["network"]["domains"][0]["domain"] == "example.test"
    assert evidence["raw_report"] == report


def test_cape_configs_produce_redacted_family_neutral_c2_candidates() -> None:
    evidence = normalize_cape_evidence(
        {
            "CAPE": {
                "configs": [
                    {
                        "family": "GenericStealer",
                        "control_url": "https://collector.example.test/gate",
                        "smtp_server": "mail.example.test",
                        "backup_ip": "198.51.100.24",
                        "bot_token": "secret-value",
                    }
                ]
            },
            "detections": [{"family": "GenericStealer"}],
        }
    )
    candidates = {
        (item["type"], item["value"]) for item in evidence["cape"]["config_candidates"]
    }
    assert ("url", "https://collector.example.test/gate") in candidates
    assert ("domain", "collector.example.test") in candidates
    assert ("domain", "mail.example.test") in candidates
    assert ("ip", "198.51.100.24") in candidates
    token = evidence["cape"]["config_records"][0]["values"]["bot_token"]
    assert token["redacted"] is True
    assert token["sha256"] != "secret-value"

    prior = cape_static_prior(evidence, "run-id", "a" * 64)
    assert prior["family"] == "GenericStealer"
    assert {item["source"] for item in prior["configuration_candidates"]} == {"cape_config"}
    assert any(
        item["type"] == "domain" and item["value"] == "collector.example.test"
        for item in prior["iocs"]
    )


def test_static_strings_supply_candidates_when_family_extractor_is_empty() -> None:
    evidence = normalize_cape_evidence(
        {
            "target": {
                "file": {
                    "strings": [
                        "https://api.telegram.org/bot-redacted-fixture/",
                        "noise without an endpoint",
                    ]
                }
            },
            "CAPE": {"configs": [], "payloads": []},
        }
    )
    candidates = evidence["cape"]["static_candidates"]
    assert any(
        item["type"] == "domain" and item["value"] == "api.telegram.org"
        for item in candidates
    )
    assert any("bot<redacted>" in item["value"] for item in candidates if item["type"] == "url")
    assert all("redacted-fixture" not in item["value"] for item in candidates)
    assert {item["source"] for item in candidates} == {"cape_static_string"}


def test_cape_evidence_waits_for_complete_report_document(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    responses = iter(
        [
            httpx.Response(200, json={"behavior": {}, "signatures": []}),
            httpx.Response(
                200,
                json={
                    "info": {"id": 42},
                    "target": {"file": {"sha256": "a" * 64}},
                    "malscore": 10.0,
                    "signatures": [{"name": "agent_tesla"}],
                },
            ),
        ]
    )
    client = CapeClient("http://cape.invalid")
    client.client = httpx.Client(
        base_url="http://cape.invalid",
        transport=httpx.MockTransport(lambda request: next(responses)),
    )
    monkeypatch.setattr("umat.windows.cape.time.sleep", lambda _seconds: None)
    assert client.evidence(42)["malscore"] == 10.0


def test_cape_static_prior_uses_cape_evidence_for_iocs_signatures_and_ttps() -> None:
    prior = cape_static_prior(
        {
            "network": {
                "hosts": ["198.51.100.7"],
                "domains": [{"domain": "C2.EXAMPLE."}],
                "http": [{"uri": "https://c2.example/check-in"}],
            },
            "signatures": [{"name": "beacon", "severity": 3}],
            "ttps": [{"signature": "beacon", "ttps": ["T1071.001", "T1059"]}],
        },
        "run-id",
        "a" * 64,
    )
    assert prior["source"] == "cape-evidence.json"
    assert prior["signatures"] == [{"name": "beacon", "severity": 3}]
    assert prior["ttps"] == [{"signature": "beacon", "ttps": ["T1071.001", "T1059"]}]
    assert prior["capabilities"] == ["T1059", "T1071.001"]
    # Dynamic destinations are observations, never independent static priors.
    assert prior["iocs"] == []
    assert prior["evidence_origin"] == "binary_static"


def test_cape_static_prior_does_not_self_correlate_browser_traffic() -> None:
    prior = cape_static_prior(
        {
            "network": {
                "domains": [
                    {"domain": "amazon.com"},
                    {"domain": "go.microsoft.com"},
                ]
            },
            "cape": {
                "config_candidates": [],
                "static_candidates": [
                    {
                        "type": "domain",
                        "value": "api.telegram.org",
                        "confidence": "strong",
                        "source": "cape_static_string",
                        "provenance": {"source": "cape_report_strings"},
                    }
                ],
            },
        },
        "run-id",
        "a" * 64,
    )
    assert [(item["type"], item["value"]) for item in prior["iocs"]] == [
        ("domain", "api.telegram.org")
    ]
    assert prior["iocs"][0]["evidence_origin"] == "binary_static"
    assert prior["iocs"][0]["source"] == "cape_static_string"
