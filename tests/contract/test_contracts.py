import json
from pathlib import Path

import pytest

from umat.contracts import ContractError, validate_contract

ROOT = Path(__file__).parents[2]
PAIRS = [
    ("case-object.schema.json", "case-object.json"),
    ("windows/windows-import.schema.json", "windows-import.json"),
    ("android/android-bundle.schema.json", "android-bundle.json"),
    ("c2/c2-input.schema.json", "c2-input.json"),
    ("c2/c2-result.schema.json", "c2-result.json"),
]


@pytest.mark.parametrize(("schema_name", "fixture_name"), PAIRS)
def test_sanitized_fixture_validates(schema_name: str, fixture_name: str) -> None:
    fixture = json.loads((ROOT / "tests/fixtures" / fixture_name).read_text())
    validate_contract(schema_name, fixture)


@pytest.mark.parametrize(("schema_name", "fixture_name"), PAIRS)
def test_unknown_major_version_fails_closed(schema_name: str, fixture_name: str) -> None:
    fixture = json.loads((ROOT / "tests/fixtures" / fixture_name).read_text())
    fixture["schema_version"] = "2.0"
    with pytest.raises(ContractError):
        validate_contract(schema_name, fixture)


def test_vocabularies_are_unique() -> None:
    for path in (ROOT / "contracts/vocabularies").glob("*.json"):
        value = json.loads(path.read_text())
        for key, entries in value.items():
            if isinstance(entries, list):
                assert len(entries) == len(set(entries)), f"duplicates in {path}:{key}"


def test_executor_contract_covers_internal_routes() -> None:
    from umat.api.app import app

    contract = json.loads((ROOT / "contracts/executor-api.openapi.yaml").read_text())
    expected = {
        "/executors/register", "/executors/capabilities", "/executors/claim",
        "/executors/windows/profile-operations/claim",
        "/executors/windows/profile-operations/{operation_id}/complete",
        "/stages/{stage_id}/sample",
        "/stages/{stage_id}/inputs/{artifact_id}",
        "/stages/{stage_id}/heartbeat", "/stages/{stage_id}/native-task",
        "/stages/{stage_id}/windows-session/ready",
        "/stages/{stage_id}/windows-session/poll",
        "/stages/{stage_id}/android-session/ready",
        "/stages/{stage_id}/android-session/poll",
        "/stages/{stage_id}/android-session/complete-command",
        "/stages/{stage_id}/artifacts", "/stages/{stage_id}/complete",
        "/stages/{stage_id}/fail", "/stages/{stage_id}/cancellation-ack",
    }
    assert set(contract["paths"]) == expected
    implemented = {
        path.removeprefix("/api/internal/v1")
        for path in app.openapi()["paths"]
        if path.startswith("/api/internal/v1")
    }
    assert implemented == expected


def test_executor_heartbeat_contract_exposes_stop_request() -> None:
    contract = json.loads((ROOT / "contracts/executor-api.openapi.yaml").read_text())
    response = contract["components"]["schemas"]["HeartbeatResponse"]
    assert response["required"] == ["lease_expires_at", "stop_requested"]
    assert set(response["properties"]["stop_requested"]["enum"]) == {
        None,
        "cancelled",
        "timeout",
    }


def test_executor_mutation_contracts_have_exact_bodies_and_signed_headers() -> None:
    from umat.api.executor_schemas import (
        ArtifactEnvelope,
        CancellationAckRequest,
        CapabilityRequest,
        ClaimRequest,
        CompleteRequest,
        FailRequest,
        HeartbeatRequest,
        NativeTaskRequest,
        RegisterExecutorRequest,
        WindowsProfileOperationCompleteRequest,
    )

    contract = json.loads((ROOT / "contracts/executor-api.openapi.yaml").read_text())
    models = {
        "RegisterExecutorRequest": RegisterExecutorRequest,
        "CapabilityRequest": CapabilityRequest,
        "ClaimRequest": ClaimRequest,
        "HeartbeatRequest": HeartbeatRequest,
        "NativeTaskRequest": NativeTaskRequest,
        "ArtifactEnvelope": ArtifactEnvelope,
        "CompleteRequest": CompleteRequest,
        "FailRequest": FailRequest,
        "CancellationAckRequest": CancellationAckRequest,
        "WindowsProfileOperationCompleteRequest": WindowsProfileOperationCompleteRequest,
    }
    for name, model in models.items():
        assert set(contract["components"]["schemas"][name].get("required", [])) == set(
            model.model_json_schema().get("required", [])
        )
    signed_stage_mutations = {
        "/stages/{stage_id}/heartbeat",
        "/stages/{stage_id}/native-task",
        "/stages/{stage_id}/artifacts",
        "/stages/{stage_id}/complete",
        "/stages/{stage_id}/fail",
        "/stages/{stage_id}/cancellation-ack",
    }
    expected_headers = {
        "X-UMAT-Timestamp",
        "X-UMAT-Nonce",
        "Idempotency-Key",
        "X-UMAT-Signature",
        "X-UMAT-Lease-Token",
    }
    parameters = contract["components"]["parameters"]
    for path in signed_stage_mutations:
        operation = contract["paths"][path]["post"]
        assert "$ref" not in operation
        names = {
            parameters[item["$ref"].rsplit("/", 1)[1]]["name"]
            for item in operation["parameters"]
            if item.get("$ref", "").startswith("#/components/parameters/")
        }
        assert expected_headers <= names
        assert operation["requestBody"]["required"] is True


def test_c2_v13_identity_mismatch_fails() -> None:
    fixture = json.loads((ROOT / "tests/fixtures/c2-result.json").read_text())
    fixture["network_events"][0]["case_id"] = "0198fd40-1111-7000-8000-000000000099"
    with pytest.raises(ContractError, match="case_id"):
        validate_contract("c2/c2-result.schema.json", fixture)


def test_native_contract_catalog_is_pinned() -> None:
    catalog = json.loads((ROOT / "contracts/native-contract-sources.json").read_text())
    c2_lock = json.loads((ROOT / "dependency-locks/c2-exfil.json").read_text())
    c2_contract = catalog["contracts"]["c2_events"]
    assert c2_contract["native_schema_version"] == "1.3"
    assert c2_contract["repository"] == c2_lock["schema_reference"]["repository"]
    assert c2_contract["commit"] == c2_lock["schema_reference"]["commit"]
    assert c2_contract["path"] == c2_lock["schema_reference"]["path"]
    assert c2_contract["sha256"] == c2_lock["schema_reference"]["sha256"]
    for contract in catalog["contracts"].values():
        assert len(contract["commit"]) == 40
