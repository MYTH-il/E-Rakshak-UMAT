from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

CONTRACT_ROOT = Path(__file__).parents[3] / "contracts"


class ContractError(ValueError):
    pass


def load_schema(relative_path: str) -> dict[str, Any]:
    path = (CONTRACT_ROOT / relative_path).resolve()
    if CONTRACT_ROOT.resolve() not in path.parents:
        raise ContractError("contract path escapes the contract root")
    return cast(dict[str, Any], json.loads(path.read_text()))


def schema_registry() -> Registry:
    resources: list[tuple[str, Resource]] = []
    for path in CONTRACT_ROOT.rglob("*.schema.json"):
        schema = json.loads(path.read_text())
        if schema_id := schema.get("$id"):
            resources.append((schema_id, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def validate_contract(relative_path: str, document: Any) -> None:
    schema = load_schema(relative_path)
    errors = sorted(
        Draft202012Validator(
            schema, registry=schema_registry(), format_checker=FormatChecker()
        ).iter_errors(document),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise ContractError(f"{relative_path}:{location}: {first.message}")
    if relative_path == "c2/c2-result.schema.json":
        _validate_c2_identity(document)


def _validate_c2_identity(document: dict[str, Any]) -> None:
    run_id = document["analysis_run_id"]
    sample_sha256 = document["sample_sha256"]
    platform = document["platform"]
    for index, event in enumerate(document["network_events"]):
        if event["case_id"] != run_id:
            raise ContractError(f"C2 event {index} case_id does not equal analysis_run_id")
        if event["sample_id"] != sample_sha256:
            raise ContractError(f"C2 event {index} sample_id does not equal sample_sha256")
        if event["platform"] != platform:
            raise ContractError(f"C2 event {index} platform does not equal result platform")
        if platform == "android" and event.get("data_type_accessed") is not None:
            raise ContractError(
                "Android network-only C2 events cannot assert an accessed data item"
            )


def validate_pinned_native_schema(
    *, document: Any, schema_path: Path, expected_sha256: str
) -> None:
    raw = schema_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ContractError("native schema digest does not match dependency lock")
    schema = json.loads(raw)
    errors = list(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(document)
    )
    if errors:
        raise ContractError(f"native contract validation failed: {errors[0].message}")
