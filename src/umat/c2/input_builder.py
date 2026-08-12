from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from umat.c2.models import C2AnalysisContext, InputArtifact
from umat.contracts import ContractError, validate_contract


class C2InputError(ContractError):
    pass


class C2InputBuilder:
    REQUIRED_KINDS = {"pcap", "platform_manifest"}

    def build(
        self,
        *,
        analysis_run_id: UUID,
        platform: str,
        sample_sha256: str,
        artifacts: list[InputArtifact],
    ) -> C2AnalysisContext:
        by_kind: dict[str, InputArtifact] = {}
        for artifact in artifacts:
            if artifact.kind in by_kind:
                raise C2InputError(f"multiple {artifact.kind!r} artifacts supplied")
            by_kind[artifact.kind] = artifact
        missing = self.REQUIRED_KINDS - set(by_kind)
        if missing:
            raise C2InputError(f"missing required C2 input artifacts: {sorted(missing)}")
        manifest = self._load_json(by_kind["platform_manifest"].local_path)
        started, ended = self._analysis_window(platform, manifest)
        guest_ip = self._guest_ip(platform, manifest)
        access_events = by_kind.get("access_events")
        correlation_eligible = self._correlation_eligible(platform, manifest, access_events)
        caveats = list(manifest.get("caveats") or [])
        if platform == "android":
            correlation_eligible = False
            access_events = None
            if "c2_network_only" not in caveats:
                caveats.append("c2_network_only")
        context = C2AnalysisContext(
            analysis_run_id=analysis_run_id,
            platform=platform,
            sample_sha256=sample_sha256,
            pcap=by_kind["pcap"],
            platform_manifest=by_kind["platform_manifest"],
            access_events=access_events,
            etw_events=by_kind.get("etw_events"),
            static_prior=by_kind.get("static_prior"),
            network_activity=by_kind.get("network_activity"),
            analysis_started_at=started,
            analysis_ended_at=ended,
            guest_ip=guest_ip,
            correlation_eligible=correlation_eligible,
            caveats=caveats,
        )
        validate_contract("c2/c2-input.schema.json", context.contract_document())
        return context

    @staticmethod
    def _load_json(path: Path) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise C2InputError("platform manifest is not valid JSON") from exc
        if not isinstance(value, dict):
            raise C2InputError("platform manifest must be a JSON object")
        return value

    @staticmethod
    def _analysis_window(platform: str, manifest: dict[str, Any]) -> tuple[datetime, datetime]:
        if platform == "android":
            window = manifest.get("analysis_window") or {}
            start_raw, end_raw = window.get("started_at"), window.get("ended_at")
        else:
            native = manifest.get("handoff_manifest") or manifest
            start_raw = native.get("detonation_start_utc")
            end_raw = native.get("detonation_end_utc")
        if not start_raw or not end_raw:
            raise C2InputError("platform manifest has no complete analysis window")
        try:
            started = datetime.fromisoformat(str(start_raw).replace("Z", "+00:00"))
            ended = datetime.fromisoformat(str(end_raw).replace("Z", "+00:00"))
        except ValueError as exc:
            raise C2InputError("analysis window timestamps are invalid") from exc
        if started.tzinfo is None or ended.tzinfo is None or ended < started:
            raise C2InputError("analysis window must be timezone-aware and ordered")
        return started, ended

    @staticmethod
    def _guest_ip(platform: str, manifest: dict[str, Any]) -> str | None:
        if platform == "android":
            return (manifest.get("emulator") or {}).get("guest_ip")
        native = manifest.get("handoff_manifest") or manifest
        return (native.get("guest_vm_identity") or {}).get("guest_ip")

    @staticmethod
    def _correlation_eligible(
        platform: str, manifest: dict[str, Any], access_events: InputArtifact | None
    ) -> bool:
        if platform != "windows" or not access_events:
            return False
        native = manifest.get("handoff_manifest") or manifest
        correlation = native.get("correlation") or {}
        return bool(correlation.get("host_network_correlation_enabled", False))
