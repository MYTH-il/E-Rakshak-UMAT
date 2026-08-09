from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from umat.audit import append_audit
from umat.db.models import (
    AdaptationRecord,
    AnalysisAttempt,
    AnalysisRun,
    AnalysisStage,
    Artifact,
    BundleImport,
    Executor,
    Platform,
    StageState,
    StageType,
    StaticIOC,
    Submission,
    WindowsAnalysisMetadata,
    WindowsCapability,
    WindowsFinding,
    WindowsRunConfiguration,
    utcnow,
)
from umat.storage import LocalArtifactStore
from umat.windows.bundle import (
    NativeWindowsValidator,
    WindowsBundleError,
    safe_extract_windows_bundle,
    verify_windows_bundle,
)


class WindowsAdaptationError(WindowsBundleError):
    pass


def _object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


class WindowsAdapter:
    def __init__(self, artifact_store: LocalArtifactStore, schema_root: Path, max_bundle_bytes: int) -> None:
        self.artifact_store = artifact_store
        self.native_validator = NativeWindowsValidator(schema_root)
        self.max_bundle_bytes = max_bundle_bytes

    async def adapt_run(self, db: AsyncSession, run_id: UUID) -> AdaptationRecord:
        run = await db.get(AnalysisRun, run_id)
        if not run or run.platform != Platform.WINDOWS:
            raise WindowsAdaptationError("Windows analysis run not found")
        stage = await db.scalar(select(AnalysisStage).where(AnalysisStage.analysis_run_id == run.id, AnalysisStage.stage_type == StageType.PLATFORM_ADAPTATION).with_for_update())
        if not stage or stage.state not in {StageState.QUEUED, StageState.RUNNING, StageState.COMPLETED}:
            raise WindowsAdaptationError("Windows adaptation stage is not ready")
        artifact = await db.scalar(select(Artifact).join(AnalysisStage, Artifact.stage_id == AnalysisStage.id).where(Artifact.analysis_run_id == run.id, Artifact.kind == "windows_bundle", AnalysisStage.stage_type == StageType.PLATFORM_ANALYSIS, AnalysisStage.state.in_([StageState.COMPLETED, StageState.PARTIAL])).order_by(Artifact.created_at.desc()).limit(1))
        if not artifact or not artifact.attempt_id:
            raise WindowsAdaptationError("run has no completed Windows bundle")
        attempt = await db.get(AnalysisAttempt, artifact.attempt_id)
        executor = await db.get(Executor, attempt.executor_id) if attempt else None
        submission = await db.get(Submission, run.submission_id)
        if not executor or not submission:
            raise WindowsAdaptationError("Windows bundle producer identity is unavailable")
        archive = self.artifact_store.verify(artifact.object_key, artifact.sha256)
        stage.state = StageState.RUNNING
        with tempfile.TemporaryDirectory(prefix=f"umat-windows-adapt-{run.id}-") as temporary:
            root = safe_extract_windows_bundle(archive, Path(temporary) / "bundle", self.max_bundle_bytes)
            manifest = verify_windows_bundle(root, Ed25519PublicKey.from_public_bytes(executor.public_key), self.native_validator)
            configuration = await db.get(WindowsRunConfiguration, run.id)
            self._identity(manifest, run, submission.sample_sha256, executor, configuration)
            adaptation = await self._persist(db, run, stage, artifact, root, manifest)
        db.add(BundleImport(analysis_run_id=run.id, stage_id=stage.id, artifact_id=artifact.id, bundle_sha256=artifact.sha256, schema_version=str(manifest["schema_version"]), validation_result={"valid": True, "executor_id": str(executor.id), "native_commit": manifest["producer"]["commit"]}))
        stage.state = StageState.COMPLETED
        stage.updated_at = utcnow()
        await append_audit(db, actor_type="system", actor_id="windows-adapter", action="windows_bundle.adapted", target_type="adaptation", target_id=str(adaptation.id), payload={"run_id": str(run.id), "source_artifact_id": str(artifact.id)})
        await db.commit()
        return adaptation

    @staticmethod
    def _identity(manifest: dict[str, Any], run: AnalysisRun, sample_sha256: str, executor: Executor, configuration: WindowsRunConfiguration | None) -> None:
        if manifest["analysis_run_id"] != str(run.id) or manifest["sample_sha256"] != sample_sha256:
            raise WindowsAdaptationError("Windows bundle run/sample identity mismatch")
        if manifest["signature"]["key_id"] != str(executor.id):
            raise WindowsAdaptationError("Windows bundle signing-key identity mismatch")
        if manifest["selected_profile"] != (configuration.profile_snapshot if configuration else {}):
            raise WindowsAdaptationError("Windows VM profile snapshot mismatch")

    async def _persist(self, db: AsyncSession, run: AnalysisRun, stage: AnalysisStage, artifact: Artifact, root: Path, manifest: dict[str, Any]) -> AdaptationRecord:
        await db.execute(update(AdaptationRecord).where(AdaptationRecord.analysis_run_id == run.id, AdaptationRecord.adapter_type == "windows", AdaptationRecord.active.is_(True)).values(active=False))
        native = root / "native"
        report, sample_meta, handoff = _object(native / "report.json"), _object(native / "sample.meta.json"), manifest["handoff_manifest"]
        adaptation = AdaptationRecord(analysis_run_id=run.id, stage_id=stage.id, source_artifact_id=artifact.id, adapter_type="windows", schema_version="1.0", active=True, validation_summary={"cape_task_id": manifest["cape"]["task_id"], "caveats": manifest["caveats"]})
        db.add(adaptation)
        await db.flush()
        db.add(WindowsAnalysisMetadata(adaptation_id=adaptation.id, analysis_run_id=run.id, cape_task_id=manifest["cape"]["task_id"], cape_package=manifest["cape"]["package"], detected_type=manifest["cape"]["detected_type"], machine_label=manifest["selected_profile"].get("cape_machine_label"), profile_snapshot=manifest["selected_profile"], network_mode=handoff.get("network_mode"), telemetry_degraded=bool((handoff.get("telemetry") or {}).get("telemetry_degraded")), details={"handoff": handoff, "report_info": report.get("info", {})}))
        self._findings(db, adaptation.id, run.id, report, sample_meta)
        self._capabilities(db, adaptation.id, run.id, native)
        self._iocs(db, adaptation.id, run.id, native, sample_meta)
        return adaptation

    @staticmethod
    def _findings(db: AsyncSession, adaptation_id: UUID, run_id: UUID, report: dict[str, Any], sample_meta: dict[str, Any]) -> None:
        signatures = report.get("signatures", [])
        for signature in signatures if isinstance(signatures, list) else []:
            if isinstance(signature, dict):
                db.add(WindowsFinding(adaptation_id=adaptation_id, analysis_run_id=run_id, category=str(signature.get("category") or "cape_signature"), kind=str(signature.get("name") or "unknown"), confidence="strong" if (signature.get("severity") or 0) >= 3 else "weak", summary=str(signature.get("description") or signature.get("name") or "CAPE signature"), details=signature))
        for hypothesis in sample_meta.get("static_hypotheses", []):
            db.add(WindowsFinding(adaptation_id=adaptation_id, analysis_run_id=run_id, category="static", kind="static_hypothesis", confidence="weak", summary=str(hypothesis), details={"source": "sample.meta.json"}))
        yara = sample_meta.get("yara") or {}
        for hit in list(yara.get("fast_hits", [])) + list(yara.get("deep_hits", [])):
            db.add(WindowsFinding(adaptation_id=adaptation_id, analysis_run_id=run_id, category="yara", kind=str(hit), confidence="strong", summary=f"YARA rule matched: {hit}", details={"rule": hit}))

    @staticmethod
    def _capabilities(db: AsyncSession, adaptation_id: UUID, run_id: UUID, native: Path) -> None:
        access = native / "behavior/access_events.json"
        if not access.is_file():
            return
        seen: set[str] = set()
        for event in json.loads(access.read_text()):
            capability = str(event["data_type"])
            if capability not in seen:
                seen.add(capability)
                db.add(WindowsCapability(adaptation_id=adaptation_id, analysis_run_id=run_id, capability=capability, source="access_events", confidence="confirmed", details={"first_event": event}))

    @staticmethod
    def _iocs(db: AsyncSession, adaptation_id: UUID, run_id: UUID, native: Path, sample_meta: dict[str, Any]) -> None:
        prior = _object(native / "analysis/c2-static-prior.json")
        for item in prior.get("iocs") or sample_meta.get("iocs") or []:
            if isinstance(item, dict) and item.get("value"):
                db.add(StaticIOC(adaptation_id=adaptation_id, analysis_run_id=run_id, ioc_type=str(item.get("type") or "unknown"), value=str(item["value"]), confidence=str(item.get("confidence") or "unconfirmed"), source="winstdt", seen_in_traffic=False, first_seen_at=None))
