from __future__ import annotations

import csv
import json
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from umat.audit import append_audit
from umat.c2.bundle import C2BundleError, safe_extract_bundle, verify_result_bundle
from umat.db.models import (
    AdaptationRecord,
    AnalysisAttempt,
    AnalysisRun,
    AnalysisStage,
    Artifact,
    AttributionResult,
    BundleImport,
    C2Finding,
    Executor,
    ExfilEvent,
    NetworkObservation,
    Platform,
    ProvenanceLink,
    StageState,
    StageType,
    StaticIOC,
    Submission,
    TimelineEvent,
    utcnow,
)
from umat.storage.local import LocalArtifactStore


class C2AdaptationError(C2BundleError):
    pass


def _json_array(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise C2AdaptationError(f"invalid adapter input {path.name}") from exc
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise C2AdaptationError(f"{path.name} must contain an array of objects")
    return cast(list[dict[str, Any]], value)


def _timestamp(value: Any, *, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise C2AdaptationError(f"invalid {field} timestamp") from exc
    if parsed.tzinfo is None:
        raise C2AdaptationError(f"{field} timestamp must be timezone-aware")
    return parsed


class C2Adapter:
    def __init__(self, artifact_store: LocalArtifactStore) -> None:
        self.artifact_store = artifact_store

    async def adapt_run(self, db: AsyncSession, run_id: UUID) -> AdaptationRecord:
        run = await db.get(AnalysisRun, run_id)
        if not run:
            raise C2AdaptationError("analysis run not found")
        stage = await db.scalar(
            select(AnalysisStage)
            .where(
                AnalysisStage.analysis_run_id == run.id,
                AnalysisStage.stage_type == StageType.C2_ADAPTATION,
            )
            .with_for_update()
        )
        if not stage or stage.state not in {
            StageState.QUEUED,
            StageState.RUNNING,
            StageState.COMPLETED,
        }:
            raise C2AdaptationError("C2 adaptation stage is not ready")
        source = await db.scalar(
            select(Artifact)
            .join(AnalysisStage, Artifact.stage_id == AnalysisStage.id)
            .where(
                Artifact.analysis_run_id == run.id,
                Artifact.kind == "c2_bundle",
                AnalysisStage.stage_type == StageType.C2_ANALYSIS,
                AnalysisStage.state.in_([StageState.COMPLETED, StageState.PARTIAL]),
            )
            .order_by(Artifact.created_at.desc())
            .limit(1)
        )
        if not source or not source.attempt_id:
            raise C2AdaptationError("run has no completed C2 result bundle")
        attempt = await db.get(AnalysisAttempt, source.attempt_id)
        executor = await db.get(Executor, attempt.executor_id) if attempt else None
        if not executor:
            raise C2AdaptationError("C2 result producer identity is unavailable")
        archive = self.artifact_store.verify(source.object_key, source.sha256)
        submission = await db.get(Submission, run.submission_id)
        if not submission:
            raise C2AdaptationError("analysis run has no submission")

        stage.state = StageState.RUNNING
        await db.flush()
        with tempfile.TemporaryDirectory(prefix=f"umat-c2-adapt-{run.id}-") as temporary:
            root = safe_extract_bundle(archive, Path(temporary) / "bundle")
            manifest = verify_result_bundle(
                root, Ed25519PublicKey.from_public_bytes(executor.public_key)
            )
            self._check_identity(manifest, run, submission.sample_sha256, executor)
            adaptation = await self._persist(db, run, stage, source, root, manifest)

        db.add(
            BundleImport(
                analysis_run_id=run.id,
                stage_id=stage.id,
                artifact_id=source.id,
                bundle_sha256=source.sha256,
                schema_version=str(manifest["schema_version"]),
                validation_result={
                    "valid": True,
                    "native_event_schema_version": manifest["native_event_schema_version"],
                    "executor_id": str(executor.id),
                },
            )
        )
        stage.state = StageState.COMPLETED
        stage.updated_at = utcnow()
        await append_audit(
            db,
            actor_type="system",
            actor_id="c2-adapter",
            action="c2_bundle.adapted",
            target_type="adaptation",
            target_id=str(adaptation.id),
            payload={"run_id": str(run.id), "source_artifact_id": str(source.id)},
        )
        await db.commit()
        return adaptation

    @staticmethod
    def _check_identity(
        manifest: dict[str, Any], run: AnalysisRun, sample_sha256: str, executor: Executor
    ) -> None:
        if manifest["analysis_run_id"] != str(run.id):
            raise C2AdaptationError("C2 result run identity mismatch")
        if manifest["sample_sha256"] != sample_sha256:
            raise C2AdaptationError("C2 result sample identity mismatch")
        if manifest["platform"] != run.platform.value:
            raise C2AdaptationError("C2 result platform identity mismatch")
        if manifest["signature"].get("key_id") != str(executor.id):
            raise C2AdaptationError("C2 result signing-key identity mismatch")
        if run.platform == Platform.ANDROID and any(
            event.get("data_type_accessed") or event.get("access_api_call")
            for event in manifest["network_events"]
        ):
            raise C2AdaptationError("Android C2 results must remain network-only")

    async def _persist(
        self,
        db: AsyncSession,
        run: AnalysisRun,
        stage: AnalysisStage,
        source: Artifact,
        root: Path,
        manifest: dict[str, Any],
    ) -> AdaptationRecord:
        await db.execute(
            update(AdaptationRecord)
            .where(
                AdaptationRecord.analysis_run_id == run.id,
                AdaptationRecord.adapter_type == "c2",
                AdaptationRecord.active.is_(True),
            )
            .values(active=False)
        )
        adaptation = AdaptationRecord(
            analysis_run_id=run.id,
            stage_id=stage.id,
            source_artifact_id=source.id,
            adapter_type="c2",
            schema_version=str(manifest["native_event_schema_version"]),
            active=True,
            validation_summary={
                "event_count": len(manifest["network_events"]),
                "correlation_mode": manifest["correlation_mode"],
                "caveats": manifest["caveats"],
            },
        )
        db.add(adaptation)
        await db.flush()
        for event in manifest["network_events"]:
            event_id = str(event["event_id"])
            db.add(
                C2Finding(
                    adaptation_id=adaptation.id,
                    analysis_run_id=run.id,
                    stage_id=stage.id,
                    source_event_id=event_id,
                    finding_kind=str(event["finding_kind"]),
                    plain_language=str(event["plain_language"]),
                    confidence=str(event["confidence_tier"]),
                    capped_by_caveat=event.get("capped_by_caveat"),
                    platform=run.platform,
                    details=event,
                )
            )
            db.add(
                NetworkObservation(
                    adaptation_id=adaptation.id,
                    analysis_run_id=run.id,
                    source_event_id=event_id,
                    destination_ip=event.get("destination_ip"),
                    destination_port=event.get("destination_port"),
                    destination_domain=event.get("destination_domain"),
                    protocol=C2Adapter._protocol(event),
                    observed_at=_timestamp(event["timestamp"], field="network event"),
                    details=event,
                )
            )
            if event["finding_kind"] in {"exfil", "correlation"}:
                db.add(
                    ExfilEvent(
                        adaptation_id=adaptation.id,
                        analysis_run_id=run.id,
                        source_event_id=event_id,
                        data_type_accessed=event.get("data_type_accessed"),
                        access_api_call=event.get("access_api_call"),
                        destination=event.get("destination_domain") or event.get("destination_ip"),
                        confidence=str(event["confidence_tier"]),
                        evidence_hash=str(event["evidence_hash"]),
                        details=event,
                    )
                )
        self._persist_iocs(db, adaptation.id, run.id, root / "iocs/iocs.csv")
        self._persist_provenance(db, adaptation.id, run.id, root / "provenance.json")
        self._persist_timeline(db, adaptation.id, run.id, root / "timeline.json")
        self._persist_attribution(db, adaptation.id, run.id, root / "attribution.json")
        return adaptation

    @staticmethod
    def _protocol(event: dict[str, Any]) -> str | None:
        if event.get("destination_port") == 53 or event.get("finding_kind") == "dns":
            return "dns"
        if event.get("destination_port") is not None:
            return "tcp"
        return None

    @staticmethod
    def _persist_iocs(db: AsyncSession, adaptation_id: UUID, run_id: UUID, path: Path) -> None:
        with path.open(newline="") as source:
            for row in csv.DictReader(source):
                if not row.get("value"):
                    continue
                db.add(
                    StaticIOC(
                        adaptation_id=adaptation_id,
                        analysis_run_id=run_id,
                        ioc_type=row.get("type") or "unknown",
                        value=row["value"],
                        confidence=row.get("confidence") or "unconfirmed",
                        source="c2-runtime",
                        seen_in_traffic=bool(row.get("source_event_id")),
                        first_seen_at=None,
                    )
                )

    @staticmethod
    def _persist_provenance(
        db: AsyncSession, adaptation_id: UUID, run_id: UUID, path: Path
    ) -> None:
        for item in _json_array(path):
            db.add(
                ProvenanceLink(
                    adaptation_id=adaptation_id,
                    analysis_run_id=run_id,
                    source_event_id=item.get("source_event_id") or item.get("event_id"),
                    item_type=item.get("item_type") or item.get("data_type"),
                    destination=item.get("destination"),
                    statement=str(
                        item.get("statement") or item.get("description") or "C2 provenance"
                    ),
                    details=item,
                )
            )

    @staticmethod
    def _persist_timeline(db: AsyncSession, adaptation_id: UUID, run_id: UUID, path: Path) -> None:
        for item in _json_array(path):
            when = item.get("occurred_at") or item.get("timestamp")
            if not when:
                continue
            db.add(
                TimelineEvent(
                    adaptation_id=adaptation_id,
                    analysis_run_id=run_id,
                    occurred_at=_timestamp(when, field="timeline"),
                    actor=str(item.get("actor") or "network"),
                    description=str(item.get("description") or item.get("event") or "C2 event"),
                    mitre_technique_id=item.get("mitre_technique_id"),
                    details=item,
                )
            )

    @staticmethod
    def _persist_attribution(
        db: AsyncSession, adaptation_id: UUID, run_id: UUID, path: Path
    ) -> None:
        for item in _json_array(path):
            family = item.get("family") or item.get("malware_family")
            if not family:
                continue
            db.add(
                AttributionResult(
                    adaptation_id=adaptation_id,
                    analysis_run_id=run_id,
                    family=str(family),
                    confidence=str(item.get("confidence") or "unconfirmed"),
                    basis=str(item.get("basis") or "network"),
                    details=item,
                )
            )
