from __future__ import annotations

import io
import json
import zipfile
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.artifact_routes import tier_allowed
from umat.api.case_routes import accessible_case, store
from umat.audit import append_audit
from umat.auth.dependencies import Principal, require_roles
from umat.db import get_db
from umat.db.models import (
    AnalysisRun,
    AndroidAnalysisMetadata,
    AndroidCapability,
    AndroidFinding,
    Artifact,
    C2Finding,
    NetworkObservation,
    Platform,
    StaticIOC,
)
from umat.storage.local import DigestMismatchError

router = APIRouter(prefix="/api/v1/analysis-runs", tags=["android-workflow"])

_REPORT_MEMBERS = {
    "static": "evidence/mobsf_static_report.json",
    "dynamic": "evidence/mobsf_dynamic_report.json",
}
_EVIDENCE_MEMBERS = {
    "screenshot": ("evidence/screenshot.png", "image/png"),
    "logcat": ("evidence/logcat.txt", "text/plain; charset=utf-8"),
    "frida-logs": ("evidence/frida_logs.json", "application/json"),
}
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_INLINE_EVIDENCE_BYTES = 4 * 1024 * 1024


async def _android_run(
    db: AsyncSession, principal: Principal, run_id: UUID
) -> AnalysisRun:
    run = await db.get(AnalysisRun, run_id)
    if not run or run.platform != Platform.ANDROID:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android analysis run not found")
    await accessible_case(db, principal, run.case_id)
    return run


async def _bundle(db: AsyncSession, run_id: UUID) -> Artifact | None:
    result: Artifact | None = await db.scalar(
        select(Artifact)
        .where(Artifact.analysis_run_id == run_id, Artifact.kind == "android_bundle")
        .order_by(Artifact.created_at.desc())
        .limit(1)
    )
    return result


def _read_member(artifact: Artifact, member: str, maximum: int) -> bytes:
    try:
        archive = store().verify(artifact.object_key, artifact.sha256)
    except DigestMismatchError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Android evidence integrity verification failed"
        ) from exc
    try:
        with zipfile.ZipFile(archive) as bundle:
            info = bundle.getinfo(member)
            if info.file_size > maximum:
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    "Android evidence item is too large for inline viewing",
                )
            return bundle.read(info)
    except (KeyError, zipfile.BadZipFile) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android evidence item not found") from exc


def _report(artifact: Artifact | None, kind: str) -> dict[str, Any] | None:
    if artifact is None:
        return None
    try:
        value = json.loads(_read_member(artifact, _REPORT_MEMBERS[kind], _MAX_REPORT_BYTES))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Registered Android report is not valid JSON"
        ) from exc
    return value if isinstance(value, dict) else None


def _artifact_row(item: Artifact) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "kind": item.kind,
        "sha256": item.sha256,
        "size_bytes": item.size_bytes,
        "media_type": item.media_type,
        "access_tier": item.access_tier.value,
        "download_path": f"/api/v1/artifacts/{item.id}",
    }


@router.get("/{run_id}/android-workflow")
async def android_workflow(
    run_id: UUID,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    run = await _android_run(db, principal, run_id)
    bundle = await _bundle(db, run.id)
    metadata = await db.scalar(
        select(AndroidAnalysisMetadata).where(AndroidAnalysisMetadata.analysis_run_id == run.id)
    )
    findings = list(
        (await db.scalars(select(AndroidFinding).where(AndroidFinding.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    capabilities = list(
        (await db.scalars(select(AndroidCapability).where(AndroidCapability.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    iocs = list(
        (await db.scalars(select(StaticIOC).where(StaticIOC.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    observations = list(
        (
            await db.scalars(
                select(NetworkObservation).where(NetworkObservation.analysis_run_id == run.id)
            )
        )
        .unique()
        .all()
    )
    c2_findings = list(
        (await db.scalars(select(C2Finding).where(C2Finding.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    artifacts = list(
        (await db.scalars(select(Artifact).where(Artifact.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    return {
        "schema_version": "1.0",
        "run": {
            "id": str(run.id),
            "case_id": str(run.case_id),
            "status": run.status.value,
            "result": run.result.value if run.result else None,
            "network_mode": run.network_mode,
            "c2_analysis_enabled": run.c2_analysis_enabled,
            "profile": run.android_configuration.profile_snapshot
            if run.android_configuration
            else None,
            "stages": [
                {
                    "stage_type": item.stage_type.value,
                    "state": item.state.value,
                    "failure_code": item.failure_code,
                    "failure_detail": item.failure_detail,
                }
                for item in run.stages
            ],
        },
        "metadata": (
            {
                "package_name": metadata.package_name,
                "app_name": metadata.app_name,
                "version_name": metadata.version_name,
                "version_code": metadata.version_code,
                "scan_hash": metadata.scan_hash,
                "api_level": metadata.api_level,
                "avd_name": metadata.avd_name,
                "guest_ip": metadata.guest_ip,
                "dynamic_completed": metadata.dynamic_completed,
                "stimulation": metadata.stimulation,
                "details": metadata.details,
            }
            if metadata
            else None
        ),
        "mobsf": {"static": _report(bundle, "static"), "dynamic": _report(bundle, "dynamic")},
        "findings": [
            {
                "phase": item.phase,
                "category": item.category,
                "kind": item.kind,
                "severity": item.severity,
                "confidence": item.confidence,
                "evidence_level": item.evidence_level,
                "summary": item.summary,
                "details": item.details,
            }
            for item in findings
        ],
        "capabilities": [
            {
                "data_type": item.data_type,
                "evidence_level": item.evidence_level,
                "confidence": item.confidence,
                "source": item.source,
                "details": item.details,
            }
            for item in capabilities
        ],
        "iocs": [
            {
                "type": item.ioc_type,
                "value": item.value,
                "confidence": item.confidence,
                "source": item.source,
                "seen_in_traffic": item.seen_in_traffic,
            }
            for item in iocs
        ],
        "network_observations": [
            {
                "destination_ip": item.destination_ip,
                "destination_port": item.destination_port,
                "destination_domain": item.destination_domain,
                "protocol": item.protocol,
                "observed_at": item.observed_at,
                "details": item.details,
            }
            for item in observations
        ],
        "c2_findings": [
            {
                "kind": item.finding_kind,
                "summary": item.plain_language,
                "confidence": item.confidence,
                "capped_by_caveat": item.capped_by_caveat,
                "details": item.details,
            }
            for item in c2_findings
        ],
        "artifacts": [_artifact_row(item) for item in artifacts if tier_allowed(principal, item.access_tier)],
        "inline_evidence": {
            name: f"/api/v1/analysis-runs/{run.id}/android-evidence/{name}"
            for name, (member, _) in _EVIDENCE_MEMBERS.items()
            if bundle is not None and _member_exists(bundle, member)
        },
    }


def _member_exists(artifact: Artifact, member: str) -> bool:
    try:
        archive = store().verify(artifact.object_key, artifact.sha256)
        with zipfile.ZipFile(archive) as bundle:
            return member in bundle.namelist()
    except (DigestMismatchError, zipfile.BadZipFile):
        return False


@router.get("/{run_id}/android-evidence/{evidence_name}")
async def android_inline_evidence(
    run_id: UUID,
    evidence_name: str,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    run = await _android_run(db, principal, run_id)
    descriptor = _EVIDENCE_MEMBERS.get(evidence_name)
    if descriptor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android evidence item not found")
    artifact = await _bundle(db, run.id)
    if artifact is None or not tier_allowed(principal, artifact.access_tier):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android evidence item not found")
    member, media_type = descriptor
    payload = _read_member(artifact, member, _MAX_INLINE_EVIDENCE_BYTES)
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="android_evidence.viewed",
        target_type="analysis_run",
        target_id=str(run.id),
        payload={"evidence_name": evidence_name, "artifact_id": str(artifact.id)},
    )
    await db.commit()
    return Response(
        io.BytesIO(payload).read(),
        media_type=media_type,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )
