from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.case_routes import accessible_case, store
from umat.audit import append_audit
from umat.auth.dependencies import Principal, current_principal
from umat.db import get_db
from umat.db.models import AccessTier, AnalysisRun, Artifact
from umat.storage.local import DigestMismatchError

router = APIRouter(prefix="/api/v1", tags=["artifacts"])


def tier_allowed(principal: Principal, tier: AccessTier) -> bool:
    if "administrator" in principal.roles:
        return True
    if "analyst" in principal.roles:
        return tier in {AccessTier.OFFICER, AccessTier.ANALYST}
    return tier == AccessTier.OFFICER


@router.get("/artifacts/{artifact_id}")
async def download_artifact(
    artifact_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    artifact = await db.get(Artifact, artifact_id)
    if not artifact:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not found")
    run = await db.get(AnalysisRun, artifact.analysis_run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not found")
    try:
        await accessible_case(db, principal, run.case_id)
    except HTTPException:
        await append_audit(db, actor_type="user", actor_id=str(principal.user.id), action="artifact.download_denied", target_type="artifact", target_id=str(artifact.id), payload={"reason": "case_access"})
        await db.commit()
        raise
    if not tier_allowed(principal, artifact.access_tier):
        await append_audit(db, actor_type="user", actor_id=str(principal.user.id), action="artifact.download_denied", target_type="artifact", target_id=str(artifact.id), payload={"reason": "access_tier"})
        await db.commit()
        raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not found")
    try:
        path = store().verify(artifact.object_key, artifact.sha256)
    except DigestMismatchError as exc:
        await append_audit(db, actor_type="system", actor_id=None, action="artifact.integrity_failed", target_type="artifact", target_id=str(artifact.id))
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "artifact integrity verification failed") from exc
    await append_audit(db, actor_type="user", actor_id=str(principal.user.id), action="artifact.downloaded", target_type="artifact", target_id=str(artifact.id), payload={"sha256": artifact.sha256})
    await db.commit()
    extensions = {
        "application/json": "json",
        "application/pdf": "pdf",
        "text/csv": "csv",
    }
    extension = extensions.get(artifact.media_type)
    analyst_suffixes = {
        "android_sample": "apk", "java_source": "zip", "smali_source": "zip",
        "application_data": "tar", "android_scan_logs": "json",
    }
    suffix = analyst_suffixes.get(artifact.kind)
    filename = (
        f"umat-report-{artifact.id}.{extension}"
        if artifact.kind in {"report", "ioc_export"} and extension
        else f"umat-{artifact.kind}-{artifact.id}.{suffix}"
        if suffix
        else f"umat-artifact-{artifact.id}"
    )
    return FileResponse(
        path,
        media_type=(
            artifact.media_type
            if artifact.kind in {"report", "ioc_export"}
            else "application/octet-stream"
        ),
        filename=filename,
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        content_disposition_type="attachment",
    )
