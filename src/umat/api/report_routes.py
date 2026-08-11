from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.case_routes import accessible_case, store
from umat.api.schemas import ReportExportResponse, ReportSnapshotResponse
from umat.audit import append_audit
from umat.auth.dependencies import Principal, current_principal
from umat.db import get_db
from umat.db.models import AnalysisRun, CaseReportSnapshot, ExportFormat, ReportExport
from umat.reporting import ReportExporter, filter_report_for_roles

router = APIRouter(prefix="/api/v1/cases", tags=["reports"])


async def latest_snapshot(
    db: AsyncSession, case_id: UUID, run_id: UUID | None = None
) -> CaseReportSnapshot | None:
    query = select(CaseReportSnapshot).where(CaseReportSnapshot.case_id == case_id)
    if run_id:
        query = query.where(CaseReportSnapshot.analysis_run_id == run_id)
    snapshot: CaseReportSnapshot | None = await db.scalar(
        query.order_by(
            CaseReportSnapshot.generated_at.desc(), CaseReportSnapshot.revision.desc()
        ).limit(1)
    )
    return snapshot


@router.get("/{case_id}/report", response_model=ReportSnapshotResponse)
async def get_report(
    case_id: UUID,
    run_id: UUID | None = None,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> ReportSnapshotResponse:
    await accessible_case(db, principal, case_id)
    if run_id:
        run = await db.get(AnalysisRun, run_id)
        if not run or run.case_id != case_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    snapshot = await latest_snapshot(db, case_id, run_id)
    if not snapshot:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "report not found")
    return ReportSnapshotResponse(
        snapshot_id=snapshot.id,
        revision=snapshot.revision,
        evidence_digest=snapshot.evidence_digest,
        generated_at=snapshot.generated_at,
        report=filter_report_for_roles(snapshot.report_json, principal.roles),
    )


async def create_export(
    case_id: UUID,
    export_format: ExportFormat,
    principal: Principal,
    db: AsyncSession,
) -> ReportExportResponse:
    await accessible_case(db, principal, case_id)
    snapshot = await latest_snapshot(db, case_id)
    if not snapshot:
        raise HTTPException(status.HTTP_409_CONFLICT, "case report is not ready")
    export = await ReportExporter(store()).create(
        db, snapshot, export_format, principal.user.id, principal.roles
    )
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="report.exported",
        target_type="report_export",
        target_id=str(export.id),
        payload={
            "case_id": str(case_id),
            "format": export_format.value,
            "sha256": export.sha256,
            "artifact_id": str(export.artifact_id),
        },
    )
    await db.commit()
    return _export_response(export)


def _export_response(export: ReportExport) -> ReportExportResponse:
    return ReportExportResponse(
        export_id=export.id,
        artifact_id=export.artifact_id,
        format=export.export_format.value,
        format_version=export.format_version,
        sha256=export.sha256,
        size_bytes=export.size_bytes,
        download_path=f"/api/v1/artifacts/{export.artifact_id}",
        created_at=export.created_at,
    )


@router.post(
    "/{case_id}/exports/json",
    response_model=ReportExportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def export_json(
    case_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> ReportExportResponse:
    return await create_export(case_id, ExportFormat.JSON, principal, db)


@router.post(
    "/{case_id}/exports/pdf",
    response_model=ReportExportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def export_pdf(
    case_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> ReportExportResponse:
    return await create_export(case_id, ExportFormat.PDF, principal, db)


@router.post(
    "/{case_id}/exports/csv",
    response_model=ReportExportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def export_csv(
    case_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> ReportExportResponse:
    return await create_export(case_id, ExportFormat.CSV, principal, db)
