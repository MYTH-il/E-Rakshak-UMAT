from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.case_routes import (
    accessible_case,
    create_platform_stage,
    resolve_android_profile,
    resolve_windows_profile,
    serialize_case,
    store,
)
from umat.api.operations_schemas import (
    RecentRunItem,
    RecentRunsResponse,
    RetryRunRequest,
    RetryRunResponse,
    RunStageDiagnostic,
    UpdateCaseRequest,
    WorkerInventoryItem,
    WorkerInventoryResponse,
    WorkerLeaseResponse,
)
from umat.api.schemas import CaseResponse, CreateCaseResponse, DuplicateCase
from umat.audit import append_audit
from umat.auth.dependencies import Principal, current_principal, require_roles
from umat.config import get_settings
from umat.db import get_db
from umat.db.models import (
    AnalysisRun,
    AnalysisStage,
    AndroidRunConfiguration,
    BackendCapabilitySnapshot,
    Case,
    CaseSample,
    Executor,
    ExecutorLease,
    ExecutorStatus,
    Platform,
    RunResult,
    RunStatus,
    Sample,
    Submission,
    WindowsRunConfiguration,
)
from umat.egress.readiness import require_controlled_egress
from umat.intake import is_structurally_valid_apk
from umat.storage.local import UploadTooLargeError

router = APIRouter(prefix="/api/v1", tags=["operations"])
RETRYABLE_RESULTS = {
    RunResult.PARTIAL,
    RunResult.INCONCLUSIVE,
    RunResult.FAILED,
    RunResult.CANCELLED,
    RunResult.UNSUPPORTED,
}


def retry_eligible(run: AnalysisRun) -> bool:
    return run.status == RunStatus.TERMINAL and run.result in RETRYABLE_RESULTS


@router.patch("/cases/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: UUID,
    body: UpdateCaseRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> CaseResponse:
    case = await accessible_case(db, principal, case_id)
    before = {"title": case.title, "reference": case.reference}
    if "title" in body.model_fields_set:
        case.title = body.title.strip() if body.title else None
    if "reference" in body.model_fields_set:
        case.reference = body.reference.strip() if body.reference else None
    after = {"title": case.title, "reference": case.reference}
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="case.metadata_updated",
        target_type="case",
        target_id=str(case.id),
        payload={"before": before, "after": after},
    )
    await db.commit()
    return serialize_case(case)


@router.post(
    "/cases/{case_id}/submissions",
    response_model=CreateCaseResponse,
    status_code=status.HTTP_201_CREATED,
)
async def add_submission(
    case_id: UUID,
    file: UploadFile = File(...),
    windows_profile_id: UUID | None = Form(default=None),
    android_profile_id: UUID | None = Form(default=None),
    network_mode: Literal["isolated_simulated", "real_world_egress"] = Form(
        default="isolated_simulated"
    ),
    c2_analysis_enabled: bool = Form(default=False),
    android_interactive: bool = Form(default=False),
    windows_interactive: bool = Form(default=False),
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> CreateCaseResponse:
    case = await accessible_case(db, principal, case_id)
    settings = get_settings()
    await require_controlled_egress(settings, network_mode)
    artifact_store = store()
    try:
        quarantined = await artifact_store.quarantine_upload(file, settings.max_upload_bytes)
    except UploadTooLargeError as exc:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, str(exc)) from exc
    filename = Path(file.filename or "unnamed").name[:512]
    platform = Platform.ANDROID if is_structurally_valid_apk(quarantined.path) else Platform.WINDOWS
    try:
        if platform == Platform.ANDROID and windows_profile_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "a Windows VM profile cannot be selected for an APK",
            )
        if platform == Platform.WINDOWS and android_profile_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "an Android profile cannot be selected for a Windows sample",
            )
        windows_profile = (
            await resolve_windows_profile(db, windows_profile_id)
            if platform == Platform.WINDOWS
            else None
        )
        android_profile = (
            await resolve_android_profile(db, android_profile_id)
            if platform == Platform.ANDROID
            else None
        )
        if (
            android_profile
            and network_mode == "isolated_simulated"
            and not android_profile.system_image.startswith("docker.io/redroid/")
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "isolated Android runs require the ReDroid profile",
            )
        duplicate_rows = (
            await db.execute(
                select(Case, Submission, AnalysisRun)
                .join(Submission, Submission.case_id == Case.id)
                .outerjoin(AnalysisRun, AnalysisRun.submission_id == Submission.id)
                .where(
                    Submission.sample_sha256 == quarantined.sha256,
                    Case.id != case.id,
                )
                .order_by(Submission.received_at.desc())
            )
        ).all()
        if not principal.is_staff:
            duplicate_rows = [
                row for row in duplicate_rows if row.Case.owner_user_id == principal.user.id
            ]
        duplicates = [
            DuplicateCase(
                case_id=row.Case.id,
                submitted_at=row.Submission.received_at,
                result=row.AnalysisRun.result.value
                if row.AnalysisRun and row.AnalysisRun.result
                else None,
            )
            for row in duplicate_rows
        ]
        sample = await db.get(Sample, quarantined.sha256)
        object_key = artifact_store.object_key(quarantined.sha256)
        if sample is None:
            sample = Sample(
                sha256=quarantined.sha256,
                size_bytes=quarantined.size_bytes,
                media_type=file.content_type or "application/octet-stream",
                object_key=object_key,
            )
            db.add(sample)
        submission = Submission(
            case_id=case.id,
            uploader_user_id=principal.user.id,
            sample_sha256=quarantined.sha256,
            original_filename=filename,
        )
        db.add(submission)
        if not await db.get(CaseSample, (case.id, quarantined.sha256)):
            db.add(CaseSample(case_id=case.id, sample_sha256=quarantined.sha256))
        await db.flush()
        run = AnalysisRun(
            case_id=case.id,
            submission_id=submission.id,
            platform=platform,
            network_mode=network_mode,
            c2_analysis_enabled=c2_analysis_enabled,
            android_interactive=android_interactive if platform == Platform.ANDROID else False,
            windows_interactive=windows_interactive if platform == Platform.WINDOWS else False,
            status=RunStatus.AWAITING_CONFIRMATION if duplicates else RunStatus.QUEUED,
        )
        db.add(run)
        await db.flush()
        if platform == Platform.WINDOWS:
            db.add(
                WindowsRunConfiguration(
                    analysis_run_id=run.id,
                    profile_id=windows_profile.id if windows_profile else None,
                    profile_snapshot=windows_profile.snapshot() if windows_profile else {},
                    selected_by_user_id=principal.user.id,
                )
            )
        else:
            assert android_profile is not None
            db.add(
                AndroidRunConfiguration(
                    analysis_run_id=run.id,
                    profile_id=android_profile.id,
                    profile_snapshot=android_profile.snapshot(),
                    selected_by_user_id=principal.user.id,
                )
            )
        if not duplicates:
            db.add(create_platform_stage(run))
        await append_audit(
            db,
            actor_type="user",
            actor_id=str(principal.user.id),
            action="case.submission_added",
            target_type="case",
            target_id=str(case.id),
            payload={
                "submission_id": str(submission.id),
                "run_id": str(run.id),
                "sample_sha256": quarantined.sha256,
                "platform": platform.value,
            },
        )
        artifact_store.promote(quarantined)
        await db.commit()
        return CreateCaseResponse(
            case_id=case.id,
            submission_id=submission.id,
            analysis_run_id=run.id,
            sample_sha256=quarantined.sha256,
            platform=platform.value,
            status=run.status.value,
            duplicate_cases=duplicates,
        )
    except BaseException:
        await db.rollback()
        quarantined.path.unlink(missing_ok=True)
        raise


def stage_diagnostic(stage: AnalysisStage) -> RunStageDiagnostic:
    attempts = sorted(stage.attempts, key=lambda item: item.attempt_number)
    latest = attempts[-1] if attempts else None
    return RunStageDiagnostic(
        id=stage.id,
        stage_type=stage.stage_type.value,
        state=stage.state.value,
        attempt_count=len(attempts),
        latest_attempt_state=latest.state.value if latest else None,
        latest_executor_id=latest.executor_id if latest else None,
        failure_code=stage.failure_code,
        failure_detail=stage.failure_detail,
        created_at=stage.created_at,
        updated_at=stage.updated_at,
    )


@router.get("/analysis-runs", response_model=RecentRunsResponse)
async def recent_runs(
    q: str | None = Query(default=None, max_length=256),
    run_status: RunStatus | None = Query(default=None, alias="status"),
    result: RunResult | None = Query(default=None),
    platform: Platform | None = Query(default=None),
    case_id: UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=10, ge=1, le=100),
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> RecentRunsResponse:
    filters = []
    if not principal.is_staff:
        filters.append(Case.owner_user_id == principal.user.id)
    if run_status:
        filters.append(AnalysisRun.status == run_status)
    if result:
        filters.append(AnalysisRun.result == result)
    if platform:
        filters.append(AnalysisRun.platform == platform)
    if case_id:
        filters.append(AnalysisRun.case_id == case_id)
    if q and q.strip():
        pattern = f"%{q.strip()}%"
        filters.append(
            or_(
                Case.title.ilike(pattern),
                Case.reference.ilike(pattern),
                Submission.original_filename.ilike(pattern),
                Submission.sample_sha256.ilike(pattern),
            )
        )
    base = (
        select(AnalysisRun, Case, Submission)
        .join(Case, Case.id == AnalysisRun.case_id)
        .join(Submission, Submission.id == AnalysisRun.submission_id)
        .where(*filters)
    )
    total = int(
        await db.scalar(select(func.count()).select_from(base.order_by(None).subquery())) or 0
    )
    rows = (
        await db.execute(
            base.order_by(AnalysisRun.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    items = []
    for run, case, submission in rows:
        profile = (
            run.windows_configuration.profile_snapshot
            if run.windows_configuration
            else run.android_configuration.profile_snapshot
            if run.android_configuration
            else None
        )
        items.append(
            RecentRunItem(
                id=run.id,
                case_id=case.id,
                case_title=case.title,
                case_reference=case.reference,
                submission_id=submission.id,
                filename=submission.original_filename,
                sample_sha256=submission.sample_sha256,
                platform=run.platform.value,
                status=run.status.value,
                result=run.result.value if run.result else None,
                network_mode=run.network_mode,
                c2_analysis_enabled=run.c2_analysis_enabled,
                android_interactive=run.android_interactive,
                windows_interactive=run.windows_interactive,
                profile=profile,
                retry_eligible=retry_eligible(run),
                created_at=run.created_at,
                updated_at=run.updated_at,
                stages=[stage_diagnostic(item) for item in run.stages],
            )
        )
    return RecentRunsResponse(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        pages=math.ceil(total / page_size) if total else 0,
    )


@router.post("/analysis-runs/{run_id}/retry", response_model=RetryRunResponse)
async def retry_run(
    run_id: UUID,
    body: RetryRunRequest,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> RetryRunResponse:
    source = await db.get(AnalysisRun, run_id, with_for_update=True)
    if not source:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    await accessible_case(db, principal, source.case_id)
    if not retry_eligible(source):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "only terminal unsuccessful runs are eligible for retry",
        )
    retried = AnalysisRun(
        case_id=source.case_id,
        submission_id=source.submission_id,
        platform=source.platform,
        network_mode=source.network_mode,
        c2_analysis_enabled=source.c2_analysis_enabled,
        android_interactive=source.android_interactive,
        windows_interactive=source.windows_interactive,
        status=RunStatus.QUEUED,
        confirmed_at=datetime.now(timezone.utc),
    )
    db.add(retried)
    await db.flush()
    if source.windows_configuration:
        configuration = source.windows_configuration
        db.add(
            WindowsRunConfiguration(
                analysis_run_id=retried.id,
                profile_id=configuration.profile_id,
                profile_snapshot=dict(configuration.profile_snapshot),
                selected_by_user_id=principal.user.id,
            )
        )
    elif source.android_configuration:
        android_configuration = source.android_configuration
        db.add(
            AndroidRunConfiguration(
                analysis_run_id=retried.id,
                profile_id=android_configuration.profile_id,
                profile_snapshot=dict(android_configuration.profile_snapshot),
                selected_by_user_id=principal.user.id,
            )
        )
    db.add(create_platform_stage(retried))
    reason = body.reason.strip()
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="run.retry_created",
        target_type="analysis_run",
        target_id=str(retried.id),
        payload={"source_run_id": str(source.id), "reason": reason},
    )
    await db.commit()
    return RetryRunResponse(
        source_run_id=source.id,
        analysis_run_id=retried.id,
        status=retried.status.value,
        reason=reason,
    )


def worker_compatibility(
    executor: Executor, snapshot: BackendCapabilitySnapshot | None
) -> dict[str, object]:
    capabilities = snapshot.capabilities if snapshot else {}
    platforms = sorted(str(item) for item in capabilities.get("platforms", []))
    issues = []
    if snapshot is None:
        issues.append("capabilities_not_advertised")
    if not executor.supported_stage_types:
        issues.append("no_supported_stages")
    if executor.executor_type in {"windows", "android", "c2", "fake"} and not platforms:
        issues.append("platforms_not_advertised")
    if executor.executor_type == "c2" and capabilities.get("native_event_schema_version") != "1.3":
        issues.append("c2_schema_mismatch")
    return {"compatible": not issues, "platforms": platforms, "issues": issues}


@router.get("/admin/workers", response_model=WorkerInventoryResponse)
async def worker_inventory(
    _: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> WorkerInventoryResponse:
    now = datetime.now(timezone.utc)
    executors = list((await db.scalars(select(Executor).order_by(Executor.name))).all())
    items = []
    for executor in executors:
        snapshot = await db.scalar(
            select(BackendCapabilitySnapshot)
            .where(BackendCapabilitySnapshot.executor_id == executor.id)
            .order_by(BackendCapabilitySnapshot.captured_at.desc())
            .limit(1)
        )
        lease_rows = (
            await db.execute(
                select(ExecutorLease, AnalysisStage, AnalysisRun)
                .join(AnalysisStage, AnalysisStage.id == ExecutorLease.stage_id)
                .join(AnalysisRun, AnalysisRun.id == AnalysisStage.analysis_run_id)
                .where(
                    ExecutorLease.executor_id == executor.id,
                    ExecutorLease.released_at.is_(None),
                )
                .order_by(ExecutorLease.expires_at)
            )
        ).all()
        leases = [
            WorkerLeaseResponse(
                lease_id=lease.id,
                stage_id=stage.id,
                analysis_run_id=run.id,
                case_id=run.case_id,
                stage_type=stage.stage_type.value,
                platform=run.platform.value,
                state=stage.state.value,
                last_heartbeat_at=lease.last_heartbeat_at,
                expires_at=lease.expires_at,
            )
            for lease, stage, run in lease_rows
        ]
        if executor.status != ExecutorStatus.ACTIVE:
            heartbeat_state = "disabled"
        elif executor.last_seen_at is None:
            heartbeat_state = "never_seen"
        elif executor.last_seen_at >= now - timedelta(minutes=2):
            heartbeat_state = "online"
        else:
            heartbeat_state = "stale"
        items.append(
            WorkerInventoryItem(
                id=executor.id,
                name=executor.name,
                executor_type=executor.executor_type,
                status=executor.status.value,
                supported_stage_types=list(executor.supported_stage_types),
                runtime_identity=snapshot.runtime_identity if snapshot else None,
                capability_schema_version=snapshot.schema_version if snapshot else None,
                capabilities=dict(snapshot.capabilities) if snapshot else {},
                metadata=dict(executor.metadata_json),
                last_seen_at=executor.last_seen_at,
                created_at=executor.created_at,
                heartbeat_state=heartbeat_state,
                active_workload=len(leases),
                active_leases=leases,
                compatibility=worker_compatibility(executor, snapshot),
            )
        )
    return WorkerInventoryResponse(generated_at=now, items=items)
