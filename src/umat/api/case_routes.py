from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.schemas import (
    CaseListItem,
    CaseResponse,
    CreateCaseResponse,
    CreateRunRequest,
    DuplicateCase,
    RunActionResponse,
    RunResponse,
    StageResponse,
    SubmissionResponse,
)
from umat.audit import append_audit
from umat.auth.dependencies import Principal, current_principal
from umat.config import get_settings
from umat.db import get_db
from umat.db.models import (
    AnalysisRun,
    AnalysisStage,
    AndroidAnalysisProfile,
    AndroidProfileState,
    AndroidRunConfiguration,
    Case,
    CaseReportSnapshot,
    CaseSample,
    Platform,
    RunResult,
    RunStatus,
    Sample,
    StageState,
    StageType,
    Submission,
    WindowsProfileState,
    WindowsRunConfiguration,
    WindowsVMProfile,
)
from umat.egress.readiness import require_controlled_egress
from umat.intake import is_structurally_valid_apk
from umat.reporting import filter_report_for_roles
from umat.storage.local import LocalArtifactStore, UploadTooLargeError

router = APIRouter(prefix="/api/v1", tags=["cases"])


def store() -> LocalArtifactStore:
    settings = get_settings()
    return LocalArtifactStore(settings.quarantine_root, settings.artifact_root)


def can_access_case(principal: Principal, case: Case) -> bool:
    return principal.is_staff or case.owner_user_id == principal.user.id


async def accessible_case(db: AsyncSession, principal: Principal, case_id: UUID) -> Case:
    case = await db.scalar(select(Case).where(Case.id == case_id))
    if not case or not can_access_case(principal, case):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "case not found")
    return case


def create_platform_stage(run: AnalysisRun) -> AnalysisStage:
    settings = get_settings()
    max_attempts, timeout_seconds = settings.policy_for_stage(StageType.PLATFORM_ANALYSIS.value)
    return AnalysisStage(
        analysis_run_id=run.id,
        stage_type=StageType.PLATFORM_ANALYSIS,
        state=StageState.QUEUED,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
    )


async def resolve_windows_profile(
    db: AsyncSession, profile_id: UUID | None
) -> WindowsVMProfile | None:
    if profile_id:
        profile = await db.get(WindowsVMProfile, profile_id)
    else:
        profile = await db.scalar(
            select(WindowsVMProfile)
            .where(
                WindowsVMProfile.state == WindowsProfileState.ACTIVE,
                WindowsVMProfile.is_default.is_(True),
            )
            .limit(1)
        )
    if profile_id and (not profile or profile.state != WindowsProfileState.ACTIVE):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Windows VM profile not found")
    return profile


async def resolve_android_profile(
    db: AsyncSession, profile_id: UUID | None
) -> AndroidAnalysisProfile:
    profile = (
        await db.get(AndroidAnalysisProfile, profile_id)
        if profile_id
        else await db.scalar(
            select(AndroidAnalysisProfile)
            .where(
                AndroidAnalysisProfile.state == AndroidProfileState.ACTIVE,
                AndroidAnalysisProfile.is_default.is_(True),
            )
            .limit(1)
        )
    )
    if not profile or profile.state != AndroidProfileState.ACTIVE:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android analysis profile not found")
    return profile


@router.post("/cases", response_model=CreateCaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    file: UploadFile = File(...),
    title: str | None = Form(default=None, max_length=256),
    reference: str | None = Form(default=None, max_length=128),
    windows_profile_id: UUID | None = Form(default=None),
    android_profile_id: UUID | None = Form(default=None),
    network_mode: Literal["isolated_simulated", "real_world_egress"] = Form(
        default="isolated_simulated"
    ),
    c2_analysis_enabled: bool = Form(default=False),
    android_interactive: bool = Form(default=False),
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> CreateCaseResponse:
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
        duplicate_query = (
            select(Case, Submission, AnalysisRun)
            .join(Submission, Submission.case_id == Case.id)
            .outerjoin(AnalysisRun, AnalysisRun.submission_id == Submission.id)
            .where(Submission.sample_sha256 == quarantined.sha256)
            .order_by(desc(Submission.received_at))
        )
        if not principal.is_staff:
            duplicate_query = duplicate_query.where(Case.owner_user_id == principal.user.id)
        duplicate_rows = (await db.execute(duplicate_query)).all()
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

        object_key = artifact_store.object_key(quarantined.sha256)
        sample = await db.get(Sample, quarantined.sha256)
        if sample is None:
            sample = Sample(
                sha256=quarantined.sha256,
                size_bytes=quarantined.size_bytes,
                media_type=file.content_type or "application/octet-stream",
                object_key=object_key,
            )
            db.add(sample)
        case = Case(owner_user_id=principal.user.id, title=title, reference=reference)
        db.add(case)
        await db.flush()
        submission = Submission(
            case_id=case.id,
            uploader_user_id=principal.user.id,
            sample_sha256=quarantined.sha256,
            original_filename=filename,
        )
        db.add(submission)
        db.add(CaseSample(case_id=case.id, sample_sha256=quarantined.sha256))
        await db.flush()
        run = AnalysisRun(
            case_id=case.id,
            submission_id=submission.id,
            platform=platform,
            network_mode=network_mode,
            c2_analysis_enabled=c2_analysis_enabled,
            android_interactive=android_interactive if platform == Platform.ANDROID else False,
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
            action="case.created",
            target_type="case",
            target_id=str(case.id),
            payload={
                "submission_id": str(submission.id),
                "run_id": str(run.id),
                "sample_sha256": quarantined.sha256,
                "platform": platform.value,
                "network_mode": network_mode,
                "c2_analysis_enabled": c2_analysis_enabled,
                "android_interactive": android_interactive
                if platform == Platform.ANDROID
                else False,
            },
        )
        if duplicates:
            await append_audit(
                db,
                actor_type="user",
                actor_id=str(principal.user.id),
                action="duplicate.warning",
                target_type="analysis_run",
                target_id=str(run.id),
                payload={"accessible_matches": len(duplicates)},
            )
        artifact_store.promote(quarantined)
        await append_audit(
            db,
            actor_type="system",
            actor_id=None,
            action="sample.promoted",
            target_type="sample",
            target_id=quarantined.sha256,
            payload={"object_key": object_key, "size_bytes": quarantined.size_bytes},
        )
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


def serialize_case(case: Case, report: dict[str, Any] | None = None) -> CaseResponse:
    return CaseResponse(
        case_id=case.id,
        owner_user_id=case.owner_user_id,
        title=case.title,
        reference=case.reference,
        created_at=case.created_at,
        submissions=[
            SubmissionResponse(
                id=s.id,
                sample_sha256=s.sample_sha256,
                original_filename=s.original_filename,
                received_at=s.received_at,
            )
            for s in case.submissions
        ],
        analysis_runs=[
            RunResponse(
                id=r.id,
                submission_id=r.submission_id,
                platform=r.platform.value,
                status=r.status.value,
                result=r.result.value if r.result else None,
                network_mode=r.network_mode,
                c2_analysis_enabled=r.c2_analysis_enabled,
                android_interactive=r.android_interactive,
                stages=[
                    StageResponse(
                        id=s.id,
                        stage_type=s.stage_type.value,
                        state=s.state.value,
                        failure_code=s.failure_code,
                        failure_detail=s.failure_detail,
                    )
                    for s in r.stages
                ],
                windows_profile=r.windows_configuration.profile_snapshot
                if r.windows_configuration
                else None,
                android_profile=r.android_configuration.profile_snapshot
                if r.android_configuration
                else None,
            )
            for r in case.runs
        ],
        report=report,
    )


@router.get("/cases", response_model=list[CaseListItem])
async def list_cases(
    principal: Principal = Depends(current_principal), db: AsyncSession = Depends(get_db)
) -> list[CaseListItem]:
    query = select(Case).order_by(desc(Case.created_at))
    if not principal.is_staff:
        query = query.where(Case.owner_user_id == principal.user.id)
    cases = list((await db.scalars(query)).unique().all())
    result = []
    for case in cases:
        latest = max(case.runs, key=lambda item: item.created_at) if case.runs else None
        snapshot = (
            await db.scalar(
                select(CaseReportSnapshot)
                .where(CaseReportSnapshot.analysis_run_id == latest.id)
                .order_by(CaseReportSnapshot.revision.desc())
                .limit(1)
            )
            if latest
            else None
        )
        result.append(
            CaseListItem(
                case_id=case.id,
                title=case.title,
                reference=case.reference,
                created_at=case.created_at,
                latest_status=latest.status.value if latest else None,
                latest_result=latest.result.value if latest and latest.result else None,
                latest_platform=latest.platform.value if latest else None,
                latest_verdict=snapshot.verdict.value if snapshot else None,
                latest_headline=snapshot.headline if snapshot else None,
            )
        )
    return result


@router.get("/cases/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> CaseResponse:
    case = await accessible_case(db, principal, case_id)
    snapshot = await db.scalar(
        select(CaseReportSnapshot)
        .where(CaseReportSnapshot.case_id == case.id)
        .order_by(CaseReportSnapshot.generated_at.desc(), CaseReportSnapshot.revision.desc())
        .limit(1)
    )
    report = filter_report_for_roles(snapshot.report_json, principal.roles) if snapshot else None
    return serialize_case(case, report)


@router.get("/cases/{case_id}/status", response_model=list[RunResponse])
async def get_case_status(
    case_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> list[RunResponse]:
    return serialize_case(await accessible_case(db, principal, case_id)).analysis_runs


@router.post(
    "/cases/{case_id}/analysis-runs",
    response_model=RunActionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_run(
    case_id: UUID,
    body: CreateRunRequest,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> RunActionResponse:
    await require_controlled_egress(get_settings(), body.network_mode)
    case = await accessible_case(db, principal, case_id)
    submission = await db.get(Submission, body.submission_id)
    if not submission or submission.case_id != case.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "submission not found")
    existing = await db.scalar(
        select(AnalysisRun).where(AnalysisRun.submission_id == submission.id)
    )
    platform = existing.platform if existing else Platform.WINDOWS
    run = AnalysisRun(
        case_id=case.id,
        submission_id=submission.id,
        platform=platform,
        network_mode=body.network_mode,
        c2_analysis_enabled=body.c2_analysis_enabled,
        android_interactive=body.android_interactive if platform == Platform.ANDROID else False,
        status=RunStatus.QUEUED,
        confirmed_at=datetime.now(timezone.utc),
    )
    db.add(run)
    await db.flush()
    if platform == Platform.WINDOWS:
        profile = await resolve_windows_profile(db, body.windows_profile_id)
        db.add(
            WindowsRunConfiguration(
                analysis_run_id=run.id,
                profile_id=profile.id if profile else None,
                profile_snapshot=profile.snapshot() if profile else {},
                selected_by_user_id=principal.user.id,
            )
        )
    else:
        android_profile = await resolve_android_profile(db, body.android_profile_id)
        if (
            body.network_mode == "isolated_simulated"
            and not android_profile.system_image.startswith("docker.io/redroid/")
        ):
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "isolated Android runs require the ReDroid profile",
            )
        db.add(
            AndroidRunConfiguration(
                analysis_run_id=run.id,
                profile_id=android_profile.id,
                profile_snapshot=android_profile.snapshot(),
                selected_by_user_id=principal.user.id,
            )
        )
    db.add(create_platform_stage(run))
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="run.created",
        target_type="analysis_run",
        target_id=str(run.id),
        payload={
            "case_id": str(case.id),
            "network_mode": body.network_mode,
            "c2_analysis_enabled": body.c2_analysis_enabled,
            "android_interactive": body.android_interactive
            if platform == Platform.ANDROID
            else False,
        },
    )
    await db.commit()
    return RunActionResponse(analysis_run_id=run.id, status=run.status.value, result=None)


async def owned_run(db: AsyncSession, principal: Principal, run_id: UUID) -> AnalysisRun:
    run = await db.get(AnalysisRun, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    await accessible_case(db, principal, run.case_id)
    return run


@router.post("/analysis-runs/{run_id}/confirm", response_model=RunActionResponse)
async def confirm_run(
    run_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> RunActionResponse:
    run = await owned_run(db, principal, run_id)
    if run.status == RunStatus.AWAITING_CONFIRMATION:
        run.status = RunStatus.QUEUED
        run.confirmed_at = datetime.now(timezone.utc)
        db.add(create_platform_stage(run))
        await append_audit(
            db,
            actor_type="user",
            actor_id=str(principal.user.id),
            action="duplicate.confirmed",
            target_type="analysis_run",
            target_id=str(run.id),
        )
        await db.commit()
    elif run.status not in {RunStatus.QUEUED, RunStatus.RUNNING}:
        raise HTTPException(status.HTTP_409_CONFLICT, "run can no longer be confirmed")
    return RunActionResponse(
        analysis_run_id=run.id,
        status=run.status.value,
        result=run.result.value if run.result else None,
    )


@router.post("/analysis-runs/{run_id}/cancel", response_model=RunActionResponse)
async def cancel_run(
    run_id: UUID,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> RunActionResponse:
    run = await owned_run(db, principal, run_id)
    if run.status == RunStatus.TERMINAL:
        return RunActionResponse(
            analysis_run_id=run.id,
            status=run.status.value,
            result=run.result.value if run.result else None,
        )
    run.cancellation_requested_at = datetime.now(timezone.utc)
    active = [
        stage for stage in run.stages if stage.state in {StageState.LEASED, StageState.RUNNING}
    ]
    if active:
        run.status = RunStatus.CANCELLING
    else:
        run.status = RunStatus.TERMINAL
        run.result = RunResult.CANCELLED
        for stage in run.stages:
            if stage.state in {StageState.WAITING, StageState.QUEUED}:
                stage.state = StageState.CANCELLED
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="run.cancellation_requested",
        target_type="analysis_run",
        target_id=str(run.id),
        payload={"active_stage_count": len(active)},
    )
    await db.commit()
    return RunActionResponse(
        analysis_run_id=run.id,
        status=run.status.value,
        result=run.result.value if run.result else None,
    )
