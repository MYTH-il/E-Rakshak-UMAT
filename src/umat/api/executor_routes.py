from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.case_routes import store
from umat.api.executor_schemas import (
    ArtifactEnvelope,
    CancellationAckRequest,
    CapabilityRequest,
    ClaimArtifact,
    ClaimRequest,
    ClaimResponse,
    CompleteRequest,
    FailRequest,
    HeartbeatRequest,
    NativeTaskRequest,
    RegisterExecutorRequest,
    RegisterExecutorResponse,
    WindowsProfileOperationCompleteRequest,
)
from umat.audit import append_audit
from umat.auth.security import random_token, token_hash
from umat.config import get_settings
from umat.db import get_db
from umat.db.models import (
    AccessTier,
    AnalysisAttempt,
    AnalysisRun,
    AnalysisStage,
    AndroidRunConfiguration,
    Artifact,
    AttemptState,
    BackendCapabilitySnapshot,
    BackendTask,
    Executor,
    ExecutorCredential,
    ExecutorEnrollmentToken,
    ExecutorLease,
    ExecutorRequest,
    ExecutorStatus,
    RunResult,
    RunStatus,
    Sample,
    StageState,
    StageType,
    Submission,
    WindowsProfileOperation,
    WindowsProfileOperationState,
    WindowsProfileOperationType,
    WindowsProfileState,
    WindowsRunConfiguration,
    WindowsVMProfile,
)
from umat.executors.security import current_executor, verify_executor_signature
from umat.storage.local import DigestMismatchError, UploadTooLargeError

router = APIRouter(prefix="/api/internal/v1", tags=["executors"])


def enum_value(value):  # type: ignore[no-untyped-def]
    return value.value if hasattr(value, "value") else value


async def signed_request(
    *,
    db: AsyncSession,
    executor: Executor,
    request: Request,
    body: dict[str, Any],
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    signature: str,
) -> tuple[ExecutorRequest, bool]:
    request_hash = verify_executor_signature(
        executor, request, body, timestamp, nonce, idempotency_key, signature
    )
    previous_key = await db.scalar(
        select(ExecutorRequest).where(
            ExecutorRequest.executor_id == executor.id,
            ExecutorRequest.idempotency_key == idempotency_key,
        )
    )
    if previous_key:
        if previous_key.request_hash != request_hash:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "idempotency key reused with different request"
            )
        return previous_key, True
    previous_nonce = await db.scalar(
        select(ExecutorRequest).where(
            ExecutorRequest.executor_id == executor.id, ExecutorRequest.nonce == nonce
        )
    )
    if previous_nonce:
        raise HTTPException(status.HTTP_409_CONFLICT, "executor nonce already used")
    record = ExecutorRequest(
        executor_id=executor.id,
        idempotency_key=idempotency_key,
        nonce=nonce,
        request_hash=request_hash,
    )
    db.add(record)
    await db.flush()
    return record, False


async def validate_lease(
    db: AsyncSession,
    executor: Executor,
    stage_id: UUID,
    lease_id: UUID,
    attempt_id: UUID,
    lease_token: str,
    *,
    allow_expired: bool = False,
) -> tuple[AnalysisStage, AnalysisAttempt, ExecutorLease]:
    stage = await db.get(AnalysisStage, stage_id)
    attempt = await db.get(AnalysisAttempt, attempt_id)
    lease = await db.get(ExecutorLease, lease_id)
    now = datetime.now(timezone.utc)
    if not stage or not attempt or not lease:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "stage lease not found")
    if (
        attempt.stage_id != stage.id
        or attempt.executor_id != executor.id
        or lease.attempt_id != attempt.id
        or lease.executor_id != executor.id
        or lease.stage_id != stage.id
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "lease identity mismatch")
    if (
        (lease.released_at and not allow_expired)
        or (not allow_expired and lease.expires_at <= now)
        or token_hash(lease_token) != lease.token_hash
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "lease is not active")
    return stage, attempt, lease


@router.post(
    "/executors/register",
    response_model=RegisterExecutorResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_executor(
    body: RegisterExecutorRequest, db: AsyncSession = Depends(get_db)
) -> RegisterExecutorResponse:
    now = datetime.now(timezone.utc)
    enrollment = await db.scalar(
        select(ExecutorEnrollmentToken)
        .where(ExecutorEnrollmentToken.token_hash == token_hash(body.enrollment_token))
        .with_for_update()
    )
    if not enrollment or enrollment.used_at or enrollment.expires_at <= now:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired enrollment token")
    try:
        public_key = base64.b64decode(body.public_key, validate=True)
        if len(public_key) != 32:
            raise ValueError
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "public_key must be a base64 Ed25519 public key"
        ) from exc
    executor = Executor(
        name=body.name,
        executor_type=enrollment.executor_type,
        status=ExecutorStatus.ACTIVE,
        public_key=public_key,
        supported_stage_types=enrollment.scopes,
        metadata_json=body.metadata,
    )
    db.add(executor)
    enrollment.used_at = now
    credential_raw = random_token(48)
    await db.flush()
    db.add(
        ExecutorCredential(
            executor_id=executor.id, token_hash=token_hash(credential_raw), scopes=enrollment.scopes
        )
    )
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="executor.registered",
        target_type="executor",
        target_id=str(executor.id),
        payload={"name": executor.name, "type": executor.executor_type},
    )
    await db.commit()
    return RegisterExecutorResponse(executor_id=executor.id, credential=credential_raw)


@router.post("/executors/capabilities", status_code=status.HTTP_204_NO_CONTENT)
async def publish_capabilities(
    body: CapabilityRequest,
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> None:
    invalid = set(body.supported_stage_types) - set(executor.supported_stage_types)
    if invalid:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"unscoped stage types: {sorted(invalid)}")
    executor.supported_stage_types = body.supported_stage_types
    executor.last_seen_at = datetime.now(timezone.utc)
    db.add(
        BackendCapabilitySnapshot(
            executor_id=executor.id,
            runtime_identity=body.runtime_identity,
            schema_version=body.schema_version,
            capabilities=body.capabilities,
        )
    )
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="executor.capabilities_published",
        target_type="executor",
        target_id=str(executor.id),
        payload={"stage_types": body.supported_stage_types, "runtime": body.runtime_identity},
    )
    await db.commit()


@router.post("/executors/windows/profile-operations/claim")
async def claim_windows_profile_operation(
    executor: Executor = Depends(current_executor), db: AsyncSession = Depends(get_db)
) -> dict[str, Any] | None:
    if (
        executor.executor_type != "windows"
        or "platform_analysis" not in executor.supported_stage_types
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Windows management scope required")
    now = datetime.now(timezone.utc)
    expired = list(
        (
            await db.scalars(
                select(WindowsProfileOperation)
                .where(
                    WindowsProfileOperation.state == WindowsProfileOperationState.LEASED,
                    WindowsProfileOperation.lease_expires_at <= now,
                )
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    for item in expired:
        item.state = WindowsProfileOperationState.QUEUED
        item.executor_id = None
        item.lease_token_hash = None
        item.lease_expires_at = None
    operation = await db.scalar(
        select(WindowsProfileOperation)
        .where(WindowsProfileOperation.state == WindowsProfileOperationState.QUEUED)
        .order_by(WindowsProfileOperation.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if not operation:
        await db.commit()
        return None
    profile = await db.get(WindowsVMProfile, operation.profile_id)
    if not profile:
        raise HTTPException(status.HTTP_409_CONFLICT, "profile operation has no profile")
    lease_token = random_token(32)
    operation.state = WindowsProfileOperationState.LEASED
    operation.executor_id = executor.id
    operation.lease_token_hash = token_hash(lease_token)
    operation.lease_expires_at = now + timedelta(seconds=get_settings().lease_ttl_seconds)
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="windows_profile.operation_leased",
        target_type="windows_profile_operation",
        target_id=str(operation.id),
        payload={"operation": operation.operation_type.value},
    )
    await db.commit()
    return {
        "operation_id": str(operation.id),
        "operation_type": operation.operation_type.value,
        "lease_token": lease_token,
        "lease_expires_at": operation.lease_expires_at.isoformat(),
        "profile": profile.snapshot(),
    }


@router.post("/executors/windows/profile-operations/{operation_id}/complete")
async def complete_windows_profile_operation(
    operation_id: UUID,
    body: WindowsProfileOperationCompleteRequest,
    request: Request,
    x_umat_timestamp: str = Header(alias="X-UMAT-Timestamp"),
    x_umat_nonce: str = Header(alias="X-UMAT-Nonce"),
    idempotency_key: str = Header(alias="Idempotency-Key"),
    x_umat_signature: str = Header(alias="X-UMAT-Signature"),
    x_umat_lease_token: str = Header(alias="X-UMAT-Lease-Token"),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    timestamp, nonce, key, signature, lease_token = (
        x_umat_timestamp,
        x_umat_nonce,
        idempotency_key,
        x_umat_signature,
        x_umat_lease_token,
    )
    if body.operation_id != operation_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "operation identity mismatch")
    record, replay = await signed_request(
        db=db,
        executor=executor,
        request=request,
        body=body.model_dump(mode="json"),
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
    )
    if replay and record.response_json:
        return record.response_json
    operation = await db.get(WindowsProfileOperation, operation_id, with_for_update=True)
    now = datetime.now(timezone.utc)
    if not operation or operation.executor_id != executor.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile operation not found")
    if (
        operation.state != WindowsProfileOperationState.LEASED
        or operation.lease_expires_at is None
        or operation.lease_expires_at <= now
        or token_hash(lease_token) != operation.lease_token_hash
    ):
        raise HTTPException(status.HTTP_409_CONFLICT, "profile operation lease is not active")
    profile = await db.get(WindowsVMProfile, operation.profile_id)
    if not profile:
        raise HTTPException(status.HTTP_409_CONFLICT, "profile operation has no profile")
    operation.native_operation_id = body.native_operation_id
    operation.error_detail = body.detail if not body.success else None
    operation.completed_at = now
    operation.state = (
        WindowsProfileOperationState.COMPLETED
        if body.success
        else WindowsProfileOperationState.FAILED
    )
    operation.result = {"cape_machine_label": body.cape_machine_label, "detail": body.detail}
    if body.success and operation.operation_type == WindowsProfileOperationType.CREATE:
        profile.cape_machine_label = body.cape_machine_label
        profile.state = WindowsProfileState.ACTIVE
        profile.error_detail = None
    elif body.success:
        profile.state = WindowsProfileState.DELETED
        profile.cape_machine_label = None
    else:
        profile.state = WindowsProfileState.ERROR
        profile.error_detail = body.detail
    response = {
        "operation_id": str(operation.id),
        "state": operation.state.value,
        "profile_state": profile.state.value,
    }
    record.response_json = response
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="windows_profile.operation_completed"
        if body.success
        else "windows_profile.operation_failed",
        target_type="windows_profile_operation",
        target_id=str(operation.id),
        payload=response,
    )
    await db.commit()
    return response


async def expire_attempt(
    db: AsyncSession,
    lease: ExecutorLease,
    attempt: AnalysisAttempt,
    stage: AnalysisStage,
    now: datetime,
    reason: str,
) -> None:
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    lease.released_at = now
    lease.release_reason = reason
    attempt.ended_at = now
    if run and run.status == RunStatus.CANCELLING:
        attempt.state = AttemptState.CANCELLED
        stage.state = StageState.CANCELLED
        remaining = (
            await db.scalar(
                select(func.count(AnalysisStage.id)).where(
                    AnalysisStage.analysis_run_id == run.id,
                    AnalysisStage.id != stage.id,
                    AnalysisStage.state.in_([StageState.LEASED, StageState.RUNNING]),
                )
            )
            or 0
        )
        if not remaining:
            pending = list(
                (
                    await db.scalars(
                        select(AnalysisStage).where(
                            AnalysisStage.analysis_run_id == run.id,
                            AnalysisStage.id != stage.id,
                            AnalysisStage.state.in_([StageState.WAITING, StageState.QUEUED]),
                        )
                    )
                ).all()
            )
            for pending_stage in pending:
                pending_stage.state = StageState.CANCELLED
            run.status = RunStatus.TERMINAL
            run.result = RunResult.CANCELLED
        return
    attempt.state = AttemptState.EXPIRED
    attempt.error_code = reason
    stage.failure_code = reason
    attempt_count = (
        await db.scalar(
            select(func.count(AnalysisAttempt.id)).where(AnalysisAttempt.stage_id == stage.id)
        )
        or 0
    )
    if attempt_count < stage.max_attempts:
        stage.state = StageState.QUEUED
        stage.next_attempt_at = now + timedelta(seconds=min(300, 2**attempt_count))
        return
    stage.state = StageState.FAILED
    if run and stage.stage_type == StageType.PLATFORM_ANALYSIS:
        run.status = RunStatus.TERMINAL
        run.result = RunResult.FAILED
    elif run:
        run.status = RunStatus.TERMINAL
        run.result = (
            RunResult.PARTIAL
            if stage.stage_type == StageType.C2_ANALYSIS
            else RunResult.INCONCLUSIVE
        )


async def expire_leases(db: AsyncSession) -> int:
    now = datetime.now(timezone.utc)
    leases = list(
        (
            await db.scalars(
                select(ExecutorLease)
                .where(ExecutorLease.released_at.is_(None))
                .order_by(ExecutorLease.expires_at)
                .with_for_update(skip_locked=True)
                .limit(1000)
            )
        ).all()
    )
    expired = 0
    for lease in leases:
        attempt = await db.get(AnalysisAttempt, lease.attempt_id)
        stage = await db.get(AnalysisStage, lease.stage_id)
        if not attempt or not stage:
            continue
        deadline = attempt.started_at + timedelta(seconds=stage.timeout_seconds)
        if lease.expires_at > now and deadline > now:
            continue
        reason = "timeout" if deadline <= now else "lease_expired"
        await expire_attempt(db, lease, attempt, stage, now, reason)
        await append_audit(
            db,
            actor_type="system",
            actor_id="scheduler",
            action="stage.timed_out" if reason == "timeout" else "stage.lease_expired",
            target_type="analysis_stage",
            target_id=str(stage.id),
            payload={"attempt_id": str(attempt.id), "reason": reason},
        )
        expired += 1
    return expired


@router.post("/executors/claim", response_model=ClaimResponse | None)
async def claim_stage(
    body: ClaimRequest,
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> ClaimResponse | None:
    allowed = set(body.stage_types).intersection(executor.supported_stage_types)
    if not allowed:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "no requested stage type is in executor scope"
        )
    await expire_leases(db)
    now = datetime.now(timezone.utc)
    snapshot = await db.scalar(
        select(BackendCapabilitySnapshot)
        .where(BackendCapabilitySnapshot.executor_id == executor.id)
        .order_by(BackendCapabilitySnapshot.captured_at.desc())
        .limit(1)
    )
    if snapshot is None:
        await db.commit()
        return None
    capabilities = snapshot.capabilities
    advertised_platforms = {str(value) for value in capabilities.get("platforms", [])}
    requested_platforms = set(body.platforms)
    compatible_platforms = requested_platforms
    platform_scoped = bool(
        allowed.intersection({StageType.PLATFORM_ANALYSIS.value, StageType.C2_ANALYSIS.value})
    )
    if platform_scoped and not advertised_platforms:
        await db.commit()
        return None
    if advertised_platforms:
        compatible_platforms = (
            requested_platforms.intersection(advertised_platforms)
            if requested_platforms
            else advertised_platforms
        )
        if requested_platforms and not compatible_platforms:
            await db.commit()
            return None
    if (
        StageType.C2_ANALYSIS.value in allowed
        and capabilities.get("native_event_schema_version") != "1.3"
    ):
        await db.commit()
        return None
    if StageType.PLATFORM_ANALYSIS.value in allowed and executor.executor_type != "fake":
        requirements = {
            "windows": {"cape_native": True, "handoff_schema": "1.0"},
            "android": {
                "ephemeral_avd": True,
                "pcap_capture": True,
                "mobsf_api": "v1",
            },
        }
        for platform in compatible_platforms or advertised_platforms:
            required = requirements.get(platform, {})
            if any(capabilities.get(name) != value for name, value in required.items()):
                await db.commit()
                return None
    stage_query = (
        select(AnalysisStage)
        .join(AnalysisRun, AnalysisRun.id == AnalysisStage.analysis_run_id)
        .where(
            AnalysisStage.state == StageState.QUEUED,
            AnalysisStage.stage_type.in_(allowed),
            (AnalysisStage.next_attempt_at.is_(None)) | (AnalysisStage.next_attempt_at <= now),
        )
        .order_by(AnalysisStage.priority.desc(), AnalysisStage.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if compatible_platforms:
        stage_query = stage_query.where(AnalysisRun.platform.in_(compatible_platforms))
    stage = await db.scalar(stage_query)
    if not stage:
        await db.commit()
        return None
    count = (
        await db.scalar(
            select(func.count(AnalysisAttempt.id)).where(AnalysisAttempt.stage_id == stage.id)
        )
        or 0
    )
    attempt = AnalysisAttempt(
        stage_id=stage.id,
        executor_id=executor.id,
        attempt_number=count + 1,
        state=AttemptState.LEASED,
    )
    db.add(attempt)
    await db.flush()
    lease_raw = random_token(32)
    expiry = now + timedelta(seconds=get_settings().lease_ttl_seconds)
    lease = ExecutorLease(
        stage_id=stage.id,
        attempt_id=attempt.id,
        executor_id=executor.id,
        token_hash=token_hash(lease_raw),
        expires_at=expiry,
    )
    db.add(lease)
    stage.state = StageState.LEASED
    stage.failure_code = None
    stage.failure_detail = None
    stage.next_attempt_at = None
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    if not run:
        raise HTTPException(status.HTTP_409_CONFLICT, "stage has no analysis run")
    run.status = RunStatus.RUNNING
    submission = await db.get(Submission, run.submission_id)
    if not submission:
        raise HTTPException(status.HTTP_409_CONFLICT, "run has no submission")
    artifact_rows = (
        await db.execute(
            select(Artifact, AnalysisStage.stage_type)
            .join(AnalysisStage, Artifact.stage_id == AnalysisStage.id)
            .where(
                Artifact.analysis_run_id == run.id,
                Artifact.stage_id != stage.id,
                AnalysisStage.state.in_([StageState.COMPLETED, StageState.PARTIAL]),
            )
            .order_by(Artifact.created_at)
        )
    ).all()
    allowed_input_kinds: set[str] | None = None
    if stage.stage_type == StageType.C2_ANALYSIS:
        allowed_input_kinds = {"pcap", "platform_manifest", "access_events", "static_prior"}
    elif stage.stage_type == StageType.PLATFORM_ADAPTATION:
        allowed_input_kinds = {"windows_bundle", "android_bundle"}
    elif stage.stage_type == StageType.C2_ADAPTATION:
        allowed_input_kinds = {"c2_bundle"}
    if allowed_input_kinds is not None:
        artifact_rows = [row for row in artifact_rows if row[0].kind in allowed_input_kinds]
    input_artifacts = [
        ClaimArtifact(
            artifact_id=artifact.id,
            kind=artifact.kind,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            media_type=artifact.media_type,
            source_stage_type=source_stage_type.value,
            download_path=f"/api/internal/v1/stages/{stage.id}/inputs/{artifact.id}",
        )
        for artifact, source_stage_type in artifact_rows
    ]
    configuration = (
        await db.get(WindowsRunConfiguration, run.id)
        if run.platform.value == "windows"
        else await db.get(AndroidRunConfiguration, run.id)
    )
    existing_native = await db.scalar(
        select(BackendTask).where(BackendTask.stage_id == stage.id).order_by(BackendTask.created_at)
    )
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="stage.leased",
        target_type="analysis_stage",
        target_id=str(stage.id),
        payload={"attempt_id": str(attempt.id), "expires_at": expiry.isoformat()},
    )
    await db.commit()
    execution_configuration = dict(configuration.profile_snapshot) if configuration else {}
    execution_configuration["network_mode"] = run.network_mode
    execution_configuration["c2_analysis_enabled"] = run.c2_analysis_enabled
    return ClaimResponse(
        stage_id=stage.id,
        attempt_id=attempt.id,
        analysis_run_id=run.id,
        stage_type=stage.stage_type.value,
        platform=run.platform.value,
        sample_sha256=submission.sample_sha256,
        lease_id=lease.id,
        lease_token=lease_raw,
        lease_expires_at=expiry,
        timeout_seconds=stage.timeout_seconds,
        input_artifacts=input_artifacts,
        sample_download_path=f"/api/internal/v1/stages/{stage.id}/sample"
        if stage.stage_type == StageType.PLATFORM_ANALYSIS
        else None,
        execution_configuration=execution_configuration,
        recovered_native_task={
            "task_type": existing_native.task_type,
            "native_task_id": existing_native.native_task_id,
            "recovery_metadata": existing_native.recovery_metadata,
        }
        if existing_native
        else None,
    )


async def verify_stage_mutation(
    *,
    db: AsyncSession,
    executor: Executor,
    request: Request,
    stage_id: UUID,
    body: dict[str, Any],
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    signature: str,
    lease_token: str,
) -> tuple[AnalysisStage, AnalysisAttempt, ExecutorLease, ExecutorRequest, bool]:
    record, replay = await signed_request(
        db=db,
        executor=executor,
        request=request,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=idempotency_key,
        signature=signature,
    )
    stage, attempt, lease = await validate_lease(
        db,
        executor,
        stage_id,
        UUID(str(body["lease_id"])),
        UUID(str(body["attempt_id"])),
        lease_token,
        allow_expired=replay,
    )
    return stage, attempt, lease, record, replay


def mutation_headers(
    x_umat_timestamp: str = Header(alias="X-UMAT-Timestamp"),
    x_umat_nonce: str = Header(alias="X-UMAT-Nonce"),
    idempotency_key: str = Header(alias="Idempotency-Key"),
    x_umat_signature: str = Header(alias="X-UMAT-Signature"),
    x_umat_lease_token: str = Header(alias="X-UMAT-Lease-Token"),
) -> tuple[str, str, str, str, str]:
    return x_umat_timestamp, x_umat_nonce, idempotency_key, x_umat_signature, x_umat_lease_token


@router.get("/stages/{stage_id}/sample")
async def download_stage_sample(
    stage_id: UUID,
    lease_id: UUID,
    attempt_id: UUID,
    request: Request,
    headers: tuple[str, str, str, str, str] = Depends(mutation_headers),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    timestamp, nonce, key, signature, lease_token = headers
    body = {"lease_id": str(lease_id), "attempt_id": str(attempt_id), "sample": True}
    stage, _, _, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
        lease_token=lease_token,
    )
    if stage.stage_type != StageType.PLATFORM_ANALYSIS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "sample input not found")
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    submission = await db.get(Submission, run.submission_id) if run else None
    if not submission:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "sample input not found")
    sample = await db.get(Sample, submission.sample_sha256)
    if not sample:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "sample input not found")
    try:
        path = store().verify(sample.object_key, sample.sha256)
    except DigestMismatchError as exc:
        await append_audit(
            db,
            actor_type="system",
            actor_id=None,
            action="sample.integrity_failed",
            target_type="sample",
            target_id=sample.sha256,
        )
        await db.commit()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "sample integrity verification failed"
        ) from exc
    if not replay:
        record.response_json = {"sample_sha256": sample.sha256}
        await append_audit(
            db,
            actor_type="executor",
            actor_id=str(executor.id),
            action="sample.downloaded_by_executor",
            target_type="sample",
            target_id=sample.sha256,
            payload={"stage_id": str(stage.id)},
        )
        await db.commit()
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=f"sample-{sample.sha256}",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        content_disposition_type="attachment",
    )


@router.get("/stages/{stage_id}/inputs/{artifact_id}")
async def download_stage_input(
    stage_id: UUID,
    artifact_id: UUID,
    lease_id: UUID,
    attempt_id: UUID,
    request: Request,
    headers: tuple[str, str, str, str, str] = Depends(mutation_headers),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    timestamp, nonce, key, signature, lease_token = headers
    body = {
        "lease_id": str(lease_id),
        "attempt_id": str(attempt_id),
        "artifact_id": str(artifact_id),
    }
    stage, _, _, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
        lease_token=lease_token,
    )
    artifact = await db.get(Artifact, artifact_id)
    if (
        not artifact
        or artifact.analysis_run_id != stage.analysis_run_id
        or artifact.stage_id == stage.id
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "input artifact not found")
    source_stage = await db.get(AnalysisStage, artifact.stage_id) if artifact.stage_id else None
    if not source_stage or source_stage.state not in {StageState.COMPLETED, StageState.PARTIAL}:
        raise HTTPException(status.HTTP_409_CONFLICT, "input artifact stage is not complete")
    try:
        path = store().verify(artifact.object_key, artifact.sha256)
    except DigestMismatchError as exc:
        await append_audit(
            db,
            actor_type="system",
            actor_id=None,
            action="executor_input.integrity_failed",
            target_type="artifact",
            target_id=str(artifact.id),
        )
        await db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "input artifact integrity failed") from exc
    if not replay:
        record.response_json = {"artifact_id": str(artifact.id), "sha256": artifact.sha256}
        await append_audit(
            db,
            actor_type="executor",
            actor_id=str(executor.id),
            action="executor_input.downloaded",
            target_type="artifact",
            target_id=str(artifact.id),
            payload={"stage_id": str(stage.id)},
        )
        await db.commit()
    return FileResponse(
        path,
        media_type="application/octet-stream",
        filename=f"input-{artifact.id}",
        headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"},
        content_disposition_type="attachment",
    )


@router.post("/stages/{stage_id}/heartbeat")
async def heartbeat(
    stage_id: UUID,
    body: HeartbeatRequest,
    request: Request,
    headers: tuple[str, str, str, str, str] = Depends(mutation_headers),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    timestamp, nonce, key, signature, lease_token = headers
    stage, attempt, lease, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body.model_dump(mode="json"),
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
        lease_token=lease_token,
    )
    if replay and record.response_json:
        return record.response_json
    now = datetime.now(timezone.utc)
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    if run and run.status == RunStatus.CANCELLING:
        lease.last_heartbeat_at = now
        lease.expires_at = now + timedelta(seconds=get_settings().lease_ttl_seconds)
        response: dict[str, Any] = {
            "lease_expires_at": lease.expires_at.isoformat(),
            "stop_requested": "cancelled",
        }
        record.response_json = response
        await db.commit()
        return response
    deadline = attempt.started_at + timedelta(seconds=stage.timeout_seconds)
    if deadline <= now:
        await expire_attempt(db, lease, attempt, stage, now, "timeout")
        await append_audit(
            db,
            actor_type="system",
            actor_id="scheduler",
            action="stage.timed_out",
            target_type="analysis_stage",
            target_id=str(stage.id),
            payload={"attempt_id": str(attempt.id), "source": "heartbeat"},
        )
        response = {"lease_expires_at": now.isoformat(), "stop_requested": "timeout"}
        record.response_json = response
        await db.commit()
        return response
    lease.last_heartbeat_at = now
    lease.expires_at = now + timedelta(seconds=get_settings().lease_ttl_seconds)
    stage.state = StageState.RUNNING
    attempt.state = AttemptState.RUNNING
    executor.last_seen_at = now
    response = {
        "lease_expires_at": lease.expires_at.isoformat(),
        "stop_requested": None,
    }
    record.response_json = response
    await db.commit()
    return response


@router.post("/stages/{stage_id}/native-task")
async def native_task(
    stage_id: UUID,
    body: NativeTaskRequest,
    request: Request,
    headers: tuple[str, str, str, str, str] = Depends(mutation_headers),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    timestamp, nonce, key, signature, lease_token = headers
    _, _, _, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body.model_dump(mode="json"),
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
        lease_token=lease_token,
    )
    if replay and record.response_json:
        return record.response_json
    existing = await db.scalar(select(BackendTask).where(BackendTask.stage_id == stage_id))
    if existing:
        if existing.native_task_id != body.native_task_id or existing.task_type != body.task_type:
            raise HTTPException(status.HTTP_409_CONFLICT, "stage already has another native task")
        response = {"backend_task_id": str(existing.id), "recovered": True}
        record.response_json = response
        await db.commit()
        return response
    task = BackendTask(
        stage_id=stage_id,
        attempt_id=body.attempt_id,
        executor_id=executor.id,
        task_type=body.task_type,
        native_task_id=body.native_task_id,
        recovery_metadata=body.recovery_metadata,
    )
    db.add(task)
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="native_task.recorded",
        target_type="analysis_stage",
        target_id=str(stage_id),
        payload={"task_type": body.task_type, "native_task_id": body.native_task_id},
    )
    response = {"backend_task_id": str(task.id), "recovered": False}
    record.response_json = response
    await db.commit()
    return response


@router.post("/stages/{stage_id}/artifacts", status_code=status.HTTP_201_CREATED)
async def upload_artifact(
    stage_id: UUID,
    request: Request,
    envelope: str = Form(...),
    file: UploadFile = File(...),
    x_umat_timestamp: str = Header(alias="X-UMAT-Timestamp"),
    x_umat_nonce: str = Header(alias="X-UMAT-Nonce"),
    idempotency_key: str = Header(alias="Idempotency-Key"),
    x_umat_signature: str = Header(alias="X-UMAT-Signature"),
    x_umat_lease_token: str = Header(alias="X-UMAT-Lease-Token"),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    try:
        metadata = ArtifactEnvelope.model_validate_json(envelope)
    except ValueError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid artifact envelope"
        ) from exc
    body = metadata.model_dump(mode="json")
    stage, _, _, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body,
        timestamp=x_umat_timestamp,
        nonce=x_umat_nonce,
        idempotency_key=idempotency_key,
        signature=x_umat_signature,
        lease_token=x_umat_lease_token,
    )
    if replay and record.response_json:
        return record.response_json
    artifact_store = store()
    try:
        quarantined = await artifact_store.quarantine_upload(
            file,
            max(get_settings().c2_max_result_bytes, get_settings().windows_max_bundle_bytes),
        )
        if quarantined.sha256 != metadata.sha256 or quarantined.size_bytes != metadata.size_bytes:
            raise DigestMismatchError("artifact content does not match signed envelope")
        stored = artifact_store.promote(quarantined)
    except (UploadTooLargeError, DigestMismatchError) as exc:
        await append_audit(
            db,
            actor_type="executor",
            actor_id=str(executor.id),
            action="artifact.rejected",
            target_type="analysis_stage",
            target_id=str(stage_id),
            payload={"reason": str(exc)},
        )
        await db.commit()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    artifact = Artifact(
        analysis_run_id=stage.analysis_run_id,
        stage_id=stage.id,
        attempt_id=metadata.attempt_id,
        kind=metadata.kind,
        sha256=metadata.sha256,
        size_bytes=metadata.size_bytes,
        media_type=metadata.media_type,
        object_key=stored.object_key,
        access_tier=AccessTier(metadata.access_tier),
        bundle_id=metadata.bundle_id,
    )
    db.add(artifact)
    await db.flush()
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="artifact.registered",
        target_type="artifact",
        target_id=str(artifact.id),
        payload={
            "run_id": str(run.id) if run else None,
            "sha256": artifact.sha256,
            "kind": artifact.kind,
        },
    )
    response = {"artifact_id": str(artifact.id)}
    record.response_json = response
    await db.commit()
    return response


async def create_next_stage(
    db: AsyncSession, run: AnalysisRun, stage_type: StageType
) -> AnalysisStage:
    existing = await db.scalar(
        select(AnalysisStage).where(
            AnalysisStage.analysis_run_id == run.id, AnalysisStage.stage_type == stage_type
        )
    )
    if existing:
        return existing
    max_attempts, timeout_seconds = get_settings().policy_for_stage(stage_type.value)
    stage = AnalysisStage(
        analysis_run_id=run.id,
        stage_type=stage_type,
        state=StageState.QUEUED,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
    )
    db.add(stage)
    await db.flush()
    return stage


async def advance_workflow(db: AsyncSession, run: AnalysisRun, completed: AnalysisStage) -> None:
    if completed.stage_type == StageType.PLATFORM_ANALYSIS:
        if not run.c2_analysis_enabled:
            await create_next_stage(db, run, StageType.PLATFORM_ADAPTATION)
        else:
            await create_next_stage(db, run, StageType.C2_ANALYSIS)
    elif completed.stage_type == StageType.C2_ANALYSIS:
        await create_next_stage(db, run, StageType.PLATFORM_ADAPTATION)
        await create_next_stage(db, run, StageType.C2_ADAPTATION)
    elif completed.stage_type == StageType.PLATFORM_ADAPTATION and not run.c2_analysis_enabled:
        await create_next_stage(db, run, StageType.CASE_AGGREGATION)
    elif completed.stage_type in {StageType.PLATFORM_ADAPTATION, StageType.C2_ADAPTATION}:
        adaptations = list(
            (
                await db.scalars(
                    select(AnalysisStage).where(
                        AnalysisStage.analysis_run_id == run.id,
                        AnalysisStage.stage_type.in_(
                            [StageType.PLATFORM_ADAPTATION, StageType.C2_ADAPTATION]
                        ),
                    )
                )
            ).all()
        )
        if len(adaptations) == 2 and all(
            item.state == StageState.COMPLETED for item in adaptations
        ):
            await create_next_stage(db, run, StageType.CASE_AGGREGATION)
    elif completed.stage_type == StageType.CASE_AGGREGATION:
        await create_next_stage(db, run, StageType.REPORT_GENERATION)
    elif completed.stage_type == StageType.REPORT_GENERATION:
        run.status = RunStatus.TERMINAL
        run.result = RunResult.COMPLETED


@router.post("/stages/{stage_id}/complete")
async def complete_stage(
    stage_id: UUID,
    body: CompleteRequest,
    request: Request,
    headers: tuple[str, str, str, str, str] = Depends(mutation_headers),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    timestamp, nonce, key, signature, lease_token = headers
    stage, attempt, lease, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body.model_dump(mode="json"),
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
        lease_token=lease_token,
    )
    if replay and record.response_json:
        return record.response_json
    requested_state = StageState(body.outcome)
    if requested_state not in {StageState.COMPLETED, StageState.PARTIAL, StageState.UNSUPPORTED}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid completion outcome")
    now = datetime.now(timezone.utc)
    stage.state = requested_state
    attempt.state = AttemptState.COMPLETED
    attempt.ended_at = now
    lease.released_at = now
    lease.release_reason = "completed"
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    if not run:
        raise HTTPException(status.HTTP_409_CONFLICT, "run missing")
    if (
        requested_state == StageState.UNSUPPORTED
        and stage.stage_type == StageType.PLATFORM_ANALYSIS
    ):
        run.status = RunStatus.TERMINAL
        run.result = RunResult.UNSUPPORTED
    elif requested_state == StageState.PARTIAL:
        run.result = RunResult.PARTIAL
        await advance_workflow(db, run, stage)
    else:
        await advance_workflow(db, run, stage)
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="stage.completed",
        target_type="analysis_stage",
        target_id=str(stage.id),
        payload={"outcome": requested_state.value},
    )
    response = {
        "stage_id": str(stage.id),
        "state": stage.state.value,
        "run_status": run.status.value,
        "run_result": run.result.value if run.result else None,
    }
    record.response_json = response
    await db.commit()
    return response


@router.post("/stages/{stage_id}/fail")
async def fail_stage(
    stage_id: UUID,
    body: FailRequest,
    request: Request,
    headers: tuple[str, str, str, str, str] = Depends(mutation_headers),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    timestamp, nonce, key, signature, lease_token = headers
    stage, attempt, lease, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body.model_dump(mode="json"),
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
        lease_token=lease_token,
    )
    if replay and record.response_json:
        return record.response_json
    now = datetime.now(timezone.utc)
    attempt.state = AttemptState.FAILED
    attempt.error_code = body.error_code
    attempt.error_detail = body.detail
    attempt.ended_at = now
    lease.released_at = now
    lease.release_reason = "failed"
    stage.failure_code = body.error_code
    stage.failure_detail = body.detail
    attempt_count = (
        await db.scalar(
            select(func.count(AnalysisAttempt.id)).where(AnalysisAttempt.stage_id == stage.id)
        )
        or 0
    )
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    if body.retryable and attempt_count < stage.max_attempts:
        stage.state = StageState.QUEUED
        stage.next_attempt_at = now + timedelta(seconds=min(300, 2**attempt_count))
    else:
        stage.state = StageState.FAILED
        if run and stage.stage_type == StageType.PLATFORM_ANALYSIS:
            run.status = RunStatus.TERMINAL
            run.result = RunResult.FAILED
        elif run:
            run.status = RunStatus.TERMINAL
            run.result = (
                RunResult.PARTIAL
                if stage.stage_type == StageType.C2_ANALYSIS
                else RunResult.INCONCLUSIVE
            )
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="stage.failed",
        target_type="analysis_stage",
        target_id=str(stage.id),
        payload={"error_code": body.error_code, "retryable": body.retryable},
    )
    response = {
        "stage_id": str(stage.id),
        "state": stage.state.value,
        "retry_at": stage.next_attempt_at.isoformat() if stage.next_attempt_at else None,
    }
    record.response_json = response
    await db.commit()
    return response


@router.post("/stages/{stage_id}/cancellation-ack")
async def cancellation_ack(
    stage_id: UUID,
    body: CancellationAckRequest,
    request: Request,
    headers: tuple[str, str, str, str, str] = Depends(mutation_headers),
    executor: Executor = Depends(current_executor),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    timestamp, nonce, key, signature, lease_token = headers
    stage, attempt, lease, record, replay = await verify_stage_mutation(
        db=db,
        executor=executor,
        request=request,
        stage_id=stage_id,
        body=body.model_dump(mode="json"),
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=key,
        signature=signature,
        lease_token=lease_token,
    )
    if replay and record.response_json:
        return record.response_json
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    if not run or run.status != RunStatus.CANCELLING:
        raise HTTPException(status.HTTP_409_CONFLICT, "run is not cancelling")
    now = datetime.now(timezone.utc)
    stage.state = StageState.CANCELLED
    attempt.state = AttemptState.CANCELLED
    attempt.ended_at = now
    lease.released_at = now
    lease.release_reason = "cancelled"
    other_active = (
        await db.scalar(
            select(func.count(AnalysisStage.id)).where(
                AnalysisStage.analysis_run_id == run.id,
                AnalysisStage.id != stage.id,
                AnalysisStage.state.in_([StageState.LEASED, StageState.RUNNING]),
            )
        )
        or 0
    )
    if not other_active:
        pending = list(
            (
                await db.scalars(
                    select(AnalysisStage).where(
                        AnalysisStage.analysis_run_id == run.id,
                        AnalysisStage.id != stage.id,
                        AnalysisStage.state.in_([StageState.WAITING, StageState.QUEUED]),
                    )
                )
            ).all()
        )
        for pending_stage in pending:
            pending_stage.state = StageState.CANCELLED
        run.status = RunStatus.TERMINAL
        run.result = RunResult.CANCELLED
    await append_audit(
        db,
        actor_type="executor",
        actor_id=str(executor.id),
        action="stage.cancellation_acknowledged",
        target_type="analysis_stage",
        target_id=str(stage.id),
    )
    response = {
        "stage_id": str(stage.id),
        "state": stage.state.value,
        "run_status": run.status.value,
    }
    record.response_json = response
    await db.commit()
    return response
