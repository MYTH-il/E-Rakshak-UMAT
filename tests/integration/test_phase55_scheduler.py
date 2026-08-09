import base64
import os
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"),
    reason="requires a migrated PostgreSQL test database",
)

from umat.api.app import app  # noqa: E402
from umat.api.executor_routes import expire_leases  # noqa: E402
from umat.auth.security import random_token, token_hash  # noqa: E402
from umat.db.models import (  # noqa: E402
    AnalysisAttempt,
    AnalysisRun,
    AnalysisStage,
    AttemptState,
    BackendCapabilitySnapshot,
    Case,
    Executor,
    ExecutorCredential,
    ExecutorLease,
    ExecutorStatus,
    Platform,
    RunStatus,
    Sample,
    StageState,
    StageType,
    Submission,
    User,
)
from umat.db.session import session_factory  # noqa: E402
from umat.executors.protocol import signature_message  # noqa: E402


def signed_headers(
    private: Ed25519PrivateKey,
    path: str,
    body: dict[str, object],
    credential: str,
    lease_token: str,
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = uuid.uuid4().hex
    idempotency = str(uuid.uuid4())
    message = signature_message(
        method="POST",
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=idempotency,
        body=body,
    )
    return {
        "Authorization": f"Bearer {credential}",
        "X-UMAT-Timestamp": timestamp,
        "X-UMAT-Nonce": nonce,
        "Idempotency-Key": idempotency,
        "X-UMAT-Signature": base64.b64encode(private.sign(message)).decode(),
        "X-UMAT-Lease-Token": lease_token,
    }


async def create_run_stage(
    *,
    user: User,
    platform: Platform,
    run_status: RunStatus,
    stage_state: StageState,
    timeout_seconds: int = 1800,
    max_attempts: int = 3,
) -> tuple[AnalysisRun, AnalysisStage]:
    suffix = uuid.uuid4().hex
    sample = Sample(
        sha256=suffix.ljust(64, "0"),
        size_bytes=1,
        media_type="application/octet-stream",
        object_key=f"objects/test/{suffix}",
    )
    case = Case(owner_user_id=user.id, title="phase55", reference=suffix)
    async with session_factory() as db:
        db.add_all([sample, case])
        await db.flush()
        submission = Submission(
            case_id=case.id,
            uploader_user_id=user.id,
            sample_sha256=sample.sha256,
            original_filename="fixture.bin",
        )
        db.add(submission)
        await db.flush()
        run = AnalysisRun(
            case_id=case.id,
            submission_id=submission.id,
            platform=platform,
            status=run_status,
        )
        db.add(run)
        await db.flush()
        stage = AnalysisStage(
            analysis_run_id=run.id,
            stage_type=StageType.PLATFORM_ANALYSIS,
            state=stage_state,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
        )
        db.add(stage)
        await db.commit()
        return run, stage


@pytest.mark.asyncio
async def test_timeout_capability_filter_and_cancellation_protocol() -> None:
    async with session_factory() as db:
        admin = await db.scalar(select(User).where(User.username == "admin"))
        assert admin

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    credential = random_token(48)
    executor = Executor(
        name=f"phase55-{uuid.uuid4().hex}",
        executor_type="fake",
        status=ExecutorStatus.ACTIVE,
        public_key=public,
        supported_stage_types=["platform_analysis"],
    )
    async with session_factory() as db:
        db.add(executor)
        await db.flush()
        db.add_all(
            [
                ExecutorCredential(
                    executor_id=executor.id,
                    token_hash=token_hash(credential),
                    scopes=["platform_analysis"],
                ),
                BackendCapabilitySnapshot(
                    executor_id=executor.id,
                    runtime_identity="phase55-fixture",
                    schema_version="1.0",
                    capabilities={"platforms": ["windows"]},
                ),
            ]
        )
        await db.commit()

    timed_run, timed_stage = await create_run_stage(
        user=admin,
        platform=Platform.WINDOWS,
        run_status=RunStatus.RUNNING,
        stage_state=StageState.RUNNING,
        timeout_seconds=1,
        max_attempts=2,
    )
    lease_token = random_token(32)
    async with session_factory() as db:
        attempt = AnalysisAttempt(
            stage_id=timed_stage.id,
            executor_id=executor.id,
            attempt_number=1,
            state=AttemptState.RUNNING,
            started_at=datetime.now(timezone.utc) - timedelta(seconds=10),
        )
        db.add(attempt)
        await db.flush()
        db.add(
            ExecutorLease(
                stage_id=timed_stage.id,
                attempt_id=attempt.id,
                executor_id=executor.id,
                token_hash=token_hash(lease_token),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
            )
        )
        await db.commit()
    async with session_factory() as db:
        assert await expire_leases(db) >= 1
        await db.commit()
        refreshed_stage = await db.get(AnalysisStage, timed_stage.id)
        assert refreshed_stage and refreshed_stage.state == StageState.QUEUED
        assert refreshed_stage.failure_code == "timeout"
        refreshed_run = await db.get(AnalysisRun, timed_run.id)
        assert refreshed_run and refreshed_run.status == RunStatus.RUNNING

    _, android_stage = await create_run_stage(
        user=admin,
        platform=Platform.ANDROID,
        run_status=RunStatus.QUEUED,
        stage_state=StageState.QUEUED,
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        incompatible = await client.post(
            "/api/internal/v1/executors/claim",
            headers={"Authorization": f"Bearer {credential}"},
            json={"stage_types": ["platform_analysis"], "platforms": ["android"]},
        )
        assert incompatible.status_code == 200
        assert incompatible.json() is None
    async with session_factory() as db:
        untouched = await db.get(AnalysisStage, android_stage.id)
        assert untouched and untouched.state == StageState.QUEUED

    cancelling_run, cancelling_stage = await create_run_stage(
        user=admin,
        platform=Platform.WINDOWS,
        run_status=RunStatus.CANCELLING,
        stage_state=StageState.RUNNING,
    )
    cancellation_token = random_token(32)
    async with session_factory() as db:
        pending_stage = AnalysisStage(
            analysis_run_id=cancelling_run.id,
            stage_type=StageType.C2_ANALYSIS,
            state=StageState.WAITING,
        )
        cancellation_attempt = AnalysisAttempt(
            stage_id=cancelling_stage.id,
            executor_id=executor.id,
            attempt_number=1,
            state=AttemptState.RUNNING,
        )
        db.add_all([pending_stage, cancellation_attempt])
        await db.flush()
        cancellation_lease = ExecutorLease(
            stage_id=cancelling_stage.id,
            attempt_id=cancellation_attempt.id,
            executor_id=executor.id,
            token_hash=token_hash(cancellation_token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=1),
        )
        db.add(cancellation_lease)
        await db.commit()

    heartbeat_body: dict[str, object] = {
        "lease_id": str(cancellation_lease.id),
        "attempt_id": str(cancellation_attempt.id),
        "state": "running",
    }
    heartbeat_path = f"/api/internal/v1/stages/{cancelling_stage.id}/heartbeat"
    ack_body: dict[str, object] = {
        "lease_id": str(cancellation_lease.id),
        "attempt_id": str(cancellation_attempt.id),
        "detail": "native task stopped",
    }
    ack_path = f"/api/internal/v1/stages/{cancelling_stage.id}/cancellation-ack"
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        heartbeat = await client.post(
            heartbeat_path,
            json=heartbeat_body,
            headers=signed_headers(
                private,
                heartbeat_path,
                heartbeat_body,
                credential,
                cancellation_token,
            ),
        )
        assert heartbeat.status_code == 200, heartbeat.text
        assert heartbeat.json()["stop_requested"] == "cancelled"
        acknowledged = await client.post(
            ack_path,
            json=ack_body,
            headers=signed_headers(
                private,
                ack_path,
                ack_body,
                credential,
                cancellation_token,
            ),
        )
        assert acknowledged.status_code == 200, acknowledged.text
        assert acknowledged.json()["run_status"] == "terminal"
    async with session_factory() as db:
        refreshed_run = await db.get(AnalysisRun, cancelling_run.id)
        assert refreshed_run and refreshed_run.result.value == "cancelled"
        refreshed_pending = await db.get(AnalysisStage, pending_stage.id)
        assert refreshed_pending and refreshed_pending.state == StageState.CANCELLED
