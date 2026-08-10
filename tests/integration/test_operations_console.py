from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"), reason="requires a migrated PostgreSQL test database"
)

from umat.api.app import app  # noqa: E402
from umat.auth.security import hash_password  # noqa: E402
from umat.db.models import (  # noqa: E402
    AnalysisAttempt,
    AnalysisRun,
    AnalysisStage,
    AndroidAnalysisProfile,
    AndroidProfileState,
    AttemptState,
    AuditEvent,
    BackendCapabilitySnapshot,
    Case,
    CaseSample,
    Executor,
    ExecutorLease,
    ExecutorStatus,
    Platform,
    Role,
    RunResult,
    RunStatus,
    Sample,
    StageState,
    StageType,
    Submission,
    User,
    WindowsProfileState,
    WindowsRunConfiguration,
    WindowsVMProfile,
)
from umat.db.session import session_factory  # noqa: E402


async def login(client: httpx.AsyncClient, username: str, password: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )
    assert response.status_code == 200, response.text
    return {"X-CSRF-Token": response.json()["csrf_token"]}


@pytest.mark.asyncio
async def test_operations_console_endpoints_cover_routine_diagnosis() -> None:
    suffix = uuid.uuid4().hex[:10]
    password = "operations-console-password"  # noqa: S105
    sample_sha256 = hashlib.sha256(f"operations-{suffix}".encode()).hexdigest()
    public_key = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    async with session_factory() as db:
        roles = {
            role.name: role
            for role in (
                await db.scalars(
                    select(Role).where(Role.name.in_(["officer", "analyst", "administrator"]))
                )
            ).all()
        }
        officer = User(
            username=f"operations-officer-{suffix}",
            password_hash=hash_password(password),
            roles=[roles["officer"]],
        )
        analyst = User(
            username=f"operations-analyst-{suffix}",
            password_hash=hash_password(password),
            roles=[roles["analyst"]],
        )
        administrator = User(
            username=f"operations-admin-{suffix}",
            password_hash=hash_password(password),
            roles=[roles["administrator"]],
        )
        db.add_all([officer, analyst, administrator])
        await db.flush()
        case = Case(
            owner_user_id=officer.id,
            title="Operations fixture",
            reference=f"OPS-{suffix}",
        )
        sample = Sample(
            sha256=sample_sha256,
            size_bytes=10,
            media_type="application/octet-stream",
            object_key=f"operations/{sample_sha256}",
        )
        db.add_all([case, sample])
        await db.flush()
        submission = Submission(
            case_id=case.id,
            uploader_user_id=officer.id,
            sample_sha256=sample.sha256,
            original_filename="failed.exe",
        )
        db.add_all([submission, CaseSample(case_id=case.id, sample_sha256=sample.sha256)])
        await db.flush()
        failed_run = AnalysisRun(
            case_id=case.id,
            submission_id=submission.id,
            platform=Platform.WINDOWS,
            status=RunStatus.TERMINAL,
            result=RunResult.FAILED,
        )
        db.add(failed_run)
        await db.flush()
        failed_stage = AnalysisStage(
            analysis_run_id=failed_run.id,
            stage_type=StageType.PLATFORM_ANALYSIS,
            state=StageState.FAILED,
            failure_code="backend_unavailable",
            failure_detail="fixture failure",
        )
        worker = Executor(
            name=f"operations-worker-{suffix}",
            executor_type="windows",
            status=ExecutorStatus.ACTIVE,
            public_key=public_key,
            supported_stage_types=["platform_analysis"],
            metadata_json={"zone": "fixture"},
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add_all([failed_stage, worker])
        await db.flush()
        attempt = AnalysisAttempt(
            stage_id=failed_stage.id,
            executor_id=worker.id,
            attempt_number=1,
            state=AttemptState.FAILED,
            error_code="backend_unavailable",
        )
        db.add(attempt)
        db.add(
            BackendCapabilitySnapshot(
                executor_id=worker.id,
                runtime_identity="winstdt-fixture@1",
                schema_version="1.0",
                capabilities={
                    "platforms": ["windows"],
                    "cape_native": True,
                    "handoff_schema": "1.0",
                },
            )
        )
        await db.flush()
        active_stage = AnalysisStage(
            analysis_run_id=failed_run.id,
            stage_type=StageType.REPORT_GENERATION,
            state=StageState.LEASED,
        )
        db.add(active_stage)
        await db.flush()
        active_attempt = AnalysisAttempt(
            stage_id=active_stage.id,
            executor_id=worker.id,
            attempt_number=1,
            state=AttemptState.LEASED,
        )
        db.add(active_attempt)
        await db.flush()
        db.add(
            ExecutorLease(
                stage_id=active_stage.id,
                attempt_id=active_attempt.id,
                executor_id=worker.id,
                token_hash=hashlib.sha256(f"lease-{suffix}".encode()).hexdigest(),
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            )
        )
        windows_profile = WindowsVMProfile(
            name=f"operations-windows-{suffix}",
            display_name="Operations Windows",
            state=WindowsProfileState.ACTIVE,
            windows_version="Windows 10 22H2",
            architecture="x64",
            vcpus=4,
            ram_mb=4096,
            disk_gb=160,
            user_profile={"username": "officer"},
            analysis_profile="standard",
            cape_template="win10-hardened",
            is_default=False,
            created_by_user_id=administrator.id,
        )
        android_profile = AndroidAnalysisProfile(
            name=f"operations-android-{suffix}",
            display_name="Operations Android",
            state=AndroidProfileState.ACTIVE,
            system_image="docker.io/redroid/redroid@sha256:"
            "d1ca0815eb68139a43d25a835e374559e9d18f5d5cea1a4288d4657c0074fb8d",
            emulator_version="redroid-11-d1ca0815",
            created_by_user_id=administrator.id,
        )
        db.add_all([windows_profile, android_profile])
        await db.flush()
        db.add(
            WindowsRunConfiguration(
                analysis_run_id=failed_run.id,
                profile_id=windows_profile.id,
                profile_snapshot=windows_profile.snapshot(),
                selected_by_user_id=analyst.id,
            )
        )
        await db.commit()
        case_id = case.id
        run_id = failed_run.id
        windows_profile_id = windows_profile.id
        android_profile_id = android_profile.id

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        officer_csrf = await login(client, officer.username, password)
        updated = await client.patch(
            f"/api/v1/cases/{case_id}",
            headers=officer_csrf,
            json={"title": "Updated operations fixture", "reference": f"UPDATED-{suffix}"},
        )
        assert updated.status_code == 200, updated.text
        assert updated.json()["title"] == "Updated operations fixture"
        added = await client.post(
            f"/api/v1/cases/{case_id}/submissions",
            headers=officer_csrf,
            files={"file": ("additional.exe", b"MZ additional fixture", "application/octet-stream")},
        )
        assert added.status_code == 201, added.text
        assert added.json()["case_id"] == str(case_id)

        recent = await client.get(
            "/api/v1/analysis-runs",
            params={"q": f"UPDATED-{suffix}", "status": "terminal", "page_size": 1},
        )
        assert recent.status_code == 200, recent.text
        assert recent.json()["total"] == 1
        item = recent.json()["items"][0]
        assert item["retry_eligible"] is True
        assert item["stages"][0]["attempt_count"] == 1
        unfiltered = await client.get("/api/v1/analysis-runs")
        assert unfiltered.status_code == 200
        assert unfiltered.json()["page_size"] == 10
        assert len(unfiltered.json()["items"]) <= 10
        forbidden_retry = await client.post(
            f"/api/v1/analysis-runs/{run_id}/retry",
            headers=officer_csrf,
            json={"reason": "operator requested retry"},
        )
        assert forbidden_retry.status_code == 403
        forbidden_workers = await client.get("/api/v1/admin/workers")
        assert forbidden_workers.status_code == 403

        await client.post("/api/v1/auth/logout", headers=officer_csrf)
        analyst_csrf = await login(client, analyst.username, password)
        retried = await client.post(
            f"/api/v1/analysis-runs/{run_id}/retry",
            headers=analyst_csrf,
            json={"reason": "backend recovered; preserve failed run and retry"},
        )
        assert retried.status_code == 200, retried.text
        assert retried.json()["source_run_id"] == str(run_id)
        assert retried.json()["status"] == "queued"

        await client.post("/api/v1/auth/logout", headers=analyst_csrf)
        admin_csrf = await login(client, administrator.username, password)
        workers = await client.get("/api/v1/admin/workers")
        assert workers.status_code == 200, workers.text
        worker_document = next(
            item for item in workers.json()["items"] if item["name"] == worker.name
        )
        assert worker_document["runtime_identity"] == "winstdt-fixture@1"
        assert worker_document["active_workload"] == 1
        assert worker_document["compatibility"]["compatible"] is True

        windows_detail = await client.get(f"/api/v1/windows/profiles/{windows_profile_id}")
        assert windows_detail.status_code == 200
        windows_updated = await client.patch(
            f"/api/v1/windows/profiles/{windows_profile_id}",
            headers=admin_csrf,
            json={"display_name": "Updated Windows", "is_default": True},
        )
        assert windows_updated.status_code == 200, windows_updated.text
        assert windows_updated.json()["is_default"] is True
        android_updated = await client.patch(
            f"/api/v1/android/profiles/{android_profile_id}",
            headers=admin_csrf,
            json={"display_name": "Updated Android", "vcpus": 6, "is_default": True},
        )
        assert android_updated.status_code == 200, android_updated.text
        assert android_updated.json()["vcpus"] == 6

    async with session_factory() as db:
        retry_audit = await db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "run.retry_created",
                AuditEvent.payload["source_run_id"].as_string() == str(run_id),
            )
        )
        assert retry_audit is not None
