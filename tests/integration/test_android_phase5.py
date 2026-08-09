from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"), reason="requires a migrated PostgreSQL test database"
)

from umat.android.adapter import AndroidAdapter  # noqa: E402
from umat.android.bundle import AndroidBundleBuilder, sha256_file  # noqa: E402
from umat.auth.security import hash_password  # noqa: E402
from umat.config import get_settings  # noqa: E402
from umat.db.models import (  # noqa: E402
    AccessTier,
    AnalysisAttempt,
    AnalysisRun,
    AnalysisStage,
    AndroidAnalysisMetadata,
    AndroidCapability,
    Artifact,
    AttemptState,
    Case,
    CaseSample,
    Executor,
    ExecutorStatus,
    Platform,
    Role,
    RunStatus,
    Sample,
    StageState,
    StageType,
    Submission,
    User,
)
from umat.db.session import session_factory  # noqa: E402
from umat.storage import LocalArtifactStore  # noqa: E402


@pytest.mark.asyncio
async def test_signed_android_bundle_adapts_to_normalized_records(tmp_path: Path) -> None:
    suffix = uuid.uuid4().hex[:10]
    sample_sha = hashlib.sha256(suffix.encode()).hexdigest()
    key = Ed25519PrivateKey.generate()
    settings = get_settings()
    store = LocalArtifactStore(settings.quarantine_root, settings.artifact_root)

    async with session_factory() as db:
        analyst_role = await db.scalar(select(Role).where(Role.name == "analyst"))
        assert analyst_role
        user = User(
            username=f"android-analyst-{suffix}",
            password_hash=hash_password("android-test-password"),  # noqa: S106
            roles=[analyst_role],
        )
        executor = Executor(
            name=f"android-executor-{suffix}",
            executor_type="android",
            status=ExecutorStatus.ACTIVE,
            public_key=key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            supported_stage_types=["platform_analysis"],
            metadata_json={},
        )
        db.add_all([user, executor])
        await db.flush()
        case = Case(owner_user_id=user.id, title="Android Phase 5", reference=suffix)
        sample = Sample(
            sha256=sample_sha,
            size_bytes=3,
            media_type="application/vnd.android.package-archive",
            object_key=f"test/android/{suffix}",
        )
        db.add_all([case, sample])
        await db.flush()
        submission = Submission(
            case_id=case.id,
            uploader_user_id=user.id,
            sample_sha256=sample_sha,
            original_filename="fixture.apk",
        )
        db.add_all([submission, CaseSample(case_id=case.id, sample_sha256=sample_sha)])
        await db.flush()
        run = AnalysisRun(
            case_id=case.id,
            submission_id=submission.id,
            platform=Platform.ANDROID,
            status=RunStatus.RUNNING,
        )
        db.add(run)
        await db.flush()
        platform_stage = AnalysisStage(
            analysis_run_id=run.id,
            stage_type=StageType.PLATFORM_ANALYSIS,
            state=StageState.COMPLETED,
        )
        adaptation_stage = AnalysisStage(
            analysis_run_id=run.id,
            stage_type=StageType.PLATFORM_ADAPTATION,
            state=StageState.QUEUED,
        )
        db.add_all([platform_stage, adaptation_stage])
        await db.flush()
        attempt = AnalysisAttempt(
            stage_id=platform_stage.id,
            executor_id=executor.id,
            attempt_number=1,
            state=AttemptState.COMPLETED,
        )
        db.add(attempt)
        await db.flush()

        static = tmp_path / "static.json"
        dynamic = tmp_path / "dynamic.json"
        pcap = tmp_path / "capture.pcap"
        static.write_text(
            json.dumps(
                {
                    "package_name": "org.example.fixture",
                    "permissions": {"android.permission.READ_CONTACTS": {}},
                    "manifest_analysis": [
                        {"rule": "exported", "severity": "high", "title": "Exported component"}
                    ],
                }
            )
        )
        dynamic.write_text(json.dumps({"api_monitor": [{"class": "ContactsContract"}]}))
        pcap.write_bytes(b"pcap fixture")
        started = datetime.now(timezone.utc)
        built = AndroidBundleBuilder(key, str(executor.id)).build(
            analysis_run_id=run.id,
            sample_sha256=sample_sha,
            scan_hash="b" * 32,
            analysis_started_at=started,
            analysis_ended_at=started + timedelta(seconds=10),
            emulator={"api_level": 30, "avd_name": "umat-integration", "guest_ip": "10.0.2.15"},
            static_report=static,
            dynamic_report=dynamic,
            evidence={"pcap": pcap},
            stimulation={"strategy": "deterministic_adb_v1", "complete": True},
            caveats=["c2_network_only"],
            destination=tmp_path / "android-bundle",
        )
        digest = sha256_file(built.archive_path)
        stored = store.store_file(built.archive_path, digest, built.archive_path.stat().st_size)
        db.add(
            Artifact(
                analysis_run_id=run.id,
                stage_id=platform_stage.id,
                attempt_id=attempt.id,
                kind="android_bundle",
                sha256=digest,
                size_bytes=stored.size_bytes,
                media_type="application/zip",
                object_key=stored.object_key,
                access_tier=AccessTier.ANALYST,
            )
        )
        await db.commit()

        adaptation = await AndroidAdapter(store, 10 * 1024 * 1024).adapt_run(db, run.id)
        metadata = await db.scalar(
            select(AndroidAnalysisMetadata).where(
                AndroidAnalysisMetadata.adaptation_id == adaptation.id
            )
        )
        capabilities = list(
            (
                await db.scalars(
                    select(AndroidCapability).where(
                        AndroidCapability.adaptation_id == adaptation.id
                    )
                )
            ).all()
        )
        assert metadata and metadata.package_name == "org.example.fixture"
        assert metadata.dynamic_completed is True
        assert [(item.data_type, item.evidence_level) for item in capabilities] == [
            ("contacts", "observed")
        ]
