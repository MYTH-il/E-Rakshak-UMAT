from __future__ import annotations

import hashlib
import os
import uuid

import httpx
import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import DBAPIError

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"), reason="requires a migrated PostgreSQL test database"
)

from umat.api.app import app  # noqa: E402
from umat.auth.security import hash_password  # noqa: E402
from umat.config import get_settings  # noqa: E402
from umat.contracts import validate_contract  # noqa: E402
from umat.db.models import (  # noqa: E402
    AccessTier,
    AdaptationRecord,
    AnalysisRun,
    AnalysisStage,
    Artifact,
    C2Finding,
    Case,
    CaseReportSnapshot,
    CaseSample,
    ExfilEvent,
    NetworkObservation,
    Platform,
    ProvenanceLink,
    Role,
    RunStatus,
    Sample,
    StageState,
    StageType,
    StaticIOC,
    Submission,
    TimelineEvent,
    User,
    WindowsCapability,
    WindowsFinding,
)
from umat.db.session import session_factory  # noqa: E402
from umat.reporting.worker import process_once  # noqa: E402
from umat.storage.local import LocalArtifactStore  # noqa: E402


def _stored_fixture(content: bytes, tmp_path):  # type: ignore[no-untyped-def]
    path = tmp_path / f"phase4-{uuid.uuid4().hex}.bin"
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    settings = get_settings()
    return LocalArtifactStore(settings.quarantine_root, settings.artifact_root).store_file(
        path, digest, len(content)
    )


@pytest.mark.asyncio
async def test_unified_report_rbac_exports_and_terminal_workflow(tmp_path) -> None:  # type: ignore[no-untyped-def]
    suffix = uuid.uuid4().hex[:10]
    password = "phase-four-integration-password"  # noqa: S105
    windows_object = _stored_fixture(b"windows-phase4-bundle", tmp_path)
    c2_object = _stored_fixture(b"c2-phase4-bundle", tmp_path)
    async with session_factory() as db:
        officer_role = await db.scalar(select(Role).where(Role.name == "officer"))
        analyst_role = await db.scalar(select(Role).where(Role.name == "analyst"))
        assert officer_role and analyst_role
        officer = User(
            username=f"phase4-officer-{suffix}",
            password_hash=hash_password(password),
            roles=[officer_role],
        )
        analyst = User(
            username=f"phase4-analyst-{suffix}",
            password_hash=hash_password(password),
            roles=[analyst_role],
        )
        db.add_all([officer, analyst])
        await db.flush()
        sample_hash = hashlib.sha256(f"sample-{suffix}".encode()).hexdigest()
        db.add(
            Sample(
                sha256=sample_hash,
                size_bytes=20,
                media_type="application/octet-stream",
                object_key=f"objects/sha256/{sample_hash[:2]}/{sample_hash[2:]}",
            )
        )
        case = Case(owner_user_id=officer.id, title="Unified fixture", reference=f"P4-{suffix}")
        db.add(case)
        await db.flush()
        submission = Submission(
            case_id=case.id,
            uploader_user_id=officer.id,
            sample_sha256=sample_hash,
            original_filename="fixture.exe",
        )
        db.add(submission)
        db.add(CaseSample(case_id=case.id, sample_sha256=sample_hash))
        await db.flush()
        run = AnalysisRun(
            case_id=case.id,
            submission_id=submission.id,
            platform=Platform.WINDOWS,
            status=RunStatus.RUNNING,
        )
        db.add(run)
        await db.flush()
        stages = {
            stage_type: AnalysisStage(
                analysis_run_id=run.id,
                stage_type=stage_type,
                state=StageState.COMPLETED
                if stage_type != StageType.CASE_AGGREGATION
                else StageState.QUEUED,
            )
            for stage_type in (
                StageType.PLATFORM_ANALYSIS,
                StageType.C2_ANALYSIS,
                StageType.PLATFORM_ADAPTATION,
                StageType.C2_ADAPTATION,
                StageType.CASE_AGGREGATION,
            )
        }
        db.add_all(stages.values())
        await db.flush()
        windows_artifact = Artifact(
            analysis_run_id=run.id,
            stage_id=stages[StageType.PLATFORM_ANALYSIS].id,
            kind="windows_bundle",
            sha256=windows_object.sha256,
            size_bytes=windows_object.size_bytes,
            media_type="application/zip",
            object_key=windows_object.object_key,
            access_tier=AccessTier.ANALYST,
        )
        c2_artifact = Artifact(
            analysis_run_id=run.id,
            stage_id=stages[StageType.C2_ANALYSIS].id,
            kind="c2_bundle",
            sha256=c2_object.sha256,
            size_bytes=c2_object.size_bytes,
            media_type="application/zip",
            object_key=c2_object.object_key,
            access_tier=AccessTier.ANALYST,
        )
        db.add_all([windows_artifact, c2_artifact])
        await db.flush()
        windows_adaptation = AdaptationRecord(
            analysis_run_id=run.id,
            stage_id=stages[StageType.PLATFORM_ADAPTATION].id,
            source_artifact_id=windows_artifact.id,
            adapter_type="windows",
            schema_version="1.0",
            active=True,
            validation_summary={"caveats": []},
        )
        c2_adaptation = AdaptationRecord(
            analysis_run_id=run.id,
            stage_id=stages[StageType.C2_ADAPTATION].id,
            source_artifact_id=c2_artifact.id,
            adapter_type="c2",
            schema_version="1.3",
            active=True,
            validation_summary={"caveats": []},
        )
        db.add_all([windows_adaptation, c2_adaptation])
        await db.flush()
        db.add(
            WindowsFinding(
                adaptation_id=windows_adaptation.id,
                analysis_run_id=run.id,
                category="behavior",
                kind="persistence",
                confidence="strong",
                summary="The sample established persistence.",
                details={"mitre_technique_id": "T1547"},
            )
        )
        db.add(
            WindowsCapability(
                adaptation_id=windows_adaptation.id,
                analysis_run_id=run.id,
                capability="browser_credentials",
                source="access_events",
                confidence="confirmed",
                details={},
            )
        )
        db.add(
            C2Finding(
                adaptation_id=c2_adaptation.id,
                analysis_run_id=run.id,
                stage_id=stages[StageType.C2_ADAPTATION].id,
                source_event_id=f"event-{suffix}",
                finding_kind="beacon",
                plain_language="The sample repeatedly contacted a remote server.",
                confidence="strong",
                platform=Platform.WINDOWS,
                details={"mitre_technique_id": "T1071"},
            )
        )
        db.add(
            NetworkObservation(
                adaptation_id=c2_adaptation.id,
                analysis_run_id=run.id,
                source_event_id=f"event-{suffix}",
                destination_ip="198.51.100.20",
                destination_port=443,
                destination_domain="phase4.invalid",
                protocol="tcp",
                observed_at=run.created_at,
                details={},
            )
        )
        db.add(
            ExfilEvent(
                adaptation_id=c2_adaptation.id,
                analysis_run_id=run.id,
                source_event_id=f"event-{suffix}",
                data_type_accessed="browser_credentials",
                destination="phase4.invalid",
                confidence="strong",
                evidence_hash="a" * 64,
                details={},
            )
        )
        db.add(
            StaticIOC(
                adaptation_id=c2_adaptation.id,
                analysis_run_id=run.id,
                ioc_type="domain",
                value="=phase4.invalid",
                confidence="strong",
                source="c2-runtime",
                seen_in_traffic=True,
            )
        )
        db.add(
            ProvenanceLink(
                adaptation_id=c2_adaptation.id,
                analysis_run_id=run.id,
                source_event_id=f"event-{suffix}",
                item_type="browser_credentials",
                destination="phase4.invalid",
                statement="Credential access preceded communication with phase4.invalid.",
                details={},
            )
        )
        db.add(
            TimelineEvent(
                adaptation_id=c2_adaptation.id,
                analysis_run_id=run.id,
                occurred_at=run.created_at,
                actor="network",
                description="Outbound TLS connection observed.",
                mitre_technique_id="T1071",
                details={},
            )
        )
        await db.commit()
        case_id = case.id

        snapshot = None
        run_status = None
        for _ in range(20):
            async with session_factory() as db:
                await process_once(db)
            async with session_factory() as db:
                snapshot = await db.scalar(
                    select(CaseReportSnapshot).where(CaseReportSnapshot.analysis_run_id == run.id)
                )
                refreshed_run = await db.get(AnalysisRun, run.id)
                run_status = refreshed_run.status if refreshed_run else None
            if snapshot is not None and run_status == RunStatus.TERMINAL:
                break
        assert snapshot is not None
        assert run_status == RunStatus.TERMINAL

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as officer_client:
        login = await officer_client.post(
            "/api/v1/auth/login",
            json={"username": f"phase4-officer-{suffix}", "password": password},
        )
        assert login.status_code == 200
        csrf = {"X-CSRF-Token": login.json()["csrf_token"]}
        detail = await officer_client.get(f"/api/v1/cases/{case_id}")
        assert detail.status_code == 200, detail.text
        document = detail.json()
        assert document["report"]["verdict"] == "suspicious"
        assert "technical" not in document["report"]
        assert document["report"]["artifacts"] == []
        validate_contract("case-object.schema.json", document)
        for export_format, media_type in (
            ("json", "application/json"),
            ("pdf", "application/pdf"),
            ("csv", "text/csv"),
        ):
            created = await officer_client.post(
                f"/api/v1/cases/{case_id}/exports/{export_format}", headers=csrf
            )
            assert created.status_code == 201, created.text
            downloaded = await officer_client.get(created.json()["download_path"])
            assert downloaded.status_code == 200
            assert downloaded.headers["content-type"].startswith(media_type)
            assert downloaded.headers["content-disposition"].startswith("attachment")
            assert hashlib.sha256(downloaded.content).hexdigest() == created.json()["sha256"]
            if export_format == "json":
                assert b'"technical"' not in downloaded.content
            if export_format == "csv":
                assert b"'=phase4.invalid" in downloaded.content

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://testserver"
    ) as analyst_client:
        login = await analyst_client.post(
            "/api/v1/auth/login",
            json={"username": f"phase4-analyst-{suffix}", "password": password},
        )
        assert login.status_code == 200
        detail = await analyst_client.get(f"/api/v1/cases/{case_id}")
        assert detail.status_code == 200
        assert detail.json()["report"]["technical"]["findings"]
        assert len(detail.json()["report"]["artifacts"]) >= 2

    async with session_factory() as db:
        final_run = await db.get(AnalysisRun, run.id)
        assert final_run and final_run.status == RunStatus.TERMINAL
    async with session_factory() as db:
        with pytest.raises(DBAPIError):
            await db.execute(
                update(CaseReportSnapshot)
                .where(CaseReportSnapshot.analysis_run_id == run.id)
                .values(headline="mutation must fail")
            )
        await db.rollback()
