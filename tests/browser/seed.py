from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from umat.auth.security import hash_password
from umat.db.models import (
    AnalysisRun,
    AnalysisStage,
    Case,
    CaseReportSnapshot,
    CaseSample,
    Platform,
    Role,
    RunResult,
    RunStatus,
    Sample,
    StageState,
    StageType,
    Submission,
    User,
    Verdict,
)
from umat.db.session import session_factory

PASSWORD = "browser-verification-password"  # noqa: S105


def report(run: AnalysisRun, sample_sha256: str, headline: str) -> dict[str, object]:
    return {
        "schema_version": "1.1",
        "analysis_run_id": str(run.id),
        "platform": "windows",
        "sample_sha256": sample_sha256,
        "verdict": "suspicious",
        "headline": headline,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "information_accessed": [],
        "destinations": [],
        "provenance": [],
        "caveats": ["network_responses_simulated"],
        "artifacts": [],
        "integrity": {
            "validated_bundle_count": 1,
            "registered_artifact_count": 0,
            "bundle_hashes": [],
        },
        "technical": {
            "findings": [
                {
                    "summary": f"Technical finding for {headline}",
                    "source": "browser_fixture",
                    "kind": "behavior",
                    "confidence": "strong",
                    "evidence_level": "observed",
                    "security_mappings": [],
                }
            ],
            "iocs": [],
            "timeline": [],
        },
    }


async def seed() -> None:
    async with session_factory() as db:
        roles = {
            role.name: role
            for role in (await db.scalars(select(Role))).all()
        }
        users: dict[str, User] = {}
        for role_name in ("officer", "analyst", "administrator"):
            username = f"browser-{role_name}"
            user = await db.scalar(select(User).where(User.username == username))
            if user is None:
                user = User(
                    username=username,
                    password_hash=hash_password(PASSWORD),
                    roles=[roles[role_name]],
                )
                db.add(user)
                await db.flush()
            else:
                user.password_hash = hash_password(PASSWORD)
                user.enabled = True
            users[role_name] = user

        failed_case = await db.scalar(select(Case).where(Case.reference == "BROWSER-FAILED"))
        if failed_case is None:
            failed_content = b"MZ browser failed run fixture"
            failed_sha256 = hashlib.sha256(failed_content).hexdigest()
            failed_sample = Sample(
                sha256=failed_sha256,
                size_bytes=len(failed_content),
                media_type="application/octet-stream",
                object_key=f"browser-fixtures/{failed_sha256}",
            )
            failed_case = Case(
                owner_user_id=users["officer"].id,
                title="Browser failed analysis",
                reference="BROWSER-FAILED",
            )
            db.add_all([failed_sample, failed_case])
            await db.flush()
            failed_submission = Submission(
                case_id=failed_case.id,
                uploader_user_id=users["officer"].id,
                sample_sha256=failed_sha256,
                original_filename="browser-failed.exe",
            )
            db.add_all(
                [
                    failed_submission,
                    CaseSample(case_id=failed_case.id, sample_sha256=failed_sha256),
                ]
            )
            await db.flush()
            failed_run = AnalysisRun(
                case_id=failed_case.id,
                submission_id=failed_submission.id,
                platform=Platform.WINDOWS,
                status=RunStatus.TERMINAL,
                result=RunResult.FAILED,
            )
            db.add(failed_run)
            await db.flush()
            db.add(
                AnalysisStage(
                    analysis_run_id=failed_run.id,
                    stage_type=StageType.PLATFORM_ANALYSIS,
                    state=StageState.FAILED,
                    failure_code="browser_fixture_failure",
                    failure_detail="The backend was unavailable during the fixture run.",
                )
            )

        existing = await db.scalar(
            select(Case).where(Case.title == "Browser report selection")
        )
        if existing is not None:
            await db.commit()
            return

        sample_content = b"MZ browser report fixture"
        sample_sha256 = hashlib.sha256(sample_content).hexdigest()
        sample = Sample(
            sha256=sample_sha256,
            size_bytes=len(sample_content),
            media_type="application/octet-stream",
            object_key=f"browser-fixtures/{sample_sha256}",
        )
        case = Case(
            owner_user_id=users["officer"].id,
            title="Browser report selection",
            reference="BROWSER-REPORT",
        )
        db.add_all([sample, case])
        await db.flush()
        submission = Submission(
            case_id=case.id,
            uploader_user_id=users["officer"].id,
            sample_sha256=sample_sha256,
            original_filename="browser-report.exe",
        )
        db.add_all([submission, CaseSample(case_id=case.id, sample_sha256=sample_sha256)])
        await db.flush()

        now = datetime.now(timezone.utc)
        for revision, headline in ((1, "First browser report"), (2, "Second browser report")):
            run = AnalysisRun(
                case_id=case.id,
                submission_id=submission.id,
                platform=Platform.WINDOWS,
                status=RunStatus.TERMINAL,
                result=RunResult.COMPLETED,
                confirmed_at=now - timedelta(minutes=3 - revision),
                created_at=now - timedelta(minutes=3 - revision),
            )
            db.add(run)
            await db.flush()
            document = report(run, sample_sha256, headline)
            db.add(
                CaseReportSnapshot(
                    case_id=case.id,
                    analysis_run_id=run.id,
                    schema_version="1.1",
                    revision=1,
                    verdict=Verdict.SUSPICIOUS,
                    headline=headline,
                    report_json=document,
                    evidence_digest=hashlib.sha256(repr(document).encode()).hexdigest(),
                    generated_at=now - timedelta(minutes=3 - revision),
                )
            )
        await db.commit()


if __name__ == "__main__":
    asyncio.run(seed())
