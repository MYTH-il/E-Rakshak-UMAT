from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import typer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.audit import append_audit
from umat.config import get_settings
from umat.db.models import (
    AnalysisRun,
    AnalysisStage,
    CaseReportSnapshot,
    RunResult,
    RunStatus,
    StageState,
    StageType,
    Verdict,
)
from umat.db.session import session_factory
from umat.reporting.aggregator import CaseAggregator

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Materialize queued case reports."""


async def _ensure_ready_aggregation_stages(db: AsyncSession) -> None:
    runs = list(
        (
            await db.scalars(
                select(AnalysisRun)
                .where(AnalysisRun.status == RunStatus.RUNNING)
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    for run in runs:
        stages = list(
            (
                await db.scalars(
                    select(AnalysisStage).where(AnalysisStage.analysis_run_id == run.id)
                )
            ).all()
        )
        by_type = {item.stage_type: item for item in stages}
        required = (
            [StageType.PLATFORM_ADAPTATION]
            if not run.c2_analysis_enabled
            else [StageType.PLATFORM_ADAPTATION, StageType.C2_ADAPTATION]
        )
        if (
            all(
                stage_type in by_type and by_type[stage_type].state == StageState.COMPLETED
                for stage_type in required
            )
            and StageType.CASE_AGGREGATION not in by_type
        ):
            max_attempts, timeout_seconds = get_settings().policy_for_stage(
                StageType.CASE_AGGREGATION.value
            )
            db.add(
                AnalysisStage(
                    analysis_run_id=run.id,
                    stage_type=StageType.CASE_AGGREGATION,
                    state=StageState.QUEUED,
                    max_attempts=max_attempts,
                    timeout_seconds=timeout_seconds,
                )
            )
    await db.flush()


async def process_once(db: AsyncSession) -> bool:
    await _ensure_ready_aggregation_stages(db)
    stage = await db.scalar(
        select(AnalysisStage)
        .where(
            AnalysisStage.stage_type.in_([StageType.CASE_AGGREGATION, StageType.REPORT_GENERATION]),
            AnalysisStage.state == StageState.QUEUED,
        )
        .order_by(AnalysisStage.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if not stage:
        await db.commit()
        return False
    run = await db.get(AnalysisRun, stage.analysis_run_id)
    if not run:
        stage.state = StageState.FAILED
        stage.failure_code = "run_missing"
        await db.commit()
        return True
    stage.state = StageState.RUNNING
    stage.updated_at = datetime.now(timezone.utc)
    try:
        if stage.stage_type == StageType.CASE_AGGREGATION:
            snapshot = await CaseAggregator().aggregate(db, run.id)
            stage.state = StageState.COMPLETED
            report_stage = await db.scalar(
                select(AnalysisStage).where(
                    AnalysisStage.analysis_run_id == run.id,
                    AnalysisStage.stage_type == StageType.REPORT_GENERATION,
                )
            )
            if not report_stage:
                max_attempts, timeout_seconds = get_settings().policy_for_stage(
                    StageType.REPORT_GENERATION.value
                )
                db.add(
                    AnalysisStage(
                        analysis_run_id=run.id,
                        stage_type=StageType.REPORT_GENERATION,
                        state=StageState.QUEUED,
                        max_attempts=max_attempts,
                        timeout_seconds=timeout_seconds,
                    )
                )
            await append_audit(
                db,
                actor_type="system",
                actor_id="report-worker",
                action="case.aggregated",
                target_type="case_report_snapshot",
                target_id=str(snapshot.id),
                payload={"run_id": str(run.id), "verdict": snapshot.verdict.value},
            )
        else:
            existing_snapshot = await db.scalar(
                select(CaseReportSnapshot)
                .where(CaseReportSnapshot.analysis_run_id == run.id)
                .order_by(CaseReportSnapshot.revision.desc())
                .limit(1)
            )
            if not existing_snapshot:
                raise ValueError("report snapshot is unavailable")
            stage.state = StageState.COMPLETED
            run.status = RunStatus.TERMINAL
            if existing_snapshot.verdict == Verdict.FAILED:
                run.result = RunResult.FAILED
            elif existing_snapshot.verdict == Verdict.INCONCLUSIVE:
                run.result = RunResult.INCONCLUSIVE
            elif run.result != RunResult.PARTIAL:
                run.result = RunResult.COMPLETED
            await append_audit(
                db,
                actor_type="system",
                actor_id="report-worker",
                action="report.generated",
                target_type="case_report_snapshot",
                target_id=str(existing_snapshot.id),
                payload={"run_id": str(run.id), "revision": existing_snapshot.revision},
            )
        stage.updated_at = datetime.now(timezone.utc)
        await db.commit()
    except Exception as exc:
        await db.rollback()
        failed = await db.get(AnalysisStage, stage.id, with_for_update=True)
        if failed:
            failed.state = StageState.FAILED
            failed.failure_code = "report_processing_failed"
            failed.failure_detail = str(exc)[:2000]
        await db.commit()
        raise
    return True


async def run_worker(once: bool, poll_seconds: float) -> None:
    while True:
        async with session_factory() as db:
            processed = await process_once(db)
        if once:
            return
        if not processed:
            await asyncio.sleep(poll_seconds)


@app.command("run")
def run(
    once: bool = typer.Option(False, "--once"),
    poll_seconds: float = typer.Option(2.0, min=0.1, max=60.0),
) -> None:
    asyncio.run(run_worker(once, poll_seconds))
