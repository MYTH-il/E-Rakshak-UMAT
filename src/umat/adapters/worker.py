from __future__ import annotations

import asyncio

import typer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.android.adapter import AndroidAdapter
from umat.c2.adapter import C2Adapter
from umat.config import get_settings
from umat.db.models import AnalysisRun, AnalysisStage, Platform, StageState, StageType
from umat.db.session import session_factory
from umat.storage import LocalArtifactStore
from umat.windows.adapter import WindowsAdapter

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Normalize queued, validated platform and C2 bundles."""


async def process_once(db: AsyncSession) -> bool:
    stage = await db.scalar(
        select(AnalysisStage)
        .where(
            AnalysisStage.stage_type.in_(
                [StageType.PLATFORM_ADAPTATION, StageType.C2_ADAPTATION]
            ),
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
    settings = get_settings()
    store = LocalArtifactStore(settings.quarantine_root, settings.artifact_root)
    try:
        if stage.stage_type == StageType.C2_ADAPTATION:
            await C2Adapter(store).adapt_run(db, run.id)
        elif run.platform == Platform.ANDROID:
            await AndroidAdapter(store, settings.android_max_bundle_bytes).adapt_run(db, run.id)
        else:
            if settings.winstdt_schema_root is None:
                raise RuntimeError("UMAT_WINSTDT_SCHEMA_ROOT is required for Windows adaptation")
            await WindowsAdapter(
                store, settings.winstdt_schema_root, settings.windows_max_bundle_bytes
            ).adapt_run(db, run.id)
    except Exception as exc:
        await db.rollback()
        failed = await db.get(AnalysisStage, stage.id, with_for_update=True)
        if failed:
            failed.state = StageState.FAILED
            failed.failure_code = "adaptation_failed"
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


if __name__ == "__main__":
    app()
