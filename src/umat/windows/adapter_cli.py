from __future__ import annotations

import asyncio
from uuid import UUID

import typer

from umat.config import get_settings
from umat.db.session import session_factory
from umat.storage import LocalArtifactStore
from umat.windows.adapter import WindowsAdapter

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Adapt validated Windows bundles into normalized UMAT records."""


async def _adapt(run_id: UUID) -> str:
    settings = get_settings()
    if settings.winstdt_schema_root is None:
        raise typer.BadParameter("UMAT_WINSTDT_SCHEMA_ROOT is required")
    adapter = WindowsAdapter(
        LocalArtifactStore(settings.quarantine_root, settings.artifact_root),
        settings.winstdt_schema_root,
        settings.windows_max_bundle_bytes,
    )
    async with session_factory() as db:
        return str((await adapter.adapt_run(db, run_id)).id)


@app.command()
def adapt(run_id: UUID = typer.Option(...)) -> None:
    typer.echo(asyncio.run(_adapt(run_id)))


if __name__ == "__main__":
    app()
