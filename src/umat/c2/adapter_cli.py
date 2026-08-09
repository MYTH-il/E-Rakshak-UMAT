from __future__ import annotations

import asyncio
from uuid import UUID

import typer

from umat.c2.adapter import C2Adapter
from umat.config import get_settings
from umat.db.session import session_factory
from umat.storage import LocalArtifactStore

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Adapt validated C2 bundles into normalized UMAT records."""


async def _adapt(run_id: UUID) -> str:
    settings = get_settings()
    adapter = C2Adapter(LocalArtifactStore(settings.quarantine_root, settings.artifact_root))
    async with session_factory() as db:
        adaptation = await adapter.adapt_run(db, run_id)
        return str(adaptation.id)


@app.command()
def adapt(run_id: UUID = typer.Option(..., help="Analysis run UUID")) -> None:
    """Validate and normalize a completed C2 bundle for a run."""
    typer.echo(asyncio.run(_adapt(run_id)))


if __name__ == "__main__":
    app()
