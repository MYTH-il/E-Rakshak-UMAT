from __future__ import annotations

import asyncio

import typer

from umat.api.executor_routes import expire_leases
from umat.db.session import session_factory

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Maintain PostgreSQL-backed leases and stage deadlines."""


async def process_once() -> int:
    async with session_factory() as db:
        expired = await expire_leases(db)
        await db.commit()
        return expired


async def run_worker(once: bool, poll_seconds: float) -> None:
    while True:
        await process_once()
        if once:
            return
        await asyncio.sleep(poll_seconds)


@app.command("run")
def run(
    once: bool = typer.Option(False, "--once"),
    poll_seconds: float = typer.Option(1.0, min=0.1, max=60.0),
) -> None:
    """Expire leases, enforce stage deadlines, and finalize abandoned cancellations."""
    asyncio.run(run_worker(once, poll_seconds))


if __name__ == "__main__":
    app()
