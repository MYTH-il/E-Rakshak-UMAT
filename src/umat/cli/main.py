from __future__ import annotations

import typer

from umat.cli.admin import app as admin_app
from umat.deployment.startup import report_deployment_status, start_system
from umat.operations.cli import app as operations_app

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Unified Malware Analysis and Triage operator command line.",
)
app.add_typer(admin_app, name="admin", help="Manage users, executors, and audit state.")
app.add_typer(operations_app, name="ops", help="Run backup and offline-media operations.")


@app.command("start")
def start(
    timeout: float = typer.Option(
        120.0,
        min=1.0,
        help="Seconds to wait for each local health endpoint.",
    ),
    skip_status: bool = typer.Option(
        False,
        help="Skip the final comprehensive deployment status gate.",
    ),
) -> None:
    """Start the installed system after a host boot."""
    start_system(timeout=timeout, skip_status=skip_status)


@app.command("status")
def status() -> None:
    """Show a concise deployment qualification summary."""
    if not report_deployment_status():
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
