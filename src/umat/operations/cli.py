from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import typer

from umat.config import get_settings
from umat.operations.backup import (
    BackupError,
    create_backup,
    restore_backup,
    rollback_restore,
    verify_backup,
)
from umat.operations.offline import (
    OfflineBundleError,
    create_offline_manifest,
    verify_offline_bundle,
)

app = typer.Typer(no_args_is_help=True, help="UMAT Phase 6 operational controls.")
backup_app = typer.Typer(no_args_is_help=True)
app.add_typer(backup_app, name="backup")
offline_app = typer.Typer(no_args_is_help=True)
app.add_typer(offline_app, name="offline")


@offline_app.command("verify")
def offline_verify(
    path: Path,
    manifest_sha256: str = typer.Option(..., help="Digest delivered separately from the bundle"),
) -> None:
    try:
        manifest = verify_offline_bundle(path, manifest_sha256)
    except OfflineBundleError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"verified offline bundle: {len(manifest['files'])} files")


@offline_app.command("seal")
def offline_seal(path: Path) -> None:
    try:
        manifest, digest = create_offline_manifest(path)
    except OfflineBundleError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"{manifest}\nsha256={digest}")


@backup_app.command("create")
def backup_create(
    destination: Path = typer.Option(Path("/var/lib/umat-backups")),
    backup_id: str | None = typer.Option(None),
) -> None:
    settings = get_settings()
    identifier = backup_id or datetime.now(timezone.utc).strftime("umat-%Y%m%dT%H%M%SZ")
    try:
        result = create_backup(
            database_url=settings.database_url,
            artifact_root=settings.artifact_root,
            backup_root=destination,
            backup_id=identifier,
        )
    except BackupError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(str(result))


@backup_app.command("verify")
def backup_verify(path: Path) -> None:
    try:
        manifest = verify_backup(path)
    except BackupError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"verified {manifest['backup_id']}: {len(manifest['artifacts'])} artifacts")


@backup_app.command("restore")
def backup_restore(
    path: Path,
    confirm_backup_id: str = typer.Option(...),
    execute: bool = typer.Option(False, "--execute", help="Perform the destructive restore"),
) -> None:
    if not execute:
        raise typer.BadParameter("restore requires --execute")
    settings = get_settings()
    try:
        recovery = restore_backup(
            database_url=settings.database_url,
            artifact_root=settings.artifact_root,
            root=path,
            expected_backup_id=confirm_backup_id,
        )
    except BackupError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"restored {confirm_backup_id}; rollback set: {recovery}")


@backup_app.command("rollback")
def backup_rollback(
    recovery: Path,
    confirm_restore_id: str = typer.Option(...),
    execute: bool = typer.Option(False, "--execute", help="Perform the destructive rollback"),
) -> None:
    if not execute:
        raise typer.BadParameter("rollback requires --execute")
    settings = get_settings()
    try:
        displaced = rollback_restore(
            database_url=settings.database_url,
            artifact_root=settings.artifact_root,
            recovery=recovery,
            expected_backup_id=confirm_restore_id,
        )
    except BackupError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(f"rolled back {confirm_restore_id}; displaced artifacts: {displaced}")
