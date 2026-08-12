from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from urllib.parse import unquote, urlsplit, urlunsplit

from umat.contracts.canonical import canonical_json


class BackupError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def database_connection(database_url: str) -> tuple[str, dict[str, str]]:
    """Return a libpq URL and environment without placing a password in argv."""
    normalized = database_url.replace("postgresql+asyncpg://", "postgresql://", 1).replace(
        "postgresql+psycopg://", "postgresql://", 1
    )
    parsed = urlsplit(normalized)
    if parsed.scheme not in {"postgresql", "postgres"}:
        raise BackupError("backup requires a PostgreSQL database URL")
    host = parsed.hostname or "127.0.0.1"
    netloc = host
    if parsed.port:
        netloc += f":{parsed.port}"
    if parsed.username:
        netloc = f"{parsed.username}@{netloc}"
    clean = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, ""))
    environment = os.environ.copy()
    if parsed.password:
        environment["PGPASSWORD"] = unquote(parsed.password)
    return clean, environment


def _run(command: list[str], *, environment: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(  # noqa: S603 - argv-only execution of fixed PostgreSQL tools
            command,
            check=True,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=3600,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = getattr(exc, "stderr", None) or str(exc)
        raise BackupError(f"command failed: {command[0]}: {detail[:1000]}") from exc


@dataclass(frozen=True)
class BackupPaths:
    root: Path
    database: Path
    artifacts: Path
    manifest: Path


def backup_paths(root: Path) -> BackupPaths:
    return BackupPaths(
        root=root,
        database=root / "database.dump",
        artifacts=root / "artifacts",
        manifest=root / "manifest.json",
    )


def _artifact_inventory(root: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    if not root.exists():
        return inventory
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        digest = sha256_file(path)
        # Content-addressed objects must agree with their path identity.
        parts = Path(relative).parts
        if len(parts) == 4 and parts[:2] == ("objects", "sha256"):
            expected = parts[2] + parts[3]
            if len(expected) == 64 and digest != expected:
                raise BackupError(f"artifact object identity mismatch: {relative}")
        inventory.append({"path": relative, "sha256": digest, "size_bytes": path.stat().st_size})
    return inventory


def create_backup(
    *, database_url: str, artifact_root: Path, backup_root: Path, backup_id: str
) -> Path:
    if not backup_id or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for character in backup_id
    ):
        raise BackupError("backup id must contain only lowercase letters, digits, '-' or '_'")
    destination = (backup_root / backup_id).resolve()
    backup_root = backup_root.resolve()
    if backup_root not in destination.parents or destination.exists():
        raise BackupError("backup destination exists or escapes backup root")
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix=f".{backup_id}-", dir=backup_root))
    try:
        paths = backup_paths(temporary)
        paths.artifacts.mkdir(mode=0o700)
        connection, environment = database_connection(database_url)
        _run(
            [
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "--file",
                str(paths.database),
                connection,
            ],
            environment=environment,
        )
        _run(["pg_restore", "--list", str(paths.database)])
        if artifact_root.exists():
            shutil.copytree(
                artifact_root, paths.artifacts, dirs_exist_ok=True, copy_function=shutil.copy2
            )
        artifacts = _artifact_inventory(paths.artifacts)
        manifest = {
            "schema_version": "1.0",
            "backup_id": backup_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "database": {
                "path": paths.database.name,
                "sha256": sha256_file(paths.database),
                "size_bytes": paths.database.stat().st_size,
                "format": "postgresql_custom",
            },
            "artifacts": artifacts,
        }
        paths.manifest.write_bytes(canonical_json(manifest) + b"\n")
        paths.manifest.chmod(0o400)
        os.replace(temporary, destination)
        return destination
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify_backup(root: Path) -> dict[str, Any]:
    paths = backup_paths(root.resolve())
    try:
        manifest = cast(dict[str, Any], json.loads(paths.manifest.read_text()))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("backup manifest is missing or invalid") from exc
    if manifest.get("schema_version") != "1.0" or manifest.get("backup_id") != root.name:
        raise BackupError("backup manifest identity mismatch")
    database = manifest.get("database") or {}
    if (
        not paths.database.is_file()
        or paths.database.stat().st_size != database.get("size_bytes")
        or sha256_file(paths.database) != database.get("sha256")
    ):
        raise BackupError("database dump digest mismatch")
    _run(["pg_restore", "--list", str(paths.database)])
    observed = _artifact_inventory(paths.artifacts)
    if observed != manifest.get("artifacts"):
        raise BackupError("artifact inventory mismatch")
    return manifest


def restore_backup(
    *, database_url: str, artifact_root: Path, root: Path, expected_backup_id: str
) -> Path:
    manifest = verify_backup(root)
    if manifest["backup_id"] != expected_backup_id:
        raise BackupError("restore confirmation does not match backup id")
    artifact_root = artifact_root.resolve()
    staging = artifact_root.with_name(f".{artifact_root.name}.restore-{expected_backup_id}")
    recovery = artifact_root.with_name(f".{artifact_root.name}.rollback-{expected_backup_id}")
    previous = recovery / "artifacts"
    recovery_database = recovery / "database.dump"
    if staging.exists() or recovery.exists():
        raise BackupError("restore staging or rollback path already exists")
    shutil.copytree(backup_paths(root).artifacts, staging, copy_function=shutil.copy2)
    connection, environment = database_connection(database_url)
    recovery.mkdir(mode=0o700)
    database_replaced = False
    try:
        _run(
            [
                "pg_dump",
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "--file",
                str(recovery_database),
                connection,
            ],
            environment=environment,
        )
        _run(["pg_restore", "--list", str(recovery_database)])
        _run(
            [
                "pg_restore",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--single-transaction",
                "--dbname",
                connection,
                str(backup_paths(root).database),
            ],
            environment=environment,
        )
        database_replaced = True
        if artifact_root.exists():
            os.replace(artifact_root, previous)
        os.replace(staging, artifact_root)
        (recovery / "restore-id").write_text(expected_backup_id + "\n")
        return recovery
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        if previous.exists() and not artifact_root.exists():
            os.replace(previous, artifact_root)
        if database_replaced:
            try:
                _run(
                    [
                        "pg_restore",
                        "--clean",
                        "--if-exists",
                        "--no-owner",
                        "--no-privileges",
                        "--single-transaction",
                        "--dbname",
                        connection,
                        str(recovery_database),
                    ],
                    environment=environment,
                )
            except BackupError as rollback_exc:
                raise BackupError(
                    f"restore failed and automatic database rollback failed; recovery is {recovery}"
                ) from rollback_exc
        shutil.rmtree(recovery, ignore_errors=True)
        raise


def rollback_restore(
    *, database_url: str, artifact_root: Path, recovery: Path, expected_backup_id: str
) -> Path:
    recovery = recovery.resolve()
    try:
        identity = (recovery / "restore-id").read_text().strip()
    except OSError as exc:
        raise BackupError("restore recovery identity is missing") from exc
    if identity != expected_backup_id:
        raise BackupError("rollback confirmation does not match restore id")
    database = recovery / "database.dump"
    previous = recovery / "artifacts"
    if not database.is_file() or not previous.is_dir():
        raise BackupError("restore recovery set is incomplete")
    _run(["pg_restore", "--list", str(database)])
    artifact_root = artifact_root.resolve()
    displaced = artifact_root.with_name(f".{artifact_root.name}.after-{expected_backup_id}")
    if displaced.exists():
        raise BackupError("post-restore artifact holding path already exists")
    connection, environment = database_connection(database_url)
    if artifact_root.exists():
        os.replace(artifact_root, displaced)
    try:
        os.replace(previous, artifact_root)
        _run(
            [
                "pg_restore",
                "--clean",
                "--if-exists",
                "--no-owner",
                "--no-privileges",
                "--single-transaction",
                "--dbname",
                connection,
                str(database),
            ],
            environment=environment,
        )
    except BaseException:
        if artifact_root.exists() and not previous.exists():
            os.replace(artifact_root, previous)
        if displaced.exists() and not artifact_root.exists():
            os.replace(displaced, artifact_root)
        raise
    return displaced
