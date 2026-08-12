from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from umat.operations.backup import (
    BackupError,
    create_backup,
    database_connection,
    restore_backup,
    rollback_restore,
    verify_backup,
)


def test_database_connection_keeps_password_out_of_argv() -> None:
    connection, environment = database_connection(
        "postgresql+asyncpg://umat:secret%20value@127.0.0.1:55432/umat"
    )
    assert connection == "postgresql://umat@127.0.0.1:55432/umat"
    assert environment["PGPASSWORD"] == "secret value"


def test_backup_create_and_verify_hashes_database_and_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = tmp_path / "artifacts"
    object_path = artifacts / "objects/sha256"
    payload = b"evidence"
    import hashlib

    digest = hashlib.sha256(payload).hexdigest()
    stored = object_path / digest[:2] / digest[2:]
    stored.parent.mkdir(parents=True)
    stored.write_bytes(payload)

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] == "pg_dump":
            Path(command[command.index("--file") + 1]).write_bytes(b"PGDMP-fixture")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = create_backup(
        database_url="postgresql://umat:secret@127.0.0.1/umat",
        artifact_root=artifacts,
        backup_root=tmp_path / "backups",
        backup_id="backup-1",
    )

    manifest = verify_backup(result)
    assert manifest["backup_id"] == "backup-1"
    assert manifest["artifacts"] == [
        {"path": f"objects/sha256/{digest[:2]}/{digest[2:]}", "sha256": digest, "size_bytes": 8}
    ]
    assert json.loads((result / "manifest.json").read_text())["database"]["size_bytes"] == 13


def test_backup_rejects_content_address_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored = tmp_path / "artifacts/objects/sha256/aa" / ("b" * 62)
    stored.parent.mkdir(parents=True)
    stored.write_bytes(b"wrong")

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] == "pg_dump":
            Path(command[command.index("--file") + 1]).write_bytes(b"PGDMP-fixture")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(BackupError, match="identity mismatch"):
        create_backup(
            database_url="postgresql://umat@127.0.0.1/umat",
            artifact_root=tmp_path / "artifacts",
            backup_root=tmp_path / "backups",
            backup_id="backup-1",
        )


def test_restore_creates_complete_recovery_and_can_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "live").write_text("live")
    backup = tmp_path / "backups/backup-1"
    (backup / "artifacts").mkdir(parents=True)
    (backup / "artifacts/restored").write_text("restored")
    (backup / "database.dump").write_bytes(b"backup-db")
    manifest = {
        "schema_version": "1.0",
        "backup_id": "backup-1",
        "database": {
            "path": "database.dump",
            "sha256": hashlib.sha256(b"backup-db").hexdigest(),
            "size_bytes": 9,
            "format": "postgresql_custom",
        },
        "artifacts": [
            {
                "path": "restored",
                "sha256": hashlib.sha256(b"restored").hexdigest(),
                "size_bytes": 8,
            }
        ],
    }
    (backup / "manifest.json").write_text(json.dumps(manifest))

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[0] == "pg_dump":
            Path(command[command.index("--file") + 1]).write_bytes(b"live-db")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_run)
    recovery = restore_backup(
        database_url="postgresql://umat@127.0.0.1/umat",
        artifact_root=artifacts,
        root=backup,
        expected_backup_id="backup-1",
    )
    assert (artifacts / "restored").read_text() == "restored"
    assert (recovery / "database.dump").read_bytes() == b"live-db"
    displaced = rollback_restore(
        database_url="postgresql://umat@127.0.0.1/umat",
        artifact_root=artifacts,
        recovery=recovery,
        expected_backup_id="backup-1",
    )
    assert (artifacts / "live").read_text() == "live"
    assert (displaced / "restored").read_text() == "restored"
