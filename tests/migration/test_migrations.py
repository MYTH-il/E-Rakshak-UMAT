import os
import shutil
import subprocess

import pytest
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("UMAT_MIGRATION_DATABASE_URL")
UV = shutil.which("uv")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL,
    reason="requires an explicitly disposable PostgreSQL migration database",
)


def alembic(*arguments: str) -> None:
    assert DATABASE_URL
    assert UV
    environment = os.environ.copy()
    environment["UMAT_DATABASE_URL"] = DATABASE_URL
    subprocess.run(  # noqa: S603
        [UV, "run", "alembic", *arguments],
        check=True,
        env=environment,
    )


def sync_url() -> str:
    assert DATABASE_URL
    return DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)


def test_full_upgrade_downgrade_and_role_seed() -> None:
    revisions = [
        "0001_phase1",
        "0002_c2_results",
        "0003_windows",
        "0004_unified_reports",
        "0005_android",
        "0006_android_profiles",
        "0007_run_network_mode",
        "0008_decouple_c2_policy",
        "0009_android_sessions",
    ]
    alembic("downgrade", "base")
    for revision in revisions:
        alembic("upgrade", revision)
    with create_engine(sync_url()).connect() as connection:
        assert connection.execute(text("select version_num from alembic_version")).scalar_one() == revisions[-1]
        assert connection.execute(text("select name from roles order by id")).scalars().all() == [
            "officer",
            "analyst",
            "administrator",
        ]
    alembic("upgrade", "head")
    with create_engine(sync_url()).connect() as connection:
        assert connection.execute(text("select count(*) from roles")).scalar_one() == 3
    alembic("downgrade", "base")
    alembic("upgrade", "head")
