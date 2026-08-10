"""Managed Android analysis profiles.

Revision ID: 0006_android_profiles
Revises: 0005_android
"""

from alembic import op

from umat.db import models  # noqa: F401
from umat.db.base import Base

revision = "0006_android_profiles"
down_revision = "0005_android"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    for table in Base.metadata.sorted_tables:
        if table.name in {"android_analysis_profiles", "android_run_configurations"}:
            table.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    op.drop_table("android_run_configurations")
    op.drop_table("android_analysis_profiles")
