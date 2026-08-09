"""Phase 5 Android/MobSF integration.

Revision ID: 0005_android
Revises: 0004_unified_reports
"""
from alembic import op

from umat.db import models  # noqa: F401
from umat.db.base import Base

revision = "0005_android"
down_revision = "0004_unified_reports"
branch_labels = None
depends_on = None

ANDROID_TABLES = {
    "android_analysis_metadata",
    "android_findings",
    "android_capabilities",
}


def upgrade() -> None:
    bind = op.get_bind()
    for schema_table in Base.metadata.sorted_tables:
        if schema_table.name in ANDROID_TABLES:
            schema_table.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    for table_name in (
        "android_capabilities",
        "android_findings",
        "android_analysis_metadata",
    ):
        op.drop_table(table_name)
