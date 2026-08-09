"""Phase 3 Windows/CAPE integration.

Revision ID: 0003_windows
Revises: 0002_c2_results
"""
from alembic import op

from umat.db import models  # noqa: F401
from umat.db.base import Base

revision = "0003_windows"
down_revision = "0002_c2_results"
branch_labels = None
depends_on = None

WINDOWS_TABLES = {
    "windows_vm_profiles",
    "windows_profile_operations",
    "windows_run_configurations",
    "windows_analysis_metadata",
    "windows_findings",
    "windows_capabilities",
}


def upgrade() -> None:
    bind = op.get_bind()
    for schema_table in Base.metadata.sorted_tables:
        if schema_table.name in WINDOWS_TABLES:
            schema_table.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    for table_name in (
        "windows_capabilities",
        "windows_findings",
        "windows_analysis_metadata",
        "windows_run_configurations",
        "windows_profile_operations",
        "windows_vm_profiles",
    ):
        op.drop_table(table_name)
