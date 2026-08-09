"""Phase 4 unified reports and exports.

Revision ID: 0004_unified_reports
Revises: 0003_windows
"""

from alembic import op

from umat.db import models  # noqa: F401
from umat.db.base import Base

revision = "0004_unified_reports"
down_revision = "0003_windows"
branch_labels = None
depends_on = None

PHASE_FOUR_TABLES = {"case_report_snapshots", "report_exports"}


def upgrade() -> None:
    bind = op.get_bind()
    for schema_table in Base.metadata.sorted_tables:
        if schema_table.name in PHASE_FOUR_TABLES:
            schema_table.create(bind=bind, checkfirst=False)
    op.execute("REVOKE UPDATE, DELETE ON case_report_snapshots FROM PUBLIC")
    op.execute("REVOKE UPDATE, DELETE ON report_exports FROM PUBLIC")
    op.execute(
        """
        CREATE FUNCTION umat_reject_report_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'report records are append-only';
        END;
        $$
        """
    )
    for table_name in PHASE_FOUR_TABLES:
        op.execute(
            f"CREATE TRIGGER {table_name}_append_only BEFORE UPDATE OR DELETE "
            f"ON {table_name} FOR EACH ROW EXECUTE FUNCTION umat_reject_report_mutation()"
        )


def downgrade() -> None:
    for table_name in ("report_exports", "case_report_snapshots"):
        op.drop_table(table_name)
    op.execute("DROP FUNCTION IF EXISTS umat_reject_report_mutation()")
    op.execute("DROP TYPE IF EXISTS report_export_format")
    op.execute("DROP TYPE IF EXISTS verdict")
