"""Phase 2 normalized C2 result tables.

Revision ID: 0002_c2_results
Revises: 0001_phase1
"""
from alembic import op

from umat.db import models  # noqa: F401
from umat.db.base import Base

revision = "0002_c2_results"
down_revision = "0001_phase1"
branch_labels = None
depends_on = None

C2_TABLES = {
    "adaptation_records",
    "c2_findings",
    "network_observations",
    "exfil_events",
    "static_iocs",
    "provenance_links",
    "timeline_events",
    "attribution_results",
}


def upgrade() -> None:
    bind = op.get_bind()
    for schema_table in Base.metadata.sorted_tables:
        if schema_table.name in C2_TABLES:
            schema_table.create(bind=bind, checkfirst=True)


def downgrade() -> None:
    # Use Alembic table drops so SQLAlchemy does not attempt to remove the
    # shared ``platform`` enum that remains owned by Phase 1 analysis_runs.
    for table_name in (
        "attribution_results",
        "timeline_events",
        "provenance_links",
        "static_iocs",
        "exfil_events",
        "network_observations",
        "c2_findings",
        "adaptation_records",
    ):
        op.drop_table(table_name)
