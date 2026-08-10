"""Decouple C2 analysis from guest network egress.

Revision ID: 0008_decouple_c2_policy
Revises: 0007_run_network_mode
"""

import sqlalchemy as sa
from alembic import op

revision = "0008_decouple_c2_policy"
down_revision = "0007_run_network_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_runs",
        sa.Column("c2_analysis_enabled", sa.Boolean(), nullable=True),
    )
    op.execute(
        "UPDATE analysis_runs SET c2_analysis_enabled = (network_mode = 'real_world_egress')"
    )
    op.alter_column("analysis_runs", "c2_analysis_enabled", nullable=False)


def downgrade() -> None:
    op.drop_column("analysis_runs", "c2_analysis_enabled")
