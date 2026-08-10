"""Persist per-run malware network policy.

Revision ID: 0007_run_network_mode
Revises: 0006_android_profiles
"""

import sqlalchemy as sa
from alembic import op

revision = "0007_run_network_mode"
down_revision = "0006_android_profiles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_runs",
        sa.Column("network_mode", sa.String(length=32), nullable=True),
    )
    # Historic runs executed the C2 workflow and therefore represent the
    # prior egress-capable behavior. New runs default fail-closed.
    op.execute("UPDATE analysis_runs SET network_mode = 'real_world_egress'")
    op.alter_column("analysis_runs", "network_mode", nullable=False)


def downgrade() -> None:
    op.drop_column("analysis_runs", "network_mode")
