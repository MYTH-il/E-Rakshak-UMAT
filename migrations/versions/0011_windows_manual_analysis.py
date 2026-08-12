"""Add explicit manual Windows analysis mode.

Revision ID: 0011_windows_manual
Revises: 0010_windows_sessions
"""

import sqlalchemy as sa
from alembic import op

revision = "0011_windows_manual"
down_revision = "0010_windows_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_runs",
        sa.Column("windows_interactive", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("analysis_runs", "windows_interactive")
