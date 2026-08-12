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
    # Revision 0001 creates its phase-one tables from current SQLAlchemy
    # metadata, so a brand-new database can already contain this later column.
    # Existing installations at 0010 do not. Keep the migration valid for both
    # paths, matching the guards used by revisions 0007 through 0009.
    connection = op.get_bind()
    existing = connection.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'analysis_runs' "
            "AND column_name = 'windows_interactive'"
        )
    )
    if existing.fetchone() is None:
        op.add_column(
            "analysis_runs",
            sa.Column(
                "windows_interactive",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            ),
        )


def downgrade() -> None:
    op.drop_column("analysis_runs", "windows_interactive")
