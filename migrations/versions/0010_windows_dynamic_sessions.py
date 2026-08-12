"""Add live-only Windows CAPE sessions.

Revision ID: 0010_windows_sessions
Revises: 0009_android_sessions
"""

import sqlalchemy as sa
from alembic import op

revision = "0010_windows_sessions"
down_revision = "0009_android_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "windows_dynamic_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.Column("stage_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_id", sa.Uuid(), nullable=False),
        sa.Column("executor_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("cape_task_id", sa.Integer(), nullable=False),
        sa.Column("machine_label", sa.String(length=128), nullable=False),
        sa.Column("console_url", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status_details", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["analysis_run_id"], ["analysis_runs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["stage_id"], ["analysis_stages.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["attempt_id"], ["analysis_attempts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["executor_id"], ["executors.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_run_id"),
    )
    for column in (
        "analysis_run_id", "stage_id", "attempt_id", "executor_id", "state",
        "cape_task_id", "machine_label", "expires_at",
    ):
        op.create_index(
            f"ix_windows_dynamic_sessions_{column}", "windows_dynamic_sessions", [column]
        )


def downgrade() -> None:
    op.drop_table("windows_dynamic_sessions")
