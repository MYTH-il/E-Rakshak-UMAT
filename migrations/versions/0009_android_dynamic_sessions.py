"""Add brokered interactive Android dynamic sessions.

Revision ID: 0009_android_sessions
Revises: 0008_decouple_c2_policy
"""

import sqlalchemy as sa
from alembic import op

revision = "0009_android_sessions"
down_revision = "0008_decouple_c2_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "analysis_runs",
        sa.Column("android_interactive", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "android_dynamic_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_run_id", sa.Uuid(), nullable=False),
        sa.Column("stage_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_id", sa.Uuid(), nullable=False),
        sa.Column("executor_id", sa.Uuid(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("scan_hash", sa.String(length=64), nullable=False),
        sa.Column("package_name", sa.String(length=512), nullable=True),
        sa.Column("main_activity", sa.String(length=1024), nullable=True),
        sa.Column("guest_ip", sa.String(length=64), nullable=True),
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
    for column in ("analysis_run_id", "stage_id", "attempt_id", "executor_id", "state", "scan_hash", "expires_at"):
        op.create_index(f"ix_android_dynamic_sessions_{column}", "android_dynamic_sessions", [column])
    op.create_table(
        "android_session_commands",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("session_id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("command_type", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("result", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["session_id"], ["android_dynamic_sessions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("session_id", "requested_by_user_id", "command_type", "state"):
        op.create_index(f"ix_android_session_commands_{column}", "android_session_commands", [column])


def downgrade() -> None:
    op.drop_table("android_session_commands")
    op.drop_table("android_dynamic_sessions")
    op.drop_column("analysis_runs", "android_interactive")
