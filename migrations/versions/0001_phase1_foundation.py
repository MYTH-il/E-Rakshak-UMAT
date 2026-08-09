"""Phase 1 control-plane foundation.

Revision ID: 0001_phase1
"""
from alembic import op
from sqlalchemy import Integer, String, column, table

from umat.db import models  # noqa: F401
from umat.db.base import Base

revision = "0001_phase1"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    phase_one_tables = {
        "users", "roles", "user_roles", "sessions", "login_attempts",
        "cases", "samples", "submissions", "case_samples", "analysis_runs",
        "analysis_stages", "stage_dependencies", "analysis_attempts",
        "executor_leases", "backend_tasks", "backend_capability_snapshots",
        "executors", "executor_credentials", "executor_requests",
        "executor_enrollment_tokens", "artifacts", "bundle_imports",
        "audit_events", "signed_audit_roots",
    }
    for schema_table in Base.metadata.sorted_tables:
        if schema_table.name in phase_one_tables:
            schema_table.create(bind=bind, checkfirst=False)
    roles = table("roles", column("id", Integer), column("name", String))
    op.bulk_insert(roles, [{"id": 1, "name": "officer"}, {"id": 2, "name": "analyst"}, {"id": 3, "name": "administrator"}])
    op.execute("REVOKE UPDATE, DELETE ON audit_events FROM PUBLIC")
    op.execute(
        """
        CREATE FUNCTION umat_reject_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'audit_events is append-only';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION umat_reject_audit_mutation()
        """
    )


def downgrade() -> None:
    phase_one_tables = {
        "users", "roles", "user_roles", "sessions", "login_attempts",
        "cases", "samples", "submissions", "case_samples", "analysis_runs",
        "analysis_stages", "stage_dependencies", "analysis_attempts",
        "executor_leases", "backend_tasks", "backend_capability_snapshots",
        "executors", "executor_credentials", "executor_requests",
        "executor_enrollment_tokens", "artifacts", "bundle_imports",
        "audit_events", "signed_audit_roots",
    }
    for schema_table in reversed(Base.metadata.sorted_tables):
        if schema_table.name in phase_one_tables:
            schema_table.drop(bind=op.get_bind(), checkfirst=False)
    op.execute("DROP FUNCTION IF EXISTS umat_reject_audit_mutation()")
