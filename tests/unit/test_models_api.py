from sqlalchemy import ForeignKeyConstraint

from umat.api.app import app
from umat.db.base import Base


def test_required_routes_exist() -> None:
    paths = set(app.openapi()["paths"])
    paths.update(route.path for route in app.routes if hasattr(route, "path"))
    required = {
        "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/session",
        "/api/v1/cases", "/api/v1/cases/{case_id}", "/api/v1/cases/{case_id}/status",
        "/api/v1/cases/{case_id}/analysis-runs", "/api/v1/analysis-runs/{run_id}/confirm",
        "/api/v1/analysis-runs/{run_id}/cancel", "/api/v1/artifacts/{artifact_id}",
        "/api/v1/analysis-runs/{run_id}/android-workflow",
        "/api/v1/analysis-runs/{run_id}/android-evidence/{evidence_name}",
        "/health/live", "/health/ready",
    }
    assert required <= paths


def test_custody_foreign_keys_do_not_cascade_delete() -> None:
    protected = {"submissions", "analysis_attempts", "artifacts", "bundle_imports"}
    for table_name in protected:
        table = Base.metadata.tables[table_name]
        for constraint in table.constraints:
            if isinstance(constraint, ForeignKeyConstraint):
                assert constraint.ondelete != "CASCADE"


def test_audit_table_is_append_only_by_design() -> None:
    audit = Base.metadata.tables["audit_events"]
    assert "event_hash" in audit.c
    assert audit.c.event_hash.unique
    assert audit.c.sequence.primary_key
