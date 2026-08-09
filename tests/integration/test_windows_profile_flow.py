import base64
import os
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"), reason="requires a migrated PostgreSQL test database"
)

from umat.api.app import app  # noqa: E402
from umat.auth.security import hash_password, random_token, token_hash  # noqa: E402
from umat.db.models import ExecutorEnrollmentToken, Role, User  # noqa: E402
from umat.db.session import session_factory  # noqa: E402
from umat.executors.protocol import signature_message  # noqa: E402


def signed_headers(
    private: Ed25519PrivateKey,
    path: str,
    body: dict,
    credential: str,
    lease_token: str,
) -> dict[str, str]:
    timestamp, nonce, key = datetime.now(timezone.utc).isoformat(), uuid.uuid4().hex, str(uuid.uuid4())
    message = signature_message(method="POST", path=path, timestamp=timestamp, nonce=nonce, idempotency_key=key, body=body)
    return {
        "Authorization": f"Bearer {credential}",
        "X-UMAT-Timestamp": timestamp,
        "X-UMAT-Nonce": nonce,
        "Idempotency-Key": key,
        "X-UMAT-Signature": base64.b64encode(private.sign(message)).decode(),
        "X-UMAT-Lease-Token": lease_token,
    }


@pytest.mark.asyncio
async def test_cape_managed_profile_lifecycle_and_run_selection() -> None:
    suffix = uuid.uuid4().hex[:10]
    admin_name, analyst_name = f"profile-admin-{suffix}", f"profile-analyst-{suffix}"
    password = "windows-profile-test-password"  # noqa: S105
    enrollment = random_token(48)
    async with session_factory() as db:
        admin_role = await db.scalar(select(Role).where(Role.name == "administrator"))
        analyst_role = await db.scalar(select(Role).where(Role.name == "analyst"))
        assert admin_role and analyst_role
        admin = User(username=admin_name, password_hash=hash_password(password), roles=[admin_role])
        analyst = User(username=analyst_name, password_hash=hash_password(password), roles=[analyst_role])
        db.add_all([admin, analyst])
        await db.flush()
        db.add(ExecutorEnrollmentToken(token_hash=token_hash(enrollment), executor_type="windows", scopes=["platform_analysis"], expires_at=datetime.now(timezone.utc) + timedelta(minutes=10), created_by_user_id=admin.id))
        await db.commit()

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        login = await client.post("/api/v1/auth/login", json={"username": admin_name, "password": password})
        assert login.status_code == 200
        csrf = {"X-CSRF-Token": login.json()["csrf_token"]}
        created = await client.post("/api/v1/windows/profiles", headers=csrf, json={"name": f"win10-{suffix}", "display_name": "Windows 10 Office", "windows_version": "Windows 10 22H2", "vcpus": 4, "ram_mb": 8192, "disk_gb": 100, "user_profile": {"username": "officer", "locale": "en-US", "timezone": "UTC", "installed_software": ["Office"]}, "analysis_profile": "standard", "cape_template": "win10-hardened", "is_default": True})
        assert created.status_code == 202, created.text
        profile_id, operation_id = created.json()["profile"]["id"], created.json()["operation_id"]

        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        registered = await client.post("/api/internal/v1/executors/register", json={"enrollment_token": enrollment, "name": f"windows-{suffix}", "public_key": base64.b64encode(public).decode(), "metadata": {}})
        assert registered.status_code == 201, registered.text
        credential = registered.json()["credential"]
        auth = {"Authorization": f"Bearer {credential}"}
        capabilities = await client.post("/api/internal/v1/executors/capabilities", headers=auth, json={"schema_version": "1.0", "runtime_identity": "winstdt-fixture", "supported_stage_types": ["platform_analysis"], "capabilities": {"platforms": ["windows"], "vm_profile_management": True}})
        assert capabilities.status_code == 204
        for _ in range(20):
            claimed = await client.post("/api/internal/v1/executors/windows/profile-operations/claim", headers=auth)
            assert claimed.status_code == 200
            operation = claimed.json()
            assert operation
            if operation["operation_id"] == operation_id:
                break
            stale_body = {"operation_id": operation["operation_id"], "success": True, "native_operation_id": f"cleanup-{suffix}", "cape_machine_label": operation["profile"].get("cape_machine_label") or f"cleanup-{operation['operation_id']}", "detail": None}
            stale_path = f"/api/internal/v1/executors/windows/profile-operations/{operation['operation_id']}/complete"
            stale = await client.post(stale_path, json=stale_body, headers=signed_headers(private, stale_path, stale_body, credential, operation["lease_token"]))
            assert stale.status_code == 200, stale.text
        else:
            pytest.fail("new Windows profile operation was not claimable")
        complete_body = {"operation_id": operation_id, "success": True, "native_operation_id": f"cape-create-{suffix}", "cape_machine_label": f"cape-win10-{suffix}", "detail": None}
        complete_path = f"/api/internal/v1/executors/windows/profile-operations/{operation_id}/complete"
        completed = await client.post(complete_path, json=complete_body, headers=signed_headers(private, complete_path, complete_body, credential, operation["lease_token"]))
        assert completed.status_code == 200, completed.text
        assert completed.json()["profile_state"] == "active"

        await client.post("/api/v1/auth/logout", headers=csrf)
        analyst_login = await client.post("/api/v1/auth/login", json={"username": analyst_name, "password": password})
        analyst_csrf = {"X-CSRF-Token": analyst_login.json()["csrf_token"]}
        case = await client.post("/api/v1/cases", headers=analyst_csrf, data={"title": "profile selection", "windows_profile_id": profile_id}, files={"file": ("sample.exe", b"MZ fixture", "application/octet-stream")})
        assert case.status_code == 201, case.text
        detail = await client.get(f"/api/v1/cases/{case.json()['case_id']}")
        snapshot = detail.json()["analysis_runs"][0]["windows_profile"]
        assert snapshot["profile_id"] == profile_id
        assert snapshot["cape_machine_label"] == f"cape-win10-{suffix}"

        await client.post("/api/v1/auth/logout", headers=analyst_csrf)
        await client.post("/api/v1/auth/login", json={"username": admin_name, "password": password})
        admin_session = await client.get("/api/v1/auth/session")
        # Login response CSRF is required because the previous token was revoked.
        relogin = await client.post("/api/v1/auth/login", json={"username": admin_name, "password": password})
        assert admin_session.status_code in {200, 401}
        deleted = await client.delete(f"/api/v1/windows/profiles/{profile_id}", headers={"X-CSRF-Token": relogin.json()["csrf_token"]})
        assert deleted.status_code == 202, deleted.text
        assert deleted.json()["profile"]["state"] == "deleting"
