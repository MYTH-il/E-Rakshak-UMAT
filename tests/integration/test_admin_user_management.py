from __future__ import annotations

import os
import uuid

import httpx
import pytest
from sqlalchemy import select

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"),
    reason="requires a migrated PostgreSQL test database",
)

from umat.api.app import app  # noqa: E402
from umat.auth.security import hash_password  # noqa: E402
from umat.db.models import Role, User  # noqa: E402
from umat.db.session import session_factory  # noqa: E402


@pytest.mark.asyncio
async def test_administrator_can_manage_user_lifecycle_and_access() -> None:
    suffix = uuid.uuid4().hex[:10]
    admin_name = f"user-admin-{suffix}"
    analyst_name = f"user-analyst-{suffix}"
    original_password = "initial-user-password"  # noqa: S105
    updated_password = "updated-user-password"  # noqa: S105
    async with session_factory() as db:
        administrator_role = await db.scalar(
            select(Role).where(Role.name == "administrator")
        )
        analyst_role = await db.scalar(select(Role).where(Role.name == "analyst"))
        assert administrator_role and analyst_role
        db.add_all(
            [
                User(
                    username=admin_name,
                    password_hash=hash_password(original_password),
                    roles=[administrator_role],
                ),
                User(
                    username=analyst_name,
                    password_hash=hash_password(original_password),
                    roles=[analyst_role],
                ),
            ]
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as analyst:
        login = await analyst.post(
            "/api/v1/auth/login",
            json={"username": analyst_name, "password": original_password},
        )
        assert login.status_code == 200
        assert (await analyst.get("/api/v1/admin/users")).status_code == 403

    async with (
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as admin,
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as managed,
    ):
        login = await admin.post(
            "/api/v1/auth/login",
            json={"username": admin_name, "password": original_password},
        )
        csrf = {"X-CSRF-Token": login.json()["csrf_token"]}
        created = await admin.post(
            "/api/v1/admin/users",
            headers=csrf,
            json={
                "username": f" Managed-{suffix} ",
                "password": original_password,
                "roles": ["officer"],
            },
        )
        assert created.status_code == 201, created.text
        user_id = created.json()["id"]
        assert created.json()["username"] == f"managed-{suffix}"

        managed_login = await managed.post(
            "/api/v1/auth/login",
            json={"username": f"managed-{suffix}", "password": original_password},
        )
        assert managed_login.status_code == 200

        changed = await admin.patch(
            f"/api/v1/admin/users/{user_id}",
            headers=csrf,
            json={
                "username": f"renamed-{suffix}",
                "password": updated_password,
                "roles": ["analyst", "officer"],
            },
        )
        assert changed.status_code == 200, changed.text
        assert changed.json()["roles"] == ["analyst", "officer"]
        assert (await managed.get("/api/v1/auth/session")).status_code == 401

        old_login = await managed.post(
            "/api/v1/auth/login",
            json={"username": f"renamed-{suffix}", "password": original_password},
        )
        assert old_login.status_code == 401
        new_login = await managed.post(
            "/api/v1/auth/login",
            json={"username": f"renamed-{suffix}", "password": updated_password},
        )
        assert new_login.status_code == 200

        revoked = await admin.post(
            f"/api/v1/admin/users/{user_id}/revoke-sessions", headers=csrf
        )
        assert revoked.status_code == 200
        assert revoked.json()["sessions_revoked"] == 1
        assert (await managed.get("/api/v1/auth/session")).status_code == 401

        self_disable = await admin.patch(
            f"/api/v1/admin/users/{login.json()['user_id']}",
            headers=csrf,
            json={"enabled": False},
        )
        assert self_disable.status_code == 409

        deleted = await admin.delete(f"/api/v1/admin/users/{user_id}", headers=csrf)
        assert deleted.status_code == 204, deleted.text
        inventory = await admin.get("/api/v1/admin/users")
        assert user_id not in {item["id"] for item in inventory.json()["items"]}
