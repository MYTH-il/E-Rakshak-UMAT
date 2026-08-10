from __future__ import annotations

import uuid

import httpx
import pytest

from umat.cape_gateway.app import create_app
from umat.cape_gateway.manager import CapeProfileManager
from umat.cape_gateway.schemas import MachineResult, ProfileRequest

TOKEN = "t" * 48


class FakeManager:
    def __init__(self) -> None:
        self.created: ProfileRequest | None = None
        self.deleted: str | None = None

    def create(self, profile: ProfileRequest) -> MachineResult:
        self.created = profile
        return MachineResult(operation_id=str(uuid.uuid4()), machine_label="umat-office-1234abcd")

    def delete(self, label: str) -> MachineResult:
        self.deleted = label
        return MachineResult(operation_id=str(uuid.uuid4()), machine_label=label)


def profile() -> dict[str, object]:
    return {
        "profile_id": "0198a04b-8a7a-7000-8000-000000000001",
        "name": "office",
        "windows_version": "Windows 10 22H2",
        "architecture": "x64",
        "vcpus": 4,
        "ram_mb": 8192,
        "disk_gb": 160,
        "user_profile": {
            "username": "analyst",
            "locale": "en-US",
            "timezone": "UTC",
            "administrator": False,
            "installed_software": ["Office"],
        },
        "analysis_profile": "standard",
        "cape_machine_label": None,
        "cape_template": "win10-hardened",
    }


@pytest.mark.asyncio
async def test_gateway_requires_bearer_token(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("UMAT_CAPE_GATEWAY_TOKEN", TOKEN)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(FakeManager())),
        base_url="http://testserver",
    ) as client:
        assert (await client.post("/api/v1/machines", json=profile())).status_code == 401


@pytest.mark.asyncio
async def test_gateway_forwards_validated_profile(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("UMAT_CAPE_GATEWAY_TOKEN", TOKEN)
    manager = FakeManager()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(manager)), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/api/v1/machines", json=profile(), headers={"Authorization": f"Bearer {TOKEN}"}
        )
    assert response.status_code == 201
    assert manager.created is not None
    assert manager.created.user_profile.username == "analyst"


@pytest.mark.asyncio
async def test_gateway_rejects_deletion_outside_managed_namespace(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("UMAT_CAPE_GATEWAY_TOKEN", TOKEN)
    manager = FakeManager()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(manager)), base_url="http://testserver"
    ) as client:
        response = await client.delete(
            "/api/v1/machines/winstdt-win10-22h2",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 422
    assert manager.deleted is None


@pytest.mark.asyncio
async def test_gateway_rejects_architecture_not_provided_by_baseline(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("UMAT_CAPE_GATEWAY_TOKEN", TOKEN)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(FakeManager())),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/api/v1/machines",
            json=profile() | {"architecture": "x86"},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert response.status_code == 422


def test_non_administrator_guest_profile_is_actually_demoted() -> None:
    script = CapeProfileManager._profile_script("encoded")
    assert "Remove-LocalGroupMember -Group 'Administrators'" in script
