from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

import httpx
import pytest

from umat.cape_gateway.app import create_app
from umat.cape_gateway.manager import CapeProfileConfiguration, CapeProfileManager
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

    def console_target(self, task_id: int, label: str) -> tuple[str, int]:
        assert task_id == 42
        assert label == "umat-office-1234abcd"
        return "127.0.0.1", 5901


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


@pytest.mark.asyncio
async def test_gateway_issues_only_authenticated_expiring_console_capabilities(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("UMAT_CAPE_GATEWAY_TOKEN", TOKEN)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(FakeManager())),
        base_url="http://testserver",
    ) as client:
        unauthenticated = await client.post(
            "/api/v1/tasks/42/console",
            json={"machine_label": "umat-office-1234abcd", "duration_seconds": 600},
        )
        response = await client.post(
            "/api/v1/tasks/42/console",
            json={"machine_label": "umat-office-1234abcd", "duration_seconds": 600},
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert unauthenticated.status_code == 401
    assert response.status_code == 200
    assert response.json()["machine_label"] == "umat-office-1234abcd"
    assert response.json()["console_url"].startswith(
        "ws://127.0.0.1:8091/api/v1/console/"
    )


def test_non_administrator_guest_profile_is_actually_demoted() -> None:
    script = CapeProfileManager._profile_script("encoded")
    assert "Remove-LocalGroupMember -Group 'Administrators'" in script


def test_generated_domain_exposes_vnc_on_loopback_only(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    configuration = CapeProfileConfiguration(
        cape_root=tmp_path,
        state_root=tmp_path / "state",
        image_root=tmp_path / "images",
        base_domain="base",
        base_disk=tmp_path / "base.qcow2",
        base_windows_version="Windows 10 22H2",
        network="isolated",
        bridge="virbr-test",
        host_ip="10.66.0.1",
        snapshot="clean",
        address_start=120,
        address_end=199,
        allowed_templates=frozenset({"win10-hardened"}),
    )
    manager = CapeProfileManager(configuration)
    source = """<domain><name>base</name><uuid>00000000-0000-0000-0000-000000000000</uuid><memory>1</memory><currentMemory>1</currentMemory><vcpu>1</vcpu><cpu><topology cores='1'/></cpu><devices><disk device='disk'><source file='/old'/></disk><interface><mac address='52:54:00:00:00:01'/></interface><graphics type='spice' listen='0.0.0.0'/></devices></domain>"""
    monkeypatch.setattr(manager, "_capture", lambda *args, **kwargs: source)
    generated = manager._domain_xml(
        ProfileRequest.model_validate(profile()),
        "umat-office-1234abcd",
        "52:54:00:01:02:03",
        tmp_path / "profile.qcow2",
    )
    root = ET.fromstring(generated)  # noqa: S314 - generated local XML
    graphics = root.findall("./devices/graphics")
    assert len(graphics) == 1
    assert graphics[0].attrib == {
        "type": "vnc",
        "port": "-1",
        "autoport": "yes",
        "listen": "127.0.0.1",
    }


def test_console_target_rejects_non_loopback_vnc(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    configuration = CapeProfileConfiguration(
        cape_root=tmp_path, state_root=tmp_path / "state", image_root=tmp_path / "images",
        base_domain="base", base_disk=tmp_path / "base.qcow2",
        base_windows_version="Windows 10 22H2", network="isolated", bridge="virbr-test",
        host_ip="10.66.0.1", snapshot="clean", address_start=120, address_end=199,
        allowed_templates=frozenset({"win10-hardened"}),
    )
    manager = CapeProfileManager(configuration)
    monkeypatch.setattr(manager, "_cape_task_machine", lambda task_id: "umat-office-1234abcd")

    def capture(command, **kwargs):  # type: ignore[no-untyped-def]
        return "running\n" if "domstate" in command else "vnc://0.0.0.0:5901\n"

    monkeypatch.setattr(manager, "_capture", capture)
    with pytest.raises(RuntimeError, match="loopback-only"):
        manager.console_target(42, "umat-office-1234abcd")


def test_console_target_translates_libvirt_display_to_tcp_port(monkeypatch, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    configuration = CapeProfileConfiguration(
        cape_root=tmp_path, state_root=tmp_path / "state", image_root=tmp_path / "images",
        base_domain="base", base_disk=tmp_path / "base.qcow2",
        base_windows_version="Windows 10 22H2", network="isolated", bridge="virbr-test",
        host_ip="10.66.0.1", snapshot="clean", address_start=120, address_end=199,
        allowed_templates=frozenset({"win10-hardened"}),
    )
    manager = CapeProfileManager(configuration)
    monkeypatch.setattr(manager, "_cape_task_machine", lambda task_id: "winstdt-win10-22h2")

    def capture(command, **kwargs):  # type: ignore[no-untyped-def]
        return "running\n" if "domstate" in command else "vnc://127.0.0.1:0\n"

    monkeypatch.setattr(manager, "_capture", capture)
    assert manager.console_target(42, "winstdt-win10-22h2") == ("127.0.0.1", 5900)
