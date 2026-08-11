from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from umat.egress.manager import EgressManager
from umat.egress.schemas import LeaseRequest, Readiness


def test_egress_manager_requires_dedicated_wireguard_uplink(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="WireGuard"):
        EgressManager("eth0", "10.77.0.53", tmp_path)


def test_egress_lease_schema_rejects_unbounded_ttl() -> None:
    with pytest.raises(ValidationError):
        LeaseRequest(
            analysis_run_id="0198fd40-1111-7000-8000-000000000004",
            platform="windows",
            guest_ip="10.66.0.101",
            ttl_seconds=3600,
        )


def test_unprovisioned_egress_manager_is_fail_closed(tmp_path: Path) -> None:
    manager = EgressManager("wg-umat-egress", "10.77.0.53", tmp_path)
    readiness = manager.readiness()
    assert readiness.status == "not_ready"
    assert readiness.checks["uplink_present"] is False


def test_lease_heartbeat_refreshes_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = EgressManager("wg-umat-egress", "10.77.0.53", tmp_path)
    monkeypatch.setattr(
        manager,
        "readiness",
        lambda: Readiness(
            status="ready",
            uplink="wg-umat-egress",
            dns_resolver="10.77.0.53",
            checks={"fixture": True},
        ),
    )
    original_is_dir = Path.is_dir
    monkeypatch.setattr(
        Path,
        "is_dir",
        lambda path: True if str(path).startswith("/sys/class/net/") else original_is_dir(path),
    )

    class Capture:
        pid = 12345

        def poll(self) -> None:
            return None

        def wait(self, timeout: int) -> int:
            return 0

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Capture())
    monkeypatch.setattr("os.killpg", lambda *args: None)
    commands: list[tuple[Any, ...]] = []
    monkeypatch.setattr(
        manager,
        "_nft",
        lambda *args, **kwargs: (
            commands.append(args) or subprocess.CompletedProcess([], 0, b"", b"")
        ),
    )
    monkeypatch.setattr(manager, "_element_bytes", lambda *args: 0)
    request = LeaseRequest(
        analysis_run_id="0198fd40-1111-7000-8000-000000000004",
        platform="windows",
        guest_ip="10.66.0.101",
    )
    manager.acquire(request)
    manager.heartbeat(request.analysis_run_id)
    manager.revoke(request.analysis_run_id)
    operations = [command[0] for command in commands]
    assert operations == ["add", "delete", "add", "delete"]
