from __future__ import annotations

import time
from pathlib import Path
from typing import Any, cast

import httpx


class CapeError(RuntimeError):
    pass


def cape_package_for_sample(sample: Path) -> str:
    """Select a CAPE package only when the native PE header is conclusive."""
    with sample.open("rb") as source:
        header = source.read(64)
        if len(header) < 64 or header[:2] != b"MZ":
            return ""
        pe_offset = int.from_bytes(header[60:64], "little")
        if pe_offset < 64 or pe_offset > 16 * 1024 * 1024:
            return ""
        source.seek(pe_offset)
        coff = source.read(24)
    if len(coff) != 24 or coff[:4] != b"PE\0\0":
        return ""
    characteristics = int.from_bytes(coff[22:24], "little")
    return "dll" if characteristics & 0x2000 else "exe"


class CapeClient:
    """Pinned CAPE HTTP client plus the deployment's CAPE machine-management gateway."""

    ACTIVE_STATES = {"pending", "running", "distributed"}

    def __init__(
        self,
        base_url: str,
        api_token: str | None = None,
        management_url: str | None = None,
        management_token: str | None = None,
        analysis_timeout_seconds: int = 180,
    ) -> None:
        headers = {"Authorization": f"Token {api_token}"} if api_token else {}
        self.client = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=60)
        management_headers = (
            {"Authorization": f"Bearer {management_token}"} if management_token else {}
        )
        self.management = httpx.Client(
            base_url=(management_url or base_url).rstrip("/"),
            headers=management_headers,
            timeout=900,
        )
        self.analysis_timeout_seconds = analysis_timeout_seconds

    def create_machine(self, profile: dict[str, Any]) -> tuple[str, str]:
        response = self.management.post("/api/v1/machines", json=profile)
        response.raise_for_status()
        value = response.json()
        return str(value["operation_id"]), str(value["machine_label"])

    def delete_machine(self, label: str) -> str:
        response = self.management.delete(f"/api/v1/machines/{label}")
        response.raise_for_status()
        return str(response.json()["operation_id"])

    def submit(self, sample: Path, profile: dict[str, Any]) -> int:
        data = {
            "machine": profile.get("cape_machine_label") or "",
            # CAPE can mistake a PE containing an archive overlay for a ZIP and
            # abort the guest before ETW finalization. Other formats remain on
            # CAPE's native automatic package selection path.
            "package": cape_package_for_sample(sample),
            "options": f"analysis_profile={profile.get('analysis_profile', 'standard')}",
            "timeout": str(self.analysis_timeout_seconds),
            "enforce_timeout": "true",
        }
        with sample.open("rb") as source:
            response = self.client.post(
                "/apiv2/tasks/create/file/",
                data=data,
                files={"file": ("sample.bin", source, "application/octet-stream")},
            )
        response.raise_for_status()
        value = response.json()
        task_ids = value.get("data", {}).get("task_ids") or value.get("task_ids") or []
        if not task_ids:
            raise CapeError(f"CAPE did not return a task ID: {value}")
        return int(task_ids[0])

    def status(self, task_id: int) -> dict[str, Any]:
        response = self.client.get(f"/apiv2/tasks/status/{task_id}/")
        response.raise_for_status()
        value = response.json()
        data = value.get("data", value)
        if isinstance(data, str):
            return {"status": data}
        if not isinstance(data, dict):
            raise CapeError("CAPE status response is not an object")
        return cast(dict[str, Any], data)

    def cancel(self, task_id: int, timeout_seconds: int = 120) -> None:
        response = self.client.post(
            f"/apiv2/tasks/status/{task_id}/",
            data={"status": "finish"},
        )
        response.raise_for_status()
        value = response.json()
        if value.get("error"):
            raise CapeError(f"CAPE rejected task cancellation: {value}")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            status_payload = self.status(task_id)
            state = str(status_payload.get("status") or status_payload.get("data"))
            if state not in self.ACTIVE_STATES:
                return
            time.sleep(1)
        raise CapeError(f"CAPE task {task_id} did not stop before the cancellation deadline")
