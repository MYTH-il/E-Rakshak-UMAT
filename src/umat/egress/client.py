from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx


class EgressClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )

    def ready(self) -> bool:
        try:
            response = self.client.get("/health/ready")
            response.raise_for_status()
            value = response.json()
            return isinstance(value, dict) and value.get("status") == "ready"
        except httpx.HTTPError:
            return False

    def acquire(self, run_id: str, platform: str, guest_ip: str) -> dict[str, Any]:
        response = self.client.post(
            "/api/v1/leases",
            json={"analysis_run_id": run_id, "platform": platform, "guest_ip": guest_ip},
        )
        response.raise_for_status()
        return dict(response.json())

    def heartbeat(self, run_id: str) -> None:
        self.client.post(f"/api/v1/leases/{run_id}/heartbeat").raise_for_status()

    def revoke(self, run_id: str) -> Path | None:
        response = self.client.delete(f"/api/v1/leases/{run_id}")
        response.raise_for_status()
        path = response.headers.get("X-UMAT-Capture-Path")
        return Path(path) if path else None
