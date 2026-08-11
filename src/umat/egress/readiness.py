from __future__ import annotations

import httpx
from fastapi import HTTPException, status

from umat.config.settings import Settings


async def require_controlled_egress(settings: Settings, network_mode: str) -> None:
    if network_mode != "real_world_egress":
        return
    try:
        async with httpx.AsyncClient(base_url=settings.egress_broker_url, timeout=3) as client:
            response = await client.get("/health/ready")
            response.raise_for_status()
            readiness = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "controlled real-world egress is unavailable; the run remains fail-closed",
        ) from exc
    if readiness.get("status") != "ready":
        failed = [name for name, value in readiness.get("checks", {}).items() if not value]
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "controlled real-world egress is not ready"
            + (f": {', '.join(failed)}" if failed else ""),
        )
