from __future__ import annotations

from ipaddress import IPv4Address
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LeaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_run_id: UUID
    platform: Literal["windows", "android"]
    guest_ip: IPv4Address
    ttl_seconds: int = Field(default=90, ge=30, le=300)


class LeaseResult(BaseModel):
    analysis_run_id: UUID
    platform: Literal["windows", "android"]
    guest_ip: IPv4Address
    expires_in_seconds: int
    capture_path: str


class Readiness(BaseModel):
    status: Literal["ready", "not_ready"]
    uplink: str
    dns_resolver: IPv4Address
    checks: dict[str, bool]
