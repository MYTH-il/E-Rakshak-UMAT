from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class UserProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    locale: str = Field(min_length=2, max_length=32)
    timezone: str = Field(min_length=1, max_length=64)
    administrator: bool = False
    installed_software: list[str] = Field(default_factory=list, max_length=100)


class ProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    windows_version: str = Field(min_length=1, max_length=128)
    architecture: Literal["x64"]
    vcpus: int = Field(ge=1, le=32)
    ram_mb: int = Field(ge=2048, le=131072)
    disk_gb: int = Field(ge=40, le=2048)
    user_profile: UserProfile
    analysis_profile: str = Field(min_length=1, max_length=64)
    cape_machine_label: str | None = None
    cape_template: str = Field(pattern=r"^[A-Za-z0-9_.-]+$")


class MachineResult(BaseModel):
    operation_id: UUID
    machine_label: str


class ConsoleRequest(BaseModel):
    machine_label: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    duration_seconds: int = Field(default=600, ge=600, le=1800)


class ConsoleResult(BaseModel):
    console_url: str
    machine_label: str
    expires_at: str
