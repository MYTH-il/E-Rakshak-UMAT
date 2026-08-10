from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class UserProfileSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    locale: str = Field(default="en-US", min_length=2, max_length=32)
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    administrator: bool = False
    installed_software: list[str] = Field(default_factory=list, max_length=100)


class CreateWindowsProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    display_name: str = Field(min_length=1, max_length=128)
    windows_version: str = Field(min_length=1, max_length=128)
    architecture: Literal["x64"] = "x64"
    vcpus: int = Field(ge=1, le=32)
    ram_mb: int = Field(ge=2048, le=131072)
    disk_gb: int = Field(ge=40, le=2048)
    user_profile: UserProfileSpec
    analysis_profile: str = Field(
        default="standard",
        pattern=r"^(standard|deep_static|tls_intercept|full_memory|full_investigation)$",
    )
    cape_template: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.-]+$")
    is_default: bool = False


class WindowsProfileResponse(BaseModel):
    id: UUID
    name: str
    display_name: str
    state: str
    windows_version: str
    architecture: str
    vcpus: int
    ram_mb: int
    disk_gb: int
    user_profile: dict[str, Any]
    analysis_profile: str
    cape_machine_label: str | None
    cape_template: str
    is_default: bool
    created_at: datetime
    retired_at: datetime | None
    error_detail: str | None


class WindowsProfileActionResponse(BaseModel):
    profile: WindowsProfileResponse
    operation_id: UUID


class UpdateWindowsProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    analysis_profile: Literal[
        "standard", "deep_static", "tls_intercept", "full_memory", "full_investigation"
    ] | None = None
    is_default: bool | None = None

    @model_validator(mode="after")
    def has_change(self) -> UpdateWindowsProfileRequest:
        if not self.model_fields_set:
            raise ValueError("at least one profile field must be supplied")
        return self


class WindowsProfileOperationResponse(BaseModel):
    id: UUID
    operation_type: str
    state: str
    executor_id: UUID | None
    native_operation_id: str | None
    result: dict[str, Any]
    error_detail: str | None
    created_at: datetime
    completed_at: datetime | None


class WindowsProfileDetailResponse(BaseModel):
    profile: WindowsProfileResponse
    operations: list[WindowsProfileOperationResponse]
