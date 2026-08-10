from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CreateAndroidProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=64)
    display_name: str = Field(min_length=1, max_length=128)
    android_version: Literal["11"] = "11"
    api_level: Literal[30] = 30
    architecture: Literal["x86_64"] = "x86_64"
    system_image: Literal[
        "system-images;android-30;default;x86_64",
        "docker.io/redroid/redroid@sha256:d1ca0815eb68139a43d25a835e374559e9d18f5d5cea1a4288d4657c0074fb8d",
    ] = "system-images;android-30;default;x86_64"
    emulator_version: Literal["34.1.19", "redroid-11-d1ca0815"] = "34.1.19"
    vcpus: int = Field(default=4, ge=1, le=16)
    ram_mb: Literal[4096] = 4096
    writable_system: Literal[True] = True
    network_mode: Literal["controlled"] = "controlled"
    interaction_profile: Literal["deterministic_adb_v1"] = "deterministic_adb_v1"
    is_default: bool = False


class AndroidProfileResponse(BaseModel):
    id: UUID
    name: str
    display_name: str
    state: str
    android_version: str
    api_level: int
    architecture: str
    system_image: str
    emulator_version: str
    vcpus: int
    ram_mb: int
    writable_system: bool
    network_mode: str
    interaction_profile: str
    is_default: bool
    qualification: dict[str, object]
    created_at: datetime
    retired_at: datetime | None


class QualifyAndroidProfileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_run_id: UUID
