from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class RegisterExecutorRequest(BaseModel):
    enrollment_token: str
    name: str = Field(min_length=1, max_length=128)
    public_key: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegisterExecutorResponse(BaseModel):
    executor_id: UUID
    credential: str


class CapabilityRequest(BaseModel):
    schema_version: str = "1.0"
    runtime_identity: str
    supported_stage_types: list[str]
    capabilities: dict[str, Any]


class ClaimRequest(BaseModel):
    stage_types: list[str]
    platforms: list[str] = Field(default_factory=list)


class ClaimArtifact(BaseModel):
    artifact_id: UUID
    kind: str
    sha256: str
    size_bytes: int
    media_type: str
    source_stage_type: str
    download_path: str


class ClaimResponse(BaseModel):
    stage_id: UUID
    attempt_id: UUID
    analysis_run_id: UUID
    stage_type: str
    platform: str
    sample_sha256: str
    lease_id: UUID
    lease_token: str
    lease_expires_at: datetime
    timeout_seconds: int
    input_artifacts: list[ClaimArtifact] = Field(default_factory=list)
    sample_download_path: str | None = None
    execution_configuration: dict[str, Any] = Field(default_factory=dict)
    recovered_native_task: dict[str, Any] | None = None


class HeartbeatRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    state: str = "running"


class NativeTaskRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    task_type: str
    native_task_id: str
    recovery_metadata: dict[str, Any] = Field(default_factory=dict)


class CompleteRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    outcome: str = "completed"
    detail: str | None = None


class FailRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    error_code: str
    detail: str
    retryable: bool = True


class CancellationAckRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    detail: str | None = None


class AndroidSessionReadyRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    scan_hash: str = Field(pattern="^[a-f0-9]{32,64}$")
    package_name: str | None = Field(default=None, max_length=512)
    main_activity: str | None = Field(default=None, max_length=1024)
    guest_ip: str | None = Field(default=None, max_length=64)
    duration_seconds: int = Field(default=900, ge=60, le=1800)


class AndroidCommandPollRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID


class AndroidCommandCompleteRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    command_id: UUID
    success: bool
    result: dict[str, Any] = Field(default_factory=dict)


class WindowsSessionReadyRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    cape_task_id: int = Field(ge=1)
    machine_label: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    console_url: str = Field(pattern=r"^ws://127\.0\.0\.1:[0-9]+/api/v1/console/", max_length=2048)
    duration_seconds: int = Field(default=600, ge=600, le=1800)


class WindowsSessionPollRequest(BaseModel):
    lease_id: UUID
    attempt_id: UUID


class ArtifactEnvelope(BaseModel):
    lease_id: UUID
    attempt_id: UUID
    kind: str
    sha256: str = Field(pattern="^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)
    media_type: str
    access_tier: str
    bundle_id: UUID | None = None


class WindowsProfileOperationCompleteRequest(BaseModel):
    operation_id: UUID
    success: bool
    native_operation_id: str | None = None
    cape_machine_label: str | None = None
    detail: str | None = None
