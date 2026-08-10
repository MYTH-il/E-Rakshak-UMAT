from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class UpdateCaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, max_length=256)
    reference: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def has_change(self) -> UpdateCaseRequest:
        if not self.model_fields_set:
            raise ValueError("at least one case field must be supplied")
        return self


class RetryRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(min_length=3, max_length=1000)


class RetryRunResponse(BaseModel):
    source_run_id: UUID
    analysis_run_id: UUID
    status: str
    reason: str


class RunStageDiagnostic(BaseModel):
    id: UUID
    stage_type: str
    state: str
    attempt_count: int
    latest_attempt_state: str | None
    latest_executor_id: UUID | None
    failure_code: str | None
    failure_detail: str | None
    created_at: datetime
    updated_at: datetime


class RecentRunItem(BaseModel):
    id: UUID
    case_id: UUID
    case_title: str | None
    case_reference: str | None
    submission_id: UUID
    filename: str
    sample_sha256: str
    platform: str
    status: str
    result: str | None
    network_mode: str
    c2_analysis_enabled: bool
    android_interactive: bool
    profile: dict[str, Any] | None
    retry_eligible: bool
    created_at: datetime
    updated_at: datetime
    stages: list[RunStageDiagnostic]


class RecentRunsResponse(BaseModel):
    items: list[RecentRunItem]
    page: int
    page_size: int
    total: int
    pages: int


class WorkerLeaseResponse(BaseModel):
    lease_id: UUID
    stage_id: UUID
    analysis_run_id: UUID
    case_id: UUID
    stage_type: str
    platform: str
    state: str
    last_heartbeat_at: datetime
    expires_at: datetime


class WorkerInventoryItem(BaseModel):
    id: UUID
    name: str
    executor_type: str
    status: str
    supported_stage_types: list[str]
    runtime_identity: str | None
    capability_schema_version: str | None
    capabilities: dict[str, Any]
    metadata: dict[str, Any]
    last_seen_at: datetime | None
    created_at: datetime
    heartbeat_state: Literal["online", "stale", "never_seen", "disabled"]
    active_workload: int
    active_leases: list[WorkerLeaseResponse]
    compatibility: dict[str, Any]


class WorkerInventoryResponse(BaseModel):
    generated_at: datetime
    items: list[WorkerInventoryItem]
