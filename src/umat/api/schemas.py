from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class SessionResponse(BaseModel):
    user_id: UUID
    username: str
    roles: list[str]
    expires_at: datetime
    csrf_token: str | None = None


class DuplicateCase(BaseModel):
    case_id: UUID
    submitted_at: datetime
    result: str | None


class CreateCaseResponse(BaseModel):
    schema_version: str = "1.0"
    case_id: UUID
    submission_id: UUID
    analysis_run_id: UUID
    sample_sha256: str
    platform: str
    status: str
    duplicate_cases: list[DuplicateCase]


class CreateRunRequest(BaseModel):
    submission_id: UUID
    windows_profile_id: UUID | None = None
    android_profile_id: UUID | None = None
    network_mode: Literal["isolated_simulated", "real_world_egress"] = "isolated_simulated"
    c2_analysis_enabled: bool = False
    android_interactive: bool = False
    windows_interactive: bool = False


class RunActionResponse(BaseModel):
    analysis_run_id: UUID
    status: str
    result: str | None


class StageResponse(BaseModel):
    id: UUID
    stage_type: str
    state: str
    failure_code: str | None
    failure_detail: str | None


class RunResponse(BaseModel):
    id: UUID
    submission_id: UUID
    platform: str
    status: str
    result: str | None
    network_mode: str
    c2_analysis_enabled: bool
    android_interactive: bool = False
    windows_interactive: bool = False
    stages: list[StageResponse]
    windows_profile: dict[str, Any] | None = None
    android_profile: dict[str, Any] | None = None


class SubmissionResponse(BaseModel):
    id: UUID
    sample_sha256: str
    original_filename: str
    received_at: datetime


class CaseResponse(BaseModel):
    schema_version: str = "1.0"
    case_id: UUID
    owner_user_id: UUID
    title: str | None
    reference: str | None
    created_at: datetime
    submissions: list[SubmissionResponse]
    analysis_runs: list[RunResponse]
    report: dict[str, Any] | None = None


class CaseListItem(BaseModel):
    case_id: UUID
    title: str | None
    reference: str | None
    created_at: datetime
    latest_status: str | None
    latest_result: str | None
    latest_platform: str | None = None
    latest_verdict: str | None = None
    latest_headline: str | None = None


class ReportSnapshotResponse(BaseModel):
    snapshot_id: UUID
    revision: int
    evidence_digest: str
    generated_at: datetime
    report: dict[str, Any]


class ReportExportResponse(BaseModel):
    export_id: UUID
    artifact_id: UUID
    format: str
    format_version: str
    sha256: str
    size_bytes: int
    download_path: str
    created_at: datetime


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str
    detail: str
    request_id: str | None = None
