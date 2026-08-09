from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, TypeEngine
from uuid6 import uuid7

from umat.db.base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def json_dict_type() -> TypeEngine[Any]:
    return MutableDict.as_mutable(JSON().with_variant(JSONB(), "postgresql"))


def json_list_type() -> TypeEngine[Any]:
    return MutableList.as_mutable(JSON().with_variant(JSONB(), "postgresql"))


def db_enum(enum_class: type[enum.StrEnum], name: str) -> Enum:
    return Enum(enum_class, name=name, values_callable=lambda values: [item.value for item in values])


class Platform(enum.StrEnum):
    WINDOWS = "windows"
    ANDROID = "android"


class RunStatus(enum.StrEnum):
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    TERMINAL = "terminal"


class RunResult(enum.StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNSUPPORTED = "unsupported"


class StageType(enum.StrEnum):
    PLATFORM_ANALYSIS = "platform_analysis"
    C2_ANALYSIS = "c2_analysis"
    PLATFORM_ADAPTATION = "platform_adaptation"
    C2_ADAPTATION = "c2_adaptation"
    CASE_AGGREGATION = "case_aggregation"
    REPORT_GENERATION = "report_generation"


class StageState(enum.StrEnum):
    WAITING = "waiting"
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNSUPPORTED = "unsupported"


class AttemptState(enum.StrEnum):
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class AccessTier(enum.StrEnum):
    OFFICER = "officer"
    ANALYST = "analyst"
    ADMINISTRATOR = "administrator"


class ExecutorStatus(enum.StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"


class WindowsProfileState(enum.StrEnum):
    PROVISIONING = "provisioning"
    ACTIVE = "active"
    RETIRED = "retired"
    DELETING = "deleting"
    DELETED = "deleted"
    ERROR = "error"


class WindowsProfileOperationType(enum.StrEnum):
    CREATE = "create"
    DELETE = "delete"


class WindowsProfileOperationState(enum.StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    COMPLETED = "completed"
    FAILED = "failed"


class Verdict(enum.StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    NO_MALICIOUS_ACTIVITY_OBSERVED = "no_malicious_activity_observed"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


class ExportFormat(enum.StrEnum):
    JSON = "json"
    PDF = "pdf"
    CSV = "csv"


class User(Base):
    __tablename__ = "users"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    roles: Mapped[list[Role]] = relationship(secondary="user_roles", lazy="selectin")


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True)


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    user: Mapped[User] = relationship(lazy="selectin")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    username: Mapped[str] = mapped_column(String(128), index=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    succeeded: Mapped[bool] = mapped_column(Boolean, default=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    owner_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), index=True)
    title: Mapped[str | None] = mapped_column(String(256))
    reference: Mapped[str | None] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    submissions: Mapped[list[Submission]] = relationship(lazy="selectin")
    runs: Mapped[list[AnalysisRun]] = relationship(lazy="selectin")


class Sample(Base):
    __tablename__ = "samples"
    sha256: Mapped[str] = mapped_column(String(64), primary_key=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    media_type: Mapped[str] = mapped_column(String(255))
    object_key: Mapped[str] = mapped_column(String(255), unique=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Submission(Base):
    __tablename__ = "submissions"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), index=True)
    uploader_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    sample_sha256: Mapped[str] = mapped_column(ForeignKey("samples.sha256", ondelete="RESTRICT"), index=True)
    original_filename: Mapped[str] = mapped_column(String(512))
    storage_id: Mapped[UUID] = mapped_column(Uuid, unique=True, default=uuid7)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    custody_state: Mapped[str] = mapped_column(String(32), default="stored")


class CaseSample(Base):
    __tablename__ = "case_samples"
    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), primary_key=True)
    sample_sha256: Mapped[str] = mapped_column(ForeignKey("samples.sha256", ondelete="RESTRICT"), primary_key=True)


class AnalysisRun(Base):
    __tablename__ = "analysis_runs"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    case_id: Mapped[UUID] = mapped_column(ForeignKey("cases.id", ondelete="RESTRICT"), index=True)
    submission_id: Mapped[UUID] = mapped_column(ForeignKey("submissions.id", ondelete="RESTRICT"), index=True)
    platform: Mapped[Platform] = mapped_column(db_enum(Platform, "platform"))
    status: Mapped[RunStatus] = mapped_column(db_enum(RunStatus, "run_status"), index=True)
    result: Mapped[RunResult | None] = mapped_column(db_enum(RunResult, "run_result"))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancellation_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    stages: Mapped[list[AnalysisStage]] = relationship(lazy="selectin")
    windows_configuration: Mapped[WindowsRunConfiguration | None] = relationship(
        lazy="selectin", uselist=False
    )


class AnalysisStage(Base):
    __tablename__ = "analysis_stages"
    __table_args__ = (UniqueConstraint("analysis_run_id", "stage_type"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    analysis_run_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True)
    stage_type: Mapped[StageType] = mapped_column(db_enum(StageType, "stage_type"), index=True)
    state: Mapped[StageState] = mapped_column(db_enum(StageState, "stage_state"), index=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=1800)
    failure_code: Mapped[str | None] = mapped_column(String(128))
    failure_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    attempts: Mapped[list[AnalysisAttempt]] = relationship(lazy="selectin")


class StageDependency(Base):
    __tablename__ = "stage_dependencies"
    parent_stage_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_stages.id", ondelete="RESTRICT"), primary_key=True)
    child_stage_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_stages.id", ondelete="RESTRICT"), primary_key=True)


class Executor(Base):
    __tablename__ = "executors"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    executor_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[ExecutorStatus] = mapped_column(db_enum(ExecutorStatus, "executor_status"), default=ExecutorStatus.ACTIVE)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    supported_stage_types: Mapped[list[str]] = mapped_column(json_list_type(), default=list)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(json_dict_type(), default=dict)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExecutorCredential(Base):
    __tablename__ = "executor_credentials"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    executor_id: Mapped[UUID] = mapped_column(ForeignKey("executors.id", ondelete="RESTRICT"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[list[str]] = mapped_column(json_list_type(), default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExecutorRequest(Base):
    __tablename__ = "executor_requests"
    __table_args__ = (
        UniqueConstraint("executor_id", "idempotency_key", name="uq_executor_requests_idempotency"),
        UniqueConstraint("executor_id", "nonce", name="uq_executor_requests_nonce"),
    )
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    executor_id: Mapped[UUID] = mapped_column(ForeignKey("executors.id", ondelete="RESTRICT"), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128))
    nonce: Mapped[str] = mapped_column(String(128))
    request_hash: Mapped[str] = mapped_column(String(64))
    response_json: Mapped[dict[str, Any] | None] = mapped_column(json_dict_type())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ExecutorEnrollmentToken(Base):
    __tablename__ = "executor_enrollment_tokens"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    executor_type: Mapped[str] = mapped_column(String(64))
    scopes: Mapped[list[str]] = mapped_column(json_list_type(), default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AnalysisAttempt(Base):
    __tablename__ = "analysis_attempts"
    __table_args__ = (UniqueConstraint("stage_id", "attempt_number"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    stage_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_stages.id", ondelete="RESTRICT"), index=True)
    executor_id: Mapped[UUID] = mapped_column(ForeignKey("executors.id", ondelete="RESTRICT"), index=True)
    attempt_number: Mapped[int] = mapped_column(Integer)
    state: Mapped[AttemptState] = mapped_column(db_enum(AttemptState, "attempt_state"))
    error_code: Mapped[str | None] = mapped_column(String(128))
    error_detail: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ExecutorLease(Base):
    __tablename__ = "executor_leases"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    stage_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_stages.id", ondelete="RESTRICT"), index=True)
    attempt_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_attempts.id", ondelete="RESTRICT"), unique=True)
    executor_id: Mapped[UUID] = mapped_column(ForeignKey("executors.id", ondelete="RESTRICT"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    release_reason: Mapped[str | None] = mapped_column(String(128))


class BackendTask(Base):
    __tablename__ = "backend_tasks"
    __table_args__ = (UniqueConstraint("executor_id", "task_type", "native_task_id"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    stage_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_stages.id", ondelete="RESTRICT"), index=True)
    attempt_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_attempts.id", ondelete="RESTRICT"))
    executor_id: Mapped[UUID] = mapped_column(ForeignKey("executors.id", ondelete="RESTRICT"))
    task_type: Mapped[str] = mapped_column(String(64))
    native_task_id: Mapped[str] = mapped_column(String(255))
    recovery_metadata: Mapped[dict[str, Any]] = mapped_column(json_dict_type(), default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BackendCapabilitySnapshot(Base):
    __tablename__ = "backend_capability_snapshots"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    executor_id: Mapped[UUID] = mapped_column(ForeignKey("executors.id", ondelete="RESTRICT"), index=True)
    runtime_identity: Mapped[str] = mapped_column(String(255))
    schema_version: Mapped[str] = mapped_column(String(16))
    capabilities: Mapped[dict[str, Any]] = mapped_column(json_dict_type())
    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Artifact(Base):
    __tablename__ = "artifacts"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    analysis_run_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True)
    stage_id: Mapped[UUID | None] = mapped_column(ForeignKey("analysis_stages.id", ondelete="RESTRICT"), index=True)
    attempt_id: Mapped[UUID | None] = mapped_column(ForeignKey("analysis_attempts.id", ondelete="RESTRICT"))
    kind: Mapped[str] = mapped_column(String(64), index=True)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    media_type: Mapped[str] = mapped_column(String(255))
    object_key: Mapped[str] = mapped_column(String(255))
    access_tier: Mapped[AccessTier] = mapped_column(db_enum(AccessTier, "access_tier"))
    bundle_id: Mapped[UUID | None] = mapped_column(Uuid, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BundleImport(Base):
    __tablename__ = "bundle_imports"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    analysis_run_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True)
    stage_id: Mapped[UUID] = mapped_column(ForeignKey("analysis_stages.id", ondelete="RESTRICT"))
    artifact_id: Mapped[UUID] = mapped_column(ForeignKey("artifacts.id", ondelete="RESTRICT"))
    bundle_sha256: Mapped[str] = mapped_column(String(64), index=True)
    schema_version: Mapped[str] = mapped_column(String(16))
    validation_result: Mapped[dict[str, Any]] = mapped_column(json_dict_type())
    imported_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    event_id: Mapped[UUID] = mapped_column(Uuid, unique=True, default=uuid7)
    actor_type: Mapped[str] = mapped_column(String(32))
    actor_id: Mapped[str | None] = mapped_column(String(128), index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(128), index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(json_dict_type())
    previous_hash: Mapped[str] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SignedAuditRoot(Base):
    __tablename__ = "signed_audit_roots"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    first_sequence: Mapped[int] = mapped_column(BigInteger)
    last_sequence: Mapped[int] = mapped_column(BigInteger)
    root_hash: Mapped[str] = mapped_column(String(64))
    key_id: Mapped[str] = mapped_column(String(128))
    signature: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AdaptationRecord(Base):
    __tablename__ = "adaptation_records"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    stage_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_stages.id", ondelete="RESTRICT"), index=True
    )
    source_artifact_id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT")
    )
    adapter_type: Mapped[str] = mapped_column(String(32), index=True)
    schema_version: Mapped[str] = mapped_column(String(16))
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    validation_summary: Mapped[dict[str, Any]] = mapped_column(json_dict_type())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class C2Finding(Base):
    __tablename__ = "c2_findings"
    __table_args__ = (UniqueConstraint("adaptation_id", "source_event_id"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    stage_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_stages.id", ondelete="RESTRICT"), index=True
    )
    source_event_id: Mapped[str] = mapped_column(String(64))
    finding_kind: Mapped[str] = mapped_column(String(64), index=True)
    plain_language: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(32), index=True)
    capped_by_caveat: Mapped[str | None] = mapped_column(String(128))
    platform: Mapped[Platform] = mapped_column(db_enum(Platform, "platform"))
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class NetworkObservation(Base):
    __tablename__ = "network_observations"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    source_event_id: Mapped[str] = mapped_column(String(64))
    destination_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    destination_domain: Mapped[str | None] = mapped_column(String(512), index=True)
    protocol: Mapped[str | None] = mapped_column(String(32))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class ExfilEvent(Base):
    __tablename__ = "exfil_events"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    source_event_id: Mapped[str] = mapped_column(String(64))
    data_type_accessed: Mapped[str | None] = mapped_column(String(64))
    access_api_call: Mapped[str | None] = mapped_column(String(512))
    destination: Mapped[str | None] = mapped_column(String(512))
    confidence: Mapped[str] = mapped_column(String(32))
    evidence_hash: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class StaticIOC(Base):
    __tablename__ = "static_iocs"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    value: Mapped[str] = mapped_column(Text)
    confidence: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(128))
    seen_in_traffic: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ProvenanceLink(Base):
    __tablename__ = "provenance_links"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    source_event_id: Mapped[str | None] = mapped_column(String(64))
    item_type: Mapped[str | None] = mapped_column(String(64))
    destination: Mapped[str | None] = mapped_column(String(512))
    statement: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class TimelineEvent(Base):
    __tablename__ = "timeline_events"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(32))
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class AttributionResult(Base):
    __tablename__ = "attribution_results"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    family: Mapped[str] = mapped_column(String(255))
    confidence: Mapped[str] = mapped_column(String(32))
    basis: Mapped[str] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class WindowsVMProfile(Base):
    __tablename__ = "windows_vm_profiles"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    name: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    state: Mapped[WindowsProfileState] = mapped_column(
        db_enum(WindowsProfileState, "windows_profile_state"), index=True
    )
    windows_version: Mapped[str] = mapped_column(String(128))
    architecture: Mapped[str] = mapped_column(String(16), default="x64")
    vcpus: Mapped[int] = mapped_column(Integer)
    ram_mb: Mapped[int] = mapped_column(Integer)
    disk_gb: Mapped[int] = mapped_column(Integer)
    user_profile: Mapped[dict[str, Any]] = mapped_column(json_dict_type(), default=dict)
    analysis_profile: Mapped[str] = mapped_column(String(64), default="standard")
    cape_machine_label: Mapped[str | None] = mapped_column(String(128), unique=True)
    cape_template: Mapped[str] = mapped_column(String(128))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_detail: Mapped[str | None] = mapped_column(Text)

    def snapshot(self) -> dict[str, Any]:
        return {
            "profile_id": str(self.id),
            "name": self.name,
            "windows_version": self.windows_version,
            "architecture": self.architecture,
            "vcpus": self.vcpus,
            "ram_mb": self.ram_mb,
            "disk_gb": self.disk_gb,
            "user_profile": self.user_profile,
            "analysis_profile": self.analysis_profile,
            "cape_machine_label": self.cape_machine_label,
            "cape_template": self.cape_template,
        }


class WindowsProfileOperation(Base):
    __tablename__ = "windows_profile_operations"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    profile_id: Mapped[UUID] = mapped_column(
        ForeignKey("windows_vm_profiles.id", ondelete="RESTRICT"), index=True
    )
    operation_type: Mapped[WindowsProfileOperationType] = mapped_column(
        db_enum(WindowsProfileOperationType, "windows_profile_operation_type")
    )
    state: Mapped[WindowsProfileOperationState] = mapped_column(
        db_enum(WindowsProfileOperationState, "windows_profile_operation_state"), index=True
    )
    executor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("executors.id", ondelete="RESTRICT")
    )
    lease_token_hash: Mapped[str | None] = mapped_column(String(64), unique=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    native_operation_id: Mapped[str | None] = mapped_column(String(255))
    result: Mapped[dict[str, Any]] = mapped_column(json_dict_type(), default=dict)
    error_detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WindowsRunConfiguration(Base):
    __tablename__ = "windows_run_configurations"
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), primary_key=True
    )
    profile_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("windows_vm_profiles.id", ondelete="RESTRICT"), index=True
    )
    profile_snapshot: Mapped[dict[str, Any]] = mapped_column(json_dict_type(), default=dict)
    selected_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class WindowsAnalysisMetadata(Base):
    __tablename__ = "windows_analysis_metadata"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), unique=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    cape_task_id: Mapped[int] = mapped_column(Integer, index=True)
    cape_package: Mapped[str | None] = mapped_column(String(128))
    detected_type: Mapped[str | None] = mapped_column(String(255))
    machine_label: Mapped[str | None] = mapped_column(String(128))
    profile_snapshot: Mapped[dict[str, Any]] = mapped_column(json_dict_type())
    network_mode: Mapped[str | None] = mapped_column(String(64))
    telemetry_degraded: Mapped[bool] = mapped_column(Boolean, default=False)
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class WindowsFinding(Base):
    __tablename__ = "windows_findings"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    category: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(128), index=True)
    confidence: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class WindowsCapability(Base):
    __tablename__ = "windows_capabilities"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    capability: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(64))
    confidence: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class AndroidAnalysisMetadata(Base):
    __tablename__ = "android_analysis_metadata"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), unique=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    package_name: Mapped[str | None] = mapped_column(String(255), index=True)
    app_name: Mapped[str | None] = mapped_column(String(255))
    version_name: Mapped[str | None] = mapped_column(String(128))
    version_code: Mapped[str | None] = mapped_column(String(64))
    scan_hash: Mapped[str] = mapped_column(String(32), index=True)
    api_level: Mapped[int] = mapped_column(Integer)
    avd_name: Mapped[str] = mapped_column(String(255))
    guest_ip: Mapped[str | None] = mapped_column(String(64))
    dynamic_completed: Mapped[bool] = mapped_column(Boolean, default=False)
    stimulation: Mapped[dict[str, Any]] = mapped_column(json_dict_type())
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class AndroidFinding(Base):
    __tablename__ = "android_findings"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    phase: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(128), index=True)
    severity: Mapped[str | None] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(32))
    evidence_level: Mapped[str] = mapped_column(String(32))
    summary: Mapped[str] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class AndroidCapability(Base):
    __tablename__ = "android_capabilities"
    __table_args__ = (UniqueConstraint("adaptation_id", "data_type", "evidence_level"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    adaptation_id: Mapped[UUID] = mapped_column(
        ForeignKey("adaptation_records.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    data_type: Mapped[str] = mapped_column(String(64), index=True)
    evidence_level: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(32))
    source: Mapped[str] = mapped_column(String(128))
    details: Mapped[dict[str, Any]] = mapped_column(json_dict_type())


class CaseReportSnapshot(Base):
    """An immutable, versioned aggregate of normalized evidence for one run."""

    __tablename__ = "case_report_snapshots"
    __table_args__ = (UniqueConstraint("analysis_run_id", "revision"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    schema_version: Mapped[str] = mapped_column(String(16))
    revision: Mapped[int] = mapped_column(Integer)
    verdict: Mapped[Verdict] = mapped_column(db_enum(Verdict, "verdict"), index=True)
    headline: Mapped[str] = mapped_column(Text)
    report_json: Mapped[dict[str, Any]] = mapped_column(json_dict_type())
    evidence_digest: Mapped[str] = mapped_column(String(64), index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ReportExport(Base):
    """Immutable registration of a rendered report artifact."""

    __tablename__ = "report_exports"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    case_id: Mapped[UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="RESTRICT"), index=True
    )
    analysis_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("analysis_runs.id", ondelete="RESTRICT"), index=True
    )
    report_snapshot_id: Mapped[UUID] = mapped_column(
        ForeignKey("case_report_snapshots.id", ondelete="RESTRICT"), index=True
    )
    artifact_id: Mapped[UUID] = mapped_column(
        ForeignKey("artifacts.id", ondelete="RESTRICT"), unique=True
    )
    export_format: Mapped[ExportFormat] = mapped_column(
        db_enum(ExportFormat, "report_export_format"), index=True
    )
    format_version: Mapped[str] = mapped_column(String(16))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    requested_by_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


Index("ix_active_lease_stage", ExecutorLease.stage_id, ExecutorLease.released_at)
