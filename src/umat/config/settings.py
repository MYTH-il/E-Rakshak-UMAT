from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="UMAT_", env_file=".env", extra="ignore", case_sensitive=False
    )

    environment: str = "development"
    database_url: str = "postgresql+asyncpg://umat:umat@127.0.0.1:55432/umat"
    api_host: str = "127.0.0.1"
    api_port: int = 8080
    quarantine_root: Path = Path("var/quarantine")
    artifact_root: Path = Path("var/artifacts")
    max_upload_bytes: int = 100 * 1024 * 1024
    session_ttl_seconds: int = 8 * 60 * 60
    lease_ttl_seconds: int = 60
    secure_cookies: bool = False
    allowed_hosts: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1", "testserver"])
    session_secret: str = "replace-this-development-secret"  # noqa: S105
    executor_enrollment_secret: str = "replace-this-enrollment-secret"  # noqa: S105
    audit_signing_key_path: Path | None = None
    c2_runtime_root: Path | None = None
    c2_work_root: Path = Path("var/c2-work")
    c2_runtime_commit: str = "bc5bb681495a02fa0ff2411087e5a00ece5b1ca3"
    c2_runtime_patch_sha256: str = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    c2_runtime_timeout_seconds: int = 1800
    c2_max_result_bytes: int = 1024 * 1024 * 1024
    winstdt_schema_root: Path | None = None
    windows_max_bundle_bytes: int = 2 * 1024 * 1024 * 1024
    android_max_bundle_bytes: int = 2 * 1024 * 1024 * 1024
    default_stage_max_attempts: int = 3
    default_stage_timeout_seconds: int = 1800
    stage_max_attempts: dict[str, int] = Field(default_factory=dict)
    stage_timeout_seconds: dict[str, int] = Field(default_factory=dict)
    login_window_seconds: int = 300
    login_max_attempts: int = 5

    @field_validator(
        "max_upload_bytes",
        "session_ttl_seconds",
        "lease_ttl_seconds",
        "c2_runtime_timeout_seconds",
        "c2_max_result_bytes",
        "windows_max_bundle_bytes",
        "android_max_bundle_bytes",
        "api_port",
    )
    @classmethod
    def positive(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("must be positive")
        return value

    @model_validator(mode="after")
    def validate_security(self) -> Settings:
        quarantine = self.quarantine_root.expanduser().resolve()
        artifacts = self.artifact_root.expanduser().resolve()
        if quarantine == artifacts or quarantine in artifacts.parents or artifacts in quarantine.parents:
            raise ValueError("quarantine and artifact roots must not overlap")
        if self.environment == "production":
            if not self.secure_cookies:
                raise ValueError("secure cookies are required in production")
            if self.session_secret.startswith("replace-this"):
                raise ValueError("a non-default session secret is required in production")
            if self.executor_enrollment_secret.startswith("replace-this"):
                raise ValueError("a non-default executor enrollment secret is required in production")
            for root in (quarantine, artifacts):
                if "www" in root.parts or "public" in root.parts:
                    raise ValueError("evidence storage cannot be inside a web root")
        self.quarantine_root = quarantine
        self.artifact_root = artifacts
        self.c2_work_root = self.c2_work_root.expanduser().resolve()
        if self.c2_runtime_root is not None:
            self.c2_runtime_root = self.c2_runtime_root.expanduser().resolve()
        if self.winstdt_schema_root is not None:
            self.winstdt_schema_root = self.winstdt_schema_root.expanduser().resolve()
        for name, value in self.stage_max_attempts.items():
            if value <= 0:
                raise ValueError(f"stage_max_attempts[{name}] must be positive")
        for name, value in self.stage_timeout_seconds.items():
            if value <= 0:
                raise ValueError(f"stage_timeout_seconds[{name}] must be positive")
        return self

    def policy_for_stage(self, stage_type: str) -> tuple[int, int]:
        return (
            self.stage_max_attempts.get(stage_type, self.default_stage_max_attempts),
            self.stage_timeout_seconds.get(stage_type, self.default_stage_timeout_seconds),
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
