from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class InputArtifact(BaseModel):
    artifact_id: UUID
    kind: str
    sha256: str
    size_bytes: int
    media_type: str
    source_stage_type: str
    local_path: Path


class C2AnalysisContext(BaseModel):
    schema_version: str = "1.0"
    analysis_run_id: UUID
    platform: str
    sample_sha256: str
    pcap: InputArtifact
    platform_manifest: InputArtifact
    access_events: InputArtifact | None = None
    static_prior: InputArtifact | None = None
    analysis_started_at: datetime
    analysis_ended_at: datetime
    guest_ip: str | None = None
    correlation_eligible: bool = False
    caveats: list[str] = Field(default_factory=list)

    def contract_document(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "analysis_run_id": str(self.analysis_run_id),
            "platform": self.platform,
            "sample_sha256": self.sample_sha256,
            "pcap": {
                "artifact_id": str(self.pcap.artifact_id),
                "sha256": self.pcap.sha256,
            },
            "analysis_window": {
                "started_at": self.analysis_started_at.isoformat(),
                "ended_at": self.analysis_ended_at.isoformat(),
            },
            "guest_ip": self.guest_ip,
            "access_events": {
                "artifact_id": str(self.access_events.artifact_id)
                if self.access_events
                else None,
                "source": "etl_derived" if self.access_events else "unavailable",
                "correlation_eligible": self.correlation_eligible,
            },
            "static_prior": {
                "artifact_id": str(self.static_prior.artifact_id)
                if self.static_prior
                else None
            },
            "platform_manifest": {
                "artifact_id": str(self.platform_manifest.artifact_id),
                "sha256": self.platform_manifest.sha256,
            },
        }


class NativeC2Result(BaseModel):
    events: list[dict[str, Any]]
    attribution: list[dict[str, Any]] = Field(default_factory=list)
    provenance: list[dict[str, Any]] = Field(default_factory=list)
    timeline: list[dict[str, Any]] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    runtime_identity: str
    tool_versions: dict[str, str] = Field(default_factory=dict)
