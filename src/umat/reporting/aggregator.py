from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.contracts.canonical import canonical_json
from umat.db.models import (
    AdaptationRecord,
    AnalysisRun,
    AnalysisStage,
    AndroidAnalysisMetadata,
    AndroidCapability,
    AndroidFinding,
    Artifact,
    AttributionResult,
    BundleImport,
    C2Finding,
    CaseReportSnapshot,
    ExfilEvent,
    NetworkObservation,
    Platform,
    ProvenanceLink,
    StageState,
    StageType,
    StaticIOC,
    Submission,
    TimelineEvent,
    Verdict,
    WindowsAnalysisMetadata,
    WindowsCapability,
    WindowsFinding,
)

SCHEMA_VERSION = "1.1"
CONFIDENCE_RANK = {"allowlisted": 0, "unconfirmed": 1, "weak": 2, "strong": 3, "confirmed": 4}
MALICIOUS_KINDS = {
    "command_and_control",
    "credential_theft",
    "exfil",
    "malware",
    "ransomware",
    "trojan",
}
NEGATIVE_BLOCKING_CAVEATS = {
    "android_api_monitoring_failed",
    "analysis_timed_out",
    "c2_analysis_failed",
    "host_telemetry_degraded",
    "network_capture_incomplete",
    "static_analysis_only",
    "stimulation_incomplete",
}


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _unique(values: Iterable[str | None]) -> list[str]:
    return sorted({value for value in values if value})


def _confidence(value: str) -> int:
    return CONFIDENCE_RANK.get(value, 1)


def filter_report_for_roles(report: dict[str, Any], roles: frozenset[str]) -> dict[str, Any]:
    """Return a role-safe copy of a report snapshot."""
    filtered = dict(report)
    is_technical = bool(roles & {"analyst", "administrator"})
    if not is_technical:
        filtered.pop("technical", None)
    allowed_tiers = (
        {"officer", "analyst", "administrator"}
        if "administrator" in roles
        else ({"officer", "analyst"} if "analyst" in roles else {"officer"})
    )
    filtered["artifacts"] = [
        dict(item)
        for item in report.get("artifacts", [])
        if item.get("access_tier") in allowed_tiers
    ]
    return filtered


class CaseAggregator:
    async def aggregate(self, db: AsyncSession, run_id: UUID) -> CaseReportSnapshot:
        run = await db.get(AnalysisRun, run_id)
        if not run:
            raise ValueError("analysis run not found")
        submission = await db.get(Submission, run.submission_id)
        if not submission:
            raise ValueError("analysis run submission not found")

        adaptations = list(
            (
                await db.scalars(
                    select(AdaptationRecord).where(
                        AdaptationRecord.analysis_run_id == run.id,
                        AdaptationRecord.active.is_(True),
                    )
                )
            ).all()
        )
        adaptation_ids = [item.id for item in adaptations]
        windows_adaptation = next(
            (item for item in adaptations if item.adapter_type == "windows"), None
        )
        android_adaptation = next(
            (item for item in adaptations if item.adapter_type == "android"), None
        )
        c2_adaptation = next((item for item in adaptations if item.adapter_type == "c2"), None)

        windows_findings = await self._rows(db, WindowsFinding, adaptation_ids)
        android_findings = await self._rows(db, AndroidFinding, adaptation_ids)
        c2_findings = await self._rows(db, C2Finding, adaptation_ids)
        windows_capabilities = await self._rows(db, WindowsCapability, adaptation_ids)
        android_capabilities = await self._rows(db, AndroidCapability, adaptation_ids)
        observations = await self._rows(db, NetworkObservation, adaptation_ids)
        exfil_events = await self._rows(db, ExfilEvent, adaptation_ids)
        iocs = await self._rows(db, StaticIOC, adaptation_ids)
        provenance = await self._rows(db, ProvenanceLink, adaptation_ids)
        timeline = await self._rows(db, TimelineEvent, adaptation_ids)
        attribution = await self._rows(db, AttributionResult, adaptation_ids)
        artifacts = list(
            (await db.scalars(select(Artifact).where(Artifact.analysis_run_id == run.id))).all()
        )
        imports = list(
            (
                await db.scalars(select(BundleImport).where(BundleImport.analysis_run_id == run.id))
            ).all()
        )
        stages = list(
            (
                await db.scalars(
                    select(AnalysisStage).where(AnalysisStage.analysis_run_id == run.id)
                )
            ).all()
        )
        windows_metadata = (
            await db.scalar(
                select(WindowsAnalysisMetadata).where(
                    WindowsAnalysisMetadata.adaptation_id == windows_adaptation.id
                )
            )
            if windows_adaptation
            else None
        )
        android_metadata = (
            await db.scalar(
                select(AndroidAnalysisMetadata).where(
                    AndroidAnalysisMetadata.adaptation_id == android_adaptation.id
                )
            )
            if android_adaptation
            else None
        )

        caveats = self._caveats(adaptations, stages, windows_metadata, run.platform)
        if not run.c2_analysis_enabled:
            caveats.append("c2_workflow_skipped")
        finding_items = self._findings(
            run, windows_findings, android_findings, c2_findings, adaptations, artifacts
        )
        verdict = self._verdict(
            finding_items,
            caveats,
            stages,
            windows_adaptation is not None or android_adaptation is not None,
            c2_adaptation is not None,
            run.c2_analysis_enabled,
        )
        headline = self._headline(verdict, finding_items, run.platform)
        generated_at = datetime.now(timezone.utc)
        report: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "analysis_run_id": str(run.id),
            "sample_sha256": submission.sample_sha256,
            "platform": run.platform.value,
            "network_mode": run.network_mode,
            "c2_analysis_enabled": run.c2_analysis_enabled,
            "generated_at": _iso(generated_at),
            "verdict": verdict.value,
            "headline": headline,
            "information_accessed": self._capabilities(
                windows_capabilities, exfil_events, run.platform, android_capabilities
            ),
            "destinations": self._destinations(observations),
            "provenance": self._provenance(provenance, run.platform),
            "caveats": caveats,
            "tested_profile": windows_metadata.profile_snapshot if windows_metadata else None,
            "artifacts": [
                {
                    "artifact_id": str(item.id),
                    "kind": item.kind,
                    "sha256": item.sha256,
                    "size_bytes": item.size_bytes,
                    "media_type": item.media_type,
                    "access_tier": item.access_tier.value,
                    "download_path": f"/api/v1/artifacts/{item.id}",
                    "created_at": _iso(item.created_at),
                }
                for item in sorted(artifacts, key=lambda row: row.created_at)
            ],
            "integrity": {
                "validated_bundle_count": sum(
                    1 for item in imports if bool(item.validation_result.get("valid"))
                ),
                "registered_artifact_count": len(artifacts),
                "bundle_hashes": _unique(item.bundle_sha256 for item in imports),
            },
            "technical": {
                "findings": finding_items,
                "iocs": [
                    {
                        "type": item.ioc_type,
                        "value": item.value,
                        "confidence": item.confidence,
                        "source": item.source,
                        "seen_in_traffic": item.seen_in_traffic,
                    }
                    for item in iocs
                ],
                "timeline": [
                    {
                        "occurred_at": _iso(item.occurred_at),
                        "actor": item.actor,
                        "description": item.description,
                        "mitre_technique_id": item.mitre_technique_id,
                    }
                    for item in sorted(timeline, key=lambda row: row.occurred_at)
                ],
                "attribution": [
                    {
                        "family": item.family,
                        "confidence": item.confidence,
                        "basis": item.basis,
                    }
                    for item in attribution
                ],
                "tool_versions": [
                    {
                        "adapter": item.adapter_type,
                        "schema_version": item.schema_version,
                        "validation": item.validation_summary,
                    }
                    for item in adaptations
                ],
                "platform_details": self._platform_details(windows_metadata, android_metadata),
            },
        }
        evidence_document = dict(report)
        evidence_document.pop("generated_at")
        evidence_digest = hashlib.sha256(canonical_json(evidence_document)).hexdigest()
        previous = await db.scalar(
            select(CaseReportSnapshot)
            .where(CaseReportSnapshot.analysis_run_id == run.id)
            .order_by(CaseReportSnapshot.revision.desc())
            .limit(1)
        )
        if previous and previous.evidence_digest == evidence_digest:
            return previous
        revision = (previous.revision + 1) if previous else 1
        snapshot = CaseReportSnapshot(
            case_id=run.case_id,
            analysis_run_id=run.id,
            schema_version=SCHEMA_VERSION,
            revision=revision,
            verdict=verdict,
            headline=headline,
            report_json=report,
            evidence_digest=evidence_digest,
            generated_at=generated_at,
        )
        db.add(snapshot)
        await db.flush()
        return snapshot

    @staticmethod
    async def _rows(db: AsyncSession, model: type[Any], adaptation_ids: list[UUID]) -> list[Any]:
        if not adaptation_ids:
            return []
        return list(
            (await db.scalars(select(model).where(model.adaptation_id.in_(adaptation_ids)))).all()
        )

    @staticmethod
    def _caveats(
        adaptations: list[AdaptationRecord],
        stages: list[AnalysisStage],
        metadata: WindowsAnalysisMetadata | None,
        platform: Platform,
    ) -> list[str]:
        values: set[str] = set()
        for item in adaptations:
            values.update(str(value) for value in item.validation_summary.get("caveats", []))
        if metadata and metadata.telemetry_degraded:
            values.add("host_telemetry_degraded")
        for stage in stages:
            if stage.state == StageState.PARTIAL:
                values.add(
                    "analysis_timed_out"
                    if stage.failure_code == "timeout"
                    else "host_telemetry_degraded"
                )
            if stage.state == StageState.FAILED and stage.stage_type == StageType.C2_ANALYSIS:
                values.add("c2_analysis_failed")
        if platform == Platform.ANDROID:
            values.add("c2_network_only")
        return sorted(values)

    @staticmethod
    def _findings(
        run: AnalysisRun,
        windows_findings: list[WindowsFinding],
        android_findings: list[AndroidFinding],
        c2_findings: list[C2Finding],
        adaptations: list[AdaptationRecord],
        artifacts: list[Artifact],
    ) -> list[dict[str, Any]]:
        adaptation_map = {item.id: item for item in adaptations}
        artifact_map: dict[UUID, list[str]] = {}
        for artifact in artifacts:
            if artifact.stage_id:
                artifact_map.setdefault(artifact.stage_id, []).append(str(artifact.id))
        findings: list[dict[str, Any]] = []
        for item in windows_findings:
            adaptation = adaptation_map[item.adaptation_id]
            findings.append(
                {
                    "finding_id": str(item.id),
                    "analysis_run_id": str(run.id),
                    "stage_id": str(adaptation.stage_id),
                    "platform": run.platform.value,
                    "source": "windows",
                    "kind": item.kind,
                    "category": item.category,
                    "confidence": item.confidence,
                    "evidence_level": "possible"
                    if item.category in {"static", "yara"}
                    else "observed",
                    "summary": item.summary,
                    "details": item.details,
                    "mitre_technique_ids": _unique(
                        [item.details.get("mitre_technique_id"), item.details.get("ttp")]
                    ),
                    "evidence_artifact_ids": artifact_map.get(adaptation.stage_id, []),
                    "caveats": [],
                }
            )
        for android_item in android_findings:
            adaptation = adaptation_map[android_item.adaptation_id]
            findings.append(
                {
                    "finding_id": str(android_item.id),
                    "analysis_run_id": str(run.id),
                    "stage_id": str(adaptation.stage_id),
                    "platform": "android",
                    "source": "android",
                    "kind": android_item.kind,
                    "category": android_item.category,
                    "confidence": android_item.confidence,
                    "evidence_level": android_item.evidence_level,
                    "summary": android_item.summary,
                    "details": android_item.details,
                    "mitre_technique_ids": _unique(
                        [
                            android_item.details.get("mitre_technique_id"),
                            android_item.details.get("masvs"),
                        ]
                    ),
                    "evidence_artifact_ids": artifact_map.get(adaptation.stage_id, []),
                    "caveats": [],
                }
            )
        for c2_item in c2_findings:
            android_network_only = run.platform == Platform.ANDROID and c2_item.finding_kind in {
                "correlation",
                "exfil",
            }
            findings.append(
                {
                    "finding_id": str(c2_item.id),
                    "analysis_run_id": str(run.id),
                    "stage_id": str(c2_item.stage_id),
                    "platform": c2_item.platform.value,
                    "source": "c2",
                    "kind": c2_item.finding_kind,
                    "category": "network",
                    "confidence": c2_item.confidence,
                    "evidence_level": (
                        "correlated"
                        if c2_item.finding_kind == "correlation" and not android_network_only
                        else "observed"
                    ),
                    "summary": (
                        "Potential outbound transfer behavior was observed, but no Android data item attribution was established."
                        if android_network_only
                        else c2_item.plain_language
                    ),
                    "details": c2_item.details,
                    "mitre_technique_ids": _unique([c2_item.details.get("mitre_technique_id")]),
                    "evidence_artifact_ids": artifact_map.get(c2_item.stage_id, []),
                    "caveats": _unique([c2_item.capped_by_caveat]),
                }
            )
        return sorted(
            findings, key=lambda item: (-_confidence(str(item["confidence"])), str(item["kind"]))
        )

    @staticmethod
    def _capabilities(
        capabilities: list[WindowsCapability],
        exfil_events: list[ExfilEvent],
        platform: Platform,
        android_capabilities: list[AndroidCapability] | None = None,
    ) -> list[dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for item in capabilities:
            result[item.capability] = {
                "data_type": item.capability,
                "evidence_level": "observed",
                "confidence": item.confidence,
                "summary": f"Access to {item.capability.replace('_', ' ')} was observed.",
            }
        for android_item in android_capabilities or []:
            current = result.get(android_item.data_type)
            candidate = {
                "data_type": android_item.data_type,
                "evidence_level": android_item.evidence_level,
                "confidence": android_item.confidence,
                "summary": (
                    f"Access to {android_item.data_type.replace('_', ' ')} was observed."
                    if android_item.evidence_level == "observed"
                    else f"The app declares permission to access {android_item.data_type.replace('_', ' ')}; use was not established."
                ),
            }
            if not current or _confidence(android_item.confidence) > _confidence(
                str(current["confidence"])
            ):
                result[android_item.data_type] = candidate
        if platform == Platform.WINDOWS:
            for exfil_item in exfil_events:
                if not exfil_item.data_type_accessed:
                    continue
                current = result.setdefault(
                    exfil_item.data_type_accessed,
                    {
                        "data_type": exfil_item.data_type_accessed,
                        "evidence_level": "observed",
                        "confidence": exfil_item.confidence,
                        "summary": f"Access to {exfil_item.data_type_accessed.replace('_', ' ')} was observed.",
                    },
                )
                current["evidence_level"] = "correlated"
                current["confidence"] = exfil_item.confidence
                current["summary"] = (
                    f"Access to {exfil_item.data_type_accessed.replace('_', ' ')} was correlated with network activity."
                )
        return sorted(result.values(), key=lambda item: str(item["data_type"]))

    @staticmethod
    def _destinations(observations: list[NetworkObservation]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, int | None], dict[str, Any]] = {}
        for item in observations:
            value = item.destination_domain or item.destination_ip
            if not value:
                continue
            key = (value, item.destination_port)
            grouped[key] = {
                "value": value,
                "ip": item.destination_ip,
                "domain": item.destination_domain,
                "port": item.destination_port,
                "protocol": item.protocol,
                "first_observed_at": _iso(item.observed_at),
            }
        return sorted(grouped.values(), key=lambda item: (str(item["value"]), item["port"] or 0))

    @staticmethod
    def _provenance(links: list[ProvenanceLink], platform: Platform) -> list[dict[str, Any]]:
        if platform == Platform.ANDROID:
            return [
                {
                    "statement": (
                        f"Network activity involving {item.destination} was observed; it is not linked to a specific Android data item."
                        if item.destination
                        else "Network activity was observed; it is not linked to a specific Android data item."
                    ),
                    "item_type": None,
                    "destination": item.destination,
                    "source_event_id": item.source_event_id,
                }
                for item in links
            ]
        return [
            {
                "statement": item.statement,
                "item_type": item.item_type,
                "destination": item.destination,
                "source_event_id": item.source_event_id,
            }
            for item in links
        ]

    @staticmethod
    def _verdict(
        findings: list[dict[str, Any]],
        caveats: list[str],
        stages: list[AnalysisStage],
        has_platform: bool,
        has_c2: bool,
        requires_c2: bool = True,
    ) -> Verdict:
        platform_stage = next(
            (item for item in stages if item.stage_type == StageType.PLATFORM_ANALYSIS), None
        )
        if not has_platform and platform_stage and platform_stage.state == StageState.FAILED:
            return Verdict.FAILED
        for finding in findings:
            details = finding.get("details") or {}
            configured_malicious = (
                details.get("verdict") == "malicious" or details.get("malicious") is True
            )
            if finding["confidence"] == "confirmed" and (
                finding["kind"] in MALICIOUS_KINDS or configured_malicious
            ):
                return Verdict.MALICIOUS
        if any(_confidence(str(item["confidence"])) >= _confidence("weak") for item in findings):
            return Verdict.SUSPICIOUS
        if (
            not has_platform
            or (requires_c2 and not has_c2)
            or NEGATIVE_BLOCKING_CAVEATS.intersection(caveats)
        ):
            return Verdict.INCONCLUSIVE
        mandatory = {
            StageType.PLATFORM_ANALYSIS,
            StageType.PLATFORM_ADAPTATION,
        }
        if requires_c2:
            mandatory.update({StageType.C2_ANALYSIS, StageType.C2_ADAPTATION})
        completed = {
            item.stage_type
            for item in stages
            if item.state in {StageState.COMPLETED, StageState.PARTIAL}
        }
        return (
            Verdict.NO_MALICIOUS_ACTIVITY_OBSERVED
            if mandatory.issubset(completed)
            else Verdict.INCONCLUSIVE
        )

    @staticmethod
    def _headline(verdict: Verdict, findings: list[dict[str, Any]], platform: Platform) -> str:
        platform_name = "Windows" if platform == Platform.WINDOWS else "Android"
        if verdict == Verdict.MALICIOUS:
            return f"Confirmed malicious behavior was detected during the {platform_name} analysis."
        if verdict == Verdict.SUSPICIOUS:
            count = len([item for item in findings if _confidence(str(item["confidence"])) >= 2])
            return f"{count} suspicious finding{'s' if count != 1 else ''} require analyst review."
        if verdict == Verdict.NO_MALICIOUS_ACTIVITY_OBSERVED:
            return "No malicious activity was observed during the completed analysis window."
        if verdict == Verdict.FAILED:
            return "The platform analysis failed before a valid result was produced."
        return "The available evidence is insufficient for a reliable conclusion."

    @staticmethod
    def _platform_details(
        windows: WindowsAnalysisMetadata | None,
        android: AndroidAnalysisMetadata | None,
    ) -> dict[str, Any] | None:
        if windows:
            return {
                "cape_task_id": windows.cape_task_id,
                "cape_package": windows.cape_package,
                "detected_type": windows.detected_type,
                "machine_label": windows.machine_label,
                "network_mode": windows.network_mode,
                "telemetry_degraded": windows.telemetry_degraded,
            }
        if android:
            return {
                "package_name": android.package_name,
                "app_name": android.app_name,
                "version_name": android.version_name,
                "version_code": android.version_code,
                "mobsf_scan_hash": android.scan_hash,
                "api_level": android.api_level,
                "avd_name": android.avd_name,
                "guest_ip": android.guest_ip,
                "dynamic_completed": android.dynamic_completed,
                "stimulation": android.stimulation,
            }
        return None
