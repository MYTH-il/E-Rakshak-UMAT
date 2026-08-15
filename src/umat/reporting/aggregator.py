from __future__ import annotations

import hashlib
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
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
from umat.geolocation import lookup_ip
from umat.windows.cape import credible_legacy_static_indicator

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
    "application_data_collection_failed",
    "analysis_timed_out",
    "c2_analysis_failed",
    "host_telemetry_degraded",
    "network_capture_incomplete",
    "static_analysis_only",
    "stimulation_incomplete",
}


# Officer-facing wording for each shared data type. The vocabulary values are
# machine identifiers; an officer reads this instead. Keep every phrase usable
# in the middle of a sentence ("This sample accessed <phrase> and ...").
_DATA_TYPE_PHRASES: dict[str, str] = {
    "browser_credentials": "saved website passwords",
    "browser_cookies": "saved website login sessions",
    "browser_history": "web browsing history",
    "keystrokes": "everything typed on the keyboard",
    "screenshot": "pictures of the screen",
    "clipboard": "copied and pasted content",
    "crypto_wallet": "cryptocurrency wallet files",
    "system_info": "details about the computer",
    "file_access": "files stored on the system",
    "documents": "personal documents",
    "sms": "text messages, including one-time passcodes",
    "contacts": "the contact list",
    "call_log": "the record of calls made and received",
    "location": "the device's location",
    "camera": "the camera",
    "microphone": "the microphone",
    "calendar": "calendar entries",
    "device_identity": "identifiers that uniquely identify the device",
    "accounts": "accounts configured on the device",
    "application_database": "information stored in the application's database",
    "application_file": "files stored by the application",
    "device_information": "information about the device and installed applications",
    "other": "other information",
}


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _unique(values: Iterable[str | None]) -> list[str]:
    return sorted({value for value in values if value})


def _confidence(value: str) -> int:
    return CONFIDENCE_RANK.get(value, 1)


def _c2_lacks_sample_process(item: C2Finding) -> bool:
    if item.finding_kind == "static_ioc":
        return False
    if item.capped_by_caveat in {"network_process_not_sample", "network_process_unattributed"}:
        return True
    refs = item.details.get("evidence_refs") if isinstance(item.details, dict) else []
    return item.finding_kind == "dns" and not any(
        isinstance(ref, dict) and ref.get("sample_lineage") is True for ref in refs or []
    )


def _effective_c2_confidence(item: C2Finding) -> str:
    if not _c2_lacks_sample_process(item) or item.confidence == "allowlisted":
        return item.confidence
    return "weak"


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
        ioc_values = [item.value for item in iocs]
        report_iocs = [
            item
            for item in iocs
            if credible_legacy_static_indicator(item.ioc_type, item.value, ioc_values)
        ]
        observed_ioc_values = {
            (
                "domain" if item.details.get("destination_domain") else "ip",
                str(item.details.get("destination_domain") or item.details.get("destination_ip")),
            )
            for item in c2_findings
            if isinstance(item.details, dict)
            and (item.details.get("destination_domain") or item.details.get("destination_ip"))
            and (
                item.finding_kind != "static_ioc"
                or "contacted on network" in str(item.details.get("static_match") or "")
            )
        }
        c2_ioc_confidence: dict[tuple[str, str], str] = {}
        for item in c2_findings:
            if not isinstance(item.details, dict):
                continue
            value = item.details.get("destination_domain") or item.details.get("destination_ip")
            if not value:
                continue
            key = ("domain" if item.details.get("destination_domain") else "ip", str(value))
            effective = _effective_c2_confidence(item)
            if _confidence(effective) > _confidence(c2_ioc_confidence.get(key, "unconfirmed")):
                c2_ioc_confidence[key] = effective
        projected_iocs = self._iocs(report_iocs, observed_ioc_values, c2_ioc_confidence)
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
        access_events = (
            self._access_events(windows_capabilities)
            if run.platform == Platform.WINDOWS
            else []
        )
        finding_items = self._findings(
            run,
            windows_findings,
            android_findings,
            c2_findings,
            adaptations,
            artifacts,
            access_events,
        )
        verdict = self._verdict(
            finding_items,
            caveats,
            stages,
            windows_adaptation is not None or android_adaptation is not None,
            c2_adaptation is not None,
            run.c2_analysis_enabled,
        )
        information_accessed = self._capabilities(
            windows_capabilities, exfil_events, run.platform, android_capabilities
        )
        destinations = self._destinations(observations)
        headline = self._headline(
            verdict, finding_items, run.platform, information_accessed, destinations
        )
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
            "information_accessed": information_accessed,
            "destinations": destinations,
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
                "access_events": access_events,
                "iocs": projected_iocs,
                "timeline": self._timeline(timeline),
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
                "platform_details": self._platform_details(
                    windows_metadata, android_metadata, finding_items
                ),
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
    def _timeline(events: list[TimelineEvent]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        static_prefix = "C2 in binary, not observed on network: "
        static_values = [
            item.description.removeprefix(static_prefix)
            for item in events
            if item.description.startswith(static_prefix)
        ]
        for item in sorted(events, key=lambda row: row.occurred_at):
            if item.description.startswith(static_prefix):
                value = item.description.removeprefix(static_prefix)
                indicator_type = (
                    "url"
                    if value.lower().startswith(("http://", "https://"))
                    else "ip"
                    if not any(character.isalpha() for character in value)
                    else "domain"
                )
                if not credible_legacy_static_indicator(indicator_type, value, static_values):
                    continue
            details = item.details if isinstance(item.details, dict) else {}
            confidence = str(
                details.get("tier")
                or details.get("confidence_tier")
                or details.get("confidence")
                or "unconfirmed"
            )
            if confidence not in CONFIDENCE_RANK:
                confidence = "unconfirmed"
            rows.append(
                {
                    "occurred_at": _iso(item.occurred_at),
                    "actor": item.actor,
                    "description": item.description,
                    "confidence": confidence,
                    "mitre_technique_id": item.mitre_technique_id,
                }
            )
        return rows

    @staticmethod
    def _iocs(
        iocs: list[StaticIOC],
        observed_values: set[tuple[str, str]] | None = None,
        confidence_overrides: dict[tuple[str, str], str] | None = None,
    ) -> list[dict[str, Any]]:
        """Project one canonical IOC row per value/source with honest origin."""
        observed_values = observed_values or set()
        confidence_overrides = confidence_overrides or {}
        grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
        for item in iocs:
            key = (item.ioc_type, item.value, item.source)
            item_confidence = confidence_overrides.get(
                (item.ioc_type, item.value), item.confidence
            )
            existing = grouped.get(key)
            if existing is None:
                grouped[key] = {
                    "type": item.ioc_type,
                    "value": item.value,
                    "confidence": item_confidence,
                    "source": item.source,
                    "seen_in_traffic": bool(
                        item.seen_in_traffic or (item.ioc_type, item.value) in observed_values
                    ),
                }
                continue
            if _confidence(item_confidence) > _confidence(str(existing["confidence"])):
                existing["confidence"] = item_confidence
            existing["seen_in_traffic"] = bool(existing["seen_in_traffic"] or item.seen_in_traffic)
        return sorted(
            grouped.values(),
            key=lambda item: (
                -_confidence(str(item["confidence"])),
                not bool(item["seen_in_traffic"]),
                str(item["value"]),
                str(item["source"]),
            ),
        )

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
        android_c2_modes = {
            str(item.validation_summary.get("correlation_mode"))
            for item in adaptations
            if item.adapter_type == "c2"
        }
        if platform == Platform.ANDROID and "temporal" not in android_c2_modes:
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
        access_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        adaptation_map = {item.id: item for item in adaptations}
        artifact_map: dict[UUID, list[str]] = {}
        for artifact in artifacts:
            if artifact.stage_id:
                artifact_map.setdefault(artifact.stage_id, []).append(str(artifact.id))
        findings: list[dict[str, Any]] = []
        static_values = [
            str(item.details.get("destination_domain") or item.details.get("destination_ip") or "")
            for item in c2_findings
            if item.finding_kind == "static_ioc" and isinstance(item.details, dict)
        ]
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
                        [
                            item.details.get("mitre_technique_id"),
                            item.details.get("ttp"),
                            *(item.details.get("mitre_technique_ids") or []),
                        ]
                    ),
                    "security_mappings": _unique(
                        [
                            *(item.details.get("mitre_technique_ids") or []),
                            item.details.get("mitre_technique_id"),
                            item.details.get("ttp"),
                        ]
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
                    "security_mappings": _unique(
                        android_item.details.get("security_mappings") or []
                    ),
                    "evidence_artifact_ids": artifact_map.get(adaptation.stage_id, []),
                    "caveats": [],
                }
            )
        for c2_item in c2_findings:
            if c2_item.finding_kind == "static_ioc":
                value = str(
                    c2_item.details.get("destination_domain")
                    or c2_item.details.get("destination_ip")
                    or ""
                )
                indicator_type = (
                    "url"
                    if value.lower().startswith(("http://", "https://"))
                    else "ip"
                    if c2_item.details.get("destination_ip")
                    else "domain"
                )
                if not credible_legacy_static_indicator(indicator_type, value, static_values):
                    continue
            android_network_only = run.platform == Platform.ANDROID and (
                c2_item.finding_kind == "exfil"
                or (
                    c2_item.finding_kind == "correlation"
                    and c2_item.capped_by_caveat != "android_temporal_correlation_only"
                )
            )
            details = dict(c2_item.details)
            summary = c2_item.plain_language
            finding_kind = c2_item.finding_kind
            confidence = _effective_c2_confidence(c2_item)
            mitre_technique_id = c2_item.details.get("mitre_technique_id")
            caveat = c2_item.capped_by_caveat
            if _c2_lacks_sample_process(c2_item):
                finding_kind = "network_observation"
                mitre_technique_id = None
                caveat = caveat or "network_process_unattributed"
                destination = details.get("destination_domain") or details.get("destination_ip")
                summary = (
                    f"Network activity involving {destination or 'an unidentified destination'} "
                    "was observed without sample-process attribution; it is not attributed to "
                    "this sample's C2 or exfiltration behavior."
                )
            if c2_item.finding_kind == "correlation":
                summary, details = CaseAggregator._restore_access_object(
                    summary, details, access_events
                )
            findings.append(
                {
                    "finding_id": str(c2_item.id),
                    "analysis_run_id": str(run.id),
                    "stage_id": str(c2_item.stage_id),
                    "platform": c2_item.platform.value,
                    "source": "c2",
                    "kind": finding_kind,
                    "category": "network",
                    "confidence": confidence,
                    "evidence_level": (
                        "correlated"
                        if finding_kind == "correlation" and not android_network_only
                        else "observed"
                    ),
                    "summary": (
                        "Potential outbound transfer behavior was observed, but no Android data item attribution was established."
                        if android_network_only
                        else summary
                    ),
                    "details": details,
                    "mitre_technique_ids": _unique([mitre_technique_id]),
                    "security_mappings": _unique([mitre_technique_id]),
                    "evidence_artifact_ids": artifact_map.get(c2_item.stage_id, []),
                    "caveats": _unique([caveat]),
                }
            )
        findings = CaseAggregator._coalesce_network_findings(findings)
        return sorted(
            findings, key=lambda item: (-_confidence(str(item["confidence"])), str(item["kind"]))
        )

    @staticmethod
    def _coalesce_network_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Coalesce legacy duplicate neutral rows while preserving provenance."""
        retained: list[dict[str, Any]] = []
        observations: dict[tuple[Any, ...], dict[str, Any]] = {}
        for finding in findings:
            details = finding.get("details")
            if (
                finding.get("source") != "c2"
                or finding.get("kind") != "network_observation"
                or not isinstance(details, dict)
            ):
                retained.append(finding)
                continue
            key = (
                finding.get("stage_id"),
                details.get("timestamp"),
                details.get("destination_domain") or details.get("destination_ip"),
                details.get("destination_port"),
                details.get("protocol"),
                tuple(finding.get("caveats") or []),
                finding.get("summary"),
            )
            existing = observations.get(key)
            if existing is None:
                details["observation_count"] = int(details.get("observation_count") or 1)
                details["source_finding_ids"] = _unique(
                    [*(details.get("source_finding_ids") or []), finding.get("finding_id")]
                )
                observations[key] = finding
                retained.append(finding)
                continue
            existing_details = existing["details"]
            existing_details["observation_count"] = int(
                existing_details.get("observation_count") or 1
            ) + int(details.get("observation_count") or 1)
            destination_ips = {
                str(value)
                for value in [
                    *(existing_details.get("observed_destination_ips") or []),
                    existing_details.get("destination_ip"),
                    details.get("destination_ip"),
                ]
                if value
            }
            if len(destination_ips) > 1:
                existing_details["observed_destination_ips"] = sorted(destination_ips)
            existing_details["source_finding_ids"] = _unique(
                [
                    *(existing_details.get("source_finding_ids") or []),
                    *(details.get("source_finding_ids") or []),
                    finding.get("finding_id"),
                ]
            )
            refs = existing_details.setdefault("evidence_refs", [])
            known = {
                canonical_json(ref)
                for ref in refs
                if isinstance(ref, dict)
            }
            for ref in details.get("evidence_refs") or []:
                if not isinstance(ref, dict):
                    continue
                canonical = canonical_json(ref)
                if canonical not in known:
                    refs.append(ref)
                    known.add(canonical)
            existing["evidence_artifact_ids"] = _unique(
                [
                    *(existing.get("evidence_artifact_ids") or []),
                    *(finding.get("evidence_artifact_ids") or []),
                ]
            )
        return retained

    @staticmethod
    def _restore_access_object(
        summary: str,
        details: dict[str, Any],
        access_events: list[dict[str, Any]],
    ) -> tuple[str, dict[str, Any]]:
        refs = [dict(ref) if isinstance(ref, dict) else ref for ref in details.get("evidence_refs", [])]
        host_ref = next(
            (ref for ref in refs if isinstance(ref, dict) and ref.get("type") == "host_access"),
            None,
        )
        if host_ref is None or host_ref.get("object_name") or host_ref.get("object_path"):
            return summary, details
        try:
            network_time = datetime.fromisoformat(str(details["timestamp"]).replace("Z", "+00:00"))
            access_time = network_time - timedelta(seconds=float(host_ref.get("time_delta_s") or 0))
        except (KeyError, TypeError, ValueError):
            return summary, details
        ranked: list[tuple[float, int, dict[str, Any]]] = []
        for index, event in enumerate(access_events):
            if not (event.get("object_name") or event.get("object_path")):
                continue
            if event.get("data_type") != details.get("data_type_accessed"):
                continue
            if event.get("api_call") != details.get("access_api_call"):
                continue
            try:
                event_time = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            except (KeyError, TypeError, ValueError):
                continue
            ranked.append((abs((event_time - access_time).total_seconds()), index, event))
        if not ranked:
            return summary, details
        difference, index, match = min(ranked, key=lambda item: (item[0], item[1]))
        if difference > 0.011:
            return summary, details
        for field in (
            "object_name", "object_path", "action", "process", "process_path",
            "process_id", "parent_process_id", "source_call_id",
        ):
            if match.get(field) is not None:
                host_ref[field] = match[field]
        details["evidence_refs"] = refs
        name = match.get("object_name") or match.get("object_path")
        path = match.get("object_path")
        if not name:
            return summary, details
        accessed = f"the file {name}"
        if path and path != name:
            accessed += f" at {path}"
        destination = details.get("destination_domain") or details.get("destination_ip")
        delta = host_ref.get("time_delta_s")
        return (
            f"This sample accessed {accessed} and contacted "
            f"{destination or 'an unidentified destination'}"
            f"{f' {delta:g} seconds later' if isinstance(delta, (int, float)) else ''}. "
            "This is shown for review and is not confirmed.",
            details,
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
            details = item.details if isinstance(item.details, dict) else {}
            events = details.get("events")
            if not isinstance(events, list):
                events = [details.get("first_event")] if isinstance(details.get("first_event"), dict) else []
            observed_objects: list[dict[str, str | int | None]] = []
            seen_objects: set[tuple[str, str, str, str, str]] = set()
            for event in events:
                if not isinstance(event, dict):
                    continue
                observed = {
                    "name": str(event.get("object_name") or "") or None,
                    "path": str(event.get("object_path") or "") or None,
                    "operation": str(event.get("access_operation") or event.get("api_call") or "") or None,
                    "process": str(event.get("process_path") or event.get("process") or "") or None,
                    "process_id": event.get("process_id") if isinstance(event.get("process_id"), int) else None,
                }
                identity = (
                    str(observed["name"] or ""),
                    str(observed["path"] or ""),
                    str(observed["operation"] or ""),
                    str(observed["process"] or ""),
                    str(observed["process_id"] or ""),
                )
                if not observed["name"] and not observed["path"] or identity in seen_objects:
                    continue
                seen_objects.add(identity)
                observed_objects.append(observed)
            result[item.capability] = {
                "data_type": item.capability,
                "evidence_level": "observed",
                "confidence": item.confidence,
                "summary": f"Access to {item.capability.replace('_', ' ')} was observed.",
                "observed_objects": observed_objects,
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
                "observed_objects": [],
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
                        "observed_objects": [],
                    },
                )
                current["evidence_level"] = "correlated"
                current["confidence"] = exfil_item.confidence
                current["summary"] = (
                    f"Access to {exfil_item.data_type_accessed.replace('_', ' ')} was correlated with network activity."
                )
        return sorted(result.values(), key=lambda item: str(item["data_type"]))

    @staticmethod
    def _access_events(capabilities: list[WindowsCapability]) -> list[dict[str, Any]]:
        """Project every normalized WinST/DT access record without summarizing it away."""
        records: list[dict[str, Any]] = []
        for capability in capabilities:
            details = capability.details if isinstance(capability.details, dict) else {}
            events = details.get("events")
            if not isinstance(events, list):
                first = details.get("first_event")
                events = [first] if isinstance(first, dict) else []
            for event in events:
                if not isinstance(event, dict):
                    continue
                records.append(
                    {
                        "timestamp": event.get("timestamp"),
                        "data_type": event.get("data_type") or capability.capability,
                        "action": event.get("access_operation") or event.get("api_call"),
                        "api_call": event.get("api_call"),
                        "object_name": event.get("object_name"),
                        "object_path": event.get("object_path"),
                        "process": event.get("process"),
                        "process_path": event.get("process_path"),
                        "process_id": event.get("process_id"),
                        "parent_process_id": event.get("parent_process_id"),
                        "source_call_id": event.get("source_call_id"),
                        "source": "winstdt_access_events",
                    }
                )
        return sorted(records, key=lambda item: str(item.get("timestamp") or ""))

    @staticmethod
    def _destinations(observations: list[NetworkObservation]) -> list[dict[str, Any]]:
        """Destinations with the attribution the C2 module already produced.

        The adapter stores the whole normalized event in NetworkObservation.details,
        so geo/ASN/reputation are already persisted — they were simply never read
        here. Without them an officer sees a bare address and port; with them the
        report can say which country, which network operator, and whether the
        destination is independently known to be malicious.

        Enrichment is merged across observations for the same destination: a
        destination seen several times may only carry attribution on one of them.
        """
        grouped: dict[tuple[str, int | None], dict[str, Any]] = {}
        static_values = [
            str(item.destination_domain or item.destination_ip or "")
            for item in observations
            if isinstance(item.details, dict) and item.details.get("finding_kind") == "static_ioc"
        ]
        for item in observations:
            value = item.destination_domain or item.destination_ip
            if not value:
                continue
            detail = item.details if isinstance(item.details, dict) else {}
            if detail.get("finding_kind") == "static_ioc":
                indicator_type = (
                    "url"
                    if value.lower().startswith(("http://", "https://"))
                    else "ip"
                    if item.destination_ip
                    else "domain"
                )
                if not credible_legacy_static_indicator(indicator_type, value, static_values):
                    continue
            key = (value, item.destination_port)
            existing = grouped.get(key)
            if existing is None:
                existing = {
                    "value": value,
                    "ip": item.destination_ip,
                    "domain": item.destination_domain,
                    "port": item.destination_port,
                    "protocol": item.protocol,
                    "first_observed_at": _iso(item.observed_at),
                    "geo_country": None,
                    "asn": None,
                    "asn_org": None,
                    "reputation_score": None,
                    "reputation_note": None,
                    "reputation_source": None,
                    "observation_count": 0,
                }
                grouped[key] = existing
            existing["observation_count"] += 1
            # keep the earliest sighting, and the first non-empty attribution
            if _iso(item.observed_at) < existing["first_observed_at"]:
                existing["first_observed_at"] = _iso(item.observed_at)
            for field in ("geo_country", "asn", "asn_org", "reputation_note", "reputation_source"):
                if existing[field] in (None, "") and detail.get(field) not in (None, ""):
                    existing[field] = detail[field]
            score = detail.get("reputation_score")
            if isinstance(score, (int, float)):
                current = existing["reputation_score"]
                if current is None or score > current:
                    existing["reputation_score"] = float(score)
        for entry in grouped.values():
            if entry["ip"] and not all(
                entry[field] for field in ("geo_country", "asn", "asn_org")
            ):
                country, asn, organization = lookup_ip(str(entry["ip"]))
                entry["geo_country"] = entry["geo_country"] or country
                entry["asn"] = entry["asn"] or asn
                entry["asn_org"] = entry["asn_org"] or organization
            # A destination is "known bad" only on an independent intel hit, not
            # on behaviour. Behaviour is already carried by the finding tier.
            entry["known_bad"] = bool(entry["reputation_score"]) and entry["reputation_score"] > 0
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
    def _headline(
        verdict: Verdict,
        findings: list[dict[str, Any]],
        platform: Platform,
        information_accessed: list[dict[str, Any]] | None = None,
        destinations: list[dict[str, Any]] | None = None,
    ) -> str:
        """The one sentence an officer reads.

        It must answer the two questions the investigation actually has — what
        was accessed, and where it went — not report the analysis's own status.
        "Confirmed malicious behavior was detected during the Windows analysis"
        is true but tells an officer nothing actionable.

        Falls back to a status sentence only when there is nothing concrete to
        name, and never claims more than the verdict supports.
        """
        platform_name = "Windows" if platform == Platform.WINDOWS else "Android"
        what = CaseAggregator._accessed_phrase(information_accessed or [])
        where = CaseAggregator._destination_phrase(destinations or [])

        if verdict == Verdict.MALICIOUS:
            if what and where:
                return f"This sample accessed {what} and contacted {where}."
            if what:
                return f"This sample accessed {what} on the analysed system."
            if where:
                return f"This sample contacted {where}."
            return (
                f"Confirmed malicious behaviour was detected during the {platform_name} analysis."
            )

        if verdict == Verdict.SUSPICIOUS:
            count = len([item for item in findings if _confidence(str(item["confidence"])) >= 2])
            noun = f"{count} suspicious finding{'s' if count != 1 else ''}"
            if what and where:
                return (
                    f"{noun}: this sample accessed {what} and contacted {where}. "
                    f"This is not confirmed and requires analyst review."
                )
            if where:
                return (
                    f"{noun}: this sample contacted {where}. This is not "
                    f"confirmed and requires analyst review."
                )
            return f"{noun} require analyst review."

        if verdict == Verdict.NO_MALICIOUS_ACTIVITY_OBSERVED:
            return (
                "No malicious activity was observed during the completed "
                "analysis window. See the analysis limitations below before "
                "treating this file as safe."
            )
        if verdict == Verdict.FAILED:
            return "The platform analysis failed before a valid result was produced."
        return (
            "The available evidence is insufficient for a reliable conclusion. "
            "See the analysis limitations below."
        )

    @staticmethod
    def _accessed_phrase(information_accessed: list[dict[str, Any]]) -> str:
        """Plain-language list of what was accessed, strongest evidence first."""
        order = {"correlated": 0, "observed": 1, "possible": 2, "declared": 3}
        ranked = sorted(
            (item for item in information_accessed if item.get("data_type")),
            key=lambda item: (
                order.get(str(item.get("evidence_level")), 9),
                -_confidence(str(item.get("confidence", "unconfirmed"))),
            ),
        )
        names: list[str] = []
        for item in ranked:
            label = _DATA_TYPE_PHRASES.get(
                str(item["data_type"]), str(item["data_type"]).replace("_", " ")
            )
            if label not in names:
                names.append(label)
        if not names:
            return ""
        if len(names) == 1:
            return names[0]
        if len(names) == 2:
            return f"{names[0]} and {names[1]}"
        rest = len(names) - 2
        kind = "other type of information" if rest == 1 else "other types of information"
        return f"{names[0]}, {names[1]} and {rest} {kind}"

    @staticmethod
    def _destination_phrase(destinations: list[dict[str, Any]]) -> str:
        values = [str(item["value"]) for item in destinations if item.get("value")]
        if not values:
            return ""
        if len(values) == 1:
            return values[0]
        rest = len(values) - 1
        noun = "other destination" if rest == 1 else "other destinations"
        return f"{values[0]} and {rest} {noun}"

    @staticmethod
    def _platform_details(
        windows: WindowsAnalysisMetadata | None,
        android: AndroidAnalysisMetadata | None,
        findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        """Platform panel for the analyst view.

        Carries the run's identity AND a summary of the platform evidence, so
        the report is a malware analysis report rather than a network report
        with metadata attached. Both platforms are summarised the same way —
        severity spread, categories, techniques — so the UI renders one
        component regardless of which backend produced the case.
        """
        detail: dict[str, Any] | None = None
        if windows:
            detail = {
                "platform": "windows",
                "cape_task_id": windows.cape_task_id,
                "cape_package": windows.cape_package,
                "detected_type": windows.detected_type,
                "machine_label": windows.machine_label,
                "network_mode": windows.network_mode,
                "telemetry_degraded": windows.telemetry_degraded,
            }
            extra = windows.details if isinstance(windows.details, dict) else {}
            for key in (
                "malscore",
                "process_tree",
                "dropped_files",
                "cape_package_detected",
                "configuration_extraction",
            ):
                if extra.get(key) is not None:
                    detail[key] = extra[key]
        elif android:
            detail = {
                "platform": "android",
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
            extra = android.details if isinstance(android.details, dict) else {}
            for key in ("permissions", "trackers", "certificate", "security_score"):
                if extra.get(key) is not None:
                    detail[key] = extra[key]
        if detail is None:
            return None
        detail["evidence_summary"] = CaseAggregator._evidence_summary(findings or [])
        return detail

    @staticmethod
    def _evidence_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Severity/category/technique rollup, identical for either platform.

        Severity lives in AndroidFinding as a column and in WindowsFinding's
        details payload, so it is read from both places and normalised.
        """
        by_source: dict[str, int] = {}
        by_category: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        techniques: set[str] = set()
        for item in findings:
            source = str(item.get("source") or "unknown")
            by_source[source] = by_source.get(source, 0) + 1
            category = str(item.get("category") or "uncategorised")
            by_category[category] = by_category.get(category, 0) + 1
            details_value = item.get("details")
            details: dict[str, Any] = details_value if isinstance(details_value, dict) else {}
            raw = item.get("severity", details.get("severity"))
            label = CaseAggregator._severity_label(raw)
            by_severity[label] = by_severity.get(label, 0) + 1
            for technique in item.get("mitre_technique_ids") or []:
                techniques.add(str(technique))
        return {
            "total_findings": len(findings),
            "by_source": dict(sorted(by_source.items())),
            "by_category": dict(sorted(by_category.items(), key=lambda kv: (-kv[1], kv[0]))),
            "by_severity": {
                key: by_severity[key]
                for key in ("high", "medium", "low", "informational", "unrated")
                if key in by_severity
            },
            "mitre_technique_ids": sorted(techniques),
            "mitre_technique_count": len(techniques),
        }

    @staticmethod
    def _severity_label(raw: Any) -> str:
        """CAPE uses 1-3 numerics; MobSF uses words. Normalise to one scale."""
        if isinstance(raw, bool) or raw is None:
            return "unrated"
        if isinstance(raw, (int, float)):
            if raw >= 3:
                return "high"
            if raw == 2:
                return "medium"
            if raw >= 1:
                return "low"
            return "informational"
        text = str(raw).strip().lower()
        if text in {"high", "critical", "dangerous"}:
            return "high"
        if text in {"medium", "warning", "moderate"}:
            return "medium"
        if text in {"low", "minor"}:
            return "low"
        if text in {"info", "informational", "secure", "good"}:
            return "informational"
        return "unrated"
