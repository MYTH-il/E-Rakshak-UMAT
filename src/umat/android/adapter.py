from __future__ import annotations

import json
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from umat.android.bundle import (
    ANDROID_COMMIT,
    AndroidBundleError,
    safe_extract_android_bundle,
    verify_android_bundle,
)
from umat.audit import append_audit
from umat.db.models import (
    AdaptationRecord,
    AnalysisAttempt,
    AnalysisRun,
    AnalysisStage,
    AndroidAnalysisMetadata,
    AndroidCapability,
    AndroidFinding,
    Artifact,
    BundleImport,
    Executor,
    NetworkObservation,
    Platform,
    StageState,
    StageType,
    StaticIOC,
    Submission,
    utcnow,
)
from umat.storage import LocalArtifactStore

PERMISSION_DATA_TYPES = {
    "android.permission.READ_SMS": "sms",
    "android.permission.RECEIVE_SMS": "sms",
    "android.permission.READ_CONTACTS": "contacts",
    "android.permission.ACCESS_FINE_LOCATION": "location",
    "android.permission.ACCESS_COARSE_LOCATION": "location",
    "android.permission.CAMERA": "camera",
    "android.permission.READ_CALL_LOG": "call_log",
    "android.permission.RECORD_AUDIO": "microphone",
    "android.permission.READ_CALENDAR": "calendar",
    "android.permission.READ_PHONE_STATE": "device_identity",
}
OBSERVED_MARKERS = {
    "sms": ("smsmanager", "content://sms"),
    "contacts": ("content://contacts", "contactscontract"),
    "location": ("locationmanager", "getlastknownlocation"),
    "camera": ("camera.open", "camera2"),
    "call_log": ("content://call_log",),
    "microphone": ("audiorecord", "mediarecorder"),
    "calendar": ("content://com.android.calendar",),
    "device_identity": ("getdeviceid", "getimei"),
}
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


class AndroidAdaptationError(AndroidBundleError):
    pass


def _object(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return cast(dict[str, Any], value) if isinstance(value, dict) else {}


def _descriptor_path(root: Path, descriptor: dict[str, Any] | None) -> Path | None:
    if not descriptor:
        return None
    path = (root / str(descriptor["path"])).resolve()
    if root.resolve() not in path.parents:
        raise AndroidAdaptationError("Android report path escapes bundle")
    return path


class AndroidAdapter:
    def __init__(self, artifact_store: LocalArtifactStore, max_bundle_bytes: int) -> None:
        self.artifact_store = artifact_store
        self.max_bundle_bytes = max_bundle_bytes

    async def adapt_run(self, db: AsyncSession, run_id: UUID) -> AdaptationRecord:
        run = await db.get(AnalysisRun, run_id)
        if not run or run.platform != Platform.ANDROID:
            raise AndroidAdaptationError("Android analysis run not found")
        stage = await db.scalar(
            select(AnalysisStage).where(
                AnalysisStage.analysis_run_id == run.id,
                AnalysisStage.stage_type == StageType.PLATFORM_ADAPTATION,
            ).with_for_update()
        )
        if not stage or stage.state not in {StageState.QUEUED, StageState.RUNNING, StageState.COMPLETED}:
            raise AndroidAdaptationError("Android adaptation stage is not ready")
        artifact = await db.scalar(
            select(Artifact)
            .join(AnalysisStage, Artifact.stage_id == AnalysisStage.id)
            .where(
                Artifact.analysis_run_id == run.id,
                Artifact.kind == "android_bundle",
                AnalysisStage.stage_type == StageType.PLATFORM_ANALYSIS,
                AnalysisStage.state.in_([StageState.COMPLETED, StageState.PARTIAL]),
            )
            .order_by(Artifact.created_at.desc())
            .limit(1)
        )
        if not artifact or not artifact.attempt_id:
            raise AndroidAdaptationError("run has no completed Android bundle")
        attempt = await db.get(AnalysisAttempt, artifact.attempt_id)
        executor = await db.get(Executor, attempt.executor_id) if attempt else None
        submission = await db.get(Submission, run.submission_id)
        if not executor or not submission:
            raise AndroidAdaptationError("Android bundle producer identity is unavailable")
        archive = self.artifact_store.verify(artifact.object_key, artifact.sha256)
        stage.state = StageState.RUNNING
        try:
            with tempfile.TemporaryDirectory(prefix=f"umat-android-adapt-{run.id}-") as temporary:
                root = safe_extract_android_bundle(
                    archive, Path(temporary) / "bundle", self.max_bundle_bytes
                )
                manifest = verify_android_bundle(
                    root, Ed25519PublicKey.from_public_bytes(executor.public_key)
                )
                self._identity(manifest, run, submission.sample_sha256, executor)
                adaptation = await self._persist(db, run, stage, artifact, root, manifest)
        except AndroidBundleError as exc:
            db.add(
                BundleImport(
                    analysis_run_id=run.id,
                    stage_id=stage.id,
                    artifact_id=artifact.id,
                    bundle_sha256=artifact.sha256,
                    schema_version="unknown",
                    validation_result={"valid": False, "reason": str(exc)[:1000]},
                )
            )
            stage.state = StageState.FAILED
            stage.failure_code = "android_bundle_rejected"
            stage.failure_detail = str(exc)[:2000]
            await append_audit(
                db,
                actor_type="system",
                actor_id="android-adapter",
                action="android_bundle.rejected",
                target_type="artifact",
                target_id=str(artifact.id),
                payload={"run_id": str(run.id), "reason": str(exc)[:1000]},
            )
            await db.commit()
            raise
        db.add(
            BundleImport(
                analysis_run_id=run.id,
                stage_id=stage.id,
                artifact_id=artifact.id,
                bundle_sha256=artifact.sha256,
                schema_version=str(manifest["schema_version"]),
                validation_result={
                    "valid": True,
                    "executor_id": str(executor.id),
                    "native_commit": manifest["producer"]["commit"],
                },
            )
        )
        stage.state = StageState.COMPLETED
        stage.updated_at = utcnow()
        await append_audit(
            db,
            actor_type="system",
            actor_id="android-adapter",
            action="android_bundle.adapted",
            target_type="adaptation",
            target_id=str(adaptation.id),
            payload={"run_id": str(run.id), "source_artifact_id": str(artifact.id)},
        )
        await db.commit()
        return adaptation

    @staticmethod
    def _identity(
        manifest: dict[str, Any], run: AnalysisRun, sample_sha256: str, executor: Executor
    ) -> None:
        if manifest["analysis_run_id"] != str(run.id) or manifest["sample_sha256"] != sample_sha256:
            raise AndroidAdaptationError("Android bundle run/sample identity mismatch")
        if manifest["signature"]["key_id"] != str(executor.id):
            raise AndroidAdaptationError("Android bundle signing-key identity mismatch")
        if manifest["producer"]["commit"] != ANDROID_COMMIT:
            raise AndroidAdaptationError("Android producer revision mismatch")

    async def _persist(
        self,
        db: AsyncSession,
        run: AnalysisRun,
        stage: AnalysisStage,
        artifact: Artifact,
        root: Path,
        manifest: dict[str, Any],
    ) -> AdaptationRecord:
        await db.execute(
            update(AdaptationRecord)
            .where(
                AdaptationRecord.analysis_run_id == run.id,
                AdaptationRecord.adapter_type == "android",
                AdaptationRecord.active.is_(True),
            )
            .values(active=False)
        )
        static = _object(_descriptor_path(root, manifest["mobsf_reports"]["static"]))
        dynamic_descriptor = manifest["mobsf_reports"].get("dynamic")
        dynamic = _object(_descriptor_path(root, dynamic_descriptor))
        network_descriptor = next(
            (item for item in manifest["artifacts"] if item.get("kind") == "network_activity"),
            None,
        )
        network_activity = _object(_descriptor_path(root, network_descriptor))
        adaptation = AdaptationRecord(
            analysis_run_id=run.id,
            stage_id=stage.id,
            source_artifact_id=artifact.id,
            adapter_type="android",
            schema_version="1.0",
            active=True,
            validation_summary={
                "scan_hash": manifest["mobsf_reports"]["scan_hash"],
                "mobsf_version": manifest["producer"]["mobsf_version"],
                "caveats": manifest["caveats"],
            },
        )
        db.add(adaptation)
        await db.flush()
        db.add(
            AndroidAnalysisMetadata(
                adaptation_id=adaptation.id,
                analysis_run_id=run.id,
                package_name=self._text(static, "package_name", "package"),
                app_name=self._text(static, "app_name", "file_name"),
                version_name=self._text(static, "version_name"),
                version_code=self._text(static, "version_code"),
                scan_hash=manifest["mobsf_reports"]["scan_hash"],
                api_level=manifest["emulator"]["api_level"],
                avd_name=manifest["emulator"]["avd_name"],
                guest_ip=manifest["emulator"].get("guest_ip"),
                dynamic_completed=dynamic_descriptor is not None,
                stimulation=manifest["stimulation"],
                details={"analysis_window": manifest["analysis_window"]},
            )
        )
        self._findings(db, adaptation.id, run.id, static, dynamic)
        self._capabilities(db, adaptation.id, run.id, static, dynamic)
        self._iocs(db, adaptation.id, run.id, static, dynamic)
        observations = list(network_activity.get("observations", [])[:5000])
        seen: set[tuple[str | None, str | None, int | None]] = {
            (item.get("destination_domain"), item.get("destination_ip"), item.get("destination_port"))
            for item in observations if isinstance(item, dict)
        }
        captured_at = (manifest.get("analysis_window") or {}).get("ended_at")
        domains = dynamic.get("domains") or {}
        if isinstance(domains, dict):
            for domain, metadata in domains.items():
                detail = metadata if isinstance(metadata, dict) else {}
                geolocation = detail.get("geolocation") or {}
                address = geolocation.get("ip") if isinstance(geolocation, dict) else None
                domain_key = (str(domain).rstrip(".").lower(), address, None)
                if domain_key in seen:
                    continue
                seen.add(domain_key)
                observations.append({
                    "observed_at": captured_at, "destination_domain": domain_key[0],
                    "destination_ip": address, "destination_port": None,
                    "protocol": "https_proxy", "source": "mobsf_dynamic_proxy",
                })
        urls = dynamic.get("urls") or []
        for raw in urls if isinstance(urls, list) else []:
            value = raw if isinstance(raw, str) else raw.get("url") if isinstance(raw, dict) else None
            parsed = urlparse(str(value)) if value else None
            if not parsed or not parsed.hostname:
                continue
            port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None)
            url_key = (parsed.hostname.lower(), None, port)
            if url_key in seen:
                continue
            seen.add(url_key)
            observations.append({
                "observed_at": captured_at, "destination_domain": url_key[0],
                "destination_ip": None, "destination_port": port,
                "protocol": parsed.scheme.lower() or "proxy", "source": "mobsf_dynamic_proxy",
            })
        for sequence, item in enumerate(observations[:5000]):
            if not isinstance(item, dict):
                continue
            db.add(NetworkObservation(
                adaptation_id=adaptation.id,
                analysis_run_id=run.id,
                source_event_id=f"android-pcap-{sequence:06d}",
                destination_ip=item.get("destination_ip"),
                destination_port=item.get("destination_port"),
                destination_domain=item.get("destination_domain"),
                protocol=item.get("protocol"),
                observed_at=datetime.fromisoformat(item["observed_at"])
                if item.get("observed_at") else utcnow(),
                details={"source": item.get("source") or "android_executor_pcap_summary"},
            ))
        return adaptation

    @staticmethod
    def _text(document: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = document.get(key)
            if value is not None and not isinstance(value, (dict, list)):
                return str(value)
        return None

    @staticmethod
    def _findings(
        db: AsyncSession,
        adaptation_id: UUID,
        run_id: UUID,
        static: dict[str, Any],
        dynamic: dict[str, Any],
    ) -> None:
        sources = (
            ("static", "manifest", static.get("manifest_analysis")),
            ("static", "code", static.get("code_analysis")),
            ("static", "certificate", static.get("certificate_analysis")),
            ("dynamic", "runtime", dynamic.get("appsec") or dynamic.get("runtime_dependencies")),
            ("dynamic", "tls", dynamic.get("tls_tests")),
        )
        for phase, category, source in sources:
            for item in AndroidAdapter._finding_items(source)[:500]:
                severity = str(item.get("severity") or item.get("level") or "").lower() or None
                summary = str(
                    item.get("title")
                    or item.get("name")
                    or item.get("description")
                    or item.get("rule")
                    or category
                )
                confidence = "strong" if severity in {"high", "critical", "warning"} else "weak"
                db.add(
                    AndroidFinding(
                        adaptation_id=adaptation_id,
                        analysis_run_id=run_id,
                        phase=phase,
                        category=category,
                        kind=str(item.get("rule") or item.get("name") or category)[:128],
                        severity=severity,
                        confidence=confidence,
                        evidence_level="observed" if phase == "dynamic" else "possible",
                        summary=summary[:4000],
                        details=item,
                    )
                )

    @staticmethod
    def _finding_items(value: Any) -> list[dict[str, Any]]:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            results: list[dict[str, Any]] = []
            for key, item in value.items():
                if isinstance(item, dict):
                    results.append({"name": str(key), **item})
                elif isinstance(item, list):
                    results.extend(child for child in item if isinstance(child, dict))
            return results
        return []

    @staticmethod
    def _capabilities(
        db: AsyncSession,
        adaptation_id: UUID,
        run_id: UUID,
        static: dict[str, Any],
        dynamic: dict[str, Any],
    ) -> None:
        permissions = static.get("permissions") or {}
        names: list[Any]
        if isinstance(permissions, dict):
            names = list(permissions)
        elif isinstance(permissions, list):
            names = permissions
        else:
            names = []
        declared: dict[str, list[str]] = {}
        for permission in names:
            data_type = PERMISSION_DATA_TYPES.get(str(permission))
            if data_type:
                declared.setdefault(data_type, []).append(str(permission))
        serialized_dynamic = json.dumps(dynamic, sort_keys=True).lower()
        for data_type, permission_names in declared.items():
            observed = any(marker in serialized_dynamic for marker in OBSERVED_MARKERS[data_type])
            db.add(
                AndroidCapability(
                    adaptation_id=adaptation_id,
                    analysis_run_id=run_id,
                    data_type=data_type,
                    evidence_level="observed" if observed else "declared",
                    confidence="confirmed" if observed else "weak",
                    source="mobsf_dynamic" if observed else "android_manifest",
                    details={"permissions": permission_names},
                )
            )

    @staticmethod
    def _iocs(
        db: AsyncSession,
        adaptation_id: UUID,
        run_id: UUID,
        static: dict[str, Any],
        dynamic: dict[str, Any],
    ) -> None:
        values: set[tuple[str, str]] = set()
        for document in (static, dynamic):
            serialized = json.dumps(document, sort_keys=True)
            for url in URL_RE.findall(serialized):
                clean = url.rstrip(".,);]\\")
                values.add(("url", clean))
                host = urlparse(clean).hostname
                if host:
                    values.add(("domain", host.lower()))
        for ioc_type, value in sorted(values)[:2000]:
            db.add(
                StaticIOC(
                    adaptation_id=adaptation_id,
                    analysis_run_id=run_id,
                    ioc_type=ioc_type,
                    value=value,
                    confidence="weak",
                    source="mobsf",
                    seen_in_traffic=False,
                    first_seen_at=None,
                )
            )
