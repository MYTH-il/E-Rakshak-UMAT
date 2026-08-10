from __future__ import annotations

import io
import json
import zipfile
from datetime import timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.artifact_routes import tier_allowed
from umat.api.case_routes import accessible_case, store
from umat.audit import append_audit
from umat.auth.dependencies import Principal, require_roles
from umat.db import get_db
from umat.db.models import (
    AnalysisRun,
    AndroidAnalysisMetadata,
    AndroidCapability,
    AndroidDynamicSession,
    AndroidFinding,
    AndroidSessionCommand,
    Artifact,
    C2Finding,
    NetworkObservation,
    Platform,
    StaticIOC,
    utcnow,
)
from umat.storage.local import DigestMismatchError

router = APIRouter(prefix="/api/v1/analysis-runs", tags=["android-workflow"])

_REPORT_MEMBERS = {
    "static": "evidence/mobsf_static_report.json",
    "dynamic": "evidence/mobsf_dynamic_report.json",
    "scan_logs": "evidence/scan_logs.json",
}
_EVIDENCE_MEMBERS = {
    "screenshot": ("evidence/screenshot.png", "image/png"),
    "logcat": ("evidence/logcat.txt", "text/plain; charset=utf-8"),
    "frida-logs": ("evidence/frida_logs.json", "application/json"),
}
_MAX_REPORT_BYTES = 16 * 1024 * 1024
_MAX_INLINE_EVIDENCE_BYTES = 4 * 1024 * 1024
_COMMANDS = {
    "screen", "tap", "swipe", "key", "text", "start_activity", "deeplink",
    "screenshot", "logcat", "frida", "api_monitor", "frida_logs",
    "activity_test", "tls_test", "proxy", "root_ca", "dependencies",
    "app_data", "list_files", "read_file", "extend", "finalize",
}


class AndroidCommandRequest(BaseModel):
    command_type: str = Field(min_length=1, max_length=64)
    payload: dict[str, Any] = Field(default_factory=dict)


async def _android_run(
    db: AsyncSession, principal: Principal, run_id: UUID
) -> AnalysisRun:
    run = await db.get(AnalysisRun, run_id)
    if not run or run.platform != Platform.ANDROID:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android analysis run not found")
    await accessible_case(db, principal, run.case_id)
    return run


async def _bundle(db: AsyncSession, run_id: UUID) -> Artifact | None:
    result: Artifact | None = await db.scalar(
        select(Artifact)
        .where(Artifact.analysis_run_id == run_id, Artifact.kind == "android_bundle")
        .order_by(Artifact.created_at.desc())
        .limit(1)
    )
    return result


def _read_member(artifact: Artifact, member: str, maximum: int) -> bytes:
    try:
        archive = store().verify(artifact.object_key, artifact.sha256)
    except DigestMismatchError as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Android evidence integrity verification failed"
        ) from exc
    try:
        with zipfile.ZipFile(archive) as bundle:
            info = bundle.getinfo(member)
            if info.file_size > maximum:
                raise HTTPException(
                    status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    "Android evidence item is too large for inline viewing",
                )
            return bundle.read(info)
    except (KeyError, zipfile.BadZipFile) as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android evidence item not found") from exc


def _report(artifact: Artifact | None, kind: str) -> dict[str, Any] | None:
    if artifact is None:
        return None
    try:
        value = json.loads(_read_member(artifact, _REPORT_MEMBERS[kind], _MAX_REPORT_BYTES))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Registered Android report is not valid JSON"
        ) from exc
    return value if isinstance(value, dict) else None


def _optional_report(artifact: Artifact | None, kind: str) -> dict[str, Any] | None:
    try:
        return _report(artifact, kind)
    except HTTPException as exc:
        if exc.status_code == status.HTTP_404_NOT_FOUND:
            return None
        raise


def _artifact_row(item: Artifact) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "kind": item.kind,
        "sha256": item.sha256,
        "size_bytes": item.size_bytes,
        "media_type": item.media_type,
        "access_tier": item.access_tier.value,
        "download_path": f"/api/v1/artifacts/{item.id}",
    }


@router.get("/{run_id}/android-workflow")
async def android_workflow(
    run_id: UUID,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    run = await _android_run(db, principal, run_id)
    bundle = await _bundle(db, run.id)
    metadata = await db.scalar(
        select(AndroidAnalysisMetadata).where(AndroidAnalysisMetadata.analysis_run_id == run.id)
    )
    findings = list(
        (await db.scalars(select(AndroidFinding).where(AndroidFinding.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    capabilities = list(
        (await db.scalars(select(AndroidCapability).where(AndroidCapability.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    iocs = list(
        (await db.scalars(select(StaticIOC).where(StaticIOC.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    observations = list(
        (
            await db.scalars(
                select(NetworkObservation).where(NetworkObservation.analysis_run_id == run.id)
            )
        )
        .unique()
        .all()
    )
    c2_findings = list(
        (await db.scalars(select(C2Finding).where(C2Finding.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    artifacts = list(
        (await db.scalars(select(Artifact).where(Artifact.analysis_run_id == run.id)))
        .unique()
        .all()
    )
    session = await db.scalar(
        select(AndroidDynamicSession).where(AndroidDynamicSession.analysis_run_id == run.id)
    )
    commands = (
        list(
            (
                await db.scalars(
                    select(AndroidSessionCommand)
                    .where(AndroidSessionCommand.session_id == session.id)
                    .order_by(AndroidSessionCommand.created_at.desc())
                    .limit(100)
                )
            ).all()
        )
        if session
        else []
    )
    return {
        "schema_version": "1.0",
        "run": {
            "id": str(run.id),
            "case_id": str(run.case_id),
            "status": run.status.value,
            "result": run.result.value if run.result else None,
            "network_mode": run.network_mode,
            "c2_analysis_enabled": run.c2_analysis_enabled,
            "android_interactive": run.android_interactive,
            "profile": run.android_configuration.profile_snapshot
            if run.android_configuration
            else None,
            "stages": [
                {
                    "stage_type": item.stage_type.value,
                    "state": item.state.value,
                    "failure_code": item.failure_code,
                    "failure_detail": item.failure_detail,
                }
                for item in run.stages
            ],
        },
        "metadata": (
            {
                "package_name": metadata.package_name,
                "app_name": metadata.app_name,
                "version_name": metadata.version_name,
                "version_code": metadata.version_code,
                "scan_hash": metadata.scan_hash,
                "api_level": metadata.api_level,
                "avd_name": metadata.avd_name,
                "guest_ip": metadata.guest_ip,
                "dynamic_completed": metadata.dynamic_completed,
                "stimulation": metadata.stimulation,
                "details": metadata.details,
            }
            if metadata
            else None
        ),
        "mobsf": {
            # Partial and failed runs legitimately omit one or both MobSF reports.
            # Keep the analyst workflow available for the evidence that survived.
            "static": _optional_report(bundle, "static"),
            "dynamic": _optional_report(bundle, "dynamic"),
            "scan_logs": _optional_report(bundle, "scan_logs"),
        },
        "findings": [
            {
                "phase": item.phase,
                "category": item.category,
                "kind": item.kind,
                "severity": item.severity,
                "confidence": item.confidence,
                "evidence_level": item.evidence_level,
                "summary": item.summary,
                "details": item.details,
            }
            for item in findings
        ],
        "capabilities": [
            {
                "data_type": item.data_type,
                "evidence_level": item.evidence_level,
                "confidence": item.confidence,
                "source": item.source,
                "details": item.details,
            }
            for item in capabilities
        ],
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
        "network_observations": [
            {
                "destination_ip": item.destination_ip,
                "destination_port": item.destination_port,
                "destination_domain": item.destination_domain,
                "protocol": item.protocol,
                "observed_at": item.observed_at,
                "details": item.details,
            }
            for item in observations
        ],
        "c2_findings": [
            {
                "kind": item.finding_kind,
                "summary": item.plain_language,
                "confidence": item.confidence,
                "capped_by_caveat": item.capped_by_caveat,
                "details": item.details,
            }
            for item in c2_findings
        ],
        "artifacts": [_artifact_row(item) for item in artifacts if tier_allowed(principal, item.access_tier)],
        "inline_evidence": {
            name: f"/api/v1/analysis-runs/{run.id}/android-evidence/{name}"
            for name, (member, _) in _EVIDENCE_MEMBERS.items()
            if bundle is not None and _member_exists(bundle, member)
        },
        "interactive_session": (
            {
                "id": str(session.id), "state": session.state,
                "scan_hash": session.scan_hash, "package_name": session.package_name,
                "main_activity": session.main_activity, "guest_ip": session.guest_ip,
                "started_at": session.started_at, "last_seen_at": session.last_seen_at,
                "expires_at": session.expires_at, "ended_at": session.ended_at,
                "status_details": session.status_details,
                "commands": [
                    {
                        "id": str(item.id), "type": item.command_type, "state": item.state,
                        "result": item.result, "created_at": item.created_at,
                        "completed_at": item.completed_at,
                    }
                    for item in commands
                ],
            }
            if session
            else None
        ),
    }


def _validate_command(command_type: str, payload: dict[str, Any]) -> dict[str, Any]:
    if command_type not in _COMMANDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unsupported Android operation")
    clean: dict[str, Any] = {}
    if command_type == "tap":
        clean = {"x": int(payload.get("x", -1)), "y": int(payload.get("y", -1))}
        if not 0 <= clean["x"] <= 4096 or not 0 <= clean["y"] <= 4096:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "tap coordinates are invalid")
    elif command_type == "swipe":
        for name in ("x1", "y1", "x2", "y2"):
            clean[name] = int(payload.get(name, -1))
            if not 0 <= clean[name] <= 4096:
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "swipe coordinates are invalid")
        clean["duration_ms"] = min(max(int(payload.get("duration_ms", 300)), 50), 3000)
    elif command_type == "key":
        clean = {"keycode": int(payload.get("keycode", 0))}
        if not 1 <= clean["keycode"] <= 400:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "keycode is invalid")
    elif command_type == "text":
        clean = {"text": str(payload.get("text", ""))[:2000]}
    elif command_type in {"start_activity", "deeplink"}:
        key = "activity" if command_type == "start_activity" else "url"
        clean = {key: str(payload.get(key, ""))[:2048]}
        if not clean[key]:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"{key} is required")
    elif command_type == "activity_test":
        test = str(payload.get("test", ""))
        if test not in {"exported", "all_activities"}:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "activity test is invalid")
        clean = {"test": test}
    elif command_type in {"proxy", "root_ca"}:
        action = str(payload.get("action", ""))
        allowed = {"set", "unset"} if command_type == "proxy" else {"install", "remove"}
        if action not in allowed:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "operation action is invalid")
        clean = {"action": action}
    elif command_type == "frida":
        action = str(payload.get("action", "spawn"))
        if action not in {"spawn", "session", "ps", "get"}:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Frida action is invalid")
        default_allowlist = {
            "api_monitor", "ssl_pinning_bypass", "root_bypass",
            "debugger_check_bypass", "dump_clipboard",
        }
        auxiliary_allowlist = {
            "enum_class", "enum_methods", "search_class", "trace_class",
            "string_catch", "string_compare", "get_dependencies",
        }
        default_hooks = {
            value.strip() for value in str(payload.get("default_hooks", "")).split(",")
            if value.strip()
        }
        auxiliary_hooks = {
            value.strip() for value in str(payload.get("auxiliary_hooks", "")).split(",")
            if value.strip()
        }
        if not default_hooks <= default_allowlist or not auxiliary_hooks <= auxiliary_allowlist:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Frida hook selection is invalid")
        clean = {
            "action": action,
            "pid": str(payload.get("pid", ""))[:16],
            "new_package": str(payload.get("new_package", ""))[:512],
            "default_hooks": ",".join(sorted(default_hooks)),
            "auxiliary_hooks": ",".join(sorted(auxiliary_hooks)),
            "class_name": str(payload.get("class_name", ""))[:1024],
            "class_search": str(payload.get("class_search", ""))[:1024],
            "class_trace": str(payload.get("class_trace", ""))[:1024],
            "frida_code": str(payload.get("frida_code", ""))[:65536],
        }
        if "enum_methods" in auxiliary_hooks and not clean["class_name"]:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Class name is required")
        if "search_class" in auxiliary_hooks and not clean["class_search"]:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Class search is required")
        if "trace_class" in auxiliary_hooks and not clean["class_trace"]:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Class trace is required")
    elif command_type == "list_files":
        clean = {"path": str(payload.get("path", "/data/data"))[:1024]}
    elif command_type == "read_file":
        clean = {"path": str(payload.get("path", ""))[:1024]}
        if not clean["path"]:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "file path is required")
    return clean


@router.post("/{run_id}/android-commands", status_code=status.HTTP_202_ACCEPTED)
async def create_android_command(
    run_id: UUID,
    body: AndroidCommandRequest,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    run = await _android_run(db, principal, run_id)
    session = await db.scalar(
        select(AndroidDynamicSession)
        .where(AndroidDynamicSession.analysis_run_id == run.id)
        .with_for_update()
    )
    if not session or session.state != "ready":
        raise HTTPException(status.HTTP_409_CONFLICT, "interactive Android session is not ready")
    payload = _validate_command(body.command_type, body.payload)
    if body.command_type == "extend":
        maximum = session.started_at + timedelta(minutes=30)
        session.expires_at = min(maximum, max(session.expires_at, utcnow()) + timedelta(minutes=5))
        await append_audit(
            db, actor_type="user", actor_id=str(principal.user.id),
            action="android_session.extended", target_type="android_dynamic_session",
            target_id=str(session.id), payload={"expires_at": session.expires_at.isoformat()},
        )
        await db.commit()
        return {"command_id": None, "state": "completed", "expires_at": session.expires_at}
    active = await db.scalar(
        select(AndroidSessionCommand).where(
            AndroidSessionCommand.session_id == session.id,
            AndroidSessionCommand.state.in_(["queued", "running"]),
        ).limit(1)
    )
    if active and body.command_type not in {"finalize"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "another Android operation is still active")
    command = AndroidSessionCommand(
        session_id=session.id, requested_by_user_id=principal.user.id,
        command_type=body.command_type, payload=payload,
    )
    db.add(command)
    await db.flush()
    await append_audit(
        db, actor_type="user", actor_id=str(principal.user.id),
        action="android_session.command_requested", target_type="android_session_command",
        target_id=str(command.id), payload={"run_id": str(run.id), "command_type": body.command_type},
    )
    await db.commit()
    return {"command_id": str(command.id), "state": command.state}


@router.get("/{run_id}/android-commands/{command_id}")
async def get_android_command(
    run_id: UUID,
    command_id: UUID,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    run = await _android_run(db, principal, run_id)
    session = await db.scalar(
        select(AndroidDynamicSession).where(AndroidDynamicSession.analysis_run_id == run.id)
    )
    command = await db.get(AndroidSessionCommand, command_id)
    if not session or not command or command.session_id != session.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android operation not found")
    return {
        "command_id": str(command.id), "type": command.command_type,
        "state": command.state, "result": command.result,
        "created_at": command.created_at, "completed_at": command.completed_at,
    }


def _member_exists(artifact: Artifact, member: str) -> bool:
    try:
        archive = store().verify(artifact.object_key, artifact.sha256)
        with zipfile.ZipFile(archive) as bundle:
            return member in bundle.namelist()
    except (DigestMismatchError, zipfile.BadZipFile):
        return False


@router.get("/{run_id}/android-evidence/{evidence_name}")
async def android_inline_evidence(
    run_id: UUID,
    evidence_name: str,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    run = await _android_run(db, principal, run_id)
    descriptor = _EVIDENCE_MEMBERS.get(evidence_name)
    if descriptor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android evidence item not found")
    artifact = await _bundle(db, run.id)
    if artifact is None or not tier_allowed(principal, artifact.access_tier):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Android evidence item not found")
    member, media_type = descriptor
    payload = _read_member(artifact, member, _MAX_INLINE_EVIDENCE_BYTES)
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="android_evidence.viewed",
        target_type="analysis_run",
        target_id=str(run.id),
        payload={"evidence_name": evidence_name, "artifact_id": str(artifact.id)},
    )
    await db.commit()
    return Response(
        io.BytesIO(payload).read(),
        media_type=media_type,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )
