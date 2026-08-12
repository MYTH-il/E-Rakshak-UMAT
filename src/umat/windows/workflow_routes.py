from __future__ import annotations

import asyncio
import glob
import os
import re
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from websockets.asyncio.client import connect
from websockets.typing import Subprotocol

from umat.api.case_routes import accessible_case
from umat.audit import append_audit
from umat.auth.dependencies import Principal, require_roles
from umat.auth.security import token_hash
from umat.db import get_db, session_factory
from umat.db.models import (
    AnalysisRun,
    Platform,
    Session,
    StageState,
    StageType,
    WindowsDynamicSession,
)

router = APIRouter(prefix="/api/v1/analysis-runs", tags=["windows-workflow"])


async def _windows_run(db: AsyncSession, principal: Principal, run_id: UUID) -> AnalysisRun:
    run = await db.get(AnalysisRun, run_id)
    if not run or run.platform != Platform.WINDOWS:
        raise HTTPException(404, "Windows analysis run not found")
    await accessible_case(db, principal, run.case_id)
    return run


def _session_payload(
    session: WindowsDynamicSession | None, active: bool
) -> dict[str, Any] | None:
    if not session:
        return None
    now = datetime.now(timezone.utc)
    state = session.state if active and session.expires_at > now else "ended"
    return {
        "id": str(session.id),
        "state": state,
        "cape_task_id": session.cape_task_id,
        "machine_label": session.machine_label,
        "started_at": session.started_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "console_path": f"/api/v1/analysis-runs/{session.analysis_run_id}/windows-console"
        if state == "ready"
        else None,
    }


@router.get("/{run_id}/windows-workflow")
async def windows_workflow(
    run_id: UUID,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    run = await _windows_run(db, principal, run_id)
    session = await db.scalar(
        select(WindowsDynamicSession).where(WindowsDynamicSession.analysis_run_id == run.id)
    )
    platform_active = any(
        stage.stage_type == StageType.PLATFORM_ANALYSIS
        and stage.state in {StageState.LEASED, StageState.RUNNING}
        for stage in run.stages
    )
    return {
        "schema_version": "1.0",
        "run": {
            "id": str(run.id),
            "case_id": str(run.case_id),
            "status": run.status.value,
            "result": run.result.value if run.result else None,
            "network_mode": run.network_mode,
            "profile": run.windows_configuration.profile_snapshot
            if run.windows_configuration
            else None,
        },
        "interactive_session": _session_payload(session, platform_active),
    }


@router.post("/{run_id}/windows-session/finish")
async def finish_windows_session(
    run_id: UUID,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    run = await _windows_run(db, principal, run_id)
    session = await db.scalar(
        select(WindowsDynamicSession)
        .where(WindowsDynamicSession.analysis_run_id == run.id)
        .with_for_update()
    )
    if not session or session.state != "ready":
        raise HTTPException(409, "live Windows session is not ready")
    session.state = "finalizing"
    session.last_seen_at = datetime.now(timezone.utc)
    await append_audit(
        db, actor_type="user", actor_id=str(principal.user.id),
        action="windows_session.finish_requested",
        target_type="windows_dynamic_session", target_id=str(session.id),
        payload={"analysis_run_id": str(run.id), "cape_task_id": session.cape_task_id},
    )
    await db.commit()
    return {"state": "finalizing"}


@router.post("/{run_id}/windows-session/launch-viewer")
async def launch_windows_viewer(
    run_id: UUID,
    principal: Principal = Depends(require_roles("analyst", "administrator")),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    run = await _windows_run(db, principal, run_id)
    session = await db.scalar(
        select(WindowsDynamicSession).where(
            WindowsDynamicSession.analysis_run_id == run.id
        )
    )
    now = datetime.now(timezone.utc)
    active = any(
        stage.stage_type == StageType.PLATFORM_ANALYSIS
        and stage.state in {StageState.LEASED, StageState.RUNNING}
        for stage in run.stages
    )
    if (
        not run.windows_interactive
        or not session
        or session.state != "ready"
        or session.expires_at <= now
        or not active
    ):
        raise HTTPException(409, "manual Windows console is not ready")
    virsh = await asyncio.create_subprocess_exec(
        "/usr/bin/virsh", "-c", "qemu:///system", "domdisplay",
        session.machine_label, "--type", "vnc",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _stderr = await asyncio.wait_for(virsh.communicate(), timeout=10)
    if virsh.returncode:
        raise HTTPException(409, "manual Windows VNC display is unavailable")
    display = stdout.decode().strip()
    match = re.fullmatch(r"vnc://127\.0\.0\.1:(\d+)", display)
    if not match:
        raise HTTPException(409, "manual Windows VNC display is not loopback-only")
    environment = os.environ.copy()
    environment.setdefault("DISPLAY", ":0")
    environment.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    authorities = await asyncio.to_thread(
        glob.glob, f"/run/user/{os.getuid()}/.mutter-Xwaylandauth.*"
    )
    if not authorities:
        raise HTTPException(409, "local analyst desktop is unavailable")
    environment["XAUTHORITY"] = authorities[0]
    viewer = await asyncio.create_subprocess_exec(
        "/usr/bin/vncviewer", "-Shared", f"127.0.0.1:{match.group(1)}",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        start_new_session=True,
        env=environment,
    )
    await asyncio.sleep(0.5)
    if viewer.returncode is not None:
        raise HTTPException(409, "TigerVNC could not open on the local analyst desktop")
    session.last_seen_at = now
    await append_audit(
        db, actor_type="user", actor_id=str(principal.user.id),
        action="windows_session.native_viewer_launched",
        target_type="windows_dynamic_session", target_id=str(session.id),
        payload={"analysis_run_id": str(run.id), "machine_label": session.machine_label},
    )
    await db.commit()
    return {"state": "launched", "viewer": "TigerVNC"}


async def _websocket_session(websocket: WebSocket, run_id: UUID) -> WindowsDynamicSession | None:
    raw = websocket.cookies.get("umat_session")
    if not raw:
        return None
    async with session_factory() as db:
        auth = await db.scalar(
            select(Session).join(Session.user).where(Session.token_hash == token_hash(raw))
        )
        now = datetime.now(timezone.utc)
        if not auth or auth.revoked_at or auth.expires_at <= now or not auth.user.enabled:
            return None
        roles = {role.name for role in auth.user.roles}
        if not roles.intersection({"analyst", "administrator"}):
            return None
        run = await db.get(AnalysisRun, run_id)
        if not run or run.platform != Platform.WINDOWS:
            return None
        session = await db.scalar(
            select(WindowsDynamicSession).where(
                WindowsDynamicSession.analysis_run_id == run_id
            )
        )
        active = any(
            stage.stage_type == StageType.PLATFORM_ANALYSIS
            and stage.state in {StageState.LEASED, StageState.RUNNING}
            for stage in run.stages
        )
        if not session or session.state != "ready" or session.expires_at <= now or not active:
            return None
        session.last_seen_at = now
        await append_audit(
            db,
            actor_type="user",
            actor_id=str(auth.user.id),
            action="windows_session.console_connected",
            target_type="windows_dynamic_session",
            target_id=str(session.id),
            payload={"analysis_run_id": str(run_id), "cape_task_id": session.cape_task_id},
        )
        await db.commit()
        return session


@router.websocket("/{run_id}/windows-console")
async def windows_console(websocket: WebSocket, run_id: UUID) -> None:
    session = await _websocket_session(websocket, run_id)
    if not session:
        await websocket.close(code=4404)
        return
    offered = websocket.headers.get("sec-websocket-protocol", "")
    subprotocol = "binary" if "binary" in {item.strip() for item in offered.split(",")} else None
    await websocket.accept(subprotocol=subprotocol)
    try:
        async with connect(
            session.console_url, subprotocols=[Subprotocol("binary")]
        ) as upstream:
            async def browser_to_gateway() -> None:
                while True:
                    message = await websocket.receive()
                    if message.get("bytes") is not None:
                        await upstream.send(message["bytes"])
                    elif message.get("type") == "websocket.disconnect":
                        return

            async def gateway_to_browser() -> None:
                async for payload in upstream:
                    if isinstance(payload, bytes):
                        await websocket.send_bytes(payload)

            tasks = {
                asyncio.create_task(browser_to_gateway()),
                asyncio.create_task(gateway_to_browser()),
            }
            _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
    except (OSError, WebSocketDisconnect):
        return
