from __future__ import annotations

import asyncio
import hmac
import os
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Protocol

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse

from umat.cape_gateway.schemas import ConsoleRequest, ConsoleResult, MachineResult, ProfileRequest


class ProfileManager(Protocol):
    def create(self, profile: ProfileRequest) -> MachineResult: ...

    def delete(self, label: str) -> MachineResult: ...

    def console_target(self, task_id: int, label: str) -> tuple[str, int]: ...


@dataclass(frozen=True)
class ConsoleCapability:
    task_id: int
    machine_label: str
    host: str
    port: int
    expires_at: datetime


def _token() -> str:
    value = os.environ.get("UMAT_CAPE_GATEWAY_TOKEN", "")
    if len(value) < 32:
        raise RuntimeError("UMAT_CAPE_GATEWAY_TOKEN must contain at least 32 characters")
    return value


def authorize(authorization: Annotated[str | None, Header()] = None) -> None:
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if not hmac.compare_digest(supplied, _token()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid gateway credential")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    _token()
    yield


def create_app(manager: ProfileManager | None = None) -> FastAPI:
    if manager is None:
        from umat.cape_gateway.manager import CapeProfileManager

        manager = CapeProfileManager.from_environment()
    consoles: dict[str, ConsoleCapability] = {}
    application = FastAPI(
        title="UMAT CAPE Management Gateway", docs_url=None, redoc_url=None, lifespan=lifespan
    )

    @application.exception_handler(RuntimeError)
    def management_error(_: object, exc: RuntimeError) -> JSONResponse:
        return JSONResponse(
            {"error": "profile_management_rejected", "detail": str(exc)}, status_code=409
        )

    @application.get("/health/live", include_in_schema=False)
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @application.post(
        "/api/v1/machines",
        response_model=MachineResult,
        dependencies=[Depends(authorize)],
        status_code=status.HTTP_201_CREATED,
    )
    def create_machine(profile: ProfileRequest) -> MachineResult:
        return manager.create(profile)

    @application.delete(
        "/api/v1/machines/{label}",
        response_model=MachineResult,
        dependencies=[Depends(authorize)],
    )
    def delete_machine(label: str) -> MachineResult:
        if not label.startswith("umat-") or not label.replace("-", "").isalnum():
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid machine label")
        return manager.delete(label)

    @application.post(
        "/api/v1/tasks/{task_id}/console",
        response_model=ConsoleResult,
        dependencies=[Depends(authorize)],
    )
    def create_console(task_id: int, body: ConsoleRequest) -> ConsoleResult:
        host, port = manager.console_target(task_id, body.machine_label)
        now = datetime.now(timezone.utc)
        for key, value in list(consoles.items()):
            if value.expires_at <= now:
                consoles.pop(key, None)
        token = secrets.token_urlsafe(48)
        expires_at = now + timedelta(seconds=body.duration_seconds)
        consoles[token] = ConsoleCapability(
            task_id, body.machine_label, host, port, expires_at
        )
        gateway_port = int(os.environ.get("UMAT_CAPE_GATEWAY_PORT", "8091"))
        return ConsoleResult(
            console_url=f"ws://127.0.0.1:{gateway_port}/api/v1/console/{token}",
            machine_label=body.machine_label,
            expires_at=expires_at.isoformat(),
        )

    @application.websocket("/api/v1/console/{token}")
    async def console_socket(websocket: WebSocket, token: str) -> None:
        capability = consoles.get(token)
        now = datetime.now(timezone.utc)
        if not capability or capability.expires_at <= now:
            consoles.pop(token, None)
            await websocket.close(code=4404)
            return
        try:
            host, port = manager.console_target(
                capability.task_id, capability.machine_label
            )
        except RuntimeError:
            consoles.pop(token, None)
            await websocket.close(code=4409)
            return
        if (host, port) != (capability.host, capability.port):
            consoles.pop(token, None)
            await websocket.close(code=4409)
            return
        await websocket.accept(subprotocol="binary")
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError:
            await websocket.close(code=1011)
            return

        async def browser_to_vnc() -> None:
            while True:
                payload = await websocket.receive_bytes()
                writer.write(payload)
                await writer.drain()

        async def vnc_to_browser() -> None:
            while payload := await reader.read(65536):
                await websocket.send_bytes(payload)

        tasks = {
            asyncio.create_task(browser_to_vnc()),
            asyncio.create_task(vnc_to_browser()),
        }
        try:
            _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
        except WebSocketDisconnect:
            pass
        finally:
            for task in tasks:
                task.cancel()
            writer.close()
            await writer.wait_closed()

    return application


app = create_app()


def run() -> None:
    uvicorn.run(
        "umat.cape_gateway.app:app",
        host=os.environ.get("UMAT_CAPE_GATEWAY_HOST", "127.0.0.1"),
        port=int(os.environ.get("UMAT_CAPE_GATEWAY_PORT", "8091")),
    )
