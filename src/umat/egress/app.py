from __future__ import annotations

import hmac
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Protocol
from uuid import UUID

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Response, status
from fastapi.responses import JSONResponse

from umat.egress.schemas import LeaseRequest, LeaseResult, Readiness


class Manager(Protocol):
    def readiness(self) -> Readiness: ...
    def acquire(self, request: LeaseRequest) -> LeaseResult: ...
    def heartbeat(self, run_id: UUID, ttl_seconds: int = 90) -> LeaseResult: ...
    def revoke(self, run_id: UUID) -> object: ...
    def close(self) -> None: ...


def _token() -> str:
    value = os.environ.get("UMAT_EGRESS_BROKER_TOKEN", "")
    if len(value) < 32:
        raise RuntimeError("UMAT_EGRESS_BROKER_TOKEN must contain at least 32 characters")
    return value


def authorize(authorization: Annotated[str | None, Header()] = None) -> None:
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if not hmac.compare_digest(supplied, _token()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid egress broker credential")


def create_app(manager: Manager | None = None) -> FastAPI:
    if manager is None:
        from umat.egress.manager import EgressManager

        manager = EgressManager.from_environment()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        _token()
        yield
        manager.close()

    application = FastAPI(
        title="UMAT Egress Broker", docs_url=None, redoc_url=None, lifespan=lifespan
    )

    @application.exception_handler(RuntimeError)
    def rejected(_: object, exc: RuntimeError) -> JSONResponse:
        return JSONResponse({"error": "egress_rejected", "detail": str(exc)}, status_code=409)

    @application.get("/health/ready", response_model=Readiness)
    def ready() -> Readiness:
        return manager.readiness()

    @application.post(
        "/api/v1/leases",
        response_model=LeaseResult,
        status_code=status.HTTP_201_CREATED,
        dependencies=[Depends(authorize)],
    )
    def acquire(request: LeaseRequest) -> LeaseResult:
        return manager.acquire(request)

    @application.post(
        "/api/v1/leases/{run_id}/heartbeat",
        response_model=LeaseResult,
        dependencies=[Depends(authorize)],
    )
    def heartbeat(run_id: UUID) -> LeaseResult:
        return manager.heartbeat(run_id)

    @application.delete(
        "/api/v1/leases/{run_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        dependencies=[Depends(authorize)],
    )
    def revoke(run_id: UUID) -> Response:
        capture = manager.revoke(run_id)
        headers = {"X-UMAT-Capture-Path": str(capture)} if capture else {}
        return Response(status_code=status.HTTP_204_NO_CONTENT, headers=headers)

    return application


app = create_app()


def run() -> None:
    uvicorn.run(
        "umat.egress.app:app",
        host="127.0.0.1",
        port=int(os.environ.get("UMAT_EGRESS_BROKER_PORT", "8092")),
    )
