from __future__ import annotations

import hmac
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Protocol

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse

from umat.cape_gateway.schemas import MachineResult, ProfileRequest


class ProfileManager(Protocol):
    def create(self, profile: ProfileRequest) -> MachineResult: ...

    def delete(self, label: str) -> MachineResult: ...


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

    return application


app = create_app()


def run() -> None:
    uvicorn.run(
        "umat.cape_gateway.app:app",
        host=os.environ.get("UMAT_CAPE_GATEWAY_HOST", "127.0.0.1"),
        port=int(os.environ.get("UMAT_CAPE_GATEWAY_PORT", "8091")),
    )
