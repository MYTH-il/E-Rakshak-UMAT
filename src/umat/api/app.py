from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
import uvicorn
from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware

from umat import __version__
from umat.api.artifact_routes import router as artifact_router
from umat.api.auth_routes import router as auth_router
from umat.api.case_routes import router as case_router
from umat.api.executor_routes import router as executor_router
from umat.api.report_routes import router as report_router
from umat.config import get_settings
from umat.db.session import session_factory
from umat.storage.local import LocalArtifactStore
from umat.windows.profile_routes import router as windows_profile_router


def configure_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.add_log_level,
            structlog.processors.JSONRenderer(),
        ]
    )


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging()
    LocalArtifactStore(settings.quarantine_root, settings.artifact_root).cleanup_temporary()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(title="UMAT Control Plane", version=__version__, lifespan=lifespan)
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    application.include_router(auth_router)
    application.include_router(case_router)
    application.include_router(artifact_router)
    application.include_router(executor_router)
    application.include_router(report_router)
    application.include_router(windows_profile_router)

    web_root = Path(__file__).parents[1] / "web"
    application.mount("/assets", StaticFiles(directory=web_root / "static"), name="assets")

    @application.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))[:128]
        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                "object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
            return response
        finally:
            structlog.contextvars.clear_contextvars()

    @application.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            {"error": f"http_{exc.status_code}", "detail": str(exc.detail), "request_id": request.headers.get("X-Request-ID")},
            status_code=exc.status_code,
            headers=exc.headers,
        )

    @application.get("/health/live", include_in_schema=False)
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready", include_in_schema=False)
    async def ready() -> dict[str, str]:
        async with session_factory() as db:
            await db.execute(text("SELECT 1"))
        return {"status": "ready"}

    @application.get("/", include_in_schema=False)
    @application.get("/login", include_in_schema=False)
    @application.get("/cases", include_in_schema=False)
    @application.get("/submit", include_in_schema=False)
    @application.get("/cases/{case_id}", include_in_schema=False)
    @application.get("/admin/windows", include_in_schema=False)
    async def web_application(case_id: str | None = None) -> FileResponse:
        del case_id
        return FileResponse(
            web_root / "index.html",
            media_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    return application


app = create_app()


def run() -> None:
    settings = get_settings()
    uvicorn.run(
        "umat.api.app:app", host=settings.api_host, port=settings.api_port, reload=False
    )
