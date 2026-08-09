from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.schemas import LoginRequest, SessionResponse
from umat.audit import append_audit
from umat.auth.dependencies import Principal, current_principal
from umat.auth.security import normalize_username, random_token, token_hash, verify_password
from umat.config import get_settings
from umat.db import get_db
from umat.db.models import LoginAttempt, Session, User

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=SessionResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> SessionResponse:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    username = normalize_username(body.username)
    ip = client_ip(request)
    recent_failures = await db.scalar(
        select(func.count(LoginAttempt.id)).where(
            LoginAttempt.succeeded.is_(False),
            LoginAttempt.attempted_at >= now - timedelta(seconds=settings.login_window_seconds),
            (LoginAttempt.username == username) | (LoginAttempt.ip_address == ip),
        )
    )
    if (recent_failures or 0) >= settings.login_max_attempts:
        await append_audit(db, actor_type="anonymous", actor_id=None, action="auth.throttled", target_type="user", target_id=username, payload={"ip": ip})
        await db.commit()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "login temporarily throttled")
    user = await db.scalar(select(User).where(User.username == username))
    valid = bool(user and user.enabled and verify_password(user.password_hash, body.password))
    db.add(LoginAttempt(username=username, ip_address=ip, succeeded=valid, attempted_at=now))
    if not valid or user is None:
        await append_audit(db, actor_type="anonymous", actor_id=None, action="auth.failed", target_type="user", target_id=username, payload={"ip": ip})
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    session_token = random_token()
    csrf_token = random_token()
    expires = now + timedelta(seconds=settings.session_ttl_seconds)
    session = Session(
        user_id=user.id,
        token_hash=token_hash(session_token),
        csrf_hash=token_hash(csrf_token),
        expires_at=expires,
        ip_address=ip,
        user_agent=(request.headers.get("user-agent") or "")[:512],
    )
    db.add(session)
    await append_audit(db, actor_type="user", actor_id=str(user.id), action="auth.succeeded", target_type="session", target_id=str(session.id), payload={"ip": ip})
    await db.commit()
    response.set_cookie(
        "umat_session",
        session_token,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=settings.session_ttl_seconds,
        path="/",
    )
    response.set_cookie(
        "umat_csrf",
        csrf_token,
        httponly=False,
        secure=settings.secure_cookies,
        samesite="strict",
        max_age=settings.session_ttl_seconds,
        path="/",
    )
    return SessionResponse(user_id=user.id, username=user.username, roles=sorted(role.name for role in user.roles), expires_at=expires, csrf_token=csrf_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response,
    principal: Principal = Depends(current_principal),
    db: AsyncSession = Depends(get_db),
) -> None:
    principal.session.revoked_at = datetime.now(timezone.utc)
    await append_audit(db, actor_type="user", actor_id=str(principal.user.id), action="auth.logout", target_type="session", target_id=str(principal.session.id))
    await db.commit()
    response.delete_cookie("umat_session", path="/")
    response.delete_cookie("umat_csrf", path="/")


@router.get("/session", response_model=SessionResponse)
async def get_session(principal: Principal = Depends(current_principal)) -> SessionResponse:
    return SessionResponse(user_id=principal.user.id, username=principal.user.username, roles=sorted(principal.roles), expires_at=principal.session.expires_at)
