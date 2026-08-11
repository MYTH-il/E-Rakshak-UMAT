from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.auth.security import token_hash
from umat.db import get_db
from umat.db.models import Session, User


@dataclass(frozen=True)
class Principal:
    user: User
    session: Session
    roles: frozenset[str]

    @property
    def is_staff(self) -> bool:
        return bool(self.roles & {"analyst", "administrator"})


async def current_principal(
    request: Request,
    db: AsyncSession = Depends(get_db),
    umat_session: str | None = Cookie(default=None),
    x_csrf_token: str | None = Header(default=None),
) -> Principal:
    if not umat_session:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    record = await db.scalar(
        select(Session).join(Session.user).where(Session.token_hash == token_hash(umat_session))
    )
    now = datetime.now(timezone.utc)
    if not record or record.revoked_at or record.expires_at <= now or not record.user.enabled:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session expired or revoked")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if not x_csrf_token or token_hash(x_csrf_token) != record.csrf_hash:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid CSRF token")
    record.last_seen_at = now
    roles = frozenset(role.name for role in record.user.roles)
    return Principal(record.user, record, roles)


def require_roles(*required: str):  # type: ignore[no-untyped-def]
    async def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.roles.intersection(required):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "insufficient role")
        return principal

    return dependency
