from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from umat.api.admin_schemas import (
    AdminUserResponse,
    SessionRevocationResponse,
    UserCreateRequest,
    UserListResponse,
    UserUpdateRequest,
)
from umat.audit import append_audit
from umat.auth.dependencies import Principal, require_roles
from umat.auth.security import hash_password, normalize_username
from umat.db import get_db
from umat.db.models import Role, Session, User

router = APIRouter(prefix="/api/v1/admin/users", tags=["administration"])


async def _lock_user_changes(db: AsyncSession) -> None:
    # Serialize console mutations so two administrators cannot concurrently
    # demote/disable each other and leave the installation without an admin.
    if db.bind and db.bind.dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(8675310)"))


async def _roles(db: AsyncSession, requested: list[str]) -> list[Role]:
    names = set(requested)
    if not names:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "at least one role is required")
    rows = list((await db.scalars(select(Role).where(Role.name.in_(names)))).all())
    unknown = names - {row.name for row in rows}
    if unknown:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"unknown role: {', '.join(sorted(unknown))}",
        )
    return sorted(rows, key=lambda row: row.name)


async def _user(db: AsyncSession, user_id: UUID) -> User:
    user = await db.scalar(select(User).where(User.id == user_id))
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return user


def _is_administrator(user: User) -> bool:
    return "administrator" in {role.name for role in user.roles}


async def _ensure_another_enabled_administrator(db: AsyncSession, target: User) -> None:
    if not target.enabled or not _is_administrator(target):
        return
    remaining = await db.scalar(
        select(func.count(User.id))
        .join(User.roles)
        .where(
            Role.name == "administrator",
            User.enabled.is_(True),
            User.id != target.id,
        )
    )
    if not remaining:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "the last enabled administrator cannot be removed or disabled",
        )


async def _revoke_sessions(db: AsyncSession, user_id: UUID) -> int:
    revoked = await db.scalars(
        update(Session)
        .where(Session.user_id == user_id, Session.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
        .returning(Session.id)
    )
    return len(revoked.all())


async def _response(db: AsyncSession, user: User) -> AdminUserResponse:
    active_sessions = await db.scalar(
        select(func.count(Session.id)).where(
            Session.user_id == user.id,
            Session.revoked_at.is_(None),
            Session.expires_at > datetime.now(timezone.utc),
        )
    )
    return AdminUserResponse(
        id=user.id,
        username=user.username,
        roles=sorted(role.name for role in user.roles),
        enabled=user.enabled,
        active_sessions=active_sessions or 0,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )


@router.get("", response_model=UserListResponse)
async def list_users(
    _: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> UserListResponse:
    users = list((await db.scalars(select(User).order_by(User.username))).all())
    roles = list((await db.scalars(select(Role.name).order_by(Role.id))).all())
    return UserListResponse(items=[await _response(db, user) for user in users], roles=roles)


@router.post("", response_model=AdminUserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreateRequest,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> AdminUserResponse:
    await _lock_user_changes(db)
    username = normalize_username(body.username)
    if not username:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "username cannot be blank")
    if await db.scalar(select(User.id).where(User.username == username)):
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
    user = User(
        username=username,
        password_hash=hash_password(body.password),
        enabled=body.enabled,
        roles=await _roles(db, body.roles),
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists") from error
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="user.created",
        target_type="user",
        target_id=str(user.id),
        payload={"username": username, "roles": sorted(body.roles), "enabled": body.enabled},
    )
    await db.commit()
    return await _response(db, user)


@router.patch("/{user_id}", response_model=AdminUserResponse)
async def update_user(
    user_id: UUID,
    body: UserUpdateRequest,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> AdminUserResponse:
    await _lock_user_changes(db)
    target = await _user(db, user_id)
    changes = body.model_fields_set
    if not changes:
        return await _response(db, target)

    previous = {
        "username": target.username,
        "roles": sorted(role.name for role in target.roles),
        "enabled": target.enabled,
    }
    new_roles = await _roles(db, body.roles) if "roles" in changes and body.roles else None
    removing_admin = new_roles is not None and "administrator" not in {
        role.name for role in new_roles
    }
    disabling = "enabled" in changes and body.enabled is False
    if target.id == principal.user.id and (removing_admin or disabling):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "you cannot remove your own administrator access or disable your own account",
        )
    if removing_admin or disabling:
        await _ensure_another_enabled_administrator(db, target)

    if "username" in changes and body.username is not None:
        username = normalize_username(body.username)
        if not username:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "username cannot be blank")
        duplicate = await db.scalar(
            select(User.id).where(User.username == username, User.id != target.id)
        )
        if duplicate:
            raise HTTPException(status.HTTP_409_CONFLICT, "username already exists")
        target.username = username
    if new_roles is not None:
        target.roles = new_roles
    if "enabled" in changes and body.enabled is not None:
        target.enabled = body.enabled
    password_changed = "password" in changes and body.password is not None
    new_password = body.password
    if password_changed and new_password is not None:
        target.password_hash = hash_password(new_password)

    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "username already exists") from error

    sessions_revoked = 0
    # Roles are loaded from the database on every authenticated request, so role
    # changes take effect immediately without disrupting unrelated sessions.
    if password_changed or disabling:
        sessions_revoked = await _revoke_sessions(db, target.id)
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="user.updated",
        target_type="user",
        target_id=str(target.id),
        payload={
            "previous": previous,
            "current": {
                "username": target.username,
                "roles": sorted(role.name for role in target.roles),
                "enabled": target.enabled,
            },
            "password_changed": password_changed,
            "sessions_revoked": sessions_revoked,
        },
    )
    await db.commit()
    return await _response(db, target)


@router.post("/{user_id}/revoke-sessions", response_model=SessionRevocationResponse)
async def revoke_user_sessions(
    user_id: UUID,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> SessionRevocationResponse:
    target = await _user(db, user_id)
    if target.id == principal.user.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "use sign out to end your own session")
    revoked = await _revoke_sessions(db, target.id)
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="user.sessions_revoked",
        target_type="user",
        target_id=str(target.id),
        payload={"sessions_revoked": revoked},
    )
    await db.commit()
    return SessionRevocationResponse(sessions_revoked=revoked)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    principal: Principal = Depends(require_roles("administrator")),
    db: AsyncSession = Depends(get_db),
) -> Response:
    await _lock_user_changes(db)
    target = await _user(db, user_id)
    if target.id == principal.user.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "you cannot delete your own account")
    await _ensure_another_enabled_administrator(db, target)
    details = {
        "username": target.username,
        "roles": sorted(role.name for role in target.roles),
    }
    await db.execute(delete(Session).where(Session.user_id == target.id))
    await db.delete(target)
    try:
        await db.flush()
    except IntegrityError as error:
        await db.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "this user owns retained records and cannot be deleted; disable the account instead",
        ) from error
    await append_audit(
        db,
        actor_type="user",
        actor_id=str(principal.user.id),
        action="user.deleted",
        target_type="user",
        target_id=str(target.id),
        payload=details,
    )
    await db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
