from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import typer
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from umat.audit import append_audit, verify_audit_chain
from umat.auth.security import hash_password, normalize_username, random_token, token_hash
from umat.db.models import (
    Executor,
    ExecutorCredential,
    ExecutorEnrollmentToken,
    ExecutorStatus,
    Role,
    Session,
    User,
)
from umat.db.session import session_factory

app = typer.Typer(no_args_is_help=True)


async def require_administrator(db: AsyncSession, username: str) -> User:
    # The CLI authenticates through local OS access; this check attributes each mutation
    # to a currently enabled administrator account in the audit chain.
    user = await db.scalar(select(User).where(User.username == normalize_username(username)))
    if not user or not user.enabled or "administrator" not in {role.name for role in user.roles}:
        raise typer.BadParameter("admin must identify an enabled administrator")
    return user


@app.command("create-user")
def create_user(
    username: str = typer.Option(...),
    role: str = typer.Option(..., help="officer, analyst, or administrator"),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True),
) -> None:
    async def operation() -> None:
        normalized = normalize_username(username)
        async with session_factory() as db:
            if await db.scalar(select(User).where(User.username == normalized)):
                raise typer.BadParameter("username already exists")
            role_row = await db.scalar(select(Role).where(Role.name == role))
            if not role_row:
                raise typer.BadParameter("unknown role")
            user = User(username=normalized, password_hash=hash_password(password), roles=[role_row])
            db.add(user)
            await db.flush()
            await append_audit(db, actor_type="local_admin", actor_id=None, action="user.created", target_type="user", target_id=str(user.id), payload={"username": normalized, "role": role})
            await db.commit()
            typer.echo(str(user.id))
    asyncio.run(operation())


@app.command("enroll-executor")
def enroll_executor(
    created_by: str = typer.Option(..., help="Administrator username"),
    executor_type: str = typer.Option(...),
    stage_type: list[str] = typer.Option(..., "--stage-type"),
    ttl_minutes: int = typer.Option(30, min=1, max=1440),
) -> None:
    async def operation() -> None:
        raw = random_token(48)
        async with session_factory() as db:
            user = await require_administrator(db, created_by)
            enrollment = ExecutorEnrollmentToken(token_hash=token_hash(raw), executor_type=executor_type, scopes=stage_type, expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes), created_by_user_id=user.id)
            db.add(enrollment)
            await db.flush()
            await append_audit(db, actor_type="user", actor_id=str(user.id), action="executor.enrollment_created", target_type="executor_enrollment", target_id=str(enrollment.id), payload={"executor_type": executor_type, "stage_types": stage_type})
            await db.commit()
            typer.echo(raw)
    asyncio.run(operation())


@app.command("set-user-role")
def set_user_role(
    admin: str = typer.Option(..., help="Administrator username for audit attribution"),
    username: str = typer.Option(...),
    role: list[str] = typer.Option(..., "--role", help="Replacement role assignment"),
) -> None:
    async def operation() -> None:
        requested = set(role)
        if not requested:
            raise typer.BadParameter("at least one role is required")
        async with session_factory() as db:
            actor = await require_administrator(db, admin)
            target = await db.scalar(select(User).where(User.username == normalize_username(username)))
            if not target:
                raise typer.BadParameter("unknown username")
            rows = list((await db.scalars(select(Role).where(Role.name.in_(requested)))).all())
            if {item.name for item in rows} != requested:
                raise typer.BadParameter("unknown role")
            previous = sorted(item.name for item in target.roles)
            target.roles = rows
            await append_audit(
                db,
                actor_type="user",
                actor_id=str(actor.id),
                action="user.roles_changed",
                target_type="user",
                target_id=str(target.id),
                payload={"previous": previous, "current": sorted(requested)},
            )
            await db.commit()
            typer.echo(str(target.id))

    asyncio.run(operation())


@app.command("set-user-enabled")
def set_user_enabled(
    admin: str = typer.Option(..., help="Administrator username for audit attribution"),
    username: str = typer.Option(...),
    enabled: bool = typer.Option(..., "--enabled/--disabled"),
) -> None:
    async def operation() -> None:
        async with session_factory() as db:
            actor = await require_administrator(db, admin)
            target = await db.scalar(select(User).where(User.username == normalize_username(username)))
            if not target:
                raise typer.BadParameter("unknown username")
            if actor.id == target.id and not enabled:
                raise typer.BadParameter("an administrator cannot disable their own account")
            target.enabled = enabled
            now = datetime.now(timezone.utc)
            revoked = 0
            if not enabled:
                revoked_ids = await db.scalars(
                    update(Session)
                    .where(Session.user_id == target.id, Session.revoked_at.is_(None))
                    .values(revoked_at=now)
                    .returning(Session.id)
                )
                revoked = len(revoked_ids.all())
            await append_audit(
                db,
                actor_type="user",
                actor_id=str(actor.id),
                action="user.enabled_changed",
                target_type="user",
                target_id=str(target.id),
                payload={"enabled": enabled, "sessions_revoked": revoked},
            )
            await db.commit()
            typer.echo(str(target.id))

    asyncio.run(operation())


@app.command("revoke-user-sessions")
def revoke_user_sessions(
    admin: str = typer.Option(..., help="Administrator username for audit attribution"),
    username: str = typer.Option(...),
) -> None:
    async def operation() -> None:
        async with session_factory() as db:
            actor = await require_administrator(db, admin)
            target = await db.scalar(select(User).where(User.username == normalize_username(username)))
            if not target:
                raise typer.BadParameter("unknown username")
            revoked_ids = await db.scalars(
                update(Session)
                .where(Session.user_id == target.id, Session.revoked_at.is_(None))
                .values(revoked_at=datetime.now(timezone.utc))
                .returning(Session.id)
            )
            revoked = len(revoked_ids.all())
            await append_audit(
                db,
                actor_type="user",
                actor_id=str(actor.id),
                action="user.sessions_revoked",
                target_type="user",
                target_id=str(target.id),
                payload={"sessions_revoked": revoked},
            )
            await db.commit()
            typer.echo(str(revoked))

    asyncio.run(operation())


@app.command("revoke-executor")
def revoke_executor(
    admin: str = typer.Option(..., help="Administrator username for audit attribution"),
    executor_name: str = typer.Option(...),
) -> None:
    async def operation() -> None:
        async with session_factory() as db:
            actor = await require_administrator(db, admin)
            executor = await db.scalar(select(Executor).where(Executor.name == executor_name))
            if not executor:
                raise typer.BadParameter("unknown executor")
            executor.status = ExecutorStatus.DISABLED
            revoked_ids = await db.scalars(
                update(ExecutorCredential)
                .where(
                    ExecutorCredential.executor_id == executor.id,
                    ExecutorCredential.revoked_at.is_(None),
                )
                .values(revoked_at=datetime.now(timezone.utc))
                .returning(ExecutorCredential.id)
            )
            revoked = len(revoked_ids.all())
            await append_audit(
                db,
                actor_type="user",
                actor_id=str(actor.id),
                action="executor.credential_revoked",
                target_type="executor",
                target_id=str(executor.id),
                payload={"credentials_revoked": revoked, "executor_name": executor.name},
            )
            await db.commit()
            typer.echo(str(executor.id))

    asyncio.run(operation())


@app.command("verify-audit")
def verify_audit() -> None:
    async def operation() -> None:
        async with session_factory() as db:
            valid, sequence = await verify_audit_chain(db)
            if not valid:
                typer.echo(f"audit chain invalid at sequence {sequence}", err=True)
                raise typer.Exit(1)
            typer.echo("audit chain valid")
    asyncio.run(operation())
