import os
import uuid

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import DBAPIError, IntegrityError

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"),
    reason="requires a migrated PostgreSQL test database",
)

from umat.auth.security import hash_password  # noqa: E402
from umat.db.models import AuditEvent, Case, Role, User  # noqa: E402
from umat.db.session import session_factory  # noqa: E402


@pytest.mark.asyncio
async def test_audit_rows_reject_update_and_delete() -> None:
    async with session_factory() as db:
        event = await db.scalar(select(AuditEvent).order_by(AuditEvent.sequence).limit(1))
        assert event
        sequence = event.sequence
        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(
                update(AuditEvent)
                .where(AuditEvent.sequence == sequence)
                .values(action="tampered")
            )
            await db.commit()
        await db.rollback()
        with pytest.raises(DBAPIError, match="append-only"):
            await db.execute(delete(AuditEvent).where(AuditEvent.sequence == sequence))
            await db.commit()


@pytest.mark.asyncio
async def test_case_custody_prevents_user_deletion() -> None:
    suffix = uuid.uuid4().hex
    async with session_factory() as db:
        role = await db.scalar(select(Role).where(Role.name == "officer"))
        assert role
        user = User(
            username=f"guard-{suffix}",
            password_hash=hash_password("phase55-database-guard"),
            roles=[role],
        )
        db.add(user)
        await db.flush()
        db.add(Case(owner_user_id=user.id, title="protected custody", reference=suffix))
        await db.commit()
        with pytest.raises(IntegrityError):
            await db.execute(delete(User).where(User.id == user.id))
            await db.commit()
