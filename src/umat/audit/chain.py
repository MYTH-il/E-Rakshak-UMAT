from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from umat.contracts.canonical import canonical_json
from umat.db.models import AuditEvent

ZERO_HASH = "0" * 64


def calculate_event_hash(previous_hash: str, fields: dict[str, Any]) -> str:
    return hashlib.sha256(previous_hash.encode("ascii") + canonical_json(fields)).hexdigest()


async def append_audit(
    db: AsyncSession,
    *,
    actor_type: str,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id: str | None,
    payload: dict[str, Any] | None = None,
) -> AuditEvent:
    if db.bind and db.bind.dialect.name == "postgresql":
        await db.execute(text("SELECT pg_advisory_xact_lock(8675309)"))
    previous = await db.scalar(select(AuditEvent).order_by(AuditEvent.sequence.desc()).limit(1))
    previous_hash = previous.event_hash if previous else ZERO_HASH
    created_at = datetime.now(timezone.utc)
    fields = {
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "payload": payload or {},
        "created_at": created_at.isoformat(),
    }
    event = AuditEvent(
        actor_type=actor_type,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        payload=payload or {},
        previous_hash=previous_hash,
        event_hash=calculate_event_hash(previous_hash, fields),
        created_at=created_at,
    )
    db.add(event)
    await db.flush()
    return event


async def verify_audit_chain(db: AsyncSession) -> tuple[bool, int | None]:
    events = list((await db.scalars(select(AuditEvent).order_by(AuditEvent.sequence))).all())
    previous_hash = ZERO_HASH
    for event in events:
        fields = {
            "actor_type": event.actor_type,
            "actor_id": event.actor_id,
            "action": event.action,
            "target_type": event.target_type,
            "target_id": event.target_id,
            "payload": event.payload,
            "created_at": event.created_at.isoformat(),
        }
        if event.previous_hash != previous_hash or event.event_hash != calculate_event_hash(
            previous_hash, fields
        ):
            return False, event.sequence
        previous_hash = event.event_hash
    return True, None
