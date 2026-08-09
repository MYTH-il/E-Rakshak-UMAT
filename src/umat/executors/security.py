from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from umat.auth.security import token_hash
from umat.db import get_db
from umat.db.models import Executor, ExecutorCredential, ExecutorStatus
from umat.executors.protocol import signature_message


async def current_executor(
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Executor:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "executor credential required")
    credential = await db.scalar(
        select(ExecutorCredential).where(ExecutorCredential.token_hash == token_hash(authorization[7:]))
    )
    now = datetime.now(timezone.utc)
    if not credential or credential.revoked_at or (credential.expires_at and credential.expires_at <= now):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid executor credential")
    executor = await db.get(Executor, credential.executor_id)
    if not executor or executor.status != ExecutorStatus.ACTIVE:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "executor disabled")
    return executor


def verify_executor_signature(
    executor: Executor,
    request: Request,
    body: Any,
    timestamp: str,
    nonce: str,
    idempotency_key: str,
    signature: str,
) -> str:
    try:
        observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if observed.tzinfo is None or abs(datetime.now(timezone.utc) - observed) > timedelta(minutes=5):
            raise ValueError("timestamp outside accepted window")
        decoded = base64.b64decode(signature, validate=True)
        message = signature_message(method=request.method, path=request.url.path, timestamp=timestamp, nonce=nonce, idempotency_key=idempotency_key, body=body)
        Ed25519PublicKey.from_public_bytes(executor.public_key).verify(decoded, message)
        import hashlib

        return hashlib.sha256(message).hexdigest()
    except (ValueError, InvalidSignature) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid executor signature") from exc
