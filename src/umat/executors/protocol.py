from __future__ import annotations

import hashlib
from typing import Any

from umat.contracts.canonical import canonical_json


class ExecutorStopRequested(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"executor stop requested: {reason}")
        self.reason = reason


def raise_for_stop(response: dict[str, Any]) -> None:
    reason = response.get("stop_requested")
    if reason in {"cancelled", "timeout"}:
        raise ExecutorStopRequested(str(reason))


def signature_message(
    *, method: str, path: str, timestamp: str, nonce: str, idempotency_key: str, body: Any
) -> bytes:
    body_hash = hashlib.sha256(canonical_json(body)).hexdigest()
    return canonical_json(
        {
            "method": method.upper(),
            "path": path,
            "timestamp": timestamp,
            "nonce": nonce,
            "idempotency_key": idempotency_key,
            "body_sha256": body_hash,
        }
    )
