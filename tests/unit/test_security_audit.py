import base64
from datetime import datetime, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException
from starlette.requests import Request

from umat.audit.chain import ZERO_HASH, calculate_event_hash, canonical_json
from umat.auth.security import hash_password, normalize_username, token_hash, verify_password
from umat.db.models import Executor
from umat.executors.security import signature_message, verify_executor_signature


def test_password_and_token_security() -> None:
    encoded = hash_password("correct horse battery staple")
    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, "correct horse battery staple")
    assert not verify_password(encoded, "wrong")
    assert normalize_username(" Admin ") == "admin"
    assert len(token_hash("secret")) == 64


def test_canonical_audit_hash_is_deterministic() -> None:
    left = calculate_event_hash(ZERO_HASH, {"b": 2, "a": 1})
    right = calculate_event_hash(ZERO_HASH, {"a": 1, "b": 2})
    assert left == right
    assert canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'


def test_executor_signature_verification() -> None:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    executor = Executor(name="fixture", executor_type="fake", public_key=public)
    request = Request({"type": "http", "method": "POST", "path": "/stage", "headers": [], "query_string": b"", "server": ("test", 80), "scheme": "http"})
    body = {"lease_id": "fixture"}
    timestamp = datetime.now(timezone.utc).isoformat()
    message = signature_message(method="POST", path="/stage", timestamp=timestamp, nonce="n", idempotency_key="k", body=body)
    signature = base64.b64encode(private.sign(message)).decode()
    assert verify_executor_signature(executor, request, body, timestamp, "n", "k", signature)
    with pytest.raises(HTTPException):
        verify_executor_signature(executor, request, {"changed": True}, timestamp, "n", "k", signature)
