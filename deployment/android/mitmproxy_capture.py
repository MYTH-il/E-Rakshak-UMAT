"""Write a bounded JSONL audit trail alongside mitmproxy's native flow archive."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from mitmproxy import http

OUTPUT = Path("/evidence/events.jsonl")
MAX_BODY = 4096


def _write(event: dict[str, object]) -> None:
    event["observed_at"] = datetime.now(timezone.utc).isoformat()
    with OUTPUT.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")


def request(flow: http.HTTPFlow) -> None:
    request = flow.request
    _write(
        {
            "event": "request",
            "method": request.method,
            "scheme": request.scheme,
            "host": request.pretty_host,
            "port": request.port,
            "path": request.path[:MAX_BODY],
            "http_version": request.http_version,
        }
    )


def response(flow: http.HTTPFlow) -> None:
    response = flow.response
    _write(
        {
            "event": "response",
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", "")[:256],
            "body_size": len(response.raw_content or b""),
        }
    )


def error(flow: http.HTTPFlow) -> None:
    _write(
        {
            "event": "error",
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "message": str(flow.error)[:1000],
        }
    )
