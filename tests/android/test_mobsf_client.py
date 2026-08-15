from __future__ import annotations

import httpx

from umat.android.mobsf import MobSFClient


def _client(handler: httpx.MockTransport) -> MobSFClient:
    client = MobSFClient("http://mobsf", "test-key")
    client.client.close()
    client.client = httpx.Client(
        base_url="http://mobsf",
        headers={"Authorization": "test-key"},
        transport=handler,
    )
    return client


def test_instrument_waits_for_api_monitor_hook_readiness() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path.endswith("/instrument"):
            return httpx.Response(200, json={"status": "ok", "message": ""})
        return httpx.Response(
            200,
            json={"data": ["Loaded Frida Script - api_monitor"]},
        )

    result = _client(httpx.MockTransport(handler)).instrument("a" * 32)

    assert result["hook_ready"] is True
    assert calls == ["/api/v1/frida/instrument", "/api/v1/frida/logs"]


def test_api_monitor_treats_missing_data_as_empty_after_hook_startup() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            json={"status": "failed", "message": "Data does not exist."},
        )

    result = _client(httpx.MockTransport(handler)).api_monitor("a" * 32)

    assert result == {"status": "waiting", "data": []}
