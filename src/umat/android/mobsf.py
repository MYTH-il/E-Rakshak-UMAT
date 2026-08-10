from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import httpx


class MobSFClient:
    """Client for the API surface pinned at the Android dependency-lock commit."""

    def __init__(self, base_url: str, api_key: str, timeout_seconds: float = 300) -> None:
        self.client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": api_key},
            timeout=timeout_seconds,
        )

    def _post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        response = self.client.post(path, data=data)
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise RuntimeError(f"MobSF returned a non-object from {path}")
        if value.get("error"):
            raise RuntimeError(f"MobSF {path} failed: {value['error']}")
        return cast(dict[str, Any], value)

    def upload(self, apk: Path) -> dict[str, Any]:
        with apk.open("rb") as source:
            response = self.client.post(
                "/api/v1/upload", files={"file": ("sample.apk", source, "application/vnd.android.package-archive")}
            )
        response.raise_for_status()
        value = response.json()
        return cast(dict[str, Any], value)

    def scan(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/scan", {"hash": scan_hash})

    def static_report(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/report_json", {"hash": scan_hash})

    def scan_logs(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/scan_logs", {"hash": scan_hash})

    def wait_static_report(
        self,
        scan_hash: str,
        *,
        timeout_seconds: int = 3600,
        poll_seconds: float = 5,
        check_stop: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        return self._wait_report(
            self.static_report, scan_hash, timeout_seconds, poll_seconds, check_stop
        )

    def start_dynamic(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/dynamic/start_analysis", {"hash": scan_hash})

    def start_activity(self, scan_hash: str, activity: str) -> dict[str, Any]:
        return self._post("/api/v1/android/start_activity", {"hash": scan_hash, "activity": activity})

    def instrument(self, scan_hash: str) -> dict[str, Any]:
        return self._post(
            "/api/v1/frida/instrument",
            {"hash": scan_hash, "default_hooks": "api_monitor", "auxiliary_hooks": "", "frida_code": ""},
        )

    def stop_dynamic(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/dynamic/stop_analysis", {"hash": scan_hash})

    def dynamic_report(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/dynamic/report_json", {"hash": scan_hash})

    def wait_dynamic_report(
        self,
        scan_hash: str,
        *,
        timeout_seconds: int = 600,
        poll_seconds: float = 5,
        check_stop: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        return self._wait_report(
            self.dynamic_report, scan_hash, timeout_seconds, poll_seconds, check_stop
        )

    def api_monitor(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/frida/api_monitor", {"hash": scan_hash})

    def frida_logs(self, scan_hash: str) -> dict[str, Any]:
        return self._post("/api/v1/frida/logs", {"hash": scan_hash})

    def android_operation(
        self, path: str, scan_hash: str, data: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        allowed = {
            "activity": "/api/v1/android/activity",
            "root_ca": "/api/v1/android/root_ca",
            "global_proxy": "/api/v1/android/global_proxy",
            "tls_tests": "/api/v1/android/tls_tests",
            "frida": "/api/v1/frida/instrument",
            "dependencies": "/api/v1/frida/get_dependencies",
        }
        endpoint = allowed.get(path)
        if endpoint is None:
            raise ValueError("unsupported MobSF Android operation")
        return self._post(endpoint, {"hash": scan_hash, **(data or {})})

    @staticmethod
    def _wait_report(
        getter: Any,
        scan_hash: str,
        timeout_seconds: int,
        poll_seconds: float,
        check_stop: Callable[[], None] | None,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if check_stop:
                check_stop()
            try:
                return cast(dict[str, Any], getter(scan_hash))
            except (httpx.HTTPStatusError, RuntimeError) as exc:
                last_error = exc
                time.sleep(poll_seconds)
        raise RuntimeError("MobSF report did not become available before timeout") from last_error
