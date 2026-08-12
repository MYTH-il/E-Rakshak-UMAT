from __future__ import annotations

import threading
import time
from collections import Counter


class Metrics:
    """Small dependency-free process metrics registry.

    Labels are deliberately fixed and bounded; never pass case, run, user, or request IDs here.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Counter[tuple[str, str]] = Counter()
        self._duration_seconds = 0.0
        self._started = time.monotonic()

    def observe_request(self, method: str, status_code: int, duration_seconds: float) -> None:
        status_class = f"{status_code // 100}xx"
        with self._lock:
            self._requests[(method, status_class)] += 1
            self._duration_seconds += duration_seconds

    @staticmethod
    def _line(name: str, value: int | float, labels: str = "") -> str:
        suffix = f"{{{labels}}}" if labels else ""
        return f"{name}{suffix} {value}"

    def render(self) -> str:
        with self._lock:
            requests = self._requests.copy()
            duration = self._duration_seconds
        lines = [
            "# HELP umat_process_uptime_seconds Process uptime.",
            "# TYPE umat_process_uptime_seconds gauge",
            self._line("umat_process_uptime_seconds", round(time.monotonic() - self._started, 3)),
            "# HELP umat_http_requests_total HTTP requests by method and status class.",
            "# TYPE umat_http_requests_total counter",
        ]
        for (method, status_class), count in sorted(requests.items()):
            labels = f'method="{method}",status_class="{status_class}"'
            lines.append(self._line("umat_http_requests_total", count, labels))
        lines.extend(
            [
                "# HELP umat_http_request_duration_seconds_sum Total HTTP request duration.",
                "# TYPE umat_http_request_duration_seconds_sum counter",
                self._line("umat_http_request_duration_seconds_sum", round(duration, 6)),
            ]
        )
        return "\n".join(lines) + "\n"


metrics = Metrics()
