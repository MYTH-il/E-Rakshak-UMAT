from __future__ import annotations

from typing import Any

from umat.windows.cape import CapeError
from umat.windows.executor import WindowsExecutor


class Response:
    def __init__(self, value: dict[str, Any] | None = None) -> None:
        self.value = value or {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.value


class Cape:
    def __init__(self) -> None:
        self.statuses = [
            {"status": "running"},
            {"status": "running"},
            {"status": "reported"},
        ]
        self.console_attempts = 0
        self.cancelled: list[int] = []

    def status(self, task_id: int) -> dict[str, Any]:
        assert task_id == 42
        return self.statuses.pop(0)

    def open_console(self, task_id: int, machine_label: str) -> dict[str, Any]:
        assert (task_id, machine_label) == (42, "umat-office-1234abcd")
        self.console_attempts += 1
        if self.console_attempts == 1:
            raise CapeError("display is not ready")
        return {"console_url": "ws://127.0.0.1:8091/api/v1/console/token"}

    def task_machine(self, task_id: int) -> str:
        return "umat-office-1234abcd"

    def cancel(self, task_id: int) -> None:
        self.cancelled.append(task_id)


def executor(cape: Cape, finalize: bool = False) -> WindowsExecutor:
    instance = object.__new__(WindowsExecutor)
    instance.cape = cape  # type: ignore[assignment]
    instance.egress = None

    def mutate(path: str, body: dict[str, Any], lease: str) -> Response:
        assert lease == "lease-token"
        if path.endswith("/heartbeat"):
            return Response()
        if path.endswith("/windows-session/ready"):
            assert body["cape_task_id"] == 42
            assert body["duration_seconds"] == 600
            return Response()
        if path.endswith("/windows-session/poll"):
            return Response({"finalize": finalize})
        raise AssertionError(path)

    instance.mutate = mutate  # type: ignore[method-assign]
    return instance


def claim() -> dict[str, Any]:
    return {
        "stage_id": "stage",
        "analysis_run_id": "run",
        "lease_token": "lease-token",
        "execution_configuration": {
            "cape_machine_label": "umat-office-1234abcd",
            "network_mode": "isolated_simulated",
            "windows_interactive": True,
        },
    }


def test_console_startup_is_retried_without_failing_cape_analysis(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("umat.windows.executor.time.sleep", lambda _seconds: None)
    cape = Cape()
    result = executor(cape)._wait(
        claim(), {"lease_id": "lease", "attempt_id": "attempt"}, 42, 0
    )
    assert result["status"] == "reported"
    assert cape.console_attempts == 2
    assert cape.cancelled == []


def test_finish_instruction_ends_cape_window_without_cancelling_umat_run(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("umat.windows.executor.time.sleep", lambda _seconds: None)
    cape = Cape()
    cape.console_attempts = 1
    cape.statuses = [{"status": "running"}, {"status": "reported"}]
    result = executor(cape, finalize=True)._wait(
        claim(), {"lease_id": "lease", "attempt_id": "attempt"}, 42, 0
    )
    assert result["status"] == "reported"
    assert cape.cancelled == [42]


def test_automated_analysis_never_opens_or_polls_manual_console(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr("umat.windows.executor.time.sleep", lambda _seconds: None)
    cape = Cape()
    automated_claim = claim()
    automated_claim["execution_configuration"]["windows_interactive"] = False
    result = executor(cape)._wait(
        automated_claim, {"lease_id": "lease", "attempt_id": "attempt"}, 42, 0
    )
    assert result["status"] == "reported"
    assert cape.console_attempts == 0
    assert cape.cancelled == []
