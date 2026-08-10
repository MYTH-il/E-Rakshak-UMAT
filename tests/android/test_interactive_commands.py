from __future__ import annotations

import pytest
from fastapi import HTTPException

from umat.android.executor import AndroidExecutor
from umat.android.workflow_routes import _validate_command


def test_interactive_command_validation_normalizes_safe_inputs() -> None:
    assert _validate_command("tap", {"x": "120", "y": 300}) == {"x": 120, "y": 300}
    assert _validate_command("activity_test", {"test": "exported"}) == {
        "test": "exported"
    }
    assert _validate_command("proxy", {"action": "set"}) == {"action": "set"}
    assert _validate_command("text", {"text": "x" * 3000}) == {"text": "x" * 2000}


@pytest.mark.parametrize(
    ("command", "payload"),
    [
        ("shell", {"command": "id"}),
        ("tap", {"x": -1, "y": 10}),
        ("activity_test", {"test": "arbitrary"}),
        ("root_ca", {"action": "replace"}),
        ("frida", {"action": "shell"}),
    ],
)
def test_interactive_command_validation_rejects_unallowlisted_operations(
    command: str, payload: dict[str, object]
) -> None:
    with pytest.raises(HTTPException):
        _validate_command(command, payload)


def test_exported_activity_test_normalizes_empty_static_result() -> None:
    executor = object.__new__(AndroidExecutor)
    result = executor._execute_interactive_command(  # noqa: SLF001
        None,  # type: ignore[arg-type]
        "a" * 32,
        "com.example.test",
        {"exported_count": {"exported_activities": 0}, "exported_activities": "[]"},
        "activity_test",
        {"test": "exported"},
    )
    assert result == {
        "status": "ok",
        "activities_tested": 0,
        "message": "No exported activities were identified in the APK.",
    }
