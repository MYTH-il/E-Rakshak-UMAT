import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umat.c2.executor import C2Executor, app


@pytest.mark.parametrize("module", ["umat.c2.executor", "umat.executors.fake"])
def test_executor_imports_do_not_load_database_code(module: str) -> None:
    script = (
        f"import sys; import {module}; "
        "assert not [name for name in sys.modules if name.startswith('umat.db')]"
    )
    subprocess.run([sys.executable, "-c", script], check=True)  # noqa: S603


def test_enrolled_c2_executor_republishes_runtime_identity_on_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"credential": "fixture", "executor_id": "fixture"}))
    published: list[str] = []

    monkeypatch.setattr(
        C2Executor,
        "publish_capabilities",
        lambda executor: published.append(executor.runtime.identity),
    )
    monkeypatch.setattr(C2Executor, "process_once", lambda _executor: False)

    result = CliRunner().invoke(
        app,
        [
            "run",
            "--fixture-runtime",
            "--state-path",
            str(state),
            "--work-root",
            str(tmp_path / "work"),
            "--once",
        ],
    )

    assert result.exit_code == 0, result.output
    assert published == ["c2-fixture@1.3"]
