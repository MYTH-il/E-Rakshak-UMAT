import subprocess
import sys

import pytest


@pytest.mark.parametrize("module", ["umat.c2.executor", "umat.executors.fake"])
def test_executor_imports_do_not_load_database_code(module: str) -> None:
    script = (
        f"import sys; import {module}; "
        "assert not [name for name in sys.modules if name.startswith('umat.db')]"
    )
    subprocess.run([sys.executable, "-c", script], check=True)  # noqa: S603
