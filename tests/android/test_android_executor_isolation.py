from __future__ import annotations

import subprocess
import sys


def test_android_executor_does_not_import_database_modules() -> None:
    code = (
        "import sys; import umat.android.executor; "
        "assert not any(name == 'umat.db' or name.startswith('umat.db.') for name in sys.modules)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)  # noqa: S603
