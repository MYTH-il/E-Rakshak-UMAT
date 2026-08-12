import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umat.c2.executor import C2Executor, C2ExecutorError, app


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


def test_c2_external_data_preflight_checks_real_sqlite_write_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    city = tmp_path / "city.mmdb"
    asn = tmp_path / "asn.mmdb"
    city.write_bytes(b"city-fixture-data")
    asn.write_bytes(b"asn-fixture-data-")
    database = tmp_path / "threatintel.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE bad_indicators (value TEXT PRIMARY KEY, source TEXT, note TEXT)"
        )
    monkeypatch.setenv("GEOLITE2_CITY_DB", str(city))
    monkeypatch.setenv("GEOLITE2_ASN_DB", str(asn))
    monkeypatch.setenv("THREATINTEL_DB", str(database))

    checked = C2Executor.preflight_external_data()

    assert checked == {
        "GEOLITE2_CITY_DB": str(city),
        "GEOLITE2_ASN_DB": str(asn),
        "THREATINTEL_DB": str(database),
    }


def test_c2_external_data_preflight_rejects_invalid_threatintel_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "threatintel.sqlite"
    database.touch()
    monkeypatch.delenv("GEOLITE2_CITY_DB", raising=False)
    monkeypatch.delenv("GEOLITE2_ASN_DB", raising=False)
    monkeypatch.setenv("THREATINTEL_DB", str(database))

    with pytest.raises(C2ExecutorError, match="lacks bad_indicators"):
        C2Executor.preflight_external_data()
