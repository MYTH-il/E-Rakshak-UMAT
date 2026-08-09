import json
from pathlib import Path

import pytest

from umat.deployment.cli import (
    CommandRunner,
    DeploymentError,
    load_manifest,
    selected_components,
)

ROOT = Path(__file__).parents[2]


def test_full_stack_manifest_matches_dependency_locks() -> None:
    manifest = load_manifest()
    winstdt = json.loads((ROOT / "dependency-locks/winstdt.json").read_text())
    android = json.loads((ROOT / "dependency-locks/android-erakshak.json").read_text())
    c2 = json.loads((ROOT / "dependency-locks/c2-exfil.json").read_text())
    components = manifest["components"]
    assert components["winstdt"]["commit"] == winstdt["commit"]
    assert components["cape"]["commit"] == winstdt["cape"]["commit"]
    assert components["android"]["commit"] == android["commit"]
    assert components["c2"]["commit"] == c2["commit"]
    assert components["c2"]["patch_series_sha256"] == c2["patch_series_sha256"]


def test_dry_run_never_executes_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess execution was attempted")

    monkeypatch.setattr("subprocess.run", forbidden)
    CommandRunner(execute=False).run(["definitely-not-an-executable"])


def test_component_selection_fails_closed() -> None:
    assert selected_components([]) == {"control-plane", "windows", "android", "services"}
    with pytest.raises(DeploymentError, match="unknown deployment components"):
        selected_components(["unknown"])


def test_control_plane_compose_requires_external_password() -> None:
    compose = (ROOT / "deployment/single-host/compose.yaml").read_text()
    assert "UMAT_POSTGRES_PASSWORD:?" in compose
    assert "POSTGRES_PASSWORD: umat" not in compose
