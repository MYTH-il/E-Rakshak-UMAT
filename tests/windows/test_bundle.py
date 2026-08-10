import json
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from umat.windows.bundle import (
    NativeWindowsValidator,
    WindowsBundleBuilder,
    WindowsBundleError,
    safe_extract_windows_bundle,
    verify_windows_bundle,
)
from umat.windows.schemas import CreateWindowsProfileRequest


class FixtureNativeValidator:
    def validate(self, root: Path, sample_sha256: str, cape_task_id: int) -> dict:
        manifest = json.loads((root / "manifest.json").read_text())
        assert manifest["sample_sha256"] == sample_sha256
        assert manifest["cape_task_id"] == cape_task_id
        return manifest


def native_bundle(root: Path) -> Path:
    (root / "network").mkdir(parents=True)
    (root / "behavior").mkdir()
    manifest = {
        "schema_version": "1.0",
        "sample_sha256": "a" * 64,
        "cape_task_id": 42,
        "network_mode": "simulated_inetsim",
        "telemetry": {"telemetry_degraded": False},
        "correlation": {"host_network_correlation_enabled": True},
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    (root / "network/capture.pcapng").write_bytes(b"pcap")
    (root / "behavior/trace.etl").write_bytes(b"etl")
    (root / "report.json").write_text('{"signatures":[]}')
    import hashlib

    paths = [root / "network/capture.pcapng", root / "behavior/trace.etl", root / "report.json"]
    (root / "hashes.sha256").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n"
            for path in paths
        )
    )
    return root


def test_windows_bundle_signature_identity_and_tamper_detection(tmp_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    validator = FixtureNativeValidator()
    built = WindowsBundleBuilder(private, "executor-1", validator).build(  # type: ignore[arg-type]
        analysis_run_id=UUID("0198fd40-1111-7000-8000-000000000001"),
        sample_sha256="a" * 64,
        cape_task_id=42,
        cape_package="generic",
        detected_type="PE32 executable",
        profile_snapshot={"name": "standard-win10", "vcpus": 4},
        native_root=native_bundle(tmp_path / "native-source"),
        destination=tmp_path / "result",
        cape_evidence={"schema_version": "1.0", "malscore": 9.5, "signatures": []},
    )
    extracted = safe_extract_windows_bundle(built.archive_path, tmp_path / "extracted", 10_000_000)
    manifest = verify_windows_bundle(extracted, private.public_key(), validator)  # type: ignore[arg-type]
    assert manifest["cape"]["task_id"] == 42
    assert manifest["selected_profile"]["name"] == "standard-win10"
    assert json.loads((extracted / "cape-evidence.json").read_text())["malscore"] == 9.5
    (extracted / "native/report.json").write_text('{"tampered":true}')
    with pytest.raises(WindowsBundleError, match="artifact mismatch"):
        verify_windows_bundle(extracted, private.public_key(), validator)  # type: ignore[arg-type]


def test_windows_profile_resource_bounds() -> None:
    valid = {
        "name": "win10-office",
        "display_name": "Windows 10 Office",
        "windows_version": "Windows 10 22H2",
        "vcpus": 4,
        "ram_mb": 8192,
        "disk_gb": 100,
        "user_profile": {"username": "analyst"},
        "cape_template": "win10-base",
    }
    assert CreateWindowsProfileRequest.model_validate(valid).analysis_profile == "standard"
    with pytest.raises(ValueError):
        CreateWindowsProfileRequest.model_validate(valid | {"vcpus": 0})
    with pytest.raises(ValueError):
        CreateWindowsProfileRequest.model_validate(valid | {"architecture": "x86"})


def test_windows_executor_import_does_not_load_database_code() -> None:
    import subprocess
    import sys

    script = "import sys; import umat.windows.executor; assert not [n for n in sys.modules if n.startswith('umat.db')]"
    subprocess.run([sys.executable, "-c", script], check=True)  # noqa: S603


def test_native_hash_manifest_must_cover_every_artifact(tmp_path: Path) -> None:
    import hashlib

    (tmp_path / "covered.bin").write_bytes(b"covered")
    (tmp_path / "uncovered.bin").write_bytes(b"uncovered")
    digest = hashlib.sha256(b"covered").hexdigest()
    (tmp_path / "hashes.sha256").write_text(f"{digest}  covered.bin\n")
    with pytest.raises(WindowsBundleError, match="does not cover every artifact"):
        NativeWindowsValidator._verify_native_hashes(tmp_path)
