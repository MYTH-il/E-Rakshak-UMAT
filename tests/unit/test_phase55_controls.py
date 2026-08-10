import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from umat.c2.models import C2AnalysisContext, InputArtifact
from umat.c2.runtime import C2RuntimeError, SubprocessC2Runtime
from umat.config.settings import Settings
from umat.executors.protocol import ExecutorStopRequested, raise_for_stop

ROOT = Path(__file__).parents[2]


def test_per_stage_policy_overrides_defaults(tmp_path: Path) -> None:
    settings = Settings(
        quarantine_root=tmp_path / "quarantine",
        artifact_root=tmp_path / "artifacts",
        default_stage_max_attempts=3,
        default_stage_timeout_seconds=1800,
        stage_max_attempts={"platform_analysis": 2},
        stage_timeout_seconds={"platform_analysis": 900},
    )
    assert settings.policy_for_stage("platform_analysis") == (2, 900)
    assert settings.policy_for_stage("c2_analysis") == (3, 1800)


def test_invalid_per_stage_policy_fails_startup(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="must be positive"):
        Settings(
            quarantine_root=tmp_path / "quarantine",
            artifact_root=tmp_path / "artifacts",
            stage_timeout_seconds={"platform_analysis": 0},
        )


@pytest.mark.parametrize("reason", ["cancelled", "timeout"])
def test_executor_stop_signal_is_fail_closed(reason: str) -> None:
    with pytest.raises(ExecutorStopRequested, match=reason):
        raise_for_stop({"stop_requested": reason})


def test_third_party_inventory_keeps_unlicensed_c2_out_of_distribution() -> None:
    inventory = json.loads(
        (ROOT / "dependency-locks/third-party-inventory.json").read_text()
    )
    components = {item["name"]: item for item in inventory["components"]}
    windows = components["WinST/DT module"]
    c2 = components["C2 Exfil analyzer"]
    assert windows["license"] is None
    assert windows["redistribution_allowed"] is False
    assert c2["license"] is None
    assert c2["redistribution_allowed"] is False
    assert "authorization" in c2["runtime_status"]


def test_packaged_c2_runtime_requires_locked_patch_digest(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    (runtime / "source/pipeline").mkdir(parents=True)
    (runtime / "source/pipeline/orchestrator.py").write_text("# fixture\n")
    tree_digest = SubprocessC2Runtime._tree_hash(runtime / "source")
    (runtime / "runtime-manifest.json").write_text(
        json.dumps(
            {
                "upstream_commit": "a" * 40,
                "effective_version": "fixture.1",
                "patch_series_sha256": "b" * 64,
                "effective_tree_sha256": tree_digest,
                "dependency_lock_sha256": "d" * 64,
            }
        )
    )
    verified = SubprocessC2Runtime(runtime, "a" * 40, 60, "b" * 64)
    assert verified.identity == "c2-exfil@fixture.1"
    with pytest.raises(C2RuntimeError, match="patch-series"):
        SubprocessC2Runtime(runtime, "a" * 40, 60, "e" * 64)


def test_c2_runtime_drains_verbose_child_output(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    pipeline = runtime / "source/pipeline"
    pipeline.mkdir(parents=True)
    runtime_data = runtime / "source/data"
    runtime_data.mkdir()
    runtime_data.chmod(0o555)
    (pipeline / "orchestrator.py").write_text(
        """import json
from pathlib import Path
print('x' * 200000)
Path('data/runtime.sqlite').write_bytes(b'runtime-state')
output = Path('output')
output.mkdir()
(output / 'exfil_events.json').write_text('[]')
"""
    )
    tree_digest = SubprocessC2Runtime._tree_hash(runtime / "source")
    (runtime / "runtime-manifest.json").write_text(
        json.dumps(
            {
                "upstream_commit": "a" * 40,
                "effective_version": "fixture.1",
                "patch_series_sha256": "b" * 64,
                "effective_tree_sha256": tree_digest,
                "dependency_lock_sha256": "d" * 64,
            }
        )
    )
    pcap = tmp_path / "input.pcap"
    manifest = tmp_path / "manifest.json"
    pcap.write_bytes(b"pcap")
    manifest.write_text("{}")

    def input_artifact(path: Path, kind: str) -> InputArtifact:
        content = path.read_bytes()
        return InputArtifact(
            artifact_id=uuid4(),
            kind=kind,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            media_type="application/json",
            source_stage_type="platform_analysis",
            local_path=path,
        )

    now = datetime.now(timezone.utc)
    context = C2AnalysisContext(
        analysis_run_id=uuid4(),
        platform="windows",
        sample_sha256="a" * 64,
        pcap=input_artifact(pcap, "pcap"),
        platform_manifest=input_artifact(manifest, "platform_manifest"),
        analysis_started_at=now,
        analysis_ended_at=now,
    )
    result = SubprocessC2Runtime(runtime, "a" * 40, 5, "b" * 64).run(
        context, tmp_path / "work"
    )
    assert result.events == []


def test_current_c2_runtime_normalizes_modern_static_prior(tmp_path: Path) -> None:
    source = tmp_path / "native-static-prior.json"
    source.write_text(
        json.dumps(
            {
                "sample_sha256": "incorrect-native-value",
                "family_attribution": {
                    "family": "RubyJumper",
                    "evidence": [{"source": "cape"}],
                },
                "capa_capabilities": ["T1059"],
                "iocs": [{"type": "domain", "value": "fixture.invalid"}],
            }
        )
    )
    artifact = InputArtifact(
        artifact_id=uuid4(),
        kind="static_prior",
        sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        size_bytes=source.stat().st_size,
        media_type="application/json",
        source_stage_type="platform_analysis",
        local_path=source,
    )
    context = C2AnalysisContext.model_construct(
        sample_sha256="a" * 64,
        static_prior=artifact,
    )
    normalized_path = SubprocessC2Runtime._prepare_static_prior(
        context, tmp_path
    )
    normalized = json.loads(normalized_path.read_text())
    assert normalized == {
        "sample_sha256": "a" * 64,
        "family": "RubyJumper",
        "capabilities": ["T1059"],
        "c2_indicators": [{"type": "domain", "value": "fixture.invalid"}],
    }
