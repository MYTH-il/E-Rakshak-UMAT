"""A missing host artifact must not discard the network evidence with it.

Observed on a Remcos RAT case. The sample was a 726 KB obfuscated batch script;
ETW captured nothing for a cmd.exe based detonation, but WinST/DT still declared
``behavior/trace.etl`` in artifact_paths. Validation required every declared
path to exist, so the bundle was rejected with
``missing WinST/DT artifact: trace_etl``, platform_analysis failed,
c2_analysis never claimed, and the officer received nothing.

The capture was present the whole time and held the RAT's C2 traffic on
TCP 3980. Losing host correlation is a genuine reduction in what can be
concluded and is reported as a caveat. Losing the network evidence as well,
because a different artifact is absent, is a self-inflicted blind spot.

What must stay fatal is unchanged: an absent PCAP, a path escaping the bundle,
and an artifact present but outside the hash manifest.
"""

import hashlib
import json
from pathlib import Path

import pytest

from umat.windows import bundle as bundle_module
from umat.windows.bundle import (
    ESSENTIAL_ARTIFACTS,
    NativeWindowsValidator,
    WindowsBundleError,
    absent_declared_artifacts,
)


@pytest.fixture
def unpinned_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise the artifact loop without the deploy-time pinned schema.

    handoff_manifest.schema.json is installed alongside the WinST/DT reporter at
    deployment, not committed here, so validate() cannot load it in a unit test.
    The digest pin is covered elsewhere; what these tests need is the
    artifact-path handling that follows it.
    """
    monkeypatch.setattr(
        bundle_module, "validate_pinned_native_schema", lambda **kwargs: None
    )


def _bundle(root: Path, artifact_paths: dict[str, str], *, write: set[str]) -> Path:
    """Build a native bundle declaring `artifact_paths`, writing only `write`."""
    (root / "network").mkdir(parents=True, exist_ok=True)
    (root / "behavior").mkdir(parents=True, exist_ok=True)
    contents = {
        "network/capture.pcapng": b"pcap",
        "behavior/trace.etl": b"etl",
        "behavior/access_events.json": b"[]",
    }
    written = []
    for relative, blob in contents.items():
        if relative in write:
            (root / relative).write_bytes(blob)
            written.append(relative)
    (root / "hashes.sha256").write_text(
        "".join(
            f"{hashlib.sha256((root / rel).read_bytes()).hexdigest()}  {rel}\n"
            for rel in written
        )
    )
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "sample_sha256": "a" * 64,
                "cape_task_id": 42,
                "network_mode": "simulated_inetsim",
                "telemetry": {"telemetry_degraded": False},
                "correlation": {"host_network_correlation_enabled": True},
                "artifact_paths": artifact_paths,
            }
        )
    )
    return root


class TestAbsentArtifactDetection:
    def test_declared_but_unwritten_artifacts_are_listed(self, tmp_path: Path) -> None:
        root = _bundle(
            tmp_path,
            {
                "pcap": "network/capture.pcapng",
                "trace_etl": "behavior/trace.etl",
                "access_events": "behavior/access_events.json",
            },
            write={"network/capture.pcapng"},
        )
        handoff = json.loads((root / "manifest.json").read_text())
        assert absent_declared_artifacts(root, handoff) == ["access_events", "trace_etl"]

    def test_essential_artifacts_are_never_reported_as_merely_absent(
        self, tmp_path: Path
    ) -> None:
        """An absent PCAP is a failure, not a caveat, so it must not appear here."""
        root = _bundle(tmp_path, {"pcap": "network/capture.pcapng"}, write=set())
        handoff = json.loads((root / "manifest.json").read_text())
        assert absent_declared_artifacts(root, handoff) == []
        assert "pcap" in ESSENTIAL_ARTIFACTS

    def test_complete_bundle_reports_nothing_absent(self, tmp_path: Path) -> None:
        root = _bundle(
            tmp_path,
            {"pcap": "network/capture.pcapng", "trace_etl": "behavior/trace.etl"},
            write={"network/capture.pcapng", "behavior/trace.etl"},
        )
        handoff = json.loads((root / "manifest.json").read_text())
        assert absent_declared_artifacts(root, handoff) == []


class TestValidationDegradesRatherThanFails:
    def test_the_remcos_case_now_validates(
        self, tmp_path: Path, unpinned_schema: None
    ) -> None:
        """trace_etl declared and not written: the run must proceed."""
        root = _bundle(
            tmp_path,
            {"pcap": "network/capture.pcapng", "trace_etl": "behavior/trace.etl"},
            write={"network/capture.pcapng"},
        )
        handoff = NativeWindowsValidator(tmp_path).validate(root, "a" * 64, 42)
        assert handoff["artifact_paths"]["trace_etl"] == "behavior/trace.etl"


class TestWhatMustStayFatal:
    def test_absent_pcap_still_fails(
        self, tmp_path: Path, unpinned_schema: None
    ) -> None:
        root = _bundle(tmp_path, {"pcap": "network/capture.pcapng"}, write=set())
        with pytest.raises(WindowsBundleError, match="missing WinST/DT artifact: pcap"):
            NativeWindowsValidator(tmp_path).validate(root, "a" * 64, 42)

    def test_path_escaping_the_bundle_still_fails(
        self, tmp_path: Path, unpinned_schema: None
    ) -> None:
        """A manifest pointing outside its own directory is broken or hostile;
        no caveat makes that safe to read."""
        root = _bundle(
            tmp_path,
            {"pcap": "network/capture.pcapng", "trace_etl": "../../etc/passwd"},
            write={"network/capture.pcapng"},
        )
        with pytest.raises(WindowsBundleError, match="escapes the bundle"):
            NativeWindowsValidator(tmp_path).validate(root, "a" * 64, 42)

    def test_present_but_unhashed_artifact_still_fails(
        self, tmp_path: Path, unpinned_schema: None
    ) -> None:
        """An artifact outside the hash manifest has no custody. Degrading here
        would let an unsigned file into a signed bundle.

        _verify_native_hashes runs first and requires the manifest to cover every
        file present, so this is caught there rather than by the per-artifact
        check that follows. Asserted on the message that is actually raised: the
        per-artifact `unhashed` branch is unreachable in practice and kept only
        as defence in depth.
        """
        root = _bundle(
            tmp_path,
            {"pcap": "network/capture.pcapng", "trace_etl": "behavior/trace.etl"},
            write={"network/capture.pcapng"},
        )
        (root / "behavior/trace.etl").write_bytes(b"etl")   # present, not in hashes.sha256
        with pytest.raises(WindowsBundleError, match="does not cover every artifact"):
            NativeWindowsValidator(tmp_path).validate(root, "a" * 64, 42)


class TestCaveatsExplainTheDegradation:
    def test_absent_host_telemetry_raises_a_caveat(self) -> None:
        from umat.windows.bundle import WindowsBundleBuilder

        caveats = WindowsBundleBuilder._caveats(
            {
                "network_mode": "simulated_inetsim",
                "telemetry": {"telemetry_degraded": False},
                "correlation": {"host_network_correlation_enabled": True},
            },
            {"network_mode": "isolated_simulated"},
            ["trace_etl"],
        )
        assert "host_telemetry_degraded" in caveats

    def test_absent_access_events_flags_correlation_unavailable(self) -> None:
        from umat.windows.bundle import WindowsBundleBuilder

        caveats = WindowsBundleBuilder._caveats(
            {
                "network_mode": "simulated_inetsim",
                "telemetry": {"telemetry_degraded": False},
                "correlation": {"host_network_correlation_enabled": True},
            },
            {"network_mode": "isolated_simulated"},
            ["access_events"],
        )
        assert "host_network_correlation_unavailable" in caveats

    def test_caveats_are_unique(self) -> None:
        """windows-import.schema.json sets uniqueItems on caveats, so a repeat
        fails contract validation and takes the whole bundle down. The absent
        artifact codes deliberately overlap with the telemetry and correlation
        flags, so this is reachable."""
        from umat.windows.bundle import WindowsBundleBuilder

        caveats = WindowsBundleBuilder._caveats(
            {
                "network_mode": "simulated_inetsim",
                "telemetry": {"telemetry_degraded": True},
                "correlation": {"host_network_correlation_enabled": False},
            },
            {"network_mode": "isolated_simulated"},
            ["trace_etl", "kernel_etl", "access_events", "clock_sync"],
        )
        assert len(caveats) == len(set(caveats)), caveats

    def test_no_absent_artifacts_leaves_caveats_unchanged(self) -> None:
        from umat.windows.bundle import WindowsBundleBuilder

        baseline = WindowsBundleBuilder._caveats(
            {
                "network_mode": "simulated_inetsim",
                "telemetry": {"telemetry_degraded": False},
                "correlation": {"host_network_correlation_enabled": True},
            },
            {"network_mode": "isolated_simulated"},
        )
        assert baseline == ["network_responses_simulated"]
