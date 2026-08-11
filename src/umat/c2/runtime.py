from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from umat.c2.models import C2AnalysisContext, NativeC2Result
from umat.executors.protocol import ExecutorStopRequested


class C2RuntimeError(RuntimeError):
    pass


class C2Runtime(Protocol):
    @property
    def identity(self) -> str: ...

    def run(
        self,
        context: C2AnalysisContext,
        work_root: Path,
        stop_requested: threading.Event | None = None,
        stop_reason: Callable[[], str] | None = None,
    ) -> NativeC2Result: ...


class SubprocessC2Runtime:
    _OUTPUT_TAIL_BYTES = 64 * 1024

    def __init__(
        self,
        runtime_root: Path,
        expected_commit: str,
        timeout_seconds: int,
        expected_patch_sha256: str | None = None,
    ) -> None:
        self.runtime_root = runtime_root.resolve()
        packaged_source = self.runtime_root / "source"
        self.source_root = (
            packaged_source
            if (packaged_source / "pipeline/orchestrator.py").is_file()
            else self.runtime_root
        )
        self.expected_commit = expected_commit
        self.expected_patch_sha256 = expected_patch_sha256
        self.timeout_seconds = timeout_seconds
        self.effective_version = expected_commit
        self._verify_runtime()

    @property
    def identity(self) -> str:
        return f"c2-exfil@{self.effective_version}"

    def _verify_runtime(self) -> None:
        orchestrator = self.source_root / "pipeline/orchestrator.py"
        if not orchestrator.is_file():
            raise C2RuntimeError("C2 runtime has no pipeline/orchestrator.py")
        marker = self.runtime_root / ".umat-runtime.json"
        runtime_manifest = self.runtime_root / "runtime-manifest.json"
        observed: str | None = None
        if runtime_manifest.is_file():
            manifest = json.loads(runtime_manifest.read_text())
            observed = str(manifest.get("upstream_commit"))
            self.effective_version = str(manifest.get("effective_version") or observed)
            if (
                self.expected_patch_sha256
                and manifest.get("patch_series_sha256") != self.expected_patch_sha256
            ):
                raise C2RuntimeError("C2 runtime patch-series digest mismatch")
            if not manifest.get("effective_tree_sha256") or not manifest.get(
                "dependency_lock_sha256"
            ):
                raise C2RuntimeError("C2 runtime manifest is incomplete")
            if self._tree_hash(self.source_root) != manifest["effective_tree_sha256"]:
                raise C2RuntimeError("C2 effective runtime tree digest mismatch")
        elif (self.runtime_root / ".git").exists():
            git = shutil.which("git")
            if not git:
                raise C2RuntimeError("git is required to verify the C2 runtime")
            result = subprocess.run(  # noqa: S603 - fixed executable and arguments
                [git, "-C", str(self.runtime_root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            observed = result.stdout.strip()
        elif marker.is_file():
            observed = str(json.loads(marker.read_text()).get("commit"))
        if observed != self.expected_commit:
            raise C2RuntimeError(
                f"C2 runtime commit mismatch: expected {self.expected_commit}, observed {observed}"
            )

    @staticmethod
    def _tree_hash(root: Path) -> str:
        lines: list[str] = []
        for path in sorted(root.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or ".pytest_cache" in path.parts:
                continue
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {path.relative_to(root)}\n")
        return hashlib.sha256("".join(lines).encode()).hexdigest()

    def run(
        self,
        context: C2AnalysisContext,
        work_root: Path,
        stop_requested: threading.Event | None = None,
        stop_reason: Callable[[], str] | None = None,
    ) -> NativeC2Result:
        work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        workspace = Path(
            tempfile.mkdtemp(prefix=f"{context.analysis_run_id}-", dir=work_root)
        ).resolve()
        runtime_data = self.source_root / "data"
        if runtime_data.is_dir():
            workspace_data = workspace / "data"
            shutil.copytree(runtime_data, workspace_data)
            for directory in [workspace_data, *workspace_data.rglob("*")]:
                if directory.is_dir():
                    directory.chmod(directory.stat().st_mode | 0o700)
                elif directory.is_file():
                    directory.chmod(directory.stat().st_mode | 0o600)
        if context.platform == "android":
            command = [
                sys.executable,
                str(Path(__file__).with_name("network_only_runtime.py")),
                str(context.pcap.local_path),
                "--sample-sha256",
                context.sample_sha256,
            ]
        else:
            command = [
                sys.executable,
                str(self.source_root / "pipeline/orchestrator.py"),
                str(context.pcap.local_path),
                "--case-id",
                str(context.analysis_run_id),
            ]
        if context.platform == "windows" and context.access_events:
            command.append(str(context.access_events.local_path))
        if context.static_prior:
            static_prior = self._prepare_static_prior(context, workspace)
            command.extend(["--static-prior", str(static_prior)])
        if context.platform == "windows":
            handoff = self._prepare_handoff(context, workspace)
            if handoff:
                command.extend(["--handoff", str(handoff)])
        environment = os.environ.copy()
        environment.pop("DATABASE_URL", None)
        environment["PYTHONPATH"] = str(self.source_root / "pipeline")
        runtime_python = self.runtime_root / ".venv/bin/python"
        command[0] = str(runtime_python) if runtime_python.is_file() else sys.executable
        process = subprocess.Popen(  # noqa: S603 - exact pinned local runtime entry point
            command,
            cwd=workspace,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout_tail = bytearray()
        stderr_tail = bytearray()

        def drain(stream: Any, tail: bytearray) -> None:
            try:
                while chunk := stream.read(8192):
                    tail.extend(chunk)
                    if len(tail) > self._OUTPUT_TAIL_BYTES:
                        del tail[: -self._OUTPUT_TAIL_BYTES]
            finally:
                stream.close()

        drainers = [
            threading.Thread(
                target=drain,
                args=(process.stdout, stdout_tail),
                daemon=True,
                name="c2-stdout-drain",
            ),
            threading.Thread(
                target=drain,
                args=(process.stderr, stderr_tail),
                daemon=True,
                name="c2-stderr-drain",
            ),
        ]
        for drainer in drainers:
            drainer.start()
        deadline = time.monotonic() + self.timeout_seconds
        while process.poll() is None:
            if stop_requested and stop_requested.is_set():
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                raise ExecutorStopRequested(stop_reason() if stop_reason else "cancelled")
            if time.monotonic() >= deadline:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                raise C2RuntimeError("C2 runtime exceeded its configured timeout")
            time.sleep(0.25)
        for drainer in drainers:
            drainer.join(timeout=10)
        if process.returncode:
            stderr = stderr_tail.decode(errors="replace")
            raise C2RuntimeError(
                f"C2 runtime failed with exit {process.returncode}: {stderr[-2000:]}"
            )
        output = workspace / "output"
        events = self._json_list(output / "exfil_events.json", required=True)
        if context.platform == "android" and context.network_activity:
            events.extend(self._proxy_network_events(context))
        return NativeC2Result(
            events=events,
            attribution=self._json_list(output / "attribution.json"),
            provenance=self._json_list(output / "provenance.json"),
            timeline=self._json_list(output / "timeline.json"),
            iocs=self._read_ioc_csv(output / "iocs.csv"),
            notes=self._notes(output / "analysis_notes.json"),
            runtime_identity=self.identity,
            tool_versions={"python": sys.version.split()[0], "c2_commit": self.expected_commit},
        )

    @staticmethod
    def _proxy_network_events(context: C2AnalysisContext) -> list[dict[str, Any]]:
        source = context.network_activity
        if source is None:
            return []
        try:
            document = json.loads(source.local_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise C2RuntimeError("Android network-activity evidence is not valid JSON") from exc
        if not isinstance(document, dict) or not isinstance(document.get("observations"), list):
            raise C2RuntimeError("Android network-activity evidence has no observation list")
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[Any, Any, Any]] = set()
        for item in document["observations"][:5000]:
            if not isinstance(item, dict):
                continue
            key = (
                item.get("destination_domain"),
                item.get("destination_ip"),
                item.get("destination_port"),
            )
            if key in seen or not (key[0] or key[1]):
                continue
            seen.add(key)
            destination = key[0] or key[1]
            normalized.append(
                {
                    "timestamp": item.get("observed_at") or context.analysis_started_at.isoformat(),
                    "destination_domain": key[0],
                    "destination_ip": key[1],
                    "destination_port": key[2],
                    "confidence_score": 0.55,
                    "confidence_tier": "weak",
                    "finding_kind": "beacon",
                    "plain_language": (
                        f"Android runtime telemetry observed a connection to {destination}; "
                        "this alone does not confirm C2 behavior."
                    ),
                    "capped_by_caveat": "c2_network_only",
                    "evidence_refs": [
                        {
                            "artifact_id": str(source.artifact_id),
                            "sha256": source.sha256,
                            "source": item.get("source") or "android_network_activity",
                            "provenance": item.get("provenance") or {},
                        },
                        {
                            "artifact_id": str(context.pcap.artifact_id),
                            "sha256": context.pcap.sha256,
                            "source": "immutable_guest_pcap",
                        },
                    ],
                }
            )
        return normalized

    @staticmethod
    def _prepare_static_prior(context: C2AnalysisContext, workspace: Path) -> Path:
        source = context.static_prior
        if source is None:
            raise C2RuntimeError("static-prior preparation requested without an artifact")
        try:
            raw = json.loads(source.local_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise C2RuntimeError("static prior is not valid JSON") from exc
        if not isinstance(raw, dict):
            raise C2RuntimeError("static prior is not a JSON object")
        attribution = raw.get("family_attribution")
        family = raw.get("family")
        if isinstance(attribution, dict) and attribution.get("evidence"):
            family = attribution.get("family") or family
        normalized = {
            "sample_sha256": context.sample_sha256,
            "family": family,
            "capabilities": raw.get("capa_capabilities") or raw.get("capabilities") or [],
            "c2_indicators": raw.get("iocs") if "iocs" in raw else raw.get("c2_indicators") or [],
        }
        target = workspace / "static-prior.json"
        target.write_text(json.dumps(normalized, sort_keys=True))
        target.chmod(0o400)
        return target

    @staticmethod
    def _json_list(path: Path, required: bool = False) -> list[dict[str, Any]]:
        if not path.is_file():
            if required:
                raise C2RuntimeError(f"C2 runtime did not produce {path.name}")
            return []
        value = json.loads(path.read_text())
        if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
            raise C2RuntimeError(f"{path.name} is not an array of objects")
        return value

    @staticmethod
    def _read_ioc_csv(path: Path) -> list[dict[str, Any]]:
        if not path.is_file():
            return []
        import csv

        normalized: list[dict[str, Any]] = []
        with path.open(newline="") as source:
            for row in csv.DictReader(source):
                domain, address = row.get("destination_domain"), row.get("destination_ip")
                value = domain or address
                if value:
                    normalized.append(
                        {
                            "type": "domain" if domain else "ip",
                            "value": value,
                            "confidence": row.get("confidence_tier") or "unconfirmed",
                            "source_event_id": "",
                        }
                    )
        return normalized

    @staticmethod
    def _prepare_handoff(context: C2AnalysisContext, workspace: Path) -> Path | None:
        try:
            wrapper = json.loads(context.platform_manifest.local_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        native = wrapper.get("handoff_manifest") if isinstance(wrapper, dict) else None
        if not isinstance(native, dict):
            native = wrapper if isinstance(wrapper, dict) else None
        if not native or native.get("schema_version") != "1.0":
            return None
        # Pass honesty gates and identity to the upstream runtime, but never
        # allow bundle-declared filesystem paths to escape UMAT's downloaded inputs.
        allowed = {
            "schema_version",
            "session_id",
            "status",
            "errors",
            "sample_sha256",
            "submitted_at_utc",
            "detonation_start_utc",
            "detonation_end_utc",
            "guest_vm_identity",
            "network_mode",
            "static_risk_score",
            "static_hypotheses",
            "cape_task_id",
            "capemon_enabled",
            "profile",
            "resolved_options",
            "capabilities",
            "correlation",
            "telemetry",
            "tool_versions",
            "artifact_paths",
            "integrity",
        }
        sanitized = {key: value for key, value in native.items() if key in allowed}
        correlation = sanitized.get("correlation")
        if isinstance(correlation, dict):
            correlation = dict(correlation)
            correlation.pop("access_events_path", None)
            sanitized["correlation"] = correlation
        target = workspace / "windows-handoff.json"
        target.write_text(json.dumps(sanitized, sort_keys=True))
        target.chmod(0o400)
        return target

    @staticmethod
    def _notes(path: Path) -> list[str]:
        if not path.is_file():
            return []
        value = json.loads(path.read_text())
        return [str(note) for note in value.get("notes", [])] if isinstance(value, dict) else []


class FixtureC2Runtime:
    """Deterministic runtime used for contract and cross-platform consistency tests."""

    @property
    def identity(self) -> str:
        return "c2-fixture@1.3"

    def run(
        self,
        context: C2AnalysisContext,
        work_root: Path,
        stop_requested: threading.Event | None = None,
        stop_reason: Callable[[], str] | None = None,
    ) -> NativeC2Result:
        if stop_requested and stop_requested.is_set():
            raise ExecutorStopRequested(stop_reason() if stop_reason else "cancelled")
        work_root.mkdir(parents=True, exist_ok=True)
        fingerprint = hashlib.sha256(context.pcap.local_path.read_bytes()).hexdigest()
        event = {
            "event_id": "0198fd40-1111-7000-8000-000000000010",
            "timestamp": context.analysis_started_at.isoformat(),
            "destination_ip": "198.51.100.10",
            "destination_port": 443,
            "destination_domain": "fixture.invalid",
            "confidence_score": 0.6,
            "confidence_tier": "weak",
            "mitre_technique_id": "T1071",
            "finding_kind": "beacon",
            "plain_language": "The sample repeatedly contacted a remote server.",
            "evidence_refs": [{"pcap_sha256": fingerprint}],
        }
        if context.platform == "windows" and context.correlation_eligible:
            event.update(
                {
                    "data_type_accessed": "browser_credentials",
                    "access_api_call": "fixture_access",
                    "finding_kind": "correlation",
                    "confidence_tier": "confirmed",
                    "plain_language": "Browser credential access was linked to outbound traffic.",
                }
            )
        return NativeC2Result(
            events=[event],
            runtime_identity=self.identity,
            tool_versions={"fixture": "1.3"},
            notes=["network responses were simulated"],
        )
