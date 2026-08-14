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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from umat.c2.models import C2AnalysisContext, NativeC2Result
from umat.executors.protocol import ExecutorStopRequested
from umat.windows.cape import credible_legacy_static_indicator


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
        if context.platform == "windows" and context.etw_events:
            command.extend(["--etw-events", str(context.etw_events.local_path)])
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
        if context.platform == "windows":
            self._correct_unclassified_egress(events)
            self._enrich_access_context(context, events)
            self._corroborate_etw_network(context, events)
            self._corroborate_etw_dns(context, events)
            self._coalesce_network_observations(events)
        if context.platform == "android" and context.network_activity:
            events.extend(self._proxy_network_events(context))
        return NativeC2Result(
            events=events,
            attribution=self._json_list(output / "attribution.json"),
            provenance=self._json_list(output / "provenance.json"),
            timeline=self._json_list(output / "timeline.json"),
            iocs=self._read_ioc_csv(output / "iocs.csv", events),
            notes=self._notes(output / "analysis_notes.json"),
            runtime_identity=self.identity,
            tool_versions={"python": sys.version.split()[0], "c2_commit": self.expected_commit},
        )

    @staticmethod
    def _correct_unclassified_egress(events: list[dict[str, Any]]) -> None:
        """Keep the upstream catch-all detector from asserting exfiltration.

        The locked analyzer exposes its native detector in evidence_refs but
        folds it to ``exfil`` because its original UMAT contract had no neutral
        observation kind. Preserve positive reputation, static, and host-access
        evidence; only the explicitly unclassified residual is corrected.
        """
        for event in events:
            refs = event.get("evidence_refs") or []
            detectors = {
                ref.get("detector")
                for ref in refs
                if isinstance(ref, dict) and ref.get("type") == "network_event"
            }
            independently_supported = bool(
                event.get("reputation_source")
                or event.get("data_type_accessed")
                or event.get("finding_kind") == "correlation"
                or any(
                    isinstance(ref, dict)
                    and ref.get("type") in {"threat_intel", "host_access", "static_prior"}
                    for ref in refs
                )
            )
            if "unclassified_egress" not in detectors or independently_supported:
                continue
            destination = event.get("destination_domain") or event.get("destination_ip")
            event["finding_kind"] = "network_observation"
            event["mitre_technique_id"] = None
            event["plain_language"] = (
                f"Network traffic to {destination or 'an unidentified destination'} was "
                "observed, but it was not attributed to C2 or data exfiltration."
            )

    @staticmethod
    def _enrich_access_context(
        context: C2AnalysisContext, events: list[dict[str, Any]]
    ) -> None:
        """Rejoin correlated rows to the lossless Windows access evidence."""
        source = context.access_events
        if source is None:
            return
        try:
            access_events = json.loads(source.local_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(access_events, list):
            return

        candidates = [item for item in access_events if isinstance(item, dict)]
        used: set[tuple[str, str]] = set()
        for event in events:
            if event.get("finding_kind") != "correlation":
                continue
            refs = event.get("evidence_refs") or []
            host_ref = next(
                (
                    ref
                    for ref in refs
                    if isinstance(ref, dict) and ref.get("type") == "host_access"
                ),
                None,
            )
            if host_ref is None:
                continue
            try:
                network_time = datetime.fromisoformat(
                    str(event["timestamp"]).replace("Z", "+00:00")
                )
                access_time = network_time - timedelta(
                    seconds=float(host_ref.get("time_delta_s") or 0)
                )
            except (KeyError, TypeError, ValueError):
                continue
            ranked: list[tuple[float, int, dict[str, Any]]] = []
            for index, candidate in enumerate(candidates):
                if candidate.get("data_type") != event.get("data_type_accessed"):
                    continue
                if candidate.get("api_call") != event.get("access_api_call"):
                    continue
                try:
                    candidate_time = datetime.fromisoformat(
                        str(candidate["timestamp"]).replace("Z", "+00:00")
                    )
                except (KeyError, TypeError, ValueError):
                    continue
                identity = (str(event.get("timestamp")), str(index))
                if identity in used:
                    continue
                ranked.append((abs((candidate_time - access_time).total_seconds()), index, candidate))
            if not ranked:
                continue
            difference, index, match = min(ranked, key=lambda item: (item[0], item[1]))
            # The upstream correlation rounds its time delta to centiseconds.
            if difference > 0.011:
                continue
            used.add((str(event.get("timestamp")), str(index)))
            for field in (
                "object_path",
                "object_name",
                "access_operation",
                "process",
                "process_id",
                "process_path",
                "parent_process_id",
                "source_call_id",
            ):
                if match.get(field) is not None:
                    host_ref[field] = match[field]
            name = match.get("object_name") or match.get("object_path")
            path = match.get("object_path")
            destination = event.get("destination_domain") or event.get("destination_ip")
            delta = host_ref.get("time_delta_s")
            if name:
                accessed = f"the file {name}"
                if path and path != name:
                    accessed += f" at {path}"
                event["plain_language"] = (
                    f"This sample accessed {accessed} and contacted "
                    f"{destination or 'an unidentified destination'}"
                    f"{f' {delta:g} seconds later' if isinstance(delta, (int, float)) else ''}. "
                    "This is shown for review and is not confirmed."
                )

    @staticmethod
    def _corroborate_etw_network(
        context: C2AnalysisContext, events: list[dict[str, Any]]
    ) -> None:
        """Bind PCAP findings to decoded kernel-network events and processes."""
        source = context.etw_events
        if source is None:
            return
        try:
            document = json.loads(source.local_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(document, dict) or document.get("schema_version") != "1.0":
            return
        raw_events = document.get("events")
        if not isinstance(raw_events, list):
            return
        uncertainty = float(document.get("maximum_uncertainty_ns") or 0) / 1_000_000_000
        tolerance = max(0.75, min(2.0, uncertainty + 0.25))
        network_events = [
            item
            for item in raw_events
            if document.get("clock_quality_acceptable") is True
            and isinstance(item, dict)
            and item.get("provider") == "Microsoft-Windows-Kernel-Network"
            and isinstance(item.get("payload"), dict)
            and item.get("timestamp")
        ]
        protected_kinds = {"static_ioc", "dns"}
        for event in events:
            destination_ip = str(event.get("destination_ip") or "")
            destination_port = int(event.get("destination_port") or 0)
            if not destination_ip or not destination_port:
                continue
            try:
                observed_at = datetime.fromisoformat(
                    str(event["timestamp"]).replace("Z", "+00:00")
                )
            except (KeyError, TypeError, ValueError):
                continue
            matches: list[tuple[float, dict[str, Any]]] = []
            for item in network_events:
                payload = item["payload"]
                try:
                    if str(payload.get("dst_ip") or "") != destination_ip:
                        continue
                    if int(payload.get("dst_port") or 0) != destination_port:
                        continue
                    etw_time = datetime.fromisoformat(
                        str(item["timestamp"]).replace("Z", "+00:00")
                    )
                except (TypeError, ValueError):
                    continue
                delta = abs((etw_time - observed_at).total_seconds())
                if delta <= tolerance:
                    matches.append((delta, item))
            matches.sort(key=lambda value: value[0])
            sample_matches = [value for value in matches if value[1].get("sample_lineage")]
            selected = sample_matches[0] if sample_matches else (matches[0] if matches else None)
            if selected:
                delta, item = selected
                payload = item["payload"]
                event.setdefault("evidence_refs", []).append(
                    {
                        "type": "etw_network",
                        "artifact_id": str(source.artifact_id),
                        "sha256": source.sha256,
                        "provider": item["provider"],
                        "timestamp": item["timestamp"],
                        "time_delta_s": round(delta, 6),
                        "pid": item.get("process_id") or payload.get("pid"),
                        "process": item.get("process"),
                        "process_path": item.get("process_path"),
                        "sample_lineage": bool(item.get("sample_lineage")),
                        "src_ip": payload.get("src_ip"),
                        "src_port": payload.get("src_port"),
                        "dst_ip": payload.get("dst_ip"),
                        "dst_port": payload.get("dst_port"),
                        "protocol": payload.get("protocol"),
                    }
                )
            if sample_matches:
                continue
            if event.get("finding_kind") in protected_kinds:
                event["capped_by_caveat"] = (
                    "network_process_not_sample" if matches else "network_process_unattributed"
                )
                continue
            process = selected[1].get("process") if selected else None
            event["finding_kind"] = "network_observation"
            event["confidence_tier"] = "weak"
            event["mitre_technique_id"] = None
            event["capped_by_caveat"] = (
                "network_process_not_sample" if matches else "network_process_unattributed"
            )
            destination = event.get("destination_domain") or destination_ip
            event["plain_language"] = (
                (
                    f"Network traffic to {destination} matched threat-intelligence evidence"
                    if event.get("reputation_source")
                    else f"Network traffic to {destination} was observed"
                )
                + (f" from {process}" if process else " without sample-process attribution")
                + "; it is not attributed to this sample's C2 or exfiltration behavior."
            )

    @staticmethod
    def _corroborate_etw_dns(
        context: C2AnalysisContext, events: list[dict[str, Any]]
    ) -> None:
        """Prevent host DNS-client activity from being attributed to the sample."""
        source = context.etw_events
        if source is None:
            return
        try:
            document = json.loads(source.local_path.read_text())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(document, dict) or document.get("schema_version") != "1.0":
            return
        raw_events = document.get("events")
        if not isinstance(raw_events, list):
            return
        dns_events = [
            item
            for item in raw_events
            if isinstance(item, dict)
            and item.get("provider") == "Microsoft-Windows-DNS-Client"
            and isinstance(item.get("payload"), dict)
            and str(item["payload"].get("QueryType") or "").lower() in {"query", "response"}
        ]
        for event in events:
            if event.get("finding_kind") != "dns" or not event.get("destination_domain"):
                continue
            domain = str(event["destination_domain"]).rstrip(".").lower()
            matches = [
                item
                for item in dns_events
                if str(item["payload"].get("QueryName") or "").rstrip(".").lower() == domain
            ]
            if not matches or any(item.get("sample_lineage") for item in matches):
                continue
            item = matches[0]
            event.setdefault("evidence_refs", []).append(
                {
                    "type": "etw_dns",
                    "artifact_id": str(source.artifact_id),
                    "sha256": source.sha256,
                    "provider": item["provider"],
                    "pid": item.get("process_id") or item["payload"].get("ProcessId"),
                    "process": item.get("process"),
                    "process_path": item.get("process_path"),
                    "sample_lineage": False,
                    "query_name": item["payload"].get("QueryName"),
                }
            )
            event["finding_kind"] = "network_observation"
            if event.get("confidence_tier") != "allowlisted":
                event["confidence_tier"] = "weak"
            event["mitre_technique_id"] = None
            event["capped_by_caveat"] = "network_process_not_sample"
            event["plain_language"] = (
                f"A DNS lookup for {event['destination_domain']} was observed from a non-sample "
                "process; it is not attributed to this sample's C2 behavior."
            )

    @staticmethod
    def _coalesce_network_observations(events: list[dict[str, Any]]) -> None:
        """Collapse duplicate neutral observations without discarding their evidence.

        The upstream analyzer can emit several host-access correlations for one
        packet observation. When ETW disproves sample-process attribution, those
        correlations all become the same neutral observation. Retain every
        supporting reference on one event instead of presenting duplicate rows.
        """
        retained: list[dict[str, Any]] = []
        observations: dict[tuple[Any, ...], dict[str, Any]] = {}
        for event in events:
            if event.get("finding_kind") != "network_observation":
                retained.append(event)
                continue
            key = (
                event.get("timestamp"),
                event.get("destination_domain") or event.get("destination_ip"),
                event.get("destination_port"),
                event.get("protocol"),
                event.get("capped_by_caveat"),
                event.get("plain_language"),
            )
            existing = observations.get(key)
            if existing is None:
                event["observation_count"] = int(event.get("observation_count") or 1)
                observations[key] = event
                retained.append(event)
                continue
            existing["observation_count"] = int(existing.get("observation_count") or 1) + int(
                event.get("observation_count") or 1
            )
            destination_ips = {
                str(value)
                for value in [
                    *(existing.get("observed_destination_ips") or []),
                    existing.get("destination_ip"),
                    event.get("destination_ip"),
                ]
                if value
            }
            if len(destination_ips) > 1:
                existing["observed_destination_ips"] = sorted(destination_ips)
            refs = existing.setdefault("evidence_refs", [])
            known = {
                canonical
                for ref in refs
                if isinstance(ref, dict)
                and (canonical := json.dumps(ref, sort_keys=True, separators=(",", ":")))
            }
            for ref in event.get("evidence_refs") or []:
                if not isinstance(ref, dict):
                    continue
                canonical = json.dumps(ref, sort_keys=True, separators=(",", ":"))
                if canonical not in known:
                    refs.append(ref)
                    known.add(canonical)
        events[:] = retained

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
        indicators = raw.get("iocs") if "iocs" in raw else raw.get("c2_indicators") or []
        if not isinstance(indicators, list):
            raise C2RuntimeError("static prior indicators are not an array")
        # Modern platform adapters explicitly identify independently obtained
        # static evidence. Do not pass runtime-observed network destinations to
        # a detector as priors: that would allow a flow to corroborate itself.
        if getattr(context, "platform", None) == "windows" and not raw.get("evidence_origin"):
            indicators = []
        elif raw.get("evidence_origin"):
            if raw["evidence_origin"] != "binary_static":
                indicators = []
            else:
                indicators = [
                    item
                    for item in indicators
                    if isinstance(item, dict)
                    and item.get("evidence_origin", "binary_static") == "binary_static"
                ]
        peer_values = [
            str(item.get("value") or "") for item in indicators if isinstance(item, dict)
        ]
        indicators = [
            item
            for item in indicators
            if not isinstance(item, dict)
            or item.get("source") != "cape_static_string"
            or credible_legacy_static_indicator(
                str(item.get("type") or "unknown"), str(item.get("value") or ""), peer_values
            )
        ]
        normalized = {
            "sample_sha256": context.sample_sha256,
            "family": family,
            "capabilities": raw.get("capa_capabilities") or raw.get("capabilities") or [],
            "c2_indicators": indicators,
        }
        # Preserve redacted extractor evidence for runtimes that understand
        # richer configuration records. Omit empty extensions so legacy inputs
        # remain byte-shape compatible with the locked runtime.
        for field in ("configuration_candidates", "extractor_records"):
            if raw.get(field):
                normalized[field] = raw[field]
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
    def _read_ioc_csv(path: Path, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not path.is_file():
            return []
        import csv

        normalized: list[dict[str, Any]] = []
        with path.open(newline="") as source:
            for row in csv.DictReader(source):
                domain, address = row.get("destination_domain"), row.get("destination_ip")
                value = domain or address
                if value:
                    matched = next(
                        (
                            event
                            for event in events
                            if str(event.get("destination_domain") or "") == str(domain or "")
                            and str(event.get("destination_ip") or "") == str(address or "")
                            and int(event.get("destination_port") or 0)
                            == int(row.get("destination_port") or 0)
                        ),
                        None,
                    )
                    observed = bool(
                        matched
                        and (
                            matched.get("finding_kind") != "static_ioc"
                            or "contacted on network" in str(matched.get("static_match") or "")
                        )
                    )
                    normalized.append(
                        {
                            "type": "domain" if domain else "ip",
                            "value": value,
                            "confidence": (
                                matched.get("confidence_tier")
                                if matched
                                else row.get("confidence_tier")
                            )
                            or "unconfirmed",
                            "source_event_id": str(matched.get("event_id")) if observed else "",
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
