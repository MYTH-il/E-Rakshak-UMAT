from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID

import httpx
import typer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from umat.android.access_events import AndroidAccessEventCollector
from umat.android.avd import AvdManager
from umat.android.bundle import ANDROID_COMMIT, MOBSF_VERSION, AndroidBundleBuilder, sha256_file
from umat.android.mobsf import MobSFClient
from umat.android.redroid import MITMPROXY_IMAGE, RedroidManager
from umat.egress.client import EgressClient
from umat.executors.protocol import ExecutorStopRequested, raise_for_stop, signature_message
from umat.intake.routing import is_structurally_valid_apk

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Run the isolated MobSF/API-30 Android executor."""


class AndroidExecutor:
    def __init__(
        self,
        *,
        umat_url: str,
        state_path: Path,
        mobsf: MobSFClient,
        work_root: Path,
        avdmanager: Path,
        emulator: Path,
        adb: Path,
        system_image: str,
        emulator_port: int,
        adb_relay: Path | None,
        adb_relay_bind_address: str | None,
        stimulation_seconds: int,
        stimulation_actions: int,
        mobsf_container: str = "android-mobsf-1",
        egress: EgressClient | None = None,
        egress_guest_ip: str | None = None,
        mitmproxy_image: str = MITMPROXY_IMAGE,
    ) -> None:
        self.client = httpx.Client(base_url=umat_url.rstrip("/"), timeout=120)
        self.state_path = state_path
        self.mobsf = mobsf
        self.work_root = work_root.resolve()
        self.avdmanager, self.emulator, self.adb = avdmanager, emulator, adb
        self.system_image, self.emulator_port = system_image, emulator_port
        self.adb_relay = adb_relay
        self.adb_relay_bind_address = adb_relay_bind_address
        self.stimulation_seconds, self.stimulation_actions = (
            stimulation_seconds,
            stimulation_actions,
        )
        self.mobsf_container = mobsf_container
        self.egress = egress
        self.egress_guest_ip = egress_guest_ip
        self.mitmproxy_image = mitmproxy_image
        self._egress_active_run: str | None = None
        self.state: dict[str, Any] = (
            json.loads(state_path.read_text()) if state_path.is_file() else {}
        )

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(self.state["private_key"]))

    def enroll(self, token: str, name: str) -> None:
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        response = self.client.post(
            "/api/internal/v1/executors/register",
            json={
                "enrollment_token": token,
                "name": name,
                "public_key": base64.b64encode(public).decode(),
                "metadata": {
                    "implementation": "umat-android-executor",
                    "android_commit": ANDROID_COMMIT,
                    "mobsf_version": MOBSF_VERSION,
                },
            },
        )
        response.raise_for_status()
        registered = response.json()
        self.state = {
            "executor_id": registered["executor_id"],
            "credential": registered["credential"],
            "private_key": base64.b64encode(raw).decode(),
            "name": name,
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_path.write_text(json.dumps(self.state, indent=2) + "\n")
        self.state_path.chmod(0o600)
        capabilities = self.client.post(
            "/api/internal/v1/executors/capabilities",
            headers=self.auth(),
            json={
                "schema_version": "1.0",
                "runtime_identity": f"android-erakshak@{ANDROID_COMMIT}",
                "supported_stage_types": ["platform_analysis"],
                "capabilities": {
                    "platforms": ["android"],
                    "api_levels": [30],
                    "ephemeral_avd": True,
                    "pcap_capture": True,
                    "mobsf_api": "v1",
                    "mobsf_version": MOBSF_VERSION,
                },
            },
        )
        capabilities.raise_for_status()

    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.state['credential']}"}

    def signed(self, method: str, path: str, body: dict[str, Any], lease: str) -> dict[str, str]:
        timestamp, nonce, key = (
            datetime.now(timezone.utc).isoformat(),
            uuid.uuid4().hex,
            str(uuid.uuid4()),
        )
        message = signature_message(
            method=method,
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            idempotency_key=key,
            body=body,
        )
        return self.auth() | {
            "X-UMAT-Timestamp": timestamp,
            "X-UMAT-Nonce": nonce,
            "Idempotency-Key": key,
            "X-UMAT-Signature": base64.b64encode(self.private_key.sign(message)).decode(),
            "X-UMAT-Lease-Token": lease,
        }

    def mutate(self, path: str, body: dict[str, Any], lease: str) -> httpx.Response:
        return self.client.post(path, json=body, headers=self.signed("POST", path, body, lease))

    def process_stage(self) -> bool:
        response = self.client.post(
            "/api/internal/v1/executors/claim",
            headers=self.auth(),
            json={"stage_types": ["platform_analysis"], "platforms": ["android"]},
        )
        response.raise_for_status()
        if response.content in {b"", b"null"}:
            return False
        claim = response.json()
        common = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]}
        try:
            with tempfile.TemporaryDirectory(
                prefix=f"umat-android-{claim['analysis_run_id']}-", dir=self.work_root
            ) as temporary:
                workspace = Path(temporary)
                sample = self._download_sample(claim, workspace)
                if not is_structurally_valid_apk(sample):
                    raise RuntimeError("claimed Android sample is not a structurally valid APK")
                recovered = claim.get("recovered_native_task")
                if recovered:
                    expected_scan_hash = str(
                        (recovered.get("recovery_metadata") or {}).get("scan_hash")
                        or recovered["native_task_id"]
                    )
                else:
                    expected_scan_hash = ""
                # A disposable worker reset also resets MobSF's upload volume.
                # Re-upload on recovery so a persisted backend task never waits
                # for a report that vanished with the previous worker overlay.
                uploaded = self.mobsf.upload(sample)
                scan_hash = str(uploaded.get("hash") or uploaded.get("scan_hash") or "")
                if len(scan_hash) != 32 or any(
                    char not in "0123456789abcdefABCDEF" for char in scan_hash
                ):
                    raise RuntimeError("MobSF upload returned an invalid scan hash")
                if expected_scan_hash and scan_hash.lower() != expected_scan_hash.lower():
                    raise RuntimeError("recovered MobSF scan hash does not match the sample")
                if not recovered:
                    native = common | {
                        "task_type": "mobsf_scan",
                        # A MobSF hash identifies content, not one execution.
                        # Scope the backend task identity to this run so the
                        # same APK can be analyzed repeatedly.
                        "native_task_id": f"{scan_hash}:{claim['analysis_run_id']}",
                        "recovery_metadata": {
                            "analysis_run_id": claim["analysis_run_id"],
                            "scan_hash": scan_hash,
                            "file_name": uploaded.get("file_name"),
                        },
                    }
                    self.mutate(
                        f"/api/internal/v1/stages/{claim['stage_id']}/native-task",
                        native,
                        claim["lease_token"],
                    ).raise_for_status()
                outcome, detail = self._analyze_with_heartbeats(
                    claim, common, workspace, scan_hash, recovered=False
                )
            completed = common | {"outcome": outcome, "detail": detail}
            self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/complete",
                completed,
                claim["lease_token"],
            ).raise_for_status()
        except ExecutorStopRequested as stop:
            if stop.reason == "cancelled":
                acknowledgement = common | {"detail": "MobSF/AVD analysis stopped"}
                self.mutate(
                    f"/api/internal/v1/stages/{claim['stage_id']}/cancellation-ack",
                    acknowledgement,
                    claim["lease_token"],
                ).raise_for_status()
        except Exception as exc:
            failed = common | {
                "error_code": "android_executor_failure",
                "detail": str(exc)[:2000],
                "retryable": True,
            }
            self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/fail",
                failed,
                claim["lease_token"],
            ).raise_for_status()
        return True

    def _analyze_with_heartbeats(
        self,
        claim: dict[str, Any],
        common: dict[str, Any],
        workspace: Path,
        scan_hash: str,
        *,
        recovered: bool,
    ) -> tuple[str, str]:
        stopped = threading.Event()
        stop_requested = threading.Event()
        stop_reasons: list[str] = []
        failures: list[Exception] = []

        def renew() -> None:
            outage_started: float | None = None
            while not stopped.wait(15):
                try:
                    self._heartbeat(claim, common)
                    if self._egress_active_run and self.egress:
                        self.egress.heartbeat(self._egress_active_run)
                    outage_started = None
                except ExecutorStopRequested as stop:
                    stop_reasons.append(stop.reason)
                    stop_requested.set()
                    return
                except Exception as exc:
                    outage_started = outage_started or time.monotonic()
                    if time.monotonic() - outage_started >= 60:
                        failures.append(exc)
                        return

        self._heartbeat(claim, common)
        thread = threading.Thread(target=renew, name="umat-android-lease-heartbeat", daemon=True)
        thread.start()
        try:
            result = self._analyze(
                claim,
                common,
                workspace,
                scan_hash,
                recovered=recovered,
                stop_requested=stop_requested,
                stop_reasons=stop_reasons,
            )
        finally:
            stopped.set()
            thread.join(timeout=5)
        if failures:
            raise RuntimeError("Android executor lease heartbeat failed") from failures[0]
        return result

    def _analyze(
        self,
        claim: dict[str, Any],
        common: dict[str, Any],
        workspace: Path,
        scan_hash: str,
        *,
        recovered: bool,
        stop_requested: threading.Event,
        stop_reasons: list[str],
    ) -> tuple[str, str]:
        def check_stop() -> None:
            if stop_requested.is_set():
                raise ExecutorStopRequested(stop_reasons[-1] if stop_reasons else "cancelled")

        started = datetime.now(timezone.utc)
        caveats: list[str] = []
        if not recovered:
            self.mobsf.scan(scan_hash)
        static = self.mobsf.wait_static_report(scan_hash, check_stop=check_stop)
        check_stop()
        static_path = workspace / "mobsf-static.json"
        self._json(static_path, static)
        profile = claim.get("execution_configuration") or {}
        system_image = str(profile.get("system_image") or self.system_image)
        redroid_image = "docker.io/redroid/redroid@sha256:d1ca0815eb68139a43d25a835e374559e9d18f5d5cea1a4288d4657c0074fb8d"
        if system_image not in {"system-images;android-30;default;x86_64", redroid_image}:
            raise RuntimeError("Android profile requests an unsupported system image")
        memory_mb = int(profile.get("ram_mb") or 4096)
        if memory_mb != 4096:
            raise RuntimeError("Android profile requests unsupported guest memory")
        avd_name = f"umat-{claim['analysis_run_id'].replace('-', '')[:20]}"
        if system_image == redroid_image:
            avd: AvdManager | RedroidManager = RedroidManager(
                adb=self.adb,
                image=redroid_image,
                memory_mb=memory_mb,
                vcpus=int(profile.get("vcpus") or 4),
                network_mode=str(profile.get("network_mode") or "isolated_simulated"),
                mitmproxy_image=self.mitmproxy_image,
            )
        else:
            if profile.get("network_mode") == "isolated_simulated":
                raise RuntimeError("isolated Android runs require the ReDroid profile")
            avd = AvdManager(
                avdmanager=self.avdmanager,
                emulator=self.emulator,
                adb=self.adb,
                system_image=system_image,
                emulator_port=self.emulator_port,
                memory_mb=memory_mb,
                adb_relay=self.adb_relay,
                adb_relay_bind_address=self.adb_relay_bind_address,
            )
        dynamic: dict[str, Any] | None = None
        stimulation: dict[str, Any] = {
            "strategy": "deterministic_adb_v1",
            "actions_completed": 0,
            "complete": False,
        }
        evidence: dict[str, Path] = {}
        egress_capture: Path | None = None
        evidence["original_apk"] = workspace / "sample.apk"
        try:
            scan_logs_path = workspace / "mobsf-scan-logs.json"
            self._json(scan_logs_path, self.mobsf.scan_logs(scan_hash))
            evidence["scan_logs"] = scan_logs_path
        except Exception as exc:
            self._json(scan_logs_path, {"status": "unavailable", "error": str(exc)[:2000]})
            evidence["scan_logs"] = scan_logs_path
        evidence.update(self._export_mobsf_sources(scan_hash, workspace))
        running = None
        dynamic_started = False
        access_collector: AndroidAccessEventCollector | None = None
        analysis_error: Exception | None = None
        try:
            running = avd.start(avd_name, workspace)
            if profile.get("network_mode") == "real_world_egress":
                if not self.egress or not running.guest_ip:
                    raise RuntimeError("controlled egress broker is not configured")
                self.egress.acquire(
                    claim["analysis_run_id"],
                    "android",
                    self.egress_guest_ip or running.guest_ip,
                )
                self._egress_active_run = claim["analysis_run_id"]
            check_stop()
            self.mobsf.start_dynamic(scan_hash)
            dynamic_started = True
            if isinstance(avd, RedroidManager):
                try:
                    proxy_state = avd.enable_analysis_proxy(workspace)
                    proxy_state_path = workspace / "mitmproxy-state.json"
                    self._json(proxy_state_path, proxy_state)
                    evidence["mitmproxy_state"] = proxy_state_path
                except Exception as exc:
                    caveats.append("android_mitmproxy_unavailable")
                    proxy_state_path = workspace / "mitmproxy-state.json"
                    self._json(
                        proxy_state_path,
                        {"status": "failed", "error": str(exc)[:2000]},
                    )
                    evidence["mitmproxy_state"] = proxy_state_path
            activity = self._main_activity(static)
            package_name = str(static.get("package_name") or static.get("package") or "")
            activation: dict[str, Any] = {
                "schema_version": "1.0",
                "package_name": package_name,
                "main_activity": activity,
            }
            if package_name and isinstance(avd, RedroidManager):
                activation["guest_preparation"] = avd.prepare_analysis(
                    package_name, self._requested_permissions(static)
                )
            try:
                activation["frida"] = self.mobsf.instrument(scan_hash)
                time.sleep(3)
            except Exception as exc:
                activation["frida"] = {"status": "failed", "error": str(exc)[:2000]}
                caveats.append("android_api_monitoring_failed")
            if package_name and isinstance(avd, RedroidManager):
                activation["stimulation"] = avd.stimulate_package(package_name, activity)
                if not activation["stimulation"].get("package_process_ids"):
                    caveats.append("android_package_process_not_observed")
            if package_name:
                if (activation.get("frida") or {}).get("hook_ready") is True:
                    access_collector = AndroidAccessEventCollector(
                        lambda: self.mobsf.api_monitor(scan_hash),
                        package_name=package_name,
                        process_ids=(activation.get("stimulation") or {}).get(
                            "package_process_ids"
                        )
                        or [],
                        started_at=started,
                    )
                    access_collector.start()
            activation_path = workspace / "android-activation.json"
            self._json(activation_path, activation)
            evidence["activation"] = activation_path
            if bool(profile.get("android_interactive")):
                if not isinstance(avd, RedroidManager):
                    raise RuntimeError("interactive Android analysis requires ReDroid")
                stimulation, interactive_evidence = self._interactive_session(
                    claim, common, avd, scan_hash, static, running.guest_ip, workspace, check_stop
                )
                evidence.update(interactive_evidence)
            else:
                stimulation = avd.stimulate(self.stimulation_seconds, self.stimulation_actions)
            stimulation["activation"] = activation
            check_stop()
            if not stimulation.get("complete"):
                caveats.append("stimulation_incomplete")
            if package_name and isinstance(avd, RedroidManager):
                try:
                    evidence["application_data"] = avd.collect_app_data(
                        workspace / "device-evidence", package_name
                    )
                except Exception:
                    caveats.append("application_data_collection_failed")
            evidence.update(avd.collect(workspace / "device-evidence"))
            if access_collector is not None:
                access_path = workspace / "android-access-events.json"
                access_collector.stop(access_path)
                evidence["access_events"] = access_path
                access_collector = None
            for kind, getter in (
                ("api_monitor", self.mobsf.api_monitor),
                ("frida_logs", self.mobsf.frida_logs),
            ):
                try:
                    path = workspace / f"{kind}.json"
                    self._json(path, getter(scan_hash))
                    evidence[kind] = path
                except Exception:
                    if "android_api_monitoring_failed" not in caveats:
                        caveats.append("android_api_monitoring_failed")
            self.mobsf.stop_dynamic(scan_hash)
            dynamic = self.mobsf.wait_dynamic_report(scan_hash, check_stop=check_stop)
        except ExecutorStopRequested:
            if dynamic_started:
                try:
                    self.mobsf.stop_dynamic(scan_hash)
                except Exception:
                    caveats.append("android_dynamic_stop_failed")
            raise
        except Exception as exc:
            analysis_error = exc
            caveats.extend(["static_analysis_only", "network_capture_incomplete"])
            if dynamic_started:
                try:
                    self.mobsf.stop_dynamic(scan_hash)
                except Exception:
                    caveats.append("android_dynamic_stop_failed")
        finally:
            if access_collector is not None:
                try:
                    access_path = workspace / "android-access-events.json"
                    access_collector.stop(access_path)
                    evidence["access_events"] = access_path
                except Exception:
                    if "android_api_monitoring_failed" not in caveats:
                        caveats.append("android_api_monitoring_failed")
            if self._egress_active_run and self.egress:
                egress_capture = self.egress.revoke(
                    self._egress_active_run,
                    workspace / "android-egress-capture.pcap",
                )
                self._egress_active_run = None
            avd.stop()
            if isinstance(avd, RedroidManager):
                evidence.update(avd.proxy_evidence())
        pcap = workspace / "android-capture.pcap"
        if not pcap.is_file() or pcap.stat().st_size == 0:
            detail = f": {analysis_error}" if analysis_error else ""
            raise RuntimeError(
                f"Android analysis did not produce a non-empty PCAP{detail}"
            ) from analysis_error
        evidence["pcap"] = pcap
        if egress_capture and egress_capture.is_file() and egress_capture.stat().st_size:
            evidence["egress_pcap"] = egress_capture
        network_activity = workspace / "network-activity.json"
        checkpoint_document: dict[str, Any] | None = None
        checkpoint_path = evidence.get("network_checkpoints")
        if checkpoint_path and checkpoint_path.is_file():
            try:
                loaded = json.loads(checkpoint_path.read_text())
                if isinstance(loaded, dict):
                    checkpoint_document = loaded
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                caveats.append("android_network_checkpoint_invalid")
        self._network_summary(
            pcap,
            running.guest_ip if running else None,
            network_activity,
            dynamic,
            checkpoint_document,
        )
        evidence["network_activity"] = network_activity
        dynamic_path: Path | None = None
        if dynamic is not None:
            dynamic_path = workspace / "mobsf-dynamic.json"
            self._json(dynamic_path, dynamic)
        quality = self._dynamic_quality(dynamic, evidence, activation if dynamic_started else {})
        stimulation["quality"] = quality
        if not quality["runtime_behavior_observed"]:
            caveats.append("android_runtime_behavior_not_observed")
        if evidence.get("activation"):
            self._json(evidence["activation"], activation | {"quality": quality})
        ended = datetime.now(timezone.utc)
        emulator_metadata = {
            "api_level": int(profile.get("api_level") or 30),
            "avd_name": avd_name,
            "guest_ip": running.guest_ip if running else None,
            "system_image": system_image,
            "runtime": "redroid" if system_image == redroid_image else "avd",
            "profile_snapshot": profile,
        }
        bundle = AndroidBundleBuilder(self.private_key, str(self.state["executor_id"])).build(
            analysis_run_id=UUID(claim["analysis_run_id"]),
            sample_sha256=claim["sample_sha256"],
            scan_hash=scan_hash,
            analysis_started_at=started,
            analysis_ended_at=ended,
            emulator=emulator_metadata,
            static_report=static_path,
            dynamic_report=dynamic_path,
            evidence=evidence,
            stimulation=stimulation,
            caveats=caveats,
            destination=workspace / "android-result",
        )
        self._upload(claim, bundle.archive_path, "android_bundle", "application/zip")
        self._upload(
            claim, bundle.root / "umat-manifest.json", "platform_manifest", "application/json"
        )
        self._upload(claim, pcap, "pcap", "application/vnd.tcpdump.pcap")
        prior = self._static_prior(static, claim)
        prior_path = workspace / "c2-static-prior.json"
        self._json(prior_path, prior)
        self._upload(claim, prior_path, "static_prior", "application/json")
        access_events_path = evidence.get("access_events")
        if access_events_path and access_events_path.is_file():
            self._upload(claim, access_events_path, "access_events", "application/json")
        for kind, artifact_path, media_type in (
            (
                "android_sample",
                evidence.get("original_apk"),
                "application/vnd.android.package-archive",
            ),
            ("java_source", evidence.get("java_source"), "application/zip"),
            ("smali_source", evidence.get("smali_source"), "application/zip"),
            ("application_data", evidence.get("application_data"), "application/x-tar"),
            ("android_scan_logs", evidence.get("scan_logs"), "application/json"),
            ("android_activation", evidence.get("activation"), "application/json"),
            ("analyst_session", evidence.get("analyst_session"), "application/json"),
            ("analyst_screenshots", evidence.get("analyst_screenshots"), "application/zip"),
            ("network_activity", evidence.get("network_activity"), "application/json"),
            (
                "mitmproxy_flows",
                evidence.get("mitmproxy_flows"),
                "application/vnd.mitmproxy.flow",
            ),
            ("mitmproxy_har", evidence.get("mitmproxy_har"), "application/json"),
            (
                "mitmproxy_events",
                evidence.get("mitmproxy_events"),
                "application/x-ndjson",
            ),
            ("mitmproxy_state", evidence.get("mitmproxy_state"), "application/json"),
            ("egress_pcap", evidence.get("egress_pcap"), "application/vnd.tcpdump.pcap"),
            (
                "android_network_checkpoints",
                evidence.get("network_checkpoints"),
                "application/json",
            ),
        ):
            if artifact_path and artifact_path.is_file():
                self._upload(claim, artifact_path, kind, media_type)
        if dynamic is None:
            return "partial", "Static analysis completed; dynamic evidence is incomplete"
        if not quality["runtime_behavior_observed"]:
            return "partial", "Dynamic execution completed without attributable runtime behavior"
        if not quality["instrumentation_evidence_observed"]:
            return (
                "partial",
                "Dynamic behavior observed, but runtime instrumentation produced no evidence",
            )
        return "completed", "MobSF static/dynamic analysis bundle validated with runtime evidence"

    @staticmethod
    def _requested_permissions(report: dict[str, Any]) -> list[str]:
        permissions = report.get("permissions") or {}
        if isinstance(permissions, dict):
            return [str(value) for value in permissions]
        if isinstance(permissions, list):
            return [
                str(item.get("permission") or item.get("name"))
                if isinstance(item, dict)
                else str(item)
                for item in permissions
            ]
        return []

    @staticmethod
    def _dynamic_quality(
        dynamic: dict[str, Any] | None,
        evidence: dict[str, Path],
        activation: dict[str, Any],
    ) -> dict[str, Any]:
        baseline_domains = {
            "connectivitycheck.gstatic.com",
            "play.googleapis.com",
            "www.google.com",
        }
        domains = dynamic.get("domains") if isinstance(dynamic, dict) else {}
        observed_domains = (
            sorted(str(value).lower() for value in domains) if isinstance(domains, dict) else []
        )
        attributable_domains = [
            value for value in observed_domains if value not in baseline_domains
        ]
        populated_sections: list[str] = []
        for name in (
            "clipboard",
            "emails",
            "sqlite",
            "runtime_dependencies",
            "xml",
            "base64_strings",
        ):
            value = dynamic.get(name) if isinstance(dynamic, dict) else None
            if value:
                populated_sections.append(name)
        api_events = 0
        api_path = evidence.get("api_monitor")
        if api_path and api_path.is_file():
            try:
                api_document = json.loads(api_path.read_text())
                api_events = (
                    len(api_document.get("data") or []) if isinstance(api_document, dict) else 0
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                pass
        stimulation = activation.get("stimulation") or {}
        process_ids = stimulation.get("package_process_ids") or []
        frida_ok = (activation.get("frida") or {}).get("status") == "ok"
        runtime_behavior = bool(attributable_domains or populated_sections or api_events)
        api_monitor_available = bool(api_path and api_path.is_file())
        instrumentation_evidence = bool(
            frida_ok and (api_monitor_available or populated_sections or api_events)
        )
        return {
            "dynamic_report_available": dynamic is not None,
            "package_process_observed": bool(process_ids),
            "frida_instrumentation_started": frida_ok,
            "api_monitor_event_count": api_events,
            "api_monitor_available": api_monitor_available,
            "observed_domains": observed_domains,
            "attributable_domains": attributable_domains,
            "populated_runtime_sections": populated_sections,
            "runtime_behavior_observed": runtime_behavior,
            "instrumentation_evidence_observed": instrumentation_evidence,
        }

    def _export_mobsf_sources(self, scan_hash: str, workspace: Path) -> dict[str, Path]:
        exports: dict[str, Path] = {}
        for kind, directory in (("java_source", "java_source"), ("smali_source", "smali_source")):
            destination = workspace / f"mobsf-{directory}"
            result = subprocess.run(  # noqa: S603
                [
                    "/usr/bin/docker",
                    "cp",
                    f"{self.mobsf_container}:/home/mobsf/.MobSF/uploads/{scan_hash}/{directory}",
                    str(destination),
                ],
                capture_output=True,
                timeout=120,
                check=False,
            )
            if result.returncode == 0 and destination.is_dir():
                archive = Path(shutil.make_archive(str(workspace / kind), "zip", destination))
                exports[kind] = archive
        return exports

    def _interactive_session(
        self,
        claim: dict[str, Any],
        common: dict[str, Any],
        avd: RedroidManager,
        scan_hash: str,
        static: dict[str, Any],
        guest_ip: str | None,
        workspace: Path,
        check_stop: Any,
    ) -> tuple[dict[str, Any], dict[str, Path]]:
        path = f"/api/internal/v1/stages/{claim['stage_id']}/android-session/ready"
        body = common | {
            "scan_hash": scan_hash,
            "package_name": str(static.get("package_name") or static.get("package") or "") or None,
            "main_activity": self._main_activity(static),
            "guest_ip": guest_ip,
            "duration_seconds": 900,
        }
        response = self.mutate(path, body, claim["lease_token"])
        response.raise_for_status()
        completed = 0
        records: list[dict[str, Any]] = []
        network_checkpoints: list[dict[str, Any]] = []
        last_checkpoint = 0.0

        def checkpoint(reason: str) -> None:
            nonlocal last_checkpoint
            captured_at = datetime.now(timezone.utc).isoformat()
            try:
                report = self.mobsf.dynamic_report(scan_hash)
                domains = report.get("domains") if isinstance(report, dict) else {}
                urls = report.get("urls") if isinstance(report, dict) else []
                network_checkpoints.append(
                    {
                        "captured_at": captured_at,
                        "reason": reason,
                        "status": "ok",
                        "domains": domains if isinstance(domains, dict) else {},
                        "urls": urls if isinstance(urls, list) else [],
                    }
                )
            except Exception as exc:
                network_checkpoints.append(
                    {
                        "captured_at": captured_at,
                        "reason": reason,
                        "status": "unavailable",
                        "error": str(exc)[:1000],
                        "domains": {},
                        "urls": [],
                    }
                )
            last_checkpoint = time.monotonic()

        def restore_evidence_proxy() -> None:
            try:
                avd.ensure_analysis_proxy()
            except Exception:
                records.append(
                    {
                        "sequence": completed,
                        "command_type": "proxy_restore",
                        "success": False,
                        "recorded_at": datetime.now(timezone.utc).isoformat(),
                    }
                )

        captures = workspace / "analyst-screenshots"
        captures.mkdir(mode=0o700)
        checkpoint("interactive_session_ready")
        restore_evidence_proxy()
        while True:
            check_stop()
            if time.monotonic() - last_checkpoint >= 15:
                checkpoint("periodic")
            poll_path = f"/api/internal/v1/stages/{claim['stage_id']}/android-session/poll"
            poll_deadline = time.monotonic() + 60
            while True:
                try:
                    poll = self.mutate(poll_path, common, claim["lease_token"])
                    break
                except httpx.TransportError:
                    check_stop()
                    if time.monotonic() >= poll_deadline:
                        raise
                    time.sleep(1)
            poll.raise_for_status()
            value = poll.json()
            command = value.get("command")
            if command:
                command_type = str(command["type"])
                if command_type in {"tls_test", "proxy", "root_ca", "finalize"}:
                    checkpoint(f"before_{command_type}")
                success = True
                try:
                    result = self._execute_interactive_command(
                        avd,
                        scan_hash,
                        body.get("package_name"),
                        static,
                        command["type"],
                        command["payload"],
                    )
                    completed += 1
                except Exception as exc:
                    success, result = False, {"error": str(exc)[:2000]}
                recorded = dict(result)
                encoded_image = recorded.pop("image_base64", None)
                if encoded_image and command["type"] in {"screenshot", "activity_test"}:
                    capture = captures / f"{completed:04d}-{command['type']}.png"
                    capture.write_bytes(base64.b64decode(encoded_image, validate=True))
                    recorded["screenshot"] = capture.name
                records.append(
                    {
                        "sequence": completed,
                        "command_type": command["type"],
                        "payload": command["payload"],
                        "success": success,
                        "result": recorded,
                        "recorded_at": datetime.now(timezone.utc).isoformat(),
                    }
                )
                complete_path = (
                    f"/api/internal/v1/stages/{claim['stage_id']}/android-session/complete-command"
                )
                complete_body = common | {
                    "command_id": command["id"],
                    "success": success,
                    "result": result,
                }
                completed_response = self.mutate(complete_path, complete_body, claim["lease_token"])
                completed_response.raise_for_status()
                if command_type in {"tls_test", "proxy", "root_ca"}:
                    checkpoint(f"after_{command_type}")
                    restore_evidence_proxy()
            if value.get("finalize"):
                checkpoint("before_finalization")
                break
            time.sleep(0.35)
        journal = workspace / "analyst-session.json"
        self._json(journal, {"schema_version": "1.0", "commands": records})
        checkpoint_path = workspace / "android-network-checkpoints.json"
        self._json(
            checkpoint_path,
            {
                "schema_version": "1.0",
                "scan_hash": scan_hash,
                "checkpoints": network_checkpoints,
            },
        )
        session_evidence = {
            "analyst_session": journal,
            "network_checkpoints": checkpoint_path,
        }
        if any(captures.iterdir()):
            session_evidence["analyst_screenshots"] = Path(
                shutil.make_archive(str(workspace / "analyst-screenshots"), "zip", captures)
            )
        return {
            "strategy": "interactive_analyst_v1",
            "actions_completed": completed,
            "complete": True,
        }, session_evidence

    def _network_summary(
        self,
        pcap: Path,
        guest_ip: str | None,
        destination: Path,
        dynamic: dict[str, Any] | None = None,
        checkpoint_document: dict[str, Any] | None = None,
    ) -> None:
        display_filter = (
            f"ip.src == {guest_ip} && !(mdns) && !(tcp.srcport == 5555)"
            if guest_ip
            else "ip && !(mdns)"
        )
        command = [
            "/usr/bin/tshark",
            "-r",
            str(pcap),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
            "-e",
            "frame.time_epoch",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "dns.qry.name",
            "-e",
            "_ws.col.Protocol",
        ]
        result = subprocess.run(command, capture_output=True, timeout=120, check=False)  # noqa: S603
        observations: list[dict[str, Any]] = []
        for line in result.stdout.decode(errors="replace").splitlines()[:5000]:
            fields = (line.split("\t") + [""] * 7)[:7]
            timestamp, ipv4, ipv6, tcp_port, udp_port, domain, protocol = fields
            if not (ipv4 or ipv6 or domain):
                continue
            observations.append(
                {
                    "observed_at": datetime.fromtimestamp(
                        float(timestamp), timezone.utc
                    ).isoformat()
                    if timestamp
                    else None,
                    "destination_ip": ipv4 or ipv6 or None,
                    "destination_port": int(tcp_port or udp_port)
                    if (tcp_port or udp_port).isdigit()
                    else None,
                    "destination_domain": domain.rstrip(".").lower() or None,
                    "protocol": protocol.lower() or None,
                    "source": "guest_pcap",
                }
            )
        # MobSF's HTTPS proxy is carried over the ADB tunnel. The bridge PCAP
        # therefore sees TCP/5555 rather than the application's destinations;
        # retain MobSF's independently captured proxy destinations as observed
        # telemetry and label their provenance explicitly.
        seen: set[tuple[str | None, str | None, int | None]] = {
            (
                item.get("destination_domain"),
                item.get("destination_ip"),
                item.get("destination_port"),
            )
            for item in observations
        }
        sidecar_events = pcap.parent / "mitmproxy" / "events.jsonl"
        if sidecar_events.is_file():
            for raw in sidecar_events.read_text(errors="replace").splitlines()[:10000]:
                try:
                    event = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict) or event.get("event") not in {"request", "error"}:
                    continue
                host = str(event.get("host") or "").rstrip(".").lower()
                port = event.get("port")
                port = int(port) if isinstance(port, int | str) and str(port).isdigit() else None
                if not host:
                    continue
                key = (host, None, port)
                if key in seen:
                    continue
                seen.add(key)
                observations.append(
                    {
                        "observed_at": event.get("observed_at"),
                        "destination_ip": None,
                        "destination_port": port,
                        "destination_domain": host,
                        "protocol": str(event.get("scheme") or "https_proxy"),
                        "source": "mitmproxy_sidecar",
                        "provenance": {
                            "transport": "isolated_explicit_proxy",
                            "event": event.get("event"),
                            "upstream": "none",
                        },
                    }
                )
        captured_at = datetime.now(timezone.utc).isoformat()
        pcap_digest = sha256_file(pcap)
        proxy_sources: list[tuple[dict[str, Any], str, str]] = []
        if isinstance(checkpoint_document, dict):
            checkpoints = checkpoint_document.get("checkpoints") or []
            for item in checkpoints if isinstance(checkpoints, list) else []:
                if isinstance(item, dict) and item.get("status") == "ok":
                    proxy_sources.append(
                        (
                            item,
                            str(item.get("captured_at") or captured_at),
                            str(item.get("reason") or "periodic"),
                        )
                    )
        if isinstance(dynamic, dict):
            proxy_sources.append((dynamic, captured_at, "final_dynamic_report"))
        for proxy_report, observed_at, checkpoint_reason in proxy_sources:
            domains = proxy_report.get("domains") or {}
            if isinstance(domains, dict):
                for domain, metadata in domains.items():
                    if not isinstance(domain, str) or not domain.strip():
                        continue
                    detail = metadata if isinstance(metadata, dict) else {}
                    geolocation = detail.get("geolocation") or {}
                    address = geolocation.get("ip") if isinstance(geolocation, dict) else None
                    domain_key = (domain.rstrip(".").lower(), address, None)
                    if domain_key in seen:
                        continue
                    seen.add(domain_key)
                    observations.append(
                        {
                            "observed_at": observed_at,
                            "destination_ip": address,
                            "destination_port": None,
                            "destination_domain": domain_key[0],
                            "protocol": "https_proxy",
                            "source": "mobsf_proxy_checkpoint",
                            "provenance": {
                                "transport": "adb_reverse_https_proxy",
                                "checkpoint_reason": checkpoint_reason,
                                "pcap_sha256": pcap_digest,
                            },
                        }
                    )
            urls = proxy_report.get("urls") or []
            for raw in urls if isinstance(urls, list) else []:
                value = (
                    raw
                    if isinstance(raw, str)
                    else raw.get("url")
                    if isinstance(raw, dict)
                    else None
                )
                if not value:
                    continue
                parsed = urlparse(str(value))
                if not parsed.hostname:
                    continue
                port = parsed.port or (
                    443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None
                )
                url_key = (parsed.hostname.lower(), None, port)
                if url_key in seen:
                    continue
                seen.add(url_key)
                observations.append(
                    {
                        "observed_at": observed_at,
                        "destination_ip": None,
                        "destination_port": port,
                        "destination_domain": url_key[0],
                        "protocol": parsed.scheme.lower() or "proxy",
                        "source": "mobsf_proxy_checkpoint",
                        "provenance": {
                            "transport": "adb_reverse_https_proxy",
                            "checkpoint_reason": checkpoint_reason,
                            "pcap_sha256": pcap_digest,
                        },
                    }
                )
        self._json(
            destination,
            {
                "schema_version": "1.0",
                "guest_ip": guest_ip,
                "capture_size_bytes": pcap.stat().st_size,
                "observations": observations,
                "parser_status": "ok" if result.returncode == 0 else "partial",
                "parser_error": result.stderr.decode(errors="replace")[:2000] or None,
                "proxy_checkpoint_count": len(proxy_sources),
            },
        )

    def _execute_interactive_command(
        self,
        avd: RedroidManager,
        scan_hash: str,
        package_name: str | None,
        static_report: dict[str, Any],
        command_type: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        if command_type in {"screen", "screenshot"}:
            return {"image_base64": base64.b64encode(avd.screenshot()).decode()}
        if command_type == "tap":
            avd.input_tap(int(payload["x"]), int(payload["y"]))
        elif command_type == "swipe":
            avd.input_swipe(
                int(payload["x1"]),
                int(payload["y1"]),
                int(payload["x2"]),
                int(payload["y2"]),
                int(payload["duration_ms"]),
            )
        elif command_type == "key":
            avd.input_key(int(payload["keycode"]))
        elif command_type == "text":
            avd.input_text(str(payload["text"]))
        elif command_type == "start_activity":
            activity = str(payload["activity"])
            if package_name and activity.startswith("."):
                component = f"{package_name}/{package_name}{activity}"
            elif "/" in activity:
                component = activity
            elif package_name:
                component = f"{package_name}/{activity}"
            else:
                raise RuntimeError("package name is unavailable")
            assert package_name is not None
            # Start from a stopped package so the requested activity lifecycle is
            # reproducible.  A warm launcher task can otherwise hide onCreate
            # behavior such as the sample's network initialization.
            avd._adb(  # noqa: SLF001 - executor owns the isolated manager
                "-s",
                avd.adb_address,
                "shell",
                "am",
                "force-stop",
                package_name,
                check=False,
            )
            activity_process = avd._adb(  # noqa: SLF001 - executor owns the isolated manager
                "-s",
                avd.adb_address,
                "shell",
                "am",
                "start",
                "-W",
                "-n",
                component,
                check=False,
            )
            output = (activity_process.stdout + activity_process.stderr).decode(errors="replace")
            if activity_process.returncode != 0 or "Error:" in output:
                raise RuntimeError(output[:2000])
            return {"status": "ok", "component": component, "output": output[:8192]}
        elif command_type == "deeplink":
            value = str(payload["url"])
            result = avd._adb(  # noqa: SLF001 - executor owns the isolated manager
                "-s",
                avd.adb_address,
                "shell",
                "am",
                "start",
                "-a",
                "android.intent.action.VIEW",
                "-d",
                value,
                check=False,
            )
            return {"output": (result.stdout + result.stderr).decode(errors="replace")[:8192]}
        elif command_type == "logcat":
            return {"logcat": avd.logcat_tail()}
        elif command_type == "api_monitor":
            return self.mobsf.api_monitor(scan_hash)
        elif command_type == "frida_logs":
            return self.mobsf.frida_logs(scan_hash)
        elif command_type == "frida":
            data = dict(payload)
            data["frida_action"] = data.pop("action")
            if data["frida_action"] == "session" and package_name:
                process_ids = avd.package_process_ids(package_name)
                if not process_ids:
                    raise RuntimeError("analyzed package process is not running")
                data["pid"] = process_ids[0]
                data["new_package"] = package_name
            frida_result = self.mobsf.android_operation("frida", scan_hash, data)
            if frida_result.get("status") == "failed":
                raise RuntimeError(str(frida_result.get("message") or "Frida operation failed"))
            return frida_result | {
                "selected_default_hooks": data.get("default_hooks", "").split(",")
                if data.get("default_hooks")
                else [],
                "selected_auxiliary_hooks": data.get("auxiliary_hooks", "").split(",")
                if data.get("auxiliary_hooks")
                else [],
                "attached_pid": data.get("pid") or None,
            }
        elif command_type == "activity_test":
            if payload.get("test") == "exported":
                counts = static_report.get("exported_count") or {}
                exported = static_report.get("exported_activities")
                if counts.get("exported_activities") == 0 or exported in {None, "[]"}:
                    return {
                        "status": "ok",
                        "activities_tested": 0,
                        "message": "No exported activities were identified in the APK.",
                    }
            activity_result = self.mobsf.android_operation("activity", scan_hash, payload)
            activity_result["image_base64"] = base64.b64encode(avd.screenshot()).decode()
            return activity_result
        elif command_type == "tls_test":
            return self.mobsf.android_operation("tls_tests", scan_hash)
        elif command_type == "proxy":
            return self.mobsf.android_operation("global_proxy", scan_hash, payload)
        elif command_type == "root_ca":
            return self.mobsf.android_operation("root_ca", scan_hash, payload)
        elif command_type == "dependencies":
            return self.mobsf.android_operation("dependencies", scan_hash)
        elif command_type == "app_data":
            return {"message": "Application data will be collected during finalization"}
        elif command_type == "list_files":
            if not package_name:
                raise RuntimeError("package name is unavailable")
            return {"files": avd.list_app_files(package_name, str(payload["path"]))}
        elif command_type == "read_file":
            if not package_name:
                raise RuntimeError("package name is unavailable")
            file_value = avd.read_app_file(package_name, str(payload["path"]))
            return {
                "content_base64": base64.b64encode(file_value).decode(),
                "size_bytes": len(file_value),
            }
        elif command_type == "finalize":
            return {"message": "Session finalization accepted"}
        else:
            raise RuntimeError("unsupported interactive Android command")
        return {"status": "ok"}

    def _heartbeat(self, claim: dict[str, Any], common: dict[str, Any]) -> None:
        body = common | {"state": "running"}
        response = self.mutate(
            f"/api/internal/v1/stages/{claim['stage_id']}/heartbeat", body, claim["lease_token"]
        )
        response.raise_for_status()
        raise_for_stop(response.json())

    def _download_sample(self, claim: dict[str, Any], workspace: Path) -> Path:
        path = claim["sample_download_path"]
        body = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"], "sample": True}
        destination, digest = workspace / "sample.apk", hashlib.sha256()
        with self.client.stream(
            "GET",
            path,
            params={"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]},
            headers=self.signed("GET", path, body, claim["lease_token"]),
        ) as response:
            response.raise_for_status()
            with destination.open("xb") as output:
                for chunk in response.iter_bytes():
                    digest.update(chunk)
                    output.write(chunk)
        if digest.hexdigest() != claim["sample_sha256"]:
            raise RuntimeError("downloaded sample digest mismatch")
        return destination

    def _upload(self, claim: dict[str, Any], source: Path, kind: str, media_type: str) -> None:
        envelope = {
            "lease_id": claim["lease_id"],
            "attempt_id": claim["attempt_id"],
            "kind": kind,
            "sha256": sha256_file(source),
            "size_bytes": source.stat().st_size,
            "media_type": media_type,
            "access_tier": "analyst",
            "bundle_id": None,
        }
        path = f"/api/internal/v1/stages/{claim['stage_id']}/artifacts"
        with source.open("rb") as stream:
            response = self.client.post(
                path,
                data={"envelope": json.dumps(envelope)},
                files={"file": (f"{kind}.bin", stream, media_type)},
                headers=self.signed("POST", path, envelope, claim["lease_token"]),
            )
        response.raise_for_status()

    @staticmethod
    def _main_activity(report: dict[str, Any]) -> str | None:
        value = report.get("main_activity")
        if value:
            return str(value)
        activities = report.get("activities")
        return str(activities[0]) if isinstance(activities, list) and activities else None

    @staticmethod
    def _json(path: Path, value: dict[str, Any]) -> None:
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

    @staticmethod
    def _static_prior(report: dict[str, Any], claim: dict[str, Any]) -> dict[str, Any]:
        values: set[tuple[str, str]] = set()
        domains = report.get("domains") or {}
        for domain in domains.keys() if isinstance(domains, dict) else []:
            values.add(("domain", str(domain)))
        for url in report.get("urls") or []:
            if isinstance(url, str):
                values.add(("url", url))
            elif isinstance(url, dict) and url.get("url"):
                values.add(("url", str(url["url"])))
        return {
            "schema_version": "1.1",
            "analysis_run_id": claim["analysis_run_id"],
            "sample_sha256": claim["sample_sha256"],
            "evidence_origin": "binary_static",
            "iocs": [
                {
                    "type": kind,
                    "value": value,
                    "confidence": "unconfirmed",
                    "source": "mobsf_static",
                    "evidence_origin": "binary_static",
                }
                for kind, value in sorted(values)
            ],
        }


@app.command()
def run(
    umat_url: str = typer.Option("http://127.0.0.1:8080", envvar="UMAT_EXECUTOR_URL"),
    mobsf_url: str = typer.Option(..., envvar="UMAT_MOBSF_URL"),
    mobsf_api_key: str = typer.Option(..., envvar="MOBSF_API_KEY"),
    avdmanager: Path = typer.Option(..., envvar="UMAT_ANDROID_AVDMANAGER"),
    emulator: Path = typer.Option(..., envvar="UMAT_ANDROID_EMULATOR"),
    adb: Path = typer.Option(..., envvar="UMAT_ANDROID_ADB"),
    system_image: str = typer.Option("system-images;android-30;default;x86_64"),
    emulator_port: int = typer.Option(5554),
    adb_relay: Path | None = typer.Option(None, envvar="UMAT_ANDROID_ADB_RELAY"),
    adb_relay_bind_address: str | None = typer.Option(
        None, envvar="UMAT_ANDROID_ADB_RELAY_BIND_ADDRESS"
    ),
    work_root: Path = typer.Option(Path("var/android-work"), envvar="UMAT_ANDROID_WORK_ROOT"),
    state_path: Path = typer.Option(
        Path("var/android-executor/state.json"), envvar="UMAT_ANDROID_STATE_PATH"
    ),
    enrollment_token: str | None = typer.Option(None, envvar="UMAT_ANDROID_ENROLLMENT_TOKEN"),
    name: str = typer.Option("android-executor", envvar="UMAT_ANDROID_EXECUTOR_NAME"),
    enroll_only: bool = typer.Option(False, help="Enroll and publish capabilities, then exit"),
    stimulation_seconds: int = typer.Option(30, min=1, max=600),
    stimulation_actions: int = typer.Option(20, min=1, max=500),
    mobsf_container: str = typer.Option("android-mobsf-1", envvar="UMAT_ANDROID_MOBSF_CONTAINER"),
    once: bool = typer.Option(False),
    poll_seconds: float = typer.Option(5.0, min=0.5),
    egress_broker_url: str = typer.Option("http://127.0.0.1:8092", envvar="UMAT_EGRESS_BROKER_URL"),
    egress_broker_token: str | None = typer.Option(None, envvar="UMAT_EGRESS_BROKER_TOKEN"),
    egress_guest_ip: str | None = typer.Option(None, envvar="UMAT_ANDROID_EGRESS_GUEST_IP"),
    mitmproxy_image: str = typer.Option(MITMPROXY_IMAGE, envvar="UMAT_ANDROID_MITMPROXY_IMAGE"),
    exit_after_analysis: bool = typer.Option(
        False, envvar="UMAT_ANDROID_EXIT_AFTER_ANALYSIS"
    ),
) -> None:
    work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    executor_process = AndroidExecutor(
        umat_url=umat_url,
        state_path=state_path,
        mobsf=MobSFClient(mobsf_url, mobsf_api_key),
        work_root=work_root,
        avdmanager=avdmanager,
        emulator=emulator,
        adb=adb,
        system_image=system_image,
        emulator_port=emulator_port,
        adb_relay=adb_relay,
        adb_relay_bind_address=adb_relay_bind_address,
        stimulation_seconds=stimulation_seconds,
        stimulation_actions=stimulation_actions,
        mobsf_container=mobsf_container,
        egress=EgressClient(egress_broker_url, egress_broker_token)
        if egress_broker_token
        else None,
        egress_guest_ip=egress_guest_ip,
        mitmproxy_image=mitmproxy_image,
    )
    if not executor_process.state:
        if not enrollment_token:
            raise typer.BadParameter("enrollment-token is required on first run")
        executor_process.enroll(enrollment_token, name)
    if enroll_only:
        return
    while True:
        processed = executor_process.process_stage()
        if processed and exit_after_analysis:
            return
        if once:
            return
        if not processed:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    app()
