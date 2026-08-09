from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import typer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from umat.android.avd import AvdManager
from umat.android.bundle import ANDROID_COMMIT, MOBSF_VERSION, AndroidBundleBuilder, sha256_file
from umat.android.mobsf import MobSFClient
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
    ) -> None:
        self.client = httpx.Client(base_url=umat_url.rstrip("/"), timeout=120)
        self.state_path = state_path
        self.mobsf = mobsf
        self.work_root = work_root.resolve()
        self.avdmanager, self.emulator, self.adb = avdmanager, emulator, adb
        self.system_image, self.emulator_port = system_image, emulator_port
        self.adb_relay = adb_relay
        self.adb_relay_bind_address = adb_relay_bind_address
        self.stimulation_seconds, self.stimulation_actions = stimulation_seconds, stimulation_actions
        self.state: dict[str, Any] = json.loads(state_path.read_text()) if state_path.is_file() else {}

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
        timestamp, nonce, key = datetime.now(timezone.utc).isoformat(), uuid.uuid4().hex, str(uuid.uuid4())
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
                    scan_hash = str(recovered["native_task_id"])
                else:
                    uploaded = self.mobsf.upload(sample)
                    scan_hash = str(uploaded.get("hash") or uploaded.get("scan_hash") or "")
                    if len(scan_hash) != 32 or any(char not in "0123456789abcdefABCDEF" for char in scan_hash):
                        raise RuntimeError("MobSF upload returned an invalid scan hash")
                    native = common | {
                        "task_type": "mobsf_scan",
                        "native_task_id": scan_hash,
                        "recovery_metadata": {
                            "analysis_run_id": claim["analysis_run_id"],
                            "file_name": uploaded.get("file_name"),
                        },
                    }
                    self.mutate(
                        f"/api/internal/v1/stages/{claim['stage_id']}/native-task",
                        native,
                        claim["lease_token"],
                    ).raise_for_status()
                outcome, detail = self._analyze_with_heartbeats(
                    claim, common, workspace, scan_hash, recovered=bool(recovered)
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
            while not stopped.wait(15):
                try:
                    self._heartbeat(claim, common)
                except ExecutorStopRequested as stop:
                    stop_reasons.append(stop.reason)
                    stop_requested.set()
                    return
                except Exception as exc:
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
        avd_name = f"umat-{claim['analysis_run_id'].replace('-', '')[:20]}"
        avd = AvdManager(
            avdmanager=self.avdmanager,
            emulator=self.emulator,
            adb=self.adb,
            system_image=self.system_image,
            emulator_port=self.emulator_port,
            adb_relay=self.adb_relay,
            adb_relay_bind_address=self.adb_relay_bind_address,
        )
        dynamic: dict[str, Any] | None = None
        stimulation: dict[str, Any] = {
            "strategy": "deterministic_adb_v1", "actions_completed": 0, "complete": False
        }
        evidence: dict[str, Path] = {}
        running = None
        try:
            running = avd.start(avd_name, workspace)
            check_stop()
            self.mobsf.start_dynamic(scan_hash)
            activity = self._main_activity(static)
            if activity:
                self.mobsf.start_activity(scan_hash, activity)
            try:
                self.mobsf.instrument(scan_hash)
            except Exception:
                caveats.append("android_api_monitoring_failed")
            stimulation = avd.stimulate(self.stimulation_seconds, self.stimulation_actions)
            check_stop()
            if not stimulation.get("complete"):
                caveats.append("stimulation_incomplete")
            evidence.update(avd.collect(workspace / "device-evidence"))
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
            try:
                self.mobsf.stop_dynamic(scan_hash)
            except Exception:
                caveats.append("android_dynamic_stop_failed")
            raise
        except Exception:
            caveats.extend(["static_analysis_only", "network_capture_incomplete"])
            try:
                self.mobsf.stop_dynamic(scan_hash)
            except Exception:
                caveats.append("android_dynamic_stop_failed")
        finally:
            avd.stop()
        pcap = workspace / "android-capture.pcap"
        if not pcap.is_file() or pcap.stat().st_size == 0:
            raise RuntimeError("Android analysis did not produce a non-empty PCAP")
        evidence["pcap"] = pcap
        dynamic_path: Path | None = None
        if dynamic is not None:
            dynamic_path = workspace / "mobsf-dynamic.json"
            self._json(dynamic_path, dynamic)
        ended = datetime.now(timezone.utc)
        emulator_metadata = {
            "api_level": 30,
            "avd_name": avd_name,
            "guest_ip": running.guest_ip if running else None,
            "system_image": self.system_image,
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
        self._upload(claim, bundle.root / "umat-manifest.json", "platform_manifest", "application/json")
        self._upload(claim, pcap, "pcap", "application/vnd.tcpdump.pcap")
        prior = self._static_prior(static, claim)
        prior_path = workspace / "c2-static-prior.json"
        self._json(prior_path, prior)
        self._upload(claim, prior_path, "static_prior", "application/json")
        return (
            ("partial", "Static analysis completed; dynamic evidence is incomplete")
            if dynamic is None
            else ("completed", "MobSF static/dynamic analysis bundle validated and registered")
        )

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
            "schema_version": "1.0",
            "analysis_run_id": claim["analysis_run_id"],
            "sample_sha256": claim["sample_sha256"],
            "iocs": [
                {"type": kind, "value": value, "confidence": "unconfirmed"}
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
    system_image: str = typer.Option("system-images;android-30;google_apis;x86_64"),
    emulator_port: int = typer.Option(5554),
    adb_relay: Path | None = typer.Option(None, envvar="UMAT_ANDROID_ADB_RELAY"),
    adb_relay_bind_address: str | None = typer.Option(
        None, envvar="UMAT_ANDROID_ADB_RELAY_BIND_ADDRESS"
    ),
    work_root: Path = typer.Option(
        Path("var/android-work"), envvar="UMAT_ANDROID_WORK_ROOT"
    ),
    state_path: Path = typer.Option(
        Path("var/android-executor/state.json"), envvar="UMAT_ANDROID_STATE_PATH"
    ),
    enrollment_token: str | None = typer.Option(
        None, envvar="UMAT_ANDROID_ENROLLMENT_TOKEN"
    ),
    name: str = typer.Option("android-executor", envvar="UMAT_ANDROID_EXECUTOR_NAME"),
    enroll_only: bool = typer.Option(False, help="Enroll and publish capabilities, then exit"),
    stimulation_seconds: int = typer.Option(30, min=1, max=600),
    stimulation_actions: int = typer.Option(20, min=1, max=500),
    once: bool = typer.Option(False),
    poll_seconds: float = typer.Option(5.0, min=0.5),
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
    )
    if not executor_process.state:
        if not enrollment_token:
            raise typer.BadParameter("enrollment-token is required on first run")
        executor_process.enroll(enrollment_token, name)
    if enroll_only:
        return
    while True:
        processed = executor_process.process_stage()
        if once:
            return
        if not processed:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    app()
