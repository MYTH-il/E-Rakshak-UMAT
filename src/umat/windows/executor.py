from __future__ import annotations

import base64
import hashlib
import json
import tempfile
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

from umat.contracts import ContractError
from umat.executors.protocol import ExecutorStopRequested, raise_for_stop, signature_message
from umat.windows.bundle import (
    NativeWindowsValidator,
    WindowsBundleBuilder,
    sha256_file,
)
from umat.windows.cape import CapeClient

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Run the CAPE/WinST-DT Windows executor."""


class WindowsExecutor:
    def __init__(
        self,
        umat_url: str,
        state_path: Path,
        cape: CapeClient,
        handoff_root: Path,
        schema_root: Path,
        work_root: Path,
    ) -> None:
        self.client = httpx.Client(base_url=umat_url.rstrip("/"), timeout=60)
        self.state_path, self.cape = state_path, cape
        self.handoff_root, self.work_root = handoff_root.resolve(), work_root.resolve()
        self.native_validator = NativeWindowsValidator(schema_root)
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
                "metadata": {"implementation": "umat-windows-executor", "cape_only": True},
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
                "runtime_identity": "winstdt@7bc74765e9d38d7ba6df3f2115db67761cb4cbd8",
                "supported_stage_types": ["platform_analysis"],
                "capabilities": {
                    "platforms": ["windows"],
                    "cape_native": True,
                    "vm_profile_management": True,
                    "handoff_schema": "1.0",
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

    def process_profile_operation(self) -> bool:
        response = self.client.post(
            "/api/internal/v1/executors/windows/profile-operations/claim", headers=self.auth()
        )
        response.raise_for_status()
        if response.content in {b"", b"null"}:
            return False
        operation = response.json()
        profile, success, detail, native_id, label = operation["profile"], True, None, None, None
        try:
            if operation["operation_type"] == "create":
                native_id, label = self.cape.create_machine(profile)
            else:
                label = profile.get("cape_machine_label")
                if not label:
                    raise RuntimeError("profile has no CAPE machine label")
                native_id = self.cape.delete_machine(str(label))
        except Exception as exc:
            success, detail = False, str(exc)[:2000]
        body = {
            "operation_id": operation["operation_id"],
            "success": success,
            "native_operation_id": native_id,
            "cape_machine_label": label,
            "detail": detail,
        }
        path = f"/api/internal/v1/executors/windows/profile-operations/{operation['operation_id']}/complete"
        completed = self.client.post(
            path, json=body, headers=self.signed("POST", path, body, operation["lease_token"])
        )
        completed.raise_for_status()
        return True

    def process_stage(self, poll_seconds: float) -> bool:
        response = self.client.post(
            "/api/internal/v1/executors/claim",
            headers=self.auth(),
            json={"stage_types": ["platform_analysis"], "platforms": ["windows"]},
        )
        response.raise_for_status()
        if response.content in {b"", b"null"}:
            return False
        claim = response.json()
        common = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]}
        try:
            recovered = claim.get("recovered_native_task")
            with tempfile.TemporaryDirectory(
                prefix=f"umat-windows-{claim['analysis_run_id']}-", dir=self.work_root
            ) as temporary:
                workspace = Path(temporary)
                if recovered:
                    task_id = int(recovered["native_task_id"])
                else:
                    sample = self._download_sample(claim, workspace)
                    task_id = self.cape.submit(sample, claim["execution_configuration"])
                    native = common | {
                        "task_type": "cape",
                        "native_task_id": str(task_id),
                        "recovery_metadata": {
                            "analysis_run_id": claim["analysis_run_id"],
                            "profile": claim["execution_configuration"],
                        },
                    }
                    self.mutate(
                        f"/api/internal/v1/stages/{claim['stage_id']}/native-task",
                        native,
                        claim["lease_token"],
                    ).raise_for_status()
                status_value = self._wait(claim, common, task_id, poll_seconds)
                if status_value.get("status") in {"failed_analysis", "failed_processing"}:
                    raise RuntimeError(f"CAPE task failed: {status_value}")
                native_root = self.handoff_root / str(task_id)
                self._wait_for_handoff(claim, common, native_root, poll_seconds)
                target = status_value.get("target")
                detected_type = (
                    target.get("file", {}).get("type") if isinstance(target, dict) else target
                )
                cape_evidence = self.cape.evidence(task_id)
                bundle = WindowsBundleBuilder(
                    self.private_key, str(self.state["executor_id"]), self.native_validator
                ).build(
                    analysis_run_id=UUID(claim["analysis_run_id"]),
                    sample_sha256=claim["sample_sha256"],
                    cape_task_id=task_id,
                    cape_package=status_value.get("package"),
                    detected_type=str(detected_type) if detected_type else None,
                    profile_snapshot=claim["execution_configuration"],
                    native_root=native_root,
                    destination=workspace / "windows-result",
                    cape_evidence=cape_evidence,
                )
                self._upload(claim, bundle.archive_path, "windows_bundle", "application/zip")
                self._upload_native_inputs(claim, native_root)
            complete = common | {
                "outcome": "completed",
                "detail": "WinST/DT bundle validated and registered",
            }
            self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/complete",
                complete,
                claim["lease_token"],
            ).raise_for_status()
        except ExecutorStopRequested as stop:
            if stop.reason == "cancelled":
                acknowledgement = common | {"detail": "CAPE task stopped"}
                self.mutate(
                    f"/api/internal/v1/stages/{claim['stage_id']}/cancellation-ack",
                    acknowledgement,
                    claim["lease_token"],
                ).raise_for_status()
        except ContractError as exc:
            failure = common | {
                "error_code": "windows_native_evidence_invalid",
                "detail": str(exc)[:2000],
                "retryable": False,
            }
            self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/fail",
                failure,
                claim["lease_token"],
            ).raise_for_status()
        except Exception as exc:
            failure = common | {
                "error_code": "windows_executor_failure",
                "detail": str(exc)[:2000],
                "retryable": True,
            }
            self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/fail", failure, claim["lease_token"]
            ).raise_for_status()
        return True

    def _download_sample(self, claim: dict[str, Any], workspace: Path) -> Path:
        path, body = (
            claim["sample_download_path"],
            {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"], "sample": True},
        )
        destination, digest = workspace / "sample.bin", hashlib.sha256()
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

    def _wait(
        self, claim: dict[str, Any], common: dict[str, Any], task_id: int, poll_seconds: float
    ) -> dict[str, Any]:
        while True:
            heartbeat = common | {"state": "running"}
            heartbeat_response = self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/heartbeat",
                heartbeat,
                claim["lease_token"],
            )
            heartbeat_response.raise_for_status()
            try:
                raise_for_stop(heartbeat_response.json())
            except ExecutorStopRequested:
                self.cape.cancel(task_id)
                raise
            value = self.cape.status(task_id)
            if value.get("status") in {
                "reported",
                "completed",
                "failed_analysis",
                "failed_processing",
            }:
                return value
            time.sleep(poll_seconds)

    def _wait_for_handoff(
        self,
        claim: dict[str, Any],
        common: dict[str, Any],
        native_root: Path,
        poll_seconds: float,
        timeout_seconds: int = 300,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            manifest = native_root / "manifest.json"
            hashes = native_root / "hashes.sha256"
            if manifest.is_file() and manifest.stat().st_size > 0 and hashes.is_file():
                return
            heartbeat = common | {"state": "running"}
            response = self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/heartbeat",
                heartbeat,
                claim["lease_token"],
            )
            response.raise_for_status()
            raise_for_stop(response.json())
            time.sleep(poll_seconds)
        raise RuntimeError("WinST/DT handoff was not published before the readiness deadline")

    def _upload_native_inputs(self, claim: dict[str, Any], native: Path) -> None:
        candidates = [
            (native / "manifest.json", "platform_manifest", "application/json"),
            (native / "network/capture.pcapng", "pcap", "application/vnd.tcpdump.pcap"),
            (native / "behavior/access_events.json", "access_events", "application/json"),
            (native / "analysis/c2-static-prior.json", "static_prior", "application/json"),
            (native / "behavior/trace.etl", "raw_etl", "application/octet-stream"),
        ]
        for path, kind, media_type in candidates:
            if path.is_file():
                self._upload(claim, path, kind, media_type)

    def _upload(self, claim: dict[str, Any], source_path: Path, kind: str, media_type: str) -> None:
        common = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]}
        envelope = common | {
            "kind": kind,
            "sha256": sha256_file(source_path),
            "size_bytes": source_path.stat().st_size,
            "media_type": media_type,
            "access_tier": "analyst",
            "bundle_id": None,
        }
        path = f"/api/internal/v1/stages/{claim['stage_id']}/artifacts"
        with source_path.open("rb") as source:
            response = self.client.post(
                path,
                data={"envelope": json.dumps(envelope)},
                files={"file": (f"{kind}.bin", source, media_type)},
                headers=self.signed("POST", path, envelope, claim["lease_token"]),
            )
        response.raise_for_status()


@app.command()
def run(
    umat_url: str = typer.Option("http://127.0.0.1:8080", envvar="UMAT_EXECUTOR_URL"),
    cape_url: str = typer.Option(..., envvar="UMAT_CAPE_URL"),
    cape_token: str | None = typer.Option(None, envvar="UMAT_CAPE_API_TOKEN"),
    cape_management_url: str | None = typer.Option(None, envvar="UMAT_CAPE_MANAGEMENT_URL"),
    cape_management_token: str | None = typer.Option(None, envvar="UMAT_CAPE_MANAGEMENT_TOKEN"),
    handoff_root: Path = typer.Option(
        Path("/srv/winstdt/handoff"), envvar="UMAT_WINDOWS_HANDOFF_ROOT"
    ),
    schema_root: Path = typer.Option(..., envvar="UMAT_WINDOWS_SCHEMA_ROOT"),
    work_root: Path = typer.Option(Path("var/windows-work"), envvar="UMAT_WINDOWS_WORK_ROOT"),
    state_path: Path = typer.Option(
        Path("var/windows-executor/state.json"), envvar="UMAT_WINDOWS_STATE_PATH"
    ),
    enrollment_token: str | None = typer.Option(None, envvar="UMAT_WINDOWS_ENROLLMENT_TOKEN"),
    name: str = typer.Option("windows-executor", envvar="UMAT_WINDOWS_EXECUTOR_NAME"),
    enroll_only: bool = typer.Option(False, help="Enroll and publish capabilities, then exit"),
    once: bool = typer.Option(False),
    poll_seconds: float = typer.Option(5.0, min=0.5),
) -> None:
    work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    executor = WindowsExecutor(
        umat_url,
        state_path,
        CapeClient(cape_url, cape_token, cape_management_url, cape_management_token),
        handoff_root,
        schema_root,
        work_root,
    )
    if not executor.state:
        if not enrollment_token:
            raise typer.BadParameter("enrollment-token is required on first run")
        executor.enroll(enrollment_token, name)
    if enroll_only:
        return
    while True:
        processed = executor.process_profile_operation() or executor.process_stage(poll_seconds)
        if once:
            return
        if not processed:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    app()
