from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import typer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from umat.c2.bundle import ResultBundleBuilder, sha256_file
from umat.c2.input_builder import C2InputBuilder
from umat.c2.models import InputArtifact
from umat.c2.runtime import C2Runtime, FixtureC2Runtime, SubprocessC2Runtime
from umat.executors.protocol import ExecutorStopRequested, raise_for_stop, signature_message

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Run the isolated C2 executor."""


class C2ExecutorError(RuntimeError):
    pass


class C2Executor:
    def __init__(
        self,
        base_url: str,
        state_path: Path,
        work_root: Path,
        runtime: C2Runtime,
        max_result_bytes: int,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.state_path = state_path
        self.work_root = work_root.resolve()
        self.runtime = runtime
        self.max_result_bytes = max_result_bytes
        self.client = httpx.Client(base_url=self.base_url, timeout=60)
        self.state: dict[str, Any] = (
            json.loads(state_path.read_text()) if state_path.is_file() else {}
        )

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(self.state["private_key"]))

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_path.write_text(json.dumps(self.state, indent=2, sort_keys=True) + "\n")
        self.state_path.chmod(0o600)

    def enroll(self, token: str, name: str) -> None:
        private_key = Ed25519PrivateKey.generate()
        private_raw = private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        public_raw = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        response = self.client.post(
            "/api/internal/v1/executors/register",
            json={
                "enrollment_token": token,
                "name": name,
                "public_key": base64.b64encode(public_raw).decode(),
                "metadata": {"implementation": "umat-c2-executor", "isolation": "subprocess"},
            },
        )
        response.raise_for_status()
        registered = response.json()
        self.state = {
            "executor_id": registered["executor_id"],
            "credential": registered["credential"],
            "private_key": base64.b64encode(private_raw).decode(),
            "name": name,
        }
        self._save()
        capabilities = self.client.post(
            "/api/internal/v1/executors/capabilities",
            headers=self.auth_headers(),
            json={
                "schema_version": "1.0",
                "runtime_identity": self.runtime.identity,
                "supported_stage_types": ["c2_analysis"],
                "capabilities": {
                    "native_event_schema_version": "1.3",
                    "platforms": ["windows", "android"],
                    "android_mode": "network_only",
                },
            },
        )
        capabilities.raise_for_status()

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.state['credential']}"}

    def signed_headers(
        self, method: str, path: str, body: dict[str, Any], lease_token: str
    ) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = uuid.uuid4().hex
        idempotency_key = str(uuid.uuid4())
        message = signature_message(
            method=method,
            path=path,
            timestamp=timestamp,
            nonce=nonce,
            idempotency_key=idempotency_key,
            body=body,
        )
        return self.auth_headers() | {
            "X-UMAT-Timestamp": timestamp,
            "X-UMAT-Nonce": nonce,
            "Idempotency-Key": idempotency_key,
            "X-UMAT-Signature": base64.b64encode(self.private_key.sign(message)).decode(),
            "X-UMAT-Lease-Token": lease_token,
        }

    def mutate(
        self, path: str, body: dict[str, Any], lease_token: str, client: httpx.Client | None = None
    ) -> httpx.Response:
        active_client = client or self.client
        return active_client.post(
            path,
            json=body,
            headers=self.signed_headers("POST", path, body, lease_token),
        )

    def claim(self) -> dict[str, Any] | None:
        response = self.client.post(
            "/api/internal/v1/executors/claim",
            headers=self.auth_headers(),
            json={"stage_types": ["c2_analysis"]},
        )
        response.raise_for_status()
        return response.json() if response.content not in {b"", b"null"} else None

    def _download_inputs(self, claim: dict[str, Any], destination: Path) -> list[InputArtifact]:
        artifacts: list[InputArtifact] = []
        for descriptor in claim["input_artifacts"]:
            body = {
                "lease_id": claim["lease_id"],
                "attempt_id": claim["attempt_id"],
                "artifact_id": descriptor["artifact_id"],
            }
            path = str(descriptor["download_path"])
            local_path = destination / f"input-{descriptor['artifact_id']}"
            digest = hashlib.sha256()
            total = 0
            with self.client.stream(
                "GET",
                path,
                params={"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]},
                headers=self.signed_headers("GET", path, body, claim["lease_token"]),
            ) as response:
                response.raise_for_status()
                with local_path.open("xb") as output:
                    for chunk in response.iter_bytes():
                        total += len(chunk)
                        if total > int(descriptor["size_bytes"]):
                            raise C2ExecutorError("input artifact exceeds declared length")
                        digest.update(chunk)
                        output.write(chunk)
            if total != int(descriptor["size_bytes"]) or digest.hexdigest() != descriptor["sha256"]:
                raise C2ExecutorError("input artifact identity verification failed")
            local_path.chmod(0o400)
            artifacts.append(InputArtifact(local_path=local_path, **descriptor))
        return artifacts

    @contextmanager
    def _heartbeat(self, claim: dict[str, Any]) -> Iterator[tuple[threading.Event, list[str]]]:
        stop = threading.Event()
        stop_requested = threading.Event()
        stop_reasons: list[str] = []
        errors: list[BaseException] = []
        common = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]}

        def renew() -> None:
            with httpx.Client(base_url=self.base_url, timeout=30) as client:
                while not stop.wait(15):
                    try:
                        response = self.mutate(
                            f"/api/internal/v1/stages/{claim['stage_id']}/heartbeat",
                            common | {"state": "running"},
                            claim["lease_token"],
                            client,
                        )
                        response.raise_for_status()
                        try:
                            raise_for_stop(response.json())
                        except ExecutorStopRequested as requested:
                            stop_reasons.append(requested.reason)
                            stop_requested.set()
                            stop.set()
                    except BaseException as exc:
                        errors.append(exc)
                        stop.set()

        initial = self.mutate(
            f"/api/internal/v1/stages/{claim['stage_id']}/heartbeat",
            common | {"state": "running"},
            claim["lease_token"],
        )
        initial.raise_for_status()
        raise_for_stop(initial.json())
        worker = threading.Thread(target=renew, daemon=True, name="c2-lease-heartbeat")
        worker.start()
        try:
            yield stop_requested, stop_reasons
            if errors:
                raise C2ExecutorError(f"lease heartbeat failed: {errors[0]}")
        finally:
            stop.set()
            worker.join(timeout=5)

    def process_once(self) -> bool:
        claim = self.claim()
        if not claim:
            return False
        common = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]}
        try:
            native_task = self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/native-task",
                common
                | {
                    "task_type": "c2-local",
                    "native_task_id": f"c2-{claim['analysis_run_id']}",
                    "recovery_metadata": {"runtime_identity": self.runtime.identity},
                },
                claim["lease_token"],
            )
            native_task.raise_for_status()
            with tempfile.TemporaryDirectory(
                prefix=f"umat-c2-executor-{claim['analysis_run_id']}-", dir=self.work_root
            ) as temporary:
                temporary_root = Path(temporary)
                with self._heartbeat(claim) as cancellation:
                    artifacts = self._download_inputs(claim, temporary_root)
                    context = C2InputBuilder().build(
                        analysis_run_id=claim["analysis_run_id"],
                        platform=claim["platform"],
                        sample_sha256=claim["sample_sha256"],
                        artifacts=artifacts,
                    )
                    stop_requested, stop_reasons = cancellation
                    native = self.runtime.run(
                        context,
                        self.work_root / "runtime",
                        stop_requested,
                        lambda: stop_reasons[-1] if stop_reasons else "cancelled",
                    )
                    bundle = ResultBundleBuilder(
                        self.private_key, str(self.state["executor_id"])
                    ).build(context, native, temporary_root / "result")
                    if bundle.archive_path.stat().st_size > self.max_result_bytes:
                        raise C2ExecutorError("C2 result bundle exceeds configured limit")
                    self._upload_bundle(claim, bundle.archive_path)
            complete = self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/complete",
                common | {"outcome": "completed", "detail": "C2 bundle registered"},
                claim["lease_token"],
            )
            complete.raise_for_status()
            return True
        except ExecutorStopRequested as stop:
            if stop.reason == "cancelled":
                acknowledgement = common | {"detail": "C2 runtime stopped"}
                response = self.mutate(
                    f"/api/internal/v1/stages/{claim['stage_id']}/cancellation-ack",
                    acknowledgement,
                    claim["lease_token"],
                )
                response.raise_for_status()
            return True
        except Exception as exc:
            failure = self.mutate(
                f"/api/internal/v1/stages/{claim['stage_id']}/fail",
                common
                | {
                    "error_code": "c2_executor_failure",
                    "detail": str(exc)[:2000],
                    "retryable": True,
                },
                claim["lease_token"],
            )
            failure.raise_for_status()
            return True

    def _upload_bundle(self, claim: dict[str, Any], archive: Path) -> None:
        digest = sha256_file(archive)
        common = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]}
        envelope = common | {
            "kind": "c2_bundle",
            "sha256": digest,
            "size_bytes": archive.stat().st_size,
            "media_type": "application/zip",
            "access_tier": "analyst",
            "bundle_id": str(uuid.uuid4()),
        }
        path = f"/api/internal/v1/stages/{claim['stage_id']}/artifacts"
        with archive.open("rb") as source:
            response = self.client.post(
                path,
                data={"envelope": json.dumps(envelope)},
                files={"file": ("c2-result.zip", source, "application/zip")},
                headers=self.signed_headers("POST", path, envelope, claim["lease_token"]),
            )
        response.raise_for_status()


@app.command()
def run(
    base_url: str = typer.Option("http://127.0.0.1:8080", envvar="UMAT_EXECUTOR_URL"),
    state_path: Path = typer.Option(
        Path("var/c2-executor/state.json"), envvar="UMAT_C2_STATE_PATH"
    ),
    work_root: Path = typer.Option(Path("var/c2-work"), envvar="UMAT_C2_WORK_ROOT"),
    runtime_root: Path | None = typer.Option(None, envvar="UMAT_C2_RUNTIME_ROOT"),
    runtime_commit: str = typer.Option("bc5bb681495a02fa0ff2411087e5a00ece5b1ca3"),
    runtime_patch_sha256: str = typer.Option(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    ),
    runtime_timeout_seconds: int = typer.Option(1800, min=1),
    max_result_bytes: int = typer.Option(1024 * 1024 * 1024, min=1),
    fixture_runtime: bool = typer.Option(False, help="Use deterministic test runtime"),
    enrollment_token: str | None = typer.Option(None, envvar="UMAT_C2_ENROLLMENT_TOKEN"),
    name: str = typer.Option("c2-executor", envvar="UMAT_C2_EXECUTOR_NAME"),
    enroll_only: bool = typer.Option(False, help="Enroll and publish capabilities, then exit"),
    once: bool = typer.Option(False),
    poll_seconds: float = typer.Option(2.0, min=0.1),
) -> None:
    work_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if fixture_runtime:
        runtime: C2Runtime = FixtureC2Runtime()
    else:
        if runtime_root is None:
            raise typer.BadParameter("runtime-root is required unless fixture-runtime is enabled")
        runtime = SubprocessC2Runtime(
            runtime_root,
            runtime_commit,
            runtime_timeout_seconds,
            runtime_patch_sha256,
        )
    executor = C2Executor(base_url, state_path, work_root, runtime, max_result_bytes)
    if not executor.state:
        if not enrollment_token:
            raise typer.BadParameter("enrollment-token is required on first run")
        executor.enroll(enrollment_token, name)
    if enroll_only:
        return
    while True:
        processed = executor.process_once()
        if once:
            return
        if not processed:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    app()
