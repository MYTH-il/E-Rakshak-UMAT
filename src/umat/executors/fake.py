from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import typer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from umat.contracts.canonical import canonical_json
from umat.executors.protocol import ExecutorStopRequested, raise_for_stop, signature_message

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    """Run the deterministic fake executor."""
ALL_STAGES = ["platform_analysis", "c2_analysis", "platform_adaptation", "c2_adaptation", "case_aggregation", "report_generation"]


class FakeExecutor:
    def __init__(self, base_url: str, state_path: Path) -> None:
        self.base_url = base_url.rstrip("/")
        self.state_path = state_path
        self.client = httpx.Client(base_url=self.base_url, timeout=30)
        self.state = json.loads(state_path.read_text()) if state_path.exists() else {}

    @property
    def private_key(self) -> Ed25519PrivateKey:
        raw = base64.b64decode(self.state["private_key"])
        return Ed25519PrivateKey.from_private_bytes(raw)

    def save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self.state, indent=2) + "\n")
        self.state_path.chmod(0o600)

    def enroll(self, enrollment_token: str, name: str, stage_types: list[str] | None = None) -> None:
        private = Ed25519PrivateKey.generate()
        private_raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        response = self.client.post("/api/internal/v1/executors/register", json={"enrollment_token": enrollment_token, "name": name, "public_key": base64.b64encode(public_raw).decode(), "metadata": {"implementation": "umat-fake-executor"}})
        response.raise_for_status()
        registered = response.json()
        self.state = {"executor_id": registered["executor_id"], "credential": registered["credential"], "private_key": base64.b64encode(private_raw).decode(), "name": name, "stage_types": stage_types or ALL_STAGES}
        self.save()
        response = self.client.post("/api/internal/v1/executors/capabilities", headers=self.auth_headers(), json={"schema_version": "1.0", "runtime_identity": "umat-fake/0.1.0", "supported_stage_types": stage_types or ALL_STAGES, "capabilities": {"fixture": True, "platforms": ["windows", "android"], "native_event_schema_version": "1.3"}})
        response.raise_for_status()

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.state['credential']}"}

    def signed_headers(self, method: str, path: str, body: dict[str, Any], lease_token: str) -> dict[str, str]:
        timestamp = datetime.now(timezone.utc).isoformat()
        nonce = uuid.uuid4().hex
        key = str(uuid.uuid4())
        message = signature_message(method=method, path=path, timestamp=timestamp, nonce=nonce, idempotency_key=key, body=body)
        return self.auth_headers() | {
            "X-UMAT-Timestamp": timestamp,
            "X-UMAT-Nonce": nonce,
            "Idempotency-Key": key,
            "X-UMAT-Signature": base64.b64encode(self.private_key.sign(message)).decode(),
            "X-UMAT-Lease-Token": lease_token,
        }

    def mutate(self, path: str, body: dict[str, Any], lease_token: str) -> httpx.Response:
        return self.client.post(path, json=body, headers=self.signed_headers("POST", path, body, lease_token))

    def claim(self) -> dict[str, Any] | None:
        response = self.client.post("/api/internal/v1/executors/claim", json={"stage_types": self.state.get("stage_types") or ALL_STAGES}, headers=self.auth_headers())
        response.raise_for_status()
        return response.json() if response.content not in {b"", b"null"} else None

    def process_once(self, mode: str) -> bool:
        claim = self.claim()
        if not claim:
            return False
        stage_id = claim["stage_id"]
        lease_token = claim["lease_token"]
        common = {"lease_id": claim["lease_id"], "attempt_id": claim["attempt_id"]}
        heartbeat = common | {"state": "running"}
        heartbeat_response = self.mutate(
            f"/api/internal/v1/stages/{stage_id}/heartbeat", heartbeat, lease_token
        )
        heartbeat_response.raise_for_status()
        try:
            raise_for_stop(heartbeat_response.json())
        except ExecutorStopRequested as stop:
            if stop.reason == "cancelled":
                acknowledgement = common | {"detail": "fake native task stopped"}
                self.mutate(
                    f"/api/internal/v1/stages/{stage_id}/cancellation-ack",
                    acknowledgement,
                    lease_token,
                ).raise_for_status()
            return True
        native = common | {"task_type": "fake", "native_task_id": f"fake-{stage_id}", "recovery_metadata": {"deterministic": True}}
        self.mutate(f"/api/internal/v1/stages/{stage_id}/native-task", native, lease_token).raise_for_status()
        if mode == "crash-after-native":
            raise SystemExit(75)
        if mode == "timeout":
            return True
        if mode == "fail":
            failure = common | {"error_code": "fake_failure", "detail": "requested fake executor failure", "retryable": False}
            self.mutate(f"/api/internal/v1/stages/{stage_id}/fail", failure, lease_token).raise_for_status()
            return True
        payload = canonical_json({"schema_version": "1.0", "analysis_run_id": claim["analysis_run_id"], "stage_type": claim["stage_type"], "fixture": True})
        digest = hashlib.sha256(payload).hexdigest()
        envelope = common | {"kind": "manifest", "sha256": digest, "size_bytes": len(payload), "media_type": "application/json", "access_tier": "analyst", "bundle_id": None}
        path = f"/api/internal/v1/stages/{stage_id}/artifacts"
        response = self.client.post(path, data={"envelope": json.dumps(envelope)}, files={"file": ("fixture.json", payload, "application/json")}, headers=self.signed_headers("POST", path, envelope, lease_token))
        response.raise_for_status()
        complete = common | {"outcome": "completed", "detail": "fake executor fixture completed"}
        self.mutate(f"/api/internal/v1/stages/{stage_id}/complete", complete, lease_token).raise_for_status()
        return True


@app.command()
def run(
    base_url: str = typer.Option("http://127.0.0.1:8080"),
    state_path: Path = typer.Option(Path("var/fake-executor/state.json")),
    enrollment_token: str | None = typer.Option(None),
    name: str = typer.Option("fake-executor"),
    stage_type: list[str] = typer.Option(
        None,
        "--stage-type",
        help=(
            "Stage type this executor claims; repeatable. MUST match the scopes the\n"
            "enrollment token was created with, or the API rejects the capability\n"
            "announcement with 403. Defaults to all six, which is only correct when\n"
            "no adapter/report worker is running."
        ),
    ),
    mode: str = typer.Option("success", help="success, fail, timeout, or crash-after-native"),
    once: bool = typer.Option(False),
    poll_seconds: float = typer.Option(2.0, min=0.1),
) -> None:
    executor = FakeExecutor(base_url, state_path)
    if not executor.state:
        if not enrollment_token:
            raise typer.BadParameter("enrollment-token is required on first run")
        executor.enroll(enrollment_token, name, list(stage_type) if stage_type else None)
    while True:
        processed = executor.process_once(mode)
        if once:
            return
        if not processed:
            time.sleep(poll_seconds)


if __name__ == "__main__":
    app()
