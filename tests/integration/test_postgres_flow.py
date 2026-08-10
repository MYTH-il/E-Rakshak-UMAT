import base64
import hashlib
import io
import json
import os
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

pytestmark = pytest.mark.skipif(
    not os.getenv("UMAT_TEST_DATABASE_URL"), reason="requires a migrated PostgreSQL test database"
)

from umat.api.app import app  # noqa: E402
from umat.api.case_routes import store  # noqa: E402
from umat.auth.security import hash_password, random_token, token_hash  # noqa: E402
from umat.c2.adapter import C2Adapter  # noqa: E402
from umat.c2.bundle import ResultBundleBuilder, sha256_file  # noqa: E402
from umat.c2.input_builder import C2InputBuilder  # noqa: E402
from umat.c2.models import InputArtifact  # noqa: E402
from umat.c2.runtime import FixtureC2Runtime  # noqa: E402
from umat.db.models import (  # noqa: E402
    AnalysisStage,
    C2Finding,
    ExecutorEnrollmentToken,
    Role,
    StageType,
    User,
)
from umat.db.session import session_factory  # noqa: E402
from umat.executors.security import signature_message  # noqa: E402


def apk_bytes() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"fixture")
        archive.writestr("classes.dex", b"fixture")
    return output.getvalue()


def signed_headers(
    private: Ed25519PrivateKey,
    path: str,
    body: dict,
    credential: str,
    lease_token: str,
    method: str = "POST",
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).isoformat()
    nonce = uuid.uuid4().hex
    idempotency = str(uuid.uuid4())
    message = signature_message(
        method=method,
        path=path,
        timestamp=timestamp,
        nonce=nonce,
        idempotency_key=idempotency,
        body=body,
    )
    return {
        "Authorization": f"Bearer {credential}",
        "X-UMAT-Timestamp": timestamp,
        "X-UMAT-Nonce": nonce,
        "Idempotency-Key": idempotency,
        "X-UMAT-Signature": base64.b64encode(private.sign(message)).decode(),
        "X-UMAT-Lease-Token": lease_token,
    }


@pytest.mark.asyncio
async def test_postgres_intake_duplicate_and_executor_protocol(tmp_path: Path) -> None:
    suffix = uuid.uuid4().hex[:10]
    username = f"analyst-{suffix}"
    password = "integration-password"  # noqa: S105
    enrollment_raw = random_token(48)
    c2_enrollment_raw = random_token(48)
    async with session_factory() as db:
        analyst_role = await db.scalar(select(Role).where(Role.name == "analyst"))
        admin = await db.scalar(select(User).where(User.username == "admin"))
        assert analyst_role and admin
        user = User(username=username, password_hash=hash_password(password), roles=[analyst_role])
        db.add(user)
        await db.flush()
        db.add(
            ExecutorEnrollmentToken(
                token_hash=token_hash(enrollment_raw),
                executor_type="fake",
                scopes=["platform_analysis"],
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                created_by_user_id=admin.id,
            )
        )
        db.add(
            ExecutorEnrollmentToken(
                token_hash=token_hash(c2_enrollment_raw),
                executor_type="c2",
                scopes=["c2_analysis"],
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
                created_by_user_id=admin.id,
            )
        )
        await db.commit()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        login = await client.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert login.status_code == 200, login.text
        csrf = login.json()["csrf_token"]
        auth_headers = {"X-CSRF-Token": csrf}
        content = apk_bytes()
        first = await client.post(
            "/api/v1/cases",
            headers=auth_headers,
            data={"title": "integration", "c2_analysis_enabled": "true"},
            files={"file": ("sample.bin", content, "application/octet-stream")},
        )
        assert first.status_code == 201, first.text
        assert first.json()["platform"] == "android"
        assert first.json()["status"] == "queued"
        target_run_id = uuid.UUID(first.json()["analysis_run_id"])
        async with session_factory() as db:
            target_stage = await db.scalar(
                select(AnalysisStage).where(
                    AnalysisStage.analysis_run_id == target_run_id,
                    AnalysisStage.stage_type == StageType.PLATFORM_ANALYSIS,
                )
            )
            assert target_stage is not None
            target_stage.priority = 10_000
            await db.commit()
        second = await client.post(
            "/api/v1/cases",
            headers=auth_headers,
            files={"file": ("looks.apk", content, "application/octet-stream")},
        )
        assert second.status_code == 201, second.text
        assert second.json()["status"] == "awaiting_confirmation"
        assert second.json()["duplicate_cases"]
        confirm = await client.post(
            f"/api/v1/analysis-runs/{second.json()['analysis_run_id']}/confirm",
            headers=auth_headers,
        )
        assert confirm.status_code == 200, confirm.text

        private = Ed25519PrivateKey.generate()
        public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        registered = await client.post(
            "/api/internal/v1/executors/register",
            json={
                "enrollment_token": enrollment_raw,
                "name": f"fake-{suffix}",
                "public_key": base64.b64encode(public).decode(),
                "metadata": {},
            },
        )
        assert registered.status_code == 201, registered.text
        credential = registered.json()["credential"]
        executor_headers = {"Authorization": f"Bearer {credential}"}
        capabilities = await client.post(
            "/api/internal/v1/executors/capabilities",
            headers=executor_headers,
            json={
                "schema_version": "1.0",
                "runtime_identity": "integration-fixture",
                "supported_stage_types": ["platform_analysis"],
                "capabilities": {
                    "fixture": True,
                    "platforms": ["windows", "android"],
                    "native_event_schema_version": "1.3",
                },
            },
        )
        assert capabilities.status_code == 204, capabilities.text
        claim = await client.post(
            "/api/internal/v1/executors/claim",
            headers=executor_headers,
            json={"stage_types": ["platform_analysis"], "platforms": ["android"]},
        )
        assert claim.status_code == 200, claim.text
        lease = claim.json()
        common = {"lease_id": lease["lease_id"], "attempt_id": lease["attempt_id"]}
        native_body = common | {
            "task_type": "fake",
            "native_task_id": f"native-{lease['stage_id']}",
            "recovery_metadata": {},
        }
        native_path = f"/api/internal/v1/stages/{lease['stage_id']}/native-task"
        native = await client.post(
            native_path,
            json=native_body,
            headers=signed_headers(
                private, native_path, native_body, credential, lease["lease_token"]
            ),
        )
        assert native.status_code == 200, native.text

        artifact_content = json.dumps(
            {
                "analysis_window": {
                    "started_at": "2026-08-08T12:00:00Z",
                    "ended_at": "2026-08-08T12:05:00Z",
                },
                "emulator": {"guest_ip": "10.0.2.15"},
                "caveats": [],
            }
        ).encode()
        envelope = common | {
            "kind": "platform_manifest",
            "sha256": hashlib.sha256(artifact_content).hexdigest(),
            "size_bytes": len(artifact_content),
            "media_type": "application/json",
            "access_tier": "officer",
            "bundle_id": None,
        }
        artifact_path = f"/api/internal/v1/stages/{lease['stage_id']}/artifacts"
        artifact = await client.post(
            artifact_path,
            data={"envelope": json.dumps(envelope)},
            files={"file": ("fixture.json", artifact_content, "application/json")},
            headers=signed_headers(
                private, artifact_path, envelope, credential, lease["lease_token"]
            ),
        )
        assert artifact.status_code == 201, artifact.text
        pcap_content = b"phase2-integration-pcap"
        pcap_envelope = common | {
            "kind": "pcap",
            "sha256": hashlib.sha256(pcap_content).hexdigest(),
            "size_bytes": len(pcap_content),
            "media_type": "application/vnd.tcpdump.pcap",
            "access_tier": "analyst",
            "bundle_id": None,
        }
        pcap_artifact = await client.post(
            artifact_path,
            data={"envelope": json.dumps(pcap_envelope)},
            files={"file": ("capture.pcap", pcap_content, "application/vnd.tcpdump.pcap")},
            headers=signed_headers(
                private, artifact_path, pcap_envelope, credential, lease["lease_token"]
            ),
        )
        assert pcap_artifact.status_code == 201, pcap_artifact.text
        complete_body = common | {"outcome": "completed", "detail": None}
        complete_path = f"/api/internal/v1/stages/{lease['stage_id']}/complete"
        complete_headers = signed_headers(
            private, complete_path, complete_body, credential, lease["lease_token"]
        )
        completed = await client.post(
            complete_path, json=complete_body, headers=complete_headers
        )
        assert completed.status_code == 200, completed.text
        replay = await client.post(complete_path, json=complete_body, headers=complete_headers)
        assert replay.status_code == 200
        assert replay.json() == completed.json()
        async with session_factory() as db:
            target_c2_stage = await db.scalar(
                select(AnalysisStage).where(
                    AnalysisStage.analysis_run_id == target_run_id,
                    AnalysisStage.stage_type == StageType.C2_ANALYSIS,
                )
            )
            assert target_c2_stage is not None
            target_c2_stage.priority = 10_000
            await db.commit()

        c2_private = Ed25519PrivateKey.generate()
        c2_public = c2_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        c2_registered = await client.post(
            "/api/internal/v1/executors/register",
            json={
                "enrollment_token": c2_enrollment_raw,
                "name": f"c2-{suffix}",
                "public_key": base64.b64encode(c2_public).decode(),
                "metadata": {"fixture": True},
            },
        )
        assert c2_registered.status_code == 201, c2_registered.text
        c2_credential = c2_registered.json()["credential"]
        c2_headers = {"Authorization": f"Bearer {c2_credential}"}
        c2_capabilities = await client.post(
            "/api/internal/v1/executors/capabilities",
            headers=c2_headers,
            json={
                "schema_version": "1.0",
                "runtime_identity": "c2-fixture@1.3",
                "supported_stage_types": ["c2_analysis"],
                    "capabilities": {
                        "native_event_schema_version": "1.3",
                        "platforms": ["windows", "android"],
                    },
            },
        )
        assert c2_capabilities.status_code == 204, c2_capabilities.text
        c2_claim_response = await client.post(
            "/api/internal/v1/executors/claim",
            headers=c2_headers,
            json={"stage_types": ["c2_analysis"]},
        )
        assert c2_claim_response.status_code == 200, c2_claim_response.text
        c2_claim = c2_claim_response.json()
        assert {item["kind"] for item in c2_claim["input_artifacts"]} == {
            "platform_manifest",
            "pcap",
        }
        local_inputs: list[InputArtifact] = []
        for item in c2_claim["input_artifacts"]:
            download_body = {
                "lease_id": c2_claim["lease_id"],
                "attempt_id": c2_claim["attempt_id"],
                "artifact_id": item["artifact_id"],
            }
            downloaded_input = await client.get(
                item["download_path"],
                params={
                    "lease_id": c2_claim["lease_id"],
                    "attempt_id": c2_claim["attempt_id"],
                },
                headers=signed_headers(
                    c2_private,
                    item["download_path"],
                    download_body,
                    c2_credential,
                    c2_claim["lease_token"],
                    method="GET",
                ),
            )
            assert downloaded_input.status_code == 200, downloaded_input.text
            local_path = tmp_path / f"input-{item['artifact_id']}"
            local_path.write_bytes(downloaded_input.content)
            local_inputs.append(InputArtifact(local_path=local_path, **item))
        context = C2InputBuilder().build(
            analysis_run_id=c2_claim["analysis_run_id"],
            platform=c2_claim["platform"],
            sample_sha256=c2_claim["sample_sha256"],
            artifacts=local_inputs,
        )
        bundle = ResultBundleBuilder(
            c2_private, c2_registered.json()["executor_id"]
        ).build(
            context,
            FixtureC2Runtime().run(context, tmp_path / "c2-runtime"),
            tmp_path / "c2-result",
        )
        c2_common = {
            "lease_id": c2_claim["lease_id"],
            "attempt_id": c2_claim["attempt_id"],
        }
        c2_envelope = c2_common | {
            "kind": "c2_bundle",
            "sha256": sha256_file(bundle.archive_path),
            "size_bytes": bundle.archive_path.stat().st_size,
            "media_type": "application/zip",
            "access_tier": "analyst",
            "bundle_id": str(uuid.uuid4()),
        }
        c2_artifact_path = f"/api/internal/v1/stages/{c2_claim['stage_id']}/artifacts"
        with bundle.archive_path.open("rb") as bundle_source:
            c2_artifact = await client.post(
                c2_artifact_path,
                data={"envelope": json.dumps(c2_envelope)},
                files={"file": ("c2-result.zip", bundle_source, "application/zip")},
                headers=signed_headers(
                    c2_private,
                    c2_artifact_path,
                    c2_envelope,
                    c2_credential,
                    c2_claim["lease_token"],
                ),
            )
        assert c2_artifact.status_code == 201, c2_artifact.text
        c2_complete_body = c2_common | {"outcome": "completed", "detail": None}
        c2_complete_path = f"/api/internal/v1/stages/{c2_claim['stage_id']}/complete"
        c2_complete = await client.post(
            c2_complete_path,
            json=c2_complete_body,
            headers=signed_headers(
                c2_private,
                c2_complete_path,
                c2_complete_body,
                c2_credential,
                c2_claim["lease_token"],
            ),
        )
        assert c2_complete.status_code == 200, c2_complete.text

        async with session_factory() as db:
            adaptation = await C2Adapter(store()).adapt_run(
                db, uuid.UUID(c2_claim["analysis_run_id"])
            )
            findings = list(
                (await db.scalars(select(C2Finding).where(C2Finding.adaptation_id == adaptation.id))).all()
            )
            assert len(findings) == 1
            assert findings[0].platform.value == "android"
            assert findings[0].details["data_type_accessed"] is None

        downloaded = await client.get(
            f"/api/v1/artifacts/{artifact.json()['artifact_id']}"
        )
        assert downloaded.status_code == 200, downloaded.text
        assert downloaded.content == artifact_content
        assert downloaded.headers["x-content-type-options"] == "nosniff"
