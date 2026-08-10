from __future__ import annotations

import time
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import httpx


class CapeError(RuntimeError):
    pass


LNK_HEADER = bytes.fromhex("4c0000000114020000000000c000000000000046")


def cape_package_for_sample(sample: Path) -> str:
    """Select a CAPE package from a validated leading file signature.

    Leading signatures deliberately take precedence over embedded/archive
    overlays. Malware commonly appends ZIP data to LNK and PE files, and
    CAPE's generic detector can otherwise select the overlay instead of the
    executable outer format.
    """
    with sample.open("rb") as source:
        header = source.read(64)
        if header.startswith(LNK_HEADER):
            return "lnk"
        if header.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            return "zip"
        if len(header) < 64 or header[:2] != b"MZ":
            return ""
        pe_offset = int.from_bytes(header[60:64], "little")
        if pe_offset < 64 or pe_offset > 16 * 1024 * 1024:
            return ""
        source.seek(pe_offset)
        coff = source.read(24)
    if len(coff) != 24 or coff[:4] != b"PE\0\0":
        return ""
    characteristics = int.from_bytes(coff[22:24], "little")
    return "dll" if characteristics & 0x2000 else "exe"


def cape_filename_for_package(package: str) -> str:
    """Return a neutral filename that retains only a validated format suffix."""
    suffix = {"lnk": ".lnk", "zip": ".zip", "dll": ".dll", "exe": ".exe"}.get(package, "")
    return f"sample{suffix or '.bin'}"


def _bounded_list(value: Any, limit: int) -> list[Any]:
    return list(value[:limit]) if isinstance(value, list) else []


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def normalize_cape_evidence(report: dict[str, Any]) -> dict[str, Any]:
    """Select bounded, format-neutral evidence from CAPE's potentially huge report."""
    behavior = _mapping(report.get("behavior"))
    network = _mapping(report.get("network"))
    suricata = _mapping(report.get("suricata"))
    cape = _mapping(report.get("CAPE"))
    return {
        "schema_version": "1.0",
        "malscore": report.get("malscore"),
        "malstatus": report.get("malstatus"),
        "signatures": _bounded_list(report.get("signatures"), 1000),
        "ttps": _bounded_list(report.get("ttps"), 2000),
        "behavior": {
            "summary": behavior.get("summary") if isinstance(behavior.get("summary"), dict) else {},
            "processtree": _bounded_list(behavior.get("processtree"), 2000),
            "enhanced": _bounded_list(behavior.get("enhanced"), 5000),
        },
        "dropped": _bounded_list(report.get("dropped"), 2000),
        "procdump": _bounded_list(report.get("procdump"), 1000),
        "cape": {
            "payloads": _bounded_list(cape.get("payloads"), 2000),
            "configs": _bounded_list(cape.get("configs"), 1000),
        },
        "network": {
            key: _bounded_list(network.get(key), 10000)
            for key in ("hosts", "domains", "dns", "http", "tcp", "udp", "smtp", "irc")
        },
        "suricata": {
            key: _bounded_list(suricata.get(key), 10000)
            for key in ("alerts", "dns", "http", "tls", "files")
        },
    }


def cape_static_prior(
    evidence: dict[str, Any], analysis_run_id: str, sample_sha256: str
) -> dict[str, Any]:
    """Build the C2/static prior from the same immutable CAPE evidence UMAT adapts."""
    indicators: set[tuple[str, str]] = set()
    network = _mapping(evidence.get("network"))
    for host in _bounded_list(network.get("hosts"), 10000):
        value = host.get("ip") if isinstance(host, dict) else host
        if value:
            indicators.add(("ip", str(value)))
    for domain in _bounded_list(network.get("domains"), 10000):
        value = (
            domain.get("domain") or domain.get("request") if isinstance(domain, dict) else domain
        )
        if value:
            indicators.add(("domain", str(value).rstrip(".").lower()))
    for request in _bounded_list(network.get("http"), 10000):
        if not isinstance(request, dict):
            continue
        value = request.get("uri") or request.get("url")
        if value:
            indicators.add(("url", str(value)))
            hostname = urlparse(str(value)).hostname
            if hostname:
                indicators.add(("domain", hostname.rstrip(".").lower()))

    signatures = [
        item for item in _bounded_list(evidence.get("signatures"), 1000) if isinstance(item, dict)
    ]
    ttp_records = [
        item for item in _bounded_list(evidence.get("ttps"), 2000) if isinstance(item, dict)
    ]
    techniques = sorted(
        {
            str(technique).upper()
            for item in ttp_records
            for technique in (item.get("ttps") or [])
            if isinstance(technique, str) and technique.upper().startswith("T")
        }
    )
    return {
        "schema_version": "1.0",
        "analysis_run_id": analysis_run_id,
        "sample_sha256": sample_sha256,
        "source": "cape-evidence.json",
        "iocs": [
            {"type": kind, "value": value, "confidence": "strong"}
            for kind, value in sorted(indicators)
        ],
        "signatures": signatures,
        "ttps": ttp_records,
        "capabilities": techniques,
    }


class CapeClient:
    """Pinned CAPE HTTP client plus the deployment's CAPE machine-management gateway."""

    ACTIVE_STATES = {"pending", "running", "distributed"}

    def __init__(
        self,
        base_url: str,
        api_token: str | None = None,
        management_url: str | None = None,
        management_token: str | None = None,
        analysis_timeout_seconds: int = 180,
    ) -> None:
        headers = {"Authorization": f"Token {api_token}"} if api_token else {}
        self.client = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=60)
        management_headers = (
            {"Authorization": f"Bearer {management_token}"} if management_token else {}
        )
        self.management = httpx.Client(
            base_url=(management_url or base_url).rstrip("/"),
            headers=management_headers,
            timeout=900,
        )
        self.analysis_timeout_seconds = analysis_timeout_seconds

    def create_machine(self, profile: dict[str, Any]) -> tuple[str, str]:
        response = self.management.post("/api/v1/machines", json=profile)
        response.raise_for_status()
        value = response.json()
        return str(value["operation_id"]), str(value["machine_label"])

    def delete_machine(self, label: str) -> str:
        response = self.management.delete(f"/api/v1/machines/{label}")
        response.raise_for_status()
        return str(response.json()["operation_id"])

    def submit(self, sample: Path, profile: dict[str, Any]) -> int:
        network_mode = profile.get("network_mode", "isolated_simulated")
        package = cape_package_for_sample(sample)
        data = {
            "machine": profile.get("cape_machine_label") or "",
            # CAPE can mistake a PE containing an archive overlay for a ZIP and
            # abort the guest before ETW finalization. Other formats remain on
            # CAPE's native automatic package selection path.
            "package": package,
            "options": (
                f"analysis_profile={profile.get('analysis_profile', 'standard')},"
                f"network_mode={'simulated_inetsim' if network_mode == 'isolated_simulated' else 'real_world_egress'}"
            ),
            "route": "none" if network_mode == "isolated_simulated" else "internet",
            "timeout": str(self.analysis_timeout_seconds),
            "enforce_timeout": "true",
        }
        with sample.open("rb") as source:
            response = self.client.post(
                "/apiv2/tasks/create/file/",
                data=data,
                files={
                    "file": (
                        cape_filename_for_package(package),
                        source,
                        "application/octet-stream",
                    )
                },
            )
        response.raise_for_status()
        value = response.json()
        task_ids = value.get("data", {}).get("task_ids") or value.get("task_ids") or []
        if not task_ids:
            raise CapeError(f"CAPE did not return a task ID: {value}")
        return int(task_ids[0])

    def status(self, task_id: int) -> dict[str, Any]:
        response = self.client.get(f"/apiv2/tasks/status/{task_id}/")
        response.raise_for_status()
        value = response.json()
        data = value.get("data", value)
        if isinstance(data, str):
            return {"status": data}
        if not isinstance(data, dict):
            raise CapeError("CAPE status response is not an object")
        return cast(dict[str, Any], data)

    def evidence(self, task_id: int) -> dict[str, Any]:
        response = self.client.get(f"/apiv2/tasks/get/report/{task_id}/json/", timeout=300)
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict):
            raise CapeError("CAPE JSON report is not an object")
        return normalize_cape_evidence(value)

    def cancel(self, task_id: int, timeout_seconds: int = 120) -> None:
        response = self.client.post(
            f"/apiv2/tasks/status/{task_id}/",
            data={"status": "finish"},
        )
        response.raise_for_status()
        value = response.json()
        if value.get("error"):
            raise CapeError(f"CAPE rejected task cancellation: {value}")
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            status_payload = self.status(task_id)
            state = str(status_payload.get("status") or status_payload.get("data"))
            if state not in self.ACTIVE_STATES:
                return
            time.sleep(1)
        raise CapeError(f"CAPE task {task_id} did not stop before the cancellation deadline")
