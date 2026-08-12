from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlparse

import httpx


class CapeError(RuntimeError):
    pass


LNK_HEADER = bytes.fromhex("4c0000000114020000000000c000000000000046")
CONFIG_ENDPOINT_KEYS = re.compile(
    r"(?:c2|command|control|host|server|domain|url|uri|gate|panel|endpoint|smtp|ftp|telegram|webhook)",
    re.IGNORECASE,
)
CONFIG_SECRET_KEYS = re.compile(
    r"(?:pass|password|token|secret|api[_-]?key|chat[_-]?id|user(?:name)?|login)", re.IGNORECASE
)
URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"(?<![\w.-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
DOMAIN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9.-])"
)


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


def _config_evidence(configs: list[Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return redacted extractor records and format-neutral network candidates."""
    records: list[dict[str, Any]] = []
    candidates: dict[tuple[str, str], dict[str, Any]] = {}

    def add(kind: str, value: str, path: str, extractor: str | None) -> None:
        normalized = value.strip().rstrip(".,;)")
        original_digest = hashlib.sha256(normalized.encode()).hexdigest()
        if kind == "url":
            parsed = urlparse(normalized)
            segments = parsed.path.split("/")
            sanitized_segments = [
                "bot<redacted>"
                if segment.lower().startswith("bot") and len(segment) > 12
                else "<redacted>"
                if len(segment) > 64
                else segment
                for segment in segments
            ]
            query = "" if CONFIG_SECRET_KEYS.search(parsed.query) else parsed.query
            normalized = parsed._replace(
                path="/".join(sanitized_segments), query=query, fragment=""
            ).geturl()
        if kind == "domain":
            normalized = normalized.rstrip(".").lower()
        if not normalized or len(normalized) > 2048:
            return
        candidates[(kind, normalized)] = {
            "type": kind,
            "value": normalized,
            "confidence": "strong",
            "source": "cape_config",
            "provenance": {
                "extractor": extractor,
                "field_path": path,
                "original_value_sha256": original_digest,
            },
        }

    def scalar(value: Any, path: str, extractor: str | None, key: str) -> Any:
        if not isinstance(value, (str, int, float, bool)) or isinstance(value, bool):
            return value
        text = str(value)[:4096]
        for url in URL_PATTERN.findall(text):
            add("url", url, path, extractor)
            host = urlparse(url).hostname
            if host:
                try:
                    ipaddress.ip_address(host)
                    add("ip", host, path, extractor)
                except ValueError:
                    add("domain", host, path, extractor)
        for email in EMAIL_PATTERN.findall(text):
            add("email", email.lower(), path, extractor)
            add("domain", email.rsplit("@", 1)[1], path, extractor)
        endpoint_key = bool(
            CONFIG_ENDPOINT_KEYS.search(key)
            or re.search(r"(?:^|[_-])(?:ip|address)(?:$|[_-])", key, re.IGNORECASE)
        )
        if endpoint_key:
            for domain in DOMAIN_PATTERN.findall(text):
                add("domain", domain, path, extractor)
            try:
                ipaddress.ip_address(text.strip("[]"))
                add("ip", text.strip("[]"), path, extractor)
            except ValueError:
                pass
        if CONFIG_SECRET_KEYS.search(key):
            return {
                "redacted": True,
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "length": len(text),
            }
        return text

    def walk(value: Any, path: str, extractor: str | None, depth: int = 0) -> Any:
        if depth > 8:
            return "<depth-limit>"
        if isinstance(value, dict):
            return {
                str(key)[:128]: walk(item, f"{path}.{str(key)[:128]}", extractor, depth + 1)
                for key, item in list(value.items())[:256]
            }
        if isinstance(value, list):
            return [walk(item, f"{path}[{index}]", extractor, depth + 1) for index, item in enumerate(value[:256])]
        key = path.rsplit(".", 1)[-1]
        return scalar(value, path, extractor, key)

    for index, config in enumerate(configs[:1000]):
        mapping = config if isinstance(config, dict) else {"value": config}
        extractor_value = mapping.get("family") or mapping.get("name") or mapping.get("type")
        extractor = str(extractor_value)[:128] if extractor_value else None
        records.append(
            {
                "extractor": extractor,
                "record_index": index,
                "values": walk(mapping, f"configs[{index}]", extractor),
            }
        )
    return records, sorted(candidates.values(), key=lambda item: (item["type"], item["value"]))


def _static_string_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Recover format-neutral endpoints when a family parser returns no config."""
    strings: list[str] = []
    target_file = _mapping(_mapping(report.get("target")).get("file"))
    strings.extend(str(item) for item in _bounded_list(target_file.get("strings"), 10000))
    for collection_name in ("dropped", "procdump"):
        for artifact in _bounded_list(report.get(collection_name), 2000):
            if isinstance(artifact, dict):
                strings.extend(
                    str(item) for item in _bounded_list(artifact.get("strings"), 2000)
                )
    cape = _mapping(report.get("CAPE"))
    for payload in _bounded_list(cape.get("payloads"), 2000):
        if isinstance(payload, dict):
            strings.extend(str(item) for item in _bounded_list(payload.get("strings"), 2000))
    _, candidates = _config_evidence([{"static_endpoint": item} for item in strings[:20000]])
    for item in candidates:
        item["source"] = "cape_static_string"
        item["confidence"] = "strong"
        item["provenance"] = {"source": "cape_report_strings"}
    return candidates


def normalize_cape_evidence(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize useful CAPE projections while retaining the source report losslessly."""
    behavior = _mapping(report.get("behavior"))
    network = _mapping(report.get("network"))
    suricata = _mapping(report.get("suricata"))
    cape = _mapping(report.get("CAPE"))
    raw_configs = cape.get("configs")
    configs = _bounded_list(raw_configs, 1000)
    if isinstance(raw_configs, dict):
        configs = [
            {"family": str(name)[:128], "config": value}
            for name, value in list(raw_configs.items())[:1000]
        ]
    config_records, config_candidates = _config_evidence(configs)
    static_candidates = _static_string_candidates(report)
    return {
        "schema_version": "1.0",
        # Projections below are deliberately bounded for downstream processing.
        # The immutable source report is retained so omitted or newly introduced
        # CAPE fields never disappear at the UMAT ingestion boundary.
        "raw_report": report,
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
            "configs": configs,
            "config_records": config_records,
            "config_candidates": config_candidates,
            "static_candidates": static_candidates,
        },
        "detections": _bounded_list(report.get("detections"), 1000),
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
    """Build an independent C2 prior from extractor and binary-static evidence.

    Runtime network observations deliberately do not belong here. Feeding an
    observed destination back as a prior lets the same packet corroborate
    itself and can promote unrelated browser or operating-system traffic.
    """
    indicators: dict[tuple[str, str], dict[str, Any]] = {}
    cape = _mapping(evidence.get("cape"))
    config_candidates = [
        item
        for item in (
            _bounded_list(cape.get("config_candidates"), 10000)
            + _bounded_list(cape.get("static_candidates"), 20000)
        )
        if isinstance(item, dict) and item.get("type") and item.get("value")
    ]
    for item in config_candidates:
        key = (str(item["type"]), str(item["value"]))
        indicators[key] = {
            "type": key[0],
            "value": key[1],
            "confidence": str(item.get("confidence") or "strong"),
            "source": str(item.get("source") or "cape_static_unknown"),
            "provenance": item.get("provenance") or {},
            "evidence_origin": "binary_static",
        }

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
    detections = [
        item for item in _bounded_list(evidence.get("detections"), 1000) if isinstance(item, dict)
    ]
    family = next((str(item["family"]) for item in detections if item.get("family")), None)
    return {
        "schema_version": "1.1",
        "analysis_run_id": analysis_run_id,
        "sample_sha256": sample_sha256,
        "source": "cape-evidence.json",
        "evidence_origin": "binary_static",
        "family": family,
        "iocs": [indicators[key] for key in sorted(indicators)],
        "signatures": signatures,
        "ttps": ttp_records,
        "capabilities": techniques,
        "configuration_candidates": config_candidates,
        "extractor_records": _bounded_list(cape.get("config_records"), 1000),
    }


class CapeClient:
    """Pinned CAPE HTTP client plus the deployment's CAPE machine-management gateway."""

    ACTIVE_STATES = {"pending", "running", "distributed"}
    MINIMUM_ANALYSIS_TIMEOUT_SECONDS = 10 * 60

    def __init__(
        self,
        base_url: str,
        api_token: str | None = None,
        management_url: str | None = None,
        management_token: str | None = None,
        analysis_timeout_seconds: int = MINIMUM_ANALYSIS_TIMEOUT_SECONDS,
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
        self.analysis_timeout_seconds = max(
            self.MINIMUM_ANALYSIS_TIMEOUT_SECONDS, analysis_timeout_seconds
        )

    def create_machine(self, profile: dict[str, Any]) -> tuple[str, str]:
        response = self.management.post("/api/v1/machines", json=profile)
        response.raise_for_status()
        value = response.json()
        return str(value["operation_id"]), str(value["machine_label"])

    def delete_machine(self, label: str) -> str:
        response = self.management.delete(f"/api/v1/machines/{label}")
        response.raise_for_status()
        return str(response.json()["operation_id"])

    def open_console(self, task_id: int, machine_label: str) -> dict[str, Any]:
        response = self.management.post(
            f"/api/v1/tasks/{task_id}/console",
            json={"machine_label": machine_label, "duration_seconds": 600},
        )
        response.raise_for_status()
        value = response.json()
        if not isinstance(value, dict) or not value.get("console_url"):
            raise CapeError("CAPE gateway did not return a console capability")
        return cast(dict[str, Any], value)

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
                + (",nohuman=1" if profile.get("windows_interactive") else "")
            ),
            # The fail-closed egress broker owns real-world routing and its
            # per-run lease. CAPE must not attempt a second route backend.
            "route": "none",
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

    def task_machine(self, task_id: int) -> str:
        response = self.client.get(f"/apiv2/tasks/view/{task_id}/")
        response.raise_for_status()
        value = response.json()
        data = value.get("data", value)
        task = data.get("task", data) if isinstance(data, dict) else {}
        machine = task.get("machine") if isinstance(task, dict) else None
        if isinstance(machine, dict):
            machine = machine.get("label") or machine.get("name")
        return str(machine or "")

    def evidence(self, task_id: int, timeout_seconds: int = 120) -> dict[str, Any]:
        """Wait for CAPE's report document, not only its task-state transition.

        CAPE can expose ``reported`` briefly before the report API has replaced
        its empty processing skeleton. Importing that skeleton permanently
        drops detections and behavioral signatures from an otherwise valid run.
        """
        deadline = time.monotonic() + timeout_seconds
        while True:
            response = self.client.get(f"/apiv2/tasks/get/report/{task_id}/json/", timeout=300)
            response.raise_for_status()
            value = response.json()
            if not isinstance(value, dict):
                raise CapeError("CAPE JSON report is not an object")
            info = _mapping(value.get("info"))
            target = _mapping(_mapping(value.get("target")).get("file"))
            if str(info.get("id")) == str(task_id) and target.get("sha256"):
                return normalize_cape_evidence(value)
            if time.monotonic() >= deadline:
                raise CapeError(f"CAPE report {task_id} was not ready before the evidence deadline")
            time.sleep(1)

    def cancel(self, task_id: int, timeout_seconds: int = 120) -> None:
        response = self.client.post(
            f"/apiv2/tasks/status/{task_id}/",
            data={"status": "finish"},
        )
        response.raise_for_status()
        # CAPE deployments can return ``error: true`` with a success message
        # after accepting the ``finish`` transition. The task state is the
        # authoritative signal; poll it instead of failing on that contradictory
        # response envelope.
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            status_payload = self.status(task_id)
            state = str(status_payload.get("status") or status_payload.get("data"))
            if state not in self.ACTIVE_STATES:
                return
            time.sleep(1)
        raise CapeError(f"CAPE task {task_id} did not stop before the cancellation deadline")
