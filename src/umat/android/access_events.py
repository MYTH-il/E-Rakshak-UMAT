from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from umat.contracts import validate_contract
from umat.contracts.canonical import canonical_json


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _api_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    value = document.get("data")
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _data_type(item: dict[str, Any]) -> tuple[str, str] | None:
    api_class = str(item.get("class") or "")
    method = str(item.get("method") or "")
    category = str(item.get("name") or "").lower()
    arguments = " ".join(str(value) for value in (item.get("arguments") or []))
    probe = f"{api_class} {method} {category} {arguments}".lower()
    mappings = (
        (("contacts", "contactscontract"), "contacts"),
        (("content://sms", "smsmessage", "sms/inbox"), "sms"),
        (("call_log", "calllog"), "call_log"),
        (("calendarcontract", "content://com.android.calendar"), "calendar"),
        (("accountmanager", "getaccounts"), "accounts"),
        (("locationmanager", "getlastknownlocation", "requestlocationupdates"), "location"),
        (("clipboardmanager", "getprimaryclip"), "clipboard"),
        (("telephonymanager", "getdeviceid", "getimei", "getsubscriberid"), "device_identity"),
        (("sqlite", "database"), "application_database"),
        (("openfileinput", "file io"), "application_file"),
        (("getinstalledpackages", "device data"), "device_information"),
    )
    data_type = next(
        (label for needles, label in mappings if any(needle in probe for needle in needles)),
        None,
    )
    if data_type is None:
        return None
    lowered_method = method.lower()
    if lowered_method.startswith(("get", "read", "open")):
        operation = "read"
    elif "query" in lowered_method:
        operation = "query"
    elif lowered_method.startswith(("list", "enumerate")) or "accounts" in lowered_method:
        operation = "enumerate"
    else:
        operation = "access"
    return data_type, operation


def _object_reference(item: dict[str, Any]) -> str | None:
    for value in item.get("arguments") or []:
        candidate = str(value)
        if candidate.startswith(("content://", "file://", "/data/", "/sdcard/")):
            return candidate[:2048]
    return None


class AndroidAccessEventCollector:
    """Timestamp MobSF API-monitor observations without changing the pinned MobSF runtime.

    MobSF's native API-monitor rows have no clock field. Polling records the first UTC
    observation of each immutable row and declares the polling interval as uncertainty.
    """

    def __init__(
        self,
        getter: Callable[[], dict[str, Any]],
        *,
        package_name: str,
        process_ids: list[str],
        started_at: datetime,
        poll_interval_seconds: float = 1.0,
    ) -> None:
        self.getter = getter
        self.package_name = package_name
        self.process_ids = sorted({int(value) for value in process_ids if str(value).isdigit()})
        self.started_at = started_at
        self.poll_interval_seconds = max(0.1, min(poll_interval_seconds, 60.0))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._events: dict[str, dict[str, Any]] = {}
        self._errors = 0

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("Android access-event collector is already started")
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="android-access-events",
        )
        self._thread.start()

    def _run(self) -> None:
        self._poll()
        while not self._stop.wait(self.poll_interval_seconds):
            self._poll()

    def _poll(self) -> None:
        poll_started = _utcnow()
        try:
            rows = _api_rows(self.getter())
        except Exception:
            self._errors += 1
            return
        observed_at = _utcnow()
        uncertainty_ms = min(
            60000,
            int(
                self.poll_interval_seconds * 1000
                + (observed_at - poll_started).total_seconds() * 1000
            ),
        )
        for item in rows[:100000]:
            canonical = canonical_json(item)
            digest = hashlib.sha256(canonical).hexdigest()
            if digest in self._events:
                continue
            classified = _data_type(item)
            if classified is None:
                continue
            data_type, operation = classified
            api_class = str(item.get("class") or "unknown")
            method = str(item.get("method") or "unknown")
            self._events[digest] = {
                "event_id": str(uuid5(NAMESPACE_URL, f"umat:android-access:{digest}")),
                "timestamp": observed_at.isoformat(),
                "timestamp_uncertainty_ms": uncertainty_ms,
                "source": "frida_api_monitor",
                "package_name": self.package_name,
                "process_ids": self.process_ids,
                "data_type": data_type,
                "api_call": f"{api_class}.{method}",
                "operation": operation,
                "object_reference": _object_reference(item),
                "called_from": str(item.get("calledFrom"))[:2048]
                if item.get("calledFrom")
                else None,
                "source_event_sha256": digest,
            }

    def stop(self, destination: Path, *, ended_at: datetime | None = None) -> dict[str, Any]:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(5.0, self.poll_interval_seconds * 2))
            if self._thread.is_alive():
                raise RuntimeError("Android access-event collector did not stop cleanly")
        ended = ended_at or _utcnow()
        maximum_uncertainty_ms = max(
            (
                int(item["timestamp_uncertainty_ms"])
                for item in self._events.values()
            ),
            default=int(self.poll_interval_seconds * 1000),
        )
        document = {
            "schema_version": "1.0",
            "platform": "android",
            "package_name": self.package_name,
            "analysis_window": {
                "started_at": self.started_at.astimezone(timezone.utc).isoformat(),
                "ended_at": ended.astimezone(timezone.utc).isoformat(),
            },
            "clock": {
                "basis": "executor_utc_first_observation",
                "quality_acceptable": self._errors == 0,
                "maximum_uncertainty_ms": maximum_uncertainty_ms,
            },
            "sources": [
                {
                    "source": "frida_api_monitor",
                    "producer": "MobSF",
                    "timestamp_semantics": "first_observed_by_executor",
                    "poll_errors": self._errors,
                }
            ],
            "events": sorted(
                self._events.values(), key=lambda item: (item["timestamp"], item["event_id"])
            ),
        }
        validate_contract("android/android-access-events.schema.json", document)
        destination.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        return document
