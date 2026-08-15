from __future__ import annotations

import ipaddress
import json
import os
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from umat.capture import pcap_has_complete_packet, wait_for_pcap_writer
from umat.egress.schemas import LeaseRequest, LeaseResult, Readiness

WINDOWS_NETWORK = ipaddress.ip_network("10.66.0.0/24")
ANDROID_NETWORK = ipaddress.ip_network("10.68.0.0/24")
INTERFACES = {"windows": "virbr-winstdt", "android": "br-umat-malware"}
GATEWAYS = {"windows": "10.66.0.1", "android": "10.68.0.1"}
SETS = {"windows": "windows_egress_v4", "android": "android_egress_v4"}
ANDROID_SCOPED_TCP_SET = "android_scoped_tcp_v4"
# This is deliberately not a generic non-web-port allowlist. It is the exact
# SpyMax endpoint qualified for the controlled Android test campaign.
ANDROID_SCOPED_TCP_ENDPOINTS = ((ipaddress.IPv4Address("37.120.141.140"), 7775),)
TCPDUMP = "/usr/bin/tcpdump"


@dataclass
class ActiveLease:
    request: LeaseRequest
    capture_path: Path
    capture: subprocess.Popen[bytes]
    bytes_transferred: int = 0


class EgressManager:
    """Own short-lived nft set entries and mandatory per-run gateway captures."""

    def __init__(
        self, uplink: str, dns_resolver: str, capture_root: Path, max_bytes: int = 100 * 1024 * 1024
    ) -> None:
        if not uplink.startswith("wg-"):
            raise RuntimeError("controlled egress uplink must be a dedicated WireGuard interface")
        if max_bytes <= 0:
            raise RuntimeError("egress byte ceiling must be positive")
        self.uplink = uplink
        self.dns_resolver = ipaddress.IPv4Address(dns_resolver)
        self.capture_root = capture_root.resolve()
        self.max_bytes = max_bytes
        self.capture_root.mkdir(parents=True, exist_ok=True, mode=0o750)
        self._leases: dict[UUID, ActiveLease] = {}
        self._lock = threading.Lock()

    @classmethod
    def from_environment(cls) -> EgressManager:
        return cls(
            os.environ.get("UMAT_EGRESS_UPLINK", "wg-umat-egress"),
            os.environ.get("UMAT_EGRESS_DNS_RESOLVER", "10.77.0.53"),
            Path(os.environ.get("UMAT_EGRESS_CAPTURE_ROOT", "/var/lib/umat-egress")),
            int(os.environ.get("UMAT_EGRESS_MAX_BYTES", str(100 * 1024 * 1024))),
        )

    def readiness(self) -> Readiness:
        checks = {
            "nft": shutil.which("nft") is not None,
            "tcpdump": Path(TCPDUMP).is_file() and os.access(TCPDUMP, os.X_OK),
            "uplink_present": Path(f"/sys/class/net/{self.uplink}").is_dir(),
            "uplink_up": self._interface_up(self.uplink),
            "recent_wireguard_handshake": self._recent_wireguard_handshake(),
            "policy_route": self._policy_route_ready(),
            "source_policy_rules": self._source_rules_ready(),
            "ipv4_forwarding": self._ipv4_forwarding(),
            "windows_policy_set": self._set_exists(SETS["windows"]),
            "android_policy_set": self._set_exists(SETS["android"]),
            "android_scoped_tcp_policy_set": self._set_exists(ANDROID_SCOPED_TCP_SET),
        }
        return Readiness(
            status="ready" if all(checks.values()) else "not_ready",
            uplink=self.uplink,
            dns_resolver=self.dns_resolver,
            checks=checks,
        )

    def acquire(self, request: LeaseRequest) -> LeaseResult:
        ready = self.readiness()
        if ready.status != "ready":
            failed = ", ".join(name for name, value in ready.checks.items() if not value)
            raise RuntimeError(f"controlled egress is not ready: {failed}")
        network = WINDOWS_NETWORK if request.platform == "windows" else ANDROID_NETWORK
        if request.guest_ip not in network:
            raise RuntimeError(f"guest address is outside the controlled {request.platform} subnet")
        interface = INTERFACES[request.platform]
        if not Path(f"/sys/class/net/{interface}").is_dir():
            raise RuntimeError(f"controlled guest interface is missing: {interface}")
        with self._lock:
            self._revoke_unlocked(request.analysis_run_id)
            capture_path = self.capture_root / f"{request.analysis_run_id}.pcap"
            capture_log = self.capture_root / f"{request.analysis_run_id}.tcpdump.log"
            capture_path.unlink(missing_ok=True)
            capture_log.unlink(missing_ok=True)
            with capture_log.open("ab") as diagnostic:
                capture = subprocess.Popen(  # noqa: S603
                    [
                        TCPDUMP,
                        "-Z",
                        "root",
                        "-s",
                        "0",
                        "-U",
                        "-nn",
                        "-i",
                        interface,
                        "-w",
                        str(capture_path),
                        "host",
                        str(request.guest_ip),
                        "and",
                        "not",
                        "host",
                        GATEWAYS[request.platform],
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=diagnostic,
                    start_new_session=True,
                )
            authorization_attempted = False
            try:
                wait_for_pcap_writer(capture, capture_path, capture_log)
                authorization_attempted = True
                self._authorize_lease(request, request.ttl_seconds)
            except Exception:
                if authorization_attempted:
                    self._deauthorize_lease(request)
                self._stop_capture(capture)
                raise
            self._leases[request.analysis_run_id] = ActiveLease(request, capture_path, capture)
        return LeaseResult(
            analysis_run_id=request.analysis_run_id,
            platform=request.platform,
            guest_ip=request.guest_ip,
            expires_in_seconds=request.ttl_seconds,
            capture_path=str(capture_path),
        )

    def heartbeat(self, run_id: UUID, ttl_seconds: int = 90) -> LeaseResult:
        with self._lock:
            lease = self._leases.get(run_id)
            if not lease or lease.capture.poll() is not None:
                raise RuntimeError("egress lease or mandatory capture is not active")
            lease.bytes_transferred += self._element_bytes(
                SETS[lease.request.platform], str(lease.request.guest_ip)
            )
            if lease.bytes_transferred > self.max_bytes:
                self._revoke_unlocked(run_id)
                raise RuntimeError("egress byte ceiling exceeded; lease revoked")
            # This host nft version has no atomic timeout refresh operation.
            # Remove the source authorization first and restore it last so a
            # partial refresh always fails closed, including scoped C2 ports.
            self._deauthorize_lease(lease.request)
            try:
                self._authorize_lease(lease.request, ttl_seconds)
            except Exception:
                self._deauthorize_lease(lease.request)
                self._stop_capture(lease.capture)
                self._leases.pop(run_id, None)
                raise
            return LeaseResult(
                analysis_run_id=run_id,
                platform=lease.request.platform,
                guest_ip=lease.request.guest_ip,
                expires_in_seconds=ttl_seconds,
                capture_path=str(lease.capture_path),
            )

    def revoke(self, run_id: UUID) -> Path | None:
        with self._lock:
            return self._revoke_unlocked(run_id)

    def capture_path(self, run_id: UUID) -> Path:
        path = self.capture_root / f"{run_id}.pcap"
        if not pcap_has_complete_packet(path):
            raise RuntimeError("mandatory egress capture is unavailable or incomplete")
        return path

    def _revoke_unlocked(self, run_id: UUID) -> Path | None:
        lease = self._leases.pop(run_id, None)
        if not lease:
            return None
        self._deauthorize_lease(lease.request)
        self._stop_capture(lease.capture)
        self._finalize_capture(lease.capture_path)
        return lease.capture_path

    def close(self) -> None:
        with self._lock:
            for run_id in list(self._leases):
                self._revoke_unlocked(run_id)

    @staticmethod
    def _stop_capture(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)

    @staticmethod
    def _finalize_capture(path: Path) -> None:
        # tcpdump drops privileges and changes the savefile to its own account.
        # Return completed evidence to the broker service group so executors can
        # ingest it without making the capture world-readable.
        if not pcap_has_complete_packet(path):
            raise RuntimeError("mandatory egress capture contains no complete packets")
        os.chown(path, os.geteuid(), os.getegid())
        path.chmod(0o640)

    @staticmethod
    def _interface_up(name: str) -> bool:
        try:
            return Path(f"/sys/class/net/{name}/operstate").read_text().strip() in {"up", "unknown"}
        except OSError:
            return False

    def _set_exists(self, name: str) -> bool:
        return self._nft("list", "set", "ip", "umat_guest_guard", name, check=False).returncode == 0

    def _authorize_lease(self, request: LeaseRequest, ttl_seconds: int) -> None:
        # Install destination-scoped entries before the source lease. Firewall
        # rules require both, so traffic cannot pass during partial setup.
        if request.platform == "android":
            for destination, port in ANDROID_SCOPED_TCP_ENDPOINTS:
                self._nft(
                    "add",
                    "element",
                    "ip",
                    "umat_guest_guard",
                    ANDROID_SCOPED_TCP_SET,
                    (
                        f"{{ {request.guest_ip} . {destination} . {port} "
                        f"timeout {ttl_seconds}s }}"
                    ),
                )
        self._nft(
            "add",
            "element",
            "ip",
            "umat_guest_guard",
            SETS[request.platform],
            f"{{ {request.guest_ip} timeout {ttl_seconds}s }}",
        )

    def _deauthorize_lease(self, request: LeaseRequest) -> None:
        # Remove the broad source gate first. Scoped tuples are then inert even
        # if cleanup is interrupted and will independently expire in-kernel.
        self._nft(
            "delete",
            "element",
            "ip",
            "umat_guest_guard",
            SETS[request.platform],
            f"{{ {request.guest_ip} }}",
            check=False,
        )
        if request.platform == "android":
            for destination, port in ANDROID_SCOPED_TCP_ENDPOINTS:
                self._nft(
                    "delete",
                    "element",
                    "ip",
                    "umat_guest_guard",
                    ANDROID_SCOPED_TCP_SET,
                    f"{{ {request.guest_ip} . {destination} . {port} }}",
                    check=False,
                )

    def _policy_route_ready(self) -> bool:
        result = subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "route", "show", "table", "51820", "default"],
            check=False,
            capture_output=True,
            text=True,
        )
        return result.returncode == 0 and f"dev {self.uplink}" in result.stdout

    def _recent_wireguard_handshake(self) -> bool:
        if shutil.which("wg") is None:
            return False
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/wg", "show", self.uplink, "latest-handshakes"],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return False
        now = int(time.time())
        timestamps = []
        for line in result.stdout.splitlines():
            try:
                timestamps.append(int(line.rsplit("\t", 1)[-1]))
            except ValueError:
                continue
        return any(timestamp > 0 and now - timestamp <= 180 for timestamp in timestamps)

    def _element_bytes(self, set_name: str, address: str) -> int:
        result = self._nft("-j", "list", "set", "ip", "umat_guest_guard", set_name)
        try:
            document = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("could not read egress byte counter") from exc
        for item in document.get("nftables", []):
            for element in (item.get("set") or {}).get("elem", []):
                value = element.get("elem") or {}
                if value.get("val") == address:
                    return int((value.get("counter") or {}).get("bytes") or 0)
        raise RuntimeError("active egress lease disappeared from the kernel policy set")

    @staticmethod
    def _source_rules_ready() -> bool:
        result = subprocess.run(  # noqa: S603
            ["/usr/sbin/ip", "rule", "show"], check=False, capture_output=True, text=True
        )
        return (
            result.returncode == 0
            and "from 10.66.0.0/24 lookup 51820" in result.stdout
            and "from 10.68.0.0/24 lookup 51820" in result.stdout
        )

    @staticmethod
    def _ipv4_forwarding() -> bool:
        try:
            return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
        except OSError:
            return False

    @staticmethod
    def _nft(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603
            ["/usr/sbin/nft", *arguments],
            check=check,
            capture_output=True,
        )
