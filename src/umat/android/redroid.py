from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from umat.android.avd import RunningAVD

MITMPROXY_IMAGE = (
    "mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
)


class RedroidManager:
    """Run one disposable, amd64-pinned Android 11 ReDroid worker."""

    def __init__(
        self,
        *,
        adb: Path,
        image: str,
        memory_mb: int = 4096,
        vcpus: int = 4,
        adb_address: str = "172.17.0.1:5555",
        boot_timeout_seconds: int = 180,
        network_mode: str = "isolated_simulated",
        mitmproxy_image: str = MITMPROXY_IMAGE,
    ) -> None:
        if "@sha256:" not in image:
            raise ValueError("ReDroid image must be pinned by digest")
        self.adb = adb
        self.image = image
        self.memory_mb = memory_mb
        self.vcpus = vcpus
        self.adb_address = adb_address
        self.boot_timeout_seconds = boot_timeout_seconds
        self.network_mode = network_mode
        self.mitmproxy_image = mitmproxy_image
        self.running: RunningAVD | None = None
        self.environment = os.environ.copy()
        self.container_name: str | None = None
        self.capture_process: subprocess.Popen[bytes] | None = None
        self.capture_log_stream: Any | None = None
        self.relay_process: subprocess.Popen[bytes] | None = None
        self.relay_log_stream: Any | None = None
        self.proxy_container_name: str | None = None
        self.proxy_address: str | None = None
        self.proxy_evidence_dir: Path | None = None

    def start(self, name: str, workspace: Path) -> RunningAVD:
        container_name = f"{name}-redroid"
        data = workspace / "redroid-data"
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
        network_arguments: list[str] = []
        dns_arguments: list[str] = []
        publish_arguments = ["-p", f"{self.adb_address}:5555"]
        if self.network_mode in {"isolated_simulated", "real_world_egress"}:
            isolated = self.network_mode == "isolated_simulated"
            network_name = "umat-android-isolated" if isolated else "umat-android-egress"
            subnet = "172.30.0.0/24" if isolated else "172.31.0.0/24"
            bridge = "br-umat-android" if isolated else "br-umat-egress"
            if self._docker("network", "inspect", network_name, check=False).returncode != 0:
                arguments = ["network", "create"]
                if isolated:
                    arguments.append("--internal")
                self._docker(
                    *arguments,
                    "--subnet",
                    subnet,
                    "--opt",
                    f"com.docker.network.bridge.name={bridge}",
                    network_name,
                )
            network_arguments = ["--network", network_name]
            if isolated:
                publish_arguments = []
            else:
                dns_arguments = ["--dns", "10.77.0.53"]
        self._docker(
            "run",
            "-d",
            "--name",
            container_name,
            "--platform",
            "linux/amd64",
            "--pull",
            "never",
            "--privileged",
            *network_arguments,
            *dns_arguments,
            "--memory",
            f"{self.memory_mb}m",
            "--cpus",
            str(self.vcpus),
            *publish_arguments,
            "-v",
            f"{data}:/data",
            "-v",
            f"{workspace}:/umat",
            self.image,
        )
        self.container_name = container_name
        guest_ip = (
            self._docker(
                "inspect",
                "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                container_name,
            )
            .stdout.strip()
            .decode()
            or None
        )
        if self.network_mode == "isolated_simulated" and guest_ip:
            relay_host, relay_port = self.adb_address.rsplit(":", 1)
            self.relay_log_stream = (workspace / "adb-relay.log").open("ab")
            self.relay_process = subprocess.Popen(  # noqa: S603
                [
                    "/usr/bin/socat",
                    f"TCP-LISTEN:{relay_port},bind={relay_host},reuseaddr,fork",
                    f"TCP:{guest_ip}:5555",
                ],
                stdout=self.relay_log_stream,
                stderr=subprocess.STDOUT,
            )
            time.sleep(0.5)
            if self.relay_process.poll() is not None:
                raise RuntimeError("ReDroid isolated ADB relay failed to start")
        # Remove any stale transport left by a previous disposable guest before
        # registering this run's relay/container endpoint.
        self._adb("disconnect", self.adb_address, check=False)
        deadline = time.monotonic() + self.boot_timeout_seconds
        while time.monotonic() < deadline:
            self._adb("connect", self.adb_address, check=False)
            boot = self._adb(
                "-s",
                self.adb_address,
                "shell",
                "getprop",
                "sys.boot_completed",
                check=False,
            )
            if boot.returncode == 0 and boot.stdout.strip() == b"1":
                break
            time.sleep(2)
        else:
            raise RuntimeError("ReDroid Android guest boot timed out")
        values = self._adb(
            "-s",
            self.adb_address,
            "shell",
            "getprop",
            "ro.product.cpu.abi",
        ).stdout.strip()
        if values != b"x86_64":
            raise RuntimeError(f"ReDroid guest ABI is not x86_64: {values!r}")
        writable = False
        last_probe_error = b""
        for _ in range(120):
            probe = self._adb(
                "-s",
                self.adb_address,
                "shell",
                "su 0 sh -c 'touch /system/umat-writable-probe && rm /system/umat-writable-probe'",
                check=False,
            )
            if probe.returncode == 0:
                writable = True
                break
            last_probe_error = probe.stderr or probe.stdout
            time.sleep(1)
        if not writable:
            raise RuntimeError(
                "ReDroid system partition is not writable through su: "
                + last_probe_error.decode(errors="replace").strip()
            )
        pcap = workspace / "android-capture.pcap"
        self.capture_log_stream = (workspace / "tcpdump.log").open("ab")
        self.capture_process = subprocess.Popen(  # noqa: S603
            [
                "/usr/bin/docker",
                "exec",
                container_name,
                "/system/bin/tcpdump",
                "-U",
                "-i",
                "any",
                "-w",
                "/umat/android-capture.pcap",
            ],
            stdout=subprocess.DEVNULL,
            stderr=self.capture_log_stream,
        )
        self.running = RunningAVD(container_name, self.adb_address, pcap, guest_ip)
        return self.running

    def enable_analysis_proxy(self, workspace: Path) -> dict[str, Any]:
        """Start an isolated evidence proxy and configure the disposable guest."""
        if self.network_mode != "isolated_simulated" or not self.container_name:
            return {"status": "not_applicable"}
        evidence = workspace / "mitmproxy"
        evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
        # The pinned image runs as an unprivileged account. Docker bind mounts
        # retain host ownership, so grant only this disposable evidence folder.
        evidence.chmod(0o777)
        name = f"{self.container_name}-mitm"
        addon = Path(__file__).parents[3] / "deployment/android/mitmproxy_capture.py"
        self._docker(
            "run",
            "-d",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            "--pull",
            "never",
            "--entrypoint",
            "/usr/local/bin/mitmdump",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "--network",
            "umat-android-isolated",
            "--ip",
            "172.30.0.3",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=32m",  # noqa: S108 - container-private tmpfs
            "-v",
            f"{evidence}:/evidence",
            "-v",
            f"{addon}:/capture.py:ro",
            self.mitmproxy_image,
            "--listen-host",
            "0.0.0.0",  # noqa: S104 - reachable only on the internal run network
            "--listen-port",
            "8080",
            "--set",
            "confdir=/evidence/certs",
            "--set",
            "hardump=/evidence/traffic.har",
            "--set",
            "termlog_verbosity=info",
            "-w",
            "/evidence/flows.mitm",
            "-s",
            "/capture.py",
        )
        self.proxy_container_name = name
        self.proxy_evidence_dir = evidence
        self.proxy_address = self._docker(
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            name,
        ).stdout.decode().strip()
        if self.proxy_address != "172.30.0.3":
            raise RuntimeError("mitmproxy sidecar did not receive its restricted address")
        certificate = evidence / "certs" / "mitmproxy-ca-cert.cer"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not certificate.is_file():
            if self._docker("inspect", "-f", "{{.State.Running}}", name, check=False).stdout.strip() != b"true":
                raise RuntimeError("mitmproxy sidecar stopped during startup")
            time.sleep(0.25)
        if not certificate.is_file():
            raise RuntimeError("mitmproxy sidecar did not generate its run-scoped CA")
        digest = subprocess.run(  # noqa: S603
            ["/usr/bin/openssl", "x509", "-inform", "PEM", "-subject_hash_old", "-in", str(certificate)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()[0]
        remote = "/data/local/tmp/umat-mitm-ca.cer"
        self._adb("-s", self.adb_address, "push", str(certificate), remote)
        target = f"/system/etc/security/cacerts/{digest}.0"
        self._adb("-s", self.adb_address, "shell", "su", "0", "cp", remote, target)
        self._adb("-s", self.adb_address, "shell", "su", "0", "chmod", "644", target)
        self.ensure_analysis_proxy()
        return {
            "status": "active",
            "address": self.proxy_address,
            "port": 8080,
            "ca_subject_hash": digest,
            "network": "umat-android-isolated",
            "upstream": "none",
        }

    def ensure_analysis_proxy(self) -> None:
        if self.proxy_address:
            self._adb(
                "-s", self.adb_address, "shell", "settings", "put", "global", "http_proxy",
                f"{self.proxy_address}:8080",
            )

    def proxy_evidence(self) -> dict[str, Path]:
        root = self.proxy_evidence_dir
        if not root:
            return {}
        candidates = {
            "mitmproxy_flows": root / "flows.mitm",
            "mitmproxy_har": root / "traffic.har",
            "mitmproxy_events": root / "events.jsonl",
            "mitmproxy_ca": root / "certs" / "mitmproxy-ca-cert.cer",
        }
        return {kind: path for kind, path in candidates.items() if path.is_file()}

    def stimulate(self, duration_seconds: int, max_actions: int) -> dict[str, Any]:
        actions = [
            ("keyevent", "82"),
            ("tap", "540", "960"),
            ("swipe", "540", "1500", "540", "450", "400"),
            ("keyevent", "4"),
        ]
        started, completed = time.monotonic(), 0
        while completed < max_actions and time.monotonic() - started < duration_seconds:
            action = actions[completed % len(actions)]
            result = self._adb("-s", self.adb_address, "shell", "input", *action, check=False)
            if result.returncode != 0:
                break
            completed += 1
            time.sleep(1)
        return {
            "strategy": "deterministic_adb_v1",
            "requested_duration_seconds": duration_seconds,
            "max_actions": max_actions,
            "actions_completed": completed,
            "complete": completed == max_actions,
        }

    def prepare_analysis(self, package_name: str, permissions: list[str]) -> dict[str, Any]:
        """Prepare deterministic, synthetic victim state without exposing host data."""
        grantable = {
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CALL_PHONE",
            "android.permission.CAMERA",
            "android.permission.GET_ACCOUNTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.SEND_SMS",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.WRITE_CONTACTS",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        }
        granted: list[str] = []
        grant_failures: dict[str, str] = {}
        for permission in sorted(set(permissions) & grantable):
            result = self._adb(
                "-s",
                self.adb_address,
                "shell",
                "pm",
                "grant",
                package_name,
                permission,
                check=False,
            )
            if result.returncode == 0:
                granted.append(permission)
            else:
                grant_failures[permission] = (result.stderr or result.stdout).decode(
                    errors="replace"
                )[:500]

        fixtures: dict[str, Any] = {}
        if "android.permission.READ_SMS" in permissions:
            fixtures["sms"] = self._seed_content(
                "content://sms/inbox",
                [
                    "--bind",
                    "address:s:+15550102020",
                    "--bind",
                    "body:s:UMAT_SYNTHETIC_OTP_482913",
                    "--bind",
                    "read:i:0",
                ],
            )
        if "android.permission.READ_CONTACTS" in permissions:
            raw = self._seed_content(
                "content://com.android.contacts/raw_contacts",
                ["--bind", "account_type:s:org.umat.fixture", "--bind", "account_name:s:UMAT"],
            )
            fixtures["contact"] = raw
            query = self._adb(
                "-s",
                self.adb_address,
                "shell",
                "su",
                "0",
                "content",
                "query",
                "--uri",
                "content://com.android.contacts/raw_contacts",
                "--projection",
                "_id",
                "--sort",
                "_id DESC",
                check=False,
            )
            raw_id = ""
            output = query.stdout.decode(errors="replace")
            if "_id=" in output:
                raw_id = output.split("_id=", 1)[1].split(",", 1)[0].splitlines()[0].strip()
            if raw_id.isdigit():
                fixtures["contact_name"] = self._seed_content(
                    "content://com.android.contacts/data",
                    [
                        "--bind",
                        f"raw_contact_id:i:{raw_id}",
                        "--bind",
                        "mimetype:s:vnd.android.cursor.item/name",
                        "--bind",
                        "data1:s:UMAT Synthetic Contact",
                    ],
                )
                fixtures["contact_phone"] = self._seed_content(
                    "content://com.android.contacts/data",
                    [
                        "--bind",
                        f"raw_contact_id:i:{raw_id}",
                        "--bind",
                        "mimetype:s:vnd.android.cursor.item/phone_v2",
                        "--bind",
                        "data1:s:+15550102021",
                    ],
                )
        return {
            "schema_version": "1.0",
            "package_name": package_name,
            "requested_permissions": sorted(set(permissions)),
            "granted_permissions": granted,
            "grant_failures": grant_failures,
            "synthetic_fixtures": fixtures,
        }

    def stimulate_package(self, package_name: str, main_activity: str | None) -> dict[str, Any]:
        actions: list[dict[str, Any]] = []
        if main_activity:
            component = (
                f"{package_name}/{package_name}{main_activity}"
                if main_activity.startswith(".")
                else f"{package_name}/{main_activity}"
            )
            actions.append(self._shell_action("launch_main", "am", "start", "-W", "-n", component))
        for name, command in (
            (
                "boot_completed",
                (
                    "am",
                    "broadcast",
                    "-a",
                    "android.intent.action.BOOT_COMPLETED",
                    "-p",
                    package_name,
                ),
            ),
            (
                "user_present",
                ("am", "broadcast", "-a", "android.intent.action.USER_PRESENT", "-p", package_name),
            ),
            (
                "connectivity_change",
                (
                    "am",
                    "broadcast",
                    "-a",
                    "android.net.conn.CONNECTIVITY_CHANGE",
                    "-p",
                    package_name,
                ),
            ),
        ):
            # Protected system broadcasts are rejected for adb's shell UID on
            # Android 11. ReDroid is disposable and rooted specifically for
            # analysis, so deliver these stimuli as root and retain the result.
            actions.append(self._shell_action(name, "su", "0", *command))
        pid = (
            self._adb("-s", self.adb_address, "shell", "pidof", package_name, check=False)
            .stdout.decode(errors="replace")
            .strip()
        )
        return {"actions": actions, "package_process_ids": pid.split() if pid else []}

    def _seed_content(self, uri: str, arguments: list[str]) -> dict[str, Any]:
        result = self._adb(
            "-s",
            self.adb_address,
            "shell",
            "su",
            "0",
            "content",
            "insert",
            "--uri",
            uri,
            *arguments,
            check=False,
        )
        return {
            "success": result.returncode == 0,
            "output": (result.stdout + result.stderr).decode(errors="replace")[:1000],
        }

    def _shell_action(self, name: str, *arguments: str) -> dict[str, Any]:
        result = self._adb(
            "-s",
            self.adb_address,
            "shell",
            *arguments,
            check=False,
        )
        return {
            "name": name,
            "success": result.returncode == 0,
            "output": (result.stdout + result.stderr).decode(errors="replace")[:2000],
        }

    def collect(self, destination: Path) -> dict[str, Path]:
        destination.mkdir(parents=True, exist_ok=True)
        logcat, screenshot = destination / "logcat.txt", destination / "screenshot.png"
        logcat.write_bytes(self._adb("-s", self.adb_address, "logcat", "-d", check=False).stdout)
        screenshot.write_bytes(
            self._adb("-s", self.adb_address, "exec-out", "screencap", "-p", check=False).stdout
        )
        metadata = destination / "redroid.json"
        metadata.write_text(json.dumps({"image": self.image, "abi": "x86_64"}, sort_keys=True))
        return {"logcat": logcat, "screenshot": screenshot, "redroid_metadata": metadata}

    def screenshot(self) -> bytes:
        return self._adb("-s", self.adb_address, "exec-out", "screencap", "-p").stdout

    def input_tap(self, x: int, y: int) -> None:
        self._adb("-s", self.adb_address, "shell", "input", "tap", str(x), str(y))

    def input_swipe(self, x1: int, y1: int, x2: int, y2: int, duration_ms: int) -> None:
        self._adb(
            "-s",
            self.adb_address,
            "shell",
            "input",
            "swipe",
            str(x1),
            str(y1),
            str(x2),
            str(y2),
            str(duration_ms),
        )

    def input_key(self, keycode: int) -> None:
        self._adb("-s", self.adb_address, "shell", "input", "keyevent", str(keycode))

    def input_text(self, value: str) -> None:
        escaped = value.replace("%", "%25").replace(" ", "%s")
        self._adb("-s", self.adb_address, "shell", "input", "text", escaped)

    def logcat_tail(self, lines: int = 500) -> str:
        output = self._adb("-s", self.adb_address, "logcat", "-d", "-t", str(lines), check=False)
        return output.stdout.decode(errors="replace")[-262144:]

    def package_process_ids(self, package_name: str) -> list[str]:
        output = self._adb("-s", self.adb_address, "shell", "pidof", package_name, check=False)
        return [
            value for value in output.stdout.decode(errors="replace").split() if value.isdigit()
        ]

    def list_app_files(self, package_name: str, path: str) -> list[dict[str, Any]]:
        root = f"/data/data/{package_name}"
        requested = path.rstrip("/") or root
        if requested != root and not requested.startswith(root + "/"):
            raise ValueError("file browsing is restricted to the analyzed application")
        result: list[dict[str, Any]] = []
        for kind, file_type in (("directory", "d"), ("file", "f")):
            output = self._adb(
                "-s",
                self.adb_address,
                "shell",
                "su",
                "0",
                "find",
                requested,
                "-maxdepth",
                "1",
                "-mindepth",
                "1",
                "-type",
                file_type,
                check=False,
            ).stdout.decode(errors="replace")
            result.extend(
                {"kind": kind, "path": line}
                for line in output.splitlines()[:500]
                if line.startswith(root)
            )
        return result

    def read_app_file(self, package_name: str, path: str, maximum: int = 2 * 1024 * 1024) -> bytes:
        root = f"/data/data/{package_name}"
        if not path.startswith(root + "/"):
            raise ValueError("file access is restricted to the analyzed application")
        probe = self._adb(
            "-s",
            self.adb_address,
            "shell",
            "su",
            "0",
            "test",
            "-f",
            path,
            check=False,
        )
        if probe.returncode != 0:
            raise ValueError("requested application path is not a regular file")
        output = self._adb("-s", self.adb_address, "exec-out", "su", "0", "cat", path, check=False)
        if output.returncode != 0:
            raise RuntimeError(output.stderr.decode(errors="replace")[:2000] or "file read failed")
        if len(output.stdout) > maximum:
            raise ValueError("file exceeds the interactive download limit")
        return output.stdout

    def collect_app_data(self, destination: Path, package_name: str) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        output = self._adb(
            "-s",
            self.adb_address,
            "exec-out",
            "su",
            "0",
            "tar",
            "-c",
            "-C",
            "/data/data",
            package_name,
            check=False,
        )
        if output.returncode != 0:
            raise RuntimeError(
                output.stderr.decode(errors="replace")[:2000] or "app data archive failed"
            )
        archive = destination / "application-data.tar"
        archive.write_bytes(output.stdout)
        return archive

    def stop(self) -> None:
        if self.proxy_address:
            self._adb(
                "-s", self.adb_address, "shell", "settings", "put", "global", "http_proxy", ":0",
                check=False,
            )
        if self.proxy_container_name:
            self._docker("stop", "--time", "10", self.proxy_container_name, check=False)
            self._docker("rm", "-f", self.proxy_container_name, check=False)
        if self.proxy_evidence_dir:
            for path in self.proxy_evidence_dir.rglob("*"):
                try:
                    path.chmod(0o600 if path.is_file() else 0o700)
                except OSError:
                    pass
        if self.relay_process:
            self.relay_process.terminate()
            try:
                self.relay_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.relay_process.kill()
                self.relay_process.wait(timeout=5)
        if self.capture_process:
            self.capture_process.terminate()
            try:
                self.capture_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.capture_process.kill()
                self.capture_process.wait(timeout=5)
        if self.container_name:
            # ReDroid creates root-only credential directories in the
            # run-scoped bind mount. Make the disposable tree traversable by
            # the executor before its TemporaryDirectory performs cleanup.
            self._docker(
                "exec",
                self.container_name,
                "chmod",
                "-R",
                "a+rwX",
                "/data",
                check=False,
            )
            self._docker("rm", "-f", self.container_name, check=False)
        if self.capture_log_stream:
            self.capture_log_stream.close()
        if self.relay_log_stream:
            self.relay_log_stream.close()
        self._adb("disconnect", self.adb_address, check=False)
        self.running = None
        self.container_name = None
        self.capture_process = None
        self.capture_log_stream = None
        self.relay_process = None
        self.relay_log_stream = None
        self.proxy_container_name = None
        self.proxy_address = None

    def _adb(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603
            [str(self.adb), *arguments], capture_output=True, timeout=30, check=check
        )

    @staticmethod
    def _docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603
            ["/usr/bin/docker", *arguments], capture_output=True, timeout=120, check=check
        )
