from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from umat.android.avd import RunningAVD


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
        self.running: RunningAVD | None = None
        self.environment = os.environ.copy()
        self.container_name: str | None = None
        self.capture_process: subprocess.Popen[bytes] | None = None
        self.capture_log_stream: Any | None = None
        self.relay_process: subprocess.Popen[bytes] | None = None
        self.relay_log_stream: Any | None = None

    def start(self, name: str, workspace: Path) -> RunningAVD:
        container_name = f"{name}-redroid"
        data = workspace / "redroid-data"
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
        network_arguments: list[str] = []
        publish_arguments = ["-p", f"{self.adb_address}:5555"]
        if self.network_mode == "isolated_simulated":
            network_name = "umat-android-isolated"
            if self._docker("network", "inspect", network_name, check=False).returncode != 0:
                self._docker(
                    "network",
                    "create",
                    "--internal",
                    "--subnet",
                    "172.30.0.0/24",
                    "--opt",
                    "com.docker.network.bridge.name=br-umat-android",
                    network_name,
                )
            network_arguments = ["--network", network_name]
            publish_arguments = []
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
            "-s", self.adb_address, "shell", "input", "swipe",
            str(x1), str(y1), str(x2), str(y2), str(duration_ms),
        )

    def input_key(self, keycode: int) -> None:
        self._adb("-s", self.adb_address, "shell", "input", "keyevent", str(keycode))

    def input_text(self, value: str) -> None:
        escaped = value.replace("%", "%25").replace(" ", "%s")
        self._adb("-s", self.adb_address, "shell", "input", "text", escaped)

    def logcat_tail(self, lines: int = 500) -> str:
        output = self._adb("-s", self.adb_address, "logcat", "-d", "-t", str(lines), check=False)
        return output.stdout.decode(errors="replace")[-262144:]

    def list_app_files(self, package_name: str, path: str) -> list[dict[str, Any]]:
        root = f"/data/data/{package_name}"
        requested = path.rstrip("/") or root
        if requested != root and not requested.startswith(root + "/"):
            raise ValueError("file browsing is restricted to the analyzed application")
        result: list[dict[str, Any]] = []
        for kind, file_type in (("directory", "d"), ("file", "f")):
            output = self._adb(
                "-s", self.adb_address, "shell", "su", "0", "find", requested,
                "-maxdepth", "1", "-mindepth", "1", "-type", file_type,
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
            "-s", self.adb_address, "shell", "su", "0", "test", "-f", path,
            check=False,
        )
        if probe.returncode != 0:
            raise ValueError("requested application path is not a regular file")
        output = self._adb(
            "-s", self.adb_address, "exec-out", "su", "0", "cat", path, check=False
        )
        if output.returncode != 0:
            raise RuntimeError(output.stderr.decode(errors="replace")[:2000] or "file read failed")
        if len(output.stdout) > maximum:
            raise ValueError("file exceeds the interactive download limit")
        return output.stdout

    def collect_app_data(self, destination: Path, package_name: str) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        output = self._adb(
            "-s", self.adb_address, "exec-out", "su", "0", "tar", "-c",
            "-C", "/data/data", package_name, check=False,
        )
        if output.returncode != 0:
            raise RuntimeError(output.stderr.decode(errors="replace")[:2000] or "app data archive failed")
        archive = destination / "application-data.tar"
        archive.write_bytes(output.stdout)
        return archive

    def stop(self) -> None:
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

    def _adb(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603
            [str(self.adb), *arguments], capture_output=True, timeout=30, check=check
        )

    @staticmethod
    def _docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(  # noqa: S603
            ["/usr/bin/docker", *arguments], capture_output=True, timeout=120, check=check
        )
