from __future__ import annotations

import ipaddress
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO


@dataclass(frozen=True)
class RunningAVD:
    name: str
    serial: str
    pcap_path: Path
    guest_ip: str | None


class AvdManager:
    """Creates a disposable API-30 AVD and guarantees emulator shutdown/deletion."""

    def __init__(
        self,
        *,
        avdmanager: Path,
        emulator: Path,
        adb: Path,
        system_image: str,
        boot_timeout_seconds: int = 180,
        emulator_port: int = 5554,
        memory_mb: int = 4096,
        sdk_root: Path | None = None,
        adb_relay: Path | None = None,
        adb_relay_bind_address: str | None = None,
    ) -> None:
        self.avdmanager = avdmanager
        self.emulator = emulator
        self.adb = adb
        self.system_image = system_image
        self.boot_timeout_seconds = boot_timeout_seconds
        self.emulator_port = emulator_port
        self.memory_mb = memory_mb
        configured_sdk = sdk_root
        if configured_sdk is None and os.environ.get("ANDROID_SDK_ROOT"):
            configured_sdk = Path(os.environ["ANDROID_SDK_ROOT"])
        if configured_sdk is None:
            inferred = emulator.parent.parent
            system_sdk = Path("/usr/lib/android-sdk")
            configured_sdk = system_sdk if (system_sdk / "platforms").is_dir() else inferred
        self.sdk_root = configured_sdk.resolve()
        self.adb_relay = adb_relay
        self.adb_relay_bind_address = adb_relay_bind_address
        self.process: subprocess.Popen[bytes] | None = None
        self.relay_process: subprocess.Popen[bytes] | None = None
        self.log_stream: BinaryIO | None = None
        self.relay_log_stream: BinaryIO | None = None
        self.running: RunningAVD | None = None
        self.environment: dict[str, str] | None = None

    def start(self, name: str, workspace: Path) -> RunningAVD:
        if self.running:
            raise RuntimeError("AVD is already running")
        avd_home = workspace / "avds"
        avd_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        environment = os.environ.copy()
        environment["ANDROID_AVD_HOME"] = str(avd_home)
        environment["ANDROID_SDK_ROOT"] = str(self.sdk_root)
        environment["ANDROID_HOME"] = str(self.sdk_root)
        self.environment = environment
        self._run(
            [
                str(self.avdmanager),
                "create",
                "avd",
                "--force",
                "--name",
                name,
                "--package",
                self.system_image,
                "--device",
                "pixel",
            ],
            environment=environment,
            input_bytes=b"no\n",
            timeout=120,
        )
        pcap_path = workspace / "android-capture.pcap"
        command = [
            str(self.emulator),
            "-avd",
            name,
            "-port",
            str(self.emulator_port),
            "-memory",
            str(self.memory_mb),
            "-feature",
            "-PlayStoreImage",
            "-no-window",
            "-no-audio",
            "-no-boot-anim",
            "-wipe-data",
            "-no-snapshot",
            "-writable-system",
            "-tcpdump",
            str(pcap_path),
        ]
        serial = f"emulator-{self.emulator_port}"
        self.running = RunningAVD(name, serial, pcap_path, None)
        # Command elements are operator-configured executable paths and fixed arguments; no shell.
        self.log_stream = (workspace / "emulator.log").open("ab")
        self.process = subprocess.Popen(  # noqa: S603
            command, env=environment, stdout=self.log_stream, stderr=subprocess.STDOUT
        )
        self._wait_for_boot(serial, environment)
        self._prepare_rooted_guest(serial, environment)
        time.sleep(5)
        self._start_adb_relay(workspace)
        guest_ip = self._guest_ip(serial, environment)
        self.running = RunningAVD(name, serial, pcap_path, guest_ip)
        return self.running

    def _wait_for_boot(self, serial: str, environment: dict[str, str]) -> None:
        deadline = time.monotonic() + self.boot_timeout_seconds
        while time.monotonic() < deadline:
            if self.process is None or self.process.poll() is not None:
                detail = ""
                if self.log_stream:
                    self.log_stream.flush()
                    log_path = Path(self.log_stream.name)
                    if log_path.is_file():
                        detail = log_path.read_text(errors="replace")[-2000:]
                raise RuntimeError(
                    "Android emulator exited before boot completed"
                    + (f": {detail}" if detail else "")
                )
            result = self._run(
                [str(self.adb), "-s", serial, "shell", "getprop", "sys.boot_completed"],
                environment=environment,
                timeout=10,
                check=False,
            )
            if result.returncode == 0 and result.stdout.strip() == b"1":
                return
            time.sleep(2)
        raise RuntimeError("Android emulator boot timed out")

    def _prepare_rooted_guest(
        self,
        serial: str,
        environment: dict[str, str],
    ) -> None:
        """Prepare an ADB-rooted disposable guest for fail-soft analysis."""
        for arguments in (["root"], ["wait-for-device"]):
            result = self._run(
                [str(self.adb), "-s", serial, *arguments],
                environment=environment,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(f"failed to prepare Android guest: {arguments[0]}")
        probe = "/data/local/tmp/umat-writable-probe"
        identity = self._run(
            [str(self.adb), "-s", serial, "shell", "id", "-u"],
            environment=environment,
            timeout=15,
            check=False,
        )
        if identity.returncode != 0 or identity.stdout.strip() != b"0":
            raise RuntimeError("Android guest did not provide root ADB access")
        result = self._run(
            [str(self.adb), "-s", serial, "shell", "touch", probe],
            environment=environment,
            timeout=15,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Android analysis data partition is not writable")
        self._run(
            [str(self.adb), "-s", serial, "shell", "rm", probe],
            environment=environment,
            timeout=15,
            check=False,
        )

    def stimulate(self, duration_seconds: int, max_actions: int) -> dict[str, Any]:
        if not self.running or not self.environment:
            raise RuntimeError("AVD is not running")
        actions = [
            ("keyevent", "82"),
            ("tap", "540", "960"),
            ("swipe", "540", "1500", "540", "450", "400"),
            ("keyevent", "4"),
            ("tap", "270", "960"),
        ]
        started = time.monotonic()
        completed = 0
        while completed < max_actions and time.monotonic() - started < duration_seconds:
            action = actions[completed % len(actions)]
            result = self._run(
                [str(self.adb), "-s", self.running.serial, "shell", "input", *action],
                environment=self.environment,
                timeout=15,
                check=False,
            )
            if result.returncode != 0:
                break
            completed += 1
            time.sleep(min(1.0, max(0.0, duration_seconds - (time.monotonic() - started))))
        return {
            "strategy": "deterministic_adb_v1",
            "requested_duration_seconds": duration_seconds,
            "max_actions": max_actions,
            "actions_completed": completed,
            "complete": completed == max_actions,
        }

    def collect(self, destination: Path) -> dict[str, Path]:
        if not self.running or not self.environment:
            raise RuntimeError("AVD is not running")
        destination.mkdir(parents=True, exist_ok=True)
        logcat = destination / "logcat.txt"
        screenshot = destination / "screenshot.png"
        logcat.write_bytes(
            self._run(
                [str(self.adb), "-s", self.running.serial, "logcat", "-d"],
                environment=self.environment,
                timeout=30,
                check=False,
            ).stdout
        )
        screenshot.write_bytes(
            self._run(
                [str(self.adb), "-s", self.running.serial, "exec-out", "screencap", "-p"],
                environment=self.environment,
                timeout=30,
                check=False,
            ).stdout
        )
        return {"logcat": logcat, "screenshot": screenshot}

    def stop(self) -> None:
        running, environment = self.running, self.environment
        if self.relay_process:
            self.relay_process.terminate()
            try:
                self.relay_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.relay_process.kill()
                self.relay_process.wait(timeout=10)
        if self.relay_log_stream:
            self.relay_log_stream.close()
        if running and environment:
            try:
                self._run(
                    [str(self.adb), "-s", running.serial, "emu", "kill"],
                    environment=environment,
                    timeout=15,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                pass
        if self.process:
            try:
                self.process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
        if self.log_stream:
            self.log_stream.close()
        if running and environment:
            self._run(
                [str(self.avdmanager), "delete", "avd", "--name", running.name],
                environment=environment,
                timeout=30,
                check=False,
            )
        self.running = None
        self.process = None
        self.relay_process = None
        self.log_stream = None
        self.relay_log_stream = None

    def _start_adb_relay(self, workspace: Path) -> None:
        """Expose emulator ADB only on an explicitly selected bridge address."""
        if self.adb_relay is None and self.adb_relay_bind_address is None:
            return
        if self.adb_relay is None or self.adb_relay_bind_address is None:
            raise RuntimeError("ADB relay executable and bind address must be configured together")
        address = ipaddress.ip_address(self.adb_relay_bind_address)
        if address.is_unspecified or address.is_loopback or address.is_multicast:
            raise RuntimeError("ADB relay must bind a specific non-loopback bridge address")
        adb_port = self.emulator_port + 1
        listen = f"TCP-LISTEN:{adb_port},bind={address},reuseaddr,fork"
        target = f"TCP:127.0.0.1:{adb_port}"
        self.relay_log_stream = (workspace / "adb-relay.log").open("ab")
        self.relay_process = subprocess.Popen(  # noqa: S603
            [str(self.adb_relay), listen, target],
            stdout=self.relay_log_stream,
            stderr=subprocess.STDOUT,
        )
        time.sleep(0.5)
        if self.relay_process.poll() is not None:
            raise RuntimeError("ADB bridge relay exited during startup")

    def __enter__(self) -> AvdManager:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.stop()

    def _guest_ip(self, serial: str, environment: dict[str, str]) -> str | None:
        result = self._run(
            [str(self.adb), "-s", serial, "shell", "ip", "route", "get", "8.8.8.8"],
            environment=environment,
            timeout=10,
            check=False,
        )
        fields = result.stdout.decode(errors="replace").split()
        try:
            return fields[fields.index("src") + 1].split("/", 1)[0]
        except (ValueError, IndexError):
            fallback = self._run(
                [str(self.adb), "-s", serial, "shell", "ip", "-o", "-4", "addr"],
                environment=environment,
                timeout=10,
                check=False,
            )
            for line in fallback.stdout.decode(errors="replace").splitlines():
                if " scope global " in line and " inet " in line:
                    return line.split(" inet ", 1)[1].split("/", 1)[0]
            return None

    @staticmethod
    def _run(
        command: list[str],
        *,
        environment: dict[str, str],
        timeout: int,
        check: bool = True,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        # Callers supply only fixed Android SDK commands and validated run-local identifiers.
        return subprocess.run(  # noqa: S603
            command,
            env=environment,
            input=input_bytes,
            capture_output=True,
            check=check,
            timeout=timeout,
        )
