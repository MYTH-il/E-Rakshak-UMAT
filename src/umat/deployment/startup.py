from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import typer

from umat.deployment.cli import PROJECT_ROOT, DeploymentError, command, path_exists

ENV_FILE = Path("/etc/umat/full-stack.env")
CONTROL_PLANE_COMPOSE = PROJECT_ROOT / "deployment/single-host/compose.yaml"
ANDROID_COMPOSE = PROJECT_ROOT / "deployment/android/compose.yaml"

FOUNDATION_UNITS = (
    "docker.service",
    "libvirtd.service",
)
SECURITY_AND_CAPE_UNITS = (
    "umat-guest-guard.service",
    "umat-egress-broker.service",
    "cape-rooter.service",
    "cape.service",
    "cape-processor.service",
    "cape-web.service",
)
CONTROL_PLANE_UNITS = (
    "umat-api.service",
    "umat-scheduler.service",
    "umat-report-worker.service",
    "umat-adapter-worker.service",
    "umat-cape-gateway.service",
    "umat-android-api-relay.service",
)
EXECUTOR_UNITS = (
    "umat-windows-executor.service",
    "umat-c2-executor.service",
    "umat-android-executor.service",
)
ANDROID_WORKER_UNIT = "umat-android-worker-controller.service"
ANDROID_WORKER_IMAGE = Path(
    "/var/lib/libvirt/images/umat-android-worker/umat-android-worker-golden.qcow2"
)


def run(command_line: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        command_line,
        check=check,
        capture_output=True,
        text=True,
    )


def sudo_systemctl(action: str, units: tuple[str, ...]) -> None:
    if not units:
        return
    run([command("sudo"), "-n", command("systemctl"), action, *units])


def reset_and_start_units(units: tuple[str, ...]) -> None:
    sudo_systemctl("reset-failed", units)
    sudo_systemctl("start", units)


def compose_up(compose_file: Path) -> None:
    run(
        [
            command("sudo"),
            "-n",
            command("docker"),
            "compose",
            "--env-file",
            str(ENV_FILE),
            "-f",
            str(compose_file),
            "up",
            "-d",
            "--no-build",
            "--pull",
            "never",
        ]
    )


def wait_for_postgres(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    command_line = [
        command("sudo"),
        "-n",
        command("docker"),
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-f",
        str(CONTROL_PLANE_COMPOSE),
        "exec",
        "-T",
        "postgres",
        "pg_isready",
        "-U",
        "umat",
        "-d",
        "umat",
    ]
    while time.monotonic() < deadline:
        result = subprocess.run(  # noqa: S603
            command_line,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return
        last_error = (result.stderr or result.stdout).strip()[:500]
        time.sleep(1)
    raise DeploymentError(
        f"UMAT PostgreSQL did not become ready within {timeout:g}s: {last_error}"
    )


def wait_for_url(name: str, url: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                if response.status < 500:
                    return
                last_error = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                return
            last_error = f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(1)
    raise DeploymentError(f"{name} did not become ready within {timeout:g}s: {last_error}")


def verify_installation() -> None:
    missing = []
    for path in (ENV_FILE, CONTROL_PLANE_COMPOSE, ANDROID_COMPOSE):
        present = path_exists(path) if path == ENV_FILE else path.is_file()
        if not present:
            missing.append(str(path))
    if missing:
        raise DeploymentError(
            "UMAT is not fully installed; missing " + ", ".join(missing)
        )
    for executable in ("docker", "sudo", "systemctl"):
        command(executable)
    run([command("sudo"), "-n", "true"])


def command_error(exc: subprocess.CalledProcessError) -> str:
    output = (exc.stderr or exc.stdout or "").strip()
    if output:
        return output.splitlines()[-1][:500]
    return f"command exited with status {exc.returncode}"


def startup_step(name: str, operation: Callable[[], object]) -> None:
    try:
        operation()
    except subprocess.CalledProcessError as exc:
        raise DeploymentError(f"{name}: {command_error(exc)}") from exc
    typer.echo(f"OK   {name}")


def qualification_detail(detail: Any) -> str:
    if isinstance(detail, dict) and "expected" in detail and "observed" in detail:
        return f"expected {detail['expected']}, observed {detail['observed']}"
    if isinstance(detail, str):
        return detail
    return json.dumps(detail, sort_keys=True)


def report_deployment_status() -> bool:
    result = run(
        [str(PROJECT_ROOT / ".venv/bin/umat-deploy"), "status"],
        check=False,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        detail = (result.stderr or result.stdout).strip() or "status returned no diagnostic"
        typer.echo(f"FAIL deployment qualification: {detail[:500]}", err=True)
        return False

    failed = [
        (name, check)
        for name, check in report.get("checks", {}).items()
        if check.get("status") == "failed"
    ]
    degraded = [
        (name, check)
        for name, check in report.get("checks", {}).items()
        if check.get("status") == "degraded"
    ]
    for name, check in degraded:
        typer.echo(f"WARN {name}: {qualification_detail(check.get('detail'))}")
    for name, check in failed:
        typer.echo(f"FAIL {name}: {qualification_detail(check.get('detail'))}", err=True)
    if failed or result.returncode != 0 or not report.get("healthy", False):
        return False
    passed = report.get("summary", {}).get("passed", 0)
    typer.echo(f"OK   deployment qualification ({passed} checks passed)")
    return True


def start_system(*, timeout: float, skip_status: bool) -> None:
    """Bring an installed single-host UMAT system to a healthy running state."""
    try:
        startup_step("installation and privileges", verify_installation)
        startup_step("Docker and libvirt", lambda: sudo_systemctl("start", FOUNDATION_UNITS))
        startup_step("UMAT PostgreSQL container", lambda: compose_up(CONTROL_PLANE_COMPOSE))
        startup_step("UMAT PostgreSQL readiness", lambda: wait_for_postgres(timeout))
        startup_step("Android and MobSF containers", lambda: compose_up(ANDROID_COMPOSE))

        startup_step(
            "guest firewall, egress broker, and CAPE",
            lambda: reset_and_start_units(SECURITY_AND_CAPE_UNITS),
        )
        startup_step(
            "UMAT control plane",
            lambda: reset_and_start_units(CONTROL_PLANE_UNITS),
        )

        startup_step(
            "UMAT API readiness",
            lambda: wait_for_url("UMAT API", "http://127.0.0.1:8080/health/live", timeout),
        )
        startup_step(
            "CAPE gateway readiness",
            lambda: wait_for_url(
                "CAPE gateway", "http://127.0.0.1:8091/health/live", timeout
            ),
        )
        startup_step(
            "MobSF readiness",
            lambda: wait_for_url("MobSF", "http://127.0.0.1:8001/", timeout),
        )

        startup_step(
            "Windows, C2, and Android executors",
            lambda: reset_and_start_units(EXECUTOR_UNITS),
        )
        if path_exists(ANDROID_WORKER_IMAGE):
            startup_step(
                "disposable Android worker",
                lambda: reset_and_start_units((ANDROID_WORKER_UNIT,)),
            )

        if not skip_status and not report_deployment_status():
            typer.echo(
                "UMAT services are running, but required qualification checks failed.",
                err=True,
            )
            raise typer.Exit(1)
        typer.echo("READY http://127.0.0.1:8080")
    except DeploymentError as exc:
        typer.echo(f"FAIL {exc}", err=True)
        raise typer.Exit(1) from exc
