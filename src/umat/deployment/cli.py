from __future__ import annotations

import getpass
import hashlib
import json
import os
import platform
import secrets
import shlex
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

import typer

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = PROJECT_ROOT / "deployment/full-stack/manifest.json"
COMPONENTS = ("control-plane", "windows", "android", "c2", "services")
app = typer.Typer(no_args_is_help=True)


class DeploymentError(RuntimeError):
    pass


def load_manifest() -> dict[str, Any]:
    value = json.loads(MANIFEST_PATH.read_text())
    if value.get("schema_version") != "1.0":
        raise DeploymentError("unsupported deployment manifest version")
    return cast(dict[str, Any], value)


@dataclass
class CommandRunner:
    execute: bool

    def run(
        self,
        command_line: list[str],
        *,
        cwd: Path | None = None,
        environment: dict[str, str] | None = None,
    ) -> None:
        typer.echo(f"+ {shlex.join(command_line)}")
        if not self.execute:
            return
        subprocess.run(  # noqa: S603
            command_line,
            cwd=cwd,
            env=environment,
            check=True,
        )


def command(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise DeploymentError(f"required command is unavailable: {name}")
    return resolved


def preflight_checks(windows_iso: Path | None = None) -> list[dict[str, Any]]:
    expected = load_manifest()["supported_host"]
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    os_release: dict[str, str] = {}
    release_path = Path("/etc/os-release")
    if release_path.is_file():
        for line in release_path.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip('"')
    add(
        "host_os",
        os_release.get("ID") == expected["distribution"]
        and os_release.get("VERSION_ID") == expected["version"],
        f"{os_release.get('ID', 'unknown')} {os_release.get('VERSION_ID', 'unknown')}",
    )
    machine = platform.machine()
    add("architecture", machine == expected["architecture"], machine)
    memory_kib = 0
    available_memory_kib = 0
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemTotal:"):
            memory_kib = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            available_memory_kib = int(line.split()[1])
            break
    memory_gib = memory_kib / 1024 / 1024
    add("memory", memory_gib >= expected["minimum_memory_gib"], f"{memory_gib:.1f} GiB")
    available_memory_gib = available_memory_kib / 1024 / 1024
    add(
        "available_memory",
        available_memory_gib >= expected["minimum_available_memory_gib"],
        f"{available_memory_gib:.1f} GiB",
    )
    free_gib = shutil.disk_usage(PROJECT_ROOT).free / 1024**3
    add("free_disk", free_gib >= expected["minimum_free_disk_gib"], f"{free_gib:.1f} GiB")
    add("kvm", Path("/dev/kvm").exists(), "/dev/kvm")
    for executable in (
        "curl",
        "docker",
        "git",
        "patch",
        "qemu-img",
        "sudo",
        "systemctl",
        "tar",
        "uv",
        "virsh",
    ):
        resolved = shutil.which(executable)
        add(f"command:{executable}", resolved is not None, resolved or "missing")
    sudo = shutil.which("sudo")
    docker = shutil.which("docker")
    if sudo and docker:
        docker_info = subprocess.run(  # noqa: S603
            [sudo, "-n", docker, "info"], check=False, capture_output=True, text=True
        )
        add(
            "docker_daemon",
            docker_info.returncode == 0,
            "reachable through sudo" if docker_info.returncode == 0 else docker_info.stderr.strip(),
        )
    if windows_iso is not None:
        resolved_iso = windows_iso.expanduser().resolve()
        add(
            "windows_iso",
            resolved_iso.is_file() and os.access(resolved_iso, os.R_OK),
            str(resolved_iso),
        )
    return checks


def ensure_preflight(windows_iso: Path | None) -> None:
    failed = [item for item in preflight_checks(windows_iso) if not item["passed"]]
    if failed:
        detail = "; ".join(f"{item['name']}: {item['detail']}" for item in failed)
        raise DeploymentError(f"deployment preflight failed: {detail}")


def verify_checkout(path: Path, component: dict[str, Any]) -> None:
    git = [command("git"), "-c", f"safe.directory={path}", "-C", str(path)]
    observed = subprocess.run(  # noqa: S603
        [*git, "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if observed != component["commit"]:
        raise DeploymentError(
            f"checkout revision mismatch at {path}: expected {component['commit']}, observed {observed}"
        )
    dirty = subprocess.run(  # noqa: S603
        [*git, "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if dirty:
        raise DeploymentError(f"checkout is modified and will not be overwritten: {path}")
    expected_tree = component.get("tree_sha256")
    if expected_tree:
        archive = subprocess.run(  # noqa: S603
            [*git, "archive", component["commit"]],
            check=True,
            capture_output=True,
        ).stdout
        if hashlib.sha256(archive).hexdigest() != expected_tree:
            raise DeploymentError(f"source tree digest mismatch at {path}")


def acquire_checkout(runner: CommandRunner, path: Path, component: dict[str, Any]) -> None:
    if path.exists():
        if runner.execute:
            verify_checkout(path, component)
        else:
            typer.echo(f"= verify existing checkout {path}")
        return
    runner.run([command("sudo"), "-n", "install", "-d", "-m", "0755", str(path.parent)])
    runner.run(
        [
            command("sudo"),
            "-n",
            command("git"),
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            component["repository"],
            str(path),
        ]
    )
    runner.run(
        [
            command("sudo"),
            "-n",
            command("git"),
            "-C",
            str(path),
            "checkout",
            "--detach",
            component["commit"],
        ]
    )
    if runner.execute:
        verify_checkout(path, component)


def install_environment(runner: CommandRunner, manifest: dict[str, Any]) -> Path:
    configuration_root = Path(manifest["paths"]["configuration_root"])
    state_root = Path(manifest["paths"]["state_root"])
    destination = configuration_root / "full-stack.env"
    typer.echo(f"+ install generated secrets at {destination}")
    if not runner.execute:
        return destination
    descriptor, temporary_name = tempfile.mkstemp(prefix="umat-deploy-", suffix=".env")
    os.close(descriptor)
    local = Path(temporary_name)
    existing = read_environment_text(destination) if path_exists(destination) else ""
    existing_values = {
        line.split("=", 1)[0]: line.split("=", 1)[1]
        for line in existing.splitlines()
        if line and not line.startswith("#") and "=" in line
    }
    present = set(existing_values)
    postgres_password = existing_values.get("UMAT_POSTGRES_PASSWORD", secrets.token_urlsafe(36))
    values = [
        ("UMAT_POSTGRES_PASSWORD", postgres_password),
        ("MOBSF_DATABASE_PASSWORD", secrets.token_urlsafe(36)),
        ("MOBSF_API_KEY", secrets.token_urlsafe(48)),
        (
            "MOBSF_POSTGRES_IMAGE_DIGEST",
            "95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b",
        ),
        ("MOBSF_IMAGE", "umat-mobsf:6462901d"),
        (
            "UMAT_DATABASE_URL",
            f"postgresql+asyncpg://umat:{postgres_password}@127.0.0.1:55432/umat",
        ),
        ("UMAT_ENVIRONMENT", "local"),
        ("UMAT_API_HOST", "127.0.0.1"),
        ("UMAT_API_PORT", "8080"),
        # The single-host deployment binds the UI to loopback over HTTP.
        # Secure cookies are appropriate only after a TLS reverse proxy is
        # configured; enabling them here prevents browsers from authenticating.
        ("UMAT_SECURE_COOKIES", "false"),
        ("UMAT_ALLOWED_HOSTS", '["localhost","127.0.0.1","10.67.0.1"]'),
        ("UMAT_SESSION_SECRET", secrets.token_urlsafe(48)),
        ("UMAT_EXECUTOR_ENROLLMENT_SECRET", secrets.token_urlsafe(48)),
        ("UMAT_CAPE_GATEWAY_TOKEN", secrets.token_urlsafe(48)),
        ("UMAT_CAPE_GATEWAY_HOST", "127.0.0.1"),
        ("UMAT_CAPE_GATEWAY_PORT", "8091"),
        ("UMAT_CAPE_MANAGEMENT_URL", "http://127.0.0.1:8091"),
        ("UMAT_QUARANTINE_ROOT", "/var/lib/umat/quarantine"),
        ("UMAT_ARTIFACT_ROOT", "/var/lib/umat/artifacts"),
        ("UMAT_C2_RUNTIME_ROOT", "/srv/winstdt/libexec/c2-exfil/478f131-umat.2"),
        ("UMAT_GEOLITE2_CITY_DB", "/srv/winstdt/c2-data/GeoLite2-City.mmdb"),
        ("UMAT_GEOLITE2_ASN_DB", "/srv/winstdt/c2-data/GeoLite2-ASN.mmdb"),
        ("UMAT_WINSTDT_SCHEMA_ROOT", "/opt/umat/upstreams/winstdt/schemas"),
    ]
    additions = [f"{key}={value}" for key, value in values if key not in present]
    if existing:
        typer.echo(f"= preserve existing secrets and add {len(additions)} missing settings")
    content = existing.rstrip("\n") + ("\n" if existing else "") + "\n".join(additions) + "\n"
    local.write_text(content)
    local.chmod(0o600)
    service_group = subprocess.run(  # noqa: S603
        [command("id"), "-gn"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    try:
        runner.run(
            [
                command("sudo"),
                "-n",
                "install",
                "-d",
                "-o",
                "root",
                "-g",
                service_group,
                "-m",
                "0750",
                str(configuration_root),
            ]
        )
        runner.run([command("sudo"), "-n", "install", "-d", "-m", "0750", str(state_root)])
        runner.run(
            [
                command("sudo"),
                "-n",
                "install",
                "-o",
                "root",
                "-g",
                service_group,
                "-m",
                "0640",
                str(local),
                str(destination),
            ]
        )
    finally:
        local.unlink(missing_ok=True)
    return destination


def selected_components(component: list[str]) -> set[str]:
    selected = set(component or COMPONENTS)
    unknown = selected - set(COMPONENTS)
    if unknown:
        raise DeploymentError(f"unknown deployment components: {sorted(unknown)}")
    return selected


def windows_guest_present() -> bool:
    virsh = shutil.which("virsh")
    if not virsh:
        return False
    result = subprocess.run(  # noqa: S603
        [virsh, "-c", "qemu:///system", "dominfo", "winstdt-win10-22h2"],
        check=False,
        capture_output=True,
    )
    return result.returncode == 0


def read_environment(path: Path) -> dict[str, str]:
    environment = os.environ.copy()
    if os.access(path, os.R_OK):
        content = path.read_text()
    else:
        content = subprocess.run(  # noqa: S603
            [command("sudo"), "-n", "cat", str(path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    for line in content.splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            environment[key] = value
    return environment


def record_state(runner: CommandRunner, manifest: dict[str, Any], components: set[str]) -> None:
    if not runner.execute:
        return
    state = {
        "schema_version": "1.0",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "components": sorted(components),
        "project_root": str(PROJECT_ROOT),
        "operator": getpass.getuser(),
    }
    descriptor, temporary_name = tempfile.mkstemp(prefix="umat-deployment-state-", suffix=".json")
    os.close(descriptor)
    local = Path(temporary_name)
    local.write_text(json.dumps(state, indent=2) + "\n")
    try:
        runner.run(
            [
                command("sudo"),
                "-n",
                "install",
                "-m",
                "0640",
                str(local),
                str(Path(manifest["paths"]["state_root"]) / "state.json"),
            ]
        )
    finally:
        local.unlink(missing_ok=True)


@app.command("preflight")
def preflight(
    windows_iso: Path | None = typer.Option(None, help="Licensed Windows 10 22H2 x64 ISO"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    checks = preflight_checks(windows_iso)
    if json_output:
        typer.echo(json.dumps({"checks": checks}, indent=2))
    else:
        for item in checks:
            status = "PASS" if item["passed"] else "FAIL"
            typer.echo(f"{status} {item['name']}: {item['detail']}")
    if any(not item["passed"] for item in checks):
        raise typer.Exit(1)


@app.command("install")
def install(
    execute: bool = typer.Option(False, "--execute", help="Apply host changes; default is dry-run"),
    component: list[str] = typer.Option([], "--component"),
    windows_iso: Path | None = typer.Option(None, help="Licensed Windows 10 22H2 x64 ISO"),
    accept_unlicensed_source: bool = typer.Option(
        False,
        "--accept-unlicensed-source",
        help="Confirm local authorization for WinST/DT and C2 source",
    ),
    allow_no_windows_guest: bool = typer.Option(
        False,
        help="Install the Windows host stack without completing a guest VM",
    ),
    skip_runtime_acceptance: bool = typer.Option(
        False,
        help="Explicitly leave harmless upstream runtime acceptance pending",
    ),
    admin_username: str = typer.Option("admin"),
    admin_password_file: Path | None = typer.Option(
        None, help="Mode-0600 password file used only when the administrator is absent"
    ),
    skip_admin_bootstrap: bool = typer.Option(False),
    skip_executor_enrollment: bool = typer.Option(
        False, help="Install executor units but leave one-time enrollment pending"
    ),
    accept_android_sdk_licenses: bool = typer.Option(
        False, help="Accept Android SDK licenses for the pinned API-30 runtime"
    ),
) -> None:
    manifest = load_manifest()
    selected = selected_components(component)
    if execute and selected.intersection({"windows", "c2"}) and not accept_unlicensed_source:
        raise typer.BadParameter(
            "Windows/C2 installation requires explicit --accept-unlicensed-source authorization"
        )
    if execute and "android" in selected and not accept_android_sdk_licenses:
        raise typer.BadParameter(
            "Android installation requires explicit --accept-android-sdk-licenses"
        )
    if (
        execute
        and "windows" in selected
        and windows_iso is None
        and not windows_guest_present()
        and not allow_no_windows_guest
    ):
        raise typer.BadParameter(
            "a licensed --windows-iso is required until the baseline Windows guest exists"
        )
    ensure_preflight(windows_iso if "windows" in selected else None)
    runner = CommandRunner(execute)
    if execute:
        runner.run([command("sudo"), "-n", "true"])
    environment_file = install_environment(runner, manifest)

    if "c2" in selected:
        acquire_checkout(
            runner,
            Path(manifest["paths"]["c2_checkout"]),
            manifest["components"]["c2"],
        )
        winstdt_checkout = Path(manifest["paths"]["winstdt_checkout"])
        acquire_checkout(runner, winstdt_checkout, manifest["components"]["winstdt"])
        c2_setup = [str(PROJECT_ROOT / "deployment/c2/install-runtime.sh")]
        if execute:
            c2_setup.append("--execute")
        runner.run(c2_setup, cwd=PROJECT_ROOT)

    if "windows" in selected:
        runner.run(
            [command("sudo"), "-n", "apt-get", "install", "-y", "tigervnc-viewer"],
            cwd=PROJECT_ROOT,
        )
        checkout = Path(manifest["paths"]["winstdt_checkout"])
        acquire_checkout(runner, checkout, manifest["components"]["winstdt"])
        setup = [str(checkout / "scripts/setup-ubuntu24-host.sh")]
        if windows_iso:
            setup.extend(["--windows-iso", str(windows_iso.expanduser().resolve())])
        if execute:
            setup.append("--execute")
        runner.run(setup, cwd=checkout)
        runtime = [str(checkout / "scripts/configure-cape-runtime.sh")]
        if execute:
            runtime.append("--execute")
        # ``uv run`` prepends the project virtualenv to PATH.  The WinST-DT
        # runtime post-check intentionally validates the distro's
        # python3-libvirt package, so keep that script on the host toolchain.
        host_environment = os.environ.copy()
        # Keep the single-host Windows guest within the host's memory budget.
        host_environment.setdefault("VM_RAM_MB", "4096")
        host_environment["PATH"] = os.pathsep.join(
            entry
            for entry in host_environment.get("PATH", "").split(os.pathsep)
            if Path(entry).resolve() != (PROJECT_ROOT / ".venv" / "bin").resolve()
        )
        runner.run(runtime, cwd=checkout, environment=host_environment)
        cape_integration = [
            str(PROJECT_ROOT / "deployment/full-stack/configure-cape-integration.sh")
        ]
        if execute:
            cape_integration.append("--execute")
        runner.run(cape_integration)
        if not allow_no_windows_guest and not skip_runtime_acceptance:
            acceptance = [str(checkout / "scripts/validate-deployment.sh")]
            if execute:
                acceptance.append("--execute")
            runner.run(acceptance, cwd=checkout)

    if "android" in selected:
        checkout = Path(manifest["paths"]["android_checkout"])
        acquire_checkout(runner, checkout, manifest["components"]["android"])
        android_runtime = [str(PROJECT_ROOT / "deployment/android/install-runtime.sh")]
        if execute:
            android_runtime.extend(["--execute", "--accept-sdk-licenses"])
        runner.run(android_runtime)
        bootstrap = [
            command("sudo"),
            "-n",
            str(PROJECT_ROOT / "deployment/android/bootstrap.sh"),
            str(checkout),
        ]
        runner.run(bootstrap)
        runner.run(
            [
                command("sudo"),
                "-n",
                command("docker"),
                "compose",
                "--env-file",
                str(environment_file),
                "-f",
                str(PROJECT_ROOT / "deployment/android/compose.yaml"),
                "up",
                "-d",
            ]
        )

    if "control-plane" in selected:
        runner.run([command("uv"), "sync", "--frozen", "--extra", "test"], cwd=PROJECT_ROOT)
        runner.run(
            [
                command("sudo"),
                "-n",
                command("docker"),
                "compose",
                "--env-file",
                str(environment_file),
                "-f",
                str(PROJECT_ROOT / "deployment/single-host/compose.yaml"),
                "up",
                "-d",
            ]
        )
        environment = read_environment(environment_file) if execute else None
        runner.run(
            [command("uv"), "run", "alembic", "upgrade", "head"],
            cwd=PROJECT_ROOT,
            environment=environment,
        )
        if not skip_admin_bootstrap:
            administrator = [
                command("uv"),
                "run",
                "umat",
                "admin",
                "create-user",
                "--username",
                admin_username,
                "--role",
                "administrator",
                "--if-missing",
                "--non-interactive",
            ]
            if admin_password_file is not None:
                administrator.extend(
                    ["--password-file", str(admin_password_file.expanduser().resolve())]
                )
            runner.run(
                administrator,
                cwd=PROJECT_ROOT,
                environment=environment,
            )
            runner.run(
                [
                    command("uv"),
                    "run",
                    "umat",
                    "admin",
                    "seed-android-profiles",
                    "--admin",
                    admin_username,
                ],
                cwd=PROJECT_ROOT,
                environment=environment,
            )

    if "services" in selected:
        # Static fallback IOC validation uses the distro's offline public suffix
        # snapshot. The fail-closed egress broker invokes distro tcpdump at the
        # fixed /usr/bin/tcpdump path and validates its PCAP before opening a
        # network lease. Install it here too because umat-deploy may be run
        # without the clean-host bootstrap.
        runner.run(
            [command("sudo"), "-n", "apt-get", "install", "-y", "publicsuffix", "tcpdump"],
            cwd=PROJECT_ROOT,
        )
        service_script = PROJECT_ROOT / "deployment/full-stack/install-services.sh"
        arguments = [str(service_script), "--project-root", str(PROJECT_ROOT)]
        if execute:
            arguments.append("--execute")
        runner.run(arguments)
        if not skip_executor_enrollment:
            enrollment_script = PROJECT_ROOT / "deployment/full-stack/enroll-executors.sh"
            enrollment_base = [
                str(enrollment_script),
                "--project-root",
                str(PROJECT_ROOT),
                "--admin",
                admin_username,
            ]
            for executor_component in ("windows", "c2", "android"):
                if executor_component in selected:
                    runner.run([*enrollment_base, "--component", executor_component])
    record_state(runner, manifest, selected)
    if execute:
        runner.run([str(PROJECT_ROOT / ".venv/bin/umat-deploy"), "status"])
    typer.echo("deployment complete" if execute else "dry-run complete; no host changes made")


def new_status_report() -> dict[str, Any]:
    return {
        "schema_version": "1.1",
        "healthy": True,
        "degraded": False,
        "summary": {"passed": 0, "degraded": 0, "failed": 0},
        "checks": {},
    }


def record_status_check(
    report: dict[str, Any],
    name: str,
    passed: bool,
    detail: Any,
    *,
    required: bool = True,
) -> None:
    status_value = "passed" if passed else "failed" if required else "degraded"
    report["checks"][name] = {
        "passed": passed,
        "requirement": "required" if required else "optional",
        "status": status_value,
        "detail": detail,
    }
    report["summary"][status_value] += 1
    if not passed and required:
        report["healthy"] = False
    if not passed and not required:
        report["degraded"] = True


@app.command("status")
def status() -> None:
    manifest = load_manifest()
    paths = manifest["paths"]
    results = new_status_report()

    def check(name: str, passed: bool, detail: Any, *, required: bool = True) -> None:
        record_status_check(results, name, passed, detail, required=required)

    locations = {
        "winstdt": paths["winstdt_checkout"],
        "cape": paths["cape_root"],
        "c2_runtime": (
            f"{paths['winstdt_runtime_root']}/libexec/c2-exfil/"
            f"{manifest['components']['c2']['effective_version']}"
        ),
        "c2_source": paths["c2_checkout"],
        "android": paths["android_checkout"],
    }
    for name, location in locations.items():
        check(f"path:{name}", Path(location).exists(), location)
    uv_version = subprocess.run(  # noqa: S603
        [command("uv"), "--version"], check=False, capture_output=True, text=True
    ).stdout.strip()
    check(
        "installer_uv",
        uv_version
        == f"uv {manifest['components']['installer']['uv_version']} (x86_64-unknown-linux-gnu)",
        uv_version,
    )
    for name, component_key, location in (
        ("winstdt_revision", "winstdt", paths["winstdt_checkout"]),
        ("cape_revision", "cape", paths["cape_root"]),
        ("c2_revision", "c2", paths["c2_checkout"]),
        ("android_revision", "android", paths["android_checkout"]),
    ):
        path = Path(location)
        if not (path / ".git").exists():
            check(name, False, "checkout unavailable")
            continue
        observed = subprocess.run(  # noqa: S603
            [command("git"), "-c", f"safe.directory={path}", "-C", str(path), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
        expected = manifest["components"][component_key]["commit"]
        check(name, observed == expected, {"expected": expected, "observed": observed})
    for service in (
        "cape.service",
        "cape-processor.service",
        "cape-web.service",
        "umat-api.service",
        "umat-scheduler.service",
        "umat-report-worker.service",
        "umat-adapter-worker.service",
        "umat-cape-gateway.service",
        "umat-windows-executor.service",
        "umat-c2-executor.service",
        "umat-android-executor.service",
    ):
        active = (
            subprocess.run(  # noqa: S603
                [command("systemctl"), "is-active", "--quiet", service], check=False
            ).returncode
            == 0
        )
        check(f"service:{service}", active, "active" if active else "inactive")
    domain = "winstdt-win10-22h2"
    domain_present = (
        subprocess.run(  # noqa: S603
            [command("virsh"), "-c", "qemu:///system", "dominfo", domain],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )
    check("windows_baseline_domain", domain_present, domain)
    snapshot = "hardened-baseline-controlled-egress-v2"
    snapshot_present = (
        subprocess.run(  # noqa: S603
            [command("virsh"), "-c", "qemu:///system", "snapshot-info", domain, snapshot],
            check=False,
            capture_output=True,
        ).returncode
        == 0
    )
    check("windows_baseline_snapshot", snapshot_present, snapshot)
    android = manifest["components"]["android"]
    image = android["image"]
    image_id = subprocess.run(  # noqa: S603
        [
            command("sudo"),
            "-n",
            command("docker"),
            "image",
            "inspect",
            image,
            "--format",
            "{{.Id}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    check(
        "android_image",
        image_id == android["image_digest"],
        {"expected": android["image_digest"], "observed": image_id},
    )

    redroid = android["runtimes"]["redroid"]
    redroid_inspection = subprocess.run(  # noqa: S603
        [
            command("sudo"),
            "-n",
            command("docker"),
            "image",
            "inspect",
            redroid["image"],
            "--format",
            "{{json .RepoDigests}}|{{.Architecture}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    redroid_observed = redroid_inspection.stdout.strip()
    expected_repo_digest = redroid["image"].removeprefix("docker.io/")
    redroid_present = (
        redroid_inspection.returncode == 0
        and expected_repo_digest in redroid_observed
        and redroid_observed.endswith(f"|{redroid['architecture']}")
    )
    check(
        "android_runtime:redroid",
        redroid_present,
        {
            "expected_image": redroid["image"],
            "expected_architecture": redroid["architecture"],
            "observed": redroid_observed or redroid_inspection.stderr.strip()[:500],
            "qualification": redroid["qualification"],
        },
        required=bool(redroid["required"]),
    )

    avd = android["runtimes"]["aosp_avd"]
    emulator = Path(avd["emulator_path"])
    emulator_output = (
        subprocess.run(  # noqa: S603
            [str(emulator), "-version"], check=False, capture_output=True, text=True
        ).stdout
        if emulator.is_file()
        else ""
    )
    expected_emulator = avd["emulator_version"]
    observed_emulator = next(
        (
            line
            for line in emulator_output.splitlines()
            if line.startswith("Android emulator version ")
        ),
        "unavailable",
    )
    check(
        "android_runtime:aosp_avd",
        f"Android emulator version {expected_emulator}" in emulator_output,
        {
            "path": str(emulator),
            "expected_version": expected_emulator,
            "observed": observed_emulator,
            "qualification": avd["qualification"],
        },
        required=bool(avd["required"]),
    )
    android_executor_environment = Path("/etc/umat/android-executor.env")
    configured_emulator = "unavailable"
    if path_exists(android_executor_environment):
        configured_emulator = next(
            (
                line.split("=", 1)[1]
                for line in read_environment_text(android_executor_environment).splitlines()
                if line.startswith("UMAT_ANDROID_EMULATOR=")
            ),
            "unavailable",
        )
    check(
        "android_runtime:aosp_avd_executor",
        configured_emulator == str(emulator),
        {"expected": str(emulator), "observed": configured_emulator},
        required=bool(avd["required"]),
    )
    runtime_manifest_path = Path(locations["c2_runtime"]) / "runtime-manifest.json"
    runtime_manifest = (
        json.loads(runtime_manifest_path.read_text()) if runtime_manifest_path.is_file() else {}
    )
    check(
        "c2_effective_runtime",
        runtime_manifest.get("upstream_commit") == manifest["components"]["c2"]["commit"]
        and runtime_manifest.get("upstream_tree_sha256")
        == manifest["components"]["c2"]["upstream_tree_sha256"]
        and runtime_manifest.get("effective_tree_sha256")
        == manifest["components"]["c2"]["effective_tree_sha256"]
        and runtime_manifest.get("dependency_lock_sha256")
        == manifest["components"]["c2"]["dependency_lock_sha256"]
        and runtime_manifest.get("patch_series_sha256")
        == manifest["components"]["c2"]["patch_series_sha256"],
        runtime_manifest or "runtime manifest unavailable",
    )
    handoff_root = Path(paths["winstdt_runtime_root"]) / "handoff"
    handoffs = sorted(
        (item for item in handoff_root.glob("*/manifest.json") if item.parent.name.isdigit()),
        key=lambda item: int(item.parent.name),
        reverse=True,
    )
    accepted_handoff: dict[str, Any] | None = None
    validator = Path(paths["winstdt_runtime_root"]) / "bin/winstdt"
    for handoff in handoffs:
        try:
            document = json.loads(handoff.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if document.get("status") != "completed":
            continue
        pcap = handoff.parent / "network/capture.pcapng"
        etl = handoff.parent / "behavior/trace.etl"
        kernel_etl = handoff.parent / "behavior/kernel.etl"
        if (
            not pcap.is_file()
            or not etl.is_file()
            or not kernel_etl.is_file()
            or pcap.stat().st_size <= 0
            or etl.stat().st_size <= 0
            or kernel_etl.stat().st_size <= 0
        ):
            continue
        validation = (
            subprocess.run(  # noqa: S603
                [str(validator), "validate-bundle", str(handoff.parent)],
                check=False,
                capture_output=True,
                text=True,
            )
            if validator.is_file()
            else None
        )
        if validation is not None and validation.returncode == 0:
            accepted_handoff = {
                "task_id": handoff.parent.name,
                "pcap_bytes": pcap.stat().st_size,
                "etl_bytes": etl.stat().st_size,
                "kernel_etl_bytes": kernel_etl.stat().st_size,
            }
            break
    check("windows_harmless_handoff", accepted_handoff is not None, accepted_handoff or "none")
    for component in ("windows", "c2", "android"):
        executor_environment = Path(f"/etc/umat/{component}-executor.env")
        if path_exists(executor_environment):
            environment_text = read_environment_text(executor_environment)
            isolated = "UMAT_DATABASE_URL=" not in environment_text
            detail: Any = "PostgreSQL credential absent" if isolated else "credential leak"
        else:
            isolated, detail = False, "environment unavailable"
        check(f"executor_isolation:{component}", isolated, detail)
    for name, url in (
        ("umat_api", "http://127.0.0.1:8080/health/live"),
        ("cape_gateway", "http://127.0.0.1:8091/health/live"),
    ):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310
                healthy = response.status == 200
                detail = response.read().decode()[:500]
        except (urllib.error.URLError, TimeoutError) as exc:
            healthy, detail = False, str(exc)
        check(f"health:{name}", healthy, detail)
    state_path = Path(paths["state_root"]) / "state.json"
    results["deployment_state"] = (
        json.loads(read_environment_text(state_path)) if path_exists(state_path) else None
    )
    typer.echo(json.dumps(results, indent=2))
    if not results["healthy"]:
        raise typer.Exit(1)


def path_exists(path: Path) -> bool:
    try:
        if path.exists():
            return True
    except PermissionError:
        pass
    return (
        subprocess.run(  # noqa: S603
            [command("sudo"), "-n", "test", "-e", str(path)], check=False
        ).returncode
        == 0
    )


def read_environment_text(path: Path) -> str:
    if os.access(path, os.R_OK):
        return path.read_text()
    return subprocess.run(  # noqa: S603
        [command("sudo"), "-n", "cat", str(path)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


if __name__ == "__main__":
    app()
