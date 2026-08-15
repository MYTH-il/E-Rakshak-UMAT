import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from umat.android.executor import app as android_executor_app
from umat.c2.executor import app as c2_executor_app
from umat.cli.main import app as main_app
from umat.deployment.cli import (
    CommandRunner,
    DeploymentError,
    load_manifest,
    new_status_report,
    path_exists,
    record_status_check,
    selected_components,
)
from umat.windows.executor import app as windows_executor_app

ROOT = Path(__file__).parents[2]


def test_full_stack_manifest_matches_dependency_locks() -> None:
    manifest = load_manifest()
    winstdt = json.loads((ROOT / "dependency-locks/winstdt.json").read_text())
    android = json.loads((ROOT / "dependency-locks/android-erakshak.json").read_text())
    c2 = json.loads((ROOT / "dependency-locks/c2-exfil.json").read_text())
    postgres = json.loads((ROOT / "dependency-locks/umat-postgres.json").read_text())
    components = manifest["components"]
    assert components["winstdt"]["commit"] == winstdt["commit"]
    assert (
        components["winstdt"]["patch_series_sha256"]
        == (winstdt["deployment_patch_series"]["patch_series_sha256"])
    )
    assert components["cape"]["commit"] == winstdt["cape"]["commit"]
    cape_patch = components["cape"]["integration_patch"]
    cape_patch_path = ROOT / cape_patch["path"]
    assert hashlib.sha256(cape_patch_path.read_bytes()).hexdigest() == cape_patch["sha256"]
    assert components["android"]["commit"] == android["commit"]
    assert components["android"]["repository"] == android["repository"]
    assert components["android"]["tree_sha256"] == android["tree_sha256"]
    assert components["android"]["patch_series_sha256"] == android["patch_series_sha256"]
    assert components["android"]["image"] == android["container_image"]
    assert components["android"]["image_digest"] == android["container_image_digest"]
    assert components["android"]["default_runtime"] == android["runtime_policy"]["default"]
    runtimes = components["android"]["runtimes"]
    required = {name for name, runtime in runtimes.items() if runtime["required"]}
    optional = {name for name, runtime in runtimes.items() if not runtime["required"]}
    assert required == set(android["runtime_policy"]["required"])
    assert optional == set(android["runtime_policy"]["optional"])
    assert runtimes["redroid"]["image"] == android["tool_versions"]["redroid_image"]
    assert runtimes["redroid"]["architecture"] == (
        android["tool_versions"]["redroid_architecture"]
    )
    assert runtimes["redroid"]["guest_abi"] == android["tool_versions"]["redroid_guest_abi"]
    assert runtimes["aosp_avd"]["emulator_version"] == (
        android["tool_versions"]["android_emulator"]
    )
    assert runtimes["aosp_avd"]["system_image"] == (
        f"system-images;android-{android['tool_versions']['android_api']};"
        f"{android['tool_versions']['android_system_image']}"
    )
    assert runtimes["aosp_avd"]["guest_abi"] == android["tool_versions"]["android_guest_abi"]
    qualification = runtimes["redroid"]["qualification"]
    assert qualification == {
        key: android["validation"][key]
        for key in ("status", "validated_at", "evidence_run_id")
    }
    assert android["validation"]["runtime"] == "redroid"
    executor_source = (ROOT / "src/umat/android/executor.py").read_text()
    schemas_source = (ROOT / "src/umat/android/schemas.py").read_text()
    assert runtimes["redroid"]["image"] in executor_source
    assert runtimes["redroid"]["image"] in schemas_source
    assert runtimes["aosp_avd"]["emulator_version"] in schemas_source
    assert components["c2"]["commit"] == c2["commit"]
    assert components["c2"]["effective_version"] == c2["effective_version"]
    assert components["c2"]["upstream_tree_sha256"] == c2["upstream_tree_sha256"]
    assert components["c2"]["effective_tree_sha256"] == c2["effective_tree_sha256"]
    assert components["c2"]["dependency_lock_sha256"] == c2["dependency_lock_sha256"]
    assert components["c2"]["patch_series_sha256"] == c2["patch_series_sha256"]
    c2_patch_digest = hashlib.sha256()
    c2_patches = sorted((ROOT / "deployment/c2/patches").glob("*.patch"))
    assert c2_patches
    for patch_path in c2_patches:
        c2_patch_digest.update(patch_path.read_bytes())
    assert c2_patch_digest.hexdigest() == c2["patch_series_sha256"]
    assert components["umat_postgres"]["image"] == (
        f"{postgres['image']}@{postgres['image_digest']}"
    )

    patch_digest = hashlib.sha256()
    declared_paths = []
    for entry in winstdt["deployment_patch_series"]["files"]:
        patch_path = ROOT / entry["path"]
        content = patch_path.read_bytes()
        assert hashlib.sha256(content).hexdigest() == entry["sha256"]
        patch_digest.update(content)
        declared_paths.append(patch_path)
    assert patch_digest.hexdigest() == (winstdt["deployment_patch_series"]["patch_series_sha256"])

    android_patch_digest = hashlib.sha256()
    for patch_path in sorted((ROOT / "deployment/android/patches").glob("*.patch")):
        android_patch_digest.update(patch_path.read_bytes())
    assert android_patch_digest.hexdigest() == android["patch_series_sha256"]
    assert sorted(declared_paths) == sorted((ROOT / "deployment/windows/patches").glob("*.patch"))


def test_status_fails_required_gates_but_only_degrades_optional_gates() -> None:
    optional_report = new_status_report()
    record_status_check(
        optional_report,
        "android_runtime:aosp_avd",
        False,
        "version drift",
        required=False,
    )
    assert optional_report["healthy"] is True
    assert optional_report["degraded"] is True
    assert optional_report["checks"]["android_runtime:aosp_avd"] == {
        "passed": False,
        "requirement": "optional",
        "status": "degraded",
        "detail": "version drift",
    }

    required_report = new_status_report()
    record_status_check(
        required_report,
        "android_runtime:redroid",
        False,
        "digest mismatch",
        required=True,
    )
    assert required_report["healthy"] is False
    assert required_report["degraded"] is False
    assert required_report["checks"]["android_runtime:redroid"]["status"] == "failed"


def test_dry_run_never_executes_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess execution was attempted")

    monkeypatch.setattr("subprocess.run", forbidden)
    CommandRunner(execute=False).run(["definitely-not-an-executable"])


def test_component_selection_fails_closed() -> None:
    assert selected_components([]) == {
        "control-plane",
        "windows",
        "android",
        "c2",
        "services",
    }
    with pytest.raises(DeploymentError, match="unknown deployment components"):
        selected_components(["unknown"])


def test_control_plane_compose_requires_external_password() -> None:
    compose = (ROOT / "deployment/single-host/compose.yaml").read_text()
    manifest = load_manifest()
    assert "UMAT_POSTGRES_PASSWORD:?" in compose
    assert "POSTGRES_PASSWORD: umat" not in compose
    assert manifest["components"]["umat_postgres"]["image"] in compose
    assert "postgres:18.4@sha256:" in compose
    assert "umat-postgres-18:/var/lib/postgresql" in compose
    assert "/var/lib/postgresql/data" not in compose
    assert "restart: unless-stopped" in compose


def test_unified_operator_command_is_installed() -> None:
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    assert "/usr/local/bin/umat" in installer
    assert '.venv/bin/umat" "\\$@"' in installer


def test_unified_operator_command_exposes_supported_groups() -> None:
    result = CliRunner().invoke(main_app, ["--help"])
    assert result.exit_code == 0
    for command_name in ("start", "status", "admin", "ops"):
        assert command_name in result.stdout


def test_startup_command_exposes_health_timeout_and_status_override() -> None:
    result = CliRunner().invoke(main_app, ["start", "--help"])
    assert result.exit_code == 0
    assert "--timeout" in result.stdout
    assert "--skip-status" in result.stdout


def test_startup_command_orders_dependencies_before_executors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr("umat.deployment.startup.verify_installation", lambda: None)
    monkeypatch.setattr(
        "umat.deployment.startup.sudo_systemctl",
        lambda action, units: events.append(f"systemctl:{action}:{units[0]}"),
    )
    monkeypatch.setattr(
        "umat.deployment.startup.reset_and_start_units",
        lambda units: (
            events.append(f"systemctl:reset-failed:{units[0]}"),
            events.append(f"systemctl:start:{units[0]}"),
        ),
    )
    monkeypatch.setattr(
        "umat.deployment.startup.compose_up",
        lambda path: events.append(f"compose:{path.parent.name}"),
    )
    monkeypatch.setattr(
        "umat.deployment.startup.wait_for_postgres",
        lambda timeout: events.append("health:UMAT PostgreSQL"),
    )
    monkeypatch.setattr(
        "umat.deployment.startup.wait_for_url",
        lambda name, url, timeout: events.append(f"health:{name}"),
    )
    monkeypatch.setattr("umat.deployment.startup.path_exists", lambda path: False)

    result = CliRunner().invoke(main_app, ["start", "--skip-status"])

    assert result.exit_code == 0
    assert events == [
        "systemctl:start:docker.service",
        "compose:single-host",
        "health:UMAT PostgreSQL",
        "compose:android",
        "systemctl:reset-failed:umat-guest-guard.service",
        "systemctl:start:umat-guest-guard.service",
        "systemctl:reset-failed:umat-api.service",
        "systemctl:start:umat-api.service",
        "health:UMAT API",
        "health:CAPE gateway",
        "health:MobSF",
        "systemctl:reset-failed:umat-windows-executor.service",
        "systemctl:start:umat-windows-executor.service",
        "systemctl:reset-failed:umat-android-executor.service",
        "systemctl:start:umat-android-executor.service",
    ]


def test_startup_uses_only_disposable_android_executor_after_cutover(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr("umat.deployment.startup.verify_installation", lambda: None)
    monkeypatch.setattr(
        "umat.deployment.startup.sudo_systemctl",
        lambda action, units: events.append(f"systemctl:{action}:{':'.join(units)}"),
    )
    monkeypatch.setattr(
        "umat.deployment.startup.reset_and_start_units",
        lambda units: events.append(f"start:{':'.join(units)}"),
    )
    monkeypatch.setattr(
        "umat.deployment.startup.compose_up",
        lambda path: events.append(f"compose:{path.parent.name}"),
    )
    monkeypatch.setattr("umat.deployment.startup.wait_for_postgres", lambda timeout: None)
    monkeypatch.setattr("umat.deployment.startup.wait_for_url", lambda *args: None)
    monkeypatch.setattr("umat.deployment.startup.path_exists", lambda path: True)

    result = CliRunner().invoke(main_app, ["start", "--skip-status"])

    assert result.exit_code == 0
    assert "compose:android" not in events
    assert "systemctl:disable:--now:umat-android-executor.service" in events
    assert "start:umat-android-worker-controller.service" in events
    assert "start:umat-android-executor.service" not in events


def test_root_owned_deployment_state_falls_back_to_sudo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InaccessiblePath(type(Path())):  # type: ignore[misc]
        def exists(self) -> bool:
            raise PermissionError

    class Result:
        returncode = 0

    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: Result())
    assert path_exists(InaccessiblePath("/var/lib/umat-deploy/state.json"))


def test_windows_executor_service_has_isolated_credentials_and_storage() -> None:
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    enrollment = (ROOT / "deployment/full-stack/enroll-windows-executor.sh").read_text()
    assert "umat-windows-executor.service" in installer
    assert "EnvironmentFile=/etc/umat/windows-executor.env" in installer
    assert "EnvironmentFile=$ENV_FILE" not in installer.split("windows_unit=", 1)[1]
    assert "ReadOnlyPaths=/srv/winstdt/handoff" in installer
    assert "-$PROJECT_ROOT/.env" in installer
    assert 'chown -R "$EXECUTOR_USER:$EXECUTOR_USER"' in installer
    assert "UMAT_DATABASE_URL" not in enrollment
    assert "--token-file" in enrollment
    cape_integration = (ROOT / "deployment/full-stack/configure-cape-integration.sh").read_text()
    assert 'chmod 0755 "$CAPE_ROOT/data/7zz"' in cape_integration
    assert "refusing to replace missing or empty CAPE reporting configuration" in cape_integration
    assert 'cp --preserve=mode,ownership "$reporting_config"' in cape_integration
    assert "generated CAPE reporting configuration did not validate" in cape_integration
    assert "qualify CAPE AgentTesla parser with a bounded decoded-string fixture" in cape_integration
    assert "CAPE AgentTesla parser qualification passed" in cape_integration
    assert "cape-guest-analyzer-retry.patch" in cape_integration
    retry_patch = (
        ROOT / "deployment/full-stack/patches/cape-guest-analyzer-retry.patch"
    ).read_text()
    assert "Transient CAPE Agent analyzer extraction failed" in retry_patch
    assert "retrying once after snapshot settle" in retry_patch
    assert "CAPE integration patch digest mismatch" in cape_integration
    assert "systemctl restart cape.service" in cape_integration


def test_service_installer_refreshes_runtime_and_requires_tcpdump() -> None:
    bootstrap = (ROOT / "install.sh").read_text()
    deployment_cli = (ROOT / "src/umat/deployment/cli.py").read_text()
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    egress_unit = (ROOT / "deployment/full-stack/umat-egress-broker.service").read_text()
    acceptance = (ROOT / "deployment/full-stack/phase6-acceptance.sh").read_text()

    assert "patch publicsuffix python3.12 python3.12-venv tcpdump" in bootstrap
    assert '"apt-get", "install", "-y", "publicsuffix", "tcpdump"' in deployment_cli
    assert 'systemctl restart "${core_units[@]}"' in installer
    assert 'systemctl restart "$executor_unit.service"' in installer
    assert "UMAT_ROTATE_EGRESS_BROKER_TOKEN" in installer
    assert "ExecStartPre=/usr/bin/test -x /usr/bin/tcpdump" in egress_unit
    assert "umat-egress-broker" in acceptance
    assert "test -x /usr/bin/tcpdump" in acceptance
    assert "test -s /usr/share/publicsuffix/effective_tld_names.dat" in acceptance


def test_clean_host_installer_is_dry_run_by_default() -> None:
    installer = (ROOT / "install.sh").read_text()
    manifest = load_manifest()
    assert "apt-get install" in installer
    assert f'UV_VERSION="{manifest["components"]["installer"]["uv_version"]}"' in installer
    assert "uv sync --frozen" in installer
    assert "umat-deploy install" in installer
    assert 'if [[ "$EXECUTE" -eq 0 ]]' in installer
    installer_lock = json.loads((ROOT / "dependency-locks/installer.json").read_text())
    requirements = (ROOT / "dependency-locks/installer-requirements.txt").read_text()
    assert f"uv=={installer_lock['uv']['version']}" in requirements
    assert installer_lock["uv"]["sha256"] in requirements


def test_all_upstream_sources_have_explicit_checkout_paths() -> None:
    manifest = load_manifest()
    assert manifest["paths"]["winstdt_checkout"] == "/opt/umat/upstreams/winstdt"
    assert manifest["paths"]["android_checkout"] == "/opt/umat/upstreams/android-erakshak"
    assert manifest["paths"]["c2_checkout"] == "/opt/umat/upstreams/c2-exfil"


def test_c2_installers_enforce_every_locked_runtime_identity_field() -> None:
    c2 = json.loads((ROOT / "dependency-locks/c2-exfil.json").read_text())
    runtime_installer = (ROOT / "deployment/c2/install-runtime.sh").read_text()
    service_installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    for value in (
        c2["commit"],
        c2["effective_version"],
        c2["effective_tree_sha256"],
        c2["dependency_lock_sha256"],
        c2["patch_series_sha256"],
    ):
        assert value in runtime_installer
    assert c2["patch_series_sha256"] in (ROOT / "src/umat/c2/executor.py").read_text()
    assert c2["effective_version"] in service_installer
    validation = c2["validation"]
    expected_result = (
        f"{validation['upstream_tests_passed']} passed, "
        f"{validation['upstream_tests_skipped']} skipped"
    )
    assert expected_result in runtime_installer
    assert (
        f'"upstream_tests_collected": {validation["upstream_tests_collected"]}'
        in runtime_installer
    )


def test_c2_data_service_policy_separates_mutable_sqlite_from_read_only_mmdb() -> None:
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    policy = (ROOT / "deployment/full-stack/umat-c2-executor-data.conf").read_text()
    assert "THREATINTEL_DB=/srv/winstdt/c2-data/threatintel.sqlite" in policy
    assert "ReadWritePaths=/srv/winstdt/c2-data" in policy
    assert "ReadOnlyPaths=/srv/winstdt/c2-data" not in policy
    assert "chmod 0440" in installer
    assert "chmod 0660" in installer
    assert 'chmod 0770 "$c2_data_root"' in installer


def test_executor_units_use_separate_identity_and_hide_control_plane_evidence() -> None:
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    assert 'EXECUTOR_USER="${UMAT_EXECUTOR_USER:-umat-executor}"' in installer
    assert "User=$EXECUTOR_USER" in installer
    assert "InaccessiblePaths=/etc/umat/full-stack.env" in installer
    assert "/var/lib/umat/artifacts /var/lib/umat/quarantine -/var/lib/umat-backups" in installer
    firewall = (ROOT / "deployment/full-stack/umat-host-firewall.nft").read_text()
    assert 'meta skuid "umat-executor" tcp dport 55432 reject' in firewall
    assert "umat-c2-executor.service.d/c2-data.conf" in installer
    assert "C2 enrichment data is partially provisioned" in installer
    assert "c2_data_present" in installer


def test_android_runtime_installer_enforces_locked_emulator_and_license() -> None:
    installer = (ROOT / "deployment/android/install-runtime.sh").read_text()
    android = json.loads((ROOT / "dependency-locks/android-erakshak.json").read_text())
    assert f'EXPECTED_EMULATOR="{android["tool_versions"]["android_emulator"]}"' in installer
    assert "--accept-sdk-licenses" in installer
    assert "system-images\\;android-30\\;default\\;x86_64" in installer


def test_android_frida_server_is_pinned_and_packaged_for_offline_runtime() -> None:
    android = json.loads((ROOT / "dependency-locks/android-erakshak.json").read_text())
    version = android["tool_versions"]["frida"]
    digest = android["tool_versions"]["frida_server_x86_64_sha256"]
    patch = (ROOT / "deployment/android/patches/0005-pinned-frida-readiness.patch").read_text()
    overlay = (ROOT / "deployment/android/Dockerfile.frida-overlay").read_text()
    bootstrap = (ROOT / "deployment/android/bootstrap.sh").read_text()

    assert f"FRIDA_SERVER_VERSION={version}" in patch
    assert f"FRIDA_SERVER_SHA256={digest}" in patch
    assert f"FRIDA_SERVER_VERSION={version}" in overlay
    assert f"FRIDA_SERVER_SHA256={digest}" in overlay
    assert "/opt/frida-server" in patch
    assert "Pinned Frida server did not become ready" in patch
    assert "0005-pinned-frida-readiness.patch" in bootstrap


def test_all_executor_units_use_isolated_environment_files() -> None:
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    assert "umat-windows-executor.service" in installer
    assert "/etc/umat/windows-executor.env" in installer
    assert "for executor_name in c2 android" in installer
    assert "umat-${executor_name}-executor.service" in installer
    assert "/etc/umat/${executor_name}-executor.env" in installer
    enrollment = (ROOT / "deployment/full-stack/enroll-executors.sh").read_text()
    assert "UMAT_DATABASE_URL" not in (
        "\n".join(
            line
            for line in installer.splitlines()
            if "executor.env" in line or "UMAT_C2_" in line or "UMAT_ANDROID_" in line
        )
    )
    assert "--enroll-only" in enrollment
    assert "UMAT_ANDROID_EMULATOR=/opt/android-sdk-34/emulator/emulator" in installer


def test_guest_firewall_is_installed_and_fail_closed() -> None:
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    rules = (ROOT / "deployment/full-stack/umat-guest-guard.nft").read_text()
    unit = (ROOT / "deployment/full-stack/umat-guest-guard.service").read_text()
    assert "umat-guest-guard umat-egress-broker" in installer
    assert 'systemctl restart "${core_units[@]}"' in installer
    assert 'iifname "virbr-winstdt" drop' in rules
    assert "ip saddr 10.66.0.101 tcp sport 8000 accept" in rules
    assert 'iifname "br-umat-android" drop' in rules
    assert 'iifname { "virbr-winstdt", "br-umat-android" } drop' in rules
    assert 'ip daddr 172.30.0.3 tcp dport 8080 accept' in rules
    assert 'iifname "virbr-umat-mgmt" ip saddr 10.67.0.10 ct state established,related accept' in rules
    assert 'tcp dport { 8092, 8443 } accept' in rules
    assert 'iifname { "virbr-umat-mgmt", "br-umat-malware" } drop' in rules
    assert "set windows_egress_v4" in rules
    assert "set android_egress_v4" in rules
    assert "set android_scoped_tcp_v4" in rules
    assert "ip saddr . ip daddr . tcp dport @android_scoped_tcp_v4" in rules
    assert 'oifname "wg-umat-egress" tcp dport { 80, 443 }' in rules
    assert "169.254.0.0/16" in rules
    assert "table ip6 umat_guest_guard6" in rules

    gateway_rules = (ROOT / "deployment/full-stack/umat-aws-egress.nft").read_text()
    assert (
        'ip saddr 10.77.0.2 ip daddr 37.120.141.140 tcp dport 7775 ct state new'
        in gateway_rules
    )
    assert 'ip saddr 10.77.0.2 tcp dport { 80, 443 }' in gateway_rules
    assert "umat-egress-broker" in installer
    assert "UMAT_EGRESS_MAX_BYTES=1073741824" in installer
    assert "Before=umat-android-executor.service umat-windows-executor.service" in unit


def test_android_worker_is_disposable_and_separates_proxy_entrypoint() -> None:
    reset = (ROOT / "deployment/android-worker/reset-worker.sh").read_text()
    controller = (ROOT / "deployment/android-worker/worker-controller.sh").read_text()
    mobsf_unit = (ROOT / "deployment/android-worker/umat-worker-mobsf.service").read_text()
    executor_unit = (ROOT / "deployment/android-worker/umat-worker-executor.service").read_text()
    source = (ROOT / "src/umat/android/redroid.py").read_text()
    redroid_launch, proxy_launch = source.split("def enable_analysis_proxy", 1)
    assert 'rm -f -- "$OVERLAY"' in reset
    assert "network=default" not in reset
    assert "UMAT_ANDROID_EGRESS_GUEST_IP=10.68.0.10" in reset
    assert "ip route replace default via 10.68.0.1 dev malware0" in reset
    assert "failures > 3" in controller
    assert "--wait --wait-timeout 300" in mobsf_unit
    assert "UMAT_CONTRACT_ROOT=/opt/umat/contracts" in executor_unit
    assert "/usr/local/bin/mitmdump" not in redroid_launch
    assert "/usr/local/bin/mitmdump" in proxy_launch


def test_android_worker_cutover_disables_host_executor_and_has_local_healthchecks() -> None:
    installer = (ROOT / "deployment/full-stack/install-services.sh").read_text()
    startup = (ROOT / "src/umat/deployment/startup.py").read_text()
    deployment_cli = (ROOT / "src/umat/deployment/cli.py").read_text()
    compose = (ROOT / "deployment/android/compose.yaml").read_text()
    assert "systemctl disable --now umat-android-executor.service" in installer
    assert "umat-android-egress-relay.service" in installer
    assert '"umat-android-egress-relay.service"' in startup
    assert '"umat-android-egress-relay.service"' in deployment_cli
    assert 'HOST_ANDROID_EXECUTOR_UNIT = "umat-android-executor.service"' in startup
    assert '"disable legacy host Android executor"' in startup
    assert 'services.append("umat-android-worker-controller.service")' in deployment_cli
    assert "http://127.0.0.1:8000/" in compose
    assert "manage.py.qcluster" in compose
    assert "host.docker.internal:8000" not in compose


def test_executor_enrollment_can_exit_without_claiming_work() -> None:
    runner = CliRunner()
    for executor_app in (windows_executor_app, c2_executor_app, android_executor_app):
        result = runner.invoke(executor_app, ["run", "--help"])
        assert result.exit_code == 0
        assert "--enroll-only" in result.stdout
