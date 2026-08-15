# Full-stack deployment

> **Implementation snapshot:** the orchestration and CAPE profile lifecycle are implemented, but
> a clean-host end-to-end installation has not yet been promoted. The UMAT control plane is pinned
> to PostgreSQL 18.4; MobSF retains its independent, validated PostgreSQL 16 lock. See the
> [root status and gaps](../../README.md#current-workstation-deployment-state) before using
> `--execute`.

The root `install.sh` is the clean-host entry point for the UMAT control plane,
WinST/DT+CAPE+C2 runtime, Android/MobSF, unified UI, and system services. It defaults to a dry run,
bootstraps a hash-pinned `uv`, and then delegates to the resumable `umat-deploy` orchestrator.

## Required Windows installation media

Provide a legitimately licensed Windows 10 22H2 x64 ISO. The installer does not download Windows
media and the project must not commit or redistribute it. Pass its absolute path with
`--windows-iso`. The conventional project-root filename `Win10_22H2_English_x64v1.iso` is ignored
by Git, but storing licensed media outside the checkout is recommended. The ISO is required to
construct the first VMCloak/CAPE baseline unless the explicit `--allow-no-windows-guest`
development escape hatch is used; that escape hatch does not produce an operational Windows
analysis deployment.

Run the command once without `--execute` and inspect the complete plan. Then add `--execute`:

```bash
# Prepare /secure/umat-admin.password beforehand with mode 0600.
./install.sh \
  --execute \
  --windows-iso /secure/media/Win10_22H2_x64.iso \
  --admin-username admin \
  --admin-password-file /secure/umat-admin.password \
  --accept-android-sdk-licenses \
  --accept-unlicensed-source
uv run umat-deploy status
```

### Starting after a host reboot

The service installer places `umat` in `/usr/local/bin`. Run it as the normal deployment
operator after a fresh boot:

```bash
umat start
```

It restores the PostgreSQL and MobSF Compose projects before starting the systemd control plane and
executors, waits for local readiness, and then runs the full deployment status gate. The operation
is safe to repeat and does not reinstall components or start an analysis guest. Use
`umat start --skip-status` only for diagnosis when an already-known qualification gate is expected
to remain degraded; service startup and endpoint readiness still fail closed.

Rerun the same command after correcting a failed upstream phase. Existing verified checkouts,
generated secrets, databases, images, and setup markers are preserved. Completion is recorded only
after the upstream harmless Windows deployment validation, executor enrollment, and final health
check succeed. `--skip-runtime-acceptance`, `--skip-executor-enrollment`, and
`--allow-no-windows-guest` deliberately leave corresponding gates open.

## Installation sequence

1. Validate Ubuntu 24.04 x86_64, passwordless sudo, KVM, ISO readability, storage, and required
   operator acknowledgements.
2. Install bootstrap packages and pinned `uv`, then synchronize the locked Python environment.
3. Materialize pinned WinST/DT, CAPE, C2, and Android/MobSF sources under `/opt/umat/upstreams` and
   verify revisions and patch-series digests.
4. Delegate Windows baseline creation to WinST/DT/VMCloak using the supplied ISO; seal the CAPE
   snapshot and configure format-aware submission and evidence handoff.
5. Install the C2 runtime, apply the digest-locked Android patch series, build the pinned MobSF
   image with its checksum-verified Frida server, install Binder/ReDroid support, and retain the
   API-30 AOSP x86_64 fallback profile.
6. Generate restricted environments, start PostgreSQL 18.4, apply migrations, create the first
   administrator, and seed Android profiles.
7. Install the API, scheduler, report/adapter workers, CAPE gateway, executor services,
   Android management/egress relays, disposable-worker controller, and the `umat-guest-guard`
   nftables service.
8. Consume one-time executor enrollment tokens and verify that executor environments contain no
   database credential.
9. Run status and harmless acceptance gates. A partial installation remains resumable and is not
   reported as healthy.

Installer reruns restart the installed UMAT services so updated aggregation, capture validation,
and configuration-fallback code is loaded immediately. The services component installs
`/usr/bin/tcpdump`, and the egress broker refuses to start unless that exact capture binary is
executable. CAPE integration verifies the tracked guest-retry patch digest before applying it and
restarts CAPE's core, web, and processor services after configuration.

When a sealed Android worker image exists, service installation disables the legacy host Android
executor before enabling the worker controller. This leaves exactly one Android claimant and keeps
privileged ReDroid execution behind the KVM boundary. The installer installs both relay units,
preserves or explicitly rotates the egress-broker token, injects the worker's restricted broker
route at reset, and validates the Android image and ReDroid identity inside the worker through the
guest agent. Before worker cutover, the host Android executor remains the supported fallback.

The installer downloads three explicitly pinned source checkouts under `/opt/umat/upstreams`:
WinST/DT, Android/MobSF, and C2. WinST/DT's own verified scripts remain responsible for CAPE,
VMCloak, the licensed Windows baseline, snapshot creation, and the effective C2 compatibility
runtime. UMAT configures their HTTP/evidence boundaries and does not fork their internal UI or VM
implementation. Operators use UMAT's unified UI; native interfaces remain diagnostic tools.

The Windows/CAPE and Android/MobSF workers, evidence adapters, optional C2 path, aggregation, and
report path have been validated end to end. The browser exposes case/run relationships, worker
inventory, profile administration, diagnostic progress, runtime observations, Android scan logs,
and evidence navigation. Native CAPE and MobSF interfaces remain engineering diagnostics.

The Windows/C2 source flag records the operator's local authorization; it does not grant
redistribution rights. A licensed ISO is required to build the first baseline guest. Existing
checkouts and generated secrets are verified and preserved on reruns, never reset.

Automatic installation creates one-time Windows, C2, and Android enrollment tokens and consumes
them immediately. For a deliberately skipped or replacement Windows enrollment, use:

```bash
uv run umat admin enroll-executor --created-by admin \
  --executor-type windows --stage-type platform_analysis > /secure/umat-windows.token
sudo deployment/full-stack/enroll-windows-executor.sh \
  --token-file /secure/umat-windows.token
```

The enrollment helper consumes the token once, writes a restricted executor-only environment,
and enables `umat-windows-executor.service`. Remove the token file after successful enrollment.

The CAPE management gateway binds only to `127.0.0.1:8091`. It owns dynamic VM profile
creation/deletion and registers those guests in CAPE without restarting active analysis workers.
The Windows executor has no libvirt access and uses separate CAPE task and management URLs.
Profiles clone the approved baseline and may enlarge, but cannot shrink, its virtual disk. Exact
smaller disks require rebuilding a VMCloak template from the licensed ISO. Deletion is rejected
while CAPE has the machine locked or libvirt reports it running.

`umat-deploy status` classifies each gate as required or optional. A failed required gate marks the
deployment unhealthy and exits nonzero; a failed optional gate keeps the required deployment
healthy but marks it degraded. Pinned source revisions, required images and runtimes, the CAPE
baseline/snapshot, all UMAT services, and local health endpoints are required. The AOSP AVD is an
optional fallback; the qualified ReDroid runtime is required. This makes a partial installation
fail closed without allowing optional tooling drift to misrepresent the supported baseline.

## Running an analysis

Use `http://127.0.0.1:8080` for the current UMAT console. Create a case, upload a sample, then create
a Windows or Android run. `isolated_simulated` is the qualified default. Offline C2 analysis is an
independent policy and may be enabled without allowing Internet egress. Real-world egress must
remain disabled until the dedicated, recorded sacrificial egress tier in
[the network architecture](../../docs/network-architecture.md) exists. Provision and qualify that
tier with the [AWS egress gateway runbook](../../docs/aws-egress-gateway.md); do not substitute the
workstation's ordinary route or an unrecorded VPN.

CAPE's configured analysis timeout covers guest detonation, not the complete platform stage. VM
startup, dump extraction, Vivisect, YARA, signatures, WinST/DT finalization, evidence download, and
adaptation can add several minutes. Inspect CAPE for native progress and UMAT for workflow-stage
progress. The executor records the CAPE task ID and resumes polling rather than resubmitting after
a restart.

Windows detonation uses a minimum 10-minute CAPE timeout. Manual runs expose a launch action that
validates the active run and loopback-only task-owned display before starting TigerVNC on the local
analyst desktop. The installer adds `tigervnc-viewer`; VNC remains bound to `127.0.0.1` and is never
published to the network. Host/guest clipboard sharing, file transfer, and independent VM power
controls are not part of this path. Access expires with the CAPE task or its 10-minute capability,
whichever happens first.

### Optional offline C2 enrichment data

GeoLite2 City, GeoLite2 ASN, and `threatintel.sqlite` may be provisioned under
`/srv/winstdt/c2-data`, outside the verified C2 runtime tree. Provision either all three files or
none: `install-services.sh` rejects a partial data set because it would misrepresent enrichment
coverage. The executor validates configured MMDB readability, the threat-intelligence schema, and
a real SQLite write transaction before it publishes capabilities or claims work.

The service grants directory write access for SQLite journal/WAL files. The two MMDB files remain
mode `0440`; do not add `/srv/winstdt/c2-data` to `ReadOnlyPaths`, because that also prevents SQLite
from opening its required write transaction. Install the tracked
`umat-c2-executor-data.conf` drop-in and restart the executor after updating the databases. A failed
preflight keeps the executor unavailable instead of exhausting analysis-stage retries.

Phase 6 provides `umat ops backup create`, `verify`, `restore`, and `rollback`. Do not manually
remove a legacy database or Docker volume merely to make the status command green.
