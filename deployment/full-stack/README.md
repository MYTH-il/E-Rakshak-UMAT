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
5. Install the C2 runtime, build MobSF, install Binder/ReDroid support, and retain the API-30 AOSP
   x86_64 Android fallback profile.
6. Generate restricted environments, start PostgreSQL 18.4, apply migrations, create the first
   administrator, and seed Android profiles.
7. Install the API, scheduler, report/adapter workers, CAPE gateway, three executors, and the
   `umat-guest-guard` nftables service.
8. Consume one-time executor enrollment tokens and verify that executor environments contain no
   database credential.
9. Run status and harmless acceptance gates. A partial installation remains resumable and is not
   reported as healthy.

The installer downloads three explicitly pinned source checkouts under `/opt/umat/upstreams`:
WinST/DT, Android/MobSF, and C2. WinST/DT's own verified scripts remain responsible for CAPE,
VMCloak, the licensed Windows baseline, snapshot creation, and the effective C2 compatibility
runtime. UMAT configures their HTTP/evidence boundaries and does not fork their internal UI or VM
implementation. Operators use UMAT's unified UI; native interfaces remain diagnostic tools.

The Windows/CAPE worker, evidence adapter, optional offline C2 path, aggregation, and report path
have been validated end to end. The current browser does not yet expose all backend parameters,
case/run relationships, worker inventory, or profile management. Use the API and CAPE native
interface for missing operations and diagnostics; see the root README's
[current UI limitations](../../README.md#current-ui-limitations).

The Windows/C2 source flag records the operator's local authorization; it does not grant
redistribution rights. A licensed ISO is required to build the first baseline guest. Existing
checkouts and generated secrets are verified and preserved on reruns, never reset.

Automatic installation creates one-time Windows, C2, and Android enrollment tokens and consumes
them immediately. For a deliberately skipped or replacement Windows enrollment, use:

```bash
uv run umat-admin enroll-executor --created-by admin \
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

`umat-deploy status` exits nonzero until pinned source revisions, images, CAPE baseline/snapshot,
all UMAT services, and local health endpoints are present. This is intentional: a partial legacy
installation is reported as incomplete rather than promoted.

## Running an analysis

Use `http://127.0.0.1:8080` for the current UMAT console. Create a case, upload a sample, then create
a Windows or Android run. `isolated_simulated` is the qualified default. Offline C2 analysis is an
independent policy and may be enabled without allowing Internet egress. Real-world egress must
remain disabled until the dedicated, recorded sacrificial egress tier in
[the network architecture](../../docs/network-architecture.md) exists.

CAPE's configured analysis timeout covers guest detonation, not the complete platform stage. VM
startup, dump extraction, Vivisect, YARA, signatures, WinST/DT finalization, evidence download, and
adaptation can add several minutes. Inspect CAPE for native progress and UMAT for workflow-stage
progress. The executor records the CAPE task ID and resumes polling rather than resubmitting after
a restart.

Phase 6 must add automated backup/restore and rollback commands. Until then, do not manually
remove a legacy database or Docker volume merely to make the status command green.
