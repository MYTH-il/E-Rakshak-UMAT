# Full-stack deployment

> **Implementation snapshot:** the orchestration and CAPE profile lifecycle are implemented, but
> a clean-host end-to-end installation has not yet been promoted. The UMAT control plane is pinned
> to PostgreSQL 18.4; MobSF retains its independent, validated PostgreSQL 16 lock. See the
> [root status and gaps](../../README.md#current-workstation-deployment-state) before using
> `--execute`.

The root `install.sh` is the clean-host entry point for the UMAT control plane,
WinST/DT+CAPE+C2 runtime, Android/MobSF, unified UI, and system services. It defaults to a dry run,
bootstraps a hash-pinned `uv`, and then delegates to the resumable `umat-deploy` orchestrator.

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

The installer downloads three explicitly pinned source checkouts under `/opt/umat/upstreams`:
WinST/DT, Android/MobSF, and C2. WinST/DT's own verified scripts remain responsible for CAPE,
VMCloak, the licensed Windows baseline, snapshot creation, and the effective C2 compatibility
runtime. UMAT configures their HTTP/evidence boundaries and does not fork their internal UI or VM
implementation. Operators use UMAT's unified UI; native interfaces remain diagnostic tools.

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

Phase 6 must add automated backup/restore and rollback commands. Until then, do not manually
remove a legacy database or Docker volume merely to make the status command green.
