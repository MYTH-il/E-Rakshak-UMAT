# Full-stack deployment

> **Implementation snapshot:** the orchestration and CAPE profile lifecycle are implemented, but
> a clean-host end-to-end installation has not yet been promoted. The development workstation is
> currently using its recoverable PostgreSQL 18 fallback while a PostgreSQL 16 restore is pending.
> See the [root status and gaps](../../README.md#current-workstation-issue-postgresql-18-to-16-migration)
> before using `--execute`.

`umat-deploy` is the pinned, idempotent entry point for the UMAT control plane,
WinST/DT+CAPE+C2 runtime, Android/MobSF, and system services. It defaults to a dry run.

```bash
uv sync --frozen --extra test
uv run umat-deploy preflight --json
uv run umat-deploy install --execute \
  --windows-iso /secure/media/Win10_22H2_x64.iso \
  --accept-unlicensed-source
uv run umat-deploy status
```

The Windows/C2 source flag records the operator's local authorization; it does not grant
redistribution rights. A licensed ISO is required to build the first baseline guest. Existing
checkouts and generated secrets are verified and preserved on reruns, never reset.

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
