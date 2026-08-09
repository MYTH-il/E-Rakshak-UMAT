# UMAT

UMAT is the control plane for the Unified Malware Analysis and Triage sandbox. It coordinates
secure intake, custody, Windows/CAPE and Android/MobSF analysis, a shared isolated C2 analyzer,
aggregation, role-filtered reporting, evidence downloads, and audit history.

This repository is an active implementation snapshot. Phases 0–5 and the Phase 5.5 control-plane
hardening work are implemented, but the repository is **not yet a production-ready or clean-host
release**. Phase 6 hardening and operations, several external-runtime promotion gates, and the
current workstation's PostgreSQL migration remain incomplete.

The authoritative design remains the
[implementation plan](umat-unified-malware-analysis-triage-implementation-plan.md).

## Current implementation status

| Area | Status | Notes |
|---|---|---|
| Phase 0 contracts and locks | Implemented | Versioned JSON schemas, vocabularies, executor OpenAPI, dependency locks, and fixtures are committed. C2 schema v1.3 and upstream Android/Windows schemas are used as references without redefining their ownership. |
| Phase 1 control plane | Implemented | Authentication/RBAC, intake, custody, deduplication, PostgreSQL models/migrations, immutable local artifacts, leases, signed executor mutations, audit chain, and fake executor. |
| Phase 2 shared C2 service | Implemented with runtime gates | Isolated executor, input/result validation, adapters, recovery, and Windows/Android inputs exist. The executable runtime remains pinned to `47225ec-winstdt.1`; schema v1.3 does not silently promote a newer runtime. |
| Phase 3 Windows/CAPE | Implemented; native evidence promotion pending | CAPE executor, recovery, adapter, VM profile selection, authenticated profile gateway, create/delete lifecycle, cancellation, and signed bundles exist. A real harmless VM-profile create/register/delete round trip passed on the development host. Existing analysis handoffs still do not satisfy the locked complete-PCAP evidence gate. |
| Phase 4 API and UI | Implemented foundation | Unified case UI, L1/L2/L3 views, aggregation, verdict policy, report worker, and JSON/PDF/CSV exports exist. Production accessibility, browser, and reverse-proxy acceptance remain Phase 6 work. |
| Phase 5 Android/MobSF | Implemented with dynamic-runtime gate | Pinned MobSF image, executor, ephemeral AVD lifecycle, bundles, PCAP and adapter paths exist. Static analysis passes; the prepared API-30 dynamic second boot remains offline on this host, so dynamic promotion is still closed. |
| Phase 5.5 hardening | Implemented | Scheduler timeouts/retries, cancellation propagation, capability matching, administrative controls, migration/security tests, deployment manifest, and fail-closed runtime gates. |
| Phase 6 hardening and operations | **Pending** | See the dedicated section below. |

## Verification evidence

As of 2026-08-09:

- Ruff passes for `src` and `tests`.
- Strict mypy passes for all 72 application source files.
- The full suite passes: **73 passed**, including PostgreSQL integration, migrations,
  authorization/security guards, scheduler behavior, reporting, Android, and Windows profile flows.
- CAPE, WinST/DT, Android, and C2 source/runtime revisions match the committed pins.
- The pinned Android image digest matches its dependency lock.
- CAPE task cancellation is enabled through its native task-status API.
- A real harmless CAPE profile was created with 4 vCPU, 4 GiB RAM, a 160 GiB virtual disk,
  selected Windows persona settings, a running-memory snapshot, and CAPE registry entry. Guarded
  deletion then removed the domain, DHCP reservation, CAPE database/config entry, and profile
  files.

These checks establish the implemented contracts and lifecycle behavior. They do not replace a
clean-host installation test or promote the external runtime gates listed below.

## Current workstation issue: PostgreSQL 18 to 16 migration

An earlier native PostgreSQL 18 development cluster occupies `127.0.0.1:55432`. The committed
full-stack deployment instead pins PostgreSQL 16.6 in Docker. The existing database contains the
audit chain and development records, so it is being migrated rather than deleted.

Current safe state at the time of this snapshot:

- Native PostgreSQL `18/umat` is active on port `55432` and remains authoritative.
- The pinned PostgreSQL 16 container is stopped.
- The original database is unchanged and its data directory remains available.
- A root-only custom backup exists at
  `/var/lib/umat-deploy/backups/umat-pg18-before-pg16.dump`.
- A derived SQL copy exists beside it. PostgreSQL 18-only `transaction_timeout`, `\restrict`, and
  `\unrestrict` directives were removed only from that derived copy.
- Restore attempts failed on those cross-version directives and rolled back to PostgreSQL 18 each
  time. No application data was lost.
- UMAT systemd services and the CAPE management gateway service are not currently promoted, so
  `umat-deploy status` intentionally exits nonzero and ports `8080`/`8091` are not listening.

Do not delete the native cluster, its data directory, either backup, or the Docker volume until a
PostgreSQL 16 restore has passed row-count checks and `umat-admin verify-audit`.

## Known implementation and promotion gaps

- A complete `umat-deploy install --execute` run has not yet been accepted on a fresh Ubuntu 24.04
  host from only a licensed Windows ISO and authorized upstream checkouts.
- PostgreSQL 16 restoration, UMAT service installation, first production administrator creation,
  executor enrollment, and final `umat-deploy status` promotion remain pending on this host.
- Windows bundle promotion requires a locked-schema WinST/DT handoff whose declared artifacts
  include a present, uniquely covered, hash-verified PCAP. Older handoffs fail closed.
- Android dynamic analysis is not promoted until the API-30 AVD completes the prepared second boot,
  dynamic MobSF analysis, PCAP collection, signed bundle validation, and cleanup.
- Windows profile clones can enlarge but cannot shrink the approved 160 GiB baseline disk. Exact
  smaller disks require rebuilding a VMCloak template from the licensed Windows ISO.
- Production Windows, Android, and C2 executor systemd units still require explicit enrollment and
  runtime credentials; executors must never receive PostgreSQL credentials.
- The reverse proxy, TLS, final guest-network policy, production filesystem mount flags, and
  separated-host topology are not complete.
- Full offline dependency staging and clean-room verification are not complete.
- The C2 and locked WinST/DT revisions do not contain explicit upstream license files. Their source
  or derived images must not be redistributed until authorization is documented. No upstream
  source is vendored here.
- Court/evidentiary readiness is not claimed; organizational procedure, key custody, and legal
  validation are outside the software test suite.

## Pending Phase 6

Phase 6 is “Hardening and operations” in the implementation plan. Remaining deliverables are:

- Reproducible offline installation and dependency/image verification from staged inputs.
- Automated PostgreSQL and artifact backup, restore, integrity verification, and rollback drills.
- Metrics, health dashboards, alerts, and structured-log collection with correlation IDs.
- Failure-recovery runbooks for leases, executors, CAPE, MobSF/AVDs, C2, reports, and storage.
- Retention controls and safely audited evidence deletion.
- Reverse proxy, TLS, secure-cookie deployment, host firewall, and final network isolation.
- Minimum-free-memory and global dynamic-analysis concurrency enforcement at deployment level.
- Security testing of the deployed topology, including proving executors cannot reach PostgreSQL.
- Operator, evidence-handling, incident-response, key-custody, and upgrade/rollback documentation.
- A future separated-host deployment guide.
- A clean Ubuntu 24.04 end-to-end acceptance run covering intake through signed evidence and reports.

## Development quick start

Requirements are Python 3.12, `uv`, and PostgreSQL. Docker Compose provides the pinned development
database. Set a non-placeholder development password consistently in both `.env` fields before
starting it.

```bash
uv sync --frozen --extra test
cp .env.example .env
# Edit UMAT_POSTGRES_PASSWORD and the password inside UMAT_DATABASE_URL.
sudo docker compose --env-file .env -f deployment/single-host/compose.yaml up -d postgres
uv run alembic upgrade head
uv run umat-admin create-user --username admin --role administrator
```

Run the long-lived processes in separate terminals:

```bash
uv run umat-api
uv run umat-scheduler run
uv run umat-report-worker run
uv run umat-adapter-worker run
```

The development UI is available at `http://127.0.0.1:8080`. PostgreSQL binds only to
`127.0.0.1:55432`; CAPE/WinST-DT retains its own ports and database.

Run the offline suite:

```bash
uv run ruff check src tests
uv run mypy src/umat
uv run pytest -q
```

PostgreSQL-backed tests require explicit disposable `UMAT_TEST_DATABASE_URL` and
`UMAT_MIGRATION_DATABASE_URL` values. Never point the migration suite at a database containing
data that must be retained.

## Full-stack deployment entry point

The deployment CLI defaults to dry-run mode:

```bash
uv run umat-deploy preflight --json
uv run umat-deploy install \
  --windows-iso /secure/media/Win10_22H2_x64.iso \
  --accept-unlicensed-source
uv run umat-deploy status
```

Only add `--execute` after reviewing the dry run, licensing/authorization, storage, network, and
Windows ISO requirements. See the [full-stack deployment guide](deployment/full-stack/README.md).

## Documentation

- [Single-host development](deployment/single-host/README.md)
- [Full-stack deployment](deployment/full-stack/README.md)
- [Phase 2 shared C2](docs/phase2-c2.md)
- [Phase 3 Windows/CAPE](docs/phase3-windows.md)
- [Phase 4 unified UI and reports](docs/phase4-unified-ui.md)
- [Phase 5 Android/MobSF](deployment/android/README.md)
- [Phase 5.5 hardening and runtime gates](docs/phase55-hardening.md)
- [Executor API contract](contracts/executor-api.openapi.yaml)
- [CAPE management contract](contracts/cape-management.openapi.yaml)
- [Dependency locks and third-party inventory](dependency-locks/third-party-inventory.json)

## Security

UMAT handles hostile content. Do not expose a development deployment to untrusted networks. Keep
CAPE, MobSF, PostgreSQL, the management gateway, and guest networks isolated; use only harmless
fixtures until all deployment gates pass. Report security issues privately rather than attaching
malware, credentials, keys, or sensitive evidence to a public GitHub issue.
