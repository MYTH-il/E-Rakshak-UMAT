# UMAT

UMAT is the control plane for the Unified Malware Analysis and Triage sandbox. It coordinates
secure intake, custody, Windows/CAPE and Android/MobSF analysis, a shared isolated C2 analyzer,
aggregation, role-filtered reporting, evidence downloads, and audit history.

This repository is an active implementation snapshot. Phases 0–5 and the Phase 5.5 control-plane
hardening work are implemented, but the repository is **not yet a production-ready or clean-host
release**. Phase 6 hardening and operations and several external-runtime promotion gates remain
incomplete.

The authoritative design remains the
[implementation plan](umat-unified-malware-analysis-triage-implementation-plan.md).

## Current implementation status

| Area | Status | Notes |
|---|---|---|
| Phase 0 contracts and locks | Implemented | Versioned JSON schemas, vocabularies, executor OpenAPI, dependency locks, and fixtures are committed. C2 schema v1.3 and upstream Android/Windows schemas are used as references without redefining their ownership. |
| Phase 1 control plane | Implemented | Authentication/RBAC, intake, custody, deduplication, PostgreSQL models/migrations, immutable local artifacts, leases, signed executor mutations, audit chain, and fake executor. |
| Phase 2 shared C2 service | Implemented with runtime gates | Isolated executor, input/result validation, adapters, recovery, and Windows/Android inputs exist. The executable runtime remains pinned to `47225ec-winstdt.1`; schema v1.3 does not silently promote a newer runtime. |
| Phase 3 Windows/CAPE | Implemented and runtime-validated | CAPE executor, recovery, adapter, VM profile selection, authenticated profile gateway, create/delete lifecycle, cancellation, and signed bundles exist. A harmless public-API run completed the real Windows stage with hash-verified PCAP and ETL evidence. |
| Phase 4 API and UI | Implemented foundation | Unified case UI, L1/L2/L3 views, aggregation, verdict policy, report worker, and JSON/PDF/CSV exports exist. Production accessibility, browser, and reverse-proxy acceptance remain Phase 6 work. |
| Phase 5 Android/MobSF | Implemented with dynamic-runtime gate | Pinned MobSF image, executor, ephemeral AVD lifecycle, bundles, PCAP and adapter paths exist. Static analysis passes; the prepared API-30 dynamic second boot remains offline on this host, so dynamic promotion is still closed. |
| Phase 5.5 hardening | Implemented | Scheduler timeouts/retries, cancellation propagation, capability matching, administrative controls, migration/security tests, deployment manifest, and fail-closed runtime gates. |
| Phase 6 hardening and operations | **Pending** | See the dedicated section below. |

## Verification evidence

As of 2026-08-09:

- Ruff passes for `src` and `tests`.
- Strict mypy passes for all 72 application source files.
- The full suite passes: **83 passed**, including PostgreSQL integration, migrations,
  authorization/security guards, scheduler behavior, reporting, Android, and Windows profile flows.
- PostgreSQL 18.4 passes the complete suite, migration downgrade/re-upgrade tests, and verification
  of the existing audit chain (over 500 events). A fresh pinned container also migrated through
  `0005_android`; the UMAT control-plane deployment is pinned to 18.4.
- CAPE, WinST/DT, Android, and C2 source/runtime revisions match the committed pins.
- The pinned Android image digest matches its dependency lock.
- CAPE task cancellation is enabled through its native task-status API.
- A real harmless CAPE profile was created with 4 vCPU, 4 GiB RAM, a 160 GiB virtual disk,
  selected Windows persona settings, a running-memory snapshot, and CAPE registry entry. Guarded
  deletion then removed the domain, DHCP reservation, CAPE database/config entry, and profile
  files.
- Harmless CAPE task 23 ran through the pinned WinST/DT reporter and produced a schema-valid,
  hash-covered 17,184-byte PCAP and 63,037,440-byte ETL. Public UMAT run
  `019fe74d-9750-7923-abe1-4654ddc1b2ca` completed the Windows stage and atomically registered its
  signed bundle, manifest, PCAP, access events, and raw ETL. Four core kernel providers were
  captured; unavailable Image and Threat-Intelligence providers are explicit caveats.

These checks establish the implemented contracts and lifecycle behavior. They do not replace a
clean-host installation test or promote the external runtime gates listed below.

## Current workstation deployment state

UMAT now officially targets PostgreSQL 18.4. No application dependency or migration requires
PostgreSQL 16: the code uses JSONB, enums, advisory transaction locks, and
`FOR UPDATE SKIP LOCKED`, all supported by PostgreSQL 18. The current native `18/umat` cluster on
`127.0.0.1:55432` is therefore supported and remains authoritative.

The earlier attempted PostgreSQL 18-to-16 downgrade is abandoned. Its root-only safety backups
and stopped PostgreSQL-16 Docker volume may be retained temporarily for recovery, but they are not
part of the active deployment and must not replace the PostgreSQL 18 database. The Compose file
uses a new `umat-postgres-18` volume name so it cannot accidentally open the old 16-format volume.

The UMAT API, scheduler, report worker, adapter worker, CAPE management gateway, and enrolled
Windows executor are installed as isolated systemd services on this workstation. The API is ready
on `127.0.0.1:8080`; CAPE retains port 8000 and the gateway uses `127.0.0.1:8091`. The Windows
executor environment contains no PostgreSQL credential. Android and C2 executor services are not
yet installed in this live service set.

## Known implementation and promotion gaps

- A complete `umat-deploy install --execute` run has not yet been accepted on a fresh Ubuntu 24.04
  host from only a licensed Windows ISO and authorized upstream checkouts.
- A first administrator exists and the Windows executor is explicitly enrolled. Installing and
  enrolling the Android and C2 executors remains necessary for a complete cross-module live run.
- Android dynamic analysis is not promoted until the API-30 AVD completes the prepared second boot,
  dynamic MobSF analysis, PCAP collection, signed bundle validation, and cleanup.
- Windows profile clones can enlarge but cannot shrink the approved 160 GiB baseline disk. Exact
  smaller disks require rebuilding a VMCloak template from the licensed Windows ISO.
- Production Android and C2 executor systemd units still require explicit enrollment and runtime
  credentials; executors must never receive PostgreSQL credentials.
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

Requirements are Python 3.12, `uv`, and PostgreSQL 18.4. Docker Compose provides the pinned
development database. Set a non-placeholder development password consistently in both `.env`
fields before starting it.

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

The clean-host installer defaults to dry-run mode and orchestrates the pinned upstream projects:

```bash
./install.sh \
  --windows-iso /secure/media/Win10_22H2_x64.iso \
  --admin-password-file /secure/umat-admin.password \
  --accept-android-sdk-licenses \
  --accept-unlicensed-source
```

Only add `--execute` after reviewing the dry run, licensing/authorization, storage, network, and
Windows ISO requirements. The script installs bootstrap dependencies and hash-pinned `uv`; the
resumable deployment CLI then fetches WinST/DT, Android/MobSF, and C2 and delegates native setup to
their supported workflows. See the [full-stack deployment guide](deployment/full-stack/README.md).

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
