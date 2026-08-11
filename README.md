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
| Phase 2 shared C2 service | Implemented with runtime gates | Isolated executor, input/result validation, adapters, recovery, and Windows/Android inputs exist. The executable runtime is pinned to upstream schema-v1.3 commit `f3e89cc` as effective runtime `f3e89cc-umat.1`, including normalized Windows handoff paths, simulated resolved-destination evidence, and cleaned threat-intelligence feed ingestion. |
| Phase 3 Windows/CAPE | Operational end to end | Submission-format normalization, CAPE execution and recovery, full JSON evidence import, WinST/DT handoff validation, adapters, aggregation, and reporting have completed real LNK-in-ZIP malware runs. CAPE itself is operational; the current UMAT UI does not expose every supported workflow and profile parameter. |
| Phase 4 API and UI | Operations console implemented | Case/run APIs, L1/L2/L3 views, aggregation, exports, case editing and in-case intake, server-filtered run history, immutable retries, diagnostic progress, worker inventory, and profile administration are available through the role-aware console. |
| Phase 5 Android/MobSF | Implemented and runtime-validated | The default pinned Android 11/API-30 x86_64 ReDroid profile supports unattended analysis and a brokered interactive analyst session with live screen/input, activities, Frida, TLS/proxy controls, logs, scoped file access, evidence capture, adaptation, aggregation, and reporting. The AOSP AVD is retained as a fallback; ARM profiles are out of scope. |
| Phase 5.5 hardening | Implemented | Scheduler timeouts/retries, cancellation propagation, capability matching, administrative controls, migration/security tests, fail-closed isolated guest networks, and a host guest-firewall service. |
| Phase 6 hardening and operations | **Pending** | See the dedicated section below. |

## Verified end-to-end workloads

The Windows/CAPE workload is operational end to end through the API and workers. It accepts the
original uploaded object, identifies and safely converts its submission shape for CAPE (including
LNK files carried in ZIP archives), executes it in the Windows guest, retrieves CAPE JSON and
WinST/DT evidence, normalizes findings, optionally runs offline C2 analysis, aggregates a verdict,
and generates the UMAT report. A real RubyJumper LNK run completed this entire path in
isolated/simulated mode with C2 enabled.

The Android workload is also runtime-qualified using the default Android 11/API-30 x86_64 ReDroid
profile. It provides a disposable writable guest, MobSF dynamic analysis, PCAP, optional offline
C2 processing, adaptation, aggregation, and reporting. The AOSP x86_64 AVD is retained as a
fallback profile. ARM/CPU-emulation profiles are intentionally out of scope and must not be
implemented or enabled without an explicit future decision.

The web console now covers routine submission, rerun/retry, diagnosis, worker health, profile,
Android interactive-session, evidence, and report operations. Native CAPE and raw UMAT APIs remain
engineering interfaces rather than requirements for routine operation.

## Verification evidence

As of 2026-08-11:

- Ruff passes for `src` and `tests`.
- Strict mypy passes for the application source tree.
- The default offline suite passes: **111 passed, 9 skipped**. The skipped tests require explicitly
  configured disposable PostgreSQL integration/migration databases.
- The CI-equivalent database-backed suite passes with **119 passed, 0 skipped** against disposable
  PostgreSQL 18.4 databases, including migration downgrade/re-upgrade tests. CI also runs four
  Playwright workflow groups covering authentication, intake, duplicate confirmation,
  reruns, retries, cancellation, case editing, in-case submission, run diagnosis, worker inventory,
  report selection, exports, role restrictions, and automated accessibility.
- JavaScript ESLint, Ruff, and strict mypy checks pass using committed dependency locks.
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
- A real isolated RubyJumper run completed CAPE, platform adaptation, optional C2 analysis, C2
  adaptation, aggregation, and report generation. CAPE's five-minute detonation window does not
  include guest startup or post-processing; dump analysis, Vivisect, YARA, signatures, and report
  generation can materially increase wall-clock duration.

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
Windows, Android, and C2 executors are installed as isolated systemd services on this workstation. The API is ready
on `127.0.0.1:8080`; CAPE retains port 8000 and the gateway uses `127.0.0.1:8091`. The Windows
executor environments contain no PostgreSQL credential. New runs default to isolated/simulated
networking; see the [network architecture and real-egress target](docs/network-architecture.md).

## Known implementation and promotion gaps

- A complete `umat-deploy install --execute` run has not yet been accepted on a fresh Ubuntu 24.04
  host from only a licensed Windows ISO and authorized upstream checkouts.
- A first administrator and all three executor types are enrolled on this workstation.
- Windows profile clones can enlarge but cannot shrink the approved 160 GiB baseline disk. Exact
  smaller disks require rebuilding a VMCloak template from the licensed Windows ISO.
- The reverse proxy, TLS, production filesystem mount flags, and separated-host topology are not complete.
- ReDroid remains privileged inside a disposable KVM worker, but no longer shares the control-plane
  host kernel. The per-run QCOW2 overlay is destroyed after completion or failure.
- Full offline dependency staging and clean-room verification are not complete.
- The C2 and locked WinST/DT revisions do not contain explicit upstream license files. Their source
  or derived images must not be redistributed until authorization is documented. No upstream
  source is vendored here.
- Court/evidentiary readiness is not claimed; organizational procedure, key custody, and legal
  validation are outside the software test suite.

## Current UI limitations

The operations console covers routine workflows. Remaining UI enhancements are deeper live CAPE
post-processing telemetry, bulk operations, server-side case pagination, and organization-specific
analysis timeout/options if those controls are approved in deployment policy. The supported
guest-profile, network, C2, Android-interactive, retry, cancellation, evidence, and diagnostic
controls are exposed with role-aware actions.

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

## Full-stack installation

### Host and media requirements

- Ubuntu 24.04 x86_64 with hardware virtualization/KVM enabled.
- A normal, passwordless-sudo-capable operator account. Do not run the installer as root.
- Docker, libvirt and sufficient storage for CAPE, Windows guests, Android images, PostgreSQL,
  samples and evidence. Bootstrap packages are installed automatically with `--execute`.
- Network access for the current online installer, or separately staged dependencies for future
  offline installation.
- A legitimately licensed **64-bit Windows 10 22H2 ISO**. The ISO is an operator-supplied input;
  UMAT does not download or redistribute Windows installation media. Keep it outside Git (the
  conventional root filename `Win10_22H2_English_x64v1.iso` is ignored).
- Explicit acceptance of Android SDK licences and authorization to use the pinned WinST/DT and C2
  sources, whose upstream repositories do not currently provide redistribution licences.

### Installer chain

The installation is resumable and follows this order:

1. `install.sh` validates the host, installs bootstrap packages and the hash-pinned `uv` tool.
2. `umat-deploy` verifies its manifest and pinned upstream revisions, then prepares secrets and
   environment files.
3. WinST/DT installs CAPE and builds the licensed Windows 10 baseline/snapshot from the supplied
   ISO; UMAT configures the CAPE integration and profile-management gateway.
4. The pinned C2 runtime and Android/MobSF/ReDroid runtime are built and verified.
5. PostgreSQL starts, migrations are applied, the first administrator and default Android profiles
   are created.
6. Hardened systemd services and the fail-closed guest firewall are installed.
7. Windows, C2, and Android executors receive one-time enrollment credentials; no executor receives
   the PostgreSQL credential.
8. Status and harmless runtime acceptance gates verify services, revisions, images, Windows
   evidence handoff, and executor isolation.

Start with a dry run; the clean-host installer orchestrates the pinned upstream projects without
changing the host:

```bash
./install.sh \
  --windows-iso /secure/media/Win10_22H2_x64.iso \
  --admin-password-file /secure/umat-admin.password \
  --accept-android-sdk-licenses \
  --accept-unlicensed-source
```

Then rerun the same command with `--execute`. Correct a failed prerequisite and rerun without
deleting state; verified checkouts, secrets, databases, images, and completed phase markers are
preserved. See the [full-stack deployment guide](deployment/full-stack/README.md) for flags,
recovery, enrollment, and status semantics.

## Usage

1. Open `http://127.0.0.1:8080` and sign in as the bootstrapped administrator.
2. Create a case, attach a sample, and create an analysis run for Windows or Android. Samples in
   `ACTUAL_MALWARE/` are intentionally ignored by Git.
3. Keep `isolated_simulated` selected for the current qualified malware baseline. Enable **C2
   analysis** independently if the captured/simulated traffic should be processed by the offline C2
   workflow. Do not select real-world egress until the external sacrificial egress architecture in
   [the network guide](docs/network-architecture.md) is deployed and authorized.
4. Monitor the platform, optional C2, adaptation, aggregation, and report stages. A nominal
   five-minute CAPE analysis commonly takes longer end to end because VM startup and native
   post-processing are outside that timer.
5. Review the UMAT report and download authorized JSON/PDF/CSV or evidence artifacts. Use CAPE's
   interface only for native diagnostics while the UMAT UI backlog remains open.

For an Android APK, leave **interactive analyst session** enabled to hold the disposable ReDroid
guest for up to 15 minutes after MobSF static preparation. Open **Android workflow** from the case
and use the live screen, touch/swipe/keyboard input, activity and deep-link launchers, logcat,
screenshots, Frida hooks or custom scripts, API monitor, TLS tester, proxy/root-CA controls, runtime
dependencies, and the application-data browser. Explicitly finalize the session to collect the
PCAP, scan logs, APK, Java/Smali exports, private application-data archive and dynamic report. A
five-minute extension is available up to a hard 30-minute session limit; expiry also forces cleanup.
All commands are allowlisted, tied to the active signed executor lease and audit logged. The API
service never receives Docker, ADB or MobSF credentials.

Operational checks:

```bash
uv run umat-deploy status
systemctl --no-pager --failed
systemctl status umat-api umat-scheduler umat-report-worker umat-adapter-worker
systemctl status umat-windows-executor umat-c2-executor umat-android-executor
```

## Documentation

- [Single-host development](deployment/single-host/README.md)
- [Full-stack deployment](deployment/full-stack/README.md)
- [Phase 2 shared C2](docs/phase2-c2.md)
- [Malware analysis network architecture](docs/network-architecture.md)
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
