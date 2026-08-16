# E-Rakshak

**Unified Cross-Platform Malware Detection and Behavioural Analysis Suite**
Problem Statement `ERH26_PS_04` · Cybersecurity & Malware Analysis

An investigator submits a suspicious Windows executable or Android APK. The suite triages
it statically, detonates it inside a disposable guest on a network with no route out,
captures host behaviour and full packet traffic from outside that guest, correlates what
was *accessed* against what was *sent*, and produces one role-filtered, hash-chained,
court-presentable report — whatever the platform.

Every finding carries the rule that produced it, a confidence tier, and the limits of the
run that produced it. A behavioural signal alone is a candidate; promotion to a higher
tier requires an independent source.

---

## Table of contents

1. [Repositories](#1-repositories)
2. [System architecture](#2-system-architecture)
3. [Project folder structure](#3-project-folder-structure)
4. [Setup and installation](#4-setup-and-installation)
5. [API documentation](#5-api-documentation)
6. [Database schema](#6-database-schema)
7. [Dependencies and requirements](#7-dependencies-and-requirements)
8. [Deployment](#8-deployment)
9. [Testing and verification](#9-testing-and-verification)
10. [Safety boundary](#10-safety-boundary)

---

## 1. Repositories

The suite is four repositories. UMAT is the control plane and pins the other three by
commit; the analysis modules never talk to each other or to the database directly.

| Component | Repository | Role |
|---|---|---|
| **UMAT** — control plane | `MYTH-il/E-Rakshak-UMAT` | Intake, custody, scheduling, aggregation, reporting, web console, PostgreSQL |
| **Windows ST/DT** | `MYTH-il/WinST-DT-module` | Static triage, CAPE detonation, ETW host telemetry, PCAP capture |
| **C2/Exfil** | `demistifying/C2-Exfil-E-Rakshak` | Network analysis, attribution, host↔network correlation |
| **Android (ST + DT)** | `d4ruvil/erakshak` | MobSF static analysis, ReDroid dynamic run, Frida instrumentation, traffic capture |

> **This repository is UMAT, the control plane.** This README documents the suite as a
> whole. For the control plane in depth — implementation status, verification evidence,
> known gaps, UI limitations and operations runbook — see
> [`docs/CONTROL-PLANE.md`](docs/CONTROL-PLANE.md).

Pinned revisions live in `dependency-locks/`. Each lock records the
upstream commit, a tree hash, and the tool versions the runtime was verified against —
so a deployment is reproducible and a drifting upstream is detected rather than silently
absorbed.

```
dependency-locks/
├── winstdt.json           commit 7bc7476 · capa 9.3.1, floss 3.1.1, diec 3.10,
│                          suricata 7.0.17, mitmproxy 12.1.1, volatility3 2.11.0
├── c2-exfil.json          commit 970e941 · python 3.12 · 360 upstream test functions
├── android-erakshak.json  commit 6462901 · MobSF 4.5.1, Frida 17.17.0, jadx 1.5.0,
│                          Android API 30, emulator 34.1.19
├── umat-postgres.json     postgres:18.4 pinned by image digest
├── installer.json         installer manifest and pinned `uv`
└── third-party-inventory.json
```

---

## 2. System architecture

### 2.1 Layers

```
┌──────────────────────────────────────────────────────────────────────────┐
│  OPERATIONS CONSOLE            role-aware · vanilla ES modules · no build │
│  officer  │  analyst  │  administrator                                    │
└─────────────────────────────────┬────────────────────────────────────────┘
                                  │  HTTPS · session cookie · RBAC
┌─────────────────────────────────▼────────────────────────────────────────┐
│  UMAT CONTROL PLANE  (FastAPI · PostgreSQL 18.4)                          │
│                                                                           │
│  intake ─ custody ─ scheduler ─ lease manager ─ aggregator ─ reporting    │
│                                                                           │
│  • holds the only database credential                                     │
│  • validates every inbound bundle against a JSON Schema contract          │
│  • hash-chains every evidence row (SHA-256, each row embeds the previous) │
└───────┬──────────────────┬───────────────────┬───────────────────────────┘
        │ /api/internal/v1 │  lease + heartbeat│  (executors poll; they are
        │                  │                   │   never called inbound)
┌───────▼────────┐ ┌───────▼────────┐ ┌────────▼────────┐
│ WINDOWS ST/DT  │ │ WINDOWS C2 /   │ │ ANDROID WORKER  │
│ EXECUTOR       │ │ EXFIL EXECUTOR │ │                 │
│                │ │                │ │                 │
│ CAPEv2 + KVM   │ │ scapy · Zeek   │ │ MobSF 4.5.1     │
│ Win10 22H2     │ │ Suricata       │ │ ReDroid API 30  │
│ ETW agent      │ │ GeoLite2       │ │ Frida 17.17.0   │
│ full PCAP      │ │ abuse.ch intel │ │ tcpdump+mitm    │
└───────┬────────┘ └───────┬────────┘ └────────┬────────┘
        │                  │                   │
   winstdt-isolated   (consumes ST/DT      172.30.0.0/24
   libvirt network     PCAP; executes       internal bridge
   (no route out)      nothing itself)      (no route out)
```

### 2.2 Stage pipeline

A run is a directed graph of stages. The scheduler leases a stage to a registered
executor, the executor heartbeats while it works, and the lease expires if it dies —
`lease_expired` is recorded distinctly from `timeout`, because the two mean different
things in an evidence log.

```
platform_analysis ──┬──> platform_adaptation ──┐
                    │                          ├──> case_aggregation ──> report_generation
   c2_analysis ─────┴──> c2_adaptation ────────┘
```

| Stage | Runs on | Produces |
|---|---|---|
| `platform_analysis` | Windows or Android worker | Raw engine output + artifact bundle (PCAP, ETW trace, MobSF report) |
| `c2_analysis` | C2 executor | Network findings, attribution, correlation candidates |
| `platform_adaptation` | Control plane | Engine output translated into the shared case model |
| `c2_adaptation` | Control plane | Network findings translated into the shared case model |
| `case_aggregation` | Control plane | One verdict, one confidence-graded finding set, caveats applied |
| `report_generation` | Report worker | Immutable snapshot + PDF / JSON / CSV exports |

### 2.3 The evidence model

Adapters translate; they never re-score. Both platforms land in the same vocabulary:

- **17 data types** — browser credentials, crypto wallet, keystrokes, screenshot,
  clipboard, documents, file access, system info, SMS, contacts, location, camera,
  call log, microphone, calendar, device identity, other.
- **5 confidence tiers**, ordered — `allowlisted < unconfirmed < weak < strong < confirmed`.
- **Honesty gates** that cap findings automatically, without human intervention:
  `network_responses_simulated`, `host_telemetry_degraded`,
  `host_network_correlation_unavailable`, and clock-quality degradation.

### 2.4 Detection thresholds

Every detector states the condition it tests. These are defaults; the value applied to a
case is recorded with the case.

| Detector | Condition | Tier reached alone |
|---|---|---|
| Beaconing | ≥ 4 connections, jitter ratio ≤ 0.25, mean interval ≥ 1 s | weak |
| Exfiltration | upload ratio ≥ 0.7 of session bytes | weak |
| DNS tunnelling | ≥ 5 encoded queries under one parent domain | strong |
| DGA (statistical) | ≥ 10 queries, entropy ≥ 3.2, NXDOMAIN ratio ≥ 0.5 | strong |
| DGA (learned) | logistic-regression score p ≥ 0.75 | weak (candidate only) |
| ICMP tunnelling | ≥ 8 packets of ≥ 64 bytes payload | weak |
| Host↔network correlation | 15 s window; `proximity×0.5 + network×0.3 + reputation×0.2` ≥ 0.6 | strong |
| Reputation | exact match in the local abuse.ch corpus | confirmed |

### 2.5 Trust boundaries

- Executors receive a scoped enrollment credential. **No executor ever receives
  `DATABASE_URL`.**
- Malware executes only inside a disposable guest, reset per sample.
- Capture happens *outside* the guest, where the sample cannot reach or alter it.
- Egress is fail-closed via an nftables broker; the Android bridge is internal-only.
- Container archives (`.zip`, `.7z`, …) are rejected at intake with an instruction to
  submit the contained sample — rather than being analysed as though they were programs.

---

## 3. Project folder structure

### 3.1 UMAT — control plane

```
E-Rakshak-UMAT/
├── install.sh                     clean-host installer (dry-run by default)
├── pyproject.toml                 deps + console scripts
├── uv.lock                        fully resolved lockfile
├── alembic.ini
├── migrations/versions/           11 migrations
├── contracts/                     JSON Schemas for inbound bundles
├── dependency-locks/              pinned upstream commits + tool versions
├── deployment/
│   ├── full-stack/                orchestrated multi-host install
│   ├── single-host/               compose.yaml (pinned PostgreSQL)
│   ├── windows/                   CAPE + guest integration
│   ├── android/                   ReDroid image, Frida overlay, patch series
│   ├── android-worker/            disposable worker, relays, systemd units
│   └── c2/                        C2 runtime build + verification
├── executors/                     executor-side packaging
├── src/umat/
│   ├── api/                       app.py + REST routers
│   ├── auth/                      sessions, Argon2, RBAC dependencies
│   ├── intake/                    upload, dedup, custody, archive rejection
│   ├── scheduler/                 stage graph, leases, retries
│   ├── executors/                 registration, claims, fake executor
│   ├── windows/  c2/  android/    per-platform executors + adapters + routes
│   ├── adapters/                  raw output → shared case model
│   ├── operations/                aggregation, case editing, run history
│   ├── reporting/                 snapshots, PDF/JSON/CSV exports, worker
│   ├── audit/                     SHA-256 hash chain, signed roots
│   ├── storage/                   immutable artifact store
│   ├── egress/                    fail-closed egress broker
│   ├── contracts/                 schema validation
│   ├── db/  models.py base.py session.py      48 tables
│   ├── config/settings.py         all UMAT_* settings
│   ├── cli/                       `umat admin …`
│   └── web/                       templates + static ES modules
└── tests/                         unit, integration, migration, Playwright
```

### 3.2 C2/Exfiltration module

```
windows_c2exfil_module/
├── pipeline/
│   ├── orchestrator.py            entry point — runs the full pipeline
│   ├── pcap_loader.py             scapy ingest
│   ├── zeek_ingest.py             conn/dns/ssl/x509 logs
│   ├── etw_ingest.py              host access events from ST/DT
│   ├── traffic_analysis.py        beaconing + exfiltration
│   ├── dns_analysis.py            tunnelling, DGA, parent-domain rollup
│   ├── dga_classifier.py          offline logistic-regression inference
│   ├── covert_channels.py         ICMP and other covert paths
│   ├── http_analysis.py  tls_analysis.py  ja3_from_pcap.py  ja3_loader.py
│   ├── app_exfil.py               FTP/SMTP upload paths
│   ├── content_recon.py           payload classification where readable
│   ├── correlation.py             host↔network join, 15 s window
│   ├── attribution.py             GeoLite2 ASN/City + reputation
│   ├── family_attribution.py      family mapping
│   ├── static_prior.py            IOC prior from ST/DT, provenance-tiered
│   ├── feed_import.py             abuse.ch ingest + shared-hosting filter
│   ├── allowlist.py               OS/vendor traffic
│   ├── bundle_filter.py  handoff.py    UMAT bundle in/out
│   ├── provenance.py  evidence.py  timeline.py  model.py
│   ├── export_iocs.py             CSV + STIX 2.1
│   ├── db_loader.py               PostgreSQL load
│   ├── datapaths.py               module-relative paths (not cwd-relative)
│   └── validate.py                precision/recall harness
├── data/
│   ├── GeoLite2-ASN.mmdb  GeoLite2-City.mmdb  GeoLite2-Country.mmdb
│   ├── threatintel.sqlite         local abuse.ch corpus
│   ├── models/dga_lr.json         auditable model weights
│   ├── ground_truth.json          validation labels
│   └── *.pcap                     reference captures (gitignored)
├── tools/train_dga_classifier.py  re-training (numpy, train-time only)
├── scripts/seed_threatintel.py    build the intel SQLite from feeds
├── schemas/  sql/  docker/  docs/
├── tests/                         27 files · 401 tests
└── requirements.txt
```

### 3.3 Windows ST/DT

```
WinST-DT-module/
├── Cargo.toml  src/main.rs        Rust static-triage binary (goblin, sha2, …)
├── winstdt/access_events.py       ETW access-event emitter
├── cape/                          analyzer, custom modules, CAPE integration
├── config/  libvirt/  suricata/   isolated network + signature config
├── gateway/                       host-side capture gateway
├── responder/                     simulated network responder
├── integrations/c2-exfil/         embedded C2 module + patch series
├── schemas/                       handoff bundle schema
├── scripts/
│   ├── setup-ubuntu24-host.sh
│   ├── configure-cape-runtime.sh
│   ├── finalize-windows-guest.sh
│   ├── validate-deployment.sh
│   ├── etw_agent/  guest_hardening/  validation/
└── docs/validation/               golden-image acceptance reports
```

### 3.4 Android module

Static analysis via MobSF 4.5.1; dynamic run inside a digest-pinned ReDroid Android 11 /
API 30 container with a checksum-verified Frida 17.17.0 server baked into the image.
Traffic is captured with tcpdump on the internal bridge and mitmproxy with a
pre-installed CA. Integration is documented in `E-Rakshak-UMAT/deployment/android/README.md`.

---

## 4. Setup and installation

### 4.1 Prerequisites

- Ubuntu 24.04 x86_64 with hardware virtualisation (KVM) enabled
- Python **3.12**, [`uv`](https://github.com/astral-sh/uv), Docker, libvirt
- PostgreSQL **18.4** (supplied as a pinned container)
- A normal operator account with passwordless sudo — **do not run the installer as root**
- A legitimately licensed **64-bit Windows 10 22H2 ISO** (operator-supplied; the project
  neither downloads nor redistributes Windows media)
- Acceptance of the Android SDK licences

### 4.2 Development quick start — control plane only

```bash
cd E-Rakshak-UMAT

uv sync --frozen --extra test
cp .env.example .env
# Set UMAT_POSTGRES_PASSWORD and the matching password inside UMAT_DATABASE_URL.

sudo docker compose --env-file .env -f deployment/single-host/compose.yaml up -d postgres
uv run alembic upgrade head
uv run umat admin create-user --username admin --role administrator
```

Run the long-lived processes in separate terminals:

```bash
uv run umat-api              # console + REST on 127.0.0.1:8080
uv run umat-scheduler run    # stage graph, leases, retries
uv run umat-report-worker run
uv run umat-adapter-worker run
```

PostgreSQL binds only to `127.0.0.1:55432`. CAPE/WinST-DT keeps its own ports and database.

### 4.3 C2/Exfiltration module — standalone

The module is stdlib-heavy by design and runs offline.

```bash
cd windows_c2exfil_module
pip install -r requirements.txt          # add --break-system-packages if needed

python pipeline/orchestrator.py                       # sample capture
python pipeline/orchestrator.py data/your.pcap        # a real capture
python pipeline/validate.py                           # precision / recall
```

**Two data assets are not in Git and must be provisioned on the analysis host:**

```bash
# 1 · GeoLite2 databases (MaxMind account required; free tier is sufficient)
#    Place GeoLite2-ASN.mmdb and GeoLite2-City.mmdb in data/, or point at them:
export GEOLITE2_ASN_DB=/opt/geoip/GeoLite2-ASN.mmdb
export GEOLITE2_CITY_DB=/opt/geoip/GeoLite2-City.mmdb

# 2 · Threat-intelligence corpus, built offline from abuse.ch feeds
python scripts/seed_threatintel.py
export THREATINTEL_DB=/opt/erakshak/threatintel.sqlite   # optional override
```

Without GeoLite2 the pipeline still runs — geo/ASN fields are simply absent, and the
report says so rather than leaving a blank. Without the intel corpus, reputation cannot
promote anything to `confirmed`.

Optional Docker services for Zeek, Suricata and PostgreSQL:

```bash
docker compose up -d postgres
docker compose run --rm zeek
docker compose run --rm suricata
python pipeline/orchestrator.py
python pipeline/db_loader.py
```

### 4.4 Windows ST/DT worker

Resumable, dry-run by default; add `--execute` to apply.

```bash
scripts/setup-ubuntu24-host.sh --windows-iso /abs/path/Win10_22H2_x64.iso --execute
scripts/configure-cape-runtime.sh --execute
scripts/finalize-windows-guest.sh \
  --qualification-only \
  --al-khaser /path/to/al-khaser.exe \
  --pafish /path/to/pafish.exe \
  --execute
scripts/validate-deployment.sh --execute
```

Review the generated anti-evasion evidence before sealing the golden image.

### 4.5 Environment variables

Control plane (`E-Rakshak-UMAT/.env`):

| Variable | Purpose |
|---|---|
| `UMAT_ENVIRONMENT` | `development` / `production` |
| `UMAT_DATABASE_URL` | PostgreSQL DSN — **control plane only** |
| `UMAT_POSTGRES_PASSWORD` | Password for the pinned container; must match the DSN |
| `UMAT_API_HOST` / `UMAT_API_PORT` | Bind address (default `127.0.0.1:8080`) |
| `UMAT_SESSION_SECRET` / `UMAT_SECURE_COOKIES` | Session signing and cookie policy |
| `UMAT_ALLOWED_HOSTS` | Host header allowlist |
| `UMAT_QUARANTINE_ROOT` / `UMAT_ARTIFACT_ROOT` | Sample quarantine and immutable artifacts |
| `UMAT_EXECUTOR_ENROLLMENT_SECRET` | One-time executor enrollment |
| `UMAT_C2_RUNTIME_ROOT` / `_WORK_ROOT` / `_COMMIT` / `_PATCH_SHA256` | Pinned C2 runtime |
| `UMAT_WINSTDT_SCHEMA_ROOT` | Handoff schema location |
| `UMAT_WINDOWS_MAX_BUNDLE_BYTES` / `UMAT_ANDROID_MAX_BUNDLE_BYTES` | Bundle size caps |
| `UMAT_STAGE_MAX_ATTEMPTS` / `UMAT_STAGE_TIMEOUT_SECONDS` | Retry and timeout policy |

C2 module: `GEOLITE2_ASN_DB`, `GEOLITE2_CITY_DB`, `THREATINTEL_DB` (all optional
overrides; defaults resolve relative to the module, not the working directory).

---

## 5. API documentation

FastAPI, mounted at `/api/v1` (operator) and `/api/internal/v1` (executors). Interactive
schema is served by the running app, and two contracts are checked into the repository:

- [`contracts/executor-api.openapi.yaml`](contracts/executor-api.openapi.yaml) — the
  executor protocol, the authoritative version of §5.7 below
- [`contracts/cape-management.openapi.yaml`](contracts/cape-management.openapi.yaml) — the
  CAPE profile-management gateway

Authentication is a session cookie issued by
`POST /api/v1/auth/login`; authorisation is role-based — `officer`, `analyst`,
`administrator`. Full evidence requires `analyst` or `administrator`.

### 5.1 Health and console

| Method | Path | Notes |
|---|---|---|
| `GET` | `/health/live` · `/health/ready` | Liveness and readiness |
| `GET` | `/metrics` | Operational metrics |
| `GET` | `/` `/login` `/cases` `/runs` `/submit` | Console pages |
| `GET` | `/cases/{case_id}` · `/analysis/{run_id}/android` | Case and run views |
| `GET` | `/admin/windows` `/admin/android` `/admin/workers` `/admin/users` | Admin views |

### 5.2 Authentication — `/api/v1/auth`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/login` | Issue a session (rate-limited by `login_max_attempts`) |
| `POST` | `/logout` | Revoke the current session |
| `GET` | `/session` | Current principal and roles |

### 5.3 Cases and runs — `/api/v1`

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/cases` | Create a case |
| `GET` | `/cases` | List cases |
| `GET` | `/cases/{case_id}` | Case detail |
| `GET` | `/cases/{case_id}/status` | Lightweight status poll |
| `PATCH` | `/cases/{case_id}` | Edit case metadata |
| `POST` | `/cases/{case_id}/submissions` | In-case sample intake |
| `POST` | `/cases/{case_id}/analysis-runs` | Create a run |
| `POST` | `/analysis-runs/{run_id}/confirm` | Confirm and queue |
| `POST` | `/analysis-runs/{run_id}/cancel` | Request cancellation |
| `POST` | `/analysis-runs/{run_id}/retry` | Immutable retry (new run, original preserved) |
| `GET` | `/analysis-runs` | Server-filtered run history |
| `GET` | `/artifacts/{artifact_id}` | Download an artifact, gated by `access_tier` |
| `GET` | `/admin/workers` | Worker inventory |

### 5.4 Reporting — `/api/v1/cases`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/{case_id}/report` | Role-filtered report snapshot |
| `POST` | `/{case_id}/exports/json` | JSON export |
| `POST` | `/{case_id}/exports/pdf` | PDF export (ReportLab) |
| `POST` | `/{case_id}/exports/csv` | CSV export |

All three formats are filtered from the **same** snapshot, so an officer and an analyst
never read divergent evidence — only different amounts of it.

### 5.5 Platform workflow — `/api/v1`

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/analysis-runs/{run_id}/windows-workflow` | Windows run progress |
| `POST` | `/analysis-runs/{run_id}/windows-session/finish` | End an interactive session |
| `POST` | `/analysis-runs/{run_id}/windows-session/launch-viewer` | Attach a console viewer |
| `WS` | `/analysis-runs/{run_id}/windows-console` | Live interactive console |
| `GET` | `/analysis-runs/{run_id}/android-workflow` | Android run progress |
| `POST` | `/analysis-runs/{run_id}/android-commands` | Queue a device command |
| `GET` | `/analysis-runs/{run_id}/android-commands/{command_id}` | Command status |
| `GET` | `/analysis-runs/{run_id}/android-evidence/{evidence_name}` | Fetch evidence |

Profiles — `/api/v1/windows/profiles/{id}` and `/api/v1/android/profiles/{id}` support
`GET`, `PATCH`, `DELETE`; Android additionally exposes `POST /{id}/qualify`.

### 5.6 Administration — `/api/v1/admin/users`

| Method | Path | Purpose |
|---|---|---|
| `PATCH` | `/{user_id}` | Update a user |
| `POST` | `/{user_id}/revoke-sessions` | Force sign-out |
| `DELETE` | `/{user_id}` | Remove a user |

Equivalent CLI: `umat admin create-user`, `set-user-role`, `set-user-enabled`,
`revoke-user-sessions`, `enroll-executor`, `revoke-executor`, `seed-android-profiles`.

### 5.7 Executor API — `/api/internal/v1`

Executors **poll**; the control plane never calls into a worker. Mutations are signed with
the executor credential and recorded in the audit chain.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/executors/register` · `/executors/capabilities` | Enrollment and capability reporting |
| `POST` | `/executors/claim` | Claim the next eligible stage (issues a lease) |
| `POST` | `/executors/windows/profile-operations/claim` | Claim a profile operation |
| `POST` | `/executors/windows/profile-operations/{id}/complete` | Complete it |
| `GET` | `/stages/{stage_id}/sample` | Download the sample under analysis |
| `GET` | `/stages/{stage_id}/inputs/{artifact_id}` | Fetch an upstream artifact (e.g. the PCAP) |
| `POST` | `/stages/{stage_id}/heartbeat` | Renew the lease |
| `POST` | `/stages/{stage_id}/native-task` | Report a native backend task |
| `POST` | `/stages/{stage_id}/windows-session/ready` · `/poll` | Interactive Windows session |
| `POST` | `/stages/{stage_id}/android-session/ready` · `/poll` · `/complete-command` | Interactive Android session |
| `POST` | `/stages/{stage_id}/artifacts` | Upload an artifact (hashed on receipt) |
| `POST` | `/stages/{stage_id}/complete` · `/fail` · `/cancellation-ack` | Terminal transitions |

**Lease semantics.** `lease_ttl_seconds` defaults to 60. An executor heartbeats inside its
own work loop; if it dies the lease expires and the stage is re-queued as `lease_expired`,
which is recorded separately from `timeout`.

### 5.8 Module interface — C2/Exfiltration

The C2 module has no HTTP surface. Its interface is a CLI plus a schema-validated bundle.

```bash
python pipeline/orchestrator.py <capture.pcap> \
  --case-id       <uuid>              # case this run belongs to
  --zeek-dir      <dir>               # pre-parsed Zeek logs
  --etw-events    <file.json>         # host access events from ST/DT
  --static-prior  <file.json>         # IOC prior from static triage
  --handoff       <bundle.json>       # UMAT handoff bundle in/out
```

The emitted bundle is validated against the contracts in `E-Rakshak-UMAT/contracts/`.
A malformed bundle is **rejected**, never partially ingested.

---

## 6. Database schema

PostgreSQL 18.4. **48 tables** defined in `src/umat/db/models.py`, versioned by 11 Alembic
migrations. All primary keys are UUID except `samples` (SHA-256) and `audit_events`
(monotonic sequence).

### 6.1 Identity and access

| Table | Notes |
|---|---|
| `users` | Argon2 password hash |
| `roles` · `user_roles` | `officer`, `analyst`, `administrator` |
| `sessions` | Server-side sessions, revocable |
| `login_attempts` | Rate limiting and lockout |

### 6.2 Custody

| Table | Key columns |
|---|---|
| `cases` | `id`, `owner_user_id → users`, `title`, `reference`, timestamps |
| `samples` | `sha256` **PK**, `size_bytes`, `media_type`, `object_key`, `first_seen_at` |
| `submissions` | `case_id`, `uploader_user_id`, `sample_sha256`, `original_filename`, `custody_state` |
| `case_samples` | Many-to-many join |

A sample is stored **once**, keyed by its own hash. Re-submitting the same file across
cases deduplicates the storage without merging the custody records.

### 6.3 Execution

| Table | Key columns |
|---|---|
| `analysis_runs` | `case_id`, `submission_id`, `platform`, `status`, `result`, `network_mode`, `c2_analysis_enabled`, `windows_interactive`, `android_interactive`, cancellation fields |
| `analysis_stages` | `analysis_run_id`, `stage_type`, `state`, `priority`, `max_attempts`, `timeout_seconds`, `failure_code`, `failure_detail` |
| `stage_dependencies` | Edges of the stage graph |
| `analysis_attempts` | One row per execution attempt |
| `executor_leases` | `stage_id`, `attempt_id`, `executor_id`, `token_hash`, `expires_at`, `last_heartbeat_at`, `released_at`, `release_reason` |
| `executors` · `executor_credentials` · `executor_requests` · `executor_enrollment_tokens` | Worker identity |
| `backend_tasks` · `backend_capability_snapshots` | Native backend (CAPE/MobSF) task tracking |

### 6.4 Evidence

| Table | Purpose |
|---|---|
| `artifacts` | `kind`, `sha256`, `size_bytes`, `media_type`, `object_key`, **`access_tier`**, `bundle_id` |
| `bundle_imports` | Ingest record per handoff bundle |
| `adaptation_records` | Provenance root for everything an adapter produced |
| `c2_findings` | `finding_kind`, `plain_language`, **`confidence`**, **`capped_by_caveat`**, `details` |
| `network_observations` · `exfil_events` · `static_iocs` | Network-side evidence |
| `provenance_links` | Ties a finding back to the artifact and event that produced it |
| `timeline_events` | Unified host+network timeline |
| `attribution_results` | Geo, ASN, reputation |
| `windows_analysis_metadata` · `windows_findings` · `windows_capabilities` | Windows platform evidence |
| `android_analysis_metadata` · `android_findings` · `android_capabilities` | Android platform evidence |

`capped_by_caveat` is the audit trail for the honesty gates: it records *which* declared
limitation held a finding below the tier its raw signal would otherwise have earned.

### 6.5 Configuration and sessions

`windows_vm_profiles`, `windows_profile_operations`, `windows_run_configurations`,
`windows_dynamic_sessions`, `android_analysis_profiles`, `android_run_configurations`,
`android_dynamic_sessions`, `android_session_commands`.

### 6.6 Reporting and audit

| Table | Purpose |
|---|---|
| `case_report_snapshots` | `schema_version`, `revision`, `verdict`, `headline`, `report_json`, **`evidence_digest`** |
| `report_exports` | One row per generated file, linked to the snapshot and the artifact |
| `audit_events` | `sequence` **PK**, `actor_type`, `action`, `target_type`, `payload`, **`previous_hash`**, **`event_hash`** |
| `signed_audit_roots` | Periodic signed roots over the chain |

**The hash chain.** Each `audit_events` row embeds the hash of the row before it. Altering
or deleting any record breaks every hash after it, and the break localises the tampering
to an exact sequence number. `case_report_snapshots.evidence_digest` binds a report to the
evidence set it describes, and the report itself is bound to the sample SHA-256.

### 6.7 Enumerations

| Enum | Values |
|---|---|
| `Platform` | `windows`, `android` |
| `RunStatus` | `awaiting_confirmation`, `queued`, `running`, `cancelling`, `terminal` |
| `RunResult` | `completed`, `partial`, `inconclusive`, `failed`, `cancelled`, `unsupported` |
| `StageType` | `platform_analysis`, `c2_analysis`, `platform_adaptation`, `c2_adaptation`, `case_aggregation`, `report_generation` |
| `StageState` | `waiting`, `queued`, `leased`, `running`, `completed`, `partial`, `failed`, `cancelled`, `unsupported` |
| `AttemptState` | `leased`, `running`, … |
| `AccessTier` | `officer`, `analyst`, `administrator` |
| `ExecutorStatus` | `pending`, `active`, `disabled` |
| `Verdict` | `malicious`, `suspicious`, `no_malicious_activity_observed`, `inconclusive`, `failed` |
| `ExportFormat` | `json`, `pdf`, `csv` |

`no_malicious_activity_observed` is deliberately not called "clean". Under containment,
absence of evidence is not evidence of absence, and the vocabulary says so.

---

## 7. Dependencies and requirements

### 7.1 Control plane — Python 3.12, resolved in `uv.lock`

```
fastapi==0.141.1          starlette==1.5.0          uvicorn[standard]>=0.34,<1
sqlalchemy[asyncio]>=2.0.36,<3                      asyncpg>=0.30,<1
psycopg[binary]>=3.2,<4   alembic>=1.14,<2          pydantic-settings>=2.7,<3
argon2-cffi>=23.1,<26     cryptography>=44,<47      python-multipart>=0.0.20,<1
jsonschema[format]>=4.23,<5                         geoip2==5.3.0
reportlab>=4.2,<5         httpx==0.28.1             websockets>=15,<16
structlog>=24.4,<26       typer>=0.15,<1            uuid6>=2024.7.10
```

Front end: server-rendered templates plus vanilla ES modules. **No framework, no build
step, no third-party CDN at run time.**

### 7.2 Windows C2/Exfiltration module

```
scapy>=2.5.0              psycopg[binary]>=3.1
geoip2>=4.7.0             pytest>=7.0
numpy>=1.24  ; extra == "train"     # re-training the DGA model only — never at run time
```

Everything else is standard library. The DGA model is scored in pure Python from
human-readable JSON weights, so **the analysis host needs no ML runtime at all**.

External services used offline: Zeek and Suricata (containers), GeoLite2 databases,
abuse.ch ThreatFox / Feodo / URLhaus in a local SQLite corpus.

### 7.3 Windows ST/DT

Rust 2024 edition (`clap` 4.5, `goblin` 0.9, `serde` 1.0, `sha2`/`sha1`/`md-5`, `regex`,
`thiserror`) plus CAPEv2 on KVM/libvirt. Pinned analysis tooling: capa 9.3.1,
FLOSS 3.1.1, Detect It Easy 3.10, Suricata 7.0.17, mitmproxy 12.1.1, Volatility 3 2.11.0.

### 7.4 Android

MobSF 4.5.1 (Poetry 2.4.1), jadx 1.5.0, Frida 17.17.0 (checksum-verified server baked into
the image), digest-pinned ReDroid Android 11 / API 30, Android emulator 34.1.19 for the
fallback AVD profile.

### 7.5 Host requirements

Ubuntu 24.04 x86_64 · KVM · Docker · libvirt · storage for CAPE, Windows guests, Android
images, PostgreSQL, samples and evidence · a licensed Windows 10 22H2 x64 ISO.

---

## 8. Deployment

### 8.1 Full-stack installer

Resumable, hash-pinned, and **dry-run by default**. It orchestrates the pinned upstream
projects without changing the host until `--execute` is passed.

```bash
cd E-Rakshak-UMAT

./install.sh \
  --windows-iso /secure/media/Win10_22H2_x64.iso \
  --admin-password-file /secure/umat-admin.password \
  --accept-android-sdk-licenses \
  --accept-unlicensed-source
```

Review the plan, then rerun the identical command with `--execute`.

Install order:

1. `install.sh` validates the host, installs bootstrap packages and the hash-pinned `uv`.
2. `umat-deploy` verifies its manifest and pinned upstream revisions, prepares secrets.
3. WinST/DT installs CAPE and builds the licensed Windows 10 baseline and snapshot from
   the supplied ISO; UMAT configures the CAPE integration and profile gateway.
4. The pinned C2 runtime and the Android MobSF/ReDroid runtime are built and verified,
   including the digest-locked patch series and packaged Frida server.
5. PostgreSQL starts, migrations apply, the first administrator and the default Android
   profiles are created.
6. Hardened systemd services, Android worker relays and controller, and the fail-closed
   guest firewall are installed.
7. Windows, C2 and Android executors receive one-time enrollment credentials.
   **No executor receives the PostgreSQL credential.** After disposable-worker cutover the
   legacy host Android executor is disabled to prevent competing claims.
8. Status and harmless runtime acceptance gates verify services, revisions, images,
   Windows evidence handoff, and executor isolation.

A failed prerequisite can be corrected and the command rerun **without deleting state** —
verified checkouts, secrets, databases, images and completed phase markers are preserved.

### 8.2 Services

```bash
systemctl status umat-api umat-scheduler umat-report-worker umat-adapter-worker
```

### 8.3 Deploying the C2 module to an existing CAPE host

The teammate running the analysis host needs three things beyond a clone:

```bash
# 1 · GeoLite2 (not redistributable — download with a MaxMind account)
cp GeoLite2-ASN.mmdb GeoLite2-City.mmdb <module>/data/
#    or export GEOLITE2_ASN_DB / GEOLITE2_CITY_DB

# 2 · Threat-intelligence corpus
python scripts/seed_threatintel.py

# 3 · Dependencies
pip install -r requirements.txt --break-system-packages
```

Paths resolve relative to the module, not the working directory, so the pipeline behaves
identically whether invoked by an operator or spawned by the UMAT executor.

### 8.4 Operational notes

- Keep `isolated_simulated` selected for the qualified malware baseline. Do not enable
  real Internet access for a malware guest.
- `deployment/single-host/compose.yaml` pins PostgreSQL by image digest.
- Samples in `ACTUAL_MALWARE/` and reference PCAPs are gitignored deliberately.

---

## 9. Testing and verification

```bash
# Control plane
cd E-Rakshak-UMAT
uv run ruff check src tests
uv run mypy src/umat
uv run pytest -q
npx playwright test            # console, exports, role restrictions, accessibility
```

PostgreSQL-backed tests require explicit **disposable** `UMAT_TEST_DATABASE_URL` and
`UMAT_MIGRATION_DATABASE_URL` values, and the migration suite exercises downgrade and
re-upgrade. Never point it at a database holding data that must be retained.

```bash
# C2 module — 401 tests across 27 files, all passing
cd windows_c2exfil_module
python -m pytest -q
python pipeline/validate.py    # precision / recall against data/ground_truth.json
```

```bash
# ST/DT host
scripts/validate-deployment.sh --execute
```

---

## 10. Safety boundary

- Malware is executed **only** inside a disposable guest on a network with no route out.
  The validation environment has no public routing element at all.
- Capture runs outside the guest; an evasion-aware sample cannot reach or alter the
  evidence.
- Egress is fail-closed. The Android bridge (`172.30.0.0/24`) is internal-only, and the
  Windows guest sits on an isolated libvirt network (`winstdt-isolated`).
- Analysing a PCAP passively — which is what the C2 module does — is safe on an ordinary
  workstation. You are not executing anything.
- TLS pinning is **reported, never bypassed**. A bypassed pin is an altered run.
- Windows installation media is operator-supplied. This project does not download or
  redistribute it.

---

### Team

Om Nagda · Dhruvil Kundaliya · Mithil Pillai · Raghav Shrivastav
