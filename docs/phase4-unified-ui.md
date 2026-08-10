# Phase 4 unified API and UI

Phase 4 adds the case aggregator, verdict policy, immutable report snapshots, role-filtered case
responses, integrity-registered JSON/PDF/CSV exports, and the primary UMAT analysis console.

## Processes

Apply migrations, then run the API and report worker in separate terminals:

```bash
uv run alembic upgrade head
```

```bash
uv run umat-api
```

```bash
uv run umat-report-worker run
```

The report worker uses PostgreSQL row locking to discover runs whose required adaptations are
complete. C2 is independently selectable: C2-enabled runs require both platform and C2 adaptation;
C2-disabled runs require only platform adaptation. It creates an immutable aggregate snapshot,
completes report generation, and makes the run terminal. `--once` processes at most one queued
aggregation/report stage for tests and operational scripts.

## Verdict policy

The aggregator consumes normalized database records only. Confirmed configured malware/C2 or
exfiltration indicators yield `malicious`; non-allowlisted weak-or-strong findings yield
`suspicious`; clean, complete mandatory telemetry yields `no_malicious_activity_observed`.
Missing mandatory evidence or material caveats yield `inconclusive`, and failure before a valid
platform import yields `failed`. The product never emits a `safe` verdict.

Android network-only C2 evidence is restricted to network observations. The aggregator removes
data-item attribution and rewrites causal provenance so a PCAP-only result cannot claim that an
Android data item was stolen.

## Role views

- Officers receive L1 verdict, capabilities, destinations, caveats, provenance, tested profile,
  safe artifacts, and exports.
- Analysts and administrators additionally receive normalized findings, IOCs, unified timeline,
  attribution, tool/adaptation versions, and authorized technical evidence.
- Artifact authorization is rechecked at download time and every successful or rejected attempt
  is audited.

The browser application communicates only with `/api/v1`. It never calls CAPE, MobSF, C2, or the
executor API. The application uses no CDN or frontend package runtime: HTML, CSS, and JavaScript
are bundled with UMAT, and attacker-controlled report values are inserted as text nodes.

The visual language is a clean-room adaptation of the pinned Android static-analysis interface
(dark panels with violet/teal hierarchy), not copied Django/AdminLTE source. This avoids coupling
UMAT to MobSF templates and avoids importing GPL-3.0-only frontend code while UMAT's distribution
license remains undecided.

## Current browser scope

The browser is an implemented foundation, not yet the complete operator console. The backend and
workers can run CAPE end to end even where the UI cannot currently express or diagnose the
operation. Pending UI work includes case management and search, a recent-analysis list, multiple
analyses per case, a complete new-analysis dialog for all platform/profile/network/C2 variations,
available-worker inventory, guest-profile lists, platform-specific Windows and Android profile
creation/retirement menus, and complete RBAC-aware navigation/actions. Native-task progress,
post-processing state, retries, cancellation, evidence, and error diagnostics also need a fuller
presentation. Until then, use `/api/v1` and native CAPE diagnostics for capabilities absent from
the browser.

## Exports

`POST /api/v1/cases/{case_id}/exports/{json|pdf|csv}` creates a new report-export custody record
and a content-addressed artifact. JSON is role-filtered, PDF is an officer-safe summary, and CSV
contains findings/IOCs with spreadsheet-formula neutralization. Downloads remain attachments with
`nosniff`; their registered digest and format version are retained.
