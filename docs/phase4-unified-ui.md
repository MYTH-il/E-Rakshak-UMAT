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
Android data item was stolen. Validated Android telemetry correlations are shown separately as
weak, temporal associations with an explicit caveat; their wording never claims that packet
contents or item-level theft were proven.

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

Runtime observations, MobSF scan-log entries, and Android application components are expanded into
bounded analyst-readable rows rather than rendered as opaque JSON blobs. Long or adversarial
Unicode component identifiers receive stable readable aliases while the escaped raw identifier
remains available in a disclosure control. The corresponding formatters are isolated ES modules
with focused Node tests, and production rendering continues to use text nodes rather than HTML
injection.

## Current browser scope

The browser now provides case creation/search, recent analyses, repeated runs per case, platform
and network/C2 choices, automated versus manual Windows execution, direct TigerVNC launch while a
Windows run is live, cancellation, run progress, evidence downloads, and paginated/searchable
technical findings, IOCs, destinations, timeline, and access events. Long filenames and paths wrap
without breaking the report layout.

Administrative guest-profile lifecycle, complete worker inventory, and the deepest native CAPE
diagnostics remain API/native-tool operations. The live Windows console intentionally provides no
independent VM power control, host clipboard bridge, or file transfer, and disappears when the
run-scoped capability expires.

## Exports

`POST /api/v1/cases/{case_id}/exports/{json|pdf|csv}` creates a new report-export custody record
and a content-addressed artifact. JSON is role-filtered, PDF is an officer-safe summary, and CSV
contains findings/IOCs with spreadsheet-formula neutralization. Downloads remain attachments with
`nosniff`; their registered digest and format version are retained.
