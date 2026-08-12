# Phase 6 operations

## Backup, restore, and rollback

Run backups from a maintenance window after stopping intake and executors. The backup is staged,
validated with `pg_restore --list`, inventories every artifact by SHA-256, checks the identity of
content-addressed objects, and is atomically published.

```bash
sudo -u <control-user> /path/to/.venv/bin/umat-ops backup create \
  --destination /var/lib/umat-backups
umat-ops backup verify /var/lib/umat-backups/<backup-id>
```

Keep backups on encrypted storage separate from the analysis host. Copy `manifest.json` and its
digest to the evidence register. A restore requires both `--execute` and the exact backup ID. It
first captures the live database and artifacts as a paired rollback set.

```bash
umat-ops backup restore /var/lib/umat-backups/<backup-id> \
  --confirm-backup-id <backup-id> --execute
umat-ops backup rollback /var/lib/umat/.artifacts.rollback-<backup-id> \
  --confirm-restore-id <backup-id> --execute
```

Perform and record a restore/rollback drill quarterly. Never delete the rollback set until the
restored service passes readiness, audit-chain verification, artifact downloads, and a test case.

## Offline inputs

An offline bundle contains `pyproject.toml`, `uv.lock`, and a populated package/image/source cache.
Seal it on the connected staging host; this makes inputs read-only, writes the complete inventory,
and prints its digest. Transport the resulting manifest SHA-256 over a separate trusted channel:

```bash
umat-ops offline seal /mnt/umat-stage
umat-ops offline verify /mnt/umat-stage --manifest-sha256 <trusted-sha256>
UV_NO_INDEX=1 UV_OFFLINE=1 UV_CACHE_DIR=/mnt/umat-stage/uv-cache uv sync --frozen --offline
```

Verification rejects missing, extra, modified, writable, and symbolic-link inputs. Image archives
must be loaded locally and compared with the digests pinned in
`deployment/full-stack/manifest.json` before services start.

## Monitoring and incident response

The API emits one JSON `http_request_completed` event per request with request ID, method, path,
status, and duration. Journald collects service stdout. Scrape `http://127.0.0.1:8080/metrics`
locally; the supplied reverse-proxy configuration blocks external metrics access. Alert on API
readiness failure, service restart, executor heartbeat age, expired leases, low disk space,
available memory below 4 GiB, repeated partial/failed runs, and backup verification failure.

For failures, preserve journals and the case audit export before intervention. Expired leases are
recovered by the scheduler; restart only the affected executor after its backend task is inspected.
CAPE or MobSF recovery must reset the disposable guest before retry. C2 startup failures must be
fixed at its enrichment/runtime preflight rather than bypassed. Storage integrity failures stop
intake until backup comparison completes.

Controlled egress remains bounded to one GiB per run, HTTP(S)/brokered DNS, and the nftables rate
limits. Windows startup and CAPE processing routinely exceed 100 MiB, so lowering the byte ceiling
below observed clean-profile traffic causes intentional fail-closed lease rejection and retries.

## TLS, firewall, and service isolation

`umat-nginx.conf` is a TLS-only reverse-proxy baseline. Install operator-managed certificates,
set `UMAT_ENVIRONMENT=production`, `UMAT_SECURE_COOKIES=true`, and the public hostname in
`UMAT_ALLOWED_HOSTS`. The API remains bound to loopback.

Review the management CIDR in `umat-host-firewall.nft` before loading it; the example deliberately
is not enabled automatically because an incorrect CIDR can lock out the operator. Executors run as
`umat-executor`; the host output rule denies that identity access to PostgreSQL. Run
`verify-executor-isolation.sh` after every firewall or unit change. Units apply memory/task limits,
and one service instance per dynamic backend is the global concurrency ceiling.

## Retention and evidence deletion

Evidence retention is case-policy driven, not an unattended age-based filesystem job. Place a case
on legal hold in the evidence register when applicable. Before approved deletion: stop intake,
create and verify a backup, export the signed audit chain and report, obtain two-person approval,
identify all content-addressed references, record the deletion authorization in the audit trail,
then remove content and verify no remaining case references it. Database records and signed audit
events are retained as tombstones. Quarantine `.part` files are non-evidence and are cleaned on API
startup. Automated destructive case retention is intentionally absent until the product has a
first-class legal-hold model; direct filesystem age deletion is unsupported.

## Acceptance and upgrades

Run `phase6-acceptance.sh /absolute/project/path` after deployment. An upgrade requires a verified
backup, verified offline inputs, migration review, a recorded runtime manifest, and a rollback
window. Roll back application code and database/artifacts as one versioned unit. Signing keys stay
offline or in an operator-controlled HSM; record custody, rotation, revocation, and recovery events.

Separated hosts are a future topology: place the API/database/storage on the control host and each
dynamic backend on its own worker network. Permit workers only to the TLS API and management
systems; never route PostgreSQL, artifact filesystem, or signing keys to workers.
