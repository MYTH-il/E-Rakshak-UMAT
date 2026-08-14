# Phase 5.5 hardening and runtime gates

Phase 5.5 closes control-plane gaps without pretending that an external malware runtime passed
when its evidence was incomplete.

Implemented and verified:

- PostgreSQL scheduler worker enforcing lease expiry and independent wall-clock stage deadlines.
- Per-stage retry/timeout policy, capability snapshots, platform matching, and C2 schema-v1.3
  capability matching.
- Heartbeat cancellation/timeout stop signals consumed by fake, Windows, Android, and C2
  executors. Final cancellation also cancels queued and waiting dependents.
- Audited CLI controls for roles, account enablement, user-session revocation, and executor
  credential revocation.
- Fresh migration, downgrade/re-upgrade, role-seed, append-only audit, and custody-FK tests.
- Immutable WinST schema worktree at commit `7bc74765e9d38d7ba6df3f2115db67761cb4cbd8`.
- C2 execution pinned to effective runtime `478f131-umat.2` and a verified patch-series digest
  `410bb5568669c559f831c386135628571874802ef57d024a87810ac6e8c9c199`.
  The unchanged schema-v1.3 boundary is the normalized contract reference. The promoted runtime
  applies GeoLite2 country/ASN enrichment to every IP-bearing event, suppresses URL-feed false
  positives for shared hosts, rolls tunnel subdomains into their claimed parent, keeps HTTP
  destination domains correctly typed, and hashes large captures in chunks.
- Android PCAP-only execution through the effective C2 runtime, followed by signed schema-v1.3
  result-bundle verification. The PCAP-only shim cannot load host-access evidence.

Runtime status and gates:

- WinST/CAPE: the ordered UMAT reporter patch series reconciles the locked reporter with its
  locked schema and supplies deployment runtime identity. Harmless CAPE task 23 and public UMAT
  run `019fe74d-9750-7923-abe1-4654ddc1b2ca` passed the native handoff and signed-artifact gates.
  UMAT continues to reject missing, unhashed, duplicate, and incompletely covered artifacts.
- CAPE VM management: the authenticated loopback gateway and native task cancellation are now
  implemented. A harmless real create/customize/snapshot/register/delete round trip passed. The
  gateway and explicitly enrolled Windows executor are installed as isolated systemd services.
- Android dynamic analysis: the locked MobSF static path passes, but API-30's prepared second
  boot remains offline. Partial static output remains the fail-closed behavior.
- Licensing: WinST/DT and the C2 repository have no license file at their locked commits. Their
  source and derived images are excluded from redistributable UMAT releases until authorization
  is recorded.

The UMAT control plane now officially targets PostgreSQL 18.4. The complete suite, migration
downgrade/re-upgrade path, and existing audit chain pass on PostgreSQL 18; no PostgreSQL-16-only
dependency was found. MobSF retains its separately validated PostgreSQL 16 runtime lock. See the
root README for the exact snapshot state and Phase 6 backlog.

The machine-readable status is in `dependency-locks/*.json` and
`dependency-locks/third-party-inventory.json`.
