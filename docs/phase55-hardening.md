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
- C2 execution pinned to effective runtime `47225ec-winstdt.1` and patch digest
  `0d82a65d6ac3d3d829f622b6bb49a8b4a1e66470355bb73ba8cdf8ea70278b57`.
  The newer repository schema v1.3 is used only as the normalized contract reference.
- Android PCAP-only execution through the effective C2 runtime, followed by signed schema-v1.3
  result-bundle verification. The PCAP-only shim cannot load host-access evidence.

Runtime status and gates:

- WinST/CAPE: installed CAPE is at the locked commit, but no existing handoff both validates
  against the locked schema and contains its declared, hash-covered PCAP. UMAT now rejects
  missing, unhashed, duplicate, and incompletely covered native artifacts.
- CAPE VM management: the authenticated loopback gateway and native task cancellation are now
  implemented. A harmless real create/customize/snapshot/register/delete round trip passed. The
  gateway systemd unit is not yet promoted on the current workstation because the PostgreSQL 16
  migration and full UMAT service installation remain incomplete.
- Android dynamic analysis: the locked MobSF static path passes, but API-30's prepared second
  boot remains offline. Partial static output remains the fail-closed behavior.
- Licensing: WinST/DT and the C2 repository have no license file at their locked commits. Their
  source and derived images are excluded from redistributable UMAT releases until authorization
  is recorded.

Deployment promotion remains closed while the earlier PostgreSQL 18 cluster owns port `55432`.
The pinned PostgreSQL 16 restore is in progress with recoverable, root-only backups; failed
cross-version restore attempts returned the host to PostgreSQL 18 without losing application
records. See the root README for the exact snapshot state and Phase 6 backlog.

The machine-readable status is in `dependency-locks/*.json` and
`dependency-locks/third-party-inventory.json`.
