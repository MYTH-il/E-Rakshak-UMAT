# UMAT integration contract

UMAT owns orchestration identifiers, custody, storage, authorization and aggregation.
Platform and C2 modules remain immutable, separately pinned producers. Executors may only
communicate with UMAT through the internal HTTP API and never receive database credentials.

All envelopes use UUIDv7 identifiers, lowercase SHA-256 strings and RFC 3339 UTC timestamps.
The submitted sample digest is always `sample_sha256`; PCAP and bundle digests are distinct.
Bundle imports fail closed on an unsupported major schema version, identity mismatch, hash
mismatch or invalid Ed25519 signature.

Native contracts remain owned by their producing repositories. UMAT verifies WinST/DT handoff,
access-event and sample metadata against the exact schemas and digests recorded in
`native-contract-sources.json`. The Android repository exposes MobSF v1 report APIs rather than a
JSON Schema, so UMAT preserves those responses byte-for-byte and validates its own Android bundle
envelope. C2 events use the upstream 1.3 SQL/event shape with a stricter UMAT profile requiring
`case_id`, `finding_kind`, `plain_language`, and `evidence_refs`; `case_id` equals
`analysis_run_id` at this boundary.

Windows imports wrap the authoritative WinST/DT handoff manifest. Android bundles are owned by
the UMAT Android executor. Both produce a platform bundle before shared C2 processing. The C2
runtime is identical across platforms and operates in a unique working directory per run.

Android v1 C2 output is network-only and cannot assert item-level theft. Windows correlation is
eligible only when normalized access events and acceptable clock-quality evidence are present.
