# Phase 3 Windows platform integration

Phase 3 connects the control plane to the pinned WinST/DT and CAPE runtime. The executor:

1. Claims only Windows platform stages and downloads the sample through a signed lease-bound
   attachment endpoint.
2. Submits it to CAPE using the immutable selected VM/profile snapshot.
3. Records the native CAPE task ID immediately and recovers it after restart without another
   submission.
4. Polls CAPE while renewing its lease.
5. Validates the handoff, access-event, and sample-metadata schemas and locked digests.
6. Seals the untouched handoff in a signed UMAT Windows bundle.
7. Registers the PCAP, manifest, normalized access events, static prior, and raw ETL with
   appropriate analyst access.
8. Completes the platform stage, which queues shared C2 analysis.

Administrators create and delete Windows VM profiles through
`/api/v1/windows/profiles`. Operations are queued to the Windows executor and delegated to the
CAPE-owned machine-management gateway. Profiles define CPU, RAM, disk, Windows version, user
profile, installed software, CAPE template, and one of the pinned analysis profiles. Only active
profiles can be selected by users. Every run stores an immutable snapshot, and deletion removes
the CAPE machine while retaining the profile record for custody and reproducibility.

The adapter validates the complete bundle again, binds it to the run, sample, executor key, CAPE
task and selected profile, then imports CAPE signatures, YARA/static findings, host-access
capabilities, IOCs, telemetry state and Windows metadata. Re-adaptation supersedes prior active
rows without deleting them.

Run it after the Windows and C2 stages complete:

```bash
umat-windows-adapter adapt --run-id ANALYSIS_RUN_UUID
```

Real detonation requires the pinned CAPE/WinST deployment and controlled malware network. Unit
and PostgreSQL integration tests use harmless fixtures and never execute uploaded files.

