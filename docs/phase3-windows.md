# Phase 3 Windows platform integration

Phase 3 connects the control plane to the pinned WinST/DT and CAPE runtime. The executor:

1. Claims only Windows platform stages and downloads the sample through a signed lease-bound
   attachment endpoint.
2. Normalizes the original object for CAPE without changing UMAT custody. Signature-first format
   detection distinguishes LNK, ZIP, EXE and DLL inputs (including files with misleading archive
   overlays), assigns the corresponding CAPE package, and uses a safe canonical submission name.
3. Records the native CAPE task ID immediately and recovers it after restart without another
   submission.
4. Polls CAPE while renewing its lease.
5. Validates the handoff, access-event, and sample-metadata schemas and locked digests.
6. Seals the untouched handoff in a signed UMAT Windows bundle.
7. Builds an independently sourced static prior from CAPE configuration-extractor output and
   endpoint strings recovered from the submitted binary, dropped files, process dumps, and CAPE
   payloads. Runtime DNS, HTTP, and destination observations are deliberately excluded so traffic
   cannot corroborate itself. Each prior indicator records its source and `binary_static`
   provenance. Signatures and ATT&CK technique/sub-technique mappings remain available as platform
   evidence rather than being misrepresented as network IOCs.
8. Completes the platform stage. The run either queues shared offline C2 analysis or proceeds
   directly to platform adaptation according to its independent `c2_analysis_enabled` policy.

Administrators create and delete Windows VM profiles through
`/api/v1/windows/profiles`. Operations are queued to the Windows executor and delegated to the
CAPE-owned machine-management gateway. Profiles define CPU, RAM, disk, Windows version, user
profile, installed software, CAPE template, and one of the pinned analysis profiles. Only active
profiles can be selected by users. Every run stores an immutable snapshot, and deletion removes
the CAPE machine while retaining the profile record for custody and reproducibility.

For a manual run, CAPE receives `nohuman=1` so its automated mouse/keyboard stimulation does not
compete with the analyst. Once the task and capture are active, UMAT exposes a run-scoped action
that launches the task-owned, loopback-only display in TigerVNC. The capability exists only during
the 10-minute detonation window. Expiry or explicit completion closes VNC, finalizes CAPE, revokes
the egress lease, collects evidence, and continues adaptation, optional C2 analysis, aggregation,
and reporting. Automated runs use the same minimum observation window but retain CAPE stimulation.

The adapter validates the complete bundle again, binds it to the run, sample, executor key, CAPE
task and selected profile, then imports CAPE signatures, CAPE ATT&CK mappings, YARA/static findings, host-access
capabilities, IOCs, telemetry state and Windows metadata. CAPE's large native report is reduced to
a bounded evidence document while also retaining the immutable native CAPE report as an analyst
artifact. Normalized access events preserve the API, operation, object filename and complete path,
process/PID/parent PID, process path, and source call ID. Both `FileName` and handle-resolved
`HandleName` arguments are supported, including `NtReadFile` events. Re-adaptation supersedes prior
active rows without deleting them. The
adapter works whether C2 is enabled or skipped and never discards platform findings merely because
C2 evidence is absent.

Run it after the Windows platform stage and, when selected, the C2 stage complete:

```bash
umat-windows-adapter adapt --run-id ANALYSIS_RUN_UUID
```

The CAPE workload has completed real automated and manual runs end to end through UMAT reporting.
CAPE's minimum ten-minute timeout is the detonation interval; guest setup and dump/Vivisect/YARA/signature
post-processing extend wall-clock time. The backend path is operational, although the current UMAT
UI does not yet expose every profile, worker, and native diagnostic control.

Real detonation requires the pinned CAPE/WinST deployment and controlled malware network. Unit
and PostgreSQL integration tests use harmless fixtures and never execute uploaded files.

The deployment applies the ordered, digest-locked reporter patches under
`deployment/windows/patches/`. They make the upstream reporter conform to its own locked handoff
schema and populate producer, guest, image, rule, and tool identity from deployment configuration.
The executor waits for atomic handoff publication after CAPE reaches a terminal native state and
fails malformed or incomplete native evidence without retrying the already-recorded CAPE task.

The clean-host installer delegates baseline VM construction and snapshot sealing to the locked
WinST/DT scripts. UMAT does not replace VMCloak or CAPE's native machine lifecycle. Dynamically
cloned selectable profiles remain guarded by the same evidence and snapshot checks. Profiles can
enlarge but cannot shrink the approved baseline virtual disk; a smaller disk requires rebuilding
the licensed baseline from the Windows ISO.
