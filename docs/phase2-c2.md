# Phase 2 shared C2 service

Phase 2 adds one shared, platform-tagged C2 path for Windows and Android:

```text
completed platform stage
  -> signed lease-bound artifact download
  -> C2 input builder
  -> pinned isolated runtime
  -> signed immutable C2 bundle (native event schema 1.3)
  -> strict C2 adapter
  -> normalized findings, observations, IOCs, attribution, timeline and provenance
```

Windows consumes PCAP plus optional ETL-derived `access_events`, ETW events, and `static_prior`
artifacts. A Windows static prior is accepted only when its provenance identifies independent
binary-static evidence. Legacy unlabeled Windows priors fail closed. CAPE runtime DNS/HTTP/host
observations never enter this channel, preventing a destination from confirming itself.
Host/network correlation is allowed only when the Windows handoff manifest explicitly enables
it. Android consumes PCAP and run metadata; the builder and adapter both enforce network-only
semantics and reject unsupported host-data claims. MobSF static indicators use the same explicit
provenance contract.

Correlated Windows events retain the complete host-access evidence reference: concrete object name
and path, access operation/API, process identity, PID lineage, and source call ID. Human-readable
findings name the accessed file rather than reducing it to the label `file_access`.

The upstream detector's residual `unclassified_egress` category is normalized to
`network_observation`, with no exfiltration ATT&CK technique. It remains visible for evidentiary
review but is not an exfiltration claim. Specific exfiltration detectors, threat-intelligence
matches, static-prior matches, and host/network correlations retain their supported classifications.

The result bundle contains `manifest.json`, `hashes.sha256`, `network-events.json`,
`exfil-events.json`, attribution, provenance, timeline, notes, IOC files, and signature
material. Validation checks the 1.3 event profile, run/sample/platform identity, executor key
identity, every member digest, and the event evidence chain before persistence.

After a C2 executor completes a stage, normalize the bundle with:

```bash
umat-c2-adapter adapt --run-id ANALYSIS_RUN_UUID
```

Adapter reruns retain immutable prior records but mark only the newest adaptation active.
The `0002_c2_results` migration is reversible to `0001_phase1` without removing shared enum
types.
