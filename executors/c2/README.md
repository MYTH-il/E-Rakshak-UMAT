# Shared C2 executor

`umat-c2-executor` is a standalone HTTP client. It has no database imports or PostgreSQL
credential and accepts only `c2_analysis` leases.

The platform executor must register completed artifacts named `pcap` and
`platform_manifest`. Windows may additionally register `access_events` and `static_prior`.
Android input is forcibly network-only even if an access-events artifact is present.

Create the one-time scoped enrollment token:

```bash
umat-admin enroll-executor --created-by admin --executor-type c2 \
  --stage-type c2_analysis
```

Run against an authorized external checkout pinned to the dependency lock:

```bash
umat-c2-executor run \
  --runtime-root /srv/winstdt/libexec/c2-exfil/bc5bb681-umat.1 \
  --runtime-commit bc5bb681495a02fa0ff2411087e5a00ece5b1ca3 \
  --runtime-patch-sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
  --enrollment-token TOKEN
```

The executor verifies the checkout commit, creates a unique directory per analysis run,
removes database configuration from the child environment, renews its lease, validates and
signs the schema-v1.3 result bundle, and uploads it as `c2_bundle`. The newer C2 repository
schema is a normalization reference and does not replace this validated effective runtime.
`--fixture-runtime` is only for
deterministic development and integration testing.

The upstream repository has no documented redistribution license in the current dependency
lock. Do not vendor its source or publish a derived image until authorization is recorded.
