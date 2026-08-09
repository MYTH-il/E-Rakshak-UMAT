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
  --runtime-root /srv/winstdt/libexec/c2-exfil/47225ec-winstdt.1 \
  --runtime-commit 47225ecb439936659e55ffa9118db083bb2f56c2 \
  --runtime-patch-sha256 0d82a65d6ac3d3d829f622b6bb49a8b4a1e66470355bb73ba8cdf8ea70278b57 \
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
