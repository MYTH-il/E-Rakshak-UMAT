# Fake executor

The fake executor is a standalone HTTP client and deliberately does not import UMAT database
code. Create a scoped enrollment token, then run it against the API:

```bash
umat-admin enroll-executor --created-by admin --executor-type fake \
  --stage-type platform_analysis --stage-type c2_analysis \
  --stage-type platform_adaptation --stage-type c2_adaptation \
  --stage-type case_aggregation --stage-type report_generation
umat-fake-executor run --enrollment-token TOKEN
```

Use `--mode fail`, `--mode timeout`, or `--mode crash-after-native` to exercise recovery.

