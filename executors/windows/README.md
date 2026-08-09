# Windows/CAPE executor

`umat-windows-executor` is a database-free executor scoped to Windows
`platform_analysis`. It submits samples only through CAPE, records the CAPE task ID before
polling, recovers that ID after a lease expiry or restart, and consumes the immutable WinST/DT
handoff at `/srv/winstdt/handoff/{task_id}`.

```bash
umat-admin enroll-executor --created-by admin --executor-type windows \
  --stage-type platform_analysis

umat-windows-executor run \
  --cape-url http://127.0.0.1:8001 \
  --cape-management-url http://127.0.0.1:8091 \
  --cape-management-token "$UMAT_CAPE_GATEWAY_TOKEN" \
  --handoff-root /srv/winstdt/handoff \
  --schema-root /opt/authorized/WinST-DT-module/schemas \
  --enrollment-token TOKEN
```

The schema directory must be from WinST/DT commit
`7bc74765e9d38d7ba6df3f2115db67761cb4cbd8`; each authoritative schema is checked against its
locked SHA-256 before use.

VM lifecycle operations are also processed by this executor. CAPE itself does not expose a
portable VM-construction API, so the deployment provides the CAPE-host management gateway
at `127.0.0.1:8091`. That gateway is responsible for CAPE/VMCloak/libvirt creation and
deletion. UMAT never invokes a hypervisor directly.

Task cancellation uses CAPE's authenticated `POST /apiv2/tasks/status/{task_id}/` finish
operation and waits until CAPE reports a non-active state. The executor acknowledges cancellation
to UMAT only after CAPE has accepted and completed that transition.
