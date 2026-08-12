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

Windows tasks have a CAPE-enforced minimum observation window of 900 seconds. For explicitly manual
runs, CAPE receives `nohuman=1`; once CAPE reports the task running, the executor requests a console
capability from the loopback management gateway.
The gateway independently verifies that the CAPE task owns the running libvirt domain before it
relays VNC. The authenticated run action validates the session again and launches TigerVNC on the
local analyst desktop. The browser receives neither a VNC address nor a gateway credential.

The console supports display, mouse, and keyboard only. Clipboard and file transfer are not enabled.
The finish API changes the live session to finalizing; the signed executor
then asks CAPE to finish the native task so CAPE can perform its ordinary dump, artifact, reporting,
shutdown, and snapshot-restoration sequence. Cancellation remains a separate UMAT run operation.

Before qualifying a deployment, run a harmless Windows acceptance sample and verify all of the
following on the real CAPE host:

1. CAPE receives `timeout=900` and `enforce_timeout=true`.
2. `virsh domdisplay <machine> --type vnc` reports only `127.0.0.1` and an auto-assigned port.
3. The Windows workflow becomes ready only after the CAPE task is running and its database task
   record names that same machine.
4. Browser keyboard and mouse input reaches the guest, while browser/guest clipboard and file
   transfer remain unavailable.
5. A second user without analyst or administrator role cannot open the console WebSocket.
6. “Finish and collect evidence” closes the console, produces the normal CAPE/WinST-DT handoff,
   and does not mark the UMAT run cancelled.
7. Natural timeout, cancellation, executor lease loss, and CAPE failure all revoke console access.
8. The libvirt domain shuts down and the next run starts from the clean CAPE snapshot.
