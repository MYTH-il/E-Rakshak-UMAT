#!/usr/bin/env bash
set -euo pipefail

readonly STORAGE="/var/lib/libvirt/images/umat-android-worker"
readonly GOLDEN="$STORAGE/umat-android-worker-golden.qcow2"
readonly OVERLAY="$STORAGE/umat-android-worker-run.qcow2"
readonly DOMAIN="umat-android-worker"

inject_egress_configuration() {
  local broker_token payload command request response pid
  broker_token="$(awk -F= '$1 == "UMAT_EGRESS_BROKER_TOKEN" {print substr($0, index($0, "=") + 1)}' /etc/umat/egress-broker.env)"
  [[ ${#broker_token} -ge 32 ]] || { echo "egress broker token is missing" >&2; return 1; }
  payload="$(printf '%s\n' \
    'UMAT_EGRESS_BROKER_URL=http://10.67.0.1:8092' \
    "UMAT_EGRESS_BROKER_TOKEN=$broker_token" \
    'UMAT_ANDROID_EGRESS_GUEST_IP=10.68.0.10' | base64 -w0)"
  command="if systemctl is-active --quiet umat-worker-executor.service; then exit 42; fi; sed -i '/^UMAT_EGRESS_BROKER_/d;/^UMAT_ANDROID_EGRESS_GUEST_IP=/d' /etc/umat/android-executor.env; printf %s '$payload' | base64 -d >> /etc/umat/android-executor.env; ip route replace default via 10.68.0.1 dev malware0"
  request="$(COMMAND="$command" python3 - <<'PY'
import json
import os
print(json.dumps({
    "execute": "guest-exec",
    "arguments": {
        "path": "/bin/sh",
        "arg": ["-c", os.environ["COMMAND"]],
        "capture-output": True,
    },
}))
PY
)"
  response="$(virsh qemu-agent-command "$DOMAIN" "$request")"
  pid="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["return"]["pid"])' <<<"$response")"
  for _ in $(seq 1 60); do
    response="$(virsh qemu-agent-command "$DOMAIN" \
      "{\"execute\":\"guest-exec-status\",\"arguments\":{\"pid\":$pid}}")"
    if grep -q '"exited":true' <<<"$response"; then
      grep -q '"exitcode":0' <<<"$response" || {
        echo "failed to inject the disposable worker egress configuration" >&2
        return 1
      }
      return 0
    fi
    sleep 1
  done
  echo "timed out injecting the disposable worker egress configuration" >&2
  return 1
}

[[ -f "$GOLDEN" ]] || { echo "sealed golden worker image is missing" >&2; exit 1; }
if virsh dominfo "$DOMAIN" >/dev/null 2>&1; then
  virsh destroy "$DOMAIN" >/dev/null 2>&1 || true
  virsh undefine "$DOMAIN" --nvram >/dev/null 2>&1 || virsh undefine "$DOMAIN"
fi
if [[ -e "$OVERLAY" ]]; then
  rm -f -- "$OVERLAY"
fi
qemu-img create -q -f qcow2 -F qcow2 -b "$GOLDEN" "$OVERLAY"
if [[ "$(id -u)" -eq 0 ]]; then
  chgrp libvirt-qemu "$OVERLAY"
else
  sudo -n chgrp libvirt-qemu "$OVERLAY"
fi
chmod 0640 "$OVERLAY"
virt-install \
  --name "$DOMAIN" --memory 6144 --vcpus 6 --cpu host-passthrough --machine q35 \
  --osinfo ubuntu24.04 \
  --import --disk "path=$OVERLAY,format=qcow2,bus=virtio,cache=none,discard=unmap" \
  --network "network=umat-android-management,model=virtio,mac=52:54:00:67:00:10" \
  --network "network=umat-android-malware,model=virtio,mac=52:54:00:68:00:10" \
  --graphics none --console pty,target_type=serial --rng /dev/urandom --noautoconsole

for _ in $(seq 1 90); do
  if virsh qemu-agent-command "$DOMAIN" '{"execute":"guest-ping"}' >/dev/null 2>&1; then
    inject_egress_configuration
    exit 0
  fi
  sleep 1
done
echo "disposable Android worker guest agent did not become ready" >&2
exit 1
