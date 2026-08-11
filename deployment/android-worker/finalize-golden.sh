#!/usr/bin/env bash
set -euo pipefail

readonly STORAGE="/var/lib/libvirt/images/umat-android-worker"
readonly DOMAIN="umat-android-worker-base"
readonly DISK="$STORAGE/umat-android-worker-base.qcow2"
readonly GOLDEN="$STORAGE/umat-android-worker-golden.qcow2"
readonly KEY="$STORAGE/umat-android-worker-ed25519"

[[ -f "$DISK" ]] || { echo "worker base disk is missing" >&2; exit 1; }
ssh -i "$KEY" umat-worker@10.67.0.10 'sudo /opt/umat/deployment/android-worker/seal-worker.sh' || true
virsh shutdown "$DOMAIN" >/dev/null
for _ in $(seq 1 60); do
  [[ "$(virsh domstate "$DOMAIN" 2>/dev/null)" == "shut off" ]] && break
  sleep 2
done
[[ "$(virsh domstate "$DOMAIN")" == "shut off" ]] || { echo "worker did not power off" >&2; exit 1; }
virsh undefine "$DOMAIN" --nvram >/dev/null 2>&1 || virsh undefine "$DOMAIN"
sudo -n chown "$(id -un):libvirt-qemu" "$DISK"
chmod 0640 "$DISK"
qemu-img check "$DISK"
if [[ -e "$GOLDEN" ]]; then
  mv "$GOLDEN" "$GOLDEN.previous.$(date +%s)"
fi
mv "$DISK" "$GOLDEN"
sudo -n chown "$(id -un):libvirt-qemu" "$GOLDEN"
chmod 0640 "$GOLDEN"
echo "Sealed golden image: $GOLDEN"
