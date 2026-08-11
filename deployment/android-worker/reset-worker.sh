#!/usr/bin/env bash
set -euo pipefail

readonly STORAGE="/var/lib/libvirt/images/umat-android-worker"
readonly GOLDEN="$STORAGE/umat-android-worker-golden.qcow2"
readonly OVERLAY="$STORAGE/umat-android-worker-run.qcow2"
readonly DOMAIN="umat-android-worker"

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
