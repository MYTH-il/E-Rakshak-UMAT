#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly ASSETS="$PROJECT_ROOT/deployment/android-worker"
readonly STORAGE="/var/lib/libvirt/images/umat-android-worker"
readonly BASE="$STORAGE/noble-server-cloudimg-amd64.img"
readonly DISK="$STORAGE/umat-android-worker-base.qcow2"
readonly SEED="$STORAGE/umat-android-worker-seed.iso"
readonly KEY="$STORAGE/umat-android-worker-ed25519"
readonly DOMAIN="umat-android-worker-base"

[[ -f "$BASE" ]] || { echo "verified Ubuntu cloud image is missing: $BASE" >&2; exit 1; }
sudo -n chown "$(id -un):libvirt-qemu" "$STORAGE"
sudo -n chmod 0710 "$STORAGE"
sudo -n chown "$(id -un):libvirt-qemu" "$BASE"
sudo -n chmod 0640 "$BASE"
if [[ ! -f "$KEY" ]]; then
  ssh-keygen -q -t ed25519 -N '' -C umat-android-worker -f "$KEY"
  chmod 0600 "$KEY"
fi

for network in management malware; do
  name="umat-android-$network"
  if ! virsh net-info "$name" >/dev/null 2>&1; then
    virsh net-define "$ASSETS/$network-network.xml"
  fi
  virsh net-autostart "$name"
  virsh net-start "$name" >/dev/null 2>&1 || true
done

if virsh dominfo "$DOMAIN" >/dev/null 2>&1; then
  echo "$DOMAIN already exists; use reset-worker.sh for disposable run overlays" >&2
  exit 1
fi

qemu-img create -q -f qcow2 -F qcow2 -b "$BASE" "$DISK" 80G
seed_dir="$(mktemp -d)"
trap 'rm -rf -- "$seed_dir"' EXIT
sed "s|SSH_PUBLIC_KEY_PLACEHOLDER|$(<"$KEY.pub")|" "$ASSETS/user-data.template" >"$seed_dir/user-data"
install -m 0644 "$ASSETS/meta-data" "$seed_dir/meta-data"
install -m 0644 "$ASSETS/network-config" "$seed_dir/network-config"
genisoimage -quiet -output "$SEED" -volid cidata -joliet -rock \
  "$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config"
sudo -n chgrp libvirt-qemu "$DISK" "$SEED"
chmod 0640 "$DISK" "$SEED"

virt-install \
  --name "$DOMAIN" \
  --memory 6144 \
  --vcpus 6 \
  --cpu host-passthrough \
  --machine q35 \
  --osinfo ubuntu24.04 \
  --import \
  --disk "path=$DISK,format=qcow2,bus=virtio,cache=none,discard=unmap" \
  --disk "path=$SEED,device=cdrom,readonly=on" \
  --network "network=umat-android-management,model=virtio,mac=52:54:00:67:00:10" \
  --network "network=umat-android-malware,model=virtio,mac=52:54:00:68:00:10" \
  --network "network=default,model=virtio,mac=52:54:00:69:00:10" \
  --graphics none \
  --console pty,target_type=serial \
  --rng /dev/urandom \
  --noautoconsole

echo "Worker booted. Wait for: ssh -i $KEY umat-worker@10.67.0.10 cloud-init status --wait"
