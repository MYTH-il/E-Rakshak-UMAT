#!/usr/bin/env bash
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "seal-worker must run as root" >&2; exit 1; }
systemctl disable --now ssh.service ssh.socket >/dev/null 2>&1 || true
gpasswd --delete umat-worker sudo >/dev/null 2>&1 || true
rm -f /etc/sudoers.d/90-cloud-init-users
passwd --lock umat-worker >/dev/null
rm -rf /home/umat-worker/.ssh
rm -rf /var/lib/umat/android-work/qualification /var/lib/umat/android-work/qualification-2 /var/lib/umat/android-work/qualification-3
cloud-init clean --logs --machine-id
install -m 0600 -o root -g root /dev/null /var/lib/umat-worker-sealed
sync
