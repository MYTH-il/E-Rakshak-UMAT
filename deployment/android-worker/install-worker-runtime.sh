#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT_ROOT="/opt/umat"
[[ "$(id -u)" -eq 0 ]] || { echo "worker runtime installer must run as root" >&2; exit 1; }
install -d -m 0755 /dev/binderfs /etc/umat
install -m 0644 "$PROJECT_ROOT/deployment/android/umat-redroid.modules-load.conf" /etc/modules-load.d/umat-redroid.conf
install -m 0644 "$PROJECT_ROOT/deployment/android/umat-redroid-binder.mount" /etc/systemd/system/dev-binderfs.mount
install -m 0644 "$PROJECT_ROOT/deployment/android-worker/umat-worker-mobsf.service" /etc/systemd/system/umat-worker-mobsf.service
install -m 0644 "$PROJECT_ROOT/deployment/android-worker/umat-worker-executor.service" /etc/systemd/system/umat-worker-executor.service
install -d -m 0700 -o umat-worker -g umat-worker \
  /var/lib/umat/android-work /var/lib/umat/executors/android
systemctl daemon-reload
systemctl enable --now dev-binderfs.mount
systemctl enable umat-worker-mobsf.service umat-worker-executor.service
