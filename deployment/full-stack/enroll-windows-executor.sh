#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=""
TOKEN_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-root) PROJECT_ROOT="${2:-}"; shift ;;
    --token-file) TOKEN_FILE="${2:-}"; shift ;;
    *) echo "usage: $0 --project-root PATH --token-file PATH" >&2; exit 2 ;;
  esac
  shift
done
[[ "$PROJECT_ROOT" = /* && -x "$PROJECT_ROOT/.venv/bin/umat-windows-executor" ]] || exit 2
[[ "$TOKEN_FILE" = /* && -r "$TOKEN_FILE" ]] || exit 2

SERVICE_USER="${UMAT_SERVICE_USER:-$(id -un)}"
FULL_ENV="${UMAT_ENV_FILE:-/etc/umat/full-stack.env}"
EXECUTOR_ENV="${UMAT_WINDOWS_EXECUTOR_ENV:-/etc/umat/windows-executor.env}"
token="$(<"$TOKEN_FILE")"
[[ "$token" =~ ^[A-Za-z0-9_-]{32,}$ ]] || { echo "invalid enrollment token" >&2; exit 2; }
gateway_token="$(sudo -n awk -F= '$1 == "UMAT_CAPE_GATEWAY_TOKEN" {print substr($0, index($0, "=") + 1)}' "$FULL_ENV")"
[[ -n "$gateway_token" ]] || { echo "CAPE gateway token is missing" >&2; exit 1; }

permanent="$(mktemp)"
enrollment="$(mktemp)"
trap 'rm -f -- "$permanent" "$enrollment"' EXIT
printf '%s\n' \
  'UMAT_EXECUTOR_URL=http://127.0.0.1:8080' \
  'UMAT_CAPE_URL=http://127.0.0.1:8000' \
  'UMAT_CAPE_MANAGEMENT_URL=http://127.0.0.1:8091' \
  "UMAT_CAPE_MANAGEMENT_TOKEN=$gateway_token" \
  'UMAT_WINDOWS_HANDOFF_ROOT=/srv/winstdt/handoff' \
  'UMAT_WINDOWS_SCHEMA_ROOT=/opt/umat/upstreams/winstdt/schemas' \
  'UMAT_WINDOWS_WORK_ROOT=/var/lib/umat/windows-work' \
  'UMAT_WINDOWS_STATE_PATH=/var/lib/umat/executors/windows/state.json' \
  'UMAT_WINDOWS_EXECUTOR_NAME=windows-executor' >"$permanent"
sudo -n install -o root -g "$(id -gn "$SERVICE_USER")" -m 0640 "$permanent" "$EXECUTOR_ENV"
cp "$permanent" "$enrollment"
printf 'UMAT_WINDOWS_ENROLLMENT_TOKEN=%s\n' "$token" >>"$enrollment"
chmod 0600 "$enrollment"
sudo -n -u "$SERVICE_USER" bash -c \
  'set -a; source "$1"; set +a; exec "$2/.venv/bin/umat-windows-executor" run --enroll-only' \
  bash "$enrollment" "$PROJECT_ROOT"
sudo -n systemctl enable --now umat-windows-executor.service
echo "Windows executor enrolled and started"
