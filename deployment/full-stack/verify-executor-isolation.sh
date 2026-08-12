#!/usr/bin/env bash
set -euo pipefail

executor_user="${UMAT_EXECUTOR_USER:-umat-executor}"
api_url="${UMAT_API_URL:-http://127.0.0.1:8080/health/live}"
postgres_host="${UMAT_POSTGRES_HOST:-127.0.0.1}"
postgres_port="${UMAT_POSTGRES_PORT:-55432}"

id "$executor_user" >/dev/null
sudo -n -u "$executor_user" curl --fail --silent --show-error --max-time 5 "$api_url" >/dev/null
if sudo -n -u "$executor_user" timeout 3 bash -c \
  "exec 3<>/dev/tcp/$postgres_host/$postgres_port" 2>/dev/null; then
  echo "FAIL: executor identity can reach PostgreSQL" >&2
  exit 1
fi
echo "PASS: executor reaches API and cannot reach PostgreSQL"
