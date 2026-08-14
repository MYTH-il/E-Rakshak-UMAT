#!/usr/bin/env bash
set -euo pipefail

project_root="${1:-}"
[[ "$project_root" == /* && -x "$project_root/.venv/bin/umat" ]] || {
  echo "usage: $0 /absolute/path/to/UMAT" >&2
  exit 2
}
env_file="${UMAT_ENV_FILE:-/etc/umat/full-stack.env}"
[[ -r "$env_file" ]] || { echo "run as root so $env_file is readable" >&2; exit 2; }
set -a
# shellcheck disable=SC1090 -- operator-selected root-owned environment file
source "$env_file"
set +a

units=(umat-api umat-scheduler umat-report-worker umat-adapter-worker umat-cape-gateway umat-egress-broker)
for unit in "${units[@]}"; do
  systemctl is-active --quiet "$unit.service"
done
test -x /usr/bin/tcpdump
test -s /usr/share/publicsuffix/effective_tld_names.dat
systemctl show --property=ExecStartPre --value umat-egress-broker.service | grep -q '/usr/bin/test -x /usr/bin/tcpdump'
curl --fail --silent --show-error http://127.0.0.1:8080/health/ready >/dev/null
curl --fail --silent --show-error http://127.0.0.1:8080/metrics | grep -q umat_process_uptime_seconds
"$project_root/.venv/bin/umat" admin verify-audit
"$project_root/deployment/full-stack/verify-executor-isolation.sh"
systemd-analyze security umat-api.service --no-pager >/dev/null
sudo -n nft list table inet umat_host >/dev/null
echo "PASS: Phase 6 service, health, metrics, audit, and isolation gates"
