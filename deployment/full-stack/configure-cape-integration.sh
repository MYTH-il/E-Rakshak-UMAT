#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
if [[ "${1:-}" == "--execute" ]]; then
  EXECUTE=1
elif [[ $# -gt 0 ]]; then
  echo "usage: $0 [--execute]" >&2
  exit 2
fi

CAPE_ROOT="${UMAT_CAPE_ROOT:-/opt/CAPEv2}"
API_CONF="$CAPE_ROOT/conf/api.conf"
if [[ ! -f "$API_CONF" ]]; then
  echo "missing CAPE API configuration: $API_CONF" >&2
  exit 1
fi

echo "+ enable CAPE taskstatus and user_stop APIs in $API_CONF"
if [[ "$EXECUTE" -eq 0 ]]; then
  echo "dry-run complete; no CAPE configuration changed"
  exit 0
fi

temporary="$(mktemp)"
trap 'rm -f -- "$temporary"' EXIT
python3 - "$API_CONF" "$temporary" <<'PY'
import configparser
import os
import sys

source, destination = sys.argv[1:]
parser = configparser.ConfigParser(strict=False)
parser.read(source)
for section in ("taskstatus", "user_stop"):
    if not parser.has_section(section):
        parser.add_section(section)
    parser.set(section, "enabled", "yes")
with open(destination, "w", encoding="utf-8") as output:
    parser.write(output)
    output.flush()
    os.fsync(output.fileno())
PY
if ! sudo -n test -e "$API_CONF.umat-before"; then
  sudo -n cp --preserve=mode,ownership "$API_CONF" "$API_CONF.umat-before"
fi
sudo -n install -o cape -g cape -m 0644 "$temporary" "$API_CONF"
sudo -n systemctl restart cape-web.service 2>/dev/null || sudo -n systemctl restart cape-web
sudo -n systemctl is-active --quiet cape-web.service 2>/dev/null || sudo -n systemctl is-active --quiet cape-web
awk '
  /^\[taskstatus\]/ { section="taskstatus"; next }
  /^\[user_stop\]/ { section="user_stop"; next }
  /^\[/ { section="" }
  section != "" && $1 == "enabled" && $3 == "yes" { enabled[section]=1 }
  END { exit enabled["taskstatus"] && enabled["user_stop"] ? 0 : 1 }
' "$API_CONF"
echo "CAPE integration configured"
