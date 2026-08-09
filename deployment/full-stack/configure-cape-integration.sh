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
WINSTDT_CHECKOUT="${UMAT_WINSTDT_CHECKOUT:-/opt/umat/upstreams/winstdt}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WINSTDT_PATCH_ROOT="$PROJECT_ROOT/deployment/windows/patches"
API_CONF="$CAPE_ROOT/conf/api.conf"
if [[ ! -f "$API_CONF" ]]; then
  echo "missing CAPE API configuration: $API_CONF" >&2
  exit 1
fi

echo "+ enable CAPE taskstatus and user_stop APIs in $API_CONF"
echo "+ install schema-compatible WinST/DT handoff reporter from locked source and patch"
if [[ "$EXECUTE" -eq 0 ]]; then
  echo "dry-run complete; no CAPE configuration changed"
  exit 0
fi

test -f "$WINSTDT_CHECKOUT/cape/modules/reporting/winstdt_handoff_export.py"
test -f "$WINSTDT_PATCH_ROOT/0001-schema-compatible-correlation.patch"
test -f "$WINSTDT_PATCH_ROOT/0002-deployment-runtime-identity.patch"
python3 - "$PROJECT_ROOT" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
lock = json.loads((root / "dependency-locks/winstdt.json").read_text())
series = lock["deployment_patch_series"]
declared = []
combined = hashlib.sha256()
for entry in series["files"]:
    path = (root / entry["path"]).resolve()
    if root not in path.parents:
        raise SystemExit(f"WinST/DT patch escapes project root: {path}")
    content = path.read_bytes()
    observed = hashlib.sha256(content).hexdigest()
    if observed != entry["sha256"]:
        raise SystemExit(f"WinST/DT patch digest mismatch: {path}")
    declared.append(path)
    combined.update(content)
observed_files = sorted((root / "deployment/windows/patches").glob("*.patch"))
if observed_files != sorted(declared):
    raise SystemExit("WinST/DT patch directory differs from the dependency lock")
if combined.hexdigest() != series["patch_series_sha256"]:
    raise SystemExit("WinST/DT patch-series digest mismatch")
PY
patched_root="$(mktemp -d)"
trap 'rm -rf -- "$patched_root" "${temporary:-}"' EXIT
mkdir -p "$patched_root/cape/modules/reporting" "$patched_root/tests"
cp "$WINSTDT_CHECKOUT/cape/modules/reporting/winstdt_handoff_export.py" \
  "$patched_root/cape/modules/reporting/winstdt_handoff_export.py"
cp "$WINSTDT_CHECKOUT/tests/test_winstdt_handoff_export.py" \
  "$patched_root/tests/test_winstdt_handoff_export.py"
for patch_file in "$WINSTDT_PATCH_ROOT"/*.patch; do
  patch --batch --forward -d "$patched_root" -p1 < "$patch_file"
done
sudo -n install -o cape -g cape -m 0644 \
  "$patched_root/cape/modules/reporting/winstdt_handoff_export.py" \
  "$CAPE_ROOT/modules/reporting/winstdt_handoff_export.py"

cape_ref="$(git -c "safe.directory=$CAPE_ROOT" -C "$CAPE_ROOT" rev-parse HEAD)"
winstdt_ref="$(git -c "safe.directory=$WINSTDT_CHECKOUT" -C "$WINSTDT_CHECKOUT" rev-parse HEAD)"
yara_ref="sha256:$(cd "$CAPE_ROOT/data/yara" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
clamav_ref="$(clamscan --version | head -n1)"
image_version="${UMAT_WINDOWS_IMAGE_VERSION:-hardened-baseline-controlled-egress-v2}"
guest_identity="${UMAT_CAPE_BASE_DOMAIN:-winstdt-win10-22h2}"
guest_ip="${UMAT_CAPE_BASE_GUEST_IP:-10.66.0.101}"
for reporting_config in \
  "$CAPE_ROOT/conf/reporting.conf" \
  "$CAPE_ROOT/custom/conf/reporting.conf.d/winstdt_handoff_export.conf"; do
  runtime_temp="$(mktemp)"
  python3 - "$reporting_config" "$runtime_temp" "$cape_ref" "$winstdt_ref" \
    "$yara_ref" "$clamav_ref" "$image_version" "$guest_identity" "$guest_ip" <<'PY'
import configparser
import os
import sys

source, destination, cape, winstdt, yara, clamav, image, guest_identity, guest_ip = sys.argv[1:]
parser = configparser.ConfigParser(strict=False)
parser.read(source)
section = "winstdt_handoff_export"
if not parser.has_section(section):
    parser.add_section(section)
values = {
    "cape_git_ref": cape,
    "winstdt_guest_agent_version": f"winstdt@{winstdt}",
    "yara_rules_ref": yara,
    "clamav_db_version": clamav,
    "image_version": image,
    "guest_vm_identity": guest_identity,
    "guest_ip": guest_ip,
}
for key, value in values.items():
    parser.set(section, key, value)
with open(destination, "w", encoding="utf-8") as output:
    parser.write(output)
    output.flush()
    os.fsync(output.fileno())
PY
  sudo -n install -o cape -g cape -m 0644 "$runtime_temp" "$reporting_config"
  rm -f -- "$runtime_temp"
done

temporary="$(mktemp)"
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
sudo -n systemctl restart cape-processor.service 2>/dev/null || sudo -n systemctl restart cape-processor
sudo -n systemctl is-active --quiet cape-web.service 2>/dev/null || sudo -n systemctl is-active --quiet cape-web
sudo -n systemctl is-active --quiet cape-processor.service 2>/dev/null || sudo -n systemctl is-active --quiet cape-processor
awk '
  /^\[taskstatus\]/ { section="taskstatus"; next }
  /^\[user_stop\]/ { section="user_stop"; next }
  /^\[/ { section="" }
  section != "" && $1 == "enabled" && $3 == "yes" { enabled[section]=1 }
  END { exit enabled["taskstatus"] && enabled["user_stop"] ? 0 : 1 }
' "$API_CONF"
echo "CAPE integration configured"
