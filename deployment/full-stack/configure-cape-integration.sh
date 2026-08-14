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
CAPE_GUEST_RETRY_PATCH="$PROJECT_ROOT/deployment/full-stack/patches/cape-guest-analyzer-retry.patch"
API_CONF="$CAPE_ROOT/conf/api.conf"
if [[ ! -f "$API_CONF" ]]; then
  echo "missing CAPE API configuration: $API_CONF" >&2
  exit 1
fi

echo "+ enable CAPE taskstatus and user_stop APIs in $API_CONF"
echo "+ install schema-compatible WinST/DT handoff reporter from locked source and patch"
echo "+ install bounded CAPE guest analyzer-extraction retry for snapshot restore races"
echo "+ make CAPE's bundled 7zz archive extractor executable"
if [[ "$EXECUTE" -eq 0 ]]; then
  echo "dry-run complete; no CAPE configuration changed"
  exit 0
fi

test -f "$WINSTDT_CHECKOUT/cape/modules/reporting/winstdt_handoff_export.py"
test -f "$WINSTDT_PATCH_ROOT/0001-schema-compatible-correlation.patch"
test -f "$WINSTDT_PATCH_ROOT/0002-deployment-runtime-identity.patch"
test -f "$CAPE_GUEST_RETRY_PATCH"
test -f "$CAPE_ROOT/data/7zz"
sudo -n chmod 0755 "$CAPE_ROOT/data/7zz"
python3 - "$PROJECT_ROOT" "$CAPE_GUEST_RETRY_PATCH" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
cape_patch = Path(sys.argv[2]).resolve()
manifest = json.loads((root / "deployment/full-stack/manifest.json").read_text())
declared_cape_patch = manifest["components"]["cape"]["integration_patch"]
expected_cape_patch = (root / declared_cape_patch["path"]).resolve()
if cape_patch != expected_cape_patch or root not in cape_patch.parents:
    raise SystemExit(f"CAPE integration patch path mismatch: {cape_patch}")
if hashlib.sha256(cape_patch.read_bytes()).hexdigest() != declared_cape_patch["sha256"]:
    raise SystemExit(f"CAPE integration patch digest mismatch: {cape_patch}")

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
cape_patch_root="$(mktemp -d)"
trap 'rm -rf -- "$patched_root" "$cape_patch_root" "${temporary:-}" "${source_temp:-}" "${runtime_temp:-}"' EXIT
mkdir -p "$patched_root/cape/modules/reporting" "$patched_root/tests" \
  "$patched_root/winstdt" "$patched_root/schemas"
git -C "$WINSTDT_CHECKOUT" show HEAD:cape/modules/reporting/winstdt_handoff_export.py > \
  "$patched_root/cape/modules/reporting/winstdt_handoff_export.py"
git -C "$WINSTDT_CHECKOUT" show HEAD:tests/test_winstdt_handoff_export.py > \
  "$patched_root/tests/test_winstdt_handoff_export.py"
git -C "$WINSTDT_CHECKOUT" show HEAD:winstdt/access_events.py > \
  "$patched_root/winstdt/access_events.py"
git -C "$WINSTDT_CHECKOUT" show HEAD:schemas/access_events.schema.json > \
  "$patched_root/schemas/access_events.schema.json"
git -C "$WINSTDT_CHECKOUT" show HEAD:schemas/handoff_manifest.schema.json > \
  "$patched_root/schemas/handoff_manifest.schema.json"
for patch_file in "$WINSTDT_PATCH_ROOT"/*.patch; do
  patch --batch --forward -d "$patched_root" -p1 < "$patch_file"
done
sudo -n install -o cape -g cape -m 0644 \
  "$patched_root/cape/modules/reporting/winstdt_handoff_export.py" \
  "$CAPE_ROOT/modules/reporting/winstdt_handoff_export.py"
mkdir -p "$cape_patch_root/lib/cuckoo/core"
cp "$CAPE_ROOT/lib/cuckoo/core/guest.py" "$cape_patch_root/lib/cuckoo/core/guest.py"
if ! grep -Fq "Transient CAPE Agent analyzer extraction failed" \
  "$cape_patch_root/lib/cuckoo/core/guest.py"; then
  patch --batch --forward -d "$cape_patch_root" -p1 < "$CAPE_GUEST_RETRY_PATCH"
fi
python3 -m py_compile "$cape_patch_root/lib/cuckoo/core/guest.py"
sudo -n install -o cape -g cape -m 0644 "$cape_patch_root/lib/cuckoo/core/guest.py" \
  "$CAPE_ROOT/lib/cuckoo/core/guest.py"
sudo -n install -o root -g root -m 0644 "$patched_root/winstdt/access_events.py" \
  "$CAPE_ROOT/winstdt/access_events.py"
sudo -n install -o "$(stat -c %U "$WINSTDT_CHECKOUT/schemas")" \
  -g "$(stat -c %G "$WINSTDT_CHECKOUT/schemas")" -m 0644 \
  "$patched_root/schemas/access_events.schema.json" \
  "$WINSTDT_CHECKOUT/schemas/access_events.schema.json"
sudo -n install -o "$(stat -c %U "$WINSTDT_CHECKOUT/schemas")" \
  -g "$(stat -c %G "$WINSTDT_CHECKOUT/schemas")" -m 0644 \
  "$patched_root/schemas/handoff_manifest.schema.json" \
  "$WINSTDT_CHECKOUT/schemas/handoff_manifest.schema.json"

cape_ref="$(git -c "safe.directory=$CAPE_ROOT" -C "$CAPE_ROOT" rev-parse HEAD)"
winstdt_ref="$(git -c "safe.directory=$WINSTDT_CHECKOUT" -C "$WINSTDT_CHECKOUT" rev-parse HEAD)"
yara_ref="sha256:$(cd "$CAPE_ROOT/data/yara" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | awk '{print $1}')"
clamav_ref="$(clamscan --version | head -n1)"
image_version="${UMAT_WINDOWS_IMAGE_VERSION:-hardened-baseline-controlled-egress-v2}"
guest_identity="${UMAT_CAPE_BASE_DOMAIN:-winstdt-win10-22h2}"
guest_ip="${UMAT_CAPE_BASE_GUEST_IP:-10.66.0.101}"
sudo -n test -s "$CAPE_ROOT/conf/reporting.conf" || {
  echo "refusing to replace missing or empty CAPE reporting configuration" >&2
  exit 1
}
sudo -n install -d -o cape -g cape -m 0755 \
  "$CAPE_ROOT/custom/conf/reporting.conf.d"
for reporting_config in \
  "$CAPE_ROOT/conf/reporting.conf" \
  "$CAPE_ROOT/custom/conf/reporting.conf.d/winstdt_handoff_export.conf"; do
  source_temp="$(mktemp)"
  runtime_temp="$(mktemp)"
  require_existing=0
  if [[ "$reporting_config" == "$CAPE_ROOT/conf/reporting.conf" ]]; then
    require_existing=1
  fi
  if sudo -n test -f "$reporting_config"; then
    sudo -n cat "$reporting_config" >"$source_temp"
  fi
  python3 - "$source_temp" "$runtime_temp" "$require_existing" "$cape_ref" "$winstdt_ref" \
    "$yara_ref" "$clamav_ref" "$image_version" "$guest_identity" "$guest_ip" <<'PY'
import configparser
import os
import sys

source, destination, required, cape, winstdt, yara, clamav, image, guest_identity, guest_ip = sys.argv[1:]
parser = configparser.ConfigParser(strict=False, interpolation=None)
parser.optionxform = str
loaded = parser.read(source)
if required == "1" and (not loaded or not parser.sections()):
    raise SystemExit("refusing to replace an unreadable, empty, or invalid reporting.conf")
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
verification = configparser.ConfigParser(strict=False, interpolation=None)
verification.optionxform = str
if not verification.read(destination) or not verification.has_section(section):
    raise SystemExit("generated CAPE reporting configuration did not validate")
for key, expected in values.items():
    if verification.get(section, key, fallback="") != expected:
        raise SystemExit(f"generated CAPE reporting configuration lost {key}")
PY
  if sudo -n test -e "$reporting_config" && ! sudo -n test -e "$reporting_config.umat-before"; then
    sudo -n cp --preserve=mode,ownership "$reporting_config" \
      "$reporting_config.umat-before"
  fi
  sudo -n install -o cape -g cape -m 0644 "$runtime_temp" "$reporting_config"
  sudo -n test -s "$reporting_config"
  rm -f -- "$source_temp" "$runtime_temp"
done

echo "+ qualify CAPE AgentTesla parser with a bounded decoded-string fixture"
sudo -n -u cape /etc/poetry/bin/poetry -C "$CAPE_ROOT" run python - <<'PY'
from cape_parsers.CAPE.community.AgentTesla import extract_config

# Exercise only the parser boundary with inert, synthetic configuration-shaped
# strings. This proves parser discovery and structured extraction without ever
# executing or embedding a malware sample in deployment qualification.
lines = [
    "fixture-prefix",
    "Mozilla/5.0",
    "587",
    "mail.example.test",
    "sender@example.test",
    "fixture-password",
    "recipient@example.test",
    *[f"fixture-padding-{index}" for index in range(32)],
]
result = extract_config("\n".join(lines).encode())
if not isinstance(result, dict):
    raise SystemExit("CAPE AgentTesla parser returned no structured result")
expected = {
    "Protocol": "SMTP",
    "Port": "587",
    "C2": "mail.example.test",
    "Username": "sender@example.test",
}
for key, value in expected.items():
    if result.get(key) != value:
        raise SystemExit(f"CAPE AgentTesla parser qualification failed for {key}")
print("CAPE AgentTesla parser qualification passed")
PY

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
sudo -n systemctl restart cape.service 2>/dev/null || sudo -n systemctl restart cape
sudo -n systemctl is-active --quiet cape-web.service 2>/dev/null || sudo -n systemctl is-active --quiet cape-web
sudo -n systemctl is-active --quiet cape-processor.service 2>/dev/null || sudo -n systemctl is-active --quiet cape-processor
sudo -n systemctl is-active --quiet cape.service 2>/dev/null || sudo -n systemctl is-active --quiet cape
awk '
  /^\[taskstatus\]/ { section="taskstatus"; next }
  /^\[user_stop\]/ { section="user_stop"; next }
  /^\[/ { section="" }
  section != "" && $1 == "enabled" && $3 == "yes" { enabled[section]=1 }
  END { exit enabled["taskstatus"] && enabled["user_stop"] ? 0 : 1 }
' "$API_CONF"
echo "CAPE integration configured"
