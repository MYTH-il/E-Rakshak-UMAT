#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="bf1f275be8027e0adf5b2e049ad2c9a556526398"
readonly TREE_SHA256="e70b39cd2c57d0e1abf1d47974535e479878b14bb0649826547f7f17964e272e"
readonly EFFECTIVE_VERSION="bf1f275-umat.2"
readonly EFFECTIVE_TREE_SHA256="b0f5341f5adee036e41d5dcd408b5371ff3a827a8f268689a561bd68cba68510"
readonly DEPENDENCY_LOCK_SHA256="18d8e1acfd170b8f8c321aa3737b465ea4f19d28bcefd9534f5b6becb6e1ea6d"
readonly PATCH_SERIES_SHA256="973f3a15d2a200f8bcc9b71465b818d97be1f43fd8ddc41e3613c2758f0f4741"
readonly THREATFOX_ARCHIVE_SHA256="95b27f9b34af50baf05d6c256c571fcb57164b3b378b92d6365e36951c9bb361"
readonly THREATFOX_FEED_SHA256="3360b7e1089d0438bba9c49e2839b0f722c5fcde8e33fa6188d8dca7f7faae61"
readonly THREATINTEL_MIN_INDICATORS=40000
readonly THREATINTEL_QUALIFIED_INDICATORS=47832
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly PATCH_DIR="$PROJECT_ROOT/deployment/c2/patches"
readonly THREATFOX_ARCHIVE="$PROJECT_ROOT/deployment/c2/feeds/threatfox.zip"
readonly CHECKOUT="${UMAT_C2_CHECKOUT:-/opt/umat/upstreams/c2-exfil}"
readonly WINSTDT_CHECKOUT="${UMAT_WINSTDT_CHECKOUT:-/opt/umat/upstreams/winstdt}"
readonly RUNTIME_ROOT="${UMAT_C2_RUNTIME_PARENT:-/srv/winstdt/libexec/c2-exfil}"
readonly DEPENDENCY_LOCK="$WINSTDT_CHECKOUT/config/c2-exfil-requirements.lock.txt"
EXECUTE=0

if [[ "${1:-}" == "--execute" ]]; then
  EXECUTE=1
elif [[ $# -ne 0 ]]; then
  echo "usage: $0 [--execute]" >&2
  exit 2
fi

[[ -d "$CHECKOUT/.git" ]] || { echo "C2 checkout is unavailable: $CHECKOUT" >&2; exit 1; }
observed_commit="$(git -c safe.directory="$CHECKOUT" -C "$CHECKOUT" rev-parse HEAD)"
[[ "$observed_commit" == "$COMMIT" ]] || {
  echo "C2 revision mismatch: expected=$COMMIT observed=$observed_commit" >&2
  exit 1
}
[[ -f "$DEPENDENCY_LOCK" ]] || { echo "C2 dependency lock is unavailable" >&2; exit 1; }
[[ -f "$THREATFOX_ARCHIVE" ]] || { echo "C2 ThreatFox archive is unavailable" >&2; exit 1; }
observed_dependency="$(sha256sum "$DEPENDENCY_LOCK" | awk '{print $1}')"
[[ "$observed_dependency" == "$DEPENDENCY_LOCK_SHA256" ]] || {
  echo "C2 dependency lock digest mismatch" >&2
  exit 1
}
observed_archive="$(sha256sum "$THREATFOX_ARCHIVE" | awk '{print $1}')"
[[ "$observed_archive" == "$THREATFOX_ARCHIVE_SHA256" ]] || {
  echo "C2 ThreatFox archive digest mismatch" >&2
  exit 1
}
mapfile -t patch_files < <(find "$PATCH_DIR" -maxdepth 1 -type f -name '*.patch' -print | sort)
observed_patch="$(for patch_file in "${patch_files[@]}"; do cat "$patch_file"; done | sha256sum | awk '{print $1}')"
[[ "$observed_patch" == "$PATCH_SERIES_SHA256" ]] || {
  echo "C2 deployment patch digest mismatch" >&2
  exit 1
}

echo "+ install C2 runtime $EFFECTIVE_VERSION from $COMMIT"
if [[ "$EXECUTE" -eq 0 ]]; then
  echo "dry-run complete; no C2 runtime changes made"
  exit 0
fi

target="$RUNTIME_ROOT/$EFFECTIVE_VERSION"
if sudo test -d "$target"; then
  echo "verified C2 runtime already exists: $target"
  exit 0
fi

sudo install -d -m 0755 "$RUNTIME_ROOT"
stage="$(sudo mktemp -d "$RUNTIME_ROOT/.${EFFECTIVE_VERSION}.XXXXXX")"
cleanup() { sudo test ! -d "$stage" || sudo mv "$stage" "$stage.failed"; }
trap cleanup EXIT
sudo chmod 0755 "$stage"
sudo install -d -m 0755 "$stage/source"
git -c safe.directory="$CHECKOUT" -C "$CHECKOUT" archive "$COMMIT" | sudo tar -x -C "$stage/source"
observed_tree="$(sudo "$PROJECT_ROOT/.venv/bin/python" - "$stage/source" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
lines = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or "__pycache__" in path.parts or ".pytest_cache" in path.parts:
        continue
    lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n")
print(hashlib.sha256("".join(lines).encode()).hexdigest())
PY
)"
[[ "$observed_tree" == "$TREE_SHA256" ]] || { echo "C2 source tree digest mismatch" >&2; exit 1; }
for patch_file in "${patch_files[@]}"; do
  sudo patch --batch --forward -d "$stage/source" -p1 < "$patch_file"
done
sudo "$PROJECT_ROOT/.venv/bin/python" - "$THREATFOX_ARCHIVE" \
  "$stage/source/data/feeds/threatfox.csv" <<'PY'
import sys
from pathlib import Path
from zipfile import ZipFile

archive_path, output_path = map(Path, sys.argv[1:])
with ZipFile(archive_path) as archive:
    if archive.namelist() != ["threatfox.csv"]:
        raise SystemExit("ThreatFox archive must contain exactly threatfox.csv")
    Path(output_path).write_bytes(archive.read("threatfox.csv"))
PY
sudo chmod 0644 "$stage/source/data/feeds/threatfox.csv"
observed_threatfox="$(sudo sha256sum "$stage/source/data/feeds/threatfox.csv" | awk '{print $1}')"
[[ "$observed_threatfox" == "$THREATFOX_FEED_SHA256" ]] || {
  echo "ThreatFox feed digest mismatch" >&2
  exit 1
}
observed_effective_tree="$(sudo "$PROJECT_ROOT/.venv/bin/python" - "$stage/source" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
lines = []
for path in sorted(root.rglob("*")):
    if not path.is_file() or "__pycache__" in path.parts or ".pytest_cache" in path.parts:
        continue
    lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n")
print(hashlib.sha256("".join(lines).encode()).hexdigest())
PY
)"
[[ "$observed_effective_tree" == "$EFFECTIVE_TREE_SHA256" ]] || {
  echo "C2 effective source tree digest mismatch" >&2
  exit 1
}

sudo python3 -m venv "$stage/.venv"
sudo "$stage/.venv/bin/pip" install --disable-pip-version-check --require-hashes \
  -r "$DEPENDENCY_LOCK"
result="$(mktemp)"
(cd "$stage/source" && sudo "$stage/.venv/bin/python" -m pytest -q) | tee "$result"
grep -Eq '345 passed, 15 skipped' "$result" || {
  echo "unexpected C2 upstream test result" >&2
  exit 1
}
rm -f "$result"
# Upstream tests initialize this ignored runtime database. The promoted source
# must retain the verified effective-tree identity; each analysis gets a workspace copy.
sudo rm -f "$stage/source/data/threatintel.sqlite"

manifest="$(mktemp)"
"$PROJECT_ROOT/.venv/bin/python" - "$manifest" <<PY
import json
from datetime import datetime, timezone
from pathlib import Path

Path("$manifest").write_text(json.dumps({
    "schema_version": "1.0",
    "upstream_commit": "$COMMIT",
    "effective_version": "$EFFECTIVE_VERSION",
    "upstream_tree_sha256": "$TREE_SHA256",
    "patch_series_sha256": "$PATCH_SERIES_SHA256",
    "effective_tree_sha256": "$EFFECTIVE_TREE_SHA256",
    "dependency_lock_sha256": "$DEPENDENCY_LOCK_SHA256",
    "threat_intelligence": {
        "feed": "data/feeds/threatfox.csv",
        "deployment_asset": "deployment/c2/feeds/threatfox.zip",
        "asset_sha256": "$THREATFOX_ARCHIVE_SHA256",
        "feed_sha256": "$THREATFOX_FEED_SHA256",
        "minimum_indicators": $THREATINTEL_MIN_INDICATORS,
        "qualified_indicators": $THREATINTEL_QUALIFIED_INDICATORS,
        "database_path": "/srv/winstdt/c2-data/threatintel.sqlite",
        "network_scope": "non_compromised_botnet_cc",
        "payload_hashes": ["md5", "sha1", "sha256"],
    },
    "validated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "upstream_tests_collected": 360,
    "upstream_tests_passed": 345,
    "upstream_tests_skipped": 15,
    "upstream_tests_deselected_missing_corpus": 0,
}, indent=2) + "\n")
PY
sudo install -m 0644 "$manifest" "$stage/runtime-manifest.json"
rm -f "$manifest"
sudo chown -R root:root "$stage"
sudo chmod -R a-w "$stage/source" "$stage/.venv"
sudo mv "$stage" "$target"
trap - EXIT
echo "promoted $target"
