#!/usr/bin/env bash
set -euo pipefail

readonly COMMIT="478f131de510ad580754f152d946086b3aeacf05"
readonly TREE_SHA256="792c340721cc75dfc9b43a5bba4908be22071b75bd99f2871e9bd85d52407c28"
readonly EFFECTIVE_VERSION="478f131-umat.1"
readonly DEPENDENCY_LOCK_SHA256="18d8e1acfd170b8f8c321aa3737b465ea4f19d28bcefd9534f5b6becb6e1ea6d"
readonly EMPTY_PATCH_SERIES_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
observed_dependency="$(sha256sum "$DEPENDENCY_LOCK" | awk '{print $1}')"
[[ "$observed_dependency" == "$DEPENDENCY_LOCK_SHA256" ]] || {
  echo "C2 dependency lock digest mismatch" >&2
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

sudo python3 -m venv "$stage/.venv"
sudo "$stage/.venv/bin/pip" install --disable-pip-version-check --require-hashes \
  -r "$DEPENDENCY_LOCK"
result="$(mktemp)"
(cd "$stage/source" && sudo "$stage/.venv/bin/pytest" -q) | tee "$result"
grep -Eq '334 passed, 15 skipped' "$result" || {
  echo "unexpected C2 upstream test result" >&2
  exit 1
}
rm -f "$result"
# Upstream tests initialize this ignored runtime database. Runtime source must
# remain byte-identical to the pinned archive; each analysis gets a workspace copy.
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
    "patch_series_sha256": "$EMPTY_PATCH_SERIES_SHA256",
    "effective_tree_sha256": "$TREE_SHA256",
    "dependency_lock_sha256": "$DEPENDENCY_LOCK_SHA256",
    "validated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "upstream_tests_collected": 349,
    "upstream_tests_passed": 334,
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
