#!/usr/bin/env bash
set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly DOMAIN="umat-android-worker"
failures=0
window_started="$(date +%s)"
booted_at="$window_started"

while true; do
  state="$(virsh domstate "$DOMAIN" 2>/dev/null || true)"
  if [[ "$state" == "running" || "$state" == "paused" || "$state" == "in shutdown" ]]; then
    sleep 5
    continue
  fi
  now="$(date +%s)"
  if (( now - booted_at >= 120 )); then
    failures=0
    window_started="$now"
  fi
  if (( now - window_started > 600 )); then
    failures=0
    window_started="$now"
  fi
  failures=$((failures + 1))
  if (( failures > 3 )); then
    echo "Android worker stopped more than three times in ten minutes; refusing reset loop" >&2
    exit 1
  fi
  "$PROJECT_ROOT/deployment/android-worker/reset-worker.sh"
  booted_at="$(date +%s)"
  sleep 10
done
