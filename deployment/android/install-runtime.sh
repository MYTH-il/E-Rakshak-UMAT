#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
ACCEPT_LICENSES=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --accept-sdk-licenses) ACCEPT_LICENSES=1 ;;
    *) echo "usage: $0 [--execute] [--accept-sdk-licenses]" >&2; exit 2 ;;
  esac
  shift
done

readonly SDK_ROOT="${ANDROID_SDK_ROOT:-/usr/lib/android-sdk}"
readonly EMULATOR_ROOT="${ANDROID_EMULATOR_ROOT:-/opt/android-sdk-34/emulator}"
readonly EXPECTED_EMULATOR="34.1.19"
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REDROID_IMAGE="docker.io/redroid/redroid@sha256:d1ca0815eb68139a43d25a835e374559e9d18f5d5cea1a4288d4657c0074fb8d"
packages=(
  platform-tools platforms\;android-30
  system-images\;android-30\;default\;x86_64
)
command -v sdkmanager >/dev/null
echo "+ sdkmanager --sdk_root=$SDK_ROOT ${packages[*]}"
if [[ "$EXECUTE" -eq 0 ]]; then
  echo 'dry-run complete; Android SDK unchanged'
  exit 0
fi
[[ "$ACCEPT_LICENSES" -eq 1 ]] || {
  echo 'Android SDK installation requires --accept-sdk-licenses' >&2
  exit 2
}
printf 'y\n%.0s' {1..100} | sudo -n sdkmanager --sdk_root="$SDK_ROOT" --licenses >/dev/null
sudo -n sdkmanager --sdk_root="$SDK_ROOT" "${packages[@]}"
observed="$($EMULATOR_ROOT/emulator -version 2>&1 | sed -n 's/^Android emulator version \([^ ]*\).*/\1/p' | head -n1)"
# Google's repository may render the same release with a trailing patch
# component (for example 34.1.19.0).  Compare the canonicalized value while
# retaining the precise observed version in diagnostics.
canonical_observed="${observed%.0}"
[[ "$canonical_observed" == "$EXPECTED_EMULATOR" ]] || {
  echo "Android emulator lock mismatch: expected=$EXPECTED_EMULATOR observed=${observed:-unknown}" >&2
  exit 1
}
test -x "$SDK_ROOT/platform-tools/adb"
test -d "$SDK_ROOT/system-images/android-30/default/x86_64"
sudo -n install -m 0644 "$PROJECT_ROOT/deployment/android/umat-redroid.modules-load.conf" /etc/modules-load.d/umat-redroid.conf
sudo -n install -d -m 0755 /dev/binderfs
sudo -n install -m 0644 "$PROJECT_ROOT/deployment/android/umat-redroid-binder.mount" /etc/systemd/system/dev-binderfs.mount
sudo -n systemctl daemon-reload
sudo -n systemctl enable --now dev-binderfs.mount
sudo -n docker pull --platform linux/amd64 "$REDROID_IMAGE"
observed_arch="$(sudo -n docker image inspect "$REDROID_IMAGE" --format '{{.Architecture}}')"
[[ "$observed_arch" == "amd64" ]] || { echo "ReDroid image is not amd64: $observed_arch" >&2; exit 1; }
echo "Android API-30 AOSP emulator and pinned ReDroid amd64 runtime installed and verified"
