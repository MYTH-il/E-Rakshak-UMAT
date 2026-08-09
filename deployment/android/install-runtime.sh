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
readonly EXPECTED_EMULATOR="37.1.11"
packages=(
  platform-tools emulator platforms\;android-30
  system-images\;android-30\;google_apis\;x86_64
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
observed="$($SDK_ROOT/emulator/emulator -version 2>&1 | sed -n 's/^Android emulator version \([^ ]*\).*/\1/p' | head -n1)"
[[ "$observed" == "$EXPECTED_EMULATOR" ]] || {
  echo "Android emulator lock mismatch: expected=$EXPECTED_EMULATOR observed=${observed:-unknown}" >&2
  exit 1
}
test -x "$SDK_ROOT/platform-tools/adb"
test -d "$SDK_ROOT/system-images/android-30/google_apis/x86_64"
echo "Android API-30 runtime installed and verified (emulator $observed)"
