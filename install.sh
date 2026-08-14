#!/usr/bin/env bash
set -euo pipefail

# Clean-host entry point. The Python deployment CLI remains the resumable
# orchestrator after this small, auditable bootstrap installs its prerequisites.
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly UV_VERSION="0.12.3"
EXECUTE=0
FORWARD=()

usage() {
  cat <<'EOF'
Usage: ./install.sh [--execute] --windows-iso PATH [umat-deploy options]

Without --execute this prints the clean-host plan and changes nothing. On an
Ubuntu 24.04 x86_64 host, --execute installs only bootstrap packages, pins uv,
then hands control to the resumable UMAT installer. A licensed Windows ISO and
explicit authorization flags are still required by the selected components.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute)
      EXECUTE=1
      FORWARD+=("--execute")
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      FORWARD+=("$1")
      ;;
  esac
  shift
done

bootstrap_packages=(
  ca-certificates curl git patch publicsuffix python3.12 python3.12-venv tcpdump
  docker.io docker-compose-v2 libvirt-daemon-system libvirt-clients
  qemu-kvm qemu-utils tar adb android-sdk openjdk-17-jre-headless socat
)

printf '+ sudo apt-get update\n'
printf '+ sudo apt-get install -y'
printf ' %q' "${bootstrap_packages[@]}"
printf '\n'
printf '+ install pinned uv %s in /opt/umat/bootstrap/uv-%s\n' "$UV_VERSION" "$UV_VERSION"
printf '+ uv sync --frozen --extra test\n'
printf '+ uv run umat-deploy install'
printf ' %q' "${FORWARD[@]}"
printf '\n'

if [[ "$EXECUTE" -eq 0 ]]; then
  echo 'dry-run complete; no host changes made'
  exit 0
fi

[[ "$(id -u)" -ne 0 ]] || {
  echo 'run the installer as a normal sudo-capable operator, not root' >&2
  exit 2
}
grep -q '^ID=ubuntu$' /etc/os-release
grep -q '^VERSION_ID="24.04"$' /etc/os-release
[[ "$(uname -m)" == "x86_64" ]]
sudo -n true
sudo -n apt-get update
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y "${bootstrap_packages[@]}"
sudo -n usermod -aG docker,kvm,libvirt "$(id -un)"
sudo -n systemctl enable --now docker.service libvirtd.service

if ! command -v uv >/dev/null 2>&1 || [[ "$(uv --version | awk '{print $2}')" != "$UV_VERSION" ]]; then
  sudo -n install -d -m 0755 /opt/umat/bootstrap
  uv_root="/opt/umat/bootstrap/uv-$UV_VERSION"
  if [[ ! -x "$uv_root/bin/uv" ]]; then
    sudo -n python3.12 -m venv "$uv_root"
    sudo -n "$uv_root/bin/pip" install --disable-pip-version-check --require-hashes \
      -r "$PROJECT_ROOT/dependency-locks/installer-requirements.txt"
  fi
  sudo -n ln -sfn "$uv_root/bin/uv" /usr/local/bin/uv
  UV_BIN=/usr/local/bin/uv
else
  UV_BIN="$(command -v uv)"
fi

cd "$PROJECT_ROOT"
"$UV_BIN" sync --frozen --extra test
exec "$UV_BIN" run umat-deploy install "${FORWARD[@]}"
