#!/usr/bin/env bash
set -euo pipefail

EXECUTE=0
PROJECT_ROOT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute) EXECUTE=1 ;;
    --project-root) PROJECT_ROOT="${2:-}"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
if [[ "$PROJECT_ROOT" != /* || ! -f "$PROJECT_ROOT/pyproject.toml" ]]; then
  echo "--project-root must be an absolute UMAT checkout" >&2
  exit 2
fi

SERVICE_USER="${UMAT_SERVICE_USER:-$(id -un)}"
ENV_FILE="${UMAT_ENV_FILE:-/etc/umat/full-stack.env}"
UNIT_DIR="/etc/systemd/system"
declare -A COMMANDS
COMMANDS[umat-api]="umat-api"
COMMANDS[umat-scheduler]="umat-scheduler run"
COMMANDS[umat-report-worker]="umat-report-worker run"
COMMANDS[umat-adapter-worker]="umat-adapter-worker run"

for name in "${!COMMANDS[@]}"; do
  unit="$(mktemp)"
  cat >"$unit" <<EOF
[Unit]
Description=UMAT ${name#umat-}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$PROJECT_ROOT
EnvironmentFile=$ENV_FILE
ExecStart=$PROJECT_ROOT/.venv/bin/${COMMANDS[$name]}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/umat $PROJECT_ROOT/var

[Install]
WantedBy=multi-user.target
EOF
  echo "+ install $UNIT_DIR/$name.service"
  if [[ "$EXECUTE" -eq 1 ]]; then
    sudo -n install -m 0644 "$unit" "$UNIT_DIR/$name.service"
  fi
  rm -f -- "$unit"
done

gateway_unit="$(mktemp)"
cat >"$gateway_unit" <<EOF
[Unit]
Description=UMAT CAPE profile-management gateway
After=network-online.target libvirtd.service cape.service
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_ROOT
EnvironmentFile=$ENV_FILE
ExecStart=$PROJECT_ROOT/.venv/bin/umat-cape-gateway
Restart=on-failure
RestartSec=3
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/opt/CAPEv2/conf /var/lib/libvirt/images/winstdt /var/lib/umat-cape-profiles

[Install]
WantedBy=multi-user.target
EOF
echo "+ install $UNIT_DIR/umat-cape-gateway.service"
if [[ "$EXECUTE" -eq 1 ]]; then
  sudo -n install -m 0644 "$gateway_unit" "$UNIT_DIR/umat-cape-gateway.service"
fi
rm -f -- "$gateway_unit"

if [[ "$EXECUTE" -eq 1 ]]; then
  sudo -n install -d -m 0750 -o "$SERVICE_USER" -g "$(id -gn "$SERVICE_USER")" \
    /var/lib/umat /var/lib/umat/quarantine /var/lib/umat/artifacts
  sudo -n install -d -m 0700 -o root -g root /var/lib/umat-cape-profiles
  mkdir -p "$PROJECT_ROOT/var"
  sudo -n systemctl daemon-reload
  sudo -n systemctl enable --now umat-api umat-scheduler umat-report-worker umat-adapter-worker umat-cape-gateway
else
  echo "dry-run complete; no services changed"
fi
