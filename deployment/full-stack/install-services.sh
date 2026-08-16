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
EXECUTOR_USER="${UMAT_EXECUTOR_USER:-umat-executor}"
ENV_FILE="${UMAT_ENV_FILE:-/etc/umat/full-stack.env}"
UNIT_DIR="/etc/systemd/system"
if [[ "$EXECUTE" -eq 1 ]] && ! id "$EXECUTOR_USER" >/dev/null 2>&1; then
  sudo -n useradd --system --home-dir /var/lib/umat/executors --shell /usr/sbin/nologin "$EXECUTOR_USER"
fi
if [[ "$EXECUTE" -eq 1 ]]; then
  sudo -n usermod -aG "$(id -gn "$SERVICE_USER")" "$EXECUTOR_USER"
fi
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
OOMPolicy=stop
MemoryHigh=1G
MemoryMax=2G
TasksMax=512
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
OOMPolicy=stop
MemoryHigh=2G
MemoryMax=4G
TasksMax=1024
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ReadWritePaths=/opt/CAPEv2/conf /var/lib/libvirt/images/winstdt /var/lib/umat-cape-profiles

[Install]
WantedBy=multi-user.target
EOF
echo "+ install $UNIT_DIR/umat-cape-gateway.service"
if [[ "$EXECUTE" -eq 1 ]]; then
  sudo -n install -m 0600 "$PROJECT_ROOT/deployment/full-stack/umat-host-firewall.nft" /etc/umat/umat-host-firewall.nft
  sudo -n install -m 0644 "$PROJECT_ROOT/deployment/full-stack/umat-nginx.conf" /etc/umat/umat-nginx.conf.example
  sudo -n install -m 0644 "$gateway_unit" "$UNIT_DIR/umat-cape-gateway.service"
fi
rm -f -- "$gateway_unit"

umat_launcher="$(mktemp)"
cat >"$umat_launcher" <<EOF
#!/usr/bin/env sh
exec "$PROJECT_ROOT/.venv/bin/umat" "\$@"
EOF
echo "+ install /usr/local/bin/umat"
if [[ "$EXECUTE" -eq 1 ]]; then
  sudo -n install -m 0755 "$umat_launcher" /usr/local/bin/umat
fi
rm -f -- "$umat_launcher"

windows_unit="$(mktemp)"
cat >"$windows_unit" <<EOF
[Unit]
Description=UMAT Windows/CAPE executor
After=network-online.target cape.service umat-api.service umat-cape-gateway.service
Wants=network-online.target

[Service]
Type=simple
User=$EXECUTOR_USER
WorkingDirectory=$PROJECT_ROOT
EnvironmentFile=/etc/umat/windows-executor.env
ExecStart=$PROJECT_ROOT/.venv/bin/umat-windows-executor run
Restart=on-failure
RestartSec=3
OOMPolicy=stop
MemoryHigh=6G
MemoryMax=8G
TasksMax=2048
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadOnlyPaths=/srv/winstdt/handoff /opt/umat/upstreams/winstdt/schemas
InaccessiblePaths=/etc/umat/full-stack.env -$PROJECT_ROOT/.env /var/lib/umat/artifacts /var/lib/umat/quarantine -/var/lib/umat-backups
ReadWritePaths=/var/lib/umat/executors/windows /var/lib/umat/windows-work

[Install]
WantedBy=multi-user.target
EOF
echo "+ install $UNIT_DIR/umat-windows-executor.service (enrollment required before enablement)"
if [[ "$EXECUTE" -eq 1 ]]; then
  sudo -n install -m 0644 "$windows_unit" "$UNIT_DIR/umat-windows-executor.service"
fi
rm -f -- "$windows_unit"

for executor_name in c2 android; do
  executor_unit="$(mktemp)"
  cat >"$executor_unit" <<EOF
[Unit]
Description=UMAT ${executor_name^^} executor
After=network-online.target umat-api.service docker.service
Wants=network-online.target

[Service]
Type=simple
User=$EXECUTOR_USER
WorkingDirectory=$PROJECT_ROOT
EnvironmentFile=/etc/umat/${executor_name}-executor.env
ExecStart=$PROJECT_ROOT/.venv/bin/umat-${executor_name}-executor run
Restart=on-failure
RestartSec=3
OOMPolicy=stop
MemoryHigh=3G
MemoryMax=4G
TasksMax=1024
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
InaccessiblePaths=/etc/umat/full-stack.env -$PROJECT_ROOT/.env /var/lib/umat/artifacts /var/lib/umat/quarantine -/var/lib/umat-backups
ReadWritePaths=/var/lib/umat/executors/${executor_name} /var/lib/umat/${executor_name}-work

[Install]
WantedBy=multi-user.target
EOF
  if [[ "$executor_name" == "c2" ]]; then
    sed -i '/ReadWritePaths=/i ReadOnlyPaths=/srv/winstdt/libexec/c2-exfil/bf1f275-umat.2' "$executor_unit"
  else
    sed -i '/ReadWritePaths=/i SupplementaryGroups=kvm docker' "$executor_unit"
  fi
  echo "+ install $UNIT_DIR/umat-${executor_name}-executor.service (enrollment required before enablement)"
  if [[ "$EXECUTE" -eq 1 ]]; then
    sudo -n install -m 0644 "$executor_unit" "$UNIT_DIR/umat-${executor_name}-executor.service"
  fi
  rm -f -- "$executor_unit"
done

# ThreatFox is shipped inside the verified C2 runtime, but the mutable SQLite
# database lives outside that read-only tree. Rebuild through a temporary file
# and atomically promote it so upgrades never expose a partial database. GeoLite
# City and ASN remain an optional pair; provisioning only one is a hard error.
c2_data_root=/srv/winstdt/c2-data
c2_runtime_root=/srv/winstdt/libexec/c2-exfil/bf1f275-umat.2
c2_threatintel="$c2_data_root/threatintel.sqlite"
c2_geolite_files=(
  "$c2_data_root/GeoLite2-City.mmdb"
  "$c2_data_root/GeoLite2-ASN.mmdb"
)
echo "+ seed required offline C2 threat intelligence and validate optional GeoLite2 data"
if [[ "$EXECUTE" -eq 1 ]]; then
  c2_python="$c2_runtime_root/.venv/bin/python"
  c2_seed="$c2_runtime_root/source/scripts/seed_threatintel.py"
  sudo -n test -x "$c2_python" || { echo "C2 runtime Python is unavailable: $c2_python" >&2; exit 1; }
  sudo -n test -f "$c2_seed" || { echo "C2 threat-intelligence seeder is unavailable: $c2_seed" >&2; exit 1; }
  sudo -n install -d -o "$SERVICE_USER" -g "$EXECUTOR_USER" -m 0770 "$c2_data_root"
  c2_threatintel_stage="$(sudo -n mktemp "$c2_data_root/.threatintel.sqlite.XXXXXX")"
  if ! sudo -n env THREATINTEL_DB="$c2_threatintel_stage" \
      "$c2_python" "$c2_seed" --rebuild; then
    sudo -n rm -f -- "$c2_threatintel_stage"
    exit 1
  fi
  sudo -n chown "$SERVICE_USER":"$EXECUTOR_USER" "$c2_threatintel_stage"
  sudo -n chmod 0660 "$c2_threatintel_stage"
  sudo -n mv -f -- "$c2_threatintel_stage" "$c2_threatintel"

  c2_geolite_present=0
  for data_file in "${c2_geolite_files[@]}"; do
    sudo -n test -f "$data_file" && ((c2_geolite_present += 1)) || true
  done
  if [[ "$c2_geolite_present" -ne 0 && "$c2_geolite_present" -ne "${#c2_geolite_files[@]}" ]]; then
    echo "GeoLite2 enrichment is partially provisioned under $c2_data_root" >&2
    exit 1
  fi

  echo "+ install $UNIT_DIR/umat-c2-executor.service.d/c2-data.conf"
  sudo -n install -d -m 0755 "$UNIT_DIR/umat-c2-executor.service.d"
  sudo -n install -m 0644 \
    "$PROJECT_ROOT/deployment/full-stack/umat-c2-executor-data.conf" \
    "$UNIT_DIR/umat-c2-executor.service.d/c2-data.conf"
  if [[ "$c2_geolite_present" -eq "${#c2_geolite_files[@]}" ]]; then
    sudo -n install -m 0644 \
      "$PROJECT_ROOT/deployment/full-stack/umat-c2-executor-geolite.conf" \
      "$UNIT_DIR/umat-c2-executor.service.d/c2-geolite.conf"
    sudo -n chown root:"$EXECUTOR_USER" "${c2_geolite_files[@]}"
    sudo -n chmod 0440 "${c2_geolite_files[@]}"
  else
    sudo -n rm -f -- "$UNIT_DIR/umat-c2-executor.service.d/c2-geolite.conf"
  fi
fi

if [[ "$EXECUTE" -eq 1 ]]; then
  sudo -n install -m 0644 "$PROJECT_ROOT/deployment/full-stack/umat-guest-guard.nft" /etc/umat/umat-guest-guard.nft
  sudo -n install -m 0644 "$PROJECT_ROOT/deployment/full-stack/umat-egress.modules-load.conf" /etc/modules-load.d/umat-egress.conf
  sudo -n install -d -m 0755 /usr/libexec/umat
  sudo -n install -m 0755 "$PROJECT_ROOT/deployment/full-stack/umat-guest-guard-compat.sh" /usr/libexec/umat/umat-guest-guard-compat
  sudo -n install -m 0644 "$PROJECT_ROOT/deployment/full-stack/umat-guest-guard.service" "$UNIT_DIR/umat-guest-guard.service"
  sudo -n install -m 0644 "$PROJECT_ROOT/deployment/android-worker/umat-android-api-relay.service" "$UNIT_DIR/umat-android-api-relay.service"
  sudo -n install -m 0644 "$PROJECT_ROOT/deployment/android-worker/umat-android-egress-relay.service" "$UNIT_DIR/umat-android-egress-relay.service"
  worker_controller="$(mktemp)"
  sed "s|PROJECT_ROOT_PLACEHOLDER|$PROJECT_ROOT|g" \
    "$PROJECT_ROOT/deployment/android-worker/umat-android-worker-controller.service" >"$worker_controller"
  sudo -n install -m 0644 "$worker_controller" "$UNIT_DIR/umat-android-worker-controller.service"
  rm -f -- "$worker_controller"
  egress_unit="$(mktemp)"
  sed -e "s|PROJECT_ROOT_PLACEHOLDER|$PROJECT_ROOT|g" \
      -e "s|SERVICE_GROUP_PLACEHOLDER|$(id -gn "$SERVICE_USER")|g" \
    "$PROJECT_ROOT/deployment/full-stack/umat-egress-broker.service" >"$egress_unit"
  sudo -n install -m 0644 "$egress_unit" "$UNIT_DIR/umat-egress-broker.service"
  rm -f -- "$egress_unit"
  sudo -n install -d -m 0750 -o "$SERVICE_USER" -g "$(id -gn "$SERVICE_USER")" \
    /var/lib/umat /var/lib/umat/quarantine /var/lib/umat/artifacts
  sudo -n install -d -m 0700 -o root -g root /var/lib/umat-cape-profiles
  sudo -n install -d -m 0750 -o root -g "$(id -gn "$SERVICE_USER")" /var/lib/umat-egress
  sudo -n install -d -m 0700 -o "$EXECUTOR_USER" -g "$EXECUTOR_USER" \
    /var/lib/umat/executors/windows /var/lib/umat/windows-work \
    /var/lib/umat/executors/c2 /var/lib/umat/c2-work \
    /var/lib/umat/executors/android /var/lib/umat/android-work
  # Older single-host installs ran executors as the service account. Preserve
  # their enrolled state while migrating all executor-private storage to the
  # dedicated identity used by the hardened units.
  sudo -n chown -R "$EXECUTOR_USER:$EXECUTOR_USER" \
    /var/lib/umat/executors/windows /var/lib/umat/windows-work \
    /var/lib/umat/executors/c2 /var/lib/umat/c2-work \
    /var/lib/umat/executors/android /var/lib/umat/android-work
  executor_group="$EXECUTOR_USER"
  c2_env="$(mktemp)"
  android_env="$(mktemp)"
  egress_env="$(mktemp)"
  trap 'rm -f -- "$c2_env" "$android_env" "$egress_env"' EXIT
  egress_token=""
  if [[ "${UMAT_ROTATE_EGRESS_BROKER_TOKEN:-0}" != "1" ]] && \
    sudo -n test -r /etc/umat/egress-broker.env; then
    egress_token="$(sudo -n awk -F= '$1 == "UMAT_EGRESS_BROKER_TOKEN" {print substr($0, index($0, "=") + 1)}' /etc/umat/egress-broker.env)"
  fi
  [[ -n "$egress_token" ]] || egress_token="$(openssl rand -hex 32)"
  # Windows startup and CAPE post-processing routinely exceed 100 MiB even when malware
  # traffic is small. Keep a finite one-GiB ceiling alongside the port and rate limits.
  printf '%s\n' \
    "UMAT_EGRESS_BROKER_TOKEN=$egress_token" \
    'UMAT_EGRESS_UPLINK=wg-umat-egress' \
    'UMAT_EGRESS_DNS_RESOLVER=10.77.0.53' \
    'UMAT_EGRESS_CAPTURE_ROOT=/var/lib/umat-egress' \
    'UMAT_EGRESS_MAX_BYTES=1073741824' >"$egress_env"
  sudo -n install -o root -g root -m 0600 "$egress_env" /etc/umat/egress-broker.env
  printf '%s\n' \
    'UMAT_EXECUTOR_URL=http://127.0.0.1:8080' \
    'UMAT_C2_STATE_PATH=/var/lib/umat/executors/c2/state.json' \
    'UMAT_C2_WORK_ROOT=/var/lib/umat/c2-work' \
    'UMAT_C2_RUNTIME_ROOT=/srv/winstdt/libexec/c2-exfil/bf1f275-umat.2' \
    'UMAT_C2_EXECUTOR_NAME=c2-executor' >"$c2_env"
  mobsf_api_key="$(sudo -n awk -F= '$1 == "MOBSF_API_KEY" {print substr($0, index($0, "=") + 1)}' "$ENV_FILE")"
  [[ -n "$mobsf_api_key" ]] || { echo 'MOBSF_API_KEY is missing' >&2; exit 1; }
  printf '%s\n' \
    'UMAT_EXECUTOR_URL=http://127.0.0.1:8080' \
    'UMAT_MOBSF_URL=http://127.0.0.1:8001' \
    "MOBSF_API_KEY=$mobsf_api_key" \
    'UMAT_ANDROID_AVDMANAGER=/usr/bin/avdmanager' \
    'UMAT_ANDROID_EMULATOR=/opt/android-sdk-34/emulator/emulator' \
    'UMAT_ANDROID_ADB=/usr/bin/adb' \
    'UMAT_ANDROID_ADB_RELAY=/usr/bin/socat' \
    'UMAT_ANDROID_ADB_RELAY_BIND_ADDRESS=172.17.0.1' \
    'UMAT_ANDROID_STATE_PATH=/var/lib/umat/executors/android/state.json' \
    'UMAT_ANDROID_WORK_ROOT=/var/lib/umat/android-work' \
    'UMAT_ANDROID_EXECUTOR_NAME=android-executor' >"$android_env"
  printf '%s\n' \
    'UMAT_ANDROID_MITMPROXY_IMAGE=mitmproxy/mitmproxy@sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f' \
    'UMAT_ANDROID_EGRESS_GUEST_IP=10.68.0.10' \
    'UMAT_EGRESS_BROKER_URL=http://127.0.0.1:8092' \
    "UMAT_EGRESS_BROKER_TOKEN=$egress_token" >>"$android_env"
  sudo -n install -o root -g "$executor_group" -m 0640 "$c2_env" /etc/umat/c2-executor.env
  sudo -n install -o root -g "$executor_group" -m 0640 "$android_env" /etc/umat/android-executor.env
  if sudo -n test -r /etc/umat/windows-executor.env; then
    windows_env="$(mktemp)"
    sudo -n cat /etc/umat/windows-executor.env >"$windows_env"
    sed -i '/^UMAT_EGRESS_BROKER_/d' "$windows_env"
    printf '%s\n' \
      'UMAT_EGRESS_BROKER_URL=http://127.0.0.1:8092' \
      "UMAT_EGRESS_BROKER_TOKEN=$egress_token" >>"$windows_env"
    sudo -n install -o root -g "$executor_group" -m 0640 "$windows_env" /etc/umat/windows-executor.env
    rm -f -- "$windows_env"
  fi
  mkdir -p "$PROJECT_ROOT/var"
  sudo -n systemctl daemon-reload
  core_units=(
    umat-guest-guard umat-egress-broker umat-api umat-scheduler
    umat-report-worker umat-adapter-worker umat-cape-gateway umat-android-api-relay
    umat-android-egress-relay
  )
  # An installer rerun is also an application upgrade. Restart existing
  # processes so reporting, capture, and configuration-fallback changes do not
  # remain hidden behind stale in-memory code.
  sudo -n systemctl enable "${core_units[@]}"
  sudo -n systemctl restart "${core_units[@]}"
  executor_units=(umat-windows-executor umat-c2-executor)
  android_worker_image=/var/lib/libvirt/images/umat-android-worker/umat-android-worker-golden.qcow2
  if ! sudo -n test -f "$android_worker_image"; then
    executor_units+=(umat-android-executor)
  fi
  for executor_unit in "${executor_units[@]}"; do
    if sudo -n systemctl is-enabled --quiet "$executor_unit.service"; then
      sudo -n systemctl restart "$executor_unit.service"
    fi
  done
  if sudo -n test -f "$android_worker_image"; then
    # The disposable worker contains the only Android executor after cutover.
    # Leaving the legacy host unit enabled creates a claim race which can run a
    # privileged ReDroid container outside the KVM isolation boundary.
    sudo -n systemctl disable --now umat-android-executor.service
    sudo -n systemctl enable --now umat-android-worker-controller.service
  fi
else
  echo "dry-run complete; no services changed"
fi
