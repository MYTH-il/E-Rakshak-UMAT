#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT=""
ADMIN="admin"
COMPONENTS=(windows c2 android)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-root) PROJECT_ROOT="${2:-}"; shift ;;
    --admin) ADMIN="${2:-}"; shift ;;
    --component) COMPONENTS=("${2:-}"); shift ;;
    *) echo "usage: $0 --project-root PATH [--admin USER] [--component windows|c2|android]" >&2; exit 2 ;;
  esac
  shift
done
[[ "$PROJECT_ROOT" = /* && -x "$PROJECT_ROOT/.venv/bin/umat" ]] || exit 2

SERVICE_USER="${UMAT_SERVICE_USER:-$(id -un)}"
FULL_ENV="${UMAT_ENV_FILE:-/etc/umat/full-stack.env}"
database_url="$(sudo -n awk -F= '$1 == "UMAT_DATABASE_URL" {print substr($0, index($0, "=") + 1)}' "$FULL_ENV")"
[[ -n "$database_url" ]] || { echo 'UMAT_DATABASE_URL is missing' >&2; exit 1; }

for _ in {1..60}; do
  curl --max-time 2 -fsS http://127.0.0.1:8080/health/ready >/dev/null && break
  sleep 1
done
curl --max-time 2 -fsS http://127.0.0.1:8080/health/ready >/dev/null

enroll_generic() {
  local component="$1" stage_type="$2" env_file="$3" state_file="$4"
  if sudo -n test -s "$state_file"; then
    echo "$component executor already enrolled"
  else
    local token enrollment
    token="$(UMAT_DATABASE_URL="$database_url" "$PROJECT_ROOT/.venv/bin/umat" admin \
      enroll-executor --created-by "$ADMIN" --executor-type "$component" --stage-type "$stage_type")"
    enrollment="$(mktemp)"
    cp "$env_file" "$enrollment"
    printf 'UMAT_%s_ENROLLMENT_TOKEN=%s\n' "${component^^}" "$token" >>"$enrollment"
    chmod 0600 "$enrollment"
    sudo -n -u "$SERVICE_USER" bash -c \
      'set -a; source "$1"; set +a; exec "$2/.venv/bin/umat-'"$component"'-executor" run --enroll-only' \
      bash "$enrollment" "$PROJECT_ROOT"
    rm -f -- "$enrollment"
    unset token
  fi
  sudo -n systemctl enable --now "umat-$component-executor.service"
}

for component in "${COMPONENTS[@]}"; do
  case "$component" in
    windows)
      if sudo -n test -s /var/lib/umat/executors/windows/state.json; then
        sudo -n systemctl enable --now umat-windows-executor.service
      else
        token_file="$(mktemp)"
        UMAT_DATABASE_URL="$database_url" "$PROJECT_ROOT/.venv/bin/umat" admin \
          enroll-executor --created-by "$ADMIN" --executor-type windows \
          --stage-type platform_analysis >"$token_file"
        chmod 0600 "$token_file"
        "$PROJECT_ROOT/deployment/full-stack/enroll-windows-executor.sh" \
          --project-root "$PROJECT_ROOT" --token-file "$token_file"
        rm -f -- "$token_file"
      fi
      ;;
    c2) enroll_generic c2 c2_analysis /etc/umat/c2-executor.env /var/lib/umat/executors/c2/state.json ;;
    android) enroll_generic android platform_analysis /etc/umat/android-executor.env /var/lib/umat/executors/android/state.json ;;
    *) echo "unknown executor component: $component" >&2; exit 2 ;;
  esac
done
