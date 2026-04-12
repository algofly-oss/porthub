#!/usr/bin/env bash
set -euo pipefail

PORT_HUB_CLIENT_VERSION="__PORT_HUB_CLIENT_VERSION__"
PORT_HUB_DEFAULT_API_URL="__PORT_HUB_API_URL__"
PORT_HUB_DEFAULT_MACHINE_ID="__PORT_HUB_MACHINE_ID__"
PORT_HUB_DEFAULT_MACHINE_TOKEN="__PORT_HUB_MACHINE_TOKEN__"
PORT_HUB_DEFAULT_AUTH_URL="__PORT_HUB_AUTH_URL__"
PORT_HUB_DEFAULT_SYNC_URL="__PORT_HUB_SYNC_URL__"
PORT_HUB_DEFAULT_CONFIG_TOML_URL="__PORT_HUB_CONFIG_TOML_URL__"
PORT_HUB_DEFAULT_CHANGES_TOML_URL="__PORT_HUB_CHANGES_TOML_URL__"
PORT_HUB_DEFAULT_LOG_STREAM_STATUS_URL="__PORT_HUB_LOG_STREAM_STATUS_URL__"
PORT_HUB_DEFAULT_LOG_STREAM_UPLOAD_URL="__PORT_HUB_LOG_STREAM_UPLOAD_URL__"
PORT_HUB_DEFAULT_RATHOLE_X86_64_URL="__PORT_HUB_RATHOLE_X86_64_URL__"
PORT_HUB_DEFAULT_RATHOLE_DARWIN_X86_64_URL="__PORT_HUB_RATHOLE_DARWIN_X86_64_URL__"
PORT_HUB_DEFAULT_RATHOLE_ARM64_URL="__PORT_HUB_RATHOLE_ARM64_URL__"
PORT_HUB_DEFAULT_RATHOLE_ARMHF_URL="__PORT_HUB_RATHOLE_ARMHF_URL__"
PORT_HUB_DEFAULT_RATHOLE_ARMV7_URL="__PORT_HUB_RATHOLE_ARMV7_URL__"
PORT_HUB_DEFAULT_HEARTBEAT_INTERVAL_SECONDS="30"
PORT_HUB_DEFAULT_CHANGES_WAIT_SECONDS="25"
PORT_HUB_DEFAULT_LOG_MAX_BYTES="1048576"
PORT_HUB_DEFAULT_AUTH_FAILURE_RETRY_SECONDS="5"
PORT_HUB_DEFAULT_CLIENT_UPDATE_RETRY_SECONDS="300"
PORT_HUB_DEFAULT_PUBLIC_IP_REFRESH_SECONDS="3600"
PORT_HUB_DEFAULT_ENABLE_DEBUG_LOGS="false"
PORT_HUB_EXPLICIT_TENANT="${PORT_HUB_TENANT:-}"
CURRENT_STEP="bootstrap"

normalize_tenant_name() {
  case "${1:-}" in
    ""|default) printf "" ;;
    *) printf "%s" "$1" ;;
  esac
}

tenant_display_name() {
  local tenant="${1:-$PORT_HUB_TENANT}"
  if [ -n "$tenant" ]; then
    printf "%s" "$tenant"
  else
    printf "default"
  fi
}

tenant_service_suffix() {
  local tenant="${1:-$PORT_HUB_TENANT}"
  if [ -z "$tenant" ]; then
    printf "default"
    return
  fi
  printf "%s" "$tenant" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-'
}

validate_tenant_name() {
  local tenant="$1"
  case "$tenant" in
    ""|default) return 0 ;;
    *[!A-Za-z0-9._-]*)
      printf "[porthub] Invalid tenant name: %s\n" "$tenant" >&2
      exit 1
      ;;
  esac
}

apply_tenant_context() {
  local requested_tenant normalized_tenant service_suffix
  requested_tenant="${1:-}"
  normalized_tenant="$(normalize_tenant_name "$requested_tenant")"
  validate_tenant_name "$normalized_tenant"

  PORT_HUB_TENANT="$normalized_tenant"
  PORT_HUB_BIN_DIR="$PORT_HUB_SHARED_BIN_DIR"
  service_suffix="$(tenant_service_suffix "$normalized_tenant")"

  if [ -n "$normalized_tenant" ]; then
    PORT_HUB_DIR="$PORT_HUB_TENANTS_DIR/$normalized_tenant"
    PORT_HUB_RUNTIME_DIR="$PORT_HUB_RUNTIME_ROOT/$normalized_tenant"
    PORT_HUB_LOG_DIR="$PORT_HUB_LOG_ROOT/$normalized_tenant"
    case "$(uname -s)" in
      Darwin)
        PORT_HUB_SERVICE_LABEL="${PORT_HUB_SERVICE_BASE_LABEL}.${service_suffix}"
        PORT_HUB_SERVICE_FILE="$PORT_HUB_SERVICE_ROOT/${PORT_HUB_SERVICE_LABEL}.plist"
        ;;
      *)
        PORT_HUB_SERVICE_LABEL="${PORT_HUB_SERVICE_BASE_LABEL}-${service_suffix}.service"
        PORT_HUB_SERVICE_FILE="$PORT_HUB_SERVICE_ROOT/${PORT_HUB_SERVICE_LABEL}"
        ;;
    esac
  else
    PORT_HUB_DIR="$PORT_HUB_ROOT_DIR"
    PORT_HUB_RUNTIME_DIR="$PORT_HUB_RUNTIME_ROOT"
    PORT_HUB_LOG_DIR="$PORT_HUB_LOG_ROOT"
    case "$(uname -s)" in
      Darwin)
        PORT_HUB_SERVICE_LABEL="$PORT_HUB_SERVICE_BASE_LABEL"
        PORT_HUB_SERVICE_FILE="$PORT_HUB_SERVICE_ROOT/${PORT_HUB_SERVICE_BASE_LABEL}.plist"
        ;;
      *)
        PORT_HUB_SERVICE_LABEL="${PORT_HUB_SERVICE_BASE_LABEL}.service"
        PORT_HUB_SERVICE_FILE="$PORT_HUB_SERVICE_ROOT/${PORT_HUB_SERVICE_LABEL}"
        ;;
    esac
  fi

  PORT_HUB_ENV_FILE="$PORT_HUB_DIR/client.env"
  PORT_HUB_STATE_FILE="$PORT_HUB_DIR/state.env"
  PORT_HUB_CONFIG_FILE="$PORT_HUB_DIR/rathole-client.toml"
  PORT_HUB_RATHOLE_BIN="$PORT_HUB_BIN_DIR/rathole"
  PORT_HUB_PID_FILE="$PORT_HUB_RUNTIME_DIR/porthub.pid"
  PORT_HUB_LOG_FILE="$PORT_HUB_LOG_DIR/porthub.log"
  PORT_HUB_LOG_BACKUP_FILE="$PORT_HUB_LOG_DIR/porthub.log.1"
  PORT_HUB_SELF_PATH="${PORT_HUB_SELF_PATH:-$(command -v porthub 2>/dev/null || printf "/usr/local/bin/porthub")}"
}

detect_platform_defaults() {
  case "$(uname -s)" in
    Darwin)
      PORT_HUB_ROOT_DIR="${PORT_HUB_ROOT_DIR:-/usr/local/etc/porthub}"
      PORT_HUB_SHARED_BIN_DIR="${PORT_HUB_SHARED_BIN_DIR:-/usr/local/libexec/porthub}"
      PORT_HUB_RUNTIME_ROOT="${PORT_HUB_RUNTIME_ROOT:-/usr/local/var/run/porthub}"
      PORT_HUB_LOG_ROOT="${PORT_HUB_LOG_ROOT:-/usr/local/var/log/porthub}"
      PORT_HUB_SERVICE_BASE_LABEL="${PORT_HUB_SERVICE_BASE_LABEL:-com.porthub.client}"
      PORT_HUB_SERVICE_ROOT="${PORT_HUB_SERVICE_ROOT:-/Library/LaunchDaemons}"
      ;;
    *)
      PORT_HUB_ROOT_DIR="${PORT_HUB_ROOT_DIR:-/etc/porthub}"
      PORT_HUB_SHARED_BIN_DIR="${PORT_HUB_SHARED_BIN_DIR:-/opt/porthub/bin}"
      PORT_HUB_RUNTIME_ROOT="${PORT_HUB_RUNTIME_ROOT:-/var/run/porthub}"
      PORT_HUB_LOG_ROOT="${PORT_HUB_LOG_ROOT:-/var/log/porthub}"
      PORT_HUB_SERVICE_BASE_LABEL="${PORT_HUB_SERVICE_BASE_LABEL:-porthub}"
      PORT_HUB_SERVICE_ROOT="${PORT_HUB_SERVICE_ROOT:-/etc/systemd/system}"
      ;;
  esac

  PORT_HUB_TENANTS_DIR="${PORT_HUB_TENANTS_DIR:-$PORT_HUB_ROOT_DIR/tenants}"
  PORT_HUB_SELF_PATH="${PORT_HUB_SELF_PATH:-$(command -v porthub 2>/dev/null || printf "/usr/local/bin/porthub")}"
  apply_tenant_context "${PORT_HUB_EXPLICIT_TENANT:-}"
}

log_plain() { printf "%s\n" "$*" >&2; }
fail() { log "ERROR" "$*"; exit 1; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"; }
require_value() {
  local label="$1"
  local value="${2:-}"
  [ -n "$value" ] || fail "Missing required value: $label"
}
require_http_url() {
  local label="$1"
  local value="${2:-}"
  case "$value" in
    http://*|https://*) ;;
    *) fail "$label must be an http(s) URL" ;;
  esac
}
step() {
  CURRENT_STEP="$1"
  log "INFO" "$CURRENT_STEP"
}
trap 'rc=$?; log "ERROR" "Command failed during: ${CURRENT_STEP} (exit ${rc})"' ERR

detect_platform_defaults

detect_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
    return
  fi
  fail "Run as root or install sudo."
}

detect_supported_platform() {
  case "$(uname -s)" in
    Linux|Darwin) return 0 ;;
    *)
      fail "Unsupported operating system: $(uname -s). Supported: Linux, macOS."
      ;;
  esac
}

collect_configured_tenants() {
  CONFIGURED_TENANTS=()

  if [ -f "$PORT_HUB_ROOT_DIR/client.env" ]; then
    CONFIGURED_TENANTS+=("default")
  fi

  if [ -d "$PORT_HUB_TENANTS_DIR" ]; then
    local tenant_dir
    for tenant_dir in "$PORT_HUB_TENANTS_DIR"/*; do
      [ -d "$tenant_dir" ] || continue
      [ -f "$tenant_dir/client.env" ] || continue
      CONFIGURED_TENANTS+=("$(basename "$tenant_dir")")
    done
  fi
}

resolve_tenant_reference() {
  local requested="${1:-}"
  local exact_match=""
  local match=""
  local configured_tenant=""
  local -a prefix_matches=()

  requested="$(normalize_tenant_name "$requested")"
  if [ -z "$requested" ]; then
    printf ""
    return 0
  fi

  collect_configured_tenants

  for configured_tenant in "${CONFIGURED_TENANTS[@]}"; do
    if [ "$configured_tenant" = "$requested" ]; then
      exact_match="$configured_tenant"
      break
    fi
  done
  if [ -n "$exact_match" ]; then
    printf "%s" "$exact_match"
    return 0
  fi

  for configured_tenant in "${CONFIGURED_TENANTS[@]}"; do
    case "$configured_tenant" in
      "$requested"*)
        prefix_matches+=("$configured_tenant")
        ;;
    esac
  done

  case "${#prefix_matches[@]}" in
    0)
      printf "%s" "$requested"
      ;;
    1)
      printf "%s" "${prefix_matches[0]}"
      ;;
    *)
      printf "[porthub] Tenant reference '%s' is ambiguous. Matches:" "$requested" >&2
      for match in "${prefix_matches[@]}"; do
        printf " %s" "$match" >&2
      done
      printf "\n" >&2
      exit 1
      ;;
  esac
}

configured_tenant_count() {
  collect_configured_tenants
  printf "%s" "${#CONFIGURED_TENANTS[@]}"
}

resolve_selected_tenant_context() {
  collect_configured_tenants

  if [ -n "${PORT_HUB_EXPLICIT_TENANT:-}" ]; then
    apply_tenant_context "$PORT_HUB_EXPLICIT_TENANT"
    return 0
  fi

  case "${#CONFIGURED_TENANTS[@]}" in
    0)
      apply_tenant_context ""
      ;;
    1)
      apply_tenant_context "${CONFIGURED_TENANTS[0]}"
      ;;
    *)
      fail "Multiple PortHub tenants are configured. Use --tenant <name> or 'porthub tenants list'."
      ;;
  esac
}

parse_global_cli_options() {
  PARSED_GLOBAL_ARGS=()
  PORT_HUB_EXPLICIT_TENANT="${PORT_HUB_TENANT:-}"

  while [ "$#" -gt 0 ]; do
    case "$1" in
      -t)
        [ "$#" -ge 2 ] || fail "Missing value for -t"
        PORT_HUB_EXPLICIT_TENANT="$(resolve_tenant_reference "$2")"
        validate_tenant_name "$PORT_HUB_EXPLICIT_TENANT"
        shift 2
        ;;
      --tenant)
        [ "$#" -ge 2 ] || fail "Missing value for --tenant"
        PORT_HUB_EXPLICIT_TENANT="$(resolve_tenant_reference "$2")"
        validate_tenant_name "$PORT_HUB_EXPLICIT_TENANT"
        shift 2
        ;;
      --tenant=*)
        PORT_HUB_EXPLICIT_TENANT="$(resolve_tenant_reference "${1#*=}")"
        validate_tenant_name "$PORT_HUB_EXPLICIT_TENANT"
        shift
        ;;
      *)
        PARSED_GLOBAL_ARGS+=("$1")
        shift
        ;;
    esac
  done
}

ensure_dirs() {
  ${SUDO:-} mkdir -p "$PORT_HUB_DIR" "$PORT_HUB_BIN_DIR" "$PORT_HUB_RUNTIME_DIR" "$PORT_HUB_LOG_DIR"
}

rotate_logs_if_needed() {
  [ -f "$PORT_HUB_LOG_FILE" ] || return 0
  local max_bytes="${PORT_HUB_LOG_MAX_BYTES:-$PORT_HUB_DEFAULT_LOG_MAX_BYTES}"
  local current_size
  current_size="$(wc -c < "$PORT_HUB_LOG_FILE" 2>/dev/null || printf "0")"
  if [ "${current_size:-0}" -lt "$max_bytes" ]; then
    return 0
  fi
  cp "$PORT_HUB_LOG_FILE" "$PORT_HUB_LOG_BACKUP_FILE" 2>/dev/null || true
  : > "$PORT_HUB_LOG_FILE"
}

can_write_log_file_directly() {
  if [ -f "$PORT_HUB_LOG_FILE" ]; then
    [ -w "$PORT_HUB_LOG_FILE" ]
    return
  fi
  [ -w "$(dirname "$PORT_HUB_LOG_FILE")" ]
}

append_log_line() {
  local line="$1"
  local log_dir
  log_dir="$(dirname "$PORT_HUB_LOG_FILE")"

  mkdir -p "$log_dir" 2>/dev/null || true

  if can_write_log_file_directly; then
    rotate_logs_if_needed
    printf "%s\n" "$line" >>"$PORT_HUB_LOG_FILE" 2>/dev/null || true
    return
  fi

  if [ -n "${SUDO:-}" ]; then
    ${SUDO:-} mkdir -p "$log_dir" >/dev/null 2>&1 || true
    printf "%s\n" "$line" | ${SUDO:-} tee -a "$PORT_HUB_LOG_FILE" >/dev/null 2>&1 || true
  fi
}

log() {
  local level="$1"
  shift
  local line timestamp
  timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
  line="[$timestamp] [$level] $*"
  append_log_line "$line"
  printf "%s\n" "$line" >&2
}

debug_log() {
  case "${PORT_HUB_ENABLE_DEBUG_LOGS:-$PORT_HUB_DEFAULT_ENABLE_DEBUG_LOGS}" in
    true|1|yes|on) log "DEBUG" "$@" ;;
    *) ;;
  esac
}

normalize_api_url() {
  local value="${1%/}"
  case "$value" in
    */api) printf "%s" "$value" ;;
    *) printf "%s/api" "$value" ;;
  esac
}

api_root_url() {
  printf "%s" "${PORT_HUB_API_URL%/}"
}

build_cli_download_url() {
  printf "%s/machines/%s/%s/downloads/porthub" \
    "$(api_root_url)" \
    "$PORT_HUB_MACHINE_ID" \
    "$PORT_HUB_MACHINE_TOKEN"
}

build_install_script_url() {
  printf "%s/machines/%s/%s/install.sh" \
    "$(api_root_url)" \
    "$PORT_HUB_MACHINE_ID" \
    "$PORT_HUB_MACHINE_TOKEN"
}

client_update_retry_seconds() {
  printf "%s" "$PORT_HUB_DEFAULT_CLIENT_UPDATE_RETRY_SECONDS"
}

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/ }"
  value="${value//$'\r'/ }"
  printf "%s" "$value"
}

detect_hostname() {
  hostname -f 2>/dev/null || hostname 2>/dev/null || printf "unknown-host"
}

detect_local_ip() {
  local detected=""
  if command -v ip >/dev/null 2>&1; then
    detected="$(ip route get 1 2>/dev/null | awk '/src/ {for (i = 1; i <= NF; i++) if ($i == "src") {print $(i+1); exit}}')"
  elif [ "$(uname -s)" = "Darwin" ] && command -v route >/dev/null 2>&1; then
    local iface
    iface="$(route get default 2>/dev/null | awk '/interface: / {print $2; exit}')"
    if [ -n "$iface" ] && command -v ipconfig >/dev/null 2>&1; then
      detected="$(ipconfig getifaddr "$iface" 2>/dev/null || true)"
    fi
  fi
  if [ -z "$detected" ] && command -v hostname >/dev/null 2>&1; then
    detected="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  printf "%s" "$detected"
}

detect_public_ip() {
  local detected="" cached_ip cached_at now refresh_seconds age
  if [ -n "${PORT_HUB_PUBLIC_IP_OVERRIDE:-}" ]; then
    printf "%s" "$PORT_HUB_PUBLIC_IP_OVERRIDE"
    return
  fi

  cached_ip="$(state_get PORT_HUB_CACHED_PUBLIC_IP)"
  cached_at="$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)"
  now="$(date +%s)"
  refresh_seconds="${PORT_HUB_PUBLIC_IP_REFRESH_SECONDS:-$PORT_HUB_DEFAULT_PUBLIC_IP_REFRESH_SECONDS}"
  if [ -z "$refresh_seconds" ] || ! [ "$refresh_seconds" -ge 60 ] 2>/dev/null; then
    refresh_seconds="$PORT_HUB_DEFAULT_PUBLIC_IP_REFRESH_SECONDS"
  fi

  if [ -n "$cached_ip" ] && [ -n "$cached_at" ]; then
    age=$((now - cached_at))
    if [ "$age" -lt 0 ]; then
      age=0
    fi
    if [ "$age" -lt "$refresh_seconds" ]; then
      printf "%s" "$cached_ip"
      return
    fi
  fi

  if command -v curl >/dev/null 2>&1; then
    detected="$(curl --fail --silent --show-error --max-time 5 ifconfig.me 2>/dev/null || true)"
    detected="$(printf "%s" "$detected" | tr -d '\r\n' | awk '{print $1}')"
  fi
  if [ -n "$detected" ]; then
    write_state \
      "$(state_get PORT_HUB_CURRENT_VERSION)" \
      "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
      "$(state_get PORT_HUB_SERVICE_MANAGER)" \
      "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
      "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
      "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
      "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
      "$(state_get PORT_HUB_RATHOLE_PID)" \
      "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
      "$(state_get PORT_HUB_SHARED_SERVICES)" \
      "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
      "$(state_get PORT_HUB_AUTH_REQUIRED)" \
      "$detected" \
      "$now"
    printf "%s" "$detected"
    return
  fi
  printf "%s" "$cached_ip"
}

extract_header() {
  local header_name="$1"
  local header_file="$2"
  awk -F": *" -v key="$header_name" '
    {
      header = tolower($1)
      expected = tolower(key)
      if (header == expected) {
        gsub(/\r/, "", $2)
        print $2
        exit
      }
    }
  ' "$header_file"
}

state_get() {
  local key="$1"
  [ -f "$PORT_HUB_STATE_FILE" ] || return 0
  awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "$PORT_HUB_STATE_FILE"
}

write_state() {
  local version="${1:-$(state_get PORT_HUB_CURRENT_VERSION)}"
  local last_sync="${2:-$(state_get PORT_HUB_LAST_SYNC_EPOCH)}"
  local manager="${3:-$(state_get PORT_HUB_SERVICE_MANAGER)}"
  local last_auth="${4:-$(state_get PORT_HUB_LAST_AUTH_EPOCH)}"
  local shared_hostname="${5:-$(state_get PORT_HUB_SHARED_HOSTNAME)}"
  local shared_local_ip="${6:-$(state_get PORT_HUB_SHARED_LOCAL_IP)}"
  local shared_public_ip="${7:-$(state_get PORT_HUB_SHARED_PUBLIC_IP)}"
  local rathole_pid="${8:-$(state_get PORT_HUB_RATHOLE_PID)}"
  local rathole_started_at="${9:-$(state_get PORT_HUB_RATHOLE_STARTED_AT)}"
  local shared_services="${10:-$(state_get PORT_HUB_SHARED_SERVICES)}"
  local last_contact="${11:-$(state_get PORT_HUB_LAST_CONTACT_EPOCH)}"
  local auth_required="${12:-$(state_get PORT_HUB_AUTH_REQUIRED)}"
  local cached_public_ip="${13:-$(state_get PORT_HUB_CACHED_PUBLIC_IP)}"
  local cached_public_ip_fetched_at="${14:-$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)}"
  local machine_disabled="${15:-$(state_get PORT_HUB_MACHINE_DISABLED)}"
  local client_update_target_version="${16:-$(state_get PORT_HUB_CLIENT_UPDATE_TARGET_VERSION)}"
  local client_update_request_id="${17:-$(state_get PORT_HUB_CLIENT_UPDATE_REQUEST_ID)}"
  local client_update_last_attempt_epoch="${18:-$(state_get PORT_HUB_CLIENT_UPDATE_LAST_ATTEMPT_EPOCH)}"
  local client_update_last_handled_request_id="${19:-$(state_get PORT_HUB_CLIENT_UPDATE_LAST_HANDLED_REQUEST_ID)}"
  cat <<EOF_STATE | ${SUDO:-} tee "$PORT_HUB_STATE_FILE" >/dev/null
PORT_HUB_CURRENT_VERSION=$version
PORT_HUB_LAST_SYNC_EPOCH=$last_sync
PORT_HUB_SERVICE_MANAGER=$manager
PORT_HUB_LAST_AUTH_EPOCH=$last_auth
PORT_HUB_SHARED_HOSTNAME=$shared_hostname
PORT_HUB_SHARED_LOCAL_IP=$shared_local_ip
PORT_HUB_SHARED_PUBLIC_IP=$shared_public_ip
PORT_HUB_RATHOLE_PID=$rathole_pid
PORT_HUB_RATHOLE_STARTED_AT=$rathole_started_at
PORT_HUB_SHARED_SERVICES=$shared_services
PORT_HUB_LAST_CONTACT_EPOCH=$last_contact
PORT_HUB_AUTH_REQUIRED=$auth_required
PORT_HUB_CACHED_PUBLIC_IP=$cached_public_ip
PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT=$cached_public_ip_fetched_at
PORT_HUB_MACHINE_DISABLED=$machine_disabled
PORT_HUB_CLIENT_UPDATE_TARGET_VERSION=$client_update_target_version
PORT_HUB_CLIENT_UPDATE_REQUEST_ID=$client_update_request_id
PORT_HUB_CLIENT_UPDATE_LAST_ATTEMPT_EPOCH=$client_update_last_attempt_epoch
PORT_HUB_CLIENT_UPDATE_LAST_HANDLED_REQUEST_ID=$client_update_last_handled_request_id
EOF_STATE
}

save_state() {
  write_state "$@"
}

count_services_in_file() {
  local file_path="$1"
  awk '/^\[client\.services\./ { count += 1 } END { print count + 0 }' "$file_path"
}

format_epoch() {
  local epoch="${1:-}"
  [ -n "$epoch" ] || return 0
  case "$(uname -s)" in
    Darwin) date -r "$epoch" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || printf "%s" "$epoch" ;;
    *) date -d "@$epoch" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || printf "%s" "$epoch" ;;
  esac
}

relative_epoch() {
  local epoch="${1:-}"
  local now diff value unit
  [ -n "$epoch" ] || return 0
  now="$(date +%s)"
  diff=$((now - epoch))
  if [ "$diff" -lt 0 ]; then
    diff=0
  fi
  if [ "$diff" -lt 60 ]; then
    if [ "$diff" -eq 1 ]; then
      printf "1 second ago"
    else
      printf "%s seconds ago" "$diff"
    fi
    return
  fi
  if [ "$diff" -lt 3600 ]; then
    value=$((diff / 60))
    unit="minutes"
    [ "$value" -eq 1 ] && unit="minute"
    printf "%s %s ago" "$value" "$unit"
    return
  fi
  if [ "$diff" -lt 86400 ]; then
    value=$((diff / 3600))
    unit="hours"
    [ "$value" -eq 1 ] && unit="hour"
    printf "%s %s ago" "$value" "$unit"
    return
  fi
  value=$((diff / 86400))
  unit="days"
  [ "$value" -eq 1 ] && unit="day"
  printf "%s %s ago" "$value" "$unit"
}

format_epoch_with_relative() {
  local epoch="${1:-}"
  local absolute relative
  [ -n "$epoch" ] || {
    printf "never"
    return
  }
  absolute="$(format_epoch "$epoch")"
  relative="$(relative_epoch "$epoch")"
  if [ -n "$relative" ]; then
    printf "%s (%s)" "$absolute" "$relative"
  else
    printf "%s" "$absolute"
  fi
}

count_shared_services() {
  [ -f "$PORT_HUB_CONFIG_FILE" ] || {
    printf "0"
    return
  }
  [ -r "$PORT_HUB_CONFIG_FILE" ] || {
    printf "%s" "$(state_get PORT_HUB_SHARED_SERVICES)"
    return
  }
  awk '/^\[client\.services\./ { count += 1 } END { print count + 0 }' "$PORT_HUB_CONFIG_FILE"
}

rathole_runtime_status() {
  local pid
  pid="$(state_get PORT_HUB_RATHOLE_PID)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    printf "running"
  elif [ -x "$PORT_HUB_RATHOLE_BIN" ]; then
    printf "installed"
  else
    printf "missing"
  fi
}

connection_status() {
  local service_state last_sync last_contact now max_age
  service_state="$(service_status)"
  if [ "$service_state" != "running" ]; then
    printf "offline"
    return
  fi
  if [ "$(state_get PORT_HUB_MACHINE_DISABLED)" = "true" ]; then
    printf "disabled"
    return
  fi
  last_sync="$(state_get PORT_HUB_LAST_SYNC_EPOCH)"
  last_contact="$(state_get PORT_HUB_LAST_CONTACT_EPOCH)"
  if [ -z "$last_contact" ]; then
    last_contact="$last_sync"
  fi
  if [ -z "$last_contact" ]; then
    printf "offline"
    return
  fi
  now="$(date +%s)"
  max_age=$(( (${PORT_HUB_HEARTBEAT_INTERVAL_SECONDS:-30} * 2) + 10 ))
  if [ $((now - last_contact)) -gt "$max_age" ]; then
    printf "offline"
    return
  fi
  if [ "$(state_get PORT_HUB_AUTH_REQUIRED)" = "true" ]; then
    printf "auth_required"
  else
    printf "online"
  fi
}

auth_failure_retry_seconds() {
  local seconds="${PORT_HUB_AUTH_FAILURE_RETRY_SECONDS:-$PORT_HUB_DEFAULT_AUTH_FAILURE_RETRY_SECONDS}"
  if [ -z "$seconds" ] || ! [ "$seconds" -ge 10 ] 2>/dev/null; then
    seconds="60"
  fi
  printf "%s" "$seconds"
}

rathole_version() {
  local output
  if [ ! -x "$PORT_HUB_RATHOLE_BIN" ]; then
    printf "not installed"
    return
  fi
  output="$("$PORT_HUB_RATHOLE_BIN" -V 2>/dev/null | head -n 1 || true)"
  if [ -z "$output" ]; then
    output="$("$PORT_HUB_RATHOLE_BIN" --version 2>/dev/null | head -n 1 || true)"
  fi
  if [ -n "$output" ]; then
    printf "%s" "$output"
  else
    printf "unknown"
  fi
}

client_version() {
  printf "%s" "$PORT_HUB_CLIENT_VERSION"
}

installed_cli_version() {
  local cli_path="${1:-$PORT_HUB_SELF_PATH}" embedded
  [ -f "$cli_path" ] || {
    printf "unknown"
    return
  }
  embedded="$(awk -F'"' '/^PORT_HUB_CLIENT_VERSION=/ { print $2; exit }' "$cli_path" 2>/dev/null || true)"
  if [ -n "$embedded" ]; then
    printf "%s" "$embedded"
  else
    printf "unknown"
  fi
}

clear_client_update_request_state() {
  write_state \
    "$(state_get PORT_HUB_CURRENT_VERSION)" \
    "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
    "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
    "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
    "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
    "$(state_get PORT_HUB_SHARED_SERVICES)" \
    "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
    "$(state_get PORT_HUB_AUTH_REQUIRED)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
    "$(state_get PORT_HUB_MACHINE_DISABLED)" \
    "" \
    "" \
    "" \
    "$(state_get PORT_HUB_CLIENT_UPDATE_LAST_HANDLED_REQUEST_ID)"
}

request_client_update_if_needed() {
  local request_id="${1:-}" target_version="${2:-}"
  local last_attempt now retry_seconds pending_request_id
  [ -n "$request_id" ] || return 0
  [ "$request_id" != "$(state_get PORT_HUB_CLIENT_UPDATE_LAST_HANDLED_REQUEST_ID)" ] || {
    clear_client_update_request_state
    return 0
  }

  pending_request_id="$(state_get PORT_HUB_CLIENT_UPDATE_REQUEST_ID)"
  last_attempt="$(state_get PORT_HUB_CLIENT_UPDATE_LAST_ATTEMPT_EPOCH)"
  now="$(date +%s)"
  retry_seconds="$(client_update_retry_seconds)"
  if [ -n "$last_attempt" ] && ! [ "$last_attempt" -ge 0 ] 2>/dev/null; then
    log "WARN" "Resetting invalid client update retry state: $last_attempt"
    last_attempt=""
  fi
  if [ "$pending_request_id" = "$request_id" ] && [ -n "$last_attempt" ] && [ $((now - last_attempt)) -lt "$retry_seconds" ]; then
    return 0
  fi

  write_state \
    "$(state_get PORT_HUB_CURRENT_VERSION)" \
    "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
    "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
    "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
    "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
    "$(state_get PORT_HUB_SHARED_SERVICES)" \
    "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
    "$(state_get PORT_HUB_AUTH_REQUIRED)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
    "$(state_get PORT_HUB_MACHINE_DISABLED)" \
    "$target_version" \
    "$request_id" \
    "$now" \
    "$(state_get PORT_HUB_CLIENT_UPDATE_LAST_HANDLED_REQUEST_ID)"

  if [ -n "$target_version" ] && [ "$target_version" = "$(client_version)" ]; then
    log "INFO" "Server requested PortHub client reinstall for current version $target_version (request $request_id)"
  else
    log "INFO" "Server requested PortHub client update (request $request_id target ${target_version:-latest})"
  fi
  run_self_cmd update >/dev/null 2>&1 &
}

handle_client_control_headers() {
  local header_file="$1"
  local update_requested target_version request_id

  update_requested="$(extract_header "X-PortHub-Client-Update-Requested" "$header_file")"
  target_version="$(extract_header "X-PortHub-Client-Target-Version" "$header_file")"
  request_id="$(extract_header "X-PortHub-Client-Update-Request-Id" "$header_file")"

  if [ "$update_requested" = "true" ] && [ -n "$request_id" ]; then
    request_client_update_if_needed "$request_id" "$target_version"
    return
  fi

  if [ -n "$(state_get PORT_HUB_CLIENT_UPDATE_TARGET_VERSION)" ]; then
    clear_client_update_request_state
  fi
}

load_env() {
  if [ -f "$PORT_HUB_ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$PORT_HUB_ENV_FILE"
    apply_tenant_context "${PORT_HUB_TENANT:-$PORT_HUB_EXPLICIT_TENANT}"
  fi

  PORT_HUB_API_URL="${PORT_HUB_API_URL:-$PORT_HUB_DEFAULT_API_URL}"
  PORT_HUB_MACHINE_ID="${PORT_HUB_MACHINE_ID:-$PORT_HUB_DEFAULT_MACHINE_ID}"
  PORT_HUB_MACHINE_TOKEN="${PORT_HUB_MACHINE_TOKEN:-$PORT_HUB_DEFAULT_MACHINE_TOKEN}"
  PORT_HUB_AUTH_URL="${PORT_HUB_AUTH_URL:-$PORT_HUB_DEFAULT_AUTH_URL}"
  PORT_HUB_SYNC_URL="${PORT_HUB_SYNC_URL:-$PORT_HUB_DEFAULT_SYNC_URL}"
  PORT_HUB_CONFIG_TOML_URL="${PORT_HUB_CONFIG_TOML_URL:-$PORT_HUB_DEFAULT_CONFIG_TOML_URL}"
  PORT_HUB_CHANGES_TOML_URL="${PORT_HUB_CHANGES_TOML_URL:-$PORT_HUB_DEFAULT_CHANGES_TOML_URL}"
  PORT_HUB_LOG_STREAM_STATUS_URL="${PORT_HUB_LOG_STREAM_STATUS_URL:-$PORT_HUB_DEFAULT_LOG_STREAM_STATUS_URL}"
  PORT_HUB_LOG_STREAM_UPLOAD_URL="${PORT_HUB_LOG_STREAM_UPLOAD_URL:-$PORT_HUB_DEFAULT_LOG_STREAM_UPLOAD_URL}"
  PORT_HUB_RATHOLE_X86_64_URL="${PORT_HUB_RATHOLE_X86_64_URL:-$PORT_HUB_DEFAULT_RATHOLE_X86_64_URL}"
  PORT_HUB_RATHOLE_DARWIN_X86_64_URL="${PORT_HUB_RATHOLE_DARWIN_X86_64_URL:-$PORT_HUB_DEFAULT_RATHOLE_DARWIN_X86_64_URL}"
  PORT_HUB_RATHOLE_ARM64_URL="${PORT_HUB_RATHOLE_ARM64_URL:-$PORT_HUB_DEFAULT_RATHOLE_ARM64_URL}"
  PORT_HUB_RATHOLE_ARMHF_URL="${PORT_HUB_RATHOLE_ARMHF_URL:-$PORT_HUB_DEFAULT_RATHOLE_ARMHF_URL}"
  PORT_HUB_RATHOLE_ARMV7_URL="${PORT_HUB_RATHOLE_ARMV7_URL:-$PORT_HUB_DEFAULT_RATHOLE_ARMV7_URL}"
  PORT_HUB_HEARTBEAT_INTERVAL_SECONDS="${PORT_HUB_HEARTBEAT_INTERVAL_SECONDS:-$PORT_HUB_DEFAULT_HEARTBEAT_INTERVAL_SECONDS}"
  PORT_HUB_CHANGES_WAIT_SECONDS="${PORT_HUB_CHANGES_WAIT_SECONDS:-$PORT_HUB_DEFAULT_CHANGES_WAIT_SECONDS}"
  PORT_HUB_LOG_MAX_BYTES="${PORT_HUB_LOG_MAX_BYTES:-$PORT_HUB_DEFAULT_LOG_MAX_BYTES}"
  PORT_HUB_AUTH_FAILURE_RETRY_SECONDS="${PORT_HUB_AUTH_FAILURE_RETRY_SECONDS:-$PORT_HUB_DEFAULT_AUTH_FAILURE_RETRY_SECONDS}"
  PORT_HUB_PUBLIC_IP_REFRESH_SECONDS="${PORT_HUB_PUBLIC_IP_REFRESH_SECONDS:-$PORT_HUB_DEFAULT_PUBLIC_IP_REFRESH_SECONDS}"
  PORT_HUB_ENABLE_DEBUG_LOGS="${PORT_HUB_ENABLE_DEBUG_LOGS:-$PORT_HUB_DEFAULT_ENABLE_DEBUG_LOGS}"
  PORT_HUB_PUBLIC_IP_OVERRIDE="${PORT_HUB_PUBLIC_IP_OVERRIDE:-}"
  PORT_HUB_SELF_PATH="${PORT_HUB_SELF_PATH:-$(command -v porthub 2>/dev/null || printf "$PORT_HUB_SELF_PATH")}"

  [ -n "$PORT_HUB_API_URL" ] || fail "Missing PortHub API URL. Run 'porthub configure'."
  [ -n "$PORT_HUB_MACHINE_ID" ] || fail "Missing machine id. Run 'porthub configure'."
  [ -n "$PORT_HUB_MACHINE_TOKEN" ] || fail "Missing machine token. Run 'porthub configure'."

  refresh_derived_urls
}

load_saved_env_if_present() {
  if [ -f "$PORT_HUB_ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$PORT_HUB_ENV_FILE"
    apply_tenant_context "${PORT_HUB_TENANT:-$PORT_HUB_EXPLICIT_TENANT}"
  fi

  if [ -z "${PORT_HUB_SELF_PATH:-}" ]; then
    PORT_HUB_SELF_PATH="$(command -v porthub 2>/dev/null || printf "/usr/local/bin/porthub")"
  fi
}

run_self_cmd() {
  local command="$1"
  shift
  if [ -n "$PORT_HUB_TENANT" ]; then
    "$PORT_HUB_SELF_PATH" "$command" --tenant "$PORT_HUB_TENANT" "$@"
  else
    "$PORT_HUB_SELF_PATH" "$command" "$@"
  fi
}

refresh_derived_urls() {
  PORT_HUB_API_URL="$(normalize_api_url "$PORT_HUB_API_URL")"
  PORT_HUB_AUTH_URL="${PORT_HUB_API_URL%/}/machines/client/auth"
  PORT_HUB_SYNC_URL="${PORT_HUB_API_URL%/}/machines/client/sync"
  PORT_HUB_CONFIG_TOML_URL="${PORT_HUB_API_URL%/}/machines/client/config.toml?machine_id=${PORT_HUB_MACHINE_ID}&token=${PORT_HUB_MACHINE_TOKEN}"
  PORT_HUB_CHANGES_TOML_URL="${PORT_HUB_API_URL%/}/machines/client/changes.toml?machine_id=${PORT_HUB_MACHINE_ID}&token=${PORT_HUB_MACHINE_TOKEN}"
  PORT_HUB_LOG_STREAM_STATUS_URL="${PORT_HUB_API_URL%/}/machines/client/log-stream?machine_id=${PORT_HUB_MACHINE_ID}&token=${PORT_HUB_MACHINE_TOKEN}"
  PORT_HUB_LOG_STREAM_UPLOAD_URL="${PORT_HUB_API_URL%/}/machines/client/logs"
  PORT_HUB_RATHOLE_X86_64_URL="${PORT_HUB_API_URL%/}/machines/${PORT_HUB_MACHINE_ID}/${PORT_HUB_MACHINE_TOKEN}/downloads/rathole/x86_64"
  PORT_HUB_RATHOLE_DARWIN_X86_64_URL="${PORT_HUB_API_URL%/}/machines/${PORT_HUB_MACHINE_ID}/${PORT_HUB_MACHINE_TOKEN}/downloads/rathole/darwin_x86_64"
  PORT_HUB_RATHOLE_ARM64_URL="${PORT_HUB_API_URL%/}/machines/${PORT_HUB_MACHINE_ID}/${PORT_HUB_MACHINE_TOKEN}/downloads/rathole/arm64"
  PORT_HUB_RATHOLE_ARMHF_URL="${PORT_HUB_API_URL%/}/machines/${PORT_HUB_MACHINE_ID}/${PORT_HUB_MACHINE_TOKEN}/downloads/rathole/armhf"
  PORT_HUB_RATHOLE_ARMV7_URL="${PORT_HUB_API_URL%/}/machines/${PORT_HUB_MACHINE_ID}/${PORT_HUB_MACHINE_TOKEN}/downloads/rathole/armv7"
}

write_env_file() {
  ensure_dirs
  cat <<EOF_ENV | ${SUDO:-} tee "$PORT_HUB_ENV_FILE" >/dev/null
PORT_HUB_TENANT=$PORT_HUB_TENANT
PORT_HUB_API_URL=$PORT_HUB_API_URL
PORT_HUB_MACHINE_ID=$PORT_HUB_MACHINE_ID
PORT_HUB_MACHINE_TOKEN=$PORT_HUB_MACHINE_TOKEN
PORT_HUB_AUTH_URL=$PORT_HUB_AUTH_URL
PORT_HUB_SYNC_URL=$PORT_HUB_SYNC_URL
PORT_HUB_CONFIG_TOML_URL=$PORT_HUB_CONFIG_TOML_URL
PORT_HUB_CHANGES_TOML_URL=$PORT_HUB_CHANGES_TOML_URL
PORT_HUB_LOG_STREAM_STATUS_URL=$PORT_HUB_LOG_STREAM_STATUS_URL
PORT_HUB_LOG_STREAM_UPLOAD_URL=$PORT_HUB_LOG_STREAM_UPLOAD_URL
PORT_HUB_RATHOLE_X86_64_URL=$PORT_HUB_RATHOLE_X86_64_URL
PORT_HUB_RATHOLE_DARWIN_X86_64_URL=$PORT_HUB_RATHOLE_DARWIN_X86_64_URL
PORT_HUB_RATHOLE_ARM64_URL=$PORT_HUB_RATHOLE_ARM64_URL
PORT_HUB_RATHOLE_ARMHF_URL=$PORT_HUB_RATHOLE_ARMHF_URL
PORT_HUB_RATHOLE_ARMV7_URL=$PORT_HUB_RATHOLE_ARMV7_URL
PORT_HUB_HEARTBEAT_INTERVAL_SECONDS=$PORT_HUB_HEARTBEAT_INTERVAL_SECONDS
PORT_HUB_CHANGES_WAIT_SECONDS=$PORT_HUB_CHANGES_WAIT_SECONDS
PORT_HUB_LOG_MAX_BYTES=$PORT_HUB_LOG_MAX_BYTES
PORT_HUB_AUTH_FAILURE_RETRY_SECONDS=$PORT_HUB_AUTH_FAILURE_RETRY_SECONDS
PORT_HUB_PUBLIC_IP_REFRESH_SECONDS=$PORT_HUB_PUBLIC_IP_REFRESH_SECONDS
PORT_HUB_ENABLE_DEBUG_LOGS=$PORT_HUB_ENABLE_DEBUG_LOGS
PORT_HUB_PUBLIC_IP_OVERRIDE=$PORT_HUB_PUBLIC_IP_OVERRIDE
PORT_HUB_SELF_PATH=$PORT_HUB_SELF_PATH
EOF_ENV
}

write_rathole_config_file() {
  local source_file="$1"
  if [ -f "$PORT_HUB_CONFIG_FILE" ]; then
    cat "$source_file" | ${SUDO:-} tee "$PORT_HUB_CONFIG_FILE" >/dev/null
    ${SUDO:-} chmod 600 "$PORT_HUB_CONFIG_FILE"
  else
    ${SUDO:-} install -m 600 "$source_file" "$PORT_HUB_CONFIG_FILE"
  fi
  # Touch the final path so Rathole's config watcher sees a direct file modification.
  ${SUDO:-} touch "$PORT_HUB_CONFIG_FILE"
}

validate_configuration() {
  require_value "PortHub API URL" "$PORT_HUB_API_URL"
  require_value "machine id" "$PORT_HUB_MACHINE_ID"
  require_value "machine token" "$PORT_HUB_MACHINE_TOKEN"
  require_value "PortHub auth URL" "$PORT_HUB_AUTH_URL"
  require_value "PortHub sync URL" "$PORT_HUB_SYNC_URL"
  require_value "PortHub config URL" "$PORT_HUB_CONFIG_TOML_URL"
  require_value "PortHub changes URL" "$PORT_HUB_CHANGES_TOML_URL"
  require_value "PortHub log stream status URL" "$PORT_HUB_LOG_STREAM_STATUS_URL"
  require_value "PortHub log stream upload URL" "$PORT_HUB_LOG_STREAM_UPLOAD_URL"
  require_http_url "PortHub API URL" "$PORT_HUB_API_URL"
  require_http_url "PortHub auth URL" "$PORT_HUB_AUTH_URL"
  require_http_url "PortHub sync URL" "$PORT_HUB_SYNC_URL"
  require_http_url "PortHub config URL" "$PORT_HUB_CONFIG_TOML_URL"
  require_http_url "PortHub changes URL" "$PORT_HUB_CHANGES_TOML_URL"
  require_http_url "PortHub log stream status URL" "$PORT_HUB_LOG_STREAM_STATUS_URL"
  require_http_url "PortHub log stream upload URL" "$PORT_HUB_LOG_STREAM_UPLOAD_URL"
}

require_configured_machine() {
  resolve_selected_tenant_context
  [ -f "$PORT_HUB_ENV_FILE" ] || fail "PortHub is not configured on this machine. Run the bootstrap/install command from the PortHub server first."
}

build_sync_payload() {
  local active="${1:-true}"
  local host_name local_ip public_ip
  host_name="$(detect_hostname)"
  local_ip="$(detect_local_ip)"
  public_ip="$(detect_public_ip)"
  cat <<EOF_JSON
{"machine_id":"$(json_escape "$PORT_HUB_MACHINE_ID")","token":"$(json_escape "$PORT_HUB_MACHINE_TOKEN")","hostname":"$(json_escape "$host_name")","local_ip":"$(json_escape "$local_ip")","public_ip":"$(json_escape "$public_ip")","is_active":$active,"client_version":"$(json_escape "$(client_version)")","client_update_last_handled_request_id":"$(json_escape "$(state_get PORT_HUB_CLIENT_UPDATE_LAST_HANDLED_REQUEST_ID)")"}
EOF_JSON
}

persist_shared_runtime() {
  local host_name local_ip public_ip
  host_name="$(detect_hostname)"
  local_ip="$(detect_local_ip)"
  public_ip="$(detect_public_ip)"
  write_state \
    "$(state_get PORT_HUB_CURRENT_VERSION)" \
    "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
    "$host_name" \
    "$local_ip" \
    "$public_ip" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)"
}

machine_post() {
  local endpoint="$1"
  local active="${2:-true}"
  local tmp_headers observed_public_ip tmp_headers_file tmp_body http_code now
  tmp_headers_file="${TMPDIR:-/tmp}/porthub-machine-post.$$.$RANDOM.headers"
  tmp_body="${TMPDIR:-/tmp}/porthub-machine-post.$$.$RANDOM.body"
  : >"$tmp_headers_file"
  http_code="$(curl --silent --show-error --location -D "$tmp_headers_file" -o "$tmp_body" -w "%{http_code}" -X POST "$endpoint" \
    -H "Content-Type: application/json" \
    --data "$(build_sync_payload "$active")" || true)"
  now="$(date +%s)"
  case "$http_code" in
    200|201)
      handle_client_control_headers "$tmp_headers_file"
      persist_shared_runtime
      observed_public_ip="$(extract_header "X-PortHub-Observed-IP" "$tmp_headers_file")"
      debug_log "Machine sync posted to $endpoint (active=$active observed_ip=${observed_public_ip:-unknown})"
      write_state \
        "$(state_get PORT_HUB_CURRENT_VERSION)" \
        "$now" \
        "$(state_get PORT_HUB_SERVICE_MANAGER)" \
        "$([ "$endpoint" = "$PORT_HUB_AUTH_URL" ] && printf "%s" "$now" || state_get PORT_HUB_LAST_AUTH_EPOCH)" \
        "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
        "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
        "${observed_public_ip:-$(state_get PORT_HUB_SHARED_PUBLIC_IP)}" \
        "$(state_get PORT_HUB_RATHOLE_PID)" \
        "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
        "$(state_get PORT_HUB_SHARED_SERVICES)" \
        "$now" \
        "false" \
        "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
        "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
        "false"
      rm -f "$tmp_headers_file" "$tmp_body"
      return 0
      ;;
    403)
      if [ "$(extract_header "X-PortHub-Machine-Disabled" "$tmp_headers_file")" = "true" ]; then
        write_state \
          "$(state_get PORT_HUB_CURRENT_VERSION)" \
          "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
          "$(state_get PORT_HUB_SERVICE_MANAGER)" \
          "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
          "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
          "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
          "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
          "$(state_get PORT_HUB_RATHOLE_PID)" \
          "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
          "$(state_get PORT_HUB_SHARED_SERVICES)" \
          "$now" \
          "false" \
          "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
          "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
          "true"
        rm -f "$tmp_headers_file" "$tmp_body"
        return 20
      fi
      ;;
  esac
  rm -f "$tmp_headers_file" "$tmp_body"
  return 1
}

machine_log_stream_requested() {
  local tmp_headers active auth_required now
  tmp_headers="$(mktemp)"
  if ! curl --silent --show-error --location -D "$tmp_headers" -o /dev/null "$PORT_HUB_LOG_STREAM_STATUS_URL"; then
    rm -f "$tmp_headers"
    return 1
  fi
  active="$(extract_header "X-PortHub-Log-Stream-Active" "$tmp_headers")"
  auth_required="$(extract_header "X-PortHub-Machine-Auth-Required" "$tmp_headers")"
  now="$(date +%s)"
  write_state \
    "$(state_get PORT_HUB_CURRENT_VERSION)" \
    "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
    "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
    "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
    "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
    "$(state_get PORT_HUB_SHARED_SERVICES)" \
    "$now" \
    "${auth_required:-false}" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
    "$(state_get PORT_HUB_MACHINE_DISABLED)"
  rm -f "$tmp_headers"
  [ "$active" = "true" ]
}

upload_log_batch() {
  local payload="" line escaped count=0
  for line in "$@"; do
    [ -n "$line" ] || continue
    escaped="$(json_escape "$line")"
    if [ "$count" -gt 0 ]; then
      payload="${payload},"
    fi
    payload="${payload}\"${escaped}\""
    count=$((count + 1))
  done
  [ "$count" -gt 0 ] || return 0
  curl --silent --show-error --fail --location \
    -X POST "$PORT_HUB_LOG_STREAM_UPLOAD_URL" \
    -H "Content-Type: application/json" \
    --data "{\"machine_id\":\"$(json_escape "$PORT_HUB_MACHINE_ID")\",\"token\":\"$(json_escape "$PORT_HUB_MACHINE_TOKEN")\",\"source\":\"client\",\"lines\":[${payload}]}" \
    >/dev/null 2>&1 || true
}

stream_logs_worker_cmd() {
  resolve_selected_tenant_context
  load_env
  validate_configuration
  touch "$PORT_HUB_LOG_FILE" 2>/dev/null || true

  local batch_size="${1:-8}" flush_seconds="${2:-2}" initial_lines="${3:-3}" line
  local -a batch=()

  if [ "$initial_lines" -gt 0 ] 2>/dev/null && [ -f "$PORT_HUB_LOG_FILE" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      batch+=("$line")
      if [ "${#batch[@]}" -ge "$batch_size" ]; then
        upload_log_batch "${batch[@]}"
        batch=()
      fi
    done < <(tail -n "$initial_lines" "$PORT_HUB_LOG_FILE" 2>/dev/null || true)

    if [ "${#batch[@]}" -gt 0 ]; then
      upload_log_batch "${batch[@]}"
      batch=()
    fi
  fi

  tail -n 0 -F "$PORT_HUB_LOG_FILE" 2>/dev/null | while true; do
    if IFS= read -r -t "$flush_seconds" line; then
      batch+=("$line")
      if [ "${#batch[@]}" -ge "$batch_size" ]; then
        upload_log_batch "${batch[@]}"
        batch=()
      fi
    else
      if [ "${#batch[@]}" -gt 0 ]; then
        upload_log_batch "${batch[@]}"
        batch=()
      fi
    fi
  done
}

log_stream_supervisor_cmd() {
  resolve_selected_tenant_context
  load_env
  validate_configuration

  local check_interval="${1:-5}" batch_size="${2:-8}" flush_seconds="${3:-2}" initial_lines="${4:-3}"
  local log_stream_pid=""

  shutdown_supervisor() {
    if [ -n "$log_stream_pid" ] && kill -0 "$log_stream_pid" 2>/dev/null; then
      kill "$log_stream_pid" 2>/dev/null || true
      wait "$log_stream_pid" 2>/dev/null || true
    fi
    exit 0
  }

  trap shutdown_supervisor INT TERM

  while true; do
    if machine_log_stream_requested; then
      if [ -z "$log_stream_pid" ] || ! kill -0 "$log_stream_pid" 2>/dev/null; then
        run_self_cmd __stream-logs-worker "$batch_size" "$flush_seconds" "$initial_lines" >/dev/null 2>&1 &
        log_stream_pid="$!"
      fi
    else
      if [ -n "$log_stream_pid" ] && kill -0 "$log_stream_pid" 2>/dev/null; then
        kill "$log_stream_pid" 2>/dev/null || true
        wait "$log_stream_pid" 2>/dev/null || true
        log_stream_pid=""
      fi
    fi

    sleep "$check_interval"
  done
}

configure_cmd() {
  step "Configuring PortHub client"
  detect_sudo
  resolve_selected_tenant_context
  load_env

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --api-url|--server-url) PORT_HUB_API_URL="$2"; shift 2 ;;
      --machine-id) PORT_HUB_MACHINE_ID="$2"; shift 2 ;;
      --machine-token) PORT_HUB_MACHINE_TOKEN="$2"; shift 2 ;;
      --auth-url) PORT_HUB_AUTH_URL="$2"; shift 2 ;;
      --sync-url) PORT_HUB_SYNC_URL="$2"; shift 2 ;;
      --config-url|--config-toml-url) PORT_HUB_CONFIG_TOML_URL="$2"; shift 2 ;;
      --changes-url|--changes-toml-url) PORT_HUB_CHANGES_TOML_URL="$2"; shift 2 ;;
      --log-stream-status-url) PORT_HUB_LOG_STREAM_STATUS_URL="$2"; shift 2 ;;
      --log-stream-upload-url) PORT_HUB_LOG_STREAM_UPLOAD_URL="$2"; shift 2 ;;
      --rathole-x86-url|--rathole-x86-64-url) PORT_HUB_RATHOLE_X86_64_URL="$2"; shift 2 ;;
      --rathole-darwin-x86-64-url) PORT_HUB_RATHOLE_DARWIN_X86_64_URL="$2"; shift 2 ;;
      --rathole-arm-url|--rathole-armhf-url) PORT_HUB_RATHOLE_ARMHF_URL="$2"; shift 2 ;;
      --rathole-arm64-url) PORT_HUB_RATHOLE_ARM64_URL="$2"; shift 2 ;;
      --rathole-armv7-url) PORT_HUB_RATHOLE_ARMV7_URL="$2"; shift 2 ;;
      --heartbeat-seconds) PORT_HUB_HEARTBEAT_INTERVAL_SECONDS="$2"; shift 2 ;;
      --changes-wait-seconds) PORT_HUB_CHANGES_WAIT_SECONDS="$2"; shift 2 ;;
      --log-max-bytes) PORT_HUB_LOG_MAX_BYTES="$2"; shift 2 ;;
      --public-ip-refresh-seconds) PORT_HUB_PUBLIC_IP_REFRESH_SECONDS="$2"; shift 2 ;;
      --debug-logs) PORT_HUB_ENABLE_DEBUG_LOGS="$2"; shift 2 ;;
      --public-ip) PORT_HUB_PUBLIC_IP_OVERRIDE="$2"; shift 2 ;;
      --self-path) PORT_HUB_SELF_PATH="$2"; shift 2 ;;
      *)
        fail "Unknown configure option: $1"
        ;;
    esac
  done

  refresh_derived_urls

  write_env_file
  log "INFO" "Wrote config to $PORT_HUB_ENV_FILE"
}

select_rathole_url() {
  local os_name arch
  os_name="$(uname -s)"
  arch="$(uname -m)"
  case "$os_name:$arch" in
    Linux:x86_64|Linux:amd64) printf "%s" "$PORT_HUB_RATHOLE_X86_64_URL" ;;
    Linux:aarch64|Linux:arm64) printf "%s" "$PORT_HUB_RATHOLE_ARM64_URL" ;;
    Linux:armv7l) printf "%s" "$PORT_HUB_RATHOLE_ARMV7_URL" ;;
    Linux:armv6l|Linux:armhf|Linux:arm) printf "%s" "$PORT_HUB_RATHOLE_ARMHF_URL" ;;
    Darwin:x86_64) printf "%s" "$PORT_HUB_RATHOLE_DARWIN_X86_64_URL" ;;
    Darwin:arm64) printf "%s" "$PORT_HUB_RATHOLE_DARWIN_X86_64_URL" ;;
    *)
      fail "Unsupported platform: $os_name $arch"
      ;;
  esac
}

ensure_rosetta_if_needed() {
  if [ "$(uname -s)" = "Darwin" ] && [ "$(uname -m)" = "arm64" ]; then
    if ! /usr/sbin/pkgutil --pkg-info com.apple.pkg.RosettaUpdateAuto >/dev/null 2>&1; then
      fail "Apple Silicon macOS currently needs Rosetta 2 for Rathole. Install it with: softwareupdate --install-rosetta --agree-to-license"
    fi
  fi
}

install_rathole_cmd() {
  step "Installing Rathole"
  detect_sudo
  resolve_selected_tenant_context
  load_env
  validate_configuration
  ensure_dirs
  need_cmd curl
  need_cmd install
  need_cmd mktemp
  ensure_rosetta_if_needed
  local download_url tmp_file
  download_url="$(select_rathole_url)"
  require_value "Rathole download URL" "$download_url"
  require_http_url "Rathole download URL" "$download_url"
  tmp_file="$(mktemp)"
  log "INFO" "Rathole target: $(uname -s) $(uname -m)"
  curl --fail --show-error --location "$download_url" -o "$tmp_file"
  ${SUDO:-} install -m 755 "$tmp_file" "$PORT_HUB_RATHOLE_BIN"
  rm -f "$tmp_file"
  log "INFO" "Installed Rathole to $PORT_HUB_RATHOLE_BIN"
}

fetch_config_cmd() {
  step "Fetching PortHub machine config"
  detect_sudo
  resolve_selected_tenant_context
  load_env
  validate_configuration
  ensure_dirs
  need_cmd curl
  need_cmd install
  need_cmd mktemp
  local tmp_body tmp_headers version shared_services http_code
  tmp_body="$(mktemp)"
  tmp_headers="$(mktemp)"
  http_code="$(curl --silent --show-error --location -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" "$PORT_HUB_CONFIG_TOML_URL" || true)"
  if [ "$http_code" = "403" ] && [ "$(extract_header "X-PortHub-Machine-Disabled" "$tmp_headers")" = "true" ]; then
    write_state \
      "$(state_get PORT_HUB_CURRENT_VERSION)" \
      "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
      "$(state_get PORT_HUB_SERVICE_MANAGER)" \
      "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
      "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
      "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
      "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
      "$(state_get PORT_HUB_RATHOLE_PID)" \
      "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
      "$(state_get PORT_HUB_SHARED_SERVICES)" \
      "$(date +%s)" \
      "false" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
      "true"
    rm -f "$tmp_body" "$tmp_headers"
    return 20
  fi
  [ "$http_code" = "200" ] || { rm -f "$tmp_body" "$tmp_headers"; return 1; }
  version="$(extract_header "X-PortHub-Config-Version" "$tmp_headers")"
  [ -n "$version" ] || { rm -f "$tmp_body" "$tmp_headers"; fail "Missing PortHub config version header"; }
  shared_services="$(count_services_in_file "$tmp_body")"
  write_rathole_config_file "$tmp_body"
  rm -f "$tmp_body" "$tmp_headers"
  write_state \
    "$version" \
    "$(date +%s)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
    "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
    "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
    "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
    "$shared_services" \
    "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
    "$(state_get PORT_HUB_AUTH_REQUIRED)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
    "false"
  log "INFO" "Fetched config version $version"
}

preflight_cmd() {
  step "Checking installation prerequisites"
  detect_sudo
  resolve_selected_tenant_context
  load_env
  validate_configuration
  detect_supported_platform
  need_cmd curl
  need_cmd awk
  need_cmd install
  need_cmd tail
  need_cmd date
  need_cmd tee
  need_cmd mkdir
  need_cmd cp
  need_cmd wc
  need_cmd hostname
  need_cmd mktemp
  case "$(service_manager)" in
    systemd|launchd) ;;
    *)
      fail "Persistent background operation requires systemd on Linux or launchd on macOS."
      ;;
  esac
  ensure_rosetta_if_needed
  ensure_dirs
  local rathole_url tmp_headers version
  rathole_url="$(select_rathole_url)"
  require_value "Rathole download URL" "$rathole_url"
  require_http_url "Rathole download URL" "$rathole_url"
  tmp_headers="$(mktemp)"
  curl --fail --show-error --location -D "$tmp_headers" -o /dev/null "$PORT_HUB_CONFIG_TOML_URL"
  version="$(extract_header "X-PortHub-Config-Version" "$tmp_headers")"
  rm -f "$tmp_headers"
  [ -n "$version" ] || fail "PortHub config endpoint did not return a config version"
  log "INFO" "OS: $(uname -s)"
  log "INFO" "Arch: $(uname -m)"
  log "INFO" "Service manager: $(service_manager)"
  log "INFO" "Config dir: $PORT_HUB_DIR"
  log "INFO" "Log file: $PORT_HUB_LOG_FILE"
  log "INFO" "Machine id: $PORT_HUB_MACHINE_ID"
  log "INFO" "Config endpoint: OK (version $version)"
  log "INFO" "Rathole download endpoint: configured"
}

service_manager() {
  case "$(uname -s)" in
    Darwin) printf "launchd" ;;
    Linux)
      if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        printf "systemd"
      else
        printf "unsupported"
      fi
      ;;
    *)
      printf "unsupported"
      ;;
  esac
}

write_service_file() {
  local manager exec_start launchd_tenant_arguments=""
  manager="$(service_manager)"
  exec_start="$PORT_HUB_SELF_PATH __service-run"
  if [ -n "$PORT_HUB_TENANT" ]; then
    exec_start="$exec_start --tenant $PORT_HUB_TENANT"
    launchd_tenant_arguments="$(printf '    <string>--tenant</string>\n    <string>%s</string>\n' "$PORT_HUB_TENANT")"
  fi
  case "$manager" in
    systemd)
      cat <<EOF_SYSTEMD | ${SUDO:-} tee "$PORT_HUB_SERVICE_FILE" >/dev/null
[Unit]
Description=PortHub client ($(tenant_display_name))
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart=$exec_start

[Install]
WantedBy=multi-user.target
EOF_SYSTEMD
      ;;
    launchd)
      cat <<EOF_LAUNCHD | ${SUDO:-} tee "$PORT_HUB_SERVICE_FILE" >/dev/null
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$PORT_HUB_SERVICE_LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PORT_HUB_SELF_PATH</string>
    <string>__service-run</string>
$launchd_tenant_arguments  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>WorkingDirectory</key>
  <string>$PORT_HUB_DIR</string>
</dict>
</plist>
EOF_LAUNCHD
      ;;
    *)
      fail "Persistent PortHub service requires systemd on Linux or launchd on macOS."
      ;;
  esac
}

service_enable_and_start() {
  local manager
  manager="$(service_manager)"
  case "$manager" in
    systemd)
      ${SUDO:-} systemctl daemon-reload
      ${SUDO:-} systemctl enable "$PORT_HUB_SERVICE_LABEL" >/dev/null
      ${SUDO:-} systemctl restart "$PORT_HUB_SERVICE_LABEL"
      ;;
    launchd)
      ${SUDO:-} launchctl bootout system "$PORT_HUB_SERVICE_FILE" >/dev/null 2>&1 || true
      ${SUDO:-} launchctl bootstrap system "$PORT_HUB_SERVICE_FILE"
      ${SUDO:-} launchctl enable "system/$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1 || true
      ${SUDO:-} launchctl kickstart -k "system/$PORT_HUB_SERVICE_LABEL"
      ;;
    *)
      fail "Unsupported service manager."
      ;;
  esac
  save_state "$(state_get PORT_HUB_CURRENT_VERSION)" "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" "$manager"
}

service_disable_and_stop() {
  local manager
  manager="$(service_manager)"
  case "$manager" in
    systemd)
      ${SUDO:-} systemctl disable --now "$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1 || true
      ;;
    launchd)
      ${SUDO:-} launchctl bootout system "$PORT_HUB_SERVICE_FILE" >/dev/null 2>&1 || true
      ${SUDO:-} launchctl disable "system/$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1 || true
      ;;
    *)
      fail "Unsupported service manager."
      ;;
  esac
}

remove_managed_path() {
  local target="$1"
  local label="$2"
  [ -n "$target" ] || return 0
  case "$target" in
    /|.|..)
      fail "Refusing to remove unsafe ${label} path: $target"
      ;;
  esac
  if [ -e "$target" ] || [ -L "$target" ]; then
    ${SUDO:-} rm -rf "$target"
    log_plain "[porthub-uninstall] Removed ${label}: $target"
  fi
}

remove_dir_if_empty() {
  local target="$1"
  local label="$2"
  [ -n "$target" ] || return 0
  case "$target" in
    /|.|..)
      fail "Refusing to remove unsafe ${label} path: $target"
      ;;
  esac
  if [ -d "$target" ]; then
    ${SUDO:-} rmdir "$target" >/dev/null 2>&1 || true
  fi
}

stop_recorded_rathole_process() {
  local pid="" found_pid=""
  local -a managed_pids=()
  if [ -f "$PORT_HUB_STATE_FILE" ]; then
    pid="$(state_get PORT_HUB_RATHOLE_PID)"
    if [ -n "$pid" ]; then
      managed_pids+=("$pid")
    fi
  fi
  if [ -z "$pid" ] && [ -f "$PORT_HUB_PID_FILE" ]; then
    pid="$(cat "$PORT_HUB_PID_FILE" 2>/dev/null || true)"
    if [ -n "$pid" ]; then
      managed_pids+=("$pid")
    fi
  fi

  while IFS= read -r found_pid; do
    [ -n "$found_pid" ] || continue
    managed_pids+=("$found_pid")
  done < <(
    ps -eo pid=,args= 2>/dev/null | awk -v bin="$PORT_HUB_RATHOLE_BIN" -v cfg="$PORT_HUB_CONFIG_FILE" '
      index($0, bin) > 0 && index($0, cfg) > 0 { print $1 }
    '
  )

  if [ "${#managed_pids[@]}" -eq 0 ]; then
    return 0
  fi

  for pid in "${managed_pids[@]}"; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
      ${SUDO:-} kill "$pid" >/dev/null 2>&1 || true
      log_plain "[porthub-uninstall] Stopped Rathole process $pid"
    fi
  done
}

remove_service_definition() {
  case "$(uname -s)" in
    Linux)
      if command -v systemctl >/dev/null 2>&1; then
        ${SUDO:-} systemctl disable --now "$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1 || true
      fi
      remove_managed_path "$PORT_HUB_SERVICE_FILE" "service file"
      if command -v systemctl >/dev/null 2>&1; then
        ${SUDO:-} systemctl daemon-reload >/dev/null 2>&1 || true
        ${SUDO:-} systemctl reset-failed "$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1 || true
      fi
      ;;
    Darwin)
      if command -v launchctl >/dev/null 2>&1; then
        ${SUDO:-} launchctl bootout system "$PORT_HUB_SERVICE_FILE" >/dev/null 2>&1 || true
        ${SUDO:-} launchctl disable "system/$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1 || true
      fi
      remove_managed_path "$PORT_HUB_SERVICE_FILE" "service file"
      ;;
    *)
      remove_managed_path "$PORT_HUB_SERVICE_FILE" "service file"
      ;;
  esac
}

service_status() {
  local manager
  manager="$(service_manager)"
  case "$manager" in
    systemd)
      if systemctl is-active --quiet "$PORT_HUB_SERVICE_LABEL" 2>/dev/null; then
        printf "running"
      else
        printf "stopped"
      fi
      ;;
    launchd)
      if launchctl print "system/$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1; then
        printf "running"
      else
        printf "stopped"
      fi
      ;;
    *)
      printf "unsupported"
      ;;
  esac
}

up_cmd() {
  step "Preparing persistent PortHub service"
  detect_sudo
  resolve_selected_tenant_context
  load_env
  validate_configuration
  need_cmd curl
  need_cmd awk
  need_cmd install
  ensure_dirs
  install_rathole_cmd
  if machine_post "$PORT_HUB_AUTH_URL" true; then
    :
  else
    rc="$?"
    if [ "$rc" -eq 20 ]; then
      fail "This machine is disabled in PortHub. Re-enable it from the server before running 'porthub up'."
    fi
    fail "Could not authenticate machine against PortHub server"
  fi
  write_state \
    "$(state_get PORT_HUB_CURRENT_VERSION)" \
    "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(date +%s)" \
    "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
    "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
    "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
    "$(state_get PORT_HUB_SHARED_SERVICES)" \
    "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
    "$(state_get PORT_HUB_AUTH_REQUIRED)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
    "false"
  log "INFO" "Authenticated machine against PortHub server"
  if ! fetch_config_cmd; then
    if [ "$?" -eq 20 ]; then
      fail "This machine is disabled in PortHub. Re-enable it from the server before running 'porthub up'."
    fi
    fail "Could not fetch PortHub machine config"
  fi
  write_service_file
  service_enable_and_start
  log "INFO" "PortHub service is up and persistent across restart"
}

down_cmd() {
  step "Stopping PortHub service"
  detect_sudo
  resolve_selected_tenant_context
  load_env
  service_disable_and_stop
  machine_post "$PORT_HUB_SYNC_URL" false || true
  log "INFO" "PortHub stopped"
}

uninstall_cmd() {
  local remove_all="false"
  local previous_tenant="${PORT_HUB_TENANT:-}"
  local tenant_name tenant_count

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --all) remove_all="true"; shift ;;
      *) fail "Unknown uninstall option: $1" ;;
    esac
  done

  step "Uninstalling PortHub client"
  detect_sudo

  if [ "$remove_all" = "true" ]; then
    collect_configured_tenants
    for tenant_name in "${CONFIGURED_TENANTS[@]}"; do
      PORT_HUB_EXPLICIT_TENANT="$tenant_name"
      apply_tenant_context "$tenant_name"
      load_saved_env_if_present

      if [ -f "$PORT_HUB_ENV_FILE" ] && [ -n "${PORT_HUB_API_URL:-}" ] && [ -n "${PORT_HUB_MACHINE_ID:-}" ] && [ -n "${PORT_HUB_MACHINE_TOKEN:-}" ]; then
        refresh_derived_urls
        machine_post "$PORT_HUB_SYNC_URL" false || true
      fi

      remove_service_definition
      stop_recorded_rathole_process
      remove_managed_path "$PORT_HUB_ENV_FILE" "environment file"
      remove_managed_path "$PORT_HUB_STATE_FILE" "state file"
      remove_managed_path "$PORT_HUB_CONFIG_FILE" "Rathole config"
      remove_managed_path "$PORT_HUB_PID_FILE" "pid file"
      remove_managed_path "$PORT_HUB_LOG_FILE" "log file"
      remove_managed_path "$PORT_HUB_LOG_BACKUP_FILE" "log backup"
      remove_dir_if_empty "$PORT_HUB_RUNTIME_DIR" "runtime dir"
      remove_dir_if_empty "$PORT_HUB_LOG_DIR" "log dir"
      remove_dir_if_empty "$PORT_HUB_DIR" "config dir"
    done

    apply_tenant_context ""
    remove_managed_path "$PORT_HUB_RATHOLE_BIN" "Rathole binary"
    remove_managed_path "$PORT_HUB_SELF_PATH" "PortHub CLI"
    remove_dir_if_empty "$PORT_HUB_BIN_DIR" "bin dir"
    remove_dir_if_empty "$PORT_HUB_TENANTS_DIR" "tenants dir"
    remove_dir_if_empty "$PORT_HUB_RUNTIME_ROOT" "runtime root"
    remove_dir_if_empty "$PORT_HUB_LOG_ROOT" "log root"
    remove_dir_if_empty "$PORT_HUB_ROOT_DIR" "config root"
    log_plain "[porthub-uninstall] PortHub client fully uninstalled"
    return 0
  fi

  resolve_selected_tenant_context
  load_saved_env_if_present

  if [ -f "$PORT_HUB_ENV_FILE" ]; then
    if [ -n "${PORT_HUB_API_URL:-}" ] && [ -n "${PORT_HUB_MACHINE_ID:-}" ] && [ -n "${PORT_HUB_MACHINE_TOKEN:-}" ]; then
      refresh_derived_urls
      machine_post "$PORT_HUB_SYNC_URL" false || true
    fi
  fi

  remove_service_definition
  stop_recorded_rathole_process

  remove_managed_path "$PORT_HUB_ENV_FILE" "environment file"
  remove_managed_path "$PORT_HUB_STATE_FILE" "state file"
  remove_managed_path "$PORT_HUB_CONFIG_FILE" "Rathole config"
  remove_managed_path "$PORT_HUB_PID_FILE" "pid file"
  remove_managed_path "$PORT_HUB_LOG_FILE" "log file"
  remove_managed_path "$PORT_HUB_LOG_BACKUP_FILE" "log backup"

  remove_dir_if_empty "$PORT_HUB_RUNTIME_DIR" "runtime dir"
  remove_dir_if_empty "$PORT_HUB_LOG_DIR" "log dir"
  remove_dir_if_empty "$PORT_HUB_DIR" "config dir"

  tenant_count="$(configured_tenant_count)"
  if [ "$tenant_count" -eq 0 ] 2>/dev/null; then
    apply_tenant_context ""
    remove_managed_path "$PORT_HUB_RATHOLE_BIN" "Rathole binary"
    remove_managed_path "$PORT_HUB_SELF_PATH" "PortHub CLI"
    remove_dir_if_empty "$PORT_HUB_BIN_DIR" "bin dir"
    remove_dir_if_empty "$PORT_HUB_TENANTS_DIR" "tenants dir"
    remove_dir_if_empty "$PORT_HUB_RUNTIME_ROOT" "runtime root"
    remove_dir_if_empty "$PORT_HUB_LOG_ROOT" "log root"
    remove_dir_if_empty "$PORT_HUB_ROOT_DIR" "config root"
    log_plain "[porthub-uninstall] PortHub client fully uninstalled"
  else
    log_plain "[porthub-uninstall] Tenant $(tenant_display_name "$PORT_HUB_TENANT") uninstalled; shared PortHub CLI remains for other tenants"
  fi

  PORT_HUB_EXPLICIT_TENANT="$previous_tenant"
  apply_tenant_context "$previous_tenant"
}

status_cmd() {
  resolve_selected_tenant_context
  load_env
  local service_state manager config_version last_sync last_auth last_contact shared_hostname
  local shared_local_ip shared_public_ip rathole_state rathole_pid rathole_started_at
  local shared_services auth_required machine_disabled
  manager="$(service_manager)"
  service_state="$(service_status)"
  config_version="$(state_get PORT_HUB_CURRENT_VERSION)"
  last_sync="$(state_get PORT_HUB_LAST_SYNC_EPOCH)"
  last_auth="$(state_get PORT_HUB_LAST_AUTH_EPOCH)"
  last_contact="$(state_get PORT_HUB_LAST_CONTACT_EPOCH)"
  shared_hostname="$(state_get PORT_HUB_SHARED_HOSTNAME)"
  shared_local_ip="$(state_get PORT_HUB_SHARED_LOCAL_IP)"
  shared_public_ip="$(state_get PORT_HUB_SHARED_PUBLIC_IP)"
  rathole_state="$(rathole_runtime_status)"
  rathole_pid="$(state_get PORT_HUB_RATHOLE_PID)"
  rathole_started_at="$(state_get PORT_HUB_RATHOLE_STARTED_AT)"
  shared_services="$(count_shared_services)"
  auth_required="$(state_get PORT_HUB_AUTH_REQUIRED)"
  machine_disabled="$(state_get PORT_HUB_MACHINE_DISABLED)"
  cat <<EOF_STATUS
PortHub Status
tenant: $(tenant_display_name)
machine_id: $PORT_HUB_MACHINE_ID
client_version: $(client_version)
rathole_version: $(rathole_version)
connection_status: $(connection_status)
auth_required: ${auth_required:-false}
machine_disabled: ${machine_disabled:-false}
service_manager: $manager
service_state: $service_state
rathole_state: $rathole_state
rathole_pid: ${rathole_pid:-n/a}
rathole_started_at: $(format_epoch_with_relative "$rathole_started_at")
last_successful_auth: $(format_epoch_with_relative "$last_auth")
last_successful_sync: $(format_epoch_with_relative "$last_sync")
last_server_contact: $(format_epoch_with_relative "$last_contact")
config_version: ${config_version:-unknown}
shared_services: $shared_services
shared_hostname: ${shared_hostname:-unknown}
shared_local_ip: ${shared_local_ip:-unknown}
shared_public_ip: ${shared_public_ip:-not set}
log_file: $PORT_HUB_LOG_FILE
EOF_STATUS
}

version_cmd() {
  resolve_selected_tenant_context
  load_env
  cat <<EOF_VERSION
PortHub Version
tenant: $(tenant_display_name)
client_version: $(client_version)
rathole_version: $(rathole_version)
EOF_VERSION
}

restart_cmd() {
  step "Restarting PortHub service"
  detect_sudo
  resolve_selected_tenant_context
  load_env
  service_enable_and_start
  log "INFO" "PortHub service restarted"
}

config_cmd() {
  resolve_selected_tenant_context
  [ -f "$PORT_HUB_ENV_FILE" ] || fail "No config found at $PORT_HUB_ENV_FILE"
  cat "$PORT_HUB_ENV_FILE"
}

print_rathole_config() {
  resolve_selected_tenant_context
  load_env
  if [ ! -f "$PORT_HUB_CONFIG_FILE" ]; then
    fail "No Rathole config found at $PORT_HUB_CONFIG_FILE"
  fi

  if [ -r "$PORT_HUB_CONFIG_FILE" ]; then
    cat "$PORT_HUB_CONFIG_FILE"
    return
  fi

  detect_sudo
  ${SUDO:-} cat "$PORT_HUB_CONFIG_FILE"
}

rathole_config_cmd() {
  local watch_mode="false"
  local interval_seconds="2"
  local current_snapshot=""
  local next_snapshot=""

  while [ "$#" -gt 0 ]; do
    case "$1" in
      -w|--watch) watch_mode="true"; shift ;;
      --interval)
        [ "$#" -ge 2 ] || fail "Missing value for --interval"
        interval_seconds="$2"
        shift 2
        ;;
      --interval=*)
        interval_seconds="${1#*=}"
        shift
        ;;
      *)
        fail "Unknown rathole config option: $1"
        ;;
    esac
  done

  if [ "$watch_mode" != "true" ]; then
    print_rathole_config
    return
  fi

  current_snapshot="$(print_rathole_config)"
  printf "%s\n" "$current_snapshot"
  while true; do
    sleep "$interval_seconds"
    next_snapshot="$(print_rathole_config)"
    if [ "$next_snapshot" != "$current_snapshot" ]; then
      printf "\n# Updated %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
      printf "%s\n" "$next_snapshot"
      current_snapshot="$next_snapshot"
    fi
  done
}

rathole_cmd() {
  local subcommand="${1:-config}"
  if [ "$#" -gt 0 ]; then
    shift
  fi

  case "$subcommand" in
    config) rathole_config_cmd "$@" ;;
    help|-h|--help|"")
      cat <<EOF_RATHOLE_USAGE
Usage: porthub rathole <subcommand> [options]

Subcommands:
  config            Print the tenant Rathole config

Options for 'porthub rathole config':
  -w, --watch       Watch the config and print updates when it changes
  --interval N      Poll interval in seconds for watch mode (default: 2)
EOF_RATHOLE_USAGE
      ;;
    *)
      fail "Unknown rathole subcommand: $subcommand"
      ;;
  esac
}

update_token_cmd() {
  local new_token="${1:-}"
  step "Updating saved machine token"
  detect_sudo
  require_configured_machine
  load_env
  [ -n "$new_token" ] || fail "Usage: porthub update-token <new-machine-token>"
  PORT_HUB_MACHINE_TOKEN="$new_token"
  refresh_derived_urls
  validate_configuration
  write_env_file
  write_state \
    "$(state_get PORT_HUB_CURRENT_VERSION)" \
    "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
    "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
    "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
    "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
    "$(state_get PORT_HUB_SHARED_SERVICES)" \
    "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
    "false"
  log "INFO" "Saved updated machine token"
  if [ "$(service_status)" = "running" ]; then
    service_enable_and_start
    log "INFO" "Restarted PortHub service with updated token"
  else
    log "INFO" "PortHub service is not running. Run 'porthub up' when ready."
  fi
}

update_cmd() {
  step "Updating PortHub CLI from server"
  detect_sudo
  require_configured_machine
  load_env
  validate_configuration
  need_cmd curl
  need_cmd install
  need_cmd mktemp
  local cli_url tmp_file service_state pending_request_id previous_version installed_version
  cli_url="$(build_cli_download_url)"
  pending_request_id="$(state_get PORT_HUB_CLIENT_UPDATE_REQUEST_ID)"
  previous_version="$(client_version)"
  if [ -n "$pending_request_id" ]; then
    log "INFO" "Starting client reinstall for request $pending_request_id"
  fi
  tmp_file="$(mktemp)"
  if ! curl --fail --show-error --location "$cli_url" -o "$tmp_file"; then
    rm -f "$tmp_file"
    fail "Could not download the latest PortHub CLI. If this machine token was refreshed, run 'porthub update-token <new-token>' or 'porthub reinstall' with the refreshed installer."
  fi
  ${SUDO:-} install -m 755 "$tmp_file" "$PORT_HUB_SELF_PATH"
  rm -f "$tmp_file"
  installed_version="$(installed_cli_version "$PORT_HUB_SELF_PATH")"
  if [ "$installed_version" = "$previous_version" ]; then
    log "INFO" "Reinstalled PortHub CLI version $installed_version at $PORT_HUB_SELF_PATH"
  else
    log "INFO" "Updated PortHub CLI from version $previous_version to $installed_version at $PORT_HUB_SELF_PATH"
  fi
  if ! run_self_cmd preflight; then
    log "WARN" "PortHub CLI was updated, but preflight could not complete. If the machine token changed, run 'porthub update-token <new-token>' and retry."
    return 0
  fi
  if ! run_self_cmd install-rathole; then
    log "WARN" "PortHub CLI was updated, but Rathole could not be refreshed. If the machine token changed, run 'porthub update-token <new-token>' and retry."
    return 0
  fi
  write_state \
    "$(state_get PORT_HUB_CURRENT_VERSION)" \
    "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
    "$(state_get PORT_HUB_SERVICE_MANAGER)" \
    "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
    "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
    "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
    "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_RATHOLE_PID)" \
    "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
    "$(state_get PORT_HUB_SHARED_SERVICES)" \
    "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
    "$(state_get PORT_HUB_AUTH_REQUIRED)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
    "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
    "$(state_get PORT_HUB_MACHINE_DISABLED)" \
    "" \
    "" \
    "" \
    "$pending_request_id"
  if [ -n "$pending_request_id" ]; then
    log "INFO" "Client reinstall completed for request $pending_request_id"
  fi
  service_state="$(service_status)"
  if [ "$service_state" = "running" ]; then
    run_self_cmd restart
  else
    log "INFO" "PortHub service is not running. Run 'porthub up' when ready."
  fi
}

reinstall_cmd() {
  step "Reinstalling PortHub from server"
  detect_sudo
  require_configured_machine
  load_env
  validate_configuration
  need_cmd curl
  need_cmd mktemp
  local install_url tmp_file
  install_url="$(build_install_script_url)"
  tmp_file="$(mktemp)"
  curl --fail --show-error --location "$install_url" -o "$tmp_file"
  chmod +x "$tmp_file"
  if [ -n "$PORT_HUB_TENANT" ]; then
    "$tmp_file" --install-path "$PORT_HUB_SELF_PATH" --tenant "$PORT_HUB_TENANT"
  else
    "$tmp_file" --install-path "$PORT_HUB_SELF_PATH"
  fi
  rm -f "$tmp_file"
}

logs_cmd() {
  step "Reading PortHub logs"
  resolve_selected_tenant_context
  local follow="false"
  local lines="100"
  local verbose="false"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -f|--follow) follow="true"; shift ;;
      --verbose) verbose="true"; shift ;;
      -n|--lines) lines="$2"; shift 2 ;;
      *) fail "Unknown logs option: $1" ;;
    esac
  done
  [ -f "$PORT_HUB_LOG_FILE" ] || fail "No logs available yet at $PORT_HUB_LOG_FILE"
  if [ "$verbose" = "true" ]; then
    if [ "$follow" = "true" ]; then
      tail -n "$lines" -f "$PORT_HUB_LOG_FILE"
    else
      tail -n "$lines" "$PORT_HUB_LOG_FILE"
    fi
    return
  fi
  if [ "$follow" = "true" ]; then
    tail -n "$lines" -f "$PORT_HUB_LOG_FILE" | awk '!/\[DEBUG\]/ { print; fflush() }'
  else
    tail -n "$lines" "$PORT_HUB_LOG_FILE" | awk '!/\[DEBUG\]/ { print }'
  fi
}

env_file_value() {
  local file_path="$1"
  local key="$2"
  [ -f "$file_path" ] || return 0
  awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "$file_path"
}

tenants_list_cmd() {
  local previous_tenant="${PORT_HUB_TENANT:-}"
  local tenant_name api_url machine_id service_state

  collect_configured_tenants
  if [ "${#CONFIGURED_TENANTS[@]}" -eq 0 ]; then
    cat <<EOF_TENANTS_EMPTY
PortHub Tenants
configured: 0
EOF_TENANTS_EMPTY
    return 0
  fi

  printf "PortHub Tenants\n"
  for tenant_name in "${CONFIGURED_TENANTS[@]}"; do
    apply_tenant_context "$tenant_name"
    api_url="$(env_file_value "$PORT_HUB_ENV_FILE" PORT_HUB_API_URL)"
    machine_id="$(env_file_value "$PORT_HUB_ENV_FILE" PORT_HUB_MACHINE_ID)"
    service_state="$(service_status)"
    printf -- "- %s machine_id=%s service=%s api=%s\n" \
      "$(tenant_display_name "$tenant_name")" \
      "${machine_id:-unknown}" \
      "$service_state" \
      "${api_url:-unknown}"
  done
  apply_tenant_context "$previous_tenant"
}

tenants_add_cmd() {
  local auto_up="true"
  local machine_id="$PORT_HUB_DEFAULT_MACHINE_ID"
  local previous_tenant="${PORT_HUB_EXPLICIT_TENANT:-}"
  local -a configure_args=()

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --machine-id)
        [ "$#" -ge 2 ] || fail "Missing value for --machine-id"
        machine_id="$2"
        configure_args+=("$1" "$2")
        shift 2
        ;;
      --machine-id=*)
        machine_id="${1#*=}"
        configure_args+=("$1")
        shift
        ;;
      --no-start)
        auto_up="false"
        shift
        ;;
      *)
        configure_args+=("$1")
        shift
        ;;
    esac
  done

  if [ -z "${PORT_HUB_EXPLICIT_TENANT:-}" ]; then
    [ -n "$machine_id" ] || fail "Missing machine id for tenant bootstrap"
    PORT_HUB_EXPLICIT_TENANT="$machine_id"
  fi

  configure_cmd "${configure_args[@]}"
  preflight_cmd
  install_rathole_cmd
  if [ "$auto_up" = "true" ]; then
    up_cmd
  else
    log_plain "[porthub-tenants] Tenant $(tenant_display_name "$PORT_HUB_EXPLICIT_TENANT") configured. Run 'porthub start -t $(tenant_display_name "$PORT_HUB_EXPLICIT_TENANT")' when ready."
  fi

  PORT_HUB_EXPLICIT_TENANT="$previous_tenant"
  apply_tenant_context "$previous_tenant"
}

tenants_remove_cmd() {
  local tenant_name="${1:-${PORT_HUB_EXPLICIT_TENANT:-}}"
  [ -n "$tenant_name" ] || fail "Usage: porthub tenants remove <tenant>"
  PORT_HUB_EXPLICIT_TENANT="$(resolve_tenant_reference "$tenant_name")"
  uninstall_cmd
}

tenants_cmd() {
  local subcommand="${1:-list}"
  if [ "$#" -gt 0 ]; then
    shift
  fi

  case "$subcommand" in
    list|ls) tenants_list_cmd "$@" ;;
    add) tenants_add_cmd "$@" ;;
    remove|rm|delete) tenants_remove_cmd "$@" ;;
    help|-h|--help|"")
      cat <<EOF_TENANTS_USAGE
Usage: porthub tenants <subcommand> [options]

Subcommands:
  list              Show configured PortHub tenants
  add               Configure and optionally start a tenant
  remove <tenant>   Remove one tenant; use 'porthub uninstall --all' to remove everything

Tenant references accept exact names or unique prefixes.
EOF_TENANTS_USAGE
      ;;
    *)
      fail "Unknown tenants subcommand: $subcommand"
      ;;
  esac
}

poll_for_change() {
  local current_version tmp_body tmp_headers http_code version url shared_services
  current_version="$(state_get PORT_HUB_CURRENT_VERSION)"
  [ -n "$current_version" ] || current_version="initial"
  tmp_body="$(mktemp)"
  tmp_headers="$(mktemp)"
  url="${PORT_HUB_CHANGES_TOML_URL}&since=${current_version}&wait_seconds=${PORT_HUB_CHANGES_WAIT_SECONDS:-25}"
  debug_log "Polling for config changes since version ${current_version}"
  http_code="$(curl --silent --show-error -D "$tmp_headers" -o "$tmp_body" -w "%{http_code}" "$url" || true)"
  case "$http_code" in
    200)
      handle_client_control_headers "$tmp_headers"
      version="$(extract_header "X-PortHub-Config-Version" "$tmp_headers")"
      [ -n "$version" ] || { rm -f "$tmp_body" "$tmp_headers"; fail "Missing PortHub config version header"; }
      shared_services="$(count_services_in_file "$tmp_body")"
      write_rathole_config_file "$tmp_body"
      write_state \
        "$version" \
        "$(date +%s)" \
        "$(state_get PORT_HUB_SERVICE_MANAGER)" \
        "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
        "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
        "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
        "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
        "$(state_get PORT_HUB_RATHOLE_PID)" \
        "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
        "$shared_services" \
        "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
        "$(state_get PORT_HUB_AUTH_REQUIRED)" \
        "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
        "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
        "false"
      debug_log "Downloaded updated config version ${version} with ${shared_services} shared services"
      rm -f "$tmp_body" "$tmp_headers"
      return 10
      ;;
    204)
      handle_client_control_headers "$tmp_headers"
      version="$(extract_header "X-PortHub-Config-Version" "$tmp_headers")"
      [ -n "$version" ] && save_state "$version" "$(date +%s)" "$(state_get PORT_HUB_SERVICE_MANAGER)"
      debug_log "No config change detected (version ${version:-$current_version})"
      rm -f "$tmp_body" "$tmp_headers"
      return 0
      ;;
    403)
      if [ "$(extract_header "X-PortHub-Machine-Disabled" "$tmp_headers")" = "true" ]; then
        write_state \
          "$(state_get PORT_HUB_CURRENT_VERSION)" \
          "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
          "$(state_get PORT_HUB_SERVICE_MANAGER)" \
          "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
          "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
          "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
          "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
          "$(state_get PORT_HUB_RATHOLE_PID)" \
          "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
          "$(state_get PORT_HUB_SHARED_SERVICES)" \
          "$(date +%s)" \
          "false" \
          "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
          "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
          "true"
        rm -f "$tmp_body" "$tmp_headers"
        return 20
      fi
      debug_log "Config poll rejected with HTTP status 403"
      rm -f "$tmp_body" "$tmp_headers"
      return 1
      ;;
    *)
      debug_log "Config poll failed with HTTP status ${http_code:-unknown}"
      rm -f "$tmp_body" "$tmp_headers"
      return 1
      ;;
  esac
}

service_run_cmd() {
  step "Running PortHub background service"
  detect_sudo
  resolve_selected_tenant_context
  load_env
  validate_configuration
  need_cmd curl
  need_cmd awk
  need_cmd install
  need_cmd mktemp
  ensure_dirs
  local rathole_pid="" log_stream_supervisor_pid="" last_sync now rc
  local auth_retry_seconds loop_sleep_seconds auth_required_mode disabled_mode

  start_rathole() {
    rotate_logs_if_needed
    if [ -n "$rathole_pid" ] && kill -0 "$rathole_pid" 2>/dev/null; then
      kill "$rathole_pid" 2>/dev/null || true
      wait "$rathole_pid" 2>/dev/null || true
    fi
    "$PORT_HUB_RATHOLE_BIN" -c "$PORT_HUB_CONFIG_FILE" >>"$PORT_HUB_LOG_FILE" 2>&1 &
    rathole_pid="$!"
    write_state \
      "$(state_get PORT_HUB_CURRENT_VERSION)" \
      "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
      "$(state_get PORT_HUB_SERVICE_MANAGER)" \
      "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
      "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
      "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
      "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
      "$rathole_pid" \
      "$(date +%s)"
    log "INFO" "Started Rathole with pid $rathole_pid"
  }

  stop_rathole() {
    if [ -n "$rathole_pid" ] && kill -0 "$rathole_pid" 2>/dev/null; then
      kill "$rathole_pid" 2>/dev/null || true
      wait "$rathole_pid" 2>/dev/null || true
    fi
    rathole_pid=""
    write_state \
      "$(state_get PORT_HUB_CURRENT_VERSION)" \
      "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
      "$(state_get PORT_HUB_SERVICE_MANAGER)" \
      "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
      "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
      "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
      "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
      "" \
      "" \
      "$(state_get PORT_HUB_SHARED_SERVICES)" \
      "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
      "$(state_get PORT_HUB_AUTH_REQUIRED)" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
      "$(state_get PORT_HUB_MACHINE_DISABLED)"
  }

  shutdown_service() {
    if [ -n "$log_stream_supervisor_pid" ] && kill -0 "$log_stream_supervisor_pid" 2>/dev/null; then
      kill "$log_stream_supervisor_pid" 2>/dev/null || true
      wait "$log_stream_supervisor_pid" 2>/dev/null || true
    fi
    machine_post "$PORT_HUB_SYNC_URL" false || true
    stop_rathole
    write_state \
      "$(state_get PORT_HUB_CURRENT_VERSION)" \
      "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
      "$(state_get PORT_HUB_SERVICE_MANAGER)" \
      "$(state_get PORT_HUB_LAST_AUTH_EPOCH)" \
      "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
      "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
      "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
      "" \
      "" \
      "$(state_get PORT_HUB_SHARED_SERVICES)" \
      "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
      "$(state_get PORT_HUB_AUTH_REQUIRED)" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
      "$(state_get PORT_HUB_MACHINE_DISABLED)"
    log "INFO" "PortHub service stopped"
    exit 0
  }

  trap shutdown_service INT TERM

  [ -x "$PORT_HUB_RATHOLE_BIN" ] || install_rathole_cmd
  if machine_post "$PORT_HUB_AUTH_URL" true; then
    write_state \
      "$(state_get PORT_HUB_CURRENT_VERSION)" \
      "$(state_get PORT_HUB_LAST_SYNC_EPOCH)" \
      "$(state_get PORT_HUB_SERVICE_MANAGER)" \
      "$(date +%s)" \
      "$(state_get PORT_HUB_SHARED_HOSTNAME)" \
      "$(state_get PORT_HUB_SHARED_LOCAL_IP)" \
      "$(state_get PORT_HUB_SHARED_PUBLIC_IP)" \
      "$(state_get PORT_HUB_RATHOLE_PID)" \
      "$(state_get PORT_HUB_RATHOLE_STARTED_AT)" \
      "$(state_get PORT_HUB_SHARED_SERVICES)" \
      "$(state_get PORT_HUB_LAST_CONTACT_EPOCH)" \
      "$(state_get PORT_HUB_AUTH_REQUIRED)" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP)" \
      "$(state_get PORT_HUB_CACHED_PUBLIC_IP_FETCHED_AT)" \
      "false"
    log "INFO" "Authenticated machine against PortHub server"
    if fetch_config_cmd; then
      start_rathole
    else
      rc="$?"
      if [ "$rc" -eq 20 ]; then
      log "WARN" "Machine is disabled in PortHub; Rathole will stay stopped until it is re-enabled"
      else
        fail "Could not fetch PortHub machine config"
      fi
    fi
  else
    rc="$?"
    if [ "$rc" -eq 20 ]; then
    log "WARN" "Machine is disabled in PortHub; Rathole will stay stopped until it is re-enabled"
    else
      fail "Could not authenticate machine against PortHub server"
    fi
  fi
  run_self_cmd __log-stream-supervisor 5 8 2 3 >/dev/null 2>&1 &
  log_stream_supervisor_pid="$!"
  last_sync="$(date +%s)"

  while true; do
    rotate_logs_if_needed
    now="$(date +%s)"
    auth_retry_seconds="$(auth_failure_retry_seconds)"
    auth_required_mode="false"
    disabled_mode="false"
    if [ "$(state_get PORT_HUB_AUTH_REQUIRED)" = "true" ]; then
      auth_required_mode="true"
    fi
    if [ "$(state_get PORT_HUB_MACHINE_DISABLED)" = "true" ]; then
      disabled_mode="true"
    fi

    if [ "$disabled_mode" = "true" ]; then
      stop_rathole
      if [ $((now - last_sync)) -ge "${PORT_HUB_HEARTBEAT_INTERVAL_SECONDS:-30}" ]; then
        if machine_post "$PORT_HUB_AUTH_URL" true; then
          log "INFO" "Machine was re-enabled in PortHub; resuming Rathole"
          if fetch_config_cmd; then
            start_rathole
          else
            rc="$?"
            if [ "$rc" -ne 20 ]; then
              log "WARN" "Config fetch after re-enable failed"
            fi
          fi
          last_sync="$now"
        else
          rc="$?"
          if [ "$rc" -ne 20 ]; then
          log "WARN" "Disabled-machine retry failed"
          sleep "$auth_retry_seconds"
          fi
        fi
      else
        sleep 5
      fi
      continue
    fi

    if [ "$auth_required_mode" != "true" ] && [ $((now - last_sync)) -ge "${PORT_HUB_HEARTBEAT_INTERVAL_SECONDS:-30}" ]; then
      if machine_post "$PORT_HUB_SYNC_URL" true; then
        save_state "$(state_get PORT_HUB_CURRENT_VERSION)" "$now" "$(state_get PORT_HUB_SERVICE_MANAGER)"
        last_sync="$now"
        debug_log "Heartbeat succeeded at $(format_epoch "$now")"
      elif [ "$?" -eq 20 ]; then
        log "WARN" "Machine was disabled in PortHub; stopping Rathole"
        stop_rathole
        last_sync="$now"
      else
        log "WARN" "Heartbeat failed"
        sleep "$auth_retry_seconds"
      fi
    fi

    if [ "$auth_required_mode" != "true" ]; then
      if poll_for_change; then
        :
      else
        rc="$?"
        if [ "$rc" -eq 10 ]; then
          log "INFO" "Received updated config version $(state_get PORT_HUB_CURRENT_VERSION)"
          if [ -n "$rathole_pid" ] && kill -0 "$rathole_pid" 2>/dev/null; then
            log "INFO" "Updated config written; waiting for Rathole hot-reload"
          else
            start_rathole
          fi
        elif [ "$rc" -eq 20 ]; then
          log "WARN" "Machine was disabled in PortHub; stopping Rathole"
          stop_rathole
        else
          log "WARN" "Config poll failed; retrying"
          sleep "$auth_retry_seconds"
        fi
      fi
    else
      loop_sleep_seconds="10"
      if [ "$auth_retry_seconds" -lt "$loop_sleep_seconds" ] 2>/dev/null; then
        loop_sleep_seconds="$auth_retry_seconds"
      fi
      sleep "$loop_sleep_seconds"
    fi

    if [ -n "$rathole_pid" ] && ! kill -0 "$rathole_pid" 2>/dev/null; then
      log "WARN" "Rathole exited unexpectedly; restarting"
      start_rathole
    fi
  done
}

usage() {
  cat <<EOF_USAGE
Usage: porthub <command> [options]

Global options:
  -t, --tenant NAME  Operate on a tenant by exact name or unique prefix

Commands:
  ls, list          Show configured tenants
  add               Add a tenant and start it
  remove            Remove one tenant; use 'uninstall --all' to remove everything
  start             Start the selected tenant
  stop              Stop the selected tenant
  restart           Restart the selected tenant
  status            Show status for the selected tenant
  logs              Show logs for the selected tenant
  update            Update the shared PortHub CLI and Rathole using the selected tenant
  version           Show installed PortHub client and Rathole versions
  tenants           Full tenant management subcommands
  adv               Show advanced maintenance commands
EOF_USAGE
}

advanced_usage() {
  cat <<EOF_ADVANCED
PortHub Advanced Commands

Public maintenance:
  configure         Write or update the selected tenant settings
  update-token      Save a new machine token for the selected tenant
  preflight         Check prerequisites for the selected tenant
  install-rathole   Download or refresh the shared Rathole binary
  config            Print the saved tenant config
  rathole config    Print the local Rathole client config (-w to watch)
  rathole-config    Print the local Rathole client config
  reinstall         Re-run the server installer for the selected tenant
  uninstall         Remove the selected tenant; use --all to remove everything
  sync              Send an immediate active heartbeat
  sync-inactive     Send an immediate inactive heartbeat
  fetch-config      Download the current Rathole client config
EOF_ADVANCED
}

main() {
  local command="${1:-}"
  local help_topic=""
  if [ "$#" -gt 0 ]; then
    shift
  fi
  if [ "$command" = "help" ] && [ "$#" -gt 0 ]; then
    help_topic="${1:-}"
    shift
  fi
  parse_global_cli_options "$@"
  set -- "${PARSED_GLOBAL_ARGS[@]}"
  case "$command" in
    list|ls) tenants_list_cmd "$@" ;;
    tenant|tenants) tenants_cmd "$@" ;;
    add) tenants_add_cmd "$@" ;;
    remove|rm)
      if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; then
        tenants_remove_cmd "$@"
      else
        uninstall_cmd "$@"
      fi
      ;;
    start|up) up_cmd "$@" ;;
    stop|down) down_cmd "$@" ;;
    configure) configure_cmd "$@" ;;
    update-token) update_token_cmd "$@" ;;
    preflight) preflight_cmd "$@" ;;
    install-rathole) install_rathole_cmd "$@" ;;
    uninstall) uninstall_cmd "$@" ;;
    restart) restart_cmd "$@" ;;
    status) status_cmd "$@" ;;
    version|-v|--version) version_cmd "$@" ;;
    logs) logs_cmd "$@" ;;
    config) config_cmd "$@" ;;
    rathole) rathole_cmd "$@" ;;
    rathole-config) rathole_config_cmd "$@" ;;
    update) update_cmd "$@" ;;
    reinstall) reinstall_cmd "$@" ;;
    sync) resolve_selected_tenant_context; load_env; machine_post "$PORT_HUB_SYNC_URL" true ;;
    sync-inactive) resolve_selected_tenant_context; load_env; machine_post "$PORT_HUB_SYNC_URL" false ;;
    fetch-config) fetch_config_cmd "$@" ;;
    __service-run) service_run_cmd "$@" ;;
    __stream-logs-worker) stream_logs_worker_cmd "$@" ;;
    __log-stream-supervisor) log_stream_supervisor_cmd "$@" ;;
    adv) advanced_usage ;;
    help)
      case "$help_topic" in
        advanced) advanced_usage ;;
        tenants|tenant) tenants_cmd help ;;
        "" ) usage ;;
        *) fail "Unknown help topic: $help_topic" ;;
      esac
      ;;
    -h|--help|"") usage ;;
    *) fail "Unknown command: $command" ;;
  esac
}

main "$@"
