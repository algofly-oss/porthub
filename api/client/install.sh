#!/usr/bin/env bash
set -euo pipefail

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
PORT_HUB_DEFAULT_CLI_URL="__PORT_HUB_CLI_URL__"
PORT_HUB_DEFAULT_HEARTBEAT_INTERVAL_SECONDS="30"
PORT_HUB_DEFAULT_CHANGES_WAIT_SECONDS="25"

PORT_HUB_INSTALL_PATH="${PORT_HUB_INSTALL_PATH:-/usr/local/bin/porthub}"
PORT_HUB_TENANT="${PORT_HUB_TENANT:-}"
PORT_HUB_PUBLIC_IP_OVERRIDE="${PORT_HUB_PUBLIC_IP_OVERRIDE:-}"
PORT_HUB_AUTO_UP="true"
CURRENT_STEP="bootstrap"
PORT_HUB_SELF_INSTALL_SCRIPT="${0:-}"

log() { printf "[porthub-install] %s\n" "$*" >&2; }
fail() { log "$*"; exit 1; }
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
extract_url_host() {
  local value="${1:-}"
  value="${value#*://}"
  value="${value%%/*}"
  value="${value%%:*}"
  printf "%s" "$value"
}
slugify_tenant_part() {
  local value="${1:-}"
  value="$(printf "%s" "$value" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-')"
  value="$(printf "%s" "$value" | sed 's/^-*//; s/-*$//; s/--*/-/g')"
  printf "%s" "$value"
}
derive_default_tenant_name() {
  local api_url="${1:-}"
  local machine_id="${2:-}"
  local host_slug machine_suffix
  host_slug="$(slugify_tenant_part "$(extract_url_host "$api_url")")"
  [ -n "$host_slug" ] || host_slug="porthub"
  machine_suffix="$machine_id"
  if [ "${#machine_suffix}" -gt 8 ]; then
    machine_suffix="${machine_suffix: -8}"
  fi
  [ -n "$machine_suffix" ] || machine_suffix="tenant"
  printf "%s-%s" "$machine_suffix" "$host_slug"
}
step() {
  CURRENT_STEP="$1"
  log "$CURRENT_STEP"
}
trap 'rc=$?; log "Install failed during: ${CURRENT_STEP} (exit ${rc})"' ERR

cleanup_self_install_script() {
  local script_path="${PORT_HUB_SELF_INSTALL_SCRIPT:-}"
  [ -n "$script_path" ] || return 0
  case "$(basename -- "$script_path")" in
    install.sh) ;;
    *) return 0 ;;
  esac
  [ -f "$script_path" ] || return 0
  rm -f -- "$script_path" 2>/dev/null || true
}

trap cleanup_self_install_script EXIT

service_manager_name() {
  case "$(uname -s)" in
    Darwin) printf "launchd" ;;
    *) printf "systemd" ;;
  esac
}

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

detect_platform() {
  case "$(uname -s)" in
    Linux|Darwin) return 0 ;;
    *)
      fail "Unsupported operating system: $(uname -s). Supported: Linux, macOS."
      ;;
  esac
}

install_runtime_dependencies() {
  local missing=()
  local brew_cmd=""

  if ! command -v lighttpd >/dev/null 2>&1; then
    missing+=("lighttpd")
  fi
  if ! command -v aria2c >/dev/null 2>&1; then
    missing+=("aria2")
  fi

  if [ "${#missing[@]}" -eq 0 ]; then
    log "Runtime helpers already installed: lighttpd, aria2c"
    return 0
  fi

  step "Installing runtime helper packages (${missing[*]})"
  case "$(uname -s)" in
    Darwin)
      brew_cmd="$(command -v brew || true)"
      [ -n "$brew_cmd" ] || fail "Missing required command: brew. Install Homebrew to provision lighttpd and aria2."
      "$brew_cmd" install "${missing[@]}"
      ;;
    Linux)
      if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update
        $SUDO apt-get install -y "${missing[@]}"
      elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y "${missing[@]}"
      elif command -v yum >/dev/null 2>&1; then
        $SUDO yum install -y "${missing[@]}"
      elif command -v zypper >/dev/null 2>&1; then
        $SUDO zypper --non-interactive install "${missing[@]}"
      elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm "${missing[@]}"
      elif command -v apk >/dev/null 2>&1; then
        $SUDO apk add --no-cache "${missing[@]}"
      else
        fail "Could not find a supported package manager to install lighttpd and aria2."
      fi
      ;;
    *)
      fail "Unsupported operating system: $(uname -s). Supported: Linux, macOS."
      ;;
  esac

  command -v lighttpd >/dev/null 2>&1 || fail "lighttpd install completed but the binary is still unavailable"
  command -v aria2c >/dev/null 2>&1 || fail "aria2 install completed but the aria2c binary is still unavailable"
  log "Runtime helpers installed successfully"
}

check_service_manager() {
  case "$(uname -s)" in
    Linux)
      command -v systemctl >/dev/null 2>&1 || fail "Linux install requires systemd/systemctl."
      [ -d /run/systemd/system ] || fail "Linux install requires a running systemd environment."
      ;;
    Darwin)
      command -v launchctl >/dev/null 2>&1 || fail "macOS install requires launchctl."
      ;;
  esac
}

preflight() {
  step "Running preflight checks"
  detect_platform
  detect_sudo
  need_cmd curl
  need_cmd install
  need_cmd tail
  need_cmd mktemp
  check_service_manager
  require_value "PortHub CLI download URL" "$PORT_HUB_CLI_URL"
  require_value "machine id" "$PORT_HUB_MACHINE_ID"
  require_value "machine token" "$PORT_HUB_MACHINE_TOKEN"
  require_http_url "PortHub CLI download URL" "$PORT_HUB_CLI_URL"
  require_http_url "PortHub API URL" "$PORT_HUB_API_URL"
  log "OS: $(uname -s)"
  log "Arch: $(uname -m)"
  log "Install path: $PORT_HUB_INSTALL_PATH"
  log "Service manager: $(service_manager_name)"
  log "Tenant: ${PORT_HUB_TENANT:-$PORT_HUB_MACHINE_ID}"
  log "Machine id: $PORT_HUB_MACHINE_ID"
  log "PortHub endpoint configuration: OK"
}

usage() {
  cat <<EOF_USAGE
Usage: install.sh [options]

Options:
  --api-url URL
  --server-url URL
  --machine-id ID
  --machine-token TOKEN
  --tenant NAME
  --auth-url URL
  --sync-url URL
  --config-url URL
  --changes-url URL
  --log-stream-status-url URL
  --log-stream-upload-url URL
  --rathole-x86-64-url URL
  --rathole-darwin-x86-64-url URL
  --rathole-arm64-url URL
  --rathole-armhf-url URL
  --rathole-armv7-url URL
  --cli-url URL
  --heartbeat-seconds N
  --changes-wait-seconds N
  --public-ip IP
  --install-path PATH
  --no-start
  --help
EOF_USAGE
}

PORT_HUB_API_URL="$PORT_HUB_DEFAULT_API_URL"
PORT_HUB_MACHINE_ID="$PORT_HUB_DEFAULT_MACHINE_ID"
PORT_HUB_MACHINE_TOKEN="$PORT_HUB_DEFAULT_MACHINE_TOKEN"
PORT_HUB_AUTH_URL="$PORT_HUB_DEFAULT_AUTH_URL"
PORT_HUB_SYNC_URL="$PORT_HUB_DEFAULT_SYNC_URL"
PORT_HUB_CONFIG_TOML_URL="$PORT_HUB_DEFAULT_CONFIG_TOML_URL"
PORT_HUB_CHANGES_TOML_URL="$PORT_HUB_DEFAULT_CHANGES_TOML_URL"
PORT_HUB_LOG_STREAM_STATUS_URL="$PORT_HUB_DEFAULT_LOG_STREAM_STATUS_URL"
PORT_HUB_LOG_STREAM_UPLOAD_URL="$PORT_HUB_DEFAULT_LOG_STREAM_UPLOAD_URL"
PORT_HUB_RATHOLE_X86_64_URL="$PORT_HUB_DEFAULT_RATHOLE_X86_64_URL"
PORT_HUB_RATHOLE_DARWIN_X86_64_URL="$PORT_HUB_DEFAULT_RATHOLE_DARWIN_X86_64_URL"
PORT_HUB_RATHOLE_ARM64_URL="$PORT_HUB_DEFAULT_RATHOLE_ARM64_URL"
PORT_HUB_RATHOLE_ARMHF_URL="$PORT_HUB_DEFAULT_RATHOLE_ARMHF_URL"
PORT_HUB_RATHOLE_ARMV7_URL="$PORT_HUB_DEFAULT_RATHOLE_ARMV7_URL"
PORT_HUB_CLI_URL="$PORT_HUB_DEFAULT_CLI_URL"
PORT_HUB_HEARTBEAT_INTERVAL_SECONDS="$PORT_HUB_DEFAULT_HEARTBEAT_INTERVAL_SECONDS"
PORT_HUB_CHANGES_WAIT_SECONDS="$PORT_HUB_DEFAULT_CHANGES_WAIT_SECONDS"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api-url|--server-url) PORT_HUB_API_URL="$2"; shift 2 ;;
    --machine-id) PORT_HUB_MACHINE_ID="$2"; shift 2 ;;
    --machine-token) PORT_HUB_MACHINE_TOKEN="$2"; shift 2 ;;
    --tenant) PORT_HUB_TENANT="$2"; shift 2 ;;
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
    --cli-url) PORT_HUB_CLI_URL="$2"; shift 2 ;;
    --heartbeat-seconds) PORT_HUB_HEARTBEAT_INTERVAL_SECONDS="$2"; shift 2 ;;
    --changes-wait-seconds) PORT_HUB_CHANGES_WAIT_SECONDS="$2"; shift 2 ;;
    --public-ip) PORT_HUB_PUBLIC_IP_OVERRIDE="$2"; shift 2 ;;
    --install-path) PORT_HUB_INSTALL_PATH="$2"; shift 2 ;;
    --no-start) PORT_HUB_AUTO_UP="false"; shift ;;
    --help|-h) usage; exit 0 ;;
    *)
      fail "Unknown option: $1"
      ;;
  esac
done

if [ -z "$PORT_HUB_TENANT" ]; then
  PORT_HUB_TENANT="$(derive_default_tenant_name "$PORT_HUB_API_URL" "$PORT_HUB_MACHINE_ID")"
fi

main() {
  preflight

  local tmp_file install_dir
  install_runtime_dependencies
  step "Downloading PortHub CLI from server"
  install_dir="${PORT_HUB_INSTALL_PATH%/*}"
  if [ -z "$install_dir" ] || [ "$install_dir" = "$PORT_HUB_INSTALL_PATH" ]; then
    install_dir="."
  fi
  $SUDO mkdir -p "$install_dir"
  tmp_file="$(mktemp)"
  curl --fail --show-error --location "$PORT_HUB_CLI_URL" -o "$tmp_file"
  $SUDO install -m 755 "$tmp_file" "$PORT_HUB_INSTALL_PATH"
  rm -f "$tmp_file"
  "$PORT_HUB_INSTALL_PATH" help >/dev/null
  log "Installed PortHub CLI at $PORT_HUB_INSTALL_PATH"

  step "Configuring PortHub tenant"
  if [ "$PORT_HUB_AUTO_UP" = "true" ]; then
    "$PORT_HUB_INSTALL_PATH" tenants add \
      --tenant "$PORT_HUB_TENANT" \
      --api-url "$PORT_HUB_API_URL" \
      --machine-id "$PORT_HUB_MACHINE_ID" \
      --machine-token "$PORT_HUB_MACHINE_TOKEN" \
      --auth-url "$PORT_HUB_AUTH_URL" \
      --sync-url "$PORT_HUB_SYNC_URL" \
      --config-toml-url "$PORT_HUB_CONFIG_TOML_URL" \
      --changes-toml-url "$PORT_HUB_CHANGES_TOML_URL" \
      --log-stream-status-url "$PORT_HUB_LOG_STREAM_STATUS_URL" \
      --log-stream-upload-url "$PORT_HUB_LOG_STREAM_UPLOAD_URL" \
      --rathole-x86-64-url "$PORT_HUB_RATHOLE_X86_64_URL" \
      --rathole-darwin-x86-64-url "$PORT_HUB_RATHOLE_DARWIN_X86_64_URL" \
      --rathole-arm64-url "$PORT_HUB_RATHOLE_ARM64_URL" \
      --rathole-armhf-url "$PORT_HUB_RATHOLE_ARMHF_URL" \
      --rathole-armv7-url "$PORT_HUB_RATHOLE_ARMV7_URL" \
      --heartbeat-seconds "$PORT_HUB_HEARTBEAT_INTERVAL_SECONDS" \
      --changes-wait-seconds "$PORT_HUB_CHANGES_WAIT_SECONDS" \
      --public-ip "$PORT_HUB_PUBLIC_IP_OVERRIDE" \
      --self-path "$PORT_HUB_INSTALL_PATH"
  else
    "$PORT_HUB_INSTALL_PATH" tenants add \
      --tenant "$PORT_HUB_TENANT" \
      --api-url "$PORT_HUB_API_URL" \
      --machine-id "$PORT_HUB_MACHINE_ID" \
      --machine-token "$PORT_HUB_MACHINE_TOKEN" \
      --auth-url "$PORT_HUB_AUTH_URL" \
      --sync-url "$PORT_HUB_SYNC_URL" \
      --config-toml-url "$PORT_HUB_CONFIG_TOML_URL" \
      --changes-toml-url "$PORT_HUB_CHANGES_TOML_URL" \
      --log-stream-status-url "$PORT_HUB_LOG_STREAM_STATUS_URL" \
      --log-stream-upload-url "$PORT_HUB_LOG_STREAM_UPLOAD_URL" \
      --rathole-x86-64-url "$PORT_HUB_RATHOLE_X86_64_URL" \
      --rathole-darwin-x86-64-url "$PORT_HUB_RATHOLE_DARWIN_X86_64_URL" \
      --rathole-arm64-url "$PORT_HUB_RATHOLE_ARM64_URL" \
      --rathole-armhf-url "$PORT_HUB_RATHOLE_ARMHF_URL" \
      --rathole-armv7-url "$PORT_HUB_RATHOLE_ARMV7_URL" \
      --heartbeat-seconds "$PORT_HUB_HEARTBEAT_INTERVAL_SECONDS" \
      --changes-wait-seconds "$PORT_HUB_CHANGES_WAIT_SECONDS" \
      --public-ip "$PORT_HUB_PUBLIC_IP_OVERRIDE" \
      --self-path "$PORT_HUB_INSTALL_PATH" \
      --no-start
  fi

  step "Installation completed"
  if [ "$PORT_HUB_AUTO_UP" = "true" ]; then
    log "PortHub tenant is up. Try: porthub status $PORT_HUB_TENANT"
    log "Live logs: porthub logs $PORT_HUB_TENANT -f"
    log "Stop tenant: porthub stop $PORT_HUB_TENANT"
    log "Remove tenant: porthub remove $PORT_HUB_TENANT"
  else
    log "Run 'porthub start $PORT_HUB_TENANT' when ready."
  fi
}

main "$@"
