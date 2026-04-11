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
PORT_HUB_PUBLIC_IP_OVERRIDE="${PORT_HUB_PUBLIC_IP_OVERRIDE:-}"
PORT_HUB_AUTO_UP="true"
CURRENT_STEP="bootstrap"

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
step() {
  CURRENT_STEP="$1"
  log "$CURRENT_STEP"
}
trap 'rc=$?; log "Install failed during: ${CURRENT_STEP} (exit ${rc})"' ERR

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

main() {
  preflight

  local tmp_file install_dir
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

  step "Writing PortHub client configuration"
  "$PORT_HUB_INSTALL_PATH" configure \
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

  step "Running PortHub preflight"
  "$PORT_HUB_INSTALL_PATH" preflight

  step "Installing Rathole via PortHub"
  "$PORT_HUB_INSTALL_PATH" install-rathole

  if [ "$PORT_HUB_AUTO_UP" = "true" ]; then
    step "Starting persistent PortHub service"
    "$PORT_HUB_INSTALL_PATH" up
  fi

  step "Installation completed"
  if [ "$PORT_HUB_AUTO_UP" = "true" ]; then
    log "PortHub is up. Try: porthub status"
    log "Live logs: porthub logs -f"
    log "Disconnect: porthub down"
  else
    log "Run 'porthub up' when ready."
  fi
}

main "$@"
