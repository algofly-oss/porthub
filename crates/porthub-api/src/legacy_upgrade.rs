//! One-time bridge for the old Bash updater's download-then-preflight contract.
//! Keep a working legacy CLI until native adoption owns a rollback receipt.
//! New enrollments use native bootstrap and never download this compatibility
//! asset. No machine credentials or gateway addresses are embedded in it.
use std::sync::LazyLock;

const SOURCE: &str = include_str!("../assets/client/legacy-update-bridge.sh");
const HOOK: &str = r#"
# Migration compatibility only. The native installer validates the enrollment,
# queues an independent worker and retains this CLI for activation rollback.
porthub_native_migration_cmd() {
  case "$(uname -s)" in
    Linux)
      reinstall_cmd "$@"
      ;;
    Darwin)
      # The native installer starts an independent launchd job and publishes
      # the Rust CLI. Keep the legacy job alive until that registration has
      # authenticated, applied configuration and reported its release.
      reinstall_cmd "$@" || return 1
      local native_version native_list native_row attempt
      native_version="$(${SUDO:-} "$PORT_HUB_SELF_PATH" version 2>/dev/null)" || {
        log_plain 'Native PortHub service did not become ready; keeping the existing service.'
        return 1
      }
      if [ -n "${PORT_HUB_CLIENT_UPDATE_TARGET_VERSION:-}" ] \
        && [ "$native_version" != "$PORT_HUB_CLIENT_UPDATE_TARGET_VERSION" ]; then
        log_plain 'Native PortHub service release does not match the requested update; keeping the existing service.'
        return 1
      fi
      attempt=0
      while [ "$attempt" -lt 30 ]; do
        native_list="$(${SUDO:-} "$PORT_HUB_SELF_PATH" list --json 2>/dev/null || true)"
        native_row="$(printf '%s\n' "$native_list" | tr '{' '\n' | grep -F '"machine_id":"'"$PORT_HUB_MACHINE_ID"'"' | head -n 1 || true)"
        case "$native_row" in
          *'"active":true'*'"state":"running"'*'"agent_version":"'"$native_version"'"'*) break ;;
          *) native_row="" ;;
        esac
        attempt=$((attempt + 1))
        sleep 2
      done
      if [ -z "$native_row" ]; then
        log_plain 'Native PortHub service did not report ready; keeping the existing service.'
        return 1
      fi
      if ! ${SUDO:-} launchctl disable "system/$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1; then
        log_plain 'Could not disable the legacy PortHub service; leaving it running.'
        return 1
      fi
      if ! ${SUDO:-} launchctl bootout system "$PORT_HUB_SERVICE_FILE" >/dev/null 2>&1; then
        ${SUDO:-} launchctl enable "system/$PORT_HUB_SERVICE_LABEL" >/dev/null 2>&1 || true
        log_plain 'Could not stop the legacy PortHub service; leaving its launchd registration enabled.'
        return 1
      fi
      log_plain 'Native PortHub service is running; legacy launchd service retired.'
      ;;
    *)
      log_plain 'Native service migration is not available for this platform yet.'
      return 1
      ;;
  esac
}
update_cmd() { porthub_native_migration_cmd "$@"; }
preflight_cmd() {
  porthub_native_migration_cmd "$@"
  # The old parent updater must stop before install-rathole and before marking
  # its request handled. Only the committed native service may acknowledge it.
  return 1
}
"#;

pub(crate) fn script() -> &'static str {
    static SCRIPT: LazyLock<String> = LazyLock::new(|| {
        let source = SOURCE
            .strip_suffix("main \"$@\"\n")
            .expect("legacy CLI must end with its one main invocation");
        let mut script = source
            .replace("__PORT_HUB_CLIENT_VERSION__", "legacy-migration")
            .replace("__PORT_HUB_API_FALLBACK_URLS__", "''");
        // Existing installations load these values from their private env
        // files. Empty defaults also prevent changing another tenant's server.
        for name in [
            "API_URL",
            "MACHINE_ID",
            "MACHINE_TOKEN",
            "AUTH_URL",
            "SYNC_URL",
            "CONFIG_TOML_URL",
            "CHANGES_TOML_URL",
            "LOG_STREAM_STATUS_URL",
            "LOG_STREAM_UPLOAD_URL",
            "RATHOLE_X86_64_URL",
            "RATHOLE_DARWIN_X86_64_URL",
            "RATHOLE_DARWIN_ARM64_URL",
            "RATHOLE_ARM64_URL",
            "RATHOLE_ARMHF_URL",
            "RATHOLE_ARMV7_URL",
            "CLI_URL",
        ] {
            script = script.replace(&format!("__PORT_HUB_{name}__"), "");
        }
        script.push_str(HOOK);
        script.push_str("\nmain \"$@\"\n");
        script
    });
    &SCRIPT
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use anyhow::{ensure, Result};
    use std::{
        io::Write,
        os::unix::fs::PermissionsExt,
        process::{Command, Stdio},
    };

    #[test]
    fn old_download_then_preflight_queues_migration_without_acknowledging_or_installing_tunnel(
    ) -> Result<()> {
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let bridge = root.path().join("bridge");
        let cli = root.path().join("porthub");
        let trace = root.path().join("trace");
        // Stub only the installer boundary. The parent uses the real old
        // update_cmd, curl/download, install overwrite, version command and
        // child preflight entrypoint from the shipped compatibility source.
        let candidate = format!(
            "{}\nreinstall_cmd() {{ printf 'queued\\n' >> \"$TEST_TRACE\"; }}\nmain \"$@\"\n",
            script().strip_suffix("main \"$@\"\n").unwrap()
        );
        std::fs::write(&bridge, &candidate)?;
        ensure!(!script().contains("__PORT_HUB_"));
        let parent = format!(
            r#"{}
detect_sudo() {{ SUDO=""; }}
require_configured_machine() {{ :; }}
load_env() {{ :; }}
validate_configuration() {{ :; }}
need_cmd() {{ :; }}
step() {{ :; }}
log() {{ :; }}
state_get() {{ if [ "$1" = PORT_HUB_CLIENT_UPDATE_REQUEST_ID ]; then printf pending-fixture; fi; }}
write_state() {{ printf 'handled\n' >> "$TEST_TRACE"; }}
build_cli_download_url() {{ printf 'file://%s' "$TEST_BRIDGE"; }}
PORT_HUB_SELF_PATH="$TEST_CLI"
PORT_HUB_API_URL=https://configured.invalid/api
PORT_HUB_TENANT=""
update_cmd
"#,
            SOURCE.strip_suffix("main \"$@\"\n").unwrap()
        );
        let mut child = Command::new("bash")
            .env("TEST_TRACE", &trace)
            .env("TEST_CLI", &cli)
            .env("TEST_BRIDGE", &bridge)
            .env("PORT_HUB_ROOT_DIR", root.path().join("config"))
            .env("PORT_HUB_SHARED_BIN_DIR", root.path().join("bin"))
            .env("PORT_HUB_RUNTIME_ROOT", root.path().join("run"))
            .env("PORT_HUB_LOG_ROOT", root.path().join("logs"))
            .env("PORT_HUB_SERVICE_ROOT", root.path().join("units"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        child.stdin.take().unwrap().write_all(parent.as_bytes())?;
        let output = child.wait_with_output()?;
        ensure!(
            output.status.success(),
            "legacy parent failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            std::fs::read_to_string(&trace)? == "queued\n",
            "migration acknowledged the old request or invoked the installer twice"
        );
        ensure!(
            std::fs::read_to_string(&cli)? == candidate,
            "legacy CLI was not preserved for native transaction rollback"
        );
        Ok(())
    }

    #[test]
    fn macos_handoff_retires_legacy_launchd_only_after_native_agent_is_running() -> Result<()> {
        let root = tempfile::tempdir()?;
        let cli = root.path().join("porthub");
        let trace = root.path().join("trace");
        std::fs::write(
            &cli,
            "#!/bin/sh\ncase \"$1\" in version) echo 1.3.1 ;; list) echo '[{\"machine_id\":\"machine-123\",\"active\":true,\"state\":\"running\",\"agent_version\":\"1.3.1\"}]' ;; esac\n",
        )?;
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755))?;
        let command = format!(
            r#"
{HOOK}
uname() {{ printf 'Darwin\n'; }}
reinstall_cmd() {{ printf 'install\n' >> "$TEST_TRACE"; }}
launchctl() {{ printf '%s\n' "$*" >> "$TEST_TRACE"; }}
log_plain() {{ :; }}
sleep() {{ :; }}
PORT_HUB_SELF_PATH="$TEST_CLI"
PORT_HUB_MACHINE_ID=machine-123
PORT_HUB_CLIENT_UPDATE_TARGET_VERSION=1.3.1
PORT_HUB_SERVICE_LABEL=com.porthub.client
PORT_HUB_SERVICE_FILE=/Library/LaunchDaemons/com.porthub.client.plist
SUDO=""
porthub_native_migration_cmd
"#
        );
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(command)
            .env("TEST_TRACE", &trace)
            .env("TEST_CLI", &cli)
            .output()?;
        ensure!(
            output.status.success(),
            "macOS migration failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            std::fs::read_to_string(trace)?
                == "install\ndisable system/com.porthub.client\nbootout system /Library/LaunchDaemons/com.porthub.client.plist\n",
            "legacy launchd service was not retired after the native agent became ready"
        );
        Ok(())
    }

    #[test]
    fn macos_handoff_keeps_legacy_service_when_native_agent_is_not_ready() -> Result<()> {
        let root = tempfile::tempdir()?;
        let cli = root.path().join("porthub");
        let trace = root.path().join("trace");
        std::fs::write(
            &cli,
            "#!/bin/sh\ncase \"$1\" in version) echo 1.3.1 ;; list) echo '[]' ;; esac\n",
        )?;
        std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755))?;
        let command = format!(
            r#"
{HOOK}
uname() {{ printf 'Darwin\n'; }}
reinstall_cmd() {{ printf 'install\n' >> "$TEST_TRACE"; }}
launchctl() {{ printf '%s\n' "$*" >> "$TEST_TRACE"; }}
log_plain() {{ :; }}
sleep() {{ :; }}
PORT_HUB_SELF_PATH="$TEST_CLI"
PORT_HUB_MACHINE_ID=machine-123
PORT_HUB_CLIENT_UPDATE_TARGET_VERSION=1.3.1
PORT_HUB_SERVICE_LABEL=com.porthub.client
PORT_HUB_SERVICE_FILE=/Library/LaunchDaemons/com.porthub.client.plist
SUDO=""
porthub_native_migration_cmd
"#
        );
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(command)
            .env("TEST_TRACE", &trace)
            .env("TEST_CLI", &cli)
            .output()?;
        ensure!(
            !output.status.success(),
            "unready native agent was accepted"
        );
        ensure!(
            std::fs::read_to_string(trace)? == "install\n",
            "legacy service was stopped before native readiness"
        );
        Ok(())
    }
}
