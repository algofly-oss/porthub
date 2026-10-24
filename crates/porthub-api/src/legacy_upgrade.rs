//! One-time bridge for the old Bash updater's download-then-preflight contract.
//! Keep a working legacy CLI until native adoption owns a rollback receipt.
//! New enrollments use native bootstrap and never download this compatibility
//! asset. No machine credentials or gateway addresses are embedded in it.
use std::sync::LazyLock;

const SOURCE: &str = include_str!("../../../api/assets/client/porthub-client.sh");
const HOOK: &str = r#"
# Migration compatibility only. The native installer validates the enrollment,
# queues an independent worker and retains this CLI for activation rollback.
porthub_native_migration_cmd() {
  if [ "$(uname -s)" != Linux ]; then
    log_plain 'Native service migration is not available for this platform yet.'
    return 1
  fi
  reinstall_cmd "$@"
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
}
