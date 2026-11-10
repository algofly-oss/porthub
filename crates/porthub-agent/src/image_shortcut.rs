//! Opt-in desktop shortcut integration. Network services never inspect or change
//! the desktop's keyboard settings; only an explicit desktop-user command does.
use anyhow::{ensure, Context, Result};

#[derive(clap::Subcommand)]
pub enum Action {
    /// Register Ctrl+Shift+U to upload the clipboard image. Disabled by default.
    Enable,
    /// Remove PortHub's shortcut without changing other keyboard bindings.
    Disable,
    /// Show whether PortHub's desktop shortcut is enabled.
    Status,
}
pub fn run(action: Action, user: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        linux::run(action, user)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = user;
        match action {
            Action::Status=>{println!("Automatic desktop shortcut is disabled. GNOME Linux setup is currently supported.");Ok(())},
            _=>anyhow::bail!("Automatic shortcut setup currently supports GNOME-based Linux desktops. You can bind `porthub image` to Ctrl+Shift+U in your desktop's keyboard settings."),
        }
    }
}
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::Command;
    const ROOT: &str = "org.gnome.settings-daemon.plugins.media-keys";
    const PATH: &str =
        "/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/porthub-image/";
    const BINDING: &str = "<Control><Shift>u";
    fn schema(path: &str) -> String {
        format!("org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:{path}")
    }
    fn settings(args: &[&str]) -> Result<String> {
        let mut command = Command::new("gsettings");
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            command.env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!(
                    "unix:path=/run/user/{}/bus",
                    rustix::process::getuid().as_raw()
                ),
            );
        }
        let output = command
            .args(args)
            .output()
            .context("GNOME gsettings is required for automatic shortcut setup")?;
        ensure!(
            output.status.success()
                && !String::from_utf8_lossy(&output.stderr).contains("failed to commit"),
            "Could not update desktop shortcuts. Run this command as your logged-in desktop user."
        );
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    }
    fn paths(value: &str) -> Result<Vec<String>> {
        let value = value.strip_prefix("@as ").unwrap_or(value).trim();
        let body = value
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .context("Invalid desktop shortcut list")?;
        if body.trim().is_empty() {
            return Ok(Vec::new());
        }
        body.split(',')
            .map(|part| {
                let path = part.trim().trim_matches(['\'', '"']);
                ensure!(
                    path.starts_with('/')
                        && path.ends_with('/')
                        && path
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"/_-.".contains(&b)),
                    "Invalid desktop shortcut path"
                );
                Ok(path.to_owned())
            })
            .collect()
    }
    fn array(paths: &[String]) -> String {
        format!(
            "[{}]",
            paths
                .iter()
                .map(|p| format!("'{p}'"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
    fn is_binding(value: &str) -> bool {
        let normalized = value
            .to_ascii_lowercase()
            .replace("<primary>", "<control>")
            .replace("<ctrl>", "<control>");
        let mut remainder = normalized.trim_matches(['\'', '"']).to_owned();
        if !remainder.contains("<control>") || !remainder.contains("<shift>") {
            return false;
        }
        remainder = remainder.replace("<control>", "").replace("<shift>", "");
        remainder == "u"
    }
    fn stable_cli(user: bool) -> Result<std::path::PathBuf> {
        let current = std::env::current_exe()?.canonicalize()?;
        let mut candidates = vec![
            crate::bootstrap::cli_path(user, None)?,
            crate::bootstrap::cli_path(!user, None)?,
        ];
        if let Some(path) = std::env::var_os("PATH") {
            candidates.extend(std::env::split_paths(&path).map(|p| p.join("porthub")));
        }
        candidates
            .into_iter()
            .find(|p| p.is_absolute() && p.canonicalize().is_ok_and(|target| target == current))
            .context("Install the updated PortHub CLI before enabling its desktop shortcut")
    }
    fn quoted(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
    pub(super) fn run(action: Action, user: bool) -> Result<()> {
        ensure!(
            !rustix::process::geteuid().is_root(),
            "Run shortcut commands as your logged-in desktop user, without sudo"
        );
        let available = settings(&["list-schemas"])?;
        ensure!(
            available.lines().any(|s| s == ROOT),
            "Automatic shortcut setup currently supports GNOME-based Linux desktops"
        );
        let mut installed = paths(&settings(&["get", ROOT, "custom-keybindings"])?)?;
        let own = schema(PATH);
        match action {
            Action::Status => {
                let enabled = installed.iter().any(|p| p == PATH)
                    && is_binding(&settings(&["get", &own, "binding"])?);
                println!(
                    "Desktop shortcut: {}",
                    if enabled {
                        "enabled — Ctrl+Shift+U uploads the clipboard image"
                    } else {
                        "disabled (default). Enable with: porthub image shortcut enable"
                    }
                );
            }
            Action::Disable => {
                installed.retain(|p| p != PATH);
                settings(&["set", ROOT, "custom-keybindings", &array(&installed)])?;
                settings(&["set", &own, "binding", "''"])?;
                println!("PortHub shortcut disabled. Other screenshot and keyboard shortcuts are unchanged.");
            }
            Action::Enable => {
                // Check other custom bindings and GNOME's built-in key maps.
                for path in &installed {
                    if path != PATH && is_binding(&settings(&["get", &schema(path), "binding"])?) {
                        anyhow::bail!("Ctrl+Shift+U is already assigned to another desktop shortcut. Free that binding first; no shortcuts were changed.");
                    }
                }
                for namespace in [
                    ROOT,
                    "org.gnome.desktop.wm.keybindings",
                    "org.gnome.shell.keybindings",
                ] {
                    let values = settings(&["list-recursively", namespace])?;
                    ensure!(!values.split(['\'','"']).any(is_binding),"Ctrl+Shift+U is already assigned to a desktop action; no shortcuts were changed");
                }
                let executable = stable_cli(user)?;
                let executable = executable.to_str().context("CLI path must be Unicode")?;
                ensure!(
                    !executable.chars().any(char::is_control),
                    "Invalid CLI path"
                );
                let command = format!(
                    "{} image{}",
                    quoted(executable),
                    if user { " --user" } else { "" }
                );
                settings(&["set", &own, "name", "'PortHub — upload clipboard image'"])?;
                settings(&["set", &own, "command", &serde_json::to_string(&command)?])?;
                settings(&["set", &own, "binding", &serde_json::to_string(BINDING)?])?;
                if !installed.iter().any(|p| p == PATH) {
                    installed.push(PATH.to_owned());
                }
                settings(&["set", ROOT, "custom-keybindings", &array(&installed)])?;
                ensure!(
                    paths(&settings(&["get", ROOT, "custom-keybindings"])?)?
                        .iter()
                        .any(|p| p == PATH)
                        && is_binding(&settings(&["get", &own, "binding"])?),
                    "Desktop did not save the shortcut"
                );
                println!("Enabled Ctrl+Shift+U: clipboard image → preferred tenant → public URL copied. Ctrl+Shift+A and other screenshot shortcuts are unchanged.");
            }
        }
        Ok(())
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn preserves_existing_bindings_and_detects_equivalent_conflicts() {
            let existing = paths(
                "['/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/flameshot/']",
            )
            .unwrap();
            let mut updated = existing.clone();
            updated.push(PATH.into());
            assert_eq!(paths(&array(&updated)).unwrap(), updated);
            updated.retain(|p| p != PATH);
            assert_eq!(updated, existing);
            assert!(is_binding("'<Primary><Shift>u'"));
            assert!(is_binding("<Shift><Control>U"));
            assert!(!is_binding("<Control><Shift>a"));
            assert!(!is_binding("<Control><Alt><Shift>u"));
            assert!(paths("['/valid/','/unsafe\"path/']").is_err());
        }
    }
}
