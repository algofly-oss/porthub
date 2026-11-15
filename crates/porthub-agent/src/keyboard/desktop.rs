//! Desktop-session supervision. No machine credentials are placed in this unit.
use anyhow::{ensure, Context, Result};
use std::{
    path::Path,
    process::{Command, Stdio},
};
pub(super) const UNIT: &str = "porthub-keyboard.service";
pub(super) fn unit(executable: &Path, user: bool) -> Result<String> {
    let path = executable
        .to_str()
        .context("Invalid desktop executable path")?;
    ensure!(
        !path.contains(['\n', '\r', '\0']),
        "Invalid desktop executable path"
    );
    let quoted = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
        .replace('$', "$$");
    Ok(format!("[Unit]\nDescription=PortHub desktop keyboard and clipboard\nPartOf=graphical-session.target\nAfter=graphical-session-pre.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nExecStart=\"{quoted}\" keyboard run{}\nRestart=always\nRestartSec=5\nTimeoutStopSec=5\n\n[Install]\nWantedBy=graphical-session.target\n",if user{" --user"}else{""}))
}
pub(super) fn desktop_entry(executable: &Path, user: bool) -> Result<String> {
    let path = executable
        .to_str()
        .context("Invalid desktop executable path")?;
    ensure!(
        !path.contains(['\n', '\r', '\0']),
        "Invalid desktop executable path"
    );
    let quoted = path
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('`', "\\`")
        .replace('$', "\\$")
        .replace('%', "%%");
    Ok(format!("[Desktop Entry]\nType=Application\nName=PortHub desktop input\nExec=\"{quoted}\" keyboard startup{}\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",if user{" --user"}else{""}))
}
fn invoke(arguments: &[&str]) -> bool {
    Command::new("systemctl")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
pub(super) fn start() -> bool {
    invoke(&["--user", "daemon-reload"]);
    invoke(&["--user", "start", UNIT]) && invoke(&["--user", "is-active", UNIT])
}
pub(super) fn install(executable: &Path, user: bool) -> Result<()> {
    let system = !user && rustix::process::geteuid().is_root();
    let config = if system {
        std::path::PathBuf::from("/etc")
    } else {
        directories::BaseDirs::new()
            .context("No desktop configuration directory")?
            .config_dir()
            .to_owned()
    };
    let units = config.join("systemd/user");
    std::fs::create_dir_all(&units)?;
    std::fs::write(units.join(UNIT), unit(executable, user)?)?;
    let wants = units.join("graphical-session.target.wants");
    std::fs::create_dir_all(&wants)?;
    let link = wants.join(UNIT);
    match std::fs::symlink_metadata(&link) {
        Ok(meta) => ensure!(
            meta.file_type().is_symlink()
                && std::fs::read_link(&link)? == Path::new("..").join(UNIT),
            "Desktop startup unit link is not owned by PortHub"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::os::unix::fs::symlink(Path::new("..").join(UNIT), &link)?
        }
        Err(e) => return Err(e.into()),
    }
    let autostart = config.join("autostart");
    let autostart = if system {
        config.join("xdg/autostart")
    } else {
        autostart
    };
    std::fs::create_dir_all(&autostart)?;
    std::fs::write(
        autostart.join("porthub-keyboard.desktop"),
        desktop_entry(executable, user)?,
    )?;
    if !system {
        if invoke(&["--user", "is-active", "graphical-session.target"]) {
            let _ = start();
        }
    } else if let Ok(output) = Command::new("loginctl")
        .args(["list-users", "--no-legend", "--no-pager"])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 2 || fields[0] == "0" {
                continue;
            }
            let name = fields[1];
            if !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                continue;
            }
            let machine = format!("{name}@.host");
            if invoke(&[
                "--user",
                "--machine",
                &machine,
                "is-active",
                "graphical-session.target",
            ]) {
                invoke(&["--user", "--machine", &machine, "daemon-reload"]);
                invoke(&["--user", "--machine", &machine, "start", UNIT]);
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_unit_supervises_reconnects_and_escapes_paths() {
        let text = unit(Path::new("/tmp/Port Hub/$agent%/porthub"), false).unwrap();
        assert!(text.contains("Restart=always\nRestartSec=5"));
        assert!(text.contains("PartOf=graphical-session.target"));
        assert!(text.contains("ExecStart=\"/tmp/Port Hub/$$agent%%/porthub\" keyboard run\n"));
        assert!(unit(Path::new("/tmp/bad\npath"), false).is_err());
        assert!(unit(Path::new("/tmp/porthub"), true)
            .unwrap()
            .contains("keyboard run --user"));
    }
}
