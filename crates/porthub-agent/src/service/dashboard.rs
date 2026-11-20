//! Owned per-user startup for explicitly authorized browser workspaces.
use super::{Layout, Manager, Spec};
use anyhow::{ensure, Context, Result};
use porthub_terminal::protocol::{digest, token};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum Action {
    Run,
    Enable,
    /// Apply the enrollment default while preserving a local disable or custom service.
    EnableDefault,
    Status,
    Disable,
}

fn executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?.canonicalize()?;
    // An installed CLI symlink follows subsequent signed upgrades.
    let invoked = std::env::args_os()
        .next()
        .map(PathBuf::from)
        .unwrap_or_default();
    if invoked.is_absolute() && invoked.canonicalize().ok().as_ref() == Some(&current) {
        return Ok(invoked);
    }
    let paths = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&paths).filter(|dir| dir.is_absolute()) {
        let candidate = dir.join("porthub");
        if candidate.canonicalize().ok().as_ref() == Some(&current) {
            return Ok(candidate);
        }
    }
    Ok(current)
}

fn render(spec: &Spec, owner: &str, registration: &str, slots: u8, user: bool) -> Result<String> {
    ensure!(
        spec.user && token(owner, 24) && token(registration, 64) && (1..=8).contains(&slots),
        "invalid dashboard service settings"
    );
    #[cfg(target_os = "linux")]
    {
        let path = super::argument(&spec.executable)?;
        ensure!(
            !spec
                .executable
                .to_string_lossy()
                .contains(['\\', '\'', '"']),
            "invalid dashboard service executable"
        );
        let mode = if user { " --user" } else { "" };
        Ok(format!("{}: {}\n[Unit]\nDescription=PortHub browser shell hosting\n\n[Service]\nType=simple\nExecStart=:{path} terminal dashboard run --owner {owner} --registration {registration} --slots {slots}{mode}\nRestart=on-failure\nRestartSec=5\nKillMode=mixed\nTimeoutStopSec=75\nUMask=0077\n\n[Install]\nWantedBy=default.target\n",super::MARKER,spec.identity))
    }
    #[cfg(target_os = "macos")]
    {
        let path = super::launchd::path(&spec.executable)?;
        let mode = if user { "<string>--user</string>" } else { "" };
        Ok(format!("{}<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{}</string><key>ProgramArguments</key><array><string>{path}</string><string>terminal</string><string>dashboard</string><string>run</string><string>--owner</string><string>{owner}</string><string>--registration</string><string>{registration}</string><string>--slots</string><string>{slots}</string>{mode}</array><key>RunAtLoad</key><true/><key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict><key>ExitTimeOut</key><integer>75</integer><key>ThrottleInterval</key><integer>5</integer><key>Umask</key><integer>63</integer></dict></plist>\n",super::launchd::marker(&spec.identity),spec.service))
    }
}

pub(crate) async fn service(
    action: Action,
    root: &Path,
    owner: &str,
    slots: u8,
    selector: Option<&str>,
    user: bool,
) -> Result<()> {
    ensure!(
        unsafe { libc::getuid() } != 0 && unsafe { libc::geteuid() } != 0,
        "dashboard services require the nonprivileged shell owner"
    );
    let layout = Layout::user()?;
    let enrollment = if user {
        Layout::user()?
    } else {
        Layout::system()?
    };
    let registration = match selector.filter(|id| token(id, 64)) {
        Some(id) if matches!(action, Action::Status | Action::Disable) => id.to_owned(),
        _ => super::readable::select(&enrollment, selector, Some(false))?.id,
    };
    let identity = digest(&format!("dashboard:{owner}:{registration}:{user}"));
    let service = format!("porthub-{}", &identity[..24]);
    let spec = Spec {
        user: true,
        profile: root.join(format!("dashboard-{identity}")),
        unit: layout.units.join(super::unit_name(&service)),
        service,
        identity,
        executable: executable()?,
        cli: None,
    };
    let bytes = render(&spec, owner, &registration, slots, user)?;
    let _lock =
        crate::profile::Lease::acquire(&root.join(format!("dashboard-config-{}", spec.identity)))?;
    let disabled = root.join(format!("dashboard-disabled-{}", spec.identity));
    if matches!(action, Action::Disable) && !disabled.try_exists()? {
        super::atomic(&disabled, b"disabled\n", true)?;
    }
    if matches!(action, Action::EnableDefault) {
        if disabled.try_exists()? || super::owned_unit(&spec)?.is_some() {
            return Ok(());
        }
    }
    let action = match action {
        Action::EnableDefault => Action::Enable,
        other => other,
    };
    if matches!(action, Action::Enable) {
        super::directory(&layout.units, false)?;
    }
    let previous = super::owned_unit(&spec)?;
    let manager = super::system_manager(true).await?;
    apply(
        action,
        manager.as_ref(),
        &spec,
        bytes.as_bytes(),
        previous.as_deref(),
    )
    .await?;
    if matches!(action, Action::Disable) {
        crate::terminal_cli::withdraw_dashboard(root, owner, &registration, user).await?;
    }
    if matches!(action, Action::Enable) {
        if disabled.try_exists()? {
            std::fs::remove_file(disabled)?;
        }
        println!("Dashboard shell hosting enabled for this OS user's login. Registration: {registration}");
    }
    Ok(())
}

async fn apply(
    action: Action,
    manager: &dyn Manager,
    spec: &Spec,
    bytes: &[u8],
    previous: Option<&[u8]>,
) -> Result<()> {
    match action {
        Action::Status => {
            if previous.is_none() {
                println!("Dashboard shell hosting is disabled");
                return Ok(());
            }
            let state = manager.state(spec).await?;
            println!(
                "Dashboard shell hosting: enabled={}, active={}",
                state.enabled, state.active
            );
        }
        Action::Disable => {
            if previous.is_none() {
                println!("Dashboard shell hosting is disabled");
                return Ok(());
            }
            let state = manager.state(spec).await?;
            if state.installed {
                manager.stop(spec).await?;
            }
            #[cfg(target_os = "linux")]
            manager.disable(spec).await?;
            std::fs::remove_file(&spec.unit)?;
            manager.reload().await?;
            println!("Dashboard shell hosting disabled");
        }
        Action::Enable => {
            if let Some(old) = previous {
                ensure!(old==bytes,"settings differ from the installed dashboard service; disable it before changing settings");
                let state = manager.state(spec).await?;
                if !state.enabled {
                    manager.enable(spec).await?;
                }
                if !state.active {
                    manager.start(spec).await?;
                }
                return started(manager, spec).await;
            }
            super::atomic(&spec.unit, bytes, true)?;
            let result = async {
                manager.reload().await?;
                manager.enable(spec).await?;
                manager.start(spec).await?;
                started(manager, spec).await
            }
            .await;
            if let Err(error) = result {
                if manager.state(spec).await.is_ok_and(|state| state.installed) {
                    manager.stop(spec).await?;
                }
                manager
                    .disable(spec)
                    .await
                    .context("could not roll back dashboard service enable")?;
                std::fs::remove_file(&spec.unit)?;
                manager.reload().await?;
                return Err(error);
            }
        }
        Action::EnableDefault | Action::Run => {
            anyhow::bail!("foreground hosting does not use the service manager")
        }
    }
    Ok(())
}

async fn started(manager: &dyn Manager, spec: &Spec) -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let state = manager.state(spec).await?;
            if state.enabled && state.active {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
    })
    .await
    .context("the dashboard shell service did not start")?
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    #[ignore = "requires a running native user service manager"]
    async fn native_user_service_enables_once_and_removes_only_its_fixture() -> Result<()> {
        let root = tempfile::tempdir()?;
        let layout = Layout::user()?;
        super::super::directory(&layout.units, false)?;
        let identity = porthub_terminal::protocol::random_token(32);
        let name = format!("porthub-{}", &identity[..24]);
        let executable = root.path().join("fixture");
        std::fs::write(&executable, "#!/bin/sh\nexec /bin/sleep 300\n")?;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))?;
        let spec = Spec {
            user: true,
            unit: layout.units.join(super::super::unit_name(&name)),
            service: name,
            identity,
            profile: root.path().join("fixture-profile"),
            executable,
            cli: None,
        };
        ensure!(!spec.unit.try_exists()?, "fixture name unexpectedly in use");
        let text = render(&spec, &"a".repeat(24), &"b".repeat(64), 2, false)?;
        let manager = super::super::system_manager(true).await?;
        let result = async {
            apply(
                Action::Enable,
                manager.as_ref(),
                &spec,
                text.as_bytes(),
                None,
            )
            .await?;
            let before = manager.state(&spec).await?;
            ensure!(
                before.enabled && before.active,
                "user manager did not start the test service"
            );
            apply(
                Action::Enable,
                manager.as_ref(),
                &spec,
                text.as_bytes(),
                Some(text.as_bytes()),
            )
            .await?;
            apply(
                Action::Status,
                manager.as_ref(),
                &spec,
                text.as_bytes(),
                Some(text.as_bytes()),
            )
            .await
        }
        .await;
        if let Some(bytes) = super::super::owned_unit(&spec)? {
            apply(
                Action::Disable,
                manager.as_ref(),
                &spec,
                text.as_bytes(),
                Some(&bytes),
            )
            .await?;
        }
        ensure!(
            !spec.unit.exists() && !manager.state(&spec).await?.enabled,
            "user service cleanup incomplete"
        );
        result
    }
}
