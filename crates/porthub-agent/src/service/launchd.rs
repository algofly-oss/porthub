//! macOS service control through the OS-provided launchd interface. Commands
//! use an absolute executable and typed arguments; no shell or installed helper
//! is involved. Each operation addresses one owned profile label.
use super::{Manager, Spec, State, OPERATION_TIMEOUT};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use std::{path::Path, process::Output, time::Duration};
use tokio::process::Command;

pub(super) fn marker(identity: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!-- {}: {identity} -->\n",
        super::MARKER
    )
}

fn xml(value: &str) -> Result<String> {
    ensure!(
        !value.chars().any(char::is_control),
        "launchd service values cannot contain control characters"
    );
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

fn path(value: &Path) -> Result<String> {
    ensure!(
        value.is_absolute(),
        "launchd service paths must be absolute"
    );
    xml(value
        .to_str()
        .context("launchd service paths must be Unicode")?)
}

pub(super) fn unit(spec: &Spec) -> Result<String> {
    ensure!(
        spec.identity.len() == 64 && spec.identity.bytes().all(|c| c.is_ascii_hexdigit()),
        "invalid launchd registration identity"
    );
    ensure!(
        spec.service == format!("porthub-{}", &spec.identity[..24]),
        "invalid launchd service label"
    );
    Ok(format!("{}<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{}</string>\n<key>ProgramArguments</key><array><string>{}</string><string>run</string><string>--profile</string><string>{}</string></array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>5</integer>\n<key>ExitTimeOut</key><integer>15</integer>\n<key>Umask</key><integer>63</integer>\n<key>ProcessType</key><string>Background</string>\n</dict></plist>\n", marker(&spec.identity), xml(&spec.service)?, path(&spec.executable)?, path(&spec.profile)?))
}

pub struct Launchd {
    domain: String,
    user: bool,
}

impl Launchd {
    pub async fn connect(user: bool) -> Result<Self> {
        if !user {
            super::require_administrator()?;
            return Ok(Self {
                domain: "system".into(),
                user,
            });
        }
        let uid = rustix::process::getuid().as_raw();
        // GUI agents are persistent at login. An SSH-only account may have a
        // user domain without an Aqua session and can still run a tunnel.
        let gui = format!("gui/{uid}");
        let output = Self::command(&["print", &gui]).await?;
        let domain = if output.status.success() {
            gui
        } else {
            let domain = format!("user/{uid}");
            Self::checked(&["print", &domain]).await?;
            domain
        };
        Ok(Self { domain, user })
    }

    async fn command(arguments: &[&str]) -> Result<Output> {
        tokio::time::timeout(
            OPERATION_TIMEOUT,
            Command::new("/bin/launchctl")
                .args(arguments)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("launchd operation timed out")?
        .context("cannot access the macOS service controller")
    }

    async fn checked(arguments: &[&str]) -> Result<Output> {
        let output = Self::command(arguments).await?;
        // Never propagate launchctl's output: it may contain service environment
        // values. Labels, profiles and credentials are omitted from errors.
        ensure!(
            output.status.success(),
            "launchd {} operation failed (exit {:?})",
            arguments[0],
            output.status.code()
        );
        Ok(output)
    }

    fn target(&self, spec: &Spec) -> Result<String> {
        ensure!(
            spec.user == self.user,
            "launchd service domain does not match registration"
        );
        ensure!(
            spec.identity.len() == 64
                && spec.identity.bytes().all(|c| c.is_ascii_hexdigit())
                && spec.service == format!("porthub-{}", &spec.identity[..24]),
            "invalid owned launchd label"
        );
        Ok(format!("{}/{}", self.domain, spec.service))
    }

    async fn loaded(&self, spec: &Spec) -> Result<Option<bool>> {
        let output = Self::command(&["print", &self.target(spec)?]).await?;
        if output.status.success() {
            return Ok(Some(
                String::from_utf8(output.stdout)?
                    .lines()
                    .any(|line| line.trim() == "state = running"),
            ));
        }
        // launchctl returns 113 for an absent service. Permissions
        // and communication failures must not be mistaken for a stopped job.
        ensure!(
            output.status.code() == Some(113),
            "cannot inspect launchd service (exit {:?})",
            output.status.code()
        );
        Ok(None)
    }
}

#[async_trait]
impl Manager for Launchd {
    async fn state(&self, spec: &Spec) -> Result<State> {
        self.target(spec)?;
        let loaded = self.loaded(spec).await?;
        let installed = super::owned_unit(spec)?.is_some() || loaded.is_some();
        let disabled = Self::checked(&["print-disabled", &self.domain]).await?;
        let disabled = String::from_utf8(disabled.stdout)?
            .lines()
            .any(|line| line.trim() == format!("\"{}\" => true", spec.service));
        Ok(State {
            installed,
            enabled: installed && !disabled,
            active: loaded == Some(true),
        })
    }
    async fn reload(&self) -> Result<()> {
        Ok(())
    }
    async fn enable(&self, spec: &Spec) -> Result<()> {
        Self::checked(&["enable", &self.target(spec)?]).await?;
        Ok(())
    }
    async fn disable(&self, spec: &Spec) -> Result<()> {
        Self::checked(&["disable", &self.target(spec)?]).await?;
        Ok(())
    }
    async fn start(&self, spec: &Spec) -> Result<()> {
        if self.loaded(spec).await?.is_some() {
            self.stop(spec).await?;
        }
        ensure!(
            super::owned_unit(spec)?.is_some(),
            "owned launchd service file is missing"
        );
        Self::checked(&[
            "bootstrap",
            &self.domain,
            spec.unit
                .to_str()
                .context("launchd unit path must be Unicode")?,
        ])
        .await?;
        Ok(())
    }
    async fn stop(&self, spec: &Spec) -> Result<()> {
        if self.loaded(spec).await?.is_none() {
            return Ok(());
        }
        Self::checked(&["bootout", &self.target(spec)?]).await?;
        tokio::time::timeout(OPERATION_TIMEOUT, async {
            while self.loaded(spec).await?.is_some()
                || crate::profile::Lease::running(&spec.profile)?
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            anyhow::Ok(())
        })
        .await
        .context("launchd service did not stop")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> Spec {
        Spec {
            user: true,
            identity: "a".repeat(64),
            service: format!("porthub-{}", "a".repeat(24)),
            profile: "/private/agent & \"quoted\"/profile.json".into(),
            executable: "/private/releases %q $ENV/porthub".into(),
            unit: "/private/LaunchAgents/owned.plist".into(),
            cli: None,
        }
    }

    #[test]
    fn launchd_arguments_are_literal_and_invalid_identity_or_paths_are_rejected() -> Result<()> {
        let mut spec = spec();
        let encoded = unit(&spec)?;
        ensure!(encoded
            .contains("<string>/private/agent &amp; &quot;quoted&quot;/profile.json</string>"));
        ensure!(encoded.contains("<string>/private/releases %q $ENV/porthub</string>"));
        spec.profile = "relative-profile.json".into();
        ensure!(unit(&spec).is_err());
        spec.profile = "/private/profile\n<key>injected</key>".into();
        ensure!(unit(&spec).is_err());
        spec.identity = "bad-->".into();
        ensure!(unit(&spec).is_err());
        Ok(())
    }

    #[test]
    fn controller_rejects_another_domain_and_unowned_labels_before_invoking_launchctl() -> Result<()>
    {
        let manager = Launchd {
            domain: "gui/501".into(),
            user: true,
        };
        let mut spec = spec();
        ensure!(manager.target(&spec)? == format!("gui/501/{}", spec.service));
        spec.user = false;
        ensure!(manager.target(&spec).is_err());
        spec.user = true;
        spec.service = "unrelated-service".into();
        ensure!(manager.target(&spec).is_err());
        Ok(())
    }
}
