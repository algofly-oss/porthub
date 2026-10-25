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

fn maintenance_unit(label: &str, argv: &[String]) -> Result<String> {
    ensure!(
        label.len() == 39
            && label.starts_with("porthub-update-")
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
        "invalid launchd maintenance label"
    );
    ensure!(
        !argv.is_empty() && argv.len() <= 33,
        "invalid launchd maintenance arguments"
    );
    let arguments = argv
        .iter()
        .map(|value| xml(value).map(|value| format!("<string>{value}</string>")))
        .collect::<Result<Vec<_>>>()?
        .concat();
    Ok(format!(
        "{}<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array>{arguments}</array><key>RunAtLoad</key><true/><key>Umask</key><integer>63</integer><key>ProcessType</key><string>Background</string><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>\n",
        marker(&label[15..])
    ))
}

fn loaded_job_matches(description: &str, expected_path: &str) -> bool {
    description
        .lines()
        .any(|line| line.trim() == format!("path = {expected_path}"))
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

    /// True only when launchd reports this exact owned service label running
    /// under the supplied PID. Used to keep an update worker outside the
    /// service process that it will stop and replace.
    pub async fn owns_process(&self, spec: &Spec, pid: u32) -> Result<bool> {
        let output = Self::command(&["print", &self.target(spec)?]).await?;
        if !output.status.success() {
            ensure!(
                output.status.code() == Some(113),
                "cannot inspect launchd service (exit {:?})",
                output.status.code()
            );
            return Ok(false);
        }
        let text = String::from_utf8(output.stdout)?;
        Ok(text.lines().any(|line| {
            line.trim()
                .strip_prefix("pid = ")
                .and_then(|value| value.parse::<u32>().ok())
                == Some(pid)
        }))
    }

    /// Install and bootstrap an independent one-shot launchd job. Its argv is
    /// encoded as plist strings, so profile paths and request values are never
    /// interpreted by a shell.
    pub async fn schedule_update(
        &self,
        state: &Path,
        executable: &Path,
        arguments: &[String],
    ) -> Result<String> {
        use sha2::{Digest, Sha256};
        let executable_text = path(executable)?;
        ensure!(
            arguments.first().is_some_and(|value| value == "update")
                && arguments.iter().any(|value| value == "--apply")
                && arguments.len() <= 32
                && arguments
                    .iter()
                    .all(|value| { value.len() <= 4096 && !value.chars().any(char::is_control) }),
            "invalid native maintenance command"
        );
        let profile = arguments
            .windows(2)
            .find(|pair| pair[0] == "--profile")
            .map(|pair| pair[1].as_str())
            .context("maintenance profile missing")?;
        ensure!(
            Path::new(profile).is_absolute(),
            "invalid maintenance profile"
        );
        let digest = format!("{:x}", Sha256::digest(profile.as_bytes()));
        let label = format!("porthub-update-{}", &digest[..24]);
        let state =
            std::fs::canonicalize(state).context("maintenance state directory must exist")?;
        let plist = state.join(format!("{label}.plist"));
        let mut argv = vec![executable_text];
        argv.extend(arguments.iter().cloned());
        let contents = maintenance_unit(&label, &argv)?;
        let target = format!("{}/{}", self.domain, label);
        let expected_path = plist
            .to_str()
            .context("maintenance plist path must be Unicode")?
            .to_owned();
        let previous = super::regular(&plist)?;
        let loaded = Self::command(&["print", &target]).await?;
        if loaded.status.success() {
            let description = String::from_utf8(loaded.stdout)?;
            ensure!(
                previous.is_some() && loaded_job_matches(&description, &expected_path),
                "launchd maintenance label is already owned by another job"
            );
            if previous.as_deref() == Some(contents.as_bytes()) {
                // An identical job may already be running. Leave it alone;
                // updates are idempotent and must not interrupt a replacement.
                return Ok(label);
            }
            ensure!(
                !description
                    .lines()
                    .any(|line| line.trim() == "state = running"),
                "a different PortHub maintenance operation is still running"
            );
            Self::checked(&["bootout", &target]).await?;
        } else {
            ensure!(
                loaded.status.code() == Some(113),
                "cannot inspect launchd maintenance job (exit {:?})",
                loaded.status.code()
            );
        }
        super::atomic(&plist, contents.as_bytes(), true)?;
        if let Err(error) = Self::checked(&["bootstrap", &self.domain, &expected_path]).await {
            let _ = std::fs::remove_file(&plist);
            return Err(error);
        }
        Ok(label)
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
    fn update_job_encodes_argv_and_rejects_untrusted_label_or_control_input() -> Result<()> {
        let label = format!("porthub-update-{}", "a".repeat(24));
        let argv = vec![
            "/private/PortHub/porthub".into(),
            "update".into(),
            "--apply".into(),
            "/private/profile & \"quoted\".json".into(),
        ];
        let plist = maintenance_unit(&label, &argv)?;
        ensure!(
            plist.contains("<!-- # Managed by PortHub native agent: aaaaaaaaaaaaaaaaaaaaaaaa -->")
        );
        ensure!(plist.contains("<string>/private/profile &amp; &quot;quoted&quot;.json</string>"));
        ensure!(maintenance_unit("../../launchd", &argv).is_err());
        let mut invalid = argv;
        invalid.push("bad\nargument".into());
        ensure!(maintenance_unit(&label, &invalid).is_err());
        ensure!(loaded_job_matches(
            "state = running\npath = /owned/job.plist\n",
            "/owned/job.plist"
        ));
        ensure!(!loaded_job_matches(
            "path = /foreign/job.plist\n",
            "/owned/job.plist"
        ));
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
