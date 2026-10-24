//! Native bootstrap from an authenticated, expiring installer capability.
//! Network errors never include bearer URLs; source credentials are rolled back
//! when service activation fails. No shell or downloader is invoked here.
use crate::{
    profile::{self, Lease, Profile},
    service::{self, Layout, Manager, Spec},
};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
#[derive(Deserialize)]
struct Enrollment {
    format_version: u32,
    profile: Profile,
}
pub async fn fetch(link: &str, insecure: bool, cancel: &CancellationToken) -> Result<Profile> {
    let url = url::Url::parse(link).map_err(|_| anyhow::anyhow!("invalid bootstrap URL"))?;
    anyhow::ensure!(
        (url.scheme() == "https" || insecure && url.scheme() == "http")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "bootstrap requires an HTTPS URL without credentials or fragment"
    );
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()?;
    let request = async {
        let mut response = client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("bootstrap gateway unavailable"))?;
        anyhow::ensure!(
            response.status().is_success(),
            "bootstrap request rejected (HTTP {})",
            response.status().as_u16()
        );
        let id = response
            .headers()
            .get("x-porthub-machine-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("bootstrap response interrupted"))?
        {
            anyhow::ensure!(
                bytes.len() + chunk.len() <= 65_536,
                "bootstrap response exceeds size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let mut enrollment: Enrollment = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid bootstrap response"))?;
        anyhow::ensure!(
            enrollment.format_version == 1 && enrollment.profile.machine_id == id,
            "bootstrap identity mismatch"
        );
        // A remote response cannot opt the client into plaintext credentials.
        enrollment.profile.allow_insecure_http_for_tests = insecure;
        enrollment.profile.validate()?;
        Ok(enrollment.profile)
    };
    tokio::select! { biased; _=cancel.cancelled()=>anyhow::bail!("bootstrap cancelled"), result=request=>result }
}
struct Source {
    path: PathBuf,
    previous: Option<Vec<u8>>,
    _lease: Lease,
    committed: bool,
}
impl Source {
    #[cfg(not(unix))]
    fn save(_: &Profile, _: &Path) -> Result<Self> {
        anyhow::bail!("native credential protection for this platform is not ready")
    }
    #[cfg(unix)]
    fn save(profile: &Profile, path: &Path) -> Result<Self> {
        let lease = Lease::acquire(path)?;
        let previous = match std::fs::symlink_metadata(path) {
            Ok(_) => {
                let existing = Profile::load(path)?;
                anyhow::ensure!(
                    service::identity(&existing) == service::identity(profile),
                    "profile belongs to a different enrollment"
                );
                Some(profile::read_private(path)?)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let saved = Self {
            path: path.into(),
            previous,
            _lease: lease,
            committed: false,
        };
        profile::write_private(
            path,
            &serde_json::to_vec_pretty(profile)?,
            saved.previous.is_some(),
        )?;
        // Keep rollback armed until the caller completes activation.
        Ok(saved)
    }
    fn restore(&mut self) -> Result<()> {
        if self.committed {
            return Ok(());
        }
        if let Some(bytes) = &self.previous {
            profile::write_private(&self.path, bytes, true)?;
        } else {
            match std::fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.committed = true;
        Ok(())
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        if !self.committed && self.restore().is_err() {
            tracing::warn!("bootstrap source rollback failed");
        }
    }
}
pub fn save(mut profile: Profile, path: &Path) -> Result<()> {
    profile.validate()?;
    let mut source = Source::save(&profile, path)?;
    source.committed = true;
    Ok(())
}
pub async fn install(
    profile: Profile,
    path: Option<&Path>,
    layout: &Layout,
    executable: &Path,
    manager: &dyn Manager,
) -> Result<Spec> {
    install_published(profile, path, layout, executable, manager, None).await
}
pub fn cli_path(user: bool, bin_directory: Option<&Path>) -> Result<PathBuf> {
    let directory = if let Some(directory) = bin_directory {
        directory.into()
    } else if user {
        directories::BaseDirs::new()
            .context("user home directory unavailable")?
            .home_dir()
            .join(".local/bin")
    } else {
        PathBuf::from("/usr/local/bin")
    };
    anyhow::ensure!(
        directory.is_absolute(),
        "CLI bin directory must be absolute"
    );
    Ok(directory.join("porthub"))
}
pub async fn install_published(
    mut profile: Profile,
    path: Option<&Path>,
    layout: &Layout,
    executable: &Path,
    manager: &dyn Manager,
    cli: Option<&Path>,
) -> Result<Spec> {
    profile.validate()?;
    let default = if path.is_none() {
        service::directory(&layout.state, true)?;
        let parent = layout.state.join("enrollments");
        service::directory(&parent, true)?;
        Some(parent.join(format!("{}.json", service::identity(&profile))))
    } else {
        None
    };
    let path = path
        .or(default.as_deref())
        .context("bootstrap profile path missing")?;
    let mut source = Source::save(&profile, path)?;
    match service::install_published(layout, path, executable, manager, cli).await {
        Ok(spec) => {
            source.committed = true;
            Ok(spec)
        }
        Err(error) => {
            source
                .restore()
                .context("service activation failed and source profile rollback failed")?;
            Err(error)
        }
    }
}
