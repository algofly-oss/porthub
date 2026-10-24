//! Per-registration path preferences. Filesystem notifications reload settings
//! outside the packet owner; changing a preference never resets a live flow.
use crate::{private_profile::Profile, profile};
use anyhow::{ensure, Result};
use notify::{RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    #[default]
    Auto,
    PreferDirect,
    PreferGateway,
}
impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::PreferDirect => "prefer-direct",
            Self::PreferGateway => "prefer-gateway",
        }
    }
    /// An ICE session may itself use TURN. Prefer that established gateway
    /// transport over the packet relay when gateway preference is requested.
    pub fn prefer_peer_transport(self, peer_uses_gateway: bool, packet_relay_ready: bool) -> bool {
        self != Self::PreferGateway || peer_uses_gateway || !packet_relay_ready
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub format_version: u32,
    pub mode: Mode,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            format_version: 1,
            mode: Mode::Auto,
        }
    }
}
pub fn path(profile: &Path) -> PathBuf {
    profile::sibling(profile, ".path-strategy.json")
}
pub fn load(profile: &Path) -> Result<Settings> {
    let path = path(profile);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Settings::default())
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) => ensure!(metadata.len() <= 4096, "path strategy exceeds size limit"),
    }
    let settings: Settings = serde_json::from_slice(&profile::read_private(&path)?)
        .map_err(|_| anyhow::anyhow!("invalid path strategy"))?;
    ensure!(
        settings.format_version == 1,
        "unsupported path strategy format"
    );
    Ok(settings)
}
pub fn save(profile: &Path, mode: Mode) -> Result<Settings> {
    Profile::load(profile)?;
    let settings = Settings {
        mode,
        ..Settings::default()
    };
    profile::write_private(&path(profile), &serde_json::to_vec_pretty(&settings)?, true)?;
    Ok(settings)
}
pub fn reset(profile: &Path) -> Result<Settings> {
    Profile::load(profile)?;
    profile::validate_parent(profile)?;
    let file = path(profile);
    match std::fs::symlink_metadata(&file) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => {
            profile::read_private(&file)?;
            std::fs::remove_file(file)?;
            #[cfg(unix)]
            std::fs::File::open(profile::validate_parent(profile)?)?.sync_all()?;
        }
    }
    Ok(Settings::default())
}

pub async fn run(
    profile: PathBuf,
    updates: watch::Sender<Mode>,
    cancel: CancellationToken,
) -> Result<()> {
    let profile = std::fs::canonicalize(profile)?;
    let wanted = path(&profile);
    let (sender, mut changes) = mpsc::channel(1);
    let notifications = sender.clone();
    let target = wanted.clone();
    let mut watcher = (|| -> Result<notify::RecommendedWatcher> {
        let mut watcher =
            notify::recommended_watcher(move |event: notify::Result<notify::Event>| match event {
                Ok(event)
                    if event.paths.iter().any(|path| path == &target)
                        && matches!(
                            event.kind,
                            notify::EventKind::Create(_)
                                | notify::EventKind::Modify(_)
                                | notify::EventKind::Remove(_)
                        ) =>
                {
                    let _ = notifications.try_send(false);
                }
                Err(_) => {
                    let _ = notifications.try_send(true);
                }
                _ => {}
            })?;
        watcher.watch(wanted.parent().unwrap(), RecursiveMode::NonRecursive)?;
        Ok(watcher)
    })()
    .ok();
    if watcher.is_none() {
        tracing::warn!("path strategy notifications unavailable; using a slow background refresh");
    }
    // Avoid a closed-channel busy loop if watcher creation fails.
    let _keepalive = sender;
    let mut fallback = tokio::time::interval(Duration::from_secs(60));
    fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Watch before the initial read so an atomic CLI write cannot be missed.
    match load(&profile) {
        Ok(settings) => {
            updates.send_replace(settings.mode);
        }
        Err(_) => tracing::warn!("path strategy update rejected; retaining previous preference"),
    }
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            event = changes.recv() => {
                if event.is_none() { return Ok(()); }
                if event == Some(true) && watcher.take().is_some() {
                    tracing::warn!("path strategy notifications stopped; using a slow background refresh");
                }
            }
            _ = fallback.tick(), if watcher.is_none() => {}
        }
        // File reads/fsync never run in the packet forwarding task.
        let file = profile.clone();
        let value = tokio::task::spawn_blocking(move || load(&file)).await?;
        match value {
            Ok(settings) => {
                updates.send_if_modified(|current| {
                    if *current == settings.mode {
                        false
                    } else {
                        *current = settings.mode;
                        true
                    }
                });
            }
            Err(_) => {
                tracing::warn!("path strategy update rejected; retaining previous preference")
            }
        }
    }
}
