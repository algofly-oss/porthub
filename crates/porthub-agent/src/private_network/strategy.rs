//! Per-registration path preferences. Filesystem notifications reload settings
//! outside the packet owner; changing a preference never resets a live flow.
use crate::{private_profile::Profile, profile};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::sync::watch;
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

pub async fn run(profile:PathBuf,updates:watch::Sender<Mode>,cancel:CancellationToken)->Result<()> {
    super::settings_watch::run(profile,path,|profile|Ok(load(profile)?.mode),updates,"path strategy",cancel).await
}
