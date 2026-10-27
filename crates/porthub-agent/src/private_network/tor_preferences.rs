//! Local opt-in/stop overrides. Enabling a local Tor client never grants a
//! remote peer proxy permission or changes the UI's exit distribution policy.
use crate::{private_profile::Profile, profile};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Auto,
    Enabled,
    Disabled,
}
impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub mode: Mode,
    pub circuit_groups: Option<usize>,
}
impl Settings {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.circuit_groups
                .is_none_or(|groups| (1..=16).contains(&groups)),
            "Tor circuit groups must be between 1 and 16"
        );
        Ok(())
    }
}
pub fn path(profile: &Path) -> PathBuf {
    profile::sibling(profile, ".tor-settings.json")
}
pub fn load(profile: &Path) -> Result<Settings> {
    let path = path(profile);
    match std::fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Settings::default())
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) => ensure!(metadata.len() <= 4096, "Tor settings exceed size limit"),
    }
    let settings: Settings = serde_json::from_slice(&profile::read_private(&path)?)
        .map_err(|_| anyhow::anyhow!("invalid Tor settings"))?;
    settings.validate()?;
    Ok(settings)
}
pub fn save(profile: &Path, mode: Mode, circuit_groups: Option<usize>) -> Result<Settings> {
    Profile::load(profile)?;
    let settings = Settings {
        mode,
        circuit_groups,
    };
    settings.validate()?;
    profile::write_private(&path(profile), &serde_json::to_vec_pretty(&settings)?, true)?;
    Ok(settings)
}
pub async fn run(
    profile: PathBuf,
    updates: watch::Sender<Settings>,
    cancel: CancellationToken,
) -> Result<()> {
    super::settings_watch::run(profile, path, load, updates, "local Tor", cancel).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_settings_are_explicit_and_bounded() {
        assert_eq!(Settings::default().mode, Mode::Auto);
        for groups in [0, 17, usize::MAX] {
            assert!(Settings {
                mode: Mode::Enabled,
                circuit_groups: Some(groups)
            }
            .validate()
            .is_err());
        }
        assert!(Settings {
            mode: Mode::Enabled,
            circuit_groups: Some(16)
        }
        .validate()
        .is_ok());
        assert!(serde_json::from_str::<Settings>(
            r#"{"mode":"enabled","circuit_groups":4,"share_with_everyone":true}"#
        )
        .is_err());
    }
}
