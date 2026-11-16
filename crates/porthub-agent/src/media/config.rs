//! Receiver-local USB identity. No globally borrowed VID/PID or network setter.
use anyhow::{ensure, Result};
use porthub_components::media_forward::UsbIdentity;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    identity: Option<UsbIdentity>,
}
fn path(profile: &Path) -> PathBuf {
    crate::profile::sibling(profile, ".media-receiver.json")
}
fn channels() -> &'static Mutex<HashMap<PathBuf, tokio::sync::watch::Sender<Option<UsbIdentity>>>> {
    static C: OnceLock<Mutex<HashMap<PathBuf, tokio::sync::watch::Sender<Option<UsbIdentity>>>>> =
        OnceLock::new();
    C.get_or_init(Mutex::default)
}
pub fn identity(profile: &Path) -> Option<UsbIdentity> {
    let value: Config = serde_json::from_slice(&std::fs::read(path(profile)).ok()?).ok()?;
    value.identity.filter(UsbIdentity::valid)
}
pub fn refresh(profile: &Path) -> tokio::sync::watch::Receiver<Option<UsbIdentity>> {
    let current = identity(profile);
    let mut all = channels().lock().unwrap_or_else(|e| e.into_inner());
    let sender = all
        .entry(profile.to_owned())
        .or_insert_with(|| tokio::sync::watch::channel(current.clone()).0);
    if *sender.borrow() != current {
        sender.send_replace(current);
    }
    sender.subscribe()
}
pub fn set(profile: &Path, identity: Option<UsbIdentity>) -> Result<()> {
    ensure!(
        identity.as_ref().is_none_or(UsbIdentity::valid),
        "Invalid receiver USB identity"
    );
    crate::profile::write_private(
        &path(profile),
        &serde_json::to_vec(&Config { identity })?,
        true,
    )?;
    refresh(profile);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn receiver_identity_is_explicit_validated_and_revocable() -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let profile = root.path().join("fixture.json");
        let mut changes = refresh(&profile);
        assert!(identity(&profile).is_none());
        assert!(set(
            &profile,
            Some(UsbIdentity {
                vendor: 0,
                product: 1
            })
        )
        .is_err());
        let fixture = UsbIdentity {
            vendor: 0x1209,
            product: 1,
        };
        set(&profile, Some(fixture.clone()))?;
        changes.changed().await?;
        assert_eq!(changes.borrow().as_ref(), Some(&fixture));
        set(&profile, None)?;
        changes.changed().await?;
        assert!(changes.borrow().is_none());
        crate::profile::write_private(
            &path(&profile),
            br#"{"identity":{"vendor":4617,"product":1},"unknown":true}"#,
            true,
        )?;
        assert!(
            identity(&profile).is_none(),
            "Unknown local configuration cannot silently enable a receiver"
        );
        Ok(())
    }
}
