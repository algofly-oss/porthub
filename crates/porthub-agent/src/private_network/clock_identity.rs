//! Only the enrolled gateway key survives restarts. UTC samples are process local.
use super::relay::PinnedRelay;
use crate::{private_profile::Profile, profile};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Serialize, Deserialize, PartialEq)]
struct Binding {
    server: String,
    peer: String,
    credential: [u8; 32],
    origin: PinnedRelay,
}
impl Binding {
    fn matches(&self, p: &Profile) -> bool {
        self.peer == p.peer_id
            && self.server == p.server
            && self.credential == <[u8; 32]>::from(Sha256::digest(p.token.as_bytes()))
    }
}

pub(crate) fn remember(path: &Path, p: &Profile, origin: &PinnedRelay) -> Result<()> {
    ensure!(
        p.server.starts_with("https://"),
        "clock identity requires an authenticated enrollment"
    );
    let url = url::Url::parse(&profile::base(&origin.url, false)?)?;
    ensure!(
        url.path() == "/"
            && origin.spki_sha256.len() == 64
            && origin.spki_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid gateway clock identity"
    );
    let binding = Binding {
        server: p.server.clone(),
        peer: p.peer_id.clone(),
        credential: Sha256::digest(p.token.as_bytes()).into(),
        origin: origin.clone(),
    };
    let file = path.with_added_extension("clock-origin.json");
    let bytes = serde_json::to_vec(&binding)?;
    if profile::read_private(&file).is_ok_and(|old| old == bytes) {
        return Ok(());
    }
    profile::write_private(&file, &bytes, true)
}

pub(crate) fn read(path: &Path, p: &Profile) -> Option<PinnedRelay> {
    let bytes = profile::read_private(&path.with_added_extension("clock-origin.json")).ok()?;
    if bytes.len() > 4096 {
        return None;
    }
    let binding: Binding = serde_json::from_slice(&bytes).ok()?;
    binding.matches(p).then_some(binding.origin)
}

#[cfg(test)]
#[test]
fn clock_identity_survives_restart_and_is_scoped_to_registration() -> Result<()> {
    let dir = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let path = dir.path().join("private.json");
    let profile: Profile = serde_json::from_value(serde_json::json!({
        "server":"https://gw.example","workspace":"000000000000000000000001",
        "peer_id":"000000000000000000000001:000000000000000000000002","token":"a".repeat(32)
    }))?;
    let pin = PinnedRelay {
        url: "https://gateway.example:443".into(),
        spki_sha256: "ab".repeat(32),
    };
    profile::write_private(&path, &serde_json::to_vec(&profile)?, false)?;
    remember(&path, &profile, &pin)?;
    let loaded = Profile::load(&path)?;
    assert!(read(&path, &loaded).as_ref() == Some(&pin));
    let mut replaced = loaded.clone();
    replaced.token = "b".repeat(32);
    assert!(read(&path, &replaced).is_none());
    replaced = loaded;
    replaced.server = "https://another.example".into();
    assert!(read(&path, &replaced).is_none());
    Ok(())
}
