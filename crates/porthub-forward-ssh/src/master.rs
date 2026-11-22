use anyhow::{ensure, Context, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use russh::keys::{
    ssh_key::{private::Ed25519Keypair, LineEnding},
    HashAlg, PrivateKey,
};
use sha2::Sha256;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

pub struct Master {
    seed: Zeroizing<[u8; 32]>,
    host: PrivateKey,
}

impl Master {
    pub fn open(path: &Path) -> Result<Self> {
        let parent = path.parent().context("missing secret directory")?;
        fs::create_dir_all(parent)?;
        if !path.try_exists()? {
            let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
            let mut seed = Zeroizing::new([0; 32]);
            OsRng.try_fill_bytes(seed.as_mut())?;
            tmp.write_all(seed.as_ref())?;
            tmp.as_file().sync_all()?;
            match tmp.persist_noclobber(path) {
                Ok(_) => {
                    #[cfg(unix)]
                    fs::File::open(parent)?.sync_all()?;
                }
                Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.error.into()),
            }
        }
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.file_type().is_file() && meta.len() == 32,
            "invalid forwarding master secret"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                meta.mode() & 0o077 == 0,
                "forwarding master secret must be private"
            );
        }
        let mut f = fs::File::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let open = f.metadata()?;
            ensure!(
                open.ino() == meta.ino() && open.dev() == meta.dev(),
                "forwarding master secret was replaced"
            );
        }
        let mut seed = Zeroizing::new([0; 32]);
        f.read_exact(seed.as_mut())?;
        let host = private(&*derive(&seed, b"porthub-forward-ssh/host/v1", &[])?)?;
        Ok(Self { seed, host })
    }
    pub fn credentials(&self, owner: &str, entry: &str) -> Result<(Zeroizing<String>, String)> {
        ensure!(
            super::valid_id(owner) && super::valid_id(entry),
            "invalid saved forwarding grant"
        );
        credential_from_seed(&*derive(
            &self.seed,
            b"porthub-forward-ssh/client/v1",
            &[owner, entry],
        )?)
    }
    pub fn launcher_key(&self, owner: &str, entry: &str) -> Result<Zeroizing<[u8; 32]>> {
        ensure!(
            super::valid_id(owner) && super::valid_id(entry),
            "invalid forwarding grant"
        );
        derive(
            &self.seed,
            b"porthub-forward-ssh/launcher/v1",
            &[owner, entry],
        )
    }
    pub fn host_public_key(&self) -> Result<String> {
        Ok(self.host.public_key().to_openssh()?)
    }
    pub fn host_fingerprint(&self) -> String {
        self.host
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
    }
    pub(crate) fn host(&self) -> PrivateKey {
        self.host.clone()
    }
}
fn derive(secret: &[u8; 32], label: &[u8], parts: &[&str]) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
    mac.update(label);
    for part in parts {
        mac.update(&[0]);
        mac.update(part.as_bytes());
    }
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}
fn private(seed: &[u8; 32]) -> Result<PrivateKey> {
    Ok(PrivateKey::new(Ed25519Keypair::from_seed(seed).into(), "")?)
}
pub fn credential_from_seed(seed: &[u8; 32]) -> Result<(Zeroizing<String>, String)> {
    let key = private(seed)?;
    Ok((
        key.to_openssh(LineEnding::LF)?,
        key.public_key().to_openssh()?,
    ))
}
