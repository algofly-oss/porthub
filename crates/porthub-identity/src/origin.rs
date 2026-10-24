//! Public certificate-key metadata transported only over the role-scoped mount.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{io::Read, path::Path};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub tls_port: u16,
    pub spki_sha256: String,
}
impl Metadata {
    pub fn from_certificate(certificate: &[u8], tls_port: u16) -> Result<Self> {
        ensure!(tls_port > 0, "invalid origin TLS listener");
        Ok(Self {
            tls_port,
            spki_sha256: hex::encode(crate::spki_sha256(certificate)?),
        })
    }
    pub fn read(path: &Path) -> Result<Self> {
        ensure!(
            std::fs::symlink_metadata(path)?.is_file(),
            "origin metadata must be a regular file"
        );
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 4096, "origin metadata exceeds limit");
        let metadata: Self = serde_json::from_slice(&bytes)?;
        ensure!(
            metadata.tls_port > 0
                && metadata.spki_sha256.len() == 64
                && metadata
                    .spki_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "invalid origin key metadata"
        );
        Ok(metadata)
    }
}
