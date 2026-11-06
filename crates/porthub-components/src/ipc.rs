//! Framing shared by core and persistent workers. Never parse CLI output.
use crate::catalog::{Component, PROTOCOL};
use anyhow::{ensure, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_FRAME: usize = 64 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub protocol: u32,
    pub component: Component,
    pub version: semver::Version,
}
impl Hello {
    pub fn validate(&self, component: Component, version: &semver::Version) -> Result<()> {
        ensure!(
            self.protocol == PROTOCOL && self.component == component && &self.version == version,
            "incompatible component worker handshake"
        );
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request<T> {
    pub id: u64,
    pub deadline_unix_ms: u64,
    pub operation: T,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response<T> {
    pub id: u64,
    pub result: T,
}

pub async fn read<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    timeout: Duration,
) -> Result<T> {
    tokio::time::timeout(timeout, async {
        let size = stream.read_u32().await? as usize;
        ensure!(
            size > 0 && size <= MAX_FRAME,
            "component IPC frame exceeds limit"
        );
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await?;
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await?
}
pub async fn write<T: Serialize>(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &T,
    timeout: Duration,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FRAME,
        "component IPC frame exceeds limit"
    );
    tokio::time::timeout(timeout, async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    })
    .await?
}
