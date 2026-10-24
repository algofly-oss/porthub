//! Control requests never traverse the public listener or reuse browser/agent
//! HTTP pools. Filesystem ownership scopes this Unix socket to core and edge.
use crate::error::{ApiError, ApiResult};
use axum::http::StatusCode;
use porthub_runtime::gateway_apply::{self, Snapshot};
use std::{path::Path, time::Duration};
pub struct Client {
    http: reqwest::Client,
}
impl Client {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            http: reqwest::Client::builder()
                .unix_socket(path.to_owned())
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(15))
                .build()?,
        })
    }
    pub async fn apply(&self, digest: &str) -> ApiResult<()> {
        let run = async {
            let mut response = self
                .http
                .post("http://localhost/apply")
                .json(&Snapshot {
                    digest: digest.into(),
                })
                .send()
                .await?;
            anyhow::ensure!(
                response.status().is_success(),
                "gateway rejected apply request"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                anyhow::ensure!(
                    bytes.len() + chunk.len() <= 1024,
                    "gateway apply response exceeded limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(
                gateway_apply::valid_digest(&snapshot.digest) && snapshot.digest == digest,
                "gateway applied another snapshot"
            );
            Ok::<(), anyhow::Error>(())
        };
        run.await.map_err(|error| {
            tracing::warn!(%error,"gateway apply IPC failed");
            ApiError::new(StatusCode::BAD_GATEWAY, "Gateway apply request failed")
        })
    }
}
