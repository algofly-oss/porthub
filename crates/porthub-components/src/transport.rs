//! Downloads deliberately carry no enrollment credentials or proxy bypasses.
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use std::{path::Path, time::Duration};
use tokio::io::AsyncWriteExt;
use url::Url;

#[derive(Debug)]
pub struct AccessDenied;
impl std::fmt::Display for AccessDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("component download access denied")
    }
}
impl std::error::Error for AccessDenied {}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn fetch(&self, url: &Url, output: &Path, limit: u64) -> Result<()>;
}

pub struct Http {
    gateway: reqwest::Client,
    github: reqwest::Client,
    allow_loopback_http: bool,
}
fn official(host: &str) -> bool {
    matches!(
        host,
        "github.com" | "release-assets.githubusercontent.com" | "objects.githubusercontent.com"
    )
}
impl Http {
    pub fn new() -> Result<Self> {
        Self::build(false)
    }
    /// Explicit fixture switch. Plain HTTP is still limited to literal loopback.
    pub fn for_loopback_tests() -> Result<Self> {
        Self::build(true)
    }
    fn build(allow_loopback_http: bool) -> Result<Self> {
        fn client() -> reqwest::ClientBuilder {
            reqwest::Client::builder()
                .user_agent("PortHub component manager")
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(300))
        }
        Ok(Self {
            gateway: client()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            github: client()
                .redirect(reqwest::redirect::Policy::custom(|attempt| {
                    let url = attempt.url();
                    if attempt.previous().len() < 4
                        && url.scheme() == "https"
                        && url.host_str().is_some_and(official)
                        && url.username().is_empty()
                        && url.password().is_none()
                    {
                        attempt.follow()
                    } else {
                        attempt.stop()
                    }
                }))
                .build()?,
            allow_loopback_http,
        })
    }
}
#[async_trait]
impl Transport for Http {
    async fn fetch(&self, url: &Url, output: &Path, limit: u64) -> Result<()> {
        let loopback = url
            .host_str()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        ensure!(
            (url.scheme() == "https"
                || self.allow_loopback_http && url.scheme() == "http" && loopback)
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none(),
            "unsafe component download URL"
        );
        let github = url.host_str() == Some("github.com");
        let client = if github { &self.github } else { &self.gateway };
        let mut response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("component download connection failed"))?;
        if matches!(response.status().as_u16(), 401 | 403) {
            return Err(AccessDenied.into());
        }
        ensure!(
            response.status().is_success(),
            "component download unavailable (HTTP {})",
            response.status().as_u16()
        );
        ensure!(
            response.content_length().is_none_or(|size| size <= limit),
            "component download exceeds size limit"
        );
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).truncate(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let mut file = options
            .open(output)
            .await
            .context("open component download temporary file")?;
        let mut total = 0u64;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("component download interrupted"))?
        {
            total = total
                .checked_add(chunk.len() as u64)
                .context("component download size overflow")?;
            ensure!(total <= limit, "component download exceeds size limit");
            file.write_all(&chunk).await?;
        }
        file.sync_all().await?;
        Ok(())
    }
}
