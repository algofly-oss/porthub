//! Downloads deliberately carry no enrollment credentials or proxy bypasses.
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use std::{path::Path, sync::Arc, time::Duration};
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

/// Core-owned routing returns a credential-free HTTP client with redirects
/// disabled and an opaque, non-logged ticket for path health feedback.
pub struct Routed {
    pub client: reqwest::Client,
    pub ticket: String,
}
#[async_trait]
pub trait Routing: Send + Sync {
    async fn route(&self, url: &Url) -> Result<Routed>;
    async fn completed(&self, ticket: &str, success: bool);
}
pub struct Http {
    client: reqwest::Client,
    routing: Option<Arc<dyn Routing>>,
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
    pub fn with_routing(mut self, routing: Arc<dyn Routing>) -> Self {
        self.routing = Some(routing);
        self
    }
    fn build(allow_loopback_http: bool) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .user_agent("PortHub component manager")
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(300))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            routing: None,
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
        let mut current = url.clone();
        let mut redirects = 0;
        let (mut response, ticket) = loop {
            let mut received = None;
            for attempt in 0..8 {
                let routed = match &self.routing {
                    Some(routing) => routing.route(&current).await?,
                    None => Routed {
                        client: self.client.clone(),
                        ticket: String::new(),
                    },
                };
                match routed.client.get(current.clone()).send().await {
                    Ok(response) => {
                        if let Some(routing) = &self.routing {
                            routing.completed(&routed.ticket, true).await;
                        }
                        received = Some((response, routed.ticket));
                        break;
                    }
                    Err(_) => {
                        if let Some(routing) = &self.routing {
                            routing.completed(&routed.ticket, false).await;
                        }
                        ensure!(
                            self.routing.is_some() && attempt < 7,
                            "component download connection failed"
                        );
                    }
                }
            }
            let (response, ticket) = received.context("component download connection failed")?;
            if response.status().is_redirection() {
                ensure!(
                    github && redirects < 4,
                    "component download redirect refused"
                );
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .context("invalid component redirect")?;
                let next = current
                    .join(location)
                    .context("invalid component redirect")?;
                ensure!(
                    next.scheme() == "https"
                        && next.host_str().is_some_and(official)
                        && next.username().is_empty()
                        && next.password().is_none()
                        && next.fragment().is_none(),
                    "unsafe component download redirect"
                );
                current = next;
                redirects += 1;
                continue;
            }
            break (response, ticket);
        };
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
        loop {
            let chunk = match response.chunk().await {
                Ok(Some(chunk)) => chunk,
                Ok(None) => break,
                Err(_) => {
                    if let Some(routing) = &self.routing {
                        routing.completed(&ticket, false).await;
                    }
                    anyhow::bail!("component download interrupted");
                }
            };
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
