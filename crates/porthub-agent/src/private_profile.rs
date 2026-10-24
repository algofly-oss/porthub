//! Private-network credentials retain the existing Go profile wire format.
//! Enrollment stages identity only; packet runtime activation is separate.
use crate::profile::{self, Lease};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub server: String,
    pub peer_id: String,
    pub token: String,
    pub workspace: String,
    #[serde(default)]
    pub fallback_servers: Vec<String>,
    #[serde(default)]
    pub allow_insecure_http_for_tests: bool,
}
impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateProfile")
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
}
fn oid(value: &str) -> bool {
    value.len() == 24 && value.bytes().all(|c| c.is_ascii_hexdigit())
}
impl Profile {
    pub fn validate(&mut self) -> Result<()> {
        anyhow::ensure!(oid(&self.workspace), "invalid private workspace ID");
        let Some((workspace, machine)) = self.peer_id.split_once(':') else {
            anyhow::bail!("invalid private peer ID");
        };
        anyhow::ensure!(
            workspace == self.workspace && oid(machine),
            "private peer identity does not match workspace"
        );
        anyhow::ensure!(
            (32..=200).contains(&self.token.len()) && !self.token.chars().any(char::is_control),
            "invalid private credential"
        );
        self.server = profile::base(&self.server, self.allow_insecure_http_for_tests)
            .map_err(|_| anyhow::anyhow!("invalid private gateway authority"))?;
        anyhow::ensure!(
            self.fallback_servers.len() <= 8,
            "too many private gateway fallbacks"
        );
        let mut fallbacks = Vec::new();
        for raw in &self.fallback_servers {
            let value = profile::base(raw, self.allow_insecure_http_for_tests)
                .map_err(|_| anyhow::anyhow!("invalid private gateway fallback"))?;
            if value != self.server && !fallbacks.contains(&value) {
                fallbacks.push(value);
            }
        }
        self.fallback_servers = fallbacks;
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = profile::read_private(path)?;
        anyhow::ensure!(bytes.len() <= 65_536, "private profile exceeds size limit");
        let mut profile: Self = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private profile"))?;
        profile.validate()?;
        Ok(profile)
    }
}
#[derive(Deserialize)]
struct Metadata {
    format_version: u32,
    kind: String,
    server: String,
    peer_id: String,
    workspace: String,
    ticket: String,
    #[serde(default)]
    fallback_servers: Vec<String>,
}
#[derive(Deserialize)]
struct Credentials {
    peer_id: String,
    workspace: String,
    token: String,
}
fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()?)
}
async fn response(
    mut response: reqwest::Response,
    cancel: &CancellationToken,
) -> Result<(reqwest::header::HeaderMap, Vec<u8>)> {
    anyhow::ensure!(
        response.status().is_success(),
        "private enrollment rejected (HTTP {})",
        response.status().as_u16()
    );
    let headers = response.headers().clone();
    let mut bytes = Vec::new();
    loop {
        let chunk = tokio::select! {biased;_=cancel.cancelled()=>anyhow::bail!("private enrollment cancelled"),chunk=response.chunk()=>chunk.map_err(|_|anyhow::anyhow!("private enrollment response interrupted"))?};
        let Some(chunk) = chunk else {
            break;
        };
        anyhow::ensure!(
            bytes.len() + chunk.len() <= 65_536,
            "private enrollment response exceeds size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok((headers, bytes))
}
fn default_path(user: bool, server: &str, peer: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let layout = if user {
        crate::service::Layout::user()?
    } else {
        crate::service::require_administrator()?;
        crate::service::Layout::system()?
    };
    let directory = layout.state.join("private");
    crate::service::directory(&directory, true)?;
    Ok(directory.join(format!(
        "{:x}.json",
        Sha256::digest(format!("{server}\n{peer}").as_bytes())
    )))
}
/// Read either an installer capability or an existing long ticket supplied on
/// stdin. Preflight the destination before consuming the one-time ticket.
pub enum Source<'a> {
    Link(&'a str),
    Ticket { server: &'a str, ticket: &'a str },
}
pub async fn enroll(
    source: Source<'_>,
    destination: Option<&Path>,
    user: bool,
    insecure: bool,
    cancel: &CancellationToken,
) -> Result<PathBuf> {
    #[cfg(not(unix))]
    {
        let _ = (source, destination, user, insecure, cancel);
        anyhow::bail!("native credential protection for this platform is not ready");
    }
    #[cfg(unix)]
    {
        let http = client()?;
        let mut expected = None;
        let (server, ticket, fallbacks) = if let Source::Link(link) = source {
            let link = url::Url::parse(link)
                .map_err(|_| anyhow::anyhow!("invalid private bootstrap URL"))?;
            anyhow::ensure!(
                (link.scheme() == "https" || insecure && link.scheme() == "http")
                    && link.host_str().is_some()
                    && link.username().is_empty()
                    && link.password().is_none()
                    && link.fragment().is_none(),
                "private bootstrap requires HTTPS"
            );
            let request = tokio::select! {biased;_=cancel.cancelled()=>anyhow::bail!("private enrollment cancelled"),result=http.get(link).header(reqwest::header::ACCEPT,"application/json").send()=>result.map_err(|_|anyhow::anyhow!("private bootstrap gateway unavailable"))?};
            let (headers, bytes) = response(request, cancel).await?;
            let metadata: Metadata = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("invalid private bootstrap metadata"))?;
            anyhow::ensure!(
                metadata.format_version == 1
                    && metadata.kind == "private"
                    && metadata
                        .peer_id
                        .strip_prefix(&format!("{}:", metadata.workspace))
                        .is_some_and(|id| headers
                            .get("x-porthub-machine-id")
                            .and_then(|h| h.to_str().ok())
                            == Some(id)),
                "private bootstrap identity mismatch"
            );
            let mut preview = Profile {
                server: metadata.server.clone(),
                peer_id: metadata.peer_id.clone(),
                workspace: metadata.workspace.clone(),
                token: "x".repeat(32),
                fallback_servers: metadata.fallback_servers.clone(),
                allow_insecure_http_for_tests: insecure,
            };
            preview.validate()?;
            expected = Some((metadata.peer_id, metadata.workspace));
            (metadata.server, metadata.ticket, metadata.fallback_servers)
        } else {
            let Source::Ticket { server, ticket } = source else {
                unreachable!()
            };
            (server.to_owned(), ticket.to_owned(), Vec::new())
        };
        let server = profile::base(&server, insecure)
            .map_err(|_| anyhow::anyhow!("invalid private gateway authority"))?;
        anyhow::ensure!(
            (32..=200).contains(&ticket.len()) && !ticket.chars().any(char::is_control),
            "invalid private installer ticket"
        );
        let destination = match destination {
            Some(path) => path.to_owned(),
            None => default_path(
                user,
                &server,
                &expected
                    .as_ref()
                    .context("explicit profile path required for a long ticket")?
                    .0,
            )?,
        };
        profile::validate_parent(&destination)?;
        anyhow::ensure!(
            std::fs::symlink_metadata(&destination)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "private profile already exists or is inaccessible"
        );
        let _lease = Lease::acquire(&destination)?;
        let request = tokio::select! {biased;_=cancel.cancelled()=>anyhow::bail!("private enrollment cancelled"),result=http.post(format!("{server}/api/access/private/bootstrap")).json(&serde_json::json!({"ticket":ticket})).send()=>result.map_err(|_|anyhow::anyhow!("private enrollment gateway unavailable"))?};
        let (_, bytes) = response(request, cancel).await?;
        let credentials: Credentials = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid private enrollment response"))?;
        if let Some((peer, workspace)) = expected {
            anyhow::ensure!(
                credentials.peer_id == peer && credentials.workspace == workspace,
                "private enrollment identity mismatch"
            );
        }
        let mut profile = Profile {
            server,
            peer_id: credentials.peer_id,
            workspace: credentials.workspace,
            token: credentials.token,
            fallback_servers: fallbacks,
            allow_insecure_http_for_tests: insecure,
        };
        profile.validate()?;
        profile::write_private(&destination, &serde_json::to_vec_pretty(&profile)?, false)?;
        Ok(destination)
    }
}
