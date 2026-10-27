//! Private-network credentials retain the existing Go profile wire format.
//! Enrollment stages identity only; packet runtime activation is separate.
use crate::profile;
#[cfg(unix)]
use crate::profile::Lease;
#[cfg(unix)]
use anyhow::Context;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;
use tokio_util::sync::CancellationToken;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub server: String,
    pub peer_id: String,
    pub token: String,
    pub workspace: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_email: Option<String>,
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
    pub fn control_profile(&self) -> profile::Profile {
        profile::Profile {
            format_version: 1,
            server: self.server.clone(),
            machine_id: self
                .peer_id
                .rsplit_once(':')
                .map_or_else(|| self.peer_id.clone(), |(_, machine)| machine.to_owned()),
            token: self.token.clone(),
            account_email: self.account_email.clone(),
            fallback_servers: self.fallback_servers.clone(),
            setup_overrides: Default::default(),
            allow_insecure_http_for_tests: self.allow_insecure_http_for_tests,
        }
    }

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
        if let Some(email) = &mut self.account_email {
            *email = email.trim().to_ascii_lowercase();
            anyhow::ensure!(
                email.len() <= 254 && !email.is_empty() && !email.chars().any(char::is_control),
                "invalid account email"
            );
        }
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
#[cfg(unix)]
struct Metadata {
    format_version: u32,
    kind: String,
    server: String,
    peer_id: String,
    workspace: String,
    ticket: String,
    #[serde(default)]
    account_email: Option<String>,
    #[serde(default)]
    fallback_servers: Vec<String>,
}
#[derive(Deserialize)]
#[cfg(unix)]
struct Credentials {
    peer_id: String,
    workspace: String,
    token: String,
}
#[cfg(unix)]
fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()?)
}
#[cfg(unix)]
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
#[cfg(unix)]
pub(crate) fn default_path(user: bool, server: &str, peer: &str) -> Result<PathBuf> {
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Deserialize)]
struct PendingInstall {
    format_version: u32,
    server: String,
    peer_id: String,
    workspace: String,
    ticket: String,
    #[serde(default)]
    account_email: Option<String>,
    #[serde(default)]
    fallback_servers: Vec<String>,
}

/// The native registration activates private networking inside its own process.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) async fn run_auto_install(
    control: std::sync::Arc<crate::control::Control>,
    public: crate::profile::Profile,
    layout: crate::service::Layout,
    cancel: CancellationToken,
) {
    use std::time::Duration;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let result = auto_install_once(&control, &public, &layout, &cancel).await;
        let delay = if result.is_ok() {
            Duration::from_secs(6 * 60 * 60)
        } else {
            tracing::warn!("automatic private enrollment is pending; it will be retried later");
            Duration::from_secs(15 * 60)
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn auto_install_once(
    control: &crate::control::Control,
    public: &crate::profile::Profile,
    layout: &crate::service::Layout,
    cancel: &CancellationToken,
) -> Result<()> {
    use anyhow::ensure;
    use reqwest::StatusCode;

    crate::service::require_administrator()?;
    activate_pending_profiles(layout, public).await?;

    let reply = tokio::select! {
        _ = cancel.cancelled() => anyhow::bail!("private enrollment cancelled"),
        reply = control.pending_private_install() => reply.map_err(|_| anyhow::anyhow!("private enrollment gateway unavailable"))?,
    };
    if reply.status == StatusCode::NO_CONTENT {
        return Ok(());
    }
    ensure!(
        reply.status == StatusCode::OK,
        "unexpected private enrollment response"
    );
    let body: serde_json::Value = serde_json::from_slice(&reply.bytes)
        .map_err(|_| anyhow::anyhow!("invalid private enrollment response"))?;
    let pending: PendingInstall =
        serde_json::from_value(body.get("data").cloned().unwrap_or_default())
            .map_err(|_| anyhow::anyhow!("invalid private enrollment response"))?;
    ensure!(
        pending.format_version == 1,
        "unsupported private enrollment response"
    );
    ensure!(
        pending
            .peer_id
            .strip_prefix(&format!("{}:", pending.workspace))
            .is_some_and(|machine| machine.eq_ignore_ascii_case(&public.machine_id)),
        "private enrollment identity mismatch"
    );
    ensure!(
        pending.fallback_servers.len() <= 8,
        "too many private gateway fallbacks"
    );
    let path = default_path(false, &pending.server, &pending.peer_id)?;
    let marker = path.with_extension("pending");
    profile::write_private(
        &marker,
        path.file_name()
            .context("private profile path is invalid")?
            .to_string_lossy()
            .as_bytes(),
        true,
    )?;
    if std::fs::symlink_metadata(&path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        enroll(
            Source::Ticket {
                server: &pending.server,
                ticket: &pending.ticket,
            },
            Some(&path),
            false,
            public.allow_insecure_http_for_tests,
            cancel,
        )
        .await?;
    }
    let mut enrolled = Profile::load(&path)?;
    ensure!(
        enrolled.peer_id == pending.peer_id && enrolled.workspace == pending.workspace,
        "private enrollment identity mismatch"
    );
    enrolled.fallback_servers = pending.fallback_servers;
    enrolled.account_email = pending.account_email.or(public.account_email.clone());
    enrolled.validate()?;
    profile::write_private(&path, &serde_json::to_vec_pretty(&enrolled)?, true)?;
    activate_profile(layout, public, &path).await?;
    std::fs::remove_file(marker)?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn pending_profiles(layout: &crate::service::Layout) -> Result<Vec<(PathBuf, PathBuf)>> {
    let root = layout.state.join("private");
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "private profile directory is unsafe"
    );
    let mut profiles = Vec::new();
    for entry in std::fs::read_dir(&root)?.take(256) {
        let marker = entry?.path();
        if marker
            .extension()
            .is_none_or(|extension| extension != "pending")
        {
            continue;
        }
        let name = String::from_utf8(profile::read_private(&marker)?)?;
        let filename = Path::new(&name)
            .file_name()
            .context("invalid private recovery marker")?;
        let path = root.join(filename);
        if Profile::load(&path).is_ok() {
            profiles.push((path, marker));
        }
    }
    Ok(profiles)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn activate_pending_profiles(
    layout: &crate::service::Layout,
    public: &crate::profile::Profile,
) -> Result<()> {
    for (path, marker) in pending_profiles(layout)? {
        let profile = Profile::load(&path)?;
        if !crate::unified::matches(public, &profile) {
            continue;
        }
        activate_profile(layout, public, &path).await?;
        std::fs::remove_file(marker)?;
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn activate_profile(
    layout: &crate::service::Layout,
    public: &crate::profile::Profile,
    path: &Path,
) -> Result<()> {
    let profile = Profile::load(path)?;
    anyhow::ensure!(crate::unified::matches(public, &profile), "private enrollment authority mismatch");
    let registration = crate::service::RegistrationProfile::Private(profile);
    let id = registration.identity();
    if crate::service::installed(layout, &id)?.is_some() {
        // Existing enable/disable state belongs to the operator. Automatic
        // enrollment only activates an identity with no owned service yet.
        return Ok(());
    }
    let _lock = crate::service::lock(layout)?;
    let public_path = layout.state.join(format!("{}.json", crate::service::identity(public)));
    if crate::unified::load(&public_path, public)?.is_some() { return Ok(()); }
    let owner = crate::service::installed(layout, &crate::service::identity(public))?
        .context("public registration disappeared during private enrollment")?;
    let manager = crate::service::system_manager(layout.user).await?;
    crate::service::install_locked(layout, path, &owner.executable, manager.as_ref(), None).await?;
    tracing::info!("private network module activated");
    Ok(())
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
        let mut account_email = None;
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
            account_email = metadata.account_email.clone();
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
                account_email: metadata.account_email.clone(),
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
            account_email,
            fallback_servers: fallbacks,
            allow_insecure_http_for_tests: insecure,
        };
        profile.validate()?;
        profile::write_private(&destination, &serde_json::to_vec_pretty(&profile)?, false)?;
        Ok(destination)
    }
}
