//! One in-process public agent per saved profile. Configuration changes and
//! presence use the control plane; established forwarding carries no API probes.
use crate::{
    control::{Control, Failure, Reply},
    profile::{self, Lease, Profile},
};
use anyhow::{Context, Result};
use porthub_tunnel::{
    client_plan::{Candidate, ClientPlan},
    EmbeddedClient,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct PrivateStatus {
    pub revision: u64,
    pub grants: usize,
    pub dns_rules: usize,
    pub lease_valid: bool,
    pub exit: Option<ExitStatus>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExitStatus {
    pub name: String,
    pub selection: String,
    pub state: String,
    pub peers: usize,
    pub available: usize,
    pub allow_direct_fallback: bool,
    #[serde(default)]
    pub peer_names: Vec<String>,
}
impl PrivateStatus {
    pub fn display(&self) -> String {
        let clean = |text: &str| text.chars().filter(|c| !c.is_control()).take(160).collect::<String>();
        let mut output = format!("Private policy: revision {}; lease {}; {} access grants; {} DNS rules", self.revision,
            if self.lease_valid { "valid" } else { "expired or unavailable" }, self.grants, self.dns_rules);
        if let Some(exit) = &self.exit {
            output.push_str(&format!("\nExit route: {}; {}; {}; {}/{} peers reachable; all offline: {}",
                clean(&exit.name), clean(&exit.selection), clean(&exit.state), exit.available, exit.peers,
                if exit.allow_direct_fallback { "allow normal internet" } else { "block" }));
            if !exit.peer_names.is_empty() {
                output.push_str(&format!("\nConfigured exit peers: {}", exit.peer_names.iter().take(16).map(|name| clean(name)).collect::<Vec<_>>().join(", ")));
            }
        } else { output.push_str("\nExit route: none"); }
        output
    }
}

#[derive(Deserialize, Serialize)]
pub struct Status {
    pub pid: u32,
    pub state: String,
    pub agent_version: String,
    pub config_version: String,
    pub service_count: usize,
    pub route: String,
    pub updated_at: u64,
    pub update_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_status: Option<PrivateStatus>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[derive(Deserialize, Serialize)]
struct Cache {
    machine_id: String,
    version: String,
    toml: String,
}
pub struct Options {
    pub heartbeat: Duration,
    pub retry: Duration,
    pub probe_timeout: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            heartbeat: Duration::from_secs(30),
            retry: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(2),
        }
    }
}
struct Session {
    client: Option<EmbeddedClient>,
    candidate: Option<Candidate>,
    version: String,
    update: String,
    count: usize,
    plan: Option<std::sync::Arc<ClientPlan>>,
    revision: u64,
    pending_update: Option<crate::update::Request>,
}
impl Session {
    async fn refresh_source(&mut self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if let (Some(plan), Some(current), Some(client)) = (&self.plan, &self.candidate, &mut self.client) {
            let source = crate::private_network::interfaces::current().await?.first()
                .context("gateway underlay unavailable")?.ip();
            if current.config.client.as_ref().and_then(|config| config.transport.tcp.source_address) != Some(source) {
                let mut plan = plan.as_ref().clone();
                plan.bind_source(source);
                let mut current = current.clone();
                current.config.client.as_mut().context("missing client configuration")?.transport.tcp.source_address = Some(source);
                // Rathole retains established streams while replacing the
                // control connection and source used by future data channels.
                client.reroute(current.config.clone()).await?;
                self.candidate = Some(current);
                self.plan = Some(std::sync::Arc::new(plan));
                self.revision = self.revision.wrapping_add(1);
            }
        }
        Ok(())
    }
    fn new() -> Self {
        Self {
            client: None,
            candidate: None,
            version: String::new(),
            update: String::new(),
            count: 0,
            plan: None,
            revision: 0,
            pending_update: None,
        }
    }
    async fn stop(&mut self) {
        if let Some(client) = self.client.take() {
            client.shutdown().await;
        }
        self.candidate = None;
        self.version.clear();
        self.count = 0;
        self.plan = None;
        self.pending_update = None;
        self.revision = self.revision.wrapping_add(1);
    }
    fn route_snapshot(&self) -> Option<crate::routes::Snapshot> {
        let plan = self.plan.as_ref()?;
        if self.count == 0 || plan.candidates.len() < 2 {
            return None;
        }
        Some(crate::routes::Snapshot {
            revision: self.revision,
            plan: plan.clone(),
            current: self.candidate.clone()?,
        })
    }
    async fn reroute(&mut self, update: crate::routes::Update) -> Result<bool> {
        if self.revision != update.revision {
            return Ok(false);
        }
        let Some(client) = &mut self.client else {
            return Ok(false);
        };
        client.reroute(update.candidate.config.clone()).await?;
        self.candidate = Some(update.candidate);
        self.revision = self.revision.wrapping_add(1);
        Ok(true)
    }
    fn status(&self, state: &str) -> Status {
        Status {
            pid: std::process::id(),
            state: state.into(),
            agent_version: crate::VERSION.into(),
            config_version: self.version.clone(),
            service_count: self.count,
            route: self
                .candidate
                .as_ref()
                .map(|c| format!("{:?}", c.kind).to_ascii_lowercase())
                .unwrap_or_default(),
            updated_at: now(),
            update_request_id: self.update.clone(),
            private_status: None,
        }
    }
    async fn apply(
        &mut self,
        path: &Path,
        profile: &Profile,
        version: String,
        content: String,
        timeout: Duration,
    ) -> Result<()> {
        anyhow::ensure!(
            !version.is_empty()
                && version.len() <= 128
                && version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid configuration version"
        );
        if self.version == version && self.client.is_some() {
            return self.refresh_source().await;
        }
        let plan = ClientPlan::parse(&content)?;
        #[cfg(target_os = "linux")]
        let plan = {
            let mut plan = plan;
            plan.bind_source(crate::private_network::interfaces::current().await?.first()
                .context("gateway underlay unavailable")?.ip());
            plan
        };
        for candidate in &plan.candidates {
            let config = candidate
                .config
                .client
                .as_ref()
                .context("missing client configuration")?;
            anyhow::ensure!(
                config.services.len() <= 4096
                    && config
                        .services
                        .values()
                        .all(|service| service.token.as_deref() == Some(profile.token.as_str())),
                "configuration service identity does not match the enrolled machine"
            );
        }
        // Retain the selected endpoint across normal service edits, so a new
        // stream does not trigger route discovery or split session channels.
        let candidate = if let Some(previous) = self
            .candidate
            .as_ref()
            .filter(|_| self.count > 0)
            .and_then(|previous| {
                plan.candidates.iter().find(|candidate| {
                    candidate.endpoint == previous.endpoint
                        && candidate.kind == previous.kind
                        && candidate.config.client.as_ref().map(|c| &c.transport)
                            == previous.config.client.as_ref().map(|c| &c.transport)
                })
            }) {
            previous.clone()
        } else {
            plan.choose(timeout).await
        };
        let cache = Cache {
            machine_id: profile.machine_id.clone(),
            version: version.clone(),
            toml: content,
        };
        profile::write_private(
            &profile::sibling(path, ".config.json"),
            &serde_json::to_vec(&cache)?,
            true,
        )?;
        let config = candidate.config.clone();
        self.count = config.client.as_ref().unwrap().services.len();
        if let Some(client) = &mut self.client {
            client.reload(config).await?;
        } else {
            self.client = Some(EmbeddedClient::new(config).await?);
        }
        self.version = version;
        self.candidate = Some(candidate);
        self.plan = Some(std::sync::Arc::new(plan));
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
    async fn reply(
        &mut self,
        path: &Path,
        profile: &Profile,
        reply: Reply,
        initial: bool,
        timeout: Duration,
    ) -> Result<()> {
        let requested = crate::update::Request::from_headers(&reply.headers)
            .ok()
            .flatten();
        if initial {
            let body = reply.json()?;
            let config = &body["data"]["config"];
            anyhow::ensure!(
                config["machine_id"] == profile.machine_id,
                "authenticated configuration belongs to another machine"
            );
            let version = config["version"]
                .as_str()
                .context("configuration version missing")?
                .to_owned();
            let content = config["files"]["client.toml"]
                .as_str()
                .context("tunnel configuration missing")?
                .to_owned();
            self.apply(path, profile, version, content, timeout).await?;
        } else {
            anyhow::ensure!(
                reply
                    .headers
                    .get("x-porthub-machine-id")
                    .and_then(|v| v.to_str().ok())
                    == Some(&profile.machine_id),
                "configuration response belongs to another machine"
            );
            if reply.status == reqwest::StatusCode::NO_CONTENT {
                self.refresh_source().await?;
                self.record_update(requested);
                return Ok(());
            }
            let version = reply
                .headers
                .get("x-porthub-config-version")
                .and_then(|v| v.to_str().ok())
                .context("configuration version missing")?
                .to_owned();
            let content = String::from_utf8(reply.bytes).context("configuration is not UTF8")?;
            self.apply(path, profile, version, content, timeout).await?;
        }
        self.record_update(requested);
        Ok(())
    }
    fn record_update(&mut self, requested: Option<crate::update::Request>) {
        if let Some(request) = &requested {
            self.update = request.id.clone();
        }
        self.pending_update = requested;
    }
}

fn state(path: &Path, session: &Session, name: &str) -> Result<()> {
    let status = session.status(name);
    profile::write_private(
        &profile::sibling(path, ".status.json"),
        &serde_json::to_vec(&status)?,
        true,
    )?;
    if crate::service::readable::refresh(path, &status).is_err() {
        tracing::debug!("local registration display snapshot unavailable");
    }
    Ok(())
}

async fn route_update(
    path: &Path,
    session: &mut Session,
    update: crate::routes::Update,
    name: &str,
) -> Result<()> {
    match session.reroute(update).await {
        Ok(true) => {
            state(path, session, name)?;
            tracing::info!("background tunnel route changed; established streams retained");
        }
        Ok(false) => {}
        Err(_) => {
            tracing::warn!("background route replacement rejected; retaining current endpoint")
        }
    }
    Ok(())
}
async fn retry_wait(
    path: &Path,
    session: &mut Session,
    monitor: &mut crate::routes::Monitor,
    cancel: &CancellationToken,
    delay: Duration,
    name: &str,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + delay;
    loop {
        monitor.set(session.revision, session.route_snapshot());
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=tokio::time::sleep_until(deadline)=>break,
            update=monitor.next()=>{
                let update=update.context("background route worker stopped")?;
                route_update(path, session, update, name).await?;
            }
        }
    }
    Ok(())
}
pub async fn run(path: PathBuf, cancel: CancellationToken, options: Options) -> Result<()> {
    run_with_logs(path, cancel, options, crate::logs::Buffer::default()).await
}
pub async fn run_with_logs(
    path: PathBuf,
    cancel: CancellationToken,
    options: Options,
    logs: crate::logs::Buffer,
) -> Result<()> {
    anyhow::ensure!(
        !options.heartbeat.is_zero() && !options.retry.is_zero(),
        "agent intervals must be positive"
    );
    let profile = Profile::load(&path)?;
    let _lease = Lease::acquire(&path)?;
    let control = std::sync::Arc::new(Control::new(profile.clone())?);
    logs.configure(&profile);
    tracing::info!("machine agent started");
    let mut log_stream = crate::logs::Guard::start(control.clone(), logs, cancel.child_token());
    let hostname = hostname::get()
        .ok()
        .and_then(|v| v.into_string().ok())
        .unwrap_or_default();
    let mut session = Session::new();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut updater = crate::autoupdate::Controller::new(&path, &profile)
        .await
        .unwrap_or_else(|_| {
            tracing::warn!(
                "automatic updates unavailable for this profile; forwarding remains active"
            );
            None
        });
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let private_install_cancel = cancel.child_token();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let _private_install_task = updater
        .as_ref()
        .and_then(crate::autoupdate::Controller::private_activation_context)
        .map(|(layout, executable)| {
            tokio::spawn(crate::private_profile::run_auto_install(
                control.clone(),
                profile.clone(),
                layout,
                executable,
                private_install_cancel.clone(),
            ))
        });
    let mut monitor = crate::routes::Monitor::new(options.heartbeat, options.probe_timeout);
    let mut status_name = "starting";
    let mut next_heartbeat = tokio::time::Instant::now();
    let mut failure_delay = options.retry;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let initial = session.client.is_none() || tokio::time::Instant::now() >= next_heartbeat;
        let started = tokio::time::Instant::now();
        monitor.set(session.revision, session.route_snapshot());
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let handled = updater
            .as_ref()
            .map(|updater| updater.handled())
            .unwrap_or_default();
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let handled = String::new();
        let maintenance = async {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let Some(updater) = &mut updater {
                return updater.next().await.is_some();
            }
            std::future::pending::<bool>().await
        };
        let fetch = async {
            if initial {
                Some(control.sync(&hostname, &handled).await)
            } else {
                tokio::select! {
                    reply=control.changes(&session.version)=>Some(reply),
                    _=tokio::time::sleep_until(next_heartbeat)=>None,
                }
            }
        };
        let reply = tokio::select! {
            _=cancel.cancelled()=>break,
            _alive=maintenance=>{
                #[cfg(target_os="linux")]
                if !_alive {updater=None;tracing::warn!("automatic update worker stopped");}
                next_heartbeat=tokio::time::Instant::now();continue;
            },
            update=monitor.next()=>{
                let update=update.context("background route worker stopped")?;
                route_update(&path, &mut session, update, status_name).await?;
                continue;
            },
            reply=fetch=>match reply {Some(reply)=>reply, None=>continue},
        };
        match reply {
            Ok(reply) => {
                if initial {
                    next_heartbeat = tokio::time::Instant::now() + options.heartbeat;
                }
                let previous = session.version.clone();
                match session
                    .reply(&path, &profile, reply, initial, options.probe_timeout)
                    .await
                {
                    Ok(()) => {
                        if previous != session.version {
                            tracing::info!(
                                services = session.count,
                                "machine configuration applied"
                            );
                        }
                        failure_delay = options.retry;
                        status_name = "running";
                        state(&path, &session, status_name)?;
                        #[cfg(any(target_os = "linux", target_os = "macos"))]
                        if let Some(updater) = &mut updater {
                            updater.request(session.pending_update.clone());
                        }
                    }
                    Err(_) => {
                        tracing::warn!(
                            "authenticated configuration rejected; retaining current services"
                        );
                        status_name = "configuration-rejected";
                        state(&path, &session, status_name)?;
                        retry_wait(
                            &path,
                            &mut session,
                            &mut monitor,
                            &cancel,
                            failure_delay,
                            status_name,
                        )
                        .await?;
                        failure_delay = (failure_delay * 2).min(Duration::from_secs(60));
                    }
                }
                // A misbehaving early-returning gateway cannot cause a hot loop.
                if started.elapsed() < Duration::from_millis(250) {
                    tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(250).saturating_sub(started.elapsed()))=>{}}
                }
            }
            Err(Failure::Rejected(410)) => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                private_install_cancel.cancel();
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                if let Some(updater) = &mut updater {
                    updater.stop().await;
                }
                session.stop().await;
                state(&path, &session, "deleted")?;
                log_stream.stop().await;
                let _ = tokio::time::timeout(Duration::from_secs(3), control.deletion_ack()).await;
                tracing::info!("machine access removed; forwarding stopped");
                return Ok(());
            }
            Err(error) => {
                let name = if matches!(error, Failure::Rejected(400 | 401 | 403)) {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    if let Some(updater) = &mut updater {
                        updater.request(None);
                    }
                    session.stop().await;
                    "authorization-required"
                } else {
                    "gateway-unavailable"
                };
                tracing::warn!(%error,"machine control is unavailable; retrying");
                status_name = name;
                state(&path, &session, status_name)?;
                retry_wait(
                    &path,
                    &mut session,
                    &mut monitor,
                    &cancel,
                    failure_delay,
                    status_name,
                )
                .await?;
                failure_delay = (failure_delay * 2).min(Duration::from_secs(60));
            }
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if let Some(updater) = &mut updater {
        updater.stop().await;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    private_install_cancel.cancel();
    session.stop().await;
    log_stream.stop().await;
    state(&path, &session, "stopped")?;
    Ok(())
}
pub fn status(path: &Path) -> Result<Status> {
    if crate::private_network::is_profile(path)? {
        crate::private_profile::Profile::load(path)?;
    } else {
        Profile::load(path)?;
    }
    let status_path = profile::sibling(path, ".status.json");
    if !status_path.try_exists()? {
        return Ok(Session::new().status("stopped"));
    }
    let mut status: Status = serde_json::from_slice(&profile::read_private(&status_path)?)?;
    if !Lease::running(path)? && !["stopped", "deleted"].contains(&status.state.as_str()) {
        status.state = "interrupted".into();
    }
    Ok(status)
}

#[cfg(test)]
mod private_status_tests {
    use super::*;
    #[test]
    fn private_policy_status_is_backwards_compatible_and_safe_for_terminals() {
        let old = serde_json::json!({"pid":1,"state":"running","agent_version":"1.5.2","config_version":"","service_count":0,"route":"private","updated_at":1,"update_request_id":""});
        assert!(serde_json::from_value::<Status>(old).unwrap().private_status.is_none());
        let status = PrivateStatus {
            revision: 7, grants: 2, dns_rules: 1, lease_valid: false,
            exit: Some(ExitStatus { name: "Exit\u{1b}\nspoof".into(), selection: "sticky".into(), state: "configuration error".into(), peers: 2, available: 0, allow_direct_fallback: false, peer_names: vec!["condor.phub".into()] }),
        };
        let rendered = status.display();
        assert!(!rendered.contains('\u{1b}'));
        assert_eq!(rendered.lines().count(), 3);
        assert!(rendered.contains("lease expired or unavailable"));
        assert!(rendered.contains("configuration error"));
        assert!(rendered.contains("all offline: block"));
        assert!(rendered.contains("condor.phub"));
    }
}
