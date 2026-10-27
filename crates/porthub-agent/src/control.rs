//! Authenticated control plane. Bounded bodies/timeouts and redacted failures
//! keep machine tokens and origin addresses out of routine agent output.
use crate::profile::Profile;
use reqwest::{Method, StatusCode};
use serde_json::Value;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
#[derive(Debug)]
pub enum Failure {
    Unavailable,
    Rejected(u16),
    InvalidResponse,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => f.write_str("gateway temporarily unavailable"),
            Self::Rejected(status) => write!(f, "gateway request rejected (HTTP {status})"),
            Self::InvalidResponse => f.write_str("invalid authenticated gateway response"),
        }
    }
}
impl std::error::Error for Failure {}
pub struct Reply {
    pub status: StatusCode,
    pub headers: reqwest::header::HeaderMap,
    pub bytes: Vec<u8>,
}
/// Ask the kernel for its default IPv4 source address. UDP connect selects a
/// route locally: it sends no packet and performs no DNS or gateway request.
fn local_address() -> String {
    let selected = (|| -> std::io::Result<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))?;
        socket.connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 9))?;
        Ok(socket.local_addr()?.ip())
    })();
    match selected {
        Ok(address) if !address.is_unspecified() && !address.is_loopback() => address.to_string(),
        _ => String::new(),
    }
}
impl Reply {
    pub fn json(&self) -> Result<Value, Failure> {
        serde_json::from_slice(&self.bytes).map_err(|_| Failure::InvalidResponse)
    }
}
pub struct Control {
    profile: Profile,
    private_peer_id: Option<String>,
    http: reqwest::Client,
    preferred: Mutex<Option<(String, Instant)>>,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    underlay: tokio::sync::Mutex<Option<(std::net::IpAddr, reqwest::Client, Instant)>>,
}
impl Control {
    pub fn new(mut profile: Profile) -> anyhow::Result<Self> {
        profile.validate()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(40))
            .build()?;
        Ok(Self {
            profile,
            private_peer_id: None,
            http,
            preferred: Mutex::new(None),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            underlay: tokio::sync::Mutex::new(None),
        })
    }
    /// Control traffic must not inherit an application exit route. Binding a
    /// physical source selects the consumer's preserved main-table source rule.
    /// Refresh lazily: no timer or discovery work runs while control is idle.
    async fn http_for(&self, base: &str) -> Result<reqwest::Client, Failure> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let loopback = url::Url::parse(base).ok().and_then(|url| url.host_str().map(str::to_owned))
                .is_some_and(|host| host == "localhost" || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
            if loopback { return Ok(self.http.clone()); }
            let mut cached = self.underlay.lock().await;
            if let Some((_, client, until)) = &*cached {
                if Instant::now() < *until { return Ok(client.clone()); }
            }
            let addresses = crate::private_network::interfaces::current().await.map_err(|_| Failure::Unavailable)?;
            let local = addresses.first().ok_or(Failure::Unavailable)?.ip();
            if let Some((previous, client, until)) = cached.as_mut() {
                if *previous == local {
                    *until = Instant::now() + Duration::from_secs(30);
                    return Ok(client.clone());
                }
            }
            let builder = reqwest::Client::builder().local_address(local);
            #[cfg(target_os = "macos")]
            let builder = builder.interface(&porthub_mesh::underlay::interface_name(local).map_err(|_| Failure::Unavailable)?);
            let client = builder.redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(2).pool_idle_timeout(Duration::from_secs(60))
                .connect_timeout(Duration::from_secs(3)).timeout(Duration::from_secs(40))
                .build().map_err(|_| Failure::Unavailable)?;
            *cached = Some((local, client.clone(), Instant::now() + Duration::from_secs(30)));
            return Ok(client);
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { let _ = base; Ok(self.http.clone()) }
    }
    async fn refresh_underlay(&self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some((_, _, until)) = self.underlay.lock().await.as_mut() { *until = Instant::now(); }
    }
    pub fn new_private(profile: &crate::private_profile::Profile) -> anyhow::Result<Self> {
        let mut control = Self::new(profile.control_profile())?;
        control.private_peer_id = Some(profile.peer_id.clone());
        Ok(control)
    }
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    pub(crate) fn authorities(&self) -> Vec<String> {
        let preferred = self
            .preferred
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|(_, until)| Instant::now() < *until)
            .map(|(base, _)| base.clone());
        let mut bases = Vec::new();
        for base in preferred
            .iter()
            .chain(std::iter::once(&self.profile.server))
            .chain(&self.profile.fallback_servers)
        {
            if !bases.contains(base) {
                bases.push(base.clone());
            }
        }
        bases
    }
    pub(crate) async fn release_request(&self, base: &str, target: &str) -> Result<reqwest::RequestBuilder, Failure> {
        Ok(self.http_for(base).await?
            .get(format!("{base}/api/{}", self.release_path(Some(target))))
            .header("x-porthub-agent-protocol", "rust-v1")
            .timeout(Duration::from_secs(600)))
    }
    pub(crate) fn release_path(&self, target: Option<&str>) -> String {
        // URL path segments encode enrollment secrets without allowing '/',
        // '?', or '#' in a token to change routing. This URL is never fetched.
        let mut path = url::Url::parse("https://relative.invalid/").unwrap();
        {
            let mut segments = path.path_segments_mut().unwrap();
            segments.extend([
                "machines",
                &self.profile.machine_id,
                &self.profile.token,
                "downloads",
            ]);
            if let Some(target) = target {
                segments.extend(["agent", target]);
            } else {
                segments.push("releases");
            }
        }
        path.path().trim_start_matches('/').to_owned()
    }
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        query: &[(&str, String)],
    ) -> Result<Reply, Failure> {
        self.request_accept(method, path, body, query, None).await
    }
    pub async fn request_accept(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        query: &[(&str, String)],
        accept: Option<&str>,
    ) -> Result<Reply, Failure> {
        let mut query = query.to_vec();
        if matches!(
            path,
            "machines/client/auth"
                | "machines/client/sync"
                | "machines/client/config"
                | "machines/client/config.toml"
                | "machines/client/changes"
                | "machines/client/changes.toml"
        ) {
            if !self.profile.setup_overrides.contains_key("public_base_url") {
                query.push(("public_base_url", self.profile.server.clone()));
            }
            query.extend(
                self.profile
                    .setup_overrides
                    .iter()
                    .map(|(key, value)| (key.as_str(), value.clone())),
            );
        }
        for base in self.authorities() {
            let http = self.http_for(&base).await?;
            let mut request = http
                .request(method.clone(), format!("{base}/api/{path}"))
                .header("x-porthub-agent-protocol", "rust-v1");
            if let Some(accept) = accept {
                request = request.header(reqwest::header::ACCEPT, accept);
            }
            if !query.is_empty() {
                request = request.query(&query);
            }
            if let Some(body) = &body {
                request = request.json(body);
            }
            let mut response = match request.send().await {
                Ok(response) => response,
                Err(_) => { self.refresh_underlay().await; continue; },
            };
            if response.status().is_redirection() || response.status().is_server_error() {
                continue;
            }
            if !response.status().is_success() {
                return Err(Failure::Rejected(response.status().as_u16()));
            }
            let status = response.status();
            let headers = response.headers().clone();
            let mut bytes = Vec::new();
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) if bytes.len() + chunk.len() <= 4 * 1024 * 1024 => {
                        bytes.extend_from_slice(&chunk)
                    }
                    Ok(None) => break,
                    Ok(Some(_)) => return Err(Failure::InvalidResponse),
                    Err(_) => return Err(Failure::Unavailable),
                }
            }
            *self.preferred.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((base, Instant::now() + Duration::from_secs(30)));
            return Ok(Reply {
                status,
                headers,
                bytes,
            });
        }
        Err(Failure::Unavailable)
    }
    pub async fn pending_private_install(&self) -> Result<Reply, Failure> {
        self.request_accept(
            Method::POST,
            "machines/client/private-install",
            Some(serde_json::json!({
                "machine_id": self.profile.machine_id,
                "token": self.profile.token,
            })),
            &[],
            Some("application/vnd.porthub.private-install+json"),
        )
        .await
    }
    pub async fn sync(&self, hostname: &str, handled: &str) -> Result<Reply, Failure> {
        self.request(Method::POST,"machines/client/sync",Some(serde_json::json!({"machine_id":self.profile.machine_id,"token":self.profile.token,"hostname":hostname,"local_ip":local_address(),"client_os":std::env::consts::OS,"client_arch":std::env::consts::ARCH,"client_os_id":crate::os_info::current().id,"client_os_name":crate::os_info::current().name,"client_version":crate::VERSION,"client_update_last_handled_request_id":handled,"is_active":true})),&[]).await
    }
    pub async fn changes(&self, version: &str) -> Result<Reply, Failure> {
        self.request(
            Method::GET,
            "machines/client/changes.toml",
            None,
            &[
                ("machine_id", self.profile.machine_id.clone()),
                ("token", self.profile.token.clone()),
                ("since", version.into()),
                ("wait_seconds", "25".into()),
            ],
        )
        .await
    }
    pub async fn deletion_ack(&self) -> Result<(), Failure> {
        self.request(Method::POST,"machines/client/deletion-ack",Some(serde_json::json!({"machine_id":self.profile.machine_id,"token":self.profile.token})),&[]).await.map(|_|())
    }
    pub async fn log_requested(&self) -> Result<bool, Failure> {
        if let Some(peer_id) = &self.private_peer_id {
            let reply = self
                .request(
                    Method::GET,
                    "private/client/log-stream",
                    None,
                    &[
                        ("peer_id", peer_id.clone()),
                        ("token", self.profile.token.clone()),
                    ],
                )
                .await?;
            let body = reply.json()?;
            if body["peer_id"] != *peer_id {
                return Err(Failure::InvalidResponse);
            }
            return body["active"].as_bool().ok_or(Failure::InvalidResponse);
        }
        let reply = self
            .request(
                Method::GET,
                "machines/client/log-stream",
                None,
                &[
                    ("machine_id", self.profile.machine_id.clone()),
                    ("token", self.profile.token.clone()),
                ],
            )
            .await?;
        if reply
            .headers
            .get("x-porthub-machine-id")
            .and_then(|value| value.to_str().ok())
            != Some(self.profile.machine_id.as_str())
        {
            return Err(Failure::InvalidResponse);
        }
        let body = reply.json()?;
        let active = body["active"].as_bool().ok_or(Failure::InvalidResponse)?;
        if reply
            .headers
            .get("x-porthub-log-stream-active")
            .and_then(|value| value.to_str().ok())
            != Some(if active { "true" } else { "false" })
        {
            return Err(Failure::InvalidResponse);
        }
        Ok(active)
    }
    pub async fn upload_logs(&self, lines: &[String]) -> Result<(), Failure> {
        if lines.is_empty() {
            return Ok(());
        }
        if lines.len() > 100 || lines.iter().any(|line| line.chars().count() > 4000) {
            return Err(Failure::InvalidResponse);
        }
        let (endpoint, body, expected_id) = if let Some(peer_id) = &self.private_peer_id {
            (
                "private/client/logs",
                serde_json::json!({"peer_id":peer_id,"token":self.profile.token,"source":"agent","lines":lines}),
                peer_id.as_str(),
            )
        } else {
            (
                "machines/client/logs",
                serde_json::json!({"machine_id":self.profile.machine_id,"token":self.profile.token,"source":"agent","lines":lines}),
                self.profile.machine_id.as_str(),
            )
        };
        let reply = self
            .request(Method::POST, endpoint, Some(body), &[])
            .await?;
        let body = reply.json()?;
        let id_field = if self.private_peer_id.is_some() {
            "peer_id"
        } else {
            "machine_id"
        };
        if body["data"][id_field] != expected_id
            || body["data"]["count"].as_u64() != Some(lines.len() as u64)
        {
            return Err(Failure::InvalidResponse);
        }
        Ok(())
    }
}
