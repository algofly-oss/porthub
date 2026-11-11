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
    #[cfg(test)]
    test_paths: Option<Vec<crate::outbound::Candidate>>,
    profile: Profile,
    outbound_settings: crate::outbound::Settings,
    path_state: tokio::sync::Mutex<std::collections::HashMap<String,crate::outbound::Selection>>,
    private_peer_id: Option<String>,
    http: reqwest::Client,
    preferred: Mutex<Option<(String, Instant)>>,
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    underlay: tokio::sync::Mutex<Option<(crate::outbound::Candidate, reqwest::Client, Instant, String)>>,
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
            #[cfg(test)]
            test_paths: None,
            profile,
            outbound_settings: crate::outbound::Settings::from_env()?,
            path_state: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            private_peer_id: None,
            http,
            preferred: Mutex::new(None),
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            underlay: tokio::sync::Mutex::new(None),
        })
    }
    /// Bind only to sources permitted by the kernel-selected egress policy.
    /// Refresh lazily: no timer or discovery work runs while control is idle.
    async fn http_for(&self, base: &str) -> Result<(reqwest::Client, Option<crate::outbound::Candidate>), Failure> {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        {
            let loopback = url::Url::parse(base).ok().and_then(|url| url.host_str().map(str::to_owned))
                .is_some_and(|host| host == "localhost" || host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()));
            #[cfg(test)]
            let loopback = loopback && self.test_paths.is_none();
            if loopback { return Ok((self.http.clone(), None)); }
            let mut cached = self.underlay.lock().await;
            if let Some((candidate, client, until, authority)) = &*cached {
                if authority == base && Instant::now() < *until { return Ok((client.clone(), Some(candidate.clone()))); }
            }
            if self.outbound_settings.system { return Ok((self.http.clone(), None)); }
            let url = url::Url::parse(base).map_err(|_| Failure::Unavailable)?;
            let host = url.host_str().ok_or(Failure::Unavailable)?;
            let port = url.port_or_known_default().ok_or(Failure::Unavailable)?;
            let destinations: Vec<_> = tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((host.trim_matches(['[',']']),port))).await
                .map_err(|_| Failure::Unavailable)?.map_err(|_| Failure::Unavailable)?.take(16).collect();
            let candidates = tokio::time::timeout(Duration::from_secs(2), crate::outbound::discover(&self.outbound_settings,&destinations)).await
                .map_err(|_| Failure::Unavailable)?.map_err(|_| Failure::Unavailable)?;
            #[cfg(test)]
            let candidates = self.test_paths.clone().unwrap_or(candidates);
            let mut state = self.path_state.lock().await;
            let candidate = state.entry(base.to_owned()).or_default().order(&candidates,Instant::now()).into_iter().next().ok_or(Failure::Unavailable)?;
            let local = candidate.source;
            let destination = candidate.destination;
            let builder = reqwest::Client::builder().local_address(local).resolve_to_addrs(host, &[destination]);
            #[cfg(target_os = "macos")]
            let builder = builder.interface(&porthub_mesh::underlay::interface_name(local).map_err(|_| Failure::Unavailable)?);
            let client = builder.redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(2).pool_idle_timeout(Duration::from_secs(60))
                .connect_timeout(Duration::from_secs(3)).timeout(Duration::from_secs(40))
                .build().map_err(|_| Failure::Unavailable)?;
            *cached = Some((candidate.clone(), client.clone(), Instant::now() + Duration::from_secs(30), base.to_owned()));
            return Ok((client, Some(candidate)));
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        { let _ = base; Ok((self.http.clone(), None)) }
    }
    async fn refresh_underlay(&self, base: &str, failed: Option<&crate::outbound::Candidate>) {
        #[cfg(any(target_os = "linux", target_os = "macos", windows))]
        {
            if let Some((_, _, until, _)) = self.underlay.lock().await.as_mut() { *until = Instant::now(); }
            let mut state = self.path_state.lock().await;
            if let Some(candidate) = failed { state.entry(base.to_owned()).or_default().failure(candidate, Instant::now()); }
        }
    }
    pub fn new_private(profile: &crate::private_profile::Profile) -> anyhow::Result<Self> {
        let mut control = Self::new(profile.control_profile())?;
        control.private_peer_id = Some(profile.peer_id.clone());
        Ok(control)
    }
    pub fn profile(&self) -> &Profile {
        &self.profile
    }
    pub(crate) fn prefer_proxy_authority(&self,base:String) {
        *self.preferred.lock().unwrap_or_else(|poison|poison.into_inner())=Some((base,Instant::now()+Duration::from_secs(60)));
    }
    #[cfg(feature="local-tor")]
    pub(crate) async fn proxy_check(&self,private:&crate::private_profile::Profile,grant:&str)->Result<bool,Failure> {
        let mut failure=Failure::Unavailable;
        'proxy_authorities: for base in self.authorities() {
          for _ in 0..8 {
            let Ok((http,candidate))=self.http_for(&base).await else {continue 'proxy_authorities;};
            let response=http.get(format!("{base}/api/access/proxy-check/{grant}"))
                .header("x-porthub-peer",&private.peer_id).bearer_auth(&private.token)
                .timeout(Duration::from_secs(5)).send().await;
            let mut response=match response {
                Ok(response)=>response,
                Err(_)=>{self.refresh_underlay(&base,candidate.as_ref()).await;if candidate.is_some(){continue;}continue 'proxy_authorities;}
            };
            if !response.status().is_success() {
                if matches!(response.status().as_u16(),401|403) {return Err(Failure::Rejected(response.status().as_u16()));}
                failure=Failure::Rejected(response.status().as_u16());continue 'proxy_authorities;
            }
            let mut bytes=Vec::new();
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) if bytes.len()+chunk.len()<=1024=>bytes.extend_from_slice(&chunk),
                    Ok(None)=>break,
                    _=>return Err(Failure::InvalidResponse),
                }
            }
            let ready=serde_json::from_slice::<Value>(&bytes).ok().and_then(|value|value.get("ready").and_then(Value::as_bool)).ok_or(Failure::InvalidResponse)?;
            if let Some(candidate)=candidate {self.path_state.lock().await.entry(base.clone()).or_default().success(candidate);}
            self.prefer_proxy_authority(base);
            return Ok(ready);
          }
        }
        Err(failure)
    }
    pub(crate) async fn stream_sources(&self, base: &str) -> Result<Vec<std::net::IpAddr>, Failure> {
        let host = url::Url::parse(base).ok().and_then(|url|url.host_str().map(str::to_owned));
        if host.as_deref()==Some("localhost") { return Ok(vec![std::net::Ipv4Addr::LOCALHOST.into()]); }
        if let Some(ip)=host.and_then(|host|host.trim_matches(['[',']']).parse::<std::net::IpAddr>().ok()).filter(std::net::IpAddr::is_loopback) {
            return Ok(vec![ip]);
        }
        #[cfg(any(target_os="linux",target_os="macos",windows))]
        {
            // Reuse control's bounded underlay cache; no new discovery timer
            // or origin probe is added for application connections.
            let authority = if base == self.profile.server { self.authorities().into_iter().next().unwrap_or_else(||base.to_owned()) } else { base.to_owned() };
            let (_,candidate)=self.http_for(&authority).await?;
            if let Some(candidate)=candidate { return Ok(vec![candidate.source]); }
            if self.outbound_settings.system { return Ok(Vec::new()); }
            Err(Failure::Unavailable)
        }
        #[cfg(not(any(target_os="linux",target_os="macos",windows)))]
        {
            let sources=crate::private_network::interfaces::current().await.map_err(|_|Failure::Unavailable)?;
            if sources.is_empty() {return Err(Failure::Unavailable);}
            Ok(sources.iter().map(std::net::SocketAddr::ip).collect())
        }
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
        Ok(self.http_for(base).await?.0
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
        // Image JSON may contain a 50 MB file plus base64 overhead. Keep normal
        // control requests short while allowing image uploads on slower links.
        let image_upload = method == Method::POST && path == "machines/client/images";
        let attempt = Duration::from_secs(if image_upload { 270 } else { 40 });
        let deadline = Instant::now() + Duration::from_secs(if image_upload { 300 } else { 45 });
        'authorities: for base in self.authorities() {
          for _ in 0..8 {
            if Instant::now() >= deadline { return Err(Failure::Unavailable); }
            let (http, candidate) = match self.http_for(&base).await { Ok(path) => path, Err(_) => continue 'authorities };
            let mut request = http
                .request(method.clone(), format!("{base}/api/{path}"))
                .header("x-porthub-agent-protocol", "rust-v1")
                .timeout(deadline.saturating_duration_since(Instant::now()).min(attempt));
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
                Err(error) => {
                    self.refresh_underlay(&base,candidate.as_ref()).await;
                    // A connect failure happens before request transmission.
                    // Never replay a possibly committed mutation on a timeout.
                    if error.is_connect() || method == Method::GET || matches!(path,"machines/client/sync"|"access/private/sync") {
                        if candidate.is_none() { continue 'authorities; }
                        continue;
                    }
                    return Err(Failure::Unavailable);
                },
            };
            if response.status().is_redirection() || response.status().is_server_error() {
                continue 'authorities;
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
            {
                let mut state = self.path_state.lock().await;
                if let Some(candidate) = candidate.clone() { state.entry(base.clone()).or_default().success(candidate); }
            }
            *self.preferred.lock().unwrap_or_else(|p| p.into_inner()) =
                Some((base, Instant::now() + Duration::from_secs(30)));
            return Ok(Reply {
                status,
                headers,
                bytes,
            });
          }
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

#[cfg(all(test,feature="local-tor"))]
mod proxy_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    async fn reply(listener:tokio::net::TcpListener,status:&str,body:&str)->anyhow::Result<()> {
        let (mut socket,_)=listener.accept().await?;let mut request=Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut bytes=[0u8;1024];let count=socket.read(&mut bytes).await?;
            anyhow::ensure!(count>0 && request.len()+count<=8192,"invalid test request");request.extend_from_slice(&bytes[..count]);
        }
        let request=String::from_utf8(request)?;
        assert!(request.starts_with(&format!("GET /api/access/proxy-check/{} ","a".repeat(24))));
        let headers=request.to_ascii_lowercase();
        assert!(headers.contains("x-porthub-peer: fixture-peer"));
        assert!(headers.contains("authorization: bearer private-test-token-01234567890123456789"));
        assert!(!headers.contains("public-test-token"));
        socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await?;
        socket.shutdown().await?;Ok(())
    }
    #[tokio::test]
    async fn proxy_preflight_authenticates_privately_and_caches_a_working_fallback()->anyhow::Result<()> {
        let primary=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let fallback=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin=format!("http://{}",primary.local_addr()?);let available=format!("http://{}",fallback.local_addr()?);
        let first=tokio::spawn(reply(primary,"503 Service Unavailable",""));
        let second=tokio::spawn(reply(fallback,"200 OK",r#"{"ready":true}"#));
        let profile:Profile=serde_json::from_value(serde_json::json!({"server":origin,"machine_id":"0123456789abcdef01234567","token":"public-test-token","fallback_servers":[available.clone()],"allow_insecure_http_for_tests":true}))?;
        let private=crate::private_profile::Profile {server:profile.server.clone(),peer_id:"fixture-peer".into(),token:"private-test-token-01234567890123456789".into(),workspace:"fixture".into(),account_email:None,fallback_servers:vec![],allow_insecure_http_for_tests:true};
        let control=Control::new(profile)?;
        assert!(control.proxy_check(&private,&"a".repeat(24)).await?);
        assert_eq!(control.authorities().first(),Some(&available));
        first.await??;second.await??;Ok(())
    }
}

#[cfg(all(test,target_os="linux"))]
mod outbound_tests {
    use super::*;
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    fn control(address: std::net::SocketAddr) -> Control {
        let profile: Profile=serde_json::from_value(serde_json::json!({"server":format!("http://{address}"),"machine_id":"0123456789abcdef01234567","token":"outbound-test-token","allow_insecure_http_for_tests":true})).unwrap();
        let mut control=Control::new(profile).unwrap();
        control.test_paths=Some(["192.0.2.253","127.0.0.2"].into_iter().map(|source|crate::outbound::Candidate {source:source.parse().unwrap(),interface:"fixture".into(),destination:address,gateway:None,metric:None}).collect());
        control
    }
    #[tokio::test]
    async fn actual_socket_failover_uses_another_source_and_reuses_it() -> anyhow::Result<()> {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let control=control(listener.local_addr()?);
        let server=tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket,peer)=listener.accept().await?;
                anyhow::ensure!(peer.ip()=="127.0.0.2".parse::<std::net::IpAddr>()?);
                let mut bytes=[0;4096]; let count=socket.read(&mut bytes).await?;
                anyhow::ensure!(count>0);
                socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await?;
            }
            anyhow::Ok(())
        });
        for _ in 0..2 { control.request(Method::GET,"fixture",None,&[]).await?; }
        server.await??;
        assert_eq!(control.path_state.lock().await.get(&control.profile.server).unwrap().selected().unwrap().source,"127.0.0.2".parse::<std::net::IpAddr>()?);
        Ok(())
    }
    #[tokio::test]
    async fn rejection_stops_failover_and_never_promotes_the_path() -> anyhow::Result<()> {
        let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let mut control=control(listener.local_addr()?);
        control.test_paths.as_mut().unwrap().remove(0);
        let server=tokio::spawn(async move {
            let (mut socket,_)=listener.accept().await?; let mut bytes=[0;4096]; socket.read(&mut bytes).await?;
            socket.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            anyhow::ensure!(tokio::time::timeout(Duration::from_millis(100),listener.accept()).await.is_err());
            anyhow::Ok(())
        });
        assert!(matches!(control.request(Method::GET,"fixture",None,&[]).await,Err(Failure::Rejected(403))));
        assert!(control.path_state.lock().await.get(&control.profile.server).unwrap().selected().is_none());
        server.await??; Ok(())
    }
}

#[cfg(all(test,unix))]
mod diagnostic_failure_tests {
    use super::*;
    #[tokio::test]
    async fn verified_tls_rejects_an_untrusted_gateway_without_sending_credentials() -> anyhow::Result<()> {
        let identity=rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let tls=axum_server::tls_rustls::RustlsConfig::from_der(vec![identity.cert.der().to_vec()],identity.signing_key.serialize_der()).await?;
        let listener=std::net::TcpListener::bind("127.0.0.1:0")?;
        let address=listener.local_addr()?; listener.set_nonblocking(true)?;
        let calls=std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)); let captured=calls.clone();
        let router=axum::Router::new().fallback(move || { let calls=captured.clone(); async move {calls.fetch_add(1,std::sync::atomic::Ordering::SeqCst);"unexpected"} });
        let handle=axum_server::Handle::new();let shutdown=handle.clone();
        let task=tokio::spawn(async move {axum_server::from_tcp_rustls(listener,tls)?.handle(handle).serve(router.into_make_service()).await});
        let profile:Profile=serde_json::from_value(serde_json::json!({"server":format!("https://{address}"),"machine_id":"0123456789abcdef01234567","token":"must-never-arrive"}))?;
        let control=Control::new(profile)?;
        assert!(matches!(control.request(Method::GET,"fixture",None,&[]).await,Err(Failure::Unavailable)));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst),0);
        shutdown.graceful_shutdown(Some(Duration::from_secs(1)));task.await??;
        Ok(())
    }
    #[tokio::test]
    async fn unresolved_gateway_fails_with_a_bounded_redacted_error() -> anyhow::Result<()> {
        let profile:Profile=serde_json::from_value(serde_json::json!({"server":"https://porthub-connectivity-test.invalid","machine_id":"0123456789abcdef01234567","token":"must-not-be-logged"}))?;
        let control=Control::new(profile)?;
        let result=tokio::time::timeout(Duration::from_secs(6),control.request(Method::GET,"fixture",None,&[])).await?;
        assert!(matches!(result,Err(Failure::Unavailable)));
        assert!(!Failure::Unavailable.to_string().contains("must-not-be-logged"));
        Ok(())
    }
}
