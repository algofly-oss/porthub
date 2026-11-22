//! Private SSH-forward host catalog. A name is published only under a current
//! enrollment lease and while its PAN address is captured by this native TUN.
use super::authority_event::Authority;
use crate::{control::Control, private_profile::Profile};
use anyhow::{anyhow, ensure, Context, Result};
use porthub_mesh::{lan_routes::Network, udp::SendPermit};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

mod tcp;
pub(super) use tcp::{Native, Reply};

const MAX_DESCRIPTORS: usize = 2048;
const MAX_CATALOG_BYTES: usize = 512 * 1024;

#[derive(Deserialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    entry_id: String,
    host: String,
    address: Ipv4Addr,
    ports: Vec<u16>,
}
#[derive(Deserialize)]
struct Catalog {
    // A legacy gateway cannot assign isolated PAN addresses. Leave its names
    // unpublished: a fallback loopback answer can expose unrelated local apps.
    #[serde(default)]
    hosts: Vec<Descriptor>,
}
fn valid_id(id: &str) -> bool {
    id.len() == 24
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Catalog {
    fn validate(mut self, suffix: &str) -> Result<Self> {
        ensure!(
            self.hosts.len() <= MAX_DESCRIPTORS,
            "too many SSH forwarding hosts"
        );
        let mut names = HashSet::new();
        let mut addresses = HashSet::new();
        for host in &mut self.hosts {
            let zone = format!(".forwards.{suffix}");
            let label = host
                .host
                .strip_suffix(&zone)
                .context("SSH hostname outside forwarding zone")?;
            ensure!(
                valid_id(&host.entry_id)
                    && (1..=63).contains(&label.len())
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "invalid SSH forwarding hostname"
            );
            ensure!(
                host.address.is_private() && addresses.insert(host.address),
                "invalid or duplicate SSH forwarding address"
            );
            ensure!(
                names.insert(label.to_string())
                    && (label == host.entry_id || names.insert(host.entry_id.clone())),
                "SSH forwarding name collision"
            );
            host.ports.sort_unstable();
            ensure!(
                host.ports.len() <= 32
                    && !host.ports.contains(&0)
                    && !host.ports.windows(2).any(|p| p[0] == p[1]),
                "invalid SSH forward port list"
            );
        }
        Ok(self)
    }
}
struct Entry {
    identity: Descriptor,
    stop: CancellationToken,
}
#[derive(Default)]
struct Entries {
    fetched: bool,
    by_address: HashMap<Ipv4Addr, Arc<Entry>>,
    by_name: HashMap<String, Ipv4Addr>,
}
impl Entries {
    fn reconcile(&mut self, catalog: Option<Catalog>) {
        let mut current = Self {
            fetched: catalog.is_some(),
            ..Default::default()
        };
        let catalog = catalog.unwrap_or(Catalog { hosts: vec![] });
        for identity in catalog.hosts {
            let address = identity.address;
            current.by_name.insert(identity.host.clone(), address);
            let (_, suffix) = identity.host.split_once('.').expect("validated SSH host");
            current
                .by_name
                .insert(format!("{}.{suffix}", identity.entry_id), address);
            let entry = if self
                .by_address
                .get(&address)
                .is_some_and(|entry| entry.identity == identity)
            {
                self.by_address.remove(&address).unwrap()
            } else {
                Arc::new(Entry {
                    identity,
                    stop: CancellationToken::new(),
                })
            };
            current.by_address.insert(address, entry);
        }
        for retired in self.by_address.values() {
            tracing::debug!("SSH host catalog entry retired");
            retired.stop.cancel();
        }
        *self = current;
    }
}
#[derive(Default)]
struct Capture {
    own: Option<Ipv4Addr>,
    pools: Vec<Network>,
    stop: CancellationToken,
}
impl Capture {
    fn allows(&self, address: Ipv4Addr) -> bool {
        self.own.is_some_and(|own| own != address)
            && self.pools.iter().any(|pool| pool.contains(address))
    }
}
struct Generation {
    client: Client,
    suffix: String,
    cursor: tokio::sync::watch::Sender<Uuid>,
    lease: RwLock<Authority<()>>,
    entries: RwLock<Entries>,
    stop: CancellationToken,
}
impl Generation {
    fn remaining(&self) -> Result<Duration> {
        ensure!(!self.stop.is_cancelled(), "private forwards retired");
        let left = self
            .lease
            .read()
            .map_err(|_| anyhow!("private lease unavailable"))?
            .remaining()?
            .context("private forwards require a witnessed lease")?;
        ensure!(!left.is_zero(), "private forwards lease expired");
        Ok(left)
    }
    async fn until_expiry(&self) {
        while let Ok(left) = self.remaining() {
            tokio::select! {_=self.stop.cancelled()=>break,_=tokio::time::sleep(left)=>{}}
        }
        tracing::debug!(remaining=?self.remaining(), "SSH host catalog lease ended");
        self.stop.cancel();
    }
    async fn run(&self) {
        let mut changes = self.cursor.subscribe();
        let mut retry = Duration::from_secs(1);
        loop {
            let _ = changes.borrow_and_update();
            let fetched = tokio::select! {biased;_=changes.changed()=>continue,result=self.client.fetch()=>result.and_then(|catalog|catalog.validate(&self.suffix))};
            let valid = fetched.is_ok();
            self.entries
                .write()
                .expect("forward catalog")
                .reconcile(fetched.ok());
            if valid {
                retry = Duration::from_secs(1);
                if changes.changed().await.is_err() {
                    return;
                }
            } else {
                tokio::select! {_=changes.changed()=>{},_=tokio::time::sleep(retry)=>{}}
                retry = (retry * 2).min(Duration::from_secs(15));
            }
        }
    }
}
#[derive(Clone, Default)]
pub(super) struct Names {
    current: Arc<RwLock<Option<Arc<Generation>>>>,
    capture: Arc<RwLock<Capture>>,
}
impl Names {
    pub(super) fn resolve(&self, name: &str) -> Result<Option<Ipv4Addr>> {
        let current = self.current.read().expect("forward generation lock");
        let g = current
            .as_ref()
            .context("private forward catalog pending")?;
        g.remaining()?;
        let entries = g.entries.read().expect("forward catalog");
        ensure!(entries.fetched, "private forward catalog pending");
        let Some(address) = entries.by_name.get(name.trim_end_matches('.')).copied() else {
            return Ok(None);
        };
        ensure!(
            self.capture
                .read()
                .expect("forward capture routes")
                .allows(address),
            "private forward route unavailable"
        );
        Ok(Some(address))
    }
    #[cfg(test)]
    pub(super) fn address(&self, name: &str) -> Option<Ipv4Addr> {
        self.resolve(name).ok().flatten()
    }
    fn target(&self, address: Ipv4Addr) -> Option<Scope> {
        let current = self.current.read().ok()?;
        let g = current.as_ref()?;
        let entry = g.entries.read().ok()?.by_address.get(&address)?.clone();
        let capture = self.capture.read().ok()?;
        capture.allows(address).then(|| Scope {
            g: g.clone(),
            entry,
            capture: capture.stop.clone(),
        })
    }
}
#[derive(Clone)]
struct Scope {
    g: Arc<Generation>,
    entry: Arc<Entry>,
    capture: CancellationToken,
}
impl Scope {
    fn current(&self) -> Option<SendPermit> {
        let lease = self.g.lease.read().ok()?.clone();
        let grant = self.entry.stop.clone();
        let generation = self.g.stop.clone();
        let capture = self.capture.clone();
        let permit = SendPermit::bounded(
            move || !grant.is_cancelled() && !generation.is_cancelled() && !capture.is_cancelled(),
            move || lease.remaining().ok().flatten(),
        );
        permit.valid().then_some(permit)
    }
    fn allows(&self, port: u16) -> bool {
        let ports = &self.entry.identity.ports;
        port != 0 && (ports.is_empty() || ports.binary_search(&port).is_ok())
    }
}
struct Client {
    control: Arc<Control>,
    profile: Profile,
    instance: String,
}
pub(super) struct Manager {
    names: Names,
    profile: Profile,
    instance: String,
}
impl Manager {
    pub(super) fn new(profile: Profile, instance: String) -> Self {
        Self {
            names: Names::default(),
            profile,
            instance,
        }
    }
    pub(super) fn names(&self) -> Names {
        self.names.clone()
    }
    pub(super) fn capture(&self, own: Option<Ipv4Addr>, pools: &[Network]) {
        let mut capture = self.names.capture.write().expect("forward capture routes");
        if capture.own != own || capture.pools != pools {
            tracing::debug!(
                have_own = own.is_some(),
                previous_pools = capture.pools.len(),
                pools = pools.len(),
                "SSH host capture changed"
            );
            capture.stop.cancel();
            *capture = Capture {
                own,
                pools: pools.to_vec(),
                stop: CancellationToken::new(),
            };
        }
    }
    pub(super) fn update<T>(&self, authority: &Authority<T>, suffix: Option<&str>) {
        let mut current = self.names.current.write().expect("forward generation lock");
        let wanted = authority
            .forward_sync
            .as_ref()
            .zip(suffix)
            .filter(|(_, s)| {
                !s.is_empty()
                    && authority
                        .remaining()
                        .is_ok_and(|r| r.is_some_and(|d| !d.is_zero()))
            });
        if let (Some(g), Some(((cursor, control), suffix))) = (current.as_ref(), wanted) {
            // The workspace write fence protects machine-to-machine TCP replay. SSH
            // grants have their own authenticated change cursor and server-side
            // stream checks. Unrelated writes must not retire an active SSH host.
            if g.suffix == suffix
                && Arc::ptr_eq(&g.client.control, control)
                && g.remaining().is_ok()
            {
                *g.lease.write().expect("forward lease lock") = authority.retained();
                g.cursor.send_if_modified(|old| {
                    if old == cursor {
                        false
                    } else {
                        *old = *cursor;
                        true
                    }
                });
                return;
            }
        }
        if let Some(old) = current.take() {
            tracing::debug!(remaining=?old.remaining(),renewed=wanted.is_some(),"SSH host catalog replaced");
            old.stop.cancel();
        }
        let Some(((cursor, control), suffix)) = wanted else {
            return;
        };
        let generation = Arc::new(Generation {
            client: Client {
                control: control.clone(),
                profile: self.profile.clone(),
                instance: self.instance.clone(),
            },
            suffix: suffix.into(),
            cursor: tokio::sync::watch::channel(*cursor).0,
            lease: RwLock::new(authority.retained()),
            entries: Default::default(),
            stop: CancellationToken::new(),
        });
        *current = Some(generation.clone());
        tokio::spawn(async move {
            tokio::select! {biased;_=generation.until_expiry()=>{},_=generation.run()=>{}}
        });
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        if let Some(old) = self
            .names
            .current
            .write()
            .expect("forward generation lock")
            .take()
        {
            old.stop.cancel();
        }
    }
}
impl Client {
    fn origins(&self) -> impl Iterator<Item = String> {
        let allow_test = self.profile.allow_insecure_http_for_tests;
        self.control.authorities().into_iter().filter(move |url| {
            url.starts_with("https://") || (allow_test && url.starts_with("http://"))
        })
    }

    async fn fetch(&self) -> Result<Catalog> {
        for base in self.origins() {
            let result = async {
                let request = self.control.forward_catalog_request(&base).await?;
                let mut response = request
                    .bearer_auth(&self.profile.token)
                    .header("x-porthub-host-forwards", "1")
                    .header("x-porthub-peer", &self.profile.peer_id)
                    .header("x-porthub-instance", &self.instance)
                    .send()
                    .await?;
                ensure!(
                    response.status() == reqwest::StatusCode::OK,
                    "private catalog denied"
                );
                ensure!(
                    response.content_length().unwrap_or(0) <= MAX_CATALOG_BYTES as u64,
                    "catalog too large"
                );
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    ensure!(
                        chunk.len() <= MAX_CATALOG_BYTES - bytes.len(),
                        "catalog too large"
                    );
                    bytes.extend_from_slice(&chunk);
                }
                Ok::<Catalog, anyhow::Error>(serde_json::from_slice(&bytes)?)
            }
            .await;
            if let Ok(catalog) = result {
                return Ok(catalog);
            }
        }
        anyhow::bail!("private forward catalog unavailable")
    }

    async fn open(&self, id: &str, port: u16, dynamic: bool) -> Result<porthub_egress::BoxStream> {
        for base in self.origins() {
            let trial = async {
                let action = if dynamic { "host-connect" } else { "connect" };
                let mut url = url::Url::parse(&format!(
                    "{base}/api/port-forwards/agent/{id}/{port}/{action}"
                ))?;
                let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
                url.set_scheme(scheme)
                    .map_err(|_| anyhow!("invalid forward origin"))?;
                let sources = self.control.stream_sources(&base).await?;
                let stream: TcpStream = porthub_mesh::underlay::connect(&url, &sources).await?;
                let _ = stream.set_nodelay(true);
                let mut request = url.as_str().into_client_request()?;
                request.headers_mut().insert(
                    "authorization",
                    format!("Bearer {}", self.profile.token).parse()?,
                );
                request
                    .headers_mut()
                    .insert("x-porthub-peer", self.profile.peer_id.parse()?);
                request
                    .headers_mut()
                    .insert("x-porthub-instance", self.instance.parse()?);
                let limits = WebSocketConfig::default()
                    .read_buffer_size(8192)
                    .write_buffer_size(8192)
                    .max_message_size(Some(65536))
                    .max_frame_size(Some(65536));
                let connector = self.control.forward_tls()?;
                let (ws, _) = tokio_tungstenite::client_async_tls_with_config(
                    request,
                    stream,
                    Some(limits),
                    connector,
                )
                .await?;
                porthub_egress::websocket::stream(ws)
            };
            if let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(4), trial).await {
                return Ok(stream);
            }
        }
        anyhow::bail!("private forward stream unavailable")
    }
}

#[cfg(test)]
mod tests;
