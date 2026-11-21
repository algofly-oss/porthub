//! Enrolled consumers of temporary SSH forwards. Each listener belongs to a
//! successful private sync and an approved catalog entry. Nothing is persisted.
use super::authority_event::Authority;
use crate::{control::Control, private_profile::Profile};
use anyhow::{anyhow, ensure, Context, Result};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_STREAMS: usize = 64;
const MAX_DESCRIPTORS: usize = 2048;
const MAX_CATALOG_BYTES: usize = 512 * 1024;

struct Generation {
    control: Arc<Control>,
    cursor: tokio::sync::watch::Sender<Uuid>,
    suffix: String,
    lease: RwLock<Authority<()>>,
    published: RwLock<HashMap<String, Arc<AtomicBool>>>,
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
            tokio::select! {
                _ = self.stop.cancelled() => break,
                _ = tokio::time::sleep(left) => {}
            }
        }
        self.stop.cancel();
    }

    async fn during<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::pin!(future);
        tokio::select! {
            biased;
            _ = self.stop.cancelled() => Err(anyhow!("private forwards retired")),
            result = std::future::poll_fn(|cx| {
                if let Err(error) = self.remaining() {
                    return std::task::Poll::Ready(Err(error));
                }
                future.as_mut().poll(cx)
            }) => result
        }
    }
}

#[derive(Clone, Default)]
pub(super) struct Names(Arc<RwLock<Option<Arc<Generation>>>>);
impl Names {
    pub(super) fn reserved(&self, name: &str) -> bool {
        let Some((id, suffix)) = name.trim_end_matches('.').split_once(".forwards.") else {
            return false;
        };
        valid_id(id)
            && self
                .0
                .read()
                .ok()
                .as_deref()
                .and_then(Option::as_ref)
                .is_some_and(|g| g.suffix == suffix)
    }
    pub(super) fn contains(&self, name: &str) -> bool {
        self.0
            .read()
            .ok()
            .as_deref()
            .and_then(Option::as_ref)
            .is_some_and(|g| {
                g.remaining().is_ok()
                    && g.published.read().is_ok_and(|names| {
                        names
                            .get(name.trim_end_matches('.'))
                            .is_some_and(|ready| ready.load(Ordering::Acquire))
                    })
            })
    }
}

struct Client {
    control: Arc<Control>,
    profile: Profile,
    instance: String,
    permits: Arc<Semaphore>,
}

pub(super) struct Manager {
    names: Names,
    profile: Profile,
    instance: String,
    permits: Arc<Semaphore>,
}
impl Manager {
    pub(super) fn new(profile: Profile, instance: String) -> Self {
        Self {
            names: Names::default(),
            profile,
            instance,
            permits: Arc::new(Semaphore::new(MAX_STREAMS)),
        }
    }
    pub(super) fn names(&self) -> Names {
        self.names.clone()
    }

    pub(super) fn update<T>(&self, authority: &Authority<T>, suffix: Option<&str>) {
        let mut current = self.names.0.write().expect("forward generation lock");
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
            if g.suffix == suffix && Arc::ptr_eq(&g.control, control) && g.remaining().is_ok() {
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
            old.stop.cancel();
        }
        let Some(((cursor, control), suffix)) = wanted else {
            return;
        };
        let generation = Arc::new(Generation {
            control: control.clone(),
            cursor: tokio::sync::watch::channel(*cursor).0,
            suffix: suffix.to_owned(),
            lease: RwLock::new(authority.retained()),
            published: Default::default(),
            stop: CancellationToken::new(),
        });
        *current = Some(generation.clone());
        let client = Arc::new(Client {
            control: control.clone(),
            profile: self.profile.clone(),
            instance: self.instance.clone(),
            permits: self.permits.clone(),
        });
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = generation.until_expiry() => {},
                _ = client.run(generation.clone()) => {}
            }
        });
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        if let Some(old) = self
            .names
            .0
            .write()
            .expect("forward generation lock")
            .take()
        {
            old.stop.cancel();
        }
    }
}

#[derive(Deserialize)]
struct Catalog {
    forwards: Vec<Descriptor>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    entry_id: String,
    host: String,
    port: u16,
}

fn valid_id(id: &str) -> bool {
    id.len() == 24
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Catalog {
    fn validate(self, suffix: &str) -> Result<BTreeMap<String, Vec<u16>>> {
        ensure!(
            self.forwards.len() <= MAX_DESCRIPTORS,
            "too many private forwards"
        );
        let mut entries: BTreeMap<String, Vec<u16>> = BTreeMap::new();
        let mut ports = HashSet::new();
        for row in self.forwards {
            ensure!(valid_id(&row.entry_id), "invalid private forward ID");
            ensure!(
                row.host == format!("{}.forwards.{suffix}", row.entry_id),
                "private forward is outside the enrolled domain"
            );
            ensure!(
                row.port != 0 && ports.insert(row.port),
                "invalid or duplicated private forward port"
            );
            entries.entry(row.entry_id).or_default().push(row.port);
        }
        for ports in entries.values_mut() {
            ports.sort_unstable();
        }
        Ok(entries)
    }
}

struct EntryTask {
    ports: Vec<u16>,
    name: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for EntryTask {
    fn drop(&mut self) {
        self.task.abort();
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

    async fn run(self: Arc<Self>, g: Arc<Generation>) {
        let mut changes = g.cursor.subscribe();
        let mut active = BTreeMap::<String, EntryTask>::new();
        let mut retry = Duration::from_secs(1);
        loop {
            let _ = changes.borrow_and_update();
            let fetched = tokio::select! {
                biased;
                _ = changes.changed() => continue,
                result = self.fetch() => result.and_then(|catalog| catalog.validate(&g.suffix)),
            };
            let valid = fetched.is_ok();
            let mut desired = fetched.unwrap_or_default();
            // A failed confirmation retires all old descriptors. An unrelated
            // edit leaves a byte stream whose exact authorized ports still exist.
            active.retain(|id, old| {
                if desired.get(id) == Some(&old.ports) {
                    desired.remove(id);
                    true
                } else {
                    g.published
                        .write()
                        .expect("forward names lock")
                        .remove(&old.name);
                    false
                }
            });
            for (id, ports) in desired {
                let name = format!("{id}.forwards.{}", g.suffix);
                let ready = Arc::new(AtomicBool::new(false));
                g.published
                    .write()
                    .expect("forward names lock")
                    .insert(name.clone(), ready.clone());
                let task = tokio::spawn(self.clone().serve_entry(
                    g.clone(),
                    id.clone(),
                    ports.clone(),
                    ready,
                ));
                active.insert(id, EntryTask { ports, name, task });
            }
            if valid {
                retry = Duration::from_secs(1);
                if changes.changed().await.is_err() {
                    return;
                }
            } else {
                tokio::select! { _=changes.changed()=>{}, _=tokio::time::sleep(retry)=>{} }
                retry = (retry * 2).min(Duration::from_secs(15));
            }
        }
    }
    async fn serve_entry(
        self: Arc<Self>,
        g: Arc<Generation>,
        id: String,
        ports: Vec<u16>,
        ready: Arc<AtomicBool>,
    ) {
        let mut retry = Duration::from_millis(200);
        loop {
            let Ok(listeners) = bind_group(&ports).await else {
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(Duration::from_secs(15));
                continue;
            };
            if g.remaining().is_err() {
                return;
            }
            retry = Duration::from_millis(200);
            let mut servers = JoinSet::new();
            for (port, listener) in listeners {
                servers.spawn(self.clone().accept(g.clone(), id.clone(), port, listener));
            }
            ready.store(true, Ordering::Release);
            servers.join_next().await;
            ready.store(false, Ordering::Release);
            servers.shutdown().await;
        }
    }

    async fn accept(
        self: Arc<Self>,
        g: Arc<Generation>,
        id: String,
        port: u16,
        listener: TcpListener,
    ) -> Result<()> {
        let mut streams = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _=g.stop.cancelled()=>return Ok(()),
                _=streams.join_next(), if !streams.is_empty()=>{},
                socket=listener.accept()=>{
                    let (mut local, _) = socket?;
                    let Ok(permit) = self.permits.clone().try_acquire_owned() else {continue};
                    let client = self.clone();
                    let entry = id.clone();
                    let g = g.clone();
                    streams.spawn(async move {
                        let _permit = permit;
                        let _ = g.during(async {
                            let mut remote = client.open(&entry, port).await?;
                            tokio::io::copy_bidirectional(&mut local, &mut remote).await?;
                            Ok(())
                        }).await;
                    });
                }
            }
        }
    }

    async fn open(&self, id: &str, port: u16) -> Result<porthub_egress::BoxStream> {
        for base in self.origins() {
            let trial = async {
                let mut url = url::Url::parse(&format!(
                    "{base}/api/port-forwards/agent/{id}/{port}/connect"
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

async fn bind_group(ports: &[u16]) -> Result<Vec<(u16, TcpListener)>> {
    let mut listeners = Vec::new();
    for &port in ports {
        listeners.push((port, TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?));
    }
    Ok(listeners)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_network::authority_clock::{NativeClock, RequestWindow};
    use axum::{
        extract::{
            ws::{Message, WebSocketUpgrade},
            Path, State,
        },
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use serde_json::{json, Value};
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const ID: &str = "0123456789abcdef01234567";
    const HOST: &str = "0123456789abcdef01234567.forwards.fixture.test";
    const PEER: &str = "000000000000000000000001:000000000000000000000002";
    const TOKEN: &str = "test-private-credential-scope-12345678";

    #[derive(Default)]
    struct Fixture {
        rows: RwLock<Vec<Value>>,
        catalogs: AtomicUsize,
        streams: AtomicUsize,
    }
    fn authorized(headers: &HeaderMap) -> bool {
        headers.get("authorization").and_then(|s| s.to_str().ok())
            == Some(format!("Bearer {TOKEN}").as_str())
            && headers.get("x-porthub-peer").and_then(|s| s.to_str().ok()) == Some(PEER)
            && headers
                .get("x-porthub-instance")
                .and_then(|s| s.to_str().ok())
                == Some("test-instance")
    }
    async fn config(State(s): State<Arc<Fixture>>, headers: HeaderMap) -> axum::response::Response {
        if !authorized(&headers) {
            return StatusCode::FORBIDDEN.into_response();
        }
        s.catalogs.fetch_add(1, Ordering::SeqCst);
        Json(json!({"forwards":s.rows.read().unwrap().clone()})).into_response()
    }
    async fn socket(
        State(s): State<Arc<Fixture>>,
        Path((id, port)): Path<(String, u16)>,
        headers: HeaderMap,
        ws: WebSocketUpgrade,
    ) -> axum::response::Response {
        let allowed = s
            .rows
            .read()
            .unwrap()
            .iter()
            .any(|row| row["entryId"] == id && row["port"] == port);
        if !authorized(&headers) || !allowed {
            return StatusCode::FORBIDDEN.into_response();
        }
        s.streams.fetch_add(1, Ordering::SeqCst);
        ws.on_upgrade(|mut ws| async move {
            while let Some(Ok(msg)) = ws.recv().await {
                match msg {
                    Message::Binary(_) => {
                        if ws.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Message::Text(eof) if eof == "eof" => {
                        let _ = ws.send(Message::Binary(b"end".as_slice().into())).await;
                        let _ = ws.send(Message::Text("eof".into())).await;
                        break;
                    }
                    _ => break,
                }
            }
        })
    }
    fn authority(cursor: Option<Uuid>, control: &Arc<Control>) -> Result<Authority<()>> {
        let mut a = Authority::new(
            (),
            Some(RequestWindow::start(Arc::new(NativeClock))?),
            chrono::Utc::now() + chrono::Duration::seconds(14),
        );
        a.forward_sync = cursor.map(|id| (id, control.clone()));
        Ok(a)
    }
    async fn wait_for(mut condition: impl FnMut() -> bool) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(4), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
        })
        .await?;
        Ok(())
    }
    async fn exchange(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
        let mut reply = vec![0; payload.len()];
        stream.write_all(payload).await?;
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut reply)).await??;
        ensure!(reply == payload, "fixture echo differs");
        Ok(())
    }

    #[tokio::test]
    async fn catalog_reconciles_live_sockets_and_retries_only_conflicted_local_ports() -> Result<()>
    {
        let gw = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let server = format!("http://{}", gw.local_addr()?);
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = occupied.local_addr()?.port();
        let spare = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let other = spare.local_addr()?.port();
        drop(spare);
        let fixture = Arc::new(Fixture::default());
        *fixture.rows.write().unwrap() = vec![
            json!({"entryId":ID,"host":HOST,"port":other}),
            json!({"entryId":ID,"host":HOST,"port":port}),
        ];
        let app = Router::new()
            .route("/api/port-forwards/agent/config", get(config))
            .route("/api/port-forwards/agent/{id}/{port}/connect", get(socket))
            .with_state(fixture.clone());
        let gateway = tokio::spawn(async move { axum::serve(gw, app).await });
        let profile = Profile {
            server,
            peer_id: PEER.into(),
            workspace: "000000000000000000000001".into(),
            token: TOKEN.into(),
            account_email: None,
            fallback_servers: vec![],
            allow_insecure_http_for_tests: true,
        };
        let control = Arc::new(Control::new_private(&profile)?);
        let lease = |cursor| authority(cursor, &control);
        let manager = Manager::new(profile, "test-instance".into());
        let names = manager.names();
        manager.update(&lease(None)?, Some("fixture.test"));
        tokio::task::yield_now().await;
        assert_eq!(fixture.catalogs.load(Ordering::SeqCst), 0);
        let first = Uuid::new_v4();
        manager.update(&lease(Some(first))?, Some("fixture.test"));
        wait_for(|| fixture.catalogs.load(Ordering::SeqCst) == 1).await?;
        assert!(!names.contains(HOST));
        drop(occupied);
        wait_for(|| names.contains(HOST)).await?;
        let mut connection = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
        exchange(&mut connection, b"before change").await?;
        manager.update(&lease(Some(first))?, Some("fixture.test"));
        assert_eq!(fixture.catalogs.load(Ordering::SeqCst), 1);
        fixture.rows.write().unwrap().reverse();
        manager.update(&lease(Some(Uuid::new_v4()))?, Some("fixture.test"));
        wait_for(|| fixture.catalogs.load(Ordering::SeqCst) == 2).await?;
        exchange(&mut connection, b"after unrelated change").await?;
        assert_eq!(fixture.streams.load(Ordering::SeqCst), 1);
        let mut half = TcpStream::connect((Ipv4Addr::LOCALHOST, other)).await?;
        half.write_all(b"hello").await?;
        half.shutdown().await?;
        let mut result = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), half.read_to_end(&mut result)).await??;
        assert_eq!(result, b"helloend");
        fixture.rows.write().unwrap().clear();
        manager.update(&lease(Some(Uuid::new_v4()))?, Some("fixture.test"));
        wait_for(|| !names.contains(HOST)).await?;
        let closure = tokio::time::timeout(Duration::from_secs(2), connection.read_u8()).await?;
        assert!(closure.is_err());
        let rebound = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await?;
        assert_eq!(rebound.local_addr()?.ip(), Ipv4Addr::LOCALHOST);
        *fixture.rows.write().unwrap() = vec![json!({"entryId":ID,"host":HOST,"port":other})];
        manager.update(&lease(Some(Uuid::new_v4()))?, Some("fixture.test"));
        wait_for(|| names.contains(&format!("{HOST}."))).await?;
        drop(manager);
        assert!(!names.contains(HOST));
        gateway.abort();
        Ok(())
    }

    #[test]
    fn scoped_descriptors_reject_substituted_alias_and_duplicate_ports() {
        let parse = |value: Value| {
            serde_json::from_value::<Catalog>(json!({"forwards":value}))
                .unwrap()
                .validate("fixture.test")
        };
        let row = json!({"entryId":ID,"host":HOST,"port":10240});
        assert!(parse(json!([row])).is_ok());
        assert!(parse(json!([row, row])).is_err());
        for (k, v) in [
            ("host", json!("localhost")),
            ("host", json!("forward.bad.test")),
            ("entryId", json!("../foreign")),
            ("port", json!(0)),
        ] {
            let mut bad = row.clone();
            bad[k] = v;
            assert!(parse(json!([bad])).is_err());
        }
    }
}
