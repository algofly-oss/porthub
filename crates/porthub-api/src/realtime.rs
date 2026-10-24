//! Authenticated Socket.IO events on the API's existing listener. Registry
//! entries contain identities, never owning SocketRefs or strong App cycles.
use crate::{
    auth,
    domain::{
        inventory,
        machine_client::{self, View},
    },
    error::{ApiError, ApiResult},
    store, App,
};
use axum::http::HeaderMap;
use futures_util::TryStreamExt;
use mongodb::bson::{doc, oid::ObjectId, Document};
use serde_json::{json, Value};
use socketioxide::{
    extract::{SocketRef, TryData},
    handler::ConnectHandler,
    layer::SocketIoLayer,
    SocketIo, TransportType,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const CTS_STATUS: &str = "/cts/machines/status-snapshot";
pub const STC_STATUS: &str = "/stc/machines/status-snapshot";
pub const STC_CHANGED: &str = "/stc/machines/status-changed";
pub const CTS_CONFIG: &str = "/cts/machines/config-snapshot";
pub const STC_CONFIG: &str = "/stc/machines/config-snapshot";
pub const STC_CONFIG_CHANGED: &str = "/stc/machines/config-changed";
pub const CTS_SUBSCRIBE: &str = "/cts/machines/log-stream-subscribe";
pub const CTS_UNSUBSCRIBE: &str = "/cts/machines/log-stream-unsubscribe";
pub const STC_LOG_STATUS: &str = "/stc/machines/log-stream-status";
pub const STC_LOG_LINE: &str = "/stc/machines/log-stream-line";

#[derive(Clone)]
enum Principal {
    User {
        id: ObjectId,
        token: Arc<str>,
    },
    Machine {
        id: ObjectId,
        owner: ObjectId,
        token: Arc<str>,
    },
}
struct Peer {
    principal: Principal,
    logs: BTreeSet<String>,
}
struct Incoming {
    event: &'static str,
    machine: Option<ObjectId>,
}
struct Actor(tokio::task::JoinHandle<()>);
impl Drop for Actor {
    fn drop(&mut self) {
        self.0.abort();
    }
}
#[derive(Default)]
struct Registry {
    peers: BTreeMap<String, Peer>,
    users: BTreeMap<String, BTreeSet<String>>,
    machines: BTreeMap<String, BTreeSet<String>>,
    logs: BTreeMap<String, BTreeSet<String>>,
}
fn remove(index: &mut BTreeMap<String, BTreeSet<String>>, key: &str, sid: &str) {
    if let Some(sids) = index.get_mut(key) {
        sids.remove(sid);
        if sids.is_empty() {
            index.remove(key);
        }
    }
}
pub struct Hub {
    io: SocketIo,
    layer: SocketIoLayer,
    registry: Mutex<Registry>,
    installed: OnceLock<()>,
    capacity: Arc<Semaphore>,
}
impl Default for Hub {
    fn default() -> Self {
        let (layer, io) = SocketIo::builder()
            .req_path("/socket.io")
            .transports([TransportType::Websocket])
            .connect_timeout(Duration::from_secs(5))
            .ping_interval(Duration::from_secs(25))
            .ping_timeout(Duration::from_secs(20))
            .max_buffer_size(256)
            .max_payload(1_000_000)
            .ws_max_message_size(1_000_000)
            .ws_max_frame_size(1_000_000)
            .build_layer();
        Self {
            io,
            layer,
            registry: Mutex::new(Registry::default()),
            installed: OnceLock::new(),
            capacity: Arc::new(Semaphore::new(4096)),
        }
    }
}
impl Hub {
    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
    fn peer(&self, sid: &str) -> Option<Principal> {
        self.registry()
            .peers
            .get(sid)
            .map(|peer| peer.principal.clone())
    }
    fn socket(&self, sid: &str) -> Option<SocketRef> {
        self.io.of("/")?.get_socket(sid.parse().ok()?)
    }
    pub fn install(app: &Arc<App>) -> SocketIoLayer {
        app.realtime.installed.get_or_init(|| {
            let connect = Arc::downgrade(app);
            let authenticate = Arc::downgrade(app);
            app.realtime.io.ns(
                "/",
                (move |socket: SocketRef| {
                    let app = connect.upgrade();
                    async move {
                        if let Some(app) = app {
                            connected(&app, socket);
                        }
                    }
                })
                .with(
                    move |socket: SocketRef, TryData(payload): TryData<Value>| {
                        let app = authenticate.upgrade();
                        async move {
                            let app = app.ok_or("Connection rejected by server")?;
                            authenticate_socket(&app, &socket, payload.unwrap_or(Value::Null)).await
                        }
                    },
                ),
            );
        });
        app.realtime.layer.clone()
    }
    fn add(&self, sid: String, principal: Principal) {
        let mut registry = self.registry();
        match &principal {
            Principal::User { id, .. } => {
                registry
                    .users
                    .entry(id.to_hex())
                    .or_default()
                    .insert(sid.clone());
            }
            Principal::Machine { id, .. } => {
                registry
                    .machines
                    .entry(id.to_hex())
                    .or_default()
                    .insert(sid.clone());
            }
        }
        registry.peers.insert(
            sid,
            Peer {
                principal,
                logs: BTreeSet::new(),
            },
        );
    }
    fn remove(&self, sid: &str) {
        let mut registry = self.registry();
        let Some(peer) = registry.peers.remove(sid) else {
            return;
        };
        match peer.principal {
            Principal::User { id, .. } => remove(&mut registry.users, &id.to_hex(), sid),
            Principal::Machine { id, .. } => remove(&mut registry.machines, &id.to_hex(), sid),
        }
        for machine in peer.logs {
            remove(&mut registry.logs, &machine, sid);
        }
    }
    fn disconnect(&self, sid: &str) {
        self.remove(sid);
        if let Some(socket) = self.socket(sid) {
            let result = socket.clone().disconnect();
            if !matches!(result, Err(socketioxide::SocketError::InternalChannelFull)) {
                socket.extensions.remove::<Arc<OwnedSemaphorePermit>>();
            }
        }
    }
    pub fn disconnect_machine(&self, id: &str) {
        let sids = self
            .registry()
            .machines
            .get(id)
            .cloned()
            .unwrap_or_default();
        for sid in sids {
            self.disconnect(&sid);
        }
    }
    pub fn disconnect_session(&self, token: &str) {
        let sids:Vec<_>=self.registry().peers.iter().filter(|(_,peer)|matches!(&peer.principal,Principal::User {token:session,..} if session.as_ref()==token))
            .map(|(sid,_)|sid.clone()).collect();
        for sid in sids {
            self.disconnect(&sid);
        }
    }
    pub fn disconnect_user(&self, id: &str) {
        let sids = self.registry().users.get(id).cloned().unwrap_or_default();
        for sid in sids {
            self.disconnect(&sid);
        }
    }
    fn send(&self, sid: &str, event: &str, value: &Value) {
        if self.peer(sid).is_none() {
            return;
        }
        if let Some(socket) = self.socket(sid) {
            if socket.emit(event, value).is_err() {
                self.disconnect(sid);
            }
        } else {
            self.remove(sid);
        }
    }
    async fn valid(&self, app: &App, sid: &str) -> ApiResult<Option<Principal>> {
        let Some(principal) = self.peer(sid) else {
            self.disconnect(sid);
            return Ok(None);
        };
        let valid = match &principal {
            Principal::User { id, token } => {
                auth::user_id(app, token).await?.as_deref() == Some(id.to_hex().as_str())
                    && app
                        .collection("users")
                        .find_one(doc! {"_id":id})
                        .await?
                        .is_some()
            }
            Principal::Machine { id, owner, token } => {
                match machine_client::authenticate(app, &id.to_hex(), token).await {
                    Ok(machine) => machine.get_object_id("user_id").ok() == Some(*owner),
                    Err(error) if error.status.is_server_error() => return Err(error),
                    Err(_) => false,
                }
            }
        };
        if valid {
            Ok(Some(principal))
        } else {
            self.disconnect(sid);
            Ok(None)
        }
    }
    async fn recipients(&self, app: &App, sids: BTreeSet<String>) -> ApiResult<Vec<String>> {
        let mut valid = Vec::new();
        for sid in sids {
            if self.valid(app, &sid).await?.is_some() {
                valid.push(sid);
            }
        }
        Ok(valid)
    }
    pub async fn log_requested(&self, app: &App, id: &str) -> ApiResult<bool> {
        let sids = self.registry().logs.get(id).cloned().unwrap_or_default();
        Ok(!self.recipients(app, sids).await?.is_empty())
    }
    pub async fn status_changed(&self, app: &App, machine: &Document) -> ApiResult<()> {
        let owner = store::id(machine.get("user_id"));
        let sids = self
            .registry()
            .users
            .get(&owner)
            .cloned()
            .unwrap_or_default();
        let payload = json!({"machine":inventory::machine(app,machine)});
        for sid in self.recipients(app, sids).await? {
            self.send(&sid, STC_CHANGED, &payload);
        }
        let id = store::id(machine.get("_id"));
        let sids = self.registry().logs.get(&id).cloned().unwrap_or_default();
        let valid = self.recipients(app, sids).await?;
        let payload = log_status(app, machine, !valid.is_empty(), None);
        for sid in valid {
            self.send(&sid, STC_LOG_STATUS, &payload);
        }
        Ok(())
    }
    pub async fn config_changed(&self, app: &App, id: &str) -> ApiResult<()> {
        let sids = self
            .registry()
            .machines
            .get(id)
            .cloned()
            .unwrap_or_default();
        let valid = self.recipients(app, sids).await?;
        if valid.is_empty() {
            return Ok(());
        }
        let id =
            ObjectId::parse_str(id).map_err(|_| ApiError::bad_request("Invalid machine id"))?;
        let Some(machine) = app.collection("machines").find_one(doc! {"_id":id}).await? else {
            return Ok(());
        };
        self.emit_config(app, &machine, valid, STC_CONFIG_CHANGED)
            .await
    }
    async fn emit_config(
        &self,
        app: &App,
        machine: &Document,
        sids: Vec<String>,
        event: &str,
    ) -> ApiResult<()> {
        let headers = HeaderMap::new();
        let query = std::collections::HashMap::new();
        let config = machine_client::bundle(
            app,
            machine,
            &View {
                headers: &headers,
                query: &query,
            },
        )
        .await?;
        let payload = json!({"machine_id":store::id(machine.get("_id")),"config":config});
        for sid in sids {
            if self.valid(app, &sid).await?.is_some() {
                self.send(&sid, event, &payload);
            }
        }
        Ok(())
    }
    pub async fn log_lines(
        &self,
        app: &App,
        machine: &Document,
        lines: &[String],
        source: &str,
    ) -> ApiResult<()> {
        let id = store::id(machine.get("_id"));
        let sids = self.registry().logs.get(&id).cloned().unwrap_or_default();
        let valid = self.recipients(app, sids).await?;
        for line in lines {
            let payload = json!({"machine_id":id,"source":source,"line":line});
            for sid in &valid {
                self.send(sid, STC_LOG_LINE, &payload);
            }
        }
        Ok(())
    }
    async fn event(
        &self,
        app: &App,
        sid: &str,
        event: &str,
        selected: Option<ObjectId>,
    ) -> ApiResult<()> {
        let Some(principal) = self.valid(app, sid).await? else {
            return Ok(());
        };
        match (event, principal) {
            (CTS_STATUS, Principal::User { id, .. }) => {
                let machines: Vec<Document> = app
                    .collection("machines")
                    .find(doc! {"user_id":id,"deletion_pending":{"$ne":true}})
                    .sort(doc! {"created_at":1})
                    .await?
                    .try_collect()
                    .await?;
                if self.valid(app, sid).await?.is_some() {
                    self.send(sid,STC_STATUS,&json!({"machines":machines.iter().map(|m|inventory::machine(app,m)).collect::<Vec<_>>()}));
                }
            }
            (CTS_CONFIG, Principal::Machine { id, token, .. }) => {
                let machine = machine_client::authenticate(app, &id.to_hex(), &token).await?;
                self.emit_config(app, &machine, vec![sid.into()], STC_CONFIG)
                    .await?;
            }
            (CTS_SUBSCRIBE | CTS_UNSUBSCRIBE, Principal::User { id, .. }) => {
                let Some(machine) = selected else {
                    return Ok(());
                };
                let Some(machine) = app
                    .collection("machines")
                    .find_one(doc! {"_id":machine,"user_id":id,"deletion_pending":{"$ne":true}})
                    .await?
                else {
                    return Ok(());
                };
                if self.valid(app, sid).await?.is_none() {
                    return Ok(());
                }
                let id = store::id(machine.get("_id"));
                let subscribe = event == CTS_SUBSCRIBE;
                {
                    let mut registry = self.registry();
                    if let Some(peer) = registry.peers.get_mut(sid) {
                        if subscribe {
                            if peer.logs.len() >= 64 {
                                return Ok(());
                            }
                            peer.logs.insert(id.clone());
                            registry
                                .logs
                                .entry(id.clone())
                                .or_default()
                                .insert(sid.into());
                        } else {
                            peer.logs.remove(&id);
                            remove(&mut registry.logs, &id, sid);
                        }
                    }
                }
                let active = self.log_requested(app, &id).await?;
                self.send(
                    sid,
                    STC_LOG_STATUS,
                    &log_status(app, &machine, active, Some(subscribe)),
                );
            }
            _ => {}
        }
        Ok(())
    }
    pub async fn close(&self) {
        self.io.close().await;
        let mut registry = self.registry();
        *registry = Registry::default();
    }
}

fn log_status(app: &App, machine: &Document, requested: bool, subscribed: Option<bool>) -> Value {
    let mut value = json!({"machine_id":store::id(machine.get("_id")),"machine_online":matches!(inventory::status(app,machine),"online"|"auth_required"),"stream_requested":requested});
    if let Some(subscribed) = subscribed {
        value["subscribed"] = json!(subscribed);
    }
    value
}
fn origin_allowed(app: &App, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get("origin") else {
        return true;
    };
    let Ok(origin) = origin
        .to_str()
        .map_err(|_| ())
        .and_then(|value| url::Url::parse(value).map_err(|_| ()))
    else {
        return false;
    };
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return false;
    }
    let mut bases = app.config.tunnel_fallback_base_urls.clone();
    bases.push(app.config.public_base_url.clone());
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("http");
    if let Some(host) = headers.get("host").and_then(|value| value.to_str().ok()) {
        bases.push(format!("{scheme}://{host}"));
    }
    bases
        .iter()
        .filter_map(|base| url::Url::parse(base).ok())
        .any(|base| base.origin() == origin.origin())
}
async fn authenticate_socket(
    app: &App,
    socket: &SocketRef,
    payload: Value,
) -> Result<(), &'static str> {
    let reject = "Connection rejected by server";
    if !origin_allowed(app, &socket.req_parts().headers) {
        return Err(reject);
    }
    let permit = app
        .realtime
        .capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| reject)?;
    let principal = if let Ok(user) = auth::current_user(app, &socket.req_parts().headers).await {
        Principal::User {
            id: user.get_object_id("_id").map_err(|_| reject)?,
            token: auth::token(&socket.req_parts().headers, app).into(),
        }
    } else {
        if payload["role"] != "machine" {
            return Err(reject);
        }
        let id = payload["machine_id"].as_str().ok_or(reject)?;
        let token = payload["token"].as_str().ok_or(reject)?;
        let machine = machine_client::authenticate(app, id, token)
            .await
            .map_err(|_| reject)?;
        Principal::Machine {
            id: machine.get_object_id("_id").map_err(|_| reject)?,
            owner: machine.get_object_id("user_id").map_err(|_| reject)?,
            token: token.into(),
        }
    };
    socket.extensions.insert(principal);
    socket.extensions.insert(Arc::new(permit));
    Ok(())
}
fn connected(app: &Arc<App>, socket: SocketRef) {
    let weak = Arc::downgrade(app);
    socket.on_disconnect(move |socket: SocketRef| {
        let app = weak.upgrade();
        async move {
            if let Some(app) = app {
                app.realtime.remove(&socket.id.to_string());
            }
            socket.extensions.remove::<Arc<Actor>>();
            socket.extensions.remove::<Arc<OwnedSemaphorePermit>>();
        }
    });
    let Some(principal) = socket.extensions.get::<Principal>() else {
        let _ = socket.disconnect();
        return;
    };
    let sid = socket.id.to_string();
    app.realtime.add(sid.clone(), principal);
    if !socket.connected() {
        app.realtime.remove(&sid);
        return;
    }
    // Keep ordered metadata work bounded; queued messages contain typed IDs,
    // not arbitrary client payloads, and the socket owns the sleeping actor.
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<Incoming>(128);
    let weak = Arc::downgrade(app);
    let actor_sid = sid.clone();
    let actor = tokio::spawn(async move {
        while let Some(command) = receiver.recv().await {
            let Some(app) = weak.upgrade() else {
                break;
            };
            if let Err(error) = app
                .realtime
                .event(&app, &actor_sid, command.event, command.machine)
                .await
            {
                tracing::warn!(detail=%error.detail,"realtime request failed");
            }
        }
    });
    socket.extensions.insert(Arc::new(Actor(actor)));
    for event in [CTS_STATUS, CTS_CONFIG, CTS_SUBSCRIBE, CTS_UNSUBSCRIBE] {
        let weak = Arc::downgrade(app);
        let sender = sender.clone();
        socket.on(
            event,
            move |socket: SocketRef, TryData(data): TryData<Value>| {
                if let Some(app) = weak.upgrade() {
                    let machine = data.ok().and_then(|value| {
                        value
                            .get("machine_id")
                            .and_then(Value::as_str)
                            .and_then(|value| ObjectId::parse_str(value).ok())
                    });
                    if sender.try_send(Incoming { event, machine }).is_err() {
                        app.realtime.disconnect(&socket.id.to_string());
                    }
                }
                std::future::ready(())
            },
        );
    }
    app.realtime.send(&sid, "join", &json!({"sid":sid}));
}
