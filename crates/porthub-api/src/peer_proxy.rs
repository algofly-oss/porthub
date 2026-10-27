//! One-use peer rendezvous on the existing API listener. No public peer proxy
//! listener is created. Pending state expires and belongs to its HTTP request.
use crate::{
    application_proxy::{self, Authorization, Target},
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use mongodb::bson::doc;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub id: String,
    pub instance: String,
    pub fingerprint: String,
}
struct Context {
    grant: String,
    client: String,
    token: String,
    target: Binding,
    host: String,
    port: u16,
}
struct Pending {
    context: Arc<Context>,
    reply: oneshot::Sender<(WebSocket, IpAddr)>,
    expires: Instant,
}
#[derive(Default)]
pub(crate) struct Hub {
    pending: Mutex<HashMap<String, Pending>>,
    providers: Mutex<HashMap<String, ProviderLease>>,
    subscribers: Mutex<HashMap<String, Subscriber>>,
    roles: tokio::sync::Mutex<HashMap<String, RoleCache>>,
}
struct ProviderLease {
    binding: Binding,
    hash: String,
    workspace: String,
    expires: Instant,
}
struct Subscriber {
    binding: Binding,
    generation: String,
    output: tokio::sync::mpsc::Sender<String>,
}
struct RoleCache {
    expires: Instant,
    targets: std::collections::HashSet<mongodb::bson::oid::ObjectId>,
}

impl Hub {
    pub(crate) fn ready(&self,binding:&Binding)->bool {
        let valid=self.providers.lock().unwrap_or_else(|poison|poison.into_inner()).get(&binding.id)
            .is_some_and(|lease|lease.binding==*binding && lease.expires>Instant::now());
        valid && self.subscribers.lock().unwrap_or_else(|poison|poison.into_inner()).get(&binding.id)
            .is_some_and(|subscriber|subscriber.binding==*binding && !subscriber.output.is_closed())
    }
    pub(crate) fn jobs(&self, peer: &str, instance: &str, fingerprint: &str) -> Vec<String> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        pending.retain(|_, entry| entry.expires > Instant::now());
        pending
            .iter()
            .filter(|(_, entry)| {
                entry.context.target.id == peer
                    && entry.context.target.instance == instance
                    && entry.context.target.fingerprint == fingerprint
            })
            .take(64)
            .map(|(id, _)| id.clone())
            .collect()
    }
}
struct Owner {
    hub: Arc<Hub>,
    id: String,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.hub
            .pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.id);
    }
}
#[derive(Serialize)]
struct Policy<'a> {
    host: &'a str,
    port: u16,
    allow_lan: bool,
    overlay: &'a [IpAddr],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    destination_ip: IpAddr,
}
fn denied() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "Peer proxy session is unavailable or revoked",
    )
}

pub(crate) async fn connect(
    app: Arc<App>,
    grant: String,
    client: String,
    token: String,
    auth: Authorization,
    target: Target,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    porthub_egress::Destination::new(target.host.clone(), target.port)
        .map_err(|_| ApiError::bad_request("Invalid proxy destination"))?;
    let binding = auth.target_peer.ok_or_else(denied)?;
    let permit = app.proxy_capacity.acquire(&grant)?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    let context = Arc::new(Context {
        grant,
        client,
        token,
        target: binding,
        host: target.host,
        port: target.port,
    });
    let (reply, ready) = oneshot::channel();
    {
        let mut entries = app
            .proxy_pending
            .pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        entries.retain(|_, entry| entry.expires > Instant::now());
        if entries.len() >= 256 {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Peer proxy capacity is in use",
            ));
        }
        entries.insert(
            id.clone(),
            Pending {
                context: context.clone(),
                reply,
                expires: Instant::now() + Duration::from_secs(20),
            },
        );
    }
    app.proxy_pending.wake(&id, &context.target);
    let _owner = Owner {
        hub: app.proxy_pending.clone(),
        id,
    };
    let (peer_socket, destination_ip) = tokio::time::timeout(Duration::from_secs(20), ready)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::GATEWAY_TIMEOUT,
                "Peer proxy did not become ready",
            )
        })?
        .map_err(|_| {
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                "Peer proxy could not open this destination",
            )
        })?;
    Ok(ws
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let forwarding = async {
                let (a_out, a_in) = socket.split();
                let (b_out, b_in) = peer_socket.split();
                tokio::try_join!(forward(a_in, b_out), forward(b_in, a_out))
            };
            let lease = async {
                loop {
                    tokio::time::sleep(Duration::from_secs(15)).await;
                    let valid = tokio::time::timeout(
                        Duration::from_secs(4),
                        application_proxy::authorize(
                            &app,
                            &context.grant,
                            &context.client,
                            &context.token,
                        ),
                    )
                    .await;
                    match valid {
                        Ok(Ok(auth))
                            if auth.target_peer.as_ref() == Some(&context.target)
                                && porthub_egress::destination::permitted(
                                    destination_ip,
                                    auth.allow_lan,
                                    &auth.overlay,
                                ) => {}
                        _ => break,
                    }
                }
            };
            tokio::select! {_=forwarding=>{},_=lease=>{}}
        }))
}
async fn forward(
    mut incoming: futures_util::stream::SplitStream<WebSocket>,
    mut outgoing: futures_util::stream::SplitSink<WebSocket, Message>,
) -> Result<(), ()> {
    while let Some(message) = incoming.next().await {
        match message.map_err(|_| ())? {
            Message::Binary(bytes) => outgoing
                .send(Message::Binary(bytes))
                .await
                .map_err(|_| ())?,
            Message::Text(text) if text == "eof" => {
                outgoing.send(Message::Text(text)).await.map_err(|_| ())?;
                return Ok(());
            }
            Message::Ping(_) | Message::Pong(_) => {}
            _ => return Err(()),
        }
    }
    Err(())
}
pub(crate) async fn serve(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let (peer, token) = application_proxy::credentials(&headers)?;
    let context = {
        let pending = app
            .proxy_pending
            .pending
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        pending
            .get(&id)
            .filter(|entry| entry.expires > Instant::now() && entry.context.target.id == peer)
            .map(|entry| entry.context.clone())
            .ok_or_else(denied)?
    };
    let current=app.collection("private_peers").find_one(doc! {
        "_id":&peer,"enabled":true,"credential_hash":crate::domain::workspaces::token_digest(&token),
        "instance":&context.target.instance,"fingerprint":&context.target.fingerprint
    }).await?.ok_or_else(denied)?;
    let auth =
        application_proxy::authorize(&app, &context.grant, &context.client, &context.token).await?;
    if auth.target_peer.as_ref() != Some(&context.target) || current.get("workspace_id").is_none() {
        return Err(denied());
    }
    let pending = app
        .proxy_pending
        .pending
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .remove(&id)
        .ok_or_else(denied)?;
    Ok(ws
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |mut socket| async move {
            let handshake = async {
                let policy = serde_json::to_string(&Policy {
                    host: &context.host,
                    port: context.port,
                    allow_lan: auth.allow_lan,
                    overlay: &auth.overlay,
                })
                .map_err(|_| ())?;
                socket
                    .send(Message::Text(policy.into()))
                    .await
                    .map_err(|_| ())?;
                let Some(Ok(Message::Text(ready))) = socket.recv().await else {
                    return Err(());
                };
                let ready: Ready = serde_json::from_str(&ready).map_err(|_| ())?;
                if !porthub_egress::destination::permitted(
                    ready.destination_ip,
                    auth.allow_lan,
                    &auth.overlay,
                ) {
                    return Err(());
                }
                Ok(ready.destination_ip)
            };
            if let Ok(Ok(destination)) =
                tokio::time::timeout(Duration::from_secs(10), handshake).await
            {
                let _ = pending.reply.send((socket, destination));
            }
        }))
}

impl Hub {
    /// Shared lazy cache: idle clients do not each poll the grants collection.
    /// UI mutations invalidate it; membership and credentials still come from
    /// the authenticated private sync immediately before lease publication.
    pub(crate) async fn is_provider(
        &self,
        app: &App,
        workspace: mongodb::bson::oid::ObjectId,
        machine: mongodb::bson::oid::ObjectId,
    ) -> bool {
        use futures_util::TryStreamExt;
        let key = workspace.to_hex();
        let mut roles = self.roles.lock().await;
        if let Some(cached) = roles
            .get(&key)
            .filter(|cached| cached.expires > Instant::now())
        {
            return cached.targets.contains(&machine);
        }
        roles.retain(|_, cached| cached.expires > Instant::now());
        if roles.len() >= 4096 {
            return false;
        }
        let lookup = async {
            app.collection(crate::routes::proxy_grants::COLLECTION)
                .find(doc! {"workspace_id":workspace,"enabled":true,"target_kind":"machine"})
                .projection(doc! {"target_machine_id":1})
                .await?
                .try_collect::<Vec<mongodb::bson::Document>>()
                .await
        };
        let Ok(Ok(records)) = tokio::time::timeout(Duration::from_millis(500), lookup).await else {
            return false;
        };
        let targets: std::collections::HashSet<_> = records
            .iter()
            .filter_map(|record| record.get_object_id("target_machine_id").ok())
            .collect();
        let enabled = targets.contains(&machine);
        roles.insert(
            key,
            RoleCache {
                expires: Instant::now() + Duration::from_secs(60),
                targets,
            },
        );
        enabled
    }
    pub(crate) async fn invalidate(&self, workspace: mongodb::bson::oid::ObjectId) {
        let key = workspace.to_hex();
        self.roles.lock().await.remove(&key);
        self.providers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .retain(|_, lease| lease.workspace != key);
    }
    pub(crate) fn publish(&self, binding: Binding, hash: &str, workspace: String, enabled: bool) {
        let mut providers = self
            .providers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        providers.retain(|_, lease| lease.expires > Instant::now());
        if !enabled {
            providers.remove(&binding.id);
            return;
        }
        if providers.len() >= 4096 && !providers.contains_key(&binding.id) {
            return;
        }
        providers.insert(
            binding.id.clone(),
            ProviderLease {
                binding,
                hash: hash.into(),
                workspace,
                expires: Instant::now() + Duration::from_secs(15),
            },
        );
    }
    fn provider(&self, peer: &str, hash: &str) -> Option<Binding> {
        self.providers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(peer)
            .filter(|lease| lease.hash == hash && lease.expires > Instant::now())
            .map(|lease| lease.binding.clone())
    }
    fn wake(&self, id: &str, binding: &Binding) {
        if let Some(subscriber) = self
            .subscribers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(&binding.id)
            .filter(|subscriber| subscriber.binding == *binding)
        {
            let _ = subscriber.output.try_send(id.into());
        }
    }
}
struct Subscription {
    hub: Arc<Hub>,
    peer: String,
    generation: String,
}
impl Drop for Subscription {
    fn drop(&mut self) {
        let mut subscribers = self
            .hub
            .subscribers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if subscribers
            .get(&self.peer)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            subscribers.remove(&self.peer);
        }
    }
}
pub(crate) async fn subscribe(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let (peer, token) = application_proxy::credentials(&headers)?;
    let hash = crate::domain::workspaces::token_digest(&token);
    let binding = app
        .proxy_pending
        .provider(&peer, &hash)
        .ok_or_else(denied)?;
    let (output, mut incoming) = tokio::sync::mpsc::channel(64);
    let generation = uuid::Uuid::new_v4().simple().to_string();
    {
        let mut subscribers = app
            .proxy_pending
            .subscribers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if subscribers.len() >= 4096 && !subscribers.contains_key(&peer) {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "Proxy provider capacity is in use",
            ));
        }
        subscribers.insert(
            peer.clone(),
            Subscriber {
                binding: binding.clone(),
                generation: generation.clone(),
                output,
            },
        );
    }
    let ownership = Subscription {
        hub: app.proxy_pending.clone(),
        peer: peer.clone(),
        generation,
    };
    let jobs = app
        .proxy_pending
        .jobs(&peer, &binding.instance, &binding.fingerprint);
    Ok(ws.max_message_size(1024).max_frame_size(1024).on_upgrade(move |mut socket|async move {
        let _ownership=ownership;
        for id in jobs {if socket.send(Message::Text(id.into())).await.is_err(){return;}}
        let mut lease=tokio::time::interval(Duration::from_secs(5));lease.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut ping=tokio::time::interval(Duration::from_secs(30));ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        lease.tick().await;ping.tick().await;
        loop {
            tokio::select! {
                message=socket.recv()=>if !matches!(message,Some(Ok(Message::Ping(_)|Message::Pong(_)))) {break;},
                id=incoming.recv()=>match id {Some(id)=>if socket.send(Message::Text(id.into())).await.is_err(){break;},None=>break},
                _=lease.tick()=>if app.proxy_pending.provider(&peer,&hash).as_ref()!=Some(&binding){break;},
                _=ping.tick()=>if socket.send(Message::Ping(Vec::new().into())).await.is_err(){break;},
            }
        }
    }))
}
