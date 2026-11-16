//! Owner-bound native media plans. This is separate from legacy USB contracts.
use crate::{
    auth,
    domain::machine_client,
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, State,
    },
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use mongodb::bson::{self, doc, oid::ObjectId, DateTime, Document};
use porthub_components::media_forward::{Plan, Source, UsbIdentity};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::oneshot;
#[derive(Default)]
pub struct Hub {
    registry: Mutex<Registry>,
    initialized: tokio::sync::OnceCell<()>,
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PairKey {
    owner: ObjectId,
    source: String,
    destination: String,
    id: String,
}
fn pair_key(owner: ObjectId, forward: &Plan) -> PairKey {
    PairKey {
        owner,
        source: forward.source.clone(),
        destination: forward.destination.clone(),
        id: forward.id.clone(),
    }
}
#[derive(Default)]
struct Registry {
    waiting: HashMap<
        PairKey,
        (
            String,
            String,
            oneshot::Sender<(WebSocket, String, String, String)>,
        ),
    >,
    active: HashMap<PairKey, String>,
}
struct PairGuard {
    app: Arc<App>,
    key: PairKey,
    nonce: String,
}
impl Drop for PairGuard {
    fn drop(&mut self) {
        let mut r = self
            .app
            .native_media
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if r.waiting.get(&self.key).is_some_and(|p| p.0 == self.nonce) {
            r.waiting.remove(&self.key);
        }
        if r.active.get(&self.key) == Some(&self.nonce) {
            r.active.remove(&self.key);
        }
    }
}

async fn pair_authorized(
    app: &App,
    id: &str,
    machine_id: &str,
    token: &str,
    side: &str,
    key: &PairKey,
) -> bool {
    tokio::time::timeout(
        Duration::from_secs(2),
        authorized_stream(app, id, machine_id, token, side),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|(owner, forward)| pair_key(owner, &forward) == *key))
}
async fn pair(
    app: Arc<App>,
    key: PairKey,
    id: String,
    side: String,
    machine_id: String,
    token: String,
    mut socket: WebSocket,
) {
    let nonce = uuid::Uuid::new_v4().to_string();
    let (send, receive) = oneshot::channel();
    let peer = {
        let mut registry = app
            .native_media
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if registry.active.contains_key(&key) {
            return;
        }
        let waiting = &mut registry.waiting;
        if let Some((_, other, _)) = waiting.get(&key) {
            if other == &side {
                return;
            }
        }
        if let Some((first, _, peer)) = waiting.remove(&key) {
            registry.active.insert(key.clone(), first);
            Some(peer)
        } else {
            if waiting.len() >= 128 {
                return;
            }
            waiting.insert(key.clone(), (nonce.clone(), side.clone(), send));
            None
        }
    };
    if let Some(peer) = peer {
        let _ = peer.send((socket, machine_id, token, side));
        return;
    }
    let _guard = PairGuard {
        app: app.clone(),
        key: key.clone(),
        nonce: nonce.clone(),
    };
    let received = tokio::time::timeout(Duration::from_secs(30), receive).await;
    {
        let mut registry = app
            .native_media
            .registry
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if registry.waiting.get(&key).is_some_and(|p| p.0 == nonce) {
            registry.waiting.remove(&key);
        }
    }
    let Ok(Ok((mut other, other_machine, other_token, other_side))) = received else {
        return;
    };
    let authorized = || async {
        let (first, second) = tokio::join!(
            pair_authorized(&app, &id, &machine_id, &token, &side, &key),
            pair_authorized(&app, &id, &other_machine, &other_token, &other_side, &key),
        );
        first && second
    };
    if !authorized().await {
        return;
    }
    // This future is polled independently of every socket read/write. A peer
    // which stops reading cannot prevent revocation, expiry, or DB-failure checks.
    let authorization = async {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if !authorized().await {
                return;
            }
        }
    };
    let forwarding = async {
        if socket.send(Message::Text("ready".into())).await.is_err()
            || other.send(Message::Text("ready".into())).await.is_err()
        {
            return;
        }
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
             _=tick.tick()=>{if socket.send(Message::Ping(vec![].into())).await.is_err()||other.send(Message::Ping(vec![].into())).await.is_err(){break;}},
             m=socket.next()=>{match m{Some(Ok(Message::Binary(b)))=>{if other.send(Message::Binary(b)).await.is_err(){break;}},Some(Ok(Message::Ping(b)))=>{if socket.send(Message::Pong(b)).await.is_err(){break;}},Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Text(t)))=>{if !signal(&t)||other.send(Message::Text(t)).await.is_err(){break;}},_=>break}},
             m=other.next()=>{match m{Some(Ok(Message::Binary(b)))=>{if socket.send(Message::Binary(b)).await.is_err(){break;}},Some(Ok(Message::Ping(b)))=>{if other.send(Message::Pong(b)).await.is_err(){break;}},Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Text(t)))=>{if !signal(&t)||socket.send(Message::Text(t)).await.is_err(){break;}},_=>break}}
            }
        }
    };
    tokio::select! {biased;_=authorization=>{},_=forwarding=>{}}
    // Never wait for a close handshake from the same stalled peer. Dropping both
    // sockets closes transport and releases the nonce-bound registry guard.
}

fn signal(text: &str) -> bool {
    text.len() <= 65536
        && serde_json::from_str::<Value>(text).is_ok_and(|v| {
            matches!(
                v["type"].as_str(),
                Some("hello" | "offer" | "answer" | "direct_ready" | "path" | "device")
            )
        })
}

async fn initialize(app: &App) -> ApiResult<()> {
    app.native_media
        .initialized
        .get_or_try_init(|| async {
            use mongodb::{options::IndexOptions, IndexModel};
            app.collection("native_media_inventory")
                .create_index(IndexModel::builder().keys(doc! {"owner":1}).build())
                .await?;
            for endpoint in ["source", "destination"] {
                app.collection("native_media_forwards")
                    .create_index(
                        IndexModel::builder()
                            .keys(doc! {"owner":1,endpoint:1})
                            .build(),
                    )
                    .await?;
            }
            app.collection("native_media_forwards")
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(
                            IndexOptions::builder()
                                .name("temporary_native_media_expiry".to_owned())
                                .expire_after(Duration::ZERO)
                                .partial_filter_expression(doc! {"persistent":false})
                                .build(),
                        )
                        .build(),
                )
                .await?;
            Ok::<(), ApiError>(())
        })
        .await?;
    Ok(())
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/media/inventory", get(inventory))
        .route("/api/media/machines/{id}/discover", post(discover))
        .route("/api/media/forwards", get(list).post(create))
        .route("/api/media/forwards/{id}", delete(remove))
        .route("/api/media/client/report", post(report))
        .route("/api/media/client/action", post(action))
        .route("/api/media/stream/{id}/{side}", get(stream))
        .layer(DefaultBodyLimit::max(131072))
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "Native media source, receiver, or authorization is unavailable",
    )
}
fn oid(id: &str) -> ApiResult<ObjectId> {
    ObjectId::parse_str(id).map_err(|_| ApiError::bad_request("Invalid machine identity"))
}
fn current() -> Document {
    doc! {"$or":[{"persistent":true},{"expires_at":{"$gt":DateTime::now()}}]}
}
async fn owner(app: &App, headers: &HeaderMap) -> ApiResult<ObjectId> {
    auth::current_user(app, headers)
        .await?
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())
}
async fn machine(app: &App, owner: ObjectId, id: &str) -> ApiResult<Document> {
    app.collection("machines").find_one(doc!{"_id":oid(id)?,"user_id":owner,"enabled":{"$ne":false},"deletion_pending":{"$ne":true}}).await?.ok_or_else(unavailable)
}
fn decode(mut row: Document) -> ApiResult<Plan> {
    for key in ["_id", "owner", "expires_at"] {
        row.remove(key);
    }
    bson::from_document(row).map_err(|_| unavailable())
}
async fn capabilities(app: &App, owner: ObjectId, id: &str) -> ApiResult<Document> {
    machine(app, owner, id).await?;
    app.collection("native_media_inventory").find_one(doc!{"_id":oid(id)?,"owner":owner,"at":{"$gt":DateTime::from_millis(DateTime::now().timestamp_millis()-45000)},"protocol":{"$in":[1,2]}}).await?.ok_or_else(unavailable)
}
async fn authorized_plan(app: &App, owner: ObjectId, plan: &Plan) -> ApiResult<()> {
    if !plan.valid() {
        return Err(unavailable());
    }
    let source = capabilities(app, owner, &plan.source).await?;
    let destination = capabilities(app, owner, &plan.destination).await?;
    let camera = plan.kind() == Some(porthub_components::media::Kind::Camera);
    if source.get_bool(if camera {
        "camera_enabled"
    } else {
        "microphone_enabled"
    }) != Ok(true)
        || camera
            && (source.get_i32("protocol") != Ok(2)
                || destination.get_i32("protocol") != Ok(2)
                || destination.get_bool("camera_receiver_available") != Ok(true))
        || destination.get_bool("receive_enabled") != Ok(true)
        || !camera && destination.get_bool("receiver_available") != Ok(true)
    {
        return Err(unavailable());
    }
    if destination
        .get_document("receiver_identity")
        .ok()
        .and_then(|v| bson::from_document::<UsbIdentity>(v.clone()).ok())
        .as_ref()
        != Some(&plan.identity)
    {
        return Err(unavailable());
    }
    let sources: Vec<Source> = source
        .get_array("sources")
        .ok()
        .and_then(|a| bson::from_bson(bson::Bson::Array(a.clone())).ok())
        .ok_or_else(unavailable)?;
    if !sources.iter().any(|s| {
        s.uid == plan.desktop_uid
            && s.desktop_session == plan.desktop_session
            && s.device.id == plan.source_id
            && Some(s.device.kind) == plan.kind()
            && s.device.can_request_capture()
    }) {
        return Err(unavailable());
    }
    Ok(())
}
async fn plans(app: &App, owner: ObjectId, endpoint: Option<&str>) -> ApiResult<Vec<Plan>> {
    let mut filter = doc! {"owner":owner,"$and":[current()]};
    if let Some(id) = endpoint {
        filter.insert("$or", vec![doc! {"source":id}, doc! {"destination":id}]);
    }
    let rows: Vec<Document> = app
        .collection("native_media_forwards")
        .find(filter)
        .limit(32)
        .await?
        .try_collect()
        .await?;
    Ok(rows.into_iter().filter_map(|r| decode(r).ok()).collect())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    machine_id: String,
    token: String,
    protocol: u8,
    usb_enabled: bool,
    microphone_enabled: bool,
    #[serde(default)]
    microphone_unavailable_reason: Option<String>,
    #[serde(default)]
    camera_unavailable_reason: Option<String>,
    #[serde(default)]
    camera_enabled: bool,
    #[serde(default)]
    camera_receiver_available: bool,
    #[serde(default)]
    camera_receiver_unavailable_reason: Option<String>,
    receive_enabled: bool,
    receiver_available: bool,
    receiver_identity: Option<UsbIdentity>,
    receiver_unavailable_reason: Option<String>,
    sources: Vec<Source>,
    #[serde(default)]
    states: Vec<porthub_components::usb::State>,
}
async fn report(State(app): State<Arc<App>>, Json(body): Json<Report>) -> ApiResult<Json<Value>> {
    if body.receiver_identity.as_ref().is_some_and(|i| !i.valid())
        || (body.receiver_available||body.camera_receiver_available) && body.receiver_identity.is_none()
        || body
            .receiver_unavailable_reason
            .as_ref()
            .is_some_and(|r| r.len() > 512 || r.chars().any(char::is_control))
        || [&body.microphone_unavailable_reason,&body.camera_unavailable_reason].iter().any(|v|v.as_ref().is_some_and(|s|s.len()>512||s.chars().any(char::is_control)))
        || !matches!(body.protocol, 1 | 2)
        || body.protocol == 1 && (body.camera_enabled || body.camera_receiver_available)
        || body
            .camera_receiver_unavailable_reason
            .as_ref()
            .is_some_and(|s| s.len() > 512 || s.chars().any(char::is_control))
        || body.sources.len() > 64
        || body.sources.iter().any(|s| !s.valid())
        || body.sources.iter().enumerate().any(|(i, s)| {
            body.sources[..i]
                .iter()
                .any(|old| old.uid == s.uid && old.device.id == s.device.id)
        })
        || body.states.len() > 32
        || body.states.iter().any(|s| {
            s.id.len() != 32
                || s.state.len() > 32
                || s.error.as_ref().is_some_and(|e| e.len() > 512)
        })
    {
        return Err(ApiError::bad_request("Invalid native media report"));
    }
    let machine = machine_client::authenticate(&app, &body.machine_id, &body.token).await?;
    initialize(&app).await?;
    let owner = machine
        .get_object_id("user_id")
        .map_err(|_| unavailable())?;
    self::machine(&app, owner, &body.machine_id).await?;
    app.collection("native_media_inventory").replace_one(doc!{"_id":oid(&body.machine_id)?},doc!{"_id":oid(&body.machine_id)?,"owner":owner,"at":DateTime::now(),"protocol":body.protocol as i32,"microphone_unavailable_reason":body.microphone_unavailable_reason,"camera_unavailable_reason":body.camera_unavailable_reason,"camera_enabled":body.camera_enabled,"camera_receiver_available":body.camera_receiver_available,"camera_receiver_unavailable_reason":body.camera_receiver_unavailable_reason,"usb_enabled":body.usb_enabled,"microphone_enabled":body.microphone_enabled,"receive_enabled":body.receive_enabled,"receiver_available":body.receiver_available,"receiver_identity":bson::to_bson(&body.receiver_identity).map_err(|_|unavailable())?,"receiver_unavailable_reason":body.receiver_unavailable_reason,"sources":bson::to_bson(&body.sources).map_err(|_|unavailable())?,"states":bson::to_bson(&body.states).map_err(|_|unavailable())?}).upsert(true).await?;
    let plans = plans(&app, owner, Some(&body.machine_id)).await?;
    let mut authorized = Vec::new();
    for plan in plans {
        if authorized_plan(&app, owner, &plan).await.is_ok() {
            authorized.push(plan);
        }
    }
    let discover=app.collection("native_media_discovery").find_one_and_delete(doc!{"_id":oid(&body.machine_id)?,"owner":owner,"requested_at":{"$gt":DateTime::from_millis(DateTime::now().timestamp_millis()-60000)}}).await?.is_some()&&(body.microphone_enabled||body.camera_enabled&&body.protocol==2);
    Ok(Json(
        json!({"protocol":body.protocol,"plans":authorized,"discover":discover}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    source: String,
    destination: String,
    desktop_uid: u32,
    desktop_session: Option<String>,
    source_id: String,
    name: String,
    identity: Option<UsbIdentity>,
    #[serde(default)]
    persistent: bool,
    #[serde(default = "microphone_mode")]
    mode: String,
}
fn microphone_mode() -> String {
    "phm1-microphone-v1".into()
}
async fn create_plan(app: &App, owner: ObjectId, body: Create) -> ApiResult<Plan> {
    let destination = capabilities(app, owner, &body.destination).await?;
    let configured: UsbIdentity = destination
        .get_document("receiver_identity")
        .ok()
        .and_then(|d| bson::from_document(d.clone()).ok())
        .ok_or_else(unavailable)?;
    let identity = body.identity.unwrap_or(configured);
    let plan = Plan {
        id: uuid::Uuid::new_v4().simple().to_string(),
        source: body.source,
        destination: body.destination,
        desktop_uid: body.desktop_uid,
        desktop_session: body.desktop_session,
        source_id: body.source_id,
        name: body.name,
        identity,
        persistent: body.persistent,
        mode: body.mode,
    };
    authorized_plan(app, owner, &plan).await?;
    let count = app
        .collection("native_media_forwards")
        .count_documents(doc! {"owner":owner,"$and":[current()]})
        .await?;
    if count >= 32 {
        return Err(ApiError::bad_request(
            "Native media forwarding limit reached",
        ));
    }
    let mut row = bson::to_document(&plan).map_err(|_| unavailable())?;
    row.insert("_id", format!("{}:{}", owner.to_hex(), plan.id));
    row.insert("owner", owner);
    row.insert(
        "expires_at",
        DateTime::from_millis(DateTime::now().timestamp_millis() + 45000),
    );
    app.collection("native_media_forwards")
        .insert_one(row)
        .await?;
    Ok(plan)
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Create>,
) -> ApiResult<Json<Value>> {
    let p = create_plan(&app, owner(&app, &headers).await?, body).await?;
    Ok(Json(json!({"plan":p})))
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers).await?;
    app.collection("native_media_forwards")
        .delete_one(doc! {"owner":owner,"id":id})
        .await?;
    Ok(Json(json!({"ok":true})))
}
async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    Ok(Json(
        json!({"plans":plans(&app,owner(&app,&headers).await?,None).await?}),
    ))
}
async fn inventory(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers).await?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"deletion_pending":{"$ne":true}})
        .projection(doc! {"_id":1,"name":1,"enabled":1})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    let reports: Vec<Document> = app
        .collection("native_media_inventory")
        .find(doc! {"owner":owner})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    let rows:Vec<Value>=machines.into_iter().filter_map(|machine|{
  let id=machine.get_object_id("_id").ok()?;let report=reports.iter().find(|r|r.get_object_id("_id")==Ok(id));
  let at=report.and_then(|r|r.get_datetime("at").ok()).map(|v|v.timestamp_millis());let enabled=machine.get_bool("enabled")!=Ok(false);
  Some(json!({"id":id.to_hex(),"name":machine.get_str("name").unwrap_or("Machine"),"enabled":enabled,"live":enabled&&at.is_some_and(|at|DateTime::now().timestamp_millis()-at<45000),"at":at,"report":report.and_then(|r|{let mut r=r.clone();r.remove("_id");r.remove("owner");r.remove("at");bson::from_document::<Value>(r).ok()})}))
 }).collect();
    Ok(Json(
        json!({"protocol":2,"modes":["phm1-microphone-v1","phv1-camera-mjpeg-v1"],"machines":rows}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    machine_id: String,
    token: String,
    action: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    plan: Option<Create>,
}
async fn action(State(app): State<Arc<App>>, Json(body): Json<Action>) -> ApiResult<Json<Value>> {
    let m = machine_client::authenticate(&app, &body.machine_id, &body.token).await?;
    let owner = m.get_object_id("user_id").map_err(|_| unavailable())?;
    machine(&app, owner, &body.machine_id).await?;
    match body.action.as_str() {
        "create" => {
            let request = body.plan.ok_or_else(unavailable)?;
            if request.source != body.machine_id {
                return Err(unavailable());
            }
            Ok(Json(json!({"plan":create_plan(&app,owner,request).await?})))
        }
        "stop" | "renew" => {
            let row = app
                .collection("native_media_forwards")
                .find_one(
                    doc! {"owner":owner,"id":&body.id,"source":&body.machine_id,"$and":[current()]},
                )
                .await?
                .ok_or_else(unavailable)?;
            let plan = decode(row)?;
            if body.action == "stop" {
                app.collection("native_media_forwards")
                    .delete_one(doc! {"owner":owner,"id":body.id})
                    .await?;
            } else {
                authorized_plan(&app, owner, &plan).await?;
                app.collection("native_media_forwards").update_one(doc!{"owner":owner,"id":body.id},doc!{"$set":{"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+45000)}}).await?;
            }
            Ok(Json(json!({"ok":true})))
        }
        _ => Err(ApiError::bad_request("Invalid media action")),
    }
}
async fn authorized_stream(
    app: &App,
    id: &str,
    machine_id: &str,
    token: &str,
    side: &str,
) -> ApiResult<(ObjectId, Plan)> {
    let m = machine_client::authenticate(app, machine_id, token).await?;
    let owner = m.get_object_id("user_id").map_err(|_| unavailable())?;
    let row = app
        .collection("native_media_forwards")
        .find_one(doc! {"owner":owner,"id":id,"$and":[current()]})
        .await?
        .ok_or_else(unavailable)?;
    let p = decode(row)?;
    if !matches!(side, "source" | "destination")
        || (side == "source" && p.source != machine_id)
        || (side == "destination" && p.destination != machine_id)
    {
        return Err(unavailable());
    }
    authorized_plan(app, owner, &p).await?;
    Ok((owner, p))
}
async fn stream(
    State(app): State<Arc<App>>,
    Path((id, side)): Path<(String, String)>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let machine_id = headers
        .get("x-porthub-machine-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_owned();
    let (owner, plan) = tokio::time::timeout(
        Duration::from_secs(2),
        authorized_stream(&app, &id, &machine_id, &token, &side),
    )
    .await
    .map_err(|_| unavailable())??;
    let key = pair_key(owner, &plan);
    Ok(ws
        .max_message_size(262144)
        .max_frame_size(262144)
        .write_buffer_size(0)
        .max_write_buffer_size(524288)
        .on_upgrade(move |socket| pair(app, key, id, side, machine_id, token, socket)))
}

async fn discover(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers).await?;
    let report = capabilities(&app, owner, &id).await?;
    if report.get_bool("microphone_enabled") != Ok(true)
        && !(report.get_i32("protocol") == Ok(2) && report.get_bool("camera_enabled") == Ok(true))
    {
        return Err(unavailable());
    }
    app.collection("native_media_discovery")
        .replace_one(
            doc! {"_id":oid(&id)?},
            doc! {"_id":oid(&id)?,"owner":owner,"requested_at":DateTime::now()},
        )
        .upsert(true)
        .await?;
    Ok(Json(json!({"requested":true})))
}
