//! Owner-only, device-specific USB forwarding. USB traffic never has a public TCP listener.
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
use porthub_components::usb::{Device, Forward, State as DeviceState};
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
}
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PairKey {
    owner: ObjectId,
    source: String,
    destination: String,
    id: String,
}
fn pair_key(owner:ObjectId,forward:&Forward)->PairKey {
    PairKey {owner,source:forward.source.clone(),destination:forward.destination.clone(),id:forward.id.clone()}
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
            .usb
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
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/usb/inventory", get(inventory))
        .route("/api/usb/forwards", get(list).post(create))
        .route("/api/usb/forwards/{id}", delete(remove))
        .route("/api/usb/client/report", post(report))
        .route("/api/usb/client/action", post(action))
        .route("/api/usb/stream/{id}/{side}", get(stream))
        .layer(DefaultBodyLimit::max(131072))
}
fn unavailable() -> ApiError {
    ApiError::new(StatusCode::CONFLICT, "USB device or forwarding unavailable")
}
fn oid(id: &str) -> ApiResult<ObjectId> {
    ObjectId::parse_str(id).map_err(|_| ApiError::bad_request("Invalid machine identity"))
}
async fn user(app: &App, headers: &HeaderMap) -> ApiResult<ObjectId> {
    auth::current_user(app, headers)
        .await?
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())
}
async fn machine(app: &App, owner: ObjectId, id: &str) -> ApiResult<Document> {
    app.collection("machines").find_one(doc!{"_id":oid(id)?,"user_id":owner,"enabled":{"$ne":false},"deletion_pending":{"$ne":true}}).await?.ok_or_else(unavailable)
}
fn current() -> Document {
    doc! {"$or":[{"persistent":true},{"expires_at":{"$gt":DateTime::now()}}]}
}
fn decode(mut row: Document) -> Result<Forward, bson::de::Error> {
    row.remove("_id");
    row.remove("owner");
    row.remove("expires_at");
    bson::from_document(row)
}
fn public(row: Document) -> Value {
    decode(row)
        .ok()
        .and_then(|v| serde_json::to_value(v).ok())
        .unwrap_or(Value::Null)
}
async fn plans(app: &App, owner: ObjectId, endpoint: Option<&str>) -> ApiResult<Vec<Document>> {
    let mut filter = doc! {"owner":owner,"$and":[current()]};
    if let Some(id) = endpoint {
        filter.insert("$or", vec![doc! {"source":id}, doc! {"destination":id}]);
    }
    Ok(app
        .collection("usb_forwards")
        .find(filter)
        .limit(64)
        .await?
        .try_collect()
        .await?)
}
async fn inventory(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let owner = user(&app, &headers).await?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"enabled":{"$ne":false},"deletion_pending":{"$ne":true}})
        .projection(doc! {"_id":1,"name":1})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    let ids: Vec<ObjectId> = machines
        .iter()
        .filter_map(|r| r.get_object_id("_id").ok())
        .collect();
    let reports: Vec<Document> = app
        .collection("usb_inventory")
        .find(doc! {"_id":{"$in":ids},"owner":owner})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"machines":machines.iter().map(|m|{let id=m.get_object_id("_id").unwrap();let r=reports.iter().find(|r|r.get_object_id("_id")==Ok(id));json!({"id":id.to_hex(),"name":m.get_str("name").unwrap_or("Machine"),"online":r.and_then(|r|r.get_datetime("at").ok()).is_some_and(|t|DateTime::now().timestamp_millis()-t.timestamp_millis()<45000),"report":r.and_then(|r|r.get_document("report").ok()).map(|r|bson::from_document::<Value>(r.clone()).unwrap_or(Value::Null))})}).collect::<Vec<_>>()}),
    ))
}
async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let owner = user(&app, &headers).await?;
    Ok(Json(
        json!({"forwards":plans(&app,owner,None).await?.into_iter().map(public).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    source: String,
    destination: String,
    busid: String,
}
fn role_allowed(report: &Document, role: &str) -> bool {
    report.get_bool("enabled") == Ok(true)
        && report.get_bool("supported") == Ok(true)
        && report.get_bool(role).unwrap_or(true)
}
async fn require_role(app: &App, owner: ObjectId, id: &str, role: &str) -> ApiResult<()> {
    let row=app.collection("usb_inventory").find_one(doc!{"_id":oid(id)?,"owner":owner,"at":{"$gt":DateTime::from_millis(DateTime::now().timestamp_millis()-45000)}}).await?.ok_or_else(unavailable)?;
    if !row.get_document("report").ok().is_some_and(|r|role_allowed(r,role)){return Err(unavailable());}
    Ok(())
}
async fn make(
    app: &App,
    owner: ObjectId,
    body: Create,
    persistent: bool,
    requested: Option<&str>,
) -> ApiResult<Value> {
    let mut body = body;
    body.source = oid(&body.source)?.to_hex();
    body.destination = oid(&body.destination)?.to_hex();
    machine(app, owner, &body.source).await?;
    machine(app, owner, &body.destination).await?;
    if body.source == body.destination || !porthub_components::usb::valid_busid(&body.busid) {
        return Err(ApiError::bad_request(
            "Choose different machines and a valid USB device",
        ));
    }
    if plans(app, owner, None).await?.len() >= 64 {
        return Err(ApiError::bad_request("USB forwarding limit reached"));
    }
    let r=app.collection("usb_inventory").find_one(doc!{"_id":oid(&body.source)?,"owner":owner,"at":{"$gt":DateTime::from_millis(DateTime::now().timestamp_millis()-45000)}}).await?.ok_or_else(unavailable)?;
    let report = r.get_document("report").map_err(|_| unavailable())?;
    require_role(app,owner,&body.destination,"can_import").await?;
    if !role_allowed(report,"can_export") {
        return Err(unavailable());
    }
    let devices: Vec<Device> = report
        .get_array("devices")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|v| bson::from_bson(v.clone()).ok())
        .collect();
    let device = devices
        .into_iter()
        .find(|d| d.busid == body.busid && d.blocked.is_none() && d.valid())
        .ok_or_else(unavailable)?;
    let id = if let Some(id) = requested {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::bad_request("Invalid USB session identity"));
        }
        id.to_owned()
    } else {
        uuid::Uuid::new_v4().simple().to_string()
    };
    // An atomic device reservation prevents two destinations racing to claim the same device.
    app.collection("usb_forwards")
        .create_index(
            mongodb::IndexModel::builder()
                .keys(doc! {"expires_at":1})
                .options(
                    mongodb::options::IndexOptions::builder()
                        .expire_after(Duration::ZERO)
                        .build(),
                )
                .build(),
        )
        .await?;
    let identity = if device.serial.is_empty() {
        device.busid.clone()
    } else {
        use sha2::{Digest, Sha256};
        format!(
            "{:x}",
            Sha256::digest(
                format!("{}:{}:{}", device.vendor, device.product, device.serial).as_bytes()
            )
        )
    };
    let key = format!("{}:{}", body.source, identity);
    let forward = Forward {
        id: id.clone(),
        source: body.source,
        destination: body.destination,
        device,
        persistent,
    };
    let mut value = bson::to_document(&forward).map_err(|_| unavailable())?;
    value.insert("_id", key.clone());
    value.insert("owner", owner);
    if !persistent {
        value.insert(
            "expires_at",
            DateTime::from_millis(DateTime::now().timestamp_millis() + 45000),
        );
    }
    app.collection("usb_forwards")
        .delete_one(doc! {"_id":&key,"persistent":false,"expires_at":{"$lte":DateTime::now()}})
        .await?;
    if app
        .collection("usb_forwards")
        .insert_one(value)
        .await
        .is_err()
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "This USB device already has a forwarding rule",
        ));
    }
    Ok(json!({"forward":forward}))
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Create>,
) -> ApiResult<Json<Value>> {
    crate::keyboard::same_origin(&app, &headers)?;
    Ok(Json(
        make(&app, user(&app, &headers).await?, body, true, None).await?,
    ))
}
async fn remove(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    crate::keyboard::same_origin(&app, &headers)?;
    let owner = user(&app, &headers).await?;
    app.collection("usb_forwards")
        .delete_one(doc! {"owner":owner,"id":id})
        .await?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    machine_id: String,
    token: String,
    enabled: bool,
    supported: bool,
    #[serde(default)]
    can_export: Option<bool>,
    #[serde(default)]
    can_import: Option<bool>,
    devices: Vec<Device>,
    states: Vec<DeviceState>,
}
async fn report(State(app): State<Arc<App>>, Json(body): Json<Report>) -> ApiResult<Json<Value>> {
    if body.devices.len() > 128
        || body.devices.iter().any(|d| !d.valid())
        || body.states.len() > 64
        || body.states.iter().any(|s| {
            s.id.len() != 32
                || s.state.len() > 32
                || s.error.as_ref().is_some_and(|e| e.len() > 512)
        })
    {
        return Err(ApiError::bad_request("Invalid USB report"));
    }
    let m = machine_client::authenticate(&app, &body.machine_id, &body.token).await?;
    if m.get_bool("enabled") == Ok(false) || m.get_bool("deletion_pending") == Ok(true) {
        return Err(unavailable());
    }
    let owner = m.get_object_id("user_id").map_err(|_| unavailable())?;
    app.collection("usb_inventory").update_one(doc!{"_id":oid(&body.machine_id)?},doc!{"$set":{"owner":owner,"at":DateTime::now(),"report":{"enabled":body.enabled,"supported":body.supported,"can_export":body.can_export.unwrap_or(body.supported),"can_import":body.can_import.unwrap_or(body.supported),"devices":bson::to_bson(&body.devices).map_err(|_|unavailable())?,"states":bson::to_bson(&body.states).map_err(|_|unavailable())?}}}).upsert(true).await?;
    let rows = if body.enabled && body.supported {
        plans(&app, owner, Some(&body.machine_id)).await?.into_iter().filter(|r| { let p=decode(r.clone()).ok(); p.is_some_and(|p|if p.source==body.machine_id {body.can_export.unwrap_or(body.supported)}else{body.can_import.unwrap_or(body.supported)}) }).collect()
    } else {
        vec![]
    };
    Ok(Json(
        json!({"forwards":rows.into_iter().map(public).collect::<Vec<_>>()}),
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
    source: String,
    #[serde(default)]
    destination: String,
    #[serde(default)]
    busid: String,
}
async fn action(
    State(app): State<Arc<App>>,
    Json(mut body): Json<Action>,
) -> ApiResult<Json<Value>> {
    let m = machine_client::authenticate(&app, &body.machine_id, &body.token).await?;
    let owner = m.get_object_id("user_id").map_err(|_| unavailable())?;
    machine(&app, owner, &body.machine_id).await?;
    if body.action == "list" {
        return Ok(Json(
            json!({"forwards":plans(&app,owner,Some(&body.machine_id)).await?.into_iter().map(public).collect::<Vec<_>>()}),
        ));
    }
    if body.action == "create" {
        body.source = oid(&body.source)?.to_hex();
        body.destination = oid(&body.destination)?.to_hex();
        body.machine_id = oid(&body.machine_id)?.to_hex();
        if body.source != body.machine_id && body.destination != body.machine_id {
            return Err(unavailable());
        }
        let existing=app.collection("usb_forwards").find_one(doc!{"owner":owner,"id":&body.id,"persistent":false,"$or":[{"source":&body.machine_id},{"destination":&body.machine_id}]}).await?;
        if let Some(row) = existing {
            if row.get_str("source") != Ok(body.source.as_str())
                || row.get_str("destination") != Ok(body.destination.as_str())
                || row
                    .get_document("device")
                    .ok()
                    .and_then(|d| d.get_str("busid").ok())
                    != Some(body.busid.as_str())
            {
                return Err(unavailable());
            }
            app.collection("usb_forwards").update_one(doc!{"_id":row.get("_id").unwrap().clone()},doc!{"$set":{"expires_at":DateTime::from_millis(DateTime::now().timestamp_millis()+45000)}}).await?;
            return Ok(Json(json!({"forward":public(row)})));
        }
        return Ok(Json(
            make(
                &app,
                owner,
                Create {
                    source: body.source,
                    destination: body.destination,
                    busid: body.busid,
                },
                false,
                Some(&body.id),
            )
            .await?,
        ));
    }
    let filter = doc! {"owner":owner,"id":&body.id,"persistent":false,"$or":[{"source":&body.machine_id},{"destination":&body.machine_id}]};
    match body.action.as_str() {
        "stop" => {
            app.collection("usb_forwards").delete_one(filter).await?;
        }
        _ => return Err(ApiError::bad_request("Invalid USB action")),
    };
    Ok(Json(json!({"ok":true})))
}
async fn authorized_stream(
    app: &App,
    id: &str,
    machine_id: &str,
    token: &str,
    side: &str,
) -> ApiResult<(ObjectId, Forward)> {
    let m = machine_client::authenticate(app, machine_id, token).await?;
    let owner = m.get_object_id("user_id").map_err(|_| unavailable())?;
    machine(app, owner, machine_id).await?;
    let row = app
        .collection("usb_forwards")
        .find_one(doc! {"owner":owner,"id":id,"$and":[current()]})
        .await?
        .ok_or_else(unavailable)?;
    let p: Forward = decode(row).map_err(|_| unavailable())?;
    if (side == "source" && p.source != machine_id)
        || (side == "destination" && p.destination != machine_id)
        || !matches!(side, "source" | "destination")
    {
        return Err(unavailable());
    }
    machine(app, owner, &p.source).await?;
    machine(app, owner, &p.destination).await?;
    require_role(app,owner,&p.source,"can_export").await?;
    require_role(app,owner,&p.destination,"can_import").await?;
    Ok((owner,p))
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
    let (owner,forward)=authorized_stream(&app, &id, &machine_id, &token, &side).await?;
    let key=pair_key(owner,&forward);
    Ok(ws
        .max_message_size(262144)
        .max_frame_size(262144)
        .on_upgrade(move |socket| pair(app, key, id, side, machine_id, token, socket)))
}
async fn pair_authorized(app:&App,id:&str,machine_id:&str,token:&str,side:&str,key:&PairKey)->bool {
    authorized_stream(app,id,machine_id,token,side).await.is_ok_and(|(owner,forward)|pair_key(owner,&forward)==*key)
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
        let mut registry = app.usb.registry.lock().unwrap_or_else(|e| e.into_inner());
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
        let mut registry = app.usb.registry.lock().unwrap_or_else(|e| e.into_inner());
        if registry.waiting.get(&key).is_some_and(|p| p.0 == nonce) {
            registry.waiting.remove(&key);
        }
    }
    let Ok(Ok((mut other, other_machine, other_token, other_side))) = received else {
        return;
    };
    if !pair_authorized(&app,&id,&machine_id,&token,&side,&key).await
        || !pair_authorized(&app,&id,&other_machine,&other_token,&other_side,&key).await
    {
        return;
    }
    if socket.send(Message::Text("ready".into())).await.is_err()
        || other.send(Message::Text("ready".into())).await.is_err()
    {
        return;
    }
    let mut tick = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
         _=tick.tick()=>{if !pair_authorized(&app,&id,&machine_id,&token,&side,&key).await||!pair_authorized(&app,&id,&other_machine,&other_token,&other_side,&key).await{break;}if socket.send(Message::Ping(vec![].into())).await.is_err()||other.send(Message::Ping(vec![].into())).await.is_err(){break;}},
         m=socket.next()=>{match m{Some(Ok(Message::Binary(b)))=>{if other.send(Message::Binary(b)).await.is_err(){break;}},Some(Ok(Message::Ping(b)))=>{if socket.send(Message::Pong(b)).await.is_err(){break;}},Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Text(t)))=>{if !signal(&t)||other.send(Message::Text(t)).await.is_err(){break;}},_=>break}},
         m=other.next()=>{match m{Some(Ok(Message::Binary(b)))=>{if socket.send(Message::Binary(b)).await.is_err(){break;}},Some(Ok(Message::Ping(b)))=>{if other.send(Message::Pong(b)).await.is_err(){break;}},Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Text(t)))=>{if !signal(&t)||socket.send(Message::Text(t)).await.is_err(){break;}},_=>break}}
        }
    }
    let _ = socket.close().await;
    let _ = other.close().await;
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

#[cfg(test)]
mod role_tests {
    use super::*;
    #[test]
    fn legacy_reports_preserve_both_roles_but_explicit_roles_are_enforced() {
        let mut report=doc!{"enabled":true,"supported":true};
        assert!(role_allowed(&report,"can_export"));
        assert!(role_allowed(&report,"can_import"));
        report.insert("can_import",false);
        assert!(role_allowed(&report,"can_export"));
        assert!(!role_allowed(&report,"can_import"));
        report.insert("enabled",false);
        assert!(!role_allowed(&report,"can_export"));
        report.insert("enabled",true);report.insert("supported",false);
        assert!(!role_allowed(&report,"can_export"));
    }
    #[test]
    fn reports_accept_optional_role_fields() {
        for roles in ["",",\"can_export\":true,\"can_import\":false"] {
            let text=format!("{{\"machine_id\":\"id\",\"token\":\"token\",\"enabled\":true,\"supported\":true,\"devices\":[],\"states\":[]{roles}}}");
            let report:Report=serde_json::from_str(&text).unwrap();
            assert!(report.can_export.unwrap_or(report.supported));
            assert_eq!(report.can_import,if roles.is_empty(){None}else{Some(false)});
        }
    }
}
