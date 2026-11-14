//! Account-owned input targets. Commands are RAM-only, bounded and never replayed
//! after disconnect. One controller per target; credentials never reach the UI.
mod devices;
mod romanize;
pub mod speech;
use crate::{
    auth,
    domain::machine_client,
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
    routing::get,
    Json, Router,
};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use mongodb::bson::{doc, oid::ObjectId, Document};
use porthub_components::keyboard::{Input, MAX_FRAME};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::mpsc;

#[derive(Clone)]
struct Host {
    id: String,
    send: mpsc::Sender<Value>,
    board: bool,
}
#[derive(Clone)]
struct Controller {
    id: String,
    send: mpsc::Sender<Value>,
}
#[derive(Default)]
struct Registry {
    hosts: HashMap<String, Host>,
    controllers: HashMap<String, Controller>,
}
#[derive(Default)]
pub struct Hub {
    registry: Mutex<Registry>,
    pub speech: tokio::sync::OnceCell<speech::Speech>,
}
fn lock(hub: &Hub) -> std::sync::MutexGuard<'_, Registry> {
    hub.registry.lock().unwrap_or_else(|e| e.into_inner())
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "VKeyboard desktop module is offline or already controlled",
    )
}
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
pub(super) fn same_origin(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    if let Some(origin) = headers.get("origin") {
        let origin = origin
            .to_str()
            .ok()
            .and_then(|v| url::Url::parse(v).ok())
            .filter(|u| {
                matches!(u.scheme(), "https" | "http")
                    && u.username().is_empty()
                    && u.password().is_none()
            })
            .ok_or_else(|| ApiError::new(StatusCode::FORBIDDEN, "Invalid VKeyboard origin"))?;
        let host = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        let expected = url::Url::parse(&format!("{}://{host}", origin.scheme()));
        let configured = url::Url::parse(&app.config.public_base_url);
        if !expected.is_ok_and(|u| u.origin() == origin.origin())
            && !configured.is_ok_and(|u| u.origin() == origin.origin())
        {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Cross-origin VKeyboard access denied",
            ));
        }
    }
    Ok(())
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/keyboard/targets", get(targets))
        .route("/api/keyboard/host", get(host))
        .route("/api/keyboard/control/{id}", get(control))
        .merge(speech::router())
        .merge(devices::router())
}
fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default()
}
async fn owned_machine(app: &App, headers: &HeaderMap, target: &str) -> ApiResult<Document> {
    let user = auth::current_user(app, headers).await?;
    let machine = ObjectId::parse_str(target).map_err(|_| unavailable())?;
    // Desktop control requires ownership; network access alone never grants HID.
    app.collection("machines").find_one(doc!{"_id":machine,"user_id":user.get_object_id("_id").map_err(|_|ApiError::unauthenticated())?,"enabled":{"$ne":false},"deletion_pending":{"$ne":true}}).await?.ok_or_else(unavailable)
}
async fn authorize_target(app: &App, headers: &HeaderMap, target: &str) -> ApiResult<()> {
    if target.starts_with("board-") {
        devices::owned(app, headers, target).await?;
    } else {
        owned_machine(app, headers, target).await?;
    }
    Ok(())
}
async fn targets(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"user_id":owner,"enabled":{"$ne":false},"deletion_pending":{"$ne":true}})
        .projection(doc! {"name":1,"hostname":1,"client_version":1})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    let mut targets = Vec::new();
    {
        let hub = lock(&app.keyboard);
        for row in machines {
            let target = row.get_object_id("_id").unwrap().to_hex();
            targets.push(json!({"id":target,"name":row.get_str("name").unwrap_or("Machine"),"kind":"desktop","online":hub.hosts.contains_key(&target),"controlled":hub.controllers.contains_key(&target),"clipboard":true}));
        }
    }
    targets.extend(devices::list(&app, owner).await?);
    Ok(Json(json!({"targets":targets})))
}
async fn host(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let machine = headers
        .get("x-porthub-machine-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let token = bearer(&headers).to_owned();
    machine_client::authenticate(&app, &machine, &token).await?;
    Ok(ws
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| host_socket(app, socket, machine, token, false)))
}
async fn send(socket: &mut WebSocket, message: &Value) -> bool {
    socket
        .send(Message::Text(message.to_string().into()))
        .await
        .is_ok()
}
async fn host_socket(
    app: Arc<App>,
    mut socket: WebSocket,
    target: String,
    token: String,
    board: bool,
) {
    let (tx, mut rx) = mpsc::channel(64);
    let identity = id();
    {
        let mut hub = lock(&app.keyboard);
        if let Some(old) = hub.hosts.insert(
            target.clone(),
            Host {
                id: identity.clone(),
                send: tx,
                board,
            },
        ) {
            let _ = old.send.try_send(json!({"type":"replaced"}));
        }
        if let Some(old) = hub.controllers.remove(&target) {
            let _ = old
                .send
                .try_send(json!({"type":"closed","error":"Desktop reconnected"}));
        }
    }
    if !send(
        &mut socket,
        &json!({"type":"ready","target":target,"version":1}),
    )
    .await
    {
        let mut hub = lock(&app.keyboard);
        if hub.hosts.get(&target).is_some_and(|h| h.id == identity) {
            hub.hosts.remove(&target);
        }
        return;
    }
    let mut ping = tokio::time::interval(Duration::from_secs(20));
    let mut last = Instant::now();
    loop {
        tokio::select! {
            _=ping.tick()=>{
                if last.elapsed()>Duration::from_secs(60){break;}
                let valid=if board{devices::authenticate(&app,&target,&token).await.is_ok()}else{machine_client::authenticate(&app,&target,&token).await.is_ok()};
                if !valid || !send(&mut socket,&json!({"type":"ping"})).await{break;}
            }
            outgoing=rx.recv()=>{let Some(message)=outgoing else{break;};if message["type"]=="replaced"{break;}if !send(&mut socket,&message).await{break;}}
            incoming=socket.next()=>{
                let Some(Ok(message))=incoming else{break;};
                match message{
                    Message::Text(text)=>{
                        let Ok(value)=serde_json::from_str::<Value>(&text)else{break;};last=Instant::now();
                        match value["type"].as_str(){
                            Some("pong")=>{},Some("ping")=>{if !send(&mut socket,&json!({"type":"pong"})).await{break;}}
                            Some("ack"|"direct_answer"|"direct_unavailable"|"device_status")=>{
                                let session=value["session"].as_str().unwrap_or_default();let hub=lock(&app.keyboard);
                                if hub.hosts.get(&target).is_some_and(|h|h.id==identity){if let Some(controller)=hub.controllers.get(&target).filter(|c|c.id==session){let _=controller.send.try_send(value);}}
                            }
                            _=>{}
                        }
                    },Message::Ping(data)=>{last=Instant::now();if socket.send(Message::Pong(data)).await.is_err(){break;}},Message::Pong(_)=>last=Instant::now(),Message::Close(_)=>break,_=>break
                }
            }
        }
    }
    {
        let mut hub = lock(&app.keyboard);
        if hub.hosts.get(&target).is_some_and(|h| h.id == identity) {
            hub.hosts.remove(&target);
            if let Some(controller) = hub.controllers.remove(&target) {
                let _ = controller
                    .send
                    .try_send(json!({"type":"closed","error":"VKeyboard disconnected"}));
            }
        }
    }
    let _ = socket.close().await;
}
async fn control(
    State(app): State<Arc<App>>,
    Path(target): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    same_origin(&app, &headers)?;
    authorize_target(&app, &headers, &target).await?;
    {
        let hub = lock(&app.keyboard);
        if !hub.hosts.contains_key(&target) || hub.controllers.contains_key(&target) {
            return Err(unavailable());
        }
    }
    Ok(ws
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| controller_socket(app, socket, target, headers)))
}
async fn controller_socket(
    app: Arc<App>,
    mut socket: WebSocket,
    target: String,
    headers: HeaderMap,
) {
    let identity = id();
    let (tx, mut rx) = mpsc::channel(64);
    let host = {
        let mut hub = lock(&app.keyboard);
        if hub.controllers.contains_key(&target) {
            return;
        }
        let Some(host) = hub.hosts.get(&target).cloned() else {
            return;
        };
        hub.controllers.insert(
            target.clone(),
            Controller {
                id: identity.clone(),
                send: tx,
            },
        );
        host
    };
    if host
        .send
        .try_send(json!({"type":"start","session":identity}))
        .is_err()
    {
        lock(&app.keyboard).controllers.remove(&target);
        return;
    }
    let _ = send(
        &mut socket,
        &json!({"type":"ready","session":identity,"direct":!host.board,"clipboard":!host.board}),
    )
    .await;
    let mut ping = tokio::time::interval(Duration::from_secs(20));
    let mut last = Instant::now();
    let (mut window, mut count) = (Instant::now(), 0u32);
    loop {
        tokio::select! {
            _=ping.tick()=>{if last.elapsed()>Duration::from_secs(60) || authorize_target(&app,&headers,&target).await.is_err() || !send(&mut socket,&json!({"type":"ping"})).await{break;}}
            outgoing=rx.recv()=>{let Some(message)=outgoing else{break;};if !send(&mut socket,&message).await || message["type"]=="closed"{break;}}
            incoming=socket.next()=>{
                let Some(Ok(Message::Text(text)))=incoming else{break;};last=Instant::now();let Ok(mut value)=serde_json::from_str::<Value>(&text)else{break;};
                if value["type"]=="pong"{continue;}
                if window.elapsed()>Duration::from_secs(1){window=Instant::now();count=0;}count+=1;if count>150{break;}
                match value["type"].as_str(){
                    Some("input")=>{
                        let input=serde_json::from_value::<Input>(value["input"].clone());
                        if input.as_ref().map_or(true,|i|i.validate().is_err()){let _=send(&mut socket,&json!({"type":"error","error":"Invalid keyboard command"})).await;continue;}
                        if host.board && matches!(input.as_ref().unwrap().command,porthub_components::keyboard::Command::Clipboard{..}|porthub_components::keyboard::Command::Paste {}){let _=send(&mut socket,&json!({"type":"ack","ack":{"id":input.unwrap().id,"ok":false,"error":"Bluetooth devices cannot update the target clipboard; use Type text"}})).await;continue;}
                    }
                    Some("direct_offer") if !host.board=>{if value["description"].as_str().is_none_or(|s|s.len()>16384){break;}}
                    Some("device") if host.board=>{if !devices::valid_command(&value["command"]){break;}}
                    _=>break
                }
                value["session"]=identity.clone().into();
                if host.send.try_send(value).is_err(){let _=send(&mut socket,&json!({"type":"closed","error":"Input channel is busy; reconnect"})).await;break;}
            }
        }
    }
    let _ = host
        .send
        .try_send(json!({"type":"stop","session":identity}));
    {
        let mut hub = lock(&app.keyboard);
        if hub
            .controllers
            .get(&target)
            .is_some_and(|c| c.id == identity)
        {
            hub.controllers.remove(&target);
        }
    }
    let _ = socket.close().await;
}
