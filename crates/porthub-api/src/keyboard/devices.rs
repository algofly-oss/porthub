//! Microcontrollers use dedicated revocable credentials, never machine or account
//! install tokens. Flashing and configuration run in the requesting browser.
use super::*;
use axum::{
    extract::{ws::WebSocketUpgrade, DefaultBodyLimit},
    routing::post,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
fn hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
pub(super) async fn owned(app: &App, headers: &HeaderMap, target: &str) -> ApiResult<Document> {
    let user = auth::current_user(app, headers).await?;
    app.collection("keyboard_devices").find_one(doc!{"_id":target,"owner_id":user.get_object_id("_id").map_err(|_|ApiError::unauthenticated())?}).await?.ok_or_else(unavailable)
}
pub(super) async fn authenticate(app: &App, target: &str, token: &str) -> ApiResult<Document> {
    if token.len() != 64 {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Invalid keyboard device credentials",
        ));
    }
    let row = app
        .collection("keyboard_devices")
        .find_one(doc! {"_id":target,"token_hash":hash(token),"enabled":true})
        .await?
        .ok_or_else(unavailable)?;
    let owner = row.get_object_id("owner_id").map_err(|_| unavailable())?;
    if app
        .collection("users")
        .find_one(doc! {"_id":owner,"account_deletion":{"$exists":false}})
        .await?
        .is_none()
    {
        return Err(unavailable());
    }
    Ok(row)
}
pub(super) async fn list(app: &App, owner: ObjectId) -> ApiResult<Vec<Value>> {
    let rows: Vec<Document> = app
        .collection("keyboard_devices")
        .find(doc! {"owner_id":owner})
        .limit(100)
        .await?
        .try_collect()
        .await?;
    let hub = lock(&app.keyboard);
    Ok(rows.iter().map(|row|{let target=row.get_str("_id").unwrap_or_default();json!({"id":target,"name":row.get_str("name").unwrap_or("Bluetooth keyboard"),"kind":"esp32","enabled":row.get_bool("enabled").unwrap_or(false),"online":hub.hosts.contains_key(target),"controlled":hub.controllers.contains_key(target),"clipboard":false})}).collect())
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/keyboard/devices", post(create))
        .route(
            "/api/keyboard/devices/{id}",
            axum::routing::patch(update).delete(remove),
        )
        .route("/api/keyboard/device/{id}", get(connect))
        .route("/api/keyboard/firmware", get(firmware))
        .route("/api/keyboard/firmware/{chip}", get(binary))
        .layer(DefaultBodyLimit::max(4096))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    name: String,
}
fn name(value: &str) -> ApiResult<&str> {
    let v = value.trim();
    if v.is_empty() || v.len() > 80 || v.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Use a device name up to 80 bytes"));
    }
    Ok(v)
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Name>,
) -> ApiResult<Json<Value>> {
    same_origin(&app, &headers)?;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    if app
        .collection("keyboard_devices")
        .count_documents(doc! {"owner_id":owner})
        .await?
        >= 100
    {
        return Err(ApiError::bad_request("Keyboard device limit reached"));
    }
    let target = format!("board-{}", id());
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    app.collection("keyboard_devices").insert_one(doc!{"_id":&target,"name":name(&body.name)?,"owner_id":owner,"token_hash":hash(&token),"enabled":true,"created_at":mongodb::bson::DateTime::now()}).await?;
    Ok(Json(json!({"id":target,"token":token})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Update {
    name: Option<String>,
    enabled: Option<bool>,
}
async fn update(
    State(app): State<Arc<App>>,
    Path(target): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Update>,
) -> ApiResult<Json<Value>> {
    same_origin(&app, &headers)?;
    owned(&app, &headers, &target).await?;
    let mut fields = Document::new();
    if let Some(n) = body.name {
        fields.insert("name", name(&n)?);
    }
    if let Some(enabled) = body.enabled {
        fields.insert("enabled", enabled);
    }
    if fields.is_empty() {
        return Err(ApiError::bad_request("No device changes supplied"));
    }
    app.collection("keyboard_devices")
        .update_one(doc! {"_id":&target}, doc! {"$set":fields})
        .await?;
    if body.enabled == Some(false) {
        disconnect(&app, &target);
    }
    Ok(Json(json!({"ok":true})))
}
fn disconnect(app: &App, target: &str) {
    let mut hub = lock(&app.keyboard);
    if let Some(host) = hub.hosts.remove(target) {
        let _ = host.send.try_send(json!({"type":"replaced"}));
    }
    if let Some(c) = hub.controllers.remove(target) {
        let _ = c
            .send
            .try_send(json!({"type":"closed","error":"Device revoked"}));
    }
}
async fn remove(
    State(app): State<Arc<App>>,
    Path(target): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    same_origin(&app, &headers)?;
    owned(&app, &headers, &target).await?;
    app.collection("keyboard_devices")
        .delete_one(doc! {"_id":&target})
        .await?;
    disconnect(&app, &target);
    Ok(Json(json!({"ok":true})))
}
async fn connect(
    State(app): State<Arc<App>>,
    Path(target): Path<String>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let token = bearer(&headers).to_owned();
    authenticate(&app, &target, &token).await?;
    Ok(ws
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| host_socket(app, socket, target, token, true)))
}
pub(super) fn valid_command(value: &Value) -> bool {
    match value["type"].as_str() {
        Some("bluetooth" | "logs") => value["on"].is_boolean(),
        Some("pairing") => value["seconds"]
            .as_u64()
            .is_some_and(|s| (10..=600).contains(&s)),
        Some("forget") => true,
        _ => false,
    }
}
fn firmware_root(app: &App) -> std::path::PathBuf {
    std::env::var_os("PORTHUB_KEYBOARD_FIRMWARE_DIR")
        .map(Into::into)
        .unwrap_or_else(|| {
            if app.config.ui_root.is_empty() {
                "/data/keyboard-firmware".into()
            } else {
                std::path::PathBuf::from(&app.config.ui_root).join("keyboard-firmware")
            }
        })
}
fn chip(value: &str) -> ApiResult<&str> {
    if matches!(value, "esp32" | "esp32c3") {
        Ok(value)
    } else {
        Err(ApiError::bad_request("Unsupported board chip"))
    }
}
async fn firmware(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    auth::current_user(&app, &headers).await?;
    let mut images = Vec::new();
    for chip in ["esp32", "esp32c3"] {
        let path = firmware_root(&app).join(format!("porthub-keyboard-{chip}.bin"));
        if let Ok(bytes) = tokio::fs::read(path).await {
            images.push(json!({"chip":chip,"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes)),"url":format!("/api/keyboard/firmware/{chip}")}));
        }
    }
    Ok(Json(json!({"images":images})))
}
async fn binary(
    State(app): State<Arc<App>>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    auth::current_user(&app, &headers).await?;
    let chip = chip(&value)?;
    let bytes = tokio::fs::read(firmware_root(&app).join(format!("porthub-keyboard-{chip}.bin")))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "Firmware has not been installed on this deployment",
            )
        })?;
    use axum::response::IntoResponse;
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("cache-control", "private, no-store"),
        ],
        bytes,
    )
        .into_response())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restricts_device_actions() {
        assert!(valid_command(&json!({"type":"pairing","seconds":120})));
        assert!(!valid_command(&json!({"type":"pairing","seconds":0})));
        assert!(!valid_command(&json!({"type":"shell","text":"foo"})));
        assert!(chip("../esp32").is_err());
    }
}
