//! Public image drops with independent room storage and browser-owned deletion.
use crate::{
    auth,
    error::{ApiError, ApiResult},
    hosted_images, App,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, oid::ObjectId, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
pub const ROOMS: &str = "image_rooms";
pub const IMAGES: &str = "image_room_images";
const STORAGE: i64 = 512 * 1024 * 1024;
const MAX_IMAGES: usize = 1000;
const DEFAULT_TTL: u32 = 3600;
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/image-rooms", get(list).post(create))
        .route(
            "/api/image-rooms/{id}",
            axum::routing::patch(update).delete(remove_room),
        )
        .route("/api/image-rooms/{id}/images", get(owner_images).delete(owner_remove_many))
        .route(
            "/api/image-rooms/{id}/images/{image}",
            axum::routing::delete(owner_remove_image),
        )
        .route(
            "/api/image-rooms/public/{id}/images",
            get(public_images).post(upload).delete(visitor_remove_many),
        )
        .route(
            "/api/image-rooms/public/{id}/images/{image}",
            axum::routing::delete(visitor_remove_image),
        )
        .route("/r/{filename}", get(raw))
        .layer(DefaultBodyLimit::max(hosted_images::MAX_BODY_BYTES))
}
fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Room or image not found")
        .header("cache-control", "no-store")
}
fn valid(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn timestamp(time: DateTime) -> String {
    format!("{}Z", crate::store::datetime(time.timestamp_millis()))
}
async fn indexes(app: &App) -> ApiResult<()> {
    app.image_rooms_initialized
        .get_or_try_init(|| async {
            app.collection(ROOMS)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"owner_id":1,"created_at":-1})
                        .build(),
                )
                .await?;
            app.collection(IMAGES)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"room_id":1,"created_at":1})
                        .build(),
                )
                .await?;
            app.collection(IMAGES)
                .create_index(IndexModel::builder().keys(doc! {"owner_id":1,"expires_at":1,"room_id":1}).build())
                .await?;
            app.collection(IMAGES)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"public_id":1})
                        .options(IndexOptions::builder().unique(true).build())
                        .build(),
                )
                .await?;
            app.collection(IMAGES)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"expires_at":1})
                        .options(IndexOptions::builder().expire_after(Duration::ZERO).build())
                        .build(),
                )
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
async fn owner(app: &App, headers: &HeaderMap) -> ApiResult<ObjectId> {
    auth::current_user(app, headers)
        .await?
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())
}
async fn room(app: &App, id: &str, owner: Option<ObjectId>) -> ApiResult<Document> {
    if !valid(id) {
        return Err(missing());
    }
    let mut filter = doc! {"_id":id};
    if let Some(owner) = owner {
        filter.insert("owner_id", owner);
    }
    app.collection(ROOMS)
        .find_one(filter)
        .await?
        .ok_or_else(missing)
}
fn room_metadata(app: &App, row: &Document) -> Value {
    let id = row.get_str("_id").unwrap_or_default();
    let path = format!("/drop?room={id}");
    json!({"id":id,"name":row.get_str("name").unwrap_or("Image room"),"enabled":row.get_bool("enabled").unwrap_or(false),
        "image_ttl_seconds":row.get_i64("image_ttl_seconds").unwrap_or(DEFAULT_TTL as i64),"max_storage":STORAGE,
        "path":path,"url":format!("{}{}",app.config.public_base_url.trim_end_matches('/'),path)})
}
fn visitor(headers: &HeaderMap, room: &str) -> Option<String> {
    let id = headers.get("x-image-visitor")?.to_str().ok()?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(format!(
        "{:x}",
        Sha256::digest(format!("porthub-image-room:{room}:{id}"))
    ))
}
fn image_metadata(app: &App, row: &Document, visitor: Option<&str>, owner: bool) -> Value {
    let mut image = hosted_images::metadata(app, row);
    let path = format!("/r/{}.png", row.get_str("public_id").unwrap_or_default());
    image["path"] = json!(path);
    image["url"] = json!(format!(
        "{}{}",
        app.config.public_base_url.trim_end_matches('/'),
        path
    ));
    image["expires_at"] = row
        .get_datetime("expires_at")
        .map(|d| json!(timestamp(*d)))
        .unwrap_or(Value::Null);
    image["can_delete"] =
        json!(owner || visitor.is_some_and(|v| row.get_str("visitor_hash").ok() == Some(v)));
    image
}
fn lifetime(seconds: u32) -> ApiResult<i64> {
    if !(60..=30 * 24 * 3600).contains(&seconds) {
        return Err(ApiError::bad_request(
            "Image lifetime must be between 1 minute and 30 days",
        ));
    }
    Ok(i64::from(seconds))
}
fn name(value: &str) -> String {
    let value: String = value.chars().filter(|c| !c.is_control()).take(80).collect();
    if value.trim().is_empty() {
        "Image room".into()
    } else {
        value.trim().into()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    name: Option<String>,
    enabled: Option<bool>,
    image_ttl_seconds: Option<u32>,
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Settings>,
) -> ApiResult<Json<Value>> {
    let _lifecycle = app.account_lifecycle.read().await;
    let owner = owner(&app, &headers).await?;
    indexes(&app).await?;
    let _admission = app.hosted_images_lock.lock().await;
    if app
        .collection(ROOMS)
        .count_documents(doc! {"owner_id":owner})
        .await?
        >= 1000
    {
        return Err(ApiError::bad_request("Room limit reached (1,000 rooms)"));
    }
    let row = doc! {"_id":uuid::Uuid::new_v4().simple().to_string(),"owner_id":owner,"name":name(body.name.as_deref().unwrap_or("")),
    "enabled":body.enabled.unwrap_or(true),"image_ttl_seconds":lifetime(body.image_ttl_seconds.unwrap_or(DEFAULT_TTL))?,"created_at":DateTime::now()};
    app.collection(ROOMS).insert_one(&row).await?;
    Ok(Json(room_metadata(&app, &row)))
}
async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let owner = owner(&app, &headers).await?;
    indexes(&app).await?;
    let rows: Vec<Document> = app
        .collection(ROOMS)
        .find(doc! {"owner_id":owner})
        .sort(doc! {"created_at":-1,"_id":1})
        .limit(1000)
        .await?
        .try_collect()
        .await?;
    let stats: Vec<Document> = app
        .collection(IMAGES)
        .aggregate([
            doc! {"$match":crate::image_storage::parents(doc!{"owner_id":owner,"expires_at":{"$gt":DateTime::now()}})},
            doc! {"$group":{"_id":"$room_id","used":{"$sum":"$size"},"count":{"$sum":1}}},
        ])
        .await?
        .try_collect()
        .await?;
    let rooms = rows
        .iter()
        .map(|row| {
            let mut value = room_metadata(&app, row);
            let stat = stats
                .iter()
                .find(|s| s.get_str("_id").ok() == row.get_str("_id").ok());
            value["used"] = json!(stat.and_then(|s| s.get_i64("used").ok()).unwrap_or(0));
            value["image_count"] = json!(stat.and_then(|s| s.get_i32("count").ok()).unwrap_or(0));
            value
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({"rooms":rooms})))
}
async fn update(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Settings>,
) -> ApiResult<Json<Value>> {
    let _lifecycle = app.account_lifecycle.read().await;
    let owner = owner(&app, &headers).await?;
    let _admission = app.hosted_images_lock.lock().await;
    let mut row = room(&app, &id, Some(owner)).await?;
    let mut changes = doc! {};
    if let Some(value) = body.name {
        changes.insert("name", name(&value));
    }
    if let Some(value) = body.enabled {
        changes.insert("enabled", value);
    }
    if let Some(value) = body.image_ttl_seconds {
        changes.insert("image_ttl_seconds", lifetime(value)?);
    }
    if !changes.is_empty() {
        app.collection(ROOMS)
            .update_one(doc! {"_id":&id,"owner_id":owner}, doc! {"$set":&changes})
            .await?;
        row.extend(changes);
    }
    Ok(Json(room_metadata(&app, &row)))
}
async fn remove_room(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let _lifecycle = app.account_lifecycle.read().await;
    let owner = owner(&app, &headers).await?;
    let _admission = app.hosted_images_lock.lock().await;
    room(&app, &id, Some(owner)).await?;
    app.collection(IMAGES)
        .delete_many(doc! {"room_id":&id,"owner_id":owner})
        .await?;
    app.collection(ROOMS)
        .delete_one(doc! {"_id":id,"owner_id":owner})
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn images(
    app: &App,
    id: &str,
    headers: &HeaderMap,
    is_owner: bool,
) -> ApiResult<Json<Value>> {
    indexes(app).await?;
    let owner = if is_owner {
        Some(owner(app, headers).await?)
    } else {
        None
    };
    let row = room(app, id, owner).await?;
    let rows: Vec<Document> = app
        .collection(IMAGES)
        .find(crate::image_storage::parents(doc! {"room_id":id,"expires_at":{"$gt":DateTime::now()}}))
        .projection(doc! {"data":0})
        .sort(doc! {"created_at":-1,"_id":1})
        .limit(MAX_IMAGES as i64)
        .await?
        .try_collect()
        .await?;
    let visitor = visitor(headers, id);
    Ok(Json(
        json!({"room":room_metadata(app,&row),"images":rows.iter().map(|r|image_metadata(app,r,visitor.as_deref(),is_owner)).collect::<Vec<_>>(),"max_storage":STORAGE}),
    ))
}
async fn public_images(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    images(&app, &id, &headers, false).await
}
async fn owner_images(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    images(&app, &id, &headers, true).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    image: String,
    #[serde(default)]
    name: String,
}
async fn upload(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Upload>,
) -> ApiResult<Json<Value>> {
    let _lifecycle = app.account_lifecycle.read().await;
    let visitor = visitor(&headers, &id)
        .ok_or_else(|| ApiError::bad_request("A browser upload identity is required"))?;
    let initial = room(&app, &id, None).await?;
    if initial.get_bool("enabled") != Ok(true) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Uploads to this room are paused",
        ));
    }
    if body.image.len() > hosted_images::MAX_BYTES.div_ceil(3) * 4 {
        return Err(ApiError::bad_request("Image exceeds 50 MB"));
    }
    let bytes = STANDARD
        .decode(&body.image)
        .map_err(|_| ApiError::bad_request("Invalid image"))?;
    let (bytes, width, height) =
        tokio::task::spawn_blocking(move || hosted_images::normalize(&bytes))
            .await
            .map_err(|_| {
                ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Image processing failed")
            })??;
    indexes(&app).await?;
    let _admission = app.hosted_images_lock.lock().await;
    // Re-check after decoding so disabling or deleting a room closes admission.
    let room = room(&app, &id, None).await?;
    if room.get_bool("enabled") != Ok(true) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Uploads to this room are paused",
        ));
    }
    let now = DateTime::now();
    app.collection(IMAGES)
        .delete_many(doc! {"room_id":&id,"expires_at":{"$lte":now}})
        .await?;
    let previous: Vec<Document> = app
        .collection(IMAGES)
        .find(crate::image_storage::parents(doc! {"room_id":&id}))
        .projection(doc! {"size":1})
        .sort(doc! {"created_at":1,"_id":1})
        .limit((MAX_IMAGES + 1) as i64)
        .await?
        .try_collect()
        .await?;
    let mut used = previous
        .iter()
        .map(|r| r.get_i64("size").unwrap_or(0))
        .sum::<i64>()
        + bytes.len() as i64;
    let mut count = previous.len() + 1;
    let mut expired = Vec::new();
    for row in &previous {
        if used <= STORAGE && count <= MAX_IMAGES {
            break;
        }
        used -= row.get_i64("size").unwrap_or(0);
        count -= 1;
        expired.push(row.get("_id").cloned().unwrap());
    }
    let ttl = room
        .get_i64("image_ttl_seconds")
        .unwrap_or(DEFAULT_TTL as i64);
    let row = doc! {"_id":uuid::Uuid::new_v4().simple().to_string(),"owner_id":room.get_object_id("owner_id").map_err(|_|missing())?,
    "room_id":&id,"visitor_hash":&visitor,"name":if body.name.trim().is_empty(){"Clipboard image".to_owned()}else{name(&body.name)},"size":bytes.len()as i64,"width":i64::from(width),"height":i64::from(height),
    "created_at":now,"expires_at":DateTime::from_millis(now.timestamp_millis()+ttl*1000)};
    let stored = crate::image_storage::insert(&app, IMAGES, row, bytes).await?;
    if stored.inserted && !expired.is_empty() {
        crate::image_storage::remove(&app, IMAGES, doc! {"room_id":&id,"_id":{"$in":expired}}).await?;
    }
    Ok(Json(image_metadata(&app, &stored.row, Some(&visitor), false)))
}

async fn owner_remove_image(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((id, image)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let _lifecycle = app.account_lifecycle.read().await;
    let owner = owner(&app, &headers).await?;
    let _admission = app.hosted_images_lock.lock().await;
    room(&app, &id, Some(owner)).await?;
    delete_image(&app, doc! {"_id":image,"room_id":id,"owner_id":owner}).await
}
async fn visitor_remove_image(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path((id, image)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let visitor = visitor(&headers, &id).ok_or_else(missing)?;
    let _admission = app.hosted_images_lock.lock().await;
    room(&app, &id, None).await?;
    delete_image(&app, doc! {"_id":image,"room_id":id,"visitor_hash":visitor}).await
}
async fn delete_image(app: &App, filter: Document) -> ApiResult<StatusCode> {
    if crate::image_storage::remove(app, IMAGES, filter).await? == 0 { return Err(missing()); }
    Ok(StatusCode::NO_CONTENT)
}
async fn raw(State(app): State<Arc<App>>, Path(filename): Path<String>) -> ApiResult<Response> {
    let code = filename
        .strip_suffix(".png")
        .filter(|c| {
            c.len() == 5
                && c.bytes()
                    .all(|b| hosted_images::PUBLIC_ALPHABET.contains(&b))
        })
        .ok_or_else(missing)?;
    // Enforce exact expiry independently of MongoDB's asynchronous TTL sweep.
    let row = app
        .collection(IMAGES)
        .find_one(doc! {"public_id":code,"expires_at":{"$gt":DateTime::now()}})
        .await?
        .ok_or_else(missing)?;
    hosted_images::image_response(&app, IMAGES, row).await
}

async fn owner_remove_many(State(app):State<Arc<App>>,headers:HeaderMap,Path(id):Path<String>,Json(body):Json<hosted_images::BulkDelete>)->ApiResult<Json<Value>> {
    let _lifecycle=app.account_lifecycle.read().await;
    let owner=owner(&app,&headers).await?;
    let filter=body.filter(doc!{"owner_id":owner,"room_id":&id})?;
    let _admission=app.hosted_images_lock.lock().await;
    room(&app,&id,Some(owner)).await?;
    let count=crate::image_storage::remove(&app, IMAGES, filter).await?;
    Ok(Json(json!({"deleted_count":count})))
}
async fn visitor_remove_many(State(app):State<Arc<App>>,headers:HeaderMap,Path(id):Path<String>,Json(body):Json<hosted_images::BulkDelete>)->ApiResult<Json<Value>> {
    let _lifecycle=app.account_lifecycle.read().await;
    let visitor=visitor(&headers,&id).ok_or_else(missing)?;
    let filter=body.filter(doc!{"room_id":&id,"visitor_hash":visitor})?;
    let _admission=app.hosted_images_lock.lock().await;
    room(&app,&id,None).await?;
    let count=crate::image_storage::remove(&app, IMAGES, filter).await?;
    Ok(Json(json!({"deleted_count":count})))
}
