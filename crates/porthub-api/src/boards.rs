//! Durable Excalidraw documents and capability-scoped guest access. Scene
//! deltas retain tombstones and use Excalidraw's version/nonce conflict rule.
use crate::{
    auth,
    error::{ApiError, ApiResult},
    image_storage, App,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{self, doc, oid::ObjectId, DateTime, Document},
    IndexModel,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use socketioxide::{
    extract::{SocketRef, TryData},
    handler::ConnectHandler,
    SocketIo,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

mod preview;

pub const COLLECTION: &str = "boards";
pub const ASSETS: &str = "board_assets";
const SCENE_BYTES: usize = 8 * 1024 * 1024;
const STORAGE: i64 = 512 * 1024 * 1024;
const ELEMENTS: usize = 20_000;

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/boards", get(list).post(create))
        .route("/api/boards/{id}", get(read).patch(update).delete(remove))
        .route("/api/boards/{id}/preview", get(preview::read).put(preview::write))
        .route("/api/boards/{id}/scene", axum::routing::patch(patch_scene))
        .route("/api/boards/{id}/sharing", axum::routing::patch(sharing))
        .layer(DefaultBodyLimit::max(SCENE_BYTES + 64 * 1024))
        .merge(
            Router::new()
                .route(
                    "/api/boards/{id}/assets/{file}",
                    get(read_asset).put(upload_asset),
                )
                .layer(DefaultBodyLimit::max(crate::hosted_images::MAX_BODY_BYTES)),
        )
        .layer(axum::middleware::map_response(
            |mut response: axum::response::Response| async move {
                response
                    .headers_mut()
                    .insert("cache-control", "no-store".parse().unwrap());
                response
                    .headers_mut()
                    .insert("referrer-policy", "no-referrer".parse().unwrap());
                response
            },
        ))
}
fn missing() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "Board not found or sharing link disabled",
    )
    .header("cache-control", "no-store")
}
fn valid(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn file_valid(id: &str) -> bool {
    !id.is_empty()
        && !matches!(id, "__proto__" | "constructor" | "prototype")
        && id.len() <= 80
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
fn title(value: &str) -> ApiResult<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > 120 || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "Board name must contain 1–120 characters",
        ));
    }
    Ok(value.into())
}
fn token() -> String {
    let mut bytes = [0; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn equal(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(Sha256::digest(a).ct_eq(&Sha256::digest(b)))
}
fn stamp(row: &Document, key: &str) -> Value {
    crate::store::field(row, key)
}
fn metadata(row: &Document, owner: bool, editable: bool) -> Value {
    let mut data = json!({"id":row.get_str("_id").unwrap_or(""),"name":row.get_str("name").unwrap_or("Untitled board"),
        "preview_revision":row.get_i64("preview_revision").unwrap_or(-1),"owner":owner,"editable":editable,"revision":row.get_i64("revision").unwrap_or(0),
        "created_at":stamp(row,"created_at"),"updated_at":stamp(row,"updated_at"),"asset_bytes":row.get_i64("asset_bytes").unwrap_or(0),"max_asset_bytes":STORAGE});
    if owner {
        data["sharing"] = json!({"enabled":row.get_bool("sharing").unwrap_or(false),"edit_token":row.get_str("edit_token").unwrap_or(""),"view_token":row.get_str("view_token").unwrap_or("")});
    }
    data
}
async fn owner(app: &App, headers: &HeaderMap) -> ApiResult<ObjectId> {
    auth::current_user(app, headers)
        .await?
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())
}
async fn load_scene(app: &App, id: &str) -> ApiResult<Document> {
    if !valid(id) {
        return Err(missing());
    }
    app.collection(COLLECTION)
        .find_one(doc! {"_id":id})
        .projection(doc! {"preview":0})
        .await?
        .ok_or_else(missing)
}
async fn load(app: &App, id: &str) -> ApiResult<Document> {
    if !valid(id) {
        return Err(missing());
    }
    app.collection(COLLECTION)
        .find_one(doc! {"_id":id})
        .projection(doc! {"elements":0,"preview":0})
        .await?
        .ok_or_else(missing)
}
#[derive(Clone)]
struct Access {
    owner: bool,
    edit: bool,
}
async fn authorize(app: &App, row: &Document, headers: &HeaderMap) -> ApiResult<Access> {
    if let Some(share) = headers.get("x-board-share") {
        let share = share.to_str().map_err(|_| missing())?;
        if share.len() != 43 || row.get_bool("sharing") != Ok(true) {
            return Err(missing());
        }
        if equal(share, row.get_str("edit_token").unwrap_or("")) {
            return Ok(Access {
                owner: false,
                edit: true,
            });
        }
        if equal(share, row.get_str("view_token").unwrap_or("")) {
            return Ok(Access {
                owner: false,
                edit: false,
            });
        }
        return Err(missing());
    }
    if row.get_object_id("owner_id").ok() == Some(owner(app, headers).await?) {
        Ok(Access {
            owner: true,
            edit: true,
        })
    } else {
        Err(missing())
    }
}
async fn owned(app: &App, id: &str, headers: &HeaderMap) -> ApiResult<Document> {
    let row = load(app, id).await?;
    if authorize(app, &row, headers).await?.owner {
        Ok(row)
    } else {
        Err(missing())
    }
}
async fn indexes(app: &App) -> ApiResult<()> {
    app.boards
        .initialized
        .get_or_try_init(|| async {
            app.collection(COLLECTION)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"owner_id":1,"updated_at":-1})
                        .build(),
                )
                .await?;
            app.collection(ASSETS)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"board_id":1,"file_id":1})
                        .options(
                            mongodb::options::IndexOptions::builder()
                                .unique(true)
                                .sparse(true)
                                .build(),
                        )
                        .build(),
                )
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
#[derive(Default, Deserialize)]
struct Search { #[serde(default)] search: String }
async fn list(State(app): State<Arc<App>>, Query(query): Query<Search>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let user = owner(&app, &headers).await?;
    let mut filter = doc! {"owner_id":user};
    let needle: String = query.search.trim().chars().take(200).collect();
    if !needle.is_empty() {
        let literal = needle.chars().fold(String::new(), |mut out, c| {
            if ".*+?^$()[]{}|\\".contains(c) { out.push('\\'); }
            out.push(c); out
        });
        let pattern = doc! {"$regex":literal,"$options":"i"};
        filter.insert("$or", bson::to_bson(&vec![
            doc! {"name":pattern.clone()},
            doc! {"elements":{"$elemMatch":{"isDeleted":{"$ne":true},"$or":[{"text":pattern.clone()},{"originalText":pattern}]}}}
        ]).unwrap());
    }
    let rows: Vec<Document> = app
        .collection(COLLECTION)
        .find(filter)
        .projection(doc! {"elements":0,"preview":0})
        .sort(doc! {"updated_at":-1,"_id":1})
        .limit(101)
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"boards":rows.iter().map(|r|metadata(r,true,true)).collect::<Vec<_>>()}),
    ))
}
#[derive(Deserialize)]
struct Name {
    name: String,
}
async fn create(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Name>,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let _lock = app.boards.lock.lock().await;
    let user = owner(&app, &headers).await?;
    indexes(&app).await?;
    if app
        .collection(COLLECTION)
        .count_documents(doc! {"owner_id":user})
        .await?
        >= 100
    {
        return Err(ApiError::bad_request(
            "You can keep up to 100 boards. Delete an unused board first.",
        ));
    }
    let now = DateTime::now();
    let row = doc! {"_id":uuid::Uuid::new_v4().simple().to_string(),"owner_id":user,"name":title(&body.name)?,"created_at":now,"updated_at":now,"revision":0_i64,"elements":[],"sharing":false,"asset_bytes":0_i64};
    app.collection(COLLECTION).insert_one(&row).await?;
    Ok(Json(metadata(&row, true, true)))
}
async fn read(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let row = load_scene(&app, &id).await?;
    let access = authorize(&app, &row, &headers).await?;
    let mut data = metadata(&row, access.owner, access.edit);
    data["appState"] = row
        .get_document("app_state")
        .ok()
        .and_then(|s| serde_json::to_value(s).ok())
        .unwrap_or_else(|| json!({"viewBackgroundColor":"#ffffff"}));
    data["elements"] = serde_json::to_value(row.get_array("elements").cloned().unwrap_or_default())
        .map_err(|_| ApiError::bad_request("Invalid board scene"))?;
    Ok(Json(data))
}
async fn update(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Name>,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let _lock = app.boards.lock.lock().await;
    let mut row = owned(&app, &id, &headers).await?;
    let name = title(&body.name)?;
    app.collection(COLLECTION)
        .update_one(
            doc! {"_id":&id},
            doc! {"$set":{"name":&name,"updated_at":DateTime::now()}},
        )
        .await?;
    row.insert("name", name);
    app.boards.broadcast(&app, &id, "changed", &json!({})).await;
    Ok(Json(metadata(&row, true, true)))
}
#[derive(Deserialize)]
struct Sharing {
    enabled: bool,
    #[serde(default)]
    rotate: bool,
}
async fn sharing(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Sharing>,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let _lock = app.boards.lock.lock().await;
    let mut row = owned(&app, &id, &headers).await?;
    row.insert("sharing", body.enabled);
    if body.enabled && (body.rotate || row.get_str("edit_token").is_err()) {
        row.insert("edit_token", token());
        row.insert("view_token", token());
    }
    let mut set = doc! {"sharing":body.enabled};
    for key in ["edit_token", "view_token"] {
        if let Some(value) = row.get(key) {
            set.insert(key, value.clone());
        }
    }
    app.collection(COLLECTION)
        .update_one(doc! {"_id":&id}, doc! {"$set":set})
        .await?;
    app.boards.broadcast(&app, &id, "changed", &json!({})).await;
    Ok(Json(metadata(&row, true, true)))
}
async fn remove(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let _lock = app.boards.lock.lock().await;
    owned(&app, &id, &headers).await?;
    let _images = app.hosted_images_lock.lock().await;
    image_storage::remove(&app, ASSETS, doc! {"board_id":&id}).await?;
    app.collection(COLLECTION)
        .delete_one(doc! {"_id":&id})
        .await?;
    app.boards.broadcast(&app, &id, "changed", &json!({})).await;
    Ok(Json(json!({"deleted":true})))
}
#[derive(Deserialize)]
struct Delta {
    elements: Vec<Value>,
    #[serde(default)]
    app_state: Option<Value>,
}
fn element_key(value: &Value) -> ApiResult<(&str, u64, u64)> {
    let id = value["id"]
        .as_str()
        .filter(|s| file_valid(s))
        .ok_or_else(|| ApiError::bad_request("Invalid drawing element ID"))?;
    let version = value["version"]
        .as_u64()
        .filter(|v| *v > 0 && *v <= 9_007_199_254_740_991)
        .ok_or_else(|| ApiError::bad_request("Invalid drawing element version"))?;
    let nonce = value["versionNonce"]
        .as_u64()
        .filter(|v| *v <= u32::MAX as u64)
        .ok_or_else(|| ApiError::bad_request("Invalid drawing element nonce"))?;
    Ok((id, version, nonce))
}
// serde_json's workspace-wide arbitrary_precision feature serializes parsed
// numbers through a private map that BSON's serde serializer does not recognize.
// Convert the JSON tree explicitly so coordinates remain native BSON numbers.
fn scene_bson(value: &Value) -> ApiResult<bson::Bson> {
    use bson::Bson;
    Ok(match value {
        Value::Null => Bson::Null,
        Value::Bool(value) => Bson::Boolean(*value),
        Value::String(value) => Bson::String(value.clone()),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                Bson::Int64(value)
            } else {
                Bson::Double(
                    value
                        .as_f64()
                        .filter(|v| v.is_finite())
                        .ok_or_else(|| ApiError::bad_request("Invalid drawing number"))?,
                )
            }
        }
        Value::Array(values) => {
            Bson::Array(values.iter().map(scene_bson).collect::<ApiResult<_>>()?)
        }
        Value::Object(values) => Bson::Document(
            values
                .iter()
                .map(|(key, value)| Ok((key.clone(), scene_bson(value)?)))
                .collect::<ApiResult<_>>()?,
        ),
    })
}
fn merge(previous: Vec<Value>, delta: Vec<Value>) -> ApiResult<Vec<Value>> {
    let mut indices = HashMap::new();
    let mut result = previous;
    for (index, element) in result.iter().enumerate() {
        indices.insert(element_key(element)?.0.to_owned(), index);
    }
    for element in delta {
        let (id, version, nonce) = element_key(&element)?;
        for field in ["x", "y", "width", "height"] {
            if !element[field].as_f64().is_some_and(f64::is_finite) {
                return Err(ApiError::bad_request(
                    "Drawing coordinates must be finite numbers",
                ));
            }
        }
        for field in ["angle", "opacity", "strokeWidth", "roughness", "fontSize"] {
            if let Some(value) = element.get(field) {
                if !value.as_f64().is_some_and(f64::is_finite) {
                    return Err(ApiError::bad_request("Invalid drawing style"));
                }
            }
        }
        if element.get("isDeleted").is_some_and(|v| !v.is_boolean()) {
            return Err(ApiError::bad_request("Invalid drawing deletion flag"));
        }
        for field in ["text", "originalText"] {
            if element
                .get(field)
                .is_some_and(|v| v.as_str().is_none_or(|s| s.len() > 512 * 1024))
            {
                return Err(ApiError::bad_request("Invalid drawing text"));
            }
        }
        if let Some(groups) = element.get("groupIds") {
            if !groups
                .as_array()
                .is_some_and(|g| g.iter().all(|id| id.as_str().is_some_and(file_valid)))
            {
                return Err(ApiError::bad_request("Invalid drawing groups"));
            }
        }
        if let Some(points) = element.get("points") {
            if !points.as_array().is_some_and(|p| {
                p.iter().all(|p| {
                    p.as_array().is_some_and(|p| {
                        p.len() == 2 && p.iter().all(|v| v.as_f64().is_some_and(f64::is_finite))
                    })
                })
            }) {
                return Err(ApiError::bad_request("Invalid drawing points"));
            }
        }
        if !matches!(
            element["type"].as_str(),
            Some(
                "rectangle"
                    | "diamond"
                    | "ellipse"
                    | "line"
                    | "arrow"
                    | "freedraw"
                    | "text"
                    | "image"
                    | "frame"
                    | "magicframe"
                    | "embeddable"
                    | "iframe"
            )
        ) {
            return Err(ApiError::bad_request("Unsupported drawing element"));
        }
        if let Some(index) = indices.get(id) {
            let (_, old_version, old_nonce) = element_key(&result[*index])?;
            if version > old_version || version == old_version && nonce < old_nonce {
                result[*index] = element;
            }
        } else {
            indices.insert(id.to_owned(), result.len());
            result.push(element);
        }
    }
    if result.len() > ELEMENTS
        || serde_json::to_vec(&result).map_or(true, |s| s.len() > SCENE_BYTES)
    {
        return Err(ApiError::bad_request("Board scene exceeds its size limit"));
    }
    // Excalidraw fractional indices describe z-order independently of arrival order.
    result.sort_by(|a, b| {
        a["index"]
            .as_str()
            .unwrap_or("")
            .cmp(b["index"].as_str().unwrap_or(""))
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    Ok(result)
}
async fn patch_scene(
    State(app): State<Arc<App>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Delta>,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let _lock = app.boards.lock.lock().await;
    if body.elements.len() > ELEMENTS
        || serde_json::to_vec(&body.elements).map_or(true, |s| s.len() > SCENE_BYTES)
    {
        return Err(ApiError::bad_request("Drawing update is too large"));
    }
    for _ in 0..8 {
        let row = load_scene(&app, &id).await?;
        if !authorize(&app, &row, &headers).await?.edit {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "This board link is view-only",
            ));
        }
        let old: Vec<Value> = serde_json::from_value(
            serde_json::to_value(row.get_array("elements").cloned().unwrap_or_default()).unwrap(),
        )
        .map_err(|_| ApiError::bad_request("Invalid board scene"))?;
        let elements = merge(old.clone(), body.elements.clone())?;
        let revision = row.get_i64("revision").unwrap_or(0);
        let old_state = row
            .get_document("app_state")
            .ok()
            .and_then(|s| serde_json::to_value(s).ok())
            .unwrap_or_else(|| json!({"viewBackgroundColor":"#ffffff"}));
        let state = if let Some(state) = &body.app_state {
            let color = state["viewBackgroundColor"]
                .as_str()
                .ok_or_else(|| ApiError::bad_request("Invalid canvas background"))?;
            if !(color == "transparent"
                || matches!(color.len(), 4 | 5 | 7 | 9)
                    && color.starts_with('#')
                    && color[1..].bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(ApiError::bad_request("Invalid canvas background"));
            }
            json!({"viewBackgroundColor":color})
        } else {
            old_state.clone()
        };
        let requested: std::collections::HashSet<_> = body
            .elements
            .iter()
            .filter_map(|e| e["id"].as_str())
            .collect();
        let canonical: Vec<_> = elements
            .iter()
            .filter(|e| e["id"].as_str().is_some_and(|id| requested.contains(id)))
            .cloned()
            .collect();
        if elements == old && state == old_state {
            return Ok(Json(
                json!({"revision":revision,"elements":canonical,"appState":state}),
            ));
        }
        let bson = scene_bson(&Value::Array(elements.clone()))?;
        if bson::to_vec(&doc! {"elements":&bson}).map_or(true, |v| v.len() > 12 * 1024 * 1024) {
            return Err(ApiError::bad_request("Board scene exceeds its size limit"));
        }
        let state_bson = scene_bson(&state)?;
        let saved=app.collection(COLLECTION).update_one(doc!{"_id":&id,"revision":revision},doc!{"$set":{"elements":bson,"app_state":state_bson,"updated_at":DateTime::now()},"$inc":{"revision":1_i64}}).await?;
        if saved.modified_count == 1 {
            let previous: HashMap<_, _> = old
                .iter()
                .filter_map(|e| e["id"].as_str().map(|id| (id, e)))
                .collect();
            let changed: Vec<_> = elements
                .iter()
                .filter(|e| {
                    e["id"]
                        .as_str()
                        .is_some_and(|id| previous.get(id).copied() != Some(*e))
                })
                .cloned()
                .collect();
            let event = json!({"revision":revision+1,"elements":changed,"appState":state});
            if serde_json::to_vec(&event).map_or(true, |v| v.len() > 64_000) {
                app.boards
                    .broadcast(&app, &id, "changed", &json!({"revision":revision+1}))
                    .await;
            } else {
                app.boards.broadcast(&app, &id, "scene", &event).await;
            }
            return Ok(Json(
                json!({"revision":revision+1,"elements":canonical,"appState":state}),
            ));
        }
    }
    Err(ApiError::new(
        StatusCode::CONFLICT,
        "Board changed while saving; retry your drawing update",
    ))
}
#[derive(Deserialize)]
struct Asset {
    image: String,
}
async fn upload_asset(
    State(app): State<Arc<App>>,
    Path((id, file)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Asset>,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    if !file_valid(&file) || body.image.len() > crate::hosted_images::MAX_BYTES.div_ceil(3) * 4 {
        return Err(ApiError::bad_request("Invalid board image"));
    }
    let row = load(&app, &id).await?;
    if !authorize(&app, &row, &headers).await?.edit {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "This board link is view-only",
        ));
    }
    let bytes = STANDARD
        .decode(&body.image)
        .map_err(|_| ApiError::bad_request("Invalid image data"))?;
    let (bytes, width, height) =
        tokio::task::spawn_blocking(move || crate::hosted_images::normalize(&bytes))
            .await
            .map_err(|_| ApiError::bad_request("Image processing failed"))??;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let _lock = app.boards.lock.lock().await;
    let _images = app.hosted_images_lock.lock().await;
    let row = load(&app, &id).await?;
    if !authorize(&app, &row, &headers).await?.edit {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "This board link is view-only",
        ));
    }
    indexes(&app).await?;
    if let Some(existing) = app
        .collection(ASSETS)
        .find_one(doc! {"board_id":&id,"file_id":&file})
        .projection(doc! {"data":0})
        .await?
    {
        if existing.get_str("digest").ok() != Some(&digest) {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "An image with this ID already exists",
            ));
        }
        return Ok(Json(json!({"id":file,"mimeType":"image/png"})));
    }
    let assets: Vec<Document> = app
        .collection(ASSETS)
        .find(image_storage::parents(doc! {"board_id":&id}))
        .projection(doc! {"size":1})
        .await?
        .try_collect()
        .await?;
    let used: i64 = assets.iter().map(|r| r.get_i64("size").unwrap_or(0)).sum();
    if assets.len() >= 1000 || used + bytes.len() as i64 > STORAGE {
        return Err(ApiError::bad_request(
            "Board image storage is full (512 MiB)",
        ));
    }
    let size = bytes.len() as i64;
    image_storage::insert(&app,ASSETS,doc!{"_id":uuid::Uuid::new_v4().simple().to_string(),"board_id":&id,"file_id":&file,"owner_id":row.get_object_id("owner_id").map_err(|_|missing())?,"created_at":DateTime::now(),"digest":digest,"size":size,"width":width as i64,"height":height as i64},bytes).await?;
    app.collection(COLLECTION)
        .update_one(doc! {"_id":&id}, doc! {"$set":{"asset_bytes":used+size}})
        .await?;
    Ok(Json(json!({"id":file,"mimeType":"image/png"})))
}
async fn read_asset(
    State(app): State<Arc<App>>,
    Path((id, file)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let _life = app.account_lifecycle.read().await;
    let row = load(&app, &id).await?;
    authorize(&app, &row, &headers).await?;
    if !file_valid(&file) {
        return Err(missing());
    }
    let asset = app
        .collection(ASSETS)
        .find_one(doc! {"board_id":&id,"file_id":&file})
        .await?
        .ok_or_else(missing)?;
    let bytes = image_storage::read(&app, ASSETS, &asset).await?;
    Ok(Json(
        json!({"id":file,"mimeType":"image/png","dataURL":format!("data:image/png;base64,{}",STANDARD.encode(bytes)),"created":asset.get_datetime("created_at").map(|d|d.timestamp_millis()).unwrap_or(0)}),
    ))
}

#[derive(Clone)]
struct Peer {
    board: String,
    headers: HeaderMap,
    name: String,
    pointer: Value,
    seen: Instant,
}
#[derive(Default)]
pub struct Hub {
    initialized: tokio::sync::OnceCell<()>,
    lock: tokio::sync::Mutex<()>,
    peers: Mutex<BTreeMap<String, Peer>>,
}
impl Hub {
    fn peers(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Peer>> {
        self.peers.lock().unwrap_or_else(|e| e.into_inner())
    }
    async fn broadcast(&self, app: &App, id: &str, event: &str, value: &Value) {
        let peers: Vec<_> = self
            .peers()
            .iter()
            .filter(|(_, p)| p.board == id)
            .map(|(s, p)| (s.clone(), p.clone()))
            .collect();
        let row = load(app, id).await;
        for (sid, peer) in peers {
            if let Ok(row) = &row {
                if authorize(app, row, &peer.headers).await.is_ok() {
                    app.realtime.board_emit(&sid, event, value);
                    continue;
                }
            }
            app.realtime.board_disconnect(&sid);
        }
    }
    async fn presence(&self, app: &App, id: &str) {
        let peers: Vec<_> = self
            .peers()
            .iter()
            .filter(|(_, p)| p.board == id)
            .map(|(sid, p)| json!({"id":sid,"name":p.name,"pointer":p.pointer}))
            .collect();
        self.broadcast(app, id, "presence", &json!(peers)).await;
    }
}
#[derive(Deserialize)]
struct Join {
    board: String,
    #[serde(default)]
    share: String,
    #[serde(default)]
    name: String,
}
pub fn install(io: &SocketIo, app: &Arc<App>) {
    let weak = Arc::downgrade(app);
    let connect = weak.clone();
    io.ns(
        "/boards",
        (move |socket: SocketRef| {
            let app = connect.upgrade();
            async move {
                if let Some(app) = app {
                    connected(&app, socket).await;
                }
            }
        })
        .with(move |socket: SocketRef, TryData(data): TryData<Join>| {
            let app = weak.upgrade();
            async move {
                let app = app.ok_or("Board unavailable")?;
                let data = data.map_err(|_| "Invalid board session")?;
                let mut headers = socket.req_parts().headers.clone();
                if !crate::realtime::origin_allowed(&app, &headers) {
                    return Err("Board origin rejected");
                }
                if !data.share.is_empty() {
                    headers.insert(
                        "x-board-share",
                        data.share.parse().map_err(|_| "Invalid sharing link")?,
                    );
                }
                let _life = app.account_lifecycle.read().await;
                let row = load(&app, &data.board)
                    .await
                    .map_err(|_| "Board unavailable")?;
                authorize(&app, &row, &headers)
                    .await
                    .map_err(|_| "Board unavailable or link disabled")?;
                let mut peers = app.boards.peers();
                if peers.len() >= 512 {
                    return Err("Board connections are full");
                }
                peers.insert(
                    socket.id.to_string(),
                    Peer {
                        board: data.board,
                        headers,
                        name: data
                            .name
                            .chars()
                            .filter(|c| !c.is_control())
                            .take(40)
                            .collect::<String>(),
                        pointer: Value::Null,
                        seen: Instant::now(),
                    },
                );
                Ok(())
            }
        }),
    );
}
async fn connected(app: &Arc<App>, socket: SocketRef) {
    let sid = socket.id.to_string();
    if !socket.connected() {
        app.boards.peers().remove(&sid);
        return;
    }
    let Some(peer) = app.boards.peers().get(&sid).cloned() else {
        let _ = socket.disconnect();
        return;
    };
    let weak = Arc::downgrade(app);
    socket.on_disconnect(move |socket: SocketRef| {
        let app = weak.upgrade();
        async move {
            if let Some(app) = app {
                let removed = app.boards.peers().remove(&socket.id.to_string());
                if let Some(peer) = removed {
                    app.boards.presence(&app, &peer.board).await;
                }
            }
        }
    });
    let weak = Arc::downgrade(app);
    socket.on(
        "pointer",
        move |socket: SocketRef, TryData(data): TryData<Value>| {
            let app = weak.upgrade();
            async move {
                let Some(app) = app else { return };
                let Ok(data) = data else { return };
                let peer = {
                    let mut peers = app.boards.peers();
                    let Some(peer) = peers.get_mut(&socket.id.to_string()) else {
                        return;
                    };
                    if peer.seen.elapsed() < Duration::from_millis(75) {
                        return;
                    }
                    peer.seen = Instant::now();
                    peer.pointer = match (data["x"].as_f64(), data["y"].as_f64()) {
                        (Some(x), Some(y)) if x.is_finite() && y.is_finite() => {
                            json!({"x":x,"y":y,"tool":"pointer"})
                        }
                        _ => Value::Null,
                    };
                    peer.clone()
                };
                app.boards.presence(&app, &peer.board).await;
            }
        },
    );
    let _ = socket.emit("ready", &json!({"id":sid}));
    app.boards.presence(app, &peer.board).await;
}
