//! Account-owned images with short public URLs. Public responses are never
//! cached so deletion takes effect on the next request, including at proxies.
use crate::{
    auth,
    domain::machine_client,
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, spec::BinarySubtype, Binary, Bson, DateTime, Document},
    options::IndexOptions,
    IndexModel,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io::Cursor, sync::Arc};

pub const COLLECTION: &str = "hosted_images";
pub const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_PIXELS: u64 = 32 * 1024 * 1024;
const MAX_IMAGES: usize = 1000;
const MAX_STORAGE: i64 = 512 * 1024 * 1024;
// Case-sensitive; omit 0, 1, I, O, i, l and o to reduce transcription mistakes.
pub(crate) const PUBLIC_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz";
pub(crate) fn short_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..5)
        .map(|_| PUBLIC_ALPHABET[rng.gen_range(0..PUBLIC_ALPHABET.len())] as char)
        .collect()
}

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/images", get(list).post(upload))
        .route("/api/images/{id}", axum::routing::delete(remove))
        .route("/api/images/public/{id}", get(public))
        .route("/i/{filename}", get(short_public))
        .route("/api/machines/client/images", post(upload))
        .layer(DefaultBodyLimit::max(12 * 1024 * 1024))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    image: String,
    request_id: Option<String>,
    #[serde(default)]
    name: String,
    machine_id: Option<String>,
    token: Option<String>,
}
fn invalid() -> ApiError {
    ApiError::bad_request("Use a valid PNG, JPEG, WebP or GIF image, up to 8 MiB and 32 megapixels")
}

// Decode and re-encode to discard metadata, trailing data, and animation. Never
// trust the filename or browser MIME type. Bound both input and decoded memory.
pub(crate) fn normalize(bytes: &[u8]) -> ApiResult<(Vec<u8>, u32, u32)> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    let mut reader = image::ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|_| invalid())?;
    if !matches!(
        reader.format(),
        Some(
            image::ImageFormat::Png
                | image::ImageFormat::Jpeg
                | image::ImageFormat::WebP
                | image::ImageFormat::Gif
        )
    ) {
        return Err(invalid());
    }
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(16384);
    limits.max_image_height = Some(16384);
    limits.max_alloc = Some(MAX_PIXELS * 8);
    reader.limits(limits);
    use image::ImageDecoder;
    let decoder = reader.into_decoder().map_err(|_| invalid())?;
    let (width, height) = decoder.dimensions();
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(invalid());
    }
    // A bounded writer also prevents incompressible images growing past Mongo's
    // document limit while encoding.
    struct Output(Vec<u8>);
    impl std::io::Write for Output {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.0.len() + data.len() > MAX_BYTES {
                return Err(std::io::Error::other("image too large"));
            }
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    use image::ImageEncoder;
    let mut output = Output(Vec::new());
    let rgba = image::DynamicImage::from_decoder(decoder)
        .map_err(|_| invalid())?
        .into_rgba8();
    image::codecs::png::PngEncoder::new(&mut output)
        .write_image(&rgba, width, height, image::ExtendedColorType::Rgba8)
        .map_err(|_| invalid())?;
    Ok((output.0, width, height))
}
fn public_path(row: &Document) -> String {
    match row.get_str("public_id") {
        Ok(id) => format!("/i/{id}.png"),
        Err(_) => format!(
            "/api/images/public/{}",
            row.get_str("_id").unwrap_or_default()
        ),
    }
}
pub(crate) fn metadata(app: &App, row: &Document) -> Value {
    let id = row.get_str("_id").unwrap_or_default();
    json!({"id":id,"name":row.get_str("name").unwrap_or("Image"),"size":row.get_i64("size").unwrap_or(0),
        "width":row.get_i64("width").unwrap_or(0),"height":row.get_i64("height").unwrap_or(0),
        "created_at":row.get_datetime("created_at").map(|d|crate::store::datetime(d.timestamp_millis())).unwrap_or_default(),
        "path":public_path(row),"url":format!("{}{}",app.config.public_base_url.trim_end_matches('/'),public_path(row))})
}
async fn indexes(app: &App) -> ApiResult<()> {
    app.hosted_images_initialized
        .get_or_try_init(|| async {
            app.collection(COLLECTION)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"owner_id":1,"created_at":-1})
                        .build(),
                )
                .await?;
            app.collection(COLLECTION)
                .create_index(
                    IndexModel::builder()
                        .keys(doc! {"public_id":1})
                        .options(IndexOptions::builder().unique(true).sparse(true).build())
                        .build(),
                )
                .await?;
            Ok::<_, ApiError>(())
        })
        .await?;
    Ok(())
}
async fn upload(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(body): Json<Upload>,
) -> ApiResult<Json<Value>> {
    let _lifecycle = app.account_lifecycle.read().await;
    let owner = match (&body.machine_id, &body.token) {
        (Some(id), Some(token)) if !token.is_empty() && token.len() <= 512 => {
            let machine = machine_client::authenticate(&app, id, token).await?;
            machine
                .get_object_id("user_id")
                .map_err(|_| ApiError::bad_request("Machine has no account owner"))?
        }
        (None, None) => auth::current_user(&app, &headers)
            .await?
            .get_object_id("_id")
            .map_err(|_| ApiError::unauthenticated())?,
        _ => return Err(ApiError::unauthenticated()),
    };
    if body.image.len() > MAX_BYTES.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let bytes = STANDARD.decode(&body.image).map_err(|_| invalid())?;
    let (bytes, width, height) = tokio::task::spawn_blocking(move || normalize(&bytes))
        .await
        .map_err(|_| {
            ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "Image processing failed")
        })??;
    indexes(&app).await?;
    // Serialize quota admission and insertion within this API process.
    let _admission = app.hosted_images_lock.lock().await;
    let id = body
        .request_id
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    if !valid_id(&id) {
        return Err(ApiError::bad_request("Invalid upload identity"));
    }
    if let Some(row) = app
        .collection(COLLECTION)
        .find_one(doc! {"_id":&id})
        .projection(doc! {"data":0})
        .await?
    {
        if row.get_object_id("owner_id").ok() == Some(owner) {
            return Ok(Json(metadata(&app, &row)));
        }
        return Err(ApiError::bad_request("Upload identity already used"));
    }
    let rows: Vec<Document> = app
        .collection(COLLECTION)
        .find(doc! {"owner_id":owner})
        .projection(doc! {"size":1})
        .sort(doc! {"created_at":1,"_id":1})
        .limit((MAX_IMAGES + 1) as i64)
        .await?
        .try_collect()
        .await?;
    let used: i64 = rows.iter().map(|r| r.get_i64("size").unwrap_or(0)).sum();
    if rows.len() >= MAX_IMAGES {
        return Err(ApiError::bad_request(
            "Image count limit reached (1,000 images). Delete some images and try again.",
        ));
    }
    // Plan oldest-first eviction, but only delete after the new image is stored.
    // Invalid uploads and failed link allocation must preserve existing images.
    let mut retained = used + bytes.len() as i64;
    let mut expired = Vec::new();
    for previous in &rows {
        if retained <= MAX_STORAGE {
            break;
        }
        retained -= previous.get_i64("size").unwrap_or(0);
        expired.push(previous.get("_id").cloned().unwrap());
    }
    let name: String = body
        .name
        .chars()
        .filter(|c| !c.is_control())
        .take(160)
        .collect();
    let mut row = doc! {"_id":&id,"owner_id":owner,"name":if name.is_empty(){"Clipboard image"}else{&name},"size":bytes.len() as i64,"width":i64::from(width),"height":i64::from(height),"created_at":DateTime::now()};
    row.insert(
        "data",
        Bson::Binary(Binary {
            subtype: BinarySubtype::Generic,
            bytes,
        }),
    );
    // The unique index is the authority even across concurrent API instances.
    // Removing the image removes its index entry, allowing the code to be reused.
    for _ in 0..16 {
        row.insert("public_id", short_id());
        match app.collection(COLLECTION).insert_one(&row).await {
            Ok(_) => {
                if !expired.is_empty() {
                    app.collection(COLLECTION)
                        .delete_many(doc! {"owner_id":owner,"_id":{"$in":&expired}})
                        .await?;
                }
                return Ok(Json(metadata(&app, &row)));
            }
            Err(error) if crate::store::duplicate(&error) => {
                if let Some(existing) = app
                    .collection(COLLECTION)
                    .find_one(doc! {"_id":&id})
                    .projection(doc! {"data":0})
                    .await?
                {
                    if existing.get_object_id("owner_id").ok() == Some(owner) {
                        return Ok(Json(metadata(&app, &existing)));
                    }
                    return Err(ApiError::bad_request("Upload identity already used"));
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err(ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "Could not allocate an image link. Please retry.",
    ))
}
async fn list(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    indexes(&app).await?;
    let rows: Vec<Document> = app
        .collection(COLLECTION)
        .find(doc! {"owner_id":owner})
        .projection(doc! {"data":0})
        .sort(doc! {"created_at":-1,"_id":1})
        .limit(MAX_IMAGES as i64)
        .await?
        .try_collect()
        .await?;
    Ok(Json(
        json!({"images":rows.iter().map(|r|metadata(&app,r)).collect::<Vec<_>>(),"max_bytes":MAX_BYTES,"max_storage":MAX_STORAGE}),
    ))
}
fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
async fn remove(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let _lifecycle = app.account_lifecycle.read().await;
    let user = auth::current_user(&app, &headers).await?;
    let owner = user
        .get_object_id("_id")
        .map_err(|_| ApiError::unauthenticated())?;
    if !valid_id(&id) {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Image not found"));
    }
    let result = app
        .collection(COLLECTION)
        .delete_one(doc! {"_id":id,"owner_id":owner})
        .await?;
    if result.deleted_count == 0 {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "Image not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn short_public(
    State(app): State<Arc<App>>,
    Path(filename): Path<String>,
) -> ApiResult<Response> {
    let id = filename
        .strip_suffix(".png")
        .filter(|id| id.len() == 5 && id.bytes().all(|b| PUBLIC_ALPHABET.contains(&b)))
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, "Image not found")
                .header("cache-control", "no-store")
        })?;
    let row = app
        .collection(COLLECTION)
        .find_one(doc! {"public_id":id})
        .await?
        .ok_or_else(|| {
            ApiError::new(StatusCode::NOT_FOUND, "Image not found")
                .header("cache-control", "no-store")
        })?;
    image_response(row)
}
async fn public(State(app): State<Arc<App>>, Path(id): Path<String>) -> ApiResult<Response> {
    let missing = || {
        ApiError::new(StatusCode::NOT_FOUND, "Image not found").header("cache-control", "no-store")
    };
    if !valid_id(&id) {
        return Err(missing());
    }
    let row = app
        .collection(COLLECTION)
        .find_one(doc! {"_id":id})
        .await?
        .ok_or_else(missing)?;
    image_response(row)
}
pub(crate) fn image_response(row: Document) -> ApiResult<Response> {
    let missing = || ApiError::new(StatusCode::NOT_FOUND, "Image not found");
    let bytes = row
        .get_binary_generic("data")
        .map_err(|_| missing())?
        .clone();
    Ok((
        [
            ("content-type", "image/png"),
            ("content-disposition", "inline"),
            ("cache-control", "no-store"),
            ("x-content-type-options", "nosniff"),
            ("referrer-policy", "no-referrer"),
        ],
        bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn png_upload_preserves_resolution_color_and_transparency() {
        let original = image::RgbaImage::from_fn(37, 19, |x, y| {
            image::Rgba([
                (x * 7) as u8,
                (y * 13) as u8,
                (x ^ y) as u8,
                ((x + y) * 4) as u8,
            ])
        });
        let mut encoded = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(original.clone())
            .write_to(&mut encoded, image::ImageFormat::Png)
            .unwrap();
        let (bytes, width, height) = normalize(encoded.get_ref()).ok().unwrap();
        assert_eq!((width, height), (37, 19));
        assert_eq!(
            image::load_from_memory(&bytes).unwrap().to_rgba8(),
            original
        );
    }
    #[test]
    fn only_decodable_images_are_published_and_metadata_is_discarded() {
        assert!(normalize(b"<svg onload='alert(1)'/>").is_err());
        assert!(normalize(b"\x89PNG\r\n\x1a\ntruncated").is_err());
        let mut bytes = Cursor::new(Vec::new());
        image::DynamicImage::new_rgb8(3, 2)
            .write_to(&mut bytes, image::ImageFormat::Png)
            .unwrap();
        let mut bytes = bytes.into_inner();
        bytes.extend_from_slice(b"private trailing metadata");
        let (out, w, h) = normalize(&bytes).ok().unwrap();
        assert_eq!((w, h), (3, 2));
        assert!(!out.windows(8).any(|b| b == b"private "));
        assert!(image::load_from_memory(&out).is_ok());
    }
}
