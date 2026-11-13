//! Small images remain inline. Larger images use bounded MongoDB documents in
//! the same collection, preserving account deletion and room TTL cleanup.
use crate::{
    error::{ApiError, ApiResult},
    App,
};
use axum::http::StatusCode;
use futures_util::TryStreamExt;
use mongodb::{
    bson::{doc, spec::BinarySubtype, Binary, Bson, DateTime, Document},
    IndexModel,
};
use std::{sync::Arc, time::Duration};

const INLINE: usize = 8 * 1024 * 1024;
const CHUNK: usize = 4 * 1024 * 1024;
fn missing() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "Image not found").header("cache-control", "no-store")
}
pub fn parents(mut filter: Document) -> Document {
    filter.insert("image_chunk", doc! {"$ne":true});
    filter
}
pub struct Stored {
    pub row: Document,
    pub inserted: bool,
}
async fn discard(app: &App, collection: &str, blob: Option<&str>) {
    if let Some(blob) = blob {
        // A failed cleanup is safe to retry in orphan maintenance. Never remove
        // a parent before its image is stored successfully.
        let _ = app
            .collection(collection)
            .delete_many(doc! {"image_chunk":true,"blob_id":blob})
            .await;
    }
}
pub async fn insert(
    app: &App,
    collection: &str,
    mut row: Document,
    bytes: Vec<u8>,
) -> ApiResult<Stored> {
    let owner = row.get("owner_id").cloned().ok_or_else(missing)?;
    let image = row.get_str("_id").map_err(|_| missing())?.to_owned();
    let blob = if bytes.len() > INLINE {
        let mut indexes = vec![
            IndexModel::builder()
                .keys(doc! {"blob_id":1,"part":1})
                .build(),
            IndexModel::builder()
                .keys(doc! {"image_chunk":1,"created_at":1,"blob_id":1,"image_id":1})
                .build(),
            IndexModel::builder()
                .keys(doc! {"owner_id":1,"image_chunk":1,"created_at":1,"_id":1,"size":1})
                .build(),
        ];
        if collection == crate::image_rooms::IMAGES {
            indexes.push(
                IndexModel::builder()
                    .keys(doc! {"room_id":1,"image_chunk":1,"created_at":1,"_id":1,"size":1})
                    .build(),
            );
            indexes.push(
                IndexModel::builder()
                    .keys(doc! {"owner_id":1,"image_chunk":1,"expires_at":1,"room_id":1,"size":1})
                    .build(),
            );
        }
        app.collection(collection).create_indexes(indexes).await?;
        let blob = uuid::Uuid::new_v4().simple().to_string();
        let mut written = false;
        for (part, data) in bytes.chunks(CHUNK).enumerate() {
            let key = format!("{blob}:{part}");
            // Room public-ID indexes predate chunking and are non-sparse.
            // Reserve an impossible public-link namespace rather than dropping
            // or weakening those live uniqueness indexes.
            let mut chunk = doc! {"_id":&key,"public_id":format!("~{key}"),"image_chunk":true,
            "image_id":&image,"blob_id":&blob,"part":part as i64,"created_at":DateTime::now(),
            "owner_id":owner.clone(),"data":Bson::Binary(Binary{subtype:BinarySubtype::Generic,bytes:data.to_vec()})};
            for field in ["room_id", "expires_at"] {
                if let Some(value) = row.get(field) {
                    chunk.insert(field, value.clone());
                }
            }
            if let Err(error) = app.collection(collection).insert_one(chunk).await {
                // A collision on the first chunk never grants ownership of an
                // existing blob. Ambiguous writes are left for orphan cleanup.
                if written {
                    discard(app, collection, Some(&blob)).await;
                }
                return Err(error.into());
            }
            written = true;
        }
        row.insert("blob_id", &blob);
        row.insert("parts", bytes.len().div_ceil(CHUNK) as i64);
        drop(bytes);
        Some(blob)
    } else {
        row.insert(
            "data",
            Bson::Binary(Binary {
                subtype: BinarySubtype::Generic,
                bytes,
            }),
        );
        None
    };
    for _ in 0..16 {
        row.insert("public_id", crate::hosted_images::short_id());
        match app.collection(collection).insert_one(&row).await {
            Ok(_) => {
                return Ok(Stored {
                    row,
                    inserted: true,
                })
            }
            Err(error) if crate::store::duplicate(&error) => {
                let existing = app
                    .collection(collection)
                    .find_one(parents(doc! {"_id":&image}))
                    .projection(doc! {"data":0})
                    .await?;
                if let Some(existing) = existing {
                    if existing.get_str("blob_id").ok() != blob.as_deref() {
                        discard(app, collection, blob.as_deref()).await;
                    }
                    if existing.get("owner_id") == Some(&owner) {
                        return Ok(Stored {
                            row: existing,
                            inserted: false,
                        });
                    }
                    return Err(ApiError::bad_request("Upload identity already used"));
                }
            }
            Err(error) => {
                // The server may have accepted an ambiguous insert. Preserve
                // any referenced blob; orphan maintenance checks parent links.
                if let Ok(None) = app
                    .collection(collection)
                    .find_one(doc! {"_id":&image,"blob_id":blob.as_deref().unwrap_or("")})
                    .await
                {
                    discard(app, collection, blob.as_deref()).await;
                }
                return Err(error.into());
            }
        }
    }
    discard(app, collection, blob.as_deref()).await;
    Err(ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "Could not allocate an image URL; try again",
    ))
}
pub async fn read(app: &App, collection: &str, row: &Document) -> ApiResult<Vec<u8>> {
    if let Ok(bytes) = row.get_binary_generic("data") {
        return Ok(bytes.clone());
    }
    let size =
        usize::try_from(row.get_i64("size").map_err(|_| missing())?).map_err(|_| missing())?;
    if size == 0 || size > crate::hosted_images::MAX_BYTES {
        return Err(missing());
    }
    let blob = row.get_str("blob_id").map_err(|_| missing())?;
    let parts = size.div_ceil(CHUNK);
    if row.get_i64("parts").ok() != Some(parts as i64) {
        return Err(missing());
    }
    let mut cursor = app.collection(collection).find(doc!{"image_chunk":true,"blob_id":blob,
        "image_id":row.get_str("_id").map_err(|_|missing())?,"owner_id":row.get("owner_id").cloned().ok_or_else(missing)?})
        .projection(doc!{"data":1,"part":1}).sort(doc!{"part":1}).limit(parts as i64 + 1).await?;
    let mut bytes = Vec::with_capacity(size);
    let mut count = 0;
    while let Some(chunk) = cursor.try_next().await? {
        let data = chunk.get_binary_generic("data").map_err(|_| missing())?;
        if count >= parts
            || chunk.get_i64("part").ok() != Some(count as i64)
            || data.len() != CHUNK.min(size - bytes.len())
        {
            return Err(missing());
        }
        bytes.extend_from_slice(data);
        count += 1;
    }
    if count != parts || bytes.len() != size {
        return Err(missing());
    }
    Ok(bytes)
}
pub async fn remove(app: &App, collection: &str, filter: Document) -> ApiResult<u64> {
    if filter.is_empty() {
        return Err(ApiError::bad_request("Image deletion requires a scope"));
    }
    let filter = parents(filter);
    let rows: Vec<Document> = app
        .collection(collection)
        .find(filter.clone())
        .projection(doc! {"blob_id":1})
        .await?
        .try_collect()
        .await?;
    let result = app.collection(collection).delete_many(filter).await?;
    let blobs: Vec<&str> = rows
        .iter()
        .filter_map(|row| row.get_str("blob_id").ok())
        .collect();
    if !blobs.is_empty() {
        let _ = app
            .collection(collection)
            .delete_many(doc! {"image_chunk":true,"blob_id":{"$in":blobs}})
            .await;
    }
    Ok(result.deleted_count)
}
pub async fn cleanup_orphans(app: &App) -> ApiResult<()> {
    let cutoff = DateTime::from_millis(DateTime::now().timestamp_millis() - 3_600_000);
    for collection in [crate::hosted_images::COLLECTION, crate::image_rooms::IMAGES, crate::boards::ASSETS] {
        let mut groups = app
            .collection(collection)
            .aggregate([
                doc! {"$match":{"image_chunk":true,"created_at":{"$lt":cutoff}}},
                doc! {"$project":{"_id":0,"blob_id":1,"image_id":1}},
                doc! {"$group":{"_id":"$blob_id","image_id":{"$first":"$image_id"}}},
            ])
            .await?;
        while let Some(group) = groups.try_next().await? {
            let (Ok(blob), Ok(image)) = (group.get_str("_id"), group.get_str("image_id")) else {
                continue;
            };
            // A suspended upload may resume with old chunk timestamps. Wait for
            // its admission lock before deciding that its blob is unreferenced.
            let _lifecycle = app.account_lifecycle.read().await;
            let _admission = app.hosted_images_lock.lock().await;
            if app
                .collection(collection)
                .find_one(parents(doc! {"_id":image,"blob_id":blob}))
                .projection(doc! {"_id":1})
                .await?
                .is_none()
            {
                discard(app, collection, Some(blob)).await;
            }
        }
    }
    Ok(())
}
pub async fn maintenance(app: Arc<App>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut timer = tokio::time::interval(Duration::from_secs(600));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { _ = stop.changed() => return, _ = timer.tick() => {} }
        tokio::select! {
            _ = stop.changed() => return,
            result = cleanup_orphans(&app) => if let Err(error) = result { tracing::warn!(detail=%error.detail,"image chunk cleanup deferred"); }
        }
    }
}
