use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use mongodb::bson::{doc, DateTime};
use rand::{RngCore, SeedableRng};
use serde_json::{json, Value};
use tower::ServiceExt;
mod support;
use support::Case;

fn large_png() -> Vec<u8> {
    let mut pixels = vec![0; 2048 * 2048 * 4];
    rand::rngs::StdRng::seed_from_u64(381).fill_bytes(&mut pixels);
    let image = image::RgbaImage::from_raw(2048, 2048, pixels).unwrap();
    let mut output = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut output, image::ImageFormat::Png)
        .unwrap();
    ensure_large(output.into_inner())
}
fn ensure_large(bytes: Vec<u8>) -> Vec<u8> {
    assert!(bytes.len() > 16 * 1024 * 1024 && bytes.len() < 50_000_000);
    bytes
}
async fn send(
    case: &Case,
    method: &str,
    path: &str,
    cookie: &str,
    visitor: &str,
    body: Value,
    expected: StatusCode,
) -> Result<Value> {
    let (status, _, value) = case
        .call(method, path, cookie, body, &[("x-image-visitor", visitor)])
        .await?;
    ensure!(
        status == expected,
        "{method} {path}: expected {expected}, got {status}: {value}"
    );
    Ok(value)
}
async fn raw(case: &Case, path: &str) -> Result<(StatusCode, Vec<u8>)> {
    let response = case
        .router
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty())?)
        .await?;
    let status = response.status();
    let bytes = to_bytes(
        response.into_body(),
        porthub_api::hosted_images::MAX_BYTES + 1024,
    )
    .await?;
    Ok((status, bytes.to_vec()))
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn large_personal_images_roundtrip_retry_evict_and_delete_all_chunks() -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("large-images@example.invalid", "user").await?;
        let payload = json!({"image":STANDARD.encode(large_png()),"name":"Large screenshot.png","request_id":uuid::Uuid::new_v4().simple().to_string()});
        let row = case.status("POST", "/api/images", &cookie, payload.clone(), StatusCode::OK).await?;
        let id = row["id"].as_str().unwrap();
        let stored = case.app.collection("hosted_images").find_one(doc!{"_id":id}).await?.unwrap();
        let blob = stored.get_str("blob_id")?;
        ensure!(!stored.contains_key("data") && stored.get_i64("parts")? > 1);
        let parts = case.app.collection("hosted_images").count_documents(doc!{"image_chunk":true,"blob_id":blob}).await?;
        ensure!(parts == stored.get_i64("parts")? as u64);
        let (status, bytes) = raw(&case, row["path"].as_str().unwrap()).await?;
        ensure!(status == StatusCode::OK && bytes.len() as u64 == row["size"].as_u64().unwrap());
        ensure!(image::load_from_memory(&bytes)?.width() == 2048);
        let retry = case.status("POST", "/api/images", &cookie, payload.clone(), StatusCode::OK).await?;
        ensure!(retry["id"] == row["id"]);
        ensure!(case.app.collection("hosted_images").count_documents(doc!{"image_chunk":true,"blob_id":blob}).await? == parts);
        let list = case.status("GET", "/api/images", &cookie, Value::Null, StatusCode::OK).await?;
        ensure!(list["images"].as_array().unwrap().len() == 1 && list["max_bytes"] == 50_000_000);
        ensure!(!list.to_string().contains("blob_id") && !list.to_string().contains("image_chunk"));
        // Storage admission must evict both the old parent and its data parts.
        case.app.collection("hosted_images").update_one(doc!{"_id":id}, doc!{"$set":{"size":512_i64*1024*1024}}).await?;
        let small = { let mut out=std::io::Cursor::new(Vec::new());image::DynamicImage::new_rgb8(2,2).write_to(&mut out,image::ImageFormat::Png)?;out.into_inner() };
        case.status("POST", "/api/images", &cookie, json!({"image":STANDARD.encode(small)}), StatusCode::OK).await?;
        ensure!(case.app.collection("hosted_images").count_documents(doc!{"blob_id":blob}).await? == 0);
        ensure!(raw(&case, row["path"].as_str().unwrap()).await?.0 == StatusCode::NOT_FOUND);
        let next = case.status("POST", "/api/images", &cookie, payload, StatusCode::OK).await?;
        let selected = case.status("DELETE", "/api/images", &cookie, json!({"ids":[next["id"]]}), StatusCode::OK).await?;
        ensure!(selected["deleted_count"] == 1);
        ensure!(case.app.collection("hosted_images").count_documents(doc!{"image_chunk":true}).await? == 0);
        // Account cleanup uses the same collection and therefore includes chunks.
        let final_image = case.status("POST", "/api/images", &cookie, json!({"image":STANDARD.encode(large_png())}), StatusCode::OK).await?;
        { let _lifecycle=case.app.account_lifecycle.write().await;porthub_api::account_delete::delete_locked(&case.app,owner).await.map_err(|e|anyhow::anyhow!("{}",e.detail))?; }
        ensure!(case.app.collection("hosted_images").count_documents(doc!{"owner_id":owner}).await? == 0);
        ensure!(raw(&case, final_image["path"].as_str().unwrap()).await?.0 == StatusCode::NOT_FOUND);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn large_room_images_keep_ownership_counts_expiry_and_deletion() -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result = async {
        let (_, cookie) = case.user("large-room@example.invalid", "user").await?;
        let room = case.status("POST", "/api/image-rooms", &cookie, json!({"name":"Large images"}), StatusCode::OK).await?;
        let id = room["id"].as_str().unwrap();
        let endpoint = format!("/api/image-rooms/public/{id}/images");
        let visitor = "a".repeat(64);
        let other = "b".repeat(64);
        let payload = json!({"image":STANDARD.encode(large_png())});
        let row = send(&case,"POST",&endpoint,"",&visitor,payload.clone(),StatusCode::OK).await?;
        let stored = case.app.collection("image_room_images").find_one(doc!{"_id":row["id"].as_str().unwrap()}).await?.unwrap();
        let blob = stored.get_str("blob_id")?;
        let chunks = case.app.collection("image_room_images").count_documents(doc!{"image_chunk":true,"blob_id":blob,"expires_at":stored.get("expires_at").cloned().unwrap()}).await?;
        ensure!(chunks == stored.get_i64("parts")? as u64);
        let (status, bytes) = raw(&case,row["path"].as_str().unwrap()).await?;
        ensure!(status == StatusCode::OK && image::load_from_memory(&bytes)?.height() == 2048);
        let listed = send(&case,"GET",&endpoint,"",&visitor,Value::Null,StatusCode::OK).await?;
        ensure!(listed["images"].as_array().unwrap().len() == 1);
        let rooms = case.status("GET","/api/image-rooms",&cookie,Value::Null,StatusCode::OK).await?;
        ensure!(rooms["rooms"][0]["image_count"] == 1 && rooms["rooms"][0]["used"] == row["size"]);
        send(&case,"DELETE",&format!("{endpoint}/{}",row["id"].as_str().unwrap()),"",&other,Value::Null,StatusCode::NOT_FOUND).await?;
        ensure!(case.app.collection("image_room_images").count_documents(doc!{"blob_id":blob}).await? > 1);
        let deleted = send(&case,"DELETE",&endpoint,"",&visitor,json!({"all":true}),StatusCode::OK).await?;
        ensure!(deleted["deleted_count"] == 1 && case.app.collection("image_room_images").count_documents(doc!{"blob_id":blob}).await? == 0);
        // Exact expiry applies to the parent and every stored chunk.
        let expired = send(&case,"POST",&endpoint,"",&visitor,payload.clone(),StatusCode::OK).await?;
        let expired_id = expired["id"].as_str().unwrap();
        case.app.collection("image_room_images").update_many(doc!{"$or":[{"_id":expired_id},{"image_id":expired_id}]},doc!{"$set":{"expires_at":DateTime::from_millis(0)}}).await?;
        ensure!(raw(&case,expired["path"].as_str().unwrap()).await?.0 == StatusCode::NOT_FOUND);
        send(&case,"POST",&endpoint,"",&visitor,payload,StatusCode::OK).await?;
        ensure!(case.app.collection("image_room_images").count_documents(doc!{"$or":[{"_id":expired_id},{"image_id":expired_id}]}).await? == 0);
        case.status("DELETE",&format!("/api/image-rooms/{id}"),&cookie,Value::Null,StatusCode::NO_CONTENT).await?;
        ensure!(case.app.collection("image_room_images").count_documents(doc!{"room_id":id}).await? == 0);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn fifty_mb_input_boundary_and_orphan_cleanup_preserve_live_images() -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let result = async {
        let (_, cookie) = case.user("image-boundary@example.invalid", "user").await?;
        let mut png = large_png();
        // Trailing bytes are intentionally discarded by normalization. This is
        // a valid PNG file whose input size exercises exactly 50 decimal MB.
        png.resize(50_000_000, 0);
        let row = case
            .status(
                "POST",
                "/api/images",
                &cookie,
                json!({"image":STANDARD.encode(&png)}),
                StatusCode::OK,
            )
            .await?;
        png.push(0);
        case.status(
            "POST",
            "/api/images",
            &cookie,
            json!({"image":STANDARD.encode(&png)}),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let id = row["id"].as_str().unwrap();
        let mut chunk = case
            .app
            .collection("hosted_images")
            .find_one(doc! {"image_chunk":true,"image_id":id})
            .await?
            .unwrap();
        let live = chunk.get_str("blob_id")?.to_owned();
        case.app
            .collection("hosted_images")
            .update_many(
                doc! {"image_chunk":true,"blob_id":&live},
                doc! {"$set":{"created_at":DateTime::from_millis(0)}},
            )
            .await?;
        let orphan = uuid::Uuid::new_v4().simple().to_string();
        chunk.insert("_id", format!("{orphan}:0"));
        chunk.insert("public_id", format!("~{orphan}:0"));
        chunk.insert("blob_id", &orphan);
        chunk.insert("image_id", uuid::Uuid::new_v4().simple().to_string());
        chunk.insert("created_at", DateTime::from_millis(0));
        case.app
            .collection("hosted_images")
            .insert_one(chunk)
            .await?;
        porthub_api::image_storage::cleanup_orphans(&case.app)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        ensure!(
            case.app
                .collection("hosted_images")
                .count_documents(doc! {"blob_id":orphan})
                .await?
                == 0
        );
        ensure!(
            case.app
                .collection("hosted_images")
                .count_documents(doc! {"image_chunk":true,"blob_id":live})
                .await?
                > 1
        );
        let listed = case
            .status("GET", "/api/images", &cookie, Value::Null, StatusCode::OK)
            .await?;
        ensure!(listed["images"].as_array().unwrap().len() == 1);
        case.app
            .collection("hosted_images")
            .delete_one(doc! {"image_chunk":true,"image_id":id,"part":0_i64})
            .await?;
        ensure!(
            raw(&case, row["path"].as_str().unwrap()).await?.0 == StatusCode::NOT_FOUND,
            "Missing parts must never produce a truncated public image"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}
