use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use futures_util::TryStreamExt;
use base64::{engine::general_purpose::STANDARD, Engine};
use mongodb::bson::{doc, DateTime};
use serde_json::{json, Value};
use tower::ServiceExt;
mod support;
use support::Case;
fn png() -> Vec<u8> {
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::new_rgb8(4, 3)
        .write_to(&mut out, image::ImageFormat::Png)
        .unwrap();
    out.into_inner()
}
async fn request(
    case: &Case,
    method: &str,
    path: &str,
    cookie: &str,
    visitor: &str,
    body: Value,
    expected: StatusCode,
) -> Result<Value> {
    let response = case
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .header("x-image-visitor", visitor)
                .body(Body::from(body.to_string()))?,
        )
        .await?;
    let status = response.status();
    let raw = response
        .headers()
        .get("content-type")
        .is_some_and(|h| h == "image/png");
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    ensure!(
        status == expected,
        "{method} {path}: expected {expected}, got {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(if bytes.is_empty() || raw {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    })
}
#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn rooms_are_public_independent_expiring_and_browser_deletions_are_authorized() -> Result<()>
{
    let case = Case::new(porthub_api::config::Config {
        public_base_url: "https://images.example.invalid".into(),
        ..Default::default()
    })
    .await?;
    let result = async {
        let (owner, cookie) = case.user("room-owner@example.invalid", "user").await?;
        let (_, outsider) = case.user("room-outsider@example.invalid", "user").await?;
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let upload = json!({"image":STANDARD.encode(png()),"name":"Screenshot.png"});
        let room = request(
            &case,
            "POST",
            "/api/image-rooms",
            &cookie,
            "",
            json!({"name":"Quick drop"}),
            StatusCode::OK,
        )
        .await?;
        ensure!(
            room["enabled"] == true
                && room["image_ttl_seconds"] == 3600
                && room["max_storage"] == 512_i64 * 1024 * 1024
        );
        let ttl_indexes:Vec<_>=case.app.collection("image_room_images").list_indexes().await?.try_collect().await?;
        ensure!(ttl_indexes.iter().any(|i|i.keys.get_i32("expires_at")==Ok(1) && i.options.as_ref().and_then(|o|o.expire_after)==Some(std::time::Duration::ZERO)));
        let id = room["id"].as_str().unwrap();
        let base = format!("/api/image-rooms/{id}");
        let public = format!("/api/image-rooms/public/{id}/images");
        // A room remains live regardless of its creation time.
        case.app
            .collection("image_rooms")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"created_at":DateTime::from_millis(1)}},
            )
            .await?;
        request(
            &case,
            "POST",
            "/api/image-rooms",
            "",
            "",
            json!({}),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        request(
            &case,
            "PATCH",
            &base,
            &outsider,
            "",
            json!({"enabled":false}),
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "POST",
            &public,
            "",
            "guessable",
            upload.clone(),
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let first = request(
            &case,
            "POST",
            &public,
            "",
            &a,
            upload.clone(),
            StatusCode::OK,
        )
        .await?;
        ensure!(
            first["can_delete"] == true
                && first["url"]
                    .as_str()
                    .unwrap()
                    .starts_with("https://images.example.invalid/r/")
        );
        let expiry = chrono::DateTime::parse_from_rfc3339(first["expires_at"].as_str().unwrap())?
            .timestamp_millis();
        ensure!((expiry - DateTime::now().timestamp_millis() - 3_600_000).abs() < 5000);
        request(
            &case,
            "GET",
            first["path"].as_str().unwrap(),
            "",
            "",
            Value::Null,
            StatusCode::OK,
        )
        .await?;
        let listed = request(&case, "GET", &public, "", &b, Value::Null, StatusCode::OK).await?;
        ensure!(
            listed["images"][0]["can_delete"] == false
                && !listed.to_string().contains("visitor_hash")
                && !listed.to_string().contains(&a)
        );
        let image = first["id"].as_str().unwrap();
        let deletion = format!("{public}/{image}");
        request(
            &case,
            "DELETE",
            &deletion,
            "",
            &b,
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "DELETE",
            &deletion,
            "",
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "DELETE",
            &format!("{base}/images/{image}"),
            &outsider,
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        let inspection = request(
            &case,
            "GET",
            &format!("{base}/images"),
            &cookie,
            "",
            Value::Null,
            StatusCode::OK,
        )
        .await?;
        ensure!(inspection["images"][0]["can_delete"] == true);
        // Changing a room's lifetime applies to future uploads, not earlier ones.
        request(
            &case,
            "PATCH",
            &base,
            &cookie,
            "",
            json!({"image_ttl_seconds":120}),
            StatusCode::OK,
        )
        .await?;
        let second = request(
            &case,
            "POST",
            &public,
            "",
            &b,
            upload.clone(),
            StatusCode::OK,
        )
        .await?;
        let second_expiry =
            chrono::DateTime::parse_from_rfc3339(second["expires_at"].as_str().unwrap())?
                .timestamp_millis();
        ensure!((second_expiry - DateTime::now().timestamp_millis() - 120_000).abs() < 5000);
        let original = case
            .app
            .collection("image_room_images")
            .find_one(doc! {"_id":image})
            .await?
            .unwrap();
        ensure!(original.get_datetime("expires_at")?.timestamp_millis() == expiry);
        // Independent storage cannot evict personal images or another room's images.
        case.app
            .collection("hosted_images")
            .insert_one(doc! {"_id":"personal-quota","owner_id":owner,"size":512_i64*1024*1024})
            .await?;
        let other = request(
            &case,
            "POST",
            "/api/image-rooms",
            &cookie,
            "",
            json!({"name":"Other room"}),
            StatusCode::OK,
        )
        .await?;
        let mut old = original.clone();
        old.insert("_id", "old-room-image");
        old.insert("public_id", "ZYx98");
        old.insert("size", 512_i64 * 1024 * 1024);
        old.insert("created_at", DateTime::from_millis(1));
        case.app
            .collection("image_room_images")
            .insert_one(&old)
            .await?;
        old.insert("_id", "other-room-image");
        old.insert("public_id", "Vwx67");
        old.insert("room_id", other["id"].as_str().unwrap());
        case.app
            .collection("image_room_images")
            .insert_one(&old)
            .await?;
        request(&case,"POST",&public,"",&a,json!({"image":STANDARD.encode(b"invalid")}),StatusCode::BAD_REQUEST).await?;
        ensure!(case.app.collection("image_room_images").find_one(doc!{"_id":"old-room-image"}).await?.is_some());
        request(
            &case,
            "POST",
            &public,
            "",
            &a,
            upload.clone(),
            StatusCode::OK,
        )
        .await?;
        ensure!(case
            .app
            .collection("image_room_images")
            .find_one(doc! {"_id":"old-room-image"})
            .await?
            .is_none());
        ensure!(case
            .app
            .collection("image_room_images")
            .find_one(doc! {"_id":"other-room-image"})
            .await?
            .is_some());
        ensure!(case
            .app
            .collection("hosted_images")
            .find_one(doc! {"_id":"personal-quota"})
            .await?
            .is_some());
        let rooms=request(&case,"GET","/api/image-rooms",&cookie,"",Value::Null,StatusCode::OK).await?;
        let stats=rooms["rooms"].as_array().unwrap();
        ensure!(stats.len()==2 && stats.iter().find(|r|r["id"]==id).unwrap()["image_count"]==3);
        ensure!(stats.iter().find(|r|r["id"]==other["id"]).unwrap()["used"]==512_i64*1024*1024);
        let hidden=request(&case,"GET","/api/image-rooms",&outsider,"",Value::Null,StatusCode::OK).await?;
        ensure!(hidden["rooms"].as_array().unwrap().is_empty());
        let personal = request(
            &case,
            "GET",
            "/api/images",
            &cookie,
            "",
            Value::Null,
            StatusCode::OK,
        )
        .await?;
        ensure!(personal["images"].as_array().unwrap().len() == 1);
        // Disabled rooms pause admission, but uploaders can still remove their images.
        request(
            &case,
            "PATCH",
            &base,
            &cookie,
            "",
            json!({"enabled":false}),
            StatusCode::OK,
        )
        .await?;
        request(
            &case,
            "POST",
            &public,
            "",
            &a,
            upload.clone(),
            StatusCode::FORBIDDEN,
        )
        .await?;
        request(
            &case,
            "DELETE",
            &deletion,
            "",
            &a,
            Value::Null,
            StatusCode::NO_CONTENT,
        )
        .await?;
        request(
            &case,
            "GET",
            first["path"].as_str().unwrap(),
            "",
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "PATCH",
            &base,
            &cookie,
            "",
            json!({"enabled":true}),
            StatusCode::OK,
        )
        .await?;
        // Expiry is enforced immediately even before MongoDB's TTL sweep.
        case.app
            .collection("image_room_images")
            .update_one(
                doc! {"_id":second["id"].as_str().unwrap()},
                doc! {"$set":{"expires_at":DateTime::from_millis(1)}},
            )
            .await?;
        request(
            &case,
            "GET",
            second["path"].as_str().unwrap(),
            "",
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        let after = request(&case, "GET", &public, "", &b, Value::Null, StatusCode::OK).await?;
        ensure!(!after["images"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == second["id"]));
        let live = after["images"][0]["id"].as_str().unwrap();
        request(
            &case,
            "DELETE",
            &format!("{base}/images/{live}"),
            &cookie,
            "",
            Value::Null,
            StatusCode::NO_CONTENT,
        )
        .await?;
        request(
            &case,
            "DELETE",
            &base,
            &outsider,
            "",
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request(
            &case,
            "DELETE",
            &base,
            &cookie,
            "",
            Value::Null,
            StatusCode::NO_CONTENT,
        )
        .await?;
        request(
            &case,
            "GET",
            &public,
            "",
            &a,
            Value::Null,
            StatusCode::NOT_FOUND,
        )
        .await?;
        ensure!(
            case.app
                .collection("image_room_images")
                .count_documents(doc! {"room_id":id})
                .await?
                == 0
        );
        // Account deletion removes its rooms and their separately stored binaries.
        {
            let _lifecycle = case.app.account_lifecycle.write().await;
            porthub_api::account_delete::delete_locked(&case.app, owner)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.detail))?;
        }
        ensure!(
            case.app
                .collection("image_rooms")
                .count_documents(doc! {"owner_id":owner})
                .await?
                == 0
        );
        ensure!(
            case.app
                .collection("image_room_images")
                .count_documents(doc! {"owner_id":owner})
                .await?
                == 0
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore="requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn bulk_room_deletion_preserves_other_visitors_and_other_rooms()->Result<()> {
    let case=Case::new(Default::default()).await?;
    let result=async {
        let (_,owner)=case.user("room-bulk-owner@example.invalid","user").await?;
        let (_,outsider)=case.user("room-bulk-outsider@example.invalid","user").await?;
        let a="a".repeat(64);let b="b".repeat(64);let payload=json!({"image":STANDARD.encode(png())});
        let room=request(&case,"POST","/api/image-rooms",&owner,"",json!({}),StatusCode::OK).await?;
        let other=request(&case,"POST","/api/image-rooms",&owner,"",json!({}),StatusCode::OK).await?;
        let public=format!("/api/image-rooms/public/{}/images",room["id"].as_str().unwrap());
        let elsewhere=format!("/api/image-rooms/public/{}/images",other["id"].as_str().unwrap());
        let own=request(&case,"POST",&public,"",&a,payload.clone(),StatusCode::OK).await?;
        request(&case,"POST",&public,"",&a,payload.clone(),StatusCode::OK).await?;
        let foreign=request(&case,"POST",&public,"",&b,payload.clone(),StatusCode::OK).await?;
        let distant=request(&case,"POST",&elsewhere,"",&a,payload.clone(),StatusCode::OK).await?;
        let selected=request(&case,"DELETE",&public,"",&a,json!({"ids":[own["id"],foreign["id"],distant["id"]]}),StatusCode::OK).await?;
        ensure!(selected["deleted_count"]==1);
        let all=request(&case,"DELETE",&public,"",&a,json!({"all":true}),StatusCode::OK).await?;
        ensure!(all["deleted_count"]==1);
        let retained=request(&case,"GET",&public,"",&b,Value::Null,StatusCode::OK).await?;
        ensure!(retained["images"].as_array().unwrap().len()==1 && retained["images"][0]["id"]==foreign["id"]);
        let second=request(&case,"GET",&elsewhere,"",&a,Value::Null,StatusCode::OK).await?;
        ensure!(second["images"].as_array().unwrap().len()==1);
        let owner_path=format!("/api/image-rooms/{}/images",room["id"].as_str().unwrap());
        request(&case,"DELETE",&owner_path,&outsider,"",json!({"all":true}),StatusCode::NOT_FOUND).await?;
        let cleared=request(&case,"DELETE",&owner_path,&owner,"",json!({"all":true}),StatusCode::OK).await?;
        ensure!(cleared["deleted_count"]==1);
        let empty=request(&case,"GET",&public,"",&a,Value::Null,StatusCode::OK).await?;
        ensure!(empty["images"].as_array().unwrap().is_empty() && empty["room"]["enabled"]==true);
        request(&case,"POST",&public,"",&a,payload,StatusCode::OK).await?;
        let second=request(&case,"GET",&elsewhere,"",&a,Value::Null,StatusCode::OK).await?;
        ensure!(second["images"].as_array().unwrap().len()==1);
        Ok::<_,anyhow::Error>(())
    }.await;
    case.db.drop().await?;result
}
