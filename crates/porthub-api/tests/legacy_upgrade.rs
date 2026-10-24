use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::config::Config;
use tower::ServiceExt;
#[allow(dead_code)]
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn old_update_urls_require_current_machine_credentials_and_keep_secrets_out_of_the_bridge(
) -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let id = ObjectId::new();
        let token = "legacy-upgrade-private-fixture-token";
        case.app
            .collection("machines")
            .insert_one(doc! {"_id":id,"token":token,"user_id":ObjectId::new(),"enabled":true})
            .await?;
        let mut expected = None;
        for suffix in ["downloads/porthub", "client.sh"] {
            let path = format!("/api/machines/{id}/{token}/{suffix}");
            let response = case
                .router
                .clone()
                .oneshot(Request::builder().uri(&path).body(Body::empty())?)
                .await?;
            ensure!(response.status() == StatusCode::OK);
            ensure!(response.headers()["cache-control"] == "no-store");
            ensure!(response.headers()["x-content-type-options"] == "nosniff");
            let body =
                String::from_utf8(to_bytes(response.into_body(), 256 * 1024).await?.to_vec())?;
            ensure!(body.starts_with("#!/usr/bin/env bash\n"));
            ensure!(
                !body.contains(token)
                    && !body.contains(&id.to_hex())
                    && !body.contains("__PORT_HUB_")
            );
            ensure!(
                body.contains("porthub_native_migration_cmd()")
                    && body.contains("PORT_HUB_CLIENT_VERSION=\"legacy-migration\"")
            );
            if let Some(previous) = &expected {
                ensure!(previous == &body);
            }
            expected = Some(body);
            let head = case
                .router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("HEAD")
                        .uri(&path)
                        .body(Body::empty())?,
                )
                .await?;
            ensure!(
                head.status() == StatusCode::OK && to_bytes(head.into_body(), 1).await?.is_empty()
            );
        }
        let path = |credential: &str| format!("/api/machines/{id}/{credential}/downloads/porthub");
        let response = case
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path("wrong-token"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(response.status() == StatusCode::GONE);
        case.app
            .collection("machines")
            .update_one(doc! {"_id":id}, doc! {"$set":{"enabled":false}})
            .await?;
        let response = case
            .router
            .clone()
            .oneshot(Request::builder().uri(path(token)).body(Body::empty())?)
            .await?;
        ensure!(response.status() == StatusCode::FORBIDDEN);
        case.app
            .collection("machines")
            .update_one(
                doc! {"_id":id},
                doc! {"$set":{"enabled":true,"token":"rotated-fixture-token"}},
            )
            .await?;
        let response = case
            .router
            .clone()
            .oneshot(Request::builder().uri(path(token)).body(Body::empty())?)
            .await?;
        ensure!(response.status() == StatusCode::GONE);
        case.app
            .collection("machines")
            .update_one(doc! {"_id":id}, doc! {"$set":{"deletion_pending":true}})
            .await?;
        let response = case
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path("rotated-fixture-token"))
                    .body(Body::empty())?,
            )
            .await?;
        ensure!(response.status() == StatusCode::GONE);
        anyhow::Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}
