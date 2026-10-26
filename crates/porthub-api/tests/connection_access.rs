use anyhow::{ensure, Result};
use axum::http::StatusCode;
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::inventory, generated};
use serde_json::json;
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn access_locks_are_owned_redacted_and_rendered_on_the_direct_listener() -> Result<()> {
    let case = Case::new(Config::default()).await?;
    let result = async {
        let (owner, cookie) = case.user("access@example.invalid", "user").await?;
        let (_, outsider) = case.user("outsider@example.invalid", "user").await?;
        let machine = doc! {"_id":ObjectId::new(),"user_id":owner,"token":"test-machine-token"};
        let connection = doc! {"_id":ObjectId::new(),"user_id":owner,"machine_id":machine.get("_id"),"external_port":31000_i64};
        case.app.collection("machines").insert_one(&machine).await?;
        case.app.collection("connections").insert_one(&connection).await?;
        let path = format!("/api/connections/access/{}", connection.get_object_id("_id")?);
        case.status("PUT", &path, &outsider, json!({"mode":"pin","secret":"123456"}), StatusCode::NOT_FOUND).await?;
        case.status("PUT", &path, &cookie, json!({"mode":"pin","secret":"123"}), StatusCode::BAD_REQUEST).await?;
        case.status("PUT", &path, &cookie, json!({"mode":"pin"}), StatusCode::BAD_REQUEST).await?;
        case.status("PUT", &path, &cookie, json!({"mode":"pin","secret":"123456"}), StatusCode::OK).await?;
        let saved = case.app.collection("connections").find_one(doc! {"_id":connection.get("_id")}).await?.unwrap();
        let verifier = saved.get_document("public_access")?.get_str("verifier")?;
        ensure!(bcrypt::verify("123456", verifier)?);
        let public = inventory::connection(&case.app, &saved, Some(&machine));
        ensure!(public["public_access"]["mode"] == "pin");
        ensure!(!public.to_string().contains(verifier) && !public.to_string().contains("123456"));
        let rendered = generated::render(&[machine.clone()], &[saved])?;
        let config = porthub_tunnel::gateway_config(&rendered)?;
        ensure!(config.server.unwrap().services.values().next().unwrap().access.is_some());
        case.status("PUT", &path, &cookie, json!({"mode":"pin"}), StatusCode::OK).await?;
        case.status("PUT", &path, &cookie, json!({"mode":"key"}), StatusCode::BAD_REQUEST).await?;
        case.status("PUT", &path, &cookie, json!({"mode":"key","secret":"new-api-key-for-test"}), StatusCode::OK).await?;
        case.status("PUT", &path, &cookie, json!({"mode":"off"}), StatusCode::OK).await?;
        let saved = case.app.collection("connections").find_one(doc! {"_id":connection.get("_id")}).await?.unwrap();
        ensure!(!saved.contains_key("public_access"));
        case.app.collection("connections").update_one(doc! {"_id":connection.get("_id")},doc! {"$set":{"temporary":true}}).await?;
        case.status("PUT", &path, &cookie, json!({"mode":"off"}), StatusCode::BAD_REQUEST).await?;
        Ok::<_, anyhow::Error>(())
    }.await;
    case.db.drop().await?;
    result
}
