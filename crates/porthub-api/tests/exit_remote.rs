//! Temporary control plane for real-host tests; never reads production MongoDB.
use anyhow::{ensure, Result};
use axum::{extract::State, http::{HeaderMap, StatusCode}, routing::post, Json};
use mongodb::bson::{doc, oid::ObjectId};
use porthub_api::{config::Config, domain::workspaces::token_digest};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires explicit remote-test runner and isolated MongoDB"]
async fn remote_exit_control_fixture() -> Result<()> {
    let ready = std::path::PathBuf::from(std::env::var("PORTHUB_TEST_REMOTE_READY")?);
    ensure!(ready.parent().is_some_and(|parent| parent.file_name().is_some_and(|name| name.to_string_lossy().starts_with("porthub-exit-remote-"))), "requires owned fixture directory");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let case = Case::new(Config {
        public_base_url: format!("http://{address}"),
        private_transport: porthub_api::private_transport::Settings::parse("[]", "", "remote-exit-fixture-secret-0123456789abcdef"),
        ..Default::default()
    }).await?;
    let (owner, _) = case.user("remote-exit@example.invalid", "user").await?;
    let ids = [ObjectId::new(), ObjectId::new(), ObjectId::new()];
    let token = uuid::Uuid::new_v4().to_string();
    let route = ObjectId::new();
    for (i, machine) in ids.iter().enumerate() {
        case.app.collection("machines").insert_one(doc! {"_id":machine,"user_id":owner,"name":format!("remote-test-{i}")}).await?;
        case.app.collection("private_peers").insert_one(doc! {"_id":format!("{owner}:{machine}"),"workspace_id":owner,"machine_id":machine,"owner_id":owner,
            "ip":format!("10.234.240.{}",i+10),"enabled":true,"credential_hash":token_digest(&token)}).await?;
    }
    case.app.collection("private_exit_nodes").insert_one(doc! {"_id":route,"workspace_id":owner,"name":"Remote test exits","enabled":true,"selection":"round_robin",
        "routing_selectors":[{"kind":"machine","id":ids[1].to_hex()},{"kind":"machine","id":ids[2].to_hex()}],
        "distribution_selectors":[{"kind":"machine","id":ids[0].to_hex()}]}).await?;
    let secret = uuid::Uuid::new_v4().to_string();
    let mode_state = (case.app.clone(), route, secret.clone());
    let control = axum::Router::new().route("/_test/mode", post(|State((app, route, secret)): State<(Arc<porthub_api::App>, ObjectId, String)>, headers: HeaderMap, Json(body): Json<Value>| async move {
        if headers.get("x-test-key").and_then(|value| value.to_str().ok()) != Some(secret.as_str()) { return StatusCode::UNAUTHORIZED; }
        let Some(mode) = body["mode"].as_str().filter(|mode| ["sticky", "round_robin", "random"].contains(mode)) else { return StatusCode::BAD_REQUEST; };
        match app.collection("private_exit_nodes").update_one(doc! {"_id":route}, doc! {"$set":{"selection":mode}}).await {
            Ok(_) => StatusCode::OK, Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    })).with_state(mode_state);
    let task = tokio::spawn(axum::serve(listener, case.router.clone().merge(control)).into_future());
    let profiles: Vec<_> = ids.iter().map(|id| json!({"workspace":owner.to_hex(),"peer_id":format!("{owner}:{id}"),"token":token,"allow_insecure_http_for_tests":true})).collect();
    std::fs::write(&ready, serde_json::to_vec(&json!({"address":address.to_string(),"profiles":profiles,"control_key":secret}))?)?;
    let stopped = ready.with_file_name("stop");
    let result = tokio::time::timeout(Duration::from_secs(480), async {
        while !stopped.exists() { tokio::time::sleep(Duration::from_millis(250)).await; }
    }).await;
    task.abort();
    case.db.drop().await?;
    let _ = std::fs::remove_file(ready);
    result?;
    Ok(())
}
use std::future::IntoFuture;
