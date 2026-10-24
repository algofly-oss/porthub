use crate::{
    auth,
    domain::inventory,
    error::{ApiError, ApiResult},
    store, App,
};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use futures_util::TryStreamExt;
use mongodb::bson::{doc, Document};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};

pub fn router() -> Router<Arc<App>> {
    Router::new().route("/api/admin/overview", get(overview))
}

async fn overview(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let admin = auth::current_user(&app, &headers).await?;
    if store::string(&admin, "role") != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Admin access required",
        ));
    }
    let users: Vec<Document> = app
        .collection("users")
        .find(doc! {})
        .sort(doc! {"created_at":1})
        .await?
        .try_collect()
        .await?;
    let machines: Vec<Document> = app
        .collection("machines")
        .find(doc! {"deletion_pending":{"$ne":true}})
        .await?
        .try_collect()
        .await?;
    let connections: Vec<Document> = app
        .collection("connections")
        .find(doc! {})
        .await?
        .try_collect()
        .await?;
    let mut by_user: HashMap<String, Vec<&Document>> = HashMap::new();
    let mut by_machine: HashMap<String, Vec<&Document>> = HashMap::new();
    for machine in &machines {
        by_user
            .entry(store::id(machine.get("user_id")))
            .or_default()
            .push(machine);
    }
    for connection in &connections {
        let id = store::id(connection.get("machine_id"));
        if !id.is_empty() {
            by_machine.entry(id).or_default().push(connection);
        }
    }
    let mut output = Vec::new();
    for user in users {
        let uid = store::id(user.get("_id"));
        let mut machine_output = Vec::new();
        for machine in by_user.get(&uid).into_iter().flatten() {
            let mid = store::id(machine.get("_id"));
            let mut ports = by_machine.get(&mid).cloned().unwrap_or_default();
            ports.sort_by(|a, b| {
                let port = |record: &&Document| {
                    record
                        .get("external_port")
                        .and_then(|port| store::json(port).as_f64())
                        .unwrap_or(0.0)
                };
                port(a).total_cmp(&port(b))
            });
            let mut record = inventory::machine(&app, machine);
            record["num_ports"] = json!(ports.len());
            record["ports"] = json!(ports
                .iter()
                .map(|connection| inventory::connection(&app, connection, Some(machine)))
                .collect::<Vec<_>>());
            machine_output.push(record);
        }
        let email = store::string(&user, "email");
        let email = if email.is_empty() {
            store::string(&user, "username")
        } else {
            email
        };
        output.push(json!({"user":{"id":uid,"name":inventory::default_field(&user,"name",json!("")),"email":email,
            "role":inventory::default_field(&user,"role",json!("user")),"created_at":store::field(&user,"created_at")},"machines":machine_output}));
    }
    Ok(Json(
        json!({"msg":"Platform overview loaded successfully","data":output}),
    ))
}
