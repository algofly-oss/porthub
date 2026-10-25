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
    Router::new()
        .route("/api/admin/overview", get(overview))
        .route(
            "/api/admin/settings/signup",
            get(signup_settings)
                .patch(update_signup)
                .delete(reset_signup),
        )
}

async fn admin_user(app: &App, headers: &HeaderMap) -> ApiResult<Document> {
    let user = auth::current_user(app, headers).await?;
    if store::string(&user, "role") != "admin" {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Admin access required",
        ));
    }
    Ok(user)
}

async fn signup_value(app: &App) -> ApiResult<(bool, bool)> {
    let setting = app
        .collection("platform_settings")
        .find_one(doc! {"_id":"platform"})
        .await?;
    let override_value = setting
        .as_ref()
        .and_then(|d| d.get_bool("signup_enabled").ok());
    Ok((
        crate::config::signup_enabled(app.config.signup_disabled, override_value),
        override_value.is_some(),
    ))
}

async fn signup_settings(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    admin_user(&app, &headers).await?;
    let (enabled, configured) = signup_value(&app).await?;
    Ok(Json(
        json!({"signup_enabled":enabled,"configured":configured,"env_default":!app.config.signup_disabled}),
    ))
}

async fn update_signup(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    crate::input::ApiBody(raw): crate::input::ApiBody,
) -> ApiResult<Json<Value>> {
    admin_user(&app, &headers).await?;
    let mut model = crate::input::Model::new(raw)?;
    let enabled = model.required_bool("signup_enabled");
    model.finish()?;
    app.collection("platform_settings")
        .update_one(
            doc! {"_id":"platform"},
            doc! {"$set":{"signup_enabled":enabled,"updated_at":mongodb::bson::DateTime::now() } },
        )
        .upsert(true)
        .await?;
    let (effective, configured) = signup_value(&app).await?;
    Ok(Json(
        json!({"signup_enabled":effective,"configured":configured,"env_default":!app.config.signup_disabled}),
    ))
}

async fn reset_signup(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    admin_user(&app, &headers).await?;
    app.collection("platform_settings")
        .update_one(
            doc! {"_id":"platform"},
            doc! {"$unset":{"signup_enabled":"","updated_at":""}},
        )
        .await?;
    let (effective, configured) = signup_value(&app).await?;
    Ok(Json(
        json!({"signup_enabled":effective,"configured":configured,"env_default":!app.config.signup_disabled}),
    ))
}

async fn overview(State(app): State<Arc<App>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    admin_user(&app, &headers).await?;
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
