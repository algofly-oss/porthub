use crate::{
    domain::machine_logs,
    error::ApiResult,
    input::{ApiBody, Model},
    store, App,
};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mongodb::bson::Document;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/log-stream", get(status))
        .route("/api/machines/client/logs", post(upload))
        .route("/api/private/client/log-stream", get(private_status))
        .route("/api/private/client/logs", post(private_upload))
}

async fn private_peer(app: &App, peer_id: &str, token: &str) -> ApiResult<Document> {
    use mongodb::bson::doc;
    let peer = app
        .collection("private_peers")
        .find_one(doc! {
            "_id": peer_id,
            "enabled": true,
            "credential_hash": crate::domain::workspaces::token_digest(token),
        })
        .await?
        .ok_or_else(|| {
            crate::error::ApiError::new(
                axum::http::StatusCode::UNAUTHORIZED,
                "Invalid private client credentials",
            )
        })?;
    Ok(peer)
}

async fn private_status(
    State(app): State<Arc<App>>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    let mut model = Model::query(query);
    let peer_id = model.required_string("peer_id");
    model.string_length("peer_id", &peer_id, 1, Some(60));
    let token = model.required_string("token");
    model.string_length("token", &token, 32, Some(200));
    model.finish()?;
    let peer = private_peer(&app, &peer_id, &token).await?;
    let machine_id = peer.get_object_id("machine_id").map_err(|_| {
        crate::error::ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "Private client is not linked to a machine",
        )
    })?;
    let active = app
        .realtime
        .log_requested(&app, &machine_id.to_hex())
        .await?;
    Ok((
        [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ],
        Json(json!({"peer_id":peer_id,"active":active})),
    )
        .into_response())
}

async fn private_upload(
    State(app): State<Arc<App>>,
    ApiBody(raw): ApiBody,
) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let peer_id = model.required_string("peer_id");
    let token = model.required_string("token");
    model.string_length("token", &token, 32, Some(200));
    let source = model
        .optional_string("source")
        .filter(|source| !source.is_empty())
        .unwrap_or_else(|| "client".into());
    let lines = model.optional_strings("lines").unwrap_or_default();
    model.finish()?;
    let peer = private_peer(&app, &peer_id, &token).await?;
    let machine_id = peer.get_object_id("machine_id").map_err(|_| {
        crate::error::ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "Private client is not linked to a machine",
        )
    })?;
    let workspace_id = peer.get_object_id("workspace_id").map_err(|_| {
        crate::error::ApiError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "Private client workspace is invalid",
        )
    })?;
    let machine = app.collection("machines").find_one(mongodb::bson::doc! {"_id":machine_id,"user_id":workspace_id,"deletion_pending":{"$ne":true}}).await?
        .ok_or_else(|| crate::error::ApiError::new(axum::http::StatusCode::GONE, "Machine deleted"))?;
    let lines = machine_logs::clean(lines);
    let source: String = source.chars().take(32).collect();
    app.realtime
        .log_lines(&app, &machine, &lines, &source)
        .await?;
    Ok(Json(
        json!({"msg":"Machine logs received successfully","data":{"peer_id":peer_id,"count":lines.len()}}),
    ))
}
async fn status(
    State(app): State<Arc<App>>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    let mut model = Model::query(query);
    let id = model.required_string("machine_id");
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    model.finish()?;
    let (machine, required) = machine_logs::touch(&app, &id, &token).await?;
    app.notify_status(&machine).await;
    let id = store::id(machine.get("_id"));
    let active = app.realtime.log_requested(&app, &id).await?;
    let mut headers = HeaderMap::new();
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-porthub-log-stream-active",
        HeaderValue::from_static(if active { "true" } else { "false" }),
    );
    headers.insert(
        "x-porthub-machine-auth-required",
        HeaderValue::from_static(if required { "true" } else { "false" }),
    );
    headers.insert(
        "x-porthub-machine-id",
        HeaderValue::from_str(&id).expect("ObjectId header"),
    );
    Ok((headers, Json(json!({"active":active}))).into_response())
}
async fn upload(State(app): State<Arc<App>>, ApiBody(raw): ApiBody) -> ApiResult<Json<Value>> {
    let mut model = Model::new(raw)?;
    let id = model.required_string("machine_id");
    let token = model.required_string("token");
    model.string_length("token", &token, 1, None);
    let source = model
        .optional_string("source")
        .filter(|source| !source.is_empty())
        .unwrap_or_else(|| "client".into());
    let lines = model.optional_strings("lines").unwrap_or_default();
    model.finish()?;
    let (machine, _) = machine_logs::touch(&app, &id, &token).await?;
    app.notify_status(&machine).await;
    let lines = machine_logs::clean(lines);
    let source: String = source.chars().take(32).collect();
    app.realtime
        .log_lines(&app, &machine, &lines, &source)
        .await?;
    Ok(Json(
        json!({"msg":"Machine logs received successfully","data":{"machine_id":store::id(machine.get("_id")),"count":lines.len()}}),
    ))
}
