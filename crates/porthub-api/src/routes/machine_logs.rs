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
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc};
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/machines/client/log-stream", get(status))
        .route("/api/machines/client/logs", post(upload))
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
