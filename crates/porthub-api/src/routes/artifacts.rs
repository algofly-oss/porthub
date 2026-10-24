use crate::{
    artifacts::{self, TARGETS},
    domain::machine_client::{self, View},
    error::{ApiError, ApiResult},
    App,
};
use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/api/machines/{first}/{second}/downloads/rathole/{target}",
            get(legacy),
        )
        .route(
            "/api/machines/{first}/{second}/downloads/agent/{target}",
            get(native),
        )
        .route(
            "/api/machines/{first}/{second}/downloads/releases",
            get(manifest),
        )
        .route(
            "/api/machines/{first}/{second}/downloads/porthub",
            get(legacy_upgrade),
        )
        .route(
            "/api/machines/{first}/{second}/client.sh",
            get(legacy_upgrade),
        )
}
async fn legacy_upgrade(
    State(app): State<Arc<App>>,
    Path((id, token)): Path<(String, String)>,
) -> ApiResult<Response> {
    machine_client::authenticate(&app, &id, &token).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_DISPOSITION, "attachment; filename=porthub"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        crate::legacy_upgrade::script(),
    )
        .into_response())
}
async fn legacy(
    State(app): State<Arc<App>>,
    Path((id, token, target)): Path<(String, String, String)>,
    request: Request,
) -> ApiResult<Response> {
    serve(&app, &id, &token, &target, request, true).await
}
async fn native(
    State(app): State<Arc<App>>,
    Path((id, token, target)): Path<(String, String, String)>,
    request: Request,
) -> ApiResult<Response> {
    serve(&app, &id, &token, &target, request, false).await
}
async fn serve(
    app: &App,
    id: &str,
    token: &str,
    target: &str,
    request: Request,
    legacy: bool,
) -> ApiResult<Response> {
    machine_client::authenticate(app, id, token).await?;
    app.artifacts
        .get(artifacts::normalize(target, legacy)?)
        .await?
        .response(request.method(), request.headers(), legacy)
        .await
}
async fn manifest(
    State(app): State<Arc<App>>,
    Path((id, token)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let machine = machine_client::authenticate(&app, &id, &token).await?;
    let query = HashMap::new();
    let view = View {
        headers: &headers,
        query: &query,
    };
    let base = view.public_base(&app, &machine);
    let base = url::Url::parse(&base)
        .map_err(|_| ApiError::bad_request("Invalid PortHub public base URL"))?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err(ApiError::bad_request("Invalid PortHub public base URL"));
    }
    let mut releases = Vec::new();
    let mut missing = Vec::new();
    for (target, _, _) in TARGETS {
        match app.artifacts.get(target).await {
            Ok(artifact) => {
                let mut release =
                    serde_json::to_value(&artifact.release).expect("fixed release schema");
                let mut url = base.clone();
                url.path_segments_mut()
                    .map_err(|_| ApiError::bad_request("Invalid PortHub public base URL"))?
                    .pop_if_empty()
                    .extend(["api", "machines", &id, &token, "downloads", "agent", target]);
                release["url"] = json!(url.as_str());
                releases.push(release);
            }
            Err(error) if error.status == StatusCode::NOT_FOUND => missing.push(*target),
            Err(error) => return Err(error),
        }
    }
    Ok(([(header::CACHE_CONTROL,HeaderValue::from_static("no-store")),
        (header::REFERRER_POLICY,HeaderValue::from_static("no-referrer"))],
        Json(json!({"format_version":1,"machine_id":machine.get_object_id("_id").expect("stored machine id").to_hex(),
            "releases":releases,"missing_targets":missing}))).into_response())
}
