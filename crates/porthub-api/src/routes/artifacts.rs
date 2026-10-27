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
        .route("/api/downloads/porthub", get(public_list))
        .route("/api/downloads/porthub/{target}", get(public_download))
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

fn public_base(configured: &str, headers: &HeaderMap) -> ApiResult<String> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let parsed = url::Url::parse(configured)
            .map_err(|_| ApiError::bad_request("Invalid PortHub public base URL"))?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ApiError::bad_request("Invalid PortHub public base URL"));
        }
        return Ok(configured.trim_end_matches('/').to_owned());
    }
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("localhost");
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| matches!(*value, "http" | "https"))
        .unwrap_or("http");
    Ok(format!("{scheme}://{host}"))
}

async fn public_list(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let base = public_base(&app.config.public_base_url, &headers)?;
    let mut items = Vec::new();
    for &(target, os, arch) in TARGETS {
        let release = match app.artifacts.release(target).await {
            Ok(release) => release,
            Err(error) if error.status == StatusCode::NOT_FOUND => continue,
            Err(error) => return Err(error),
        };
        items.push(json!({
            "target": target,
            "os": os,
            "arch": arch,
            "size": release.size,
            "version": release.version,
            "url": format!("{base}/api/downloads/porthub/{target}"),
        }));
    }
    Ok(Json(json!({"data": items})))
}

async fn public_download(
    State(app): State<Arc<App>>,
    Path(target): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let target = artifacts::normalize(&target, false)?;
    let mut response = app
        .artifacts
        .get(target)
        .await?
        .response(request.method(), request.headers(), false)
        .await?;
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static("attachment; filename=\"porthub\""),
    );
    if let Some(version) = response.headers().get("x-porthub-agent-release").cloned() {
        response.headers_mut().insert("x-porthub-version", version);
    }
    Ok(response)
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
        match app.artifacts.release(target).await {
            Ok(metadata) => {
                let mut release =
                    serde_json::to_value(&metadata).expect("fixed release schema");
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

#[cfg(test)]
mod public_download_tests {
    use super::public_base;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn public_download_links_use_configured_base_or_forwarded_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("porthub.example:8443"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https, http"));
        assert_eq!(
            public_base("", &headers).ok().as_deref(),
            Some("https://porthub.example:8443")
        );
        assert_eq!(
            public_base("https://public.example/root/", &headers)
                .ok()
                .as_deref(),
            Some("https://public.example/root")
        );
        assert!(public_base("javascript:alert(1)", &headers).is_err());
    }
}
