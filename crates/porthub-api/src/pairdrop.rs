//! Isolated, anonymous PairDrop frontend and signaling behind the portal origin.
use crate::App;
use axum::{
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{any, get},
    Router,
};
use std::sync::Arc;
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/pairdrop", get(canonical))
        .route("/pairdrop/", any(forward))
        .route("/pairdrop/{*path}", any(forward))
}
async fn canonical(uri: Uri) -> Response {
    let target = format!(
        "/pairdrop/{}",
        uri.query().map(|q| format!("?{q}")).unwrap_or_default()
    );
    (StatusCode::TEMPORARY_REDIRECT, [(header::LOCATION, target)]).into_response()
}
async fn forward(State(app): State<Arc<App>>, mut request: Request) -> Response {
    let Some(upstream) = &app.pairdrop else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "PairDrop is not configured on this portal.",
        )
            .into_response();
    };
    if !crate::realtime::origin_allowed(&app, request.headers()) {
        return (StatusCode::FORBIDDEN, "PairDrop origin rejected").into_response();
    }
    let path = request
        .uri()
        .path()
        .strip_prefix("/pairdrop")
        .unwrap_or("/");
    let target = format!(
        "{}{}",
        if path.is_empty() { "/" } else { path },
        request
            .uri()
            .query()
            .map(|q| format!("?{q}"))
            .unwrap_or_default()
    );
    let Ok(uri) = target.parse::<Uri>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    *request.uri_mut() = uri;
    // PairDrop is public and receives no portal sessions or account credentials.
    for name in ["cookie", "authorization", "x-transfer-key", "x-board-share"] {
        request.headers_mut().remove(name);
    }
    let mut response = upstream.forward(request).await;
    if let Some(location) = response
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.starts_with('/') && !s.starts_with("//"))
    {
        if let Ok(value) = HeaderValue::from_str(&format!("/pairdrop{location}")) {
            response.headers_mut().insert(header::LOCATION, value);
        }
    }
    response.headers_mut().remove(header::SET_COOKIE);
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'self'"),
    );
    response
}
