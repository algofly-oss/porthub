//! Serve the exported Next.js application without a production Node process.
//! Clean page URLs map to their exported HTML files; API paths remain API 404s.
use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use std::path::{Component, Path, PathBuf};
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

pub struct StaticUi {
    root: PathBuf,
}
impl StaticUi {
    pub fn new(root: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            root: root.canonicalize()?,
        })
    }
    pub async fn serve(&self, request: Request) -> Response {
        if !matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD
        ) {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let path = match percent_encoding::percent_decode_str(request.uri().path()).decode_utf8() {
            Ok(path) => path.into_owned(),
            Err(_) => return StatusCode::NOT_FOUND.into_response(),
        };
        if path.contains(['\\', '\0'])
            || Path::new(path.trim_start_matches('/'))
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return StatusCode::NOT_FOUND.into_response();
        }
        if let Ok(resolved) =
            tokio::fs::canonicalize(self.root.join(path.trim_start_matches('/'))).await
        {
            if !resolved.starts_with(&self.root) {
                return StatusCode::NOT_FOUND.into_response();
            }
        }
        let immutable = path.starts_with("/_next/static/");
        let (parts, body) = request.into_parts();
        // Keep a body-free copy for a page fallback after a missing asset.
        let retry = Request::from_parts(parts.clone(), Body::empty());
        let mut response = match ServeDir::new(&self.root)
            .precompressed_gzip()
            .oneshot(Request::from_parts(parts, body))
            .await
        {
            Ok(response) => response.map(Body::new),
            Err(error) => match error {},
        };
        if response.status() == StatusCode::NOT_FOUND {
            let candidate = self.root.join(format!("{}.html", path.trim_matches('/')));
            let (file, status) = match tokio::fs::canonicalize(&candidate).await {
                Ok(file) if file.starts_with(&self.root) => (file, StatusCode::OK),
                _ => (self.root.join("404.html"), StatusCode::NOT_FOUND),
            };
            response = match ServeFile::new(file)
                .precompressed_gzip()
                .oneshot(retry)
                .await
            {
                Ok(response) => response.map(Body::new),
                Err(error) => match error {},
            };
            if status == StatusCode::NOT_FOUND {
                *response.status_mut() = status;
            }
        }
        let cacheable = immutable && response.status().is_success();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(if cacheable {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            }),
        );
        response
    }
}
