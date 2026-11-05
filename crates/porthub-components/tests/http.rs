use axum::{http::StatusCode, response::Redirect, routing::get, Router};
use porthub_components::transport::{AccessDenied, Http, Transport};
use std::time::Duration;
#[tokio::test]
async fn native_http_enforces_bounds_denials_and_no_gateway_redirects() {
    let app = Router::new()
        .route("/ok", get(|| async { "verified payload" }))
        .route("/large", get(|| async { "x".repeat(1024) }))
        .route("/denied", get(|| async { StatusCode::FORBIDDEN }))
        .route(
            "/redirect",
            get(|| async { Redirect::temporary("https://attacker.test/tool") }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let http = Http::for_loopback_tests().unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    let url = |path: &str| format!("http://{address}{path}").parse().unwrap();
    http.fetch(&url("/ok"), file.path(), 64).await.unwrap();
    assert_eq!(std::fs::read(file.path()).unwrap(), b"verified payload");
    assert!(http.fetch(&url("/large"), file.path(), 64).await.is_err());
    assert!(http
        .fetch(&url("/denied"), file.path(), 64)
        .await
        .unwrap_err()
        .is::<AccessDenied>());
    assert!(http
        .fetch(&url("/redirect"), file.path(), 64)
        .await
        .is_err());
    assert!(Http::new()
        .unwrap()
        .fetch(&url("/ok"), file.path(), 64)
        .await
        .is_err());
    assert!(http
        .fetch(&"http://example.com/tool".parse().unwrap(), file.path(), 64)
        .await
        .is_err());
    task.abort();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap_err();
}
