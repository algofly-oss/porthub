use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use mongodb::Client;
use porthub_api::{config::Config, App};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn old_shell_routes_refuse_access_before_authentication_or_storage() {
    let client = Client::with_uri_str("mongodb://127.0.0.1:1").await.unwrap();
    let app = Arc::new(App::new(
        Config::default(),
        client.database("retired_terminal"),
    ));
    let router = porthub_api::router(app);
    for (method, path) in [
        (Method::GET, "/terminal"),
        (Method::GET, "/terminal.html"),
        (Method::GET, "/api/terminal/host"),
        (Method::GET, "/api/terminal/join"),
        (Method::POST, "/api/terminal/info"),
        (Method::GET, "/api/machines/123/terminal-sessions"),
        (Method::POST, "/api/machines/123/terminal-sessions"),
        (Method::GET, "/api/machines/123/terminal-sessions/abc/join"),
        (
            Method::POST,
            "/api/machines/123/terminal-sessions/abc/guest-links",
        ),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", "Bearer previously-issued-capability")
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::GONE, "{path}");
    }
}
