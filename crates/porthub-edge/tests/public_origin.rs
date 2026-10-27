use axum::{
    body::{to_bytes, Body},
    http::Request,
    routing::get,
    Router,
};
use tower::ServiceExt;

#[tokio::test]
async fn http2_authority_preserves_browser_origin_and_overrides_forged_forwarded_host() {
    let app = Router::new().route("/", get(|headers: axum::http::HeaderMap| async move {
        format!("{}|{}|{}", headers["host"].to_str().unwrap(),
            headers["x-forwarded-host"].to_str().unwrap(),
            headers["x-forwarded-proto"].to_str().unwrap())
    }));
    let app = porthub_edge::listener_router_with_public_origin(
        app, false, Some("https://porthub.example:8443"));
    for host in [None, Some("forged.example")] {
        let mut request = Request::builder()
            .version(axum::http::Version::HTTP_2)
            .uri("https://porthub.example:8443/")
            .header("x-forwarded-host", "forged.example");
        if let Some(host) = host { request = request.header("host", host); }
        let response = app.clone().oneshot(request.body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(to_bytes(response.into_body(), 1024).await.unwrap(),
            "porthub.example:8443|porthub.example:8443|https");
    }
}
#[tokio::test]
async fn configured_external_https_authority_preserves_https_for_http_origin_without_trusting_forwarded_headers(
) {
    let app = Router::new().route(
        "/",
        get(|headers: axum::http::HeaderMap| async move {
            headers["x-forwarded-proto"].to_str().unwrap().to_owned()
        }),
    );
    let app = porthub_edge::listener_router_with_public_origin(
        app,
        false,
        Some("https://porthub.example"),
    );
    for (host, forged, expected) in [
        ("porthub.example", "http", "https"),
        ("porthub.example:443", "http", "https"),
        ("other.example", "https", "http"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("host", host)
                    .header("x-forwarded-proto", forged)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            expected
        );
    }
}
