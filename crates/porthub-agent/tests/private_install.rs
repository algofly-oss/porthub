#![cfg(unix)]
use axum::{extract::Json, http::HeaderMap, routing::post, Router};
use porthub_agent::{control::Control, profile::Profile};
use serde_json::Value;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

async fn pending(headers: HeaderMap, Json(body): Json<Value>) -> axum::http::StatusCode {
    assert_eq!(
        headers.get("accept").and_then(|value| value.to_str().ok()),
        Some("application/vnd.porthub.private-install+json")
    );
    assert_eq!(
        headers
            .get("x-porthub-agent-protocol")
            .and_then(|value| value.to_str().ok()),
        Some("rust-v1")
    );
    assert_eq!(body["machine_id"], "0123456789abcdef01234567");
    assert_eq!(body["token"], "machine-secret");
    axum::http::StatusCode::NO_CONTENT
}

#[tokio::test]
async fn native_private_install_request_uses_authenticated_machine_body_and_media_type() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let app = Router::new().route("/api/machines/client/private-install", post(pending));
    let cancel = CancellationToken::new();
    let server_cancel = cancel.clone();
    let server = tokio::spawn(async move {
        tokio::select! {
            result = axum::serve(listener, app) => result.unwrap(),
            _ = server_cancel.cancelled() => {}
        }
    });
    let profile = Profile {
        format_version: 1,
        server: format!("http://{address}"),
        machine_id: "0123456789abcdef01234567".into(),
        token: "machine-secret".into(),
        account_email: None,
        fallback_servers: Vec::new(),
        setup_overrides: Default::default(),
        allow_insecure_http_for_tests: true,
    };
    let control = Arc::new(Control::new(profile).unwrap());
    let reply = control.pending_private_install().await.unwrap();
    assert_eq!(reply.status, axum::http::StatusCode::NO_CONTENT);
    cancel.cancel();
    server.await.unwrap();
}
