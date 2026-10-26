#![cfg(unix)]
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::any,
    Router,
};
use porthub_runtime::{
    proxy::{HttpProxy, ProxyPool},
    public_access::Config,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[tokio::test]
async fn locked_proxy_blocks_before_upstream_and_strips_key_after_validation() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let server = Router::new().fallback(any(move |request: Request<Body>| {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            assert!(!request.headers().contains_key("x-porthub-key"));
            let body = to_bytes(request.into_body(), 1024).await.unwrap();
            (StatusCode::OK, body)
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, server).await.unwrap();
    });
    let proxy = HttpProxy::web(&format!("http://{address}"), true, ProxyPool::default())
        .unwrap()
        .with_access(
            "mapping",
            Some(Config {
                verifier: bcrypt::hash("test-api-key-value", 10).unwrap(),
                pin: false,
            }),
        )
        .unwrap();
    let denied = proxy.forward(Request::new(Body::empty())).await;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let accepted = proxy
        .forward(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header("x-porthub-key", "test-api-key-value")
                .body(Body::from("file data"))
                .unwrap(),
        )
        .await;
    assert_eq!(accepted.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(accepted.into_body(), 1024).await.unwrap(),
        "file data"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn direct_stream_gate_checks_each_keepalive_request() {
    use hyper_util::rt::TokioIo;
    use porthub_runtime::public_access::{forward_io, Gate};
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let (visitor, visitor_server) = tokio::io::duplex(8192);
    let (upstream, upstream_server) = tokio::io::duplex(8192);
    let backend = tokio::spawn(async move {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(upstream_server),
                hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        assert!(!request.headers().contains_key("x-porthub-key"));
                        Ok::<_, std::convert::Infallible>(axum::http::Response::new(Body::new(
                            request.into_body(),
                        )))
                    }
                }),
            )
            .await
            .unwrap();
    });
    let gate = Arc::new(
        Gate::new(
            "direct",
            Config {
                verifier: bcrypt::hash("direct-test-key", 10).unwrap(),
                pin: false,
            },
        )
        .unwrap(),
    );
    let forwarding = tokio::spawn(forward_io(visitor_server, upstream, gate));
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(visitor))
        .await
        .unwrap();
    let connection = tokio::spawn(async move {
        connection.await.unwrap();
    });
    for (key, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("direct-test-key"), StatusCode::OK),
        (None, StatusCode::UNAUTHORIZED),
    ] {
        let mut request = Request::builder().method("POST").uri("/upload");
        if let Some(key) = key {
            request = request.header("x-porthub-key", key);
        }
        let response = sender
            .send_request(request.body(Body::from("streamed payload")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let body = to_bytes(Body::new(response.into_body()), 8192)
            .await
            .unwrap();
        if expected == StatusCode::OK {
            assert_eq!(body, "streamed payload");
        }
    }
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    drop(sender);
    connection.await.unwrap();
    forwarding.await.unwrap().unwrap();
    backend.abort();
}

#[tokio::test]
async fn sixteen_parallel_first_requests_share_verification_without_rejections() {
    use porthub_runtime::public_access::Gate;
    let gate = Arc::new(
        Gate::new(
            "parallel",
            Config {
                verifier: bcrypt::hash("parallel-transfer-key", 10).unwrap(),
                pin: false,
            },
        )
        .unwrap(),
    );
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let gate = gate.clone();
        tasks.spawn(async move {
            let request = Request::builder()
                .header("x-porthub-key", "parallel-transfer-key")
                .body(Body::empty())
                .unwrap();
            assert!(gate.authorize(request, false).await.is_ok());
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    let wrong = Request::builder()
        .header("x-porthub-key", "parallel-transfer-bad")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        gate.authorize(wrong, false).await.unwrap_err().status(),
        StatusCode::UNAUTHORIZED
    );
}
