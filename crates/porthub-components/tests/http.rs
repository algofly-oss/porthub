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

struct TestRoutes {
    calls: std::sync::atomic::AtomicUsize,
    reports: tokio::sync::Mutex<Vec<bool>>,
    deny: bool,
}
#[async_trait::async_trait]
impl porthub_components::transport::Routing for TestRoutes {
    async fn route(
        &self,
        _url: &url::Url,
    ) -> anyhow::Result<porthub_components::transport::Routed> {
        use std::sync::atomic::Ordering;
        let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(!self.deny, "administrator route policy denied");
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(1));
        if attempt == 0 {
            builder = builder.local_address("192.0.2.123".parse::<std::net::IpAddr>()?);
        }
        Ok(porthub_components::transport::Routed {
            client: builder.build()?,
            ticket: attempt.to_string(),
        })
    }
    async fn completed(&self, _ticket: &str, success: bool) {
        self.reports.lock().await.push(success);
    }
}
#[tokio::test]
async fn routed_download_retries_failed_sources_but_never_retries_access_denial() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/ok", get(|| async { "payload" }))
        .route("/denied", get(|| async { StatusCode::FORBIDDEN }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let routes = Arc::new(TestRoutes {
        calls: AtomicUsize::new(0),
        reports: Default::default(),
        deny: false,
    });
    let http = Http::for_loopback_tests()
        .unwrap()
        .with_routing(routes.clone());
    let file = tempfile::NamedTempFile::new().unwrap();
    http.fetch(
        &format!("http://{address}/ok").parse().unwrap(),
        file.path(),
        64,
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(file.path()).unwrap(), b"payload");
    assert_eq!(routes.calls.load(Ordering::SeqCst), 2);
    assert_eq!(*routes.reports.lock().await, vec![false, true]);
    let error = http
        .fetch(
            &format!("http://{address}/denied").parse().unwrap(),
            file.path(),
            64,
        )
        .await
        .unwrap_err();
    assert!(error.is::<AccessDenied>());
    assert_eq!(routes.calls.load(Ordering::SeqCst), 3);
    let denied = Arc::new(TestRoutes {
        calls: AtomicUsize::new(0),
        reports: Default::default(),
        deny: true,
    });
    let http = Http::for_loopback_tests()
        .unwrap()
        .with_routing(denied.clone());
    assert!(http
        .fetch(
            &format!("http://{address}/ok").parse().unwrap(),
            file.path(),
            64
        )
        .await
        .is_err());
    assert_eq!(denied.calls.load(Ordering::SeqCst), 1);
    assert!(denied.reports.lock().await.is_empty());
    server.abort();
}
