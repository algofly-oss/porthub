#![cfg(unix)]
use anyhow::{ensure, Result};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use porthub_runtime::{
    proxy::ProxyPool,
    upstreams::{Binding, Mode, PriorityPolicy, Routing, Strategy, Upstreams},
    web_routes::{Config, Route, Selection, WebRoutes},
};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinSet};
struct Backend {
    url: String,
    healthy: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
}
async fn backend(workers: &mut JoinSet<()>, name: &'static str, delay: u64) -> Result<Backend> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let healthy = Arc::new(AtomicBool::new(true));
    let writes = Arc::new(AtomicUsize::new(0));
    let h = healthy.clone();
    let w = writes.clone();
    let router = Router::new().fallback(move |request: Request<Body>| {
        let h = h.clone();
        let w = w.clone();
        async move {
            if request.method() == "POST" {
                w.fetch_add(1, Ordering::SeqCst);
            }
            if request.uri().path() == "/health" {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            let status = if !h.load(Ordering::SeqCst) {
                StatusCode::SERVICE_UNAVAILABLE
            } else if request.uri().path() == "/application-error" {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            };
            axum::http::Response::builder()
                .status(status)
                .body(Body::from(format!(
                    "{name}|{}|{}",
                    request.uri(),
                    request
                        .headers()
                        .get("cookie")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("")
                )))
                .unwrap()
        }
    });
    workers.spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    Ok(Backend {
        url,
        healthy,
        writes,
    })
}
fn binding(id: &str, url: &str, priority: u32, weight: u32) -> Binding {
    Binding {
        id: id.into(),
        target_url: url.into(),
        pass_host: false,
        enabled: true,
        priority,
        weight,
        health_path: None,
    }
}
fn routing() -> Routing {
    let mut r = Routing::default();
    r.health.path = "/health".into();
    r.health.interval_seconds = 1;
    r.health.cooldown_seconds = 1;
    r.health.unhealthy_after = 1;
    r.health.healthy_after = 2;
    r
}
fn pool(bindings: Vec<Binding>, config: Routing) -> Result<Upstreams> {
    Upstreams::new(
        "test",
        &["app.example".into()],
        bindings,
        config,
        None,
        ProxyPool::default(),
    )
}
async fn get(pool: &Upstreams, path: &str) -> Result<(StatusCode, String)> {
    let r = pool
        .forward(Request::builder().uri(path).body(Body::empty())?)
        .await;
    Ok((
        r.status(),
        String::from_utf8(to_bytes(r.into_body(), 4096).await?.to_vec())?,
    ))
}

#[tokio::test]
async fn manual_priority_fails_over_and_restores_preferred_after_two_successes() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "primary", 0).await?;
    let b = backend(&mut workers, "backup", 0).await?;
    let p = pool(
        vec![
            binding("backup", &b.url, 20, 1),
            binding("primary", &a.url, 1, 1),
        ],
        routing(),
    )?;
    ensure!(get(&p, "/").await?.1.starts_with("primary"));
    a.healthy.store(false, Ordering::SeqCst);
    ensure!(get(&p, "/").await?.1.starts_with("backup"));
    ensure!(p.status().iter().find(|s| s.id == "primary").unwrap().state == "unhealthy");
    a.healthy.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    p.check_health().await;
    ensure!(
        get(&p, "/").await?.1.starts_with("backup"),
        "one successful probe must not restore a down endpoint"
    );
    tokio::time::sleep(Duration::from_millis(1050)).await;
    p.check_health().await;
    ensure!(get(&p, "/").await?.1.starts_with("primary"));
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn balancing_ignores_manual_priorities_and_weights_have_exact_share() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "A", 0).await?;
    let b = backend(&mut workers, "B", 0).await?;
    let mut r = routing();
    r.mode = Mode::Balance;
    r.strategy = Strategy::RoundRobin;
    let p = pool(
        vec![binding("a", &a.url, 1, 3), binding("b", &b.url, 100, 1)],
        r.clone(),
    )?;
    let mut names = Vec::new();
    for _ in 0..6 {
        names.push(get(&p, "/").await?.1.chars().next().unwrap());
    }
    ensure!(names == vec!['A', 'B', 'A', 'B', 'A', 'B']);
    r.strategy = Strategy::WeightedRoundRobin;
    let p = pool(
        vec![binding("a", &a.url, 1, 3), binding("b", &b.url, 100, 1)],
        r,
    )?;
    let mut count = 0;
    for _ in 0..20 {
        if get(&p, "/").await?.1.starts_with('A') {
            count += 1;
        }
    }
    ensure!(count == 15);
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn health_priority_ignores_manual_order_and_chooses_responsive_endpoint() -> Result<()> {
    let mut workers = JoinSet::new();
    let slow = backend(&mut workers, "slow", 80).await?;
    let fast = backend(&mut workers, "fast", 1).await?;
    let mut r = routing();
    r.priority_policy = PriorityPolicy::Health;
    let p = pool(
        vec![
            binding("slow", &slow.url, 1, 1),
            binding("fast", &fast.url, 100, 1),
        ],
        r,
    )?;
    p.check_health().await;
    ensure!(get(&p, "/").await?.1.starts_with("fast"));
    fast.healthy.store(false, Ordering::SeqCst);
    ensure!(get(&p, "/").await?.1.starts_with("slow"));
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn least_connections_tracks_stream_body_lifetime() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "A", 0).await?;
    let b = backend(&mut workers, "B", 0).await?;
    let mut r = routing();
    r.mode = Mode::Balance;
    r.strategy = Strategy::LeastConnections;
    let p = pool(
        vec![binding("a", &a.url, 1, 1), binding("b", &b.url, 1, 1)],
        r,
    )?;
    let held = p.forward(Request::new(Body::empty())).await;
    ensure!(p.status()[0].active_connections == 1);
    for _ in 0..5 {
        ensure!(get(&p, "/").await?.1.starts_with('B'));
    }
    drop(held);
    ensure!(p.status().iter().all(|s| s.active_connections == 0));
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn writes_and_application_errors_are_not_replayed() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "A", 0).await?;
    let b = backend(&mut workers, "B", 0).await?;
    let p = pool(
        vec![binding("a", &a.url, 1, 1), binding("b", &b.url, 2, 1)],
        routing(),
    )?;
    ensure!(get(&p, "/application-error").await?.0 == StatusCode::INTERNAL_SERVER_ERROR);
    ensure!(p.status()[1].requests == 0);
    a.healthy.store(false, Ordering::SeqCst);
    let response = p
        .forward(
            Request::builder()
                .method("POST")
                .body(Body::from("must execute once"))?,
        )
        .await;
    ensure!(response.status() == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(a.writes.load(Ordering::SeqCst) == 1 && b.writes.load(Ordering::SeqCst) == 0);
    ensure!(get(&p, "/").await?.1.starts_with('B'));
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn affinity_is_scoped_removed_from_upstream_and_falls_back_when_unhealthy() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "A", 0).await?;
    let b = backend(&mut workers, "B", 0).await?;
    let mut r = routing();
    r.mode = Mode::Balance;
    r.sticky_sessions = true;
    let p = pool(
        vec![binding("a", &a.url, 1, 1), binding("b", &b.url, 1, 1)],
        r,
    )?;
    let request = || {
        Request::builder()
            .header("cookie", "session=abc; ph_upstream_test=b")
            .body(Body::empty())
            .unwrap()
    };
    let response = p.forward_with_security(request(), true).await;
    ensure!(response.headers()["set-cookie"]
        .to_str()?
        .contains("; Secure"));
    let body = to_bytes(response.into_body(), 4096).await?;
    ensure!(body.as_ref() == b"B|/|session=abc");
    b.healthy.store(false, Ordering::SeqCst);
    let response = p.forward(request()).await;
    ensure!(to_bytes(response.into_body(), 4096)
        .await?
        .starts_with(b"A|"));
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn no_healthy_bindings_returns_503_and_disabled_targets_are_never_contacted() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "A", 0).await?;
    let mut b = binding("a", &a.url, 1, 1);
    b.enabled = false;
    let p = pool(vec![b], routing())?;
    ensure!(get(&p, "/").await?.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(p.status()[0].requests == 0 && p.status()[0].state == "disabled");
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn closed_socket_is_replaced_and_attempt_limit_is_respected() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "live", 0).await?;
    let dead = TcpListener::bind("127.0.0.1:0").await?;
    let address = dead.local_addr()?;
    drop(dead);
    let bindings = vec![
        binding("dead", &format!("http://{address}"), 1, 1),
        binding("live", &a.url, 2, 1),
    ];
    let mut r = routing();
    r.max_attempts = 1;
    let p = pool(bindings.clone(), r)?;
    ensure!(get(&p, "/").await?.0 == StatusCode::SERVICE_UNAVAILABLE);
    ensure!(p.status()[1].requests == 0);
    let p = pool(bindings, routing())?;
    ensure!(get(&p, "/").await?.1.starts_with("live"));
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn reload_keeps_health_counters_and_rejected_snapshot_keeps_existing_routes() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "A", 0).await?;
    let routes = WebRoutes::new(None);
    let route = Route {
        id: "test".into(),
        hosts: vec!["app.example".into()],
        target_url: a.url.clone(),
        bindings: vec![binding("a", &a.url, 1, 1)],
        routing: Some(routing()),
        pass_host: false,
        http: true,
        https: true,
        access: None,
    };
    let config = Config {
        routes: vec![route.clone()],
    };
    routes.reload(config.clone())?;
    let request = || {
        Request::builder()
            .header("host", "app.example")
            .body(Body::empty())
            .unwrap()
    };
    let Selection::Proxy(p) = routes.select(&request(), false) else {
        panic!()
    };
    get(&p, "/").await?;
    routes.reload(config)?;
    let snapshot = routes.health_snapshot();
    ensure!(snapshot["routes"]["test"][0]["requests"] == 1);
    let mut invalid = route;
    invalid.bindings[0].target_url = "file:///etc/passwd".into();
    ensure!(routes
        .reload(Config {
            routes: vec![invalid]
        })
        .is_err());
    ensure!(matches!(
        routes.select(&request(), false),
        Selection::Proxy(_)
    ));
    workers.shutdown().await;
    Ok(())
}
#[test]
fn invalid_settings_and_legacy_defaults_are_validated() {
    let defaults: Routing = serde_json::from_str("{}").unwrap();
    assert_eq!(defaults.response_timeout_seconds, 310);
    assert!(defaults.validate().is_ok());
    let mut invalid = defaults.clone();
    invalid.health.path = "http://elsewhere/".into();
    assert!(invalid.validate().is_err());
    invalid = defaults.clone();
    invalid.max_attempts = 0;
    assert!(invalid.validate().is_err());
    assert!(serde_json::from_str::<Routing>(r#"{"mode":"unknown"}"#).is_err());
    assert!(
        serde_json::from_str::<Routing>(r#"{"health":{"interval_seconds":0}}"#)
            .unwrap()
            .validate()
            .is_err()
    );
}

#[tokio::test]
async fn probe_thresholds_and_overrides_recover_without_client_traffic() -> Result<()> {
    let mut workers = JoinSet::new();
    let a = backend(&mut workers, "A", 0).await?;
    let mut r = routing();
    r.health.unhealthy_after = 2;
    r.health.healthy_after = 1;
    r.health.path = "/application-error".into();
    let mut b = binding("a", &a.url, 1, 1);
    b.health_path = Some("/health".into());
    let p = pool(vec![b], r)?;
    p.check_health().await;
    ensure!(
        p.status()[0].state == "healthy",
        "binding override must replace proxy-wide health path"
    );
    a.healthy.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    p.check_health().await;
    ensure!(p.status()[0].state == "degraded");
    tokio::time::sleep(Duration::from_millis(1050)).await;
    p.check_health().await;
    ensure!(p.status()[0].state == "unhealthy");
    a.healthy.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1050)).await;
    p.check_health().await;
    ensure!(p.status()[0].state == "healthy");
    workers.shutdown().await;
    Ok(())
}
#[tokio::test]
async fn pooled_uploads_stay_streamed_and_are_never_buffered_for_retry() -> Result<()> {
    use futures_util::StreamExt;
    let seen = Arc::new(tokio::sync::Notify::new());
    let ack = seen.clone();
    let release = Arc::new(tokio::sync::Notify::new());
    let send = release.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let mut workers = JoinSet::new();
    workers.spawn(async move {
        axum::serve(
            listener,
            Router::new().fallback(move |request: Request<Body>| {
                let ack = ack.clone();
                async move {
                    let mut stream = request.into_body().into_data_stream();
                    let mut bytes = stream.next().await.unwrap().unwrap().len();
                    ack.notify_one();
                    while let Some(chunk) = stream.next().await {
                        bytes += chunk.unwrap().len();
                    }
                    bytes.to_string()
                }
            }),
        )
        .await
        .unwrap();
    });
    let stream = futures_util::stream::unfold(0, move |step| {
        let send = send.clone();
        async move {
            match step {
                0 => Some((
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"first")),
                    1,
                )),
                1 => {
                    send.notified().await;
                    Some((Ok(axum::body::Bytes::from_static(b"last")), 2))
                }
                _ => None,
            }
        }
    });
    let p = pool(vec![binding("a", &url, 1, 1)], routing())?;
    let task = tokio::spawn(async move {
        p.forward(
            Request::builder()
                .method("POST")
                .body(Body::from_stream(stream))
                .unwrap(),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(1), seen.notified()).await?;
    release.notify_one();
    let response = task.await?;
    ensure!(to_bytes(response.into_body(), 1024).await?.as_ref() == b"9");
    workers.shutdown().await;
    Ok(())
}
