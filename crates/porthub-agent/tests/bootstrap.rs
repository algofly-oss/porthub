#![cfg(unix)]
mod common;
use anyhow::{ensure, Result};
use axum::{
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use porthub_agent::{
    bootstrap,
    profile::{Lease, Profile},
};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
const ID: &str = "0123456789abcdef01234567";
fn enrollment(server: &str) -> Value {
    json!({"format_version":1,"profile":{"format_version":1,"server":server,"machine_id":ID,
        "token":"bootstrap-private-token","fallback_servers":[],"setup_overrides":{"public_base_url":server},"allow_insecure_http_for_tests":true}})
}
#[tokio::test]
async fn bootstrap_requires_explicit_plaintext_opt_in_checks_identity_and_preserves_profile_authority(
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let root = format!("http://{}", listener.local_addr()?);
    let good = enrollment(&root);
    let mut wrong = good.clone();
    wrong["profile"]["machine_id"] = json!("ffffffffffffffffffffffff");
    let mut malformed = good.clone();
    malformed["profile"]["setup_overrides"]["public_base_url"] = json!("https://other.example");
    let app = Router::new()
        .route(
            "/install/good",
            get(move |headers: HeaderMap| {
                let body = good.clone();
                async move {
                    assert_eq!(headers["accept"], "application/json");
                    ([("x-porthub-machine-id", ID)], Json(body))
                }
            }),
        )
        .route(
            "/install/wrong",
            get(move || {
                let body = wrong.clone();
                async move { ([("x-porthub-machine-id", ID)], Json(body)) }
            }),
        )
        .route(
            "/install/authority",
            get(move || {
                let body = malformed.clone();
                async move { ([("x-porthub-machine-id", ID)], Json(body)) }
            }),
        )
        .route(
            "/install/large",
            get(|| async { ([("x-porthub-machine-id", ID)], "x".repeat(70000)) }),
        );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let result = async {
        let cancel = CancellationToken::new();
        ensure!(
            bootstrap::fetch(&format!("{root}/install/good"), false, &cancel)
                .await
                .is_err()
        );
        let profile = bootstrap::fetch(&format!("{root}/install/good"), true, &cancel).await?;
        ensure!(
            profile.machine_id == ID
                && profile.server == root
                && profile.setup_overrides["public_base_url"] == root
        );
        for route in ["wrong", "authority", "large"] {
            let error = bootstrap::fetch(&format!("{root}/install/{route}"), true, &cancel)
                .await
                .err()
                .unwrap()
                .to_string();
            ensure!(!error.contains("bootstrap-private-token") && !error.contains(&root));
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    result
}
#[tokio::test]
async fn bootstrap_cannot_follow_redirects_and_cancelled_requests_do_not_wait_for_the_network(
) -> Result<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let other = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let location = format!("http://{}/stolen", other.local_addr()?);
    let app = Router::new().fallback(move || {
        let counter = counter.clone();
        async move {
            counter.fetch_add(1, Ordering::SeqCst);
            StatusCode::OK
        }
    });
    let other_task = tokio::spawn(async move {
        let _ = axum::serve(other, app).await;
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let root = format!("http://{}", listener.local_addr()?);
    let started = Arc::new(tokio::sync::Notify::new());
    let notify = started.clone();
    let app = Router::new()
        .route(
            "/install/redirect",
            get(move || {
                let location = location.clone();
                async move { (StatusCode::FOUND, [("location", location)]).into_response() }
            }),
        )
        .route(
            "/install/stalled",
            get(move || {
                let notify = notify.clone();
                async move {
                    notify.notify_one();
                    std::future::pending::<StatusCode>().await
                }
            }),
        );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let result = async {
        ensure!(bootstrap::fetch(
            &format!("{root}/install/redirect"),
            true,
            &CancellationToken::new()
        )
        .await
        .is_err());
        ensure!(calls.load(Ordering::SeqCst) == 0);
        let cancel = CancellationToken::new();
        let stopped = cancel.clone();
        let link = format!("{root}/install/stalled");
        let job = tokio::spawn(async move { bootstrap::fetch(&link, true, &stopped).await });
        tokio::time::timeout(Duration::from_secs(1), started.notified()).await?;
        cancel.cancel();
        ensure!(tokio::time::timeout(Duration::from_secs(1), job)
            .await??
            .is_err());
        Ok::<_, anyhow::Error>(())
    }
    .await;
    server.abort();
    other_task.abort();
    result
}
#[test]
fn credential_save_refuses_foreign_profiles_symlinks_and_active_owners() -> Result<()> {
    let directory = common::private_dir()?;
    let path = directory.path().join("profile");
    let mut profile: Profile =
        serde_json::from_value(enrollment("https://hub.example")["profile"].clone())?;
    profile.allow_insecure_http_for_tests = false;
    bootstrap::save(profile.clone(), &path)?;
    let bytes = std::fs::read(&path)?;
    let owner = Lease::acquire(&path)?;
    profile.token = "new-token".into();
    ensure!(bootstrap::save(profile.clone(), &path).is_err());
    drop(owner);
    profile.machine_id = "ffffffffffffffffffffffff".into();
    ensure!(bootstrap::save(profile, &path).is_err());
    ensure!(std::fs::read(&path)? == bytes);
    let link = directory.path().join("symlink");
    std::os::unix::fs::symlink(&path, &link)?;
    let profile: Profile = serde_json::from_slice(&bytes)?;
    ensure!(bootstrap::save(profile, &link).is_err());
    ensure!(std::fs::read(&path)? == bytes);
    Ok(())
}
