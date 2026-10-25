#![cfg(unix)]
mod common;
use anyhow::{ensure, Result};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use porthub_agent::{control::Control, profile::Profile, update};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio_util::sync::CancellationToken;

const ID: &str = "0123456789abcdef01234567";
const TOKEN: &str = "release-private-token-0123456789";
const TARGET: &str = "x86_64";
const VERSION: &str = "native-fixture-2";

#[test]
fn update_requests_require_explicit_pending_flag_and_bounded_identity_and_target() -> Result<()> {
    use porthub_agent::update::Request;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-porthub-client-update-request-id", "request-1".parse()?);
    headers.insert("x-porthub-client-target-version", "native-v2".parse()?);
    ensure!(Request::from_headers(&headers)?.is_none());
    headers.insert("x-porthub-client-update-requested", "true".parse()?);
    ensure!(Request::from_headers(&headers)?.unwrap().id == "request-1");
    headers.remove("x-porthub-client-target-version");
    ensure!(Request::from_headers(&headers).is_err());
    for (id, target) in [
        ("../foreign", "v2"),
        ("request", "bad version"),
        ("", "v2"),
        ("request", ""),
    ] {
        ensure!(Request {
            id: id.into(),
            target_version: target.into()
        }
        .validate()
        .is_err());
    }
    Ok(())
}

struct Fixture {
    catalog: Mutex<Value>,
    mode: Mutex<&'static str>,
    bytes: Vec<u8>,
    calls: AtomicUsize,
}
fn catalog(bytes: &[u8]) -> Value {
    json!({"format_version":1,"machine_id":ID,"releases":[{
        "target":TARGET,"os":"linux","arch":"x86_64","asset":"porthub-x86_64",
        "version":VERSION,"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(bytes)),
        "url":"http://unconfigured.invalid/credentials-must-never-go-here"
    }]})
}
async fn asset(State(state): State<Arc<Fixture>>) -> Response {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let mode = *state.mode.lock().unwrap();
    match mode {
        "unavailable" => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        "forbidden" => return StatusCode::FORBIDDEN.into_response(),
        "redirect" => {
            return (
                StatusCode::FOUND,
                [(header::LOCATION, "http://unconfigured.invalid/leak")],
            )
                .into_response()
        }
        "slow" => {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
        _ => {}
    }
    let body = match mode {
        "corrupt" => vec![0xff; state.bytes.len()],
        "short" => state.bytes[..state.bytes.len() - 1].to_vec(),
        "large" => [state.bytes.clone(), vec![0]].concat(),
        _ => state.bytes.clone(),
    };
    let hash = format!("{:x}", Sha256::digest(&state.bytes));
    (
        [
            ("x-porthub-agent-target", TARGET.to_owned()),
            (
                "x-porthub-agent-release",
                if mode == "metadata" {
                    "foreign-version"
                } else {
                    VERSION
                }
                .to_owned(),
            ),
            ("x-porthub-agent-sha256", hash),
        ],
        body,
    )
        .into_response()
}
async fn fixture() -> Result<(
    Arc<Fixture>,
    String,
    tokio::task::JoinHandle<std::io::Result<()>>,
)> {
    let bytes: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let state = Arc::new(Fixture {
        catalog: Mutex::new(catalog(&bytes)),
        mode: Mutex::new("normal"),
        bytes,
        calls: AtomicUsize::new(0),
    });
    let router = Router::new()
        .route(
            &format!("/api/machines/{ID}/{TOKEN}/downloads/releases"),
            get(|State(state): State<Arc<Fixture>>| async move {
                Json(state.catalog.lock().unwrap().clone())
            }),
        )
        .route(
            &format!("/api/machines/{ID}/{TOKEN}/downloads/agent/{TARGET}"),
            get(asset),
        )
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move { axum::serve(listener, router).await });
    Ok((state, base, task))
}
fn control(server: String, fallback_servers: Vec<String>) -> Result<Control> {
    Control::new(Profile {
        format_version: 1,
        server,
        machine_id: ID.into(),
        token: TOKEN.into(),
        account_email: None,
        setup_overrides: Default::default(),
        fallback_servers,
        allow_insecure_http_for_tests: true,
    })
}
fn empty(path: &Path) -> Result<bool> {
    Ok(std::fs::read_dir(path)?.next().is_none())
}

#[tokio::test]
async fn authenticated_release_is_streamed_verified_and_staged_without_using_catalog_urls(
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let (fixture, base, server) = fixture().await?;
    let control = control(base, vec![])?;
    let root = common::private_dir()?;
    let cancel = CancellationToken::new();
    let release = update::discover(&control, TARGET, &cancel).await?;
    let staged = update::stage(&control, &release, root.path(), &cancel).await?;
    ensure!(staged.executable.parent().unwrap().file_name().unwrap() == release.sha256.as_str());
    ensure!(std::fs::read(&staged.executable)? == fixture.bytes);
    ensure!(std::fs::metadata(&staged.executable)?.permissions().mode() & 0o777 == 0o755);
    let again = update::stage(&control, &release, root.path(), &cancel).await?;
    ensure!(again.executable == staged.executable && std::fs::read_dir(root.path())?.count() == 1);
    ensure!(fixture.calls.load(Ordering::SeqCst) == 2);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn release_catalog_rejects_foreign_identity_platform_metadata_and_duplicate_targets_before_download(
) -> Result<()> {
    let (fixture, base, server) = fixture().await?;
    let control = control(base, vec![])?;
    let good = catalog(&fixture.bytes);
    for (pointer, value) in [
        ("/machine_id", json!("ffffffffffffffffffffffff")),
        ("/format_version", json!(2)),
        ("/releases/0/os", json!("windows")),
        ("/releases/0/arch", json!("aarch64")),
        ("/releases/0/asset", json!("../../porthub")),
        ("/releases/0/version", json!("version\nwith-control")),
        ("/releases/0/sha256", json!("bad-digest")),
        ("/releases/0/size", json!(0)),
        ("/releases/0/size", json!(256 * 1024 * 1024 + 1u64)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        *fixture.catalog.lock().unwrap() = bad;
        ensure!(
            update::discover(&control, TARGET, &CancellationToken::new())
                .await
                .is_err()
        );
    }
    let mut duplicate = good.clone();
    duplicate["releases"]
        .as_array_mut()
        .unwrap()
        .push(good["releases"][0].clone());
    *fixture.catalog.lock().unwrap() = duplicate;
    ensure!(
        update::discover(&control, TARGET, &CancellationToken::new())
            .await
            .is_err()
    );
    ensure!(fixture.calls.load(Ordering::SeqCst) == 0);
    server.abort();
    Ok(())
}

#[tokio::test]
async fn bad_release_bodies_and_headers_never_publish_executables_or_leave_temporary_files(
) -> Result<()> {
    let (fixture, base, server) = fixture().await?;
    let control = control(base, vec![])?;
    let root = common::private_dir()?;
    let cancel = CancellationToken::new();
    let release = update::discover(&control, TARGET, &cancel).await?;
    for mode in ["corrupt", "short", "large", "metadata"] {
        *fixture.mode.lock().unwrap() = mode;
        let error = update::stage(&control, &release, root.path(), &cancel)
            .await
            .err()
            .unwrap()
            .to_string();
        ensure!(!error.contains(TOKEN) && !error.contains("127.0.0.1"));
        ensure!(empty(root.path())?);
    }
    server.abort();
    Ok(())
}

#[tokio::test]
async fn release_network_failures_and_redirects_use_only_configured_fallbacks_but_authentication_does_not(
) -> Result<()> {
    let (primary, base, a) = fixture().await?;
    let (fallback, other, b) = fixture().await?;
    let control = control(base, vec![other])?;
    let root = common::private_dir()?;
    let cancel = CancellationToken::new();
    let release = update::discover(&control, TARGET, &cancel).await?;
    for mode in ["unavailable", "redirect"] {
        *primary.mode.lock().unwrap() = mode;
        update::stage(&control, &release, root.path(), &cancel).await?;
    }
    ensure!(fallback.calls.load(Ordering::SeqCst) == 2);
    *primary.mode.lock().unwrap() = "forbidden";
    ensure!(update::stage(&control, &release, root.path(), &cancel)
        .await
        .is_err());
    ensure!(fallback.calls.load(Ordering::SeqCst) == 2);
    a.abort();
    b.abort();
    Ok(())
}

#[tokio::test]
async fn release_cancellation_and_unsafe_staging_directories_leave_existing_files_intact(
) -> Result<()> {
    let (fixture, base, server) = fixture().await?;
    let control = control(base, vec![])?;
    let root = common::private_dir()?;
    let cancel = CancellationToken::new();
    let release = update::discover(&control, TARGET, &cancel).await?;
    *fixture.mode.lock().unwrap() = "slow";
    let operation = update::stage(&control, &release, root.path(), &cancel);
    tokio::pin!(operation);
    tokio::select! { result=&mut operation=>{result?;anyhow::bail!("download unexpectedly completed");}, _=tokio::time::sleep(std::time::Duration::from_millis(30))=>{} }
    cancel.cancel();
    ensure!(operation.await.is_err());
    ensure!(empty(root.path())?);
    let link = root.path().join("linked");
    std::os::unix::fs::symlink(root.path(), &link)?;
    ensure!(
        update::stage(&control, &release, &link, &CancellationToken::new())
            .await
            .is_err()
    );
    server.abort();
    Ok(())
}
