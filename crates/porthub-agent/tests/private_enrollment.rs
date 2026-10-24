#![cfg(unix)]
use axum::{
    extract::State,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use porthub_agent::private_profile::{self, Profile, Source};
use serde_json::{json, Value};
use std::{
    os::unix::fs::PermissionsExt,
    process::Stdio,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio_util::sync::CancellationToken;
const WORKSPACE: &str = "0123456789abcdef01234567";
const MACHINE: &str = "abcdef0123456789abcdef01";
const TICKET: &str = "fixture-private-ticket-0123456789abcdef";
const TOKEN: &str = "fixture-private-credential-0123456789abcdef";
struct Fixture {
    server: String,
    claims: AtomicUsize,
    mode: AtomicUsize,
}
async fn metadata(State(state): State<Arc<Fixture>>) -> Response {
    if state.mode.load(Ordering::SeqCst) == 1 {
        return (
            axum::http::StatusCode::FOUND,
            [(header::LOCATION, "/other")],
        )
            .into_response();
    }
    let mut body = json!({"format_version":1,"kind":"private","server":state.server,"peer_id":format!("{WORKSPACE}:{MACHINE}"),"workspace":WORKSPACE,"ticket":TICKET,"fallback_servers":[]});
    if state.mode.load(Ordering::SeqCst) == 2 {
        body["workspace"] = json!("wrong-workspace");
    }
    let mut response = Json(body).into_response();
    response
        .headers_mut()
        .insert("x-porthub-machine-id", HeaderValue::from_static(MACHINE));
    response
}
async fn bootstrap(State(state): State<Arc<Fixture>>, Json(body): Json<Value>) -> Json<Value> {
    assert_eq!(body["ticket"], TICKET);
    state.claims.fetch_add(1, Ordering::SeqCst);
    Json(json!({"peer_id":format!("{WORKSPACE}:{MACHINE}"),"workspace":WORKSPACE,"token":TOKEN}))
}
async fn fixture() -> (Arc<Fixture>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let state = Arc::new(Fixture {
        server: format!("http://{}", listener.local_addr().unwrap()),
        claims: AtomicUsize::new(0),
        mode: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/install/fixture", get(metadata))
        .route("/api/access/private/bootstrap", post(bootstrap))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (state, task)
}
fn directory() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

#[tokio::test]
async fn private_enrollment_stores_go_compatible_private_profile_without_replacing_files() {
    let (fixture, task) = fixture().await;
    let directory = directory();
    let path = directory.path().join("private.json");
    let cancel = CancellationToken::new();
    let link = format!("{}/install/fixture", fixture.server);
    private_profile::enroll(Source::Link(&link), Some(&path), true, true, &cancel)
        .await
        .unwrap();
    let profile = Profile::load(&path).unwrap();
    assert_eq!(profile.token, TOKEN);
    assert_eq!(profile.workspace, WORKSPACE);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let bytes = std::fs::read(&path).unwrap();
    let saved: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(saved.get("format_version").is_none());
    assert!(!format!("{profile:?}").contains(TOKEN));
    assert!(!format!("{profile:?}").contains("127.0.0.1"));
    assert!(
        private_profile::enroll(Source::Link(&link), Some(&path), true, true, &cancel)
            .await
            .is_err()
    );
    assert_eq!(fixture.claims.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    task.abort();
}

#[tokio::test]
async fn private_enrollment_rejects_bad_metadata_redirects_and_unsafe_destinations_before_claiming()
{
    let (fixture, task) = fixture().await;
    let directory = directory();
    let path = directory.path().join("private.json");
    let cancel = CancellationToken::new();
    let link = format!("{}/install/fixture", fixture.server);
    for mode in [1, 2] {
        fixture.mode.store(mode, Ordering::SeqCst);
        assert!(
            private_profile::enroll(Source::Link(&link), Some(&path), true, true, &cancel)
                .await
                .is_err()
        );
    }
    fixture.mode.store(0, Ordering::SeqCst);
    assert!(
        private_profile::enroll(Source::Link(&link), Some(&path), true, false, &cancel)
            .await
            .is_err()
    );
    std::os::unix::fs::symlink(directory.path().join("missing"), &path).unwrap();
    assert!(
        private_profile::enroll(Source::Link(&link), Some(&path), true, true, &cancel)
            .await
            .is_err()
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        private_profile::enroll(Source::Link(&link), Some(&path), true, true, &cancel)
            .await
            .is_err()
    );
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    cancel.cancel();
    assert!(
        private_profile::enroll(Source::Link(&link), Some(&path), true, true, &cancel)
            .await
            .is_err()
    );
    assert_eq!(fixture.claims.load(Ordering::SeqCst), 0);
    task.abort();
}

#[tokio::test]
async fn actual_cli_enroll_reads_long_ticket_from_stdin_and_keeps_logs_clean() {
    use tokio::io::AsyncWriteExt;
    let (fixture, task) = fixture().await;
    let directory = directory();
    let path = directory.path().join("private.json");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_porthub"))
        .arg("enroll")
        .arg("--server")
        .arg(&fixture.server)
        .arg("--profile")
        .arg(&path)
        .arg("--allow-insecure-http-for-tests")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(TICKET.as_bytes())
        .await
        .unwrap();
    let output = child.wait_with_output().await.unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [TOKEN, TICKET, "127.0.0.1"] {
        assert!(!text.contains(secret));
    }
    assert!(text.contains("not activated"));
    assert_eq!(Profile::load(&path).unwrap().token, TOKEN);
    task.abort();
}
