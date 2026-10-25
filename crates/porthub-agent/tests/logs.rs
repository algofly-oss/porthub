use anyhow::{ensure, Result};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use porthub_agent::{
    control::Control,
    logs::{self, Buffer},
    profile::Profile,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::Write,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::fmt::MakeWriter;
const ID: &str = "0123456789abcdef01234567";
const TOKEN: &str = "private-agent-log-token";
fn profile(server: String) -> Profile {
    Profile {
        format_version: 1,
        server,
        machine_id: ID.into(),
        token: TOKEN.into(),
        account_email: None,
        setup_overrides: Default::default(),
        fallback_servers: vec![],
        allow_insecure_http_for_tests: true,
    }
}
fn options() -> logs::Options {
    logs::Options {
        poll: Duration::from_millis(30),
        flush: Duration::from_millis(20),
        max_retry: Duration::from_millis(120),
    }
}
async fn until(mut check: impl FnMut() -> bool) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !check() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?;
    Ok(())
}
#[derive(Default)]
struct StateData {
    active: AtomicBool,
    wrong_id: AtomicBool,
    gone: AtomicBool,
    polls: AtomicUsize,
    failures: AtomicUsize,
    attempts: Mutex<Vec<(Instant, Value)>>,
    delivered: Mutex<Vec<Value>>,
}
struct Mock {
    state: Arc<StateData>,
    control: Arc<Control>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn status(
    State(state): State<Arc<StateData>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    assert_eq!(query["machine_id"], ID);
    assert_eq!(query["token"], TOKEN);
    state.polls.fetch_add(1, Ordering::SeqCst);
    if state.gone.load(Ordering::SeqCst) {
        return StatusCode::GONE.into_response();
    }
    let active = state.active.load(Ordering::SeqCst);
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-porthub-machine-id",
        if state.wrong_id.load(Ordering::SeqCst) {
            "ffffffffffffffffffffffff"
        } else {
            ID
        }
        .parse()
        .unwrap(),
    );
    headers.insert(
        "x-porthub-log-stream-active",
        if active { "true" } else { "false" }.parse().unwrap(),
    );
    headers.insert("x-porthub-machine-auth-required", "true".parse().unwrap());
    (headers, Json(json!({"active":active}))).into_response()
}
async fn upload(State(state): State<Arc<StateData>>, Json(body): Json<Value>) -> Response {
    assert_eq!(body["machine_id"], ID);
    assert_eq!(body["token"], TOKEN);
    assert_eq!(body["source"], "agent");
    assert!(body["lines"].as_array().unwrap().len() <= 100);
    state
        .attempts
        .lock()
        .unwrap()
        .push((Instant::now(), body.clone()));
    if state
        .failures
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
            left.checked_sub(1)
        })
        .is_ok()
    {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let count = body["lines"].as_array().unwrap().len();
    state.delivered.lock().unwrap().push(body);
    Json(json!({"data":{"machine_id":ID,"count":count}})).into_response()
}
impl Mock {
    async fn new() -> Result<Self> {
        let state = Arc::new(StateData::default());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let control = Arc::new(Control::new(profile(format!(
            "http://{}",
            listener.local_addr()?
        )))?);
        let router = Router::new()
            .route("/api/machines/client/sync",post(|Json(body):Json<Value>|async move {
                assert_eq!(body["machine_id"],ID);assert_eq!(body["token"],TOKEN);
                Json(json!({"data":{"config":{"machine_id":ID,"version":"logs-test",
                    "files":{"client.toml":"[client]\nremote_addr='ws://127.0.0.1:9/api/tunnel'\n"}}}}))
            }))
            .route("/api/machines/client/changes.toml",get(||async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let mut headers=HeaderMap::new();headers.insert("x-porthub-machine-id",ID.parse().unwrap());
                (StatusCode::NO_CONTENT,headers)
            }))
            .route("/api/machines/client/log-stream", get(status))
            .route("/api/machines/client/logs", post(upload))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok(Self {
            state,
            control,
            server,
        })
    }
    fn delivered(&self) -> Vec<Value> {
        self.state.delivered.lock().unwrap().clone()
    }
}

#[test]
fn diagnostic_redaction_precedes_truncation_and_retention() {
    let buffer = Buffer::default();
    let mut p = profile("https://gateway.example".into());
    p.token = "private?&\"\\secret".into();
    buffer.configure(&p);
    let escaped = serde_json::to_string(&p.token).unwrap();
    let percent: String = url::form_urlencoded::byte_serialize(p.token.as_bytes()).collect();
    buffer.record(&format!("failed token={} escaped={} encoded={} host=gateway.example URL=HTTPS://user:other@gateway.example/path?token={} local=192.168.80.118:123 v6=[2001:db8::1]:443 scoped=fe80::1%eth0\u{1b}[31m",p.token,escaped,percent,p.token));
    let text = buffer.batch(None, 3, 100).lines.join("\n");
    for hidden in [
        &p.token,
        &escaped[1..escaped.len() - 1],
        &percent,
        "gateway.example",
        "192.168.80.118",
        "2001:db8::1",
        "fe80::1",
        "other",
        "\\secret",
        "\u{1b}",
    ] {
        assert!(!text.contains(hidden), "diagnostic was not fully redacted");
    }
    assert!(
        text.contains("failed token=[redacted]")
            && text.contains("[endpoint]")
            && text.contains("[address]")
    );
    buffer.record(&"😀".repeat(4100));
    // Oversized raw events are omitted completely rather than exposing a
    // credential split at a truncation boundary.
    assert_eq!(
        buffer.batch(None, 1, 1).lines[0],
        "diagnostic event omitted (size limit)"
    );
    buffer.record(&"é".repeat(4100));
    assert_eq!(buffer.batch(None, 1, 1).lines[0].chars().count(), 4000);
}

#[test]
fn writer_joins_partial_writes_and_bounds_raw_events_before_console_output() -> Result<()> {
    let buffer = Buffer::default();
    buffer.configure(&profile("https://gateway.example".into()));
    {
        let mut writer = buffer.make_writer();
        writer.write_all(b"token=private-agent-")?;
        writer.write_all(b"log-token URL=https://gateway.example/private\n")?;
    }
    let text = buffer.batch(None, 1, 1).lines.join("\n");
    ensure!(text == "token=[redacted] URL=[endpoint]");
    {
        let mut writer = buffer.make_writer();
        writer.write_all(b"token=private-agent-")?;
        writer.write_all(&vec![b'x'; 17 * 1024])?;
    }
    ensure!(buffer.batch(None, 1, 1).lines[0] == "diagnostic event omitted (size limit)");
    Ok(())
}

#[test]
fn ring_bounds_bytes_lines_and_cursor_batches_while_preserving_recent_context() {
    let buffer = Buffer::default();
    for i in 0..1000 {
        buffer.record(&format!("{i} {}", "é".repeat(1000)));
    }
    let mut cursor = Some(0);
    let mut retained = Vec::new();
    loop {
        let batch = buffer.batch(cursor, 3, 100);
        if batch.lines.is_empty() {
            break;
        }
        cursor = Some(batch.next);
        retained.extend(batch.lines);
    }
    assert!(retained.len() <= 256 && retained.iter().map(String::len).sum::<usize>() <= 128 * 1024);
    assert!(retained.last().unwrap().starts_with("999 "));
    assert_eq!(buffer.batch(None, 3, 100).lines.len(), 3);
    assert!(buffer.batch(cursor, 3, 100).lines.is_empty());
    buffer.record("new event");
    assert_eq!(buffer.batch(cursor, 3, 100).lines, ["new event"]);
}

#[tokio::test]
async fn uploads_are_demand_driven_resubscription_uses_tail_and_cancellation_stops_polling(
) -> Result<()> {
    let mock = Mock::new().await?;
    let buffer = Buffer::default();
    buffer.configure(mock.control.profile());
    for i in 0..6 {
        buffer.record(&format!("old {i}"));
    }
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(logs::run(
        mock.control.clone(),
        buffer.clone(),
        cancel.clone(),
        options(),
    ));
    until(|| mock.state.polls.load(Ordering::SeqCst) >= 3).await?;
    ensure!(mock.delivered().is_empty());
    mock.state.active.store(true, Ordering::SeqCst);
    until(|| !mock.delivered().is_empty()).await?;
    ensure!(mock.delivered()[0]["lines"] == json!(["old 3", "old 4", "old 5"]));
    buffer.record(&format!("live {TOKEN} 10.1.2.3"));
    until(|| mock.delivered().len() >= 2).await?;
    ensure!(mock.delivered()[1]["lines"] == json!(["live [redacted] [address]"]));
    mock.state.active.store(false, Ordering::SeqCst);
    let before = mock.state.polls.load(Ordering::SeqCst);
    until(|| mock.state.polls.load(Ordering::SeqCst) >= before + 2).await?;
    let delivered = mock.delivered().len();
    buffer.record("retained while no viewer");
    let before = mock.state.polls.load(Ordering::SeqCst);
    until(|| mock.state.polls.load(Ordering::SeqCst) >= before + 2).await?;
    ensure!(mock.delivered().len() == delivered);
    mock.state.active.store(true, Ordering::SeqCst);
    until(|| mock.delivered().len() > delivered).await?;
    ensure!(mock.delivered().last().unwrap()["lines"]
        .as_array()
        .unwrap()
        .iter()
        .any(|line| line == "retained while no viewer"));
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), worker).await??;
    let polls = mock.state.polls.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(70)).await;
    ensure!(mock.state.polls.load(Ordering::SeqCst) == polls);
    Ok(())
}

#[tokio::test]
async fn wrong_machine_status_cannot_enable_upload_and_upload_failures_back_off_without_losing_pending_batch(
) -> Result<()> {
    let mock = Mock::new().await?;
    mock.state.active.store(true, Ordering::SeqCst);
    mock.state.wrong_id.store(true, Ordering::SeqCst);
    let buffer = Buffer::default();
    buffer.record("initial diagnostic");
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(logs::run(
        mock.control.clone(),
        buffer.clone(),
        cancel.clone(),
        options(),
    ));
    until(|| mock.state.polls.load(Ordering::SeqCst) >= 2).await?;
    ensure!(mock.delivered().is_empty());
    mock.state.failures.store(3, Ordering::SeqCst);
    mock.state.wrong_id.store(false, Ordering::SeqCst);
    until(|| !mock.state.attempts.lock().unwrap().is_empty()).await?;
    buffer.record("newer diagnostic");
    until(|| mock.delivered().len() >= 2).await?;
    {
        let times = mock.state.attempts.lock().unwrap();
        ensure!(times.len() >= 5);
        ensure!(times[1].0.duration_since(times[0].0) >= Duration::from_millis(29));
        ensure!(
            times[2].0.duration_since(times[1].0) >= Duration::from_millis(59),
            "successful demand polls must not reset upload backoff"
        );
        ensure!(times[0].1["lines"] == times[3].1["lines"]);
    }
    ensure!(mock.delivered()[0]["lines"] == json!(["initial diagnostic"]));
    ensure!(mock.delivered()[1]["lines"] == json!(["newer diagnostic"]));
    cancel.cancel();
    worker.await?;
    Ok(())
}

#[tokio::test]
async fn deleted_registration_stops_log_worker_and_dropping_owner_cancels_a_stalled_request(
) -> Result<()> {
    let mock = Mock::new().await?;
    mock.state.gone.store(true, Ordering::SeqCst);
    tokio::time::timeout(
        Duration::from_secs(1),
        logs::run(
            mock.control.clone(),
            Buffer::default(),
            CancellationToken::new(),
            options(),
        ),
    )
    .await?;
    ensure!(mock.state.polls.load(Ordering::SeqCst) == 1);
    let started = Arc::new(tokio::sync::Notify::new());
    let notify = started.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let control = Arc::new(Control::new(profile(format!(
        "http://{}",
        listener.local_addr()?
    )))?);
    let router = Router::new().fallback(move || {
        let notify = notify.clone();
        async move {
            notify.notify_one();
            std::future::pending::<StatusCode>().await
        }
    });
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let cancel = CancellationToken::new();
    let guard = logs::Guard::start(control, Buffer::default(), cancel.clone());
    tokio::time::timeout(Duration::from_secs(1), started.notified()).await?;
    drop(guard);
    ensure!(cancel.is_cancelled());
    server.abort();
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn actual_cli_captures_runtime_logs_uploads_on_demand_and_redacts_debug_console_output(
) -> Result<()> {
    use std::process::{Child, Command, Stdio};
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    let mock = Mock::new().await?;
    mock.state.active.store(true, Ordering::SeqCst);
    let directory = super_private_dir()?;
    let path = directory.path().join("machine.json");
    mock.control.profile().save_new(&path)?;
    let stdout_path = directory.path().join("stdout");
    let stderr_path = directory.path().join("stderr");
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_porthub"))
            .args(["run", "--profile"])
            .arg(&path)
            .env("RUST_LOG", "debug")
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&stdout_path)?)
            .stderr(std::fs::File::create(&stderr_path)?)
            .spawn()?,
    );
    until(|| {
        mock.delivered().iter().any(|batch| {
            batch["lines"].as_array().unwrap().iter().any(|line| {
                line.as_str()
                    .unwrap()
                    .contains("machine configuration applied")
            })
        })
    })
    .await?;
    // Stop only this child, exercising the binary's native signal cancellation.
    ensure!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) } == 0);
    until(|| child.0.try_wait().ok().flatten().is_some()).await?;
    ensure!(child.0.try_wait()?.unwrap().success());
    let stdout = std::fs::read_to_string(stdout_path)?;
    let stderr = std::fs::read_to_string(stderr_path)?;
    ensure!(stdout.contains("machine configuration applied"));
    for output in [&stdout, &stderr] {
        ensure!(
            !output.contains(TOKEN)
                && !output.contains("127.0.0.1")
                && !output.contains(&mock.control.profile().server)
        );
    }
    for batch in mock.delivered() {
        for line in batch["lines"].as_array().unwrap() {
            ensure!(
                !line.as_str().unwrap().contains(TOKEN)
                    && !line.as_str().unwrap().contains("127.0.0.1")
            );
        }
    }
    Ok(())
}
#[cfg(unix)]
fn super_private_dir() -> Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    Ok(tempfile::Builder::new()
        .prefix("porthub-log-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?)
}
