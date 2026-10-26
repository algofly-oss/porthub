//! Event-driven directory synchronization and per-user managed background jobs.
use crate::{state, upload};
use anyhow::{bail, ensure, Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use notify::{EventKind, RecursiveMode, Watcher};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::RwLock};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Dirty {
    full: bool,
    paths: BTreeSet<PathBuf>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Options {
    pub path: PathBuf,
    pub url: String,
    pub connections: usize,
    pub contents_only: bool,
    pub force: bool,
}
impl Options {
    pub fn validate(&mut self) -> Result<()> {
        ensure!(
            !std::fs::symlink_metadata(&self.path)?.is_symlink(),
            "watch source cannot be a symlink"
        );
        self.path = std::fs::canonicalize(&self.path)?;
        ensure!(self.path.is_dir(), "--watch requires a directory");
        let url = reqwest::Url::parse(&self.url)?;
        ensure!(
            matches!(url.scheme(), "http" | "https") && url.host_str().is_some(),
            "destination must be an HTTP or HTTPS URL"
        );
        // A receiver must never generate events within its own source tree via
        // checkpoints or registration writes.
        let jobs = std::fs::canonicalize(state::directory("sync-jobs")?)?;
        ensure!(
            !jobs.starts_with(&self.path),
            "PortHub state directory must be outside the watched source"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    options: Options,
    token: String,
    control: Option<SocketAddr>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Status {
    pub id: String,
    pub source: PathBuf,
    pub destination: String,
    pub state: String,
    pub completed_runs: u64,
    pub last_success_unix: Option<u64>,
    pub message: String,
}
#[derive(Clone)]
struct Control {
    token: String,
    cancel: CancellationToken,
    status: Arc<RwLock<Status>>,
}
fn authorized(headers: &HeaderMap, control: &Control) -> bool {
    headers.get("authorization").and_then(|v| v.to_str().ok())
        == Some(format!("Bearer {}", control.token).as_str())
}
async fn status_handler(
    State(control): State<Control>,
    headers: HeaderMap,
) -> Result<Json<Status>, StatusCode> {
    if !authorized(&headers, &control) {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(Json(control.status.read().await.clone()))
}
async fn stop_handler(State(control): State<Control>, headers: HeaderMap) -> StatusCode {
    if !authorized(&headers, &control) {
        return StatusCode::FORBIDDEN;
    }
    control.cancel.cancel();
    StatusCode::NO_CONTENT
}
fn random() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn record_path(id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 16 && id.bytes().all(|v| v.is_ascii_hexdigit()),
        "invalid sync job ID"
    );
    Ok(state::directory("sync-jobs")?.join(format!("{id}.json")))
}
fn read_record(id: &str) -> Result<Record> {
    let path = record_path(id)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && !metadata.is_symlink() && metadata.len() <= 64 * 1024,
        "invalid sync job record"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "sync job record must be private"
        );
    }
    let record: Record = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(
        record
            .control
            .is_none_or(|address| address.ip().is_loopback()),
        "invalid sync control address"
    );
    Ok(record)
}
struct Registration {
    id: String,
    token: String,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if read_record(&self.id).is_ok_and(|record| record.token == self.token) {
            if let Ok(path) = record_path(&self.id) {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}
fn sanitized_url(value: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(value) else {
        return "invalid destination".into();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}
fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?)
}
pub async fn status(id: &str) -> Result<Status> {
    let record = read_record(id)?;
    let address = record.control.context("sync job has not started")?;
    Ok(client()?
        .get(format!("http://{address}/status"))
        .bearer_auth(record.token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}
pub async fn list() -> Result<Vec<Status>> {
    let mut result = Vec::new();
    for entry in std::fs::read_dir(state::directory("sync-jobs")?)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().is_none_or(|v| v != "json") {
            continue;
        }
        if let Some(id) = path.file_stem().and_then(|v| v.to_str()) {
            if let Ok(value) = status(id).await {
                result.push(value);
            }
        }
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}
pub async fn stop(id: &str) -> Result<()> {
    let record = read_record(id)?;
    let address = record.control.context("sync job has not started")?;
    client()?
        .post(format!("http://{address}/stop"))
        .bearer_auth(record.token)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Start a separate session without forwarding URL credentials in process args.
pub async fn detach(mut options: Options) -> Result<String> {
    options.validate()?;
    let id = random()[..16].to_owned();
    let token = random();
    let path = record_path(&id)?;
    state::write_private(
        &path,
        &serde_json::to_vec(&Record {
            options,
            token: token.clone(),
            control: None,
        })?,
    )?;
    let registration = Registration {
        id: id.clone(),
        token,
    };
    let mut command = std::process::Command::new(std::env::current_exe()?);
    command
        .args(["sync", "run", &id])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // The only pre-exec operation is async-signal-safe setsid.
        unsafe {
            command.pre_exec(|| {
                if rustix::process::setsid().is_err() {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000008 | 0x00000200); // DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    }
    let mut child = command.spawn().context("cannot start detached sync job")?;
    for _ in 0..100 {
        if status(&id).await.is_ok() {
            let mut registration = registration;
            registration.token.clear(); // The worker now owns cleanup.
                                        // Reap the child when it exits without keeping the parent alive.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(id);
        }
        if let Some(exit) = child.try_wait()? {
            bail!("sync worker exited during startup ({exit})");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let _ = child.kill();
    let _ = child.wait();
    bail!("sync worker did not become ready")
}

pub async fn worker(id: String, cancel: CancellationToken) -> Result<()> {
    let record = read_record(&id)?;
    ensure!(record.control.is_none(), "sync job is already running");
    run_registered(id, record, cancel).await
}
pub async fn watch(mut options: Options, cancel: CancellationToken) -> Result<()> {
    options.validate()?;
    run_registered(
        random()[..16].to_owned(),
        Record {
            options,
            token: random(),
            control: None,
        },
        cancel,
    )
    .await
}
async fn run_registered(id: String, mut record: Record, cancel: CancellationToken) -> Result<()> {
    record.options.validate()?;
    let (events, mut receiver) = tokio::sync::mpsc::channel::<()>(1);
    let dirty = Arc::new(Mutex::new(Dirty {
        full: true,
        paths: BTreeSet::new(),
    }));
    let changes = dirty.clone();
    let watched_root = record.options.path.clone();
    let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
        if matches!(event, Ok(ref event) if matches!(event.kind, EventKind::Access(_))) {
            return;
        }
        let mut dirty = changes.lock().unwrap_or_else(|error| error.into_inner());
        match event {
            Ok(event) if !event.need_rescan() && !event.paths.is_empty() => {
                for path in event.paths {
                    if path == watched_root {
                        dirty.full = true;
                    } else if path.starts_with(&watched_root) && !dirty.full {
                        dirty.paths.insert(path);
                    }
                }
                if dirty.paths.len() > 1024 {
                    dirty.full = true;
                }
            }
            _ => dirty.full = true,
        }
        if dirty.full {
            dirty.paths.clear();
        }
        if dirty.full || !dirty.paths.is_empty() {
            let _ = events.try_send(());
        }
    })?;
    watcher.watch(&record.options.path, RecursiveMode::Recursive)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    record.control = Some(listener.local_addr()?);
    let state = Arc::new(RwLock::new(Status {
        id: id.clone(),
        source: record.options.path.clone(),
        destination: sanitized_url(&record.options.url),
        state: "syncing".into(),
        completed_runs: 0,
        last_success_unix: None,
        message: "Initial sync".into(),
    }));
    let app = Router::new()
        .route("/status", get(status_handler))
        .route("/stop", post(stop_handler))
        .with_state(Control {
            token: record.token.clone(),
            cancel: cancel.clone(),
            status: state.clone(),
        });
    state::write_private(&record_path(&id)?, &serde_json::to_vec(&record)?)?;
    let _registration = Registration {
        id: id.clone(),
        token: record.token.clone(),
    };
    let server_cancel = cancel.clone();
    let control = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(server_cancel.cancelled_owned())
            .await;
    });
    eprintln!(
        "Watching {} (job {id}); Ctrl-C or porthub sync stop {id} to stop",
        record.options.path.display()
    );
    let result = sync_loop(
        &record.options,
        state,
        &mut receiver,
        &mut watcher,
        dirty,
        cancel.clone(),
    )
    .await;
    cancel.cancel();
    let _ = control.await;
    drop(watcher);
    result
}
async fn sync_loop(
    options: &Options,
    state: Arc<RwLock<Status>>,
    events: &mut tokio::sync::mpsc::Receiver<()>,
    watcher: &mut notify::RecommendedWatcher,
    dirty: Arc<Mutex<Dirty>>,
    cancel: CancellationToken,
) -> Result<()> {
    let mut retry = Duration::from_secs(5);
    loop {
        let changes = {
            let mut dirty = dirty.lock().unwrap_or_else(|error| error.into_inner());
            while events.try_recv().is_ok() {}
            std::mem::take(&mut *dirty)
        };
        if !changes.full && changes.paths.is_empty() {
            tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = events.recv() => {} }
            continue;
        }
        state.write().await.state = "syncing".into();
        // Reattach on a full recovery pass: a deleted/recreated source root
        // must not leave a watcher attached to its old inode.
        let watching = if changes.full {
            let _ = watcher.unwatch(&options.path);
            watcher.watch(&options.path, RecursiveMode::Recursive)
        } else {
            Ok(())
        };
        let result = if let Err(error) = watching {
            Err(error.into())
        } else {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Ok(()),
                result = async {
                    if changes.full {
                        upload::put_path(options.path.clone(), options.url.clone(), options.connections, options.contents_only, options.force).await
                    } else {
                        upload::put_changed_paths(options.path.clone(), options.url.clone(), options.connections, options.contents_only, options.force, changes.paths.into_iter().collect()).await
                    }
                } => result,
            }
        };
        let delay = {
            let mut status = state.write().await;
            match result {
                Ok(message) => {
                    status.state = "watching".into();
                    status.completed_runs += 1;
                    status.last_success_unix =
                        Some(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
                    status.message = message;
                    eprintln!("{}", status.message);
                    retry = Duration::from_secs(5);
                    None
                }
                Err(_) => {
                    dirty.lock().unwrap_or_else(|error| error.into_inner()).full = true;
                    // Transport errors can include credentials or origin URLs.
                    status.state = "retrying".into();
                    status.message =
                        format!("Sync incomplete; resume in {} seconds", retry.as_secs());
                    eprintln!("{}", status.message);
                    let delay = retry;
                    retry = (retry * 2).min(Duration::from_secs(60));
                    Some(delay)
                }
            }
        };
        if let Some(delay) = delay {
            // Local events must not defeat network backoff.
            tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(delay) => {} }
        } else {
            tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = events.recv() => {} }
            // Debounce writes, but bound the delay during continuous changes.
            let maximum = tokio::time::sleep(Duration::from_secs(2));
            tokio::pin!(maximum);
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = &mut maximum => break,
                    _ = tokio::time::sleep(Duration::from_millis(500)) => break,
                    _ = events.recv() => {},
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_never_exposes_url_credentials_or_query() {
        assert_eq!(
            sanitized_url("http://user:secret@peer:8001/folder/?token=private#secret"),
            "http://peer:8001/folder/"
        );
        for id in ["../escape", "", "0123456789abcdeg"] {
            assert!(record_path(id).is_err());
        }
    }
    #[tokio::test]
    async fn control_requires_capability_and_stop_cancels_upload() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let options = Options {
            path: directory.path().to_owned(),
            url: "http://127.0.0.1:1/nested/".into(),
            connections: 16,
            contents_only: false,
            force: false,
        };
        let cancel = CancellationToken::new();
        let task = tokio::spawn(watch(options, cancel.clone()));
        let job = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(job) = list()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|job| job.source == directory.path())
                {
                    break job;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        let record = read_record(&job.id)?;
        let response = client()?
            .post(format!("http://{}/stop", record.control.unwrap()))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!cancel.is_cancelled());
        stop(&job.id).await?;
        tokio::time::timeout(Duration::from_secs(2), task).await???;
        assert!(status(&job.id).await.is_err());
        Ok(())
    }
}
