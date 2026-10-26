//! Temporary public exposures using the machine credential already installed
//! for the selected PortHub registration.
use anyhow::{bail, ensure, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[derive(Clone, Serialize, Deserialize)]
struct Session {
    id: String,
    pid: u32,
    profile: PathBuf,
    local_port: u16,
    external_port: Option<u16>,
    subdomain: Option<String>,
    status: String,
    exposure_id: Option<String>,
    tcp_url: Option<String>,
    proxy_url: Option<String>,
    message: Option<String>,
}

fn exposure_dir(layout: &crate::service::Layout, create: bool) -> Result<PathBuf> {
    if create {
        fs::create_dir_all(&layout.state)?;
    }
    let path = layout.state.join("exposures");
    if create {
        fs::create_dir_all(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = fs::symlink_metadata(&path)?;
            ensure!(
                metadata.is_dir() && metadata.uid() == rustix::process::getuid().as_raw(),
                "exposure state directory ownership is unsafe"
            );
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(path)
}

fn session_path(layout: &crate::service::Layout, id: &str, create: bool) -> Result<PathBuf> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid exposure ID"
    );
    Ok(exposure_dir(layout, create)?.join(format!("{id}.json")))
}

fn save_session(layout: &crate::service::Layout, session: &Session) -> Result<()> {
    crate::profile::write_private(
        &session_path(layout, &session.id, true)?,
        &serde_json::to_vec_pretty(session)?,
        true,
    )
}

fn load_session(path: &Path) -> Result<Session> {
    let bytes = crate::profile::read_private(path)?;
    let session: Session = serde_json::from_slice(&bytes)?;
    ensure!(session.id.len() == 32 && session.id.bytes().all(|byte| byte.is_ascii_hexdigit()), "invalid exposure state identity");
    Ok(session)
}

fn base_url(server: &str, path: &str) -> String {
    format!("{}/api/{path}", server.trim_end_matches('/'))
}

async fn request(
    client: &reqwest::Client,
    profile: &crate::profile::Profile,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value> {
    let mut last = None;
    for server in std::iter::once(&profile.server).chain(profile.fallback_servers.iter()) {
        let response = match client.post(base_url(server, path)).json(body).send().await {
            Ok(response) => response,
            Err(error) => {
                last = Some(error.without_url().to_string());
                continue;
            }
        };
        let status = response.status();
        let payload: serde_json::Value = response.json().await.unwrap_or_default();
        if status.is_success() {
            return Ok(payload.get("data").cloned().unwrap_or(payload));
        }
        let detail = payload
            .get("detail")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Gateway rejected the exposure request");
        if status.is_server_error() {
            last = Some(detail.to_owned());
            continue;
        }
        bail!("{detail} (HTTP {status})");
    }
    bail!(
        "{}",
        last.unwrap_or_else(|| "Could not reach the PortHub gateway".into())
    )
}

async fn ready_registration(profile_path: &Path, user: bool) -> Result<crate::profile::Profile> {
    let profile = crate::profile::Profile::load(profile_path)?;
    let layout = if user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let manager = crate::service::system_manager(user).await?;
    let state = crate::service::status(&layout, profile_path, manager.as_ref()).await?;
    ensure!(
        state.installed,
        "selected registration has no managed service"
    );
    if !state.active {
        if !user {
            crate::service::require_administrator()?;
        }
        crate::service::action(
            &layout,
            profile_path,
            crate::service::Action::Start,
            manager.as_ref(),
        )
        .await?;
    }
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            if crate::runtime::status(profile_path).is_ok_and(|status| status.state == "running") {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context("PortHub service did not become ready")??;
    Ok(profile)
}

fn state_value(
    profile: &crate::profile::Profile,
    local_port: u16,
    external_port: Option<u16>,
    subdomain: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({"machine_id":profile.machine_id,"token":profile.token,"local_port":local_port,
        "external_port":external_port,"subdomain":subdomain})
}

async fn run_worker(
    layout: crate::service::Layout,
    profile_path: PathBuf,
    id: String,
    local_port: u16,
    external_port: Option<u16>,
    subdomain: Option<String>,
) -> Result<()> {
    let lock_path = exposure_dir(&layout, true)?.join(format!("{id}.lock"));
    let lock = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .context("exposure session already exists")?;
    lock.lock_exclusive()?;
    let profile = crate::profile::Profile::load(&profile_path)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(12))
        .build()?;

    let mut session = Session {
        id: id.clone(),
        pid: std::process::id(),
        profile: profile_path,
        local_port,
        external_port,
        subdomain: subdomain.clone(),
        status: "starting".into(),
        exposure_id: None,
        tcp_url: None,
        proxy_url: None,
        message: None,
    };
    save_session(&layout, &session)?;
    let result = async {
        let mut body = state_value(&profile, local_port, external_port, subdomain.as_deref());
        body["request_id"] = serde_json::json!(id);
        let created = request(&client, &profile, "machines/client/expose", &body).await?;
        session.exposure_id = created.get("exposure_id").and_then(serde_json::Value::as_str).map(str::to_owned);
        ensure!(session.exposure_id.is_some(), "gateway did not return an exposure identity");
        session.external_port = created.get("external_port").and_then(serde_json::Value::as_u64).map(|p| p as u16);
        session.tcp_url = created.get("tcp_url").and_then(serde_json::Value::as_str).map(str::to_owned);
        session.proxy_url = created.get("proxy_url").and_then(serde_json::Value::as_str).map(str::to_owned);
        session.status = "running".into();
        save_session(&layout, &session)?;
        println!("Public TCP: {}", session.tcp_url.as_deref().unwrap_or("unavailable"));
        if let Some(url) = &session.proxy_url { println!("Web address: https://{url} (HTTP is also available)"); }
        println!("Local target: 127.0.0.1:{local_port}");
        println!("Exposure ID: {id}");
        let exposure_id = session.exposure_id.as_deref().context("missing exposure identity")?;
        let stopped = wait_for_stop(&layout, &id);
        let shutdown = wait_shutdown();
        tokio::pin!(stopped, shutdown);
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    request(&client, &profile, "machines/client/expose/renew", &serde_json::json!({"machine_id":profile.machine_id,"token":profile.token,"exposure_id":exposure_id})).await?;
                }
                result = &mut shutdown => { result?; break; }
            }
        }
        request(&client, &profile, "machines/client/expose/close", &serde_json::json!({"machine_id":profile.machine_id,"token":profile.token,"exposure_id":exposure_id})).await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    if let Err(error) = result {
        if let Some(exposure_id) = session.exposure_id.as_deref() {
            let _ = request(&client, &profile, "machines/client/expose/close", &serde_json::json!({"machine_id":profile.machine_id,"token":profile.token,"exposure_id":exposure_id})).await;
        }
        session.status = "failed".into();
        session.message = Some(error.to_string());
        save_session(&layout, &session)?;
        return Err(error);
    }
    let _ = fs::remove_file(session_path(&layout, &id, false)?);
    let _ = fs::remove_file(stop_path(&layout, &id)?);
    let _ = lock.unlock();
    let _ = fs::remove_file(lock_path);
    println!("Temporary exposure closed.");
    Ok(())
}

#[cfg(unix)]
async fn wait_shutdown() -> Result<()> {
    if let Ok(mut signal) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = signal.recv() => {},
        }
    }
    Ok(())
}

fn stop_path(layout: &crate::service::Layout, id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid exposure ID"
    );
    Ok(exposure_dir(layout, false)?.join(format!("{id}.stop")))
}

async fn wait_for_stop(layout: &crate::service::Layout, id: &str) {
    use notify::Watcher;
    let Ok(path) = stop_path(layout, id) else { return; };
    let (send, mut changes) = tokio::sync::mpsc::channel(1);
    let watcher = notify::recommended_watcher(move |_event: notify::Result<notify::Event>| { let _ = send.try_send(()); })
        .ok().and_then(|mut watcher| {
            watcher.watch(path.parent()?, notify::RecursiveMode::NonRecursive).ok()?;
            Some(watcher)
        });
    loop {
        if path.exists() { return; }
        if watcher.is_some() && changes.recv().await.is_some() { continue; }
        // Filesystem notification may be unavailable on a mounted state
        // directory. Keep a low-frequency fallback for that case only.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(not(unix))]
async fn wait_shutdown() -> Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}

fn read_sessions(layout: &crate::service::Layout) -> Result<Vec<Session>> {
    let path = exposure_dir(layout, false)?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    for entry in fs::read_dir(path)?.take(4096) {
        let entry = entry?;
        if entry.path().extension().is_some_and(|ext| ext == "json") {
            if let Ok(session) = load_session(&entry.path()) {
                result.push(session);
            }
        }
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}

pub fn list(layout: &crate::service::Layout) -> Result<()> {
    let sessions = read_sessions(layout)?;
    if sessions.is_empty() {
        println!("No active PortHub exposures.");
        return Ok(());
    }
    println!(
        "{:<12} {:<8} {:<24} {}",
        "EXPOSURE", "STATUS", "PUBLIC TCP", "WEB ADDRESS"
    );
    for session in sessions {
        let status = if session.status == "running" || session.status == "starting" {
            let lock_path = exposure_dir(layout, false)?.join(format!("{}.lock", session.id));
            match OpenOptions::new().read(true).write(true).open(lock_path) {
                Ok(lock) => match lock.try_lock_exclusive() {
                    Ok(()) => "stopped",
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => &session.status,
                    Err(_) => "unknown",
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => "stopped",
                Err(_) => "unknown",
            }
        } else { &session.status };
        println!(
            "{:<12} {:<8} {:<24} {}",
            &session.id[..12],
            status,
            session.tcp_url.as_deref().unwrap_or("starting"),
            session.proxy_url.as_deref().unwrap_or("—")
        );
    }
    Ok(())
}

pub fn stop(layout: &crate::service::Layout, id: &str) -> Result<()> {
    ensure!(
        id.len() >= 8 && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid exposure ID"
    );
    let sessions = read_sessions(layout)?;
    let mut matches = sessions
        .into_iter()
        .filter(|session| session.id.starts_with(id));
    let session = matches.next().context("exposure not found")?;
    ensure!(
        matches.next().is_none(),
        "exposure ID is ambiguous; use more characters"
    );
    let path = session_path(layout, &session.id, false)?;
    let lock_path = exposure_dir(layout, false)?.join(format!("{}.lock", session.id));
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    match lock.try_lock_exclusive() {
        Ok(()) => {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(stop_path(layout, &session.id)?);
            drop(lock);
            let _ = fs::remove_file(lock_path);
            bail!(
                "Exposure process is no longer running; its gateway lease will expire automatically"
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
    }
    crate::profile::write_private(&stop_path(layout, &session.id)?, b"stop\n", true)?;
    println!(
        "Stopping exposure {}; the gateway mapping is being removed…",
        &session.id[..12]
    );
    Ok(())
}

pub async fn start(
    layout: crate::service::Layout,
    profile_path: PathBuf,
    local_port: u16,
    external_port: Option<u16>,
    subdomain: Option<String>,
    detach: bool,
) -> Result<()> {
    ensure!(local_port > 0, "local port must be from 1 to 65535");
    let _profile = ready_registration(&profile_path, layout.user).await?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    if !detach {
        return run_worker(
            layout,
            profile_path,
            id,
            local_port,
            external_port,
            subdomain,
        )
        .await;
    }
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["expose", &local_port.to_string(), "--worker"])
        .arg("--profile")
        .arg(&profile_path)
        .arg("--session-id")
        .arg(&id);
    if layout.user {
        command.arg("--user");
    }
    if let Some(port) = external_port {
        command.arg("--port").arg(port.to_string());
    }
    if let Some(domain) = &subdomain {
        command.arg("--subdomain").arg(domain);
    }
    command.stdin(Stdio::null());
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(exposure_dir(&layout, true)?.join(format!("{id}.log")))?;
    command
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x00000200 | 0x00000008); // DETACHED_PROCESS | DETACHED_PROCESS_GROUP
    }
    let child = command
        .spawn()
        .context("could not start detached PortHub exposure")?;
    drop(child);
    let path = session_path(&layout, &id, false)?;
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(session) = load_session(&path) {
                if session.status == "running" {
                    return Ok::<Session, anyhow::Error>(session);
                }
                if session.status == "failed" {
                    bail!(
                        "background exposure failed: {}",
                        session.message.as_deref().unwrap_or("unknown error")
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .context(
        "background exposure did not become ready; run `porthub expose list` to check its status",
    )??;
    println!(
        "Public TCP: {}",
        ready.tcp_url.as_deref().unwrap_or("unavailable")
    );
    if let Some(url) = &ready.proxy_url {
        println!("Web address: https://{url} (HTTP is also available)");
    }
    println!("Local target: 127.0.0.1:{local_port}");
    println!("Exposure ID: {}", &id[..12]);
    println!("Stop with: porthub expose stop {}", &id[..12]);
    Ok(())
}

pub async fn worker(
    layout: crate::service::Layout,
    profile: PathBuf,
    id: String,
    local_port: u16,
    port: Option<u16>,
    subdomain: Option<String>,
) -> Result<()> {
    let registered = crate::service::registrations(&layout)?
        .into_iter()
        .any(|entry| entry.spec.profile == profile);
    ensure!(
        registered,
        "exposure worker profile is not an installed registration"
    );
    run_worker(layout, profile, id, local_port, port, subdomain).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    #[tokio::test]
    async fn worker_uses_installed_credentials_and_stop_removes_gateway_mapping() -> Result<()> {
        use axum::{routing::post, Json, Router};
        let closed = Arc::new(AtomicUsize::new(0));
        let count = closed.clone();
        let router = Router::new()
            .route("/api/machines/client/expose", post(|Json(body): Json<serde_json::Value>| async move {
                assert_eq!(body["token"], "test-only-token");
                assert_eq!(body["machine_id"], "0123456789abcdef01234567");
                assert_eq!(body["local_port"], 8000);
                assert_eq!(body["request_id"].as_str().unwrap().len(), 32);
                Json(serde_json::json!({"data":{"exposure_id":"test-exposure","external_port":31000,"tcp_url":"gateway.invalid:31000"}}))
            }))
            .route("/api/machines/client/expose/close", post(move |Json(body): Json<serde_json::Value>| {
                let count = count.clone();
                async move {
                    assert_eq!(body["token"], "test-only-token");
                    assert_eq!(body["exposure_id"], "test-exposure");
                    count.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"data":{"closed":true}}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let server = format!("http://{}", listener.local_addr()?);
        let gateway = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        let directory = tempfile::tempdir()?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let layout = crate::service::Layout { user: true, state: directory.path().join("state"), releases: directory.path().join("releases"), units: directory.path().join("units") };
        let profile = directory.path().join("profile.json");
        crate::profile::write_private(&profile, &serde_json::to_vec(&serde_json::json!({"server":server,"machine_id":"0123456789abcdef01234567","token":"test-only-token","allow_insecure_http_for_tests":true}))?, false)?;
        let id = uuid::Uuid::new_v4().simple().to_string();
        let worker = tokio::spawn(run_worker(layout.clone(), profile, id.clone(), 8000, None, None));
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if load_session(&session_path(&layout, &id, false)?).is_ok_and(|session| session.status == "running") { return Ok::<_, anyhow::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        stop(&layout, &id[..12])?;
        tokio::time::timeout(Duration::from_secs(3), worker).await???;
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        assert!(read_sessions(&layout)?.is_empty());
        assert!(!stop_path(&layout, &id)?.exists());
        assert!(!exposure_dir(&layout, false)?.join(format!("{id}.lock")).exists());
        gateway.abort();
        Ok(())
    }

    #[test]
    fn malformed_state_does_not_crash_list_or_match_a_stop_request() -> Result<()> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let path = directory.path().join("bad.json");
        crate::profile::write_private(&path, br#"{"id":"x","pid":1,"profile":"/unused","local_port":8000,"external_port":null,"subdomain":null,"status":"running","exposure_id":null,"tcp_url":null,"proxy_url":null,"message":null}"#, false)?;
        assert!(load_session(&path).is_err());
        Ok(())
    }
}
