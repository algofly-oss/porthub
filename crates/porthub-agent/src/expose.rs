//! Temporary public exposures using the machine credential already installed
//! for the selected PortHub registration.
use anyhow::{bail, ensure, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
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
    ensure!(
        session.id.len() == 32 && session.id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid exposure state identity"
    );
    Ok(session)
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
    let Ok(path) = stop_path(layout, id) else {
        return;
    };
    let (send, mut changes) = tokio::sync::mpsc::channel(1);
    let watcher = porthub_transfer::notifications::watcher(move |_event: notify::Result<notify::Event>| {
        let _ = send.try_send(());
    })
    .ok()
    .and_then(|mut watcher| {
        watcher
            .watch(path.parent()?, notify::RecursiveMode::NonRecursive)
            .ok()?;
        Some(watcher)
    });
    loop {
        if path.exists() {
            return;
        }
        if watcher.is_some() && changes.recv().await.is_some() {
            continue;
        }
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
                    Err(error)
                        if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() =>
                    {
                        &session.status
                    }
                    Err(_) => "unknown",
                },
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => "stopped",
                Err(_) => "unknown",
            }
        } else {
            &session.status
        };
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
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {}
        Err(error) => return Err(error.into()),
    }
    crate::profile::write_private(&stop_path(layout, &session.id)?, b"stop\n", true)?;
    println!(
        "Stopping exposure {}; the gateway mapping is being removed…",
        &session.id[..12]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_state_does_not_crash_list_or_match_a_stop_request() -> Result<()> {
        let directory = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let path = directory.path().join("bad.json");
        crate::profile::write_private(&path, br#"{"id":"x","pid":1,"profile":"/unused","local_port":8000,"external_port":null,"subdomain":null,"status":"running","exposure_id":null,"tcp_url":null,"proxy_url":null,"message":null}"#, false)?;
        assert!(load_session(&path).is_err());
        Ok(())
    }
}

/// Exposure jobs belong to the invoking OS account, independently of whether
/// the selected registration runs as a system or per-user service.
pub fn job_layout() -> Result<crate::service::Layout> {
    let base = match std::env::var_os("PORTHUB_STATE_DIR") {
        Some(path) => PathBuf::from(path),
        None => directories::BaseDirs::new()
            .context("cannot locate user state")?
            .data_local_dir().join("porthub"),
    };
    let root = base.join("jobs");
    Ok(crate::service::Layout {
        user: true,
        state: root.clone(),
        releases: root.join("unused-releases"),
        units: root.join("unused-units"),
    })
}

/// Prepare this account's dedicated PortHub job state. Older transfer tools
/// could create the default app directory with a group-writable umask. Tighten
/// only that owned app directory; never chmod an arbitrary environment path.
pub(crate) fn prepare_job_directory()->Result<PathBuf> {
    let root=job_layout()?.state;
    if std::env::var_os("PORTHUB_STATE_DIR").is_none() {
        let base=root.parent().context("job state parent missing")?;
        #[cfg(unix)]
        if let Ok(metadata)=fs::symlink_metadata(base) {
            use std::os::unix::fs::{MetadataExt,PermissionsExt};
            ensure!(metadata.is_dir() && metadata.uid()==rustix::process::getuid().as_raw(),"PortHub user state ownership is unsafe");
            crate::service::directory(base.parent().context("user state parent missing")?,false)?;
            fs::set_permissions(base,fs::Permissions::from_mode(0o700))?;
        }
    }
    crate::service::directory(&root,true)?;
    Ok(root)
}

#[cfg(any(unix, windows))]
pub async fn broker_worker(
    registration_layout: crate::service::Layout,
    registration: String,
    id: String,
    local_port: u16,
    external_port: Option<u16>,
    subdomain: Option<String>,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let layout = job_layout()?;
    let lock_path = exposure_dir(&layout, true)?.join(format!("{id}.lock"));
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock.try_lock_exclusive().context("Exposure already has an owner")?;
    let mut session = Session {
        id: id.clone(),
        pid: std::process::id(),
        profile: registration.clone().into(),
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
        let request = crate::exposure_broker::Request { request_id: id.clone(), local_port, external_port, subdomain };
        let (mut connection, reply) = crate::exposure_broker::connect(&registration_layout, &registration, &request).await?;
        session.exposure_id = reply.exposure_id;
        session.external_port = reply.external_port;
        session.tcp_url = reply.tcp_url;
        session.proxy_url = reply.proxy_url;
        session.status = "running".into();
        save_session(&layout, &session)?;
        print_session(&session);
        let mut closed = String::new();
        tokio::select! {
            _ = cancel.cancelled() => {},
            _ = wait_for_stop(&layout, &id) => {},
            signal = wait_shutdown() => { signal?; },
            _ = connection.read_line(&mut closed) => { bail!("registration agent closed the exposure"); }
        }
        connection.get_mut().write_all(b"stop\n").await?;
        let count = tokio::time::timeout(Duration::from_secs(15), connection.read_line(&mut closed)).await??;
        ensure!(count > 0 && closed == "closed\n", "exposure disconnected; its gateway lease will expire automatically");
        Ok::<_, anyhow::Error>(())
    }.await;
    if let Err(error) = result {
        session.status = "failed".into();
        session.message = Some(error.to_string());
        save_session(&layout, &session)?;
        return Err(error);
    }
    let _ = fs::remove_file(session_path(&layout, &id, false)?);
    let _ = fs::remove_file(stop_path(&layout, &id)?);
    let _ = lock.unlock();
    drop(lock);
    let _ = fs::remove_file(lock_path);
    println!("Temporary exposure closed.");
    Ok(())
}
fn print_session(session: &Session) {
    println!(
        "Public TCP: {}",
        session.tcp_url.as_deref().unwrap_or("unavailable")
    );
    if let Some(url) = &session.proxy_url {
        println!("Web address: https://{url} (HTTP is also available)");
    }
    println!("Local target: 127.0.0.1:{}", session.local_port);
    println!("Exposure ID: {}", &session.id[..12]);
}

pub(crate) fn select_registration(layout:&crate::service::Layout,selector:Option<&str>)->Result<crate::service::readable::Record> {
    select_registration_in(layout,selector,crate::os_info::is_wsl())
}
fn select_registration_in(layout:&crate::service::Layout,selector:Option<&str>,wsl:bool)->Result<crate::service::readable::Record> {
    crate::service::readable::select(layout,selector,Some(false)).with_context(|| {
        if wsl {"Cannot select a WSL exposure registration. Run the Linux installer and start PortHub inside this WSL distribution; Windows and other WSL distributions have separate registrations. Check porthub ls here, and use --user for a user installation."}
        else {"Cannot select an exposure registration. Check porthub ls and start the registration; use --user for a user installation."}
    })
}

#[cfg(any(unix, windows))]
pub async fn start_registered(
    user: bool,
    selector: Option<&str>,
    local_port: u16,
    external_port: Option<u16>,
    subdomain: Option<String>,
    detach: bool,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let registration_layout = if user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let registration=select_registration(&registration_layout,selector)?;
    let id = uuid::Uuid::new_v4().simple().to_string();
    if !detach {
        return broker_worker(
            registration_layout,
            registration.id,
            id,
            local_port,
            external_port,
            subdomain,
            cancel,
        )
        .await;
    }
    crate::mapping_jobs::start(crate::mapping_jobs::Spec::Exposure {
        user, registration: registration.id, local_port, external_port, subdomain,
    }, true, cancel).await
}

/// Used only by the detached HTTP parent to print its own child's exposure.
pub fn print_ready_for_pid(pid: u32, port: u16) -> Result<bool> {
    if let Some(session) = read_sessions(&job_layout()?)?.into_iter().find(|session| {
        session.pid == pid && session.local_port == port && session.status == "running"
    }) {
        print_session(&session);
        return Ok(true);
    }
    Ok(false)
}

#[cfg(test)]
mod exposure_selection_tests {
    use super::*;
    #[test]
    fn missing_wsl_registration_explains_the_linux_windows_boundary_without_starting_a_server()->Result<()> {
        let root=tempfile::tempdir()?;
        let layout=crate::service::Layout {user:false,state:root.path().join("state"),releases:root.path().join("releases"),units:root.path().join("units")};
        let error=select_registration_in(&layout,None,true).unwrap_err().to_string();
        assert!(error.contains("inside this WSL distribution"));assert!(error.contains("Windows and other WSL distributions"));assert!(error.contains("porthub ls"));
        assert!(!layout.state.exists());Ok(())
    }
}

// Runtime state is separate from durable mapping intent.
pub(crate) fn session_active(id: &str) -> Result<bool> {
    let layout=job_layout()?;
    let path=exposure_dir(&layout,false)?.join(format!("{id}.lock"));
    if !path.try_exists()? {return Ok(false);}
    let lock=OpenOptions::new().read(true).write(true).open(path)?;
    match lock.try_lock_exclusive() {
        Ok(())=>{FileExt::unlock(&lock)?;Ok(false)},
        Err(e) if e.raw_os_error()==fs2::lock_contended_error().raw_os_error()=>Ok(true),
        Err(e)=>Err(e.into()),
    }
}
pub(crate) fn session_ready(id: &str) -> Result<bool> {
    let layout=job_layout()?;
    Ok(load_session(&session_path(&layout,id,false)?).is_ok_and(|s|s.status=="running") && session_active(id)?)
}
pub(crate) fn ready_port(id: &str) -> Result<Option<u16>> {
    if !session_ready(id)? {return Ok(None);}
    Ok(load_session(&session_path(&job_layout()?,id,false)?)?.external_port)
}
pub(crate) fn describe_session(id: &str) -> Result<()> {
    if let Ok(session)=load_session(&session_path(&job_layout()?,id,false)?) {print_session(&session);}
    Ok(())
}
/// Adopt already running detached workers without interrupting their sockets.
pub async fn enable_existing_recovery() -> Result<()> {
    for session in read_sessions(&job_layout()?)? {
        if session.status!="running" || !session_active(&session.id)? {continue;}
        // Only detached legacy workers are migrated; foreground sessions stay temporary.
        let pid=sysinfo::Pid::from_u32(session.pid);
        let mut system=sysinfo::System::new();
        system.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]),true,
            sysinfo::ProcessRefreshKind::nothing().with_cmd(sysinfo::UpdateKind::Always));
        if !system.process(pid).is_some_and(|p|p.cmd().iter().any(|s|s=="--worker") && p.cmd().iter().any(|s|s=="expose")) {continue;}
        let mut found=None;
        for user in [false,true] {
            #[cfg(windows)] if user {continue;}
            let layout=if user {crate::service::Layout::user()?} else {crate::service::Layout::system()?};
            if crate::service::readable::list(&layout)?.iter().any(|r|!r.private && r.id==session.profile.to_string_lossy()) {found=Some(user);break;}
        }
        if let Some(user)=found {
            crate::mapping_jobs::adopt_exposure(session.id,crate::mapping_jobs::Spec::Exposure {
                user,registration:session.profile.to_string_lossy().into_owned(),local_port:session.local_port,
                external_port:session.external_port,subdomain:session.subdomain,
            })?;
        }
    }
    crate::mapping_jobs::enable_recovery().await
}

pub(crate) fn list_unmanaged() -> Result<usize> {
    let mut count=0;
    for session in read_sessions(&job_layout()?)? {
        if crate::mapping_jobs::is_saved(&session.id)? {continue;}
        println!("{}  {}  recovery:false", &session.id[..12], if session_active(&session.id)? {&session.status} else {"stopped"});
        print_session(&session);count+=1;
    }
    Ok(count)
}
pub(crate) fn legacy_status(selector: Option<&str>) -> Result<()> {
    let rows=read_sessions(&job_layout()?)?.into_iter().filter(|s|selector.is_none_or(|id|s.id.starts_with(id)||s.local_port.to_string()==id)).collect::<Vec<_>>();
    ensure!(rows.len()==1,"Select an exposure ID from porthub expose ls");
    let session=&rows[0];
    println!("Status: {}; recovery:false", if session_active(&session.id)? {&session.status} else {"stopped"});
    print_session(session);Ok(())
}
