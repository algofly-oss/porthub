//! Local, credential-free exposure requests. The installed agent authenticates
//! the OS caller and keeps gateway credentials inside its privileged process.
use anyhow::{ensure, Context, Result};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
};
use tokio_util::sync::CancellationToken;

use crate::exposure_protocol::line;
pub use crate::exposure_protocol::{Reply, Request};
pub fn endpoint(layout: &crate::service::Layout, id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid registration identity"
    );
    Ok(crate::service::readable::directory(layout)?.join(format!("{}.sock", &id[..24])))
}
fn grant_path(profile: &Path) -> PathBuf {
    crate::profile::sibling(profile, ".local-access.json")
}
/// Called during authorized installation. An upgrade retains the enrolled local
/// user; it never silently grants access to whoever happens to run the updater.
pub(crate) fn record_installer(profile: &Path) -> Result<()> {
    let path = grant_path(profile);
    if path.exists() {
        return Ok(());
    }
    let current = rustix::process::geteuid().as_raw();
    let owner = if current == 0 {
        std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
    } else {
        Some(current)
    };
    if let Some(owner) = owner {
        crate::profile::write_private(&path, &serde_json::to_vec(&owner)?, false)?;
    }
    Ok(())
}
fn authorized(uid: u32, profile: &Path) -> bool {
    let service_uid = rustix::process::geteuid().as_raw();
    if uid == 0 || uid == service_uid {
        return true;
    }
    if service_uid != 0 {
        return false;
    }
    if crate::profile::read_private(&grant_path(profile))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<u32>(&bytes).ok())
        == Some(uid)
    {
        return true;
    }
    // Existing installs predate local-user grants. Local OS administrators can
    // already read machine credentials through elevation; authenticate their
    // membership without prompting for elevation or exposing those credentials.
    administrator(uid)
}
fn administrator(uid: u32) -> bool {
    let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 16384];
    let mut result = std::ptr::null_mut();
    // SAFETY: buffers live for the complete reentrant lookup and group lookup.
    if unsafe {
        libc::getpwuid_r(
            uid,
            entry.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        return false;
    }
    let entry = unsafe { entry.assume_init() };
    if entry.pw_name.is_null() {
        return false;
    }
    let mut groups = vec![0 as libc::gid_t; 256];
    let mut count = groups.len() as libc::c_int;
    #[cfg(target_os = "macos")]
    let found = unsafe {
        libc::getgrouplist(
            entry.pw_name,
            entry.pw_gid as libc::c_int,
            groups.as_mut_ptr().cast(),
            &mut count,
        )
    };
    #[cfg(not(target_os = "macos"))]
    let found =
        unsafe { libc::getgrouplist(entry.pw_name, entry.pw_gid, groups.as_mut_ptr(), &mut count) };
    if found < 0 || count < 0 || count as usize > groups.len() {
        return false;
    }
    for name in [c"sudo", c"wheel", c"admin"] {
        let mut group = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut data = vec![0u8; 16384];
        let mut result = std::ptr::null_mut();
        if unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                group.as_mut_ptr(),
                data.as_mut_ptr().cast(),
                data.len(),
                &mut result,
            )
        } != 0
            || result.is_null()
        {
            continue;
        }
        if groups[..count as usize].contains(&unsafe { group.assume_init() }.gr_gid) {
            return true;
        }
    }
    false
}
async fn serve_one(
    stream: UnixStream,
    profile: PathBuf,
    control: Arc<crate::control::Control>,
    cancel: CancellationToken,
) -> Result<()> {
    let uid = stream.peer_cred()?.uid();
    if !tokio::task::spawn_blocking(move || authorized(uid, &profile)).await? {
        let mut stream = stream;
        return crate::exposure_protocol::send(
            &mut stream,
            &Reply {
                error: Some("This local account is not authorized for the registration".into()),
                exposure_id: None,
                external_port: None,
                tcp_url: None,
                proxy_url: None,
            },
        )
        .await;
    }
    crate::exposure_protocol::serve_connection(stream, control, cancel).await
}
pub struct Guard {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    path: PathBuf,
}
impl Guard {
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if tokio::time::timeout(Duration::from_secs(15), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.cancel.cancel();
        // Existing sessions finish their bounded close request. Removing only
        // the listener pathname prevents new sessions during service shutdown.
        let _ = std::fs::remove_file(&self.path);
        let _ = &self.task;
    }
}
pub fn start(
    profile: &Path,
    control: Arc<crate::control::Control>,
    cancel: CancellationToken,
) -> Result<Option<Guard>> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    let id = crate::service::identity(control.profile());
    let layouts = [
        crate::service::Layout::system(),
        crate::service::Layout::user(),
    ];
    let layout = layouts.into_iter().flatten().find(|layout| {
        crate::service::installed(layout, &id)
            .ok()
            .flatten()
            .is_some_and(|spec| spec.profile == profile)
    });
    let Some(layout) = layout else {
        return Ok(None);
    };
    let path = endpoint(&layout, &id)?;
    crate::service::directory(
        path.parent().context("missing local control directory")?,
        false,
    )?;
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        ensure!(
            meta.file_type().is_socket() && meta.uid() == rustix::process::geteuid().as_raw(),
            "local exposure socket is not owned"
        );
        // The profile's existing Lease already prevents a second live owner.
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
    let token = cancel.child_token();
    let task_cancel = token.clone();
    let profile = profile.to_owned();
    let task = tokio::spawn(async move {
        let capacity = Arc::new(tokio::sync::Semaphore::new(32));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = task_cancel.cancelled() => break,
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break; };
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                    let profile = profile.clone(); let control = control.clone(); let cancel = task_cancel.clone();
                    tasks.spawn(async move { let _permit = permit; let _ = serve_one(stream, profile, control, cancel).await; });
                }
            }
        }
        task_cancel.cancel();
        if tokio::time::timeout(Duration::from_secs(15), async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tasks.abort_all();
        }
    });
    Ok(Some(Guard {
        cancel: token,
        task,
        path,
    }))
}
pub async fn connect(
    layout: &crate::service::Layout,
    registration: &str,
    request: &Request,
) -> Result<(BufReader<UnixStream>, Reply)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    request.validate()?;
    let path = endpoint(layout, registration)?;
    let meta = std::fs::symlink_metadata(&path)
        .context("registration agent is unavailable; start or update it first")?;
    let expected = if layout.user {
        rustix::process::geteuid().as_raw()
    } else {
        0
    };
    ensure!(
        meta.file_type().is_socket() && meta.uid() == expected,
        "local registration endpoint is not trusted"
    );
    let mut stream = UnixStream::connect(path).await?;
    ensure!(
        stream.peer_cred()?.uid() == expected,
        "local registration agent identity mismatch"
    );
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await?;
    let mut reader = BufReader::new(stream);
    let response: Reply = serde_json::from_slice(
        &tokio::time::timeout(Duration::from_secs(45), line(&mut reader))
            .await
            .context("exposure request timed out")??,
    )?;
    ensure!(
        response.error.is_none(),
        "{}",
        response
            .error
            .as_deref()
            .unwrap_or("exposure request failed")
    );
    Ok((reader, response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[test]
    fn unknown_local_users_and_arbitrary_messages_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        assert!(!authorized(u32::MAX - 1, &root.path().join("absent.json")));
        let mut request = Request {
            request_id: "a".repeat(32),
            local_port: 8000,
            external_port: None,
            subdomain: Some("test-app".into()),
        };
        assert!(request.validate().is_ok());
        request.subdomain = Some("host/other".into());
        assert!(request.validate().is_err());
        request.subdomain = None;
        request.local_port = 0;
        assert!(request.validate().is_err());
        assert!(serde_json::from_str::<Request>(
            r#"{"request_id":"a","local_port":8000,"token":"injected"}"#
        )
        .is_err());
    }
    #[tokio::test]
    async fn local_caller_never_receives_credentials_and_disconnect_closes_mapping() -> Result<()> {
        use axum::{routing::post, Json, Router};
        let created = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let create_count = created.clone();
        let close_count = closed.clone();
        let router = Router::new()
            .route("/api/machines/client/expose", post(move |Json(body): Json<serde_json::Value>| {
                let count = create_count.clone(); async move {
                    assert_eq!(body["machine_id"], "0123456789abcdef01234567"); assert_eq!(body["token"], "never-return-this-token");
                    assert_eq!(body["local_port"], 8000); count.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({"data":{"exposure_id":"lease-1","external_port":12345,"tcp_url":"http://gateway.example:12345","token":"never-return-this-token"}}))
                }
            }))
            .route("/api/machines/client/expose/close", post(move |Json(body): Json<serde_json::Value>| {
                let count = close_count.clone(); async move {
                    assert_eq!(body["exposure_id"], "lease-1"); assert_eq!(body["token"], "never-return-this-token");
                    count.fetch_add(1, Ordering::SeqCst); Json(serde_json::json!({"data":{}}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let server = format!("http://{}", listener.local_addr()?);
        let api = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let profile: crate::profile::Profile = serde_json::from_value(
            serde_json::json!({"server":server,"machine_id":"0123456789abcdef01234567","token":"never-return-this-token","allow_insecure_http_for_tests":true}),
        )?;
        let control = Arc::new(crate::control::Control::new(profile)?);
        let root = tempfile::tempdir()?;
        let (client, server) = UnixStream::pair()?;
        let broker = tokio::spawn(serve_one(
            server,
            root.path().join("profile.json"),
            control,
            CancellationToken::new(),
        ));
        let request = Request {
            request_id: "a".repeat(32),
            local_port: 8000,
            external_port: None,
            subdomain: None,
        };
        let mut client = BufReader::new(client);
        let mut bytes = serde_json::to_vec(&request)?;
        bytes.push(b'\n');
        client.get_mut().write_all(&bytes).await?;
        let reply = line(&mut client).await?;
        assert!(!String::from_utf8_lossy(&reply).contains("never-return"));
        assert_eq!(
            serde_json::from_slice::<Reply>(&reply)?.external_port,
            Some(12345)
        );
        drop(client);
        tokio::time::timeout(Duration::from_secs(3), broker).await???;
        assert_eq!(created.load(Ordering::SeqCst), 1);
        assert_eq!(closed.load(Ordering::SeqCst), 1);
        api.abort();
        Ok(())
    }
}
