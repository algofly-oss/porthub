//! Windows local exposure broker. Pipe ACLs grant only the enrolling Windows
//! account, SYSTEM and Administrators. Clients verify the server PID through SCM.
pub use crate::exposure_protocol::{Reply, Request};
use anyhow::{ensure, Context, Result};
use std::{
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions},
};
use tokio_util::sync::CancellationToken;
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

fn grant_path(profile: &Path) -> PathBuf {
    crate::profile::sibling(profile, ".local-access.json")
}
fn sid() -> Result<String> {
    let mut token = std::ptr::null_mut();
    // SAFETY: all output pointers address live, appropriately sized buffers.
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "cannot identify installing Windows account"
    );
    struct Handle(HANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    let _token = Handle(token);
    let mut buffer = [0usize; 256];
    let mut needed = 0;
    ensure!(
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut needed,
            )
        } != 0,
        "cannot read installing Windows identity"
    );
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = std::ptr::null_mut();
    ensure!(
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } != 0,
        "cannot format Windows identity"
    );
    let mut length = 0;
    while length < 256 && unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let value = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe {
        LocalFree(text.cast());
    }
    let value = value?;
    ensure!(valid_sid(&value), "invalid Windows local identity");
    Ok(value)
}
fn valid_sid(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() < 184
        && value[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
}
pub(crate) fn record_installer(profile: &Path) -> Result<()> {
    let path = grant_path(profile);
    if path.exists() {
        return Ok(());
    }
    let owner = sid()?;
    // An unattended SYSTEM upgrade cannot infer which interactive account
    // enrolled an older machine. It must not grant every local user access.
    if owner == "S-1-5-18" {
        return Ok(());
    }
    crate::profile::write_private(&path, &serde_json::to_vec(&owner)?, false)
}
pub fn endpoint(_layout: &crate::service::Layout, id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid registration identity"
    );
    Ok(format!(r"\\.\pipe\PortHub.Expose.{id}").into())
}
fn pipe(path: &Path, owner: Option<&str>, first: bool) -> Result<NamedPipeServer> {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(owner) = owner {
        ensure!(valid_sid(owner), "invalid exposure owner");
        // No FILE_CREATE_PIPE_INSTANCE right: the unprivileged client cannot
        // create another server instance under the trusted endpoint name.
        sddl.push_str(&format!("(A;;0x00100083;;;{owner})"));
    }
    let wide = sddl.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        } != 0,
        "cannot create exposure pipe permissions"
    );
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                path,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    };
    unsafe {
        LocalFree(descriptor);
    }
    Ok(result?)
}
pub struct Guard {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
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
    }
}
pub fn start(
    profile: &Path,
    control: Arc<crate::control::Control>,
    cancel: CancellationToken,
) -> Result<Option<Guard>> {
    let layout = crate::service::Layout::system()?;
    let id = crate::service::identity(control.profile());
    let Some(spec) = crate::service::installed(&layout, &id)? else {
        return Ok(None);
    };
    ensure!(
        spec.profile == profile,
        "local exposure registration mismatch"
    );
    let owner = match crate::profile::read_private(&grant_path(profile)) {
        Ok(bytes) => Some(serde_json::from_slice::<String>(&bytes)?),
        Err(_) if !grant_path(profile).exists() => None,
        Err(error) => return Err(error),
    };
    let path = endpoint(&layout, &id)?;
    let mut listener = pipe(&path, owner.as_deref(), true)?;
    let token = cancel.child_token();
    let work = token.clone();
    let task = tokio::spawn(async move {
        let capacity = Arc::new(tokio::sync::Semaphore::new(32));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = work.cancelled() => break,
                _ = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.connect() => {
                    if accepted.is_err() { break; }
                    let next = match pipe(&path, owner.as_deref(), false) { Ok(next) => next, Err(_) => break };
                    let stream = std::mem::replace(&mut listener, next);
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                    let control = control.clone(); let cancel = work.clone();
                    tasks.spawn(async move { let _permit = permit; let _ = crate::exposure_protocol::serve_connection(stream, control, cancel).await; });
                }
            }
        }
        work.cancel();
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
    }))
}
fn verified_pipe(layout: &crate::service::Layout, registration: &str) -> Result<NamedPipeClient> {
    ensure!(
        !layout.user,
        "Windows exposures use the installed system registration"
    );
    let path = endpoint(layout, registration)?;
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // Match the narrow client ACL instead of requesting GENERIC_WRITE (which
    // also includes the server-only FILE_CREATE_PIPE_INSTANCE bit).
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0x00100083,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT,
            std::ptr::null_mut(),
        )
    };
    ensure!(handle != INVALID_HANDLE_VALUE, "local exposure control unavailable; start or update the registered agent, or reinstall once to authorize this Windows account");
    let stream = unsafe { NamedPipeClient::from_raw_handle(handle) }?;
    let mut server_pid = 0;
    ensure!(
        unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut server_pid) } != 0,
        "cannot verify local agent identity"
    );
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(
        format!("porthub-{}", &registration[..24]),
        ServiceAccess::QUERY_STATUS,
    )?;
    ensure!(
        service.query_status()?.process_id == Some(server_pid),
        "local exposure pipe is not served by the registered agent"
    );
    Ok(stream)
}

pub async fn connect(
    layout: &crate::service::Layout,
    registration: &str,
    request: &Request,
) -> Result<(BufReader<NamedPipeClient>, Reply)> {
    request.validate()?;
    // Native SCM handles are not Send. Finish identity verification and drop
    // every synchronous handle before the async pipe exchange can suspend.
    let stream = verified_pipe(layout, registration)?;
    let mut reader = BufReader::new(stream);
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    reader.get_mut().write_all(&bytes).await?;
    let reply: Reply = serde_json::from_slice(
        &tokio::time::timeout(
            Duration::from_secs(45),
            crate::exposure_protocol::line(&mut reader),
        )
        .await
        .context("exposure request timed out")??,
    )?;
    ensure!(
        reply.error.is_none(),
        "{}",
        reply.error.as_deref().unwrap_or("exposure request failed")
    );
    Ok((reader, reply))
}

#[cfg(test)]
mod tests {
    #[test]
    fn connection_future_can_run_in_a_background_task() {
        let layout = crate::service::Layout::system().unwrap();
        let registration = "a".repeat(64);
        let request = super::Request {
            request_id: "b".repeat(32),
            local_port: 8000,
            external_port: None,
            subdomain: None,
        };
        fn assert_send<T: Send>(_: T) {}
        assert_send(super::connect(&layout, &registration, &request));
    }
}
