//! Windows desktop identity comes from the named-pipe peer's process token.
//! Neither a network plan nor a client-supplied session ID can create this proof.
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};
use std::os::windows::io::AsRawHandle;
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE},
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenSessionId,
        TokenStatistics, TokenUser, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
    },
    System::{
        Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId},
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
/// Stable principal is public inventory metadata. Live proof remains tied to
/// this OS logon/session and is used only on the local authenticated channel.
#[derive(Clone, Debug)]
pub(crate) struct PeerIdentity {
    sid: String,
    session: u32,
    principal: String,
    proof: String,
}
impl PeerIdentity {
    pub(crate) fn desktop_session(&self) -> &str {
        &self.principal
    }
    pub(crate) fn connection_proof(&self) -> &str {
        &self.proof
    }
    pub(crate) fn session_id(&self) -> u32 {
        self.session
    }
}
fn identity(sid: String, session: u32, authentication: [u8; 8]) -> Result<PeerIdentity> {
    ensure!(
        session != 0 && !["S-1-5-18", "S-1-5-19", "S-1-5-20"].contains(&sid.as_str()),
        "Media sources require an authenticated interactive user session"
    );
    ensure!(
        sid.starts_with("S-1-")
            && sid.len() < 184
            && sid[4..].bytes().all(|b| b.is_ascii_digit() || b == b'-'),
        "Invalid Windows media principal"
    );
    let mut principal = Sha256::new();
    principal.update(b"PortHub Windows media principal v1\0");
    principal.update(sid.as_bytes());
    let principal = format!("windows:{:x}", principal.finalize());
    let mut proof = Sha256::new();
    proof.update(b"PortHub Windows media logon v1\0");
    proof.update(sid.as_bytes());
    proof.update([0]);
    proof.update(authentication);
    proof.update(session.to_le_bytes());
    Ok(PeerIdentity {
        sid,
        session,
        principal,
        proof: format!("{:x}", proof.finalize()),
    })
}
fn process_identity(process: HANDLE, pid: u32) -> Result<PeerIdentity> {
    let mut token = std::ptr::null_mut();
    ensure!(
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0,
        "Cannot query Windows media caller token"
    );
    let token = OwnedHandle(token);
    let mut buffer = [0usize; 256];
    let mut needed = 0;
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut needed,
            )
        } != 0
            && needed as usize <= std::mem::size_of_val(&buffer)
            && needed as usize >= std::mem::size_of::<TOKEN_USER>(),
        "Cannot read media caller SID"
    );
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = std::ptr::null_mut();
    ensure!(
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } != 0,
        "Cannot format media caller SID"
    );
    let sid = unsafe {
        let mut length = 0;
        while length < 184 && *text.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        value
    }?;
    let mut session = 0u32;
    needed = 0;
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenSessionId,
                (&mut session as *mut u32).cast(),
                4,
                &mut needed,
            )
        } != 0
            && needed == 4,
        "Cannot identify Windows media token session"
    );
    let mut process_session = 0;
    ensure!(
        unsafe { ProcessIdToSessionId(pid, &mut process_session) } != 0
            && process_session == session,
        "Windows media process/session mismatch"
    );
    let mut statistics: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
    needed = 0;
    ensure!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenStatistics,
                (&mut statistics as *mut TOKEN_STATISTICS).cast(),
                std::mem::size_of::<TOKEN_STATISTICS>() as u32,
                &mut needed,
            )
        } != 0
            && needed as usize == std::mem::size_of::<TOKEN_STATISTICS>(),
        "Cannot identify Windows media logon"
    );
    let mut authentication = [0; 8];
    authentication[..4].copy_from_slice(&statistics.AuthenticationId.LowPart.to_le_bytes());
    authentication[4..].copy_from_slice(&statistics.AuthenticationId.HighPart.to_le_bytes());
    identity(sid, session, authentication)
}
pub(crate) fn current() -> Result<PeerIdentity> {
    process_identity(unsafe { GetCurrentProcess() }, unsafe {
        GetCurrentProcessId()
    })
}
/// Called on the connected server instance before dispatch, while the client
/// process handle is held. ACL authorization alone is insufficient for media.
pub(crate) fn peer(pipe: &NamedPipeServer, enroller: &str) -> Result<PeerIdentity> {
    let mut pid = 0;
    ensure!(
        unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } != 0 && pid != 0,
        "Cannot identify media pipe caller"
    );
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    ensure!(!process.is_null(), "Cannot open media pipe caller identity");
    let process = OwnedHandle(process);
    let value = process_identity(process.0, pid)?;
    let mut pipe_session = 0;
    ensure!(
        unsafe { GetNamedPipeClientSessionId(pipe.as_raw_handle(), &mut pipe_session) } != 0
            && pipe_session == value.session,
        "Media pipe client/session mismatch"
    );
    let mut checked = 0;
    ensure!(
        unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut checked) } != 0
            && checked == pid,
        "Media pipe caller changed"
    );
    ensure!(
        value.sid == enroller,
        "Media desktop does not belong to the enrolling Windows account"
    );
    Ok(value)
}
pub(crate) fn validate_policy(value: &serde_json::Value) -> Result<()> {
    let own = current()?;
    ensure!(
        value["type"] == "policy"
            && value["uid"] == 0
            && value["desktop_session"].as_str() == Some(own.desktop_session())
            && value["desktop_proof"].as_str() == Some(own.connection_proof()),
        "Installed media broker did not authenticate this Windows logon"
    );
    Ok(())
}
/// No enrollment credentials are inherited by the optional native helper.
pub(crate) fn configure_command(command: &mut tokio::process::Command) -> Result<()> {
    let _identity = current()?;
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW, only internal helper.
    for key in [
        "SystemRoot",
        "WINDIR",
        "USERPROFILE",
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    Ok(())
}
pub(crate) async fn run(
    layout: crate::service::Layout,
    registration: String,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<()> {
    let _identity = current()?;
    super::host::run(layout, registration, cancel).await
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn named_pipe_identity_is_native_and_noninteractive_callers_are_rejected() -> Result<()> {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        let name = format!(
            r"\\.\pipe\PortHub.OwnedMediaIdentity.{}.{}",
            unsafe { GetCurrentProcessId() },
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&name)?;
        let client = ClientOptions::new().open(&name)?;
        tokio::time::timeout(std::time::Duration::from_secs(5), server.connect()).await??;
        match current() {
            Ok(own) => {
                let verified = peer(&server, &own.sid)?;
                assert_eq!(verified.desktop_session(), own.desktop_session());
                assert_eq!(verified.connection_proof(), own.connection_proof());
                assert_eq!(verified.session_id(), own.session_id());
                assert!(
                    peer(&server, &format!("{}-999", own.sid)).is_err(),
                    "Wrong enrolling SID was accepted"
                );
            }
            Err(error) => {
                ensure!(
                    error
                        .to_string()
                        .contains("authenticated interactive user session"),
                    "Unexpected native identity failure: {error}"
                );
                assert!(
                    peer(&server, "S-1-5-21-1-2-3-1001").is_err(),
                    "A noninteractive caller manufactured a desktop identity"
                );
            }
        }
        drop(client);
        drop(server);
        Ok(())
    }
    #[test]
    fn stable_principal_survives_login_but_live_proof_does_not() {
        let a = identity("S-1-5-21-1-2-3-1001".into(), 1, [1; 8]).unwrap();
        let b = identity("S-1-5-21-1-2-3-1001".into(), 2, [2; 8]).unwrap();
        assert_eq!(a.desktop_session(), b.desktop_session());
        assert_ne!(a.connection_proof(), b.connection_proof());
        assert_ne!(
            a.desktop_session(),
            identity("S-1-5-21-1-2-3-1002".into(), 1, [1; 8])
                .unwrap()
                .desktop_session()
        );
        assert!(identity("S-1-5-18".into(), 1, [1; 8]).is_err());
        assert!(identity("S-1-5-21-1".into(), 0, [1; 8]).is_err());
    }
}
