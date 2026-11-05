//! Local worker transports. Endpoint ownership is checked in addition to the
//! version handshake; an endpoint name is never treated as authentication.
use crate::catalog::{Artifact, Component};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type Stream = Box<dyn Io>;

#[derive(Clone, Debug)]
pub struct Endpoint(String);
impl Endpoint {
    pub fn for_artifact(cache: &Path, artifact: &Artifact) -> Result<Self> {
        artifact.validate()?;
        let identity = format!(
            "{}\n{}\n{}\n{}\n{}",
            cache.display(),
            artifact.component,
            artifact.version,
            artifact.target,
            artifact.executable.sha256
        );
        let digest = format!("{:x}", Sha256::digest(identity.as_bytes()));
        #[cfg(unix)]
        {
            let root = std::path::PathBuf::from(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .join(format!(
                "porthub-workers-{}",
                rustix::process::geteuid().as_raw()
            ));
            crate::store::directory(&root)?;
            let path = root.join(format!("{}-{}.sock", artifact.component, &digest[..48]));
            ensure!(
                path.as_os_str().len() < 104,
                "component worker socket path exceeds platform limit"
            );
            Ok(Self(
                path.to_str()
                    .context("component worker socket path must be UTF-8")?
                    .into(),
            ))
        }
        #[cfg(windows)]
        {
            let account = crate::windows_security::process_account(std::process::id())?;
            let owner = format!("{:x}", Sha256::digest(account.as_bytes()));
            Ok(Self(format!(
                r"\\.\pipe\PortHub.Components.{}.{digest}",
                &owner[..24]
            )))
        }
    }
    pub fn address(&self) -> &str {
        &self.0
    }
    /// Worker CLI startup accepts only the deterministic private endpoint shape.
    pub fn parse(component: Component, value: &str) -> Result<Self> {
        #[cfg(unix)]
        {
            let root = std::path::PathBuf::from(if cfg!(target_os = "macos") {
                "/private/tmp"
            } else {
                "/tmp"
            })
            .join(format!(
                "porthub-workers-{}",
                rustix::process::geteuid().as_raw()
            ));
            crate::store::directory(&root)?;
            let path = Path::new(value);
            ensure!(
                path.parent() == Some(root.as_path()),
                "worker socket must be in this account's private runtime directory"
            );
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .context("invalid worker socket name")?;
            let digest = name
                .strip_prefix(&format!("{component}-"))
                .and_then(|s| s.strip_suffix(".sock"))
                .context("invalid worker socket name")?;
            ensure!(
                digest.len() == 48
                    && digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "invalid worker socket identity"
            );
        }
        #[cfg(windows)]
        {
            let account = crate::windows_security::process_account(std::process::id())?;
            let owner = format!("{:x}", Sha256::digest(account.as_bytes()));
            let prefix = format!(r"\\.\pipe\PortHub.Components.{}.", &owner[..24]);
            ensure!(
                value
                    .strip_prefix(&prefix)
                    .is_some_and(crate::catalog::digest),
                "worker pipe must belong to this account"
            );
            let _ = component;
        }
        Ok(Self(value.into()))
    }
    pub async fn connect(&self) -> Result<Stream> {
        #[cfg(unix)]
        {
            check_socket(Path::new(&self.0))?;
            let stream = tokio::net::UnixStream::connect(&self.0).await?;
            ensure!(
                stream.peer_cred()?.uid() == rustix::process::geteuid().as_raw(),
                "component worker peer belongs to another account"
            );
            Ok(Box::new(stream))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
            let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(&self.0)?;
            let mut pid = 0;
            ensure!(
                unsafe { GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut pid) } != 0,
                "cannot inspect component worker pipe peer"
            );
            crate::windows_security::same_account(pid)?;
            Ok(Box::new(stream))
        }
    }
}
#[cfg(unix)]
fn check_socket(path: &Path) -> Result<std::fs::Metadata> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "component worker socket is not owned privately"
    );
    Ok(metadata)
}

pub struct Listener {
    endpoint: Endpoint,
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(windows)]
    next: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}
impl Listener {
    pub async fn bind(endpoint: Endpoint) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            // A crashed worker leaves a socket inode. Only remove an owned socket
            // that rejects connections; never unlink a live listener or a file.
            if Path::new(endpoint.address()).try_exists()? {
                let old = check_socket(Path::new(endpoint.address()))?;
                match tokio::net::UnixStream::connect(endpoint.address()).await {
                    Ok(_) => anyhow::bail!("component worker already running"),
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                        let current = check_socket(Path::new(endpoint.address()))?;
                        ensure!(
                            old.dev() == current.dev() && old.ino() == current.ino(),
                            "component socket changed during recovery"
                        );
                        std::fs::remove_file(endpoint.address())?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            let listener = tokio::net::UnixListener::bind(endpoint.address())?;
            std::fs::set_permissions(endpoint.address(), std::fs::Permissions::from_mode(0o600))?;
            let metadata = check_socket(Path::new(endpoint.address()))?;
            Ok(Self {
                endpoint,
                listener,
                identity: (metadata.dev(), metadata.ino()),
            })
        }
        #[cfg(windows)]
        {
            let next = Some(crate::windows_security::pipe(endpoint.address(), true)?);
            Ok(Self { endpoint, next })
        }
    }
    pub async fn accept(&mut self) -> Result<Stream> {
        #[cfg(unix)]
        {
            let (stream, _) = self.listener.accept().await?;
            ensure!(
                stream.peer_cred()?.uid() == rustix::process::geteuid().as_raw(),
                "component client belongs to another account"
            );
            Ok(Box::new(stream))
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
            let pipe = self
                .next
                .as_ref()
                .context("component pipe listener unavailable")?;
            pipe.connect().await?;
            let stream = self.next.take().unwrap();
            // Keep one listening instance alive while established clients run.
            self.next = Some(crate::windows_security::pipe(
                self.endpoint.address(),
                false,
            )?);
            let mut pid = 0;
            ensure!(
                unsafe { GetNamedPipeClientProcessId(stream.as_raw_handle(), &mut pid) } != 0,
                "cannot inspect component client pipe peer"
            );
            crate::windows_security::same_account(pid)?;
            Ok(Box::new(stream))
        }
    }
}
#[cfg(unix)]
impl Drop for Listener {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        if check_socket(Path::new(self.endpoint.address()))
            .is_ok_and(|m| (m.dev(), m.ino()) == self.identity)
        {
            let _ = std::fs::remove_file(self.endpoint.address());
        }
    }
}
