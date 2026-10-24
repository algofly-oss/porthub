//! Unix sockets shared only with the container roles that need them. A lock
//! prevents parallel owners from replacing an active listener during restart.
use anyhow::{bail, Context, Result};
use fs2::FileExt;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::net::{UnixListener, UnixStream};

pub struct SocketLease {
    path: PathBuf,
    device: u64,
    inode: u64,
    _lock: File,
}
impl Drop for SocketLease {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

pub async fn bind(path: &Path) -> Result<(UnixListener, SocketLease)> {
    let directory = path
        .parent()
        .context("Unix socket requires a parent directory")?;
    if !directory.is_dir() {
        bail!("Unix socket directory does not exist");
    }
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(PathBuf::from(lock_name))
        .context("open Unix socket ownership lock")?;
    lock.try_lock_exclusive()
        .context("Unix socket is already owned by another process")?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                bail!("refusing to replace a non-socket IPC path");
            }
            match UnixStream::connect(path).await {
                Ok(_) => bail!("Unix socket already has an active listener"),
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)?
                }
                Err(error) => return Err(error).context("check previous Unix socket listener"),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path).context("bind internal Unix socket")?;
    let metadata = std::fs::symlink_metadata(path)?;
    let lease = SocketLease {
        path: path.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        _lock: lock,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok((listener, lease))
}
