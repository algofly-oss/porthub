//! Package hooks may replace resolv.conf. Keep the administrator's original
//! resolver file/symlink so enrollment only integrates NSS, not upstream DNS.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
#[derive(PartialEq, Eq, Serialize, Deserialize)]
enum Saved {
    Link(PathBuf),
    File {
        bytes: Vec<u8>,
        mode: u32,
        uid: u32,
        gid: u32,
        context: Option<Vec<u8>>,
    },
}
impl Saved {
    fn read(path: &Path) -> Result<Self> {
        let meta = std::fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Ok(Self::Link(std::fs::read_link(path)?));
        }
        anyhow::ensure!(
            meta.is_file(),
            "resolver configuration is not a regular file or symlink"
        );
        anyhow::ensure!(
            meta.len() <= 65536,
            "resolver configuration exceeds the backup size limit"
        );
        let file = std::fs::File::open(path)?;
        let mut context = vec![0u8; 4096];
        // SAFETY: the file descriptor remains open and the named attribute and
        // output buffer are valid for this bounded Linux filesystem call.
        let length = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                c"security.selinux".as_ptr(),
                context.as_mut_ptr().cast(),
                context.len(),
            )
        };
        let context = if length >= 0 {
            context.truncate(length as usize);
            Some(context)
        } else {
            let error = std::io::Error::last_os_error();
            anyhow::ensure!(
                matches!(
                    error.raw_os_error(),
                    Some(libc::ENODATA) | Some(libc::EOPNOTSUPP)
                ),
                "cannot preserve the resolver's security label"
            );
            None
        };
        Ok(Self::File {
            bytes: std::fs::read(path)?,
            mode: meta.mode() & 0o777,
            uid: meta.uid(),
            gid: meta.gid(),
            context,
        })
    }
    fn restore(&self, path: &Path) -> Result<()> {
        use std::io::Write;
        let parent = path.parent().context("resolver parent directory missing")?;
        let temporary = tempfile::NamedTempFile::new_in(parent)?;
        match self {
            Self::Link(target) => {
                let name = temporary.path().to_path_buf();
                temporary.close()?;
                std::os::unix::fs::symlink(target, &name)?;
                if let Err(error) = std::fs::rename(&name, path) {
                    let _ = std::fs::remove_file(&name);
                    return Err(error.into());
                }
            }
            Self::File {
                bytes,
                mode,
                uid,
                gid,
                context,
            } => {
                let mut temporary = temporary;
                // SAFETY: a live owned descriptor; IDs came from the original
                // configuration, before any package hook ran.
                anyhow::ensure!(
                    unsafe { libc::fchown(temporary.as_raw_fd(), *uid, *gid) } == 0,
                    "cannot restore resolver configuration ownership"
                );
                if let Some(context) = context {
                    // SAFETY: the descriptor, attribute name and captured byte
                    // slice remain valid throughout the filesystem call.
                    anyhow::ensure!(
                        unsafe {
                            libc::fsetxattr(
                                temporary.as_raw_fd(),
                                c"security.selinux".as_ptr(),
                                context.as_ptr().cast(),
                                context.len(),
                                0,
                            )
                        } == 0,
                        "cannot restore resolver configuration security label"
                    );
                }
                temporary
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(*mode))?;
                temporary.write_all(bytes)?;
                temporary.as_file().sync_all()?;
                temporary.persist(path)?;
            }
        }
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    fn package_owned_stub(&self) -> bool {
        matches!(self,Self::Link(target) if ["/run/systemd/resolve/stub-resolv.conf","/run/systemd/resolve/resolv.conf","../run/systemd/resolve/stub-resolv.conf","../run/systemd/resolve/resolv.conf"].iter().any(|value|target==Path::new(value)))
    }
}
pub(crate) async fn preserve<F: Future<Output = Result<bool>>>(
    path: &Path,
    operation: F,
) -> Result<bool> {
    use std::io::Write;
    let original = Saved::read(path)
        .context("read existing resolver configuration before package preparation")?;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random)
        .map_err(|_| anyhow::anyhow!("resolver backup identifier unavailable"))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let backup = path.with_file_name(format!("resolv.conf.porthub-backup-{suffix}.json"));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&backup)?;
    serde_json::to_writer(&mut file, &original)?;
    file.flush()?;
    file.sync_all()?;
    let outcome = operation.await;
    let current=Saved::read(path).context("package preparation left resolver configuration unavailable; restore the file or symlink recorded in the resolv.conf.porthub-backup JSON snapshot")?;
    if current != original {
        anyhow::ensure!(current.package_owned_stub(),"resolver configuration changed unexpectedly during package preparation; administrator changes were preserved and the original is recorded in the resolv.conf.porthub-backup JSON snapshot");
        original.restore(path).context("restore existing DNS configuration after package preparation; original is recorded in the resolv.conf.porthub-backup JSON snapshot")?;
    }
    outcome
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn package_hook_cannot_replace_existing_dns_servers_with_a_stub() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        std::fs::write(&path, "search internal.invalid\nnameserver 172.31.0.2\n")?;
        let original = std::fs::read(&path)?;
        preserve(&path, async {
            std::fs::remove_file(&path)?;
            std::os::unix::fs::symlink("/run/systemd/resolve/stub-resolv.conf", &path)?;
            Ok(true)
        })
        .await?;
        assert_eq!(std::fs::read(&path)?, original);
        Ok(())
    }
    #[tokio::test]
    async fn original_network_manager_symlink_and_live_updates_are_retained_even_on_package_failure(
    ) -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        let managed = directory.path().join("nm-resolv.conf");
        std::fs::write(&managed, "nameserver 192.0.2.1\n")?;
        std::os::unix::fs::symlink(&managed, &path)?;
        let result = preserve(&path, async {
            std::fs::remove_file(&path)?;
            std::os::unix::fs::symlink("/run/systemd/resolve/stub-resolv.conf", &path)?;
            std::fs::write(&managed, "nameserver 192.0.2.2\n")?;
            Ok(false)
        })
        .await?;
        assert!(!result);
        assert_eq!(std::fs::read_link(&path)?, managed);
        assert!(std::fs::read_to_string(path)?.contains("192.0.2.2"));
        Ok(())
    }
    #[tokio::test]
    async fn unexpected_administrator_changes_are_not_overwritten() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 192.0.2.1\n")?;
        let error = preserve(&path, async {
            std::fs::write(&path, "nameserver 198.51.100.1\n")?;
            Ok(true)
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("changed unexpectedly"));
        assert!(std::fs::read_to_string(path)?.contains("198.51.100.1"));
        Ok(())
    }
}
