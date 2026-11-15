//! Publish an interactive CLI without replacing an unrelated executable.
//! The enclosing service installation lock serializes publication and rollback.
use super::{directory, Layout};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::File;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

enum Previous {
    Missing,
    Link(PathBuf),
    ExistingFile(tempfile::TempDir),
}
fn cli_name() -> &'static str {
    if cfg!(windows) {
        "porthub.exe"
    } else {
        "porthub"
    }
}
pub(crate) struct Publication {
    path: PathBuf,
    target: PathBuf,
    previous: Previous,
    committed: bool,
}
pub(crate) fn hash_file(path: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 256 * 1024 * 1024,
        "CLI target must be a bounded regular file"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == rustix::process::getuid().as_raw()
                && metadata.permissions().mode() & 0o022 == 0,
            "CLI executable is not owned securely"
        );
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    let current = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.dev() == current.dev() && metadata.ino() == current.ino(),
            "CLI executable changed during validation"
        );
    }
    anyhow::ensure!(current.is_file(), "CLI target must be a regular file");
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
/// Hash an existing CLI during an explicit bootstrap adoption. A system or
/// package installer may publish the CLI through a symlink, so resolve that
/// link once and apply the same bounded, owned-file checks to its target.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn hash_adoption_source(path: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            anyhow::ensure!(
                metadata.uid() == rustix::process::getuid().as_raw(),
                "CLI link is not owned by this account"
            );
        }
    } else {
        anyhow::ensure!(metadata.is_file(), "existing CLI is not a regular file");
    }
    let target = std::fs::canonicalize(path)?;
    let metadata = std::fs::symlink_metadata(&target)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 256 * 1024 * 1024,
        "CLI target must be a bounded regular file"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        anyhow::ensure!(
            metadata.permissions().mode() & 0o022 == 0,
            "CLI executable permissions are unsafe"
        );
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(target)?;
    let current = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.dev() == current.dev() && metadata.ino() == current.ino(),
            "CLI executable changed during adoption"
        );
    }
    anyhow::ensure!(current.is_file(), "CLI target must be a regular file");
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn hash_adoption_source(path: &Path) -> Result<String> {
    hash_file(path)
}
fn owned_target(layout: &Layout, target: &Path) -> Result<()> {
    let parent = target
        .parent()
        .context("CLI target has no release directory")?;
    let name = parent
        .file_name()
        .and_then(|name| name.to_str())
        .context("CLI release identity missing")?;
    anyhow::ensure!(
        target.is_absolute()
            && parent.parent() == Some(layout.releases.as_path())
            && target.file_name().is_some_and(|name| name == cli_name())
            && name.len() == 64
            && name.bytes().all(|b| b.is_ascii_hexdigit()),
        "existing CLI is not a managed PortHub release; legacy adoption must be explicit"
    );
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(metadata.is_dir(), "CLI release directory must be real");
    directory(parent, false)?;
    anyhow::ensure!(
        hash_file(target)? == name,
        "managed CLI release checksum mismatch"
    );
    Ok(())
}
/// Read-only ownership check for a native update's shared CLI. Legacy files
/// require adoption; an update may replace only an existing managed link.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn managed_link(layout: &Layout, path: &Path) -> Result<PathBuf> {
    anyhow::ensure!(
        path.is_absolute() && path.file_name().is_some_and(|name| name == cli_name()),
        "native update requires an absolute CLI path"
    );
    let metadata = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        metadata.file_type().is_symlink(),
        "native update requires a managed CLI link"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.uid() == rustix::process::getuid().as_raw(),
            "CLI link ownership is unsafe"
        );
    }
    let parent = path.parent().context("CLI needs a parent directory")?;
    directory(parent, false)?;
    let canonical = std::fs::canonicalize(parent)?;
    for protected in [&layout.state, &layout.releases, &layout.units] {
        anyhow::ensure!(
            !canonical.starts_with(std::fs::canonicalize(protected)?),
            "CLI overlaps managed service state"
        );
    }
    let target = std::fs::read_link(path)?;
    owned_target(layout, &target)?;
    Ok(target)
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn restore_link(
    layout: &Layout,
    path: &Path,
    expected: &Path,
    previous: &Path,
) -> Result<()> {
    let current = managed_link(layout, path)?;
    anyhow::ensure!(
        current == expected || current == previous,
        "shared CLI changed after native update"
    );
    owned_target(layout, previous)?;
    if current != previous {
        replace_link(path, previous)?;
    }
    Ok(())
}
fn state(
    layout: &Layout,
    path: &Path,
    target: &Path,
    legacy_hash: Option<&str>,
) -> Result<Previous> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Previous::Missing),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.uid() == rustix::process::getuid().as_raw(),
                    "CLI link is not owned by this account"
                );
            }
            let previous = std::fs::read_link(path)?;
            if let Some(expected) = legacy_hash {
                anyhow::ensure!(
                    hash_adoption_source(path)? == expected,
                    "existing CLI changed during adoption"
                );
            } else {
                owned_target(layout, &previous)?;
            }
            Ok(Previous::Link(previous))
        }
        Ok(metadata) if metadata.is_file() => {
            let parent = path.parent().context("CLI needs a bin directory")?;
            let backup = private_directory(parent)?;
            let saved = backup.path().join("porthub");
            std::fs::hard_link(path, &saved)?;
            let current_hash = if legacy_hash.is_some() {
                hash_adoption_source(&saved)?
            } else {
                hash_file(&saved)?
            };
            let expected_hash = match legacy_hash {
                Some(hash) => hash.to_owned(),
                None => hash_file(target)?,
            };
            if current_hash != expected_hash {
                #[cfg(windows)]
                {
                    // Windows publishes a regular executable copy rather than
                    // a symlink. Accept an earlier copy only when its bytes are
                    // still backed by a checksum-verified immutable release.
                    anyhow::ensure!(
                        legacy_hash.is_none(),
                        "existing CLI changed during adoption"
                    );
                    let previous = layout.releases.join(&current_hash).join(cli_name());
                    owned_target(layout, &previous)?;
                }
                #[cfg(not(windows))]
                anyhow::bail!("existing CLI is not the selected native binary; legacy adoption must be explicit");
            }
            Ok(Previous::ExistingFile(backup))
        }
        _ => anyhow::bail!("existing CLI is not an owned executable"),
    }
}
fn private_directory(parent: &Path) -> Result<tempfile::TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix(".porthub-cli-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    Ok(builder.tempdir_in(parent)?)
}
#[cfg(unix)]
fn replace_link(path: &Path, target: &Path) -> Result<()> {
    let parent = path.parent().context("CLI needs a bin directory")?;
    let directory = private_directory(parent)?;
    let staged = directory.path().join("porthub");
    std::os::unix::fs::symlink(target, &staged)?;
    // Darwin checks symlink read permission during canonicalization. A root
    // installer with umask 077 must still publish a CLI readable by local users.
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(staged.as_os_str().as_bytes())?;
        if unsafe { libc::lchmod(name.as_ptr(), 0o755) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("cannot set CLI symlink permissions");
        }
    }
    std::fs::rename(staged, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(windows)]
fn replace_link(path: &Path, target: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
    };
    let parent = path.parent().context("CLI needs a bin directory")?;
    let directory = private_directory(parent)?;
    let staged = directory.path().join("porthub.exe");
    std::fs::copy(target, &staged).context("cannot stage the PortHub CLI executable")?;
    let path_wide = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let staged_wide = staged
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let exists = std::fs::symlink_metadata(path).is_ok();
    // SAFETY: Both paths are NUL-terminated UTF-16 strings that remain alive
    // for the duration of the native call. The staged file shares the target
    // volume, so Windows can publish it atomically.
    let result = unsafe {
        if exists {
            ReplaceFileW(
                path_wide.as_ptr(),
                staged_wide.as_ptr(),
                std::ptr::null(),
                REPLACEFILE_WRITE_THROUGH,
                std::ptr::null(),
                std::ptr::null(),
            )
        } else {
            MoveFileExW(
                staged_wide.as_ptr(),
                path_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        }
    };
    anyhow::ensure!(
        result != 0,
        "Windows refused to atomically publish the PortHub CLI ({})",
        std::io::Error::last_os_error()
    );
    Ok(())
}
#[cfg(not(any(unix, windows)))]
fn replace_link(_: &Path, _: &Path) -> Result<()> {
    anyhow::bail!("native CLI publication for this platform is not implemented yet")
}
fn is_published(path: &Path, target: &Path) -> bool {
    #[cfg(unix)]
    {
        std::fs::read_link(path).ok().as_deref() == Some(target)
    }
    #[cfg(windows)]
    {
        hash_file(path).ok() == hash_file(target).ok()
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, target);
        false
    }
}
impl Publication {
    pub(crate) fn prepare(layout: &Layout, path: &Path, target: &Path) -> Result<Self> {
        Self::prepare_inner(layout, path, target, None)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(crate) fn prepare_adoption(
        layout: &Layout,
        path: &Path,
        target: &Path,
        expected_legacy_hash: &str,
    ) -> Result<Self> {
        Self::prepare_inner(layout, path, target, Some(expected_legacy_hash))
    }
    fn prepare_inner(
        layout: &Layout,
        path: &Path,
        target: &Path,
        legacy_hash: Option<&str>,
    ) -> Result<Self> {
        anyhow::ensure!(
            path.is_absolute() && path.file_name().is_some_and(|name| name == cli_name()),
            "CLI bin directory must be absolute"
        );
        let parent = path.parent().context("CLI needs a bin directory")?;
        directory(parent, false)?;
        let parent = std::fs::canonicalize(parent)?;
        for protected in [&layout.state, &layout.releases, &layout.units] {
            anyhow::ensure!(
                !parent.starts_with(std::fs::canonicalize(protected)?),
                "CLI bin directory overlaps managed service state"
            );
        }
        let path = parent.join(cli_name());
        owned_target(layout, target)?;
        let previous = state(layout, &path, target, legacy_hash)?;
        #[cfg(windows)]
        if matches!(&previous, Previous::ExistingFile(_)) && hash_file(&path)? == hash_file(target)?
        {
            // Reinstalling the exact CLI must work while that executable is
            // running. No replacement is needed, and rollback has no bytes to
            // restore because the published content is already identical.
            return Ok(Self {
                path,
                target: target.into(),
                previous,
                committed: true,
            });
        }
        let mut publication = Self {
            path: path.clone(),
            target: target.into(),
            previous,
            committed: false,
        };
        // Do not arm rollback before replacing the pathname. If publication
        // fails before rename, an existing file must remain untouched.
        publication.committed = true;
        if let Err(error) = replace_link(&path, target) {
            if is_published(&path, target) {
                publication.committed = false;
            }
            return Err(error);
        }
        publication.committed = false;
        Ok(publication)
    }
    pub(crate) fn restore(&mut self) -> Result<()> {
        if self.committed {
            return Ok(());
        }
        anyhow::ensure!(
            is_published(&self.path, &self.target),
            "published CLI changed during installation; refusing to replace it"
        );
        match &self.previous {
            Previous::Missing => std::fs::remove_file(&self.path)?,
            Previous::Link(target) => replace_link(&self.path, target)?,
            Previous::ExistingFile(backup) => {
                #[cfg(unix)]
                std::fs::rename(backup.path().join("porthub"), &self.path)?;
                #[cfg(windows)]
                {
                    let saved = backup.path().join("porthub");
                    if hash_file(&self.path)? != hash_file(&saved)? {
                        replace_link(&self.path, &saved)?;
                    }
                }
            }
        }
        #[cfg(unix)]
        File::open(self.path.parent().context("CLI needs a bin directory")?)?.sync_all()?;
        self.committed = true;
        Ok(())
    }
    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}
impl Drop for Publication {
    fn drop(&mut self) {
        if !self.committed && self.restore().is_err() {
            tracing::error!("interactive CLI rollback failed");
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod darwin_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn published_cli_link_is_readable_for_desktop_setup() -> Result<()> {
        let root = tempfile::tempdir()?;
        let binary = root.path().join("release");
        std::fs::write(&binary, b"fixture")?;
        let cli = root.path().join("porthub");
        replace_link(&cli, &binary)?;
        anyhow::ensure!(std::fs::symlink_metadata(&cli)?.permissions().mode() & 0o777 == 0o755);
        anyhow::ensure!(std::fs::read_link(&cli)? == binary);
        anyhow::ensure!(cli.canonicalize()? == binary.canonicalize()?);
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    fn release(layout: &Layout, bytes: &[u8]) -> Result<PathBuf> {
        let hash = format!("{:x}", Sha256::digest(bytes));
        let parent = layout.releases.join(hash);
        std::fs::create_dir_all(&parent)?;
        let executable = parent.join(cli_name());
        std::fs::write(&executable, bytes)?;
        Ok(executable)
    }

    #[test]
    fn managed_regular_cli_updates_roll_back_and_reject_foreign_bytes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let layout = Layout {
            user: false,
            state: root.path().join("native"),
            releases: root.path().join("releases"),
            units: root.path().join("units"),
        };
        for path in [&layout.state, &layout.releases, &layout.units] {
            std::fs::create_dir_all(path)?;
        }
        let old = release(&layout, b"old verified executable")?;
        let new = release(&layout, b"new verified executable")?;
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin)?;
        let cli = bin.join(cli_name());
        std::fs::copy(&old, &cli)?;
        {
            let mut update = Publication::prepare(&layout, &cli, &new)?;
            assert_eq!(hash_file(&cli)?, hash_file(&new)?);
            update.restore()?;
            assert_eq!(hash_file(&cli)?, hash_file(&old)?);
        }
        {
            let mut update = Publication::prepare(&layout, &cli, &new)?;
            update.commit();
        }
        assert_eq!(hash_file(&cli)?, hash_file(&new)?);
        std::fs::write(&cli, b"foreign executable")?;
        assert!(Publication::prepare(&layout, &cli, &new).is_err());
        assert_eq!(std::fs::read(&cli)?, b"foreign executable");
        std::fs::copy(&old, &cli)?;
        std::fs::write(&old, b"corrupted immutable release")?;
        assert!(Publication::prepare(&layout, &cli, &new).is_err());
        assert_eq!(std::fs::read(&cli)?, b"old verified executable");
        Ok(())
    }
}
