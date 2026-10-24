use anyhow::{Context, Result};
use std::{
    io::Write,
    path::{Path, PathBuf},
};

pub fn directory(kind: &str) -> Result<PathBuf> {
    let base = match std::env::var_os("PORTHUB_STATE_DIR") {
        Some(path) => PathBuf::from(path),
        None => directories::BaseDirs::new()
            .context("cannot find the user's state directory")?
            .data_local_dir()
            .join("porthub"),
    };
    let path = base.join(kind);
    std::fs::create_dir_all(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(path)
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .context("checkpoint requires a parent directory")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".porthub-checkpoint-")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// Publish without replacement on Windows, macOS and Linux, including file
/// systems without hard links. Failed publication must keep resume data intact.
pub async fn publish(part: &Path, target: &Path) -> Result<()> {
    let part = part.to_owned();
    let target = target.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut path = tempfile::TempPath::try_from_path(part)?;
        path.disable_cleanup(true);
        path.persist_noclobber(target).map_err(|error| error.error)
    })
    .await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn publication_never_overwrites_and_keeps_partial_on_collision() {
        let directory = tempfile::tempdir().unwrap();
        let part = directory.path().join("download.part");
        let target = directory.path().join("download");
        std::fs::write(&part, b"new contents").unwrap();
        std::fs::write(&target, b"existing contents").unwrap();
        assert!(publish(&part, &target).await.is_err());
        assert_eq!(std::fs::read(&part).unwrap(), b"new contents");
        assert_eq!(std::fs::read(&target).unwrap(), b"existing contents");
        std::fs::remove_file(&target).unwrap();
        publish(&part, &target).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new contents");
        assert!(!part.exists());
    }
    #[test]
    fn checkpoint_replacement_remains_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("checkpoint");
        write_private(&path, b"first").unwrap();
        write_private(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
