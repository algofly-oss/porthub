//! Local durable end markers bridge database outages. They contain no capabilities
//! or terminal contents and must live on the API's persistent data volume.
use anyhow::{ensure, Result};
use std::{
    fs::{self, OpenOptions},
    path::{Path, PathBuf},
};

fn valid(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "invalid terminal journal directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}
pub(crate) fn record(path: &Path, id: &str) -> Result<()> {
    ensure!(valid(id), "invalid terminal journal identity");
    directory(path)?;
    let file_path = path.join(id);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&file_path) {
        Ok(file) => file.sync_all()?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            ensure!(
                fs::symlink_metadata(file_path)?.is_file(),
                "invalid terminal journal marker"
            );
        }
        Err(error) => return Err(error.into()),
    }
    sync_directory(path)?;
    // Persist creation of the journal directory as well as the marker itself.
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}
pub(crate) fn contains(path: &Path, id: &str) -> Result<bool> {
    ensure!(valid(id), "invalid terminal journal identity");
    match fs::symlink_metadata(path.join(id)) {
        Ok(_) => Ok(true), // Even malformed markers fail closed.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
pub(crate) fn pending(path: &Path) -> Result<Vec<String>> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut ids = Vec::new();
    for entry in entries {
        let name = entry?.file_name();
        let Some(id) = name.to_str() else { continue };
        if valid(id) {
            ids.push(id.to_owned());
        }
        if ids.len() == 64 {
            break;
        }
    }
    Ok(ids)
}
pub(crate) fn remove(path: &Path, id: &str) -> Result<()> {
    ensure!(valid(id), "invalid terminal journal identity");
    match fs::remove_file(path.join(id)) {
        Ok(()) => sync_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
pub(crate) async fn run<T: Send + 'static>(
    job: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    tokio::task::spawn_blocking(job).await?
}
pub(crate) async fn is_ended(path: Option<PathBuf>, id: String) -> Result<bool> {
    match path {
        Some(path) => run(move || contains(&path, &id)).await,
        None => Ok(false),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn marker_survives_reopen_and_is_removed_only_explicitly() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("ends");
        let id = "0123456789abcdef0123456789abcdef";
        assert!(!contains(&path, id)?);
        record(&path, id)?;
        record(&path, id)?;
        assert_eq!(pending(&path)?, vec![id]);
        assert!(contains(&PathBuf::from(&path), id)?);
        assert!(record(&path, "../unsafe").is_err());
        remove(&path, id)?;
        assert!(!contains(&path, id)?);
        Ok(())
    }
    #[cfg(unix)]
    #[test]
    fn directory_symlinks_are_rejected_and_marker_symlinks_fail_closed() -> Result<()> {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("ends");
        fs::create_dir(&path)?;
        let alias = temp.path().join("alias");
        symlink(&path, &alias)?;
        let id = "0123456789abcdef0123456789abcdef";
        assert!(record(&alias, id).is_err());
        symlink(temp.path().join("missing"), path.join(id))?;
        assert!(contains(&path, id)?);
        assert!(record(&path, id).is_err());
        Ok(())
    }
}
