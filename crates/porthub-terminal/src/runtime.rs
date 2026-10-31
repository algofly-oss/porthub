//! Verified private runtime cache. Content-addressed directories allow an old
//! active session to retain its helper when the CLI updates.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: String,
    target: String,
    files: BTreeMap<String, String>,
}

pub struct Runtime {
    pub executable: PathBuf,
    pub terminfo: PathBuf,
    pub version: String,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn relative(path: &Path) -> bool {
    !path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)))
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0,
        "terminal runtime cache must be a private directory owned by the current user"
    );
    Ok(())
}

fn verify(directory: &Path, expected: &Manifest, manifest_bytes: &[u8]) -> Result<Runtime> {
    private_directory(directory)?;
    let mut files = expected.files.clone();
    files.insert("manifest.json".into(), hash(manifest_bytes));
    for (name, digest) in files {
        let path = Path::new(&name);
        ensure!(relative(path), "invalid terminal runtime manifest path");
        let mut current = directory.to_path_buf();
        for component in path.components() {
            current.push(component);
            let metadata = fs::symlink_metadata(&current)?;
            ensure!(
                !metadata.file_type().is_symlink()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.mode() & 0o022 == 0,
                "terminal runtime contains an unsafe path"
            );
        }
        let metadata = fs::symlink_metadata(&current)?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1 && metadata.len() <= 16 * 1024 * 1024,
            "invalid terminal runtime file"
        );
        ensure!(
            hash(&fs::read(&current)?) == digest,
            "terminal runtime checksum mismatch: {name}"
        );
    }
    ensure!(
        expected.files.contains_key("tmux")
            && expected
                .files
                .keys()
                .any(|name| name.starts_with("terminfo/")),
        "terminal runtime is incomplete"
    );
    Ok(Runtime {
        executable: directory.join("tmux"),
        terminfo: directory.join("terminfo"),
        version: expected.version.clone(),
    })
}

/// `bundle` must come from the CLI's embedded, release-validated bytes. Manifest
/// hashes validate installed files; they do not authenticate arbitrary uploads.
pub fn install(bundle: &[u8], cache: &Path, target: &str) -> Result<Runtime> {
    ensure!(
        bundle.len() <= 8 * 1024 * 1024,
        "terminal runtime archive is too large"
    );
    private_directory(cache)?;
    let destination = cache.join(hash(bundle));
    let temporary = tempfile::Builder::new()
        .prefix(".terminal-")
        .tempdir_in(cache)?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    let reader = flate2::read::GzDecoder::new(bundle).take(32 * 1024 * 1024);
    let mut archive = tar::Archive::new(reader);
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        ensure!(
            relative(&path) && seen.insert(path.clone()) && seen.len() <= 128,
            "invalid or duplicate terminal runtime archive path"
        );
        let kind = entry.header().entry_type();
        ensure!(
            kind.is_dir() || kind.is_file(),
            "terminal runtime archive contains a link or special file"
        );
        let output = temporary.path().join(&path);
        if kind.is_dir() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&output)?;
        } else {
            let size = entry.size();
            total = total
                .checked_add(size)
                .context("terminal archive size overflow")?;
            ensure!(
                size <= 16 * 1024 * 1024 && total <= 24 * 1024 * 1024,
                "terminal runtime archive exceeds size limit"
            );
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(output.parent().unwrap())?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&output)?;
            ensure!(
                std::io::copy(&mut entry, &mut file)? == size,
                "truncated terminal runtime archive"
            );
            file.flush()?;
            fs::set_permissions(
                &output,
                fs::Permissions::from_mode(if path == Path::new("tmux") {
                    0o500
                } else {
                    0o400
                }),
            )?;
        }
    }
    let manifest_bytes = fs::read(temporary.path().join("manifest.json"))?;
    ensure!(
        manifest_bytes.len() <= 32768,
        "terminal runtime manifest too large"
    );
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.target == target,
        "terminal runtime target does not match this CLI"
    );
    verify(temporary.path(), &manifest, &manifest_bytes)?;
    if destination.exists() || fs::symlink_metadata(&destination).is_ok() {
        return verify(&destination, &manifest, &manifest_bytes);
    }
    // Concurrent installers can race only at this atomic rename. Neither one
    // overwrites a populated runtime directory belonging to the other.
    match fs::rename(temporary.path(), &destination) {
        Ok(()) => {}
        Err(_) if destination.exists() => {}
        Err(error) => return Err(error.into()),
    }
    verify(&destination, &manifest, &manifest_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bundle(link: bool) -> Result<Vec<u8>> {
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let files = [
            ("tmux", b"test helper".as_slice()),
            ("terminfo/x/xterm", b"terminal".as_slice()),
        ];
        for (name, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o600);
            header.set_cksum();
            tar.append_data(&mut header, name, bytes)?;
        }
        let manifest = serde_json::to_vec(
            &serde_json::json!({"version":"test","target":"test-target",
            "files":files.into_iter().map(|(name,bytes)|(name,hash(bytes))).collect::<BTreeMap<_,_>>()}),
        )?;
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        tar.append_data(&mut header, "manifest.json", manifest.as_slice())?;
        if link {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            tar.append_link(&mut header, "escape", "/tmp")?;
        }
        Ok(tar.into_inner()?.finish()?)
    }

    #[test]
    fn install_checks_target_and_revalidates_existing_content() -> Result<()> {
        let cache = tempfile::tempdir()?;
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700))?;
        let bytes = bundle(false)?;
        assert!(install(&bytes, cache.path(), "wrong-target").is_err());
        let runtime = install(&bytes, cache.path(), "test-target")?;
        assert_eq!(runtime.version, "test");
        assert_eq!(
            runtime.executable.metadata()?.permissions().mode() & 0o777,
            0o500
        );
        assert_eq!(
            install(&bytes, cache.path(), "test-target")?.executable,
            runtime.executable
        );
        fs::set_permissions(&runtime.executable, fs::Permissions::from_mode(0o600))?;
        fs::write(&runtime.executable, b"tampered")?;
        assert!(install(&bytes, cache.path(), "test-target").is_err());
        Ok(())
    }

    #[test]
    fn links_and_shared_cache_directories_are_rejected() -> Result<()> {
        let cache = tempfile::tempdir()?;
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o700))?;
        assert!(install(&bundle(true)?, cache.path(), "test-target").is_err());
        fs::set_permissions(cache.path(), fs::Permissions::from_mode(0o755))?;
        assert!(install(&bundle(false)?, cache.path(), "test-target").is_err());
        Ok(())
    }
}
