use crate::{
    catalog::{Artifact, Catalog, Component, CATALOG_ASSET, MAX_CATALOG, REPOSITORY},
    transport::{AccessDenied, Transport},
};
use anyhow::{ensure, Context, Result};
use fs2::FileExt;
use semver::Version;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sources {
    GatewayThenGithub,
    GatewayOnly,
    GithubOnly,
}
#[derive(Clone)]
pub struct Settings {
    pub gateway: Option<Url>,
    pub sources: Sources,
    pub core: Version,
    pub target: String,
    pub disabled: BTreeSet<Component>,
    pub pins: BTreeMap<Component, Version>,
}
impl Settings {
    fn validate(&self) -> Result<()> {
        ensure!(
            crate::catalog::TARGETS.contains(&self.target.as_str()),
            "unsupported component target"
        );
        ensure!(
            self.sources != Sources::GatewayOnly || self.gateway.is_some(),
            "gateway-only components require a gateway"
        );
        if let Some(gateway) = &self.gateway {
            ensure!(
                gateway.has_host()
                    && gateway.username().is_empty()
                    && gateway.password().is_none()
                    && gateway.query().is_none()
                    && gateway.fragment().is_none(),
                "invalid component gateway"
            );
        }
        Ok(())
    }
    fn gateway_url(&self, path: &str) -> Result<Option<Url>> {
        self.gateway
            .as_ref()
            .map(|gateway| {
                // Preserve installations served below a path prefix.
                Url::parse(&format!(
                    "{}/{path}",
                    gateway.as_str().trim_end_matches('/')
                ))
                .map_err(Into::into)
            })
            .transpose()
    }
}
#[derive(Clone)]
pub struct Manager {
    root: PathBuf,
    settings: Settings,
    transport: Arc<dyn Transport>,
}

fn regular(path: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "unsafe component file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == rustix::process::geteuid().as_raw() && metadata.mode() & 0o022 == 0,
            "component file is not owned securely"
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "component file is a reparse point"
        );
    }
    Ok(metadata)
}
fn directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for ancestor in path.ancestors().skip(1) {
            let Ok(meta) = std::fs::symlink_metadata(ancestor) else {
                continue;
            };
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "unsafe component cache ancestor"
            );
            ensure!(
                (meta.uid() == 0 || meta.uid() == rustix::process::geteuid().as_raw())
                    && (meta.mode() & 0o022 == 0 || meta.uid() == 0 && meta.mode() & 0o1000 != 0),
                "component cache ancestor is writable by another account: {}",
                ancestor.display()
            );
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "unsafe component directory"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                ensure!(
                    meta.uid() == rustix::process::geteuid().as_raw() && meta.mode() & 0o077 == 0,
                    "component cache must be private and owned by this account"
                );
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                ensure!(
                    meta.file_attributes() & 0x400 == 0,
                    "component cache is a reparse point"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .context("component directory requires a parent")?;
            let metadata = std::fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "unsafe component directory parent"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{DirBuilderExt, MetadataExt};
                // A sticky temporary directory is acceptable for a new private cache.
                ensure!(
                    (metadata.uid() == rustix::process::geteuid().as_raw()
                        && metadata.mode() & 0o022 == 0)
                        || metadata.uid() == 0 && metadata.mode() & 0o1000 != 0,
                    "component directory parent is not owned securely"
                );
                match std::fs::DirBuilder::new().mode(0o700).create(path) {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(e.into()),
                }
            }
            #[cfg(not(unix))]
            match std::fs::create_dir(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
            return directory(path);
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(windows)]
    crate::windows_security::secure_directory(path)?;
    Ok(())
}
async fn lock(root: &Path, name: &str, cancel: &CancellationToken) -> Result<File> {
    directory(root)?;
    let path = root.join(name);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&path)?;
    regular(&path)?;
    tokio::time::timeout(Duration::from_secs(330), async {
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => return Ok(file),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {},
                Err(error) => return Err(error.into()),
            }
            tokio::select! { _ = cancel.cancelled() => anyhow::bail!("component operation cancelled"),
                _ = tokio::time::sleep(Duration::from_millis(100)) => {} }
        }
    }).await?
}
fn verified(path: &Path, blob: &crate::catalog::Blob) -> Result<bool> {
    let metadata = match regular(path) {
        Ok(metadata) => metadata,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Ok(false)
        }
        Err(error) => return Err(error),
    };
    if metadata.len() != blob.size {
        return Ok(false);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let size = file.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    Ok(format!("{:x}", hasher.finalize()) == blob.sha256)
}
fn publish(mut file: tempfile::NamedTempFile, destination: &Path, executable: bool) -> Result<()> {
    file.as_file_mut().flush()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(if executable {
                0o700
            } else {
                0o600
            }))?;
    }
    file.as_file().sync_all()?;
    file.persist(destination).map_err(|e| e.error)?;
    #[cfg(unix)]
    File::open(
        destination
            .parent()
            .context("component destination requires a parent")?,
    )?
    .sync_all()?;
    Ok(())
}
fn extract(
    archive: &Path,
    root: &Path,
    artifact: &Artifact,
    allowed: &BTreeSet<PathBuf>,
) -> Result<tempfile::NamedTempFile> {
    let decoder = flate2::read::GzDecoder::new(File::open(archive)?);
    let mut archive = tar::Archive::new(decoder);
    let mut result = None;
    let mut names = BTreeSet::new();
    let mut expanded = 0u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        ensure!(
            path.components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
            "unsafe component archive path"
        );
        ensure!(
            allowed.contains(&path),
            "unexpected executable in component archive"
        );
        ensure!(
            entry.header().entry_type().is_file(),
            "component archive must contain only regular executables"
        );
        ensure!(
            names.insert(path.clone()) && names.len() <= 128,
            "duplicate or excessive component archive entries"
        );
        let size = entry.header().size()?;
        expanded = expanded
            .checked_add(size)
            .context("component archive size overflow")?;
        ensure!(
            expanded <= 1024 * 1024 * 1024 && size <= crate::catalog::MAX_EXECUTABLE,
            "component archive expands beyond limit"
        );
        if path == Path::new(&artifact.member()) {
            ensure!(
                size == artifact.executable.size,
                "component archive executable size mismatch"
            );
            let mut temporary = tempfile::NamedTempFile::new_in(root)?;
            let copied = std::io::copy(&mut entry, temporary.as_file_mut())?;
            ensure!(copied == size, "component archive is truncated");
            ensure!(
                verified(temporary.path(), &artifact.executable)?,
                "component executable checksum mismatch"
            );
            result = Some(temporary);
        } else {
            // Validate other tools rather than extracting them. Exact member names
            // come from their catalog entries; no archive name is used as a path.
            ensure!(size > 0, "empty component archive executable");
            std::io::copy(&mut entry, &mut std::io::sink())?;
        }
    }
    result.context("requested executable is missing from component archive")
}
impl Manager {
    pub fn new(root: PathBuf, settings: Settings, transport: Arc<dyn Transport>) -> Result<Self> {
        settings.validate()?;
        ensure!(
            root.is_absolute()
                && !root
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "component cache requires an absolute normalized path"
        );
        directory(&root)?;
        Ok(Self {
            root,
            settings,
            transport,
        })
    }
    pub fn cached_catalog(&self) -> Result<Option<Catalog>> {
        let path = self.root.join(CATALOG_ASSET);
        match regular(&path) {
            Ok(metadata) => {
                ensure!(
                    metadata.len() <= MAX_CATALOG as u64,
                    "cached component catalog exceeds size limit"
                );
                Ok(Some(Catalog::parse(&std::fs::read(path)?)?))
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    async fn fetch(
        &self,
        url: &Url,
        file: &Path,
        max: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        tokio::select! { biased; _ = cancel.cancelled() => anyhow::bail!("component operation cancelled"),
        result = self.transport.fetch(url, file, max) => result }
    }
    pub async fn refresh(&self, cancel: &CancellationToken) -> Result<Catalog> {
        let _lock = lock(&self.root, "catalog.lock", cancel).await?;
        let cached = self.cached_catalog()?;
        let mut sources = Vec::new();
        if self.settings.sources != Sources::GithubOnly {
            if let Some(url) = self
                .settings
                .gateway_url("api/downloads/components/catalog")?
            {
                sources.push(url);
            }
        }
        if self.settings.sources != Sources::GatewayOnly {
            sources.push(Url::parse(&format!(
                "https://github.com/{REPOSITORY}/releases/latest/download/{CATALOG_ASSET}"
            ))?);
        }
        for source in sources {
            let temporary = tempfile::NamedTempFile::new_in(&self.root)?;
            match self
                .fetch(&source, temporary.path(), MAX_CATALOG as u64, cancel)
                .await
            {
                Ok(()) => {
                    let catalog = Catalog::parse(&std::fs::read(temporary.path())?)?;
                    if let Some(previous) = &cached {
                        ensure!(
                            catalog.release >= previous.release,
                            "component catalog downgrade rejected"
                        );
                        if catalog.release == previous.release {
                            ensure!(
                                serde_json::to_vec(&catalog)? == serde_json::to_vec(previous)?,
                                "published component catalog changed"
                            );
                        }
                    }
                    publish(temporary, &self.root.join(CATALOG_ASSET), false)?;
                    return Ok(catalog);
                }
                Err(error) if error.is::<AccessDenied>() => return Err(error),
                Err(_) if cancel.is_cancelled() => anyhow::bail!("component operation cancelled"),
                Err(_) => {}
            }
        }
        cached.context("component catalog unavailable from allowed download sources")
    }
    pub fn selected<'a>(&self, catalog: &'a Catalog, component: Component) -> Result<&'a Artifact> {
        ensure!(
            !self.settings.disabled.contains(&component),
            "component disabled by administrator policy"
        );
        catalog
            .select(
                component,
                &self.settings.core,
                &self.settings.target,
                self.settings.pins.get(&component),
            )
            .context("no compatible component for this core, platform, and version preference")
    }
    pub async fn ensure(
        &self,
        catalog: &Catalog,
        component: Component,
        cancel: &CancellationToken,
    ) -> Result<PathBuf> {
        catalog.validate()?;
        let artifact = self.selected(catalog, component)?.clone();
        let _lock = lock(&self.root, &format!("{component}.lock"), cancel).await?;
        // Content-addressed paths keep active workers and previous versions intact.
        let destination = self.root.join(format!(
            "{}-{}-{}{}",
            component,
            artifact.version,
            artifact.executable.sha256,
            if artifact.target.contains("windows") {
                ".exe"
            } else {
                ""
            }
        ));
        let check_path = destination.clone();
        let blob = artifact.executable.clone();
        if tokio::task::spawn_blocking(move || verified(&check_path, &blob)).await?? {
            return Ok(destination);
        }
        if self.settings.sources != Sources::GithubOnly {
            if let Some(url) = self.settings.gateway_url(&artifact.gateway_path())? {
                let temporary = tempfile::NamedTempFile::new_in(&self.root)?;
                match self
                    .fetch(&url, temporary.path(), artifact.executable.size, cancel)
                    .await
                {
                    Ok(()) => {
                        ensure!(
                            verified(temporary.path(), &artifact.executable)?,
                            "gateway component checksum mismatch"
                        );
                        publish(temporary, &destination, true)?;
                        return Ok(destination);
                    }
                    Err(error) if error.is::<AccessDenied>() => return Err(error),
                    Err(_) if cancel.is_cancelled() => {
                        anyhow::bail!("component operation cancelled")
                    }
                    Err(_) => {}
                }
            }
        }
        ensure!(
            self.settings.sources != Sources::GatewayOnly,
            "component unavailable from gateway; GitHub fallback disabled"
        );
        let archive = tempfile::NamedTempFile::new_in(&self.root)?;
        self.fetch(
            &Url::parse(&artifact.github_url())?,
            archive.path(),
            artifact.archive.size,
            cancel,
        )
        .await?;
        ensure!(
            verified(archive.path(), &artifact.archive)?,
            "component archive checksum mismatch"
        );
        let root = self.root.clone();
        let allowed = catalog
            .artifacts
            .iter()
            .filter(|a| a.release == artifact.release && a.target == artifact.target)
            .map(|a| PathBuf::from(a.member()))
            .collect();
        let file = tokio::task::spawn_blocking(move || {
            extract(archive.path(), &root, &artifact, &allowed)
        })
        .await??;
        publish(file, &destination, true)?;
        Ok(destination)
    }
    /// Downloads are serialized here; commands coalesce through the same locks.
    pub async fn prefetch(&self, cancel: &CancellationToken) -> Result<()> {
        let catalog = self.refresh(cancel).await?;
        for component in Component::OPTIONAL {
            if cancel.is_cancelled() {
                break;
            }
            if self.selected(&catalog, component).is_err() {
                continue;
            }
            if self.ensure(&catalog, component, cancel).await.is_err() && !cancel.is_cancelled() {
                tracing::warn!(component = %component, "optional component prefetch unavailable; core remains active");
            }
        }
        Ok(())
    }
}
