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
pub struct Refresh {
    pub catalog: Catalog,
    pub fresh: bool,
}

#[derive(Clone)]
pub struct Manager {
    root: PathBuf,
    settings: Settings,
    transport: Arc<dyn Transport>,
    shared: Option<crate::shared::Cache>,
}

pub(crate) fn regular(path: &Path) -> Result<std::fs::Metadata> {
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
pub(crate) fn directory(path: &Path) -> Result<()> {
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
pub(crate) async fn lock(root: &Path, name: &str, cancel: &CancellationToken) -> Result<File> {
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
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {},
                Err(error) => return Err(error.into()),
            }
            tokio::select! { _ = cancel.cancelled() => anyhow::bail!("component operation cancelled"),
                _ = tokio::time::sleep(Duration::from_millis(100)) => {} }
        }
    }).await?
}
pub fn verified(path: &Path, blob: &crate::catalog::Blob) -> Result<bool> {
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
/// Verify a catalog-authorized archive and extract exactly the requested tool.
/// The caller owns the private output directory and publishes the returned file.
pub fn extract_verified(archive: &Path, root: &Path, artifact: &Artifact, catalog: &Catalog)
    -> Result<tempfile::NamedTempFile>
{
    catalog.validate()?;
    ensure!(catalog.artifacts.iter().any(|entry| entry.same_tool(artifact)
        && entry.release == artifact.release && entry.archive == artifact.archive),
        "component is not authorized by catalog");
    ensure!(verified(archive, &artifact.archive)?, "component archive checksum mismatch");
    let allowed = catalog.artifacts.iter().filter(|entry| entry.target == artifact.target
        && entry.release == artifact.release).map(|entry| PathBuf::from(entry.member())).collect();
    extract(archive, root, artifact, &allowed)
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
            allowed.contains(&path) || path == Path::new(".porthub-build-receipts.json"),
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
        if path == Path::new(".porthub-build-receipts.json") {
            // Authenticated archive metadata is retained for future CI reuse only.
            // Never write it into the executable cache or use it as a path.
            ensure!(size > 0 && size <= 8 * 1024 * 1024, "build receipts exceed size limit");
            let copied = std::io::copy(&mut entry, &mut std::io::sink())?;
            ensure!(copied == size, "build receipts are truncated");
        } else if path == Path::new(&artifact.member()) {
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
// macOS exposes standard /var, /tmp and /etc aliases as root-owned
// symlinks. Normalize only those OS aliases, never arbitrary cache symlinks.
#[cfg(target_os = "macos")]
pub(crate) fn normalize_system_alias(root: PathBuf) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    for alias in ["/var", "/tmp", "/etc"] {
        let base = Path::new(alias);
        if let Ok(relative) = root.strip_prefix(base) {
            let metadata = std::fs::symlink_metadata(base)?;
            if !metadata.file_type().is_symlink() {
                return Ok(root);
            }
            let target = std::fs::canonicalize(base)?;
            ensure!(
                metadata.uid() == 0
                    && target == Path::new("/private").join(base.file_name().unwrap()),
                "untrusted macOS system directory alias"
            );
            return Ok(target.join(relative));
        }
    }
    Ok(root)
}
impl Manager {
    pub fn cache_root(&self) -> &Path {
        &self.root
    }
    pub fn new(root: PathBuf, settings: Settings, transport: Arc<dyn Transport>) -> Result<Self> {
        settings.validate()?;
        ensure!(
            root.is_absolute()
                && !root
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "component cache requires an absolute normalized path"
        );
        #[cfg(target_os = "macos")]
        let root = normalize_system_alias(root)?;
        directory(&root)?;
        Ok(Self {
            root,
            settings,
            transport,
            shared: None,
        })
    }
    pub fn with_shared_cache(mut self, root: PathBuf, publish: bool) -> Result<Self> {
        self.shared = Some(if publish {
            crate::shared::Cache::writer(root)?
        } else {
            crate::shared::Cache::reader(root)?
        });
        Ok(self)
    }
    pub fn cached_catalog(&self) -> Result<Option<Catalog>> {
        let private = self.private_catalog()?;
        let shared = self
            .shared
            .as_ref()
            .and_then(|cache| cache.catalog().ok().flatten());
        Ok(match (private, shared) {
            (Some(private), Some(shared)) if shared.release > private.release => Some(shared),
            (Some(private), _) => Some(private),
            (None, shared) => shared,
        })
    }
    fn private_catalog(&self) -> Result<Option<Catalog>> {
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
        Ok(self.refresh_state(cancel).await?.catalog)
    }
    pub async fn refresh_state(&self, cancel: &CancellationToken) -> Result<Refresh> {
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
                        catalog.validate_successor(previous)?;
                    }
                    publish(temporary, &self.root.join(CATALOG_ASSET), false)?;
                    self.mirror_catalog(&catalog).await;
                    return Ok(Refresh {
                        catalog,
                        fresh: true,
                    });
                }
                Err(error) if error.is::<AccessDenied>() => return Err(error),
                Err(_) if cancel.is_cancelled() => anyhow::bail!("component operation cancelled"),
                Err(_) => {}
            }
        }
        cached
            .map(|catalog| Refresh {
                catalog,
                fresh: false,
            })
            .context("component catalog unavailable from allowed download sources")
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
        let destination = self.binary_path(&artifact);
        let check_path = destination.clone();
        let blob = artifact.executable.clone();
        if tokio::task::spawn_blocking(move || verified(&check_path, &blob)).await?? {
            self.record(&artifact)?;
            self.mirror_artifact(&artifact, &destination).await;
            return Ok(destination);
        }
        if let Some(shared) = self.shared.clone() {
            let mut temporary = tempfile::NamedTempFile::new_in(&self.root)?;
            let copy = artifact.clone();
            let result = tokio::task::spawn_blocking(move || {
                if shared.copy_into(&copy, temporary.as_file_mut())? {
                    Ok(Some(temporary))
                } else {
                    Ok::<_, anyhow::Error>(None)
                }
            })
            .await?;
            if let Ok(Some(temporary)) = result {
                publish(temporary, &destination, true)?;
                self.record(&artifact)?;
                return Ok(destination);
            }
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
                        self.record(&artifact)?;
                        self.mirror_artifact(&artifact, &destination).await;
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
        let extraction = artifact.clone();
        let file = tokio::task::spawn_blocking(move || {
            extract(archive.path(), &root, &extraction, &allowed)
        })
        .await??;
        publish(file, &destination, true)?;
        self.record(&artifact)?;
        self.mirror_artifact(&artifact, &destination).await;
        Ok(destination)
    }
    async fn remember_catalog(&self, catalog: &Catalog, cancel: &CancellationToken) -> Result<()> {
        let _lock = lock(&self.root, "catalog.lock", cancel).await?;
        if let Some(previous) = self.private_catalog()? {
            if previous.release > catalog.release {
                return Ok(());
            }
            catalog.validate_successor(&previous)?;
            if previous.release == catalog.release {
                return Ok(());
            }
        }
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.write_all(&serde_json::to_vec(catalog)?)?;
        publish(file, &self.root.join(CATALOG_ASSET), false)
    }
    async fn mirror_catalog(&self, catalog: &Catalog) {
        if let Some(shared) = self.shared.clone().filter(|cache| cache.is_writer()) {
            let catalog = catalog.clone();
            if !matches!(
                tokio::task::spawn_blocking(move || shared.publish_catalog(&catalog)).await,
                Ok(Ok(()))
            ) {
                tracing::warn!(
                    "shared component catalog unavailable; private cache remains usable"
                );
            }
        }
    }
    async fn mirror_artifact(&self, artifact: &Artifact, binary: &Path) {
        if let Some(shared) = self.shared.clone().filter(|cache| cache.is_writer()) {
            let artifact = artifact.clone();
            let binary = binary.to_owned();
            if !matches!(
                tokio::task::spawn_blocking(move || shared.publish_artifact(&artifact, &binary))
                    .await,
                Ok(Ok(()))
            ) {
                tracing::warn!(
                    "shared component publication unavailable; private tool remains usable"
                );
            }
        }
    }
    fn binary_path(&self, artifact: &Artifact) -> PathBuf {
        self.root.join(format!(
            "{}-{}-{}{}",
            artifact.component,
            artifact.version,
            artifact.executable.sha256,
            if artifact.target.contains("windows") {
                ".exe"
            } else {
                ""
            }
        ))
    }
    fn record(&self, artifact: &Artifact) -> Result<()> {
        let path = self.root.join(format!(
            "installed-{}-{}-{}.json",
            artifact.component, artifact.version, artifact.target
        ));
        if path.try_exists()? {
            let metadata = regular(&path)?;
            ensure!(
                metadata.len() <= 16384,
                "installed component receipt exceeds limit"
            );
            let previous: Artifact = serde_json::from_slice(&std::fs::read(&path)?)?;
            ensure!(
                previous.same_tool(artifact),
                "installed component version changed"
            );
            return Ok(());
        }
        let mut file = tempfile::NamedTempFile::new_in(&self.root)?;
        file.write_all(&serde_json::to_vec(artifact)?)?;
        publish(file, &path, false)
    }
    /// Receipts retain installation intent even when the old binary is missing
    /// or no longer compatible after a core upgrade.
    pub async fn has_installation(&self, component: Component) -> Result<bool> {
        let root = self.root.clone();
        let target = self.settings.target.clone();
        tokio::task::spawn_blocking(move || {
            let prefix = format!("installed-{component}-");
            for (count, entry) in std::fs::read_dir(root)?.enumerate() {
                ensure!(
                    count < 4096,
                    "component cache needs cleanup; too many entries"
                );
                let path = entry?.path();
                if !path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with(&prefix) && s.ends_with(".json"))
                {
                    continue;
                }
                ensure!(
                    regular(&path)?.len() <= 16384,
                    "installed component receipt exceeds limit"
                );
                let artifact: Artifact = serde_json::from_slice(&std::fs::read(&path)?)?;
                artifact.validate()?;
                if artifact.component == component && artifact.target == target {
                    return Ok(true);
                }
            }
            Ok(false)
        })
        .await?
    }
    /// Verified local versions are independent of the gateway's inventory.
    /// Receipts retain older tool metadata when the latest catalog advances.
    pub async fn installed(&self, component: Component) -> Result<Vec<(Artifact, PathBuf)>> {
        ensure!(
            !self.settings.disabled.contains(&component),
            "component disabled by administrator policy"
        );
        let manager = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut installed = Vec::new();
            let prefix = format!("installed-{component}-");
            let mut count = 0;
            for entry in std::fs::read_dir(&manager.root)? {
                let path = entry?.path();
                count += 1;
                ensure!(
                    count <= 4096,
                    "component cache needs cleanup; too many entries"
                );
                if !path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.starts_with(&prefix) && s.ends_with(".json"))
                {
                    continue;
                }
                ensure!(
                    regular(&path)?.len() <= 16384,
                    "installed component receipt exceeds limit"
                );
                let artifact: Artifact = serde_json::from_slice(&std::fs::read(&path)?)?;
                artifact.validate()?;
                if artifact.component != component
                    || artifact.target != manager.settings.target
                    || !artifact.core.matches(&manager.settings.core)
                    || !artifact.protocols.contains(&crate::catalog::PROTOCOL)
                    || manager
                        .settings
                        .pins
                        .get(&component)
                        .is_some_and(|pin| pin != &artifact.version)
                {
                    continue;
                }
                let binary = manager.binary_path(&artifact);
                if verified(&binary, &artifact.executable)? {
                    installed.push((artifact, binary));
                }
            }
            installed.sort_by(|a, b| b.0.version.cmp(&a.0.version));
            Ok(installed)
        })
        .await?
    }
    /// Interactive commands use the current local catalog immediately. The
    /// maintenance worker refreshes it separately; first use fetches if absent.
    pub async fn resolve(
        &self,
        component: Component,
        cancel: &CancellationToken,
    ) -> Result<(Artifact, PathBuf)> {
        let catalog = match self.cached_catalog()? {
            Some(catalog) => catalog,
            None => self.refresh(cancel).await?,
        };
        let latest = self.selected(&catalog, component)?.clone();
        self.remember_catalog(&catalog, cancel).await?;
        match self.ensure(&catalog, component, cancel).await {
            Ok(path) => Ok((latest, path)),
            Err(error) => {
                if error.is::<AccessDenied>() || cancel.is_cancelled() {
                    return Err(error);
                }
                if let Some((artifact, path)) = self
                    .installed(component)
                    .await?
                    .into_iter()
                    .find(|(a, _)| a.version <= latest.version)
                {
                    tracing::warn!(component = %component, version = %artifact.version, "using verified compatible local component; update unavailable");
                    return Ok((artifact, path));
                }
                Err(error)
            }
        }
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
