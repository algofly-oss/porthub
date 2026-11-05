//! Lazy, persistent GitHub release cache. Metadata is shared; binaries are
//! fetched only for a requested target and published only after verification.
use crate::artifacts::{Release, TARGETS};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    sync::{Mutex, OnceCell, Semaphore},
};

const MAX_BINARY: u64 = 256 * 1024 * 1024;
const REFRESH: Duration = Duration::from_secs(300);
const MARKER: &str = ".porthub-release-cache";

#[derive(Clone, Deserialize, Serialize)]
struct Index {
    format_version: u32,
    repository: String,
    version: String,
    etag: Option<String>,
    releases: BTreeMap<String, Release>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    components: Option<porthub_components::catalog::Catalog>,
}
struct State {
    index: Option<Index>,
    retry_at: Instant,
    checked_at: Instant,
    failed: bool,
}
#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}
#[derive(Deserialize)]
struct GithubAsset {
    name: String,
    size: u64,
    digest: Option<String>,
    state: String,
}

pub struct Remote {
    root: PathBuf,
    repository: String,
    metadata_url: String,
    download_base: String,
    http: reqwest::Client,
    state: RwLock<State>,
    refresh: Mutex<()>,
    initialized: OnceCell<()>,
    targets: BTreeMap<&'static str, Mutex<()>>,
    downloads: Semaphore,
    component_download: Mutex<()>,
    background: AtomicBool,
}

fn numeric_version(value: &str) -> Option<[u64; 3]> {
    let values: Vec<_> = value.split('.').collect();
    if values.len() != 3 {
        return None;
    }
    let mut version = [0; 3];
    for (i, value) in values.iter().enumerate() {
        if value.is_empty()
            || value.len() > 10
            || !value.bytes().all(|b| b.is_ascii_digit())
            || value.len() > 1 && value.starts_with('0')
        {
            return None;
        }
        version[i] = value.parse().ok()?;
    }
    Some(version)
}
fn asset_name(target: &str, os: &str) -> String {
    format!(
        "porthub-{target}{}",
        if os == "windows" { ".exe" } else { "" }
    )
}
impl Index {
    fn validate(&self, repository: &str) -> Result<()> {
        ensure!(
            self.format_version == 1
                && self.repository == repository
                && numeric_version(&self.version).is_some()
                && self.releases.len() == TARGETS.len(),
            "invalid release cache index"
        );
        if let Some(components) = &self.components {
            components.validate()?;
            ensure!(components.release.to_string() == self.version, "cached component release differs");
        }
        for (target, os, arch) in TARGETS {
            let release = self
                .releases
                .get(*target)
                .context("release target missing")?;
            ensure!(
                release.target == *target
                    && release.os == *os
                    && release.arch == *arch
                    && release.asset == asset_name(target, os)
                    && release.version == self.version
                    && release.sha256.len() == 64
                    && release.sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    && (1..=MAX_BINARY).contains(&release.size),
                "invalid release target metadata"
            );
        }
        Ok(())
    }
}

impl Remote {
    pub fn github(root: PathBuf, repository: &str) -> Result<Arc<Self>> {
        let parts: Vec<_> = repository.split('/').collect();
        ensure!(
            parts.len() == 2
                && parts.iter().all(|part| !part.is_empty()
                    && part.len() <= 100
                    && !matches!(*part, "." | "..")
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))),
            "invalid agent release repository"
        );
        Self::new(
            root,
            repository.into(),
            format!("https://api.github.com/repos/{repository}/releases/latest"),
            format!("https://github.com/{repository}/releases/download"),
            false,
        )
    }
    fn new(
        root: PathBuf,
        repository: String,
        metadata_url: String,
        download_base: String,
        fixture: bool,
    ) -> Result<Arc<Self>> {
        ensure!(
            root.is_absolute(),
            "agent release cache requires an absolute path"
        );
        let http = reqwest::Client::builder()
            .user_agent("PortHub-release-cache")
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(180))
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(move |attempt| {
                let host = attempt.url().host_str().unwrap_or_default();
                if attempt.previous().len() >= 5 {
                    return attempt.stop();
                }
                if fixture && host == "127.0.0.1"
                    || attempt.url().scheme() == "https"
                        && (host == "github.com"
                            || host == "api.github.com"
                            || host.ends_with(".githubusercontent.com")
                            || host.ends_with(".blob.core.windows.net"))
                {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()?;
        let cached = (|| {
            if !regular(&root, true).ok()?
                || !regular(&root.join(MARKER), false).ok()?
                || std::fs::read_to_string(root.join(MARKER)).ok()?.trim() != repository
                || !regular(&root.join("latest.json"), false).ok()?
            {
                return None;
            }
            let bytes = std::fs::read(root.join("latest.json")).ok()?;
            if bytes.len() > 256 * 1024 {
                return None;
            }
            let index: Index = serde_json::from_slice(&bytes).ok()?;
            index.validate(&repository).ok()?;
            Some(index)
        })();
        Ok(Arc::new(Self {
            root,
            repository,
            metadata_url,
            download_base,
            http,
            state: RwLock::new(State {
                index: cached,
                retry_at: Instant::now(),
                checked_at: Instant::now() - REFRESH,
                failed: false,
            }),
            refresh: Mutex::new(()),
            initialized: OnceCell::new(),
            targets: TARGETS
                .iter()
                .map(|(target, _, _)| (*target, Mutex::new(())))
                .collect(),
            downloads: Semaphore::new(2),
            component_download: Mutex::new(()),
            background: AtomicBool::new(false),
        }))
    }
    pub fn version(&self) -> Option<String> {
        self.state
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .index
            .as_ref()
            .map(|index| index.version.clone())
    }
    /// Called by control requests; no network wait is added to their path.
    pub fn refresh_background(self: &Arc<Self>) {
        if Instant::now()
            < self
                .state
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .retry_at
        {
            return;
        }
        if self
            .background
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            struct Reset(Arc<Remote>);
            impl Drop for Reset {
                fn drop(&mut self) {
                    self.0.background.store(false, Ordering::Release);
                }
            }
            let _reset = Reset(this.clone());
            let _ = this.latest(false).await;
        });
    }
    async fn initialize(&self) -> Result<()> {
        self.initialized
            .get_or_try_init(|| async {
                let root = self.root.clone();
                let repository = self.repository.clone();
                tokio::task::spawn_blocking(move || {
                    if !root.try_exists()? {
                        std::fs::create_dir_all(&root)?;
                    }
                    ensure!(
                        regular(&root, true)?,
                        "unsafe agent release cache directory"
                    );
                    let marker = root.join(MARKER);
                    if marker.try_exists()? {
                        ensure!(
                            regular(&marker, false)?
                                && std::fs::read_to_string(&marker)?.trim() == repository,
                            "agent cache belongs to another repository"
                        );
                    } else {
                        ensure!(
                            std::fs::read_dir(&root)?.next().is_none(),
                            "refusing to adopt a nonempty release cache"
                        );
                        atomic(&marker, repository.as_bytes())?;
                    }
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
                Ok::<_, anyhow::Error>(())
            })
            .await?;
        Ok(())
    }
    async fn latest(&self, force: bool) -> Result<Index> {
        let existing = || {
            let state = self.state.read().unwrap_or_else(|p| p.into_inner());
            (
                state.index.clone(),
                Instant::now() < state.retry_at
                    && (!force
                        || state.failed
                        || state.checked_at.elapsed() < Duration::from_secs(1)),
            )
        };
        let (cached, fresh) = existing();
        if fresh {
            return cached.context("agent release metadata temporarily unavailable");
        }
        let _guard = self.refresh.lock().await;
        let (cached, fresh) = existing();
        if fresh {
            return cached.context("agent release metadata temporarily unavailable");
        }
        let result = self.fetch_index(cached.as_ref()).await;
        let mut state = self.state.write().unwrap_or_else(|p| p.into_inner());
        state.retry_at = Instant::now() + REFRESH;
        state.checked_at = Instant::now();
        state.failed = result.is_err();
        if state.failed {
            state.retry_at = Instant::now() + Duration::from_secs(60);
        }
        match result {
            Ok(index) => {
                state.index = Some(index.clone());
                Ok(index)
            }
            Err(_) if cached.is_some() => {
                tracing::warn!(
                    "GitHub release refresh unavailable; retaining the verified cached release"
                );
                Ok(cached.unwrap())
            }
            Err(error) => Err(error),
        }
    }
    async fn fetch_index(&self, cached: Option<&Index>) -> Result<Index> {
        self.initialize().await?;
        let mut request = self
            .http
            .get(&self.metadata_url)
            .header("accept", "application/vnd.github+json")
            .timeout(Duration::from_secs(20));
        if let Some(etag) = cached.and_then(|index| index.etag.as_ref()) {
            request = request.header("if-none-match", etag);
        }
        let mut response = request.send().await?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return cached.cloned().context("release cache missing");
        }
        ensure!(
            response.status() == reqwest::StatusCode::OK,
            "GitHub release metadata unavailable"
        );
        let etag = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() <= 256)
            .map(str::to_owned);
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 256 * 1024,
                "release metadata exceeds size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let release: GithubRelease = serde_json::from_slice(&bytes)?;
        let version = release
            .tag_name
            .strip_prefix('v')
            .context("invalid release tag")?
            .to_owned();
        let numeric = numeric_version(&version).context("invalid release version")?;
        ensure!(
            !release.draft && !release.prerelease && release.assets.len() <= 128,
            "release is not a stable complete release"
        );
        if let Some(previous) = cached {
            ensure!(
                numeric >= numeric_version(&previous.version).unwrap(),
                "release downgrade rejected"
            );
        }
        let mut assets = BTreeMap::new();
        for asset in release.assets {
            ensure!(
                assets.insert(asset.name.clone(), asset).is_none(),
                "duplicate release asset"
            );
        }
        let manifest = if let Some(asset) = assets.get(porthub_components::catalog::CATALOG_ASSET) {
            ensure!(asset.state == "uploaded" && asset.size > 0
                && asset.size <= porthub_components::catalog::MAX_CATALOG as u64,
                "invalid compact release manifest asset");
            let digest = asset.digest.as_deref().and_then(|value| value.strip_prefix("sha256:"))
                .context("compact release manifest digest missing")?;
            let url = format!("{}/v{}/{}", self.download_base, version, porthub_components::catalog::CATALOG_ASSET);
            let mut response = self.http.get(url).timeout(Duration::from_secs(20)).send().await?;
            ensure!(response.status().is_success(), "compact release manifest unavailable");
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(bytes.len() as u64 + chunk.len() as u64 <= asset.size,
                    "compact release manifest exceeds declared size");
                bytes.extend_from_slice(&chunk);
            }
            ensure!(bytes.len() as u64 == asset.size && format!("{:x}", Sha256::digest(&bytes)) == digest,
                "compact release manifest checksum mismatch");
            let manifest = porthub_components::manifest::ReleaseManifest::parse(&bytes)?;
            ensure!(manifest.release.to_string() == version && manifest.repository == self.repository,
                "compact release identity mismatch");
            Some(manifest)
        } else { None };
        if let Some(previous) = cached.and_then(|index| index.components.as_ref()) {
            manifest.as_ref().context("compact release cannot discard component metadata")?
                .components.validate_successor(previous)?;
        }
        let mut releases = BTreeMap::new();
        for (target, os, arch) in TARGETS {
            let name = asset_name(target, os);
            let asset = assets.get(&name).context("release platform missing")?;
            for suffix in if manifest.is_some() { &[""][..] } else { &["", ".version", ".sha256"][..] } {
                let asset = assets
                    .get(&format!("{name}{suffix}"))
                    .context("release sidecar missing")?;
                ensure!(asset.state == "uploaded", "release asset is not ready");
            }
            let digest = asset
                .digest
                .as_deref()
                .and_then(|value| value.strip_prefix("sha256:"))
                .context("release digest missing")?;
            if let Some(manifest) = &manifest {
                let declared = manifest.core_assets.iter().find(|asset| asset.target == *target)
                    .context("compact release target missing")?;
                ensure!(declared.asset == name && declared.executable.size == asset.size
                    && declared.executable.sha256 == digest.to_ascii_lowercase(),
                    "compact release core asset differs from GitHub metadata");
            }
            releases.insert(
                (*target).to_owned(),
                Release {
                    target: (*target).into(),
                    os: (*os).into(),
                    arch: (*arch).into(),
                    asset: name,
                    version: version.clone(),
                    sha256: digest.to_ascii_lowercase(),
                    size: asset.size,
                },
            );
        }
        let index = Index {
            format_version: 1,
            repository: self.repository.clone(),
            version,
            etag,
            releases,
            components: manifest.map(|manifest| manifest.components),
        };
        index.validate(&self.repository)?;
        let path = self.root.join("latest.json");
        let bytes = serde_json::to_vec(&index)?;
        tokio::task::spawn_blocking(move || atomic(&path, &bytes)).await??;
        Ok(index)
    }
    pub async fn components(&self) -> Result<porthub_components::catalog::Catalog> {
        self.latest(false).await?.components.context("component release metadata unavailable")
    }
    pub async fn component(&self, component: &str, version: &str, target: &str, digest: &str)
        -> Result<(porthub_components::catalog::Artifact, tokio::fs::File)>
    {
        let catalog = self.components().await?;
        let artifact = catalog.artifacts.iter().find(|entry| entry.component.to_string() == component
            && entry.version.to_string() == version && entry.target == target && entry.executable.sha256 == digest)
            .context("component is not in the verified release catalog")?.clone();
        let _lock = self.component_download.lock().await;
        let directory = self.root.join("components");
        if !regular(&directory, true)? { tokio::fs::create_dir(&directory).await?; }
        let destination = directory.join(format!("{}-{}-{}", artifact.component, artifact.version, artifact.executable.sha256));
        let candidate = destination.clone();
        let blob = artifact.executable.clone();
        let valid = tokio::task::spawn_blocking(move || porthub_components::store::verified(&candidate, &blob)).await??;
        if !valid {
            let _permit = self.downloads.acquire().await?;
            let archive_path = directory.join(format!("archive-{}.tar.gz", artifact.archive.sha256));
            let check = archive_path.clone();
            let archive_blob = artifact.archive.clone();
            let cached = tokio::task::spawn_blocking(move || porthub_components::store::verified(&check, &archive_blob)).await??;
            let temporary = if cached { None } else {
                let archive = tempfile::NamedTempFile::new_in(&directory)?;
                let url = format!("{}/v{}/{}", self.download_base, artifact.release, artifact.archive_name());
                let mut response = self.http.get(url).timeout(Duration::from_secs(300)).send().await?;
                ensure!(response.status().is_success(), "component archive unavailable");
                let mut file = tokio::fs::File::from_std(archive.reopen()?);
                let mut size = 0u64;
                while let Some(chunk) = response.chunk().await? {
                    size = size.checked_add(chunk.len() as u64).context("component archive size overflow")?;
                    ensure!(size <= artifact.archive.size, "component archive exceeds size limit");
                    file.write_all(&chunk).await?;
                }
                file.flush().await?; file.sync_all().await?; drop(file);
                Some(archive)
            };
            let metadata = artifact.clone();
            let output = destination.clone();
            tokio::task::spawn_blocking(move || {
                let source = temporary.as_ref().map_or(archive_path.as_path(), |file| file.path());
                let extracted = porthub_components::store::extract_verified(source, &directory, &metadata, &catalog)?;
                if let Some(archive) = temporary { archive.persist(&archive_path)?; }
                extracted.as_file().sync_all()?;
                extracted.persist(output)?;
                std::fs::File::open(directory)?.sync_all()?;
                Ok::<_, anyhow::Error>(())
            }).await??;
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(destination).await?;
        ensure!(file.metadata().await?.is_file(), "invalid component cache entry");
        Ok((artifact, file))
    }
    pub async fn release(&self, target: &'static str) -> Result<Release> {
        self.latest(false)
            .await?
            .releases
            .get(target)
            .cloned()
            .context("unsupported release target")
    }
    pub async fn refresh_latest(&self) -> Result<()> {
        self.latest(true).await.map(|_| ())
    }
    pub async fn ensure(&self, target: &'static str, force: bool) -> Result<PathBuf> {
        let _target = self
            .targets
            .get(target)
            .context("unsupported release target")?
            .lock()
            .await;
        let release = self.release(target).await?;
        self.initialize().await?;
        let directory = self.root.join(&release.version);
        if !directory.try_exists()? {
            tokio::fs::create_dir(&directory).await?;
        }
        ensure!(regular(&directory, true)?, "unsafe release directory");
        let path = directory.join(&release.asset);
        if !force
            && regular(&path, false)?
            && tokio::fs::metadata(&path).await?.len() == release.size
            && tokio::fs::read_to_string(directory.join(format!("{}.sha256", release.asset)))
                .await
                .ok()
                == Some(format!("{}  {}\n", release.sha256, release.asset))
            && tokio::fs::read_to_string(directory.join(format!("{}.version", release.asset)))
                .await
                .ok()
                == Some(format!("{}\n", release.version))
        {
            return Ok(directory);
        }
        let _permit = self.downloads.acquire().await?;
        let url = format!(
            "{}/v{}/{}",
            self.download_base, release.version, release.asset
        );
        let mut response = self.http.get(url).send().await?;
        ensure!(
            response.status() == reqwest::StatusCode::OK
                && response
                    .content_length()
                    .is_none_or(|length| length == release.size),
            "release download size or status mismatch"
        );
        let temporary = tempfile::NamedTempFile::new_in(&directory)?;
        let mut output = tokio::fs::File::from_std(temporary.reopen()?);
        let mut hash = Sha256::new();
        let mut size = 0u64;
        while let Some(chunk) = response.chunk().await? {
            size += chunk.len() as u64;
            ensure!(
                size <= release.size && size <= MAX_BINARY,
                "release download exceeds size limit"
            );
            hash.update(&chunk);
            output.write_all(&chunk).await?;
        }
        ensure!(
            size == release.size && format!("{:x}", hash.finalize()) == release.sha256,
            "release download checksum mismatch"
        );
        output.flush().await?;
        output.sync_all().await?;
        drop(output);
        let destination = path.clone();
        let hash_path = directory.join(format!("{}.sha256", release.asset));
        let version_path = directory.join(format!("{}.version", release.asset));
        let checksum = format!("{}  {}\n", release.sha256, release.asset);
        let version = format!("{}\n", release.version);
        tokio::task::spawn_blocking(move || {
            temporary.persist(destination)?;
            atomic(&hash_path, checksum.as_bytes())?;
            atomic(&version_path, version.as_bytes())?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        drop(_permit);
        self.prune().await?;
        Ok(directory)
    }
    async fn prune(&self) -> Result<()> {
        // An already open artifact remains readable after unlinking an older
        // cache directory. Only numeric, owned cache release directories qualify.
        let _quiet = self.downloads.acquire_many(2).await?;
        let _index = self.refresh.lock().await;
        let Some(keep) = self.version() else {
            return Ok(());
        };
        let mut entries = tokio::fs::read_dir(&self.root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != keep && numeric_version(&name).is_some() && entry.file_type().await?.is_dir()
            {
                tokio::fs::remove_dir_all(entry.path()).await?;
            }
        }
        Ok(())
    }
}

fn regular(path: &Path, directory: bool) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                !meta.file_type().is_symlink(),
                "release cache symlink rejected"
            );
            Ok(if directory {
                meta.is_dir()
            } else {
                meta.is_file()
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("release cache parent missing")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path as AxumPath, State as AxumState},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::get,
        Json, Router,
    };
    use std::sync::atomic::AtomicUsize;

    struct Fixture {
        version: RwLock<String>,
        metadata: AtomicUsize,
        binaries: AtomicUsize,
        offline: AtomicBool,
        corrupt: AtomicBool,
        incomplete: AtomicBool,
        compact: AtomicBool,
    }
    fn payload(version: &str, name: &str) -> Vec<u8> {
        format!("native release {version}: {name}").into_bytes()
    }
    const TOOL_BYTES: &[u8] = b"standalone tool fixture";
    fn tool_archive() -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(TOOL_BYTES.len() as u64); header.set_mode(0o755); header.set_cksum();
        archive.append_data(&mut header, "sync/0.1.0/porthub-sync", TOOL_BYTES).unwrap();
        archive.append_data(&mut header, "stats/0.1.0/porthub-stats", TOOL_BYTES).unwrap();
        archive.into_inner().unwrap().finish().unwrap()
    }
    fn compact_manifest(version: &str) -> Vec<u8> {
        use porthub_components::{catalog::{Artifact, Blob, Catalog, Component, REPOSITORY}, manifest::{CoreAsset, ReleaseManifest}};
        let core_assets = TARGETS.iter().map(|(target, os, _)| {
            let name = asset_name(target, os);
            let body = payload(version, &name);
            CoreAsset { target: (*target).into(), asset: name,
                executable: Blob { size: body.len() as u64, sha256: format!("{:x}", Sha256::digest(body)) } }
        }).collect();
        let mut components = Catalog { schema_version: 1, repository: REPOSITORY.into(), release: version.parse().unwrap(),
            artifacts: vec![Artifact { component: Component::Sync, version: "0.1.0".parse().unwrap(),
                target: porthub_components::catalog::TARGETS[0].into(), core: ">=1.0.0".parse().unwrap(), protocols: vec![1],
                source_revision: "a".repeat(40), build_inputs: "b".repeat(64),
                executable: Blob { size: TOOL_BYTES.len() as u64, sha256: format!("{:x}", Sha256::digest(TOOL_BYTES)) }, release: version.parse().unwrap(),
                archive: Blob { size: tool_archive().len() as u64, sha256: format!("{:x}", Sha256::digest(tool_archive())) } }] };
        let mut stats = components.artifacts[0].clone();
        stats.component = Component::Stats;
        components.artifacts.push(stats);
        serde_json::to_vec(&ReleaseManifest { schema_version: 2, repository: REPOSITORY.into(), release: version.parse().unwrap(), core_assets, components }).unwrap()
    }
    async fn metadata(AxumState(state): AxumState<Arc<Fixture>>, headers: HeaderMap) -> Response {
        state.metadata.fetch_add(1, Ordering::SeqCst);
        if state.offline.load(Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let version = state.version.read().unwrap().clone();
        let etag = format!("\"{version}\"");
        if headers
            .get("if-none-match")
            .and_then(|value| value.to_str().ok())
            == Some(etag.as_str())
        {
            return StatusCode::NOT_MODIFIED.into_response();
        }
        let mut assets = Vec::new();
        for (target, os, _) in TARGETS {
            let name = asset_name(target, os);
            let body = payload(&version, &name);
            for suffix in if state.compact.load(Ordering::SeqCst) { &[""][..] } else { &["", ".version", ".sha256"][..] } {
                assets.push(serde_json::json!({"name":format!("{name}{suffix}"),"size":body.len(),"digest":format!("sha256:{:x}",Sha256::digest(&body)),"state":"uploaded",
                    "browser_download_url":"http://untrusted.invalid/ignored"}));
            }
        }
        if state.compact.load(Ordering::SeqCst) {
            let body = compact_manifest(&version);
            assets.push(serde_json::json!({"name":porthub_components::catalog::CATALOG_ASSET,
                "size":body.len(),"digest":format!("sha256:{:x}",Sha256::digest(body)),"state":"uploaded"}));
        }
        if state.incomplete.load(Ordering::SeqCst) {
            assets.pop();
        }
        ([("etag", etag)], Json(serde_json::json!({"tag_name":format!("v{version}"),"draft":false,"prerelease":false,"assets":assets}))).into_response()
    }
    async fn binary(
        AxumState(state): AxumState<Arc<Fixture>>,
        AxumPath((version, name)): AxumPath<(String, String)>,
    ) -> Response {
        state.binaries.fetch_add(1, Ordering::SeqCst);
        if state.offline.load(Ordering::SeqCst) {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        let mut body = if name == porthub_components::catalog::CATALOG_ASSET {
            compact_manifest(version.trim_start_matches('v'))
        } else if name.starts_with("porthub-tools-") { tool_archive()
        } else { payload(version.trim_start_matches('v'), &name) };
        if state.corrupt.load(Ordering::SeqCst) {
            body[0] ^= 1;
        }
        body.into_response()
    }
    async fn fixture() -> Result<(
        tempfile::TempDir,
        Arc<Fixture>,
        Arc<Remote>,
        tokio::task::JoinHandle<()>,
    )> {
        let root = tempfile::tempdir()?;
        let state = Arc::new(Fixture {
            version: RwLock::new("1.7.0".into()),
            metadata: AtomicUsize::new(0),
            binaries: AtomicUsize::new(0),
            offline: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
            incomplete: AtomicBool::new(false),
            compact: AtomicBool::new(false),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let router = Router::new()
            .route("/latest", get(metadata))
            .route("/download/{version}/{name}", get(binary))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let remote = Remote::new(
            root.path().join("cache"),
            porthub_components::catalog::REPOSITORY.into(),
            format!("{base}/latest"),
            format!("{base}/download"),
            true,
        )?;
        Ok((root, state, remote, task))
    }
    #[tokio::test]
    async fn component_downloads_are_verified_coalesced_and_repaired() -> Result<()> {
        use tokio::io::AsyncReadExt;
        let (_root, state, remote, task) = fixture().await?;
        state.compact.store(true, Ordering::SeqCst);
        let catalog = remote.components().await?;
        let tool = catalog.artifacts[0].clone();
        let version = tool.version.to_string();
        let (one, two) = tokio::join!(
            remote.component("sync", &version, &tool.target, &tool.executable.sha256),
            remote.component("sync", &version, &tool.target, &tool.executable.sha256));
        for result in [one, two] {
            let (_, mut file) = result?;
            let mut bytes = Vec::new(); file.read_to_end(&mut bytes).await?;
            assert_eq!(bytes, TOOL_BYTES);
        }
        assert_eq!(state.binaries.load(Ordering::SeqCst), 2, "one manifest and one archive");
        assert!(remote.component("sync", "9.0.0", &tool.target, &tool.executable.sha256).await.is_err());
        assert!(remote.component("../sync", &version, &tool.target, &tool.executable.sha256).await.is_err());
        assert_eq!(state.binaries.load(Ordering::SeqCst), 2);
        let path = remote.root.join("components").join(format!("sync-{}-{}", tool.version, tool.executable.sha256));
        tokio::fs::write(&path, b"corrupt").await?;
        remote.component("sync", &version, &tool.target, &tool.executable.sha256).await?;
        assert_eq!(tokio::fs::read(path).await?, TOOL_BYTES);
        assert_eq!(state.binaries.load(Ordering::SeqCst), 2, "repair reuses the verified archive");
        state.offline.store(true, Ordering::SeqCst);
        let stats = &catalog.artifacts[1];
        let (_, mut stats_file) = remote.component("stats", &stats.version.to_string(), &stats.target, &stats.executable.sha256).await?;
        let mut bytes = Vec::new(); stats_file.read_to_end(&mut bytes).await?;
        assert_eq!(bytes, TOOL_BYTES);
        assert_eq!(state.binaries.load(Ordering::SeqCst), 2, "a second tool shares the archive while upstream is offline");
        state.offline.store(false, Ordering::SeqCst);
        let archive_path = remote.root.join("components").join(format!("archive-{}.tar.gz", tool.archive.sha256));
        tokio::fs::write(archive_path, b"damaged archive").await?;
        let path = remote.root.join("components").join(format!("sync-{}-{}", tool.version, tool.executable.sha256));
        tokio::fs::remove_file(&path).await?;
        remote.component("sync", &version, &tool.target, &tool.executable.sha256).await?;
        assert_eq!(tokio::fs::read(path).await?, TOOL_BYTES);
        assert_eq!(state.binaries.load(Ordering::SeqCst), 3, "a damaged cached archive is fetched and verified again");

        task.abort(); Ok(())
    }
    #[tokio::test]
    async fn corrupt_component_archives_are_never_published() -> Result<()> {
        let (_root, state, remote, task) = fixture().await?;
        state.compact.store(true, Ordering::SeqCst);
        let tool = remote.components().await?.artifacts[0].clone();
        state.corrupt.store(true, Ordering::SeqCst);
        assert!(remote.component("sync", &tool.version.to_string(), &tool.target, &tool.executable.sha256).await.is_err());
        let mut files = tokio::fs::read_dir(remote.root.join("components")).await?;
        assert!(files.next_entry().await?.is_none());
        task.abort(); Ok(())
    }
    #[test]
    fn shared_manifest_rejects_incomplete_duplicate_or_conflicting_core_metadata() -> Result<()> {
        use porthub_components::{catalog::Catalog, manifest::ReleaseManifest};
        let bytes = compact_manifest("1.11.0");
        let manifest = ReleaseManifest::parse(&bytes)?;
        assert_eq!(Catalog::parse(&bytes)?.release, manifest.release);
        let mut incomplete = manifest.clone(); incomplete.core_assets.pop();
        assert!(incomplete.validate().is_err());
        let mut duplicate = manifest.clone(); duplicate.core_assets[1] = duplicate.core_assets[0].clone();
        assert!(duplicate.validate().is_err());
        let mut traversal = manifest.clone(); traversal.core_assets[0].asset = "../porthub".into();
        assert!(traversal.validate().is_err());
        let mut conflict = manifest.clone(); conflict.components.release = "1.10.0".parse()?;
        assert!(conflict.validate().is_err());
        let mut bad_digest = manifest.clone(); bad_digest.core_assets[0].executable.sha256 = "z".repeat(64);
        assert!(bad_digest.validate().is_err());
        Ok(())
    }
    #[tokio::test]
    async fn compact_release_needs_no_sidecars_and_persists_validated_components() -> Result<()> {
        let (_root, state, remote, task) = fixture().await?;
        state.compact.store(true, Ordering::SeqCst);
        let release = remote.release("x86_64").await?;
        assert_eq!(release.version, "1.7.0");
        let index = remote.state.read().unwrap().index.clone().unwrap();
        assert!(index.components.is_some());
        let persisted: Index = serde_json::from_slice(&tokio::fs::read(remote.root.join("latest.json")).await?)?;
        persisted.validate(porthub_components::catalog::REPOSITORY)?;
        assert!(persisted.components.is_some());
        let _asset = remote.ensure("x86_64", false).await?;
        task.abort();
        Ok(())
    }
    #[tokio::test]
    async fn corrupt_compact_manifest_cannot_replace_a_verified_legacy_index() -> Result<()> {
        let (_root, state, remote, task) = fixture().await?;
        remote.release("x86_64").await?;
        let previous = remote.state.read().unwrap().index.clone().unwrap();
        state.compact.store(true, Ordering::SeqCst);
        *state.version.write().unwrap() = "1.8.0".into();
        state.corrupt.store(true, Ordering::SeqCst);
        assert!(remote.fetch_index(Some(&previous)).await.is_err());
        assert_eq!(remote.state.read().unwrap().index.as_ref().unwrap().version, "1.7.0");
        let persisted: Index = serde_json::from_slice(&tokio::fs::read(remote.root.join("latest.json")).await?)?;
        assert_eq!(persisted.version, "1.7.0");
        task.abort();
        Ok(())
    }
    fn expire(remote: &Remote) {
        let mut state = remote.state.write().unwrap();
        state.retry_at = Instant::now();
        state.checked_at = Instant::now() - REFRESH;
    }

    #[tokio::test]
    async fn metadata_is_lazy_and_concurrent_downloads_share_one_verified_persistent_asset(
    ) -> Result<()> {
        let (_root, state, remote, task) = fixture().await?;
        assert_eq!(remote.release("x86_64").await?.version, "1.7.0");
        assert_eq!(state.binaries.load(Ordering::SeqCst), 0);
        assert!(!remote.root.join("1.7.0").try_exists()?);
        let mut jobs = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let remote = remote.clone();
            jobs.spawn(async move { remote.ensure("x86_64", false).await });
        }
        while let Some(result) = jobs.join_next().await {
            result??;
        }
        assert_eq!(state.binaries.load(Ordering::SeqCst), 1);
        assert_eq!(
            std::fs::read(remote.root.join("1.7.0/porthub-x86_64"))?,
            payload("1.7.0", "porthub-x86_64")
        );
        assert!(!remote.root.join("1.7.0/porthub-arm64").try_exists()?);
        state.offline.store(true, Ordering::SeqCst);
        let restarted = Remote::new(
            remote.root.clone(),
            remote.repository.clone(),
            remote.metadata_url.clone(),
            remote.download_base.clone(),
            true,
        )?;
        assert_eq!(restarted.version().as_deref(), Some("1.7.0"));
        restarted.ensure("x86_64", false).await?;
        assert_eq!(state.binaries.load(Ordering::SeqCst), 1);
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn corrupt_downloads_are_not_published_and_corrupt_cache_files_are_repaired() -> Result<()>
    {
        let (_root, state, remote, task) = fixture().await?;
        state.corrupt.store(true, Ordering::SeqCst);
        assert!(remote.ensure("x86_64", false).await.is_err());
        assert!(!remote.root.join("1.7.0/porthub-x86_64").try_exists()?);
        state.corrupt.store(false, Ordering::SeqCst);
        remote.ensure("x86_64", false).await?;
        let path = remote.root.join("1.7.0/porthub-x86_64");
        let mut bytes = std::fs::read(&path)?;
        bytes[0] ^= 1;
        std::fs::write(&path, bytes)?;
        let catalog = crate::artifacts::Catalog::fixture(remote.clone());
        let artifact = catalog
            .get("x86_64")
            .await
            .map_err(|_| anyhow::anyhow!("cached artifact repair failed"))?;
        assert_eq!(artifact.release.version, "1.7.0");
        assert_eq!(std::fs::read(path)?, payload("1.7.0", "porthub-x86_64"));
        assert_eq!(state.binaries.load(Ordering::SeqCst), 3);
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn new_release_prunes_old_cache_but_open_transfers_survive() -> Result<()> {
        let (_root, state, remote, task) = fixture().await?;
        let catalog = crate::artifacts::Catalog::fixture(remote.clone());
        let old = catalog
            .get("x86_64")
            .await
            .map_err(|_| anyhow::anyhow!("initial artifact missing"))?;
        *state.version.write().unwrap() = "1.8.0".into();
        expire(&remote);
        remote.ensure("arm64", false).await?;
        assert_eq!(remote.version().as_deref(), Some("1.8.0"));
        assert!(!remote.root.join("1.7.0").try_exists()?);
        let response = old
            .response(&axum::http::Method::GET, &HeaderMap::new(), false)
            .await
            .map_err(|_| anyhow::anyhow!("old response unavailable"))?;
        let bytes = axum::body::to_bytes(response.into_body(), 1024).await?;
        assert_eq!(bytes.as_ref(), payload("1.7.0", "porthub-x86_64"));
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn partial_or_older_releases_do_not_replace_a_good_catalog_and_idle_checks_do_not_poll(
    ) -> Result<()> {
        let (_root, state, remote, task) = fixture().await?;
        for _ in 0..64 {
            remote.refresh_background();
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while remote.version().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        for _ in 0..64 {
            remote.refresh_background();
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(state.metadata.load(Ordering::SeqCst), 1);
        assert_eq!(state.binaries.load(Ordering::SeqCst), 0);
        *state.version.write().unwrap() = "1.8.0".into();
        state.incomplete.store(true, Ordering::SeqCst);
        expire(&remote);
        assert_eq!(remote.release("arm64").await?.version, "1.7.0");
        state.incomplete.store(false, Ordering::SeqCst);
        *state.version.write().unwrap() = "1.6.0".into();
        expire(&remote);
        assert_eq!(remote.release("arm64").await?.version, "1.7.0");
        task.abort();
        Ok(())
    }
}
