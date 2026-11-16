//! Optional, isolated media publication cache. Legacy release indexes never gain
//! new fields; absent media assets cannot affect ordinary agent startup.
use super::*;
use porthub_components::{
    catalog::{MAX_CATALOG, REPOSITORY},
    media_store::{Artifact, Manifest, ASSET},
    store,
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Index {
    format_version: u32,
    repository: String,
    release: String,
    manifest: Option<Manifest>,
}
impl Index {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == 1
                && self.repository == REPOSITORY
                && numeric_version(&self.release).is_some(),
            "Invalid media cache index"
        );
        if let Some(m) = &self.manifest {
            m.validate()?;
            ensure!(
                m.release.to_string() == self.release,
                "Media release mismatch"
            );
            production_manifest(m)?;
        }
        Ok(())
    }
    fn successor(&self, old: &Self) -> Result<()> {
        self.validate()?;
        old.validate()?;
        ensure!(
            numeric_version(&self.release) >= numeric_version(&old.release),
            "Media release downgrade rejected"
        );
        if self.release == old.release {
            ensure!(
                self.manifest == old.manifest,
                "Published media release changed"
            );
        }
        if let (Some(new), Some(old)) = (&self.manifest, &old.manifest) {
            new.successor(old)?;
        }
        Ok(())
    }
}
#[derive(Default)]
pub(super) struct State {
    index: Option<Index>,
    checked: Option<Instant>,
    loaded: bool,
    failed: bool,
}
fn production_manifest(m: &Manifest) -> Result<()> {
    m.validate_publication()
}

impl Remote {
    pub async fn media_catalog(&self) -> Result<Manifest> {
        self.initialize().await?;
        ensure!(
            self.repository == REPOSITORY,
            "Media repository is not trusted"
        );
        let directory = self.root.join("media");
        let private = directory.clone();
        tokio::task::spawn_blocking(move || store::secure_private_directory(&private)).await??;
        let mut state = self.media.lock().await;
        if !state.loaded {
            let path = directory.join("index.json");
            if regular(&path, false)? {
                let mut options = tokio::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
                let file = options.open(path).await?;
                ensure!(
                    file.metadata().await?.is_file()
                        && file.metadata().await?.len() <= (MAX_CATALOG + 4096) as u64,
                    "Media index exceeds bound"
                );
                let mut bytes = Vec::new();
                tokio::io::AsyncReadExt::read_to_end(
                    &mut tokio::io::AsyncReadExt::take(file, (MAX_CATALOG + 4097) as u64),
                    &mut bytes,
                )
                .await?;
                ensure!(
                    bytes.len() <= MAX_CATALOG + 4096,
                    "Media index exceeds bound"
                );
                let cached: Index = serde_json::from_slice(&bytes)?;
                cached.validate()?;
                state.index = Some(cached);
            }
            state.loaded = true;
        }
        if !state.checked.is_some_and(|at| at.elapsed() < REFRESH) {
            // The same bounded HTTPS/redirect policy as ordinary releases is reused.
            let candidate = async {
                let next = self.fetch_media_index().await?;
                if let Some(old) = &state.index {
                    next.successor(old)?;
                }
                Ok::<_, anyhow::Error>(next)
            }
            .await;
            let next = match candidate {
                Ok(next) => next,
                Err(error) => {
                    state.checked = Some(Instant::now());
                    state.failed = true;
                    return Err(error);
                }
            };
            let path = directory.join("index.json");
            let bytes = serde_json::to_vec(&next)?;
            tokio::task::spawn_blocking(move || atomic(&path, &bytes)).await??;
            state.index = Some(next);
            state.checked = Some(Instant::now());
            state.failed = false;
        }
        ensure!(!state.failed, "Media publication validation failed");
        state
            .index
            .as_ref()
            .and_then(|i| i.manifest.clone())
            .context("This release has no optional media helper")
    }
    async fn fetch_media_index(&self) -> Result<Index> {
        let response = self
            .http
            .get(&self.metadata_url)
            .header("accept", "application/vnd.github+json")
            .timeout(Duration::from_secs(20))
            .send()
            .await?;
        let bytes = bounded(response, 256 * 1024).await?;
        let release: GithubRelease = serde_json::from_slice(&bytes)?;
        let version = release
            .tag_name
            .strip_prefix('v')
            .context("Invalid media release tag")?;
        ensure!(
            numeric_version(version).is_some()
                && !release.draft
                && !release.prerelease
                && release.assets.len() <= 128,
            "Invalid stable media release"
        );
        let mut assets = BTreeMap::new();
        for a in release.assets {
            ensure!(
                assets.insert(a.name.clone(), a).is_none(),
                "Duplicate release asset"
            );
        }
        let optional: Vec<_> = assets
            .keys()
            .filter(|n| n.as_str() == ASSET || n.starts_with("porthub-media-helper-"))
            .cloned()
            .collect();
        let manifest = if optional.is_empty() {
            None
        } else {
            let declared = assets
                .get(ASSET)
                .context("Incomplete optional media release")?;
            ensure!(
                declared.state == "uploaded"
                    && declared.size > 0
                    && declared.size <= MAX_CATALOG as u64,
                "Invalid media manifest asset"
            );
            let digest = declared
                .digest
                .as_deref()
                .and_then(|s| s.strip_prefix("sha256:"))
                .context("Missing media manifest digest")?;
            let url = format!("{}/v{}/{}", self.download_base, version, ASSET);
            let bytes = bounded(
                self.http
                    .get(url)
                    .timeout(Duration::from_secs(20))
                    .send()
                    .await?,
                declared.size,
            )
            .await?;
            ensure!(
                bytes.len() as u64 == declared.size
                    && format!("{:x}", Sha256::digest(&bytes)) == digest,
                "Media manifest checksum mismatch"
            );
            let m = Manifest::parse(&bytes)?;
            production_manifest(&m)?;
            ensure!(
                m.release.to_string() == version,
                "Media manifest release mismatch"
            );
            let mut expected = std::collections::BTreeSet::from([ASSET.to_owned()]);
            for a in &m.artifacts {
                let name = a.archive_name();
                let row = assets.get(&name).context("Missing media archive")?;
                ensure!(
                    row.state == "uploaded"
                        && row.size == a.archive.size
                        && row.digest.as_deref()
                            == Some(format!("sha256:{}", a.archive.sha256).as_str()),
                    "Media archive publication metadata mismatch"
                );
                expected.insert(name);
            }
            ensure!(
                expected == optional.into_iter().collect(),
                "Unexpected optional media asset"
            );
            Some(m)
        };
        let index = Index {
            format_version: 1,
            repository: self.repository.clone(),
            release: version.into(),
            manifest,
        };
        index.validate()?;
        Ok(index)
    }
    /// Returns an archive, never executable bytes. Its sole member is validated
    /// against the same typed manifest before the opened descriptor is returned.
    pub async fn media_archive(
        &self,
        version: &str,
        target: &str,
        digest: &str,
    ) -> Result<(Artifact, tokio::fs::File)> {
        let manifest = self.media_catalog().await?;
        let artifact = manifest
            .artifacts
            .iter()
            .find(|a| {
                a.version.to_string() == version
                    && a.target == target
                    && a.executable.sha256 == digest
            })
            .cloned()
            .context("Unknown media artifact")?;
        let _lock = self.component_download.lock().await;
        let _permit = self.downloads.acquire().await?;
        let directory = self.root.join("media");
        let archive_path = directory.join(format!("archive-{}.tar.gz", artifact.archive.sha256));
        let path = archive_path.clone();
        let blob = artifact.archive.clone();
        let valid = tokio::task::spawn_blocking(move || store::verified(&path, &blob)).await??;
        if !valid {
            let temporary = tempfile::NamedTempFile::new_in(&directory)?;
            let url = format!(
                "{}/v{}/{}",
                self.download_base,
                manifest.release,
                artifact.archive_name()
            );
            let mut response = self
                .http
                .get(url)
                .timeout(Duration::from_secs(180))
                .send()
                .await?;
            ensure!(response.status().is_success(), "Media archive unavailable");
            let mut file = tokio::fs::File::from_std(temporary.reopen()?);
            let mut count = 0u64;
            while let Some(chunk) = response.chunk().await? {
                count = count
                    .checked_add(chunk.len() as u64)
                    .context("Media size overflow")?;
                ensure!(
                    count <= artifact.archive.size,
                    "Media archive exceeds bound"
                );
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            file.sync_all().await?;
            drop(file);
            let a = artifact.clone();
            let dir = directory.clone();
            let destination = archive_path.clone();
            tokio::task::spawn_blocking(move || {
                let _verified = porthub_components::media_store::extract_verified_archive(
                    temporary.path(),
                    &dir,
                    &a,
                )?;
                temporary.persist(destination)?;
                Ok::<_, anyhow::Error>(())
            })
            .await??;
        } else {
            let path = archive_path.clone();
            let dir = directory.clone();
            let a = artifact.clone();
            tokio::task::spawn_blocking(move || {
                porthub_components::media_store::extract_verified_archive(&path, &dir, &a)
                    .map(|_| ())
            })
            .await??;
        }
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options.open(archive_path).await?;
        ensure!(file.metadata().await?.is_file(), "Invalid media cache file");
        Ok((artifact, file))
    }
}
async fn bounded(mut response: reqwest::Response, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "Media publication unavailable"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            (bytes.len() as u64)
                .checked_add(chunk.len() as u64)
                .is_some_and(|n| n <= maximum),
            "Media response exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::{Path as AxumPath, State as AxumState},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::get,
        Json, Router,
    };
    use std::sync::atomic::AtomicUsize;
    struct Fixture {
        manifest: RwLock<Manifest>,
        archive: Vec<u8>,
        downloads: AtomicUsize,
        missing: AtomicBool,
        corrupt: AtomicBool,
    }
    fn blob(bytes: &[u8]) -> porthub_components::catalog::Blob {
        porthub_components::catalog::Blob {
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }
    fn archive() -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut h = tar::Header::new_gnu();
        h.set_size(5);
        h.set_mode(0o755);
        h.set_cksum();
        tar.append_data(
            &mut h,
            "media-helper/0.1.0/porthub-media-helper",
            &b"bytes"[..],
        )
        .unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }
    fn manifest(archive: &[u8]) -> Manifest {
        Manifest {
            schema_version: 1,
            namespace: "porthub-media".into(),
            repository: REPOSITORY.into(),
            release: "1.11.51".parse().unwrap(),
            artifacts: ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]
                .into_iter()
                .map(|target| Artifact {
                    version: "0.1.0".parse().unwrap(),
                    target: target.into(),
                    core: ">=1.11.34".parse().unwrap(),
                    protocol: 1,
                    source_revision: "a".repeat(40),
                    build_inputs: "b".repeat(64),
                    executable: blob(b"bytes"),
                    archive: blob(archive),
                })
                .collect(),
        }
    }
    async fn metadata(AxumState(s): AxumState<Arc<Fixture>>) -> Json<serde_json::Value> {
        let m = s.manifest.read().unwrap().clone();
        let bytes = serde_json::to_vec(&m).unwrap();
        let mut assets = vec![];
        if !s.missing.load(Ordering::SeqCst) {
            assets.push(serde_json::json!({"name":ASSET,"size":bytes.len(),"digest":format!("sha256:{:x}",Sha256::digest(&bytes)),"state":"uploaded"}));
            for a in &m.artifacts {
                assets.push(serde_json::json!({"name":a.archive_name(),"size":a.archive.size,"digest":format!("sha256:{}",a.archive.sha256),"state":"uploaded"}));
            }
        }
        Json(
            serde_json::json!({"tag_name":format!("v{}",m.release),"draft":false,"prerelease":false,"assets":assets}),
        )
    }
    async fn download(
        AxumState(s): AxumState<Arc<Fixture>>,
        AxumPath((_version, name)): AxumPath<(String, String)>,
    ) -> Response {
        s.downloads.fetch_add(1, Ordering::SeqCst);
        if name == ASSET {
            return serde_json::to_vec(&*s.manifest.read().unwrap())
                .unwrap()
                .into_response();
        }
        if s.corrupt.load(Ordering::SeqCst) {
            return b"corrupt".to_vec().into_response();
        }
        if s.manifest
            .read()
            .unwrap()
            .artifacts
            .iter()
            .any(|a| a.archive_name() == name)
        {
            s.archive.clone().into_response()
        } else {
            StatusCode::NOT_FOUND.into_response()
        }
    }
    async fn fixture() -> Result<(
        tempfile::TempDir,
        Arc<Remote>,
        Arc<Fixture>,
        tokio_util::task::AbortOnDropHandle<()>,
    )> {
        let tmp = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let archive = archive();
        let state = Arc::new(Fixture {
            manifest: RwLock::new(manifest(&archive)),
            archive,
            downloads: AtomicUsize::new(0),
            missing: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let router = Router::new()
            .route("/latest", get(metadata))
            .route("/download/{version}/{name}", get(download))
            .with_state(state.clone());
        let task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        }));
        std::fs::create_dir(tmp.path().join("cache"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                tmp.path().join("cache"),
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        let remote = Remote::new(
            tmp.path().join("cache"),
            REPOSITORY.into(),
            format!("{base}/latest"),
            format!("{base}/download"),
            true,
        )?;
        Ok((tmp, remote, state, task))
    }
    #[tokio::test]
    async fn optional_catalog_and_archive_are_verified_cached_and_coalesced() -> Result<()> {
        let (_tmp, r, s, _task) = fixture().await?;
        let (a, b) = tokio::join!(r.media_catalog(), r.media_catalog());
        let m = a?;
        assert_eq!(m, b?);
        assert_eq!(s.downloads.load(Ordering::SeqCst), 1);
        let a = &m.artifacts[0];
        let (meta, mut file) = r
            .media_archive(&a.version.to_string(), &a.target, &a.executable.sha256)
            .await?;
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut file, &mut bytes).await?;
        assert_eq!(bytes, s.archive);
        assert_eq!(meta.archive.size, bytes.len() as u64);
        assert_ne!(meta.archive.sha256, meta.executable.sha256);
        assert_eq!(s.downloads.load(Ordering::SeqCst), 2);
        assert!(
            !r.root.join("latest.json").exists(),
            "legacy index remains untouched"
        );
        assert!(r
            .media_archive("0.1.0", "../../invalid", &a.executable.sha256)
            .await
            .is_err());
        tokio::fs::write(
            r.root
                .join("media")
                .join(format!("archive-{}.tar.gz", a.archive.sha256)),
            b"broken",
        )
        .await?;
        r.media_archive("0.1.0", &a.target, &a.executable.sha256)
            .await?;
        assert_eq!(s.downloads.load(Ordering::SeqCst), 3);
        Ok(())
    }
    #[tokio::test]
    async fn legacy_absence_and_untrusted_or_changed_media_fail_closed() -> Result<()> {
        let (_tmp, r, s, _task) = fixture().await?;
        s.missing.store(true, Ordering::SeqCst);
        assert!(r.media_catalog().await.is_err());
        assert_eq!(s.downloads.load(Ordering::SeqCst), 0);
        s.manifest.write().unwrap().release = "1.11.52".parse()?;
        s.missing.store(false, Ordering::SeqCst);
        r.media.lock().await.checked = None;
        let m = r.media_catalog().await?;
        s.manifest.write().unwrap().artifacts[0].build_inputs = "c".repeat(64);
        r.media.lock().await.checked = None;
        assert!(r.media_catalog().await.is_err());
        assert!(m.successor(&m).is_ok());
        Ok(())
    }
    #[tokio::test]
    async fn corrupt_archive_or_executable_digest_never_becomes_downloadable() -> Result<()> {
        let (_tmp, r, s, _task) = fixture().await?;
        s.corrupt.store(true, Ordering::SeqCst);
        let m = r.media_catalog().await?;
        let a = &m.artifacts[0];
        assert!(r
            .media_archive("0.1.0", &a.target, &a.executable.sha256)
            .await
            .is_err());
        assert!(!r
            .root
            .join("media")
            .join(format!("archive-{}.tar.gz", a.archive.sha256))
            .exists());
        let (_other, remote, state, _server) = fixture().await?;
        for artifact in &mut state.manifest.write().unwrap().artifacts {
            artifact.executable.sha256 = "c".repeat(64);
        }
        let m = remote.media_catalog().await?;
        let a = &m.artifacts[0];
        assert!(
            remote
                .media_archive("0.1.0", &a.target, &a.executable.sha256)
                .await
                .is_err(),
            "Archive hash alone must not authorize a different executable"
        );
        assert!(!remote
            .root
            .join("media")
            .join(format!("archive-{}.tar.gz", a.archive.sha256))
            .exists());
        Ok(())
    }
    #[test]
    fn production_targets_and_agent_minimum_are_explicit() -> Result<()> {
        let mut m = manifest(&archive());
        production_manifest(&m)?;
        m.artifacts[0].core = ">=1.11.33".parse()?;
        assert!(production_manifest(&m).is_err());
        m.artifacts[0].core = ">=1.11.34".parse()?;
        let mut w = m.artifacts[0].clone();
        w.target = "x86_64-pc-windows-msvc".into();
        m.artifacts.push(w);
        production_manifest(&m)?;
        m.artifacts[2].target = "unknown".into();
        assert!(m.validate().is_err());
        Ok(())
    }
}
