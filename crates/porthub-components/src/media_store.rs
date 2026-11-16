//! Optional media artifacts have a separate catalog; old agents never parse new component variants.
use crate::{
    catalog::{Blob, MAX_ARCHIVE, MAX_CATALOG, MAX_EXECUTABLE, REPOSITORY},
    store::{self, Settings, Sources},
    transport::{AccessDenied, Transport},
};
use anyhow::{ensure, Context, Result};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
use url::Url;
pub const ASSET: &str = "porthub-media-components.json";
pub const NAMESPACE: &str = "porthub-media";
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub version: Version,
    pub target: String,
    pub core: VersionReq,
    pub protocol: u32,
    pub source_revision: String,
    pub build_inputs: String,
    pub executable: Blob,
    pub archive: Blob,
}
impl Artifact {
    pub fn member(&self) -> String {
        format!(
            "media-helper/{}/porthub-media-helper{}",
            self.version,
            if self.target.contains("windows") {
                ".exe"
            } else {
                ""
            }
        )
    }
    pub fn archive_name(&self) -> String {
        format!("porthub-media-helper-{}.tar.gz", self.target)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.version.pre.is_empty() && self.version.build.is_empty() && self.protocol == 1,
            "Unsupported media artifact version/protocol"
        );
        ensure!(
            ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "x86_64-pc-windows-msvc"]
                .contains(&self.target.as_str()),
            "Unsupported media target"
        );
        ensure!(
            self.source_revision.len() == 40
                && self
                    .source_revision
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Invalid media source revision"
        );
        ensure!(
            crate::catalog::digest(&self.build_inputs),
            "Invalid media build provenance"
        );
        self.executable.validate(MAX_EXECUTABLE)?;
        self.archive.validate(MAX_ARCHIVE)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub namespace: String,
    pub repository: String,
    pub release: Version,
    pub artifacts: Vec<Artifact>,
}
impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() <= MAX_CATALOG, "Media manifest exceeds bound");
        let value: Self = serde_json::from_slice(bytes).context("Invalid media manifest")?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.namespace == NAMESPACE
                && self.repository == REPOSITORY,
            "Untrusted media manifest namespace/repository"
        );
        ensure!(
            self.release.pre.is_empty()
                && self.release.build.is_empty()
                && !self.artifacts.is_empty()
                && self.artifacts.len() <= 32,
            "Invalid media release"
        );
        let mut unique = BTreeSet::new();
        for artifact in &self.artifacts {
            artifact.validate()?;
            ensure!(
                unique.insert((&artifact.version, &artifact.target)),
                "Duplicate media artifact"
            );
        }
        Ok(())
    }
    /// Production optional release set; private fixtures use validate() instead.
    pub fn validate_publication(&self)->Result<()> {
        self.validate()?;
        let mut targets=BTreeSet::new();
        let first=&self.artifacts[0];
        for artifact in &self.artifacts {
            ensure!(artifact.version==first.version&&artifact.source_revision==first.source_revision&&artifact.build_inputs==first.build_inputs,"Media targets must share reviewed source and build inputs");
            ensure!(targets.insert(artifact.target.as_str()),"Duplicate media publication target");
            let requirement=artifact.core.to_string();
            let minimum=requirement.strip_prefix(">=").and_then(|v|v.parse::<Version>().ok());
            ensure!(minimum.is_some_and(|v|v>=Version::new(1,11,34)&&v.pre.is_empty()&&v.build.is_empty()),"Production media helper requires explicit agent minimum >=1.11.34");
        }
        ensure!(targets.contains("x86_64-unknown-linux-gnu")&&targets.contains("aarch64-unknown-linux-gnu")&&targets.is_subset(&BTreeSet::from(["x86_64-unknown-linux-gnu","aarch64-unknown-linux-gnu","x86_64-pc-windows-msvc"])),"Incomplete or unsupported media publication targets");
        Ok(())
    }
    pub fn successor(&self, old: &Self) -> Result<()> {
        self.validate()?;
        old.validate()?;
        ensure!(
            self.release >= old.release,
            "Media manifest downgrade rejected"
        );
        ensure!(
            self.release != old.release || self == old,
            "Published media release changed"
        );
        for a in &self.artifacts {
            if let Some(previous)=old.artifacts.iter().filter(|b|b.target==a.target).map(|b|&b.version).max(){ensure!(&a.version>=previous,"Media helper downgrade rejected");}
            if let Some(b) = old
                .artifacts
                .iter()
                .find(|b| a.version == b.version && a.target == b.target)
            {
                ensure!(a == b, "Published media artifact changed");
            }
        }
        Ok(())
    }
}
pub struct Manager {
    root: PathBuf,
    settings: Settings,
    transport: Arc<dyn Transport>,
}
impl Manager {
    pub fn new(root: PathBuf, settings: Settings, transport: Arc<dyn Transport>) -> Result<Self> {
        settings.validate()?;
        store::secure_private_directory(&root)?;
        Ok(Self {
            root,
            settings,
            transport,
        })
    }
    pub fn cached(&self) -> Result<Option<Manifest>> {
        let path = self.root.join(ASSET);
        match store::regular(&path) {
            Ok(meta) => {
                ensure!(
                    meta.len() <= MAX_CATALOG as u64,
                    "Media manifest exceeds bound"
                );
                Ok(Some(Manifest::parse(&std::fs::read(path)?)?))
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
        path: &Path,
        max: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        tokio::select! {biased;_=cancel.cancelled()=>anyhow::bail!("Media artifact operation cancelled"),r=self.transport.fetch(url,path,max)=>r}
    }
    pub async fn refresh(&self, cancel: &CancellationToken) -> Result<Manifest> {
        let _lock = store::lock(&self.root, "media-catalog.lock", cancel).await?;
        let old = self.cached()?;
        let mut urls = Vec::new();
        if self.settings.sources != Sources::GithubOnly {
            if let Some(url) = self.settings.gateway_url("api/downloads/media/catalog")? {
                urls.push(url);
            }
        }
        if self.settings.sources != Sources::GatewayOnly {
            urls.push(Url::parse(&format!(
                "https://github.com/{REPOSITORY}/releases/latest/download/{ASSET}"
            ))?);
        }
        for url in urls {
            let temp = tempfile::NamedTempFile::new_in(&self.root)?;
            match self
                .fetch(&url, temp.path(), MAX_CATALOG as u64, cancel)
                .await
            {
                Ok(()) => {
                    let manifest = Manifest::parse(&std::fs::read(temp.path())?)?;
                    if let Some(old) = &old {
                        manifest.successor(old)?;
                    }
                    store::publish(temp, &self.root.join(ASSET), false)?;
                    return Ok(manifest);
                }
                Err(e) if e.is::<AccessDenied>() => return Err(e),
                Err(_) if cancel.is_cancelled() => {
                    anyhow::bail!("Media artifact operation cancelled")
                }
                Err(_) => {}
            }
        }
        old.context("No verified media manifest available")
    }
    /// Read-only preflight for desktop startup: never downloads or starts a helper.
    pub fn cached_executable(&self) -> Result<Option<PathBuf>> {
        let Some(manifest) = self.cached()? else {
            return Ok(None);
        };
        let Some(artifact) = manifest
            .artifacts
            .iter()
            .filter(|a| a.target == self.settings.target && a.core.matches(&self.settings.core))
            .max_by_key(|a| &a.version)
        else {
            return Ok(None);
        };
        let directory = self.root.join(format!(
            "helper-{}-{}",
            artifact.version, artifact.executable.sha256
        ));
        let path = directory.join(if artifact.target.contains("windows") {
            "porthub-media-helper.exe"
        } else {
            "porthub-media-helper"
        });
        Ok(store::verified(&path, &artifact.executable)?.then_some(path))
    }
    pub async fn ensure(&self, manifest: &Manifest, cancel: &CancellationToken) -> Result<PathBuf> {
        manifest.validate()?;
        // Untrusted caller-supplied manifests cannot bypass the source refresh/cache boundary.
        let trusted = self
            .cached()?
            .context("Media manifest has not been fetched from an approved source")?;
        ensure!(
            &trusted == manifest,
            "Media manifest differs from approved cached release"
        );
        let artifact = manifest
            .artifacts
            .iter()
            .filter(|a| a.target == self.settings.target && a.core.matches(&self.settings.core))
            .max_by_key(|a| &a.version)
            .context("No compatible native media helper")?;
        let _lock = store::lock(&self.root, "media-helper.lock", cancel).await?;
        let directory = self.root.join(format!(
            "helper-{}-{}",
            artifact.version, artifact.executable.sha256
        ));
        store::directory(&directory)?;
        let destination = directory.join(if artifact.target.contains("windows") {
            "porthub-media-helper.exe"
        } else {
            "porthub-media-helper"
        });
        if store::verified(&destination, &artifact.executable)? {
            return Ok(destination);
        }
        let mut urls = Vec::new();
        if self.settings.sources != Sources::GithubOnly {
            if let Some(url) = self.settings.gateway_url(&format!(
                "api/downloads/media/{}/{}/{}",
                artifact.version, artifact.target, artifact.executable.sha256
            ))? {
                urls.push(url);
            }
        }
        if self.settings.sources != Sources::GatewayOnly {
            urls.push(Url::parse(&format!(
                "https://github.com/{REPOSITORY}/releases/download/v{}/{}",
                manifest.release,
                artifact.archive_name()
            ))?);
        }
        for url in urls {
            let archive = tempfile::NamedTempFile::new_in(&self.root)?;
            match self.fetch(&url, archive.path(), MAX_ARCHIVE, cancel).await {
                Ok(()) => {
                    ensure!(
                        store::verified(archive.path(), &artifact.archive)?,
                        "Media archive digest mismatch"
                    );
                    let executable = extract(archive.path(), &directory, artifact)?;
                    store::publish(executable, &destination, true)?;
                    return Ok(destination);
                }
                Err(e) if e.is::<AccessDenied>() => return Err(e),
                Err(_) if cancel.is_cancelled() => {
                    anyhow::bail!("Media artifact operation cancelled")
                }
                Err(_) => {}
            }
        }
        anyhow::bail!("Verified native media helper unavailable")
    }
}
/// Verify a namespaced archive and its sole executable without running it.
/// Used by the gateway and offline publisher before exposing immutable bytes.
pub fn extract_verified_archive(path:&Path,root:&Path,artifact:&Artifact)->Result<tempfile::NamedTempFile> {
    artifact.validate()?;
    ensure!(store::verified(path,&artifact.archive)?,"Media archive digest mismatch");
    extract(path,root,artifact)
}
fn extract(path: &Path, root: &Path, artifact: &Artifact) -> Result<tempfile::NamedTempFile> {
    let decoder = flate2::read::GzDecoder::new(std::fs::File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut result = None;
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?.into_owned();
        ensure!(
            path == Path::new(&artifact.member())
                && entry.header().entry_type().is_file()
                && result.is_none(),
            "Unexpected media archive member"
        );
        ensure!(
            entry.size() == artifact.executable.size,
            "Media executable size mismatch"
        );
        let mut file = tempfile::NamedTempFile::new_in(root)?;
        let count = std::io::copy(&mut entry.take(MAX_EXECUTABLE + 1), file.as_file_mut())?;
        ensure!(
            count == artifact.executable.size
                && store::verified(file.path(), &artifact.executable)?,
            "Media executable digest mismatch"
        );
        result = Some(file);
    }
    result.context("Media executable missing from archive")
}
