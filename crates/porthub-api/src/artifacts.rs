//! Native release assets. Hashing is bounded and cached by the opened file's
//! identity; downloads keep that descriptor across atomic bundle replacement.
//! GitHub assets are fetched lazily into a persistent verified cache. Local
//! immutable bundles remain available for offline validation and fixtures.
use crate::error::{ApiError, ApiResult};
use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};
use tokio_util::io::ReaderStream;

pub const TARGETS: &[(&str, &str, &str)] = &[
    ("x86_64", "linux", "x86_64"),
    ("x86", "linux", "x86"),
    ("arm64", "linux", "aarch64"),
    ("armhf", "linux", "arm"),
    ("armv7", "linux", "armv7"),
    ("darwin_x86_64", "macos", "x86_64"),
    ("darwin_arm64", "macos", "aarch64"),
    ("windows_x86_64", "windows", "x86_64"),
    ("windows_x86", "windows", "x86"),
    ("windows_arm64", "windows", "aarch64"),
];
/// Offline validation of a complete release before publishing it to GitHub.
/// No database, credentials, network, or running API is needed.
pub async fn verify_complete(root: &Path, version: &str) -> anyhow::Result<Vec<Release>> {
    use std::collections::BTreeSet;
    anyhow::ensure!(!version.is_empty(), "release version is required");
    let mut expected = BTreeSet::new();
    for (target, _, _) in TARGETS {
        let asset = format!(
            "porthub-{target}{}",
            if target.starts_with("windows_") {
                ".exe"
            } else {
                ""
            }
        );
        for suffix in ["", ".version", ".sha256"] {
            expected.insert(format!("{asset}{suffix}"));
        }
    }
    let mut actual = BTreeSet::new();
    let mut entries = tokio::fs::read_dir(root).await?;
    while let Some(entry) = entries.next_entry().await? {
        anyhow::ensure!(
            entry.file_type().await?.is_file(),
            "release directory must contain only regular files"
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("invalid release filename"))?;
        actual.insert(name);
    }
    anyhow::ensure!(
        actual == expected,
        "release bundle requires exactly one complete ten-platform release"
    );
    let catalog = Catalog::new(Some(root.into()));
    let mut releases = Vec::new();
    for (target, _, _) in TARGETS {
        let artifact = catalog
            .get(target)
            .await
            .map_err(|_| anyhow::anyhow!("release asset validation failed for {target}"))?;
        anyhow::ensure!(
            artifact.release.version == version,
            "release version mismatch for {target}"
        );
        releases.push(artifact.release);
    }
    Ok(releases)
}
pub fn normalize(target: &str, legacy: bool) -> ApiResult<&'static str> {
    let target = match target {
        "amd64" | "linux_amd64" | "linux_x86_64" => "x86_64",
        "x86" if legacy => "x86_64",
        "i386" | "i686" | "linux_x86" => "x86",
        "aarch64" | "linux_arm64" => "arm64",
        "arm" => "armhf",
        "darwin_amd64" | "macos_x86_64" => "darwin_x86_64",
        "macos_arm64" => "darwin_arm64",
        "windows_amd64" | "win64" => "windows_x86_64",
        "win32" => "windows_x86",
        "windows_aarch64" => "windows_arm64",
        value => value,
    };
    TARGETS
        .iter()
        .find(|(name, _, _)| *name == target)
        .map(|(name, _, _)| *name)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                if legacy {
                    "Unsupported Rathole target"
                } else {
                    "Unsupported agent target"
                },
            )
        })
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Release {
    pub target: String,
    pub os: String,
    pub arch: String,
    pub asset: String,
    pub version: String,
    pub sha256: String,
    pub size: u64,
}
#[derive(PartialEq, Eq)]
struct Fingerprint {
    size: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}
impl Fingerprint {
    fn new(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            size: meta.len(),
            modified: meta.modified().ok(),
            #[cfg(unix)]
            identity: (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec()),
        }
    }
}
pub struct Artifact {
    pub release: Release,
    file: File,
    modified: Option<SystemTime>,
}
pub struct Catalog {
    root: Option<PathBuf>,
    cache: Mutex<BTreeMap<PathBuf, (Fingerprint, String)>>,
    remote: Option<std::sync::Arc<crate::release_cache::Remote>>,
}
fn unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "Agent release metadata is unavailable",
    )
}
fn absent(asset: &str) -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, &format!("Asset not found: {asset}"))
}
async fn open(path: &Path) -> std::io::Result<File> {
    let mut options = tokio::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path).await?;
    if !file.metadata().await?.is_file() {
        return Err(std::io::Error::other("asset is not a regular file"));
    }
    Ok(file)
}
async fn text(path: &Path, optional: bool) -> ApiResult<Option<String>> {
    let file = match open(path).await {
        Ok(file) => file,
        Err(error) if optional && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(unavailable()),
    };
    if file.metadata().await.map_err(|_| unavailable())?.len() > 512 {
        return Err(unavailable());
    }
    let mut value = Vec::new();
    file.take(513)
        .read_to_end(&mut value)
        .await
        .map_err(|_| unavailable())?;
    if value.len() > 512 {
        return Err(unavailable());
    }
    String::from_utf8(value)
        .map(Some)
        .map_err(|_| unavailable())
}
impl Catalog {
    pub fn new(root: Option<PathBuf>) -> Self {
        Self {
            root,
            cache: Mutex::new(BTreeMap::new()),
            remote: None,
        }
    }
    pub fn github(root: PathBuf, repository: &str) -> anyhow::Result<Self> {
        Ok(Self { root: None, cache: Mutex::new(BTreeMap::new()), remote: Some(crate::release_cache::Remote::github(root, repository)?) })
    }
    #[cfg(test)]
    pub(crate) fn fixture(remote: std::sync::Arc<crate::release_cache::Remote>) -> Self {
        Self { root: None, cache: Mutex::new(BTreeMap::new()), remote: Some(remote) }
    }
    pub fn version(&self, fallback: &str) -> String {
        match &self.remote { Some(remote) => remote.version().unwrap_or_default(), None => fallback.to_owned() }
    }
    pub fn refresh_background(&self) {
        if let Some(remote) = &self.remote { remote.refresh_background(); }
    }
    pub async fn refresh_latest(&self) -> ApiResult<()> {
        if let Some(remote) = &self.remote { remote.refresh_latest().await.map_err(|_| unavailable())?; }
        Ok(())
    }
    /// Catalog listing must not populate every platform's binary cache.
    pub async fn release(&self, target: &'static str) -> ApiResult<Release> {
        if let Some(remote) = &self.remote {
            return remote.release(target).await.map_err(|_| unavailable());
        }
        Ok(self.get(target).await?.release)
    }
    pub async fn get(&self, target: &'static str) -> ApiResult<Artifact> {
        if let Some(remote) = &self.remote {
            let root = remote.ensure(target, false).await.map_err(|_| unavailable())?;
            match self.get_local(target, Some(&root)).await {
                Ok(artifact) => return Ok(artifact),
                Err(_) => {
                    let root = remote.ensure(target, true).await.map_err(|_| unavailable())?;
                    return self.get_local(target, Some(&root)).await;
                }
            }
        }
        self.get_local(target, self.root.as_deref()).await
    }
    async fn get_local(&self, target: &'static str, root: Option<&Path>) -> ApiResult<Artifact> {
        let (target, os, arch) = TARGETS
            .iter()
            .find(|(name, _, _)| *name == target)
            .ok_or_else(unavailable)?;
        let asset = format!(
            "porthub-{target}{}",
            if *os == "windows" { ".exe" } else { "" }
        );
        let root = root.ok_or_else(|| absent(&asset))?;
        let root = tokio::fs::canonicalize(root)
            .await
            .map_err(|_| absent(&asset))?;
        let path = root.join(&asset);
        let mut file = open(&path).await.map_err(|_| absent(&asset))?;
        let meta = file.metadata().await.map_err(|_| unavailable())?;
        let before = Fingerprint::new(&meta);
        let version = text(&root.join(format!("{asset}.version")), false)
            .await?
            .unwrap_or_default()
            .trim()
            .to_owned();
        if version.is_empty()
            || version.len() > 128
            || !version
                .bytes()
                .all(|ch| ch.is_ascii_alphanumeric() || b"._+-".contains(&ch))
        {
            return Err(unavailable());
        }
        let mut cache = self.cache.lock().await;
        let sha256 =
            if let Some((_, hash)) = cache.get(&path).filter(|(identity, _)| *identity == before) {
                hash.clone()
            } else {
                let mut hash = Sha256::new();
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let read = file.read(&mut buffer).await.map_err(|_| unavailable())?;
                    if read == 0 {
                        break;
                    }
                    hash.update(&buffer[..read]);
                }
                if Fingerprint::new(&file.metadata().await.map_err(|_| unavailable())?) != before {
                    return Err(unavailable());
                }
                let hash = format!("{:x}", hash.finalize());
                // At most the fixed platform matrix is retained per configured root.
                if cache.len() >= TARGETS.len() {
                    cache.clear();
                }
                cache.insert(path.clone(), (before, hash.clone()));
                hash
            };
        drop(cache);
        if let Some(expected) = text(&root.join(format!("{asset}.sha256")), true).await? {
            let mut fields = expected.split_whitespace();
            let digest = fields.next().unwrap_or_default();
            if !digest.eq_ignore_ascii_case(&sha256)
                || fields
                    .next()
                    .is_some_and(|name| name.trim_start_matches('*') != asset)
                || fields.next().is_some()
            {
                return Err(unavailable());
            }
        }
        file.rewind().await.map_err(|_| unavailable())?;
        Ok(Artifact {
            release: Release {
                target: (*target).into(),
                os: (*os).into(),
                arch: (*arch).into(),
                asset,
                version,
                sha256,
                size: meta.len(),
            },
            file,
            modified: meta.modified().ok(),
        })
    }
}
fn header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}
pub(crate) fn matches_etag(value: &str, etag: &str, weak: bool) -> bool {
    value.split(',').any(|value| {
        let value = value.trim();
        value == "*"
            || (if weak {
                value.strip_prefix("W/").unwrap_or(value)
            } else {
                value
            }) == etag
    })
}
fn not_modified(modified: Option<SystemTime>, date: &str) -> bool {
    modified
        .zip(httpdate::parse_http_date(date).ok())
        .is_some_and(|(modified, date)| {
            modified
                .duration_since(UNIX_EPOCH)
                .ok()
                .zip(date.duration_since(UNIX_EPOCH).ok())
                .is_some_and(|(modified, date)| modified.as_secs() <= date.as_secs())
        })
}
enum Range {
    Full,
    Part(u64, u64),
    Invalid,
}
fn range(value: &str, size: u64) -> Range {
    let Some(value) = value.strip_prefix("bytes=") else {
        return Range::Full;
    };
    if value.contains(',') {
        return Range::Full;
    } // Multi-range requests may be ignored.
    let Some((start, end)) = value.split_once('-') else {
        return Range::Invalid;
    };
    if size == 0 {
        return Range::Invalid;
    }
    if start.is_empty() {
        return match end.parse::<u64>() {
            Ok(suffix) if suffix > 0 => Range::Part(size.saturating_sub(suffix), size - 1),
            _ => Range::Invalid,
        };
    }
    let Ok(start) = start.parse::<u64>() else {
        return Range::Invalid;
    };
    let end = if end.is_empty() {
        size - 1
    } else {
        match end.parse::<u64>() {
            Ok(end) => end.min(size - 1),
            _ => return Range::Invalid,
        }
    };
    if start > end || start >= size {
        Range::Invalid
    } else {
        Range::Part(start, end)
    }
}
impl Artifact {
    pub async fn response(
        mut self,
        method: &Method,
        headers: &HeaderMap,
        legacy: bool,
    ) -> ApiResult<Response> {
        let etag = format!("\"{}\"", self.release.sha256);
        let mut output = HeaderMap::new();
        for (key, value) in [
            ("content-type", "application/octet-stream".into()),
            ("cache-control", "no-store".into()),
            ("referrer-policy", "no-referrer".into()),
            ("x-content-type-options", "nosniff".into()),
            ("accept-ranges", "bytes".into()),
            ("etag", etag.clone()),
            (
                "content-disposition",
                format!(
                    "attachment; filename=\"{}\"",
                    if legacy {
                        "rathole"
                    } else {
                        &self.release.asset
                    }
                ),
            ),
            ("x-porthub-agent-target", self.release.target.clone()),
            ("x-porthub-agent-release", self.release.version.clone()),
            ("x-porthub-agent-asset", self.release.asset.clone()),
            ("x-porthub-agent-sha256", self.release.sha256.clone()),
        ] {
            output.insert(
                axum::http::HeaderName::from_static(key),
                HeaderValue::from_str(&value).map_err(|_| unavailable())?,
            );
        }
        if legacy {
            for (key, value) in [
                ("x-porthub-rathole-target", &self.release.target),
                ("x-porthub-rathole-release", &self.release.version),
                ("x-porthub-rathole-asset", &self.release.asset),
            ] {
                output.insert(
                    axum::http::HeaderName::from_static(key),
                    HeaderValue::from_str(value).map_err(|_| unavailable())?,
                );
            }
        }
        if let Some(modified) = self.modified {
            output.insert(
                header::LAST_MODIFIED,
                HeaderValue::from_str(&httpdate::fmt_http_date(modified))
                    .map_err(|_| unavailable())?,
            );
        }
        let mut status = StatusCode::OK;
        if header(headers, header::IF_MATCH).is_some_and(|value| !matches_etag(value, &etag, false))
            || (!headers.contains_key(header::IF_MATCH)
                && header(headers, header::IF_UNMODIFIED_SINCE).is_some_and(|value| {
                    httpdate::parse_http_date(value).is_ok() && !not_modified(self.modified, value)
                }))
        {
            status = StatusCode::PRECONDITION_FAILED;
        } else if header(headers, header::IF_NONE_MATCH)
            .is_some_and(|value| matches_etag(value, &etag, true))
            || (!headers.contains_key(header::IF_NONE_MATCH)
                && header(headers, header::IF_MODIFIED_SINCE)
                    .is_some_and(|value| not_modified(self.modified, value)))
        {
            status = StatusCode::NOT_MODIFIED;
        }
        if status != StatusCode::OK {
            return Ok((status, output, Body::empty()).into_response());
        }
        let if_range = header(headers, header::IF_RANGE)
            .is_none_or(|value| value == etag || not_modified(self.modified, value));
        let selected = if if_range {
            header(headers, header::RANGE)
                .map_or(Range::Full, |value| range(value, self.release.size))
        } else {
            Range::Full
        };
        let (start, length) = match selected {
            Range::Full => (0, self.release.size),
            Range::Part(start, end) => {
                status = StatusCode::PARTIAL_CONTENT;
                output.insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes {start}-{end}/{}", self.release.size))
                        .map_err(|_| unavailable())?,
                );
                (start, end - start + 1)
            }
            Range::Invalid => {
                output.insert(
                    header::CONTENT_RANGE,
                    HeaderValue::from_str(&format!("bytes */{}", self.release.size))
                        .map_err(|_| unavailable())?,
                );
                return Ok(
                    (StatusCode::RANGE_NOT_SATISFIABLE, output, Body::empty()).into_response()
                );
            }
        };
        output.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&length.to_string()).map_err(|_| unavailable())?,
        );
        let body = if *method == Method::HEAD {
            Body::empty()
        } else {
            self.file
                .seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|_| unavailable())?;
            Body::from_stream(ReaderStream::new(self.file.take(length)))
        };
        Ok((status, output, body).into_response())
    }
}
