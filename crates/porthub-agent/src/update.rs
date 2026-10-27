//! Authenticated release selection and streaming integrity verification. Catalog
//! URLs never supply a new credential authority or an executable path.
use crate::{
    control::{Control, Failure},
    service,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const MAX_BINARY: u64 = 256 * 1024 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub id: String,
    pub target_version: String,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "invalid update request identity"
        );
        ensure!(
            !self.target_version.is_empty()
                && self.target_version.len() <= 128
                && self
                    .target_version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)),
            "invalid update target version"
        );
        Ok(())
    }
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Result<Option<Self>> {
        if headers
            .get("x-porthub-client-update-requested")
            .and_then(|value| value.to_str().ok())
            != Some("true")
        {
            return Ok(None);
        }
        let request = Self {
            id: headers
                .get("x-porthub-client-update-request-id")
                .and_then(|value| value.to_str().ok())
                .context("update request identity missing")?
                .into(),
            target_version: headers
                .get("x-porthub-client-target-version")
                .and_then(|value| value.to_str().ok())
                .context("update target version missing")?
                .into(),
        };
        request.validate()?;
        Ok(Some(request))
    }
}

pub fn native_target() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Ok("x86_64"),
        ("linux", "x86") => Ok("x86"),
        ("linux", "aarch64") => Ok("arm64"),
        ("linux", "arm") if env!("PORTHUB_RUST_TARGET").starts_with("armv7") => Ok("armv7"),
        ("linux", "arm") => Ok("armhf"),
        ("macos", "x86_64") => Ok("darwin_x86_64"),
        ("macos", "aarch64") => Ok("darwin_arm64"),
        ("windows", "x86_64") => Ok("windows_x86_64"),
        ("windows", "x86") => Ok("windows_x86"),
        ("windows", "aarch64") => Ok("windows_arm64"),
        _ => anyhow::bail!("agent updates are unavailable for this platform"),
    }
}
fn platform(target: &str) -> Option<(&'static str, &'static str)> {
    match target {
        "x86_64" => Some(("linux", "x86_64")),
        "x86" => Some(("linux", "x86")),
        "arm64" => Some(("linux", "aarch64")),
        "armhf" => Some(("linux", "arm")),
        "armv7" => Some(("linux", "armv7")),
        "darwin_x86_64" => Some(("macos", "x86_64")),
        "darwin_arm64" => Some(("macos", "aarch64")),
        "windows_x86_64" => Some(("windows", "x86_64")),
        "windows_x86" => Some(("windows", "x86")),
        "windows_arm64" => Some(("windows", "aarch64")),
        _ => None,
    }
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
impl Release {
    fn validate(&self, requested: &str) -> Result<()> {
        let expected = platform(requested).context("unsupported native release target")?;
        ensure!(
            self.target == requested && (self.os.as_str(), self.arch.as_str()) == expected,
            "release platform does not match the requested target"
        );
        let suffix = if self.os == "windows" { ".exe" } else { "" };
        ensure!(
            self.asset == format!("porthub-{requested}{suffix}"),
            "invalid release asset name"
        );
        ensure!(
            !self.version.is_empty()
                && self.version.len() <= 128
                && self
                    .version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte)),
            "invalid release version"
        );
        ensure!(
            self.sha256.len() == 64 && self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "invalid release SHA256"
        );
        ensure!(
            self.size > 0 && self.size <= MAX_BINARY,
            "invalid release binary size"
        );
        Ok(())
    }
}
#[derive(Deserialize)]
struct Catalog {
    format_version: u64,
    machine_id: String,
    releases: Vec<Release>,
}
pub async fn discover(
    control: &Control,
    target: &str,
    cancel: &CancellationToken,
) -> Result<Release> {
    ensure!(
        platform(target).is_some(),
        "unsupported native release target"
    );
    let profile = control.profile();
    let path = control.release_path(None);
    let fetch = async {
        let reply = control
            .request(reqwest::Method::GET, &path, None, &[])
            .await?;
        let catalog: Catalog = serde_json::from_slice(&reply.bytes)
            .map_err(|_| anyhow::anyhow!("invalid authenticated release catalog"))?;
        ensure!(
            catalog.format_version == 1 && catalog.machine_id == profile.machine_id,
            "release catalog enrollment identity mismatch"
        );
        ensure!(
            catalog.releases.len() <= 32,
            "release catalog exceeds target limit"
        );
        let mut matching = catalog
            .releases
            .into_iter()
            .filter(|release| release.target == target);
        let release = matching
            .next()
            .context("requested native release is not published")?;
        ensure!(
            matching.next().is_none(),
            "release catalog contains duplicate targets"
        );
        release.validate(target)?;
        Ok(release)
    };
    tokio::select! { biased; _=cancel.cancelled()=>anyhow::bail!("release discovery cancelled"), result=tokio::time::timeout(Duration::from_secs(60),fetch)=>result.context("release discovery timed out")? }
}

pub struct Staged {
    pub release: Release,
    pub executable: PathBuf,
}
impl Staged {
    /// Run only the version command of an integrity-checked native executable.
    /// Output, time and child lifetime stay bounded before any service changes.
    pub async fn verify_executable(&self, cancel: &CancellationToken) -> Result<()> {
        ensure!(!cancel.is_cancelled(), "release verification cancelled");
        self.release.validate(native_target()?)?;
        let directory = self
            .executable
            .parent()
            .and_then(Path::parent)
            .context("staged release directory missing")?;
        service::directory(directory, false)?;
        let verified = &self.executable;
        service::directory(
            verified
                .parent()
                .context("staged release directory missing")?,
            false,
        )?;
        ensure!(
            verified.file_name().is_some_and(|name| name
                == if cfg!(windows) {
                    "porthub.exe"
                } else {
                    "porthub"
                })
                && verified
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case(&self.release.sha256)),
            "staged executable no longer matches the selected release"
        );
        ensure!(
            service::publication::hash_file(verified)?.eq_ignore_ascii_case(&self.release.sha256),
            "staged executable checksum verification failed"
        );
        let check = async {
            use std::process::Stdio;
            use tokio::io::AsyncReadExt;
            let mut child = tokio::process::Command::new(verified)
                .arg("version")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|_| anyhow::anyhow!("native release version check could not start"))?;
            let mut bytes = Vec::new();
            child
                .stdout
                .take()
                .context("native release version output missing")?
                .take(4097)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| anyhow::anyhow!("native release version output interrupted"))?;
            ensure!(
                bytes.len() <= 4096,
                "native release version output exceeds limit"
            );
            let status = child
                .wait()
                .await
                .map_err(|_| anyhow::anyhow!("native release version check interrupted"))?;
            ensure!(
                status.success()
                    && std::str::from_utf8(&bytes).is_ok_and(
                        |value| value.trim() == format!("porthub {}", self.release.version)
                    ),
                "native executable version does not match the published release"
            );
            Ok(())
        };
        tokio::select! {
            biased;
            _=cancel.cancelled()=>anyhow::bail!("release verification cancelled"),
            result=tokio::time::timeout(Duration::from_secs(5),check)=>result.context("native release version check timed out")?,
        }
    }
}
pub async fn stage(
    control: &Control,
    release: &Release,
    directory: &Path,
    cancel: &CancellationToken,
) -> Result<Staged> {
    release.validate(&release.target)?;
    service::directory(directory, false)?;
    let download = async {
        for base in control.authorities() {
            let mut response = match control.release_request(&base, &release.target).await?.send().await {
                Ok(response) => response,
                Err(_) => continue,
            };
            if response.status().is_redirection() || response.status().is_server_error() {
                continue;
            }
            if response.status() != reqwest::StatusCode::OK {
                return Err(Failure::Rejected(response.status().as_u16()).into());
            }
            // Require the selected metadata, not a different artifact supplied
            // by a racing publication or stale fallback server.
            let header = |name: &str| {
                response
                    .headers()
                    .get(name)
                    .and_then(|value| value.to_str().ok())
            };
            ensure!(
                header("x-porthub-agent-target") == Some(release.target.as_str())
                    && header("x-porthub-agent-release") == Some(release.version.as_str())
                    && header("x-porthub-agent-sha256")
                        .is_some_and(|value| value.eq_ignore_ascii_case(&release.sha256)),
                "download metadata does not match the selected release"
            );
            ensure!(
                response
                    .content_length()
                    .is_none_or(|size| size == release.size),
                "release download size mismatch"
            );
            let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
            let mut hash = Sha256::new();
            let mut total = 0u64;
            let mut interrupted = false;
            loop {
                let chunk = tokio::time::timeout(Duration::from_secs(20), response.chunk()).await;
                match chunk {
                    Ok(Ok(Some(chunk))) => {
                        total = total
                            .checked_add(chunk.len() as u64)
                            .context("release size overflow")?;
                        ensure!(
                            total <= release.size,
                            "release download exceeds declared size"
                        );
                        hash.update(&chunk);
                        temporary.write_all(&chunk)?;
                    }
                    Ok(Ok(None)) => break,
                    _ => {
                        interrupted = true;
                        break;
                    }
                }
            }
            if interrupted {
                continue;
            }
            ensure!(total == release.size, "release download was truncated");
            ensure!(
                format!("{:x}", hash.finalize()).eq_ignore_ascii_case(&release.sha256),
                "release checksum verification failed"
            );
            temporary.as_file().sync_all()?;
            let executable = service::binary(temporary.path(), directory)?;
            ensure!(
                executable
                    .parent()
                    .and_then(Path::file_name)
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case(&release.sha256)),
                "staged release identity mismatch"
            );
            return Ok(Staged {
                release: release.clone(),
                executable,
            });
        }
        Err(Failure::Unavailable.into())
    };
    tokio::select! { biased; _=cancel.cancelled()=>anyhow::bail!("release download cancelled"), result=tokio::time::timeout(Duration::from_secs(600),download)=>result.context("release download timed out")? }
}
