//! Private, portable machine profiles. URLs identify the enrolled gateway;
//! runtime-selected origins never replace the saved authority.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default = "version")]
    pub format_version: u32,
    pub server: String,
    pub machine_id: String,
    pub token: String,
    #[serde(default)]
    pub fallback_servers: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub setup_overrides: BTreeMap<String, String>,
    #[serde(default)]
    pub allow_insecure_http_for_tests: bool,
}
fn version() -> u32 {
    1
}
impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachineProfile")
            .field("machine_id", &self.machine_id)
            .field("fallback_count", &self.fallback_servers.len())
            .finish_non_exhaustive()
    }
}
pub fn base(value: &str, insecure: bool) -> Result<String> {
    let parsed = url::Url::parse(value).context("invalid gateway URL")?;
    anyhow::ensure!(
        (parsed.scheme() == "https" || insecure && parsed.scheme() == "http")
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "gateway requires an HTTPS URL without credentials, query or fragment"
    );
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}
impl Profile {
    pub fn validate(&mut self) -> Result<()> {
        anyhow::ensure!(
            self.format_version == 1,
            "unsupported machine profile version"
        );
        anyhow::ensure!(
            self.machine_id.len() == 24 && self.machine_id.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid machine ID"
        );
        self.machine_id.make_ascii_lowercase();
        anyhow::ensure!(
            (1..=512).contains(&self.token.len()) && !self.token.contains(['\r', '\n']),
            "invalid machine token"
        );
        self.server = base(&self.server, self.allow_insecure_http_for_tests)?;
        anyhow::ensure!(
            self.fallback_servers.len() <= 8,
            "at most eight gateway fallbacks are allowed"
        );
        let mut fallbacks = Vec::new();
        for fallback in &self.fallback_servers {
            let fallback = base(fallback, self.allow_insecure_http_for_tests)?;
            if fallback != self.server && !fallbacks.contains(&fallback) {
                fallbacks.push(fallback);
            }
        }
        self.fallback_servers = fallbacks;
        anyhow::ensure!(self.setup_overrides.len() <= 3, "invalid setup overrides");
        for (key, value) in &mut self.setup_overrides {
            anyhow::ensure!(
                matches!(
                    key.as_str(),
                    "public_base_url" | "rathole_server_address" | "service_domain"
                ) && value.len() <= 2048
                    && !value.chars().any(char::is_control),
                "invalid setup override"
            );
            *value = value.trim().to_owned();
            if key == "public_base_url" {
                *value = base(value, self.allow_insecure_http_for_tests)?;
                anyhow::ensure!(
                    *value == self.server,
                    "setup public authority does not match the enrolled gateway"
                );
            }
        }
        self.setup_overrides.retain(|_, value| !value.is_empty());
        Ok(())
    }
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_private(path)?;
        anyhow::ensure!(bytes.len() <= 65536, "machine profile exceeds size limit");
        let mut profile: Self =
            serde_json::from_slice(&bytes).context("invalid machine profile")?;
        profile.validate()?;
        Ok(profile)
    }
    pub fn import_for_service(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        checked_import(path, true)?
            .take(65537)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(bytes.len() <= 65536, "machine profile exceeds size limit");
        let mut profile: Self =
            serde_json::from_slice(&bytes).context("invalid machine profile")?;
        profile.validate()?;
        Ok(profile)
    }
    pub fn save_new(&self, path: &Path) -> Result<()> {
        let mut profile = self.clone();
        profile.validate()?;
        write_private(path, &serde_json::to_vec_pretty(&profile)?, false)
    }
}
fn checked(path: &Path) -> Result<File> {
    checked_import(path, false)
}
fn checked_import(path: &Path, root_import: bool) -> Result<File> {
    #[cfg(not(unix))]
    let _ = root_import;
    let metadata = std::fs::symlink_metadata(path).context("read machine state metadata")?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 4 * 1024 * 1024,
        "machine state must be a bounded regular file"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        anyhow::ensure!(
            (metadata.uid() == rustix::process::getuid().as_raw()
                || root_import && rustix::process::geteuid().is_root())
                && metadata.permissions().mode() & 0o077 == 0,
            "machine state must be owned by this user and private (0600)"
        );
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let current = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.dev() == current.dev() && metadata.ino() == current.ino(),
            "machine state changed during read"
        );
    }
    anyhow::ensure!(current.is_file(), "machine state must be a regular file");
    Ok(file)
}
pub fn read_private(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    checked(path)?
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 4 * 1024 * 1024,
        "machine state exceeds size limit"
    );
    Ok(bytes)
}
pub(crate) fn validate_parent(path: &Path) -> Result<&Path> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata =
        std::fs::symlink_metadata(parent).context("machine state directory does not exist")?;
    anyhow::ensure!(
        metadata.is_dir(),
        "machine state parent must be a real directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == rustix::process::getuid().as_raw()
                && metadata.permissions().mode() & 0o022 == 0,
            "machine state directory must be owned by this user and not writable by others"
        );
    }
    Ok(parent)
}
pub fn write_private(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = validate_parent(path)?;
    if replace {
        match checked(path) {
            Ok(_) => {}
            Err(error) if path.try_exists()? => return Err(error),
            Err(_) => {}
        }
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".porthub-state-")
        .tempfile_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if replace {
        temporary.persist(path).map_err(|e| e.error)?;
    } else {
        temporary.persist_noclobber(path).map_err(|e| e.error)?;
    }
    #[cfg(windows)]
    if crate::service::windows_acl::is_managed(path) {
        crate::service::windows_acl::secure(path, false)?;
    }
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}
pub struct Lease {
    _file: File,
}
impl Lease {
    fn file(profile: &Path, create: bool) -> Result<File> {
        let path = sibling(profile, ".lock");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(&path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(metadata.is_file(), "profile lock must be a regular file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            anyhow::ensure!(
                metadata.uid() == rustix::process::getuid().as_raw()
                    && metadata.permissions().mode() & 0o077 == 0,
                "profile lock must be owned by this user and private"
            );
        }
        Ok(file)
    }
    pub fn running(profile: &Path) -> Result<bool> {
        if !sibling(profile, ".lock").try_exists()? {
            return Ok(false);
        }
        let file = Self::file(profile, false)?;
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(false),
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }
    pub fn acquire(profile: &Path) -> Result<Self> {
        let file = Self::file(profile, true)?;
        fs2::FileExt::try_lock_exclusive(&file)
            .context("this machine profile is already running")?;
        Ok(Self { _file: file })
    }
}
