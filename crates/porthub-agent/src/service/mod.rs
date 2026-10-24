//! Native per-profile service lifecycle. Installations use an immutable binary
//! release, private copied credentials and owned unit files. Operations never
//! enumerate or modify unrelated services.
use crate::profile::{self, Profile};
use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
#[cfg(any(target_os = "macos", all(test, unix)))]
pub mod launchd;
mod process;
pub(crate) mod publication;
#[cfg(target_os = "linux")]
pub mod systemd;
const MARKER: &str = "# Managed by PortHub native agent";
fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
pub fn identity(profile: &Profile) -> String {
    hex(Sha256::digest(
        format!("{}\n{}", profile.server, profile.machine_id).as_bytes(),
    ))
}
pub(crate) enum RegistrationProfile {
    Public(Profile),
    Private(crate::private_profile::Profile),
}
impl RegistrationProfile {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        // Public legacy imports retain their existing securely-owned 0644
        // compatibility; private credentials always require private mode.
        let public = Profile::import_for_service(path);
        if let Ok(profile) = public {
            return Ok(Self::Public(profile));
        }
        Ok(Self::Private(crate::private_profile::Profile::load(path)?))
    }
    pub(crate) fn identity(&self) -> String {
        match self {
            Self::Public(profile) => identity(profile),
            Self::Private(profile) => hex(Sha256::digest(
                format!("private\n{}\n{}", profile.server, profile.peer_id).as_bytes(),
            )),
        }
    }
    fn machine_id(&self) -> String {
        match self {
            Self::Public(profile) => profile.machine_id.clone(),
            Self::Private(profile) => profile
                .peer_id
                .split_once(':')
                .map_or(profile.peer_id.as_str(), |(_, machine)| machine)
                .into(),
        }
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        Ok(match self {
            Self::Public(profile) => serde_json::to_vec_pretty(profile)?,
            Self::Private(profile) => serde_json::to_vec_pretty(profile)?,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Layout {
    pub user: bool,
    pub state: PathBuf,
    pub releases: PathBuf,
    pub units: PathBuf,
}
impl Layout {
    pub fn system() -> Result<Self> {
        #[cfg(target_os = "linux")]
        return Ok(Self {
            user: false,
            state: "/etc/porthub/native".into(),
            releases: "/opt/porthub/releases".into(),
            units: "/etc/systemd/system".into(),
        });
        #[cfg(target_os = "macos")]
        return Ok(Self {
            user: false,
            state: "/Library/Application Support/PortHub/native".into(),
            releases: "/Library/Application Support/PortHub/releases".into(),
            units: "/Library/LaunchDaemons".into(),
        });
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("native service installation for this platform is not implemented yet")
    }
    pub fn user() -> Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let dirs =
                directories::BaseDirs::new().context("cannot find per-user service locations")?;
            Ok(Self {
                user: true,
                state: dirs.config_dir().join("porthub/native"),
                releases: dirs.data_local_dir().join("porthub/releases"),
                units: {
                    #[cfg(target_os = "linux")]
                    {
                        dirs.config_dir().join("systemd/user")
                    }
                    #[cfg(target_os = "macos")]
                    {
                        dirs.home_dir().join("Library/LaunchAgents")
                    }
                },
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        anyhow::bail!("native user services for this platform are not implemented yet")
    }
}
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Spec {
    #[serde(default)]
    pub user: bool,
    pub identity: String,
    pub service: String,
    pub profile: PathBuf,
    pub executable: PathBuf,
    pub unit: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli: Option<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub installed: bool,
    pub enabled: bool,
    pub active: bool,
}
#[async_trait]
pub trait Manager: Send + Sync {
    async fn state(&self, spec: &Spec) -> Result<State>;
    async fn reload(&self) -> Result<()>;
    async fn enable(&self, spec: &Spec) -> Result<()>;
    async fn disable(&self, spec: &Spec) -> Result<()>;
    async fn start(&self, spec: &Spec) -> Result<()>;
    async fn stop(&self, spec: &Spec) -> Result<()>;
    async fn reset_failed(&self, _spec: &Spec) -> Result<()> {
        Ok(())
    }
}
#[async_trait]
pub trait Readiness: Send + Sync {
    async fn wait(&self, spec: &Spec) -> Result<()>;
}
pub struct RuntimeReady;
#[async_trait]
impl Readiness for RuntimeReady {
    async fn wait(&self, spec: &Spec) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if crate::runtime::status(&spec.profile).is_ok_and(|status| {
                    let executable_matches = process::matches(status.pid, &spec.executable);
                    status.state == "running"
                        && status.agent_version == crate::VERSION
                        && executable_matches
                }) {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .context("native registration did not become ready")?
    }
}
pub(crate) fn directory(path: &Path, private: bool) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_dir(),
                "service directory must be a real directory"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                anyhow::ensure!(
                    metadata.uid() == rustix::process::getuid().as_raw()
                        && metadata.permissions().mode() & 0o022 == 0,
                    "service directory must be owned by this account and not writable by others"
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().context("service directory needs a parent")?;
            if !parent.exists() {
                directory(parent, false)?;
            }
            let metadata = std::fs::symlink_metadata(parent)?;
            anyhow::ensure!(
                metadata.is_dir(),
                "service directory parent must be a real directory"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                anyhow::ensure!(
                    metadata.uid() == rustix::process::getuid().as_raw()
                        && metadata.permissions().mode() & 0o022 == 0,
                    "service directory parent is not owned securely"
                );
            }
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(if private { 0o700 } else { 0o755 });
            }
            builder.create(path)?;
            #[cfg(unix)]
            File::open(parent)?.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}
fn regular(path: &Path) -> Result<Option<Vec<u8>>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 4 * 1024 * 1024,
        "managed service state must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == rustix::process::getuid().as_raw()
                && metadata.permissions().mode() & 0o022 == 0,
            "managed service state ownership is unsafe"
        );
    }
    Ok(Some(std::fs::read(path)?))
}
pub(crate) fn atomic(path: &Path, bytes: &[u8], private: bool) -> Result<()> {
    let parent = path.parent().context("service state needs a directory")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(std::fs::Permissions::from_mode(if private {
                0o600
            } else {
                0o644
            }))?;
    }
    file.as_file().sync_all()?;
    file.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(not(target_os = "macos"))]
fn argument(path: &Path) -> Result<String> {
    let value = path
        .to_str()
        .context("service paths must be valid Unicode")?;
    anyhow::ensure!(
        path.is_absolute() && !value.chars().any(char::is_control),
        "service paths must be absolute without control characters"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    ))
}
#[cfg(not(target_os = "macos"))]
pub fn unit(spec: &Spec) -> Result<String> {
    // systemd rejects these characters in the executable itself even when
    // correctly escaped. Profile arguments can still contain quoted characters.
    anyhow::ensure!(
        !spec
            .executable
            .to_str()
            .context("service executable must be Unicode")?
            .contains(['\\', '\"', '\'']),
        "systemd executable paths cannot contain quotes or backslashes"
    );
    let target = if spec.user {
        "default.target"
    } else {
        "multi-user.target"
    };
    let network = if spec.user {
        ""
    } else {
        "After=network-online.target\nWants=network-online.target\n"
    };
    Ok(format!("{MARKER}: {}\n[Unit]\nDescription=PortHub machine agent\n{network}StartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=simple\nExecStart=:{} run --profile {}\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=15\nUMask=0077\n\n[Install]\nWantedBy={target}\n",spec.identity,argument(&spec.executable)?,argument(&spec.profile)?))
}
#[cfg(target_os = "macos")]
pub fn unit(spec: &Spec) -> Result<String> {
    launchd::unit(spec)
}
fn unit_name(service: &str) -> String {
    format!(
        "{service}.{}",
        if cfg!(target_os = "macos") {
            "plist"
        } else {
            "service"
        }
    )
}
fn owned_unit(spec: &Spec) -> Result<Option<Vec<u8>>> {
    let previous = regular(&spec.unit)?;
    if let Some(bytes) = &previous {
        anyhow::ensure!(
            bytes.starts_with(
                {
                    #[cfg(target_os = "macos")]
                    {
                        launchd::marker(&spec.identity)
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        format!("{MARKER}: {}\n", spec.identity)
                    }
                }
                .as_bytes()
            ),
            "service unit exists and is not owned by this PortHub profile"
        );
    }
    Ok(previous)
}
pub(crate) fn binary(source: &Path, releases: &Path) -> Result<PathBuf> {
    anyhow::ensure!(
        std::fs::symlink_metadata(source)?.is_file(),
        "agent executable source must be a regular file"
    );
    let source = std::fs::canonicalize(source)?;
    let metadata = std::fs::metadata(&source)?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 256 * 1024 * 1024,
        "agent executable must be a bounded regular file"
    );
    let mut source = File::open(source)?;
    let mut staged = tempfile::NamedTempFile::new_in(releases)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        staged.write_all(&buffer[..count])?;
    }
    staged.as_file().sync_all()?;
    let release = releases.join(hex(hash.finalize()));
    directory(&release, false)?;
    let path = release.join(if cfg!(windows) {
        "porthub.exe"
    } else {
        "porthub"
    });
    if let Ok(metadata) = std::fs::symlink_metadata(&path) {
        anyhow::ensure!(
            metadata.is_file() && metadata.len() == staged.as_file().metadata()?.len(),
            "installed release executable is not owned or intact"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            anyhow::ensure!(
                metadata.uid() == rustix::process::getuid().as_raw()
                    && metadata.permissions().mode() & 0o022 == 0,
                "installed release executable has unsafe ownership"
            );
        }
        let mut existing = File::open(&path)?;
        let mut check = Sha256::new();
        loop {
            let n = existing.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            check.update(&buffer[..n]);
        }
        anyhow::ensure!(
            hex(check.finalize()) == release.file_name().unwrap().to_string_lossy(),
            "installed release checksum does not match its identity"
        );
        return Ok(path);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    staged
        .persist_noclobber(&path)
        .map_err(|error| error.error)?;
    #[cfg(unix)]
    File::open(&release)?.sync_all()?;
    Ok(path)
}
struct Files {
    saved: Vec<(PathBuf, Option<Vec<u8>>, bool)>,
    committed: bool,
}
impl Files {
    fn new() -> Self {
        Self {
            saved: Vec::new(),
            committed: false,
        }
    }
    fn write(&mut self, path: &Path, bytes: &[u8], private: bool) -> Result<()> {
        self.saved.push((path.into(), regular(path)?, private));
        atomic(path, bytes, private)
    }
    fn rollback(&mut self) -> Result<()> {
        for (path, previous, private) in self.saved.iter().rev() {
            if let Some(bytes) = previous {
                atomic(path, bytes, *private)?;
            } else {
                match std::fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
        self.committed = true;
        Ok(())
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        if !self.committed {
            if let Err(error) = self.rollback() {
                tracing::error!(%error,"service files rollback failed");
            }
        }
    }
}
fn manifest(layout: &Layout, id: &str) -> PathBuf {
    layout.state.join(format!("{id}.service.json"))
}
pub(crate) fn installed(layout: &Layout, id: &str) -> Result<Option<Spec>> {
    let Some(bytes) = regular(&manifest(layout, id))? else {
        return Ok(None);
    };
    let spec: Spec = serde_json::from_slice(&bytes)?;
    anyhow::ensure!(
        spec.identity == id
            && spec.user == layout.user
            && spec.service == format!("porthub-{}", &id[..24])
            && spec.profile == layout.state.join(format!("{id}.json"))
            && spec.unit == layout.units.join(unit_name(&spec.service))
            && spec.executable.parent().and_then(Path::parent)==Some(layout.releases.as_path())
            && spec.executable.file_name().is_some_and(|name|name==if cfg!(windows){"porthub.exe"}else{"porthub"})
            && spec.cli.as_ref().is_none_or(|path|path.is_absolute() && path.file_name().is_some_and(|name|name=="porthub"))
            && spec.executable.parent().and_then(Path::file_name).and_then(|name|name.to_str()).is_some_and(|name|name.len()==64&&name.bytes().all(|b|b.is_ascii_hexdigit())),
        "installed service manifest does not match its profile"
    );
    owned_unit(&spec)?;
    Ok(Some(spec))
}
pub struct Registration {
    pub spec: Spec,
    pub machine_id: String,
}
/// Read only owned native manifests. Legacy registrations are imported by a
/// separate workflow; arbitrary paths are never accepted as tenant selectors.
pub fn registrations(layout: &Layout) -> Result<Vec<Registration>> {
    if !layout.user {
        require_administrator()?;
    }
    owned_registrations(layout)
}
pub(crate) fn owned_registrations(layout: &Layout) -> Result<Vec<Registration>> {
    let metadata =
        match std::fs::symlink_metadata(&layout.state) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error).context(
                "cannot read registrations; use administrator access for system profiles or --user",
            ),
        };
    anyhow::ensure!(metadata.is_dir(), "service state directory must be real");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        anyhow::ensure!(
            metadata.uid() == rustix::process::getuid().as_raw()
                && metadata.permissions().mode() & 0o022 == 0,
            "service state directory ownership is unsafe"
        );
    }
    let mut entries = Vec::new();
    for (count, entry) in std::fs::read_dir(&layout.state)?.enumerate() {
        anyhow::ensure!(count < 32768, "registration directory exceeds entry limit");
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = name.strip_suffix(".service.json") else {
            continue;
        };
        if id.len() != 64 || !id.bytes().all(|ch| ch.is_ascii_hexdigit()) {
            continue;
        }
        let Some(spec) = installed(layout, id)? else {
            continue;
        };
        let profile = RegistrationProfile::load(&spec.profile)?;
        anyhow::ensure!(
            profile.identity() == id,
            "registration does not match its profile"
        );
        anyhow::ensure!(entries.len() < 4096, "too many local registrations");
        entries.push(Registration {
            spec,
            machine_id: profile.machine_id(),
        });
    }
    entries.sort_by(|a, b| a.spec.identity.cmp(&b.spec.identity));
    Ok(entries)
}
pub fn select(layout: &Layout, selector: Option<&str>) -> Result<Registration> {
    let entries = registrations(layout)?;
    let mut matches: Vec<_> = if let Some(selector) = selector {
        let id = selector.to_ascii_lowercase();
        anyhow::ensure!(
            (id.len() >= 6 && id.len() <= 64 && id.bytes().all(|ch| ch.is_ascii_hexdigit()))
                || (id.starts_with("porthub-")
                    && id.len() == 32
                    && id[8..].bytes().all(|ch| ch.is_ascii_hexdigit())),
            "invalid tenant selector"
        );
        entries
            .into_iter()
            .filter(|entry| {
                entry.spec.identity.starts_with(&id)
                    || entry.machine_id.starts_with(&id)
                    || entry.spec.service == id
            })
            .collect()
    } else {
        entries
    };
    anyhow::ensure!(
        !matches.is_empty(),
        "no matching native PortHub registration"
    );
    anyhow::ensure!(
        matches.len() == 1,
        "multiple native registrations match; pass a longer id from porthub ls"
    );
    Ok(matches.remove(0))
}
pub(crate) fn lock(layout: &Layout) -> Result<crate::profile::Lease> {
    crate::profile::Lease::acquire(&layout.state.join("installations"))
}
#[cfg(target_os = "linux")]
pub(crate) fn bind_cli(layout: &Layout, id: &str, cli: &Path) -> Result<()> {
    // The caller holds the normal installation lock through publication.
    let mut spec = installed(layout, id)?.context("native registration missing")?;
    spec.cli = Some(cli.to_owned());
    atomic(
        &manifest(layout, id),
        &serde_json::to_vec_pretty(&spec)?,
        true,
    )
}
/// Prepare and activate one service. Layout injection is for isolated staging;
/// the CLI always derives system locations and checks administrative privileges.
pub async fn install(
    layout: &Layout,
    source: &Path,
    executable: &Path,
    manager: &dyn Manager,
) -> Result<Spec> {
    install_published(layout, source, executable, manager, None).await
}
pub async fn install_published(
    layout: &Layout,
    source: &Path,
    executable: &Path,
    manager: &dyn Manager,
    cli: Option<&Path>,
) -> Result<Spec> {
    directory(&layout.state, true)?;
    directory(&layout.releases, false)?;
    directory(&layout.units, false)?;
    let _lock = lock(layout)?;
    install_locked(layout, source, executable, manager, cli).await
}
/// The caller holds the layout installation lock for a larger transaction.
pub(crate) async fn install_locked(
    layout: &Layout,
    source: &Path,
    executable: &Path,
    manager: &dyn Manager,
    cli: Option<&Path>,
) -> Result<Spec> {
    let profile = RegistrationProfile::load(source)?;
    anyhow::ensure!(
        !layout.user || !matches!(profile, RegistrationProfile::Private(_)),
        "private network services require system network privileges"
    );
    let id = profile.identity();
    directory(&layout.state, true)?;
    directory(&layout.releases, false)?;
    directory(&layout.units, false)?;
    let previous = installed(layout, &id)?;
    let executable = binary(executable, &layout.releases)?;
    let spec = Spec {
        user: layout.user,
        identity: id.clone(),
        service: format!("porthub-{}", &id[..24]),
        profile: layout.state.join(format!("{id}.json")),
        unit: layout
            .units
            .join(unit_name(&format!("porthub-{}", &id[..24]))),
        executable,
        cli: cli
            .map(Path::to_owned)
            .or_else(|| previous.as_ref().and_then(|spec| spec.cli.clone())),
    };
    owned_unit(&spec)?;
    let old = manager.state(&spec).await?;
    anyhow::ensure!(
        !old.installed || previous.is_some(),
        "service registration is not owned by PortHub"
    );
    let mut publication = cli
        .map(|path| publication::Publication::prepare(layout, path, &spec.executable))
        .transpose()?;
    let mut files = Files::new();
    files.write(&spec.profile, &profile.bytes()?, true)?;
    files.write(&spec.unit, unit(&spec)?.as_bytes(), false)?;
    files.write(
        &manifest(layout, &id),
        &serde_json::to_vec_pretty(&spec)?,
        true,
    )?;
    let mut attempted_start = false;
    let result = async {
        manager.reload().await?;
        manager.enable(&spec).await?;
        manager.reset_failed(&spec).await?;
        attempted_start = true;
        manager.start(&spec).await
    }
    .await;
    if let Err(error) = result {
        if attempted_start {
            let _ = manager.stop(&spec).await;
        }
        if !old.enabled {
            let _ = manager.disable(&spec).await;
        }
        let rollback = files.rollback();
        let cli_rollback = publication
            .as_mut()
            .map(|publication| publication.restore())
            .transpose();
        let _ = manager.reload().await;
        if let Some(previous) = &previous {
            if old.enabled {
                let _ = manager.enable(previous).await;
            }
            if old.active && attempted_start {
                let _ = manager.reset_failed(previous).await;
                let _ = manager.start(previous).await;
            }
        }
        if let Err(rollback) = rollback {
            return Err(error.context(format!(
                "service activation and file rollback failed: {rollback}"
            )));
        }
        if let Err(rollback) = cli_rollback {
            return Err(error.context(format!(
                "service activation and CLI rollback failed: {rollback}"
            )));
        }
        return Err(error.context("service activation failed; previous files restored"));
    }
    files.committed = true;
    if let Some(publication) = &mut publication {
        publication.commit();
    }
    Ok(spec)
}
#[derive(Clone, Copy)]
pub enum Action {
    Start,
    Stop,
    Restart,
    Uninstall { purge: bool },
}
pub async fn action(
    layout: &Layout,
    source: &Path,
    action: Action,
    manager: &dyn Manager,
) -> Result<Spec> {
    let profile = RegistrationProfile::load(source)?;
    let id = profile.identity();
    directory(&layout.state, true)?;
    let _lock = lock(layout)?;
    let spec = installed(layout, &id)?.context("this PortHub profile has no managed service")?;
    match action {
        Action::Start => {
            if !manager.state(&spec).await?.active {
                manager.start(&spec).await?;
            }
        }
        Action::Stop => manager.stop(&spec).await?,
        Action::Restart => {
            manager.stop(&spec).await?;
            manager.start(&spec).await?;
        }
        Action::Uninstall { purge } => {
            manager.stop(&spec).await?;
            manager.disable(&spec).await?;
            match std::fs::remove_file(&spec.unit) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            manager.reload().await?;
            manager.reset_failed(&spec).await?;
            if purge {
                anyhow::ensure!(
                    !profile::Lease::running(&spec.profile)?,
                    "managed profile still has a running owner"
                );
                for suffix in [
                    ".config.json",
                    ".status.json",
                    ".update-attempt.json",
                    ".update-commit.json",
                    ".lock",
                    "",
                ] {
                    let path = profile::sibling(&spec.profile, suffix);
                    if regular(&path)?.is_some() {
                        std::fs::remove_file(path)?;
                    }
                }
            }
            std::fs::remove_file(manifest(layout, &id))?;
        }
    }
    Ok(spec)
}
pub async fn status(layout: &Layout, source: &Path, manager: &dyn Manager) -> Result<State> {
    let profile = RegistrationProfile::load(source)?;
    let id = profile.identity();
    match installed(layout, &id)? {
        Some(spec) => manager.state(&spec).await,
        None => Ok(State {
            installed: false,
            enabled: false,
            active: false,
        }),
    }
}
pub async fn system_manager(user: bool) -> Result<Box<dyn Manager>> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = user;
    #[cfg(target_os = "linux")]
    return Ok(Box::new(if user {
        systemd::Systemd::connect_user().await?
    } else {
        systemd::Systemd::connect().await?
    }));
    #[cfg(target_os = "macos")]
    return Ok(Box::new(launchd::Launchd::connect(user).await?));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    anyhow::bail!("native service controller for this platform is not implemented yet")
}
pub fn require_administrator() -> Result<()> {
    #[cfg(unix)]
    anyhow::ensure!(
        rustix::process::geteuid().is_root(),
        "run with administrative privileges to manage system services"
    );
    Ok(())
}
pub const OPERATION_TIMEOUT: Duration = Duration::from_secs(20);
