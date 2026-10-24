//! Durable replacement of an existing native Linux registration and its paired
//! private service. The independent worker owns this transaction, not a service
//! being restarted. Download verification and update acknowledgement are separate.
use crate::{
    profile::{self, Profile},
    service::{self, Layout, Manager, Readiness, Spec, State},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize)]
struct Entry {
    spec: Spec,
    state: State,
    profile_hash: String,
    unit_hash: String,
    manifest_hash: String,
}
pub struct Plan {
    entries: Vec<Entry>,
    cli: Option<(PathBuf, PathBuf)>,
}
impl Plan {
    pub fn registrations(&self) -> usize {
        self.entries.len()
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn manifest(layout: &Layout, id: &str) -> PathBuf {
    layout.state.join(format!("{id}.service.json"))
}
fn read(path: &Path) -> Result<Vec<u8>> {
    crate::legacy::read_owned(path, 65536)
}
fn release(layout: &Layout, path: &Path) -> Result<()> {
    let expected = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .context("native release identity missing")?;
    ensure!(
        path.parent().and_then(Path::parent) == Some(layout.releases.as_path())
            && path.file_name().is_some_and(|name| name == "porthub")
            && expected.len() == 64
            && expected.bytes().all(|byte| byte.is_ascii_hexdigit())
            && service::publication::hash_file(path)? == expected,
        "native release is not owned and intact"
    );
    Ok(())
}
fn belongs(profile: &service::RegistrationProfile, public: &Profile) -> bool {
    match profile {
        service::RegistrationProfile::Public(existing) => {
            existing.server == public.server && existing.machine_id == public.machine_id
        }
        service::RegistrationProfile::Private(existing) => {
            existing.server == public.server
                && existing
                    .peer_id
                    .split_once(':')
                    .is_some_and(|(_, machine)| machine == public.machine_id)
        }
    }
}
/// Inspection is read-only and must include the matching installed public
/// identity. Profiles from another gateway or machine are never included.
pub async fn plan(
    layout: &Layout,
    public: &Profile,
    cli: Option<&Path>,
    manager: &dyn Manager,
) -> Result<Plan> {
    let mut public = public.clone();
    public.validate()?;
    let mut entries = Vec::new();
    let mut public_found = false;
    for registration in service::owned_registrations(layout)? {
        let spec = registration.spec;
        let profile = service::RegistrationProfile::load(&spec.profile)?;
        if !belongs(&profile, &public) {
            continue;
        }
        if let service::RegistrationProfile::Public(existing) = &profile {
            ensure!(
                existing.token == public.token,
                "native update enrollment credential mismatch"
            );
            ensure!(!public_found, "duplicate native public registration");
            public_found = true;
        }
        ensure!(
            read(&spec.unit)? == service::unit(&spec)?.as_bytes(),
            "native service unit was customized; explicit migration required"
        );
        release(layout, &spec.executable)?;
        let state = manager.state(&spec).await?;
        ensure!(
            state.installed,
            "native service is not installed in the service manager"
        );
        entries.push(Entry {
            profile_hash: hash(&read(&spec.profile)?),
            unit_hash: hash(&read(&spec.unit)?),
            manifest_hash: hash(&read(&manifest(layout, &spec.identity))?),
            spec,
            state,
        });
    }
    ensure!(
        public_found && entries.len() <= 2,
        "native update requires the installed public registration and at most its private pair"
    );
    let cli = cli
        .map(|path| {
            service::publication::managed_link(layout, path).map(|target| (path.to_owned(), target))
        })
        .transpose()?;
    Ok(Plan { entries, cli })
}
#[derive(Serialize, Deserialize)]
struct Journal {
    format_version: u32,
    state: String,
    executable: PathBuf,
    entries: Vec<Entry>,
    cli: Option<(PathBuf, PathBuf)>,
    #[serde(default)]
    request: Option<crate::update::Request>,
    #[serde(default)]
    public_id: String,
}
fn write(receipt: &Path, journal: &Journal) -> Result<()> {
    profile::write_private(
        &receipt.join("journal.json"),
        &serde_json::to_vec_pretty(journal)?,
        true,
    )
}
struct Preserve<'a> {
    inner: &'a dyn Manager,
    state: State,
}
#[async_trait::async_trait]
impl Manager for Preserve<'_> {
    async fn state(&self, spec: &Spec) -> Result<State> {
        self.inner.state(spec).await
    }
    async fn reload(&self) -> Result<()> {
        self.inner.reload().await
    }
    async fn enable(&self, spec: &Spec) -> Result<()> {
        if self.state.enabled {
            self.inner.enable(spec).await
        } else {
            Ok(())
        }
    }
    async fn disable(&self, spec: &Spec) -> Result<()> {
        self.inner.disable(spec).await
    }
    async fn start(&self, spec: &Spec) -> Result<()> {
        if self.state.active {
            self.inner.start(spec).await
        } else {
            Ok(())
        }
    }
    async fn stop(&self, spec: &Spec) -> Result<()> {
        self.inner.stop(spec).await
    }
    async fn reset_failed(&self, spec: &Spec) -> Result<()> {
        self.inner.reset_failed(spec).await
    }
}
fn original(layout: &Layout, entry: &Entry) -> Result<()> {
    ensure!(
        service::installed(layout, &entry.spec.identity)?.as_ref() == Some(&entry.spec),
        "native registration changed after inspection"
    );
    ensure!(
        hash(&read(&entry.spec.profile)?) == entry.profile_hash
            && hash(&read(&entry.spec.unit)?) == entry.unit_hash
            && hash(&read(&manifest(layout, &entry.spec.identity))?) == entry.manifest_hash,
        "native service files changed after inspection"
    );
    Ok(())
}
fn independent(entries: &[Entry]) -> Result<()> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        entries
            .iter()
            .all(|entry| !cgroup.contains(&format!("{}.service", entry.spec.service))),
        "native updates must run in an independent maintenance worker"
    );
    Ok(())
}
/// Executable must already have passed authenticated staging and its version
/// check. Holding the normal installation lock serializes every service edit.
pub async fn apply(
    layout: &Layout,
    plan: Plan,
    executable: &Path,
    manager: &dyn Manager,
    ready: &dyn Readiness,
) -> Result<PathBuf> {
    apply_requested(layout, plan, executable, manager, ready, None).await
}
pub async fn apply_requested(
    layout: &Layout,
    plan: Plan,
    executable: &Path,
    manager: &dyn Manager,
    ready: &dyn Readiness,
    request: Option<crate::update::Request>,
) -> Result<PathBuf> {
    if let Some(request) = &request {
        request.validate()?;
        ensure!(
            request.target_version == crate::VERSION,
            "update worker version differs from requested target"
        );
    }
    service::directory(&layout.state, true)?;
    service::directory(&layout.releases, false)?;
    let _lock = service::lock(layout)?;
    independent(&plan.entries)?;
    for entry in &plan.entries {
        original(layout, entry)?;
        ensure!(
            manager.state(&entry.spec).await? == entry.state,
            "native service state changed after inspection"
        );
    }
    if let Some((path, target)) = &plan.cli {
        ensure!(
            service::publication::managed_link(layout, path)? == *target,
            "shared CLI changed after inspection"
        );
    }
    let executable = service::binary(executable, &layout.releases)?;
    use std::os::unix::fs::PermissionsExt;
    let receipt = tempfile::Builder::new()
        .prefix("upgrade-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(&layout.state)?
        .keep();
    for (i, entry) in plan.entries.iter().enumerate() {
        for (suffix, path) in [
            ("profile", entry.spec.profile.clone()),
            ("unit", entry.spec.unit.clone()),
            ("manifest", manifest(layout, &entry.spec.identity)),
        ] {
            profile::write_private(&receipt.join(format!("{i}.{suffix}")), &read(&path)?, false)?;
        }
    }
    let public_id = plan
        .entries
        .iter()
        .find_map(
            |entry| match service::RegistrationProfile::load(&entry.spec.profile) {
                Ok(service::RegistrationProfile::Public(_)) => Some(entry.spec.identity.clone()),
                _ => None,
            },
        )
        .context("public update identity missing")?;
    let mut journal = Journal {
        format_version: 1,
        state: "prepared".into(),
        executable,
        entries: plan.entries,
        cli: plan.cli,
        request,
        public_id,
    };
    write(&receipt, &journal)?;
    // Persist the receipt's directory entry before any installed state changes.
    std::fs::File::open(&layout.state)?.sync_all()?;
    if let Some(request) = &journal.request {
        remember(
            &layout.state.join(format!("{}.json", journal.public_id)),
            &receipt,
            request,
        )?;
    }
    let result: Result<()> = async {
        journal.state = "activating".into();
        write(&receipt, &journal)?;
        for (i, entry) in journal.entries.iter().enumerate() {
            if entry.spec.executable == journal.executable {
                if entry.state.active {
                    ready.wait(&entry.spec).await?;
                }
                continue;
            }
            let spec = service::install_locked(
                layout,
                &receipt.join(format!("{i}.profile")),
                &journal.executable,
                &Preserve {
                    inner: manager,
                    state: entry.state.clone(),
                },
                None,
            )
            .await?;
            if entry.state.active {
                ready.wait(&spec).await?;
            }
        }
        let mut publication = if let Some((path, previous)) = &journal.cli {
            ensure!(
                service::publication::managed_link(layout, path)? == *previous,
                "shared CLI changed during update"
            );
            Some(service::publication::Publication::prepare(
                layout,
                path,
                &journal.executable,
            )?)
        } else {
            None
        };
        journal.state = "committed".into();
        write(&receipt, &journal)?;
        if let Some(publication) = &mut publication {
            publication.commit();
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        if recover_locked(layout, &receipt, &mut journal, manager)
            .await
            .is_err()
        {
            return Err(error.context(format!(
                "native update needs recovery; receipt: {}",
                receipt.display()
            )));
        }
        return Err(error.context(format!(
            "native update failed; previous services restored; receipt: {}",
            receipt.display()
        )));
    }
    if let Some(request) = &journal.request {
        let source = layout.state.join(format!("{}.json", journal.public_id));
        if remember(&source, &receipt, request).is_err() {
            tracing::warn!("update committed; acknowledgement index will be recovered");
        }
    }
    Ok(receipt)
}
#[derive(Serialize, Deserialize)]
struct CommitIndex {
    receipt: String,
    request: crate::update::Request,
}
fn remember(source: &Path, receipt: &Path, request: &crate::update::Request) -> Result<()> {
    let name = receipt
        .file_name()
        .and_then(|name| name.to_str())
        .context("update receipt name missing")?;
    profile::write_private(
        &profile::sibling(source, ".update-commit.json"),
        &serde_json::to_vec(&CommitIndex {
            receipt: name.into(),
            request: request.clone(),
        })?,
        true,
    )
}
fn proves(
    layout: &Layout,
    source: &Path,
    public: &Profile,
    request: &crate::update::Request,
    executable: &Path,
    receipt: &Path,
) -> Result<bool> {
    if receipt.parent() != Some(layout.state.as_path()) {
        return Ok(false);
    }
    let journal: Journal =
        serde_json::from_slice(&profile::read_private(&receipt.join("journal.json"))?)?;
    let id = service::identity(public);
    let bound = Profile::load(source)?;
    if bound.server != public.server
        || bound.machine_id != public.machine_id
        || bound.token != public.token
    {
        return Ok(false);
    }
    if journal.format_version != 1
        || journal.state != "committed"
        || journal.request.as_ref() != Some(request)
        || journal.public_id != id
        || source != layout.state.join(format!("{id}.json"))
        || journal.entries.is_empty()
        || journal.entries.len() > 2
        || std::fs::canonicalize(&journal.executable).ok().as_deref() != Some(executable)
    {
        return Ok(false);
    }
    let profile_hash = hash(&profile::read_private(source)?);
    if !journal
        .entries
        .iter()
        .any(|entry| entry.spec.identity == id && entry.profile_hash == profile_hash)
    {
        return Ok(false);
    }
    for entry in &journal.entries {
        let Some(installed) = service::installed(layout, &entry.spec.identity)? else {
            return Ok(false);
        };
        if std::fs::canonicalize(&installed.executable).ok().as_deref() != Some(executable)
            || read(&installed.unit)? != service::unit(&installed)?.as_bytes()
        {
            return Ok(false);
        }
    }
    Ok(true)
}
/// A heartbeat may acknowledge only a committed transaction for this request,
/// current executable and enrollment. Rollback invalidates the same receipt.
pub fn committed(
    layout: &Layout,
    source: &Path,
    public: &Profile,
    request: &crate::update::Request,
    executable: &Path,
) -> Result<bool> {
    request.validate()?;
    if request.target_version != crate::VERSION {
        return Ok(false);
    }
    let index = profile::sibling(source, ".update-commit.json");
    if index.try_exists()? {
        let index: CommitIndex = serde_json::from_slice(&profile::read_private(&index)?)?;
        if index.request == *request {
            ensure!(
                index.receipt.starts_with("upgrade-")
                    && index.receipt.len() <= 128
                    && index
                        .receipt
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
                "invalid update receipt index"
            );
            return proves(
                layout,
                source,
                public,
                request,
                executable,
                &layout.state.join(index.receipt),
            );
        }
    }
    // Recover the narrow crash window after journal commit but before writing
    // its index. This scan runs only while a matching update is outstanding.
    let mut receipts = 0;
    for (count, entry) in std::fs::read_dir(&layout.state)?.enumerate() {
        ensure!(count < 32768, "native update state exceeds entry limit");
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("upgrade-") {
            continue;
        }
        receipts += 1;
        ensure!(receipts <= 1024, "native update receipt limit exceeded");
        if proves(layout, source, public, request, executable, &entry.path()).unwrap_or(false) {
            remember(source, &entry.path(), request)?;
            return Ok(true);
        }
    }
    Ok(false)
}
pub fn failed(layout: &Layout, source: &Path, request: &crate::update::Request) -> Result<bool> {
    let path = profile::sibling(source, ".update-commit.json");
    if !path.try_exists()? {
        return Ok(false);
    }
    let index: CommitIndex = serde_json::from_slice(&profile::read_private(&path)?)?;
    if index.request != *request {
        return Ok(false);
    }
    ensure!(
        index.receipt.starts_with("upgrade-")
            && index.receipt.len() <= 128
            && index
                .receipt
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
        "invalid update receipt index"
    );
    let journal: Journal = serde_json::from_slice(&profile::read_private(
        &layout.state.join(index.receipt).join("journal.json"),
    )?)?;
    Ok(journal.format_version == 1
        && journal.request.as_ref() == Some(request)
        && journal.state == "rolled-back")
}
fn validate(layout: &Layout, receipt: &Path, journal: &Journal) -> Result<()> {
    ensure!(
        receipt.parent() == Some(layout.state.as_path())
            && receipt
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("upgrade-")),
        "native update receipt is outside managed state"
    );
    ensure!(
        journal.format_version == 1
            && !journal.entries.is_empty()
            && journal.entries.len() <= 2
            && matches!(
                journal.state.as_str(),
                "prepared" | "activating" | "committed" | "rolling-back" | "rolled-back"
            ),
        "invalid native update receipt"
    );
    ensure!(
        journal.executable.parent().and_then(Path::parent) == Some(layout.releases.as_path()),
        "native update release path is invalid"
    );
    for (i, entry) in journal.entries.iter().enumerate() {
        let bytes = profile::read_private(&receipt.join(format!("{i}.manifest")))?;
        let previous: Spec = serde_json::from_slice(&bytes)?;
        ensure!(
            previous == entry.spec
                && hash(&bytes) == entry.manifest_hash
                && previous.identity.len() == 64
                && previous
                    .identity
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                && previous.user == layout.user
                && previous.service == format!("porthub-{}", &previous.identity[..24])
                && previous.profile == layout.state.join(format!("{}.json", previous.identity))
                && previous.unit == layout.units.join(format!("{}.service", previous.service))
                && previous.executable.parent().and_then(Path::parent)
                    == Some(layout.releases.as_path()),
            "invalid native update backup paths"
        );
        let source = receipt.join(format!("{i}.profile"));
        ensure!(
            service::RegistrationProfile::load(&source)?.identity() == previous.identity
                && hash(&read(&source)?) == entry.profile_hash
                && hash(&profile::read_private(&receipt.join(format!("{i}.unit")))?)
                    == entry.unit_hash,
            "native update backup changed"
        );
        ensure!(
            read(&receipt.join(format!("{i}.unit")))? == service::unit(&previous)?.as_bytes(),
            "invalid native update unit backup"
        );
        release(layout, &previous.executable)?;
    }
    Ok(())
}
pub async fn rollback(layout: &Layout, receipt: &Path, manager: &dyn Manager) -> Result<()> {
    ensure!(
        receipt.parent() == Some(layout.state.as_path())
            && receipt
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("upgrade-")),
        "native update receipt is outside managed state"
    );
    profile::validate_parent(&receipt.join("journal.json"))?;
    let _lock = service::lock(layout)?;
    // Check the directory itself before reading a private recovery journal.
    let mut journal: Journal =
        serde_json::from_slice(&profile::read_private(&receipt.join("journal.json"))?)?;
    validate(layout, receipt, &journal)?;
    independent(&journal.entries)?;
    if journal.state == "rolled-back" {
        return Ok(());
    }
    recover_locked(layout, receipt, &mut journal, manager).await
}
async fn recover_locked(
    layout: &Layout,
    receipt: &Path,
    journal: &mut Journal,
    manager: &dyn Manager,
) -> Result<()> {
    validate(layout, receipt, journal)?;
    let mut changed = Vec::new();
    for entry in &journal.entries {
        let current = service::installed(layout, &entry.spec.identity)?
            .context("native registration disappeared after update")?;
        ensure!(
            current.executable == entry.spec.executable || current.executable == journal.executable,
            "native service changed after update"
        );
        ensure!(
            hash(&read(&current.profile)?) == entry.profile_hash,
            "native credentials changed after update"
        );
        let mut replacement = entry.spec.clone();
        replacement.executable = journal.executable.clone();
        let unit = read(&current.unit)?;
        ensure!(
            unit == service::unit(&entry.spec)?.as_bytes()
                || unit == service::unit(&replacement)?.as_bytes(),
            "native service unit changed after update"
        );
        changed.push(current != entry.spec || hash(&unit) != entry.unit_hash);
    }
    journal.state = "rolling-back".into();
    write(receipt, journal)?;
    if let Some((path, previous)) = &journal.cli {
        service::publication::restore_link(layout, path, &journal.executable, previous)?;
    }
    for (entry, changed) in journal.entries.iter().zip(&changed) {
        if *changed {
            manager.stop(&entry.spec).await?;
        }
    }
    for (i, entry) in journal.entries.iter().enumerate() {
        if !changed[i] {
            continue;
        }
        service::atomic(
            &entry.spec.profile,
            &profile::read_private(&receipt.join(format!("{i}.profile")))?,
            true,
        )?;
        service::atomic(
            &entry.spec.unit,
            &profile::read_private(&receipt.join(format!("{i}.unit")))?,
            false,
        )?;
        service::atomic(
            &manifest(layout, &entry.spec.identity),
            &profile::read_private(&receipt.join(format!("{i}.manifest")))?,
            true,
        )?;
    }
    if changed.iter().any(|changed| *changed) {
        manager.reload().await?;
    }
    for entry in &journal.entries {
        let current = manager.state(&entry.spec).await?;
        if current.enabled != entry.state.enabled {
            if entry.state.enabled {
                manager.enable(&entry.spec).await?;
            } else {
                manager.disable(&entry.spec).await?;
            }
        }
        if current.active != entry.state.active {
            if entry.state.active {
                manager.reset_failed(&entry.spec).await?;
                manager.start(&entry.spec).await?;
            } else {
                manager.stop(&entry.spec).await?;
            }
        }
    }
    journal.state = "rolled-back".into();
    write(receipt, journal)
}
