//! Explicit adoption of generated legacy Linux registrations. Credentials and
//! old unit files remain intact. A private journal and CLI backup permit
//! rollback after activation failure or an interrupted operator command.
use crate::{
    legacy, profile,
    service::{self, Action, Layout, Manager, Spec, State},
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
struct Prepared {
    legacy: Spec,
    bytes: Vec<u8>,
    id: String,
    unit_hash: String,
    state: State,
}
pub struct Plan {
    entries: Vec<Prepared>,
    cli: PathBuf,
    cli_hash: String,
}
#[derive(Serialize)]
pub struct Receipt {
    pub path: PathBuf,
    pub state: String,
    pub registrations: usize,
}
pub fn receipts(layout: &Layout) -> Result<Vec<Receipt>> {
    if !layout.state.try_exists()? {
        return Ok(Vec::new());
    }
    real_directory(&layout.state)?;
    let mut receipts = Vec::new();
    for (count, entry) in std::fs::read_dir(&layout.state)?.enumerate() {
        ensure!(count < 32768, "adoption state exceeds entry limit");
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("adoption-") {
            continue;
        }
        let path = entry.path();
        real_directory(&path)?;
        let (state, registrations) = if path.join("journal.json").try_exists()? {
            let record: Journal =
                serde_json::from_slice(&profile::read_private(&path.join("journal.json"))?)?;
            ensure!(
                record.version == 1
                    && matches!(
                        record.state.as_str(),
                        "preparing" | "committed" | "rolling-back" | "rolled-back"
                    ),
                "invalid adoption receipt"
            );
            (record.state, record.entries.len())
        } else {
            ("staging-incomplete".into(), 0)
        };
        receipts.push(Receipt {
            path,
            state,
            registrations,
        });
    }
    receipts.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(receipts)
}
pub struct Options {
    pub legacy_root: PathBuf,
    pub cli: PathBuf,
    pub private_executable: PathBuf,
    pub server: Option<String>,
    pub fallback_servers: Vec<String>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            legacy_root: "/etc/porthub".into(),
            cli: "/usr/local/bin/porthub".into(),
            private_executable: "/opt/porthub/bin/porthub".into(),
            server: None,
            fallback_servers: vec![],
        }
    }
}
impl Plan {
    pub fn registrations(&self) -> usize {
        self.entries.len()
    }
    /// Automatic installer migration is limited to its one matching public
    /// identity and that machine's private registration. Multi-tenant adoption
    /// remains an explicit operator action.
    pub fn for_enrollment(mut self, enrollment: &profile::Profile) -> Result<Self> {
        let mut enrollment = enrollment.clone();
        enrollment.validate()?;
        let mut public = 0;
        for entry in &mut self.entries {
            if let Ok(existing) = serde_json::from_slice::<profile::Profile>(&entry.bytes) {
                public += 1;
                ensure!(
                    existing.machine_id == enrollment.machine_id
                        && existing.token == enrollment.token
                        && existing.server == enrollment.server,
                    "installer does not match the existing legacy enrollment"
                );
                entry.bytes = serde_json::to_vec(&enrollment)?;
                entry.id = service::identity(&enrollment);
            } else {
                let private: crate::private_profile::Profile =
                    serde_json::from_slice(&entry.bytes)?;
                ensure!(
                    private
                        .peer_id
                        .split_once(':')
                        .is_some_and(|(_, machine)| machine == enrollment.machine_id)
                        && private.server == enrollment.server,
                    "another private registration requires explicit adoption"
                );
            }
        }
        ensure!(public==1,"installer migration requires one matching public registration; use explicit adoption for multiple tenants");
        Ok(self)
    }
}
pub struct Handoff {
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub registrations: usize,
}
/// Stage a stable executable before queueing a separate manager-owned job.
/// Temporary installer directories may disappear as soon as the caller exits.
pub async fn prepare_handoff(
    layout: &Layout,
    options: &Options,
    executable: &Path,
    manager: &dyn Manager,
) -> Result<Handoff> {
    let plan = inspect(layout, options, manager, true).await?;
    prepare_handoff_plan(layout, options, executable, plan)
}
fn prepare_handoff_plan(
    layout: &Layout,
    options: &Options,
    executable: &Path,
    plan: Plan,
) -> Result<Handoff> {
    service::directory(&layout.state, true)?;
    service::directory(&layout.releases, false)?;
    let executable = service::binary(executable, &layout.releases)?;
    let path = |path: &Path| {
        path.to_str()
            .map(str::to_owned)
            .context("adoption paths must be Unicode")
    };
    let mut arguments = vec![
        "adopt-legacy".into(),
        "--apply".into(),
        "--legacy-root".into(),
        path(&options.legacy_root)?,
        "--cli".into(),
        path(&options.cli)?,
        "--private-executable".into(),
        path(&options.private_executable)?,
    ];
    if let Some(server) = &options.server {
        arguments.extend(["--server".into(), server.clone()]);
    }
    for server in &options.fallback_servers {
        arguments.extend(["--fallback-server".into(), server.clone()]);
    }
    Ok(Handoff {
        executable,
        arguments,
        registrations: plan.registrations(),
    })
}
pub async fn prepare_enrollment_handoff(
    layout: &Layout,
    options: &Options,
    executable: &Path,
    manager: &dyn Manager,
    enrollment: &profile::Profile,
) -> Result<Handoff> {
    let plan = inspect(layout, options, manager, true)
        .await?
        .for_enrollment(enrollment)?;
    let mut prepared = prepare_handoff_plan(layout, options, executable, plan)?;
    let bytes = serde_json::to_vec(enrollment)?;
    let source = layout.state.join(format!("handoff-{}.json", hash(&bytes)));
    if source.try_exists()? {
        ensure!(
            profile::read_private(&source)? == bytes,
            "staged installer enrollment changed"
        );
    } else {
        profile::write_private(&source, &bytes, false)?;
    }
    prepared.arguments.extend([
        "--enrollment".into(),
        source
            .to_str()
            .context("staged enrollment path must be Unicode")?
            .to_owned(),
    ]);
    Ok(prepared)
}
fn real_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir(),
        "legacy registration directory must be real"
    );
    ensure!(
        service::trusted_directory(path, &metadata),
        "legacy registration directory ownership is unsafe"
    );
    Ok(())
}
fn unit(
    layout: &Layout,
    service: String,
    source: PathBuf,
    executable: PathBuf,
    expected: &str,
) -> Result<(Spec, String)> {
    let path = layout.units.join(format!("{service}.service"));
    let bytes = legacy::read_owned(&path, 65536)?;
    let text = std::str::from_utf8(&bytes).context("legacy unit must be UTF-8")?;
    let commands: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("ExecStart="))
        .collect();
    ensure!(
        commands == [expected]
            && text
                .lines()
                .any(|line| line.starts_with("Description=PortHub ")),
        "unit does not match the generated PortHub registration"
    );
    Ok((
        Spec {
            cli: None,
            user: false,
            identity: String::new(),
            service,
            profile: source,
            executable,
            unit: path,
        },
        hash(&bytes),
    ))
}
/// Read-only inspection. The CLI enforces administrator access before calling
/// this function; injected directories/managers support isolated tests.
pub async fn plan(layout: &Layout, options: &Options, manager: &dyn Manager) -> Result<Plan> {
    inspect(layout, options, manager, false).await
}
async fn inspect(
    layout: &Layout,
    options: &Options,
    manager: &dyn Manager,
    permit_current_service: bool,
) -> Result<Plan> {
    ensure!(
        !layout.user
            && options.cli.is_absolute()
            && options
                .cli
                .file_name()
                .is_some_and(|name| name == "porthub"),
        "legacy adoption requires a system CLI path"
    );
    real_directory(&options.legacy_root)?;
    real_directory(&layout.units)?;
    let cli_bytes = legacy::read_owned(&options.cli, 4 * 1024 * 1024)?;
    ensure!(
        (cli_bytes.starts_with(b"#!/usr/bin/env bash") || cli_bytes.starts_with(b"#!/bin/bash"))
            && cli_bytes
                .windows(24)
                .any(|bytes| bytes == b"PORT_HUB_CLIENT_VERSION=")
            && cli_bytes.windows(13).any(|bytes| bytes == b"__service-run"),
        "shared executable is not the generated legacy PortHub CLI"
    );
    let mut sources = Vec::new();
    let default = options.legacy_root.join("client.env");
    if default.try_exists()? {
        sources.push(default);
    }
    let tenants = options.legacy_root.join("tenants");
    if tenants.try_exists()? {
        real_directory(&tenants)?;
        for (count, entry) in std::fs::read_dir(&tenants)?.enumerate() {
            ensure!(count < 256, "too many legacy registrations");
            let path = entry?.path();
            real_directory(&path)?;
            let source = path.join("client.env");
            if source.try_exists()? {
                sources.push(source);
            }
        }
    }
    sources.sort();
    let mut entries = Vec::new();
    let mut names = HashSet::new();
    let mut identities = HashSet::new();
    for source in sources {
        let bytes = legacy::read_owned(&source, 65536)?;
        let values = legacy::assignments(&bytes)?;
        let tenant = values
            .get("PORT_HUB_TENANT")
            .map(String::as_str)
            .unwrap_or("");
        ensure!(
            tenant.len() <= 120
                && tenant.bytes().all(|byte| byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || b"-_.".contains(&byte)),
            "invalid legacy tenant identity"
        );
        ensure!(
            values
                .get("PORT_HUB_SELF_PATH")
                .is_some_and(|value| Path::new(value) == options.cli),
            "legacy registration uses another shared CLI"
        );
        let profile = legacy::parse_with_server(
            &bytes,
            options.fallback_servers.clone(),
            options.server.as_deref(),
        )?;
        let service = if tenant.is_empty() {
            "porthub".into()
        } else {
            format!("porthub-{tenant}")
        };
        let expected = if tenant.is_empty() {
            format!("{} __service-run", options.cli.display())
        } else {
            format!("{} __service-run --tenant {tenant}", options.cli.display())
        };
        let (legacy, unit_hash) = unit(layout, service, source, options.cli.clone(), &expected)?;
        ensure!(
            names.insert(legacy.service.clone()),
            "duplicate legacy service registration"
        );
        let id = service::identity(&profile);
        ensure!(
            identities.insert(id.clone()),
            "duplicate legacy machine registration"
        );
        let state = manager.state(&legacy).await?;
        entries.push(Prepared {
            legacy,
            bytes: serde_json::to_vec(&profile)?,
            id,
            unit_hash,
            state,
        });
    }
    let private = options.legacy_root.join("private.json");
    if private.try_exists()? {
        let bytes = profile::read_private(&private)?;
        ensure!(
            bytes.len() <= 65536,
            "legacy private profile exceeds size limit"
        );
        let mut profile: crate::private_profile::Profile = serde_json::from_slice(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid legacy private profile"))?;
        if let Some(server) = &options.server {
            profile.server = server.clone();
        }
        profile.fallback_servers = options.fallback_servers.clone();
        profile.validate()?;
        let id = hash(format!("private\n{}\n{}", profile.server, profile.peer_id).as_bytes());
        let expected = format!(
            "{} run --profile {}",
            options.private_executable.display(),
            private.display()
        );
        let (legacy, unit_hash) = unit(
            layout,
            "porthub-private".into(),
            private,
            options.private_executable.clone(),
            &expected,
        )?;
        let state = manager.state(&legacy).await?;
        ensure!(
            identities.insert(id.clone()),
            "duplicate legacy machine registration"
        );
        entries.push(Prepared {
            legacy,
            bytes: serde_json::to_vec(&profile)?,
            id,
            unit_hash,
            state,
        });
    }
    ensure!(
        !entries.is_empty(),
        "no generated legacy registrations found"
    );
    // Replacing a shared CLI must not strand an omitted tenant or another unit.
    let marker = options
        .cli
        .to_str()
        .context("legacy CLI path must be Unicode")?;
    for (count, entry) in std::fs::read_dir(&layout.units)?.enumerate() {
        ensure!(count < 32768, "unit directory exceeds entry limit");
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "service")
            || !entry.file_type()?.is_file()
        {
            continue;
        }
        let bytes = legacy::read_unit_candidate(&path, 65536)?;
        let uses_cli = std::str::from_utf8(&bytes).ok().is_some_and(|text| {
            text.lines()
                .any(|line| line.starts_with("ExecStart=") && line.contains(marker))
        });
        if uses_cli {
            ensure!(
                legacy::read_owned(&path, 65536)? == bytes,
                "legacy unit changed during inspection"
            );
        }
        ensure!(
            !uses_cli || entries.iter().any(|entry| entry.legacy.unit == path),
            "another service still uses the legacy CLI; include every registration before adoption"
        );
    }
    for identity in &identities {
        ensure!(
            service::installed(layout, identity)?.is_none(),
            "a matching native registration already exists; use native service management"
        );
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/self/cgroup") {
        ensure!(
            permit_current_service
                || !entries
                    .iter()
                    .any(|entry| cgroup.contains(&format!("/{}.service", entry.legacy.service))),
            "use --handoff when adopting from inside a legacy agent service"
        );
    }
    Ok(Plan {
        entries,
        cli: options.cli.clone(),
        cli_hash: hash(&cli_bytes),
    })
}

pub use crate::service::{Readiness, RuntimeReady};
// Preserve deliberately stopped registrations without briefly contacting the
// gateway or advertising a new private fingerprint during their upgrade.
struct StagingManager<'a> {
    inner: &'a dyn Manager,
    enabled: bool,
}
#[async_trait::async_trait]
impl Manager for StagingManager<'_> {
    async fn state(&self, spec: &Spec) -> Result<State> {
        self.inner.state(spec).await
    }
    async fn reload(&self) -> Result<()> {
        self.inner.reload().await
    }
    async fn enable(&self, spec: &Spec) -> Result<()> {
        if self.enabled {
            self.inner.enable(spec).await
        } else {
            Ok(())
        }
    }
    async fn disable(&self, spec: &Spec) -> Result<()> {
        self.inner.disable(spec).await
    }
    async fn start(&self, _: &Spec) -> Result<()> {
        Ok(())
    }
    async fn stop(&self, spec: &Spec) -> Result<()> {
        self.inner.stop(spec).await
    }
    async fn reset_failed(&self, spec: &Spec) -> Result<()> {
        self.inner.reset_failed(spec).await
    }
}
#[derive(Serialize, Deserialize)]
struct Entry {
    legacy: Spec,
    source: PathBuf,
    id: String,
    unit_hash: String,
    state: State,
}
#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    state: String,
    cli: PathBuf,
    cli_hash: String,
    executable: PathBuf,
    entries: Vec<Entry>,
}
fn journal(path: &Path, value: &Journal) -> Result<()> {
    profile::write_private(
        &path.join("journal.json"),
        &serde_json::to_vec(value)?,
        true,
    )
}

pub async fn apply(
    layout: &Layout,
    plan: Plan,
    executable: &Path,
    manager: &dyn Manager,
    readiness: &dyn Readiness,
) -> Result<PathBuf> {
    service::directory(&layout.state, true)?;
    service::directory(&layout.releases, false)?;
    let _lease = profile::Lease::acquire(&layout.state.join("legacy-adoption"))?;
    ensure!(
        hash(&legacy::read_owned(&plan.cli, 4 * 1024 * 1024)?) == plan.cli_hash,
        "legacy CLI changed after inspection"
    );
    for entry in &plan.entries {
        ensure!(
            hash(&legacy::read_owned(&entry.legacy.unit, 65536)?) == entry.unit_hash,
            "legacy unit changed after inspection"
        );
        ensure!(
            manager.state(&entry.legacy).await? == entry.state,
            "legacy service state changed after inspection"
        );
        ensure!(
            service::installed(layout, &entry.id)?.is_none(),
            "matching native registration appeared after inspection"
        );
    }
    let executable = service::binary(executable, &layout.releases)?;
    use std::os::unix::fs::PermissionsExt;
    let receipt = tempfile::Builder::new()
        .prefix("adoption-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(&layout.state)?
        .keep();
    // Persistent backups retain original mode/ownership through hard links.
    std::fs::hard_link(&plan.cli, receipt.join("legacy-cli"))?;
    ensure!(
        hash(&legacy::read_owned(
            &receipt.join("legacy-cli"),
            4 * 1024 * 1024
        )?) == plan.cli_hash,
        "legacy CLI changed during backup"
    );
    let mut entries = Vec::new();
    for (index, prepared) in plan.entries.into_iter().enumerate() {
        let source = receipt.join(format!("{index}.json"));
        profile::write_private(&source, &prepared.bytes, false)?;
        profile::write_private(
            &receipt.join(format!("{index}.unit")),
            &legacy::read_owned(&prepared.legacy.unit, 65536)?,
            false,
        )?;
        entries.push(Entry {
            legacy: prepared.legacy,
            source,
            id: prepared.id,
            unit_hash: prepared.unit_hash,
            state: prepared.state,
        });
    }
    let mut record = Journal {
        version: 1,
        state: "preparing".into(),
        cli: plan.cli,
        cli_hash: plan.cli_hash,
        executable,
        entries,
    };
    journal(&receipt, &record)?;
    std::fs::File::open(&layout.state)?.sync_all()?;
    let result: Result<()> = async {
        for entry in &record.entries {
            if entry.state.active {
                manager.stop(&entry.legacy).await?;
            }
            if entry.state.enabled {
                manager.disable(&entry.legacy).await?;
            }
        }
        for entry in &record.entries {
            if entry.state.active {
                let spec =
                    service::install(layout, &entry.source, &record.executable, manager).await?;
                readiness.wait(&spec).await?;
                if !entry.state.enabled {
                    manager.disable(&spec).await?;
                }
            } else {
                service::install(
                    layout,
                    &entry.source,
                    &record.executable,
                    &StagingManager {
                        inner: manager,
                        enabled: entry.state.enabled,
                    },
                )
                .await?;
            }
        }
        let _installation_lock = service::lock(layout)?;
        let mut publication = service::publication::Publication::prepare_adoption(
            layout,
            &record.cli,
            &record.executable,
            &record.cli_hash,
        )?;
        for entry in &record.entries {
            service::bind_cli(layout, &entry.id, &record.cli)?;
        }
        record.state = "committed".into();
        journal(&receipt, &record)?;
        publication.commit();
        Ok(())
    }
    .await;
    if let Err(error) = result {
        if rollback_inner(layout, &receipt, &mut record, manager)
            .await
            .is_err()
        {
            return Err(error.context(format!(
                "adoption failed and rollback needs recovery; receipt: {}",
                receipt.display()
            )));
        }
        return Err(error.context(format!(
            "adoption failed; original CLI and legacy services restored; receipt: {}",
            receipt.display()
        )));
    }
    Ok(receipt)
}
pub async fn rollback(layout: &Layout, receipt: &Path, manager: &dyn Manager) -> Result<()> {
    service::directory(&layout.state, true)?;
    let _lease = profile::Lease::acquire(&layout.state.join("legacy-adoption"))?;
    real_directory(receipt)?;
    ensure!(
        receipt.parent() == Some(layout.state.as_path())
            && receipt
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("adoption-")),
        "recovery receipt is outside managed adoption state"
    );
    let mut record: Journal =
        serde_json::from_slice(&profile::read_private(&receipt.join("journal.json"))?)?;
    ensure!(
        record.version == 1
            && matches!(
                record.state.as_str(),
                "preparing" | "committed" | "rolling-back" | "rolled-back"
            ),
        "invalid adoption receipt"
    );
    if record.state == "rolled-back" {
        return Ok(());
    }
    rollback_inner(layout, receipt, &mut record, manager).await
}
async fn rollback_inner(
    layout: &Layout,
    receipt: &Path,
    record: &mut Journal,
    manager: &dyn Manager,
) -> Result<()> {
    ensure!(
        record.entries.len() <= 257,
        "adoption receipt exceeds registration limit"
    );
    ensure!(
        hash(&legacy::read_owned(
            &receipt.join("legacy-cli"),
            4 * 1024 * 1024
        )?) == record.cli_hash,
        "legacy CLI backup checksum mismatch"
    );
    for (index, entry) in record.entries.iter().enumerate() {
        ensure!(
            entry.source == receipt.join(format!("{index}.json"))
                && entry.legacy.unit
                    == layout
                        .units
                        .join(format!("{}.service", entry.legacy.service))
                && (entry.legacy.service == "porthub"
                    || entry.legacy.service.starts_with("porthub-"))
                && entry
                    .legacy
                    .service
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)),
            "invalid adoption registration paths"
        );
        ensure!(
            hash(&legacy::read_owned(&entry.legacy.unit, 65536)?) == entry.unit_hash,
            "legacy service changed since adoption"
        );
        ensure!(
            service::RegistrationProfile::load(&entry.source)?.identity() == entry.id,
            "adoption profile identity changed"
        );
    }
    let mut installed = Vec::new();
    for entry in &record.entries {
        if let Some(native) = service::installed(layout, &entry.id)? {
            ensure!(
                native.executable == record.executable,
                "native registration changed after adoption"
            );
            installed.push(entry);
        }
    }
    record.state = "rolling-back".into();
    journal(receipt, record)?;
    // Refuse to replace any CLI except the adopted release or the untouched
    // original. Native registration deletion retains its immutable release.
    if std::fs::symlink_metadata(&record.cli)?
        .file_type()
        .is_symlink()
    {
        ensure!(
            std::fs::read_link(&record.cli)? == record.executable,
            "shared CLI changed after adoption"
        );
        let staged = receipt.join("restore-cli");
        if staged.try_exists()? {
            ensure!(
                hash(&legacy::read_owned(&staged, 4 * 1024 * 1024)?) == record.cli_hash,
                "staged recovery CLI checksum mismatch"
            );
        } else {
            std::fs::hard_link(receipt.join("legacy-cli"), &staged)?;
        }
        std::fs::rename(staged, &record.cli)?;
        std::fs::File::open(
            record
                .cli
                .parent()
                .context("CLI needs a parent directory")?,
        )?
        .sync_all()?;
    } else {
        ensure!(
            hash(&legacy::read_owned(&record.cli, 4 * 1024 * 1024)?) == record.cli_hash,
            "shared CLI changed after adoption"
        );
    }
    for entry in installed {
        service::action(
            layout,
            &entry.source,
            Action::Uninstall { purge: true },
            manager,
        )
        .await?;
    }
    for entry in &record.entries {
        if entry.state.enabled {
            manager.enable(&entry.legacy).await?;
        } else {
            manager.disable(&entry.legacy).await?;
        }
        if entry.state.active {
            manager.reset_failed(&entry.legacy).await?;
            manager.start(&entry.legacy).await?;
        }
    }
    record.state = "rolled-back".into();
    journal(receipt, record)?;
    Ok(())
}
