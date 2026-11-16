use super::transaction::{self, Backend, Installed, Journal, Phase};
use crate::{
    control::Control,
    features::{self, Feature},
    profile::{self, Profile},
    service::{self, Layout, Manager, Spec},
    update::{self, Release, Request, Staged},
};
use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncReadExt,
    sync::{mpsc, watch},
};
use tokio_util::sync::CancellationToken;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}
fn record_path(source: &Path) -> PathBuf {
    profile::sibling(source, ".windows-update.json")
}
fn same_file(a: &Path, b: &Path) -> bool {
    a.canonicalize()
        .ok()
        .zip(b.canonicalize().ok())
        .is_some_and(|(a, b)| a == b)
}
fn permitted(source: &Path) -> bool {
    features::load(source).is_ok_and(|p| p.enabled(Feature::AutoUpdate))
}
fn expected_target() -> &'static str {
    env!("PORTHUB_RUST_TARGET")
}
fn pinned_release(layout: &Layout, path: &Path, expected: &str) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    ensure!(
        expected.len() == 64
            && expected.bytes().all(|b| b.is_ascii_hexdigit())
            && path == layout.releases.join(expected).join("porthub.exe"),
        "Release path is outside its pinned immutable directory"
    );
    let directory = std::fs::symlink_metadata(path.parent().context("Release parent missing")?)?;
    ensure!(
        directory.is_dir() && directory.file_attributes() & 0x400 == 0,
        "Release directory must not be a reparse point"
    );
    ensure!(
        super::verified_file::hash(path, &[expected])?.eq_ignore_ascii_case(expected),
        "Pinned update executable changed"
    );
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: u32,
    nonce: String,
    request: Request,
    created: u64,
    updated: u64,
    phase: Phase,
    previous: Spec,
    previous_manifest: Vec<u8>,
    previous_unit: Vec<u8>,
    profile_sha256: String,
    previous_sha256: String,
    release: Release,
    candidate: PathBuf,
    source_revision: String,
    rust_target: String,
    authorizer_pid: u32,
    attempts: u8,
    previous_cli: Option<super::shared_image::Cli>,
    publish_cli: bool,
    previous_version: String,
    previous_desktops: Vec<super::desktop::Desktop>,
}
impl Record {
    fn validate(&self, layout: &Layout, path: &Path) -> Result<()> {
        self.request.validate()?;
        ensure!(
            self.schema == 1
                && self.nonce.len() == 32
                && self.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid Windows update journal identity"
        );
        ensure!(
            self.previous.profile.parent() == Some(layout.state.as_path())
                && path == record_path(&self.previous.profile),
            "Update journal is outside its managed registration"
        );
        let public = Profile::load(&self.previous.profile)?;
        ensure!(
            self.previous.identity == service::identity(&public)
                && self.previous.service == format!("porthub-{}", &self.previous.identity[..24])
                && !self.previous.user,
            "Update registration binding changed"
        );
        ensure!(
            digest(&profile::read_private(&self.previous.profile)?) == self.profile_sha256,
            "Enrollment changed; automatic update/rollback refused"
        );
        ensure!(
            self.previous.profile
                == layout
                    .state
                    .join(format!("{}.json", self.previous.identity))
                && self.previous.unit
                    == layout.units.join(format!("{}.json", self.previous.service)),
            "Journal paths differ from owned native registration"
        );
        ensure!(
            self.previous_manifest.len() <= 8192 && self.previous_unit.len() <= 8192,
            "Previous registration snapshot exceeds bounds"
        );
        ensure!(
            serde_json::from_slice::<Spec>(&self.previous_manifest)? == self.previous,
            "Previous manifest snapshot mismatch"
        );
        if let Some(cli) = &self.previous_cli {
            ensure!(
                cli.path == crate::bootstrap::cli_path(false, None)?,
                "Shared CLI is outside its standard published path"
            );
            pinned_release(layout, &cli.image.executable, &cli.image.sha256)?;
            if self.phase != Phase::Prepared {
                let allowed = if self.publish_cli {
                    vec![cli.image.sha256.as_str(), self.release.sha256.as_str()]
                } else {
                    vec![cli.image.sha256.as_str()]
                };
                super::verified_file::hash(&cli.path, &allowed)?;
            }
        }
        ensure!(
            !self.publish_cli
                || self.previous.cli.as_ref() == self.previous_cli.as_ref().map(|c| &c.path),
            "Tenant has no authority to publish the shared CLI"
        );
        ensure!(
            self.previous_desktops.len() <= 8,
            "Desktop snapshot exceeds account bound"
        );
        for desktop in &self.previous_desktops {
            pinned_release(layout, &desktop.image.executable, &desktop.image.sha256)?;
        }
        ensure!(
            self.release.arch == std::env::consts::ARCH
                && self.release.asset == format!("porthub-{}.exe", update::native_target()?)
                && std::fs::metadata(&self.candidate)?.len() == self.release.size,
            "Journal native asset identity/size mismatch"
        );
        ensure!(
            self.release.version == self.request.target_version
                && self.release.target == update::native_target()?
                && self.release.os == "windows"
                && self.rust_target == expected_target(),
            "Update release target/version mismatch"
        );
        ensure!(
            self.candidate
                == layout
                    .releases
                    .join(&self.release.sha256)
                    .join("porthub.exe"),
            "Candidate path is not its immutable release"
        );
        ensure!(
            self.previous.executable
                == layout
                    .releases
                    .join(&self.previous_sha256)
                    .join("porthub.exe"),
            "Previous executable path mismatch"
        );
        ensure!(
            self.source_revision.len() == 40
                && self.source_revision.bytes().all(|b| b.is_ascii_hexdigit()),
            "Candidate source revision missing"
        );
        ensure!(
            self.previous_sha256 != self.release.sha256 && self.authorizer_pid > 0,
            "Invalid previous/candidate endpoints"
        );
        pinned_release(layout, &self.previous.executable, &self.previous_sha256)?;
        pinned_release(layout, &self.candidate, &self.release.sha256)?;
        Ok(())
    }
    fn load(layout: &Layout, path: &Path) -> Result<Self> {
        let bytes = profile::read_private(path)?;
        ensure!(bytes.len() <= 65536, "Update journal exceeds limit");
        let r: Self = serde_json::from_slice(&bytes)?;
        r.validate(layout, path)?;
        Ok(r)
    }
}
struct Durable {
    path: PathBuf,
    record: Record,
}
impl Journal for Durable {
    fn phase(&self) -> Phase {
        self.record.phase
    }
    fn persist(&mut self, phase: Phase) -> Result<()> {
        let mut next = self.record.clone();
        next.phase = phase;
        next.updated = now();
        profile::write_private(&self.path, &serde_json::to_vec(&next)?, true)?;
        self.record = next;
        Ok(())
    }
}
#[derive(Clone)]
struct Native {
    layout: Layout,
    source: PathBuf,
    public: Profile,
    spec: Spec,
}
impl Native {
    async fn inspect(source: &Path, public: &Profile) -> Result<Option<Self>> {
        let Some(layout) = crate::private_profile::windows_service_layout(source, public)? else {
            return Ok(None);
        };
        let spec = service::installed(&layout, &service::identity(public))?
            .context("Installed public registration missing")?;
        ensure!(
            same_file(&spec.executable, &std::env::current_exe()?),
            "Updater is not the immutable SCM image"
        );
        service::publication::owned_target(&layout, &spec.executable)?;
        ensure!(
            image_path(std::process::id()).is_some_and(|p| same_file(&p, &spec.executable)),
            "Actual native process image mismatch"
        );
        ensure!(
            Profile::load(source)?.token == public.token,
            "Updater enrollment changed"
        );
        if let Some(cli) = &spec.cli {
            ensure!(
                *cli == crate::bootstrap::cli_path(false, None)?,
                "Automatic updates require the standard managed CLI destination"
            );
            let hash = service::publication::hash_file(cli)?;
            service::publication::owned_target(
                &layout,
                &layout.releases.join(hash).join("porthub.exe"),
            )?;
        }
        Ok(Some(Self {
            layout,
            source: source.into(),
            public: public.clone(),
            spec,
        }))
    }
    fn committed(&self, request: &Request) -> bool {
        let Ok(r) = Record::load(&self.layout, &record_path(&self.source)) else {
            return false;
        };
        transaction::can_ack(
            r.phase,
            transaction::CommitIdentity {
                request: &r.request,
                version: &r.release.version,
                source: &r.source_revision,
            },
            transaction::CommitIdentity {
                request,
                version: crate::VERSION,
                source: crate::BUILD_REVISION,
            },
        ) && same_file(&r.candidate, &self.spec.executable)
    }
}
fn image_path(pid: u32) -> Option<PathBuf> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        },
    };
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0u16; 32768];
        let mut size = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        Some(PathBuf::from(
            String::from_utf16(&buffer[..size as usize]).ok()?,
        ))
    }
}
async fn ready(
    layout: &Layout,
    source: &Path,
    expected: &Path,
    version: Option<&str>,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let id = service::identity(&Profile::load(source)?);
            if let Some(spec) = service::installed(layout, &id)? {
                if same_file(&spec.executable, expected) {
                    if let Ok(status) = crate::runtime::status(source) {
                        if status.state == "running"
                            && version.is_none_or(|v| status.agent_version == v)
                            && status.updated_at <= now()
                            && now().saturating_sub(status.updated_at) <= 90
                            && (status.route != "private"
                                || status
                                    .private_status
                                    .as_ref()
                                    .is_none_or(|p| p.dns_verified != Some(false)))
                            && image_path(status.pid).is_some_and(|p| same_file(&p, expected))
                            && service::windows::Windows::owns_process(&spec, status.pid)?
                        {
                            return Ok(());
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .context("Windows native runtime readiness timed out")?
}
async fn image_version(layout: &Layout, path: &Path) -> Result<super::shared_image::Image> {
    service::publication::owned_target(layout, path)?;
    let sha256 = service::publication::hash_file(path)?;
    let check = async {
        let mut child = tokio::process::Command::new(path)
            .arg("version")
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("Shared image version unavailable")?
            .take(4097)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 4096 && child.wait().await?.success(),
            "Shared image version probe failed"
        );
        let text = std::str::from_utf8(&bytes)?.trim();
        let version = text
            .strip_prefix("porthub ")
            .context("Unknown shared executable version")?;
        ensure!(
            porthub_components::release_version::compare(version, version).is_some(),
            "Unversioned shared executable preserved"
        );
        Ok(super::shared_image::Image {
            executable: path.into(),
            sha256,
            version: version.into(),
        })
    };
    tokio::time::timeout(Duration::from_secs(5), check)
        .await
        .context("Shared image version probe timed out")?
}
async fn capture_cli(
    layout: &Layout,
    owned: Option<&Path>,
) -> Result<Option<super::shared_image::Cli>> {
    let path = crate::bootstrap::cli_path(false, None)?;
    if let Some(owned) = owned {
        ensure!(owned == path, "Nonstandard CLI destination preserved");
    }
    if !path.try_exists()? {
        ensure!(owned.is_none(), "Owned shared CLI disappeared");
        return Ok(None);
    }
    let hash = service::publication::hash_file(&path)?;
    let image = image_version(layout, &layout.releases.join(&hash).join("porthub.exe")).await?;
    ensure!(
        service::publication::hash_file(&path)? == hash,
        "Shared CLI changed while selecting maintenance scope"
    );
    Ok(Some(super::shared_image::Cli { path, image }))
}
async fn capture_desktops(layout: &Layout, source: &Path) -> Result<Vec<super::desktop::Desktop>> {
    let mut result = vec![];
    for (sid, paths) in super::desktop::paths(layout, source).await? {
        let mut best: Option<super::shared_image::Image> = None;
        for path in paths {
            // Custom/unowned actions remain the strict refresher's responsibility;
            // never execute them merely to ask their version.
            if service::publication::owned_target(layout, &path).is_err() {
                continue;
            }
            let image = image_version(layout, &path).await?;
            best = Some(match best {
                None => image,
                Some(old) => super::shared_image::higher(&old, &image)?.clone(),
            });
        }
        if let Some(image) = best {
            result.push(super::desktop::Desktop { sid, image });
        }
    }
    Ok(result)
}
struct Actual {
    layout: Layout,
    record: Record,
}
impl Actual {
    async fn manager(
        &self,
        rollback: bool,
    ) -> Result<super::desktop_manager::DesktopManager<service::windows::Windows>> {
        let mut image = super::shared_image::Image {
            executable: if rollback {
                self.record.previous.executable.clone()
            } else {
                self.record.candidate.clone()
            },
            sha256: if rollback {
                self.record.previous_sha256.clone()
            } else {
                self.record.release.sha256.clone()
            },
            version: if rollback {
                self.record.previous_version.clone()
            } else {
                self.record.release.version.clone()
            },
        };
        if let Some(cli) = &self.record.previous_cli {
            image = super::shared_image::higher(&image, &cli.image)?.clone();
        }
        for desktop in &self.record.previous_desktops {
            image = super::shared_image::higher(&image, &desktop.image)?.clone();
        }
        // Preserve a still higher image introduced by an operator since capture;
        // our own candidate is allowed to roll back to its pinned predecessors.
        for current in capture_desktops(&self.layout, &self.record.previous.profile).await? {
            if !rollback || current.image.sha256 != self.record.release.sha256 {
                image = super::shared_image::higher(&image, &current.image)?.clone();
            }
        }
        service::publication::owned_target(&self.layout, &image.executable)?;
        Ok(super::desktop_manager::DesktopManager {
            inner: service::windows::Windows,
            target: image.executable,
        })
    }
}
#[async_trait]
impl Backend for Actual {
    async fn installed(&self) -> Result<Installed> {
        self.record
            .validate(&self.layout, &record_path(&self.record.previous.profile))?;
        if let Some(cli) = &self.record.previous_cli {
            let expected = if self.record.publish_cli {
                vec![
                    cli.image.sha256.as_str(),
                    self.record.release.sha256.as_str(),
                ]
            } else {
                vec![cli.image.sha256.as_str()]
            };
            super::verified_file::hash(&cli.path, &expected)?;
        }
        let Some(spec) = service::installed(&self.layout, &self.record.previous.identity)? else {
            return Ok(Installed::Foreign);
        };
        if spec == self.record.previous {
            return Ok(Installed::Previous);
        };
        let mut expected = self.record.previous.clone();
        expected.executable = self.record.candidate.clone();
        Ok(if spec == expected {
            Installed::Candidate
        } else {
            Installed::Foreign
        })
    }
    fn permitted(&self) -> bool {
        permitted(&self.record.previous.profile)
    }
    async fn install_candidate(&self) -> Result<()> {
        ensure!(
            self.permitted(),
            "Automatic updates disabled before service transaction"
        );
        let manager = self.manager(false).await?;
        self.record
            .validate(&self.layout, &record_path(&self.record.previous.profile))?;
        service::publication::owned_target(&self.layout, &self.record.candidate)?;
        ensure!(
            self.permitted(),
            "Automatic updates revoked during final executable/desktop verification"
        );
        service::install_locked(
            &self.layout,
            &self.record.previous.profile,
            &self.record.candidate,
            &manager,
            if self.record.publish_cli {
                self.record.previous.cli.as_deref()
            } else {
                None
            },
        )
        .await?;
        Ok(())
    }
    async fn ready_candidate(&self) -> Result<()> {
        ready(
            &self.layout,
            &self.record.previous.profile,
            &self.record.candidate,
            Some(&self.record.release.version),
        )
        .await
    }
    async fn restore_previous(&self) -> Result<()> {
        // Rollback needs no AutoUpdate permission: it restores only the same
        // enrollment and two previously verified service/CLI endpoints.
        service::publication::owned_target(&self.layout, &self.record.previous.executable)?;
        if let Some(cli) = &self.record.previous_cli {
            super::verified_file::hash(
                &cli.path,
                &[
                    cli.image.sha256.as_str(),
                    self.record.release.sha256.as_str(),
                ],
            )?;
            let mut publication = service::publication::Publication::prepare(
                &self.layout,
                &cli.path,
                &cli.image.executable,
            )?;
            publication.commit();
        }
        service::install_locked(
            &self.layout,
            &self.record.previous.profile,
            &self.record.previous.executable,
            &self.manager(true).await?,
            None,
        )
        .await?;
        Ok(())
    }
    async fn ready_previous(&self) -> Result<()> {
        ready(
            &self.layout,
            &self.record.previous.profile,
            &self.record.previous.executable,
            None,
        )
        .await
    }
}
/// Align interrupted publication metadata to the actual journal-owned SCM
/// endpoint. Unknown bytes or another CLI publication are never overwritten.
async fn reconcile(layout: &Layout, record: &Record) -> Result<()> {
    record.validate(layout, &record_path(&record.previous.profile))?;
    let mut candidate = record.previous.clone();
    candidate.executable = record.candidate.clone();
    let manifest = layout
        .state
        .join(format!("{}.service.json", record.previous.identity));
    let current_manifest = profile::read_private(&manifest)?;
    let current_unit = profile::read_private(&record.previous.unit)?;
    let new_manifest = serde_json::to_vec_pretty(&candidate)?;
    let new_unit = service::unit(&candidate)?.into_bytes();
    ensure!(
        transaction::known_snapshot(&current_manifest, &record.previous_manifest, &new_manifest)
            && transaction::known_snapshot(&current_unit, &record.previous_unit, &new_unit),
        "Operator registration edits preserved; automatic reconciliation refused"
    );
    let manager = service::windows::Windows;
    let old = manager
        .state(&record.previous)
        .await
        .ok()
        .filter(|s| s.installed);
    let new = manager.state(&candidate).await.ok().filter(|s| s.installed);
    let (actual, state) = match (old, new) {
        (Some(state), None) => (&record.previous, state),
        (None, Some(state)) => (&candidate, state),
        _ => anyhow::bail!("SCM endpoint differs from both pinned update images"),
    };
    ensure!(
        state.enabled,
        "Operator disabled native service; automatic recovery refused"
    );
    let actual_manifest = if actual == &record.previous {
        &record.previous_manifest
    } else {
        &new_manifest
    };
    let actual_unit = if actual == &record.previous {
        &record.previous_unit
    } else {
        &new_unit
    };
    // Existing trust/publication primitives keep files atomic and ACLs protected.
    if current_manifest != *actual_manifest {
        profile::write_private(&manifest, actual_manifest, true)?;
    }
    if current_unit != *actual_unit {
        profile::write_private(&record.previous.unit, actual_unit, true)?;
    }
    if let Some(cli) = &record.previous_cli {
        let wanted = if super::shared_image::reconcile_candidate(
            record.phase,
            actual == &candidate,
            record.publish_cli,
        ) {
            &record.candidate
        } else {
            &cli.image.executable
        };
        let expected = service::publication::hash_file(wanted)?;
        if super::verified_file::hash(
            &cli.path,
            &[cli.image.sha256.as_str(), record.release.sha256.as_str()],
        )? != expected
        {
            let mut publication =
                service::publication::Publication::prepare(layout, &cli.path, wanted)?;
            publication.commit();
        }
    }
    if !state.active {
        service::publication::owned_target(layout, &actual.executable)?;
        manager.start(actual).await?;
    }
    Ok(())
}
fn startup_snapshots(layout: &Layout, record: &Record) -> Result<super::recovery_wait::Snapshot> {
    use super::recovery_wait::Snapshot;
    let mut candidate = record.previous.clone();
    candidate.executable = record.candidate.clone();
    let wanted = [
        (
            layout
                .state
                .join(format!("{}.service.json", record.previous.identity)),
            &record.previous_manifest,
            serde_json::to_vec_pretty(&candidate)?,
        ),
        (
            record.previous.unit.clone(),
            &record.previous_unit,
            service::unit(&candidate)?.into_bytes(),
        ),
    ];
    for (path, old, new) in wanted {
        match profile::read_private(&path) {
            Ok(bytes) => {
                if !transaction::known_snapshot(&bytes, old, &new) {
                    return Ok(Snapshot::Foreign);
                }
            }
            Err(error) => {
                if error.downcast_ref::<std::io::Error>().is_some_and(|e| {
                    matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::Interrupted
                    ) || matches!(e.raw_os_error(), Some(32 | 33))
                }) {
                    return Ok(Snapshot::Transient);
                }
                return Err(error);
            }
        }
    }
    Ok(Snapshot::Known)
}
/// A protected unfinished record may survive reboot with its manifest ahead of
/// SCM. Prove the REAL starting SCM process against either endpoint before
/// launching the same trusted staged worker; no manifest-only authorization.
pub(crate) async fn service_start_recovery(source: &Path) -> Result<()> {
    let layout = Layout::system()?;
    let path = record_path(source);
    if !path.try_exists()? {
        return Ok(());
    }
    let record = Record::load(&layout, &path)?;
    if record.phase.terminal() {
        return Ok(());
    }
    let mut candidate = record.previous.clone();
    candidate.executable = record.candidate.clone();
    let current = std::env::current_exe()?;
    let spec = if same_file(&current, &record.previous.executable) {
        &record.previous
    } else if same_file(&current, &record.candidate) {
        &candidate
    } else {
        anyhow::bail!("Starting service is outside journal update endpoints")
    };
    ensure!(
        image_path(std::process::id()).is_some_and(|p| same_file(&p, &spec.executable))
            && service::windows::Windows::owns_process(spec, std::process::id())?,
        "Update recovery requires the actual registered SCM process"
    );
    if let Ok(lease) = profile::Lease::acquire(&profile::sibling(&path, ".worker")) {
        drop(lease);
        spawn_worker(&record, &path).await?;
    }
    // A crash can leave the manifest ahead of SCM. Let reconciliation align it
    // before runtime constructs its SCM-authorized Controller. Do not wait for
    // candidate readiness here: the worker needs this runtime to start first.
    super::recovery_wait::wait(
        || startup_snapshots(&layout, &record),
        || {
            Ok(service::installed(&layout, &record.previous.identity)?
                .is_some_and(|s| same_file(&s.executable, &current)))
        },
        Duration::from_secs(10),
    )
    .await
}
/// Runs only from a verified staged executable, independently of the SCM process
/// it will replace. The durable per-registration lease prevents concurrent work.
pub(super) async fn maintenance(path: &Path) -> Result<()> {
    service::require_administrator()?;
    let layout = Layout::system()?;
    Record::load(&layout, path)?; // Validate the managed path before creating its lease.
    let _lease = profile::Lease::acquire(&profile::sibling(path, ".worker"))?;
    let _installation = service::lock(&layout)?;
    let mut record = Record::load(&layout, path)?;
    let _enrollment = super::enrollment_guard::EnrollmentGuard::acquire(
        &record.previous.profile,
        &record.profile_sha256,
    )?;
    record.validate(&layout, path)?;
    ensure!(
        same_file(&record.candidate, &std::env::current_exe()?)
            && record.release.version == crate::VERSION
            && record.source_revision == crate::BUILD_REVISION,
        "Maintenance worker provenance differs from staged core"
    );
    let staged = Staged {
        release: record.release.clone(),
        executable: record.candidate.clone(),
    };
    staged.verify_executable(&CancellationToken::new()).await?;
    if record.phase == Phase::Prepared
        && (now().saturating_sub(record.created) > 600
            || !service::windows::Windows::owns_process(&record.previous, record.authorizer_pid)
                .unwrap_or(false))
    {
        let mut expired = Durable {
            path: path.into(),
            record,
        };
        expired.persist(Phase::Cancelled)?;
        return Ok(());
    }
    if record.phase == Phase::Prepared {
        let cli = capture_cli(&layout, record.previous.cli.as_deref()).await?;
        ensure!(
            record.previous_cli.is_none() || cli.is_some(),
            "Shared CLI disappeared during staging; preserved"
        );
        if let (Some(before), Some(after)) = (&record.previous_cli, &cli) {
            ensure!(
                super::shared_image::higher(&before.image, &after.image)?.sha256
                    == after.image.sha256,
                "Shared CLI was intentionally downgraded during staging; preserved"
            );
        }
        let image = super::shared_image::Image {
            executable: record.candidate.clone(),
            sha256: record.release.sha256.clone(),
            version: record.release.version.clone(),
        };
        record.publish_cli = super::shared_image::publish_candidate(
            record.previous.cli.is_some(),
            cli.as_ref().map(|c| &c.image),
            &image,
        )?;
        record.previous_cli = cli;
        record.previous_desktops = capture_desktops(&layout, &record.previous.profile).await?;
        profile::write_private(path, &serde_json::to_vec(&record)?, true)?;
    }
    if !record.phase.terminal() {
        reconcile(&layout, &record).await?;
    }
    let actual = Actual {
        layout,
        record: record.clone(),
    };
    let mut journal = Durable {
        path: path.into(),
        record,
    };
    // A service transaction must settle even if the old service exits. No parent
    // lifetime cancellation or kill-on-drop can interrupt the replacement here.
    transaction::execute(&actual, &mut journal).await
}
async fn provenance(staged: &Staged, cancel: &CancellationToken) -> Result<String> {
    staged.verify_executable(cancel).await?;
    let mut command = tokio::process::Command::new(&staged.executable);
    command
        .args(["version", "--verbose"])
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let probe = async {
        let mut child = command.spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("Version output missing")?
            .take(4097)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 4096 && child.wait().await?.success(),
            "Version provenance probe failed"
        );
        let text = std::str::from_utf8(&bytes)?;
        transaction::parse_provenance(text, &staged.release.version, expected_target())
    };
    tokio::select! {_=cancel.cancelled()=>anyhow::bail!("Version probe cancelled"),r=tokio::time::timeout(Duration::from_secs(8),probe)=>r.context("Version provenance probe timed out")?}
}
async fn spawn_worker(record: &Record, path: &Path) -> Result<()> {
    // Cached validation is never sufficient immediately before execution.
    service::publication::owned_target(&Layout::system()?, &record.candidate)?;
    // Worker is short-lived and must survive the old service's normal shutdown.
    let child = tokio::process::Command::new(&record.candidate)
        .arg("__windows-update")
        .arg("--record")
        .arg(path)
        .creation_flags(0x08000200)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(false)
        .spawn()?;
    drop(child);
    Ok(())
}
async fn prepare(native: &Native, request: &Request, cancel: &CancellationToken) -> Result<()> {
    ensure!(permitted(&native.source), "Automatic updates disabled");
    request.validate()?;
    let _lease =
        profile::Lease::acquire(&profile::sibling(&record_path(&native.source), ".worker"))?;
    let path = record_path(&native.source);
    let mut attempts = 0;
    if path.try_exists()? {
        let old = Record::load(&native.layout, &path)?;
        if !old.phase.terminal() {
            drop(_lease);
            return spawn_worker(&old, &path).await;
        }
        if old.request == *request && old.phase == Phase::Committed {
            return Ok(());
        }
        if old.request == *request {
            ensure!(
                now().saturating_sub(old.updated) >= transaction::retry_seconds(old.attempts),
                "Previous automatic attempt is cooling down"
            );
            attempts = old.attempts.saturating_add(1);
        }
    }
    let control = Control::new(native.public.clone())?;
    let mut release = update::discover(&control, update::native_target()?, cancel).await?;
    release.sha256.make_ascii_lowercase();
    ensure!(
        release.version == request.target_version
            && transaction::target_allowed(crate::VERSION, &release.version),
        "Published release differs from requested newer core"
    );
    let staged = update::stage(&control, &release, &native.layout.releases, cancel).await?;
    let revision = provenance(&staged, cancel).await?;
    let capability = async {
        let mut child = tokio::process::Command::new(&staged.executable)
            .arg("__windows-update-protocol")
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let mut bytes = Vec::new();
        child
            .stdout
            .take()
            .context("Maintenance protocol output missing")?
            .take(129)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(
            bytes.len() <= 128
                && child.wait().await?.success()
                && std::str::from_utf8(&bytes).is_ok_and(|text| text.trim() == super::PROTOCOL),
            "Published core has no compatible Windows maintenance protocol"
        );
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {_=cancel.cancelled()=>anyhow::bail!("Maintenance capability probe cancelled"),r=tokio::time::timeout(Duration::from_secs(5),capability)=>r.context("Maintenance capability probe timed out")??}
    ensure!(
        permitted(&native.source) && !cancel.is_cancelled(),
        "Update preparation revoked"
    );
    // Staging may take minutes. Re-authorize the actual old service and the
    // exact credentials immediately before creating a maintenance capability.
    let profile_bytes = profile::read_private(&native.source)?;
    let mut latest: Profile = serde_json::from_slice(&profile_bytes)?;
    latest.validate()?;
    ensure!(
        latest.server == native.public.server
            && latest.machine_id == native.public.machine_id
            && latest.token == native.public.token,
        "Enrollment changed during update preparation"
    );
    ensure!(
        service::installed(&native.layout, &native.spec.identity)?.as_ref() == Some(&native.spec)
            && service::windows::Windows::owns_process(&native.spec, std::process::id())?
            && image_path(std::process::id())
                .is_some_and(|p| same_file(&p, &native.spec.executable)),
        "Authorizing SCM process changed during staging"
    );
    let previous_cli = capture_cli(&native.layout, native.spec.cli.as_deref()).await?;
    let previous_desktops = capture_desktops(&native.layout, &native.source).await?;
    let candidate_image = super::shared_image::Image {
        executable: staged.executable.clone(),
        sha256: release.sha256.clone(),
        version: release.version.clone(),
    };
    let publish_cli = super::shared_image::publish_candidate(
        native.spec.cli.is_some(),
        previous_cli.as_ref().map(|c| &c.image),
        &candidate_image,
    )?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("Update nonce unavailable"))?;
    let record = Record {
        schema: 1,
        nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
        request: request.clone(),
        created: now(),
        updated: now(),
        phase: Phase::Prepared,
        previous: native.spec.clone(),
        previous_manifest: profile::read_private(
            &native
                .layout
                .state
                .join(format!("{}.service.json", native.spec.identity)),
        )?,
        previous_unit: profile::read_private(&native.spec.unit)?,
        profile_sha256: digest(&profile_bytes),
        previous_sha256: service::publication::hash_file(&native.spec.executable)?,
        release,
        candidate: staged.executable,
        source_revision: revision,
        rust_target: expected_target().into(),
        authorizer_pid: std::process::id(),
        attempts,
        previous_cli,
        publish_cli,
        previous_version: crate::VERSION.into(),
        previous_desktops,
    };
    record.validate(&native.layout, &path)?;
    profile::write_private(&path, &serde_json::to_vec(&record)?, true)?;
    drop(_lease);
    spawn_worker(&record, &path).await
}
pub(crate) struct Controller {
    native: Native,
    current: Option<Request>,
    settings: watch::Sender<Option<Request>>,
    events: mpsc::Receiver<()>,
    stop: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Controller {
    pub async fn new(source: &Path, public: &Profile) -> Result<Option<Self>> {
        let Some(native) = Native::inspect(source, public).await? else {
            return Ok(None);
        };
        let (settings, receiver) = watch::channel(None);
        let (sender, events) = mpsc::channel(1);
        let stop = CancellationToken::new();
        let task = tokio::spawn(run(native.clone(), receiver, sender, stop.clone()));
        Ok(Some(Self {
            native,
            current: None,
            settings,
            events,
            stop,
            task,
        }))
    }
    pub fn request(&mut self, request: Option<Request>) {
        if self.current != request {
            self.settings.send_replace(request.clone());
            self.current = request;
        }
    }
    pub fn handled(&self) -> String {
        self.current
            .as_ref()
            .filter(|r| self.native.committed(r))
            .map(|r| r.id.clone())
            .unwrap_or_default()
    }
    pub async fn next(&mut self) -> Option<()> {
        self.events.recv().await
    }
    pub async fn stop(&mut self) {
        self.stop.cancel();
        if tokio::time::timeout(Duration::from_secs(3), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}
async fn run(
    native: Native,
    mut settings: watch::Receiver<Option<Request>>,
    events: mpsc::Sender<()>,
    stop: CancellationToken,
) {
    let mut policy = features::subscribe(&native.source);
    let mut delay = Duration::from_secs(30);
    let mut auto = permitted(&native.source);
    loop {
        let requested = settings.borrow_and_update().clone();
        let path = record_path(&native.source);
        // Recovery is authorized by the existing protected journal, not a fresh
        // server request. It must also finish rollback after AutoUpdate is off.
        let interrupted = path.try_exists().unwrap_or(false)
            && Record::load(&native.layout, &path).is_ok_and(|r| !r.phase.terminal());
        if interrupted {
            if let Ok(record) = Record::load(&native.layout, &path) {
                if let Ok(lease) = profile::Lease::acquire(&profile::sibling(&path, ".worker")) {
                    drop(lease);
                    let _ = spawn_worker(&record, &path).await;
                }
            }
        } else if let Some(request) = requested.as_ref().filter(|r| {
            transaction::target_allowed(crate::VERSION, &r.target_version)
                && permitted(&native.source)
        }) {
            let cancel = stop.child_token();
            let attempt = prepare(&native, request, &cancel);
            match super::preparation::guarded(
                attempt,
                &stop,
                &cancel,
                &mut settings,
                &mut policy,
                |p| p.enabled(Feature::AutoUpdate),
                &mut auto,
            )
            .await
            {
                super::preparation::Awaited::Stopped => return,
                super::preparation::Awaited::Changed => {
                    delay = Duration::from_secs(30);
                    continue;
                }
                super::preparation::Awaited::Finished(result) => {
                    if result.is_err() {
                        tracing::warn!(
                            "Windows core update preparation pending; retrying with backoff"
                        );
                    }
                }
            }
        }
        if requested.as_ref().is_some_and(|r| native.committed(r)) {
            let _ = events.try_send(());
        }
        let wait_cancel = stop.child_token();
        match super::preparation::guarded(
            tokio::time::sleep(delay),
            &stop,
            &wait_cancel,
            &mut settings,
            &mut policy,
            |p| p.enabled(Feature::AutoUpdate),
            &mut auto,
        )
        .await
        {
            super::preparation::Awaited::Stopped => return,
            super::preparation::Awaited::Changed => delay = Duration::from_secs(30),
            super::preparation::Awaited::Finished(()) => {
                delay = (delay * 2).min(Duration::from_secs(900))
            }
        }
    }
}
