//! PRIVATE full authenticated PHV1 destination; no production enrollment/service.
//! Source is the exact generated Linux fixture, never a physical camera.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::json;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::io::BufReader;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
const ENV: &str = "PORTHUB_WINDOWS_VIDEO_DESTINATION_SPEC";
const AUTH: &str = "root-reviewed-generated-windows-video-destination-v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: PathBuf,
    profile: PathBuf,
    source_machine: String,
    destination_machine: String,
    source_id: String,
    source_uid: u32,
    expected_direct_peer: IpAddr,
    lifetime_seconds: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedPlan {
    id: String,
    source: String,
    destination: String,
    source_id: String,
    mode: String,
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn private(path: &Path, directory: bool) -> Result<()> {
    super::windows_fixture_security::private(path, directory)
}
fn copy_private_acl(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW},
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        },
    };
    private(source, false)?;
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut descriptor = std::ptr::null_mut();
    let mut dacl = std::ptr::null_mut();
    let mut owner = std::ptr::null_mut();
    ensure!(
        unsafe {
            GetNamedSecurityInfoW(
                source.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut descriptor,
            )
        } == 0,
        "Cannot read private fixture DACL"
    );
    struct Free(*mut core::ffi::c_void);
    impl Drop for Free {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _owned = Free(descriptor);
    ensure!(
        !dacl.is_null()
            && !owner.is_null()
            && unsafe {
                SetNamedSecurityInfoW(
                    destination.as_mut_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION
                        | OWNER_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    owner,
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null_mut(),
                )
            } == 0,
        "Cannot protect private runtime DACL"
    );
    Ok(())
}
impl Config {
    fn validate(&self) -> Result<()> {
        let name = self
            .root
            .file_name()
            .and_then(|v| v.to_str())
            .context("Private destination root required")?;
        let suffix = name
            .strip_prefix("porthub-windows-video-destination-")
            .context("Wrong private destination namespace")?;
        ensure!(
            hex(suffix, 32)
                && self.root.parent() == Some(std::env::temp_dir().as_path())
                && self.profile == self.root.join("input-profile.json"),
            "Only private temporary destination profile allowed"
        );
        ensure!(
            hex(&self.source_machine, 24)
                && hex(&self.destination_machine, 24)
                && self.source_machine != self.destination_machine
                && self
                    .source_id
                    .strip_prefix("media:")
                    .is_some_and(|s| hex(s, 64))
                && self.source_uid > 0,
            "Exact generated Linux source/destination required"
        );
        ensure!(
            (1..=180).contains(&self.lifetime_seconds)
                && matches!(self.expected_direct_peer,IpAddr::V4(ip)if ip.is_private()&&!ip.is_loopback()),
            "Bounded exact LAN destination fixture required"
        );
        Ok(())
    }
    fn load() -> Result<Self> {
        ensure!(
            std::env::var("PORTHUB_WINDOWS_VIDEO_DESTINATION_AUTHORIZED").as_deref() == Ok(AUTH),
            "Explicit private generated destination authorization required"
        );
        let path =
            PathBuf::from(std::env::var_os(ENV).context("Private destination spec required")?);
        private(&path, false)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(metadata.len() <= 8192, "Destination spec exceeds bound");
        let c: Self = serde_json::from_slice(&crate::profile::read_private(&path)?)?;
        c.validate()?;
        ensure!(
            path.parent() == Some(c.root.as_path()),
            "Spec outside private root"
        );
        private(&c.root, true)?;
        private(&c.profile, false)?;
        ensure!(
            std::env::var_os("PORTHUB_STATE_DIR").map(PathBuf::from)
                == Some(c.root.join("desktop-state")),
            "Destination policy must be fixture-local"
        );
        let marker = c.root.join("allow-generated-destination");
        private(&marker, false)?;
        ensure!(
            crate::profile::read_private(&marker)?
                == b"root-approved-generated-windows-video-destination-v1\n",
            "Private destination approval missing"
        );
        c.input_profile()?;
        Ok(c)
    }
    fn input_profile(&self) -> Result<crate::profile::Profile> {
        let p = crate::profile::Profile::load(&self.profile)?;
        let u = url::Url::parse(&p.server)?;
        ensure!(
            p.machine_id == self.destination_machine
                && p.allow_insecure_http_for_tests
                && p.fallback_servers.is_empty()
                && u.scheme() == "http"
                && u.host_str() == Some("127.0.0.1")
                && u.port().is_some()
                && u.path() == "/",
            "Only exact private loopback gateway profile allowed"
        );
        Ok(p)
    }
    fn layout(&self) -> crate::service::Layout {
        crate::service::Layout {
            user: false,
            state: self.root.join("native"),
            releases: self.root.join("releases"),
            units: self.root.join("units"),
        }
    }
    fn runtime_profile(&self) -> Result<PathBuf> {
        Ok(self.layout().state.join(format!(
            "{}.json",
            crate::service::identity(&self.input_profile()?)
        )))
    }
    fn verify_profile(&self, path: &Path) -> Result<()> {
        ensure!(
            path == self.runtime_profile()?,
            "Wrong destination runtime profile"
        );
        private(path, false)?;
        let actual = crate::profile::Profile::load(path)?;
        let expected = self.input_profile()?;
        ensure!(
            actual.machine_id == expected.machine_id
                && actual.server == expected.server
                && actual.token == expected.token
                && actual.fallback_servers.is_empty(),
            "Destination credentials/profile changed"
        );
        Ok(())
    }
    fn approved(&self) -> Result<Option<ApprovedPlan>> {
        let path = self.root.join("expected-plan.json");
        if !path.try_exists()? {
            return Ok(None);
        }
        private(&path, false)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(metadata.len() <= 2048, "Private plan marker exceeds bound");
        let plan: ApprovedPlan = serde_json::from_slice(&crate::profile::read_private(&path)?)?;
        ensure!(
            hex(&plan.id, 32)
                && plan.source == self.source_machine
                && plan.destination == self.destination_machine
                && plan.source_id == self.source_id
                && plan.mode == "phv1-camera-mjpeg-v1",
            "Unexpected private API plan marker"
        );
        Ok(Some(plan))
    }
    fn verify_known(
        &self,
        plan: &porthub_components::media_forward::Plan,
        source: bool,
    ) -> Result<()> {
        ensure!(
            !source
                && plan.valid()
                && !plan.persistent
                && plan.kind() == Some(porthub_components::media::Kind::Camera)
                && plan.source == self.source_machine
                && plan.destination == self.destination_machine
                && plan.source_id == self.source_id
                && plan.desktop_uid == self.source_uid
                && plan.desktop_session.is_none()
                && plan.identity.vendor == 0x1209
                && plan.identity.product == 1
                && plan.format() == Some(porthub_components::media::VideoFormat::baseline_mjpeg()),
            "Destination refuses other source, purpose, format or plan"
        );
        Ok(())
    }
}
/// Never compiled into a production executable. No environment-only bypass:
/// every capability report revalidates the account-owned private spec/credentials.
pub(crate) fn available_for_fixture() -> bool {
    std::env::var_os(ENV).is_some() && Config::load().is_ok()
}
async fn wait_approved_plan(
    mut read: impl FnMut() -> Result<Option<ApprovedPlan>>,
    id: &str,
    cancel: &CancellationToken,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5),async {loop {if let Some(expected)=read()?{ensure!(expected.id==id,"Plan differs from exact authenticated API result");return Ok::<_,anyhow::Error>(())}tokio::select!{_=cancel.cancelled()=>anyhow::bail!("Private destination cancelled before plan approval"),_=tokio::time::sleep(Duration::from_millis(25))=>{}}}}).await.context("Private API plan approval deadline")??;
    Ok(())
}
pub(crate) async fn verify_plan(
    profile: &Path,
    plan: &porthub_components::media_forward::Plan,
    source: bool,
    cancel: &CancellationToken,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    c.verify_profile(profile)?;
    c.verify_known(plan, source)?;
    wait_approved_plan(|| c.approved(), &plan.id, cancel).await?;
    crate::profile::write_private(
        &c.root.join("plan-verified.json"),
        &serde_json::to_vec(
            &json!({"id":plan.id,"source_id":plan.source_id,"source":plan.source,"destination":plan.destination,"kind":"camera","generated_only":true}),
        )?,
        true,
    )?;
    Ok(())
}
pub(crate) fn verify_carrier(
    stream: Option<&tokio_rustls::TlsStream<tokio::net::TcpStream>>,
    profile: &crate::profile::Profile,
    id: &str,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    let input = c.input_profile()?;
    ensure!(
        profile.machine_id == input.machine_id && profile.token == input.token,
        "Wrong private destination profile"
    );
    let expected = c.approved()?.context("Exact API plan not approved")?;
    ensure!(expected.id == id, "Wrong private carrier plan");
    let socket = stream
        .context("Private destination refuses relay/SCTP media fallback")?
        .get_ref()
        .0;
    ensure!(
        socket.peer_addr()?.ip() == c.expected_direct_peer,
        "TLS peer is not exact generated source LAN machine"
    );
    crate::profile::write_private(
        &c.root.join("direct-carrier.json"),
        &serde_json::to_vec(
            &json!({"transport":"authenticated-direct-tls","local":socket.local_addr()?.ip().to_string(),"peer":socket.peer_addr()?.ip().to_string(),"id":id,"before_attach":true,"generated_only":true}),
        )?,
        true,
    )?;
    Ok(())
}
pub(crate) fn authorize_attachment(
    profile: &Path,
    plan: &porthub_components::media_forward::Plan,
    slot: u16,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    c.verify_profile(profile)?;
    c.verify_known(plan, false)?;
    ensure!(
        slot > 0 && c.approved()?.is_some_and(|p| p.id == plan.id),
        "Unapproved private attachment"
    );
    let path = c.root.join("direct-carrier.json");
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 4096,
        "Authenticated direct carrier proof missing or oversized"
    );
    let proof: serde_json::Value = serde_json::from_slice(&crate::profile::read_private(&path)?)?;
    ensure!(
        proof["id"] == plan.id
            && proof["transport"] == "authenticated-direct-tls"
            && proof["peer"].as_str() == Some(c.expected_direct_peer.to_string().as_str())
            && proof["before_attach"] == true,
        "Private native attachment requires exact authenticated source TLS first"
    );
    Ok(())
}
pub(crate) fn attached(
    profile: &Path,
    plan: &porthub_components::media_forward::Plan,
    slot: u16,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    c.verify_profile(profile)?;
    c.verify_known(plan, false)?;
    ensure!(
        c.approved()?.is_some_and(|p| p.id == plan.id) && slot > 0,
        "Unapproved destination attachment"
    );
    crate::profile::write_private(
        &c.root.join("destination-attached.json"),
        &serde_json::to_vec(
            &json!({"id":plan.id,"serial":plan.id,"vendor":"1209","product":"0001","slot":slot,"physical_camera":false,"source_capture_started":false}),
        )?,
        true,
    )?;
    Ok(())
}
#[tokio::test]
#[ignore = "Root-reviewed generated PHV1 Windows destination only; never captures a local source"]
async fn authenticated_generated_windows_video_destination() -> Result<()> {
    crate::service::require_administrator()?;
    let c = Config::load()?;
    let layout = c.layout();
    for p in [&layout.state, &layout.releases, &layout.units] {
        crate::service::directory(p, true)?;
    }
    let profile = c.input_profile()?;
    let id = crate::service::identity(&profile);
    let path = c.runtime_profile()?;
    crate::profile::write_private(&path, &serde_json::to_vec(&profile)?, false)?;
    // Apply the same protected current-account DACL as the already-reviewed input,
    // rather than relying on inherited permissions for runtime credential state.
    copy_private_acl(&c.profile, &path)?;
    for feature in ["keyboard", "usb", "microphone-share", "camera-share"] {
        let (control, _reply) = tokio::io::duplex(4096);
        crate::features::serve(
            BufReader::new(control),
            &path,
            json!({"operation":"client_features","feature":feature,"enabled":false}),
        )
        .await?;
    }
    super::config::set(
        &path,
        Some(porthub_components::media_forward::UsbIdentity {
            vendor: 0x1209,
            product: 1,
        }),
    )?;
    let status = crate::service::readable::directory(&layout)?;
    crate::service::directory(&status, false)?;
    let record = crate::service::readable::Record {
        format_version: 1,
        id: id.clone(),
        machine_id: profile.machine_id.clone(),
        email: String::new(),
        gateway: profile.server.clone(),
        private: false,
        enabled: true,
        active: Some(true),
        state: "private-generated-video-destination".into(),
        agent_version: crate::VERSION.into(),
        ports: 0,
        route: String::new(),
        updated_at: 1,
        strategy: Default::default(),
        strategy_override: false,
        private_status: None,
    };
    crate::service::atomic(
        &status.join(format!("{id}.json")),
        &serde_json::to_vec(&record)?,
        false,
    )?;
    let control = Arc::new(crate::control::Control::new(profile)?);
    let cancel = CancellationToken::new();
    let _cancel = cancel.clone().drop_guard();
    let stop = cancel.clone();
    let root = c.root.clone();
    let seconds = c.lifetime_seconds;
    let _timer = AbortOnDropHandle::new(tokio::spawn(async move {
        let end = tokio::time::Instant::now() + Duration::from_secs(seconds);
        while tokio::time::Instant::now() < end && !root.join("stop").exists() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        stop.cancel();
    }));
    let worker = super::worker::start(path, control, cancel.child_token());
    crate::profile::write_private(
        &c.root.join("agent-ready.json"),
        &serde_json::to_vec(
            &json!({"registration":id,"source_capture_started":false,"receiver_only":true,"pid":std::process::id()}),
        )?,
        true,
    )?;
    cancel.cancelled().await;
    drop(worker);
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
#[test]
fn destination_spec_rejects_production_profiles_public_peers_and_unbounded_time() {
    let root = std::env::temp_dir().join(format!(
        "porthub-windows-video-destination-{}",
        "a".repeat(32)
    ));
    let mut c = Config {
        profile: root.join("input-profile.json"),
        root,
        source_machine: "a".repeat(24),
        destination_machine: "b".repeat(24),
        source_id: format!("media:{}", "c".repeat(64)),
        source_uid: 1000,
        expected_direct_peer: "192.168.0.3".parse().unwrap(),
        lifetime_seconds: 120,
    };
    c.validate().unwrap();
    c.profile = PathBuf::from(r"C:\ProgramData\PortHub\native\real.json");
    assert!(c.validate().is_err());
    c.profile = c.root.join("input-profile.json");
    c.expected_direct_peer = "8.8.8.8".parse().unwrap();
    assert!(c.validate().is_err());
    c.expected_direct_peer = "192.168.0.3".parse().unwrap();
    c.lifetime_seconds = 181;
    assert!(c.validate().is_err());
}
#[test]
fn destination_purpose_gate_rejects_other_sources_and_persistent_or_microphone_plans() {
    let root = std::env::temp_dir().join(format!(
        "porthub-windows-video-destination-{}",
        "a".repeat(32)
    ));
    let c = Config {
        profile: root.join("input-profile.json"),
        root,
        source_machine: "a".repeat(24),
        destination_machine: "b".repeat(24),
        source_id: format!("media:{}", "c".repeat(64)),
        source_uid: 1000,
        expected_direct_peer: "192.168.0.3".parse().unwrap(),
        lifetime_seconds: 120,
    };
    let mut p = porthub_components::media_forward::Plan {
        id: "d".repeat(32),
        source: c.source_machine.clone(),
        destination: c.destination_machine.clone(),
        desktop_uid: 1000,
        desktop_session: None,
        source_id: c.source_id.clone(),
        name: "Generated PHV1 private camera proof".into(),
        identity: porthub_components::media_forward::UsbIdentity {
            vendor: 0x1209,
            product: 1,
        },
        persistent: false,
        mode: "phv1-camera-mjpeg-v1".into(),
    };
    c.verify_known(&p, false).unwrap();
    assert!(c.verify_known(&p, true).is_err());
    p.persistent = true;
    assert!(c.verify_known(&p, false).is_err());
    p.persistent = false;
    p.mode = "phm1-microphone-v1".into();
    assert!(c.verify_known(&p, false).is_err());
    p.mode = "phv1-camera-mjpeg-v1".into();
    p.source_id = format!("media:{}", "e".repeat(64));
    assert!(c.verify_known(&p, false).is_err());
    p.source_id = c.source_id.clone();
    p.desktop_uid = 1001;
    assert!(c.verify_known(&p, false).is_err());
    p.desktop_uid = 1000;
    p.identity.vendor = 1;
    assert!(c.verify_known(&p, false).is_err());
}

// Exact native MediaFoundation consumer; these WindowsSDK deps are private-test
// dev-dependencies in the reviewed snapshot, never part of the production agent.
#[path = "../../../porthub-media-helper/src/windows_video.rs"]
mod native_video;
#[path = "windows_video_plan_consumer.rs"]
mod ordinary_consumer;
#[path = "windows_video_plan_identity.rs"]
mod plan_identity;

#[tokio::test(start_paused = true)]
async fn destination_approval_wait_is_cancellable_and_never_accepts_another_plan() {
    let cancel = CancellationToken::new();
    let stopped = cancel.clone();
    let task =
        tokio::spawn(
            async move { wait_approved_plan(|| Ok(None), &"a".repeat(32), &stopped).await },
        );
    tokio::task::yield_now().await;
    cancel.cancel();
    assert!(
        task.await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    let wrong = ApprovedPlan {
        id: "b".repeat(32),
        source: "a".repeat(24),
        destination: "b".repeat(24),
        source_id: format!("media:{}", "c".repeat(64)),
        mode: "phv1-camera-mjpeg-v1".into(),
    };
    let mut wrong = Some(wrong);
    let error = wait_approved_plan(
        || Ok(wrong.take()),
        &"a".repeat(32),
        &CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("exact authenticated API"));
    let error = wait_approved_plan(|| Ok(None), &"a".repeat(32), &CancellationToken::new())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("deadline"));
}
