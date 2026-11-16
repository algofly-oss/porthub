//! Private GENERATED-PHV1 proof. No physical source, helper bypass, service
//! installation or production profile. Actual OS peer auth/API/transport/UVC stay.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
const ENV: &str = "PORTHUB_NATIVE_VIDEO_FIXTURE_SPEC";
const JPEG: &[u8] = include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg");
fn generated_jpeg_digest() -> String {
    format!("{:x}", sha2::Sha256::digest(JPEG))
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Agent,
    SyntheticDesktop,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: PathBuf,
    role: Role,
    profile: PathBuf,
    registration: Option<String>,
    expected_direct_peer: IpAddr,
    lifetime_seconds: u64,
    receiver: bool,
}
impl Config {
    fn validate(&self) -> Result<()> {
        let name = self
            .root
            .file_name()
            .and_then(|s| s.to_str())
            .context("Invalid private video root")?;
        ensure!(
            self.root.parent() == Some(Path::new("/tmp"))
                && name.starts_with("porthub-native-video-e2e-")
                && name.len() >= 55
                && name.len() <= 100
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "Private video root must be unique and owned"
        );
        ensure!(
            self.profile == self.root.join("input-profile.json"),
            "Production profiles are forbidden"
        );
        ensure!(
            (1..=180).contains(&self.lifetime_seconds),
            "Private video lifetime exceeds bound"
        );
        ensure!(
            matches!(self.expected_direct_peer,IpAddr::V4(ip)if ip.is_private()&&!ip.is_loopback()),
            "Exact physical LAN peer required"
        );
        if matches!(self.role, Role::SyntheticDesktop) {
            ensure!(
                !self.receiver
                    && self.registration.as_ref().is_some_and(
                        |id| id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
                    ),
                "Synthetic desktop requires only its public registration"
            );
        }
        Ok(())
    }
    fn load() -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            std::env::var("PORTHUB_NATIVE_VIDEO_FIXTURE_AUTHORIZED").as_deref()
                == Ok("root-reviewed-generated-phv1-v1"),
            "Explicit private GENERATED video authorization required"
        );
        let path =
            PathBuf::from(std::env::var_os(ENV).context("Private video specification required")?);
        let m = std::fs::symlink_metadata(&path)?;
        ensure!(
            m.is_file()
                && !m.file_type().is_symlink()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0
                && m.len() <= 8192,
            "Unsafe private video specification"
        );
        let c: Self = serde_json::from_slice(&std::fs::read(&path)?)?;
        c.validate()?;
        let m = std::fs::symlink_metadata(&c.root)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o022 == 0,
            "Unsafe private video root"
        );
        ensure!(
            path.parent() == Some(c.root.as_path()),
            "Specification is outside owned root"
        );
        ensure!(
            std::env::var_os("PORTHUB_STATE_DIR").map(PathBuf::from)
                == Some(c.root.join("desktop-state")),
            "Desktop policy must remain fixture-local"
        );
        Ok(c)
    }
    fn layout(&self) -> crate::service::Layout {
        crate::service::Layout {
            user: true,
            state: self.root.join("native"),
            releases: self.root.join("releases"),
            units: self.root.join("units"),
        }
    }
    fn approve(&self) -> Result<()> {
        ensure!(
            crate::profile::read_private(&self.root.join("allow-generated-video-plan"))?
                == b"root-approved-generated-phv1-v1\n",
            "Generated-only plan approval missing"
        );
        Ok(())
    }
}
fn private_profile(p: &crate::profile::Profile) -> Result<()> {
    let u = url::Url::parse(&p.server)?;
    ensure!(
        p.allow_insecure_http_for_tests
            && p.fallback_servers.is_empty()
            && u.scheme() == "http"
            && u.host_str() == Some("127.0.0.1")
            && u.port().is_some()
            && u.path() == "/",
        "Only isolated loopback signaling without production fallback is allowed"
    );
    Ok(())
}
/// Invoked before peer-ready/native attachment. This proof never silently uses
/// gateway or SCTP media fallback; only the exact LAN authenticated TLS socket.
pub(crate) fn verify_carrier(
    stream: Option<&tokio_rustls::TlsStream<tokio::net::TcpStream>>,
    profile: &crate::profile::Profile,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    c.approve()?;
    private_profile(profile)?;
    let stream = stream.context("Generated camera proof requires authenticated direct TLS")?;
    let socket = stream.get_ref().0;
    ensure!(
        socket.peer_addr()?.ip() == c.expected_direct_peer,
        "Camera TLS peer is not selected physical machine"
    );
    crate::profile::write_private(
        &c.root.join("video-direct-carrier.json"),
        &serde_json::to_vec(
            &json!({"transport":"authenticated-direct-tls","local":socket.local_addr()?.ip().to_string(),"peer":socket.peer_addr()?.ip().to_string(),"before_capture":true,"source":"generated-phv1-not-physical-camera"}),
        )?,
        true,
    )?;
    Ok(())
}
fn source(c: &Config) -> porthub_components::media::Device {
    use porthub_components::media::{stable_source_id, CaptureState, Device, Kind};
    Device {
        id: stable_source_id(
            Kind::Camera,
            "private-generated-colorbars",
            &c.root.to_string_lossy(),
        ),
        name: "Generated colorbars · private proof".into(),
        kind: Kind::Camera,
        backend: "private-generated-phv1".into(),
        native_id: "generated-not-a-camera".into(),
        capture_available: true,
        capture_state: CaptureState::Ready,
        unavailable_reason: None,
    }
}
async fn lifetime(root: PathBuf, cancel: CancellationToken, seconds: u64) {
    let deadline = tokio::time::sleep(Duration::from_secs(seconds));
    tokio::pin!(deadline);
    loop {
        tokio::select! {_=&mut deadline=>break,_=tokio::time::sleep(Duration::from_millis(100))=>if root.join("stop").exists(){break;}}
    }
    cancel.cancel();
}
async fn send(
    writer: &Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    value: &serde_json::Value,
) -> Result<()> {
    tokio::time::timeout(Duration::from_millis(100), async {
        super::host_wire::json(&mut *writer.lock().await, value).await
    })
    .await??;
    Ok(())
}
fn inventory(
    device: &porthub_components::media::Device,
    root_allowed: bool,
    user_allowed: bool,
    request: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut value = json!({"type":"inventory","devices":if root_allowed&&user_allowed{vec![device.clone()]}else{vec![]},"microphone_unavailable_reason":"Synthetic camera proof only","camera_unavailable_reason":if root_allowed&&user_allowed{None}else{Some("Synthetic camera disabled by root or desktop policy")}});
    if let Some(request) = request {
        value["request"] = request.clone();
    }
    value
}
async fn synthetic_desktop(c: &Config, cancel: CancellationToken) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Synthetic host must use the real unprivileged OS peer"
    );
    let own_directory = crate::components::state_directory()?.join("media");
    crate::service::directory(&own_directory, true)?;
    let own = own_directory.join("desktop-media.json");
    let mut gui = crate::features::subscribe(&own);
    let stream = tokio::time::timeout(
        Duration::from_secs(5),
        crate::exposure_broker::connect_stream(&c.layout(), c.registration.as_deref().unwrap()),
    )
    .await??;
    let (read, mut write) = stream.into_split();
    write.write_all(b"{\"operation\":\"media_host\"}\n").await?;
    let writer = Arc::new(tokio::sync::Mutex::new(write));
    let mut read = super::host_wire::Reader::new(read);
    let hello = tokio::time::timeout(Duration::from_secs(5), read.next()).await??;
    let hello: serde_json::Value = serde_json::from_slice(&hello)?;
    ensure!(
        hello["type"] == "policy"
            && hello["uid"].as_u64() == Some(unsafe { libc::geteuid() } as u64),
        "OS-authenticated synthetic principal differs"
    );
    let mut root_allowed = hello["camera"] == true;
    let mut user_allowed = gui
        .borrow_and_update()
        .enabled(crate::features::Feature::CameraShare);
    let device = source(c);
    send(
        &writer,
        &inventory(&device, root_allowed, user_allowed, None),
    )
    .await?;
    let (frames, starts) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let mut active: Option<(String, CancellationToken, AbortOnDropHandle<Result<()>>)> = None;
    crate::profile::write_private(
        &c.root.join("synthetic-host-ready.json"),
        &serde_json::to_vec(
            &json!({"source_id":device.id,"uid":unsafe{libc::geteuid()},"frames_generated":0,"physical_camera":false}),
        )?,
        true,
    )?;
    let mut revoked_user = false;
    let result=async{loop{tokio::select!{biased;
        _=cancel.cancelled()=>break,
        changed=gui.changed()=>{
            changed?;user_allowed=gui.borrow_and_update().enabled(crate::features::Feature::CameraShare);
            if !user_allowed{if let Some((id,stop,task))=active.take(){stop.cancel();drop(task);send(&writer,&json!({"type":"stopped","session":id})).await?;}}
            send(&writer,&inventory(&device,root_allowed,user_allowed,None)).await?;
        },
        done=async{(&mut active.as_mut().unwrap().2).await},if active.is_some()=>{
            let(id,stop,task)=active.take().unwrap();stop.cancel();drop(task);send(&writer,&json!({"type":"error","session":id})).await?;
            done??;anyhow::bail!("Synthetic producer unexpectedly stopped");
        },
        _=tokio::time::sleep(Duration::from_millis(100))=>{
            if !revoked_user&&c.root.join("revoke-desktop-camera").exists(){
                let(control,_reply)=tokio::io::duplex(4096);crate::features::serve(BufReader::new(control),&own,json!({"operation":"client_features","feature":"camera-share","enabled":false})).await?;
                ensure!(!crate::features::enabled(&own,crate::features::Feature::CameraShare),"Desktop camera policy did not change");revoked_user=true;
            }
            crate::profile::write_private(&c.root.join("synthetic-host-live.json"),&serde_json::to_vec(&json!({"golden_jpeg_sha256":generated_jpeg_digest(),"frames_generated":frames.load(Ordering::Relaxed),"capture_starts":starts.load(Ordering::Relaxed),"active":active.is_some(),"root_allowed":root_allowed,"desktop_allowed":user_allowed,"physical_camera":false}))?,true)?;
        },
        bytes=read.next()=>{
            let value:serde_json::Value=serde_json::from_slice(&bytes?)?;
            match value["type"].as_str(){
                Some("policy")=>{ensure!(value["uid"].as_u64()==Some(unsafe{libc::geteuid()}as u64),"Synthetic principal changed");root_allowed=value["camera"]==true;if !root_allowed{if let Some((_,stop,task))=active.take(){stop.cancel();drop(task);}}send(&writer,&inventory(&device,root_allowed,user_allowed,None)).await?;},
                Some("discover")=>send(&writer,&inventory(&device,root_allowed,user_allowed,value.get("request"))).await?,
                Some("capture-camera")=>{
                    ensure!(root_allowed&&user_allowed&&active.is_none()&&value["source"]==device.id,"Wrong, disabled or duplicate synthetic camera selection");
                    let session=value["session"].as_str().context("Missing synthetic capture nonce")?.to_owned();ensure!(session.len()==32&&session.bytes().all(|b|b.is_ascii_hexdigit()),"Invalid synthetic capture nonce");
                    c.approve()?;starts.fetch_add(1,Ordering::Relaxed);send(&writer,&json!({"type":"started","session":session})).await?;
                    let stop=cancel.child_token();let end=stop.clone();let write=writer.clone();let count=frames.clone();let epoch=session.clone();
                    let task=AbortOnDropHandle::new(tokio::spawn(async move{
                        let origin=std::time::Instant::now();let mut sequence=0;let mut tick=tokio::time::interval(Duration::from_micros(66_667));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                        loop{tokio::select!{biased;_=end.cancelled()=>return Ok(()),_=tick.tick()=>{
                            let frame=porthub_components::media::VideoFrame{sequence,source_monotonic_micros:origin.elapsed().as_micros()as u64,format:porthub_components::media::VideoFormat::baseline_mjpeg(),jpeg:JPEG.to_vec()};
                            let bytes=super::host_wire::video(&epoch,&frame).context("Invalid generated PHV1 frame")?;
                            tokio::select!{biased;_=end.cancelled()=>return Ok(()),r=async{let mut write=write.lock().await;super::host_wire::write_camera(&mut *write,&bytes).await}=>r?};sequence+=1;count.fetch_add(1,Ordering::Relaxed);
                        }}}
                    }));active=Some((session,stop,task));
                },
                Some("stop")=>{if active.as_ref().is_some_and(|(id,_,_)|Some(id.as_str())==value["session"].as_str()){let(id,stop,task)=active.take().unwrap();stop.cancel();drop(task);send(&writer,&json!({"type":"stopped","session":id})).await?;}},
                _=>anyhow::bail!("Unexpected synthetic source command"),
            }
        }
    }}Ok::<_,anyhow::Error>(())}.await;
    if let Some((_, stop, task)) = active.take() {
        stop.cancel();
        drop(task);
    }
    crate::profile::write_private(
        &c.root.join("synthetic-host-proof.json"),
        &serde_json::to_vec(
            &json!({"source":"generated-phv1-not-physical-camera","golden_jpeg_sha256":generated_jpeg_digest(),"frames_generated":frames.load(Ordering::Relaxed),"capture_starts":starts.load(Ordering::Relaxed),"physical_camera":false,"no_image_files":true}),
        )?,
        true,
    )?;
    result
}

#[tokio::test]
#[ignore = "Requires Root-reviewed generated PHV1 API/TLS/UVC fixture; no physical camera source"]
async fn authenticated_generated_camera_fixture_endpoint() -> Result<()> {
    let c = Config::load()?;
    c.approve()?;
    let cancel = CancellationToken::new();
    let _cancel_on_exit = cancel.clone().drop_guard();
    let _timer = AbortOnDropHandle::new(tokio::spawn(lifetime(
        c.root.clone(),
        cancel.clone(),
        c.lifetime_seconds,
    )));
    if matches!(c.role, Role::SyntheticDesktop) {
        return synthetic_desktop(&c, cancel).await;
    }
    let layout = c.layout();
    for path in [&layout.state, &layout.releases, &layout.units] {
        crate::service::directory(path, true)?;
    }
    let profile = crate::profile::Profile::load(&c.profile)?;
    private_profile(&profile)?;
    let id = crate::service::identity(&profile);
    let path = layout.state.join(format!("{id}.json"));
    crate::profile::write_private(&path, &serde_json::to_vec(&profile)?, false)?;
    let spec = crate::service::Spec {
        user: true,
        identity: id.clone(),
        service: format!("porthub-{}", &id[..24]),
        profile: path.clone(),
        executable: layout.releases.join("a".repeat(64)).join("porthub"),
        unit: layout.units.join(format!("porthub-{}.service", &id[..24])),
        cli: None,
    };
    crate::profile::write_private(
        &layout.state.join(format!("{id}.service.json")),
        &serde_json::to_vec(&spec)?,
        false,
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
        state: "synthetic-camera-fixture".into(),
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
    // Exercise independence from keyboard, raw USB and microphone-sharing flags.
    for feature in ["keyboard", "usb", "microphone-share"] {
        let (control, _reply) = tokio::io::duplex(4096);
        crate::features::serve(
            BufReader::new(control),
            &path,
            json!({"operation":"client_features","feature":feature,"enabled":false}),
        )
        .await?;
    }
    if c.receiver {
        super::config::set(
            &path,
            Some(porthub_components::media_forward::UsbIdentity {
                vendor: 0x1209,
                product: 1,
            }),
        )?;
    }
    let control = Arc::new(crate::control::Control::new(profile)?);
    let _broker = crate::exposure_broker::start_registered(
        &path,
        control.clone(),
        cancel.child_token(),
        &layout,
    )?;
    let _worker = super::worker::start(path.clone(), control, cancel.child_token());
    crate::profile::write_private(
        &c.root.join("agent-ready.json"),
        &serde_json::to_vec(
            &json!({"registration":id,"source":"generated-phv1-not-physical-camera"}),
        )?,
        true,
    )?;
    let mut revoked = false;
    loop {
        tokio::select! {_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(100))=>{if !revoked&&c.root.join("revoke-camera").exists(){let work=async{let mut s=crate::exposure_broker::connect_stream(&layout,&id).await?;s.write_all(b"{\"operation\":\"client_features\",\"feature\":\"camera-share\",\"enabled\":false}\n").await?;let mut bytes=Vec::new();BufReader::new(s.take(16385)).read_until(b'\n',&mut bytes).await?;let reply:serde_json::Value=serde_json::from_slice(&bytes)?;ensure!(reply.get("error").is_none()&&!crate::features::enabled(&path,crate::features::Feature::CameraShare),"Camera source policy did not really change");Ok::<_,anyhow::Error>(())};tokio::time::timeout(Duration::from_secs(2),work).await??;revoked=true;}}}
    }
    cancel.cancel();
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
#[test]
fn generated_fixture_rejects_real_profiles_and_unbounded_scope() {
    let root = PathBuf::from(format!("/tmp/porthub-native-video-e2e-{}", "a".repeat(32)));
    let mut c = Config {
        profile: root.join("input-profile.json"),
        root,
        role: Role::Agent,
        registration: None,
        expected_direct_peer: "192.168.0.166".parse().unwrap(),
        lifetime_seconds: 120,
        receiver: false,
    };
    assert!(c.validate().is_ok());
    c.profile = "/etc/porthub/native/real.json".into();
    assert!(c.validate().is_err());
    c.profile = c.root.join("input-profile.json");
    c.lifetime_seconds = 181;
    assert!(c.validate().is_err());
}

#[test]
fn generated_inventory_cannot_override_either_camera_policy() {
    let root = PathBuf::from(format!("/tmp/porthub-native-video-e2e-{}", "a".repeat(32)));
    let config = Config {
        profile: root.join("input-profile.json"),
        root,
        role: Role::Agent,
        registration: None,
        expected_direct_peer: "192.168.0.166".parse().unwrap(),
        lifetime_seconds: 120,
        receiver: false,
    };
    let source = source(&config);
    for (root, user) in [(false, true), (true, false), (false, false)] {
        assert!(inventory(&source, root, user, None)["devices"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    assert_eq!(
        inventory(&source, true, true, None)["devices"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
#[test]
fn generated_profile_refuses_remote_or_production_signaling() {
    let mut p = crate::profile::Profile {
        format_version: 1,
        server: "http://127.0.0.1:18090/".into(),
        machine_id: "a".repeat(24),
        token: "private-fixture-not-production".into(),
        account_email: None,
        fallback_servers: vec![],
        setup_overrides: Default::default(),
        allow_insecure_http_for_tests: true,
    };
    assert!(private_profile(&p).is_ok());
    p.server = "https://porthub.algofly.in/".into();
    assert!(private_profile(&p).is_err());
    p.server = "http://127.0.0.1:18090/".into();
    p.fallback_servers
        .push("https://porthub.algofly.in/".into());
    assert!(private_profile(&p).is_err());
}
