//! Private Linux receiver for an exact Windows native source. No local capture.
use anyhow::{ensure, Context, Result};
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
mod pcm;
pub(crate) use pcm::PcmProof;
mod video;
pub(crate) use video::VideoProof;
const ENV: &str = "PORTHUB_WINDOWS_RECEIVER_FIXTURE_SPEC";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: PathBuf,
    profile: PathBuf,
    expected_direct_peer: IpAddr,
    lifetime_seconds: u64,
    source_id: String,
    desktop_session: String,
    kind: porthub_components::media::Kind,
}
impl Config {
    fn load() -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            std::env::var("PORTHUB_WINDOWS_RECEIVER_FIXTURE_AUTHORIZED").as_deref()
                == Ok("root-reviewed-windows-receiver-v1"),
            "Explicit Windows-source receiver authorization required"
        );
        let spec = PathBuf::from(std::env::var_os(ENV).context("Receiver config required")?);
        let metadata = std::fs::symlink_metadata(&spec)?;
        ensure!(
            metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.len() <= 8192,
            "Unsafe receiver config"
        );
        let c: Self = serde_json::from_slice(&std::fs::read(&spec)?)?;
        c.validate()?;
        let metadata = std::fs::symlink_metadata(&c.root)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && spec.parent() == Some(c.root.as_path()),
            "Unsafe owned receiver root"
        );
        ensure!(
            std::env::var_os("PORTHUB_STATE_DIR").map(PathBuf::from)
                == Some(c.root.join("desktop-state")),
            "Receiver policy must remain fixture-local"
        );
        Ok(c)
    }
    fn validate(&self) -> Result<()> {
        let name = self
            .root
            .file_name()
            .and_then(|x| x.to_str())
            .context("Invalid receiver root")?;
        let suffix = name
            .strip_prefix("porthub-windows-media-receiver-")
            .context("Wrong receiver root")?;
        ensure!(
            self.root.parent() == Some(Path::new("/tmp"))
                && suffix.len() == 32
                && suffix.bytes().all(|b| b.is_ascii_hexdigit())
                && self.profile == self.root.join("input-profile.json"),
            "Only private receiver profile allowed"
        );
        ensure!(
            (1..=180).contains(&self.lifetime_seconds)
                && matches!(self.expected_direct_peer,IpAddr::V4(ip)if ip.is_private()&&!ip.is_loopback()),
            "Invalid bounded receiver peer/lifetime"
        );
        ensure!(
            self.source_id.len() == 70
                && self.source_id.starts_with("media:")
                && self.source_id[6..].bytes().all(|b| b.is_ascii_hexdigit())
                && porthub_components::media_forward::valid_desktop(0, Some(&self.desktop_session)),
            "Exact Windows source/principal required"
        );
        Ok(())
    }
    fn approve(&self) -> Result<()> {
        ensure!(
            crate::profile::read_private(&self.root.join("allow-native-plan"))?
                == b"root-approved-windows-receiver-v1\n",
            "Private receiver approval missing"
        );
        Ok(())
    }
    fn layout(&self) -> crate::service::Layout {
        crate::service::Layout {
            user: true,
            state: self.root.join("native"),
            releases: self.root.join("releases"),
            units: self.root.join("units"),
        }
    }
}
fn private_profile(profile: &crate::profile::Profile) -> Result<()> {
    let u = url::Url::parse(&profile.server)?;
    ensure!(
        profile.allow_insecure_http_for_tests
            && profile.fallback_servers.is_empty()
            && u.scheme() == "http"
            && u.host_str() == Some("127.0.0.1")
            && u.port().is_some()
            && u.path() == "/",
        "Only private loopback signaling allowed"
    );
    Ok(())
}
pub(crate) fn verify_plan(
    plan: &porthub_components::media_forward::Plan,
    source: bool,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    c.approve()?;
    ensure!(
        !source
            && plan.valid()
            && plan.identity.vendor == 0x1209
            && plan.identity.product == 1
            && plan.kind() == Some(c.kind)
            && plan.source_id == c.source_id
            && plan.desktop_uid == 0
            && plan.desktop_session.as_deref() == Some(c.desktop_session.as_str()),
        "Receiver refuses any other source/kind/principal"
    );
    let record = c.root.join("receiver-plan.json");
    if record.exists() {
        let previous: porthub_components::media_forward::Plan =
            serde_json::from_slice(&crate::profile::read_private(&record)?)?;
        ensure!(
            previous.id == plan.id,
            "Only one private receiver plan is allowed per root"
        );
    } else {
        crate::profile::write_private(&record, &serde_json::to_vec(plan)?, false)?;
    }
    Ok(())
}
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
    let stream = stream.context("Native Windows proof requires authenticated direct TLS")?;
    let socket = stream.get_ref().0;
    ensure!(
        socket.peer_addr()?.ip() == c.expected_direct_peer,
        "Wrong physical Windows peer"
    );
    crate::profile::write_private(
        &c.root.join("direct-carrier.json"),
        &serde_json::to_vec(
            &json!({"transport":"authenticated-direct-tls","peer":socket.peer_addr()?.ip().to_string(),"local":socket.local_addr()?.ip().to_string(),"before_capture":true,"proof":"native-windows-source-receiver"}),
        )?,
        true,
    )?;
    Ok(())
}
#[tokio::test]
#[ignore = "Root-reviewed native Windows source receiver only; never captures local devices"]
async fn native_windows_source_receiver() -> Result<()> {
    let c = Config::load()?;
    c.approve()?;
    let cancel = CancellationToken::new();
    let _cancel_on_exit = cancel.clone().drop_guard();
    let root = c.root.clone();
    let done = cancel.clone();
    let seconds = c.lifetime_seconds;
    let _timer = AbortOnDropHandle::new(tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
        while tokio::time::Instant::now() < deadline && !root.join("stop").exists() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        done.cancel();
    }));
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
        state: "windows-source-receiver-fixture".into(),
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
    for feature in ["keyboard", "usb", "microphone-share", "camera-share"] {
        let (control, _reply) = tokio::io::duplex(4096);
        crate::features::serve(
            BufReader::new(control),
            &path,
            json!({"operation":"client_features","feature":feature,"enabled":false}),
        )
        .await?;
    }
    {
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
        &serde_json::to_vec(&json!({"registration":id,"source":"native-windows-source-receiver"}))?,
        true,
    )?;
    cancel.cancelled().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    Ok(())
}
#[test]
fn windows_receiver_rejects_real_profiles_and_other_principals() {
    let mut c = Config {
        root: PathBuf::from(format!(
            "/tmp/porthub-windows-media-receiver-{}",
            "a".repeat(32)
        )),
        profile: PathBuf::from(format!(
            "/tmp/porthub-windows-media-receiver-{}/input-profile.json",
            "a".repeat(32)
        )),
        expected_direct_peer: "192.168.0.169".parse().unwrap(),
        lifetime_seconds: 120,
        source_id: format!("media:{}", "b".repeat(64)),
        desktop_session: format!("windows:{}", "c".repeat(64)),
        kind: porthub_components::media::Kind::Camera,
    };
    assert!(c.validate().is_ok());
    c.desktop_session = "windows:untrusted".into();
    assert!(c.validate().is_err());
    c.desktop_session = format!("windows:{}", "c".repeat(64));
    c.profile = PathBuf::from("/etc/porthub/profile.json");
    assert!(c.validate().is_err());
}
