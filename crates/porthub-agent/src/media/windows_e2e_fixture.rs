//! Private Windows source endpoint. Never installs a service or touches enrollment.
//! The only SCM alternative is a pipe served by this same reviewed test process.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;
const ENV: &str = "PORTHUB_WINDOWS_MEDIA_FIXTURE_SPEC";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: PathBuf,
    profile: PathBuf,
    expected_direct_peer: IpAddr,
    lifetime_seconds: u64,
    source_id: String,
    kind: String,
}
impl Config {
    fn layout(&self) -> crate::service::Layout {
        crate::service::Layout {
            user: false,
            state: self.root.join("native"),
            releases: self.root.join("releases"),
            units: self.root.join("units"),
        }
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.source_id.len() == 70
                && self.source_id.starts_with("media:")
                && self.source_id[6..].bytes().all(|b| b.is_ascii_hexdigit())
                && ["microphone", "camera"].contains(&self.kind.as_str()),
            "Exact selected source and kind required"
        );
        let name = self
            .root
            .file_name()
            .and_then(|x| x.to_str())
            .context("Private fixture root required")?;
        ensure!(
            name.starts_with("porthub-windows-media-")
                && name.len() == 54
                && name[22..].bytes().all(|b| b.is_ascii_hexdigit()),
            "Use unique private Windows fixture root"
        );
        ensure!(
            self.root.parent() == Some(std::env::temp_dir().as_path())
                && self.profile == self.root.join("input-profile.json"),
            "Only private temporary fixture profiles allowed"
        );
        ensure!(
            (1..=180).contains(&self.lifetime_seconds)
                && matches!(self.expected_direct_peer,IpAddr::V4(ip) if ip.is_private()&&!ip.is_loopback()),
            "Invalid bounded fixture peer/lifetime"
        );
        Ok(())
    }
    fn load() -> Result<Self> {
        ensure!(
            std::env::var("PORTHUB_WINDOWS_MEDIA_FIXTURE_AUTHORIZED").as_deref()
                == Ok("root-reviewed-windows-source-v1"),
            "Explicit fixture review required"
        );
        let path = PathBuf::from(std::env::var_os(ENV).context("Fixture spec required")?);
        private(&path, false)?;
        let bytes = crate::profile::read_private(&path)?;
        ensure!(bytes.len() <= 8192, "Fixture config too large");
        let c: Self = serde_json::from_slice(&bytes)?;
        c.validate()?;
        ensure!(
            path.parent() == Some(c.root.as_path()),
            "Spec outside fixture root"
        );
        private(&c.root, true)?;
        private(&c.profile, false)?;
        ensure!(
            std::env::var_os("PORTHUB_STATE_DIR").map(PathBuf::from)
                == Some(c.root.join("desktop-state"))
                && std::env::var_os("PORTHUB_COMPONENT_CACHE").map(PathBuf::from)
                    == Some(c.root.join("cache")),
            "Separate private helper cache/policy required"
        );
        let _ = super::windows_host::current()?;
        Ok(c)
    }
    fn profile(&self) -> Result<crate::profile::Profile> {
        let p = crate::profile::Profile::load(&self.profile)?;
        let u = url::Url::parse(&p.server)?;
        ensure!(
            p.allow_insecure_http_for_tests
                && p.fallback_servers.is_empty()
                && u.scheme() == "http"
                && u.host_str() == Some("127.0.0.1")
                && u.port().is_some()
                && u.path() == "/",
            "Loopback-only private API required"
        );
        Ok(p)
    }
}
// DACL validation is native and fail-closed; no inherited or other-user ACEs.
pub(super) fn private(path:&Path,directory:bool)->Result<()> {
    super::windows_fixture_security::private(path,directory)
}
pub(crate) fn require_registration(layout: &crate::service::Layout, id: &str) -> Result<()> {
    let c = Config::load()?;
    ensure!(
        layout.state == c.layout().state && id == crate::service::identity(&c.profile()?),
        "Private fixture registration mismatch"
    );
    Ok(())
}
pub(crate) fn fixture_connection(
    layout: &crate::service::Layout,
    id: &str,
    pid: u32,
) -> Result<bool> {
    if std::env::var_os(ENV).is_none() {
        return Ok(false);
    }
    require_registration(layout, id)?;
    ensure!(
        pid == std::process::id(),
        "Private pipe is not served by this fixture process"
    );
    Ok(true)
}
fn append_diagnostic(rows:&mut Vec<serde_json::Value>,stage:&'static str,count:usize,millis:u64)->bool {
    const STAGES:&[&str]=&["capability-start","report-start","report-ok","report-error","plans-decoded","plans-eligible","plan-skipped","plan-accepted","session-start","session-ok","session-error","websocket-start","websocket-open","peer-ready","negotiate-start","negotiate-ok"];
    if rows.len()>=96 || !STAGES.contains(&stage) {return false;}
    rows.push(serde_json::json!({"stage":stage,"elapsed_ms":millis,"count":count.min(32)}));true
}
#[test]
fn diagnostic_metadata_is_bounded_and_allowlisted(){
    let mut rows=Vec::new();assert!(!append_diagnostic(&mut rows,"native-secret",0,0));
    for i in 0..96 {assert!(append_diagnostic(&mut rows,"plans-decoded",usize::MAX,i));}
    assert!(!append_diagnostic(&mut rows,"report-ok",0,100));assert_eq!(rows.len(),96);assert_eq!(rows[0]["count"],32);
    assert!(rows.iter().all(|row|row.as_object().unwrap().len()==3));
}
/// Private numeric stage metadata only: no error strings, paths, credentials or media.
pub(crate) fn diagnostic(profile: &Path, stage: &'static str, count: usize) {
    if std::env::var_os(ENV).is_none() { return; }
    let _ = (|| -> Result<()> {
        let c = Config::load()?;
        ensure!(crate::service::identity(&c.profile()?) == profile.file_stem().and_then(|v|v.to_str()).unwrap_or(""), "Wrong diagnostic profile");
        static RECORDS: std::sync::OnceLock<std::sync::Mutex<(std::time::Instant,Vec<serde_json::Value>)>> = std::sync::OnceLock::new();
        let mut records=RECORDS.get_or_init(||std::sync::Mutex::new((std::time::Instant::now(),Vec::new()))).lock().unwrap_or_else(|e|e.into_inner());
        if records.1.len()>=96 {return Ok(());}
        let millis=records.0.elapsed().as_millis().min(u64::MAX as u128) as u64;
        if !append_diagnostic(&mut records.1,stage,count,millis) {return Ok(());}
        crate::profile::write_private(&c.root.join("worker-stages.json"),&serde_json::to_vec(&records.1)?,true)?;
        Ok(())
    })();
}
pub(crate) fn verify_carrier(
    stream: Option<&tokio_rustls::TlsStream<tokio::net::TcpStream>>,
    profile: &crate::profile::Profile,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    ensure!(
        profile.machine_id == c.profile()?.machine_id,
        "Wrong private source profile"
    );
    let marker = c.root.join("allow-native-plan");
    private(&marker, false)?;
    ensure!(
        crate::profile::read_private(&marker)? == b"root-approved-windows-media-v1\n",
        "No explicit private native plan approval"
    );
    let s = stream.context("Private source refuses relay fallback")?;
    ensure!(
        s.get_ref().0.peer_addr()?.ip() == c.expected_direct_peer,
        "Wrong direct TLS physical peer"
    );
    crate::profile::write_private(
        &c.root.join("direct-carrier.json"),
        &serde_json::to_vec(
            &serde_json::json!({"transport":"authenticated-direct-tls","peer":c.expected_direct_peer.to_string(),"before_capture":true}),
        )?,
        true,
    )?;
    Ok(())
}
#[tokio::test]
#[ignore = "Root-reviewed interactive Windows source fixture; no automatic capture"]
async fn native_windows_authenticated_source_fixture() -> Result<()> {
    let c = Config::load()?;
    let layout = c.layout();
    for d in [&layout.state, &layout.releases, &layout.units] {
        crate::service::directory(d, true)?;
    }
    let profile = c.profile()?;
    let id = crate::service::identity(&profile);
    let path = layout.state.join(format!("{id}.json"));
    crate::profile::write_private(&path, &serde_json::to_vec(&profile)?, false)?;
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
        state: "private-fixture".into(),
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
    let _cancel_on_drop = cancel.clone().drop_guard();
    let mut listener = crate::exposure_broker::media_fixture_listener(&layout, &id, true)?;
    let server_cancel = cancel.clone();
    let server_profile = path.clone();
    let server_layout = layout.clone();
    let server_id = id.clone();
    let server_control = control.clone();
    let mut server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {_=server_cancel.cancelled()=>break,_=tasks.join_next(),if !tasks.is_empty()=>{},accepted=listener.connect()=>{accepted?;let next=crate::exposure_broker::media_fixture_listener(&server_layout,&server_id,false)?;let stream=std::mem::replace(&mut listener,next);ensure!(tasks.len()<16,"Fixture pipe capacity exhausted");let peer=crate::exposure_broker::media_fixture_peer(&stream)?;let control=server_control.clone();let stop=server_cancel.clone();let path=server_profile.clone();tasks.spawn(async move{crate::exposure_protocol::serve_connection_as_windows_user(stream,control,stop,path,Some(peer)).await});}}
        }
        tasks.abort_all();
        Ok::<_, anyhow::Error>(())
    });
    crate::profile::write_private(
        &c.root.join("source-ready.json"),
        &serde_json::to_vec(
            &serde_json::json!({"registration":id,"desktop_session":super::windows_host::current()?.desktop_session(),"pid":std::process::id(),"capture_started":false}),
        )?,
        true,
    )?;
    let mut host = tokio::spawn(super::host::run(layout, id, cancel.child_token()));
    let _worker = super::worker::start(path, control, cancel.child_token());
    let result = tokio::select! {
     result=&mut host=>result.map_err(anyhow::Error::from).and_then(|r|r),
     result=&mut server=>result.map_err(anyhow::Error::from).and_then(|r|r),
     _=tokio::time::sleep(Duration::from_secs(c.lifetime_seconds))=>Ok(()),
     _=async{loop{if c.root.join("stop").exists(){break}tokio::time::sleep(Duration::from_millis(50)).await;}}=>Ok(())
    };
    cancel.cancel();
    if !host.is_finished()
        && tokio::time::timeout(Duration::from_secs(2), &mut host)
            .await
            .is_err()
    {
        host.abort();
    }
    if !server.is_finished()
        && tokio::time::timeout(Duration::from_secs(2), &mut server)
            .await
            .is_err()
    {
        server.abort();
    }
    result
}

#[test]
fn windows_source_fixture_rejects_production_paths_unbounded_lifetime_and_public_peer() {
    let root = std::env::temp_dir().join(format!("porthub-windows-media-{}", "a".repeat(32)));
    let mut c = Config {
        profile: root.join("input-profile.json"),
        root,
        expected_direct_peer: "192.168.0.166".parse().unwrap(),
        lifetime_seconds: 120,
        source_id: format!("media:{}", "a".repeat(64)),
        kind: "camera".into(),
    };
    c.validate().unwrap();
    c.profile = PathBuf::from(r"C:\ProgramData\PortHub\native\real.json");
    assert!(c.validate().is_err());
    c.profile = c.root.join("input-profile.json");
    c.lifetime_seconds = 181;
    assert!(c.validate().is_err());
    c.lifetime_seconds = 120;
    c.expected_direct_peer = "8.8.8.8".parse().unwrap();
    assert!(c.validate().is_err());
}

pub(crate) fn verify_plan(
    plan: &porthub_components::media_forward::Plan,
    source: bool,
) -> Result<()> {
    if std::env::var_os(ENV).is_none() {
        return Ok(());
    }
    let c = Config::load()?;
    let own = super::windows_host::current()?;
    ensure!(
        source
            && plan.source_id == c.source_id
            && plan.desktop_uid == 0
            && plan.desktop_session.as_deref() == Some(own.desktop_session())
            && matches!(
                (c.kind.as_str(), plan.kind()),
                ("camera", Some(porthub_components::media::Kind::Camera))
                    | (
                        "microphone",
                        Some(porthub_components::media::Kind::Microphone)
                    )
            ),
        "Fixture plan does not match explicitly selected Windows source"
    );
    Ok(())
}
