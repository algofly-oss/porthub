//! Private native proof runner, absent from production builds. It never installs
//! services or activates capture by itself: only an authenticated API plan plus
//! an ordinary receiver consumer can request the explicit source.
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::{net::IpAddr, path::{Path, PathBuf}, sync::Arc, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;
#[derive(Deserialize)]
#[serde(rename_all="kebab-case")]
enum Role { Agent, Desktop }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    root: PathBuf,
    role: Role,
    /// A fixture-only credential file, never an installed registration.
    profile: PathBuf,
    registration: Option<String>,
    expected_direct_peer: IpAddr,
    lifetime_seconds: u64,
    receiver: bool,
}
impl Config {
    fn validate(&self) -> Result<()> {
        let name=self.root.file_name().and_then(|s|s.to_str()).context("Invalid fixture root")?;
        ensure!(self.root.parent()==Some(Path::new("/tmp")) && name.starts_with("porthub-native-media-e2e-") && name.len()>=48 && name.len()<=100 && name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'),"Use a unique private media fixture root");
        ensure!(self.profile.parent()==Some(self.root.as_path()) && self.profile.file_name().is_some_and(|s|s=="input-profile.json"),"Only fixture-local credentials are allowed");
        ensure!((1..=180).contains(&self.lifetime_seconds),"Fixture lifetime exceeds bounds");
        ensure!(matches!(self.expected_direct_peer,IpAddr::V4(ip) if ip.is_private() && !ip.is_loopback()),"Require the exact physical LAN peer");
        if matches!(self.role,Role::Desktop){ensure!(self.registration.as_ref().is_some_and(|id|id.len()==64&&id.bytes().all(|b|b.is_ascii_hexdigit())),"Desktop fixture requires only its public registration identity");}
        Ok(())
    }
    fn load() -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        ensure!(std::env::var("PORTHUB_NATIVE_MEDIA_FIXTURE_AUTHORIZED").as_deref()==Ok("root-reviewed-microphone-v1"),"Native fixture requires explicit reviewed authorization");
        let path=PathBuf::from(std::env::var_os("PORTHUB_NATIVE_MEDIA_FIXTURE_SPEC").context("Fixture specification required")?);
        let meta=std::fs::symlink_metadata(&path)?;
        ensure!(meta.is_file()&&!meta.file_type().is_symlink()&&meta.uid()==unsafe{libc::geteuid()}&&meta.mode()&0o077==0&&meta.len()<=8192,"Unsafe private fixture specification");
        let config:Self=serde_json::from_slice(&std::fs::read(&path)?)?;
        config.validate()?;
        let root=std::fs::symlink_metadata(&config.root)?;
        ensure!(root.is_dir()&&!root.file_type().is_symlink()&&root.uid()==unsafe{libc::geteuid()}&&root.mode()&0o022==0,"Unsafe fixture root");
        ensure!(std::env::var_os("PORTHUB_COMPONENT_CACHE").map(PathBuf::from)==Some(config.root.join("cache")) && std::env::var_os("PORTHUB_STATE_DIR").map(PathBuf::from)==Some(config.root.join("desktop-state")),"Fixture must isolate component cache and user policy state");
        ensure!(path.parent()==Some(config.root.as_path()),"Fixture specification must belong to its private root");
        Ok(config)
    }
    fn layout(&self)->crate::service::Layout {
        crate::service::Layout{user:true,state:self.root.join("native"),releases:self.root.join("releases"),units:self.root.join("units")}
    }
}
fn validate_private_profile(profile:&crate::profile::Profile)->Result<()> {
    let url=url::Url::parse(&profile.server)?;
    ensure!(profile.allow_insecure_http_for_tests&&profile.fallback_servers.is_empty()&&url.scheme()=="http"&&url.host_str()==Some("127.0.0.1")&&url.port().is_some()&&url.path()=="/","Fixture signaling must use the isolated loopback API with no production fallback");
    Ok(())
}
fn require_native_plan_approval(root:&Path)->Result<()> {
    let bytes=crate::profile::read_private(&root.join("allow-native-plan"))?;
    ensure!(bytes==b"root-approved-native-media-v1\n","Private native plan has no explicit local approval");
    Ok(())
}
/// Runs before transport-ready, source capture, or receiver attachment. A
/// plaintext gateway fallback can never carry PCM in this private proof.
pub(crate) fn verify_carrier(stream:Option<&tokio_rustls::TlsStream<tokio::net::TcpStream>>, profile:&crate::profile::Profile)->Result<()> {
    if std::env::var_os("PORTHUB_NATIVE_MEDIA_FIXTURE_SPEC").is_none(){return Ok(());}
    let config=Config::load()?;
    validate_private_profile(profile)?;
    require_native_plan_approval(&config.root)?;
    let stream=stream.context("Private proof refuses gateway/SCTP fallback; authenticated direct TLS is required")?;
    let peer=stream.get_ref().0.peer_addr()?;
    ensure!(peer.ip()==config.expected_direct_peer,"Negotiated TLS peer is not the selected physical LAN machine");
    let receipt=serde_json::json!({"transport":"authenticated-direct-tls","peer":peer.ip().to_string(),"local":stream.get_ref().0.local_addr()?.ip().to_string(),"before_capture":true});
    crate::profile::write_private(&config.root.join("direct-carrier.json"),&serde_json::to_vec(&receipt)?,true)?;
    Ok(())
}
fn verify_revoked_reply(bytes:&[u8],profile:&Path)->Result<()> {
    ensure!(bytes.len()<=16384&&bytes.last()==Some(&b'\n'),"Invalid bounded policy reply");
    let reply:serde_json::Value=serde_json::from_slice(bytes)?;
    ensure!(reply.get("error").is_none()&&reply["features"].as_array().is_some_and(|rows|rows.iter().any(|r|r["feature"]=="microphone-share"&&r["enabled"]==false))&&!crate::features::enabled(profile,crate::features::Feature::MicrophoneShare),"Source policy was not actually revoked");
    Ok(())
}
async fn stopped(root:&Path,cancel:CancellationToken,seconds:u64){
    let deadline=tokio::time::sleep(Duration::from_secs(seconds));tokio::pin!(deadline);
    loop{tokio::select!{_= &mut deadline=>break,_=tokio::time::sleep(Duration::from_millis(100))=>if root.join("stop").exists(){break;}}}
    cancel.cancel();
}
#[tokio::test]
#[ignore="Explicit root-reviewed native PHM1 fixture; may publish an owned UAC endpoint only after authenticated planning"]
async fn native_authenticated_media_fixture_endpoint()->Result<()> {
    let _=tracing_subscriber::fmt().with_env_filter("off,porthub_agent::media=debug").with_writer(std::io::stderr).try_init();
    let config=Config::load()?;
    let layout=config.layout();
    for directory in [&layout.state,&layout.releases,&layout.units]{crate::service::directory(directory,true)?;}
    if matches!(config.role,Role::Desktop) {
        ensure!(unsafe{libc::geteuid()}!=0,"Run the desktop proof as its real unprivileged user");
        let cancel=CancellationToken::new();
        let timer=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(stopped_owned(config.root.clone(),cancel.clone(),config.lifetime_seconds)));
        let id=config.registration.as_deref().context("Public registration identity required")?;
        tokio::select!{_=cancel.cancelled()=>{},result=super::host::run(layout,id.to_owned(),cancel.child_token())=>result?}
        cancel.cancel();drop(timer);return Ok(());
    }
    let profile=crate::profile::Profile::load(&config.profile)?;
    validate_private_profile(&profile)?;
    let id=crate::service::identity(&profile);
    let path=layout.state.join(format!("{id}.json"));
    let cancel=CancellationToken::new();
    let timer=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(stopped_owned(config.root.clone(),cancel.clone(),config.lifetime_seconds)));
    match config.role {
        Role::Desktop=>unreachable!(),
        Role::Agent=>{
            crate::profile::write_private(&path,&serde_json::to_vec(&profile)?,false)?;
            let spec=crate::service::Spec{user:true,identity:id.clone(),service:format!("porthub-{}",&id[..24]),profile:path.clone(),executable:layout.releases.join("a".repeat(64)).join("porthub"),unit:layout.units.join(format!("porthub-{}.service",&id[..24])),cli:None};
            crate::profile::write_private(&layout.state.join(format!("{id}.service.json")),&serde_json::to_vec(&spec)?,false)?;
            let status=crate::service::readable::directory(&layout)?;
            crate::service::directory(&status,false)?;
            let record=crate::service::readable::Record{format_version:1,id:id.clone(),machine_id:profile.machine_id.clone(),email:String::new(),gateway:profile.server.clone(),private:false,enabled:true,active:Some(true),state:"fixture".into(),agent_version:crate::VERSION.into(),ports:0,route:String::new(),updated_at:1,strategy:Default::default(),strategy_override:false,private_status:None};
            crate::service::atomic(&status.join(format!("{id}.json")),&serde_json::to_vec(&record)?,false)?;
            if config.receiver{super::config::set(&path,Some(porthub_components::media_forward::UsbIdentity{vendor:0x1209,product:1}))?;}
            let control=Arc::new(crate::control::Control::new(profile)?);
            let _broker=crate::exposure_broker::start_registered(&path,control.clone(),cancel.child_token(),&layout)?;
            let _worker=super::worker::start(path.clone(),control,cancel.child_token());
            crate::profile::write_private(&config.root.join("agent-ready.json"),&serde_json::to_vec(&serde_json::json!({"registration":id,"fixture":true}))?,true)?;
            let mut revoked=false;
            loop{tokio::select!{_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(100))=>{
                if !revoked&&config.root.join("revoke-microphone").exists(){
                    let work=async{let mut stream=crate::exposure_broker::connect_stream(&layout,&id).await?;stream.write_all(b"{\"operation\":\"client_features\",\"feature\":\"microphone-share\",\"enabled\":false}\n").await?;let mut bytes=Vec::new();BufReader::new(stream.take(16385)).read_until(b'\n',&mut bytes).await?;verify_revoked_reply(&bytes,&path)?;Ok::<_,anyhow::Error>(())};
                    tokio::time::timeout(Duration::from_secs(2),work).await??;revoked=true;
                }
            }}}
            cancel.cancel();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    cancel.cancel();drop(timer);Ok(())
}
async fn stopped_owned(root:PathBuf,cancel:CancellationToken,seconds:u64){stopped(&root,cancel,seconds).await}
#[test]
fn private_fixture_configuration_rejects_production_paths_and_unbounded_runs(){
    let root=PathBuf::from(format!("/tmp/porthub-native-media-e2e-{}","a".repeat(32)));
    let mut c=Config{profile:root.join("input-profile.json"),root,role:Role::Agent,registration:None,expected_direct_peer:"192.168.0.166".parse().unwrap(),lifetime_seconds:120,receiver:false};
    assert!(c.validate().is_ok());c.profile="/etc/porthub/native/real.json".into();assert!(c.validate().is_err());c.profile=c.root.join("input-profile.json");c.lifetime_seconds=181;assert!(c.validate().is_err());
}

#[tokio::test]
async fn revocation_proof_requires_the_real_disabled_policy_and_successful_reply()->Result<()> {
    let root=tempfile::tempdir()?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(root.path(),std::fs::Permissions::from_mode(0o700))?;
    let profile=root.path().join("fixture.json");
    let fake=b"{\"features\":[{\"feature\":\"microphone-share\",\"enabled\":false}]}\n";
    assert!(verify_revoked_reply(fake,&profile).is_err(),"A claimed reply cannot substitute for a real policy change");
    let(mut client,server)=tokio::io::duplex(16384);
    crate::features::serve(BufReader::new(server),&profile,serde_json::json!({"operation":"client_features","feature":"microphone-share","enabled":false})).await?;
    let mut bytes=Vec::new();BufReader::new((&mut client).take(16385)).read_until(b'\n',&mut bytes).await?;
    verify_revoked_reply(&bytes,&profile)?;
    assert!(verify_revoked_reply(b"{\"error\":\"denied\"}\n",&profile).is_err());
    assert!(verify_revoked_reply(b"{\"features\":[]}\n",&profile).is_err());
    assert!(verify_revoked_reply(&vec![b'x';16385],&profile).is_err());
    Ok(())
}

#[test]
fn private_fixture_never_uses_a_production_gateway_or_fallback() {
    let mut profile:crate::profile::Profile=serde_json::from_value(serde_json::json!({"server":"http://127.0.0.1:50001","machine_id":"a".repeat(24),"token":"private-fixture-only","allow_insecure_http_for_tests":true})).unwrap();
    assert!(validate_private_profile(&profile).is_ok());
    profile.fallback_servers.push("https://production.invalid".into());assert!(validate_private_profile(&profile).is_err());profile.fallback_servers.clear();
    profile.server="https://production.invalid".into();assert!(validate_private_profile(&profile).is_err());
}

#[test]
fn database_plans_cannot_bypass_the_private_local_hardware_gate()->Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root=tempfile::tempdir()?;std::fs::set_permissions(root.path(),std::fs::Permissions::from_mode(0o700))?;
    assert!(require_native_plan_approval(root.path()).is_err());
    crate::profile::write_private(&root.path().join("allow-native-plan"),b"not-approved\n",false)?;
    assert!(require_native_plan_approval(root.path()).is_err());
    crate::profile::write_private(&root.path().join("allow-native-plan"),b"root-approved-native-media-v1\n",true)?;
    require_native_plan_approval(root.path())?;Ok(())
}
