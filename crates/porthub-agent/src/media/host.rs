//! Desktop sibling task. It retains no enrollment credentials and captures only
//! sources explicitly requested through the OS-authenticated installed agent.
use super::{host_wire, session::Session};
use crate::features::{self, Feature};
use anyhow::{ensure, Context, Result};
use porthub_components::{
    media::{Device, Kind, LocalInventory, Operation, SessionRequest},
    media_store::{Manager, Manifest},
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;
async fn send<W: tokio::io::AsyncWrite + Unpin>(
    writer: &Arc<Mutex<W>>,
    value: &Value,
) -> Result<()> {
    // Control replies must not queue behind stalled PCM writers and prevent
    // the desktop reader from processing a policy revocation. A failed control
    // write drops the connection and cancels its independently supervised
    // capture children.
    tokio::time::timeout(Duration::from_millis(100), async {
        host_wire::json(&mut *writer.lock().await, value).await
    })
    .await
    .context("Media control writer is unresponsive")?
}
fn preferences() -> Result<PathBuf> {
    let root = crate::components::state_directory()?.join("media");
    crate::service::directory(&root, true)?;
    Ok(root.join("desktop-media.json"))
}
fn required(kind: Kind) -> Feature {
    match kind {
        Kind::Microphone => Feature::MicrophoneShare,
        Kind::Camera => Feature::CameraShare,
        Kind::Speaker => Feature::MediaReceive,
    }
}
fn permitted(profile: &Path, kind: Kind) -> bool {
    features::load(profile).is_ok_and(|p| p.enabled(required(kind)))
}
#[derive(Clone, Copy)]
struct Allowed {
    microphone: bool,
    camera: bool,
    speaker: bool,
}
impl Allowed {
    fn read(value: &Value) -> Self {
        Self {
            microphone: value["microphone"] == true,
            camera: value["camera"] == true,
            speaker: value["speaker"] == true,
        }
    }
    fn kind(self, kind: Kind) -> bool {
        match kind {
            Kind::Microphone => self.microphone,
            Kind::Camera => self.camera,
            Kind::Speaker => self.speaker,
        }
    }
    fn any(self, own: &Path) -> bool {
        [Kind::Microphone, Kind::Camera, Kind::Speaker]
            .into_iter()
            .any(|kind| self.kind(kind) && permitted(own, kind))
    }
}
fn retire(
    active: &HashMap<String, CancellationToken>,
    kinds: &HashMap<String, Kind>,
    allowed: Allowed,
    own: &Path,
) {
    for (id, stop) in active {
        if kinds
            .get(id)
            .is_none_or(|kind| !allowed.kind(*kind) || !permitted(own, *kind))
        {
            stop.cancel();
        }
    }
}
async fn inventory(
    manager: &Manager,
    manifest: &Manifest,
    cancel: &CancellationToken,
) -> Result<LocalInventory> {
    let binary = manager.ensure(manifest, cancel).await?;
    #[cfg(target_os = "linux")]
    let uid = unsafe { libc::geteuid() };
    #[cfg(target_os = "linux")]
    ensure!(uid != 0, "Use the unprivileged desktop media session");
    #[cfg(windows)]
    let _desktop = super::windows_host::current()?;
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("inventory-local")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(target_os = "linux")]
    command.env("XDG_RUNTIME_DIR", format!("/run/user/{uid}"));
    #[cfg(windows)]
    super::windows_host::configure_command(&mut command)?;
    #[cfg(target_os = "linux")]
    if let Some(base) = directories::BaseDirs::new() {
        command.env("HOME", base.home_dir());
    }
    let mut child = command
        .spawn()
        .context("Native media adapter cannot start")?;
    let output = child
        .stdout
        .take()
        .context("Native media inventory output unavailable")?;
    let mut bytes = Vec::new();
    tokio::select! {biased;_=cancel.cancelled()=>anyhow::bail!("Media discovery cancelled"),result=tokio::time::timeout(Duration::from_secs(5),async{output.take(128*1024+1).read_to_end(&mut bytes).await?;ensure!(bytes.len()<=128*1024,"Media inventory exceeds bound");ensure!(child.wait().await?.success(),"Native media inventory unavailable");Ok::<_,anyhow::Error>(())})=>result??}
    let inventory: LocalInventory =
        serde_json::from_slice(&bytes).context("Invalid local native inventory")?;
    ensure!(inventory.valid(), "Invalid local source identity");
    let mut ids = std::collections::HashSet::new();
    ensure!(
        inventory
            .sources
            .iter()
            .all(|s| ids.insert(s.device.id.clone())),
        "Ambiguous native source identity"
    );
    Ok(inventory)
}
fn visible(sources: &LocalInventory, own: &Path, allowed: Allowed) -> Vec<Device> {
    sources
        .sources
        .iter()
        .filter(|source| {
            allowed.kind(source.device.kind)
                && permitted(own, source.device.kind)
                && !source
                    .device
                    .unavailable_reason
                    .as_deref()
                    .is_some_and(|s| s.starts_with("Ambiguous"))
        })
        .map(|source| source.device.clone())
        .collect()
}
fn inventory_message(
    cache: &LocalInventory,
    own: &Path,
    allowed: Allowed,
    request: Option<&str>,
) -> Value {
    let mut value = json!({"type":"inventory","devices":visible(cache,own,allowed),"microphone_unavailable_reason":cache.microphone_unavailable_reason,"camera_unavailable_reason":cache.camera_unavailable_reason,"speaker_unavailable_reason":cache.speaker_unavailable_reason});
    for (kind, key) in [
        (Kind::Microphone, "microphone_unavailable_reason"),
        (Kind::Camera, "camera_unavailable_reason"),
        (Kind::Speaker, "speaker_unavailable_reason"),
    ] {
        if !allowed.kind(kind) {
            value[key] = json!("Source sharing is disabled by this client");
        } else if !permitted(own, kind) {
            value[key] = json!("Source sharing is disabled by the desktop user");
        }
    }

    if let Some(request) = request {
        value["request"] = json!(request);
    }
    value
}
/// Existing GUI worker owns this task; there is no additional resident daemon.
pub(crate) async fn run(
    layout: crate::service::Layout,
    registration: String,
    cancel: CancellationToken,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "Media user host cannot impersonate a desktop from the system agent"
    );
    #[cfg(windows)]
    let _desktop = super::windows_host::current()?;
    let own = preferences()?;
    let gateway = crate::service::readable::list(&layout)?
        .into_iter()
        .find(|r| r.id == registration)
        .context("Registered media gateway unavailable")?
        .gateway;
    let manager = Arc::new(crate::components::media_manager(Some(&gateway))?);
    let mut cache = LocalInventory::default();
    // Startup never refreshes/downloads. A cached, verified adapter is queried once.
    if manager.cached_executable()?.is_some() {
        if let Some(manifest) = manager.cached()? {
            cache = inventory(&manager, &manifest, &cancel)
                .await
                .unwrap_or_default();
        }
    }
    loop {
        if cancel.is_cancelled() {
            return Ok(());
        }
        if let Err(error) = connection(
            &layout,
            &registration,
            &own,
            manager.clone(),
            &mut cache,
            cancel.child_token(),
        )
        .await
        {
            tracing::debug!(reason=%error,"Media desktop connection unavailable");
        }
        tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(5))=>{}}
    }
}
async fn connection(
    layout: &crate::service::Layout,
    registration: &str,
    own: &Path,
    manager: Arc<Manager>,
    cache: &mut LocalInventory,
    cancel: CancellationToken,
) -> Result<()> {
    let mut stream = crate::exposure_broker::connect_stream(layout, registration).await?;
    stream
        .write_all(b"{\"operation\":\"media_host\"}\n")
        .await?;
    let (read, write) = tokio::io::split(stream);
    let mut read = host_wire::Reader::new(read);
    let writer = Arc::new(Mutex::new(write));
    let hello = tokio::time::timeout(Duration::from_secs(5), read.next()).await??;
    let hello: Value = serde_json::from_slice(&hello)?;
    #[cfg(target_os = "linux")]
    ensure!(
        hello["type"] == "policy"
            && hello["uid"].as_u64() == Some(unsafe { libc::geteuid() } as u64),
        "Installed media broker did not authenticate this desktop user"
    );
    #[cfg(windows)]
    super::windows_host::validate_policy(&hello)?;
    let mut root_allowed = Allowed::read(&hello);
    send(&writer, &inventory_message(cache, own, root_allowed, None)).await?;
    let mut active = HashMap::<String, CancellationToken>::new();
    let mut playback_inputs = HashMap::<String, tokio::sync::mpsc::Sender<Vec<u8>>>::new();
    let mut active_sources = HashMap::<String, String>::new();
    let mut active_kinds = HashMap::<String, Kind>::new();
    let mut own_policy = features::subscribe(own);
    let mut jobs = tokio::task::JoinSet::new();
    let mut discoveries = tokio::task::JoinSet::<(String, Result<LocalInventory>)>::new();
    let mut discovery_request: Option<String> = None;
    let connection = cancel.child_token();
    let _closed = CancelOnDrop(connection.clone());
    loop {
        tokio::select! {biased;
            _=cancel.cancelled()=>break,
            changed=own_policy.changed()=>{if changed.is_err(){break;}retire(&active,&active_kinds,root_allowed,own);send(&writer,&inventory_message(cache,own,root_allowed,None)).await?;},
            done=jobs.join_next(),if !jobs.is_empty()=>{if let Some(Ok((id,outcome)))=done{active.remove(&id);playback_inputs.remove(&id);active_kinds.remove(&id);if let Some(source)=active_sources.remove(&id){if matches!(outcome,2|3){if let Some(device)=cache.sources.iter_mut().map(|s|&mut s.device).find(|d|d.id==source){device.capture_available=false;device.capture_state=if outcome==3{porthub_components::media::CaptureState::Unsupported}else{porthub_components::media::CaptureState::Denied};device.unavailable_reason=Some(if outcome==3{super::session::CaptureUnsupported.to_string()}else{super::session::CaptureDenied(device.kind).to_string()});}}}send(&writer,&json!({"type":match outcome{3=>"unsupported",2=>"denied",1=>"error",_=>"stopped"},"session":id})).await?;}},
            done=discoveries.join_next(),if !discoveries.is_empty()=>{
                if let Some(Ok((request,result)))=done {
                    if discovery_request.as_deref()!=Some(request.as_str()){continue;}
                    discovery_request=None;
                    match result {
                        Ok(devices) if root_allowed.any(own)=>{*cache=devices;send(&writer,&inventory_message(cache,own,root_allowed,Some(&request))).await?;},
                        _=>send(&writer,&json!({"type":"error","request":request})).await?,
                    }
                }
            },
            bytes=read.next()=>{
                let bytes=bytes?;
                if bytes.first()==Some(&0)&&bytes.len()>=33 {let id=std::str::from_utf8(&bytes[1..33])?;let frame=host_wire::parse_pcm(&bytes,id).context("Invalid speaker PCM")?;if let Some(tx)=playback_inputs.get(id){let _=super::playback::enqueue_pcm(tx,frame.pcm)?;}continue;}
                let value:Value=serde_json::from_slice(&bytes)?;
                match value["type"].as_str(){
                    Some("policy")=>{
                        #[cfg(windows)] super::windows_host::validate_policy(&value)?;
                        root_allowed=Allowed::read(&value);retire(&active,&active_kinds,root_allowed,own);if !root_allowed.any(own){discoveries.abort_all();if let Some(request)=discovery_request.take(){send(&writer,&json!({"type":"error","request":request})).await?;}}send(&writer,&inventory_message(cache,own,root_allowed,None)).await?;},
                    Some("discover")=>{
                        ensure!(root_allowed.any(own),"Native media sharing disabled by client or user policy");let request=value["request"].as_str().context("Missing discovery identity")?.to_owned();ensure!(request.len()==32,"Invalid discovery identity");
                        if discovery_request.is_some(){send(&writer,&json!({"type":"error","request":request})).await?;continue;}
                        discovery_request=Some(request.clone());
                        let manager=manager.clone();let stop=connection.child_token();
                        discoveries.spawn(async move {
                            let result=async{let manifest=manager.refresh(&stop).await?;inventory(&manager,&manifest,&stop).await}.await;
                            (request,result)
                        });
                    },
                    Some("capture-playback")|Some("render-playback")=>{
                        let render=value["type"]=="render-playback";let id=value["session"].as_str().context("Missing speaker session")?.to_owned();
                        ensure!(id.len()==32&&id.bytes().all(|v|v.is_ascii_hexdigit())&&!active.contains_key(&id)&&active.len()<4,"Invalid speaker session");
                        ensure!(root_allowed.kind(Kind::Speaker)&&permitted(own,Kind::Speaker),"Speaker forwarding disabled by user policy");
                        let source=value["source"].as_str().unwrap_or("");let selected=if !render{Some(visible(cache,own,root_allowed).into_iter().find(|d|d.id==source&&d.kind==Kind::Speaker&&d.can_request_capture()).context("Exact selected speaker unavailable")?)}else{None};
                        let manifest=manager.cached()?.context("No verified audio helper")?;let stop=connection.child_token();active.insert(id.clone(),stop.clone());active_kinds.insert(id.clone(),Kind::Speaker);
                        let(tx,mut rx)=tokio::sync::mpsc::channel::<Vec<u8>>(4);if render{playback_inputs.insert(id.clone(),tx);}
                        let manager=manager.clone();let own=own.to_owned();let writer=writer.clone();
                        jobs.spawn(async move{let result=async{let mut session=Session::spawn_local(&own,SessionRequest{operation:if render{Operation::RenderPlayback}else{Operation::CapturePlayback},session:id.clone(),name:"PortHub speaker forwarding".into(),source_id:selected.map(|d|d.id),video_format:None,camera_identity:None},&manager,&manifest,&stop).await?;
                        send(&writer,&json!({"type":"started","session":id})).await?;
                        let mut continuity=porthub_components::media::PcmContinuity::default();
                        loop{tokio::select!{biased;_=stop.cancelled()=>break,
                         frame=rx.recv(),if render=>{let Some(mut frame)=frame else{break;};let result=session.write_pcm(&frame).await;frame.fill(0);result?;},
                         frame=session.read_network_frame(),if !render=>{let mut frame=frame?;ensure!(continuity.accept(&frame),"Playback capture discontinuity");let mut bytes=host_wire::pcm(&id,&frame).context("Invalid captured playback PCM")?;frame.pcm.fill(0);let result=host_wire::write(&mut *writer.lock().await,&bytes).await;bytes.fill(0);result?;}
                        }}Ok::<(),anyhow::Error>(())}.await;(id,if result.is_err(){1}else{0})});
                    },
                    Some("capture")|Some("capture-camera")=>{
                        let kind=if value["type"]=="capture-camera"{Kind::Camera}else{Kind::Microphone};
                        let id=value["session"].as_str().context("Missing media session identity")?.to_owned();let source=value["source"].as_str().context("Missing explicit source")?;
                        ensure!(id.len()==32&&id.bytes().all(|v|v.is_ascii_hexdigit())&&!active.contains_key(&id)&&active.len()<4,"Invalid or busy media session");
                        if !root_allowed.kind(kind)||!permitted(own,kind){send(&writer,&json!({"type":"error","session":id})).await?;continue;}
                        let device=visible(cache,own,root_allowed).into_iter().find(|d|d.id==source&&d.kind==kind).context("Requested source is not registered for this user")?;
                        ensure!(device.can_request_capture(),"Selected native source is unsupported or permission denied");
                        let camera_identity=cache.sources.iter().find(|source|source.device.id==device.id).and_then(|source|source.camera_identity.clone());
                        active_sources.insert(id.clone(),device.id.clone());active_kinds.insert(id.clone(),kind);
                        let manifest=manager.cached()?.context("No verified media manifest")?;
                        let stop=connection.child_token();active.insert(id.clone(),stop.clone());let writer=writer.clone();let manager=manager.clone();let own=own.to_owned();
                        jobs.spawn(async move{
                            let result=async{
                                let camera=kind==Kind::Camera;let mut capture=Session::spawn_local(&own,SessionRequest{operation:if camera{Operation::CaptureCamera}else{Operation::CaptureMicrophone},session:id.clone(),name:device.name,source_id:Some(device.id),video_format:if camera{Some(porthub_components::media::VideoFormat::baseline_mjpeg())}else{None},camera_identity:if camera{camera_identity}else{None}},&manager,&manifest,&stop).await?;
                                send(&writer,&json!({"type":"started","session":id})).await?;
                                if camera {loop{tokio::select!{biased;_=stop.cancelled()=>break,frame=capture.read_video_frame()=>{let mut frame=frame?;let mut bytes=host_wire::video(&id,&frame).context("Invalid native camera frame")?;frame.jpeg.fill(0);let result=host_wire::write_camera(&mut *writer.lock().await,&bytes).await;bytes.fill(0);result?;}}}}else{loop {tokio::select!{biased;_=stop.cancelled()=>break,frame=capture.read_network_frame()=>{let frame=frame?;let bytes=host_wire::pcm(&id,&frame).context("Invalid native PCM frame")?;host_wire::write(&mut *writer.lock().await,&bytes).await?;}}}}
                                Ok::<_,anyhow::Error>(())
                            }.await;
                            let outcome=if result.as_ref().err().is_some_and(|e|e.is::<super::session::CaptureUnsupported>()){3}else if result.as_ref().err().is_some_and(|e|e.is::<super::session::CaptureDenied>()){2}else if result.is_err(){1}else{0};
                            (id,outcome)
                        });
                    },
                    Some("stop")=>{if let Some(id)=value["session"].as_str(){if let Some(stop)=active.get(id){stop.cancel();}}},
                    _=>anyhow::bail!("Invalid installed media broker command"),
                }
            }
        }
    }
    connection.cancel();
    jobs.abort_all();
    discoveries.abort_all();
    Ok(())
}
struct CancelOnDrop(CancellationToken);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(test)]
mod control_tests {
    use super::*;

    #[tokio::test]
    async fn stalled_pcm_writer_cannot_hold_control_reader_indefinitely() -> Result<()> {
        let (stream, _peer) = tokio::io::duplex(64);
        let writer = Arc::new(Mutex::new(stream));
        let held_by_pcm = writer.lock().await;
        let stopped = CancellationToken::new();
        let child = stopped.child_token();
        let outcome = {
            let _connection = CancelOnDrop(stopped);
            tokio::time::timeout(
                Duration::from_secs(1),
                send(&writer, &json!({"type":"stopped","session":"fixture"})),
            )
            .await?
        };
        assert!(outcome.is_err());
        assert!(
            child.is_cancelled(),
            "Failed control delivery retires capture children"
        );
        drop(held_by_pcm);
        Ok(())
    }
}
