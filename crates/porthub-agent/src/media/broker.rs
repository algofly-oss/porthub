//! Credential-free desktop media channel, entered only after native caller authorization.
use super::host_wire;
use crate::features::{self, Feature};
use anyhow::{ensure, Context, Result};
use porthub_components::media::{Device, Kind, PcmContinuity, PcmFrame};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader},
    sync::{mpsc, oneshot, Notify},
};
use tokio_util::sync::CancellationToken;
#[derive(Clone)]
pub struct Source {
    pub uid: u32,
    pub desktop_session: Option<String>,
    pub device: Device,
}
struct Queue {
    frames: VecDeque<PcmFrame>,
    bytes: usize,
    closed: bool,
}
struct Frames {
    queue: Mutex<Queue>,
    notify: Notify,
}
impl Frames {
    fn new() -> Self {
        Self {
            queue: Mutex::new(Queue {
                frames: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            notify: Notify::new(),
        }
    }
    fn push(&self, frame: PcmFrame) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if q.closed {
            return;
        }
        while q.bytes + frame.pcm.len() > 19200 {
            if let Some(mut old) = q.frames.pop_front() {
                q.bytes -= old.pcm.len();
                old.pcm.fill(0);
            } else {
                break;
            }
        }
        q.bytes += frame.pcm.len();
        q.frames.push_back(frame);
        self.notify.notify_one();
    }
    fn close(&self) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        for f in &mut q.frames {
            f.pcm.fill(0);
        }
        q.frames.clear();
        q.bytes = 0;
        q.closed = true;
        self.notify.notify_one();
    }
}
pub struct Capture {
    frames: Arc<Frames>,
    stop: CancellationToken,
    permissions: tokio::sync::watch::Receiver<features::Policy>,
}
impl Capture {
    pub async fn next(&mut self) -> Result<PcmFrame> {
        loop {
            if !self.permissions.borrow().enabled(Feature::MicrophoneShare)
                || self.stop.is_cancelled()
            {
                self.frames.close();
                anyhow::bail!("Media capture permission revoked or session closed");
            }
            let notified = self.frames.notify.notified();
            {
                let mut queue = self.frames.queue.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(frame) = queue.frames.pop_front() {
                    queue.bytes -= frame.pcm.len();
                    return Ok(frame);
                }
                ensure!(!queue.closed, "Media user capture closed");
            }
            tokio::select! {biased;_=self.stop.cancelled()=>{},changed=self.permissions.changed()=>{if changed.is_err(){self.frames.close();anyhow::bail!("Media policy authority closed");}},_=notified=>{}}
        }
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        self.stop.cancel();
        self.frames.close();
    }
}
struct VideoQueue {
    frame: Option<porthub_components::media::VideoFrame>,
    closed: bool,
}
struct VideoFrames {
    queue: Mutex<VideoQueue>,
    notify: Notify,
}
impl VideoFrames {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VideoQueue {
                frame: None,
                closed: false,
            }),
            notify: Notify::new(),
        }
    }
    fn push(&self, mut frame: porthub_components::media::VideoFrame) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if q.closed {
            frame.jpeg.fill(0);
            return;
        }
        if let Some(mut old) = q.frame.replace(frame) {
            old.jpeg.fill(0);
        }
        self.notify.notify_one();
    }
    fn close(&self) {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut frame) = q.frame.take() {
            frame.jpeg.fill(0);
        }
        q.closed = true;
        self.notify.notify_one();
    }
}
pub struct CameraCapture {
    frames: Arc<VideoFrames>,
    stop: CancellationToken,
    permissions: tokio::sync::watch::Receiver<features::Policy>,
}
impl CameraCapture {
    pub async fn next(&mut self) -> Result<porthub_components::media::VideoFrame> {
        loop {
            if !self.permissions.borrow().enabled(Feature::CameraShare) || self.stop.is_cancelled()
            {
                self.frames.close();
                anyhow::bail!("Camera policy revoked or session closed");
            }
            let notified = self.frames.notify.notified();
            {
                let mut q = self.frames.queue.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(frame) = q.frame.take() {
                    return Ok(frame);
                }
                ensure!(!q.closed, "Camera user capture closed");
            }
            tokio::select! {biased;_=self.stop.cancelled()=>{},r=self.permissions.changed()=>{if r.is_err(){self.frames.close();anyhow::bail!("Camera policy authority closed");}},_=notified=>{}}
        }
    }
}
impl Drop for CameraCapture {
    fn drop(&mut self) {
        self.stop.cancel();
        self.frames.close();
    }
}
fn required(kind: Kind) -> Feature {
    match kind {
        Kind::Microphone => Feature::MicrophoneShare,
        Kind::Camera => Feature::CameraShare,
        Kind::Speaker => Feature::MediaReceive,
    }
}
enum Call {
    Playback {
        render: bool,
        source: String,
        reply: oneshot::Sender<Result<tokio::io::DuplexStream>>,
        stop: CancellationToken,
    },
    Camera {
        uid: u32,
        source: String,
        reply: oneshot::Sender<Result<CameraCapture>>,
        stop: CancellationToken,
    },
    Discover(oneshot::Sender<Result<Vec<Source>>>),
    Capture {
        uid: u32,
        source: String,
        reply: oneshot::Sender<Result<Capture>>,
        stop: CancellationToken,
    },
}
#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct Availability {
    #[serde(default)]
    pub speaker_unavailable_reason: Option<String>,
    pub microphone_unavailable_reason: Option<String>,
    pub camera_unavailable_reason: Option<String>,
}
fn decode_availability(value: &Value) -> Result<Availability> {
    let a = Availability {
        speaker_unavailable_reason:value.get("speaker_unavailable_reason").filter(|v|!v.is_null()).map(|v|v.as_str().map(str::to_owned).context("Invalid speaker reason")).transpose()?,
        microphone_unavailable_reason: value
            .get("microphone_unavailable_reason")
            .filter(|v| !v.is_null())
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .context("Invalid microphone reason")
            })
            .transpose()?,
        camera_unavailable_reason: value
            .get("camera_unavailable_reason")
            .filter(|v| !v.is_null())
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .context("Invalid camera reason")
            })
            .transpose()?,
    };
    ensure!(
        [
            &a.speaker_unavailable_reason,
            &a.microphone_unavailable_reason,
            &a.camera_unavailable_reason
        ]
        .iter()
        .all(|v| v
            .as_ref()
            .is_none_or(|s| s.len() <= 512 && !s.chars().any(char::is_control))),
        "Invalid source availability reason"
    );
    Ok(a)
}
pub fn availability(profile: &Path) -> Availability {
    hosts()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(profile)
        .map(|h| {
            h.availability
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        })
        .unwrap_or_else(|| Availability {
            speaker_unavailable_reason:Some("No authorized desktop audio session".into()),
            microphone_unavailable_reason: Some(
                "No authorized desktop source session is connected".into(),
            ),
            camera_unavailable_reason: Some(
                "No authorized desktop source session is connected".into(),
            ),
        })
}
struct Host {
    availability: Arc<Mutex<Availability>>,
    identity: String,
    uid: u32,
    desktop_session: Option<String>,
    sources: Arc<Mutex<Vec<Device>>>,
    calls: mpsc::Sender<Call>,
}
fn hosts() -> &'static Mutex<HashMap<PathBuf, Host>> {
    static HOSTS: OnceLock<Mutex<HashMap<PathBuf, Host>>> = OnceLock::new();
    HOSTS.get_or_init(Mutex::default)
}
fn policy(profile: &Path) -> features::Policy {
    features::subscribe(profile).borrow().clone()
}
fn media_policy(
    profile: &Path,
    uid: u32,
    desktop_session: Option<&str>,
    desktop_proof: Option<&str>,
) -> Value {
    let p = policy(profile);
    json!({"type":"policy","uid":uid,"desktop_session":desktop_session,"desktop_proof":desktop_proof,"microphone":p.enabled(Feature::MicrophoneShare),"camera":p.enabled(Feature::CameraShare),"speaker":p.enabled(Feature::MediaReceive),"receive":p.enabled(Feature::MediaReceive)})
}
fn decode_devices(value: &Value) -> Result<Vec<Device>> {
    let rows: Vec<Device> = serde_json::from_value(value["devices"].clone())
        .context("Invalid media source inventory")?;
    ensure!(
        rows.len() <= 64 && rows.iter().all(Device::valid),
        "Invalid media source inventory"
    );
    let mut ids = std::collections::HashSet::new();
    ensure!(
        rows.iter().all(|d| ids.insert(d.id.clone())),
        "Duplicate media source identity"
    );
    Ok(rows)
}
pub(crate) fn connected(profile: &Path) -> bool {
    hosts()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(profile)
}
pub fn inventory(profile: &Path) -> Vec<Source> {
    let allowed = policy(profile);
    let registry = hosts().lock().unwrap_or_else(|e| e.into_inner());
    registry
        .get(profile)
        .map(|h| {
            h.sources
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|d| allowed.enabled(required(d.kind)))
                .cloned()
                .map(|device| Source {
                    uid: h.uid,
                    desktop_session: h.desktop_session.clone(),
                    device,
                })
                .collect()
        })
        .unwrap_or_default()
}
pub async fn discover(profile: &Path) -> Result<Vec<Source>> {
    ensure!(
        policy(profile).enabled(Feature::MicrophoneShare)
            || policy(profile).enabled(Feature::CameraShare)
            || policy(profile).enabled(Feature::MediaReceive),
        "Native media sharing disabled locally"
    );
    let calls = hosts()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(profile)
        .map(|h| h.calls.clone())
        .context("No authorized desktop media session is connected")?;
    let (tx, rx) = oneshot::channel();
    calls
        .try_send(Call::Discover(tx))
        .map_err(|_| anyhow::anyhow!("Media user host is busy"))?;
    tokio::time::timeout(Duration::from_secs(60), rx)
        .await
        .context("Media source discovery timed out")??
}
pub async fn capture(
    profile: &Path,
    uid: u32,
    source: &str,
    parent: &CancellationToken,
) -> Result<Capture> {
    capture_session(profile, uid, None, source, parent).await
}
pub async fn capture_session(
    profile: &Path,
    uid: u32,
    desktop_session: Option<&str>,
    source: &str,
    parent: &CancellationToken,
) -> Result<Capture> {
    ensure!(
        porthub_components::media_forward::valid_desktop(uid, desktop_session),
        "Invalid desktop media principal"
    );
    ensure!(
        policy(profile).enabled(Feature::MicrophoneShare),
        "Microphone sharing disabled locally"
    );
    let calls = {
        let registry = hosts().lock().unwrap_or_else(|e| e.into_inner());
        let h = registry
            .get(profile)
            .context("No authorized desktop media session is connected")?;
        ensure!(
            h.uid == uid
                && h.desktop_session.as_deref() == desktop_session
                && h.sources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|d| d.id == source
                        && d.kind == Kind::Microphone
                        && d.can_request_capture()),
            "Selected source does not belong to the authorized user session"
        );
        h.calls.clone()
    };
    let stop = parent.child_token();
    let (tx, rx) = oneshot::channel();
    calls
        .try_send(Call::Capture {
            uid,
            source: source.into(),
            reply: tx,
            stop: stop.clone(),
        })
        .map_err(|_| anyhow::anyhow!("Media user host is busy"))?;
    let result = tokio::select! {biased;_=parent.cancelled()=>Err(anyhow::anyhow!("Media capture cancelled")),r=tokio::time::timeout(Duration::from_secs(10),rx)=>match r{Ok(Ok(result))=>result,_=>Err(anyhow::anyhow!("Media user capture did not become ready"))}};
    if result.is_err() {
        stop.cancel();
    }
    result
}
pub async fn capture_camera_session(
    profile: &Path,
    uid: u32,
    desktop_session: Option<&str>,
    source: &str,
    parent: &CancellationToken,
) -> Result<CameraCapture> {
    ensure!(
        porthub_components::media_forward::valid_desktop(uid, desktop_session)
            && policy(profile).enabled(Feature::CameraShare),
        "Camera principal or local permission unavailable"
    );
    let calls = {
        let registry = hosts().lock().unwrap_or_else(|e| e.into_inner());
        let host = registry
            .get(profile)
            .context("No authorized desktop camera session")?;
        ensure!(
            host.uid == uid
                && host.desktop_session.as_deref() == desktop_session
                && host
                    .sources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|d| d.id == source && d.kind == Kind::Camera && d.can_request_capture()),
            "Camera does not belong to the selected user session"
        );
        host.calls.clone()
    };
    let stop = parent.child_token();
    let (tx, rx) = oneshot::channel();
    calls
        .try_send(Call::Camera {
            uid,
            source: source.into(),
            reply: tx,
            stop: stop.clone(),
        })
        .map_err(|_| anyhow::anyhow!("Camera host busy"))?;
    let result = tokio::select! {biased;_=parent.cancelled()=>Err(anyhow::anyhow!("Camera capture cancelled")),result=tokio::time::timeout(Duration::from_secs(10),rx)=>match result{Ok(Ok(v))=>v,_=>Err(anyhow::anyhow!("Camera user capture did not become ready"))}};
    if result.is_err() {
        stop.cancel();
    }
    result
}
/// Only an OS-authenticated connected desktop can open playback. Remote plans
/// select the source output monitor; rendering uses the destination desktop.
pub async fn playback(
    profile: &Path,
    principal: Option<(u32, Option<&str>)>,
    source: &str,
    render: bool,
    parent: &CancellationToken,
) -> Result<tokio::io::DuplexStream> {
    ensure!(
        policy(profile).enabled(Feature::MediaReceive),
        "Speaker forwarding disabled locally"
    );
    let calls = {
        let registry = hosts().lock().unwrap_or_else(|e| e.into_inner());
        let h = registry
            .get(profile)
            .context("No authenticated desktop audio host")?;
        ensure!(h.sources.lock().unwrap_or_else(|e|e.into_inner()).iter().any(|d|d.kind==Kind::Speaker&&d.can_request_capture()),"Desktop helper does not support playback");
        if let Some((uid, session)) = principal {
            ensure!(
                h.uid == uid && h.desktop_session.as_deref() == session,
                "Speaker desktop principal changed"
            );
        }
        if !render {
            ensure!(
                h.sources
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|d| d.id == source && d.kind == Kind::Speaker && d.can_request_capture()),
                "Selected speaker is unavailable"
            );
        }
        h.calls.clone()
    };
    let (tx, rx) = oneshot::channel();
    let stop = parent.child_token();
    calls
        .try_send(Call::Playback {
            render,
            source: source.into(),
            reply: tx,
            stop: stop.clone(),
        })
        .map_err(|_| anyhow::anyhow!("Desktop audio host busy"))?;
    let result = tokio::select! {biased;_=parent.cancelled()=>Err(anyhow::anyhow!("Speaker session cancelled")),r=tokio::time::timeout(Duration::from_secs(10),rx)=>match r{Ok(Ok(r))=>r,_=>Err(anyhow::anyhow!("Speaker desktop did not become ready"))}};
    if result.is_err() {
        stop.cancel();
    }
    result
}
struct Playback {
    stream: Option<tokio::io::DuplexStream>,
    reply: Option<oneshot::Sender<Result<tokio::io::DuplexStream>>>,
    incoming: mpsc::Sender<Vec<u8>>,
    stop: CancellationToken,
}
impl Drop for Playback {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
struct Active {
    kind: Kind,
    camera_frames: Option<Arc<VideoFrames>>,
    camera_ready: Option<oneshot::Sender<Result<CameraCapture>>>,
    video_next: u64,
    video_timestamp: Option<u64>,
    frames: Arc<Frames>,
    stop: CancellationToken,
    ready: Option<oneshot::Sender<Result<Capture>>>,
    continuity: PcmContinuity,
    source: String,
}
impl Drop for Active {
    fn drop(&mut self) {
        self.stop.cancel();
        self.frames.close();
        if let Some(frames) = &self.camera_frames {
            frames.close();
        }
    }
}
struct Guard {
    profile: PathBuf,
    identity: String,
}
impl Drop for Guard {
    fn drop(&mut self) {
        let mut registry = hosts().lock().unwrap_or_else(|e| e.into_inner());
        if registry
            .get(&self.profile)
            .is_some_and(|h| h.identity == self.identity)
        {
            registry.remove(&self.profile);
        }
    }
}
fn nonce() -> Result<String> {
    let mut b = [0; 16];
    getrandom::fill(&mut b)?;
    Ok(b.iter().map(|b| format!("{b:02x}")).collect())
}
/// uid must come from the OS peer credentials, never from a request field.
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    reader: BufReader<S>,
    profile: PathBuf,
    uid: u32,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        uid > 0,
        "Run the media user host in an authenticated unprivileged desktop session"
    );
    serve_identity(reader, profile, uid, None, None, cancel).await
}
#[cfg(windows)]
pub(crate) async fn serve_windows<S: AsyncRead + AsyncWrite + Unpin>(
    reader: BufReader<S>,
    profile: PathBuf,
    identity: super::windows_host::PeerIdentity,
    cancel: CancellationToken,
) -> Result<()> {
    let principal = identity.desktop_session().to_owned();
    let proof = identity.connection_proof().to_owned();
    serve_identity(reader, profile, 0, Some(principal), Some(proof), cancel).await
}
async fn serve_identity<S: AsyncRead + AsyncWrite + Unpin>(
    reader: BufReader<S>,
    profile: PathBuf,
    uid: u32,
    desktop_session: Option<String>,
    desktop_proof: Option<String>,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        porthub_components::media_forward::valid_desktop(uid, desktop_session.as_deref()),
        "Invalid authenticated media principal"
    );
    let (read, mut write) = tokio::io::split(reader);
    let mut read = host_wire::Reader::camera(read);
    host_wire::json(
        &mut write,
        &media_policy(
            &profile,
            uid,
            desktop_session.as_deref(),
            desktop_proof.as_deref(),
        ),
    )
    .await?;
    let initial = tokio::time::timeout(Duration::from_secs(5), read.next()).await??;
    let initial: Value = serde_json::from_slice(&initial)?;
    ensure!(
        initial["type"] == "inventory",
        "Media host did not register inventory"
    );
    let devices = decode_devices(&initial)?;
    let availability = Arc::new(Mutex::new(decode_availability(&initial)?));
    let sources = Arc::new(Mutex::new(devices));
    let (tx, mut calls) = mpsc::channel(4);
    let identity = nonce()?;
    {
        let mut registry = hosts().lock().unwrap_or_else(|e| e.into_inner());
        ensure!(
            !registry.contains_key(&profile),
            "A media user session is already connected for this registration"
        );
        registry.insert(
            profile.clone(),
            Host {
                availability: availability.clone(),
                identity: identity.clone(),
                uid,
                desktop_session: desktop_session.clone(),
                sources: sources.clone(),
                calls: tx,
            },
        );
    }
    let _guard = Guard {
        profile: profile.clone(),
        identity,
    };
    let mut permissions = features::subscribe(&profile);
    let mut active = HashMap::<String, Active>::new();
    let mut playbacks = HashMap::<String, Playback>::new();
    let (audio_tx, mut audio_rx) = mpsc::channel::<(String, Vec<u8>)>(4);
    let (mut discover, mut request_id) =
        (None::<oneshot::Sender<Result<Vec<Source>>>>, String::new());
    let (stop_send, mut stops) = mpsc::channel::<String>(8);
    let connection = cancel.child_token();
    let mut watches = tokio::task::JoinSet::new();
    loop {
        tokio::select! {biased;
            _=cancel.cancelled()=>break,
            changed=permissions.changed()=>{if changed.is_err(){break;}if !permissions.borrow().enabled(Feature::MediaReceive){playbacks.clear();}let stopped=active.iter().filter(|(_,a)|!permissions.borrow().enabled(required(a.kind))).map(|(id,_)|id.clone()).collect::<Vec<_>>();for id in &stopped{active.remove(id);}host_wire::json(&mut write,&media_policy(&profile,uid,desktop_session.as_deref(),desktop_proof.as_deref())).await?;for session in stopped{host_wire::json(&mut write,&json!({"type":"stop","session":session})).await?;}},
            _=watches.join_next(),if !watches.is_empty()=>{},
            Some((id,mut bytes))=audio_rx.recv()=>{if playbacks.get(&id).is_some_and(|p|!p.stop.is_cancelled()) {tokio::time::timeout(Duration::from_secs(1),host_wire::write(&mut write,&bytes)).await.context("Speaker desktop writer stalled")??;}bytes.fill(0);},
            Some(session)=stops.recv()=>{let playback=playbacks.remove(&session).is_some();if active.remove(&session).is_some()||playback{host_wire::json(&mut write,&json!({"type":"stop","session":session})).await?;}},
            call=calls.recv()=>match call{
                Some(Call::Playback{render,source,reply,stop})=>{
                 if !policy(&profile).enabled(Feature::MediaReceive)||stop.is_cancelled()||active.len()+playbacks.len()>=4 {let _=reply.send(Err(anyhow::anyhow!("Speaker host busy or disabled")));continue;}
                 let session=nonce()?;let(client,mut pipe)=tokio::io::duplex(19200);let(tx,mut rx)=mpsc::channel::<Vec<u8>>(4);let taskstop=stop.clone();let ended=stop_send.clone();let id=session.clone();let outgoing=audio_tx.clone();
                 watches.spawn(async move{let work=async{if render {let mut reader=host_wire::Reader::new(&mut pipe);loop{let bytes=reader.next().await?;ensure!(bytes.len()>=33,"Invalid speaker frame");let epoch=std::str::from_utf8(&bytes[1..33])?;let frame=host_wire::parse_pcm(&bytes,epoch).context("Invalid speaker frame")?;let bytes=host_wire::pcm(&id,&frame).context("Invalid speaker frame")?;outgoing.send((id.clone(),bytes)).await.map_err(|_|anyhow::anyhow!("Speaker host closed"))?;}}else{while let Some(mut bytes)=rx.recv().await{let result=host_wire::write(&mut pipe,&bytes).await;bytes.fill(0);result?;}Ok::<(),anyhow::Error>(())}};tokio::select!{biased;_=taskstop.cancelled()=>{},_=work=>{}}let _=ended.send(id).await;});
                 host_wire::json(&mut write,&json!({"type":if render{"render-playback"}else{"capture-playback"},"session":session,"source":source})).await?;
                 playbacks.insert(session,Playback{stream:Some(client),reply:Some(reply),incoming:tx,stop});
                },
                Some(Call::Discover(reply))=>{if discover.is_some(){let _=reply.send(Err(anyhow::anyhow!("Discovery already in progress")));continue;}request_id=nonce()?;host_wire::json(&mut write,&json!({"type":"discover","request":request_id})).await?;discover=Some(reply);},
                Some(Call::Camera{uid:caller,source,reply,stop})=>{
                    let retired=active.iter().filter(|(_,state)|state.stop.is_cancelled()).map(|(id,_)|id.clone()).collect::<Vec<_>>();for id in retired{active.remove(&id);host_wire::json(&mut write,&json!({"type":"stop","session":id})).await?;}
                    if caller!=uid||!policy(&profile).enabled(Feature::CameraShare)||stop.is_cancelled()||active.len()+playbacks.len()>=4||active.values().any(|a|a.source==source){let _=reply.send(Err(anyhow::anyhow!("Camera source busy or disabled")));continue;}
                    let session=nonce()?;let token=stop.clone();let ended=stop_send.clone();let id=session.clone();let parent=connection.clone();watches.spawn(async move{tokio::select!{_=token.cancelled()=>{let _=ended.send(id).await;},_=parent.cancelled()=>{}}});
                    host_wire::json(&mut write,&json!({"type":"capture-camera","session":session,"source":source})).await?;active.insert(session,Active{kind:Kind::Camera,camera_frames:Some(Arc::new(VideoFrames::new())),camera_ready:Some(reply),video_next:0,video_timestamp:None,frames:Arc::new(Frames::new()),stop,ready:None,continuity:Default::default(),source});
                },
                Some(Call::Capture{uid:caller,source,reply,stop})=>{
                    // A same-interface reset can request its replacement before
                    // the cancellation watcher has run. Retire only already
                    // cancelled leases before applying the exclusive-source guard.
                    let retired=active.iter().filter(|(_,state)|state.stop.is_cancelled()).map(|(id,_)|id.clone()).collect::<Vec<_>>();
                    for id in retired {active.remove(&id);host_wire::json(&mut write,&json!({"type":"stop","session":id})).await?;}
                    if caller!=uid||!policy(&profile).enabled(Feature::MicrophoneShare)||stop.is_cancelled()||active.len()+playbacks.len()>=4||active.values().any(|a|a.source==source){let _=reply.send(Err(anyhow::anyhow!("Microphone source is busy or disabled")));continue;}
                    let session=nonce()?;let frames=Arc::new(Frames::new());let token=stop.clone();let ended=stop_send.clone();let id=session.clone();let parent=connection.clone();watches.spawn(async move{tokio::select!{_=token.cancelled()=>{let _=ended.send(id).await;},_=parent.cancelled()=>{}}});
                    host_wire::json(&mut write,&json!({"type":"capture","session":session,"source":source})).await?;active.insert(session,Active{kind:Kind::Microphone,camera_frames:None,camera_ready:None,video_next:0,video_timestamp:None,frames,stop,ready:Some(reply),continuity:Default::default(),source});
                },None=>break,
            },
            message=read.next()=>{
                let message=message?;
                if message.first()==Some(&1){ensure!(message.len()>=33,"Invalid camera envelope");let session=std::str::from_utf8(&message[1..33])?;let Some(state)=active.get_mut(session)else{continue;};ensure!(state.kind==Kind::Camera&&state.camera_ready.is_none(),"Camera data arrived for a different purpose or before readiness");let frame=host_wire::parse_video(&message,session).context("Invalid native camera frame")?;ensure!(frame.format==porthub_components::media::VideoFormat::baseline_mjpeg()&&frame.sequence>=state.video_next&&state.video_timestamp.is_none_or(|at|frame.source_monotonic_micros>=at),"Replayed camera frame");state.video_next=frame.sequence.checked_add(1).context("Camera sequence overflow")?;state.video_timestamp=Some(frame.source_monotonic_micros);state.camera_frames.as_ref().context("Missing camera queue")?.push(frame);continue;}
                if message.first()==Some(&0)&&message.len()>=33 {let id=std::str::from_utf8(&message[1..33])?;if let Some(p)=playbacks.get(id){ensure!(p.reply.is_none(),"Speaker PCM before readiness");let _=super::playback::enqueue_pcm(&p.incoming,message)?;continue;}}
                if message.first()==Some(&0){ensure!(message.len()>=33,"Invalid media source frame");let session=std::str::from_utf8(&message[1..33])?;let Some(state)=active.get_mut(session)else{continue;};ensure!(state.kind==Kind::Microphone&&state.ready.is_none(),"Media data arrived for the wrong purpose or before readiness");let frame=host_wire::parse_pcm(&message,session).context("Invalid media PCM frame")?;ensure!(state.continuity.accept(&frame),"Replayed or overlapping media frame");state.frames.push(frame);continue;}
                ensure!(message.len()<=128*1024,"Media control message exceeds bound");let value:Value=serde_json::from_slice(&message)?;
                match value["type"].as_str(){
                    Some("inventory")if value["request"]==request_id||value.get("request").is_none()=>{let mut rows=decode_devices(&value)?;*availability.lock().unwrap_or_else(|e|e.into_inner())=decode_availability(&value)?;let explicit=discover.is_some()&&value["request"]==request_id;{let mut current=sources.lock().unwrap_or_else(|e|e.into_inner());if !explicit{for device in &mut rows{if let Some(known)=current.iter().find(|d|d.id==device.id&&matches!(d.capture_state,porthub_components::media::CaptureState::Denied|porthub_components::media::CaptureState::Unsupported)){device.capture_state=known.capture_state;device.capture_available=false;device.unavailable_reason=known.unavailable_reason.clone();}}}*current=rows.clone();}if explicit{if let Some(reply)=discover.take(){let _=reply.send(Ok(rows.into_iter().map(|device|Source{uid,desktop_session:desktop_session.clone(),device}).collect()));}}},
                    Some("started")=>{let id=value["session"].as_str().context("Missing media session")?;if let Some(p)=playbacks.get_mut(id){ensure!(policy(&profile).enabled(Feature::MediaReceive),"Speaker policy revoked");if let Some(reply)=p.reply.take(){let _=reply.send(Ok(p.stream.take().unwrap()));}continue;}let Some(state)=active.get_mut(id)else{continue;};if state.kind==Kind::Camera{ensure!(policy(&profile).enabled(Feature::CameraShare),"Camera disabled while starting");let Some(reply)=state.camera_ready.take()else{continue;};if let Some(device)=sources.lock().unwrap_or_else(|e|e.into_inner()).iter_mut().find(|d|d.id==state.source){device.capture_state=porthub_components::media::CaptureState::Ready;device.capture_available=true;device.unavailable_reason=None;}let _=reply.send(Ok(CameraCapture{frames:state.camera_frames.as_ref().unwrap().clone(),stop:state.stop.clone(),permissions:permissions.clone()}));continue;}let Some(reply)=state.ready.take()else{continue;};ensure!(policy(&profile).enabled(Feature::MicrophoneShare),"Media disabled while capture started");if let Some(device)=sources.lock().unwrap_or_else(|e|e.into_inner()).iter_mut().find(|d|d.id==state.source){device.capture_state=porthub_components::media::CaptureState::Ready;device.capture_available=true;device.unavailable_reason=None;}let _=reply.send(Ok(Capture{frames:state.frames.clone(),stop:state.stop.clone(),permissions:permissions.clone()}));},
                    Some("unsupported")=>{let id=value["session"].as_str().context("Missing unsupported camera session")?;if let Some(mut state)=active.remove(id){ensure!(state.kind==Kind::Camera,"Unsupported camera response for different purpose");if let Some(device)=sources.lock().unwrap_or_else(|e|e.into_inner()).iter_mut().find(|d|d.id==state.source){device.capture_available=false;device.capture_state=porthub_components::media::CaptureState::Unsupported;device.unavailable_reason=Some(super::session::CaptureUnsupported.to_string());}if let Some(reply)=state.camera_ready.take(){let _=reply.send(Err(super::session::CaptureUnsupported.into()));}}},
                    Some("denied")=>{let id=value["session"].as_str().context("Missing denied media session")?;if let Some(mut state)=active.remove(id){if let Some(device)=sources.lock().unwrap_or_else(|e|e.into_inner()).iter_mut().find(|d|d.id==state.source){device.capture_available=false;device.capture_state=porthub_components::media::CaptureState::Denied;device.unavailable_reason=Some(super::session::CaptureDenied(state.kind).to_string());}if let Some(reply)=state.ready.take(){let _=reply.send(Err(super::session::CaptureDenied(state.kind).into()));}if let Some(reply)=state.camera_ready.take(){let _=reply.send(Err(super::session::CaptureDenied(state.kind).into()));}}},
                    Some("error")=>{if let Some(id)=value["session"].as_str(){playbacks.remove(id);if let Some(mut state)=active.remove(id){if let Some(reply)=state.ready.take(){let _=reply.send(Err(anyhow::anyhow!("Native user microphone could not start")));}if let Some(reply)=state.camera_ready.take(){let _=reply.send(Err(anyhow::anyhow!("Native user camera could not start")));}}}else if let Some(reply)=discover.take(){let _=reply.send(Err(anyhow::anyhow!("Native media adapter unavailable")));}},
                    Some("stopped")=>{if let Some(id)=value["session"].as_str(){playbacks.remove(id);active.remove(id);}},
                    _=>anyhow::bail!("Invalid media user broker response"),
                }
            },
        }
    }
    connection.cancel();
    watches.abort_all();
    drop(active);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn speaker_broker_binds_selected_source_and_renders_only_after_ready() -> Result<()> {
        tokio::time::timeout(Duration::from_secs(5),async {
        let root=tempfile::tempdir()?;
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(root.path(),std::fs::Permissions::from_mode(0o700))?;}
        let profile=root.path().join("profile.json");
        for feature in ["microphone-share","camera-share","usb"]{let(control,_reply)=tokio::io::duplex(4096);features::serve(BufReader::new(control),&profile,json!({"operation":"client_features","feature":feature,"enabled":false})).await?;}
        let cancel=CancellationToken::new();let(server,client)=tokio::io::duplex(16384);let path=profile.clone();let stop=cancel.clone();
        let host=tokio::spawn(async move{serve(BufReader::new(server),path,1000,stop).await});
        let(read,mut write)=tokio::io::split(client);let mut read=host_wire::Reader::new(read);read.next().await?;
        let mut device=source();device.kind=Kind::Speaker;device.id=format!("media:{}","b".repeat(64));
        host_wire::json(&mut write,&json!({"type":"inventory","devices":[device.clone()]})).await?;
        while inventory(&profile).is_empty(){tokio::task::yield_now().await;}
        assert!(playback(&profile,Some((1001,None)),&device.id,false,&cancel).await.is_err());
        assert!(playback(&profile,Some((1000,None)),"media:foreign",false,&cancel).await.is_err());
        let path=profile.clone();let stop=cancel.clone();let selected=device.id.clone();
        let capture=tokio::spawn(async move{playback(&path,Some((1000,None)),&selected,false,&stop).await});
        let command:Value=serde_json::from_slice(&read.next().await?)?;assert_eq!(command["type"],"capture-playback");assert_eq!(command["source"],device.id);
        host_wire::json(&mut write,&json!({"type":"started","session":command["session"]})).await?;
        let pipe=capture.await??;let mut captured=host_wire::Reader::new(pipe);
        let frame=PcmFrame{sequence:0,sample_offset:0,source_monotonic_micros:0,pcm:0.25f32.to_le_bytes().repeat(48)};
        let bytes=host_wire::pcm(command["session"].as_str().unwrap(),&frame).unwrap();host_wire::write(&mut write,&bytes).await?;
        assert_eq!(captured.next().await?,bytes);
        let path=profile.clone();let stop=cancel.clone();let render=tokio::spawn(async move{playback(&path,None,"",true,&stop).await});
        let command:Value=serde_json::from_slice(&read.next().await?)?;assert_eq!(command["type"],"render-playback");
        host_wire::json(&mut write,&json!({"type":"started","session":command["session"]})).await?;
        let mut output=render.await??;let bytes=host_wire::pcm(&"a".repeat(32),&frame).unwrap();host_wire::write(&mut output,&bytes).await?;
        let received=read.next().await?;let decoded=host_wire::parse_pcm(&received,command["session"].as_str().unwrap()).unwrap();assert_eq!(decoded.pcm,frame.pcm);
        drop(output);let stopped:Value=serde_json::from_slice(&read.next().await?)?;assert_eq!(stopped["type"],"stop");assert_eq!(stopped["session"],command["session"]);
        cancel.cancel();drop(captured);host.await??;Ok::<(),anyhow::Error>(())
        }).await??;Ok(())
    }

    fn source() -> Device {
        Device {
            id: "media:stable-endpoint".into(),
            name: "Fixture microphone".into(),
            kind: Kind::Microphone,
            backend: "pipewire".into(),
            native_id: "alsa_input.exact".into(),
            capture_available: false,
            capture_state: porthub_components::media::CaptureState::PermissionUnknown,
            unavailable_reason: Some("Access requires explicit capture".into()),
        }
    }
    #[tokio::test]
    async fn typed_os_denial_is_cached_and_does_not_auto_retry_capture() -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let profile = root.path().join("fixture.json");
        let cancel = CancellationToken::new();
        let (server, client) = tokio::io::duplex(16384);
        let path = profile.clone();
        let stop = cancel.clone();
        let _host = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            serve(BufReader::new(server), path, 1000, stop).await
        }));
        let (read, mut write) = tokio::io::split(client);
        let mut read = host_wire::Reader::new(read);
        read.next().await?;
        host_wire::json(
            &mut write,
            &json!({"type":"inventory","devices":[source()]}),
        )
        .await?;
        for _ in 0..100 {
            if !inventory(&profile).is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let path = profile.clone();
        let stop = cancel.clone();
        let requested =
            tokio::spawn(async move { capture(&path, 1000, "media:stable-endpoint", &stop).await });
        let command: Value = serde_json::from_slice(&read.next().await?)?;
        host_wire::json(
            &mut write,
            &json!({"type":"denied","session":command["session"]}),
        )
        .await?;
        let error = requested
            .await?
            .err()
            .context("OS-denied capture must fail")?;
        assert!(error.is::<super::super::session::CaptureDenied>());
        let sources = inventory(&profile);
        assert_eq!(
            sources[0].device.capture_state,
            porthub_components::media::CaptureState::Denied
        );
        assert!(!sources[0].device.capture_available);
        assert!(capture(&profile, 1000, "media:stable-endpoint", &cancel)
            .await
            .is_err());
        // A queued policy notification is not an explicit retry and cannot
        // silently reset the denied source. Only fresh requested discovery can.
        let path = profile.clone();
        let refreshed = tokio::spawn(async move { discover(&path).await });
        let discovery: Value = serde_json::from_slice(&read.next().await?)?;
        assert_eq!(discovery["type"], "discover");
        host_wire::json(
            &mut write,
            &json!({"type":"inventory","request":discovery["request"],"devices":[source()]}),
        )
        .await?;
        let refreshed = refreshed.await??;
        assert_eq!(
            refreshed[0].device.capture_state,
            porthub_components::media::CaptureState::PermissionUnknown
        );
        assert!(
            !refreshed[0].device.capture_available,
            "Enumeration must not invent permission grants"
        );
        let path = profile.clone();
        let stop = cancel.clone();
        let retried =
            tokio::spawn(async move { capture(&path, 1000, "media:stable-endpoint", &stop).await });
        let retry: Value = serde_json::from_slice(&read.next().await?)?;
        assert_eq!(retry["type"], "capture");
        assert_ne!(retry["session"], command["session"]);
        // This fixture simulates an OS which still denies the new explicit
        // attempt. It must return to denied instead of automatic retry loops.
        host_wire::json(
            &mut write,
            &json!({"type":"denied","session":retry["session"]}),
        )
        .await?;
        assert!(retried
            .await?
            .err()
            .context("A denied retry must fail")?
            .is::<super::super::session::CaptureDenied>());
        assert_eq!(
            inventory(&profile)[0].device.capture_state,
            porthub_components::media::CaptureState::Denied
        );
        assert!(capture(&profile, 1000, "media:stable-endpoint", &cancel)
            .await
            .is_err());
        host_wire::json(
            &mut write,
            &json!({"type":"inventory","request":discovery["request"],"devices":[source()]}),
        )
        .await?;
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            inventory(&profile)[0].device.capture_state,
            porthub_components::media::CaptureState::Denied,
            "A stale completed discovery cannot silently clear a newer denial"
        );
        host_wire::json(
            &mut write,
            &json!({"type":"inventory","devices":[source()]}),
        )
        .await?;
        for _ in 0..100 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            inventory(&profile)[0].device.capture_state,
            porthub_components::media::CaptureState::Denied,
            "Background inventory is not an explicit permission retry"
        );
        cancel.cancel();
        Ok(())
    }
    #[tokio::test]
    async fn broker_binds_source_user_session_and_revokes_media_independently_of_keyboard(
    ) -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let profile = root.path().join("fixture.json");
        let cancel = CancellationToken::new();
        let (server, client) = tokio::io::duplex(16384);
        let parent = cancel.clone();
        let path = profile.clone();
        let task =
            tokio::spawn(async move { serve(BufReader::new(server), path, 1000, parent).await });
        let (read, mut write) = tokio::io::split(client);
        let mut read = host_wire::Reader::new(read);
        let hello: Value = serde_json::from_slice(&read.next().await?)?;
        ensure!(hello["uid"] == 1000 && !hello.to_string().contains("token"));
        host_wire::json(
            &mut write,
            &json!({"type":"inventory","devices":[source()]}),
        )
        .await?;
        for _ in 0..100 {
            if !inventory(&profile).is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        ensure!(inventory(&profile).len() == 1);
        ensure!(
            capture(&profile, 1001, "media:stable-endpoint", &cancel)
                .await
                .is_err(),
            "A different user cannot select this capture source"
        );
        let request_profile = profile.clone();
        let request_stop = cancel.clone();
        let requested = tokio::spawn(async move {
            capture(
                &request_profile,
                1000,
                "media:stable-endpoint",
                &request_stop,
            )
            .await
        });
        let start: Value = serde_json::from_slice(&read.next().await?)?;
        ensure!(
            start["type"] == "capture"
                && !start.to_string().contains("token")
                && !start.to_string().contains("machine_id")
        );
        let session = start["session"].as_str().unwrap();
        host_wire::json(&mut write, &json!({"type":"started","session":session})).await?;
        let mut capture = requested.await??;
        let frame = PcmFrame {
            sequence: 0,
            sample_offset: 0,
            source_monotonic_micros: 1,
            pcm: vec![0; 8],
        };
        host_wire::write(&mut write, &host_wire::pcm(session, &frame).unwrap()).await?;
        ensure!(capture.next().await? == frame);
        let (control, _reply) = tokio::io::duplex(4096);
        crate::features::serve(
            BufReader::new(control),
            &profile,
            json!({"operation":"client_features","feature":"keyboard","enabled":false}),
        )
        .await?;
        let update: Value = serde_json::from_slice(&read.next().await?)?;
        ensure!(update["microphone"] == true);
        let frame = PcmFrame {
            sequence: 1,
            sample_offset: 2,
            source_monotonic_micros: 2,
            pcm: vec![0; 8],
        };
        host_wire::write(&mut write, &host_wire::pcm(session, &frame).unwrap()).await?;
        ensure!(
            capture.next().await? == frame,
            "Keyboard denial must not revoke media"
        );
        let (control, _reply) = tokio::io::duplex(4096);
        crate::features::serve(
            BufReader::new(control),
            &profile,
            json!({"operation":"client_features","feature":"microphone-share","enabled":false}),
        )
        .await?;
        ensure!(tokio::time::timeout(Duration::from_secs(1), capture.next())
            .await?
            .is_err());
        ensure!(inventory(&profile).is_empty());
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), task).await???;
        Ok(())
    }
    #[tokio::test]
    async fn camera_latest_queue_and_permissions_are_independent_of_microphone_and_keyboard(
    ) -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        async fn set_feature(profile: &Path, name: &str) -> Result<()> {
            let (server, _client) = tokio::io::duplex(16384);
            features::serve(
                BufReader::new(server),
                profile,
                json!({"operation":"client_features","feature":name,"enabled":false}),
            )
            .await?;
            Ok(())
        }
        let profile = root.path().join("camera.json");
        set_feature(&profile, "microphone-share").await?;
        let cancel = CancellationToken::new();
        let (server, client) = tokio::io::duplex(65536);
        let path = profile.clone();
        let stop = cancel.clone();
        let _host = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            serve(BufReader::new(server), path, 1000, stop).await
        }));
        let (read, mut write) = tokio::io::split(client);
        let mut read = host_wire::Reader::new(read);
        let hello: Value = serde_json::from_slice(&read.next().await?)?;
        assert_eq!(hello["microphone"], false);
        assert_eq!(hello["camera"], true);
        let mut camera = source();
        camera.kind = Kind::Camera;
        camera.id = "media:camera-endpoint".into();
        camera.capture_available = false;
        camera.capture_state = porthub_components::media::CaptureState::PermissionUnknown;
        host_wire::json(&mut write, &json!({"type":"inventory","devices":[camera]})).await?;
        for _ in 0..100 {
            if !inventory(&profile).is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(inventory(&profile)[0].device.kind, Kind::Camera);
        let path = profile.clone();
        let stop = cancel.clone();
        let request = tokio::spawn(async move {
            capture_camera_session(&path, 1000, None, "media:camera-endpoint", &stop).await
        });
        let command: Value = serde_json::from_slice(&read.next().await?)?;
        assert_eq!(command["type"], "capture-camera");
        let session = command["session"].as_str().unwrap();
        host_wire::json(&mut write, &json!({"type":"started","session":session})).await?;
        let mut capture = request.await??;
        // Minimal bounded JPEG metadata exercises framing/queueing, not a native image decoder.
        for sequence in 0..3 {
            let frame = porthub_components::media::VideoFrame {
                sequence,
                source_monotonic_micros: sequence,
                format: porthub_components::media::VideoFormat::baseline_mjpeg(),
                jpeg: vec![
                    255, 216, 255, 192, 0, 11, 8, 1, 224, 2, 128, 1, 1, 17, 0, 255, 217,
                ],
            };
            host_wire::write_camera(&mut write, &host_wire::video(session, &frame).unwrap())
                .await?;
        }
        for _ in 0..100 {
            if capture
                .frames
                .queue
                .lock()
                .unwrap()
                .frame
                .as_ref()
                .is_some_and(|f| f.sequence == 2)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(capture.next().await?.sequence, 2);
        set_feature(&profile, "keyboard").await?;
        assert!(
            tokio::time::timeout(Duration::from_millis(10), capture.next())
                .await
                .is_err()
        );
        set_feature(&profile, "camera-share").await?;
        assert!(tokio::time::timeout(Duration::from_secs(1), capture.next())
            .await?
            .is_err());
        assert!(capture.frames.queue.lock().unwrap().frame.is_none());
        cancel.cancel();
        Ok(())
    }
}
