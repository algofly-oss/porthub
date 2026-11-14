//! Optional USB forwarding module in the existing native agent.
pub(crate) mod cli;
#[cfg(target_os = "linux")]
mod direct;
#[cfg(target_os = "linux")]
mod linux;
use crate::{
    control::Control,
    features::{self, Feature},
};
use anyhow::{ensure, Context, Result};
pub use cli::{run, Args};
use porthub_components::usb::{Forward, State};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
pub struct Worker {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = &self.task;
    }
}
struct Session {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
    configuration: String,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
fn inventory() -> Vec<porthub_components::usb::Device> {
    #[cfg(target_os = "linux")]
    return linux::inventory();
    #[cfg(not(target_os = "linux"))]
    return vec![];
}
pub fn start(path: PathBuf, control: Arc<Control>, cancel: CancellationToken) -> Worker {
    let cancel = cancel.child_token();
    let work = cancel.clone();
    let task = tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        linux::recover(&path);
        let mut policy = features::subscribe(&path);
        let mut sessions: HashMap<String, Session> = HashMap::new();
        let states = Arc::new(Mutex::new(HashMap::<String, State>::new()));
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=work.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}sessions.clear();},_=tick.tick()=>{}}
            let enabled = policy.borrow().enabled(Feature::Usb);
            if !enabled {
                sessions.clear();
            }
            let report_states = states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .values()
                .cloned()
                .collect::<Vec<_>>();
            let p = control.profile();
            let body = json!({"machine_id":p.machine_id,"token":p.token,"enabled":enabled,"supported":cfg!(target_os="linux"),"devices":inventory(),"states":report_states});
            let result = tokio::select! {_=work.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}sessions.clear();continue;},reply=control.request(reqwest::Method::POST,"usb/client/report",Some(body),&[])=>reply};
            let plans = result
                .ok()
                .and_then(|r| r.json().ok())
                .and_then(|v| serde_json::from_value::<Vec<Forward>>(v["forwards"].clone()).ok());
            let Some(plans) = plans else {
                sessions.clear();
                continue;
            };
            sessions.retain(|id, s| {
                !s.task.is_finished()
                    && plans.iter().any(|p| {
                        &p.id == id
                            && serde_json::to_string(p).ok().as_deref()
                                == Some(s.configuration.as_str())
                    })
            });
            states
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|id, _| plans.iter().any(|p| &p.id == id));
            if !enabled || !features::enabled(&path, Feature::Usb) {
                continue;
            }
            for plan in plans.into_iter().take(64) {
                if sessions.contains_key(&plan.id) {
                    continue;
                }
                let configuration = serde_json::to_string(&plan).unwrap_or_default();
                let id = plan.id.clone();
                let child = work.child_token();
                let session_cancel = child.clone();
                let path = path.clone();
                let control = control.clone();
                let states = states.clone();
                let task = tokio::spawn(async move {
                    set_state(&states, &plan.id, "connecting", None);
                    let result = tokio::select! {_=session_cancel.cancelled()=>Ok(()),result=session(&path,control,&plan,states.clone())=>result};
                    match result {
                        Ok(()) => set_state(&states, &plan.id, "disconnected", None),
                        Err(e) => set_state(
                            &states,
                            &plan.id,
                            "error",
                            Some(format!("{e:#}").chars().take(512).collect()),
                        ),
                    }
                });
                sessions.insert(
                    id,
                    Session {
                        cancel: child,
                        task,
                        configuration,
                    },
                );
            }
        }
        sessions.clear();
    });
    Worker { cancel, task }
}
type States = Arc<Mutex<HashMap<String, State>>>;
fn set_state(states: &States, id: &str, state: &str, error: Option<String>) {
    states.lock().unwrap_or_else(|e| e.into_inner()).insert(
        id.into(),
        State {
            id: id.into(),
            state: state.into(),
            error,
        },
    );
}
#[cfg(not(target_os = "linux"))]
async fn session(_: &Path, _: Arc<Control>, _: &Forward, _: States) -> Result<()> {
    anyhow::bail!("Native USB forwarding currently requires Linux kernel USB/IP support")
}
#[cfg(target_os = "linux")]
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
#[cfg(target_os = "linux")]
async fn open(control: &Control, plan: &Forward, side: &str) -> Result<Socket> {
    use tokio_tungstenite::tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig};
    for base in control.authorities() {
        let mut url = url::Url::parse(&format!("{base}/api/usb/stream/{}/{side}", plan.id))?;
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" if control.profile().allow_insecure_http_for_tests => "ws",
            _ => continue,
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("Invalid USB gateway"))?;
        let result = tokio::time::timeout(Duration::from_secs(12), async {
            let sources = control.stream_sources(&base).await?;
            ensure!(!sources.is_empty(), "No approved USB network path");
            let stream = porthub_mesh::underlay::connect(&url, &sources).await?;
            porthub_mesh::configure_tcp(&stream);
            stream.set_nodelay(true)?;
            let mut request = url.as_str().into_client_request()?;
            request.headers_mut().insert(
                "x-porthub-machine-id",
                control.profile().machine_id.parse()?,
            );
            request.headers_mut().insert(
                "authorization",
                format!("Bearer {}", control.profile().token).parse()?,
            );
            let (socket, _) = tokio_tungstenite::client_async_tls_with_config(
                request,
                stream,
                Some(
                    WebSocketConfig::default()
                        .max_message_size(Some(262144))
                        .max_frame_size(Some(262144)),
                ),
                None,
            )
            .await?;
            Ok::<_, anyhow::Error>(socket)
        })
        .await;
        if let Ok(Ok(socket)) = result {
            control.prefer_proxy_authority(base);
            return Ok(socket);
        }
    }
    anyhow::bail!("USB gateway unavailable")
}
#[cfg(target_os = "linux")]
async fn text(socket: &mut Socket, value: Value) -> Result<()> {
    use futures_util::SinkExt;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            value.to_string().into(),
        ))
        .await?;
    Ok(())
}
#[cfg(target_os = "linux")]
async fn next_text(socket: &mut Socket) -> Result<Value> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    loop {
        match socket.next().await.context("USB signaling closed")?? {
            Message::Text(value) => return Ok(serde_json::from_str(&value)?),
            Message::Ping(b) => socket.send(Message::Pong(b)).await?,
            Message::Pong(_) => {}
            _ => anyhow::bail!("Invalid USB signaling"),
        }
    }
}
#[cfg(target_os = "linux")]
async fn negotiate(
    socket: &mut Socket,
    source: bool,
    allowed: bool,
) -> Result<Option<direct::Direct>> {
    text(socket, json!({"type":"hello","direct":allowed})).await?;
    let hello = tokio::time::timeout(Duration::from_secs(8), next_text(socket)).await??;
    ensure!(hello["type"] == "hello", "Invalid USB peer greeting");
    let both = allowed && hello["direct"] == true;
    let mut direct = if both {
        let candidates = direct::Candidates::gather().await?;
        if source {
            let offer = tokio::time::timeout(Duration::from_secs(8), next_text(socket)).await??;
            ensure!(offer["type"] == "offer", "Invalid USB offer");
            let (peer, answer) =
                candidates.answer(offer["sdp"].as_str().context("Missing USB offer")?)?;
            text(socket, json!({"type":"answer","sdp":answer})).await?;
            Some(candidates.run(peer))
        } else {
            let (mut peer, offer) = candidates.offer()?;
            text(socket, json!({"type":"offer","sdp":offer})).await?;
            let answer = tokio::time::timeout(Duration::from_secs(8), next_text(socket)).await??;
            ensure!(answer["type"] == "answer", "Invalid USB answer");
            peer.accept_answer(
                std::time::Instant::now(),
                answer["sdp"].as_str().context("Missing USB answer")?,
            )?;
            Some(candidates.run(peer))
        }
    } else {
        None
    };
    let mut connected = direct.as_mut().and_then(|d| d.connected.take());
    let mut local_ready = false;
    let mut peer_ready = false;
    let deadline = tokio::time::sleep(Duration::from_secs(if source { 5 } else { 8 }));
    tokio::pin!(deadline);
    loop {
        if source && (!both || local_ready && peer_ready) {
            let route = if both { "direct" } else { "relay" };
            text(socket, json!({"type":"path","route":route})).await?;
            return Ok(if both { direct } else { None });
        }
        tokio::select! {
         result=async{if let Some(ready)=connected.as_mut(){ready.await.map_err(|_|anyhow::anyhow!("Direct USB negotiation failed"))}else{std::future::pending().await}}=>{connected=None;if result.is_ok(){local_ready=true;text(socket,json!({"type":"direct_ready"})).await?;}},
         value=next_text(socket)=>{let value=value?;match value["type"].as_str(){Some("direct_ready")=>peer_ready=true,Some("path") if !source=>{return match value["route"].as_str(){Some("direct") if local_ready=>Ok(direct),Some("relay")=>Ok(None),_=>anyhow::bail!("USB path selection failed")};},_=>anyhow::bail!("Unexpected USB signaling")}},
         _=&mut deadline=>{if source{text(socket,json!({"type":"path","route":"relay"})).await?;return Ok(None);}anyhow::bail!("USB path selection timed out")}
        }
    }
}
#[cfg(target_os = "linux")]
async fn session(path: &Path, control: Arc<Control>, plan: &Forward, states: States) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;
    let source = plan.source == control.profile().machine_id;
    ensure!(
        source || plan.destination == control.profile().machine_id,
        "USB rule does not belong to this machine"
    );
    ensure!(plan.device.valid(), "Invalid USB device configuration");
    linux::module(source).await?;
    let mut socket = open(
        &control,
        plan,
        if source { "source" } else { "destination" },
    )
    .await?;
    let ready = tokio::time::timeout(Duration::from_secs(35), socket.next())
        .await?
        .context("USB peer disconnected")??;
    ensure!(
        matches!(ready,Message::Text(ref s) if s.as_str()=="ready"),
        "USB peer is unavailable"
    );
    let allowed = crate::terminal_policy::direct_allowed(path, control.profile());
    let mut direct = negotiate(&mut socket, source, allowed).await?;
    // Exchange fresh kernel identifiers after replugging; retain the configured physical identity.
    let device = if source {
        inventory()
            .into_iter()
            .find(|d| d.same_device(&plan.device))
            .context("USB device unplugged or changed")?
    } else {
        plan.device.clone()
    };
    text(
        &mut socket,
        json!({"type":"device","device":if source{Some(&device)}else{None}}),
    )
    .await?;
    let remote = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let value = next_text(&mut socket).await?;
            if value["type"] == "direct_ready" {
                continue;
            }
            ensure!(value["type"] == "device", "Invalid USB device metadata");
            return Ok::<_, anyhow::Error>(value);
        }
    })
    .await??;
    let device = if source {
        device
    } else {
        let d: porthub_components::usb::Device = serde_json::from_value(remote["device"].clone())?;
        ensure!(
            d.valid() && d.same_device(&plan.device),
            "USB device identity changed"
        );
        d
    };
    let (_handoff, mut stream) = linux::handoff(path, &device, source)?;
    set_state(
        &states,
        &plan.id,
        if direct.is_some() {
            "active-direct"
        } else {
            "active-relay"
        },
        None,
    );
    let mut bytes = vec![0u8; 16384];
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    let mut policy = features::subscribe(path);
    loop {
        tokio::select! {
         changed=policy.changed()=>{if changed.is_err()||!policy.borrow().enabled(Feature::Usb)||!policy.borrow().enabled(Feature::DirectConnections){break;}},
         _=heartbeat.tick()=>{socket.send(Message::Ping(vec![].into())).await?;},
         read=stream.read(&mut bytes)=>{let n=read?;if n==0{break;}if let Some(d)=&direct{d.send.send(bytes[..n].to_vec()).await.context("Direct USB transport closed")?;}else{socket.send(Message::Binary(bytes[..n].to_vec().into())).await?;}},
         incoming=async{if let Some(d)=direct.as_mut(){d.incoming.recv().await}else{std::future::pending().await}}=>{let incoming=incoming.context("Direct USB transport closed")?;stream.write_all(&incoming).await?;},
         incoming=socket.next()=>{match incoming{Some(Ok(Message::Binary(b))) if direct.is_none()=>stream.write_all(&b).await?,Some(Ok(Message::Ping(b)))=>socket.send(Message::Pong(b)).await?,Some(Ok(Message::Pong(_)))=>{},_=>break,}}
        }
    }
    Ok(())
}
/// The OS-authenticated local broker keeps machine credentials inside the agent.
pub(crate) async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut reader: tokio::io::BufReader<S>,
    control: Arc<Control>,
    message: Value,
    cancel: CancellationToken,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut body = message;
    let lease = body["action"] == "create";
    body.as_object_mut()
        .context("Invalid USB request")?
        .remove("operation");
    body["machine_id"] = control.profile().machine_id.clone().into();
    body["token"] = control.profile().token.clone().into();
    let request = async {
        let reply = control
            .request(
                reqwest::Method::POST,
                "usb/client/action",
                Some(body.clone()),
                &[],
            )
            .await?;
        Ok::<_, anyhow::Error>(reply.json()?)
    };
    let result = request.await;
    let reply = match result {
        Ok(value) => value,
        Err(e) => json!({"error":e.to_string()}),
    };
    reader
        .get_mut()
        .write_all(format!("{reply}\n").as_bytes())
        .await?;
    if !lease || reply.get("error").is_some() {
        return Ok(());
    }
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.tick().await;
    loop {
        tokio::select! {_=cancel.cancelled()=>break,frame=crate::exposure_protocol::line(&mut reader)=>{if frame.is_err(){break;}},_=tick.tick()=>{if control.request(reqwest::Method::POST,"usb/client/action",Some(body.clone()),&[]).await.is_err(){break;}}}
    }
    body["action"] = "stop".into();
    let _ = control
        .request(reqwest::Method::POST, "usb/client/action", Some(body), &[])
        .await;
    Ok(())
}
