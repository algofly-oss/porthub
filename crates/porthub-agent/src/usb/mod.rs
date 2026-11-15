//! Optional USB forwarding module in the existing native agent.
pub(crate) mod cli;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod direct;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod tcp;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os="macos")]
mod macos;
#[cfg(any(target_os="macos",test))]
mod userspace;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod protocol;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
mod windows_drivers;
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
    #[cfg(windows)]
    return windows::inventory();
    #[cfg(target_os="macos")]
    return macos::inventory();
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return vec![];
}
fn supported()->bool {
    #[cfg(any(target_os="linux",target_os="macos"))] {true}
    #[cfg(windows)] {windows::supported()}
    #[cfg(not(any(target_os="linux",target_os="macos",windows)))] {false}
}
#[cfg(any(target_os="linux",target_os="macos",windows))]
enum Handoff {
    #[cfg(target_os="macos")] Mac(macos::Handoff),
    #[cfg(target_os="linux")] Linux(linux::Handoff),
    #[cfg(windows)] Windows(windows::Handoff),
}
fn transport_policy(policy: &features::Policy) -> [bool; 3] {
    [
        Feature::Usb,
        Feature::DirectConnections,
        Feature::PrivateNetwork,
    ]
    .map(|feature| policy.enabled(feature))
}
pub fn start(path: PathBuf, control: Arc<Control>, cancel: CancellationToken) -> Worker {
    let cancel = cancel.child_token();
    let work = cancel.clone();
    let task = tokio::spawn(async move {
        #[cfg(target_os = "linux")]
        linux::recover(&path);
        #[cfg(windows)]
        windows::recover(&path);
        #[cfg(windows)]
        let preparing={let path=path.clone();let control=control.clone();tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {if let Err(error)=windows_drivers::prepare(&path,control).await{tracing::warn!(%error,"Windows USB driver preparation unavailable");}}))};
        let mut policy = features::subscribe(&path);
        let mut permissions = transport_policy(&policy.borrow());
        let mut sessions: HashMap<String, Session> = HashMap::new();
        let states = Arc::new(Mutex::new(HashMap::<String, State>::new()));
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=work.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}let next=transport_policy(&policy.borrow());if next!=permissions{sessions.clear();permissions=next;}},_=tick.tick()=>{}}
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
            let mut body = json!({"machine_id":p.machine_id,"token":p.token,"enabled":enabled,"supported":supported(),"can_export":supported(),"can_import":supported()&&!cfg!(target_os="macos"),"devices":if enabled{inventory()}else{vec![]},"states":report_states});
            let result = tokio::select! {_=work.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}let next=transport_policy(&policy.borrow());if next!=permissions{sessions.clear();permissions=next;}continue;},reply=control.request(reqwest::Method::POST,"usb/client/report",Some(body.clone()),&[])=>reply};
            let result=if matches!(result,Err(crate::control::Failure::Rejected(422))) { body.as_object_mut().unwrap().remove("can_export");body.as_object_mut().unwrap().remove("can_import");if cfg!(target_os="macos"){body["supported"]=json!(false);}control.request(reqwest::Method::POST,"usb/client/report",Some(body),&[]).await }else{result};
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
                    let prefer_direct = states
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&plan.id)
                        .is_none_or(|s| s.state != "retry-relay");
                    set_state(&states, &plan.id, "connecting", None);
                    let result = tokio::select! {_=session_cancel.cancelled()=>Ok(()),result=session(&path,control,&plan,states.clone(),prefer_direct)=>result};
                    let was_direct = states
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .get(&plan.id)
                        .is_some_and(|s| s.state == "active-direct");
                    if was_direct {
                        set_state(
                            &states,
                            &plan.id,
                            "retry-relay",
                            Some(
                                "Direct USB path interrupted; reconnecting through the gateway"
                                    .into(),
                            ),
                        );
                        return;
                    }
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
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
async fn session(_: &Path, _: Arc<Control>, _: &Forward, _: States, _: bool) -> Result<()> {
    anyhow::bail!("Native USB forwarding currently requires Linux kernel USB/IP support")
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn text(socket: &mut Socket, value: Value) -> Result<()> {
    use futures_util::SinkExt;
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            value.to_string().into(),
        ))
        .await?;
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
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
#[cfg(any(target_os="linux",target_os="macos",windows))]
struct Carrier {tcp:Option<tcp::Stream>,sctp:Option<direct::Direct>}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn negotiate(
    socket: &mut Socket,
    source: bool,
    allowed: bool,
    control: &Control,
) -> Result<Carrier> {
    let candidates = if allowed {
        direct::Candidates::gather(Some(control)).await.ok()
    } else {
        None
    };
    let listener=if source && allowed {tcp::Listener::bind(Some(control)).await.ok()} else {None};
    text(
        socket,
        json!({"type":"hello","direct":candidates.is_some(),"bulk_tcp":allowed,"bulk_offer":listener.as_ref().map(|l|&l.offer)}),
    )
    .await?;
    let hello = tokio::time::timeout(Duration::from_secs(8), next_text(socket)).await??;
    ensure!(hello["type"] == "hello", "Invalid USB peer greeting");
    if allowed && hello["bulk_tcp"]==true {
        let stream=if source {
            if let Some(listener)=listener {listener.accept().await.ok()} else {None}
        } else if let Ok(offer)=serde_json::from_value::<tcp::Offer>(hello["bulk_offer"].clone()) {
            tcp::connect(offer,Some(control)).await.ok()
        } else {None};
        text(socket,json!({"type":"direct_ready","bulk":true,"ready":stream.is_some()})).await?;
        let remote=tokio::time::timeout(Duration::from_secs(8),next_text(socket)).await??;
        ensure!(remote["type"]=="direct_ready" && remote["bulk"]==true,"Invalid bulk USB negotiation");
        if remote["ready"]==true {if let Some(stream)=stream {return Ok(Carrier{tcp:Some(stream),sctp:None});}}
    }
    let both = candidates.is_some() && hello["direct"] == true;
    let mut direct = if both {
        let candidates = candidates.context("Direct USB candidates unavailable")?;
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
            return Ok(Carrier{tcp:None,sctp:if both { direct } else { None }});
        }
        tokio::select! {
         result=async{if let Some(ready)=connected.as_mut(){ready.await.map_err(|_|anyhow::anyhow!("Direct USB negotiation failed"))}else{std::future::pending().await}}=>{connected=None;if result.is_ok(){local_ready=true;text(socket,json!({"type":"direct_ready"})).await?;}else if let Some(peer)=direct.as_mut(){if let Err(error)=peer.stopped().await{tracing::debug!(%error,"USB direct negotiation unavailable; keeping gateway fallback");}}},
         value=next_text(socket)=>{let value=value?;match value["type"].as_str(){Some("direct_ready")=>peer_ready=true,Some("path") if !source=>{return match value["route"].as_str(){Some("direct") if local_ready=>Ok(Carrier{tcp:None,sctp:direct}),Some("relay")=>Ok(Carrier{tcp:None,sctp:None}),_=>anyhow::bail!("USB path selection failed")};},_=>anyhow::bail!("Unexpected USB signaling")}},
         _=&mut deadline=>{if source{text(socket,json!({"type":"path","route":"relay"})).await?;return Ok(Carrier{tcp:None,sctp:None});}anyhow::bail!("USB path selection timed out")}
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn session(
    path: &Path,
    control: Arc<Control>,
    plan: &Forward,
    states: States,
    prefer_direct: bool,
) -> Result<()> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    let source = plan.source == control.profile().machine_id;
    ensure!(
        source || plan.destination == control.profile().machine_id,
        "USB rule does not belong to this machine"
    );
    ensure!(plan.device.valid(), "Invalid USB device configuration");
    #[cfg(target_os="linux")] linux::module(source).await?;
    #[cfg(windows)] windows::module(source).await?;
    #[cfg(target_os="macos")] macos::prepare(source).await?;
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
    let allowed = prefer_direct && crate::terminal_policy::direct_allowed(path, control.profile());
    let direct = negotiate(&mut socket, source, allowed, &control).await?;
    // Exchange fresh kernel identifiers after replugging; retain the configured physical identity.
    let mut device = if source {
        inventory()
            .into_iter()
            .find(|d| d.same_device(&plan.device))
            .context("USB device unplugged or changed")?
    } else {
        plan.device.clone()
    };
    let mut prepared=None;
    let mut wire=None;
    if source {
        #[cfg(target_os="linux")] {
            wire=Some(protocol::local_device(&device)?);
            let(guard,stream)=linux::handoff(path,&device,true)?;prepared=Some((Handoff::Linux(guard),stream));
        }
        #[cfg(target_os="macos")] {
            let(guard,stream,actual,bytes)=macos::source(path,&device).await?;device=actual;wire=Some(bytes);prepared=Some((Handoff::Mac(guard),stream));
        }
        #[cfg(windows)] {
            let(guard,stream,actual,bytes)=windows::source(path,&device).await?;device=actual;wire=Some(bytes);prepared=Some((Handoff::Windows(guard),stream));
        }
    }
    text(
        &mut socket,
        json!({"type":"device","device":if source{Some(&device)}else{None},"usbip":wire}),
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
    let(mut handoff,stream)=if source {prepared.context("USB source handoff unavailable")?} else {
        #[cfg(target_os="macos")] {anyhow::bail!("macOS can export USB devices only")}
        #[cfg(target_os="linux")] {let(guard,stream)=linux::handoff(path,&device,false)?;(Handoff::Linux(guard),stream)}
        #[cfg(windows)] {
            let bytes=if remote["usbip"].is_null(){protocol::legacy_device(&device)?}else{serde_json::from_value::<Vec<u8>>(remote["usbip"].clone())?};
            let(guard,stream)=windows::destination(&device,&bytes).await?;(Handoff::Windows(guard),stream)
        }
    };
    set_state(
        &states,
        &plan.id,
        if direct.tcp.is_some() || direct.sctp.is_some() {
            "active-direct"
        } else {
            "active-relay"
        },
        None,
    );
    let transfer=async {
        if let Some(bulk)=direct.tcp {
            tracing::info!("USB selected authenticated bulk TCP path");
            bridge_bulk(stream,socket,bulk,features::subscribe(path)).await
        } else {bridge(stream,socket,direct.sctp,features::subscribe(path)).await}
    };
    #[cfg(windows)] {let Handoff::Windows(guard)=&mut handoff;tokio::select!{result=transfer=>result,error=guard.failed()=>error}}
    #[cfg(any(target_os="linux",target_os="macos"))] {let _guard=handoff;transfer.await}
}
#[cfg(any(target_os="linux",target_os="macos",windows))]
async fn bridge_bulk<S:tokio::io::AsyncRead+tokio::io::AsyncWrite+Unpin>(mut kernel:S,mut socket:Socket,mut bulk:tcp::Stream,mut policy:tokio::sync::watch::Receiver<features::Policy>)->Result<()> {
    use futures_util::{SinkExt,StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    let transfer=tokio::io::copy_bidirectional_with_sizes(&mut kernel,&mut bulk,65536,65536);
    tokio::pin!(transfer);
    let mut heartbeat=tokio::time::interval(Duration::from_secs(15));
    loop {tokio::select! {
        result=&mut transfer=>{let (sent,received)=result?;tracing::debug!(sent,received,"USB bulk stream closed");return Ok(());},
        frame=socket.next()=>match frame {Some(Ok(Message::Ping(bytes)))=>socket.send(Message::Pong(bytes)).await?,Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Close(_)))|None=>return Ok(()),Some(Err(error))=>return Err(error.into()),_=>anyhow::bail!("Unexpected bulk USB control message")},
        _=heartbeat.tick()=>socket.send(Message::Ping(vec![].into())).await?,
        changed=policy.changed()=>if changed.is_err()||!policy.borrow().enabled(Feature::Usb)||!policy.borrow().enabled(Feature::DirectConnections){return Ok(());}
    }}
}
// Independent pumps preserve full-duplex progress when either carrier applies
// backpressure. Never replay kernel USB requests after a path fails.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn bridge<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    socket: Socket,
    mut direct: Option<direct::Direct>,
    mut policy: tokio::sync::watch::Receiver<crate::features::Policy>,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut sink, mut source) = socket.split();
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (ws_send, mut outgoing) = tokio::sync::mpsc::channel(8);
    let upload_socket = ws_send.clone();
    let control_socket = ws_send.clone();
    let direct_send = direct.as_ref().map(|d| d.send.clone());
    let local = direct.is_some();
    let upload = async move {
        let mut bytes = vec![0u8; 16384];
        loop {
            let n = reader.read(&mut bytes).await?;
            if n == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            if let Some(send) = &direct_send {
                send.send(bytes[..n].to_vec())
                    .await
                    .context("Direct USB transport closed")?;
            } else {
                upload_socket
                    .send(Message::Binary(bytes[..n].to_vec().into()))
                    .await
                    .context("USB gateway closed")?;
            }
        }
    };
    let carrier = async move {
        while let Some(message) = outgoing.recv().await {
            sink.send(message).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        loop {
            tokio::select! {
             message=source.next()=>{match message{Some(Ok(Message::Binary(b))) if !local=>writer.write_all(&b).await?,Some(Ok(Message::Ping(b)))=>{control_socket.send(Message::Pong(b)).await.context("USB gateway closed")?;},Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Close(_)))|None=>return Ok::<_,anyhow::Error>(()),Some(Err(e))=>return Err(e.into()),_=>anyhow::bail!("Unexpected USB carrier message")}},
             data=async{if let Some(d)=direct.as_mut(){d.incoming.recv().await}else{std::future::pending().await}}=>{writer.write_all(&data.context("Direct USB transport closed")?).await?;}
            }
        }
    };
    tokio::pin!(upload, carrier, download);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
         result=&mut upload=>return result,result=&mut carrier=>return result,result=&mut download=>return result,
         _=heartbeat.tick()=>{let _=ws_send.try_send(Message::Ping(vec![].into()));},
         changed=policy.changed()=>{if changed.is_err()||!policy.borrow().enabled(Feature::Usb)||local&&!policy.borrow().enabled(Feature::DirectConnections){return Ok(());}}
        }
    }
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

#[cfg(all(test, target_os = "linux"))]
mod stream_tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;
    async fn full_duplex(local: bool) -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let relayed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = relayed.clone();
        let _relay = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let (a, _) = listener.accept().await?;
            let mut a = tokio_tungstenite::accept_async(a).await?;
            let (b, _) = listener.accept().await?;
            let mut b = tokio_tungstenite::accept_async(b).await?;
            loop {
                tokio::select! {
                 message=a.next()=>{match message{Some(Ok(Message::Binary(bytes)))=>{counted.fetch_add(bytes.len(),std::sync::atomic::Ordering::Relaxed);b.send(Message::Binary(bytes)).await?;},Some(Ok(Message::Ping(bytes)))=>a.send(Message::Pong(bytes)).await?,Some(Ok(Message::Pong(_)))=>{},_=>break}},
                 message=b.next()=>{match message{Some(Ok(Message::Binary(bytes)))=>{counted.fetch_add(bytes.len(),std::sync::atomic::Ordering::Relaxed);a.send(Message::Binary(bytes)).await?;},Some(Ok(Message::Ping(bytes)))=>b.send(Message::Pong(bytes)).await?,Some(Ok(Message::Pong(_)))=>{},_=>break}}
                }
            }
            Ok::<_, anyhow::Error>(())
        }));
        let (a, _) = tokio_tungstenite::connect_async(format!("ws://{address}")).await?;
        let (b, _) = tokio_tungstenite::connect_async(format!("ws://{address}")).await?;
        let (direct_a, direct_b) = if local {
            let ca = direct::Candidates::gather(None).await?;
            let cb = direct::Candidates::gather(None).await?;
            let (mut ap, offer) = ca.offer()?;
            let (bp, answer) = cb.answer(&offer)?;
            ap.accept_answer(std::time::Instant::now(), &answer)?;
            let mut a = ca.run(ap);
            let mut b = cb.run(bp);
            tokio::time::timeout(Duration::from_secs(8), async {
                a.connected.take().unwrap().await?;
                b.connected.take().unwrap().await?;
                Ok::<_, anyhow::Error>(())
            })
            .await??;
            (Some(a), Some(b))
        } else {
            (None, None)
        };
        let (ka, app_a) = tokio::io::duplex(1024);
        let (kb, app_b) = tokio::io::duplex(1024);
        let (policy, rx) = tokio::sync::watch::channel(crate::features::Policy::default());
        let mut bridge_a = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(bridge(
            ka,
            a,
            direct_a,
            rx.clone(),
        )));
        let mut bridge_b =
            tokio_util::task::AbortOnDropHandle::new(tokio::spawn(bridge(kb, b, direct_b, rx)));
        let (mut ar, mut aw) = tokio::io::split(app_a);
        let (mut br, mut bw) = tokio::io::split(app_b);
        let a_bytes = vec![17; 2 * 1024 * 1024];
        let b_bytes = vec![93; 2 * 1024 * 1024];
        tokio::time::timeout(Duration::from_secs(15), async {
            let send_a = aw.write_all(&a_bytes);
            let send_b = bw.write_all(&b_bytes);
            let receive_a = async {
                let mut bytes = vec![0; b_bytes.len()];
                ar.read_exact(&mut bytes).await?;
                ensure!(bytes == b_bytes, "B→A USB bytes changed");
                Ok::<_, anyhow::Error>(())
            };
            let receive_b = async {
                let mut bytes = vec![0; a_bytes.len()];
                br.read_exact(&mut bytes).await?;
                ensure!(bytes == a_bytes, "A→B USB bytes changed");
                Ok::<_, anyhow::Error>(())
            };
            let (sa, sb, ra, rb) = tokio::join!(send_a, send_b, receive_a, receive_b);
            sa?;
            sb?;
            ra?;
            rb?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        if local {
            ensure!(
                relayed.load(std::sync::atomic::Ordering::Relaxed) == 0,
                "Direct USB bytes must bypass the gateway"
            );
        }
        let mut disabled = crate::features::Policy::default();
        disabled.disabled.insert(Feature::Usb, true);
        policy.send_replace(disabled);
        tokio::time::timeout(Duration::from_secs(2), async {
            (&mut bridge_a).await??;
            (&mut bridge_b).await??;
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
    #[tokio::test]
    async fn relay_usb_stream_remains_full_duplex_under_backpressure() -> Result<()> {
        full_duplex(false).await
    }
    #[tokio::test]
    async fn direct_usb_stream_remains_full_duplex_and_revokes_locally() -> Result<()> {
        full_duplex(true).await
    }
}
