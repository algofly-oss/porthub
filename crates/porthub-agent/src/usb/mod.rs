//! Optional USB forwarding module in the existing native agent.
#[cfg(any(target_os="linux",target_os="macos",windows))]
pub(crate) mod media_transport;
pub(crate) mod cli;
mod relay;
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
#[cfg(any(windows, test))]
mod prerequisite_retry;
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
fn inventory_for(path: &Path) -> Vec<porthub_components::usb::Device> {
    let mut devices = inventory();
    #[cfg(target_os = "linux")]
    devices.extend(relay::inventory(path));
    #[cfg(not(target_os = "linux"))] let _ = path;
    devices.truncate(128); devices
}
fn capabilities()->[bool;2] {
    #[cfg(target_os="linux")] { [true,true] }
    #[cfg(target_os="macos")] { [true,false] }
    #[cfg(windows)] { [windows::host_installed(),windows::receive_installed()] }
    #[cfg(not(any(target_os="linux",target_os="macos",windows)))] { [false,false] }
}
fn ordinary_report(body:&mut Value) {
    if let Some(object)=body.as_object_mut(){object.remove("imports");}
    if let Some(devices)=body["devices"].as_array_mut(){devices.retain(|d|!d["busid"].as_str().is_some_and(relay::is_alias));}
}
fn legacy_report(body:&mut Value) {
    ordinary_report(body);
    // Old gateways have no directional roles. Advertising partial support
    // there could authorize a destination that cannot receive USB devices.
    body["supported"]=json!(body["can_export"].as_bool()==Some(true)&&body["can_import"].as_bool()==Some(true));
    if let Some(object)=body.as_object_mut(){object.remove("can_export");object.remove("can_import");}
}
#[cfg(any(target_os="linux",target_os="macos",windows))]
enum Handoff {
    #[cfg(target_os="macos")] Mac(macos::Handoff),
    #[cfg(target_os="linux")] Linux(linux::Handoff),
    #[cfg(target_os="linux")] RelaySource(relay::Lease),
    #[cfg(target_os="linux")] RelayDestination,
    #[cfg(windows)] Windows(windows::Handoff),
}
/// Lifetime-owned native local controller attachment for receiver-local class
/// devices. The returned TCP stream contains raw USB/IP URBs; Windows' private
/// capability/import handshake is already consumed by its existing adapter.
#[cfg(any(target_os="linux",windows))]
pub(crate) struct VirtualReceiver { _guard:Handoff }
#[cfg(any(target_os="linux",windows))]
impl VirtualReceiver {
    pub(crate) async fn failed(&mut self)->Result<()> {
        #[cfg(windows)] {let Handoff::Windows(guard)=&mut self._guard;guard.failed().await}
        #[cfg(not(windows))] {std::future::pending().await}
    }
}
#[cfg(any(target_os="linux",windows))]
pub(crate) async fn attach_virtual(profile:&Path,device:&porthub_components::usb::Device,wire:&[u8])->Result<(VirtualReceiver,tokio::net::TcpStream)> {
    ensure!(features::enabled(profile,Feature::Usb),"Local USB receiving is disabled by client policy");
    ensure!(device.busid.starts_with("65535-")&&device.busnum==65535,"Invalid receiver-local virtual USB namespace");
    protocol::validate(wire,device)?;
    #[cfg(target_os="linux")] {linux::module(false).await?;let(guard,stream)=linux::handoff(profile,device,false)?;return Ok((VirtualReceiver{_guard:Handoff::Linux(guard)},stream));}
    #[cfg(windows)] {windows::module(false).await?;let(guard,stream)=windows::destination(device,wire).await?;return Ok((VirtualReceiver{_guard:Handoff::Windows(guard)},stream));}
    #[cfg(not(any(target_os="linux",windows)))] {anyhow::bail!("Receiver-local USB devices require Linux or the signed Windows virtual controller");}
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
        let _preparing={let path=path.clone();let control=control.clone();let cancel=work.child_token();tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {prerequisite_retry::run(features::subscribe(&path),cancel,||async {match windows_drivers::prepare(&path,control.clone()).await {Ok(())=>true,Err(error)=>{tracing::warn!(%error,"Windows USB driver preparation unavailable; retrying with backoff");false}}}).await;}))};
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
            let [can_export,can_import]=capabilities();
            let mut body = json!({"machine_id":p.machine_id,"token":p.token,"enabled":enabled,"supported":can_export||can_import,"can_export":can_export,"can_import":can_import,"devices":if enabled{inventory_for(&path)}else{vec![]},"states":report_states});
            #[cfg(target_os="linux")] {
                let mut imports=relay::imports(&path);
                imports.retain(|r|body["devices"].as_array().is_some_and(|devices|devices.iter().any(|d|d["busid"]==r.busid)));
                if let Some(devices)=body["devices"].as_array_mut(){devices.retain(|d|!d["busid"].as_str().is_some_and(relay::is_alias)||imports.iter().any(|r|d["busid"]==r.busid));}
                body["imports"]=json!(imports);
            }
            let result = tokio::select! {_=work.cancelled()=>break,changed=policy.changed()=>{if changed.is_err(){break;}let next=transport_policy(&policy.borrow());if next!=permissions{sessions.clear();permissions=next;}continue;},reply=control.request(reqwest::Method::POST,"usb/client/report",Some(body.clone()),&[])=>reply};
            // Gateways with directional roles but no relay support must keep
            // ordinary USB (including export-only Mac sources) operational.
            let result=if matches!(result,Err(crate::control::Failure::Rejected(422))) { ordinary_report(&mut body);control.request(reqwest::Method::POST,"usb/client/report",Some(body.clone()),&[]).await }else{result};
            let result=if matches!(result,Err(crate::control::Failure::Rejected(422))) { legacy_report(&mut body);control.request(reqwest::Method::POST,"usb/client/report",Some(body),&[]).await }else{result};
            let response = result.ok().and_then(|r| r.json().ok());
            #[cfg(target_os="linux")]
            relay::gateway(&path,response.as_ref().is_some_and(|v|v["relay_version"]==1));
            let plans = response.and_then(|v|serde_json::from_value::<Vec<Forward>>(v["forwards"].clone()).ok());
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
                    #[cfg(target_os="linux")]
                    let _import = if plan.destination == control.profile().machine_id {
                        match relay::register(&path,&plan) { Ok(guard)=>Some(guard),Err(error)=>{set_state(&states,&plan.id,"error",Some(error.to_string()));return;} }
                    } else { None };
                    #[cfg(target_os="linux")]
                    let reroute = _import.as_ref().map(relay::ImportGuard::subscribe);
                    #[cfg(not(target_os="linux"))]
                    let reroute: Option<tokio::sync::watch::Receiver<u64>> = None;
                    let result = loop {
                        let mut epoch=reroute.clone();if let Some(changes)=epoch.as_mut(){changes.borrow_and_update();}
                        let result=tokio::select! {_=session_cancel.cancelled()=>break Ok(()),result=session(&path,control.clone(),&plan,states.clone(),prefer_direct,epoch)=>result};
                        if result.as_ref().is_err_and(|error|error.is::<relay::Reconfigure>()) {
                            set_state(&states,&plan.id,"connecting",None);
                            tokio::select!{_=session_cancel.cancelled()=>break Ok(()),_=tokio::time::sleep(Duration::from_millis(300))=>{}}
                            continue;
                        }
                        break result;
                    };
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
async fn session(_: &Path, _: Arc<Control>, _: &Forward, _: States, _: bool, _: Option<tokio::sync::watch::Receiver<u64>>) -> Result<()> {
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
struct Carrier {tcp:Option<tcp::Stream>,sctp:Option<direct::Direct>,restart:bool}
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
        json!({"type":"hello","restart":1,"direct":candidates.is_some(),"bulk_tcp":allowed,"bulk_offer":listener.as_ref().map(|l|&l.offer)}),
    )
    .await?;
    let hello = tokio::time::timeout(Duration::from_secs(8), next_text(socket)).await??;
    ensure!(hello["type"] == "hello", "Invalid USB peer greeting");
    let restart=hello["restart"]==1;
    if allowed && hello["bulk_tcp"]==true {
        let stream=if source {
            if let Some(listener)=listener {listener.accept().await.ok()} else {None}
        } else if let Ok(offer)=serde_json::from_value::<tcp::Offer>(hello["bulk_offer"].clone()) {
            tcp::connect(offer,Some(control)).await.ok()
        } else {None};
        text(socket,json!({"type":"direct_ready","bulk":true,"ready":stream.is_some()})).await?;
        let remote=tokio::time::timeout(Duration::from_secs(8),next_text(socket)).await??;
        ensure!(remote["type"]=="direct_ready" && remote["bulk"]==true,"Invalid bulk USB negotiation");
        if remote["ready"]==true {if let Some(stream)=stream {return Ok(Carrier{tcp:Some(stream),sctp:None,restart});}}
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
            return Ok(Carrier{tcp:None,sctp:if both { direct } else { None },restart});
        }
        tokio::select! {
         result=async{if let Some(ready)=connected.as_mut(){ready.await.map_err(|_|anyhow::anyhow!("Direct USB negotiation failed"))}else{std::future::pending().await}}=>{connected=None;if result.is_ok(){local_ready=true;text(socket,json!({"type":"direct_ready"})).await?;}else if let Some(peer)=direct.as_mut(){if let Err(error)=peer.stopped().await{tracing::debug!(%error,"USB direct negotiation unavailable; keeping gateway fallback");}}},
         value=next_text(socket)=>{let value=value?;match value["type"].as_str(){Some("direct_ready")=>peer_ready=true,Some("path") if !source=>{return match value["route"].as_str(){Some("direct") if local_ready=>Ok(Carrier{tcp:None,sctp:direct,restart}),Some("relay")=>Ok(Carrier{tcp:None,sctp:None,restart}),_=>anyhow::bail!("USB path selection failed")};},_=>anyhow::bail!("Unexpected USB signaling")}},
         _=&mut deadline=>{if source{text(socket,json!({"type":"path","route":"relay"})).await?;return Ok(Carrier{tcp:None,sctp:None,restart});}anyhow::bail!("USB path selection timed out")}
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
    reroute: Option<tokio::sync::watch::Receiver<u64>>,
) -> Result<()> {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;
    let source = plan.source == control.profile().machine_id;
    ensure!(
        source || plan.destination == control.profile().machine_id,
        "USB rule does not belong to this machine"
    );
    ensure!(plan.device.valid(), "Invalid USB device configuration");
    #[cfg(target_os="linux")]
    let mut relayed = if source && relay::is_alias(&plan.device.busid) {
        // A positive capability report alone is insufficient after authority
        // failover. Authorize this exact ancestry on the selected gateway; an
        // old gateway's404 must never permit an unvalidated imported alias.
        let p=control.profile();
        let reply=control.request(reqwest::Method::POST,"usb/client/relay-authorize",Some(json!({"machine_id":p.machine_id,"token":p.token,"id":plan.id})),&[]).await.map_err(|_|anyhow::anyhow!("Gateway cannot authorize this USB relay; upgrade the gateway and recreate its forwarding rule"))?;
        let authorization=reply.json()?;
        ensure!(authorization["relay_version"]==1&&authorization["upstream_id"]==relay::upstream(path,&plan.device.busid)?,"USB relay lineage authorization changed");
        let mut lease=relay::claim(path,&plan.device.busid,&plan.id)?;
        let (stream,metadata)=tokio::time::timeout(Duration::from_secs(60),lease.ready()).await??;
        Some((lease,stream,metadata))
    } else { None };
    #[cfg(target_os="linux")] if relayed.is_none(){linux::module(source).await?;}
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
        inventory_for(path)
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
            if let Some((lease,stream,metadata))=relayed.take(){device=metadata.device;wire=Some(metadata.wire);prepared=Some((Handoff::RelaySource(lease),stream));}
            else {wire=Some(protocol::local_device(&device)?);let(guard,stream)=linux::handoff(path,&device,true)?;prepared=Some((Handoff::Linux(guard),stream));}
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
        #[cfg(target_os="linux")] {
            let bytes=if remote["usbip"].is_null(){protocol::legacy_device(&device)?}else{serde_json::from_value::<Vec<u8>>(remote["usbip"].clone())?};
            if let Some(stream)=relay::destination(path,plan,relay::Metadata{device:device.clone(),wire:bytes,restart:direct.restart})? {(Handoff::RelayDestination,stream)}
            else {let(guard,stream)=linux::handoff(path,&device,false)?;relay::local(path,&plan.id,guard.virtual_port().context("USB import port missing")?)?;(Handoff::Linux(guard),stream)}
        }
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
            bridge_bulk(stream,socket,bulk,features::subscribe(path),reroute,direct.restart).await
        } else {bridge(stream,socket,direct.sctp,features::subscribe(path),reroute,direct.restart).await}
    };
    #[cfg(windows)] {let Handoff::Windows(guard)=&mut handoff;tokio::select!{result=transfer=>result,error=guard.failed()=>error}}
    #[cfg(any(target_os="linux",target_os="macos"))] {let _guard=handoff;transfer.await}
}
fn planned_ack(value:&str)->bool {serde_json::from_str::<Value>(value).is_ok_and(|v|v["type"]=="path"&&v["route"]=="restart-ack")}
fn restart_frame(ack:bool)->tokio_tungstenite::tungstenite::Message {tokio_tungstenite::tungstenite::Message::Text(json!({"type":"path","route":if ack{"restart-ack"}else{"restart"}}).to_string().into())}
fn planned_restart(value:&str)->bool {
    serde_json::from_str::<Value>(value).is_ok_and(|v|v["type"]=="path"&&v["route"]=="restart")
}
async fn rerouted(changes:&mut Option<tokio::sync::watch::Receiver<u64>>) {
    match changes {Some(changes)=>{let _=changes.changed().await;},None=>std::future::pending().await}
}
#[cfg(any(target_os="linux",target_os="macos",windows))]
async fn bridge_bulk<S:tokio::io::AsyncRead+tokio::io::AsyncWrite+Unpin>(kernel:S,socket:Socket,bulk:tcp::Stream,policy:tokio::sync::watch::Receiver<features::Policy>,reroute:Option<tokio::sync::watch::Receiver<u64>>,restart:bool)->Result<()> {
    bridge_bulk_with_policy(kernel,socket,bulk,policy,reroute,restart,Feature::Usb).await
}
#[cfg(any(target_os="linux",target_os="macos",windows))]
async fn send_control(
    socket: &mut Socket,
    message: tokio_tungstenite::tungstenite::Message,
) -> Result<()> {
    use futures_util::SinkExt;
    tokio::time::timeout(Duration::from_secs(2), socket.send(message))
        .await
        .map_err(|_| anyhow::anyhow!("USB control write timed out"))??;
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn bridge_bulk_with_policy<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    kernel: S,
    mut socket: Socket,
    mut bulk: tcp::Stream,
    policy: tokio::sync::watch::Receiver<features::Policy>,
    mut reroute: Option<tokio::sync::watch::Receiver<u64>>,
    restart: bool,
    required: Feature,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    enum Action {
        Closed,
        LocalRestart,
        PeerRestart,
        PeerAck,
    }
    let revoked = |mut policy: tokio::sync::watch::Receiver<features::Policy>| async move {
        loop {
            if !policy.borrow().enabled(required)
                || !policy.borrow().enabled(Feature::DirectConnections)
            {
                return;
            }
            if policy.changed().await.is_err() {
                return;
            }
        }
    };
    let mut kernel = relay::RoutedStream::new(kernel, reroute.is_some());
    // Normal control traffic must never suspend payload copying or local revocation.
    let action = {
        let transfer =
            tokio::io::copy_bidirectional_with_sizes(&mut kernel, &mut bulk, 65536, 65536);
        let control = async {
            let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
            loop {
                tokio::select! {
                    frame = socket.next() => match frame {
                        Some(Ok(Message::Ping(bytes))) => send_control(&mut socket, Message::Pong(bytes)).await?,
                        Some(Ok(Message::Pong(_))) => {},
                        Some(Ok(Message::Text(value))) if planned_restart(&value) => return Ok::<_, anyhow::Error>(Action::PeerRestart),
                        Some(Ok(Message::Text(value))) if planned_ack(&value) => return Ok(Action::PeerAck),
                        Some(Ok(Message::Close(_))) | None => return Ok(Action::Closed),
                        Some(Err(error)) => return Err(error.into()),
                        _ => anyhow::bail!("Unexpected bulk USB control message"),
                    },
                    _ = heartbeat.tick() => send_control(&mut socket, Message::Ping(vec![].into())).await?,
                    _ = rerouted(&mut reroute), if restart => return Ok(Action::LocalRestart),
                }
            }
        };
        tokio::select! {
            result = transfer => { let (sent, received) = result?; tracing::debug!(sent, received, "USB bulk stream closed"); return Ok(()); },
            result = control => result?,
            _ = revoked(policy.clone()) => return Ok(()),
        }
    }; // Drop the copy future, retaining both carrier handles for the planned ACK.
    match action {
        Action::Closed => Ok(()),
        Action::PeerAck => Err(relay::Reconfigure.into()),
        Action::LocalRestart | Action::PeerRestart => {
            let handshake = async {
                if matches!(action, Action::PeerRestart) {
                    socket.send(restart_frame(true)).await?;
                } else {
                    socket.send(restart_frame(false)).await?;
                    let value = next_text(&mut socket).await?;
                    if planned_restart(&value.to_string()) {
                        socket.send(restart_frame(true)).await?;
                    } else {
                        ensure!(
                            planned_ack(&value.to_string()),
                            "USB peer did not acknowledge rerouting"
                        );
                    }
                }
                Err::<(), anyhow::Error>(relay::Reconfigure.into())
            };
            tokio::select! {
                result = tokio::time::timeout(Duration::from_secs(2), handshake) => result?,
                _ = revoked(policy) => Ok(()),
            }
        }
    }
}
// Independent pumps preserve full-duplex progress when either carrier applies
// backpressure. Never replay kernel USB requests after a path fails.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn bridge<S:tokio::io::AsyncRead+tokio::io::AsyncWrite+Unpin>(stream:S,socket:Socket,direct:Option<direct::Direct>,policy:tokio::sync::watch::Receiver<features::Policy>,reroute:Option<tokio::sync::watch::Receiver<u64>>,restart:bool)->Result<()> {
    bridge_with_policy(stream,socket,direct,policy,reroute,restart,Feature::Usb).await
}
#[cfg(any(target_os="linux",target_os="macos",windows))]
async fn bridge_with_policy<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: S,
    socket: Socket,
    mut direct: Option<direct::Direct>,
    mut policy: tokio::sync::watch::Receiver<crate::features::Policy>,
    mut reroute: Option<tokio::sync::watch::Receiver<u64>>,
    restart: bool,
    required:Feature,
) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;
    let (mut sink, mut source) = socket.split();
    let stream=relay::RoutedStream::new(stream,reroute.is_some());
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (ws_send, mut outgoing) = tokio::sync::mpsc::channel::<(Message,Option<tokio::sync::oneshot::Sender<()>>)>(8);
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
                    .send((Message::Binary(bytes[..n].to_vec().into()),None))
                    .await
                    .context("USB gateway closed")?;
            }
        }
    };
    let carrier = async move {
        while let Some((message,ack)) = outgoing.recv().await {
            sink.send(message).await?;
            if let Some(ack)=ack{let _=ack.send(());}
        }
        Ok::<_, anyhow::Error>(())
    };
    let download = async {
        loop {
            tokio::select! {
             message=source.next()=>{match message{Some(Ok(Message::Binary(b))) if !local=>writer.write_all(&b).await?,Some(Ok(Message::Ping(b)))=>{control_socket.send((Message::Pong(b),None)).await.context("USB gateway closed")?;},Some(Ok(Message::Pong(_)))=>{},Some(Ok(Message::Text(value))) if planned_restart(&value)=>{let(ack,sent)=tokio::sync::oneshot::channel();control_socket.send((restart_frame(true),Some(ack))).await?;sent.await?;return Err(relay::Reconfigure.into());},Some(Ok(Message::Text(value))) if planned_ack(&value)=>return Err(relay::Reconfigure.into()),Some(Ok(Message::Close(_)))|None=>return Ok::<_,anyhow::Error>(()),Some(Err(e))=>return Err(e.into()),_=>anyhow::bail!("Unexpected USB carrier message")}},
             data=async{if let Some(d)=direct.as_mut(){d.incoming.recv().await}else{std::future::pending().await}}=>{writer.write_all(&data.context("Direct USB transport closed")?).await?;}
            }
        }
    };
    tokio::pin!(upload, carrier, download);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
         result=&mut upload=>return result,result=&mut carrier=>return result,result=&mut download=>return result,
         _=heartbeat.tick()=>{let _=ws_send.try_send((Message::Ping(vec![].into()),None));},
         _=rerouted(&mut reroute),if restart=>{
            let (ack,ready)=tokio::sync::oneshot::channel();
            let notify=async {
                let send=ws_send.send((restart_frame(false),Some(ack)));
                tokio::pin!(send);
                tokio::select!{result=&mut send=>{result?;},result=&mut carrier=>{return result;}}
                tokio::select!{result=ready=>{result?;},result=&mut carrier=>{return result;}}
                // Continue polling the control carrier and receiver until the
                // peer acknowledges, while retaining the existing data stream.
                tokio::select!{result=&mut download=>result,result=&mut carrier=>result}
            };
            return tokio::time::timeout(Duration::from_secs(2),notify).await?;
         },
         changed=policy.changed()=>{if changed.is_err()||!policy.borrow().enabled(required)||local&&!policy.borrow().enabled(Feature::DirectConnections){return Ok(());}}
        }
    }
}
/// The OS-authenticated local broker keeps machine credentials inside the agent.
pub(crate) async fn serve<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut reader: tokio::io::BufReader<S>,
    control: Arc<Control>,
    path: &Path,
    message: Value,
    cancel: CancellationToken,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut body = message;
    if body["action"] == "devices" {
        let reply=json!({"devices":inventory_for(path)});
        reader.get_mut().write_all(format!("{reply}\n").as_bytes()).await?;
        return Ok(());
    }
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
            None,
            false,
        )));
        let mut bridge_b =
            tokio_util::task::AbortOnDropHandle::new(tokio::spawn(bridge(kb, b, direct_b, rx, None, false)));
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
    #[tokio::test]
    async fn planned_rerouting_ack_beats_local_eof_on_gateway_and_bulk() -> Result<()> {
        use futures_util::{SinkExt,StreamExt};
        use tokio_tungstenite::tungstenite::Message;
        for bulk in [false,true] {
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let address=listener.local_addr()?;
            let _gateway=tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
                let (a,_)=listener.accept().await?;let mut a=tokio_tungstenite::accept_async(a).await?;
                let (b,_)=listener.accept().await?;let mut b=tokio_tungstenite::accept_async(b).await?;
                loop {tokio::select! {
                    frame=a.next()=>match frame {Some(Ok(Message::Text(value)))=>{tokio::time::sleep(Duration::from_millis(60)).await;b.send(Message::Text(value)).await?;},Some(Ok(Message::Ping(v)))=>a.send(Message::Pong(v)).await?,Some(Ok(Message::Pong(_)))=>{},_=>break},
                    frame=b.next()=>match frame {Some(Ok(Message::Text(value)))=>{tokio::time::sleep(Duration::from_millis(60)).await;a.send(Message::Text(value)).await?;},Some(Ok(Message::Ping(v)))=>b.send(Message::Pong(v)).await?,Some(Ok(Message::Pong(_)))=>{},_=>break},
                }}Ok::<(),anyhow::Error>(())
            }));
            let(a,_)=tokio_tungstenite::connect_async(format!("ws://{address}")).await?;
            let(b,_)=tokio_tungstenite::connect_async(format!("ws://{address}")).await?;
            let(ka,app_a)=tokio::io::duplex(128);let(kb,_app_b)=tokio::io::duplex(128);
            let(_policy,rx)=tokio::sync::watch::channel(crate::features::Policy::default());
            let(change,changes)=tokio::sync::watch::channel(0u64);
            let(mut first,mut second)=if bulk {
                let listener=tcp::Listener::bind(None).await?;let offer=listener.offer.clone();
                let(ta,tb)=tokio::join!(listener.accept(),tcp::connect(offer,None));
                (tokio::spawn(bridge_bulk(ka,a,ta?,rx.clone(),Some(changes),true)),tokio::spawn(bridge_bulk(kb,b,tb?,rx,None,true)))
            } else {
                (tokio::spawn(bridge(ka,a,None,rx.clone(),Some(changes),true)),tokio::spawn(bridge(kb,b,None,rx,None,true)))
            };
            // The local consumer can close before the lease destructor sends
            // its notification. A fast FIN must not outrun the slower gateway.
            drop(app_a);tokio::task::yield_now().await;change.send_replace(1);
            let(first,second)=tokio::time::timeout(Duration::from_secs(3),async{tokio::join!(&mut first,&mut second)}).await?;
            let first=first?;ensure!(first.as_ref().is_err_and(|e|e.is::<relay::Reconfigure>()),"initiator bulk={bulk} misclassified planned rerouting: {first:?}");
            let second=second?;ensure!(second.as_ref().is_err_and(|e|e.is::<relay::Reconfigure>()),"peer bulk={bulk} treated planned rerouting as direct-path failure: {second:?}");
        }
        Ok(())
    }

}

#[cfg(test)]
mod capability_tests {
    use super::*;
    #[test]
    fn gateway44_contract_preserves_ordinary_devices_and_directional_roles() {
        // Exact report shape accepted before relay fields were introduced.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct Gateway44Report {
            machine_id:String, token:String, enabled:bool, supported:bool,
            can_export:Option<bool>, can_import:Option<bool>,
            devices:Vec<porthub_components::usb::Device>, states:Vec<State>,
        }
        let device=json!({"busid":"1-2","vendor":"1377","product":"1100","serial":"fixture","name":"Microphone","busnum":1,"devnum":2,"speed":3,"blocked":null});
        let mut alias=device.clone();alias["busid"]=json!("0-123");
        for (export,import) in [(true,true),(true,false)] {
            let mut body=json!({"machine_id":"fixture","token":"test-token","enabled":true,"supported":true,"can_export":export,"can_import":import,"devices":[device.clone(),alias.clone()],"states":[],"imports":[{"busid":"0-123","upstream_id":"f".repeat(32)}]});
            assert!(serde_json::from_value::<Gateway44Report>(body.clone()).is_err());
            ordinary_report(&mut body);
            let report:Gateway44Report=serde_json::from_value(body).expect("gateway44 rejects ordinary report");
            assert!(report.enabled&&report.supported);
            assert_eq!(report.can_export,Some(export));assert_eq!(report.can_import,Some(import));
            assert_eq!(report.devices.len(),1);assert_eq!(report.devices[0].busid,"1-2");
        }
    }
    #[test]
    fn old_gateway_never_turns_partial_roles_into_receiver_support(){
        for (export,import) in [(false,false),(true,false),(false,true),(true,true)] {
            let mut body=json!({"supported":export||import,"can_export":export,"can_import":import,"enabled":true,"devices":[]});
            legacy_report(&mut body);
            assert_eq!(body["supported"],json!(export&&import));
            assert!(body.get("can_export").is_none()&&body.get("can_import").is_none());
            assert_eq!(body["enabled"],true);
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod control_backpressure_tests {
    use super::*;
    use futures_util::SinkExt;
    use std::{
        os::fd::AsRawFd,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn scenario(revoke: bool) -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let client = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let (server, _) = listener.accept().await?;
        for (stream, opt) in [(&client, libc::SO_SNDBUF), (&server, libc::SO_RCVBUF)] {
            let size = 1024i32;
            ensure!(
                unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        opt,
                        (&size as *const i32).cast(),
                        4,
                    )
                } == 0
            );
        }
        let client = Socket::from_raw_socket(
            tokio_tungstenite::MaybeTlsStream::Plain(client),
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        let mut server = tokio_tungstenite::WebSocketStream::from_raw_socket(
            server,
            tokio_tungstenite::tungstenite::protocol::Role::Server,
            None,
        )
        .await;
        let (mut kernel, internal) = tokio::io::duplex(4096);
        let listener = tcp::Listener::bind(None).await?;
        let offer = listener.offer.clone();
        let (a, b) = tokio::join!(listener.accept(), tcp::connect(offer, None));
        let (bulk, mut peer) = (a?, b?);
        let (policy, rx) = tokio::sync::watch::channel(crate::features::Policy::default());
        let mut bridge = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(
            bridge_bulk_with_policy(internal, client, bulk, rx, None, false, Feature::Usb),
        ));
        kernel.write_all(b"initial").await?;
        let mut initial = [0u8; 7];
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut initial)).await??;
        ensure!(&initial == b"initial");
        let count = Arc::new(AtomicUsize::new(0));
        let sent = count.clone();
        let flood = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            for _ in 0..100000 {
                server
                    .send(tokio_tungstenite::tungstenite::Message::Ping(
                        vec![1; 125].into(),
                    ))
                    .await?;
                sent.fetch_add(1, Ordering::SeqCst);
            }
            Ok::<(), anyhow::Error>(())
        }));
        tokio::time::sleep(Duration::from_millis(500)).await;
        let before = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let after = count.load(Ordering::SeqCst);
        kernel.write_all(b"blocked").await?;
        let mut data = [0u8; 7];
        let payload_stalled =
            tokio::time::timeout(Duration::from_millis(300), peer.read_exact(&mut data))
                .await
                .is_err();
        let forward: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let backward: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 239) as u8).collect();
        let mut got_forward = vec![0; forward.len()];
        let mut got_backward = vec![0; backward.len()];
        {
            let (kr, kw) = tokio::io::split(&mut kernel);
            let (pr, pw) = tokio::io::split(&mut peer);
            let (mut kr, mut kw, mut pr, mut pw) = (kr, kw, pr, pw);
            tokio::time::timeout(Duration::from_secs(1), async {
                let (a, b, c, d) = tokio::join!(
                    kw.write_all(&forward),
                    pr.read_exact(&mut got_forward),
                    pw.write_all(&backward),
                    kr.read_exact(&mut got_backward)
                );
                a?;
                b?;
                c?;
                d?;
                Ok::<(), anyhow::Error>(())
            })
            .await??;
        }
        ensure!(
            got_forward == forward && got_backward == backward,
            "bulk full-duplex byte ordering changed"
        );
        peer.write_all(b"reverse").await?;
        let mut reverse = [0; 7];
        tokio::time::timeout(Duration::from_millis(300), kernel.read_exact(&mut reverse)).await??;
        ensure!(&reverse == b"reverse");
        if revoke {
            let mut disabled = crate::features::Policy::default();
            disabled.disabled.insert(Feature::Usb, true);
            policy.send_replace(disabled);
        }
        let bound = if revoke {
            Duration::from_millis(300)
        } else {
            Duration::from_secs(3)
        };
        let outcome = tokio::time::timeout(bound, &mut bridge).await?;
        flood.abort();
        let _ = flood.await;
        if revoke {
            outcome??;
        } else {
            ensure!(
                outcome?
                    .unwrap_err()
                    .to_string()
                    .contains("control write timed out")
            );
        }
        eprintln!(
            "real TCP websocket: ping_count_before={before} after={after} payload_stalled={payload_stalled} revoke={revoke}"
        );
        ensure!(
            before > 0 && before == after,
            "control sender did not become backpressured"
        );
        ensure!(!payload_stalled, "pending control must not block payload");
        Ok(())
    }
    #[tokio::test]
    async fn blocked_control_keeps_full_duplex_and_revokes_immediately() -> Result<()> {
        scenario(true).await
    }
    #[tokio::test]
    async fn blocked_control_disconnects_at_bounded_deadline() -> Result<()> {
        scenario(false).await
    }
}
