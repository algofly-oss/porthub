//! Bounded control/signaling owner. HTTPS never runs in the packet forwarding
//! loop, and a session is replaced only on a peer process/certificate change.
use super::policy::{PeerInfo, Snapshot};
use crate::private_profile::Profile;
use anyhow::{ensure, Result};
use bytes::Bytes;
use porthub_mesh::{udp::Session, Description, Identity, Kind, State};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch, RwLock},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
#[derive(Clone, Deserialize, Serialize)]
struct Signal {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    from: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    to: String,
    session: String,
    description: Description,
}
#[derive(Deserialize)]
struct Reply {
    snapshot: Snapshot,
    #[serde(default)]
    sparse_sequence: Option<u64>,
    #[serde(default)]
    pair_responses: Vec<porthub_network::policy::PairResponse>,
    #[serde(default)]
    stream_protocols:Vec<String>,
    #[serde(default)]
    signals: Vec<Signal>,
    #[serde(default)]
    ice_servers: Vec<IceServer>,
    #[serde(default)]
    direct_relay_url: Option<String>,
    #[serde(default)]
    relay_auth_token: String,
    #[serde(default)]
    proxy_jobs: Vec<String>,
    #[serde(default)]
    proxy_provider: bool,
}
#[derive(Clone, Deserialize)]
struct IceServer {
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    credential: String,
}
struct Prepared {
    info: PeerInfo,
    interfaces: Vec<SocketAddr>,
    session: Session,
    packets: mpsc::Receiver<Bytes>,
}
async fn prepare(
    profile: Profile,
    interfaces: Vec<SocketAddr>,
    info: PeerInfo,
    identity: Identity,
    base: String,
    direct_origin: Option<String>,
    servers: Vec<IceServer>,
) -> Result<Prepared> {
    let settings = crate::outbound::Settings::from_env()?;
    let interfaces = if profile.allow_insecure_http_for_tests || settings.system { interfaces } else {
        let url = url::Url::parse(&base)?;
        let host = url.host_str().ok_or_else(|| anyhow::anyhow!("gateway hostname missing"))?;
        let destinations: Vec<_> = tokio::time::timeout(Duration::from_secs(2),tokio::net::lookup_host((host.trim_matches(['[',']']),url.port_or_known_default().unwrap_or(443)))).await??.take(16).collect();
        let permitted = tokio::time::timeout(Duration::from_secs(2),crate::outbound::discover(&settings,&destinations)).await??;
        interfaces.into_iter().filter(|address|permitted.iter().any(|p|p.source==address.ip())).collect()
    };
    ensure!(!interfaces.is_empty(), "no policy-permitted private session source; check interface preferences and VPN routing");
    let credential = servers.iter().find(|server| {
        server
            .urls
            .iter()
            .any(|url| url == "turn:relay.porthub.invalid:443?transport=tcp")
    });
    let mut allocation = None;
    if let Some(credential) = credential {
        for (url, allow_plaintext) in turn_origins(
            direct_origin.as_deref(),
            &base,
            profile.allow_insecure_http_for_tests,
        ) {
            // Origin discovery comes from authenticated sync. Negotiation stays
            // in this background task; payloads retain peer-pinned DTLS.
            if let Ok(Ok(ready)) = tokio::time::timeout(
                Duration::from_secs(3),
                porthub_mesh::relay::Allocation::connect_bound(
                    url.as_str(),
                    &credential.username,
                    &credential.credential,
                    allow_plaintext,
                    &interfaces.iter().map(|address| address.ip()).collect::<Vec<_>>(),
                ),
            )
            .await
            {
                allocation = Some(ready);
                break;
            }
        }
    }
    let stun_servers: Vec<_> = servers
        .iter()
        .flat_map(|server| server.urls.iter())
        .filter(|url| url.starts_with("stun:"))
        .take(2)
        .cloned()
        .collect();
    let (session, packets) = Session::gather(
        &interfaces,
        &profile.peer_id,
        &info.id,
        identity,
        &info.fingerprint,
        allocation,
        &stun_servers,
    )
    .await?;
    Ok(Prepared {
        info,
        interfaces,
        session,
        packets,
    })
}
fn turn_origins(
    direct_origin: Option<&str>,
    base: &str,
    allow_plaintext_base: bool,
) -> Vec<(url::Url, bool)> {
    let mut result = Vec::new();
    for (origin, explicit) in direct_origin
        .into_iter()
        .map(|origin| (origin, true))
        .chain(std::iter::once((base, false)))
    {
        let Ok(mut url) = url::Url::parse(origin) else {
            continue;
        };
        if url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            continue;
        }
        let allow_plaintext = explicit || allow_plaintext_base;
        let scheme = match url.scheme() {
            "https" => "wss",
            "http" if allow_plaintext => "ws",
            _ => continue,
        };
        if url.set_scheme(scheme).is_err() {
            continue;
        }
        url.set_path("/api/access/private/relay");
        if !result.iter().any(|(existing, _)| *existing == url) {
            result.push((url, allow_plaintext));
        }
    }
    result
}
struct Live {
    info: PeerInfo,
    session: Session,
    nonce: String,
    created: Instant,
}
// Advertisement follows negotiated mode. Sparse must never offer PHT1 while
// application/retransmission origins are not bounded by an ACK-chunk protocol.
#[path="stream_offer.rs"]
mod stream_offer;
use stream_offer::Offer as StreamOffer;
pub(crate) use stream_offer::NativeReady;

pub enum Event {
    #[cfg(feature = "local-tor")]
    TorLocal { bytes: Bytes },
    Snapshot(super::authority_event::Authority<Snapshot>),
    Pair(super::authority_event::Authority<porthub_network::policy::PairResponse>),
    Packet {
        peer: String,
        bytes: Bytes,
        direct: bool,
        carrier_direct: bool,
        received_at: Instant,
    },
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    GuardedStreamLocal {
        peer:String,
        packet:porthub_network::tcp_stream::tagged::Packet,
    },
    #[cfg(feature = "private-stream")]
    StreamLocal {
        peer: String,
        bytes: Bytes,
        scope:porthub_mesh::udp::SendPermit,
    },
    #[cfg(feature = "private-stream")]
    StreamDatagram {
        permit:Option<porthub_mesh::udp::SendPermit>,
        destination: std::net::Ipv4Addr,
        payload: Bytes,
    },
}
pub type Sessions = Arc<RwLock<HashMap<String, Session>>>;
pub struct LocalIdentity {
    pub traffic: Option<Arc<super::traffic::Tracker>>,
    pub instance: String,
    pub certificate: Identity,
}
pub fn nonce() -> Result<String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| anyhow::anyhow!("private session randomness unavailable"))?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}
pub async fn run(
    profile: Profile,
    interfaces: Vec<SocketAddr>,
    sessions: Sessions,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) -> Result<()> {
    run_instance(profile, interfaces, sessions, events, nonce()?, cancel).await
}
pub async fn run_instance(
    profile: Profile,
    interfaces: Vec<SocketAddr>,
    sessions: Sessions,
    events: mpsc::Sender<Event>,
    instance: String,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        !interfaces.is_empty() && interfaces.len() <= 16,
        "no usable private network interface"
    );
    let (_sender, interfaces) = watch::channel(interfaces);
    let (relay_config, _) = watch::channel(None);
    run_watched_instance(
        profile,
        interfaces,
        sessions,
        events,
        relay_config,
        instance,
        cancel,
    )
    .await
}
/// The packet owner supplies a kernel-driven interface snapshot. An empty
/// snapshot pauses new peer preparations without tearing down healthy sessions
/// or preventing authenticated policy/relay discovery during a network outage.
pub async fn run_watched_instance(
    profile: Profile,
    interfaces: watch::Receiver<Vec<SocketAddr>>,
    sessions: Sessions,
    events: mpsc::Sender<Event>,
    relay_config: watch::Sender<Option<super::relay::Config>>,
    instance: String,
    cancel: CancellationToken,
) -> Result<()> {
    run_watched_identity(
        profile,
        interfaces,
        sessions,
        events,
        relay_config,
        LocalIdentity {
            traffic: None,
            instance,
            certificate: Identity::new()?,
        },
        cancel,
    )
    .await
}
pub async fn run_watched_identity(
    profile: Profile,
    mut interfaces: watch::Receiver<Vec<SocketAddr>>,
    sessions: Sessions,
    events: mpsc::Sender<Event>,
    relay_config: watch::Sender<Option<super::relay::Config>>,
    local: LocalIdentity,
    cancel: CancellationToken,
) -> Result<()> {
    run_watched_sparse(profile,interfaces,sessions,events,relay_config,local,cancel,None).await
}
pub async fn run_watched_sparse(
    profile: Profile,
    interfaces: watch::Receiver<Vec<SocketAddr>>,
    sessions: Sessions,
    events: mpsc::Sender<Event>,
    relay_config: watch::Sender<Option<super::relay::Config>>,
    local: LocalIdentity,
    cancel: CancellationToken,
    sparse: Option<super::sparse::Control>,
) -> Result<()> {
    run_watched_sparse_owned(profile,interfaces,sessions,events,relay_config,local,cancel,sparse,None,None,None).await
}
pub(crate) async fn run_watched_sparse_owned(
    profile: Profile,
    mut interfaces: watch::Receiver<Vec<SocketAddr>>,
    sessions: Sessions,
    events: mpsc::Sender<Event>,
    relay_config: watch::Sender<Option<super::relay::Config>>,
    local: LocalIdentity,
    cancel: CancellationToken,
    mut sparse: Option<super::sparse::Control>,
    authority_domain:Option<super::authority_event::Domain>,
    native_streams:Option<watch::Receiver<Option<NativeReady>>>,
    native_profile:Option<std::path::PathBuf>,
) -> Result<()> {
    ensure!(
        interfaces.borrow().len() <= 16,
        "private interface limit exceeded"
    );
    let mut interface_changes_open = true;
    let LocalIdentity {
        traffic,
        instance,
        certificate: identity,
    } = local;
    let control = crate::control::Control::new_private(&profile)?;
    let mut bases = control.authorities();
    // Never advertise PHT1 for guarded sparse mode until ACK-chunk provenance exists.
    // An older gateway declining sparse negotiation restores legacy PHT1 next sync.
    let mut stream_offer=StreamOffer::new(sparse.is_some());
    let mut preferred = 0;
    let mut peers: HashMap<String, Live> = HashMap::new();
    let mut readers = JoinSet::new();
    let mut preparing: JoinSet<(String, Result<Prepared>)> = JoinSet::new();
    let mut in_flight = HashSet::new();
    let mut pending: Vec<Signal> = Vec::new();
    let mut acks: Vec<String> = Vec::new();
    let mut seen: HashMap<String, Instant> = HashMap::new();
    #[cfg(feature="local-tor")]
    let proxy_manager=super::proxy_egress::Manager::start(profile.clone(),interfaces.clone(),cancel.clone());
    let mut lan_interfaces = Vec::new();
    let mut lan_networks = Vec::new();
    let mut lan_refreshed = None::<Instant>;
    loop {
        let cycle_started=tokio::time::Instant::now();
        let current_interfaces = interfaces.borrow().clone();
        if current_interfaces != lan_interfaces
            || lan_refreshed.is_none_or(|at| at.elapsed() >= Duration::from_secs(60))
        {
            // Refresh outside the packet loop. Failure clears stale advertisements
            // without blocking the authenticated control heartbeat.
            lan_networks = super::lan_discovery::connected(&current_interfaces).unwrap_or_default();
            lan_interfaces = current_interfaces;
            lan_refreshed = Some(Instant::now());
        }
        let sent = pending.len().min(16);
        let acked = acks.len().min(128);
        let paths: BTreeMap<_, _> = peers
            .iter()
            .map(|(id, peer)| {
                (
                    id.clone(),
                    if peer.session.state() == State::Ready {
                        if peer.session.is_relay() {
                            "relay"
                        } else {
                            "direct"
                        }
                    } else {
                        "connecting"
                    },
                )
            })
            .collect();
        let mut body = serde_json::json!({"peer_id":profile.peer_id,"token":profile.token,
            "fingerprint":identity.fingerprint(),"instance":instance,"stream_transport":stream_offer.offered(native_streams.as_ref()),"tor_exit":cfg!(all(feature="local-tor",any(target_os="linux",target_os="macos"))),"signals":&pending[..sent],
            "acks":&acks[..acked],"paths":paths,"lan_networks":lan_networks,"lan_exit":cfg!(any(target_os="linux",target_os="macos")),"application_proxy":cfg!(feature="local-tor")});
        if let Some(resolver)=&mut sparse {body["sparse"]=resolver.batch()?;
            if let Some(path)=&native_profile{if let Some(repair)=super::native_owner::repair_request(path)?{body["native_repair"]=serde_json::to_value(repair)?;}}
        }
        if let Some(report)=traffic.as_ref().and_then(|t|t.report()){body["traffic"]=serde_json::to_value(report)?;}
        let sent_sequence=body["traffic"]["rows"].as_array().and_then(|r|r.last()).and_then(|r|r["sequence"].as_u64()).unwrap_or(0);
        let mut reply = None;
        let request_window = super::authority_event::request_start(authority_domain.as_ref())?;
        let request = control.request(reqwest::Method::POST,"access/private/sync",Some(body),&[]);
        let result = tokio::select! { _=cancel.cancelled()=>return Ok(()), result=request=>result };
        match result {
            Ok(value) => {
                if sent_sequence>0 {if let Ok(reply)=serde_json::from_slice::<serde_json::Value>(&value.bytes){if let Some(ack)=reply["traffic_ack"].as_u64().filter(|ack|*ack<=sent_sequence){if let Some(t)=&traffic{t.acknowledge(ack,reply["traffic_discarded_rows"].as_u64().unwrap_or(0));}}}}
                reply = serde_json::from_slice::<Reply>(&value.bytes).ok();
                bases = control.authorities();
                preferred = 0;
            }
            Err(crate::control::Failure::Rejected(401 | 403)) => {if let Some(resolver)=&sparse{resolver.handle().revoke_all();}cancel.cancel();anyhow::bail!("private gateway rejected this enrollment");},
            Err(_) => {}
        }
        if let Some(mut reply) = reply {
            stream_offer.observe_reply(&reply.snapshot,&reply.stream_protocols);
            let request_window = if reply.snapshot.sparse.is_some() {request_window} else {None};
            super::authority_event::Authority::new((),request_window.clone(),reply.snapshot.expires_at).check()?;
            ensure!(reply.snapshot.sparse.is_none()||sparse.is_some(),"sparse private authority was not negotiated");
            ensure!(reply.snapshot.pair_acl.is_none(),"pair-only compact ACL supplied as base authority");
            ensure!(reply.pair_responses.len()<=32,"private pair response exceeds limits");
            ensure!(
                reply.snapshot.self_ == profile.peer_id
                    && reply.snapshot.workspace == profile.workspace,
                "private gateway returned a different identity"
            );
            ensure!(
                reply.snapshot.peers.len() <= 4096 && reply.signals.len() <= 128 && reply.proxy_jobs.len() <=64,
                "private sync exceeds limits"
            );
            #[cfg(feature="local-tor")]
            {
                let mut origins=Vec::new();
                if let Some(origin)=&reply.direct_relay_url {origins.push(origin.clone());}
                origins.extend(bases.iter().cloned());origins.dedup();
                proxy_manager.update(origins,reply.proxy_provider,&reply.proxy_jobs);
            }
            pending.drain(..sent);
            acks.drain(..acked);
            let now = Instant::now();
            let current_interfaces = interfaces.borrow_and_update().clone();
            ensure!(
                current_interfaces.len() <= 16,
                "private interface limit exceeded"
            );
            seen.retain(|_, at| now.duration_since(*at) < Duration::from_secs(90));
            let mut transport_peers=reply.snapshot.peers.clone();
            if let Some(resolver)=&sparse {
                if reply.snapshot.sparse.is_some() {
                    ensure!(reply.sparse_sequence==Some(resolver.sequence()),"private pair response sequence changed");
                    resolver.handle().update_base_authority(&reply.snapshot,super::authority_event::Authority::new((),request_window.clone(),reply.snapshot.expires_at));
                    transport_peers.extend(resolver.handle().peers());
                    let mut validator=porthub_network::policy::Engine::default();validator.apply(reply.snapshot.clone())?;
                    for cached in resolver.handle().leases(){let _=validator.install_pair(cached);}
                    for resolution in &mut reply.pair_responses {
                        if resolution.status=="allowed" {
                            if let Some(lease)=&resolution.lease {
                                // Validate independent authority before spending a transport slot. Native
                                // packet owner repeats this check before installing routes or exposing DNS.
                                if validator.install_pair(lease.clone()).is_ok(){transport_peers.push(lease.peer.clone());}
                                else {resolution.status="invalid".into();resolution.lease=None;}
                            }
                        }
                    }
                } else {resolver.handle().update_base_authority(&reply.snapshot,super::authority_event::Authority::new((),request_window.clone(),reply.snapshot.expires_at));}
            }
            let direct_relay = if reply.snapshot.sparse.is_some() && transport_peers.iter().all(|p|p.id==profile.peer_id){None}else{Some(super::relay::Config {
                direct_url: reply.direct_relay_url.clone().filter(|url|!url.is_empty()),
                relay_token:(32..=128).contains(&reply.relay_auth_token.len()).then(||reply.relay_auth_token.clone()),
            })};
            if *relay_config.borrow()!=direct_relay{relay_config.send_replace(direct_relay);}
            let valid: HashMap<_, _> = transport_peers.iter()
                .filter(|peer| peer.id != profile.peer_id)
                .map(|peer| (peer.id.clone(), peer))
                .collect();
            let remove: Vec<_> = peers
                .iter()
                .filter(|(id, live)| {
                    valid.get(*id).is_none_or(|info| {
                        info.fingerprint != live.info.fingerprint
                            || info.instance != live.info.instance
                    }) || (matches!(live.session.state(), State::Closed | State::Failed)
                        && live.created.elapsed() > Duration::from_secs(10))
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in remove {
                if let Some(live) = peers.remove(&id) {
                    live.session.close().await;
                }
                sessions.write().await.remove(&id);
                pending.retain(|signal| signal.to != id);
            }
            // Preparation, including gateway allocation, never holds up sync
            // leases or packet forwarding. Bound both concurrent negotiations
            // and the total number of peer transports.
            while let Some(result) = preparing.try_join_next() {
                let Ok((id, result)) = result else {
                    continue;
                };
                in_flight.remove(&id);
                let Ok(prepared) = result else {
                    continue;
                };
                if !valid.get(&id).is_some_and(|info| {
                    info.fingerprint == prepared.info.fingerprint
                        && info.instance == prepared.info.instance
                }) || !prepared
                    .interfaces
                    .iter()
                    .any(|address| current_interfaces.contains(address))
                {
                    prepared.session.close().await;
                    continue;
                }
                let session = prepared.session;
                readers.spawn(read_packets(
                    prepared.packets,
                    session.clone(),
                    id.clone(),
                    events.clone(),
                    cancel.clone(),
                ));
                let nonce = nonce()?;
                if profile.peer_id < id {
                    pending.push(Signal {
                        id: String::new(),
                        from: String::new(),
                        to: id.clone(),
                        session: nonce.clone(),
                        description: session.description(),
                    });
                }
                sessions.write().await.insert(id.clone(), session.clone());
                peers.insert(
                    id,
                    Live {
                        info: prepared.info,
                        session,
                        nonce,
                        created: now,
                    },
                );
            }
            let mut order: Vec<_> = valid.keys().cloned().collect();
            order.sort();
            for id in order {
                let info = valid[&id];
                if current_interfaces.is_empty()
                    || peers.len() + in_flight.len() >= 64
                    || in_flight.len() >= 4
                {
                    break;
                }
                if peers.contains_key(&id)
                    || in_flight.contains(&id)
                    || info.fingerprint.is_empty()
                    || info.instance.is_empty()
                {
                    continue;
                }
                in_flight.insert(id.clone());
                let profile = profile.clone();
                let interfaces = current_interfaces.clone();
                let info = info.clone();
                let identity = identity.clone();
                let base = bases[preferred].clone();
                let direct_origin = reply.direct_relay_url.clone();
                let servers = reply.ice_servers.clone();
                preparing.spawn(async move {
                    let result = prepare(
                        profile,
                        interfaces,
                        info,
                        identity,
                        base,
                        direct_origin,
                        servers,
                    )
                    .await;
                    (id, result)
                });
            }
            for signal in reply.signals {
                if signal.id.is_empty() || signal.id.len() > 128 || signal.session.len() > 64 {
                    continue;
                }
                if seen.contains_key(&signal.id) {
                    if acks.len() < 1024 {
                        acks.push(signal.id.clone());
                    }
                    continue;
                }
                if seen.len() >= 8192 {
                    continue;
                }
                let Some(live) = peers.get_mut(&signal.from) else {
                    continue;
                };
                let accepted = match signal.description.r#type {
                    Kind::Offer if profile.peer_id > signal.from => {
                        if live.session.state() != State::Waiting && live.nonce != signal.session {
                            live.session.close().await;
                            peers.remove(&signal.from);
                            sessions.write().await.remove(&signal.from);
                            pending.retain(|pending| pending.to != signal.from);
                            // Leave this offer unacknowledged. The next sync
                            // prepares a fresh transport in the background;
                            // the gateway will replay the same offer to it.
                            continue;
                        }
                        if live
                            .session
                            .remote(&signal.from, signal.description)
                            .await
                            .is_ok()
                        {
                            live.nonce = signal.session.clone();
                            pending.push(Signal {
                                id: String::new(),
                                from: String::new(),
                                to: signal.from.clone(),
                                session: signal.session,
                                description: live.session.description(),
                            });
                            true
                        } else {
                            false
                        }
                    }
                    Kind::Answer | Kind::Candidate if live.nonce == signal.session => live
                        .session
                        .remote(&signal.from, signal.description)
                        .await
                        .is_ok(),
                    _ => false,
                };
                if accepted {
                    if acks.len() < 1024 {
                        acks.push(signal.id.clone());
                    }
                    seen.insert(signal.id, now);
                }
            }
            ensure!(
                pending.len() <= 1024,
                "private signaling backlog exceeds limit"
            );
            let response_expiry=reply.snapshot.expires_at;
            tokio::select! {_=cancel.cancelled()=>return Ok(()), result=events.send(Event::Snapshot(super::authority_event::Authority::new(reply.snapshot,request_window.clone(),response_expiry)))=>ensure!(result.is_ok(),"private packet owner closed")};
            for resolution in reply.pair_responses {
                tokio::select!{_=cancel.cancelled()=>return Ok(()),result=events.send(Event::Pair(super::authority_event::Authority::new(resolution,request_window.clone(),response_expiry)))=>ensure!(result.is_ok(),"private pair owner closed")};
            }
        }
        while readers.try_join_next().is_some() {}
        let interval = if sparse.as_ref().is_some_and(|s|s.handle().enabled()&&s.urgent()){1}else if pending.is_empty()
            && in_flight.is_empty()
            && peers
                .values()
                .all(|peer| peer.session.state() == State::Ready)
        {
            5
        } else {
            1
        };
        tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            changed=interfaces.changed(), if interface_changes_open=>{
                if changed.is_err() { interface_changes_open=false; }
            },
            _=tokio::time::sleep(Duration::from_secs(interval))=>{},_=async{if let Some(resolver)=&sparse{resolver.demand().await}else{std::future::pending::<()>().await}}=>{}
        }
        // Miss notifications coalesce; a local packet flood cannot turn lookup into an
        // unbounded HTTP loop or starve ordinary lease renewal/other registrations.
        if sparse.is_some(){tokio::select!{_=cancel.cancelled()=>return Ok(()),_=tokio::time::sleep_until(cycle_started+Duration::from_secs(1))=>{}}}
    }
}

// Protocol `direct` means the peer RTC carrier (including TURN), not the
// physically direct path. Keep QoS/path selection unchanged; telemetry gets a
// separate actual carrier-path classification.
fn peer_packet(peer:String,bytes:Bytes,relayed:bool)->Event {
    Event::Packet{peer,bytes,direct:true,carrier_direct:!relayed,received_at:Instant::now()}
}

async fn read_packets(
    mut packets: mpsc::Receiver<Bytes>,
    session: Session,
    peer: String,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {_=cancel.cancelled()=>break,
            packet=packets.recv()=>{let Some(bytes)=packet else {break;};
                let _=events.try_send(peer_packet(peer.clone(),bytes,session.is_relay()));
            }
        }
    }
}

#[cfg(test)]
mod origin_tests {
    #[test]
    fn stream_advertisement_declines_sparse_and_restores_legacy_after_old_gateway_reply(){
        let expected=if cfg!(feature="private-stream"){"quic1"}else{""};
        assert_eq!(super::StreamOffer::new(false).transport(),expected);
        let mut offer=super::StreamOffer::new(true);assert_eq!(offer.transport(),"");
        offer.observe(false);assert_eq!(offer.transport(),expected);
        offer.observe(true);assert_eq!(offer.transport(),"");
        offer.observe(false);assert_eq!(offer.transport(),expected);
    }

    use super::turn_origins;
    #[test]
    fn authenticated_direct_turn_origin_precedes_secure_fallback() {
        let origins = turn_origins(
            Some("http://192.0.2.1:8345/api"),
            "https://gateway.example/api",
            false,
        );
        assert_eq!(origins.len(), 2);
        assert_eq!(
            origins[0].0.as_str(),
            "ws://192.0.2.1:8345/api/access/private/relay"
        );
        assert!(origins[0].1);
        assert_eq!(origins[1].0.scheme(), "wss");
        assert!(!origins[1].1);
        assert!(turn_origins(None, "http://gateway.example", false).is_empty());
    }
    #[test]
    fn turn_origin_rejects_embedded_credentials_and_url_metadata() {
        for origin in [
            "http://user:secret@192.0.2.1",
            "http://192.0.2.1/?token=secret",
            "http://192.0.2.1/#fragment",
            "file:///tmp/socket",
        ] {
            let origins = turn_origins(Some(origin), "https://gateway.example", false);
            assert_eq!(origins.len(), 1);
            assert_eq!(origins[0].0.scheme(), "wss");
        }
    }
}

#[cfg(test)]
mod telemetry_carrier_tests {
    use super::*;
    #[test]
    fn turn_traffic_is_relayed_without_changing_peer_probe_protocol_identity() {
        let mut sender=super::super::probe::Quality::default();
        let mut receiver=super::super::probe::Quality::default();
        let now=Instant::now();let mut replies=0;
        for packet in sender.start("peer",true,123,now) {
            let Event::Packet{bytes,direct,carrier_direct,..}=peer_packet("peer".into(),packet,true)else{unreachable!()};
            assert!(direct);assert!(!carrier_direct);
            replies+=receiver.handle("peer",direct,&bytes,now).unwrap().len();
        }
        assert_eq!(replies,super::super::probe::PROBE_PACKETS as usize);
        let Event::Packet{direct,carrier_direct,..}=peer_packet("peer".into(),Bytes::new(),false)else{unreachable!()};assert!(direct&&carrier_direct);
    }
}
