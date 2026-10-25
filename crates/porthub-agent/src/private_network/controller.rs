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
    signals: Vec<Signal>,
    #[serde(default)]
    ice_servers: Vec<IceServer>,
    #[serde(default)]
    direct_relay_url: Option<String>,
    #[serde(default)]
    relay_auth_token: String,
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
    id: String,
    info: PeerInfo,
    identity: Identity,
    base: String,
    servers: Vec<IceServer>,
) -> Result<Prepared> {
    let credential = servers.iter().find(|server| {
        server
            .urls
            .iter()
            .any(|url| url == "turn:relay.porthub.invalid:443?transport=tcp")
    });
    let mut allocation = None;
    if let Some(credential) = credential {
        let mut url = url::Url::parse(&base)?;
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .map_err(|_| anyhow::anyhow!("invalid private relay URL"))?;
        url.set_path("/api/access/private/relay");
        allocation = porthub_mesh::relay::Allocation::connect(
            url.as_str(),
            &credential.username,
            &credential.credential,
            profile.allow_insecure_http_for_tests,
        )
        .await
        .ok();
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
        &id,
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
struct Live {
    info: PeerInfo,
    session: Session,
    nonce: String,
    created: Instant,
}
pub enum Event {
    Snapshot(Snapshot),
    Packet {
        peer: String,
        bytes: Bytes,
        direct: bool,
        received_at: Instant,
    },
}
pub type Sessions = Arc<RwLock<HashMap<String, Session>>>;
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
    mut interfaces: watch::Receiver<Vec<SocketAddr>>,
    sessions: Sessions,
    events: mpsc::Sender<Event>,
    relay_config: watch::Sender<Option<super::relay::Config>>,
    instance: String,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        interfaces.borrow().len() <= 16,
        "private interface limit exceeded"
    );
    let mut interface_changes_open = true;
    let identity = Identity::new()?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4))
        .build()?;
    let mut bases = vec![profile.server.clone()];
    bases.extend(profile.fallback_servers.clone());
    let mut preferred = 0;
    let mut peers: HashMap<String, Live> = HashMap::new();
    let mut readers = JoinSet::new();
    let mut preparing: JoinSet<(String, Result<Prepared>)> = JoinSet::new();
    let mut in_flight = HashSet::new();
    let mut pending: Vec<Signal> = Vec::new();
    let mut acks: Vec<String> = Vec::new();
    let mut seen: HashMap<String, Instant> = HashMap::new();
    loop {
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
        let body = serde_json::json!({"peer_id":profile.peer_id,"token":profile.token,
            "fingerprint":identity.fingerprint(),"instance":instance,"signals":&pending[..sent],
            "acks":&acks[..acked],"paths":paths});
        let mut reply = None;
        for offset in 0..bases.len() {
            let index = (preferred + offset) % bases.len();
            let request = async {
                let mut response = client
                    .post(format!("{}/api/access/private/sync", bases[index]))
                    .json(&body)
                    .send()
                    .await?;
                let status = response.status();
                if status == reqwest::StatusCode::FORBIDDEN
                    || status == reqwest::StatusCode::UNAUTHORIZED
                {
                    anyhow::bail!("private gateway rejected this enrollment");
                }
                ensure!(
                    status.is_success(),
                    "private control temporarily unavailable"
                );
                let mut data = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    ensure!(
                        data.len() + chunk.len() <= 4 * 1024 * 1024,
                        "private sync exceeds size limit"
                    );
                    data.extend_from_slice(&chunk);
                }
                serde_json::from_slice::<Reply>(&data)
                    .map_err(|_| anyhow::anyhow!("invalid private control response"))
            };
            let result =
                tokio::select! {_=cancel.cancelled()=>return Ok(()),result=request=>result};
            if let Ok(value) = result {
                preferred = index;
                reply = Some(value);
                break;
            }
        }
        if let Some(reply) = reply {
            let direct_relay = super::relay::Config {
                direct_url: reply.direct_relay_url.filter(|url| !url.is_empty()),
                relay_token: (32..=128)
                    .contains(&reply.relay_auth_token.len())
                    .then(|| reply.relay_auth_token.clone()),
            };
            if *relay_config.borrow() != Some(direct_relay.clone()) {
                relay_config.send_replace(Some(direct_relay));
            }
            ensure!(
                reply.snapshot.self_ == profile.peer_id
                    && reply.snapshot.workspace == profile.workspace,
                "private gateway returned a different identity"
            );
            ensure!(
                reply.snapshot.peers.len() <= 4096 && reply.signals.len() <= 128,
                "private sync exceeds limits"
            );
            pending.drain(..sent);
            acks.drain(..acked);
            let now = Instant::now();
            let current_interfaces = interfaces.borrow_and_update().clone();
            ensure!(
                current_interfaces.len() <= 16,
                "private interface limit exceeded"
            );
            seen.retain(|_, at| now.duration_since(*at) < Duration::from_secs(90));
            let valid: HashMap<_, _> = reply
                .snapshot
                .peers
                .iter()
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
                let servers = reply.ice_servers.clone();
                preparing.spawn(async move {
                    let result = prepare(
                        profile,
                        interfaces,
                        id.clone(),
                        info,
                        identity,
                        base,
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
            tokio::select! {_=cancel.cancelled()=>return Ok(()), result=events.send(Event::Snapshot(reply.snapshot))=>ensure!(result.is_ok(),"private packet owner closed")};
        }
        while readers.try_join_next().is_some() {}
        let interval = if pending.is_empty()
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
            _=tokio::time::sleep(Duration::from_secs(interval))=>{}
        }
    }
}

async fn read_packets(
    mut packets: mpsc::Receiver<Bytes>,
    peer: String,
    events: mpsc::Sender<Event>,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {_=cancel.cancelled()=>break,
            packet=packets.recv()=>{let Some(bytes)=packet else {break;};
                let _=events.try_send(Event::Packet{peer:peer.clone(),bytes,direct:true,received_at:Instant::now()});
            }
        }
    }
}
