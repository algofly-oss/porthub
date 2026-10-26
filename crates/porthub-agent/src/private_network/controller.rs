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
    info: PeerInfo,
    identity: Identity,
    base: String,
    direct_origin: Option<String>,
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
pub enum Event {
    Snapshot(Snapshot),
    Packet {
        peer: String,
        bytes: Bytes,
        direct: bool,
        received_at: Instant,
    },
    #[cfg(feature = "private-stream")]
    StreamLocal {
        peer: String,
        bytes: Bytes,
    },
    #[cfg(feature = "private-stream")]
    StreamDatagram {
        destination: std::net::Ipv4Addr,
        payload: Bytes,
    },
}
pub type Sessions = Arc<RwLock<HashMap<String, Session>>>;
pub struct LocalIdentity {
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
    ensure!(
        interfaces.borrow().len() <= 16,
        "private interface limit exceeded"
    );
    let mut interface_changes_open = true;
    let LocalIdentity {
        instance,
        certificate: identity,
    } = local;
    let make_client = |local: Option<std::net::IpAddr>| reqwest::Client::builder()
        .local_address(local)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4))
        .build();
    let mut bound = interfaces.borrow().first().map(|address| address.ip());
    let mut client = make_client(bound)?;
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
        let next_bind = interfaces.borrow().first().map(|address| address.ip());
        if next_bind != bound { client = make_client(next_bind)?; bound = next_bind; }
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
            "fingerprint":identity.fingerprint(),"instance":instance,"stream_transport":if cfg!(feature="private-stream") {"quic1"} else {""},"signals":&pending[..sent],
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
                direct_url: reply.direct_relay_url.clone().filter(|url| !url.is_empty()),
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

#[cfg(test)]
mod origin_tests {
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
