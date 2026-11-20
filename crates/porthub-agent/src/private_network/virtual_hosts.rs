//! An assigned virtual host is a separate ACL principal with its own mesh identity.
//! Its packet worker terminates only authorized TCP and UDP flows to a fixed LAN host.
use super::{
    authority_event::{self, Authority},
    controller, relay, sparse,
};
use crate::private_profile::Profile;
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use porthub_mesh::udp::SendPermit;
use porthub_network::{
    policy::{Engine, Packet},
    tcp_stream::{Flow, tagged},
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
mod flows;
mod lan;
use lan::Lan;

#[derive(Clone, Deserialize, PartialEq, Eq)]
pub struct Spec {
    pub(super) peer_id: String,
    pub(super) target_ip: Ipv4Addr,
    pub(super) token: String,
}
type Assignments = watch::Receiver<Option<Authority<Vec<Spec>>>>;

pub(super) fn validate(hosts: &[Spec], parent: &Profile) -> Result<()> {
    ensure!(hosts.len() <= 64, "too many virtual hosts");
    let mut ids = HashSet::new();
    for h in hosts {
        ensure!(
            h.peer_id.len() <= 128
                && h.peer_id
                    .split_once(':')
                    .is_some_and(|(workspace, id)| workspace == parent.workspace
                        && id.len() == 24
                        && id.bytes().all(|b| b.is_ascii_hexdigit()))
                && h.peer_id != parent.peer_id
                && ids.insert(&h.peer_id)
                && h.target_ip.is_private()
                && (32..=256).contains(&h.token.len()),
            "invalid virtual host assignment"
        );
    }
    Ok(())
}

#[derive(Clone)]
struct Parent {
    spec: Arc<Spec>,
    assignments: Assignments,
    stop: CancellationToken,
}
impl Parent {
    fn authority(&self) -> Option<Authority<()>> {
        if self.stop.is_cancelled() {
            return None;
        }
        let list = self.assignments.borrow();
        let authority = list.as_ref()?;
        // remaining() checks the same live witness and retirement domain as
        // accepted(), and also requires a bounded assignment.
        (authority.remaining().ok()?? > Duration::ZERO
            && authority.value.iter().any(|h| h == self.spec.as_ref()))
        .then(|| authority.retained())
    }
    fn permit(&self) -> Option<SendPermit> {
        let bound = self.authority()?;
        let parent = self.clone();
        Some(SendPermit::bounded(
            move || parent.authority().is_some(),
            move || bound.remaining().ok().flatten(),
        ))
    }
}

pub(super) async fn manage(
    parent: Profile,
    interfaces: watch::Receiver<Vec<SocketAddr>>,
    mut lists: Assignments,
    stop: CancellationToken,
) -> Result<()> {
    let mut running: HashMap<String, (Arc<Spec>, CancellationToken)> = HashMap::new();
    let mut tasks = JoinSet::new();
    let mut identities = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=stop.cancelled()=>break,
            changed=lists.changed()=>if changed.is_err(){break},
            _=tick.tick()=>{},
            Some(joined)=tasks.join_next_with_id(),if !tasks.is_empty()=>{
                let task=match joined {Ok((task,()))=>task,Err(error)=>error.id()};
                if let Some(id)=identities.remove(&task){running.remove(&id); }
                continue;
            }
        }
        let desired = lists
            .borrow()
            .as_ref()
            .and_then(|a| a.accepted().ok())
            .cloned()
            .unwrap_or_default();
        // Keep the old owner until its worker exits, including when a child is replaced.
        for (id, (spec, cancel)) in &running {
            if !desired
                .iter()
                .any(|h| &h.peer_id == id && h == spec.as_ref())
            {
                cancel.cancel();
            }
        }
        for spec in desired {
            if running.contains_key(&spec.peer_id) {
                continue;
            }
            let token = stop.child_token();
            let protected = Parent {
                spec: Arc::new(spec),
                assignments: lists.clone(),
                stop: token.clone(),
            };
            let id = protected.spec.peer_id.clone();
            running.insert(id.clone(), (protected.spec.clone(), token.clone()));
            let mut profile = parent.clone();
            profile.peer_id = id.clone();
            profile.token = protected.spec.token.clone();
            let links = interfaces.clone();
            let worker = tasks.spawn(async move {
                let _guard = token.clone().drop_guard();
                if run(profile, protected, links).await.is_err() && !token.is_cancelled() {
                    tracing::debug!("virtual host private worker will retry");
                }
            });
            identities.insert(worker.id(), id);
        }
    }
    for (_, cancel) in running.values() {
        cancel.cancel();
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[derive(Clone)]
struct Admission {
    parent: Parent,
    pairs: sparse::Handle,
    peer: String,
    domain: authority_event::Domain,
}
impl Admission {
    fn current(&self) -> Option<SendPermit> {
        if !self.domain.valid() {
            return None;
        }
        let base = self.pairs.current_base()?;
        let child = authority_event::send_permit(Some(&base), &self.pairs, &self.peer).ok()??;
        let domain = self.domain.clone();
        Some(
            SendPermit::combine(vec![child, self.parent.permit()?])
                .constrain(move || domain.valid()),
        )
    }
}

/// A session reader or stamped relay record can signal changed peer metadata.
/// The triggering packet is discarded; a subsequent packet needs an exact match.
fn packet_origin_matches(
    current: &porthub_network::policy::PeerInfo,
    origin: &porthub_network::policy::PeerInfo,
    direct: bool,
    refresh: impl FnOnce(),
) -> bool {
    if current.id != origin.id || current.ip != origin.ip {
        return false;
    }
    let identity_matches = current.instance == origin.instance && current.fingerprint == origin.fingerprint;
    if direct {
        if !identity_matches { refresh(); }
        return identity_matches;
    }
    let Some(stamp) = origin.relay_origin.as_deref() else { return false; };
    if stamp.len() != 32 || !stamp.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return false;
    }
    if identity_matches && current.relay_origin.as_deref() == Some(stamp) {
        return true;
    }
    refresh();
    false
}

async fn run(
    profile: Profile,
    parent: Parent,
    interfaces: watch::Receiver<Vec<SocketAddr>>,
) -> Result<()> {
    let stop = parent.stop.child_token();
    let _guard = stop.clone().drop_guard();
    let (pairs, control) = sparse::channel();
    let (event_tx, mut events) = mpsc::channel(512);
    let sessions: controller::Sessions = Default::default();
    let instance = controller::nonce()?;
    let (config_tx, config_rx) = watch::channel(None);
    let (relay, packets) = relay::channel();
    let mut owners = JoinSet::new();
    let authority_owner = authority_event::Owner::new();
    owners.spawn(controller::run_endpoint(
        profile.clone(),
        interfaces.clone(),
        sessions.clone(),
        event_tx.clone(),
        config_tx,
        controller::LocalIdentity {
            traffic: None,
            instance: instance.clone(),
            certificate: porthub_mesh::Identity::new()?,
        },
        stop.clone(),
        Some(control),
        Some(authority_owner.domain()),
        None,
        None,
        true,
    ));
    owners.spawn(relay::run_bound(
        profile.clone(),
        instance,
        relay.clone(),
        packets,
        config_rx,
        interfaces.clone(),
        event_tx,
        stop.clone(),
    ));
    let (stack, mut tcp_out, runner) = tagged::forwarding_stack()?;
    owners.spawn(runner.run(stop.clone()));
    let (udp_send, mut udp_out) = mpsc::channel(256);
    let mut flows = flows::Flows::new(stack, udp_send);
    let mut policy = Engine::default();
    let mut paths = porthub_network::paths::Pinned::default();
    let mut own = None;
    let mut refreshed = HashMap::<String, std::time::Instant>::new();
    let lan = Lan::find(parent.spec.target_ip, &interfaces.borrow())?;
    let mut audit = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _=stop.cancelled()=>break,
            Some(_)=owners.join_next()=>break,
            _=audit.tick()=>{
                ensure!(parent.authority().is_some(),"virtual host parent unavailable");
                ensure!(lan==Lan::find(parent.spec.target_ip,&interfaces.borrow())?,"virtual host LAN changed");
                if own.is_some(){ensure!(pairs.authority_valid() && policy.valid_lease(),"virtual host lease expired");}
                flows.prune();
                refreshed.retain(|_, at| at.elapsed() < Duration::from_secs(2));
            }
            Some(event)=events.recv()=>match event {
                controller::Event::Snapshot(a)=>{
                    let snapshot=a.accepted()?;
                    let sparse=snapshot.sparse.as_ref().context("virtual host requires private pair authorization")?;
                    ensure!(!sparse.capture_pools.iter().any(|pool|pool.contains(parent.spec.target_ip)),"virtual host target overlaps the private network");
                    let address=snapshot.peers.iter().find(|p|p.id==profile.peer_id).context("virtual host identity absent")?.ip;
                    ensure!(own.is_none_or(|old|old==address),"virtual host address changed");
                    policy.apply(snapshot.clone())?;own=Some(address);relay.update_authority(a.retained(),pairs.clone());
                }
                controller::Event::Pair(a)=>{
                    let res=a.accepted()?;
                    if res.status=="allowed" {
                        if let Some(lease)=res.lease.as_ref() {
                            if policy.install_pair(lease.clone()).is_ok(){
                                pairs.installed_authority(&res.query,lease.clone(),a.retained());continue;
                            }
                        }
                    }
                    sparse::apply_denial(&pairs,&mut policy,res);pairs.unavailable(&res.query);
                }
                controller::Event::Packet{peer,bytes,origin,direct,carrier_direct,..}=>{
                    let Some(pkt)=Packet::parse(&bytes) else{continue;};
                    if Some(pkt.destination())!=own || !matches!(bytes[9],6|17){continue;}
                    let Some(info)=pairs.by_id(&peer) else{pairs.request_peer_once(&peer);continue;};
                    if !origin.is_some_and(|p| packet_origin_matches(&info, &p, direct, || {
                        if refreshed.len() < 256 && !refreshed.contains_key(&peer) {
                            refreshed.insert(peer.clone(), std::time::Instant::now());
                            pairs.request_peer_once(&peer);
                        }
                    })) { continue; }
                    if !pairs.touch_peer(&peer)|| !policy.check(&bytes,&peer,true){continue;}
                    let Some(domain)=pairs.pair_authority(&peer).and_then(|a|a.retirement_domain()) else{continue;};
                    let grant=Admission{parent:parent.clone(),pairs:pairs.clone(),peer,domain};
                    if let Some(permit)=grant.current(){paths.observe(pkt,direct);flows.receive(bytes,grant,permit,&lan,carrier_direct).await;}
                }
                _=>{}
            },
            Some(packet)=tcp_out.recv()=>{
                if let Some((id,permit))=flows.tcp_egress(&packet) {
                    let admitted=SendPermit::combine(vec![permit,packet.admission()]);
                    let _=packet.deliver(|bytes|async {
                        transmit(&mut policy,&mut paths,&sessions,&relay,&id,bytes,admitted).await;
                        Ok(())
                    }).await;
                }
            }
            Some((peer,bytes,permit))=udp_out.recv()=>transmit(&mut policy,&mut paths,&sessions,&relay,&peer,bytes,permit).await
        }
    }
    Ok(())
}

async fn transmit(
    policy: &mut Engine,
    paths: &mut porthub_network::paths::Pinned,
    sessions: &controller::Sessions,
    relay: &relay::Sender,
    peer: &str,
    bytes: Bytes,
    permit: SendPermit,
) {
    if !permit.valid() || !policy.check(&bytes, peer, false) {
        return;
    }
    let session = sessions
        .read()
        .await
        .get(peer)
        .filter(|s| s.state() == porthub_mesh::State::Ready)
        .cloned();
    let Some(packet) = Packet::parse(&bytes) else {
        return;
    };
    // Use the same carrier as the incoming flow, as registered peers do.
    // Queue pressure must not reorder one TCP stream across two carriers.
    match paths.choose(packet, session.is_some(), relay.is_ready()) {
        Some(true) => {
            if let Some(session) = session {
                let _ = session.send_guarded(bytes, Some(permit));
            }
        }
        Some(false) => {
            let _ = relay.send_guarded(peer, &bytes, Some(permit));
        }
        None => (),
    }
}

#[cfg(test)]
mod origin_refresh_tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn rotated_relay_record_requests_refresh_without_admitting_stale_data() {
        let current: porthub_network::policy::PeerInfo = serde_json::from_value(serde_json::json!({
            "id":"sender", "ip":"10.0.0.2", "fingerprint":"first", "instance":"one",
            "hostname":"sender.phub", "relay_origin":"1".repeat(32)
        })).unwrap();
        let mut record = current.clone();
        let requests = Cell::new(0);
        let refresh = || requests.set(requests.get()+1);
        assert!(packet_origin_matches(&current, &record, false, refresh));
        record.relay_origin = Some("2".repeat(32));
        assert!(!packet_origin_matches(&current, &record, false, refresh));
        assert_eq!(requests.get(), 1);
        record.instance = "two".into();
        assert!(!packet_origin_matches(&current, &record, true, refresh));
        assert!(packet_origin_matches(&record, &record, false, refresh));
        record.relay_origin = None;
        assert!(!packet_origin_matches(&current, &record, false, refresh));
        record.relay_origin = Some("2".repeat(32));
        record.ip = "10.0.0.3".parse().unwrap();
        assert!(!packet_origin_matches(&current, &record, false, refresh));
        assert_eq!(requests.get(), 2);
    }
}
