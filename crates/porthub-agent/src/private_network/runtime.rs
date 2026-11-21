//! Linux packet owner: one TUN read, bounded peer delivery, and no gateway
//! requests on the packet path. Dropping the exclusive TUN removes its routes.
use super::{
    controller::{self, Event, Sessions},
    device::Tun,
    dns,
    policy::{Engine, ExitRoute, Packet, Snapshot},
};
use crate::{
    private_profile::Profile,
    profile::{self, Lease},
};
use anyhow::{ensure, Context, Result};
use crate::unified::PrivateStage;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
#[path="cold_datagrams.rs"]
mod cold_datagrams;
#[cfg(all(target_os="linux",feature="private-sparse"))]
#[path="pending_exit.rs"]
mod pending_exit;
#[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]
#[path="fixture_gate.rs"]
mod fixture_gate;
#[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]
pub(crate) fn provider_fixture_phase(phase:&'static str,generation:u64,count:usize){
    static EVENTS:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
    if EVENTS.fetch_add(1,std::sync::atomic::Ordering::Relaxed)<128 {
        eprintln!("native_provider_pending phase={phase} generation={generation} count={count}");
    }
}


// A deliberately replaced stream owner may finish normally while the profile
// remains live. Current-owner failure and cleanup errors remain actionable.
fn stream_owner_completed(current:u64,stopping:bool,finished:Option<std::result::Result<(u64,Result<()>),tokio::task::JoinError>>)->Result<bool>{
    match finished{
        Some(Ok((_,Ok(())))) if stopping=>Ok(true),
        Some(Ok((generation,Ok(())))) if generation!=current=>Ok(false),
        Some(Ok((_,Err(error))))=>Err(error),Some(Err(error))=>Err(error.into()),
        _=>anyhow::bail!("private stream owner stopped unexpectedly"),
    }
}

fn retire_route_conflicts(policy:&mut Engine,handle:&super::sparse::Handle,conflicts:&[std::net::Ipv4Addr])->Vec<String>{
    let peers:Vec<_>=handle.peers().into_iter().filter(|peer|conflicts.contains(&peer.ip)).collect();
    for peer in &peers{policy.revoke_pair(&peer.id);handle.retire(&peer.id);}
    peers.into_iter().map(|peer|peer.id).collect()
}
// Sparse base replies intentionally omit idle identities. Counter handles must
// follow the effective base+installed pair set, without discarding pending rows.
fn reconcile_traffic(tracker:&super::traffic::Tracker,own:&str,base:Option<&Snapshot>,pairs:&super::sparse::Handle)->HashMap<String,Arc<super::traffic::Counters>> {
    if !pairs.enabled() {
        return tracker.reconcile(base.into_iter().flat_map(|base|base.peers.iter()).filter(|peer|peer.id!=own).map(|peer|peer.id.clone()));
    }
    let mut ids=std::collections::BTreeSet::new();
    if let Some(base)=base {ids.extend(base.peers.iter().filter(|peer|peer.id!=own).map(|peer|peer.id.clone()));}
    ids.extend(pairs.peers().into_iter().filter(|peer|peer.id!=own).map(|peer|peer.id));
    tracker.reconcile(ids.into_iter())
}
#[cfg(all(target_os="linux",feature="private-sparse"))]
fn refresh_provider(base:&Snapshot,handle:&super::sparse::Handle,own:&str,readiness:&super::exit_forwarding::Readiness,clients:&mut std::collections::BTreeSet<std::net::Ipv4Addr>,plan:&mut super::exit_forwarding::Plan)->Result<()> {
    let view=super::exit_plumbing::project(base,&handle.exit_leases());let wanted=super::exit_plumbing::provider_clients(&view,own);
    if wanted!=*clients{*plan=readiness.request(wanted.clone())?;*clients=wanted;}Ok(())
}
#[cfg(feature="private-sparse")]
fn incoming_exit_permit(base:Option<&super::authority_event::Authority<()>>,handle:&super::sparse::Handle,peer:&str,origin:Option<Arc<porthub_network::policy::PeerInfo>>)->Result<Option<porthub_mesh::udp::SendPermit>>{
    let permit=super::authority_event::send_exit_permit(base,handle,peer)?;
    Ok(match origin.filter(|origin|origin.relay_origin.is_some()){
        Some(origin)=>{let handle=handle.clone();permit.map(|permit|permit.constrain(move||handle.matches_relay_origin(&origin)))},
        None=>permit,
    })
}
#[cfg(all(target_os="linux",feature="private-sparse"))]
fn retain_provider(queue:&mut pending_exit::Queue,bytes:bytes::Bytes,origin:Arc<porthub_network::policy::PeerInfo>,base:&super::authority_event::Authority<()>,received_at:Instant,received_boot:Option<Duration>,binding:Option<(&super::exit_forwarding::Plan,porthub_mesh::udp::SendPermit)>)->bool {
    #[cfg(feature="netns-tests")]
    let (phase,generation)=binding.as_ref().map(|(plan,_)|("retained_wait_native",plan.diagnostic_generation())).unwrap_or(("retained_before_pair",0));
    let peer=origin.clone();if !queue.push_at(bytes,origin,base,received_at,received_boot){return false;}
    if let Some((plan,permit))=binding{if !queue.bind_last(plan,&peer,permit){queue.discard_last();return false;}}
    #[cfg(feature="netns-tests")]
    provider_fixture_phase(phase,generation,queue.len());
    true
}
async fn audit_capture(device:&mut Option<Arc<Tun>>,profile:&std::path::Path,snapshot:&Snapshot,peers:&[std::net::Ipv4Addr])->Result<porthub_network::capture_routes::SparseAudit>{
    let sparse=snapshot.sparse.as_ref().ok_or_else(||anyhow::anyhow!("private capture audit requires negotiated authority"))?;
    let own=snapshot.peers.iter().find(|peer|peer.id==snapshot.self_).ok_or_else(||anyhow::anyhow!("native capture identity missing"))?.ip;
    match super::native_owner::reconcile(device,profile,own,&sparse.capture_pools,peers).await?{
        super::native_owner::Outcome::Active(audit)=>Ok(audit),
        super::native_owner::Outcome::Retired(_)=>anyhow::bail!("native source quarantined after LAN/VPN/VM conflict; safe new address allocation required"),
    }
}

fn verified_lan(policy: &Engine, peer: &str, session: Option<&porthub_mesh::udp::Session>) -> bool {
    session.is_some_and(|s| policy.pair_peer(peer).is_some_and(|p| s.on_lan(&p.lan_networks)))
}

fn send_authorized(authority:Option<&super::authority_event::Authority<()>>,pairs:&super::sparse::Handle,peer:&str,session:&porthub_mesh::udp::Session,bytes:bytes::Bytes)->Result<()> {
    session.send_guarded(bytes,super::authority_event::send_permit(authority,pairs,peer)?)
}

#[cfg(all(feature="private-sparse",feature="private-stream"))]
fn raw_syn_send_permit(authority:Option<&super::authority_event::Authority<()>>,pairs:&super::sparse::Handle,peer:&str,original:porthub_mesh::udp::SendPermit)->Option<porthub_mesh::udp::SendPermit>{
    let current=super::authority_event::send_permit(authority,pairs,peer).ok()?;
    let permit=porthub_mesh::udp::SendPermit::combine(std::iter::once(original).chain(current).collect());
    permit.valid().then_some(permit)
}

fn send_probe_authorized(authority:Option<&super::authority_event::Authority<()>>,pairs:&super::sparse::Handle,peer:&str,session:&porthub_mesh::udp::Session,bytes:bytes::Bytes)->Result<()> {
    ensure!(super::probe::valid_frame(&bytes,true),"invalid direct measurement frame");
    session.send_guarded(bytes,super::authority_event::send_probe_permit(authority,pairs,peer)?)
}

fn send_exit_authorized(authority:Option<&super::authority_event::Authority<()>>,pairs:&super::sparse::Handle,peer:&str,session:&porthub_mesh::udp::Session,bytes:bytes::Bytes)->Result<()> {
    session.send_guarded(bytes,super::authority_event::send_exit_permit(authority,pairs,peer)?)
}

async fn write_exit_authorized(authority:Option<&super::authority_event::Authority<()>>,handle:&super::sparse::Handle,peer:&str,tun:&Tun,bytes:&[u8])->Result<()> {
    if handle.revoked(){return Ok(());}
    let pair=if handle.enabled(){
        if authority.is_none(){return Ok(());}
        match handle.exit_pair_authority(peer){Some(pair)=>Some(pair),None=>return Ok(())}
    }else{None};
    let delivery=async {if let Some(pair)=pair {pair.during(tun.write(bytes)).await}else{tun.write(bytes).await}};
    if let Some(authority)=authority {authority.during(delivery).await} else {delivery.await}
}

async fn write_authorized(authority:Option<&super::authority_event::Authority<()>>,handle:&super::sparse::Handle,peer:Option<&str>,tun:&Tun,bytes:&[u8])->Result<()> {
    let pair=if handle.enabled(){
        if let Some(peer)=peer {match handle.pair_authority(peer){Some(pair)=>Some(pair),None=>return Ok(())}}else{None}
    }else{None};
    let delivery=async {if let Some(pair)=pair {pair.during(tun.write(bytes)).await}else{tun.write(bytes).await}};
    if let Some(authority)=authority {authority.during(delivery).await} else {delivery.await}
}

fn mark_activity(activity: &mut HashMap<String, Instant>, peer: &str, now: Instant) {
    if let Some(last) = activity.get_mut(peer) {
        *last = now;
    } else if activity.len() < 4096 {
        activity.insert(peer.to_owned(), now);
    }
}

// Native fixture observation only: increments after the guarded stream path
// successfully writes TCP payload to this process's real owned TUN. Raw packet
// fallback and handshake-only events cannot satisfy the worker's data proof.
#[cfg(all(target_os="linux",feature="netns-tests",feature="private-sparse",feature="private-stream"))]
static TEST_GUARDED_NATIVE_PAYLOAD:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);
#[cfg(all(target_os="linux",feature="netns-tests",feature="private-sparse",feature="private-stream"))]
pub fn test_guarded_native_payload_bytes()->u64 {TEST_GUARDED_NATIVE_PAYLOAD.load(std::sync::atomic::Ordering::Relaxed)}
#[cfg(all(target_os="linux",feature="netns-tests",feature="private-sparse",feature="private-stream"))]
fn observe_guarded_native_payload(bytes:&[u8]) {
    if bytes.len()<40||bytes[0]>>4!=4||bytes[9]!=6{return;}
    let ip=usize::from(bytes[0]&15)*4;
    if ip<20||bytes.len()<ip+20{return;}
    let tcp=usize::from(bytes[ip+12]>>4)*4;
    if tcp<20||bytes.len()<=ip+tcp{return;}
    TEST_GUARDED_NATIVE_PAYLOAD.fetch_add((bytes.len()-ip-tcp)as u64,std::sync::atomic::Ordering::Relaxed);
}

fn relay_probe(
    sender: &super::relay::Sender,
    ips: &HashMap<String, std::net::Ipv4Addr>,
    own: &str,
    peer: &str,
    payload: &[u8],
) -> Result<()> {
    let source = ips
        .get(own)
        .ok_or_else(|| anyhow::anyhow!("private probe source unavailable"))?;
    let destination = ips
        .get(peer)
        .ok_or_else(|| anyhow::anyhow!("private probe target unavailable"))?;
    let packet = porthub_mesh::control_packet::encode(
        porthub_mesh::control_packet::PROBE,
        *source,
        *destination,
        payload,
    )?;
    sender.send_probe(peer, &packet)
}

#[cfg(feature = "local-tor")]
fn apply_cli_system_tor(
    snapshot: &mut Snapshot,
    settings: &super::tor_preferences::Settings,
) {
    if !settings.system_wide {
        return;
    }
    let local_peer = snapshot.self_.clone();
    for route in &mut snapshot.exit_routes {
        route.clients.retain(|client| client != &local_peer);
    }
    snapshot.exit_routes.retain(|route| !route.clients.is_empty());
    snapshot.exit_routes.push(ExitRoute {
        id: format!("cli-tor-{local_peer}"),
        name: "Local Tor (CLI)".into(),
        routing_peers: Vec::new(),
        tor_enabled: true,
        tor_circuit_groups: settings.circuit_groups.unwrap_or(4),
        clients: vec![local_peer],
        selection: porthub_mesh::exit_policy::Selection::Sticky,
        traffic_mode: porthub_mesh::exit_policy::TrafficMode::InternetOnly,
        allow_direct_fallback: false,
        masquerade: true,
        block_lan_access: true,
    });
}

#[cfg(all(test, feature = "local-tor"))]
mod cli_system_tor_tests {
    use super::*;

    #[test]
    fn local_tor_override_preserves_the_gateway_acl_and_peer_exit_role() {
        let snapshot: Snapshot = serde_json::from_value(serde_json::json!({
            "workspace":"workspace",
            "self":"local",
            "revision":7,
            "expires_at":chrono::Utc::now()+chrono::Duration::seconds(60),
            "peers":[
                {"id":"local","ip":"10.203.0.2","fingerprint":"local-fp","instance":"local-i","hostname":"local.phub"},
                {"id":"consumer","ip":"10.203.0.3","fingerprint":"consumer-fp","instance":"consumer-i","hostname":"consumer.phub"}
            ],
            "grants":[],
            "exit_routes":[{
                "id":"peer-exit","name":"Local peer exit","routing_peers":["local"],
                "clients":["consumer"],"traffic_mode":"internet_only"
            }]
        })).unwrap();
        Engine::default().apply(snapshot.clone()).unwrap();

        let mut effective = snapshot.clone();
        apply_cli_system_tor(&mut effective, &super::super::tor_preferences::Settings {
            mode: super::super::tor_preferences::Mode::Enabled,
            circuit_groups: Some(8),
            system_wide: true,
        });

        assert_eq!(snapshot.exit_routes.len(), 1);
        assert_eq!(effective.exit_routes.len(), 2);
        assert!(effective.exit_routes.iter().any(|route| route.id == "peer-exit"
            && route.routing_peers == vec!["local".to_owned()]
            && route.clients == vec!["consumer".to_owned()]));
        assert!(effective.exit_routes.iter().any(|route| route.id == "cli-tor-local"
            && route.tor_enabled && route.clients == vec!["local".to_owned()]
            && route.tor_circuit_groups == 8 && !route.allow_direct_fallback));
    }
}

#[cfg(feature = "private-stream")]
#[derive(Clone, Default)]
struct StreamCarrierPlan {
    source: Option<std::net::Ipv4Addr>,
    valid_until: Option<Instant>,
    routes: HashMap<std::net::Ipv4Addr, (String, bool, Option<Instant>, Option<Arc<super::traffic::Counters>>)>,
}
#[cfg(feature = "private-stream")]
async fn stream_carrier(
    mut packets: mpsc::Receiver<porthub_mesh::streams::Datagram>,
    plans: watch::Receiver<StreamCarrierPlan>,
    sessions: Sessions,
    relay: super::relay::Sender,
    cancel: CancellationToken,
) -> Result<()> {
    loop {
        let packet = tokio::select! {_=cancel.cancelled()=>return Ok(()),packet=packets.recv()=>{let Some(packet)=packet else {return Ok(());};packet}};
        if packet.permit.as_ref().is_some_and(|permit|!permit.valid()){continue;}
        let route = {
            let plan = plans.borrow();
            if plan
                .valid_until
                .is_none_or(|deadline| deadline <= Instant::now())
            {
                continue;
            }
            plan.source.zip(plan.routes.get(&packet.address).cloned())
        };
        let Some((source, (peer, prefer, pair_deadline,counter))) = route else {
            continue;
        };
        if pair_deadline.is_some_and(|d|d<=Instant::now()){continue;}
        let bytes = porthub_mesh::control_packet::encode(
            porthub_mesh::control_packet::STREAM,
            source,
            packet.address,
            &packet.payload,
        )?;
        let session = sessions
            .read()
            .await
            .get(&peer)
            .filter(|session| session.state() == porthub_mesh::State::Ready)
            .cloned();
        // Await only in this bounded carrier worker. Pressure propagates to
        // Quinn's writable notification instead of discarding congestion bursts.
        let send = async {
            if let Some(session) = session.filter(|_| prefer || !relay.is_ready()) {
                if session.send_stream_guarded(bytes.clone(),packet.permit.clone()).await.is_ok() {
                    if let Some(c)=counter.as_ref(){c.add(true,!session.is_relay(),bytes.len());}
                    return;
                }
            }
            if relay.is_ready() {
                if relay.send_stream_guarded(&peer, &bytes,packet.permit.clone()).await.is_ok(){if let Some(c)=counter.as_ref(){c.add(true,false,bytes.len());}}
            }
        };
        tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tokio::time::timeout(Duration::from_millis(200),send)=>{}}
    }
}

pub async fn run(path: PathBuf, cancel: CancellationToken) -> Result<()> {
    let profile = Profile::load(&path)?;
    let logs = crate::logs::Buffer::default();
    logs.configure_private(&profile);
    run_with_logs(path, cancel, logs).await
}

pub async fn run_with_logs(
    path: PathBuf,
    cancel: CancellationToken,
    logs: crate::logs::Buffer,
) -> Result<()> {
    #[cfg(not(feature = "private-sparse"))]
    return run_inner(path, cancel, Some(logs)).await;

    #[cfg(feature = "private-sparse")]
    loop {
        let result = run_inner(path.clone(), cancel.child_token(), Some(logs.clone())).await;
        if cancel.is_cancelled() {
            return Ok(());
        }
        let error = match result {
            Err(error) => error,
            Ok(()) => return Ok(()),
        };
        let Some(delay) = super::authority_clock::standalone_retry_delay(&error) else {
            return Err(error);
        };
        // run_inner has revoked the expired authority and released its routes.
        tracing::info!(?delay, "private authority expired; requesting a fresh lease");
        if !delay.is_zero() {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = crate::unified::suspend_aware_delay(delay) => {}
            }
        }
    }
}

fn check_installed_authority(
    policy: &mut Engine,
    installed: Option<&super::authority_event::Authority<()>>,
) -> Result<()> {
    if let Some(authority) = installed {
        if let Err(error) = authority.check() {
            policy.revoke();
            return Err(error.context("private request-start authority expired"));
        }
    }
    Ok(())
}

/// The parent registration owns the single log stream and update lifecycle.
pub(crate) async fn run_embedded(path: PathBuf, cancel: CancellationToken) -> Result<()> {
    run_inner(path, cancel, None).await
}

async fn run_inner(path: PathBuf, cancel: CancellationToken, logs: Option<crate::logs::Buffer>) -> Result<()> {
    let profile = Profile::load(&path).context(PrivateStage::Profile)?;
    let _lease = Lease::acquire(&path).context(PrivateStage::Lease)?;
    // Declared after Lease: revocation drops before another runtime can own it.
    let authority_owner=super::authority_event::Owner::new();
    let control = Arc::new(crate::control::Control::new_private(&profile).context(PrivateStage::Control)?);
    // Embedded private networking shares the parent registration's maintenance
    // worker. A standalone private enrollment owns its own background updates.
    let owns_component_maintenance = logs.is_some();
    let mut component_maintenance = None;
    #[cfg(feature="private-sparse")]
    let (component_clock, component_clock_rx)=tokio::sync::watch::channel(None);
    let mut log_stream = logs.map(|logs| crate::logs::Guard::start(control, logs, cancel.child_token()));
    // Older VPN discovery clients skip tun0-prefixed devices but advertise
    // unrecognized TUN names as physical ICE endpoints to other machines.
    #[cfg(target_os = "linux")]
    let prefix = "tun0ph";
    #[cfg(not(target_os = "linux"))]
    let prefix = "ph";
    let name = format!(
        "{prefix}{}",
        &format!("{:x}", Sha256::digest(profile.peer_id.as_bytes()))[..8]
    );
    let traffic=super::traffic::Tracker::new(&path);
    let mut traffic_counters:HashMap<String,Arc<super::traffic::Counters>>=HashMap::new();
    let sessions: Sessions = Default::default();
    let (events, mut input) = mpsc::channel(4096);
    let work = cancel.child_token();
    let mut tasks = JoinSet::new();
    tasks.spawn({let t=traffic.clone();let c=work.clone();async move{t.run(c).await;Ok::<(),anyhow::Error>(())}});
    #[cfg(target_os="linux")]
    let _wsl_local_dns=crate::wsl_local_dns::start(&cancel);
    let (strategy_updates, strategy) =
        tokio::sync::watch::channel(super::strategy::load(&path).context(PrivateStage::Strategy)?.mode);
    tasks.spawn(super::strategy::run(
        path.clone(),
        strategy_updates,
        work.clone(),
    ));
    let instance = controller::nonce()?;
    let identity = porthub_mesh::Identity::new().context(PrivateStage::Identity)?;
    let mut next_probe_id = u64::from_str_radix(&instance[..16], 16)?;
    let (interface_updates, mut interfaces) = tokio::sync::watch::channel(Vec::new());
    let (route_changes,mut route_events)=tokio::sync::watch::channel(0u64);
    let mut route_events_open=true;let mut last_route_audit:Option<Instant>=None;
    tasks.spawn(super::interfaces::watch_with_routes(interface_updates,if cfg!(feature="private-sparse"){Some(route_changes)}else{None}, work.clone()));
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    let virtual_assignments = {
        let (send,receive) = watch::channel(None);
        tasks.spawn(super::virtual_hosts::manage(profile.clone(),interfaces.clone(),receive,work.clone()));
        send
    };
    let (relay_sender, relay_input) = super::relay::channel();
    #[cfg(feature = "private-stream")]
    let (stream_output, stream_input) = mpsc::channel(256);
    #[cfg(feature = "private-stream")]
    let (stream_plans, stream_plan_updates) = watch::channel(StreamCarrierPlan::default());
    #[cfg(feature = "private-stream")]
    tasks.spawn(stream_carrier(
        stream_input,
        stream_plan_updates,
        sessions.clone(),
        relay_sender.clone(),
        work.clone(),
    ));
    let (relay_config, relay_config_updates) = watch::channel(None);
    tasks.spawn(super::relay::run_bound(
        profile.clone(),
        instance.clone(),
        relay_sender.clone(),
        relay_input,
        relay_config_updates,
        interfaces.clone(),
        events.clone(),
        work.clone(),
    ));
    let (sparse_handle,sparse_control)=super::sparse::channel();
    #[allow(unused_variables)]
    let (native_streams,native_stream_updates)=watch::channel(None::<controller::NativeReady>);
    tasks.spawn(PrivateStage::Controller.run(controller::run_watched_sparse_owned(
        profile.clone(),
        interfaces.clone(),
        sessions.clone(),
        events.clone(),
        relay_config,
        controller::LocalIdentity {
            traffic:Some(traffic.clone()),
            instance,
            certificate: identity.clone(),
        },
        work.clone(),
        if cfg!(feature="private-sparse"){Some(sparse_control)}else{None},
        Some(authority_owner.domain()),
        Some(native_stream_updates),
        Some(path.clone()),
    )));
    let mut device: Option<Arc<Tun>> = None;
    let mut local_address=super::address_lifecycle::Binding::default();
    #[cfg(feature = "private-stream")]
    let mut stream_router: Option<super::stream_router::Router> = None;
    #[cfg(feature="private-stream")]
    let mut stream_router_sparse_mode:Option<bool>=None;
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    let mut guarded_flows:Option<super::sparse_dispatch::Node>=None;
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    let mut guarded_owner:Option<CancellationToken>=None;
    let mut guarded_generation=0u64;
    let mut guarded_owners:JoinSet<(u64,Result<()>)>=JoinSet::new();
    #[allow(unused_mut)]
    let mut stream_owner_generation=0u64;
    let mut stream_owners:JoinSet<(u64,Result<()>)>=JoinSet::new();
    let mut zone = None;
    let mut dns_registration: Option<dns::Registration> = None;
    let mut registered_suffixes: Vec<String> = Vec::new();
    let mut registered_rules = Vec::new();
    let mut dns_port: Option<u16> = None;
    #[cfg(feature="local-tor")]
    let mut dns_upstream:Option<Arc<super::dns_upstream::Upstream>>=None;
    let mut policy = Engine::default();
    let mut sparse_authority:Option<Snapshot>=None;
    let mut installed_authority:Option<super::authority_event::Authority<()>>=None;
    let mut capture_configured=false;
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    let mut native_stream_safe=false;
    let mut private_status = crate::runtime::PrivateStatus::default();
    #[cfg(target_os="linux")]
    let (dns_target,dns_health,dns_write) = {
        let (target,input)=watch::channel(None);
        let (result,health)=watch::channel(None);
        let write = Arc::new(tokio::sync::Mutex::new(()));
        tasks.spawn(crate::private_dns_setup::monitor(input,result,write.clone(),work.clone()));
        (target,health,write)
    };
    let mut exit_route = None;
    let mut sparse_exit_intent:Option<porthub_network::policy::ExitIntent>=None;
    let mut cold_datagrams=cold_datagrams::Queue::default();
    let mut cold_tick=tokio::time::interval(Duration::from_millis(50));
    cold_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut exit_traffic_mode = porthub_mesh::exit_policy::TrafficMode::default();
    let mut exit_lan_peers: Vec<(String, Vec<porthub_mesh::lan_routes::Network>)> = Vec::new();
    #[cfg(any(target_os="linux",target_os="macos"))]
    let mut exit_lan_networks:Vec<porthub_mesh::lan_routes::Network> = Vec::new();
    let mut interface_changes_open=true;
    #[cfg(feature="local-tor")]
    let mut local_tor: Option<super::tor_exit::LocalTor> = None;
    #[cfg(feature="local-tor")]
    let mut tor_route_groups=None;
    #[cfg(feature="local-tor")]
    let (tor_changes,mut tor_settings)=watch::channel(super::tor_preferences::load(&path).context(PrivateStage::TorPreferences)?);
    #[cfg(feature="local-tor")]
    let mut latest_snapshot: Option<super::authority_event::Authority<Snapshot>> = None;
    #[cfg(feature="local-tor")]
    tasks.spawn(super::tor_preferences::run(path.clone(),tor_changes,work.clone()));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let mut exit_fallback = super::exit_selection::Fallback::default();
    let mut exit_available = 0;
    let mut online_peers = std::collections::HashSet::new();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let (exit_consumer, exit_applied) = {
        let (sender, receiver) = watch::channel(None);
        let (report, applied) = watch::channel("pending");
        tasks.spawn(super::exit_routes::watch_plans_reported(receiver,interfaces.clone(),work.clone(),Some(report)));
        (sender, applied)
    };
    let mut exit_selection = super::exit_selection::FlowTable::new(profile.peer_id.clone());
    #[cfg(target_os = "linux")]
    let mut exit_clients = std::collections::BTreeSet::new();
    #[cfg(all(target_os="linux",not(feature="private-sparse")))]
    let exit_refresh = {
        let (sender, receiver) = watch::channel(std::collections::BTreeSet::new());
        tasks.spawn(super::exit_forwarding::watch(name.clone(), receiver, work.clone()));sender
    };
    #[cfg(all(target_os="linux",feature="private-sparse"))]
    let (exit_refresh,mut exit_ready_notice)={
        let(readiness,requests)=super::exit_forwarding::readiness_channel();
        tasks.spawn(super::exit_forwarding::watch_ready(name.clone(),requests,work.clone()));
        (readiness.clone(),readiness)
    };
    #[cfg(all(target_os="linux",feature="private-sparse"))]
    let mut exit_native_plan=exit_refresh.request(exit_clients.clone())?;
    #[cfg(all(target_os="linux",feature="private-sparse"))]
    let mut pending_provider=pending_exit::Queue::default();
    #[cfg(all(target_os="linux",feature="private-sparse"))]
    let mut provider_tick=tokio::time::interval(Duration::from_millis(50));
    #[cfg(all(target_os="linux",feature="private-sparse"))]
    provider_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    #[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]
    let mut provider_fixture_gate=fixture_gate::Gate::new(&path,&profile.peer_id)?;
    #[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]
    if provider_fixture_gate.is_some(){exit_refresh.fixture_withhold(true);}
    #[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]
    let mut fixture_gate_tick=tokio::time::interval(Duration::from_millis(25));
    let mut paths = super::paths::Pinned::default();
    let mut path_quality = super::probe::Quality::default();
    let mut by_ip = HashMap::new();
    let mut peer_ips = HashMap::new();
    let mut last_activity = HashMap::new();
    let mut probe_cursor = 0usize;
    let mut buffer = [0u8; porthub_mesh::MAX_PACKET + 1];
    let mut status_tick = tokio::time::interval(Duration::from_secs(30));
    status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut probe_tick = tokio::time::interval(Duration::from_secs(1));
    probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let result = loop {
        let run: Result<()> = async {loop {
        check_installed_authority(&mut policy, installed_authority.as_ref())?;
        if !sparse_handle.authority_valid(){policy.revoke();anyhow::bail!("private gateway revoked the base authority");}
        tokio::select! {
        _=cancel.cancelled()=>break,
        _=work.cancelled()=>{policy.revoke();if cancel.is_cancelled(){break;}anyhow::bail!("private worker authority ended");},
        finished=guarded_owners.join_next(),if !guarded_owners.is_empty()=>{if stream_owner_completed(guarded_generation,work.is_cancelled(),finished)?{break;}},
        finished=stream_owners.join_next(),if !stream_owners.is_empty()=>{if stream_owner_completed(stream_owner_generation,work.is_cancelled(),finished)?{break;}},
        finished=tasks.join_next(),if !tasks.is_empty()=>{match finished {Some(Ok(Ok(()))) if work.is_cancelled()=>break,Some(Ok(Err(error)))=>return Err(if error.downcast_ref::<PrivateStage>().is_some(){error}else{error.context(PrivateStage::Background)}),_=>anyhow::bail!("private background task stopped")}},
        event=input.recv()=>match event {
            #[cfg(all(feature="private-sparse",feature="private-stream"))]
            Some(Event::VirtualHosts(list))=>{
                list.check()?;
                virtual_assignments.send_replace(Some(list));
            },
            Some(Event::Snapshot(authority))=>{
                authority.check()?;
                #[cfg(feature="local-tor")]
                let cached_authority=authority.clone();
                let snapshot=authority.accepted()?.clone();
                ensure!(snapshot.self_==profile.peer_id && snapshot.workspace==profile.workspace,"private policy identity changed");
                #[cfg(feature="private-sparse")]
                component_clock.send_replace(authority.clock_sample());
                let mut route_snapshot=super::exit_plumbing::project(&snapshot,&sparse_handle.exit_leases());
                #[cfg(feature="local-tor")]
                {
                    latest_snapshot=Some(cached_authority);
                    apply_cli_system_tor(&mut route_snapshot,&tor_settings.borrow());
                }
                // Derive the active intent once, after local CLI projection but
                // before any await can leave old-scope payload permits live.
                sparse_exit_intent=snapshot.sparse.as_ref().and_then(|s|s.exit_intents.iter().find(|intent|
                    intent.role==porthub_network::policy::ExitRole::Client && route_snapshot.exit_routes.iter().any(|route|route.id==intent.id&&route.clients.contains(&profile.peer_id)))).cloned();
                cold_datagrams.observe(sparse_exit_intent.as_ref().and_then(|intent|cold_datagrams::Scope::from(&snapshot,intent)));
                #[cfg(all(target_os="linux",feature="private-sparse"))]
                pending_provider.observe(pending_exit::Scope::from(&snapshot));
                let own=snapshot.peers.iter().find(|p|p.id==profile.peer_id).ok_or_else(||anyhow::anyhow!("private policy omits local peer"))?;
                local_address.check(own.ip)?;
                let routes:Vec<_>=snapshot.peers.iter().filter(|p|p.id!=profile.peer_id).map(|p|p.ip).collect();
                let first_ready = device.is_none();
                policy.apply(snapshot.clone())?;
                installed_authority=Some(authority.retained());
                sparse_authority=Some(snapshot.clone());
                sparse_handle.update_base_authority(&snapshot,authority.retained());
                sparse_handle.exit_picker().observe(&snapshot);
                relay_sender.update_authority(authority.retained(),sparse_handle.clone());
                let mut routes=routes;
                routes.extend(sparse_handle.peers().iter().map(|p|p.ip));
                #[cfg(feature="private-stream")]
                {
                    let mode=snapshot.sparse.is_some();
                    if stream_router_sparse_mode!=Some(mode){
                        if let Some(previous)=stream_router.take(){previous.retire();}
                        stream_router_sparse_mode=Some(mode);
                    }
                    if stream_router.is_none() {
                        // One current plus one retiring owner maximum. A fast
                        // old/new-gateway mode flap must not retain old stacks.
                        while stream_owners.len()>=2 {
                            match tokio::time::timeout(Duration::from_secs(2),stream_owners.join_next()).await.map_err(|_|anyhow::anyhow!("retired private stream owner did not stop"))? {
                                Some(Ok((_,Ok(()))))=>{},Some(Ok((_,Err(error))))=>return Err(error),_=>anyhow::bail!("retired private stream owner failed"),
                            }
                        }
                        stream_owner_generation=stream_owner_generation.checked_add(1).ok_or_else(||anyhow::anyhow!("private stream generation exhausted"))?;
                        let generation=stream_owner_generation;
                        let (router,background)=super::stream_router::new(profile.peer_id.clone(),own.ip,identity.clone(),events.clone(),work.child_token())?;
                        stream_router=Some(router);let carrier=stream_output.clone();
                        stream_owners.spawn(async move{(generation,background.with_carrier(carrier).run().await)});
                    }
                }
                #[cfg(all(feature="private-sparse",feature="private-stream"))]
                {
                    if snapshot.sparse.is_none() {
                        if let Some(owner)=guarded_owner.take(){
                            owner.cancel();
                            // Completion of the intentionally retired sparse
                            // owner must not look like current-owner failure.
                            guarded_generation=guarded_generation.checked_add(1).ok_or_else(||anyhow::anyhow!("guarded runtime generation exhausted"))?;
                        }
                        guarded_flows=None;
                    } else if guarded_flows.is_none() {
                        while guarded_owners.len()>=2 {
                            match tokio::time::timeout(Duration::from_secs(2),guarded_owners.join_next()).await.map_err(|_|anyhow::anyhow!("retired guarded flow owner did not stop"))? {
                                Some(Ok((_,Ok(()))))=>{},Some(Ok((_,Err(error))))=>return Err(error),_=>anyhow::bail!("retired guarded flow owner failed"),
                            }
                        }
                        let owner=work.child_token();
                        let (flows,background)=super::sparse_dispatch::Node::new(profile.workspace.clone(),profile.peer_id.clone(),identity.clone(),sparse_handle.clone(),events.clone(),owner.clone())?;
                        guarded_generation=guarded_generation.checked_add(1).ok_or_else(||anyhow::anyhow!("guarded runtime generation exhausted"))?;
                        let generation=guarded_generation;
                        guarded_owners.spawn(async move{(generation,background.run().await)});
                        guarded_owner=Some(owner);guarded_flows=Some(flows);
                    }
                }
                if let Some(tun)=&device {
                    if snapshot.sparse.is_none(){tun.update_routes(&routes).await?;}
                } else {
                    let tun=if let Some(sparse)=&snapshot.sparse{
                        super::native_owner::open(&path,&name,own.ip,&sparse.capture_pools,&routes).await.context(PrivateStage::NativeOwner)?
                    }else{
                        super::native_owner::admit_legacy(&path,own.ip).context(PrivateStage::LegacyAdmission)?;
                        #[cfg(windows)]{Arc::new(Tun::open_owned(&path,&name,own.ip,&routes,super::native_ownership::HostAdmission::Legacy).await?)}
                        #[cfg(not(windows))]{Arc::new(Tun::open(&name,own.ip,&routes).await?)}
                    };
                    local_address.configured(own.ip)?;
                    let server=dns::Server::bind(own.ip).await.context(PrivateStage::DnsListener)?;let port=server.port()?;
                    server.zone.write().await.set_sparse(sparse_handle.clone());
                    #[cfg(feature="local-tor")]
                    {
                        let names=std::iter::once(&profile.server).chain(profile.fallback_servers.iter())
                            .filter_map(|server|url::Url::parse(server).ok().and_then(|server|server.host_str().map(|host|host.to_ascii_lowercase())))
                            .collect();
                        server.protect_management(names,interfaces.clone()).await;
                    }
                    zone=Some(server.zone.clone());
                    #[cfg(feature="local-tor")]
                    {dns_upstream=Some(server.upstream.clone());}
                    tasks.spawn(server.serve(work.clone()));
                    dns_port=Some(port);
                    device=Some(tun);
                }
                if snapshot.sparse.is_some(){
                    let audit=audit_capture(&mut device,&path,&snapshot,&routes).await?;
                    #[cfg(all(feature="private-sparse",feature="private-stream"))]
                    {native_stream_safe=audit.capture.conflicting.is_empty()&&audit.conflicting_peers.is_empty();if !native_stream_safe{native_streams.send_replace(None);}}

                    retire_route_conflicts(&mut policy,&sparse_handle,&audit.conflicting_peers);
                    if !audit.capture.conflicting.is_empty(){tracing::warn!(conflicting_pools=audit.capture.conflicting.len(),"private capture pools conflict with existing routes; safe known hosts retained, range migration required for ambiguous addresses");}
                    capture_configured=true;last_route_audit=Some(Instant::now());
                }else if capture_configured{device.as_ref().unwrap().update_capture_routes(&[]).await?;capture_configured=false;}
                #[cfg(feature="private-stream")]
                {authority.check()?;stream_router.as_ref().unwrap().update_pairs_authorized(&snapshot,&policy.private_stream_pair_snapshots(),installed_authority.clone(),Some(sparse_handle.clone()))?;}
                online_peers = super::exit_plumbing::online_peers(&route_snapshot);
                private_status.revision = snapshot.revision;
                private_status.grants = snapshot.grants.len();
                private_status.dns_rules = snapshot.dns_rules.len();
                private_status.exit = route_snapshot.exit_routes.iter().find(|route| route.clients.contains(&profile.peer_id)).map(|route| crate::runtime::ExitStatus {
                    name: route.name.clone(), traffic_mode: route.traffic_mode, selection: match route.selection { porthub_mesh::exit_policy::Selection::Sticky => "sticky", porthub_mesh::exit_policy::Selection::RoundRobin => "round robin", porthub_mesh::exit_policy::Selection::Random => "random" }.into(), state: "pending".into(),
                    peers: route.routing_peers.len()+usize::from(route.tor_enabled && route.traffic_mode.internet()), available: 0, allow_direct_fallback: route.allow_direct_fallback,
                    peer_names: route.routing_peers.iter().take(16).filter_map(|id| route_snapshot.peers.iter().find(|peer| &peer.id == id).map(|peer| peer.hostname.clone())).chain((route.tor_enabled && route.traffic_mode.internet()).then(||"Local Tor".into())).collect(),
                });
                #[cfg(feature="local-tor")]
                {
                    tor_route_groups=route_snapshot.exit_routes.iter().find(|route|route.clients.contains(&profile.peer_id) && route.tor_enabled && route.traffic_mode.internet()).map(|route|route.tor_circuit_groups);
                    super::tor_exit::reconcile(&mut local_tor,tor_route_groups,&tor_settings.borrow(),&path.with_extension("tor"),interfaces.clone(),events.clone(),work.child_token())?;
                }
                exit_route = route_snapshot.exit_routes.iter().find(|route| route.clients.contains(&profile.peer_id))
                    .map(|route| {
                        exit_traffic_mode = route.traffic_mode;
                        exit_lan_peers = route.routing_peers.iter().filter_map(|id| {
                            route_snapshot.peers.iter().find(|peer| &peer.id == id)
                                .map(|peer| (id.clone(), peer.lan_networks.clone()))
                        }).collect();
                        let mut peers=route.routing_peers.clone();
                        #[cfg(feature="local-tor")]
                        if route.tor_enabled && route.traffic_mode.internet() {peers.push(super::tor_exit::LOCAL_TOR.into());}
                        (peers,route.selection,route.allow_direct_fallback)
                    });
                if let Some(intent)=&sparse_exit_intent {
                    let destination=if intent.traffic_mode.internet(){std::net::Ipv4Addr::new(1,1,1,1)}else{intent.lan_networks.first().map(|network|network.address()).unwrap_or(std::net::Ipv4Addr::new(10,0,0,1))};
                    sparse_handle.exit_picker().request(&intent.id,&"0".repeat(64),destination,true);
                }
                // Apply a received policy before processing another packet;
                // the periodic tick only refreshes transport availability.
                if let Some((peers, mode, _)) = &exit_route {
                    let live = sessions.read().await;
                    let mut available = peers.iter().filter(|peer| policy.valid_lease() && online_peers.contains(*peer) && (relay_sender.is_ready() || live.get(*peer).is_some_and(|session| session.state() == porthub_mesh::State::Ready))).cloned().collect::<Vec<_>>();
                    #[cfg(feature="local-tor")]
                    if peers.iter().any(|peer|peer==super::tor_exit::LOCAL_TOR) && local_tor.as_ref().is_some_and(|tor|tor.ready()) {available.push(super::tor_exit::LOCAL_TOR.into());}
                    exit_available = available.len();
                    exit_selection.configure(available, *mode);
                } else { exit_available = 0; exit_selection.configure(Vec::new(), Default::default()); }
                #[cfg(target_os = "linux")]
                {
                    let clients: std::collections::BTreeSet<_> = route_snapshot.exit_routes.iter()
                        .filter(|route| route.routing_peers.contains(&profile.peer_id))
                        .flat_map(|route| &route.clients)
                        .filter_map(|id| route_snapshot.peers.iter().find(|peer| &peer.id == id).map(|peer| peer.ip)).collect();
                    if clients != exit_clients {
                        #[cfg(feature="private-sparse")]
                        {exit_native_plan=exit_refresh.request(clients.clone())?;}
                        #[cfg(not(feature="private-sparse"))]
                        exit_refresh.send_replace(clients.clone());
                        exit_clients = clients;
                    }
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    let tun = device.as_ref().expect("private tunnel initialized");
                    tun.exit_mtu(!route_snapshot.exit_routes.is_empty()).await?;
                    let bypass = exit_fallback.update(exit_route.as_ref().is_some_and(|(_, _, allowed)| *allowed), exit_available, policy.valid_lease(), Instant::now());
                    exit_lan_networks=if exit_route.is_some() && exit_traffic_mode.lan() {
                        sparse_exit_intent.as_ref().map(|intent|intent.lan_networks.clone()).unwrap_or_else(||super::exit_plan::lan_networks(&exit_lan_peers,|id|exit_selection.available(id)))
                    } else {Vec::new()};
                    let desired=exit_route.as_ref().map(|_|super::exit_plan::Plan{index:tun.index,own:own.ip,mode:exit_traffic_mode,bypass,networks:exit_lan_networks.clone()});
                    if *exit_consumer.borrow() != desired { exit_consumer.send_replace(desired); }
                }
                #[cfg(feature="local-tor")]
                refresh_tor_dns(&dns_upstream,&local_tor,&exit_route,exit_available,&policy);
                // Register every advertised private DNS suffix on the owned
                // tunnel resolver. This also applies suffix changes live.
                {let mut zone=zone.as_ref().unwrap().write().await;authority.check()?;zone.update(&route_snapshot)?;}
                let mut suffixes=snapshot.dns_suffixes.iter().map(|suffix|suffix.trim_matches('.').to_ascii_lowercase()).filter(|suffix|!suffix.is_empty()).collect::<Vec<_>>();
                if let Some((_,suffix))=own.hostname.split_once('.') { suffixes.push(suffix.trim_matches('.').to_ascii_lowercase()); }
                suffixes.extend(snapshot.dns_rules.iter().map(|rule|porthub_mesh::dns_policy::zone(rule).trim_end_matches('.').to_ascii_lowercase()));
                if route_snapshot.exit_routes.iter().any(|route|route.tor_enabled && route.traffic_mode.internet() && route.clients.contains(&profile.peer_id)) {suffixes.push(".".into());}
                suffixes.sort();suffixes.dedup();
                if registered_suffixes!=suffixes || registered_rules!=snapshot.dns_rules {
                    let tun=device.as_ref().expect("private tunnel initialized");
                    let port=dns_port.ok_or_else(||anyhow::anyhow!("private DNS listener missing"))?;
                    #[cfg(all(target_os = "linux", feature = "netns-tests"))]
                    let isolated = std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1") && std::path::Path::new("/.dockerenv").is_file();
                    #[cfg(not(all(target_os = "linux", feature = "netns-tests")))]
                    let isolated = false;
                    #[cfg(target_os="linux")]
                    let _dns_guard = dns_write.lock().await;
                    if !isolated { dns::replace_registration(&mut dns_registration,&path,tun.index,own.ip,port,&suffixes).await.context(PrivateStage::DnsRegistration)?; }
                    #[cfg(target_os="linux")]
                    {dns_target.send_if_modified(|previous| {
                        let next=Some(crate::private_dns_setup::LookupTarget {
                            hostname: own.hostname.clone(),
                            address: own.ip,
                            link: (!isolated).then(||crate::private_dns_setup::LinkDns { interface:tun.name.clone(),index:tun.index,port,suffixes:suffixes.clone() }),
                        });
                        if *previous==next {false} else {*previous=next;true}
                    });}
                    registered_suffixes=suffixes;
                    registered_rules=snapshot.dns_rules.clone();
                } else {
                    // Renaming a peer within the same suffix leaves the OS resolver routes intact.
                    #[cfg(target_os="linux")]
                    crate::private_dns_setup::update_probe_hostname(&dns_target, &own.hostname);
                }
                traffic_counters=reconcile_traffic(&traffic,&profile.peer_id,Some(&snapshot),&sparse_handle);
                by_ip=snapshot.peers.iter().map(|p|(p.ip,p.id.clone())).collect();
                peer_ips=snapshot.peers.iter().map(|p|(p.id.clone(),p.ip)).collect();
                for peer in sparse_handle.peers(){by_ip.insert(peer.ip,peer.id.clone());peer_ips.insert(peer.id,peer.ip);}
                #[cfg(all(feature="private-sparse",feature="private-stream"))]
                {
                    // This is a bounded native-owner observation, not a new
                    // authority. Release approval remains closed in Offer.
                    let ready=if snapshot.sparse.is_some()&&native_stream_safe {
                        Some(controller::NativeReady::prepared(&snapshot,authority.retained(),device.as_ref().expect("native tunnel initialized"),work.clone())?)
                    } else {None};
                    native_streams.send_replace(ready);
                }
                // Publish initial readiness immediately. Waiting for
                // the periodic refresh can make a healthy service miss the
                // installer's readiness deadline after a slow initial sync.
                authority.check()?;
                if first_ready {
                    status_tick.reset_immediately();
                    if owns_component_maintenance {
                        #[cfg(feature="private-sparse")]
                        let maintenance=crate::components::private_background(&profile.server,&work,component_clock_rx.clone());
                        #[cfg(not(feature="private-sparse"))]
                        let maintenance=crate::components::background(&profile.server,&work);
                        component_maintenance = maintenance.map(Some)
                            .unwrap_or_else(|_| { tracing::warn!("optional component maintenance unavailable; private networking remains active"); None });
                    }
                }
            },
            Some(Event::Pair(authority))=>{
                authority.check()?;
                #[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]
                if provider_fixture_gate.as_mut().is_some_and(|gate|gate.intercept(&authority)){continue;}
                let response=authority.accepted()?.clone();
                if response.status!="allowed"||response.lease.is_none(){
                    if let Some(peer)=super::sparse::apply_denial(&sparse_handle,&mut policy,&response){
                        by_ip.retain(|_,id|id!=&peer.id);peer_ips.remove(&peer.id);
                        if let Some(tun)=&device{if tun.update_routes(&peer_ips.values().copied().collect::<Vec<_>>()).await.is_err(){tracing::warn!("could not remove a retired private pair route");}}
                        #[cfg(feature="private-stream")]
                        if let (Some(router),Some(base))=(&stream_router,&sparse_authority){router.update_pairs_authorized(base,&policy.private_stream_pair_snapshots(),installed_authority.clone(),Some(sparse_handle.clone()))?;}
                    }
                    traffic_counters=reconcile_traffic(&traffic,&profile.peer_id,sparse_authority.as_ref(),&sparse_handle);
                    #[cfg(all(target_os="linux",feature="private-sparse"))]
                    if let Some(base)=&sparse_authority{refresh_provider(base,&sparse_handle,&profile.peer_id,&exit_refresh,&mut exit_clients,&mut exit_native_plan)?;}
                    sparse_handle.unavailable(&response.query);continue;
                }
                let lease=response.lease.expect("checked pair lease");
                let id=lease.peer.id.clone();
                if policy.install_pair(lease.clone()).is_err(){sparse_handle.unavailable(&response.query);continue;}
                if device.is_none(){policy.revoke_pair(&id);continue;}
                let mut routes:Vec<_>=peer_ips.values().copied().collect();routes.retain(|ip|peer_ips.get(&id)!=Some(ip));routes.push(lease.peer.ip);
                let base=sparse_authority.as_ref().ok_or_else(||anyhow::anyhow!("private pair arrived before base authority"))?;
                let audit=audit_capture(&mut device,&path,base,&routes).await?;last_route_audit=Some(Instant::now());
                    #[cfg(all(feature="private-sparse",feature="private-stream"))]
                    {native_stream_safe=audit.capture.conflicting.is_empty()&&audit.conflicting_peers.is_empty();if !native_stream_safe{native_streams.send_replace(None);}}

                let retired=retire_route_conflicts(&mut policy,&sparse_handle,&audit.conflicting_peers);
                for retired in retired{peer_ips.remove(&retired);by_ip.retain(|_,peer|peer!=&retired);}
                if !audit.accepted_peers.contains(&lease.peer.ip){
                    policy.revoke_pair(&id);sparse_handle.retire(&id);sparse_handle.unavailable(&response.query);peer_ips.remove(&id);by_ip.retain(|_,peer|peer!=&id);
                    #[cfg(feature="private-stream")]
                    if let Some(router)=&stream_router{router.update_pairs_authorized(base,&policy.private_stream_pair_snapshots(),installed_authority.clone(),Some(sparse_handle.clone()))?;}
                    continue;
                }
                by_ip.retain(|_,peer|peer!=&id);by_ip.insert(lease.peer.ip,id.clone());peer_ips.insert(id.clone(),lease.peer.ip);
                authority.check()?;
                sparse_handle.installed_authority(&response.query,lease,authority.retained());
                #[cfg(all(target_os="linux",feature="private-sparse"))]
                if let Some(base)=&sparse_authority{refresh_provider(base,&sparse_handle,&profile.peer_id,&exit_refresh,&mut exit_clients,&mut exit_native_plan)?;}
                traffic_counters=reconcile_traffic(&traffic,&profile.peer_id,sparse_authority.as_ref(),&sparse_handle);
                #[cfg(feature="private-stream")]
                if let (Some(router),Some(base))=(&stream_router,&sparse_authority){router.update_pairs_authorized(base,&policy.private_stream_pair_snapshots(),installed_authority.clone(),Some(sparse_handle.clone()))?;}
            },
            Some(Event::Packet{peer,bytes,direct,carrier_direct,received_at,origin,received_boot})=>{
                check_installed_authority(&mut policy, installed_authority.as_ref())?;
                if !sparse_handle.authority_valid(){policy.revoke();anyhow::bail!("private request-start authority expired");}
                #[cfg(feature="private-sparse")]
                if !direct&&origin.as_ref().is_some_and(|origin|origin.relay_origin.as_deref().is_none_or(|stamp|stamp.len()!=32||!stamp.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)))){continue;}
                if sparse_handle.enabled()&&(policy.pair_peer(&peer).is_none()||!sparse_handle.touch_peer(&peer)){
                    sparse_handle.request_peer_once(&peer);
                    #[cfg(all(target_os="linux",feature="private-sparse"))]
                    if let (Some(origin),Some(base),Some(envelope))=(origin.as_ref(),installed_authority.as_ref(),porthub_mesh::control_packet::decode(porthub_mesh::control_packet::EXIT,bytes.clone())) {
                        if origin.id==peer&&origin.ip==envelope.source&&peer_ips.get(&profile.peer_id)==Some(&envelope.destination)
                            && Packet::parse(&envelope.payload).is_some_and(|packet|packet.source()==origin.ip&&packet.destination()!=envelope.destination) {
                            retain_provider(&mut pending_provider,envelope.payload,origin.clone(),base,received_at,received_boot,None);
                        }
                    }
                    continue;
                }
                let now=received_at;
                if let Some(envelope) = porthub_mesh::control_packet::decode(porthub_mesh::control_packet::EXIT, bytes.clone()) {
                    if peer_ips.get(&peer) != Some(&envelope.source) || peer_ips.get(&profile.peer_id) != Some(&envelope.destination) { continue; }
                    let Some(packet) = Packet::parse(&envelope.payload) else { continue; };
                    let is_reply = peer_ips.get(&profile.peer_id) == Some(&packet.destination());
                    #[cfg(feature="private-sparse")]
                    if sparse_handle.enabled(){if let Some(origin)=origin.as_ref(){
                        let Some(current)=sparse_handle.by_id(&peer) else{continue;};
                        if origin.id!=current.id||origin.ip!=current.ip||origin.fingerprint!=current.fingerprint||origin.instance!=current.instance{continue;}
                        if origin.relay_origin.as_ref().is_some_and(|stamp|current.relay_origin.as_ref()!=Some(stamp)){
                            sparse_handle.request_peer_once(&peer);
                            #[cfg(target_os="linux")]
                            if !is_reply {if let Some(base)=installed_authority.as_ref(){retain_provider(&mut pending_provider,envelope.payload,origin.clone(),base,received_at,received_boot,None);}}
                            continue;
                        }
                    }}
                    #[cfg(target_os = "linux")]
                    let can_forward = exit_clients.contains(&packet.source());
                    #[cfg(not(target_os = "linux"))]
                    let can_forward = false;
                    if let Some(c)=traffic_counters.get(&peer){c.add(false,carrier_direct,bytes.len());}
                    if (is_reply || can_forward) && policy.check_exit(&envelope.payload, &peer, true) {
                        mark_activity(&mut last_activity, &peer, now);
                        paths.observe(packet, direct);
                        if is_reply {
                            exit_selection.observe(&packet.flow_id(), &peer, Instant::now(), packet.flow_ttl());
                            exit_selection.observe_close(&packet.flow_id(), &peer, false, packet.is_finish(), packet.is_reset(), Instant::now());
                        }
                        #[cfg(all(target_os="linux",feature="private-sparse"))]
                        if !is_reply&&sparse_handle.enabled(){
                            let Some(base)=installed_authority.as_ref() else{continue;};
                            let Ok(Some(original))=incoming_exit_permit(Some(base),&sparse_handle,&peer,origin.clone()) else{continue;};
                            if !exit_refresh.ready(&exit_native_plan){
                                let Some(observed)=origin.clone() else{continue;};
                                retain_provider(&mut pending_provider,envelope.payload,observed,base,received_at,received_boot,Some((&exit_native_plan,original)));continue;
                            }
                            let ready=exit_refresh.clone();let plan=exit_native_plan.clone();let live=original.clone().constrain(move||ready.ready(&plan));
                            if let Some(tun)=&device{
                                let delivered=pending_exit::during(live,async{tokio::select!{_=work.cancelled()=>anyhow::bail!("private authority ended before packet delivery"),result=write_exit_authorized(Some(base),&sparse_handle,&peer,tun,&envelope.payload)=>result}}).await?;
                                if delivered.is_none()&&original.valid(){if let Some(observed)=origin.clone(){retain_provider(&mut pending_provider,envelope.payload,observed,base,received_at,received_boot,Some((&exit_native_plan,original)));}}
                            }
                            continue;
                        }
                        #[cfg(feature="private-sparse")]
                        if sparse_handle.enabled(){
                            let Ok(Some(permit))=incoming_exit_permit(installed_authority.as_ref(),&sparse_handle,&peer,origin.clone()) else{continue;};
                            if let Some(tun)=&device{let _=super::authority_event::during_permit(permit,async{tokio::select!{_=work.cancelled()=>anyhow::bail!("private authority ended before packet delivery"),result=write_exit_authorized(installed_authority.as_ref(),&sparse_handle,&peer,tun,&envelope.payload)=>result}}).await?;}
                            continue;
                        }
                        if let Some(tun) = &device { tokio::select!{_=work.cancelled()=>anyhow::bail!("private authority ended before packet delivery"),result=write_exit_authorized(installed_authority.as_ref(),&sparse_handle,&peer,tun,&envelope.payload)=>result?}; }
                    }
                    continue;
                }
                #[cfg(feature="private-stream")]
                if let Some(envelope)=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::STREAM,bytes.clone()) {
                    if peer_ips.get(&peer)==Some(&envelope.source) && peer_ips.get(&profile.peer_id)==Some(&envelope.destination) {
                        if let Some(c)=traffic_counters.get(&peer){c.add(false,carrier_direct,bytes.len());}
                        #[cfg(feature="private-sparse")]
                        if sparse_handle.enabled() {
                            if let Some(flows)=&guarded_flows {
                                // Withdrawal stops cold allocation, not an existing
                                // pinned flow whose current ACL/identity still match.
                                let allow_new=sparse_handle.by_id(&peer).is_some_and(|p|p.stream_transport=="quic3-credit");
                                let _=flows.receive_offered(&peer,envelope.source,envelope.payload,allow_new);
                            }
                            continue;
                        }
                        if let Some(router)=&stream_router {router.receive(envelope.source,envelope.payload).await;}
                    }
                    continue;
                }
                let (probe_bytes,wrapped_probe)=if let Some(envelope)=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::PROBE,bytes.clone()) {
                    if peer_ips.get(&peer)!=Some(&envelope.source) || peer_ips.get(&profile.peer_id)!=Some(&envelope.destination) {continue;}
                    (envelope.payload,true)
                } else {(bytes.clone(),false)};
                if bytes.get(9)==Some(&porthub_mesh::control_packet::PROBE)&&!wrapped_probe{continue;}
                if wrapped_probe&&!super::probe::valid_frame(&probe_bytes,direct){continue;}
                if super::probe::valid_frame(&probe_bytes,direct)&&sparse_handle.enabled()&&sparse_handle.metadata_authority(&peer).is_none(){continue;}
                if let Some(replies)=path_quality.handle(&peer,direct,&probe_bytes,now) {
                    if !replies.is_empty() {
                        if direct {
                            if let Some(session)=sessions.read().await.get(&peer) {
                                for reply in replies { let _=send_probe_authorized(installed_authority.as_ref(),&sparse_handle,&peer,session,reply); }
                            }
                        } else {
                            for reply in replies { let _=relay_probe(&relay_sender,&peer_ips,&profile.peer_id,&peer,&reply); }
                        }
                    }
                    continue;
                }
                if let Some(c)=traffic_counters.get(&peer){c.add(false,carrier_direct,bytes.len());}
                mark_activity(&mut last_activity,&peer,now);
                if policy.check(&bytes,&peer,true) {
                    #[cfg(all(feature="private-sparse",feature="private-stream"))]
                    if sparse_handle.enabled() && guarded_flows.as_ref().is_some_and(|flows|!flows.raw_ingress(&bytes)){continue;}
                    if let Some(packet)=Packet::parse(&bytes) {paths.observe(packet,direct);}
                    if let Some(tun)=&device {tokio::select!{_=work.cancelled()=>anyhow::bail!("private authority ended before packet delivery"),result=write_authorized(installed_authority.as_ref(),&sparse_handle,Some(&peer),tun,&bytes)=>result?};}
                }
            },
            #[cfg(all(feature="private-sparse",feature="private-stream"))]
            Some(Event::GuardedRawSyn{handoff})=>{
                if !sparse_handle.enabled(){continue;}
                let peer=handoff.peer().to_owned();
                let Ok((bytes,original))=handoff.release() else {continue;};
                let Some(parsed)=Packet::parse(&bytes) else {continue;};
                if peer_ips.get(&profile.peer_id)!=Some(&parsed.source())
                    || peer_ips.get(&peer)!=Some(&parsed.destination())
                    || !policy.check(&bytes,&peer,false){continue;}
                let Some(permit)=raw_syn_send_permit(installed_authority.as_ref(),&sparse_handle,&peer,original) else {continue;};
                let peers=sessions.read().await;
                let direct=peers.get(&peer).filter(|session|session.state()==porthub_mesh::State::Ready);
                let relay_ready=relay_sender.is_ready();let mode=*strategy.borrow();
                let default=mode.prefer_peer_transport(direct.is_some_and(|session|session.is_relay()),relay_ready);
                let prefer=if mode==super::strategy::Mode::Auto {path_quality.prefer_peer(&peer,default,Instant::now(),|| verified_lan(&policy,&peer,direct))}else{default};
                match paths.choose_preferred(parsed,direct.is_some(),relay_ready,prefer){
                    Some(true)=>{if let Some(session)=direct{let size=bytes.len();if session.send_guarded(bytes,Some(permit)).is_ok(){if let Some(c)=traffic_counters.get(&peer){c.add(true,!session.is_relay(),size);}}}},
                    Some(false)=>{if relay_sender.send_guarded(&peer,&bytes,Some(permit)).is_ok(){if let Some(c)=traffic_counters.get(&peer){c.add(true,false,bytes.len());}}},
                    None=>{},
                }
            },
            #[cfg(all(feature="private-sparse",feature="private-stream"))]
            Some(Event::GuardedStreamLocal{peer,packet})=>{
                // The queue owns the exact native first-origin packet. Never
                // relabel it using StreamLocal's current-only byte delivery.
                if !sparse_handle.enabled(){continue;}
                check_installed_authority(&mut policy, installed_authority.as_ref())?;
                if installed_authority.is_none() {
                    policy.revoke();anyhow::bail!("guarded native request-start authority expired");
                }
                if !sparse_handle.enabled()||!packet.valid()||!sparse_handle.touch_peer(&peer){continue;}
                if !policy.check(packet.bytes(),&peer,true){continue;}
                if let Some(tun)=&device {
                    let cancelled=&work;let authority=installed_authority.as_ref();let handles=&sparse_handle;let remote=&peer;
                    let delivered=packet.deliver(|bytes|async move {
                        tokio::select!{_=cancelled.cancelled()=>anyhow::bail!("private native owner ended before delivery"),result=write_authorized(authority,handles,Some(remote),tun,&bytes)=>result}
                    }).await;
                    #[cfg(all(target_os="linux",feature="netns-tests"))]
                    if delivered.is_ok(){observe_guarded_native_payload(packet.bytes());}
                    // Retired per-flow originals are dropped; an actual native
                    // IO failure remains actionable instead of hiding it.
                    if packet.valid(){delivered?;}
                }
            },
            #[cfg(feature="private-stream")]
            Some(Event::StreamLocal {peer,bytes,scope})=>{
                if !scope.valid(){continue;}
                check_installed_authority(&mut policy, installed_authority.as_ref())?;
                if sparse_handle.enabled()&&!sparse_handle.touch_peer(&peer){continue;}
                let parsed=Packet::parse(&bytes);
                let reset=parsed.is_some_and(|packet|packet.is_reset() && peer_ips.get(&profile.peer_id)==Some(&packet.destination()));
                if policy.check(&bytes,&peer,true) || reset {
                    if let Some(tun)=&device {
                        let delivered=scope.during(async{tokio::select!{_=work.cancelled()=>anyhow::bail!("private authority ended before packet delivery"),result=write_authorized(installed_authority.as_ref(),&sparse_handle,Some(&peer),tun,&bytes)=>result}}).await;
                        match delivered {Ok(result)=>result?,Err(_) if !scope.valid()=>continue,Err(error)=>return Err(error)}
                    }
                }
            },
            #[cfg(feature="private-stream")]
            Some(Event::StreamDatagram {destination,payload,permit})=>{
                if permit.as_ref().is_some_and(|permit|!permit.valid()){continue;}
                check_installed_authority(&mut policy, installed_authority.as_ref())?;
                if sparse_handle.enabled() {
                    if permit.as_ref().is_none_or(|permit|permit.remaining().is_none()){continue;}
                    #[cfg(feature="private-sparse")]
                    if guarded_flows.is_none() || super::stream_chunks::carrier::Frame::decode(payload.clone()).is_err(){continue;}
                    #[cfg(not(feature="private-sparse"))]
                    continue;
                } else {
                    let Some(router)=&stream_router else {continue;};if !router.valid_lease(){continue;}
                }
                let (Some(peer),Some(source))=(by_ip.get(&destination),peer_ips.get(&profile.peer_id)) else {sparse_handle.request_ip(destination);continue;};
                if sparse_handle.enabled()&&(policy.pair_peer(peer).is_none()||!sparse_handle.touch_peer(peer)){sparse_handle.request_ip(destination);continue;}
                let packet=porthub_mesh::control_packet::encode(porthub_mesh::control_packet::STREAM,*source,destination,&payload)?;
                let peers=sessions.read().await;
                let direct=peers.get(peer).filter(|session|session.state()==porthub_mesh::State::Ready);
                let relay_ready=relay_sender.is_ready();let mode=*strategy.borrow();
                // The reliable stream already supplies encryption and recovery.
                // An explicit gateway preference selects its packet carrier,
                // rather than adding a second TURN/DTLS transport around it.
                let default=mode!=super::strategy::Mode::PreferGateway || !relay_ready;
                let prefer=if mode==super::strategy::Mode::Auto {path_quality.prefer_peer(peer,default,Instant::now(),|| verified_lan(&policy,peer,direct))} else {default};
                if let Some(session)=direct.filter(|_|prefer || !relay_ready) {let n=packet.len();if session.send_guarded(packet,permit).is_ok(){if let Some(c)=traffic_counters.get(peer){c.add(true,!session.is_relay(),n);}}}
                else if relay_ready {if relay_sender.send_guarded(peer,&packet,permit).is_ok(){if let Some(c)=traffic_counters.get(peer){c.add(true,false,packet.len());}}}
            },
            #[cfg(feature="local-tor")]
            Some(Event::TorLocal {bytes})=>{
                check_installed_authority(&mut policy, installed_authority.as_ref())?;
                if local_tor.is_some() && Packet::parse(&bytes).is_some_and(|packet|peer_ips.get(&profile.peer_id)==Some(&packet.destination())) {
                    if let Some(tun)=&device {tokio::select!{_=work.cancelled()=>anyhow::bail!("private authority ended before packet delivery"),result=write_authorized(installed_authority.as_ref(),&sparse_handle,None,tun,&bytes)=>result?};}
                }
            },
            None=>anyhow::bail!("private control owner stopped"),
        },
        packet=async {match &device {Some(device)=>{
            #[cfg(target_os="macos")]{
                let authority=installed_authority.as_ref().ok_or_else(||anyhow::anyhow!("native local routing has no installed base authority"))?;
                let deadline=policy.lease_deadline().ok_or_else(||anyhow::anyhow!("native local routing has no base policy lease"))?;
                device.packet_loop().read_next(device.as_ref(),authority,deadline,&work,&mut buffer).await
            }
            #[cfg(not(target_os="macos"))]{device.read(&mut buffer).await}
        },None=>std::future::pending().await}}=>{
            #[cfg(target_os="macos")]let size=match packet?{super::owned_packet_loop::Read::Local=>continue,super::owned_packet_loop::Read::Remote(size)=>size};
            #[cfg(not(target_os="macos"))]let size=packet?;if size>porthub_mesh::MAX_PACKET {continue;}
            check_installed_authority(&mut policy, installed_authority.as_ref())?;
            let Some(parsed)=Packet::parse(&buffer[..size]) else {continue;};
            #[cfg(feature="local-tor")]
            if let Some(tor)=local_tor.as_mut().filter(|tor|tor.owns(&buffer[..size])) {
                tor.packet(bytes::Bytes::copy_from_slice(&buffer[..size]));continue;
            }
            let overlay_destination=sparse_authority.as_ref().and_then(|base|base.sparse.as_ref()).is_some_and(|s|s.capture_pools.iter().any(|pool|pool.contains(parsed.destination())));
            // Retain only cold UDP/ICMP or an opening SYN while the authenticated
            // picker runs. Established TCP data and SYN+ACK never enter this buffer.
            if (matches!(buffer.get(9),Some(1|17))||parsed.opening_sequence().is_some()) && !overlay_destination
                && peer_ips.get(&profile.peer_id)==Some(&parsed.source())
                && !by_ip.contains_key(&parsed.destination()) && exit_traffic_mode.permits(parsed.destination())
                && exit_selection.assigned_peer(&parsed.flow_id(),Instant::now(),parsed.opening_sequence()).is_none() {
                if let (Some(intent),Some(authority))=(&sparse_exit_intent,&installed_authority) {
                    let tag=super::exit_picker::flow_tag(&parsed.flow_id().selection_tag(),parsed.opening_sequence());
                    let choice=if intent.tor_enabled{sparse_handle.exit_picker().cached_choice(&intent.id,&tag,parsed.destination(),false)}else{None};
                    if cold_datagrams::peer_retention_applies(choice.as_ref(),parsed.opening_sequence()) {
                    if cold_datagrams.push(&buffer[..size],authority,Instant::now()) {
                        sparse_handle.exit_picker().request(&intent.id,&tag,parsed.destination(),false);
                    }
                    continue;
                    }else{cold_datagrams.discard_flow(parsed.flow_id());}
                }
            }
            let exit_peer = if peer_ips.get(&profile.peer_id) == Some(&parsed.source()) && !by_ip.contains_key(&parsed.destination()) {
                if !exit_traffic_mode.permits(parsed.destination()) { None }
                else if sparse_exit_intent.is_some() && overlay_destination { None }
                else if let Some(intent)=&sparse_exit_intent {
                    let now=Instant::now();let flow=parsed.flow_id();let syn=parsed.opening_sequence();
                    if let Some(assigned)=exit_selection.assigned_peer(&flow,now,syn).map(str::to_owned) {
                        // An unavailable established NAT identity is never a new selection.
                        exit_selection.select_for_peer(flow,now,parsed.flow_ttl(),syn,Some(&assigned)).map(str::to_owned)
                    } else {
                        let tag=super::exit_picker::flow_tag(&flow.selection_tag(),syn);
                        let selected=sparse_handle.exit_picker().request(&intent.id,&tag,parsed.destination(),false);
                        let peer=match selected {
                            Some(porthub_network::policy::ExitChoice::Peer{id}) if sparse_handle.exit_pair_authority(&id).is_some()=>Some(id),
                            #[cfg(feature="local-tor")]
                            Some(porthub_network::policy::ExitChoice::LocalTor) if local_tor.as_ref().is_some_and(|tor|tor.ready())=>Some(super::tor_exit::LOCAL_TOR.into()),
                            _=>None,
                        };
                        let assigned=exit_selection.select_for_peer(flow,now,parsed.flow_ttl(),syn,peer.as_deref()).map(str::to_owned);
                        if assigned.is_some(){sparse_handle.exit_picker().committed(&intent.id,&tag);}
                        assigned
                    }
                }
                else if parsed.destination().is_private() {
                    exit_selection.select_for_peer_with(parsed.flow_id(), Instant::now(), parsed.flow_ttl(), parsed.opening_sequence(), |available| {
                        porthub_mesh::lan_routes::choose_with_single_fallback(parsed.destination(),
                            exit_lan_peers.iter().filter(|(id,_)|available.binary_search(id).is_ok())
                                .map(|(id,networks)|(id.as_str(),networks.as_slice()))).map(str::to_owned)
                    }).map(str::to_owned)
                } else {
                    exit_selection.select_with_syn(parsed.flow_id(), Instant::now(), parsed.flow_ttl(), parsed.opening_sequence()).map(str::to_owned)
                }
            } else if !by_ip.contains_key(&parsed.source()) {
                by_ip.get(&parsed.destination()).cloned()
            } else { None };
            if let Some(peer) = exit_peer {
                #[cfg(feature="local-tor")]
                if peer==super::tor_exit::LOCAL_TOR {
                    if let Some(tor)=local_tor.as_mut() {tor.packet(bytes::Bytes::copy_from_slice(&buffer[..size]));}
                    continue;
                }
                if size <= porthub_mesh::MAX_PACKET - 20 && policy.check_exit(&buffer[..size], &peer, false) {
                    exit_selection.observe_close(&parsed.flow_id(), &peer, true, parsed.is_finish(), parsed.is_reset(), Instant::now());
                    mark_activity(&mut last_activity, &peer, Instant::now());
                    let peers = sessions.read().await;
                    let direct = peers.get(&peer).filter(|session| session.state() == porthub_mesh::State::Ready);
                    let relay_ready = relay_sender.is_ready();
                    let mode = *strategy.borrow();
                    let default = mode.prefer_peer_transport(direct.is_some_and(|session| session.is_relay()), relay_ready);
                    let prefer = if mode == super::strategy::Mode::Auto {
                        path_quality.prefer_peer(&peer, default, Instant::now(), || verified_lan(&policy, &peer, direct))
                    } else { default };
                    if let (Some(source), Some(destination), Some(use_direct)) = (
                        peer_ips.get(&profile.peer_id), peer_ips.get(&peer),
                        paths.choose_preferred(parsed, direct.is_some(), relay_ready, prefer),
                    ) {
                        let packet = porthub_mesh::control_packet::encode(porthub_mesh::control_packet::EXIT, *source, *destination, &buffer[..size])?;
                        if use_direct {
                            if let Some(session) = direct {let n=packet.len();if send_exit_authorized(installed_authority.as_ref(),&sparse_handle,&peer,session,packet).is_ok(){if let Some(c)=traffic_counters.get(&peer){c.add(true,!session.is_relay(),n);}} }
                        } else { if relay_sender.send_exit(&peer, &packet).is_ok(){if let Some(c)=traffic_counters.get(&peer){c.add(true,false,packet.len());}} }
                    }
                }
                continue;
            }
            // A pending exit selection is not an unknown private peer. Keep
            // its metadata in the bounded picker instead of filling both queues.
            if sparse_exit_intent.is_some() && !overlay_destination && exit_traffic_mode.permits(parsed.destination())
                && peer_ips.get(&profile.peer_id)==Some(&parsed.source()) && !by_ip.contains_key(&parsed.destination()) {continue;}
            let Some(peer)=by_ip.get(&parsed.destination()) else {if peer_ips.get(&profile.peer_id)==Some(&parsed.source()){sparse_handle.request_ip(parsed.destination());}continue;};
            if sparse_handle.enabled()&&(policy.pair_peer(peer).is_none()||!sparse_handle.touch_peer(peer)){sparse_handle.request_ip(parsed.destination());continue;}
            if policy.check(&buffer[..size],peer,false) {
                mark_activity(&mut last_activity,peer,std::time::Instant::now());
                let peers=sessions.read().await;
                let direct=peers.get(peer).filter(|session|session.state()==porthub_mesh::State::Ready);
                let relay_ready=relay_sender.is_ready();
                let mode=*strategy.borrow();
                // Start the connection on an available carrier while ICE gathers.
                // Dropping its SYN here adds the operating system's retransmission delay.
                let default_prefer_peer=mode.prefer_peer_transport(direct.is_some_and(|session|session.is_relay()),relay_ready);
                let prefer_peer=if mode==super::strategy::Mode::Auto {
                    path_quality.prefer_peer(peer,default_prefer_peer,std::time::Instant::now(),|| verified_lan(&policy,peer,direct))
                } else { default_prefer_peer };
                #[cfg(all(feature="private-sparse",feature="private-stream"))]
                if sparse_handle.enabled() {
                    if let Some(flows)=&guarded_flows {
                        let negotiated=sparse_handle.by_id(peer).is_some_and(|p|p.stream_transport=="quic3-credit");
                        let prefer_stream=negotiated&&(!prefer_peer || direct.is_none_or(|session|session.is_relay()));
                        if flows.kernel_packet(peer,bytes::Bytes::copy_from_slice(&buffer[..size]),prefer_stream){continue;}
                    }
                }
                #[cfg(feature="private-stream")]
                if let Some(router)=&stream_router {
                    let prefer_stream=!prefer_peer || direct.is_none_or(|session|session.is_relay());
                    if router.kernel_packet(peer,bytes::Bytes::copy_from_slice(&buffer[..size]),prefer_stream){continue;}
                }
                match paths.choose_preferred(parsed,direct.is_some(),relay_ready,prefer_peer) {
                    Some(true)=>{if let Some(session)=direct {if send_authorized(installed_authority.as_ref(),&sparse_handle,peer,session,bytes::Bytes::copy_from_slice(&buffer[..size])).is_ok(){if let Some(c)=traffic_counters.get(peer){c.add(true,!session.is_relay(),size);}}}},
                    Some(false)=>{if relay_sender.send(peer,&buffer[..size]).is_ok(){if let Some(c)=traffic_counters.get(peer){c.add(true,false,size);}}},None=>{}
                }
            } else {
                #[cfg(feature = "private-stream")]
                if let (Some(tun), Some(reply)) = (&device, policy.closed_local_tcp_reply(&buffer[..size], peer)) {
                    // Local socket feedback only. Do not transmit a reset to another machine.
                    tokio::select! {
                        _ = work.cancelled() => anyhow::bail!("private authority ended before local socket feedback"),
                        result = write_authorized(installed_authority.as_ref(), &sparse_handle, Some(peer), tun, &reply) => result?,
                    }
                }
            }
        },
        result=async {
            #[cfg(feature="local-tor")]
            {tor_settings.changed().await}
            #[cfg(not(feature="local-tor"))]
            {std::future::pending::<std::result::Result<(),tokio::sync::watch::error::RecvError>>().await}
        }=>{
            if result.is_err(){anyhow::bail!("Tor settings owner stopped");}
            #[cfg(feature="local-tor")]
            {
                super::tor_exit::reconcile(&mut local_tor,tor_route_groups,&tor_settings.borrow(),&path.with_extension("tor"),interfaces.clone(),events.clone(),work.child_token())?;
                refresh_tor_dns(&dns_upstream,&local_tor,&exit_route,exit_available,&policy);
                if let Some(snapshot)=latest_snapshot.clone().filter(|snapshot| snapshot.value.expires_at > porthub_network::local_wall_time() && snapshot.check().is_ok()) {
                    events.send(Event::Snapshot(snapshot)).await.map_err(|_|anyhow::anyhow!("private packet owner closed"))?;
                }
            }
        },
        changed=route_events.changed(),if route_events_open=>{
            if changed.is_err(){route_events_open=false;}else if sparse_handle.enabled(){
                if let Some(base)=sparse_authority.as_ref().filter(|_|device.is_some()){
                    let audit=audit_capture(&mut device,&path,base,&peer_ips.values().copied().collect::<Vec<_>>()).await?;last_route_audit=Some(Instant::now());
                    #[cfg(all(feature="private-sparse",feature="private-stream"))]
                    {native_stream_safe=audit.capture.conflicting.is_empty()&&audit.conflicting_peers.is_empty();if !native_stream_safe{native_streams.send_replace(None);}}

                    let retired=retire_route_conflicts(&mut policy,&sparse_handle,&audit.conflicting_peers);
                    for id in retired{peer_ips.remove(&id);by_ip.retain(|_,peer|peer!=&id);}
                    #[cfg(feature="private-stream")]
                    if let Some(router)=&stream_router{router.update_pairs_authorized(base,&policy.private_stream_pair_snapshots(),installed_authority.clone(),Some(sparse_handle.clone()))?;}
                }
            }
        },
        changed=interfaces.changed(),if interface_changes_open=>{
            if changed.is_err(){interface_changes_open=false;}
            else {

            }
        },
        fixture_wake=async {
            #[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]
            {if provider_fixture_gate.as_ref().is_some_and(|gate|gate.active()){fixture_gate_tick.tick().await;Ok::<_,anyhow::Error>(())}else{std::future::pending().await}}
            #[cfg(not(all(target_os="linux",feature="private-sparse",feature="netns-tests")))]{std::future::pending::<Result<()>>().await}
        }=>{fixture_wake?;#[cfg(all(target_os="linux",feature="private-sparse",feature="netns-tests"))]if let Some(gate)=&mut provider_fixture_gate{gate.poll(&events,&exit_refresh)?;}},
        provider_wake=async {
            #[cfg(all(target_os="linux",feature="private-sparse"))]
            {if pending_provider.len()>0{tokio::select!{_=provider_tick.tick()=>Ok::<_,anyhow::Error>(()),result=exit_ready_notice.changed()=>result}}else{std::future::pending().await}}
            #[cfg(not(all(target_os="linux",feature="private-sparse")))]
            {std::future::pending::<Result<()>>().await}
        }=>{
            provider_wake?;
            #[cfg(all(target_os="linux",feature="private-sparse"))]
            for _ in 0..pending_provider.len().min(16){
                let Some(mut entry)=pending_provider.pop() else{break;};let peer=entry.origin.id.clone();
                let Some(current)=sparse_handle.by_id(&peer) else{if !entry.refresh_requested{sparse_handle.request_peer_once(&peer);entry.refresh_requested=true;}pending_provider.pending(entry);continue;};
                if !pending_exit::same_identity(&entry.origin,&current){continue;}
                if !pending_exit::same_peer(&entry.origin,&current){
                    if !entry.refresh_requested{sparse_handle.request_peer_once(&peer);entry.refresh_requested=true;}
                    pending_provider.pending(entry);continue;
                }
                let Some(packet)=Packet::parse(&entry.bytes) else{continue;};
                if !exit_clients.contains(&packet.source())||!policy.check_exit(&entry.bytes,&peer,true){continue;}
                let Ok(Some(original))=incoming_exit_permit(Some(&entry.base),&sparse_handle,&peer,Some(entry.origin.clone())) else{continue;};
                if !entry.bind(&exit_native_plan,&current,original){continue;}
                if !exit_refresh.ready(&exit_native_plan){
                    #[cfg(feature="netns-tests")]
                    if let Some(gate)=&mut provider_fixture_gate{gate.waiting(exit_native_plan.diagnostic_generation());}
                    pending_provider.pending(entry);continue;
                }
                let Ok(Some(current_permit))=incoming_exit_permit(installed_authority.as_ref(),&sparse_handle,&peer,Some(entry.origin.clone())) else{continue;};
                let Ok(guard)=entry.guard(&exit_native_plan,&current,current_permit,&exit_refresh) else{continue;};
                if let Some(tun)=&device{
                    let delivered=pending_exit::during(guard,async{tokio::select!{_=work.cancelled()=>anyhow::bail!("private authority ended before packet delivery"),result=write_exit_authorized(installed_authority.as_ref(),&sparse_handle,&peer,tun,&entry.bytes)=>result}}).await?;
                    #[cfg(feature="netns-tests")]
                    if delivered.is_some(){provider_fixture_phase("pending_native_write_complete",exit_native_plan.diagnostic_generation(),1);}
                    if delivered.is_none()&&entry.valid(){pending_provider.pending(entry);}
                }
            }
        },
        _=cold_tick.tick(),if cold_datagrams.len()>0=>{
            let scope=sparse_authority.as_ref().zip(sparse_exit_intent.as_ref())
                .and_then(|(base,intent)|cold_datagrams::Scope::from(base,intent));
            cold_datagrams.observe(scope);
            for _ in 0..cold_datagrams.len().min(16) {
                let Some(item)=cold_datagrams.pop(Instant::now()) else{break;};
                let Some(intent)=&sparse_exit_intent else{continue;};
                let Some(parsed)=Packet::parse(&item.bytes) else{continue;};
                if !intent.traffic_mode.permits(parsed.destination()) || sparse_authority.as_ref().and_then(|base|base.sparse.as_ref()).is_some_and(|s|s.capture_pools.iter().any(|pool|pool.contains(parsed.destination()))){continue;}
                let selected=exit_selection.assigned_peer(&item.flow,Instant::now(),item.syn).map(str::to_owned)
                    .map(cold_datagrams::assigned_choice)
                    .or_else(||sparse_handle.exit_picker().request(&intent.id,&item.tag,parsed.destination(),false));
                if !cold_datagrams::peer_retention_applies(selected.as_ref(),item.syn){cold_datagrams.discard_flow(item.flow);continue;}
                let Some(porthub_network::policy::ExitChoice::Peer{id:peer})=selected else{cold_datagrams.pending(item);continue;};
                if sparse_handle.exit_pair_authority(&peer).is_none(){cold_datagrams.pending(item);continue;}
                let peers=sessions.read().await;
                let direct=peers.get(&peer).filter(|session|session.state()==porthub_mesh::State::Ready);
                let relay_ready=relay_sender.is_ready();let mode=*strategy.borrow();
                let default=mode.prefer_peer_transport(direct.is_some_and(|session|session.is_relay()),relay_ready);
                let prefer=if mode==super::strategy::Mode::Auto{path_quality.prefer_peer(&peer,default,Instant::now(),|| verified_lan(&policy,&peer,direct))}else{default};
                let Some(use_direct)=paths.choose_preferred(parsed,direct.is_some(),relay_ready,prefer) else{cold_datagrams.pending(item);continue;};
                if !item.valid(Instant::now())||work.is_cancelled(){continue;}
                let assigned=exit_selection.select_for_peer(item.flow,Instant::now(),parsed.flow_ttl(),item.syn,Some(&peer));
                // Pair/choice publication precedes the next health tick's
                // availability view. Retain the ORIGINAL datagram, not a new TTL.
                if assigned.is_none(){cold_datagrams.pending(item);continue;}
                if assigned!=Some(peer.as_str())||!policy.check_exit(&item.bytes,&peer,false){continue;}
                let (Some(source),Some(destination))=(peer_ips.get(&profile.peer_id),peer_ips.get(&peer)) else{cold_datagrams.pending(item);continue;};
                let Ok(Some(current))=super::authority_event::send_exit_permit(installed_authority.as_ref(),&sparse_handle,&peer) else{continue;};
                let permit=item.permit(current);
                let packet=porthub_mesh::control_packet::encode(porthub_mesh::control_packet::EXIT,*source,*destination,&item.bytes)?;
                let n=packet.len();
                let sent=if use_direct {direct.is_some_and(|session|session.send_guarded(packet,Some(permit)).is_ok())}
                    else{relay_sender.send_exit_guarded(&peer,&packet,Some(permit)).is_ok()};
                if sent {
                    sparse_handle.exit_picker().committed(&intent.id,&item.tag);
                    mark_activity(&mut last_activity,&peer,Instant::now());
                    if let Some(c)=traffic_counters.get(&peer){c.add(true,use_direct&&direct.is_some_and(|s|!s.is_relay()),n);}
                }else{cold_datagrams.pending(item);}
            }
        },
        _=probe_tick.tick(),if device.is_some()=>{
            #[cfg(target_os = "macos")]
            if let (Some(zone), Some(registration)) = (zone.as_ref(), dns_registration.as_mut()) {
                dns::maintain_macos_registration(zone, registration).await;
            }
            #[cfg(feature="local-tor")]
            let picker_tor_ready=local_tor.as_ref().is_some_and(|tor|tor.ready());
            #[cfg(not(feature="local-tor"))]
            let picker_tor_ready=false;
            sparse_handle.exit_picker().update_carriers(relay_sender.is_ready(),picker_tor_ready);

            check_installed_authority(&mut policy, installed_authority.as_ref())?;
            if sparse_handle.enabled()&&last_route_audit.is_none_or(|at|at.elapsed()>=Duration::from_secs(5)){
                if let Some(base)=sparse_authority.as_ref().filter(|_|device.is_some()){
                    let audit=audit_capture(&mut device,&path,base,&peer_ips.values().copied().collect::<Vec<_>>()).await?;last_route_audit=Some(Instant::now());
                    #[cfg(all(feature="private-sparse",feature="private-stream"))]
                    {native_stream_safe=audit.capture.conflicting.is_empty()&&audit.conflicting_peers.is_empty();if !native_stream_safe{native_streams.send_replace(None);}}

                    let retired=retire_route_conflicts(&mut policy,&sparse_handle,&audit.conflicting_peers);
                    for id in retired{peer_ips.remove(&id);by_ip.retain(|_,peer|peer!=&id);}
                    #[cfg(feature="private-stream")]
                    if let Some(router)=&stream_router{router.update_pairs_authorized(base,&policy.private_stream_pair_snapshots(),installed_authority.clone(),Some(sparse_handle.clone()))?;}
                }
            }
            if sparse_handle.enabled(){
                let expired:Vec<_>=policy.pair_snapshots().into_iter().filter_map(|(snapshot,_)| snapshot.peers.into_iter().find(|p|p.id!=profile.peer_id)).filter(|p|!sparse_handle.peer_is_live(&p.id)).map(|p|p.id).collect();
                let removed=!expired.is_empty();
                for id in expired {policy.revoke_pair(&id);sparse_handle.retire(&id);peer_ips.remove(&id);by_ip.retain(|_,peer|peer!=&id);}
                if removed {if let Some(tun)=&device {tun.update_routes(&peer_ips.values().copied().collect::<Vec<_>>()).await?;}}
                for peer in policy.active_pair_flows(){sparse_handle.touch_peer(&peer);}
                #[cfg(feature="private-stream")]
                if let Some(router)=&stream_router{for peer in router.active_peers(){sparse_handle.touch_peer(&peer);}}
            }
            if sparse_handle.enabled() {
                if let Some(base)=&sparse_authority {
                    let projection=super::exit_plumbing::project(base,&sparse_handle.exit_leases());
                    online_peers=super::exit_plumbing::online_peers(&projection);
                    if let Some(intent)=&sparse_exit_intent {
                        let mut peers=projection.exit_routes.iter().find(|route|route.id==intent.id).map(|route|route.routing_peers.clone()).unwrap_or_default();
                        #[cfg(feature="local-tor")]
                        if intent.tor_enabled&&intent.traffic_mode.internet(){peers.push(super::tor_exit::LOCAL_TOR.into());}
                        exit_lan_peers=peers.iter().filter_map(|id|projection.peers.iter().find(|peer|&peer.id==id).map(|peer|(id.clone(),peer.lan_networks.clone()))).collect();
                        if let Some(status)=private_status.exit.as_mut() {
                            status.peer_names=peers.iter().take(16).filter_map(|id|projection.peers.iter().find(|peer|&peer.id==id).map(|peer|peer.hostname.clone())).collect();
                            #[cfg(feature="local-tor")]
                            if peers.iter().any(|peer|peer==super::tor_exit::LOCAL_TOR){status.peer_names.push("Local Tor".into());}
                        }
                        exit_route=Some((peers,intent.selection,intent.allow_direct_fallback));
                    }
                    #[cfg(target_os="linux")]
                    {
                        let clients:std::collections::BTreeSet<_>=projection.exit_routes.iter().filter(|route|route.routing_peers.contains(&profile.peer_id))
                            .flat_map(|route|&route.clients).filter_map(|id|projection.peers.iter().find(|peer|&peer.id==id).map(|peer|peer.ip)).collect();
                        if clients!=exit_clients{
                            #[cfg(feature="private-sparse")]
                            {exit_native_plan=exit_refresh.request(clients.clone())?;}
                            #[cfg(not(feature="private-sparse"))]
                            exit_refresh.send_replace(clients.clone());
                            exit_clients=clients;
                        }
                    }
                }
            }

            if let Some((peers, mode, _)) = &exit_route {
                let live = sessions.read().await;
                let mut available = peers.iter().filter(|peer| policy.valid_lease() && online_peers.contains(*peer) && (relay_sender.is_ready() || live.get(*peer).is_some_and(|session| session.state() == porthub_mesh::State::Ready))).cloned().collect::<Vec<_>>();
                #[cfg(feature="local-tor")]
                if peers.iter().any(|peer|peer==super::tor_exit::LOCAL_TOR) && local_tor.as_ref().is_some_and(|tor|tor.ready()) {available.push(super::tor_exit::LOCAL_TOR.into());}
                exit_available = available.len();
                exit_selection.configure(available, *mode);
            } else { exit_available = 0; exit_selection.configure(Vec::new(), Default::default()); }
            let now=std::time::Instant::now();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            if let (Some(tun), Some(own)) = (&device, peer_ips.get(&profile.peer_id)) {
                let bypass = exit_fallback.update(exit_route.as_ref().is_some_and(|(_, _, allowed)| *allowed), exit_available, policy.valid_lease(), now);
                exit_lan_networks=if exit_route.is_some() && exit_traffic_mode.lan() {
                    sparse_exit_intent.as_ref().map(|intent|intent.lan_networks.clone()).unwrap_or_else(||super::exit_plan::lan_networks(&exit_lan_peers,|id|exit_selection.available(id)))
                } else {Vec::new()};
                let desired=exit_route.as_ref().map(|_|super::exit_plan::Plan{index:tun.index,own:*own,mode:exit_traffic_mode,bypass,networks:exit_lan_networks.clone()});
                if *exit_consumer.borrow() != desired { exit_consumer.send_replace(desired); }
            }
            #[cfg(feature="local-tor")]
            refresh_tor_dns(&dns_upstream,&local_tor,&exit_route,exit_available,&policy);
            policy.prune_pairs();
            if sparse_handle.enabled(){traffic_counters=reconcile_traffic(&traffic,&profile.peer_id,sparse_authority.as_ref(),&sparse_handle);}
            #[cfg(feature="private-stream")]
            {
                let mode=*strategy.borrow();
                let default=mode!=super::strategy::Mode::PreferGateway || !relay_sender.is_ready();
                let peers=sessions.read().await;
                let routes=by_ip.iter().filter(|(_,peer)|*peer!=&profile.peer_id).map(|(ip,peer)|{
                    let prefer=if mode==super::strategy::Mode::Auto {path_quality.prefer_peer(peer,default,now,|| verified_lan(&policy,peer,peers.get(peer)))} else {default};
                    let deadline=if sparse_handle.enabled(){policy.pair_snapshots().into_iter().find(|(snapshot,_)|snapshot.peers.iter().any(|p|&p.id==peer)).map(|(_,deadline)|deadline).or(Some(now))}else{None};
                    (*ip,(peer.clone(),prefer,deadline,traffic_counters.get(peer).cloned()))
                }).collect();
                stream_plans.send_replace(StreamCarrierPlan {source:peer_ips.get(&profile.peer_id).copied(),valid_until:stream_router.as_ref().filter(|router|router.valid_lease()).map(|_|now+Duration::from_secs(2)),routes});
            }
            #[cfg(feature="private-stream")]
            if sparse_handle.enabled(){if let (Some(router),Some(base))=(&stream_router,&sparse_authority){router.update_pairs_authorized(base,&policy.private_stream_pair_snapshots(),installed_authority.clone(),Some(sparse_handle.clone()))?;}}
            path_quality.prune(now);
            last_activity.retain(|_,seen|now.saturating_duration_since(*seen)<Duration::from_secs(600));
            let peers=sessions.read().await;
            let mut ready:Vec<_>=peers.iter().filter(|(_,session)|session.state()==porthub_mesh::State::Ready)
                .map(|(id,session)|(id.clone(),session.clone())).collect();
            ready.sort_by(|left,right|left.0.cmp(&right.0));
            if !ready.is_empty() {
                let start=probe_cursor%ready.len();
                // One relay burst fits comfortably in the bounded queue and
                // keeps aggregate background traffic low; rotate promptly.
                let count=ready.len().min(1);
                for offset in 0..count {
                    let (peer,session)=&ready[(start+offset)%ready.len()];
                    if last_activity.get(peer).is_some_and(|seen|now.saturating_duration_since(*seen)<Duration::from_secs(20)) { continue; }
                    if !relay_sender.is_ready() { continue; }
                    for direct in [true,false] {
                        let nonce=next_probe_id;
                        next_probe_id=next_probe_id.wrapping_add(1).max(1);
                        let burst=path_quality.start(peer,direct,nonce,now);
                        let mut complete=true;
                        for packet in burst {
                            let sent=if direct { send_probe_authorized(installed_authority.as_ref(),&sparse_handle,peer,session,packet) } else { relay_probe(&relay_sender,&peer_ips,&profile.peer_id,peer,&packet) };
                            if sent.is_err() { complete=false; break; }
                        }
                        if !complete {
                            path_quality.cancel(peer,direct,nonce,now);
                        }
                    }
                }
                probe_cursor=(start+count)%ready.len();
            }
        },
        _=status_tick.tick()=>{
            check_installed_authority(&mut policy, installed_authority.as_ref())?;
            #[cfg(feature="private-stream")]
            if let Some(router)=&stream_router {router.log_transport_stats();}
            let peers=sessions.read().await;
            let count=peers.values().filter(|peer|peer.state()==porthub_mesh::State::Ready).count();
            #[cfg(feature="private-stream")]
            if tracing::enabled!(tracing::Level::DEBUG) {
                let peer_sessions: Vec<_> = peers.iter().map(|(id, session)| (id.clone(), session.clone())).collect();
                drop(peers);
                for (peer_id, session) in peer_sessions {
                    if let Ok(stats) = session.statistics().await {
                        tracing::debug!(
                            peer_id,
                            carrier = if session.is_relay() { "relay" } else { "direct" },
                            sent_bytes = stats.sent_bytes,
                            received_bytes = stats.received_bytes,
                            dropped_outgoing = stats.dropped_outgoing,
                            dropped_incoming = stats.dropped_incoming,
                            write_errors = stats.write_errors,
                            read_errors = stats.read_errors,
                            "private peer carrier statistics"
                        );
                    }
                }
            }
            #[cfg(feature="local-tor")]
            {
                let settings=tor_settings.borrow();
                private_status.tor=Some(crate::runtime::TorStatus {
                    state:match local_tor.as_ref() {Some(tor) if tor.ready()=>"ready",Some(_)=>"preparing",None if settings.mode==super::tor_preferences::Mode::Disabled=>"disabled",None=>"off"}.into(),
                    mode:settings.mode.as_str().into(),
                    circuit_groups:settings.circuit_groups.or(tor_route_groups).unwrap_or(4),
                });
            }
            #[cfg(target_os="linux")]
            {
                private_status.dns_integration=Some(crate::private_prerequisites::dns_status().into());
                private_status.dns_verified=Some(dns_health.borrow().unwrap_or(false));
            }
            private_status.native_repair = if device.is_none() {
                super::native_owner::repair_status(&path).ok().flatten()
            } else {
                None
            };
            private_status.relay_ready = Some(relay_sender.is_ready());
            private_status.lease_valid = policy.valid_lease();
            if let Some(exit) = &mut private_status.exit {
                exit.available = exit_available;
                #[cfg(any(target_os="linux",target_os="macos"))]
                {exit.state=(*exit_applied.borrow()).to_owned();}
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                { exit.state = "not supported on this platform".into(); }
                if !private_status.lease_valid { exit.state.push_str("; policy expired"); }
                else if exit_available == 0 && exit.state == "exit routing active" { exit.state = "blocked: no reachable exit".into(); }
            }
            let status=crate::runtime::Status{pid:std::process::id(),state:if device.is_some(){"running"}else{"connecting"}.into(),agent_version:crate::VERSION.into(),config_version:String::new(),service_count:count,route:"private".into(),updated_at:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),update_request_id:String::new(),private_status:Some(private_status.clone())};
            profile::write_private(&profile::sibling(&path,".status.json"),&serde_json::to_vec(&status)?,true)?;
            if crate::service::readable::refresh(&path,&status).is_err(){tracing::debug!("local registration display snapshot unavailable");}
        }
    }}Ok(())}.await;
        #[cfg(target_os = "linux")]
        if run.as_ref().is_err_and(|e| e.is::<super::device::LinkDown>() && !e.is::<PrivateStage>())
            && sparse_handle.enabled() && route_events_open && device.is_some()
            && sparse_authority.is_some() && !work.is_cancelled()
        {
            // An inbound datagram raced the kernel link-change notification.
            // Drop that datagram and wake the normal ownership/route audit.
            // The next iteration rechecks authority before processing any traffic.
            route_events.mark_changed();
            continue;
        }
        break run;
    };
    cold_datagrams.observe(None); // revoke retained payloads AND final carrier permits before teardown
    #[cfg(all(target_os="linux",feature="private-sparse"))]
    pending_provider.observe(None);
    private_status.native_repair = super::native_owner::repair_status(&path).ok().flatten();
    let authority_expired = installed_authority.as_ref().is_some_and(|authority| authority.check().is_err());
    if authority_expired {
        policy.revoke();
        sparse_handle.revoke_all();
    }
    if let Err(error) = &result {
        private_status.last_failure = Some(crate::runtime::PrivateWorkerFailure {
            stage: crate::unified::private_failure_stage(error).to_owned(),
            reason: crate::unified::private_failure_reason(error).to_owned(),
        });
    }
    if authority_expired || private_status.native_repair.is_some() || result.is_err() {
        private_status.relay_ready = Some(false);
        private_status.dns_verified = Some(false);
        private_status.lease_valid = false;
        let status=crate::runtime::Status{pid:std::process::id(),state:"stopped".into(),agent_version:crate::VERSION.into(),config_version:String::new(),service_count:0,route:"private".into(),updated_at:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),update_request_id:String::new(),private_status:Some(private_status.clone())};
        if let Ok(bytes)=serde_json::to_vec(&status) {if profile::write_private(&profile::sibling(&path,".status.json"),&bytes,true).is_err(){tracing::warn!("private shutdown status update failed");}}
        let _ = crate::service::readable::refresh(&path, &status);
    }
    authority_owner.revoke();
    work.cancel();
    drop(component_maintenance);
    if tokio::time::timeout(Duration::from_secs(2), async {
        while !tasks.is_empty()||!stream_owners.is_empty()||!guarded_owners.is_empty(){
            tokio::select!{_=tasks.join_next(),if !tasks.is_empty()=>{},_=stream_owners.join_next(),if !stream_owners.is_empty()=>{},_=guarded_owners.join_next(),if !guarded_owners.is_empty()=>{}}
        }
    })
    .await
    .is_err()
    {
        tasks.abort_all();stream_owners.abort_all();guarded_owners.abort_all();
    }
    while tasks.join_next().await.is_some() {}
    while stream_owners.join_next().await.is_some() {}
    while guarded_owners.join_next().await.is_some() {}
    // Drain the final counter tail only after every carrier producer stopped.
    let final_traffic=traffic.clone();let _=tokio::task::spawn_blocking(move||final_traffic.sample()).await;
    for session in sessions.write().await.drain().map(|(_, session)| session) {
        session.close().await;
    }
    if let Err(error)=dns::shutdown_registration(&mut dns_registration).await{tracing::warn!("owned private DNS cleanup pending: {error}");}
    drop(dns_registration);
    drop(device);
    if crate::service::readable::stopped(&path).is_err() {
        tracing::debug!("local registration display snapshot unavailable");
    }
    if let Some(log_stream) = &mut log_stream { log_stream.stop().await; }
    result
}


#[cfg(feature="local-tor")]
fn refresh_tor_dns(upstream:&Option<Arc<super::dns_upstream::Upstream>>,tor:&Option<super::tor_exit::LocalTor>,route:&Option<(Vec<String>,porthub_mesh::exit_policy::Selection,bool)>,available:usize,policy:&Engine) {
    let Some(upstream)=upstream else {return;};
    let configuration=route.as_ref().filter(|(peers,_,_)|peers.iter().any(|peer|peer==super::tor_exit::LOCAL_TOR)).map(|(_,_,fallback)| {
        let tor_available=usize::from(tor.as_ref().is_some_and(|tor|tor.ready()));
        super::dns_upstream::TorDns {
            resolver:tor.as_ref().map(|tor|tor.resolver()),
            allow_other:policy.valid_lease() && (available>tor_available || (*fallback && available==0)),
            valid_until:policy.lease_deadline().unwrap_or_else(Instant::now),
        }
    });
    upstream.set_tor(configuration);
}

#[cfg(all(test, feature = "private-stream"))]
#[path = "traffic_transport_tests.rs"]
mod traffic_transport_tests;
#[cfg(test)]
mod sparse_native_audit_tests {
    use super::*;
    #[test]
    fn effective_traffic_tracks_pairs_across_base_renewal_without_resetting_counters() {
        use porthub_network::policy::{Lookup,PairLease};
        let own=format!("{}:{}","a".repeat(24),"b".repeat(24));
        let b=format!("{}:{}","c".repeat(24),"d".repeat(24));
        let c=format!("{}:{}","e".repeat(24),"f".repeat(24));
        let epoch="a".repeat(64);
        let base:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":own,"revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":epoch},"peers":[{"id":own,"ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"}],"grants":[]})).unwrap();
        let (handle,_)=super::super::sparse::channel();handle.update_base(&base);
        for (id,ip) in [(&b,"10.203.1.2"),(&c,"10.203.2.2")] {
            let lease:PairLease=serde_json::from_value(serde_json::json!({"workspace":"w","self":own,"epoch":epoch,"revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(15),"local":{"id":own,"ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"},"peer":{"id":id,"ip":ip,"fingerprint":format!("remote-{id}"),"instance":format!("instance-{id}"),"hostname":"b.phub"},"grants":[{"source":own,"destination":id,"protocol":"any","ports":[]}]})).unwrap();
            handle.installed(&Lookup{kind:"peer".into(),value:id.clone()},lease);
        }
        let mut builder=tempfile::Builder::new();builder.prefix("pair-traffic-");
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;builder.permissions(std::fs::Permissions::from_mode(0o700));}
        let root=builder.tempdir().unwrap();
        let tracker=super::super::traffic::Tracker::new(&root.path().join("profile.json"));
        let first=reconcile_traffic(&tracker,&own,Some(&base),&handle);
        assert_eq!(first.len(),2);assert!(!first.contains_key(&own));
        first[&b].add(true,false,100);first[&c].add(true,true,200);
        // A local-only base reply must not evict independently leased counters.
        handle.update_base(&base);
        let renewed=reconcile_traffic(&tracker,&own,Some(&base),&handle);
        assert!(Arc::ptr_eq(&first[&b],&renewed[&b]));
        assert!(Arc::ptr_eq(&first[&c],&renewed[&c]));
        handle.retire(&b);
        let retired=reconcile_traffic(&tracker,&own,Some(&base),&handle);
        assert!(!retired.contains_key(&b));assert_eq!(retired.len(),1);
        assert!(Arc::ptr_eq(&first[&c],&retired[&c]));
        // Tracker retains the retired handle's unsampled tail for its sampler.
        assert!(Arc::ptr_eq(&first[&b],&tracker.counter(&b).unwrap()));
        std::thread::sleep(Duration::from_millis(2));
        tracker.sample();
        let pending=tracker.report().expect("retired pair tail must be durable");
        let b_row=pending.rows.iter().find(|row|row.peer_id==b).unwrap();
        let c_row=pending.rows.iter().find(|row|row.peer_id==c).unwrap();
        assert_eq!(b_row.relay_sent,100);assert_eq!(c_row.direct_sent,200);
        assert!(tracker.counter(&b).is_none());assert!(tracker.counter(&c).is_some());

    }
    #[test]
    fn native_conflict_retires_only_exact_peer_authority_and_dns_cache() {
        use porthub_network::policy::{Lookup,PairLease};
        let epoch="a".repeat(64);
        let snapshot:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":epoch},"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"}],"grants":[]})).unwrap();
        let (handle,_)=super::super::sparse::channel();handle.update_base(&snapshot);
        let mut policy=Engine::default();policy.apply(snapshot).unwrap();
        for (id,ip) in [("b","10.203.1.2"),("c","10.203.2.2")] {
            let lease:PairLease=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","epoch":epoch,"revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(15),"local":{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"},"peer":{"id":id,"ip":ip,"fingerprint":format!("remote-{id}"),"instance":format!("instance-{id}"),"hostname":format!("{id}.phub")},"grants":[{"source":"a","destination":id,"protocol":"any","ports":[]}]})).unwrap();
            policy.install_pair(lease.clone()).unwrap();handle.installed(&Lookup{kind:"peer".into(),value:id.into()},lease);
        }
        assert_eq!(retire_route_conflicts(&mut policy,&handle,&["10.203.1.2".parse().unwrap()]),vec!["b"]);
        assert!(policy.pair_peer("b").is_none());assert!(handle.by_id("b").is_none());
        assert!(handle.dns_ttl("10.203.1.2".parse().unwrap()).is_none());
        assert!(policy.pair_peer("c").is_some());assert!(handle.by_id("c").is_some());assert!(policy.valid_lease());
        assert!(retire_route_conflicts(&mut policy,&handle,&["10.203.99.99".parse().unwrap()]).is_empty());
    }
}

#[cfg(test)]
mod stream_retirement_tests {
    use super::*;
    #[tokio::test]
    async fn actual_joined_retirement_does_not_stop_replacement_and_shutdown_is_normal()->Result<()>{
        let mut owners=JoinSet::new();let old=CancellationToken::new();let stop=old.clone();
        owners.spawn(async move{stop.cancelled().await;(1,Ok(()))});old.cancel();
        ensure!(!stream_owner_completed(2,false,owners.join_next().await)?,"retired owner stopped replacement profile");
        owners.spawn(async{(2,Ok(()))});ensure!(stream_owner_completed(2,false,owners.join_next().await).is_err(),"unexpected live owner stop hidden");
        owners.spawn(async{(2,Ok(()))});ensure!(stream_owner_completed(2,true,owners.join_next().await)?,"normal profile shutdown became stream failure");
        owners.spawn(async{(1,Err(anyhow::anyhow!("retired-native-cleanup-error")))});
        let error=stream_owner_completed(2,false,owners.join_next().await).unwrap_err();ensure!(error.to_string().contains("retired-native-cleanup-error"),"old-owner cleanup failure was hidden or replaced");Ok(())
    }
}

#[cfg(all(test,feature="private-sparse"))]
mod relay_origin_runtime_tests {
 use super::*;
 use std::sync::atomic::{AtomicUsize,Ordering};
 fn fixture()->(super::super::sparse::Handle,super::super::authority_event::Authority<()>,porthub_network::policy::PairLease){
  let expiry=chrono::Utc::now()+chrono::Duration::seconds(15);let epoch="a".repeat(64);
  let base:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":expiry,"sparse":{"protocol":1,"epoch":epoch,"exit_epoch":"e".repeat(64)},"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"}],"grants":[]})).unwrap();
  let pair:porthub_network::policy::PairLease=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","epoch":"a".repeat(64),"revision":1,"expires_at":expiry,"local":base.peers[0],"peer":{"id":"b","ip":"10.203.1.2","fingerprint":"remote","instance":"remote-instance","hostname":"b.phub","relay_origin":"1".repeat(32)},"grants":[],"exit":{"epoch":"e".repeat(64),"route_id":"route","client":"a","router":"b","traffic_mode":"internet_only"}})).unwrap();
  let authority=super::super::authority_event::Authority::new((),super::super::authority_event::request_start(None).unwrap(),expiry);
  let(handle,_)=super::super::sparse::channel();handle.update_base_authority(&base,authority.clone());let query=porthub_network::policy::Lookup{kind:"peer".into(),value:"b".into()};handle.installed_authority(&query,pair.clone(),authority.clone());(handle,authority,pair)
 }
 #[tokio::test]
 async fn relayed_reply_pending_write_rechecks_incarnation_without_requiring_provider_ack(){
  struct Pending(Arc<AtomicUsize>);impl std::future::Future for Pending{type Output=Result<()>;fn poll(self:std::pin::Pin<&mut Self>,_:&mut std::task::Context<'_>)->std::task::Poll<Self::Output>{self.0.fetch_add(1,Ordering::SeqCst);std::task::Poll::Pending}}
  let(handle,base,mut pair)=fixture();let origin=Arc::new(pair.peer.clone());let permit=incoming_exit_permit(Some(&base),&handle,"b",Some(origin)).unwrap().unwrap();assert!(permit.valid());
  let direct=super::super::authority_event::send_exit_permit(Some(&base),&handle,"b").unwrap().unwrap();let polls=Arc::new(AtomicUsize::new(0));let task=tokio::spawn(super::super::authority_event::during_permit(permit,Pending(polls.clone())));
  tokio::time::timeout(Duration::from_millis(200),async{while polls.load(Ordering::SeqCst)==0{tokio::task::yield_now().await;}}).await.unwrap();let before=polls.load(Ordering::SeqCst);
  pair.peer.relay_origin=Some("2".repeat(32));let query=porthub_network::policy::Lookup{kind:"peer".into(),value:"b".into()};handle.installed_authority(&query,pair,base.clone());
  assert!(direct.valid(),"stamp-only change must preserve independent direct RTC authority");
  assert!(tokio::time::timeout(Duration::from_millis(200),task).await.unwrap().unwrap().unwrap().is_none());assert_eq!(polls.load(Ordering::SeqCst),before,"old relay reply polled native write after rebind");
 }
 #[test]
 fn stamp_mismatch_requests_one_fresh_pair_without_evicting_old_direct_authority(){
  let(handle,base,mut pair)=fixture();let mut new_origin=pair.peer.clone();new_origin.relay_origin=Some("2".repeat(32));
  let old=super::super::authority_event::send_exit_permit(Some(&base),&handle,"b").unwrap().unwrap();assert!(!handle.matches_relay_origin(&new_origin));
  assert!(handle.request_peer_once("b"));for _ in 0..1000{assert!(!handle.request_peer_once("b"));}assert!(old.valid());assert_eq!(handle.by_id("b").unwrap().relay_origin,Some("1".repeat(32)));
  pair.peer=new_origin.clone();let query=porthub_network::policy::Lookup{kind:"peer".into(),value:"b".into()};handle.installed_authority(&query,pair,base);assert!(handle.matches_relay_origin(&new_origin));
  for field in 0..3{let mut foreign=new_origin.clone();match field{0=>foreign.ip="10.203.2.9".parse().unwrap(),1=>foreign.fingerprint="foreign".into(),_=>foreign.instance="foreign".into()};assert!(!handle.matches_relay_origin(&foreign));}
 }
}

#[cfg(all(test,feature="private-sparse",feature="private-stream"))]
mod raw_preopen_egress_tests {
    use super::*;
    #[test]
    fn raw_syn_pair_expiry_is_a_local_drop_and_final_carrier_keeps_original_guard()->Result<()> {
        use super::super::{authority_event::Authority,authority_clock::{RequestWindow,NativeClock}};
        let a=porthub_mesh::Identity::new()?;let b=porthub_mesh::Identity::new()?;
        let own=porthub_mesh::streams::Peer{id:"a".into(),ip:"10.234.250.1".parse()?,fingerprint:a.fingerprint().into(),instance:"a-instance".into()};
        let peer=porthub_mesh::streams::Peer{id:"b".into(),ip:"10.235.1.2".parse()?,fingerprint:b.fingerprint().into(),instance:"b-instance".into()};
        let expiry=chrono::Utc::now()+chrono::Duration::seconds(60);
        let base=Authority::new((),Some(RequestWindow::start(std::sync::Arc::new(NativeClock))?),expiry);
        let info=|p:&porthub_mesh::streams::Peer|serde_json::json!({"id":p.id,"ip":p.ip,"fingerprint":p.fingerprint,"instance":p.instance,"hostname":format!("{}.phub",p.id)});
        let snapshot:Snapshot=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":expiry,"sparse":{"protocol":1,"epoch":"a".repeat(64)},"peers":[info(&own)],"grants":[]}))?;
        let pair=serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","epoch":"a".repeat(64),"revision":1,"expires_at":expiry,"local":info(&own),"peer":info(&peer),"grants":[{"source":"a","destination":"b","protocol":"tcp","ports":[{"start":443,"end":443}]}]}))?;
        let(handle,_)=super::super::sparse::channel();handle.update_base_authority(&snapshot,base.clone());
        handle.installed_authority(&porthub_network::policy::Lookup{kind:"peer".into(),value:"b".into()},pair,base.clone());
        let original=porthub_mesh::udp::SendPermit::bounded(||true,||Some(Duration::from_secs(5)));
        assert!(raw_syn_send_permit(None,&handle,"b",original.clone()).is_none());
        let queued=raw_syn_send_permit(Some(&base),&handle,"b",original.clone()).unwrap();assert!(queued.valid());
        handle.revoke_all();
        assert!(!queued.valid());
        assert!(raw_syn_send_permit(Some(&base),&handle,"b",original).is_none());
        Ok(())
    }
}
