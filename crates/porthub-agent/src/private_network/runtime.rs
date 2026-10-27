//! Linux packet owner: one TUN read, bounded peer delivery, and no gateway
//! requests on the packet path. Dropping the exclusive TUN removes its routes.
use super::{
    controller::{self, Event, Sessions},
    device::Tun,
    dns,
    policy::{Engine, Packet},
};
use crate::{
    private_profile::Profile,
    profile::{self, Lease},
};
use anyhow::{ensure, Result};
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

fn mark_activity(activity: &mut HashMap<String, Instant>, peer: &str, now: Instant) {
    if let Some(last) = activity.get_mut(peer) {
        *last = now;
    } else if activity.len() < 4096 {
        activity.insert(peer.to_owned(), now);
    }
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
    sender.send(peer, &packet)
}

async fn send_exit(
    sessions: &Sessions, relay: &super::relay::Sender,
    ips: &HashMap<String, std::net::Ipv4Addr>, own: &str, peer: &str,
    payload: &[u8], prefer_direct: bool,
) -> Result<()> {
    let (Some(source), Some(destination)) = (ips.get(own), ips.get(peer)) else { return Ok(()); };
    let packet = porthub_mesh::control_packet::encode(porthub_mesh::control_packet::EXIT, *source, *destination, payload)?;
    let peers = sessions.read().await;
    let direct = peers.get(peer).filter(|session| session.state() == porthub_mesh::State::Ready);
    if let Some(session) = direct.filter(|_| prefer_direct || !relay.is_ready()) {
        let _ = session.send(packet);
    } else if relay.is_ready() { let _ = relay.send(peer, &packet); }
    Ok(())
}

#[cfg(feature = "private-stream")]
#[derive(Clone, Default)]
struct StreamCarrierPlan {
    source: Option<std::net::Ipv4Addr>,
    valid_until: Option<Instant>,
    routes: HashMap<std::net::Ipv4Addr, (String, bool)>,
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
        let Some((source, (peer, prefer))) = route else {
            continue;
        };
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
                if session.send_stream(bytes.clone()).await.is_ok() {
                    return;
                }
            }
            if relay.is_ready() {
                let _ = relay.send_stream(&peer, &bytes).await;
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
    let profile = Profile::load(&path)?;
    let _lease = Lease::acquire(&path)?;
    let control = Arc::new(crate::control::Control::new_private(&profile)?);
    let mut log_stream = crate::logs::Guard::start(control, logs, cancel.child_token());
    let name = format!(
        "ph{}",
        &format!("{:x}", Sha256::digest(profile.peer_id.as_bytes()))[..8]
    );
    let sessions: Sessions = Default::default();
    let (events, mut input) = mpsc::channel(4096);
    let work = cancel.child_token();
    let mut tasks = JoinSet::new();
    let (strategy_updates, strategy) =
        tokio::sync::watch::channel(super::strategy::load(&path)?.mode);
    tasks.spawn(super::strategy::run(
        path.clone(),
        strategy_updates,
        work.clone(),
    ));
    let instance = controller::nonce()?;
    let identity = porthub_mesh::Identity::new()?;
    let mut next_probe_id = u64::from_str_radix(&instance[..16], 16)?;
    let (interface_updates, interfaces) = tokio::sync::watch::channel(Vec::new());
    tasks.spawn(super::interfaces::watch(interface_updates, work.clone()));
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
    tasks.spawn(controller::run_watched_identity(
        profile.clone(),
        interfaces.clone(),
        sessions.clone(),
        events.clone(),
        relay_config,
        controller::LocalIdentity {
            instance,
            certificate: identity.clone(),
        },
        work.clone(),
    ));
    let mut device: Option<Arc<Tun>> = None;
    #[cfg(feature = "private-stream")]
    let mut stream_router: Option<super::stream_router::Router> = None;
    let mut zone = None;
    let mut dns_registration: Option<dns::Registration> = None;
    let mut registered_suffixes: Vec<String> = Vec::new();
    let mut registered_rules = Vec::new();
    let mut dns_port: Option<u16> = None;
    let mut policy = Engine::default();
    let mut private_status = crate::runtime::PrivateStatus::default();
    let mut exit_route = None;
    #[cfg(target_os = "linux")]
    let mut exit_fallback = super::exit_selection::Fallback::default();
    let mut exit_available = 0;
    let mut online_peers = std::collections::HashSet::new();
    #[cfg(target_os = "linux")]
    let (exit_consumer, exit_applied) = {
        let (sender, receiver) = watch::channel(None);
        let (report, applied) = watch::channel("pending");
        tasks.spawn(super::exit_routes::watch_reported(receiver, interfaces.clone(), work.clone(), Some(report)));
        (sender, applied)
    };
    let mut exit_selection = super::exit_selection::FlowTable::new(profile.peer_id.clone());
    #[cfg(target_os = "linux")]
    let mut exit_kernel: Option<super::exit_kernel::Kernel> = None;
    #[cfg(target_os = "linux")]
    let mut exit_clients = std::collections::BTreeSet::new();
    #[cfg(target_os = "linux")]
    let exit_refresh = {
        let (sender, receiver) = watch::channel(std::collections::BTreeSet::new());
        tasks.spawn(super::exit_forwarding::watch(name.clone(), receiver, work.clone()));
        sender
    };
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
    let result:Result<()>=async {loop {tokio::select! {
        _=cancel.cancelled()=>break,
        finished=tasks.join_next(),if !tasks.is_empty()=>{match finished {Some(Ok(Ok(()))) if work.is_cancelled()=>break,Some(Ok(Err(error)))=>return Err(error),_=>anyhow::bail!("private background task stopped")}},
        event=input.recv()=>match event {
            Some(Event::Snapshot(snapshot))=>{
                ensure!(snapshot.self_==profile.peer_id && snapshot.workspace==profile.workspace,"private policy identity changed");
                let own=snapshot.peers.iter().find(|p|p.id==profile.peer_id).ok_or_else(||anyhow::anyhow!("private policy omits local peer"))?;
                let routes:Vec<_>=snapshot.peers.iter().filter(|p|p.id!=profile.peer_id).map(|p|p.ip).collect();
                let first_ready = device.is_none();
                policy.apply(snapshot.clone())?;
                #[cfg(feature="private-stream")]
                {
                    if stream_router.is_none() {
                        let (router,background)=super::stream_router::new(profile.peer_id.clone(),own.ip,identity.clone(),events.clone(),work.child_token())?;
                        stream_router=Some(router);tasks.spawn(background.with_carrier(stream_output.clone()).run());
                    }
                    stream_router.as_ref().unwrap().update(&snapshot)?;
                }
                if let Some(tun)=&device {
                    tun.update_routes(&routes).await?;
                } else {
                    let tun=Arc::new(Tun::open(&name,own.ip,&routes).await?);
                    let server=dns::Server::bind(own.ip).await?;let port=server.port()?;
                    zone=Some(server.zone.clone()); tasks.spawn(server.serve(work.clone()));
                    dns_port=Some(port);
                    device=Some(tun);
                }
                online_peers = snapshot.peers.iter().filter(|peer| peer.online).map(|peer| peer.id.clone()).collect();
                private_status.revision = snapshot.revision;
                private_status.grants = snapshot.grants.len();
                private_status.dns_rules = snapshot.dns_rules.len();
                private_status.exit = snapshot.exit_routes.iter().find(|route| route.clients.contains(&profile.peer_id)).map(|route| crate::runtime::ExitStatus {
                    name: route.name.clone(), selection: match route.selection { porthub_mesh::exit_policy::Selection::Sticky => "sticky", porthub_mesh::exit_policy::Selection::RoundRobin => "round robin", porthub_mesh::exit_policy::Selection::Random => "random" }.into(), state: "pending".into(),
                    peers: route.routing_peers.len(), available: 0, allow_direct_fallback: route.allow_direct_fallback,
                    peer_names: route.routing_peers.iter().take(16).filter_map(|id| snapshot.peers.iter().find(|peer| &peer.id == id).map(|peer| peer.hostname.clone())).collect(),
                });
                exit_route = snapshot.exit_routes.iter().find(|route| route.clients.contains(&profile.peer_id))
                    .map(|route| (route.routing_peers.clone(), route.selection, route.allow_direct_fallback));
                // Apply a received policy before processing another packet;
                // the periodic tick only refreshes transport availability.
                if let Some((peers, mode, _)) = &exit_route {
                    let live = sessions.read().await;
                    let available = peers.iter().filter(|peer| online_peers.contains(*peer) && (relay_sender.is_ready() || live.get(*peer).is_some_and(|session| session.state() == porthub_mesh::State::Ready))).cloned().collect::<Vec<_>>();
                    exit_available = available.len();
                    exit_selection.configure(available, *mode);
                } else { exit_available = 0; exit_selection.configure(Vec::new(), Default::default()); }
                #[cfg(target_os = "linux")]
                {
                    let tun = device.as_ref().expect("private tunnel initialized");
                    tun.exit_mtu(!snapshot.exit_routes.is_empty()).await?;
                    let clients: std::collections::BTreeSet<_> = snapshot.exit_routes.iter()
                        .filter(|route| route.routing_peers.contains(&profile.peer_id))
                        .flat_map(|route| &route.clients)
                        .filter_map(|id| snapshot.peers.iter().find(|peer| &peer.id == id).map(|peer| peer.ip)).collect();
                    let bypass = exit_fallback.update(exit_route.as_ref().is_some_and(|(_, _, allowed)| *allowed), exit_available, policy.valid_lease(), Instant::now());
                    let desired = exit_route.as_ref().map(|_| (tun.index, own.ip, bypass));
                    if *exit_consumer.borrow() != desired { exit_consumer.send_replace(desired); }
                    if clients != exit_clients {
                        if exit_kernel.is_none() && !clients.is_empty() { exit_kernel = Some(super::exit_kernel::Kernel::new(&name)?); }
                        exit_refresh.send_replace(clients.clone());
                        if let Some(kernel) = &exit_kernel { kernel.apply(&clients).await?; }
                        exit_clients = clients;
                    }
                }
                // Register every advertised private DNS suffix on the owned
                // tunnel resolver. This also applies suffix changes live.
                zone.as_ref().unwrap().write().await.update(&snapshot)?;
                let mut suffixes=snapshot.dns_suffixes.iter().map(|suffix|suffix.trim_matches('.').to_ascii_lowercase()).filter(|suffix|!suffix.is_empty()).collect::<Vec<_>>();
                if let Some((_,suffix))=own.hostname.split_once('.') { suffixes.push(suffix.trim_matches('.').to_ascii_lowercase()); }
                suffixes.extend(snapshot.dns_rules.iter().map(|rule|porthub_mesh::dns_policy::zone(rule).trim_end_matches('.').to_ascii_lowercase()));
                suffixes.sort();suffixes.dedup();
                if registered_suffixes!=suffixes || registered_rules!=snapshot.dns_rules {
                    let tun=device.as_ref().expect("private tunnel initialized");
                    let port=dns_port.ok_or_else(||anyhow::anyhow!("private DNS listener missing"))?;
                    dns_registration=None;
                    #[cfg(all(target_os = "linux", feature = "netns-tests"))]
                    let isolated = std::env::var("PORTHUB_TEST_OWNED_NETNS").as_deref() == Ok("1") && std::path::Path::new("/.dockerenv").is_file();
                    #[cfg(not(all(target_os = "linux", feature = "netns-tests")))]
                    let isolated = false;
                    if !isolated { dns_registration=Some(dns::register(tun.index,own.ip,port,&suffixes).await?); }
                    registered_suffixes=suffixes;
                    registered_rules=snapshot.dns_rules.clone();
                }
                by_ip=snapshot.peers.iter().map(|p|(p.ip,p.id.clone())).collect();
                peer_ips=snapshot.peers.iter().map(|p|(p.id.clone(),p.ip)).collect();
                // Publish initial readiness immediately. Waiting for
                // the periodic refresh can make a healthy service miss the
                // installer's readiness deadline after a slow initial sync.
                if first_ready { status_tick.reset_immediately(); }
            },
            Some(Event::Packet{peer,bytes,direct,received_at})=>{
                let now=received_at;
                if let Some(envelope) = porthub_mesh::control_packet::decode(porthub_mesh::control_packet::EXIT, bytes.clone()) {
                    if peer_ips.get(&peer) != Some(&envelope.source) || peer_ips.get(&profile.peer_id) != Some(&envelope.destination) { continue; }
                    let Some(packet) = Packet::parse(&envelope.payload) else { continue; };
                    let is_reply = peer_ips.get(&profile.peer_id) == Some(&packet.destination());
                    #[cfg(target_os = "linux")]
                    let can_forward = exit_clients.contains(&packet.source());
                    #[cfg(not(target_os = "linux"))]
                    let can_forward = false;
                    if (is_reply || can_forward) && policy.check_exit(&envelope.payload, &peer, true) {
                        if is_reply {
                            exit_selection.observe(&packet.flow_id(), &peer, Instant::now(), packet.flow_ttl());
                            exit_selection.observe_close(&packet.flow_id(), &peer, false, packet.is_finish(), packet.is_reset(), Instant::now());
                        }
                        if let Some(tun) = &device { tun.write(&envelope.payload).await?; }
                    }
                    continue;
                }
                #[cfg(feature="private-stream")]
                if let Some(envelope)=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::STREAM,bytes.clone()) {
                    if peer_ips.get(&peer)==Some(&envelope.source) && peer_ips.get(&profile.peer_id)==Some(&envelope.destination) {
                        if let Some(router)=&stream_router {router.receive(envelope.source,envelope.payload).await;}
                    }
                    continue;
                }
                let probe_bytes=if let Some(envelope)=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::PROBE,bytes.clone()) {
                    if peer_ips.get(&peer)!=Some(&envelope.source) || peer_ips.get(&profile.peer_id)!=Some(&envelope.destination) {continue;}
                    envelope.payload
                } else {bytes.clone()};
                if let Some(replies)=path_quality.handle(&peer,direct,&probe_bytes,now) {
                    if !replies.is_empty() {
                        if direct {
                            if let Some(session)=sessions.read().await.get(&peer) {
                                for reply in replies { let _=session.send(reply); }
                            }
                        } else {
                            for reply in replies { let _=relay_probe(&relay_sender,&peer_ips,&profile.peer_id,&peer,&reply); }
                        }
                    }
                    continue;
                }
                mark_activity(&mut last_activity,&peer,now);
                if policy.check(&bytes,&peer,true) {
                    if let Some(packet)=Packet::parse(&bytes) {paths.observe(packet,direct);}
                    if let Some(tun)=&device {tun.write(&bytes).await?;}
                }
            },
            #[cfg(feature="private-stream")]
            Some(Event::StreamLocal {peer,bytes})=>{
                let parsed=Packet::parse(&bytes);
                let reset=parsed.is_some_and(|packet|packet.is_reset() && peer_ips.get(&profile.peer_id)==Some(&packet.destination()));
                if policy.check(&bytes,&peer,true) || reset {
                    if let Some(tun)=&device {tun.write(&bytes).await?;}
                }
            },
            #[cfg(feature="private-stream")]
            Some(Event::StreamDatagram {destination,payload})=>{
                let Some(router)=&stream_router else {continue;};if !router.valid_lease(){continue;}
                let (Some(peer),Some(source))=(by_ip.get(&destination),peer_ips.get(&profile.peer_id)) else {continue;};
                let packet=porthub_mesh::control_packet::encode(porthub_mesh::control_packet::STREAM,*source,destination,&payload)?;
                let peers=sessions.read().await;
                let direct=peers.get(peer).filter(|session|session.state()==porthub_mesh::State::Ready);
                let relay_ready=relay_sender.is_ready();let mode=*strategy.borrow();
                // The reliable stream already supplies encryption and recovery.
                // An explicit gateway preference selects its packet carrier,
                // rather than adding a second TURN/DTLS transport around it.
                let default=mode!=super::strategy::Mode::PreferGateway || !relay_ready;
                let prefer=if mode==super::strategy::Mode::Auto {path_quality.prefer_peer(peer,default,Instant::now())} else {default};
                if let Some(session)=direct.filter(|_|prefer || !relay_ready) {let _=session.send(packet);}
                else if relay_ready {let _=relay_sender.send(peer,&packet);}
            },
            None=>anyhow::bail!("private control owner stopped"),
        },
        packet=async {match &device {Some(device)=>device.read(&mut buffer).await,None=>std::future::pending().await}}=>{
            let size=packet?;if size>porthub_mesh::MAX_PACKET {continue;}
            let Some(parsed)=Packet::parse(&buffer[..size]) else {continue;};
            let exit_peer = if peer_ips.get(&profile.peer_id) == Some(&parsed.source()) && !by_ip.contains_key(&parsed.destination()) {
                exit_selection.select_with_syn(parsed.flow_id(), Instant::now(), parsed.flow_ttl(), parsed.opening_sequence()).map(str::to_owned)
            } else if !by_ip.contains_key(&parsed.source()) {
                by_ip.get(&parsed.destination()).cloned()
            } else { None };
            if let Some(peer) = exit_peer {
                if size <= porthub_mesh::MAX_PACKET - 20 && policy.check_exit(&buffer[..size], &peer, false) {
                    exit_selection.observe_close(&parsed.flow_id(), &peer, true, parsed.is_finish(), parsed.is_reset(), Instant::now());
                    let prefer = *strategy.borrow() != super::strategy::Mode::PreferGateway;
                    send_exit(&sessions, &relay_sender, &peer_ips, &profile.peer_id, &peer, &buffer[..size], prefer).await?;
                }
                continue;
            }
            let Some(peer)=by_ip.get(&parsed.destination()) else {continue;};
            if policy.check(&buffer[..size],peer,false) {
                mark_activity(&mut last_activity,peer,std::time::Instant::now());
                let peers=sessions.read().await;
                let direct=peers.get(peer).filter(|session|session.state()==porthub_mesh::State::Ready);
                let relay_ready=relay_sender.is_ready();
                let mode=*strategy.borrow();
                let default_prefer_peer=mode.prefer_peer_transport(direct.is_some_and(|session|session.is_relay()),relay_ready);
                let prefer_peer=if mode==super::strategy::Mode::Auto {
                    path_quality.prefer_peer(peer,default_prefer_peer,std::time::Instant::now())
                } else { default_prefer_peer };
                #[cfg(feature="private-stream")]
                if let Some(router)=&stream_router {
                    let prefer_stream=!prefer_peer || direct.is_none_or(|session|session.is_relay());
                    if router.kernel_packet(peer,bytes::Bytes::copy_from_slice(&buffer[..size]),prefer_stream){continue;}
                }
                match paths.choose_preferred(parsed,direct.is_some(),relay_ready,prefer_peer) {
                    Some(true)=>{if let Some(session)=direct {let _=session.send(bytes::Bytes::copy_from_slice(&buffer[..size]));}},
                    Some(false)=>{let _=relay_sender.send(peer,&buffer[..size]);},None=>{}
                }
            }
        },
        _=probe_tick.tick(),if device.is_some()=>{
            if let Some((peers, mode, _)) = &exit_route {
                let live = sessions.read().await;
                let available = peers.iter().filter(|peer| online_peers.contains(*peer) && (relay_sender.is_ready() || live.get(*peer).is_some_and(|session| session.state() == porthub_mesh::State::Ready))).cloned().collect::<Vec<_>>();
                exit_available = available.len();
                exit_selection.configure(available, *mode);
            } else { exit_available = 0; exit_selection.configure(Vec::new(), Default::default()); }
            let now=std::time::Instant::now();
            #[cfg(target_os = "linux")]
            if let (Some(tun), Some(own)) = (&device, peer_ips.get(&profile.peer_id)) {
                let bypass = exit_fallback.update(exit_route.as_ref().is_some_and(|(_, _, allowed)| *allowed), exit_available, policy.valid_lease(), now);
                let desired = exit_route.as_ref().map(|_| (tun.index, *own, bypass));
                if *exit_consumer.borrow() != desired { exit_consumer.send_replace(desired); }
            }
            #[cfg(feature="private-stream")]
            {
                let mode=*strategy.borrow();
                let default=mode!=super::strategy::Mode::PreferGateway || !relay_sender.is_ready();
                let routes=by_ip.iter().filter(|(_,peer)|*peer!=&profile.peer_id).map(|(ip,peer)|{
                    let prefer=if mode==super::strategy::Mode::Auto {path_quality.prefer_peer(peer,default,now)} else {default};
                    (*ip,(peer.clone(),prefer))
                }).collect();
                stream_plans.send_replace(StreamCarrierPlan {source:peer_ips.get(&profile.peer_id).copied(),valid_until:stream_router.as_ref().filter(|router|router.valid_lease()).map(|_|now+Duration::from_secs(2)),routes});
            }
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
                            let sent=if direct { session.send(packet) } else { relay_probe(&relay_sender,&peer_ips,&profile.peer_id,peer,&packet) };
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
            private_status.lease_valid = policy.valid_lease();
            if let Some(exit) = &mut private_status.exit {
                exit.available = exit_available;
                #[cfg(target_os = "linux")]
                { exit.state = (*exit_applied.borrow()).to_owned(); }
                #[cfg(not(target_os = "linux"))]
                { exit.state = "not supported on this platform".into(); }
                if !private_status.lease_valid { exit.state.push_str("; policy expired"); }
                else if exit_available == 0 && exit.state == "exit routing active" { exit.state = "blocked: no reachable exit".into(); }
            }
            let status=crate::runtime::Status{pid:std::process::id(),state:if device.is_some(){"running"}else{"connecting"}.into(),agent_version:crate::VERSION.into(),config_version:String::new(),service_count:count,route:"private".into(),updated_at:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),update_request_id:String::new(),private_status:Some(private_status.clone())};
            profile::write_private(&profile::sibling(&path,".status.json"),&serde_json::to_vec(&status)?,true)?;
            if crate::service::readable::refresh(&path,&status).is_err(){tracing::debug!("local registration display snapshot unavailable");}
        }
    }}Ok(())}.await;
    work.cancel();
    if tokio::time::timeout(Duration::from_secs(2), async {
        while !tasks.is_empty() {
            let _ = tasks.join_next().await;
        }
    })
    .await
    .is_err()
    {
        tasks.abort_all();
    }
    while tasks.join_next().await.is_some() {}
    for session in sessions.write().await.drain().map(|(_, session)| session) {
        session.close().await;
    }
    #[cfg(target_os = "linux")]
    if let Some(kernel) = &exit_kernel {
        if kernel.clear().await.is_err() { tracing::warn!("exit firewall cleanup pending; owned TUN removal disables forwarding"); }
    }
    drop(dns_registration);
    drop(device);
    if crate::service::readable::stopped(&path).is_err() {
        tracing::debug!("local registration display snapshot unavailable");
    }
    log_stream.stop().await;
    result
}
