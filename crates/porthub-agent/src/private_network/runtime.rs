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
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

fn mark_activity(activity: &mut HashMap<String, Instant>, peer: &str, now: Instant) {
    if let Some(last) = activity.get_mut(peer) {
        *last = now;
    } else if activity.len() < 4096 {
        activity.insert(peer.to_owned(), now);
    }
}

pub async fn run(path: PathBuf, cancel: CancellationToken) -> Result<()> {
    let profile = Profile::load(&path)?;
    let _lease = Lease::acquire(&path)?;
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
    let mut next_probe_id = u64::from_str_radix(&instance[..16], 16)?;
    let (interface_updates, interfaces) = tokio::sync::watch::channel(Vec::new());
    tasks.spawn(super::interfaces::watch(interface_updates, work.clone()));
    let (relay_sender, relay_input) = super::relay::channel();
    tasks.spawn(super::relay::run(
        profile.clone(),
        instance.clone(),
        relay_sender.clone(),
        relay_input,
        events.clone(),
        work.clone(),
    ));
    tasks.spawn(controller::run_watched_instance(
        profile.clone(),
        interfaces,
        sessions.clone(),
        events,
        instance,
        work.clone(),
    ));
    let mut device: Option<Arc<Tun>> = None;
    let mut zone = None;
    let mut dns_registration: Option<dns::Registration> = None;
    let mut registered_suffixes: Vec<String> = Vec::new();
    let mut dns_port: Option<u16> = None;
    let mut policy = Engine::default();
    let mut paths = super::paths::Pinned::default();
    let mut path_quality = super::probe::Quality::default();
    let mut by_ip = HashMap::new();
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
                policy.apply(snapshot.clone())?;
                if let Some(tun)=&device {
                    tun.update_routes(&routes).await?;
                } else {
                    let tun=Arc::new(Tun::open(&name,own.ip,&routes).await?);
                    let server=dns::Server::bind(own.ip).await?;let port=server.port()?;
                    zone=Some(server.zone.clone()); tasks.spawn(server.serve(work.clone()));
                    dns_port=Some(port);
                    device=Some(tun);
                }
                // Register every advertised private DNS suffix on the owned
                // tunnel resolver. This also applies suffix changes live.
                let mut suffixes=snapshot.dns_suffixes.iter().map(|suffix|suffix.trim_matches('.').to_ascii_lowercase()).filter(|suffix|!suffix.is_empty()).collect::<Vec<_>>();
                if let Some((_,suffix))=own.hostname.split_once('.') { suffixes.push(suffix.trim_matches('.').to_ascii_lowercase()); }
                suffixes.sort();suffixes.dedup();
                if registered_suffixes!=suffixes {
                    let tun=device.as_ref().expect("private tunnel initialized");
                    let port=dns_port.ok_or_else(||anyhow::anyhow!("private DNS listener missing"))?;
                    dns_registration=None;
                    dns_registration=Some(dns::register(tun.index,own.ip,port,&suffixes).await?);
                    registered_suffixes=suffixes;
                }
                by_ip=snapshot.peers.iter().map(|p|(p.ip,p.id.clone())).collect();
                zone.as_ref().unwrap().write().await.update(&snapshot)?;
            },
            Some(Event::Packet{peer,bytes,direct,received_at})=>{
                let now=received_at;
                if let Some(replies)=path_quality.handle(&peer,direct,&bytes,now) {
                    if !replies.is_empty() {
                        if direct {
                            if let Some(session)=sessions.read().await.get(&peer) {
                                for reply in replies { let _=session.send(reply); }
                            }
                        } else {
                            for reply in replies { let _=relay_sender.send(&peer,&reply); }
                        }
                    }
                    continue;
                }
                mark_activity(&mut last_activity,&peer,now);
                if policy.check(&bytes,&peer,true) {
                    if let Some(packet)=Packet::parse(&bytes) {paths.observe(packet,direct);}
                    if let Some(tun)=&device {tun.write(&bytes).await?;}
                }
            },None=>anyhow::bail!("private control owner stopped"),
        },
        packet=async {match &device {Some(device)=>device.read(&mut buffer).await,None=>std::future::pending().await}}=>{
            let size=packet?;if size>porthub_mesh::MAX_PACKET {continue;}
            let Some(parsed)=Packet::parse(&buffer[..size]) else {continue;};
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
                match paths.choose_preferred(parsed,direct.is_some(),relay_ready,prefer_peer) {
                    Some(true)=>{if let Some(session)=direct {let _=session.send(bytes::Bytes::copy_from_slice(&buffer[..size]));}},
                    Some(false)=>{let _=relay_sender.send(peer,&buffer[..size]);},None=>{}
                }
            }
        },
        _=probe_tick.tick(),if device.is_some()=>{
            let now=std::time::Instant::now();
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
                            let sent=if direct { session.send(packet) } else { relay_sender.send(peer,&packet) };
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
            let peers=sessions.read().await;
            let count=peers.values().filter(|peer|peer.state()==porthub_mesh::State::Ready).count();
            let status=crate::runtime::Status{pid:std::process::id(),state:if device.is_some(){"running"}else{"connecting"}.into(),agent_version:crate::VERSION.into(),config_version:String::new(),service_count:count,route:"private".into(),updated_at:SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),update_request_id:String::new()};
            profile::write_private(&profile::sibling(&path,".status.json"),&serde_json::to_vec(&status)?,true)?;
        }
    }}Ok(())}.await;
    work.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    for session in sessions.write().await.drain().map(|(_, session)| session) {
        session.close().await;
    }
    drop(dns_registration);
    drop(device);
    result
}
