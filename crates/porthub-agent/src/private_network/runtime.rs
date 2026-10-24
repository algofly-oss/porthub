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
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;
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
    let instance = controller::nonce()?;
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
    let mut registered_suffix = String::new();
    let mut policy = Engine::default();
    let mut paths = super::paths::Pinned::default();
    let mut by_ip = HashMap::new();
    let mut buffer = [0u8; porthub_mesh::MAX_PACKET + 1];
    let mut status_tick = tokio::time::interval(Duration::from_secs(30));
    status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
                    ensure!(own.hostname.split_once('.').is_some_and(|(_,suffix)|suffix==registered_suffix),"private DNS suffix changed; restart required");
                } else {
                    let tun=Arc::new(Tun::open(&name,own.ip,&routes).await?);
                    let server=dns::Server::bind(own.ip).await?;let port=server.port()?;
                    zone=Some(server.zone.clone()); tasks.spawn(server.serve(work.clone()));
                    // Resolver registration is tied only to this owned link.
                    let (_,suffix)=own.hostname.split_once('.').ok_or_else(||anyhow::anyhow!("private DNS suffix missing"))?;
                    dns::register(tun.index,own.ip,port,suffix).await?;registered_suffix=suffix.into();
                    device=Some(tun);
                }
                by_ip=snapshot.peers.iter().map(|p|(p.ip,p.id.clone())).collect();
                zone.as_ref().unwrap().write().await.update(&snapshot)?;
            },
            Some(Event::Packet{peer,bytes,direct})=>{
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
                let peers=sessions.read().await;
                let direct=peers.get(peer).filter(|session|session.state()==porthub_mesh::State::Ready);
                match paths.choose(parsed,direct.is_some(),relay_sender.is_ready()) {
                    Some(true)=>{if let Some(session)=direct {let _=session.send(bytes::Bytes::copy_from_slice(&buffer[..size]));}},
                    Some(false)=>{let _=relay_sender.send(peer,&buffer[..size]);},None=>{}
                }
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
    drop(device);
    result
}
