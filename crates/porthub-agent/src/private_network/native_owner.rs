//! Whole native ownership retirement. Prefix-only withdrawal leaves an external
//! connected socket's source address usable on a new LAN (native regression).
//! Quarantine is a denial record, never an authorization/route adoption record.
use anyhow::{ensure,Context,Result};
use porthub_mesh::lan_routes::Network;
use porthub_network::capture_routes::SparseAudit;
use serde::{Deserialize,Serialize};
use std::{collections::BTreeSet,net::Ipv4Addr,path::{Path,PathBuf},sync::Arc};
use super::device::Tun;
const LIMIT:usize=65536;
const MAX_RETIRED:usize=1024;
#[derive(Debug)]pub(super) struct Conflict(pub SparseAudit);
impl std::fmt::Display for Conflict{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("native private ranges conflict with LAN/VPN/VM; entire source owner must retire")}}
impl std::error::Error for Conflict{}
pub(super) fn conflict(audit:SparseAudit)->Result<SparseAudit>{
    if audit.own_conflict||!audit.capture.conflicting.is_empty()||!audit.conflicting_peers.is_empty(){Err(Conflict(audit).into())}else{Ok(audit)}
}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]
struct Record{version:u8,binding:String,retired:BTreeSet<Ipv4Addr>,active:Option<Assignment>,#[serde(default)]repair:Option<porthub_network::native_repair::Request>}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]
struct Assignment{own:Ipv4Addr,pools:Vec<Network>}
fn binding(profile:&Path)->Result<String>{
    use sha2::{Digest,Sha256};
    let bytes=crate::profile::read_private(profile)?;let value:serde_json::Value=serde_json::from_slice(&bytes)?;
    let mut digest=Sha256::new();digest.update(b"porthub-native-source-quarantine-v1\0");
    digest.update(profile.canonicalize()?.as_os_str().as_encoded_bytes());
    for key in ["server","workspace","peer_id"]{let field=value.get(key).and_then(|v|v.as_str()).filter(|s|!s.is_empty()&&s.len()<=4096).context("native quarantine profile identity missing")?;digest.update((field.len()as u64).to_be_bytes());digest.update(field.as_bytes());}
    Ok(format!("{:x}",digest.finalize()))
}
fn path(profile:&Path)->Result<PathBuf>{
    #[cfg(windows)]{super::windows_state::state_path(profile,".native-quarantine.json")}
    #[cfg(not(windows))]{Ok(crate::profile::sibling(profile,".native-quarantine.json"))}
}
fn read(profile:&Path)->Result<(PathBuf,Record)>{
    let path=path(profile)?;let binding=binding(profile)?;
    #[cfg(windows)]let bytes=super::windows_state::read_bytes_bounded(&path,LIMIT)?;
    #[cfg(not(windows))]let bytes=match crate::profile::read_private(&path){Ok(bytes)=>Some(bytes),Err(_error) if !path.try_exists()?=>None,Err(error)=>return Err(error)};
    let record=if let Some(bytes)=bytes{ensure!(bytes.len()<=LIMIT,"native quarantine exceeds byte bound");serde_json::from_slice(&bytes)?}else{Record{version:1,binding:binding.clone(),retired:BTreeSet::new(),active:None,repair:None}};
    ensure!(record.version==1&&record.binding==binding&&record.retired.len()<=MAX_RETIRED&&record.retired.iter().all(Ipv4Addr::is_private),"native quarantine identity/limits changed; repair required");
    if let Some(repair)=&record.repair{repair.validate()?;ensure!(record.retired.contains(&repair.source),"native repair source lacks retirement proof");}
    if let Some(active)=&record.active{ensure!(active.own.is_private()&&!active.pools.is_empty()&&active.pools.len()<=porthub_network::capture_routes::MAX_CAPTURE_PREFIXES,"native active assignment invalid");}
    Ok((path,record))
}
fn save(path:&Path,record:&Record)->Result<()>{
    let bytes=serde_json::to_vec(record)?;ensure!(bytes.len()<=LIMIT,"native source history requires safe repair; refusing truncation");
    #[cfg(windows)]{super::windows_state::write_bytes_bounded(path,&bytes,LIMIT)}
    #[cfg(not(windows))]{crate::profile::write_private(path,&bytes,true)}
}
fn covered(old:&Network,new:&[Network])->bool{new.iter().any(|new|new.prefix()<=old.prefix()&&new.contains(old.address()))}
/// Persist the active capture scope BEFORE assigning a source address. Scope
/// expansion is allowed, but shrinking/changing it under the same source IP is
/// not: old external sockets must not acquire a new LAN route on a fresh sync.
pub(super) fn prepare(profile:&Path,own:Ipv4Addr,pools:&[Network])->Result<()>{
    ensure!(own.is_private()&&!pools.is_empty()&&pools.len()<=porthub_network::capture_routes::MAX_CAPTURE_PREFIXES,"invalid native assignment");
    let lock_path=path(profile)?;let _lease=crate::profile::Lease::acquire(&lock_path)?;
    let(path,mut record)=read(profile)?;
    ensure!(!record.retired.contains(&own),"native source address quarantined; a safe new private address allocation is required");
    if let Some(previous)=&record.active{
        if previous.own==own{ensure!(previous.pools.iter().all(|pool|covered(pool,pools)),"native capture retirement requires a new source allocation; old sockets may remain bound");}
        else{ensure!(record.retired.contains(&previous.own)||record.retired.len()<MAX_RETIRED,"native retired-source budget exhausted; safe repair required");record.retired.insert(previous.own);}
    }
    if record.active.as_ref().is_some_and(|active|active.own==own&&active.pools==pools){return Ok(());}
    record.active=Some(Assignment{own,pools:pools.to_vec()});record.repair=None;save(&path,&record)
}
fn quarantine(profile:&Path,own:Ipv4Addr)->Result<()>{quarantine_scope(profile,own,None)}
fn quarantine_scope(profile:&Path,own:Ipv4Addr,blocked:Option<Vec<Network>>)->Result<()>{
    let lock_path=path(profile)?;let _lease=crate::profile::Lease::acquire(&lock_path)?;
    let(path,mut record)=read(profile)?;
    ensure!(record.active.as_ref().is_some_and(|a|a.own==own),"cannot quarantine an unbound native source");
    ensure!(record.retired.contains(&own)||record.retired.len()<MAX_RETIRED,"native quarantine budget exhausted; source still must retire");
    record.retired.insert(own);
    if record.repair.is_none()||blocked.is_some(){
        let blocked=blocked.unwrap_or_else(||record.active.as_ref().unwrap().pools.clone());
        let mut nonce=[0u8;16];getrandom::fill(&mut nonce)?;
        let repair=porthub_network::native_repair::Request{protocol:1,nonce:format!("{:032x}",u128::from_be_bytes(nonce)),source:own,blocked};repair.validate()?;record.repair=Some(repair);
    }
    save(&path,&record)
}
fn conflict_scope(audit:&SparseAudit,pools:&[Network],own:Ipv4Addr)->Vec<Network>{
    pools.iter().copied().filter(|pool|audit.capture.conflicting.contains(pool)||(audit.own_conflict&&pool.contains(own))||audit.conflicting_peers.iter().any(|ip|pool.contains(*ip))).collect()
}
/// Read-only protected repair feedback. The server must independently bind this
/// to its fresh enrolled source assignment; the report never chooses an IP.
pub(super) fn repair_request(profile:&Path)->Result<Option<porthub_network::native_repair::Request>>{
    if !path(profile)?.try_exists()?{return Ok(None);}
    let(_,record)=read(profile)?;Ok(record.repair)
}
fn retire(device:&mut Option<Arc<Tun>>)->Result<()>{
    let owner=device.take().context("native owner disappeared")?;
    // Runtime owns the only strong reference; advertised readiness is Weak.
    let weak=Arc::downgrade(&owner);drop(owner);
    ensure!(weak.upgrade().is_none(),"native owner still pinned; closure not proven");Ok(())
}
/// Existing legacy profiles have no record and keep their prior contract. A
/// profile that already used sparse native capture cannot silently downgrade
/// and resurrect its old bound source after a quarantine/mode change.
pub(super) fn admit_legacy(profile:&Path,own:Ipv4Addr)->Result<()>{
    let state=path(profile)?;if !state.try_exists()?{return Ok(());}
    let _lease=crate::profile::Lease::acquire(&state)?;let(path,mut record)=read(profile)?;
    ensure!(!record.retired.contains(&own),"legacy mode cannot resurrect a quarantined native source; update/allocation required");
    if let Some(previous)=record.active.take(){
        ensure!(previous.own!=own,"sparse-to-legacy native downgrade needs a new safe source allocation");
        ensure!(record.retired.contains(&previous.own)||record.retired.len()<MAX_RETIRED,"native retired-source budget exhausted");record.retired.insert(previous.own);save(&path,&record)?;
    }Ok(())
}
pub(super) async fn open(profile:&Path,name:&str,own:Ipv4Addr,pools:&[Network],peers:&[Ipv4Addr])->Result<Arc<Tun>>{
    prepare(profile,own,pools)?;
    #[cfg(windows)]let result=Tun::open_owned_sparse(profile,name,own,peers,pools).await;
    #[cfg(not(windows))]let result=async{Tun::preflight_sparse(own,pools,peers).await?;Tun::open(name,own,peers).await}.await;
    match result{Ok(tun)=>Ok(Arc::new(tun)),Err(error)=>{
        if let Some(conflict)=error.downcast_ref::<Conflict>(){quarantine_scope(profile,own,Some(conflict_scope(&conflict.0,pools,own))).context("unsafe native source must remain quarantined")?;}
        Err(error)
    }}
}
pub(super) enum Outcome{Active(SparseAudit),Retired(SparseAudit)}
/// Production owner helper, also used by the actual warmed-UDP native fixture.
/// Backends signal Conflict BEFORE deleting any individual source routes.
pub(super) async fn reconcile(device:&mut Option<Arc<Tun>>,profile:&Path,own:Ipv4Addr,pools:&[Network],peers:&[Ipv4Addr])->Result<Outcome>{
    if device.as_ref().context("native owner absent")?.own_ip()!=own{
        let prepared=prepare(profile,own,pools);retire(device)?;prepared?;
        anyhow::bail!("native source allocation changed; old address retired before reopening");
    }
    if let Err(error)=prepare(profile,own,pools){
        let persisted=quarantine(profile,own);retire(device)?;
        return Err(error.context(if persisted.is_ok(){"native source quarantined after unsafe assignment change"}else{"native owner retired; quarantine needs repair"}));
    }
    let result={let tun=device.as_ref().context("native owner absent")?;tokio::time::timeout(std::time::Duration::from_secs(2),tun.reconcile_sparse(pools,peers)).await.map_err(|_|anyhow::anyhow!("native route audit timed out")).and_then(|result|result)};
    match result{
        Ok(audit)=>Ok(Outcome::Active(audit)),
        Err(error)=>{
            let typed=error.downcast::<Conflict>();
            let persisted=if let Ok(conflict)=&typed{quarantine_scope(profile,own,Some(conflict_scope(&conflict.0,pools,own)))}else{Ok(())};
            retire(device)?;
            persisted.context("native source retired but durable quarantine needs repair")?;
            match typed{Ok(conflict)=>Ok(Outcome::Retired(conflict.0)),Err(error)=>Err(error)}
        }
    }
}

#[cfg(all(test,not(windows)))]
mod tests {
    use super::*;
    fn profile()->Result<(tempfile::TempDir,PathBuf)>{
        use std::os::unix::fs::PermissionsExt;
        let root=tempfile::Builder::new().permissions(std::fs::Permissions::from_mode(0o700)).tempdir()?;let path=root.path().join("profile.json");
        crate::profile::write_private(&path,br#"{"server":"https://fixture.invalid","workspace":"workspace","peer_id":"peer","token":"fixture"}"#,false)?;Ok((root,path))
    }
    #[test]
    fn persisted_quarantine_rejects_same_source_across_fresh_calls_and_legacy_downgrade()->Result<()> {
        let(_root,path)=profile()?;let own="10.203.0.2".parse()?;let pools=["10.203.0.0/24".parse()?];
        prepare(&path,own,&pools)?;quarantine(&path,own)?;
        assert!(prepare(&path,own,&pools).is_err());assert!(admit_legacy(&path,own).is_err());
        prepare(&path,"10.204.0.2".parse()?,&["10.204.0.0/24".parse()?])?;
        assert!(prepare(&path,own,&pools).is_err());assert!(read(&path)?.1.retired.contains(&own));Ok(())
    }
    #[test]
    fn expansion_preserves_source_but_scope_retirement_needs_new_source()->Result<()> {
        let(_root,path)=profile()?;let own="10.203.0.2".parse()?;prepare(&path,own,&["10.203.0.0/24".parse()?])?;
        prepare(&path,own,&["10.203.0.0/23".parse()?,"10.204.0.0/24".parse()?])?;
        let before=std::fs::read(super::path(&path)?)?;
        assert!(prepare(&path,own,&["10.204.0.0/24".parse()?]).is_err());assert_eq!(std::fs::read(super::path(&path)?)?,before);
        prepare(&path,"10.204.0.2".parse()?,&["10.204.0.0/24".parse()?])?;assert!(read(&path)?.1.retired.contains(&own));Ok(())
    }
    #[test]
    fn malformed_foreign_and_overflow_history_fail_without_reset_or_truncation()->Result<()> {
        let(_root,path)=profile()?;let own="10.203.0.2".parse()?;let pools=["10.203.0.0/24".parse()?];prepare(&path,own,&pools)?;
        let(state,mut record)=read(&path)?;record.retired=(1..=MAX_RETIRED as u32).map(|n|Ipv4Addr::from(u32::from(Ipv4Addr::new(10,250,0,0))+n)).collect();save(&state,&record)?;
        let before=std::fs::read(&state)?;assert!(prepare(&path,"10.204.0.2".parse()?,&pools).is_err());assert_eq!(std::fs::read(&state)?,before);
        record.binding="f".repeat(64);save(&state,&record)?;assert!(prepare(&path,own,&pools).is_err());assert_eq!(read(&path).err().is_some(),true);Ok(())
    }
    #[test]
    fn denied_concurrent_writer_preserves_actual_private_journal()->Result<()> {
        let(_root,path)=profile()?;let pools=["10.203.0.0/24".parse()?];let own="10.203.0.2".parse()?;prepare(&path,own,&pools)?;
        let state=super::path(&path)?;let before=std::fs::read(&state)?;let held=crate::profile::Lease::acquire(&state)?;
        assert!(quarantine(&path,own).is_err());assert_eq!(std::fs::read(&state)?,before);drop(held);quarantine(&path,own)?;assert!(prepare(&path,own,&pools).is_err());Ok(())
    }
    #[test]
    fn legacy_without_sparse_history_remains_unchanged()->Result<()> {
        let(_root,path)=profile()?;admit_legacy(&path,"10.203.0.2".parse()?)?;assert!(!super::path(&path)?.exists());Ok(())
    }
}
