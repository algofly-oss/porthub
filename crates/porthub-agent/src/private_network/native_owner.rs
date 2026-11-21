//! Whole native ownership retirement. Prefix-only withdrawal leaves an external
//! connected socket's source address usable on a new LAN (native regression).
//! Quarantine is a denial record, never an authorization/route adoption record.
use anyhow::{ensure,Context,Result};
use porthub_mesh::lan_routes::Network;
use porthub_network::capture_routes::SparseAudit;
use serde::{Deserialize,Serialize};
use std::{collections::BTreeSet,net::Ipv4Addr,path::{Path,PathBuf},sync::Arc};
use super::device::Tun;
#[path="native_source.rs"]
pub(super) mod source;

const LIMIT:usize=65536;
const MAX_RETIRED:usize=1024;
#[derive(Debug)]pub(super) struct Conflict(pub SparseAudit);
impl std::fmt::Display for Conflict{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{f.write_str("native private ranges conflict with LAN/VPN/VM; entire source owner must retire")}}
impl std::error::Error for Conflict{}
pub(super) fn conflict(audit:SparseAudit)->Result<SparseAudit>{
    if audit.own_conflict||!audit.capture.conflicting.is_empty()||!audit.conflicting_peers.is_empty(){Err(Conflict(audit).into())}else{Ok(audit)}
}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]
struct Record{version:u8,binding:String,retired:BTreeSet<Ipv4Addr>,active:Option<Assignment>,#[serde(default)]repair:Option<porthub_network::native_repair::Request>,#[serde(default)]retirement:Option<Retirement>}
#[derive(Serialize,Deserialize)]#[serde(deny_unknown_fields)]
struct Assignment{own:Ipv4Addr,pools:Vec<Network>,#[serde(default)]pin:Option<source::Pin>}
#[derive(Clone,PartialEq,Eq,Serialize,Deserialize)]#[serde(deny_unknown_fields)]
struct Retirement{nonce:String,pin:source::Pin,state:RetirementState}
#[derive(Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
enum RetirementState{Pending,Completed}
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
    let record=if let Some(bytes)=bytes{ensure!(bytes.len()<=LIMIT,"native quarantine exceeds byte bound");serde_json::from_slice(&bytes)?}else{Record{version:1,binding:binding.clone(),retired:BTreeSet::new(),active:None,repair:None,retirement:None}};
    ensure!(record.version==1&&record.binding==binding&&record.retired.len()<=MAX_RETIRED&&record.retired.iter().all(Ipv4Addr::is_private),"native quarantine identity/limits changed; repair required");
    if let Some(repair)=&record.repair{repair.validate()?;ensure!(record.retired.contains(&repair.source),"native repair source lacks retirement proof");}
    if let Some(active)=&record.active{ensure!(active.own.is_private()&&!active.pools.is_empty()&&active.pools.len()<=porthub_network::capture_routes::MAX_CAPTURE_PREFIXES,"native active assignment invalid");}
    if let Some(active)=&record.active{if let Some(pin)=&active.pin{pin.validate()?;}}
    if let Some(retirement)=&record.retirement{retirement.pin.validate()?;ensure!(record.repair.as_ref().is_some_and(|request|request.nonce==retirement.nonce),"native retirement does not match repair generation");}
    Ok((path,record))
}
/// Read a display-only snapshot. Proving shutdown and publishing a request
/// belong to the owner and controller, never to a status read.
pub(super) fn repair_status(profile: &Path) -> Result<Option<crate::runtime::NativeRepairStatus>> {
    use crate::runtime::NativeRepairStatus;
    if !path(profile)?.try_exists()? {
        return Ok(None);
    }
    let (_, record) = read(profile)?;
    let Some((request, active)) = record.repair.as_ref().zip(record.active.as_ref()) else {
        return Ok(None);
    };
    if request.source != active.own {
        return Ok(None);
    }
    let status = match record.retirement.map(|r| r.state) {
        Some(RetirementState::Completed) => NativeRepairStatus::AwaitingNewAssignment,
        _ => NativeRepairStatus::AwaitingSourceShutdown,
    };
    Ok(Some(status))
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
        else{ensure!(record.repair.is_none()||record.retirement.as_ref().is_some_and(|r|r.state==RetirementState::Completed),"previous native source shutdown is not acknowledged");ensure!(record.retired.contains(&previous.own)||record.retired.len()<MAX_RETIRED,"native retired-source budget exhausted; safe repair required");record.retired.insert(previous.own);}
    }
    if record.active.as_ref().is_some_and(|active|active.own==own&&active.pools==pools){return Ok(());}
    let pin=record.active.as_ref().filter(|active|active.own==own).and_then(|active|active.pin.clone());
    record.active=Some(Assignment{own,pools:pools.to_vec(),pin});save(&path,&record)
}
fn quarantine(profile:&Path,own:Ipv4Addr)->Result<()>{quarantine_scope(profile,own,None)}
fn quarantine_scope(profile:&Path,own:Ipv4Addr,blocked:Option<Vec<Network>>)->Result<()>{
    let lock_path=path(profile)?;let _lease=crate::profile::Lease::acquire(&lock_path)?;
    let(path,mut record)=read(profile)?;
    ensure!(record.active.as_ref().is_some_and(|a|a.own==own),"cannot quarantine an unbound native source");
    ensure!(record.retired.contains(&own)||record.retired.len()<MAX_RETIRED,"native quarantine budget exhausted; source still must retire");
    record.retired.insert(own);
    if record.repair.as_ref().is_none_or(|request|request.source!=own)||blocked.is_some(){
        let blocked=blocked.unwrap_or_else(||record.active.as_ref().unwrap().pools.clone());
        let mut nonce=[0u8;16];getrandom::fill(&mut nonce)?;
        let repair=porthub_network::native_repair::Request{protocol:1,nonce:format!("{:032x}",u128::from_be_bytes(nonce)),source:own,blocked};repair.validate()?;record.repair=Some(repair);
    }
    let request=record.repair.as_ref().expect("repair created above");
    let pin=record.active.as_ref().and_then(|active|active.pin.clone()).unwrap_or(source::Pin::Unknown);
    record.retirement=Some(Retirement{nonce:request.nonce.clone(),pin,state:RetirementState::Pending});
    save(&path,&record)
}
fn conflict_scope(audit:&SparseAudit,pools:&[Network],own:Ipv4Addr)->Vec<Network>{
    pools.iter().copied().filter(|pool|audit.capture.conflicting.contains(pool)||(audit.own_conflict&&pool.contains(own))||audit.conflicting_peers.iter().any(|ip|pool.contains(*ip))).collect()
}
fn owner_path(profile:&Path)->Result<PathBuf>{
    #[cfg(windows)]{super::windows_state::state_path(profile,".native-source-owner")}
    #[cfg(not(windows))]{Ok(crate::profile::sibling(profile,".native-source-owner"))}
}
fn probe_absent(profile:&Path,pin:&source::Pin,own:Ipv4Addr)->Result<source::Pin>{
    #[cfg(windows)]{super::device::recover_source_absence(profile,pin,own)}
    #[cfg(not(windows))]{let _=profile;source::verify_absent(pin,own)}
}
// Caller holds the exclusive live-owner lease BEFORE taking the journal lease.
// Every publication, including a completed record after restart, gets a fresh
// OS probe. Pending records confer no authority by their serialized shape.
fn repair_under_owner(profile:&Path,probe:impl FnOnce(&source::Pin,Ipv4Addr)->Result<source::Pin>)->Result<Option<porthub_network::native_repair::Request>>{
    repair_under_owner_with(profile,probe,save)
}
fn repair_under_owner_with(profile:&Path,probe:impl FnOnce(&source::Pin,Ipv4Addr)->Result<source::Pin>,persist:impl Fn(&Path,&Record)->Result<()>)->Result<Option<porthub_network::native_repair::Request>>{
    let state=path(profile)?;let _journal=crate::profile::Lease::acquire(&state)?;
    let(path,mut record)=read(profile)?;
    let Some(request)=record.repair.clone()else{return Ok(None)};
    let pin=record.retirement.as_ref().map(|r|r.pin.clone()).or_else(||record.active.as_ref().and_then(|a|a.pin.clone())).unwrap_or(source::Pin::Unknown);
    let proof=match probe(&pin,request.source){Ok(pin)=>pin,Err(error)=>{
        let pending=Retirement{nonce:request.nonce.clone(),pin,state:RetirementState::Pending};
        if record.retirement.as_ref()!=Some(&pending){record.retirement=Some(pending);persist(&path,&record)?;}
        return Err(error.context("native source shutdown remains unproven; repair not published"));
    }};
    proof.validate()?;
    let completed=Retirement{nonce:request.nonce.clone(),pin:proof,state:RetirementState::Completed};
    if record.retirement.as_ref()!=Some(&completed){record.retirement=Some(completed);persist(&path,&record)?;}
    Ok(Some(request))
}
/// Feedback is published only after acknowledged native retirement. The live
/// owner lease prevents a controller read from racing quarantine-before-close.
pub(super) fn repair_request(profile:&Path)->Result<Option<porthub_network::native_repair::Request>>{
    repair_request_with(profile,|pin,own|probe_absent(profile,pin,own))
}
fn repair_request_with(profile:&Path,probe:impl FnOnce(&source::Pin,Ipv4Addr)->Result<source::Pin>)->Result<Option<porthub_network::native_repair::Request>>{
    if !path(profile)?.try_exists()?{return Ok(None);}
    let owner=owner_path(profile)?;
    if crate::profile::Lease::running(&owner)?{return Ok(None);}
    let _owner=match crate::profile::Lease::acquire(&owner){Ok(lease)=>lease,Err(error)=>{if crate::profile::Lease::running(&owner)?{return Ok(None);}return Err(error)}};
    let request=repair_under_owner(profile,probe)?;
    // The gateway already assigned a new source, but native construction may
    // have failed before its final pin checkpoint. Keep the old ACK locally for
    // safe rebind; never poison normal sync with a now-stale source report.
    let active=read(profile)?.1.active.map(|active|active.own);
    Ok(request.filter(|request|active==Some(request.source)))
}
fn bind_pin(profile:&Path,own:Ipv4Addr,pin:source::Pin)->Result<()>{
    pin.validate()?;let state=path(profile)?;let _lease=crate::profile::Lease::acquire(&state)?;let(path,mut record)=read(profile)?;
    let active=record.active.as_mut().context("native source intent absent")?;ensure!(active.own==own,"source changed before native pin checkpoint");active.pin=Some(pin);
    if record.repair.as_ref().is_some_and(|request|request.source!=own){record.repair=None;record.retirement=None;}
    save(&path,&record)
}
/// Caller still holds the live-owner lease across fresh old-source proof,
/// durable new-source intent and native open. No standalone bool grants rebind.
pub(super) fn allow_source_rebind(profile:&Path,old:Ipv4Addr,new:Ipv4Addr,guid:&str)->Result<()> {source_rebind_intent(profile,old,new,guid,true)}
/// Read-only recovery of an already-checkpointed new adapter assignment still
/// requires a fresh OS absence probe before a Pending acknowledgement can heal.
pub(super) fn inspect_rebound_source(profile:&Path,old:Ipv4Addr,new:Ipv4Addr,guid:&str)->Result<()> {source_rebind_intent(profile,old,new,guid,false)}
fn source_rebind_intent(profile:&Path,old:Ipv4Addr,new:Ipv4Addr,guid:&str,require_completed:bool)->Result<()> {
    let(_,record)=read(profile)?;
    ensure!(old!=new&&record.retired.contains(&old)&&!record.retired.contains(&new)&&record.active.as_ref().is_some_and(|active|active.own==new),"source rebind is not the pending safe assignment");
    let request=record.repair.as_ref().context("source rebind lacks retained retirement generation")?;
    let retirement=record.retirement.as_ref().context("source rebind lacks native shutdown acknowledgement")?;
    ensure!(request.source==old&&retirement.nonce==request.nonce&&(!require_completed||retirement.state==RetirementState::Completed),"source rebind shutdown generation is stale or pending");
    ensure!(matches!(&retirement.pin,source::Pin::Windows{guid:owned,..} if owned==guid),"source rebind changed protected adapter GUID");
    Ok(())
}
fn retire(device:&mut Option<Arc<Tun>>,profile:&Path)->Result<()>{
    let owner=device.take().context("native owner disappeared")?;
    source::release_owner(owner,|owner|{
        #[cfg(windows)]{owner.stop_source_checked()}
        #[cfg(not(windows))]{let _=owner;Ok(())}
    })?;
    if read(profile)?.1.repair.is_some(){ensure!(repair_request(profile)?.is_some(),"native retirement completion is still owned by another verifier");}
    Ok(())
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
/// Server-side migration may arrive while the agent was stopped normally:
/// there is no local collision request yet, but a persistent Windows adapter
/// still carries its old protected record. Create and prove that retirement
/// generation BEFORE replacing active intent or configuring the new source.
fn stage_offline_retirement(profile:&Path,next:Ipv4Addr)->Result<bool>{
    let previous=read(profile)?.1.active.map(|active|active.own);
    if let Some(previous)=previous.filter(|previous|*previous!=next){quarantine(profile,previous)?;return Ok(true);}
    Ok(false)
}
#[cfg(test)]
pub(super) async fn open(profile:&Path,name:&str,own:Ipv4Addr,pools:&[Network],peers:&[Ipv4Addr])->Result<Arc<Tun>>{
    Ok(open_with_dns(profile,name,own,pools,peers, #[cfg(target_os = "linux")] None).await?.0)
}

#[cfg(target_os = "linux")]
fn retained(profile: &Path, own: Ipv4Addr, local: Option<super::linux_handoff::Stored>) -> Result<Option<(super::device::RetainedLink, std::fs::File, super::dns::Server)>> {
    use std::os::unix::fs::FileExt;
    let Some(stored) = local.or_else(super::linux_handoff::take) else { return Ok(None); };
    let checked = (move || {
        let (_,record) = read(profile)?;
        ensure!(record.repair.is_none() && !record.retired.contains(&own), "previous private owner requires retirement");
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};
        let metadata = stored.state.metadata()?;
        let fd = stored.state.as_raw_fd();
        ensure!(metadata.is_file() && metadata.nlink()==0 && metadata.uid()==rustix::process::geteuid().as_raw()
            && unsafe {libc::fcntl(fd,libc::F_GET_SEALS)} >= 0
            && std::fs::read_link(format!("/proc/self/fd/{fd}"))?.as_os_str()=="/memfd:porthub-private-routes (deleted)",
            "invalid private route checkpoint object");
        let length = metadata.len();
        ensure!(length > 8 && length <= 1024 * 1024 + 8, "invalid previous route checkpoint size");
        let mut size=[0u8;8];
        stored.state.read_exact_at(&mut size,0)?;
        ensure!(u64::from_le_bytes(size)==length-8,"incomplete previous route checkpoint");
        let mut data=vec![0u8;length as usize-8];
        stored.state.read_exact_at(&mut data,8)?;
        let link = super::device::RetainedLink::import(stored.anchor,&data)?;
        ensure!(link.matches(&record.binding,record.active.as_ref().filter(|a|a.own==own).and_then(|a|a.pin.as_ref()),own), "previous private assignment no longer matches");
        let dns = super::dns::Server::from_retained(own,stored.udp,stored.tcp)?;
        Ok::<_,anyhow::Error>((link,stored.state,dns))
    })();
    match checked {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            super::linux_handoff::clear()?;
            tracing::debug!(%error,"discarded old private service handles");
            Ok(None)
        }
    }
}

pub(super) async fn open_with_dns(
    profile: &Path, name: &str, own: Ipv4Addr, pools: &[Network], peers: &[Ipv4Addr],
    #[cfg(target_os = "linux")] local: Option<super::linux_handoff::Stored>,
) -> Result<(Arc<Tun>, Option<super::dns::Server>)> {
    let _owner=crate::profile::Lease::acquire(&owner_path(profile)?)?;
    #[cfg(target_os="linux")]
    let local_handles=local.is_some();
    #[cfg(target_os = "linux")]
    let mut inherited = retained(profile, own, local)?;
    if read(profile)?.1.repair.is_some(){repair_under_owner(profile,|pin,own|probe_absent(profile,pin,own))?;}
    if stage_offline_retirement(profile,own)?{repair_under_owner(profile,|pin,own|probe_absent(profile,pin,own))?;}
    if let Err(error) = prepare(profile,own,pools) {
        #[cfg(target_os = "linux")]
        if inherited.take().is_some() { super::linux_handoff::clear()?; }
        return Err(error);
    }
    if read(profile)?.1.active.as_ref().and_then(|active|active.pin.as_ref()).is_none(){
        let state=path(profile)?;let _journal=crate::profile::Lease::acquire(&state)?;let(path,mut record)=read(profile)?;
        record.active.as_mut().context("source intent missing")?.pin=Some(source::Pin::Intent{name:name.into()});save(&path,&record)?;
    }
    #[cfg(windows)]let result=Tun::open_owned_sparse(profile,name,own,peers,pools).await;
    #[cfg(target_os="macos")]let result=async{Tun::preflight_sparse(own,pools,peers).await?;Tun::open(name,own,peers).await}.await;
    #[cfg(not(target_os="linux"))]let dns=None;
    #[cfg(target_os="linux")]
    let mut dns = None;
    #[cfg(target_os="linux")]
    let result = async {
        let binding = binding(profile)?;
        if let Some((link,journal,server)) = inherited {
            match Tun::restore(link,name,own,pools,peers).await {
                Ok(mut tun) => {
                    if !local_handles { tun.mark_restored(); }
                    tun.journal_routes(&binding, Some(journal)).await?;
                    dns = Some(server);
                    return Ok(tun);
                }
                Err(error) => {
                    super::linux_handoff::clear()?;
                    tracing::debug!(%error,"rebuilding changed private link");
                }
            }
        }
        Tun::preflight_sparse(own,pools,peers).await?;
        if !cfg!(feature="private-sparse") && !super::linux_handoff::available() { return Tun::open(name,own,peers).await; }
        let restartable = async {
            let mut tun = Tun::create(name,own,peers,true).await?;
            tun.journal_routes(&binding,None).await?;
            Ok::<_,anyhow::Error>(tun)
        }.await;
        match restartable {
            Ok(tun) => Ok(tun),
            Err(error) => {
                tracing::debug!(%error,"using exclusive private TUN after restart support was unavailable");
                Tun::preflight_sparse(own,pools,peers).await?;
                Tun::open(name,own,peers).await
            }
        }
    }.await;
    match result{Ok(tun)=>{bind_pin(profile,own,tun.source_pin())?;tun.bind_source_lease(_owner)?;Ok((Arc::new(tun),dns))},Err(error)=>{
        if let Some(conflict)=error.downcast_ref::<Conflict>(){quarantine_scope(profile,own,Some(conflict_scope(&conflict.0,pools,own))).context("unsafe native source must remain quarantined")?;}
        Err(error)
    }}
}
pub(super) enum Outcome{Active(SparseAudit),Retired(SparseAudit)}
/// Production owner helper, also used by the actual warmed-UDP native fixture.
/// Backends signal Conflict BEFORE deleting any individual source routes.
pub(super) async fn reconcile(device:&mut Option<Arc<Tun>>,profile:&Path,own:Ipv4Addr,pools:&[Network],peers:&[Ipv4Addr])->Result<Outcome>{
    {
        let tun=device.as_ref().context("native owner absent")?;
        if !tun.has_source_lease()? {
            tun.bind_source_lease(crate::profile::Lease::acquire(&owner_path(profile)?)?)?;
            // Legacy-to-sparse handover: the previous device had no capture
            // pools; establish its exact source intent before any quarantine.
            if read(profile)?.1.active.is_none(){prepare(profile,tun.own_ip(),&[Network::from_address(tun.own_ip(),32)?])?;}
            bind_pin(profile,tun.own_ip(),tun.source_pin())?;
        }
    }
    if device.as_ref().context("native owner absent")?.own_ip()!=own{
        let previous=device.as_ref().unwrap().own_ip();
        let persisted=quarantine(profile,previous);let stopped=retire(device,profile);
        stopped?;persisted?;prepare(profile,own,pools)?;
        anyhow::bail!("native source allocation changed; old address retired before reopening");
    }
    if let Err(error)=prepare(profile,own,pools){
        let persisted=quarantine(profile,own);retire(device,profile)?;
        return Err(error.context(if persisted.is_ok(){"native source quarantined after unsafe assignment change"}else{"native owner retired; quarantine needs repair"}));
    }
    let result={let tun=device.as_ref().context("native owner absent")?;tokio::time::timeout(std::time::Duration::from_secs(2),tun.reconcile_sparse(pools,peers)).await.map_err(|_|anyhow::anyhow!("native route audit timed out")).and_then(|result|result)};
    match result{
        Ok(audit)=>Ok(Outcome::Active(audit)),
        Err(error)=>{
            let typed=error.downcast::<Conflict>();
            let persisted=if let Ok(conflict)=&typed{quarantine_scope(profile,own,Some(conflict_scope(&conflict.0,pools,own)))}else{Ok(())};
            retire(device,profile)?;
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
        assert!(prepare(&path,"10.204.0.2".parse()?,&["10.204.0.0/24".parse()?]).is_err());
        repair_under_owner(&path,|pin,_|Ok(pin.clone()))?; // injected OS absence, not native proof
        prepare(&path,"10.204.0.2".parse()?,&["10.204.0.0/24".parse()?])?;
        assert!(prepare(&path,own,&pools).is_err());assert!(read(&path)?.1.retired.contains(&own));Ok(())
    }
    #[test]
    fn status_observes_only_the_current_quarantine_without_advancing_it() -> Result<()> {
        use crate::runtime::NativeRepairStatus::*;
        let (_root, path) = profile()?;
        let own = "10.203.0.2".parse()?;
        let pools = ["10.203.0.0/24".parse()?];
        assert_eq!(repair_status(&path)?, None);
        prepare(&path, own, &pools)?;
        assert_eq!(repair_status(&path)?, None);
        quarantine(&path, own)?;
        let journal = super::path(&path)?;
        let pending = std::fs::read(&journal)?;
        assert_eq!(repair_status(&path)?, Some(AwaitingSourceShutdown));
        assert_eq!(std::fs::read(&journal)?, pending);
        repair_under_owner(&path, |pin, _| Ok(pin.clone()))?;
        assert_eq!(repair_status(&path)?, Some(AwaitingNewAssignment));
        prepare(&path, "10.204.0.2".parse()?, &["10.204.0.0/24".parse()?])?;
        assert_eq!(repair_status(&path)?, None);
        Ok(())
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
    #[test]
    fn pending_close_cannot_publish_while_live_owner_holds_lease()->Result<()> {
        let(_root,path)=profile()?;let own="10.203.0.2".parse()?;prepare(&path,own,&["10.203.0.0/24".parse()?])?;
        bind_pin(&path,own,source::Pin::Intent{name:"ph-fixture".into()})?;
        let owner=crate::profile::Lease::acquire(&owner_path(&path)?)?;
        quarantine(&path,own)?;
        let (_,pending)=read(&path)?;assert!(matches!(pending.retirement.unwrap().state,RetirementState::Pending));
        assert!(repair_request(&path)?.is_none(),"controller raced durable quarantine before OS close");
        drop(owner);
        let nonce=read(&path)?.1.repair.unwrap().nonce;
        assert!(repair_under_owner(&path,|_,_|anyhow::bail!("native source remains")).is_err());
        let repair=repair_under_owner(&path,|pin,_|Ok(pin.clone()))?.unwrap();
        assert_eq!(repair.nonce,nonce);assert!(matches!(read(&path)?.1.retirement.unwrap().state,RetirementState::Completed));
        Ok(())
    }
    #[test]
    fn completed_restart_requires_fresh_probe_and_failed_proof_returns_to_pending()->Result<()> {
        let(_root,path)=profile()?;let own="10.203.0.2".parse()?;prepare(&path,own,&["10.203.0.0/24".parse()?])?;quarantine(&path,own)?;
        let first=repair_under_owner(&path,|pin,_|Ok(pin.clone()))?.unwrap();
        // Read the actual serialized completion anew, as a restarted controller.
        assert!(matches!(read(&path)?.1.retirement.unwrap().state,RetirementState::Completed));
        let probes=std::cell::Cell::new(0);
        assert!(repair_under_owner(&path,|_,_|{probes.set(probes.get()+1);anyhow::bail!("source reappeared")}).is_err());
        assert_eq!(probes.get(),1);assert!(matches!(read(&path)?.1.retirement.unwrap().state,RetirementState::Pending));
        let recovered=repair_under_owner(&path,|pin,_|Ok(pin.clone()))?.unwrap();assert_eq!(recovered.nonce,first.nonce);
        Ok(())
    }
    #[test]
    fn completion_persistence_failure_cannot_publish_and_retry_preserves_original_nonce()->Result<()> {
        let(_root,path)=profile()?;let own="10.203.0.2".parse()?;prepare(&path,own,&["10.203.0.0/24".parse()?])?;quarantine(&path,own)?;
        let before=std::fs::read(super::path(&path)?)?;
        assert!(repair_under_owner_with(&path,|pin,_|Ok(pin.clone()),|_,_|anyhow::bail!("injected fsync failure")).is_err());
        assert_eq!(std::fs::read(super::path(&path)?)?,before);
        assert!(matches!(read(&path)?.1.retirement.unwrap().state,RetirementState::Pending));
        let nonce=read(&path)?.1.repair.unwrap().nonce;
        assert_eq!(repair_under_owner(&path,|pin,_|Ok(pin.clone()))?.unwrap().nonce,nonce);
        Ok(())
    }
    #[test]
    fn scope_expansion_preserves_observed_pin_until_conflict_retirement()->Result<()> {
        let(_root,path)=profile()?;let own="10.203.0.2".parse()?;prepare(&path,own,&["10.203.0.0/24".parse()?])?;
        let pin=source::Pin::Interface{name:"ph-fixture".into(),index:22};bind_pin(&path,own,pin.clone())?;
        prepare(&path,own,&["10.203.0.0/23".parse()?])?;
        assert_eq!(read(&path)?.1.active.unwrap().pin,Some(pin.clone()));
        quarantine(&path,own)?;assert_eq!(read(&path)?.1.retirement.unwrap().pin,pin);Ok(())
    }

    #[test]
    fn source_rebind_requires_matching_completed_nonce_and_preserves_old_denial()->Result<()> {
        let(_root,path)=profile()?;let old="10.203.0.2".parse()?;let new="10.204.0.2".parse()?;prepare(&path,old,&["10.203.0.0/24".parse()?])?;
        let pin=source::Pin::Windows{name:"owned".into(),index:2,guid:"a".repeat(32),luid:3};bind_pin(&path,old,pin)?;quarantine(&path,old)?;
        assert!(prepare(&path,new,&["10.204.0.0/24".parse()?]).is_err());
        repair_under_owner(&path,|pin,_|Ok(pin.clone()))?;prepare(&path,new,&["10.204.0.0/24".parse()?])?;
        allow_source_rebind(&path,old,new,&"a".repeat(32))?;
        assert!(allow_source_rebind(&path,old,new,&"b".repeat(32)).is_err());
        let(state,mut record)=read(&path)?;record.retirement.as_mut().unwrap().state=RetirementState::Pending;save(&state,&record)?;
        assert!(allow_source_rebind(&path,old,new,&"a".repeat(32)).is_err());
        // Recovery can inspect an existing new-record assignment, but Pending
        // still cannot authorize another native source assignment.
        inspect_rebound_source(&path,old,new,&"a".repeat(32))?;
        record.retirement.as_mut().unwrap().nonce="f".repeat(32);save(&state,&record)?;
        assert!(allow_source_rebind(&path,old,new,&"a".repeat(32)).is_err());
        record.retirement.as_mut().unwrap().nonce=record.repair.as_ref().unwrap().nonce.clone();record.retirement.as_mut().unwrap().state=RetirementState::Completed;save(&state,&record)?;
        bind_pin(&path,new,source::Pin::Windows{name:"owned".into(),index:2,guid:"a".repeat(32),luid:3})?;
        let record=read(&path)?.1;assert!(record.retired.contains(&old));assert!(record.repair.is_none());
        fixture_assignment_ready(&path,old,new)?;assert!(fixture_assignment_ready(&path,old,old).is_err());Ok(())
    }

    #[test]
    fn offline_server_renumber_stages_old_source_before_replacing_active_intent()->Result<()> {
        let(_root,path)=profile()?;let old="10.203.0.2".parse()?;let new="10.204.0.2".parse()?;
        prepare(&path,old,&["10.203.0.0/24".parse()?])?;
        let pin=source::Pin::Windows{name:"owned".into(),index:2,guid:"a".repeat(32),luid:3};bind_pin(&path,old,pin)?;
        assert!(read(&path)?.1.repair.is_none(),"ordinary stopped owner had no collision request");
        assert!(stage_offline_retirement(&path,new)?);
        let before=read(&path)?.1;assert_eq!(before.active.unwrap().own,old);assert!(matches!(before.retirement.unwrap().state,RetirementState::Pending));
        assert!(prepare(&path,new,&["10.204.0.0/24".parse()?]).is_err());
        repair_under_owner(&path,|pin,_|Ok(pin.clone()))?;
        prepare(&path,new,&["10.204.0.0/24".parse()?])?;
        allow_source_rebind(&path,old,new,&"a".repeat(32))?;
        assert!(read(&path)?.1.retired.contains(&old));Ok(())
    }

    #[test]
    fn failed_new_constructor_retains_local_ack_without_uploading_stale_source()->Result<()> {
        let(_root,path)=profile()?;let old="10.203.0.2".parse()?;let new="10.204.0.2".parse()?;
        prepare(&path,old,&["10.203.0.0/24".parse()?])?;
        bind_pin(&path,old,source::Pin::Windows{name:"owned".into(),index:2,guid:"a".repeat(32),luid:3})?;
        stage_offline_retirement(&path,new)?;repair_under_owner(&path,|pin,_|Ok(pin.clone()))?;
        prepare(&path,new,&["10.204.0.0/24".parse()?])?;
        let probes=std::cell::Cell::new(0);
        assert!(repair_request_with(&path,|pin,_|{probes.set(probes.get()+1);Ok(pin.clone())})?.is_none());
        assert_eq!(probes.get(),1,"local ACK still needs restart absence proof");
        allow_source_rebind(&path,old,new,&"a".repeat(32))?;
        assert!(read(&path)?.1.repair.is_some(),"failed constructor must retain old local rebind generation");Ok(())
    }

}

/// Native fixture checks the actual protected assignment after successful bind,
/// independently of repair_request's intentional live-owner publication veto.
#[cfg(test)]
pub(super) fn fixture_assignment_ready(profile:&Path,old:Ipv4Addr,new:Ipv4Addr)->Result<()> {
    let(_,record)=read(profile)?;
    ensure!(record.active.as_ref().is_some_and(|active|active.own==new&&active.pin.is_some())&&record.retired.contains(&old)&&record.repair.is_none()&&record.retirement.is_none(),"fresh native assignment did not retire old feedback generation");Ok(())
}

// Fixture-only failure metadata: never serialize arbitrary error Display text.
#[cfg(test)]
pub(super) fn fixture_failure_chain(error:&anyhow::Error)->serde_json::Value {
    use sha2::{Digest,Sha256};
    const GUARDS:&[&str]=&[
        "native source shutdown remains unproven; repair not published",
        "stopped adapter GUID changed; preserved",
        "stopped adapter lacks verified baseline",
        "stopped adapter contains a source or foreign address; preserved",
        "stopped adapter contains an unowned or retired route; preserved",
        "stopped adapter has a live unacknowledged intent; preserved",
        "owned adapter changed externally",
        "adapter changed during final source-absence proof",
        "retired route remains after deletion",
        "recovered compound remains",
        "recovered shared child disappeared",
    ];
    let causes:Vec<_>=error.chain().take(8).map(|cause|{
        let message=cause.to_string();
        serde_json::json!({"guard":GUARDS.iter().copied().find(|guard|*guard==message),
            "message_sha256":format!("{:x}",Sha256::digest(message.as_bytes())),
            "message_bytes":message.len(),
            "os_error":cause.downcast_ref::<std::io::Error>().and_then(|error|error.raw_os_error())})
    }).collect();
    serde_json::json!({"causes":causes,"truncated":error.chain().count()>8})
}
#[cfg(test)]
mod fixture_failure_chain_tests {
    #[test]
    fn bounded_chain_preserves_guard_and_errno_without_dynamic_text() {
        let error=anyhow::Error::from(std::io::Error::from_raw_os_error(1168))
            .context("credential-like-sentinel/private/profile")
            .context("native source shutdown remains unproven; repair not published");
        let value=super::fixture_failure_chain(&error);
        assert_eq!(value["causes"].as_array().unwrap().len(),3);
        assert_eq!(value["causes"][0]["guard"],"native source shutdown remains unproven; repair not published");
        assert_eq!(value["causes"][2]["os_error"],1168);
        let output=value.to_string();assert!(!output.contains("credential-like-sentinel"));assert!(!output.contains("private/profile"));
        let mut error=anyhow::anyhow!("unapproved dynamic sentinel");
        for _ in 0..10 {error=error.context("context");}
        let value=super::fixture_failure_chain(&error);
        assert_eq!(value["causes"].as_array().unwrap().len(),8);assert_eq!(value["truncated"],true);
    }
}

#[cfg(test)]
pub(super) fn fixture_retry_socket_setup<T>(mut setup: impl FnMut() -> Result<T>) -> Result<T> {
    for attempt in 0..32 {
        match setup() {
            Ok(value) => return Ok(value),
            Err(error) => {
                let transient = error.chain()
                    .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .is_some_and(|error| matches!(error.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied));
                if !transient || attempt == 31 { return Err(error); }
            }
        }
    }
    unreachable!("bounded setup returns on final attempt")
}

#[cfg(test)]
mod fixture_socket_setup_tests {
    use anyhow::Result;
    use super::fixture_retry_socket_setup as retry_setup;
    #[test]
    fn fixture_setup_retries_only_bounded_address_conflicts() {
        for kind in [std::io::ErrorKind::AddrInUse, std::io::ErrorKind::PermissionDenied] {
            let mut attempts = 0;
            let result: Result<()> = retry_setup(|| {
                attempts += 1;
                Err(anyhow::Error::from(std::io::Error::from(kind)).context("fixed setup stage"))
            });
            assert!(result.is_err());
            assert_eq!(attempts, 32);
        }
        let mut attempts = 0;
        let result: Result<()> = retry_setup(|| {
            attempts += 1;
            Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into())
        });
        assert!(result.is_err());
        assert_eq!(attempts, 1);
        let mut attempts = 0;
        assert_eq!(retry_setup(|| {
            attempts += 1;
            if attempts < 3 { Err(std::io::Error::from(std::io::ErrorKind::AddrInUse).into()) }
            else { Ok(7) }
        }).unwrap(), 7);
        assert_eq!(attempts, 3);
    }
}
