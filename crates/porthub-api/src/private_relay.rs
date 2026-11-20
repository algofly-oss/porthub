//! Private gateway fallback on the existing authenticated API port. Leases are
//! published only after private sync's final credential and membership check.
use crate::{
    domain::workspaces::token_digest,
    error::{ApiError, ApiResult},
    App,
};
use axum::body::Bytes;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{HeaderMap, HeaderValue, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
#[cfg(test)]
use porthub_mesh::RELAY_BATCH_MAGIC;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
const MAX_CONTROL_WORKSPACES:usize=16384;
const MAX_RELAY_LANES: u8 = 4;
const MAX_RELAY_PEERS: usize = 4096;
const MAX_RELAY_CONNECTIONS: usize = MAX_RELAY_PEERS * MAX_RELAY_LANES as usize;
#[derive(Clone)]
struct Lease {
    credential_hash: String,
    identity_generation:u64,
    origin: Option<Arc<porthub_mesh::relay_origin::Origin>>,
    hash: String,
    relay_token: String,
    instance: String,
    ip: Ipv4Addr,
    allowed: HashSet<String>,
    expires: Instant,
    sparse_epoch: Option<String>,
    exit_epoch: Option<String>,
    workspace: Option<(String,u64)>,
}
pub(crate) struct PairPeerPin {pub id:String,pub hash:String,pub instance:String,pub ip:Ipv4Addr,pub epoch:Option<String>,pub origin_stamp:Option<String>,pub generation:Option<u64>}
#[derive(Clone)]
struct PairAuthority {
    generation:u64,
    owner_generation:u64,
    left: String, right: String,
    left_hash: String, right_hash: String,
    left_instance: String, right_instance: String,
    left_ip: Ipv4Addr, right_ip: Ipv4Addr,
    left_epoch: Option<String>, right_epoch: Option<String>,
    expires: Instant,
}
struct Connection {
    instance: String,
    generation: u64,
    output: mpsc::Sender<QueuedPacket>,
}
#[derive(Clone, PartialEq, Eq)]
struct ForwardReceipt {
    source:String,target:String,source_hash:String,target_hash:String,
    source_instance:String,target_instance:String,source_generation:u64,target_generation:u64,exit:bool,owner:Option<u64>,expires:Instant,
}
impl ForwardReceipt {
    fn valid(&self,hub:&Inner,now:Instant)->bool {
        if self.expires<=now || !hub.allowed_scope(&self.source,&self.target,now,self.exit){return false;}
        let (Some(a),Some(b))=(hub.leases.get(&self.source),hub.leases.get(&self.target))else{return false;};
        if a.credential_hash!=self.source_hash||b.credential_hash!=self.target_hash||a.instance!=self.source_instance||b.instance!=self.target_instance||a.identity_generation!=self.source_generation||b.identity_generation!=self.target_generation{return false;}
        let key = PairLookup::new(&self.source, &self.target);
        self.owner.is_none_or(|owner|(if self.exit{&hub.exit_pairs}else{&hub.pairs}).get(&key).is_some_and(|p|p.owner_generation==owner))
    }
}
fn measurement_frame(bytes:&[u8])->bool {
    bytes.len()==1200 && bytes.get(..8)==Some(b"PHUBQOS1") && bytes[8]<=1 && bytes[9]==0 && bytes[11]==32 && bytes[10]<32
        && ((bytes[8]==0&&bytes[20..24]==[0;4])||(bytes[8]==1&&bytes[20..24]!=[0;4]))
}
struct Forward<'a> {
    packet: &'a [u8],
    output: mpsc::Sender<QueuedPacket>,
    generation: u64,
    expires: Instant,
    receipt: ForwardReceipt,
    origin: Option<Arc<porthub_mesh::relay_origin::Origin>>,
}
impl Forward<'_> {
    fn enqueue(self, source: &str, permit: mpsc::OwnedPermit<QueuedPacket>, budget: OwnedSemaphorePermit) {
        let mut bytes = Vec::with_capacity(1 + source.len() + self.packet.len());
        bytes.push(source.len() as u8);
        bytes.extend_from_slice(source.as_bytes());
        bytes.extend_from_slice(self.packet);
        permit.send(QueuedPacket { bytes, origin: self.origin, receipt: Some(self.receipt), _budget: budget });
    }
}
struct Admission { hash:String, instance:String, generation:u64, expires:Instant, workspace:Option<(String,u64)> }
type PairTable = hashbrown::HashMap<(String, String), PairAuthority, std::collections::hash_map::RandomState>;

// Hash the same two strings, in the same order, as the owned tuple on insertion.
#[derive(Hash)]
struct PairLookup<'a>(&'a str, &'a str);

impl<'a> PairLookup<'a> {
    fn new(a: &'a str, b: &'a str) -> Self {
        if a <= b { Self(a, b) } else { Self(b, a) }
    }
}

impl hashbrown::Equivalent<(String, String)> for PairLookup<'_> {
    fn equivalent(&self, key: &(String, String)) -> bool {
        self.0 == key.0 && self.1 == key.1
    }
}

#[derive(Default)]
struct Inner {
    leases: HashMap<String, Lease>,
    revoked: HashMap<String, Instant>,
    revoked_cleanup_at: Option<Instant>,
    connections: HashMap<String, HashMap<u8, Connection>>,
    pairs: PairTable,
    exit_pairs: PairTable,
    generation: u64,
    admissions: HashMap<String, Admission>,
    workspace_generations: HashMap<String, (u64, bool)>,
    workspace_cleanup_at:Option<Instant>,
    admission_generation: u64,
    lease_generation:u64,
    pair_generation:u64,
    admission_cleanup_at: Option<Instant>,
    dropped_packets: AtomicU64,
}
struct QueuedPacket {
    bytes: Vec<u8>,
    origin: Option<Arc<porthub_mesh::relay_origin::Origin>>,
    receipt: Option<ForwardReceipt>,
    // Released on dequeue/drop, including connection teardown and cancellation.
    _budget: OwnedSemaphorePermit,
}
impl std::ops::Deref for QueuedPacket {
    type Target = [u8];
    fn deref(&self) -> &[u8] { &self.bytes }
}
pub struct Hub(Mutex<Inner>, Arc<Semaphore>);
impl Default for Hub {
    fn default() -> Self {
        Self(Mutex::new(Inner::default()), Arc::new(Semaphore::new(MAX_RELAY_QUEUE_BUDGET)))
    }
}
impl Inner {
    fn prune_workspace_generations(&mut self,now:Instant) {
        if self.workspace_cleanup_at.is_some_and(|next|next>now){return;}
        // Only expired tickets/leases are removed. Any live authority pins its
        // workspace generation. A future real request must reread the durable
        // head before rebinding an evicted idle workspace; absent maps admit none.
        self.admissions.retain(|_,a|a.expires>now);
        self.leases.retain(|_,l|l.expires>now);
        let live:HashSet<String>=self.admissions.values().filter_map(|a|a.workspace.as_ref().map(|(w,_)|w.clone()))
            .chain(self.leases.values().filter_map(|l|l.workspace.as_ref().map(|(w,_)|w.clone()))).collect();
        self.workspace_generations.retain(|w,_|live.contains(w));
        self.workspace_cleanup_at=Some(now+Duration::from_secs(5));
    }
    fn allowed_pair(&self, source:&str, target:&str, now:Instant)->bool {self.allowed_scope(source,target,now,false)}
    fn allowed_scope(&self, source:&str, target:&str, now:Instant,exit:bool)->bool {
        let (Some(a),Some(b))=(self.leases.get(source),self.leases.get(target)) else{return false;};
        if a.expires<=now || b.expires<=now {return false;}
        if a.sparse_epoch.is_none() && b.sparse_epoch.is_none() {return a.allowed.contains(target)&&b.allowed.contains(source);}
        let key = PairLookup::new(source, target);
        let Some(pair)=(if exit{&self.exit_pairs}else{&self.pairs}).get(&key).filter(|p|p.expires>now) else{return false;};
        let (Some(left),Some(right))=(self.leases.get(&pair.left),self.leases.get(&pair.right)) else{return false;};
        left.credential_hash==pair.left_hash && right.credential_hash==pair.right_hash
            && left.instance==pair.left_instance && right.instance==pair.right_instance
            && left.ip==pair.left_ip && right.ip==pair.right_ip
            && (if exit{&left.exit_epoch}else{&left.sparse_epoch})==&pair.left_epoch && (if exit{&right.exit_epoch}else{&right.sparse_epoch})==&pair.right_epoch
            && (left.sparse_epoch.is_some()||left.allowed.contains(&pair.right))
            && (right.sparse_epoch.is_some()||right.allowed.contains(&pair.left))
    }
}
impl Hub {
    pub(crate) fn block_workspace(&self,workspace:&str) {
        let generation=self.0.lock().unwrap_or_else(|p|p.into_inner()).workspace_generations.get(workspace).map(|(g,_)|*g).unwrap_or(0);
        self.workspace_generation(workspace,generation,true);
    }
    /// Apply a freshly read durable workspace head. Generation advance or a
    /// migration fence retires ALL old tickets/leases/connections under that
    /// exact authenticated workspace binding; late publications fail closed.
    pub(crate) fn workspace_generation(&self, workspace:&str, generation:u64, blocked:bool)->bool {
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());
        let old=hub.workspace_generations.get(workspace).copied();
        if old.is_some_and(|(g,_)|generation<g) {return false;}
        if old.is_none()&&hub.workspace_generations.len()>=MAX_CONTROL_WORKSPACES {
            hub.prune_workspace_generations(Instant::now());
            if hub.workspace_generations.len()>=MAX_CONTROL_WORKSPACES{return false;}
        }
        if old==Some((generation,blocked)){return !blocked;}
        let retired:HashSet<String>=hub.admissions.iter().filter(|(_,a)|a.workspace.as_ref().is_some_and(|(w,_)|w==workspace)).map(|(id,_)|id.clone())
            .chain(hub.leases.iter().filter(|(_,l)|l.workspace.as_ref().is_some_and(|(w,_)|w==workspace)).map(|(id,_)|id.clone())).collect();
        hub.admissions.retain(|id,_|!retired.contains(id));
        hub.leases.retain(|id,_|!retired.contains(id));
        hub.connections.retain(|id,_|!retired.contains(id));
        hub.pairs.retain(|_,pair|!retired.contains(&pair.left)&&!retired.contains(&pair.right));
        hub.exit_pairs.retain(|_,pair|!retired.contains(&pair.left)&&!retired.contains(&pair.right));
        hub.workspace_generations.insert(workspace.into(),(generation,blocked));
        !blocked
    }
    /// A bounded authenticated control-read ticket. A denial/identity replacement invalidates
    /// earlier in-flight reads without quarantining later newly authorized requests.
    pub(crate) fn begin_admission(&self,id:&str,hash:&str,instance:&str)->Option<u64>{self.begin_admission_bound(id,hash,instance,None)}
    pub(crate) fn begin_workspace_admission(&self,id:&str,hash:&str,instance:&str,workspace:&str)->Option<u64>{self.begin_admission_bound(id,hash,instance,Some(workspace))}
    fn begin_admission_bound(&self,id:&str,hash:&str,instance:&str,workspace:Option<&str>)->Option<u64>{
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        let workspace=match workspace {
            Some(w)=>Some((w.to_owned(),hub.workspace_generations.get(w).filter(|(_,blocked)|!*blocked)?.0)),
            None=>None,
        };
        if hub.admission_cleanup_at.is_none_or(|at|at<=now){
            hub.admissions.retain(|_,a|a.expires>now);hub.admission_cleanup_at=Some(now+Duration::from_secs(60));
        }
        if hub.admissions.len()>=16384&&!hub.admissions.contains_key(id){return None;}
        hub.admission_generation=hub.admission_generation.checked_add(1)?;
        let generation=hub.admission_generation;
        hub.admissions.insert(id.into(),Admission{hash:hash.into(),instance:instance.into(),generation,expires:now+Duration::from_secs(60),workspace});
        Some(generation)
    }
    pub(crate) fn admission_snapshot(&self,id:&str,hash:&str,instance:&str)->Option<u64>{
        let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());
        hub.admissions.get(id).filter(|a|a.hash==hash&&a.instance==instance&&a.expires>Instant::now()).map(|a|a.generation)
    }
    pub(crate) fn withdraw_bound(&self,id:&str,hash:&str,instance:&str,generation:u64)->bool{
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());
        let matches=hub.admissions.get(id).is_some_and(|a|a.hash==hash&&a.instance==instance&&generation==a.generation);
        if !matches{return false;}
        hub.admissions.remove(id);
        // A newer successful incarnation is never removed by an older failed request.
        if hub.leases.get(id).is_some_and(|l|l.credential_hash==hash&&l.instance==instance){
            hub.leases.remove(id);hub.connections.remove(id);hub.pairs.retain(|_,p|p.left!=id&&p.right!=id);
            hub.exit_pairs.retain(|_,p|p.left!=id&&p.right!=id);
        }
        true
    }
    /// Reversible peer toggle / credential rotation: retire exact current
    /// authority without the account-deletion quarantine. New freshly checked
    /// credentials can enroll immediately; old request tickets stay invalid.
    pub(crate) fn retire_identities(&self,ids:&[String]) {
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());
        for id in ids {hub.admissions.remove(id);hub.leases.remove(id);hub.connections.remove(id);hub.pairs.retain(|_,p|p.left!=*id&&p.right!=*id);hub.exit_pairs.retain(|_,p|p.left!=*id&&p.right!=*id);}
    }
    pub fn revoke(&self, ids: &[String]) {
        let mut hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now=Instant::now();
        if hub.revoked_cleanup_at.is_none() { hub.revoked_cleanup_at=Some(now+Duration::from_secs(60)); }
        for id in ids {
            hub.admissions.remove(id);
            hub.leases.remove(id); hub.connections.remove(id);
            hub.pairs.retain(|_, pair| pair.left != *id && pair.right != *id);
            hub.exit_pairs.retain(|_, pair| pair.left != *id && pair.right != *id);
            // Fence sync responses already in flight when the account retired.
            hub.revoked.insert(id.clone(), Instant::now()+Duration::from_secs(60));
        }
    }
    pub fn publish(
        &self,
        id: &str,
        hash: &str,
        instance: &str,
        ip: Ipv4Addr,
        allowed: HashSet<String>,
    ) -> String {
        self.publish_admitted(id,hash,instance,ip,allowed,None)
    }
    pub(crate) fn publish_admitted(&self,id:&str,hash:&str,instance:&str,ip:Ipv4Addr,allowed:HashSet<String>,admission:Option<u64>)->String {
        let mut hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if admission.is_some_and(|g|!hub.admissions.get(id).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==g&&a.expires>now)){return String::new();}
        if hub.revoked_cleanup_at.is_some_and(|next|next<=now) {
            hub.revoked.retain(|_, expires| *expires > now);
            hub.revoked_cleanup_at=(!hub.revoked.is_empty()).then_some(now+Duration::from_secs(60));
        }
        if hub.revoked.get(id).is_some_and(|expires|*expires>now) { return String::new(); }
        hub.leases.retain(|_, lease| lease.expires > now);
        if hub.leases.len() >= 16384 && !hub.leases.contains_key(id) {
            return String::new();
        }
        let relay_token = hub
            .leases
            .get(id)
            .filter(|lease| {
                lease.expires > now && lease.credential_hash == hash && lease.instance == instance
            })
            .map(|lease| lease.relay_token.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
        let workspace=admission.and_then(|_|hub.admissions.get(id).and_then(|a|a.workspace.clone()));
        let old=hub.leases.get(id);
        let old_origin=old.and_then(|lease|lease.origin.clone());
        let stable=old.filter(|l|l.credential_hash==hash&&l.instance==instance&&l.ip==ip&&l.sparse_epoch.is_none()&&l.allowed==allowed).map(|l|l.identity_generation);
        let identity_generation=match stable{Some(value)=>value,None=>{let Some(value)=hub.lease_generation.checked_add(1)else{return String::new();};hub.lease_generation=value;value}};
        let origin=old_origin.filter(|_|stable.is_some());
        hub.leases.insert(
            id.into(),
            Lease {
                credential_hash: hash.into(),
                origin,
                identity_generation,
                hash: token_digest(&relay_token),
                relay_token: relay_token.clone(),
                instance: instance.into(),
                ip,
                allowed,
                expires: now + Duration::from_secs(15),
                sparse_epoch: None,
                exit_epoch: None,
                workspace,
            },
        );
        relay_token
    }
    /// Sparse callers publish a base identity, not a whole-account authorization list.
    /// No relay connection slot is allocated until an actual caller opens a transport.
    pub(crate) fn publish_sparse(&self, id:&str, hash:&str, instance:&str, ip:Ipv4Addr, epoch:&str)->String {
        self.publish_sparse_admitted(id,hash,instance,ip,epoch,None)
    }
    pub(crate) fn publish_sparse_admitted(&self,id:&str,hash:&str,instance:&str,ip:Ipv4Addr,epoch:&str,admission:Option<u64>)->String {
        self.publish_sparse_scoped(id,hash,instance,ip,epoch,None,admission)
    }
    pub(crate) fn publish_sparse_exit_admitted(&self,id:&str,hash:&str,instance:&str,ip:Ipv4Addr,epoch:&str,exit_epoch:&str,admission:Option<u64>)->String {
        self.publish_sparse_scoped(id,hash,instance,ip,epoch,Some(exit_epoch),admission)
    }
    fn publish_sparse_scoped(&self,id:&str,hash:&str,instance:&str,ip:Ipv4Addr,epoch:&str,exit_epoch:Option<&str>,admission:Option<u64>)->String {
        let valid=|v:&str|v.len()==64&&v.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase());
        if !valid(epoch)||exit_epoch.is_some_and(|e|!valid(e)){return String::new();}
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if admission.is_some_and(|g|!hub.admissions.get(id).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==g&&a.expires>now)){return String::new();}
        if hub.revoked.get(id).is_some_and(|expires|*expires>now) {return String::new();}
        hub.leases.retain(|_,lease|lease.expires>now);hub.pairs.retain(|_,p|p.expires>now);
        hub.exit_pairs.retain(|_,p|p.expires>now);
        if hub.leases.len()>=16384 && !hub.leases.contains_key(id) {return String::new();}
        let old=hub.leases.get(id);
        let unchanged=old.is_some_and(|l|l.credential_hash==hash&&l.instance==instance&&l.ip==ip&&l.sparse_epoch.as_deref()==Some(epoch));
        let exit_unchanged=old.is_some_and(|l|l.credential_hash==hash&&l.instance==instance&&l.ip==ip&&l.exit_epoch.as_deref()==exit_epoch);
        let token=old.filter(|l|l.credential_hash==hash&&l.instance==instance).map(|l|l.relay_token.clone()).unwrap_or_else(||uuid::Uuid::new_v4().simple().to_string());
        let old_origin=old.and_then(|lease|lease.origin.clone());
        let stable=old.filter(|l|l.credential_hash==hash&&l.instance==instance&&l.ip==ip&&l.sparse_epoch.is_some()).map(|l|l.identity_generation);
        let identity_generation=match stable{Some(value)=>value,None=>{let Some(value)=hub.lease_generation.checked_add(1)else{return String::new();};hub.lease_generation=value;value}};
        if !unchanged {hub.pairs.retain(|_,p|p.left!=id&&p.right!=id);}
        if !exit_unchanged {hub.exit_pairs.retain(|_,p|p.left!=id&&p.right!=id);}
        let workspace=admission.and_then(|_|hub.admissions.get(id).and_then(|a|a.workspace.clone()));
        let origin=old_origin.filter(|_|stable.is_some());
        hub.leases.insert(id.into(),Lease{origin,workspace,credential_hash:hash.into(),identity_generation,hash:token_digest(&token),relay_token:token.clone(),instance:instance.into(),ip,allowed:HashSet::new(),expires:now+Duration::from_secs(15),sparse_epoch:Some(epoch.into()),exit_epoch:exit_epoch.map(str::to_owned)});
        token
    }
    /// Called from the authenticated sync's fresh source projection, never from
    /// relay frames. Cache one immutable identity per server lease incarnation.
    pub(crate) fn bind_origin(&self, peer: porthub_network::policy::PeerInfo, hash:&str, admission:u64) -> bool {
        let mut origin=porthub_mesh::relay_origin::Origin{peer:peer.id,ip:peer.ip,fingerprint:peer.fingerprint,instance:peer.instance,stamp:"0".repeat(32)};
        // Validate before any retirement and before entering the packet path.
        if origin.validate().is_err(){return false;}
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if !hub.admissions.get(&origin.peer).is_some_and(|a|a.hash==hash&&a.instance==origin.instance&&a.generation==admission&&a.expires>now){return false;}
        let Some(lease)=hub.leases.get(&origin.peer) else{return false;};
        if lease.expires<=now||lease.credential_hash!=hash || lease.instance!=origin.instance || lease.ip!=origin.ip{return false;}
        if lease.origin.as_ref().is_some_and(|old|old.fingerprint==origin.fingerprint){return true;}
        let replacing=lease.origin.is_some();
        if replacing {
            let Some(next)=hub.lease_generation.checked_add(1) else{return false;};hub.lease_generation=next;
            hub.pairs.retain(|_,p|p.left!=origin.peer&&p.right!=origin.peer);
            hub.exit_pairs.retain(|_,p|p.left!=origin.peer&&p.right!=origin.peer);
            hub.leases.get_mut(&origin.peer).unwrap().identity_generation=next;
        }
        origin.stamp=uuid::Uuid::new_v4().simple().to_string();let id=origin.peer.clone();
        hub.leases.get_mut(&id).unwrap().origin=Some(Arc::new(origin));
        true
    }
    pub(crate) fn project_origin(&self,peer:&mut porthub_network::policy::PeerInfo,hash:&str) {
        peer.relay_origin=None;
        let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());
        if let Some(lease)=hub.leases.get(&peer.id).filter(|l|l.expires>Instant::now()&&l.credential_hash==hash&&l.instance==peer.instance&&l.ip==peer.ip){
            if let Some(origin)=lease.origin.as_ref().filter(|origin|origin.fingerprint==peer.fingerprint){peer.relay_origin=Some(origin.stamp.clone());}
        }
    }
    /// Called only after an authenticated API pair lookup has compiled a nonempty exact ACL.
    /// Coarse relay eligibility is reciprocal; the endpoint engines still enforce packet ACLs.
    pub(crate) fn publish_pair(&self,source:&str,target:&str,epoch:&str)->bool{self.publish_pair_epochs(source,target,epoch,epoch)}
    pub(crate) fn publish_pair_epochs(&self, source:&str, target:&str, epoch:&str,target_epoch:&str)->bool {
        self.publish_pair_checked(source,target,epoch,target_epoch,None,false)
    }
    pub(crate) fn publish_pair_admitted(&self,source:&str,epoch:&str,hash:&str,instance:&str,generation:u64,target:&PairPeerPin)->bool{
        self.publish_pair_checked(source,&target.id,epoch,target.epoch.as_deref().unwrap_or_default(),Some((hash,instance,generation,target)),false)
    }
    pub(crate) fn publish_exit_pair_admitted(&self,source:&str,epoch:&str,hash:&str,instance:&str,generation:u64,target:&PairPeerPin)->bool{
        self.publish_pair_checked(source,&target.id,epoch,target.epoch.as_deref().unwrap_or_default(),Some((hash,instance,generation,target)),true)
    }
    fn publish_pair_checked(&self,source:&str,target:&str,epoch:&str,target_epoch:&str,request:Option<(&str,&str,u64,&PairPeerPin)>,exit:bool)->bool{
        if source==target {return false;}
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        hub.pairs.retain(|_,p|p.expires>now);
        hub.exit_pairs.retain(|_,p|p.expires>now);
        let (Some(a),Some(b))=(hub.leases.get(source),hub.leases.get(target)) else{return false;};
        if request.is_some_and(|(hash,instance,generation,pin)|a.credential_hash!=hash||a.instance!=instance||b.credential_hash!=pin.hash||b.instance!=pin.instance||b.ip!=pin.ip||!hub.admissions.get(source).is_some_and(|r|r.hash==hash&&r.instance==instance&&r.generation==generation&&r.expires>now)){return false;}
        if request.is_some_and(|(_,_,_,pin)| a.origin.is_some() && pin.origin_stamp.as_deref()!=b.origin.as_ref().map(|origin|origin.stamp.as_str())){return false;}
        if a.expires<=now || b.expires<=now || (if exit{a.exit_epoch.as_deref()}else{a.sparse_epoch.as_deref()})!=Some(epoch)
            || (if exit{b.exit_epoch.as_deref()}else{b.sparse_epoch.as_deref()}).is_some_and(|e|e!=target_epoch)
            || (exit&&b.exit_epoch.is_none())
            || (!exit&&b.sparse_epoch.is_none() && !b.allowed.contains(source)) {return false;}
        let key=if source<target {(source.to_owned(),target.to_owned())}else{(target.to_owned(),source.to_owned())};
        let selected=if exit{&hub.exit_pairs}else{&hub.pairs};
        if !selected.contains_key(&key) && (hub.pairs.len()+hub.exit_pairs.len()>=8192 || hub.pairs.values().chain(hub.exit_pairs.values()).filter(|p|p.left==source||p.right==source).count()>=256 || hub.pairs.values().chain(hub.exit_pairs.values()).filter(|p|p.left==target||p.right==target).count()>=256) {return false;}
        let Some(generation)=hub.pair_generation.checked_add(1)else{return false;};
        let previous=selected.get(&key);
        let owner_generation=previous.filter(|p|{
            let (l,r,le,re)=if p.left==source{(a,b,Some(epoch),if exit{b.exit_epoch.as_deref()}else{b.sparse_epoch.as_deref()})}else{(b,a,if exit{b.exit_epoch.as_deref()}else{b.sparse_epoch.as_deref()},Some(epoch))};
            p.left_hash==l.credential_hash&&p.right_hash==r.credential_hash&&p.left_instance==l.instance&&p.right_instance==r.instance&&p.left_ip==l.ip&&p.right_ip==r.ip&&p.left_epoch.as_deref()==le&&p.right_epoch.as_deref()==re
        }).map(|p|p.owner_generation).unwrap_or(generation);
        let pair=PairAuthority{generation,owner_generation,left:source.into(),right:target.into(),left_hash:a.credential_hash.clone(),right_hash:b.credential_hash.clone(),left_instance:a.instance.clone(),right_instance:b.instance.clone(),left_ip:a.ip,right_ip:b.ip,left_epoch:if exit{a.exit_epoch.clone()}else{a.sparse_epoch.clone()},right_epoch:if exit{b.exit_epoch.clone()}else{b.sparse_epoch.clone()},expires:now+Duration::from_secs(15)};
        hub.pair_generation=generation;
        (if exit{&mut hub.exit_pairs}else{&mut hub.pairs}).insert(key,pair);true
    }
    /// Capture existing incident authority before any target/ACL reads. Epochs here
    /// describe the authority being retired, not the newly-denied policy state.
    pub(crate) fn observe_pairs(&self,source:&str,hash:&str,instance:&str,generation:u64)->HashMap<String,PairPeerPin>{
        let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if !hub.admissions.get(source).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==generation&&a.expires>now){return HashMap::new();}
        hub.pairs.values().filter_map(|p|{
            if p.expires<=now{return None;}
            let pin=if p.left==source&&p.left_hash==hash&&p.left_instance==instance{
                PairPeerPin{id:p.right.clone(),hash:p.right_hash.clone(),instance:p.right_instance.clone(),ip:p.right_ip,epoch:p.right_epoch.clone(),origin_stamp:None,generation:Some(p.generation)}
            }else if p.right==source&&p.right_hash==hash&&p.right_instance==instance{
                PairPeerPin{id:p.left.clone(),hash:p.left_hash.clone(),instance:p.left_instance.clone(),ip:p.left_ip,epoch:p.left_epoch.clone(),origin_stamp:None,generation:Some(p.generation)}
            }else{return None;};Some((pin.id.clone(),pin))
        }).collect()
    }
    pub(crate) fn retire_pair_admitted(&self,source:&str,hash:&str,instance:&str,generation:u64,target:&PairPeerPin)->bool{
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if !hub.admissions.get(source).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==generation&&a.expires>now){return false;}
        let Some(local)=hub.leases.get(source).filter(|a|a.credential_hash==hash&&a.instance==instance&&a.expires>now)else{return false;};
        let key=if source<target.id.as_str(){(source.to_owned(),target.id.clone())}else{(target.id.clone(),source.to_owned())};
        let Some(pair)=hub.pairs.get(&key)else{return false;};
        if target.generation!=Some(pair.generation){return false;}
        if !hub.leases.get(&target.id).is_some_and(|peer|peer.credential_hash==target.hash&&peer.instance==target.instance&&peer.ip==target.ip&&peer.sparse_epoch==target.epoch&&peer.expires>now){return false;}
        let matches=if pair.left==source{
            pair.left_hash==hash&&pair.left_instance==instance&&pair.left_ip==local.ip&&pair.left_epoch==local.sparse_epoch
            &&pair.right_hash==target.hash&&pair.right_instance==target.instance&&pair.right_ip==target.ip&&pair.right_epoch==target.epoch
        }else{
            pair.right_hash==hash&&pair.right_instance==instance&&pair.right_ip==local.ip&&pair.right_epoch==local.sparse_epoch
            &&pair.left_hash==target.hash&&pair.left_instance==target.instance&&pair.left_ip==target.ip&&pair.left_epoch==target.epoch
        };
        if matches{
            hub.pairs.remove(&key);
            // Any target-side authorization read already in flight must revalidate
            // after this observed denial. Committed unrelated leases remain intact.
            if hub.admissions.get(&target.id).is_some_and(|a|a.hash==target.hash&&a.instance==target.instance){hub.admissions.remove(&target.id);}
        }matches
    }
    pub(crate) fn observe_exit_pairs(&self,source:&str,hash:&str,instance:&str,generation:u64)->HashMap<String,PairPeerPin>{
        let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if !hub.admissions.get(source).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==generation&&a.expires>now){return HashMap::new();}
        hub.exit_pairs.values().filter_map(|p|{
            if p.expires<=now{return None;}
            let pin=if p.left==source&&p.left_hash==hash&&p.left_instance==instance{
                PairPeerPin{id:p.right.clone(),hash:p.right_hash.clone(),instance:p.right_instance.clone(),ip:p.right_ip,epoch:p.right_epoch.clone(),origin_stamp:None,generation:Some(p.generation)}
            }else if p.right==source&&p.right_hash==hash&&p.right_instance==instance{
                PairPeerPin{id:p.left.clone(),hash:p.left_hash.clone(),instance:p.left_instance.clone(),ip:p.left_ip,epoch:p.left_epoch.clone(),origin_stamp:None,generation:Some(p.generation)}
            }else{return None;};Some((pin.id.clone(),pin))
        }).collect()
    }
    pub(crate) fn retire_exit_pair_admitted(&self,source:&str,hash:&str,instance:&str,generation:u64,target:&PairPeerPin)->bool{
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if !hub.admissions.get(source).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==generation&&a.expires>now){return false;}
        let Some(local)=hub.leases.get(source).filter(|a|a.credential_hash==hash&&a.instance==instance&&a.expires>now)else{return false;};
        let key=if source<target.id.as_str(){(source.to_owned(),target.id.clone())}else{(target.id.clone(),source.to_owned())};
        let Some(pair)=hub.exit_pairs.get(&key)else{return false;};
        if target.generation!=Some(pair.generation){return false;}
        if !hub.leases.get(&target.id).is_some_and(|peer|peer.credential_hash==target.hash&&peer.instance==target.instance&&peer.ip==target.ip&&peer.exit_epoch==target.epoch&&peer.expires>now){return false;}
        let matches=if pair.left==source{
            pair.left_hash==hash&&pair.left_instance==instance&&pair.left_ip==local.ip&&pair.left_epoch==local.exit_epoch
            &&pair.right_hash==target.hash&&pair.right_instance==target.instance&&pair.right_ip==target.ip&&pair.right_epoch==target.epoch
        }else{
            pair.right_hash==hash&&pair.right_instance==instance&&pair.right_ip==local.ip&&pair.right_epoch==local.exit_epoch
            &&pair.left_hash==target.hash&&pair.left_instance==target.instance&&pair.left_ip==target.ip&&pair.left_epoch==target.epoch
        };
        if matches{
            hub.exit_pairs.remove(&key);
            // Any target-side authorization read already in flight must revalidate
            // after this observed denial. Committed unrelated leases remain intact.
            if hub.admissions.get(&target.id).is_some_and(|a|a.hash==target.hash&&a.instance==target.instance){hub.admissions.remove(&target.id);}
        }matches
    }
    pub(crate) fn revoke_pair(&self,source:&str,target:&str){let key=if source<target{(source.to_owned(),target.to_owned())}else{(target.to_owned(),source.to_owned())};self.0.lock().unwrap_or_else(|p|p.into_inner()).pairs.remove(&key);}
    pub(crate) fn revoke_exit_pair(&self,source:&str,target:&str){let key=if source<target{(source.to_owned(),target.to_owned())}else{(target.to_owned(),source.to_owned())};self.0.lock().unwrap_or_else(|p|p.into_inner()).exit_pairs.remove(&key);}
    pub(crate) fn pair_neighbors(&self,id:&str)->Vec<String>{
        let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        let mut pairs:Vec<_>=hub.pairs.values().chain(hub.exit_pairs.values()).filter(|p|p.expires>now&&(p.left==id||p.right==id))
            .filter(|p|hub.allowed_pair(&p.left,&p.right,now)||hub.allowed_scope(&p.left,&p.right,now,true)).collect();
        pairs.sort_by_key(|p|std::cmp::Reverse(p.expires));
        let mut seen=HashSet::new();
        pairs.into_iter().filter_map(|p|{let peer=if p.left==id{p.right.clone()}else{p.left.clone()};seen.insert(peer.clone()).then_some(peer)}).collect()
    }
    pub(crate) fn peer_alive(&self, id: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .leases
            .get(id)
            .is_some_and(|lease| lease.expires > Instant::now())
    }
    pub(crate) fn pair_allowed(&self, source: &str, target: &str) -> bool {
        let hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        hub.allowed_pair(source, target, now)
    }
    pub(crate) fn change_workspace(&self, id: &str, hash: &str, instance: &str) -> Option<mongodb::bson::oid::ObjectId> {
        let hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let lease = hub.leases.get(id)?;
        if lease.expires <= Instant::now() || lease.credential_hash != hash || lease.instance != instance { return None; }
        let (workspace, generation) = lease.workspace.as_ref()?;
        if hub.workspace_generations.get(workspace) != Some(&(*generation, false)) { return None; }
        mongodb::bson::oid::ObjectId::parse_str(workspace).ok()
    }
    fn authorized(&self, id: &str, hash: &str, instance: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .leases
            .get(id)
            .is_some_and(|lease| {
                lease.expires > Instant::now()
                    && (lease.hash == hash || lease.credential_hash == hash)
                    && lease.instance == instance
            })
    }
    async fn route(&self, source: &str, hash: &str, instance: &str, lane: u8, frame: Bytes) {
        let Ok(records) = porthub_mesh::batch::decode(frame) else {
            return;
        };
        for record in records {
            let route = {
                let hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
                let Some(route) = Self::route_record(&hub, source, hash, instance, lane, &record, Instant::now()) else {
                    continue;
                };
                // While the routing lock is held the validated identities, scope and
                // target lane cannot change. Revalidate after any capacity wait below.
                if let Ok(permit) = route.output.clone().try_reserve_owned() {
                    let Ok(budget) = self.1.clone().try_acquire_owned() else {
                        hub.dropped_packets.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if route.expires > Instant::now() {
                        route.enqueue(source, permit, budget);
                    }
                    continue;
                }
                route
            };
            // Only this source reader waits. Other peers keep forwarding, and
            // queue capacity still enforces the existing global memory budget.
            let output = route.output.clone();
            let permit = if matches!(route.packet[9], 6 | porthub_mesh::control_packet::STREAM | porthub_mesh::control_packet::EXIT) {
                let deadline = route
                    .expires
                    .min(Instant::now() + Duration::from_millis(200));
                tokio::time::timeout_at(deadline.into(), output.reserve_owned())
                    .await
                    .ok()
                    .and_then(Result::ok)
            } else {
                output.try_reserve_owned().ok()
            };
            let Some(permit) = permit else {
                self.0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .dropped_packets
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // Reserve globally before allocating a forwarded packet. Queue sizing
            // alone cannot bound memory as earlier queues retain their capacities.
            let Ok(budget) = self.1.clone().try_acquire_owned() else {
                self.0.lock().unwrap_or_else(|p| p.into_inner())
                    .dropped_packets.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
            // A lease, ACL, IP, credential or target generation can change while
            // capacity is unavailable. Revalidate before committing the packet.
            let Some(current) =
                Self::route_record(&hub, source, hash, instance, lane, &record, Instant::now())
            else {
                continue;
            };
            if !route.receipt.valid(&hub,Instant::now()) || current.receipt.exit!=route.receipt.exit || current.generation != route.generation || !current.output.same_channel(&route.output)
            {
                continue;
            }
            // Retain the original admission and its deadline across the wait.
            route.enqueue(source, permit, budget);
        }
    }
    async fn while_authorized<T>(&self,receipts:&[ForwardReceipt],operation:impl std::future::Future<Output=T>)->Option<T> {
        tokio::pin!(operation);
        let mut tick=tokio::time::interval(Duration::from_millis(50));tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let guarded=std::future::poll_fn(|cx|{
                {let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();if receipts.iter().any(|r|!r.valid(&hub,now)){return std::task::Poll::Ready(None);}}
                operation.as_mut().poll(cx).map(Some)
            });
            tokio::select!{value=guarded=>return value,_=tick.tick()=>{}}
        }
    }
    fn route_record<'a>(
        hub: &Inner,
        source: &str,
        hash: &str,
        instance: &str,
        lane: u8,
        frame: &'a [u8],
        now: Instant,
    ) -> Option<Forward<'a>> {
        let (&length, rest) = frame.split_first()?;
        let length = usize::from(length);
        if length == 0 || length > 60 || rest.len() < length + 20 || rest.len() > length + 1380 {
            return None;
        }
        let Ok(target) = std::str::from_utf8(&rest[..length]) else {
            return None;
        };
        let packet = &rest[length..];
        if packet[0] >> 4 != 4
            || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        {
            return None;
        }
        let a = hub.leases.get(source).filter(|a| {
            a.expires > now
                && (a.hash == hash || a.credential_hash == hash)
                && a.instance == instance
        })?;
        let b = hub
            .leases
            .get(target)
            .filter(|b| b.expires > now)?;
        let exit=match packet[9] {
            porthub_mesh::control_packet::EXIT=>{porthub_mesh::control_packet::decode(porthub_mesh::control_packet::EXIT,Bytes::copy_from_slice(packet))?;true},
            porthub_mesh::control_packet::PROBE=>{
                let envelope=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::PROBE,Bytes::copy_from_slice(packet))?;
                if !measurement_frame(&envelope.payload){return None;}
                !hub.allowed_pair(source,target,now)
            },
            _=>false,
        };
        if !hub.allowed_scope(source,target,now,exit) {return None;}
        let key = PairLookup::new(source, target);
        let pair=(if exit{&hub.exit_pairs}else{&hub.pairs}).get(&key);
        let expires=a.expires.min(b.expires).min(pair.map(|p|p.expires).unwrap_or(a.expires));
        let receipt=ForwardReceipt{source:source.into(),target:target.into(),source_hash:a.credential_hash.clone(),target_hash:b.credential_hash.clone(),source_instance:a.instance.clone(),target_instance:b.instance.clone(),source_generation:a.identity_generation,target_generation:b.identity_generation,exit,owner:pair.map(|p|p.owner_generation),expires};
        if packet[12..16] != a.ip.octets() || packet[16..20] != b.ip.octets() {
            return None;
        }
        let connections = hub
            .connections
            .get(target)
            .filter(|connections| !connections.is_empty())?;
        let connection = connections
            .get(&lane)
            .or_else(|| connections.get(&0))
            .or_else(|| connections.values().next())
            .filter(|connection| connection.instance == b.instance)?;
        Some(Forward {
            packet,
            output: connection.output.clone(),
            generation: connection.generation,
            expires,
            receipt,
            origin:a.origin.clone(),
        })
    }
}
pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/access/private/relay", get(upgrade))
        .route(
            "/api/access/private/relay/speedtest",
            get(crate::legacy_turn::speedtest).post(crate::legacy_turn::speedtest),
        )
}
fn header(headers: &HeaderMap, key: &str) -> ApiResult<String> {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 256)
        .map(String::from)
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::FORBIDDEN,
                "Private relay authentication required",
            )
        })
}
fn relay_lane_header(headers: &HeaderMap, key: &str, default: u8) -> ApiResult<u8> {
    let Some(value) = headers.get(key) else {
        return Ok(default);
    };
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u8>().ok())
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "Invalid private relay lane"))
}
async fn upgrade(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    if !headers.contains_key("x-porthub-peer") {
        if !app.config.private_transport.enabled() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "Private relay unavailable",
            ));
        }
        return Ok(ws
            .read_buffer_size(8192)
            .write_buffer_size(8192)
            .max_write_buffer_size(131072)
            .max_message_size(65536)
            .max_frame_size(65536)
            .on_upgrade(move |socket| crate::legacy_turn::serve(app, socket)));
    }
    let id = header(&headers, "x-porthub-peer")?;
    let instance = header(&headers, "x-porthub-instance")?;
    let auth = header(&headers, "authorization")?;
    let token = auth.strip_prefix("Bearer ").ok_or_else(|| {
        ApiError::new(
            StatusCode::FORBIDDEN,
            "Private relay authentication required",
        )
    })?;
    let hash = token_digest(token);
    if !app.private_relay.authorized(&id, &hash, &instance) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "Private relay lease unavailable",
        ));
    }
    let lanes = relay_lane_header(&headers, "x-porthub-relay-lanes", 1)?;
    let lane = relay_lane_header(&headers, "x-porthub-relay-lane", 0)?;
    if !(1..=MAX_RELAY_LANES).contains(&lanes) || lane >= lanes {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "Invalid private relay lane",
        ));
    }
    let batch = headers
        .get("x-porthub-relay-batch")
        .is_some_and(|value| value == "1");
    let prefixes = batch
        && headers
            .get("x-porthub-relay-prefix")
            .is_some_and(|value| value == "1");
    let origins = headers.get("x-porthub-relay-origin").is_some_and(|v|v=="1");
    let mut response = ws
        .read_buffer_size(8192)
        .write_buffer_size(8192)
        .max_write_buffer_size(65536)
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |socket| {
            serve(
                app, socket, id, hash, instance, lane, lanes, batch, prefixes, origins,
            )
        });
    if origins {response.headers_mut().insert("x-porthub-relay-origin",HeaderValue::from_static("1"));}
    if batch {
        response
            .headers_mut()
            .insert("x-porthub-relay-batch", HeaderValue::from_static("1"));
    }
    if prefixes {
        response
            .headers_mut()
            .insert("x-porthub-relay-prefix", HeaderValue::from_static("1"));
    }
    response.headers_mut().insert(
        "x-porthub-relay-lanes",
        HeaderValue::from_str(&lanes.to_string()).expect("numeric lane count is a valid header"),
    );
    Ok(response)
}
async fn serve(
    app: Arc<App>,
    socket: WebSocket,
    id: String,
    hash: String,
    instance: String,
    lane: u8,
    lanes: u8,
    batch: bool,
    prefixes: bool,
    origins: bool,
) {
    let (generation, mut packets) = {
        let mut hub = app
            .private_relay
            .0
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        // The lease can change while the HTTP upgrade completes. A stale
        // instance must never evict the current instance's connected lanes.
        if !hub.leases.get(&id).is_some_and(|lease| {
            lease.expires > Instant::now()
                && lease.instance == instance
                && (lease.hash == hash || lease.credential_hash == hash)
        }) {
            return;
        }
        if hub.connections.len() >= MAX_RELAY_PEERS && !hub.connections.contains_key(&id) {
            return;
        }
        let active: usize = hub.connections.values().map(HashMap::len).sum();
        if active >= MAX_RELAY_CONNECTIONS
            && !hub
                .connections
                .get(&id)
                .is_some_and(|peer| peer.contains_key(&lane))
        {
            return;
        }
        let capacity =
            (relay_queue_capacity(active.saturating_add(1)) / usize::from(lanes)).max(16);
        let (output, packets) = mpsc::channel(capacity);
        hub.generation = hub.generation.wrapping_add(1);
        let generation = hub.generation;
        let channels = hub.connections.entry(id.clone()).or_default();
        if channels
            .values()
            .any(|connection| connection.instance != instance)
        {
            channels.clear();
        }
        channels.insert(
            lane,
            Connection {
                instance: instance.clone(),
                generation,
                output,
            },
        );
        (generation, packets)
    };
    let (mut socket, mut incoming) = socket.split();
    let reading = tokio_util::sync::CancellationToken::new();
    let stopping = reading.clone();
    let reader_app = app.clone();
    let reader_id = id.clone();
    let reader_hash = hash.clone();
    let reader_instance = instance.clone();
    let (pongs, mut pong_rx) = mpsc::channel(8);
    // ACK/control frames must still reach their peer while the opposite
    // direction is waiting for TCP write capacity.
    let reader = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        loop {
            tokio::select! {
                _=stopping.cancelled()=>break,
                frame=incoming.next()=>match frame {
                    Some(Ok(Message::Binary(bytes)))=>reader_app.private_relay.route(&reader_id,&reader_hash,&reader_instance,lane,bytes).await,
                    Some(Ok(Message::Ping(bytes)))=>if pongs.try_send(bytes).is_err(){break;},
                    Some(Ok(Message::Pong(_)))=>{},
                    _=>break,
                }
            }
        }
        stopping.cancel();
    }));
    let mut lease_check = tokio::time::interval(Duration::from_secs(5));
    let mut drop_report = tokio::time::interval(Duration::from_secs(10));
    drop_report.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=reading.cancelled()=>break,
            _=lease_check.tick()=>{if !app.private_relay.authorized(&id,&hash,&instance){break;}},
            _=drop_report.tick()=>{
                let dropped=app.private_relay.0.lock().unwrap_or_else(|p|p.into_inner()).dropped_packets.swap(0,Ordering::Relaxed);
                if dropped>0 {tracing::warn!(dropped_packets=dropped,"private relay gateway queue overflowed");}
            },
            Some(bytes)=pong_rx.recv()=>{if !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Pong(bytes))).await,Ok(Ok(()))){break;}},
            packet=packets.recv()=>{
                let Some(packet)=packet else{break;};
                if !app.private_relay.authorized(&id,&hash,&instance){break;}
                let QueuedPacket{bytes:mut output,receipt,_budget,origin}=packet;
                let mut origin_records=vec![origin];
                let mut budgets=vec![_budget];
                let mut receipts=receipt.into_iter().collect::<Vec<_>>();
                {let hub=app.private_relay.0.lock().unwrap_or_else(|p|p.into_inner());if receipts.iter().any(|r|!r.valid(&hub,Instant::now())){continue;}}
                if batch {
                    let mut records=vec![output];
                    while records.len()<if origins{24}else{32} {
                        match packets.try_recv(){Ok(packet)=>{
                            let QueuedPacket{bytes,receipt,_budget,origin}=packet;
                            if let Some(receipt)=receipt {
                                // A batch often consists of one peer pair at one exact
                                // admission deadline. Its final write checks every distinct
                                // receipt under the hub lock on each poll.
                                if receipts.last() != Some(&receipt) {
                                    if !receipt.valid(&app.private_relay.0.lock().unwrap_or_else(|p|p.into_inner()), Instant::now()) {
                                        continue;
                                    }
                                    receipts.push(receipt);
                                }
                            }
                            budgets.push(_budget);records.push(bytes);origin_records.push(origin);
                        },Err(_)=>break}
                    }
                    let encoded=if origins && origin_records.iter().all(Option::is_some) && records.iter().any(|bytes|bytes.get(1+usize::from(bytes[0])+9)==Some(&porthub_mesh::control_packet::EXIT)) {
                        let records:Vec<_>=records.into_iter().zip(origin_records).map(|(bytes,origin)|{let n=usize::from(bytes[0]);(origin.unwrap(),Bytes::copy_from_slice(&bytes[1+n..]))}).collect();
                        porthub_mesh::relay_origin::encode(&records).map(|b|b.to_vec())
                    }else{porthub_mesh::batch::encode(&records,prefixes)};
                    let Ok(encoded)=encoded else {break;};
                    output=encoded;
                }else if origins && output.get(1+usize::from(output[0])+9)==Some(&porthub_mesh::control_packet::EXIT) {
                    if let Some(origin)=origin_records.pop().flatten(){let n=usize::from(output[0]);let Ok(encoded)=porthub_mesh::relay_origin::encode(&[(origin,Bytes::copy_from_slice(&output[1+n..]))]) else{break;};output=encoded.to_vec();}
                }
                let sent=app.private_relay.while_authorized(&receipts,tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Binary(output.into())))).await;
                drop(budgets);
                if !matches!(sent,Some(Ok(Ok(())))){break;}
            }
        }
    }
    reading.cancel();
    reader.abort();
    let _ = reader.await;
    let mut hub = app
        .private_relay
        .0
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let remove_peer = if let Some(channels) = hub.connections.get_mut(&id) {
        if channels
            .get(&lane)
            .is_some_and(|connection| connection.generation == generation)
        {
            channels.remove(&lane);
        }
        channels.is_empty()
    } else {
        false
    };
    if remove_peer {
        hub.connections.remove(&id);
    }
}

const MIN_RELAY_QUEUE_PACKETS: usize = 128;
const MAX_RELAY_QUEUE_PACKETS: usize = 2048;
// Keep the worst-case queued packet budget at or below the old 4096 x 128 cap.
const MAX_RELAY_QUEUE_BUDGET: usize = 4096 * MIN_RELAY_QUEUE_PACKETS;
fn relay_queue_capacity(active_connections: usize) -> usize {
    (MAX_RELAY_QUEUE_BUDGET / active_connections.max(1))
        .clamp(MIN_RELAY_QUEUE_PACKETS, MAX_RELAY_QUEUE_PACKETS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_4097_online_identities_allocate_no_transport_seats_and_only_exact_pair_authority() {
        let hub=Hub::default();let epoch="a".repeat(64);
        for i in 0..4097u32 {let id=format!("peer-{i}");let ip=Ipv4Addr::from(u32::from(Ipv4Addr::new(10,203,0,1))+i);
            assert!(!hub.publish_sparse(&id,&format!("credential-{i}"),"instance",ip,&epoch).is_empty());}
        {let inner=hub.0.lock().unwrap();assert_eq!(inner.leases.len(),4097);assert!(inner.connections.is_empty());assert!(inner.pairs.is_empty());}
        assert!(!hub.pair_allowed("peer-0","peer-4096"));assert!(hub.publish_pair("peer-0","peer-4096",&epoch));
        assert!(hub.pair_allowed("peer-4096","peer-0"));assert!(!hub.pair_allowed("peer-1","peer-4096"));
        assert_eq!(hub.0.lock().unwrap().pairs.len(),1);
        hub.publish_sparse("peer-4096","credential-4096","new-instance",Ipv4Addr::new(10,203,16,1),&epoch);
        assert!(!hub.pair_allowed("peer-0","peer-4096"));assert!(hub.0.lock().unwrap().pairs.is_empty());
    }
    #[test]
    fn sparse_pair_expiry_policy_rotation_and_legacy_denial_are_independent() {
        let hub=Hub::default();let epoch="a".repeat(64);
        hub.publish_sparse("a","credential-a","instance-a",Ipv4Addr::new(10,203,0,1),&epoch);
        hub.publish("b","credential-b","instance-b",Ipv4Addr::new(10,203,0,2),HashSet::new());
        assert!(!hub.publish_pair("a","b",&epoch));
        hub.publish("b","credential-b","instance-b",Ipv4Addr::new(10,203,0,2),HashSet::from(["a".into()]));
        assert!(hub.publish_pair("a","b",&epoch));assert!(hub.pair_allowed("a","b"));
        hub.0.lock().unwrap().pairs.values_mut().next().unwrap().expires=Instant::now()-Duration::from_secs(1);
        assert!(!hub.pair_allowed("a","b"));assert!(hub.peer_alive("a"));assert!(hub.publish_pair("a","b",&epoch));
        hub.publish_sparse("a","credential-a","instance-a",Ipv4Addr::new(10,203,0,1),&"b".repeat(64));
        assert!(!hub.pair_allowed("a","b"));assert!(hub.peer_alive("b"));
    }

    #[test]
    fn overlapping_same_incarnation_syncs_cannot_withdraw_or_publish_over_newer_request(){
        let hub=Hub::default();let epoch="a".repeat(64);let ip=Ipv4Addr::new(10,0,0,1);
        let first=hub.begin_admission("a","hash-a","instance-a").unwrap();
        assert!(!hub.publish_sparse_admitted("a","hash-a","instance-a",ip,&epoch,Some(first)).is_empty());
        // An invalid-credential lookup pins this BEFORE awaiting the database.
        let observed=hub.admission_snapshot("a","hash-a","instance-a").unwrap();
        let later=hub.begin_admission("a","hash-a","instance-a").unwrap();
        assert_ne!(first,later,"a new request needs a new publication ticket even for the same process");
        assert!(!hub.publish_sparse_admitted("a","hash-a","instance-a",ip,&epoch,Some(later)).is_empty());
        assert!(!hub.withdraw_bound("a","hash-a","instance-a",first));
        assert!(!hub.withdraw_bound("a","hash-a","instance-a",observed));
        assert!(hub.peer_alive("a"));
        assert!(hub.publish_sparse_admitted("a","hash-a","instance-a",ip,&epoch,Some(first)).is_empty());
        assert!(hub.withdraw_bound("a","hash-a","instance-a",later));assert!(!hub.peer_alive("a"));
    }

    #[test]
    fn older_pair_decisions_cannot_publish_retire_or_renew_newer_request_or_target_epoch(){
        let hub=Hub::default();let a="a".repeat(64);let b="b".repeat(64);let c="c".repeat(64);
        let ip=Ipv4Addr::new(10,0,0,1);let remote=Ipv4Addr::new(10,0,0,2);
        let first=hub.begin_admission("a","hash-a","instance-a").unwrap();
        hub.publish_sparse_admitted("a","hash-a","instance-a",ip,&a,Some(first));
        let target_read=hub.begin_admission("b","hash-b","instance-b").unwrap();
        hub.publish_sparse_admitted("b","hash-b","instance-b",remote,&b,Some(target_read));
        hub.publish_sparse("c","hash-c","instance-c",Ipv4Addr::new(10,0,0,3),&c);
        let old=PairPeerPin{id:"b".into(),hash:"hash-b".into(),instance:"instance-b".into(),ip:remote,epoch:Some(b.clone()),origin_stamp:None,generation:None};
        assert!(hub.publish_pair_admitted("a",&a,"hash-a","instance-a",first,&old));
        let observed_first=hub.observe_pairs("a","hash-a","instance-a",first).remove("b").unwrap();
        let later=hub.begin_admission("a","hash-a","instance-a").unwrap();
        hub.publish_sparse_admitted("a","hash-a","instance-a",ip,&a,Some(later));
        assert!(hub.publish_pair_admitted("a",&a,"hash-a","instance-a",later,&old));
        assert!(hub.publish_pair_epochs("a","c",&a,&c));
        let key=("a".to_owned(),"b".to_owned());let deadline=hub.0.lock().unwrap().pairs[&key].expires;
        assert!(!hub.retire_pair_admitted("a","hash-a","instance-a",first,&observed_first));
        assert!(!hub.publish_pair_admitted("a",&a,"hash-a","instance-a",first,&old));
        assert_eq!(hub.0.lock().unwrap().pairs[&key].expires,deadline);
        let observed=hub.observe_pairs("a","hash-a","instance-a",later).remove("b").unwrap();
        // A newer committed target decision is protected even when bindings and
        // policy hashes happen to be identical: its pair generation changed.
        assert!(hub.publish_pair_admitted("b",&b,"hash-b","instance-b",target_read,&PairPeerPin{id:"a".into(),hash:"hash-a".into(),instance:"instance-a".into(),ip,epoch:Some(a.clone()),origin_stamp:None,generation:None}));
        assert!(!hub.retire_pair_admitted("a","hash-a","instance-a",later,&observed));
        let observed=hub.observe_pairs("a","hash-a","instance-a",later).remove("b").unwrap();
        assert!(hub.retire_pair_admitted("a","hash-a","instance-a",later,&observed));
        assert!(!hub.pair_allowed("a","b"));assert!(hub.pair_allowed("a","c"));
        assert!(hub.admission_snapshot("b","hash-b","instance-b").is_none(),"target in-flight read must not reintroduce retired authority");
        assert!(!hub.publish_pair_admitted("b",&b,"hash-b","instance-b",target_read,&PairPeerPin{id:"a".into(),hash:"hash-a".into(),instance:"instance-a".into(),ip,epoch:Some(a.clone()),origin_stamp:None,generation:None}));
        let fresh=hub.begin_admission("b","hash-b","instance-b").unwrap();
        hub.publish_sparse_admitted("b","hash-b","instance-b",remote,&a,Some(fresh));
        assert!(!hub.publish_pair_admitted("a",&a,"hash-a","instance-a",later,&old));
        let current=PairPeerPin{epoch:Some(a.clone()),..old};
        assert!(hub.publish_pair_admitted("a",&a,"hash-a","instance-a",later,&current));
        let mut stale=hub.observe_pairs("a","hash-a","instance-a",later).remove("b").unwrap();
        stale.epoch=Some(b);assert!(!hub.retire_pair_admitted("a","hash-a","instance-a",later,&stale));
        stale.epoch=Some(a.clone());stale.instance="old-process".into();
        assert!(!hub.retire_pair_admitted("a","hash-a","instance-a",later,&stale));
        assert!(!hub.publish_pair_admitted("a",&a,"hash-a","instance-a",later,&stale));
    }

    #[test]
    fn authoritative_source_withdrawal_fences_inflight_publication_only_for_exact_binding(){
        let hub=Hub::default();let epoch="a".repeat(64);
        let old=hub.begin_admission("a","hash-a","instance-a").unwrap();
        let other=hub.begin_admission("b","hash-b","instance-b").unwrap();
        assert!(!hub.publish_sparse_admitted("a","hash-a","instance-a",Ipv4Addr::new(10,0,0,1),&epoch,Some(old)).is_empty());
        assert!(!hub.publish_sparse_admitted("b","hash-b","instance-b",Ipv4Addr::new(10,0,0,2),&epoch,Some(other)).is_empty());
        assert!(hub.publish_pair("a","b",&epoch));
        assert!(!hub.withdraw_bound("a","wrong-token","instance-a",old));
        assert!(!hub.withdraw_bound("a","hash-a","stale-instance",old));
        assert!(hub.pair_allowed("a","b"));
        assert!(hub.withdraw_bound("a","hash-a","instance-a",old));
        assert!(!hub.peer_alive("a"));assert!(hub.peer_alive("b"));assert!(!hub.pair_allowed("a","b"));
        assert!(hub.publish_sparse_admitted("a","hash-a","instance-a",Ipv4Addr::new(10,0,0,1),&epoch,Some(old)).is_empty());
        // A new fresh authorized read may recover immediately; no denial quarantine.
        let fresh=hub.begin_admission("a","hash-a","instance-a").unwrap();assert_ne!(fresh,old);
        assert!(!hub.publish_sparse_admitted("a","hash-a","instance-a",Ipv4Addr::new(10,0,0,1),&epoch,Some(fresh)).is_empty());
        assert!(!hub.withdraw_bound("a","hash-a","instance-a",old));
        assert!(hub.peer_alive("a"));
        let replacement=hub.begin_admission("a","hash-new","instance-new").unwrap();
        assert!(!hub.publish_sparse_admitted("a","hash-new","instance-new",Ipv4Addr::new(10,0,0,1),&epoch,Some(replacement)).is_empty());
        assert!(!hub.withdraw_bound("a","hash-a","instance-a",fresh));
        assert!(hub.peer_alive("a"));
        assert!(hub.publish_sparse_admitted("a","hash-a","instance-a",Ipv4Addr::new(10,0,0,1),&epoch,Some(fresh)).is_empty());
        hub.revoke(&["a".into()]);
        assert!(hub.publish_sparse_admitted("a","hash-a","instance-a",Ipv4Addr::new(10,0,0,1),&epoch,Some(fresh)).is_empty());
    }

    #[tokio::test]
    async fn global_budget_is_shared_and_released_on_disconnect() {
        let hub = Hub(Mutex::new(Inner::default()), Arc::new(Semaphore::new(2)));
        let a_ip = Ipv4Addr::new(10, 0, 0, 1);
        let b_ip = Ipv4Addr::new(10, 0, 0, 2);
        let token = hub.publish("a", "credential-a", "instance-a", a_ip, HashSet::from(["b".into()]));
        hub.publish("b", "credential-b", "instance-b", b_ip, HashSet::from(["a".into()]));
        let (output, mut received) = mpsc::channel(16);
        hub.0.lock().unwrap().connections.insert("b".into(), HashMap::from([(0, Connection {
            instance: "instance-b".into(), generation: 1, output,
        })]));
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&a_ip.octets());
        packet[16..20].copy_from_slice(&b_ip.octets());
        let mut record = vec![1, b'b'];
        record.extend_from_slice(&packet);
        let hash = token_digest(&token);
        // Bad credentials, stale instances and forged source IPs never consume budget.
        hub.route("a", "wrong", "instance-a", 0, record.clone().into()).await;
        hub.route("a", &hash, "stale", 0, record.clone().into()).await;
        let mut forged = record.clone();
        forged[14] = 99;
        hub.route("a", &hash, "instance-a", 0, forged.into()).await;
        assert_eq!(hub.1.available_permits(), 2);
        for lane in 0..3 {
            hub.route("a", &hash, "instance-a", lane, record.clone().into()).await;
        }
        assert_eq!(received.len(), 2);
        assert_eq!(hub.1.available_permits(), 0);
        drop(received.recv().await.unwrap());
        assert_eq!(hub.1.available_permits(), 1);
        hub.route("a", &hash, "instance-a", 1, record.into()).await;
        assert_eq!(hub.1.available_permits(), 0);
        drop(received);
        assert_eq!(hub.1.available_permits(), 2);
    }

    #[test]
    fn account_revocation_invalidates_live_relay_credentials() {
        let hub=Hub::default();
        let token=hub.publish("retired","credential","instance",Ipv4Addr::LOCALHOST,HashSet::new());
        assert!(hub.authorized("retired",&token_digest(&token),"instance"));
        hub.revoke(&["retired".into()]);
        assert!(!hub.authorized("retired",&token_digest(&token),"instance"));
        assert!(!hub.authorized("retired","credential","instance"));
        assert!(hub.publish("retired","credential","instance",Ipv4Addr::LOCALHOST,HashSet::new()).is_empty());
    }

    #[test]
    fn relay_queue_capacity_scales_per_connection() {
        assert_eq!(relay_queue_capacity(1), MAX_RELAY_QUEUE_PACKETS);
        assert_eq!(relay_queue_capacity(256), MAX_RELAY_QUEUE_PACKETS);
        assert_eq!(relay_queue_capacity(512), 1024);
        assert_eq!(relay_queue_capacity(4096), MIN_RELAY_QUEUE_PACKETS);
    }

    #[test]
    fn relay_credentials_are_ephemeral_and_stable_for_a_live_instance() {
        let hub = Hub::default();
        let allowed = HashSet::new();
        let token = hub.publish(
            "peer",
            "stored-machine-credential-hash",
            "instance-a",
            Ipv4Addr::LOCALHOST,
            allowed.clone(),
        );
        assert_eq!(token.len(), 32);
        assert!(hub.authorized("peer", &token_digest(&token), "instance-a"));
        assert!(hub.authorized("peer", "stored-machine-credential-hash", "instance-a"));
        assert_eq!(
            token,
            hub.publish(
                "peer",
                "stored-machine-credential-hash",
                "instance-a",
                Ipv4Addr::LOCALHOST,
                allowed.clone(),
            )
        );
        let replacement = hub.publish(
            "peer",
            "stored-machine-credential-hash",
            "instance-b",
            Ipv4Addr::LOCALHOST,
            allowed,
        );
        assert_ne!(token, replacement);
        assert!(!hub.authorized("peer", &token_digest(&token), "instance-a"));
        assert!(hub.authorized("peer", &token_digest(&replacement), "instance-b"));
    }

    #[tokio::test]
    async fn reliable_forwarding_waits_without_locking_the_hub_and_rechecks_revocation() {
        let hub = Hub::default();
        let a_ip = Ipv4Addr::new(10, 0, 0, 1);
        let b_ip = Ipv4Addr::new(10, 0, 0, 2);
        let token = hub.publish(
            "a",
            "credential-a",
            "instance-a",
            a_ip,
            HashSet::from(["b".into()]),
        );
        hub.publish(
            "b",
            "credential-b",
            "instance-b",
            b_ip,
            HashSet::from(["a".into()]),
        );
        let (output, mut received) = mpsc::channel(1);
        hub.0.lock().unwrap().connections.insert(
            "b".into(),
            HashMap::from([(
                0,
                Connection {
                    instance: "instance-b".into(),
                    generation: 1,
                    output: output.clone(),
                },
            )]),
        );
        let packet = porthub_mesh::control_packet::encode(
            porthub_mesh::control_packet::STREAM,
            a_ip,
            b_ip,
            &[1, 2, 3],
        )
        .unwrap();
        let mut record = vec![1, b'b'];
        record.extend_from_slice(&packet);
        let hash = token_digest(&token);
        output.send(QueuedPacket { bytes: vec![0], origin:None, receipt:None, _budget: hub.1.clone().acquire_owned().await.unwrap() }).await.unwrap();
        let mut waiting =
            Box::pin(hub.route("a", &hash, "instance-a", 0, Bytes::copy_from_slice(&record)));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        assert!(
            hub.0.try_lock().is_ok(),
            "slow recipient must not lock other peers"
        );
        received.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap();
        let forwarded = received.recv().await.unwrap();
        assert_eq!(&forwarded[..2], &[1, b'a']);
        assert_eq!(&forwarded[2..], packet.as_ref());

        output.send(QueuedPacket { bytes: vec![0], origin:None, receipt:None, _budget: hub.1.clone().acquire_owned().await.unwrap() }).await.unwrap();
        let mut waiting =
            Box::pin(hub.route("a", &hash, "instance-a", 0, Bytes::copy_from_slice(&record)));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        hub.publish("b", "credential-b", "instance-b", b_ip, HashSet::new());
        received.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap();
        assert!(
            received.try_recv().is_err(),
            "revoked packet must not be committed"
        );
        assert_eq!(
            hub.0
                .lock()
                .unwrap()
                .dropped_packets
                .load(Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn batched_and_legacy_frames_route_the_same_way() {
        let hub = Hub::default();
        let a_ip = Ipv4Addr::new(10, 0, 0, 1);
        let b_ip = Ipv4Addr::new(10, 0, 0, 2);
        let a = hub.publish(
            "peer-a",
            "credential-a",
            "instance-a",
            a_ip,
            HashSet::from(["peer-b".to_owned()]),
        );
        hub.publish(
            "peer-b",
            "credential-b",
            "instance-b",
            b_ip,
            HashSet::from(["peer-a".to_owned()]),
        );
        let (output, mut received) = mpsc::channel(8);
        hub.0.lock().unwrap().connections.insert(
            "peer-b".into(),
            HashMap::from([(
                0,
                Connection {
                    instance: "instance-b".into(),
                    generation: 1,
                    output,
                },
            )]),
        );
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[8] = 64;
        packet[12..16].copy_from_slice(&a_ip.octets());
        packet[16..20].copy_from_slice(&b_ip.octets());
        let mut record = vec![6];
        record.extend_from_slice(b"peer-b");
        record.extend_from_slice(&packet);
        let mut batch = RELAY_BATCH_MAGIC.to_vec();
        for _ in 0..2 {
            batch.extend_from_slice(&(record.len() as u16).to_be_bytes());
            batch.extend_from_slice(&record);
        }
        hub.route(
            "peer-a",
            &token_digest(&a),
            "instance-a",
            0,
            Bytes::copy_from_slice(&batch),
        )
        .await;
        hub.route(
            "peer-a",
            &token_digest(&a),
            "instance-a",
            0,
            Bytes::copy_from_slice(&record),
        )
        .await;
        let compact = porthub_mesh::batch::encode(&[record.clone(), record.clone()], true).unwrap();
        hub.route("peer-a", &token_digest(&a), "instance-a", 0, compact.into())
            .await;
        for _ in 0..5 {
            let forwarded = received.try_recv().expect("forwarded packet");
            assert_eq!(forwarded[0], 6);
            assert_eq!(&forwarded[1..7], b"peer-a");
            assert_eq!(&forwarded[7..], &packet);
        }
    }

    #[test]
    fn relay_routes_matching_lanes_and_falls_back_to_legacy_lane_zero() {
        let hub = Hub::default();
        let a_ip = Ipv4Addr::new(10, 0, 0, 1);
        let b_ip = Ipv4Addr::new(10, 0, 0, 2);
        let a = hub.publish(
            "peer-a",
            "credential-a",
            "instance-a",
            a_ip,
            HashSet::from(["peer-b".to_owned()]),
        );
        hub.publish(
            "peer-b",
            "credential-b",
            "instance-b",
            b_ip,
            HashSet::from(["peer-a".to_owned()]),
        );
        let (lane0, _lane0_rx) = mpsc::channel(4);
        let (lane1, _lane1_rx) = mpsc::channel(4);
        hub.0.lock().unwrap().connections.insert(
            "peer-b".into(),
            HashMap::from([
                (
                    0,
                    Connection {
                        instance: "instance-b".into(),
                        generation: 1,
                        output: lane0.clone(),
                    },
                ),
                (
                    1,
                    Connection {
                        instance: "instance-b".into(),
                        generation: 2,
                        output: lane1.clone(),
                    },
                ),
            ]),
        );
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        packet[8] = 64;
        packet[12..16].copy_from_slice(&a_ip.octets());
        packet[16..20].copy_from_slice(&b_ip.octets());
        let mut record = vec![6];
        record.extend_from_slice(b"peer-b");
        record.extend_from_slice(&packet);
        let hash = token_digest(&a);
        let route_lane1 = Hub::route_record(
            &hub.0.lock().unwrap(),
            "peer-a",
            &hash,
            "instance-a",
            1,
            &record,
            Instant::now(),
        )
        .expect("lane 1 should be available");
        assert!(route_lane1.output.same_channel(&lane1));
        let route_legacy = Hub::route_record(
            &hub.0.lock().unwrap(),
            "peer-a",
            &hash,
            "instance-a",
            3,
            &record,
            Instant::now(),
        )
        .expect("legacy peer should fall back to lane 0");
        assert!(route_legacy.output.same_channel(&lane0));
    }
}

#[cfg(test)]
mod migration_fence_tests {
    use super::*;
    #[test]
    fn workspace_fence_retires_late_tickets_without_touching_other_tenant() {
        let hub=Hub::default();let ip=Ipv4Addr::new(10,0,0,2);
        assert!(hub.workspace_generation("a",0,false));
        let old=hub.begin_workspace_admission("legacy-opaque-peer","hash","instance","a").unwrap();
        let foreign=hub.begin_admission("ab:p","hash","instance").unwrap();
        assert!(!hub.publish_admitted("legacy-opaque-peer","hash","instance",ip,HashSet::new(),Some(old)).is_empty());
        assert!(!hub.workspace_generation("a",1,true));
        assert!(hub.begin_workspace_admission("legacy-opaque-peer","hash","instance","a").is_none());
        assert!(hub.publish_admitted("legacy-opaque-peer","hash","instance",ip,HashSet::new(),Some(old)).is_empty());
        assert!(!hub.publish_admitted("ab:p","hash","instance",ip,HashSet::new(),Some(foreign)).is_empty());
        assert!(!hub.workspace_generation("a",0,false));
        assert!(hub.workspace_generation("a",1,false));
        assert!(hub.publish_admitted("legacy-opaque-peer","hash","instance",ip,HashSet::new(),Some(old)).is_empty());
        let fresh=hub.begin_workspace_admission("legacy-opaque-peer","hash","instance","a").unwrap();
        assert!(!hub.publish_admitted("legacy-opaque-peer","hash","instance",ip,HashSet::new(),Some(fresh)).is_empty());
    }
    #[test]
    fn reversible_retirement_rejects_old_ticket_without_quarantining_fresh_enable(){
        let hub=Hub::default();let ip=Ipv4Addr::new(10,0,0,2);
        let old=hub.begin_admission("peer","hash","instance").unwrap();
        assert!(!hub.publish_admitted("peer","hash","instance",ip,HashSet::new(),Some(old)).is_empty());
        hub.retire_identities(&["peer".into()]);
        assert!(hub.publish_admitted("peer","hash","instance",ip,HashSet::new(),Some(old)).is_empty());
        let fresh=hub.begin_admission("peer","hash","instance").unwrap();
        assert!(!hub.publish_admitted("peer","hash","instance",ip,HashSet::new(),Some(fresh)).is_empty());
        assert!(!hub.withdraw_bound("peer","hash","instance",old));
        assert!(!hub.publish_admitted("peer","hash","instance",ip,HashSet::new(),Some(fresh)).is_empty());
    }

    #[test]
    fn idle_workspace_metadata_reclaims_without_retiring_live_authority(){
        let hub=Hub::default();
        for i in 0..MAX_CONTROL_WORKSPACES {assert!(hub.workspace_generation(&format!("workspace-{i}"),1,false));}
        let ticket=hub.begin_workspace_admission("opaque-peer","hash","instance","workspace-0").unwrap();
        assert!(!hub.publish_admitted("opaque-peer","hash","instance",Ipv4Addr::new(10,0,0,2),HashSet::new(),Some(ticket)).is_empty());
        assert!(hub.workspace_generation("new-workspace",1,false));
        let inner=hub.0.lock().unwrap();assert_eq!(inner.workspace_generations.len(),2);assert_eq!(inner.workspace_generations.get("workspace-0"),Some(&(1,false)));drop(inner);
        assert!(!hub.publish_admitted("opaque-peer","hash","instance",Ipv4Addr::new(10,0,0,2),HashSet::new(),Some(ticket)).is_empty());
    }
    #[test]
    fn idle_eviction_cannot_resurrect_expired_ticket_or_admit_without_fresh_head(){
        let hub=Hub::default();
        for i in 0..MAX_CONTROL_WORKSPACES {assert!(hub.workspace_generation(&format!("workspace-{i}"),7,false));}
        let old=hub.begin_workspace_admission("opaque-peer","hash","instance","workspace-0").unwrap();
        hub.publish_admitted("opaque-peer","hash","instance",Ipv4Addr::new(10,0,0,2),HashSet::new(),Some(old));
        {let mut inner=hub.0.lock().unwrap();inner.admissions.get_mut("opaque-peer").unwrap().expires=Instant::now()-Duration::from_secs(1);inner.leases.get_mut("opaque-peer").unwrap().expires=Instant::now()-Duration::from_secs(1);}
        assert!(hub.workspace_generation("new-workspace",1,false));
        assert!(hub.publish_admitted("opaque-peer","hash","instance",Ipv4Addr::new(10,0,0,2),HashSet::new(),Some(old)).is_empty());
        assert!(hub.begin_workspace_admission("opaque-peer","hash","instance","workspace-0").is_none());
        assert!(hub.workspace_generation("workspace-0",8,false));
        let fresh=hub.begin_workspace_admission("opaque-peer","hash","instance","workspace-0").unwrap();
        assert!(!hub.publish_admitted("opaque-peer","hash","instance",Ipv4Addr::new(10,0,0,2),HashSet::new(),Some(fresh)).is_empty());
        assert!(!hub.withdraw_bound("opaque-peer","hash","instance",old));
    }

}

#[cfg(test)]
mod exit_scope_tests {
    use super::*;
    fn publish(hub:&Hub,id:&str,private:&str,exit:&str)->u64 {
        let ticket=hub.begin_admission(id,&format!("hash-{id}"),&format!("instance-{id}")).unwrap();
        let ip=if id=="a"{Ipv4Addr::new(10,203,0,1)}else{Ipv4Addr::new(10,203,0,2)};
        assert!(!hub.publish_sparse_exit_admitted(id,&format!("hash-{id}"),&format!("instance-{id}"),ip,private,exit,Some(ticket)).is_empty());ticket
    }
    fn pin(id:&str,epoch:&str)->PairPeerPin {PairPeerPin{id:id.into(),hash:format!("hash-{id}"),instance:format!("instance-{id}"),ip:if id=="a"{Ipv4Addr::new(10,203,0,1)}else{Ipv4Addr::new(10,203,0,2)},epoch:Some(epoch.into()),origin_stamp:None,generation:None}}
    fn fixture()->(Hub,mpsc::Receiver<QueuedPacket>,u64,u64) {
        let hub=Hub::default();let a=publish(&hub,"a",&"a".repeat(64),&"e".repeat(64));let b=publish(&hub,"b",&"b".repeat(64),&"f".repeat(64));
        let(tx,rx)=mpsc::channel(8);hub.0.lock().unwrap().connections.insert("b".into(),HashMap::from([(0,Connection{instance:"instance-b".into(),generation:1,output:tx})]));(hub,rx,a,b)
    }
    fn wire(protocol:u8)->Vec<u8> {
        let mut payload=vec![0;1200];payload[..8].copy_from_slice(b"PHUBQOS1");payload[11]=32;
        if matches!(protocol,porthub_mesh::control_packet::EXIT|porthub_mesh::control_packet::PROBE|porthub_mesh::control_packet::STREAM){porthub_mesh::control_packet::encode(protocol,Ipv4Addr::new(10,203,0,1),Ipv4Addr::new(10,203,0,2),&payload).unwrap().to_vec()}
        else {let mut packet=vec![0;20];packet[0]=0x45;packet[3]=20;packet[9]=protocol;packet[12..16].copy_from_slice(&[10,203,0,1]);packet[16..20].copy_from_slice(&[10,203,0,2]);packet}
    }
    fn frame(packet:&[u8])->Vec<u8>{let mut frame=vec![1,b'b'];frame.extend_from_slice(packet);frame}
    fn receipt(hub:&Hub,packet:&[u8])->Option<ForwardReceipt>{Hub::route_record(&hub.0.lock().unwrap(),"a","hash-a","instance-a",0,&frame(packet),Instant::now()).map(|route|route.receipt)}
    fn exit(hub:&Hub,ticket:u64){assert!(hub.publish_exit_pair_admitted("a",&"e".repeat(64),"hash-a","instance-a",ticket,&pin("b",&"f".repeat(64))));}
    fn private(hub:&Hub,ticket:u64){assert!(hub.publish_pair_admitted("a",&"a".repeat(64),"hash-a","instance-a",ticket,&pin("b",&"b".repeat(64))));}
    #[test]
    fn exit_only_authority_never_admits_private_stream_or_unvalidated_probe_payload() {
        let(hub,_rx,a,_)=fixture();exit(&hub,a);
        assert!(receipt(&hub,&wire(porthub_mesh::control_packet::EXIT)).unwrap().exit);
        assert!(receipt(&hub,&wire(porthub_mesh::control_packet::PROBE)).unwrap().exit);
        for protocol in [6,17,porthub_mesh::control_packet::STREAM]{assert!(receipt(&hub,&wire(protocol)).is_none());}
        let mut malformed=wire(porthub_mesh::control_packet::PROBE);malformed[20]=0;assert!(receipt(&hub,&malformed).is_none());
        let mut payload=vec![0;1200];payload[..8].copy_from_slice(b"PHUBQOS1");payload[11]=32;payload[9]=1;
        let wrong=porthub_mesh::control_packet::encode(porthub_mesh::control_packet::PROBE,Ipv4Addr::new(10,203,0,1),Ipv4Addr::new(10,203,0,2),&payload).unwrap();assert!(receipt(&hub,&wrong).is_none());
    }
    #[test]
    fn private_epoch_change_cannot_promote_an_old_probe_to_exit_authority() {
        let(hub,_rx,a,_)=fixture();private(&hub,a);exit(&hub,a);let old=receipt(&hub,&wire(porthub_mesh::control_packet::PROBE)).unwrap();assert!(!old.exit);
        publish(&hub,"a",&"c".repeat(64),&"e".repeat(64));assert!(!old.valid(&hub.0.lock().unwrap(),Instant::now()));
        let fresh=receipt(&hub,&wire(porthub_mesh::control_packet::PROBE)).unwrap();assert!(fresh.exit);assert!(fresh.valid(&hub.0.lock().unwrap(),Instant::now()));assert!(receipt(&hub,&wire(6)).is_none());
    }
    #[test]
    fn exit_revoke_regrant_does_not_revive_old_bytes_and_private_survives() {
        let(hub,_rx,a,_)=fixture();private(&hub,a);exit(&hub,a);let old=receipt(&hub,&wire(porthub_mesh::control_packet::EXIT)).unwrap();
        publish(&hub,"a",&"a".repeat(64),&"d".repeat(64));assert!(!old.valid(&hub.0.lock().unwrap(),Instant::now()));assert!(receipt(&hub,&wire(6)).is_some());
        let fresh=publish(&hub,"a",&"a".repeat(64),&"e".repeat(64));exit(&hub,fresh);assert!(!old.valid(&hub.0.lock().unwrap(),Instant::now()));assert!(receipt(&hub,&wire(porthub_mesh::control_packet::EXIT)).is_some());
    }
    #[test]
    fn equivalent_reciprocal_renewal_preserves_owner_but_never_old_expiry() {
        let(hub,_rx,a,b)=fixture();exit(&hub,a);let mut old=receipt(&hub,&wire(porthub_mesh::control_packet::EXIT)).unwrap();let expiry=old.expires;
        assert!(hub.publish_exit_pair_admitted("b",&"f".repeat(64),"hash-b","instance-b",b,&pin("a",&"e".repeat(64))));
        assert!(old.valid(&hub.0.lock().unwrap(),Instant::now()));assert_eq!(old.expires,expiry);
        old.expires=Instant::now()-Duration::from_millis(1);assert!(!old.valid(&hub.0.lock().unwrap(),Instant::now()));
    }
    #[tokio::test]
    async fn actual_queued_exit_cancels_blocked_delivery_on_source_revocation() {
        let(hub,mut rx,a,_)=fixture();exit(&hub,a);hub.route("a","hash-a","instance-a",0,Bytes::from(frame(&wire(porthub_mesh::control_packet::EXIT)))).await;
        let packet=rx.recv().await.unwrap();let receipt=packet.receipt.clone().unwrap();let before=hub.1.available_permits();
        let signal=std::sync::atomic::AtomicBool::new(false);
        let revoke=async{tokio::time::sleep(Duration::from_millis(20)).await;hub.retire_identities(&["a".into()]);};
        let receipts=[receipt];let delivery=hub.while_authorized(&receipts,async{signal.store(true,Ordering::SeqCst);std::future::pending::<()>().await});
        let(result,_)=tokio::time::timeout(Duration::from_secs(1),async{tokio::join!(delivery,revoke)}).await.unwrap();assert!(result.is_none());assert!(signal.load(Ordering::SeqCst));drop(packet);assert_eq!(hub.1.available_permits(),before+1);
    }
    #[test]
    fn exit_publication_requires_exact_fresh_admission_and_current_target_generation() {
        let(hub,_rx,a,_)=fixture();let mut wrong=pin("b",&"0".repeat(64));assert!(!hub.publish_exit_pair_admitted("a",&"e".repeat(64),"hash-a","instance-a",a,&wrong));
        wrong=pin("b",&"f".repeat(64));wrong.instance="foreign".into();assert!(!hub.publish_exit_pair_admitted("a",&"e".repeat(64),"hash-a","instance-a",a,&wrong));
        let fresh=hub.begin_admission("a","hash-a","instance-a").unwrap();assert!(!hub.publish_exit_pair_admitted("a",&"e".repeat(64),"hash-a","instance-a",a,&pin("b",&"f".repeat(64))));assert!(hub.publish_exit_pair_admitted("a",&"e".repeat(64),"hash-a","instance-a",fresh,&pin("b",&"f".repeat(64))));
    }
    #[test]
    fn private_and_exit_authorities_share_total_and_incident_record_budgets() {
        let(hub,_rx,a,_)=fixture();exit(&hub,a);
        {let mut inner=hub.0.lock().unwrap();let seed=inner.exit_pairs.values().next().unwrap().clone();for index in 0..255 {let mut pair=seed.clone();pair.right=format!("other-{index}");inner.exit_pairs.insert(("a".into(),pair.right.clone()),pair);}}
        assert!(!hub.publish_pair_admitted("a",&"a".repeat(64),"hash-a","instance-a",a,&pin("b",&"b".repeat(64))));
        // Replacing an existing class is not a new resource admission.
        exit(&hub,a);
        {let mut inner=hub.0.lock().unwrap();inner.exit_pairs.clear();let seed=PairAuthority{generation:1,owner_generation:1,left:"other-left".into(),right:"other-right".into(),left_hash:"h".into(),right_hash:"h".into(),left_instance:"i".into(),right_instance:"i".into(),left_ip:Ipv4Addr::LOCALHOST,right_ip:Ipv4Addr::LOCALHOST,left_epoch:Some("e".repeat(64)),right_epoch:Some("f".repeat(64)),expires:Instant::now()+Duration::from_secs(15)};for index in 0..8192 {inner.exit_pairs.insert((format!("x{index}"),format!("y{index}")),seed.clone());}}
        assert!(!hub.publish_pair_admitted("a",&"a".repeat(64),"hash-a","instance-a",a,&pin("b",&"b".repeat(64))));assert_eq!(hub.0.lock().unwrap().pairs.len(),0);
    }
    #[test]
    fn exit_denial_retirement_pins_publication_and_cannot_remove_private_authority() {
        let(hub,_rx,a,_)=fixture();private(&hub,a);exit(&hub,a);
        let old=hub.observe_exit_pairs("a","hash-a","instance-a",a).remove("b").unwrap();exit(&hub,a);
        assert!(!hub.retire_exit_pair_admitted("a","hash-a","instance-a",a,&old));
        let current=hub.observe_exit_pairs("a","hash-a","instance-a",a).remove("b").unwrap();assert!(hub.retire_exit_pair_admitted("a","hash-a","instance-a",a,&current));
        assert!(hub.pair_allowed("a","b"));assert!(receipt(&hub,&wire(porthub_mesh::control_packet::EXIT)).is_none());
    }

}

#[cfg(test)]
mod origin_tests {
    use super::*;
    fn peer()->porthub_network::policy::PeerInfo{serde_json::from_value(serde_json::json!({"id":"a","ip":"10.203.0.1","fingerprint":"fp","instance":"instance","hostname":"a.phub"})).unwrap()}
    fn publish(hub:&Hub)->u64{let p=peer();let a=hub.begin_admission(&p.id,"hash",&p.instance).unwrap();assert!(!hub.publish_sparse_admitted(&p.id,"hash",&p.instance,p.ip,&"a".repeat(64),Some(a)).is_empty());assert!(hub.bind_origin(p,"hash",a));a}
    #[test]
    fn final_pair_publication_rejects_projected_stamp_from_before_target_revival(){
      for exit in [false,true] {
        let hub=Hub::default();let source=publish(&hub);let epoch="a".repeat(64);let exit_epoch="e".repeat(64);
        if exit{hub.publish_sparse_exit_admitted("a","hash","instance",Ipv4Addr::new(10,203,0,1),&epoch,&exit_epoch,Some(source));}
        let publish_b=||{
            let ticket=hub.begin_admission("b","hash-b","instance-b").unwrap();
            if exit{hub.publish_sparse_exit_admitted("b","hash-b","instance-b",Ipv4Addr::new(10,203,0,2),&epoch,&exit_epoch,Some(ticket));}
            else{hub.publish_sparse_admitted("b","hash-b","instance-b",Ipv4Addr::new(10,203,0,2),&epoch,Some(ticket));}
            let peer=serde_json::from_value(serde_json::json!({"id":"b","ip":"10.203.0.2","fingerprint":"fp-b","instance":"instance-b","hostname":"b.phub"})).unwrap();
            assert!(hub.bind_origin(peer,"hash-b",ticket));
        };publish_b();
        let stamp=hub.0.lock().unwrap().leases["b"].origin.as_ref().unwrap().stamp.clone();
        let permission=if exit{&exit_epoch}else{&epoch};
        let mut pin=PairPeerPin{id:"b".into(),hash:"hash-b".into(),instance:"instance-b".into(),ip:Ipv4Addr::new(10,203,0,2),epoch:Some(permission.clone()),origin_stamp:Some(stamp),generation:None};
        let publish_pair=|pin:&PairPeerPin|if exit{hub.publish_exit_pair_admitted("a",permission,"hash","instance",source,pin)}else{hub.publish_pair_admitted("a",permission,"hash","instance",source,pin)};
        assert!(publish_pair(&pin));
        let stamp=pin.origin_stamp.take();assert!(!publish_pair(&pin),"missing stamp is not a wildcard");pin.origin_stamp=stamp;
        hub.0.lock().unwrap().leases.get_mut("b").unwrap().expires=Instant::now()-Duration::from_secs(1);publish_b();
        assert!(!publish_pair(&pin));
        pin.origin_stamp=Some(hub.0.lock().unwrap().leases["b"].origin.as_ref().unwrap().stamp.clone());
        assert!(publish_pair(&pin));
      }
    }
    #[test]
    fn expired_lease_cannot_bind_and_malformed_replacement_has_no_retirement_side_effect(){
        let hub=Hub::default();publish(&hub);let original=hub.0.lock().unwrap().leases["a"].origin.clone().unwrap();
        let ticket=hub.begin_admission("a","hash","instance").unwrap();
        let mut malformed=peer();malformed.fingerprint="x".repeat(257);
        assert!(!hub.bind_origin(malformed,"hash",ticket));assert!(Arc::ptr_eq(hub.0.lock().unwrap().leases["a"].origin.as_ref().unwrap(),&original));
        hub.0.lock().unwrap().leases.get_mut("a").unwrap().expires=Instant::now()-Duration::from_secs(1);
        let fresh=hub.begin_admission("a","hash","instance").unwrap();assert!(!hub.bind_origin(peer(),"hash",fresh));
    }
    #[tokio::test]
    async fn queued_packet_keeps_original_server_stamp_and_receipt_retires_on_same_identity_revival(){
        let hub=Hub::default();let epoch="a".repeat(64);publish(&hub);
        let b=hub.begin_admission("b","hash-b","instance-b").unwrap();
        hub.publish_sparse_admitted("b","hash-b","instance-b",Ipv4Addr::new(10,203,0,2),&epoch,Some(b));
        assert!(hub.publish_pair("a","b",&epoch));
        let(tx,mut rx)=mpsc::channel(4);hub.0.lock().unwrap().connections.insert("b".into(),HashMap::from([(0,Connection{instance:"instance-b".into(),generation:1,output:tx})]));
        let mut packet=vec![0;20];packet[0]=0x45;packet[3]=20;packet[9]=17;packet[12..16].copy_from_slice(&[10,203,0,1]);packet[16..20].copy_from_slice(&[10,203,0,2]);
        let mut frame=vec![1,b'b'];frame.extend_from_slice(&packet);
        hub.route("a","hash","instance",0,frame.into()).await;
        let queued=rx.recv().await.unwrap();let original=queued.origin.as_ref().unwrap().stamp.clone();
        assert!(queued.receipt.as_ref().unwrap().valid(&hub.0.lock().unwrap(),Instant::now()));
        hub.0.lock().unwrap().leases.get_mut("a").unwrap().expires=Instant::now()-Duration::from_secs(1);
        publish(&hub);
        assert!(!queued.receipt.as_ref().unwrap().valid(&hub.0.lock().unwrap(),Instant::now()));
        assert_eq!(queued.origin.as_ref().unwrap().stamp,original);
        assert_ne!(hub.0.lock().unwrap().leases["a"].origin.as_ref().unwrap().stamp,original);
    }
    #[test]
    fn heartbeat_retains_stamp_but_expiry_restart_and_fingerprint_rebind_do_not(){
        let hub=Hub::default();publish(&hub);let mut original=peer();hub.project_origin(&mut original,"hash");let stamp=original.relay_origin.clone().unwrap();assert_eq!(stamp.len(),32);
        publish(&hub);let mut same=peer();hub.project_origin(&mut same,"hash");assert_eq!(same.relay_origin,Some(stamp.clone()));
        let pinned=hub.0.lock().unwrap().leases["a"].origin.clone().unwrap();
        hub.0.lock().unwrap().leases.get_mut("a").unwrap().expires=Instant::now()-Duration::from_secs(1);
        publish(&hub);let mut revived=peer();hub.project_origin(&mut revived,"hash");assert_ne!(revived.relay_origin,original.relay_origin);assert_eq!(pinned.stamp,stamp);
        let admission=hub.admission_snapshot("a","hash","instance").unwrap();let mut changed=peer();changed.fingerprint="fp-new".into();assert!(hub.bind_origin(changed.clone(),"hash",admission));hub.project_origin(&mut changed,"hash");assert_ne!(changed.relay_origin,revived.relay_origin);
        let restart=Hub::default();publish(&restart);let mut fresh=peer();restart.project_origin(&mut fresh,"hash");assert_ne!(fresh.relay_origin,original.relay_origin);
        let mut wrong=peer();restart.project_origin(&mut wrong,"wrong-hash");assert!(wrong.relay_origin.is_none());
    }
}
