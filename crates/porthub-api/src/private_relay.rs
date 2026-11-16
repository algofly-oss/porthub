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
const MAX_RELAY_LANES: u8 = 4;
const MAX_RELAY_PEERS: usize = 4096;
const MAX_RELAY_CONNECTIONS: usize = MAX_RELAY_PEERS * MAX_RELAY_LANES as usize;
#[derive(Clone)]
struct Lease {
    credential_hash: String,
    hash: String,
    relay_token: String,
    instance: String,
    ip: Ipv4Addr,
    allowed: HashSet<String>,
    expires: Instant,
    sparse_epoch: Option<String>,
    workspace: Option<(String,u64)>,
}
pub(crate) struct PairPeerPin {pub id:String,pub hash:String,pub instance:String,pub ip:Ipv4Addr,pub epoch:Option<String>,pub generation:Option<u64>}
#[derive(Clone)]
struct PairAuthority {
    generation:u64,
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
struct Forward<'a> {
    packet: &'a [u8],
    output: mpsc::Sender<QueuedPacket>,
    generation: u64,
    expires: Instant,
}
struct Admission { hash:String, instance:String, generation:u64, expires:Instant, workspace:Option<(String,u64)> }
#[derive(Default)]
struct Inner {
    leases: HashMap<String, Lease>,
    revoked: HashMap<String, Instant>,
    revoked_cleanup_at: Option<Instant>,
    connections: HashMap<String, HashMap<u8, Connection>>,
    pairs: HashMap<(String,String), PairAuthority>,
    generation: u64,
    admissions: HashMap<String, Admission>,
    workspace_generations: HashMap<String, (u64, bool)>,
    admission_generation: u64,
    pair_generation:u64,
    admission_cleanup_at: Option<Instant>,
    dropped_packets: AtomicU64,
}
struct QueuedPacket {
    bytes: Vec<u8>,
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
    fn allowed_pair(&self, source:&str, target:&str, now:Instant)->bool {
        let (Some(a),Some(b))=(self.leases.get(source),self.leases.get(target)) else{return false;};
        if a.expires<=now || b.expires<=now {return false;}
        if a.sparse_epoch.is_none() && b.sparse_epoch.is_none() {return a.allowed.contains(target)&&b.allowed.contains(source);}
        let key=if source<target{(source.to_owned(),target.to_owned())}else{(target.to_owned(),source.to_owned())};
        let Some(pair)=self.pairs.get(&key).filter(|p|p.expires>now) else{return false;};
        let (Some(left),Some(right))=(self.leases.get(&pair.left),self.leases.get(&pair.right)) else{return false;};
        left.credential_hash==pair.left_hash && right.credential_hash==pair.right_hash
            && left.instance==pair.left_instance && right.instance==pair.right_instance
            && left.ip==pair.left_ip && right.ip==pair.right_ip
            && left.sparse_epoch==pair.left_epoch && right.sparse_epoch==pair.right_epoch
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
    /// exact stable workspace prefix; late in-flight publications fail closed.
    pub(crate) fn workspace_generation(&self, workspace:&str, generation:u64, blocked:bool)->bool {
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());
        let old=hub.workspace_generations.get(workspace).copied();
        if old.is_some_and(|(g,_)|generation<g) {return false;}
        if old.is_none()&&hub.workspace_generations.len()>=16384 {return false;}
        if old==Some((generation,blocked)){return !blocked;}
        let retired:HashSet<String>=hub.admissions.iter().filter(|(_,a)|a.workspace.as_ref().is_some_and(|(w,_)|w==workspace)).map(|(id,_)|id.clone())
            .chain(hub.leases.iter().filter(|(_,l)|l.workspace.as_ref().is_some_and(|(w,_)|w==workspace)).map(|(id,_)|id.clone())).collect();
        hub.admissions.retain(|id,_|!retired.contains(id));
        hub.leases.retain(|id,_|!retired.contains(id));
        hub.connections.retain(|id,_|!retired.contains(id));
        hub.pairs.retain(|_,pair|!retired.contains(&pair.left)&&!retired.contains(&pair.right));
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
        }
        true
    }
    /// Reversible peer toggle / credential rotation: retire exact current
    /// authority without the account-deletion quarantine. New freshly checked
    /// credentials can enroll immediately; old request tickets stay invalid.
    pub(crate) fn retire_identities(&self,ids:&[String]) {
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());
        for id in ids {hub.admissions.remove(id);hub.leases.remove(id);hub.connections.remove(id);hub.pairs.retain(|_,p|p.left!=*id&&p.right!=*id);}
    }
    pub fn revoke(&self, ids: &[String]) {
        let mut hub = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let now=Instant::now();
        if hub.revoked_cleanup_at.is_none() { hub.revoked_cleanup_at=Some(now+Duration::from_secs(60)); }
        for id in ids {
            hub.admissions.remove(id);
            hub.leases.remove(id); hub.connections.remove(id);
            hub.pairs.retain(|_, pair| pair.left != *id && pair.right != *id);
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
        hub.leases.insert(
            id.into(),
            Lease {
                credential_hash: hash.into(),
                hash: token_digest(&relay_token),
                relay_token: relay_token.clone(),
                instance: instance.into(),
                ip,
                allowed,
                expires: now + Duration::from_secs(15),
                sparse_epoch: None,
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
        if epoch.len()!=64 || !epoch.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()) {return String::new();}
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if admission.is_some_and(|g|!hub.admissions.get(id).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==g&&a.expires>now)){return String::new();}
        if hub.revoked.get(id).is_some_and(|expires|*expires>now) {return String::new();}
        hub.leases.retain(|_,lease|lease.expires>now);hub.pairs.retain(|_,p|p.expires>now);
        if hub.leases.len()>=16384 && !hub.leases.contains_key(id) {return String::new();}
        let old=hub.leases.get(id);
        let unchanged=old.is_some_and(|l|l.credential_hash==hash&&l.instance==instance&&l.ip==ip&&l.sparse_epoch.as_deref()==Some(epoch));
        let token=old.filter(|l|l.credential_hash==hash&&l.instance==instance).map(|l|l.relay_token.clone()).unwrap_or_else(||uuid::Uuid::new_v4().simple().to_string());
        if !unchanged {hub.pairs.retain(|_,p|p.left!=id&&p.right!=id);}
        let workspace=admission.and_then(|_|hub.admissions.get(id).and_then(|a|a.workspace.clone()));
        hub.leases.insert(id.into(),Lease{workspace,credential_hash:hash.into(),hash:token_digest(&token),relay_token:token.clone(),instance:instance.into(),ip,allowed:HashSet::new(),expires:now+Duration::from_secs(15),sparse_epoch:Some(epoch.into())});
        token
    }
    /// Called only after an authenticated API pair lookup has compiled a nonempty exact ACL.
    /// Coarse relay eligibility is reciprocal; the endpoint engines still enforce packet ACLs.
    pub(crate) fn publish_pair(&self,source:&str,target:&str,epoch:&str)->bool{self.publish_pair_epochs(source,target,epoch,epoch)}
    pub(crate) fn publish_pair_epochs(&self, source:&str, target:&str, epoch:&str,target_epoch:&str)->bool {
        self.publish_pair_checked(source,target,epoch,target_epoch,None)
    }
    pub(crate) fn publish_pair_admitted(&self,source:&str,epoch:&str,hash:&str,instance:&str,generation:u64,target:&PairPeerPin)->bool{
        self.publish_pair_checked(source,&target.id,epoch,target.epoch.as_deref().unwrap_or_default(),Some((hash,instance,generation,target)))
    }
    fn publish_pair_checked(&self,source:&str,target:&str,epoch:&str,target_epoch:&str,request:Option<(&str,&str,u64,&PairPeerPin)>)->bool{
        if source==target {return false;}
        let mut hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        hub.pairs.retain(|_,p|p.expires>now);
        let (Some(a),Some(b))=(hub.leases.get(source),hub.leases.get(target)) else{return false;};
        if request.is_some_and(|(hash,instance,generation,pin)|a.credential_hash!=hash||a.instance!=instance||b.credential_hash!=pin.hash||b.instance!=pin.instance||b.ip!=pin.ip||!hub.admissions.get(source).is_some_and(|r|r.hash==hash&&r.instance==instance&&r.generation==generation&&r.expires>now)){return false;}
        if a.expires<=now || b.expires<=now || a.sparse_epoch.as_deref()!=Some(epoch)
            || b.sparse_epoch.as_deref().is_some_and(|e|e!=target_epoch)
            || (b.sparse_epoch.is_none() && !b.allowed.contains(source)) {return false;}
        let key=if source<target {(source.to_owned(),target.to_owned())}else{(target.to_owned(),source.to_owned())};
        if !hub.pairs.contains_key(&key) && (hub.pairs.len()>=8192 || hub.pairs.values().filter(|p|p.left==source||p.right==source).count()>=256 || hub.pairs.values().filter(|p|p.left==target||p.right==target).count()>=256) {return false;}
        let Some(generation)=hub.pair_generation.checked_add(1)else{return false;};
        let pair=PairAuthority{generation,left:source.into(),right:target.into(),left_hash:a.credential_hash.clone(),right_hash:b.credential_hash.clone(),left_instance:a.instance.clone(),right_instance:b.instance.clone(),left_ip:a.ip,right_ip:b.ip,left_epoch:a.sparse_epoch.clone(),right_epoch:b.sparse_epoch.clone(),expires:now+Duration::from_secs(15)};
        hub.pair_generation=generation;
        hub.pairs.insert(key,pair);true
    }
    /// Capture existing incident authority before any target/ACL reads. Epochs here
    /// describe the authority being retired, not the newly-denied policy state.
    pub(crate) fn observe_pairs(&self,source:&str,hash:&str,instance:&str,generation:u64)->HashMap<String,PairPeerPin>{
        let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if !hub.admissions.get(source).is_some_and(|a|a.hash==hash&&a.instance==instance&&a.generation==generation&&a.expires>now){return HashMap::new();}
        hub.pairs.values().filter_map(|p|{
            if p.expires<=now{return None;}
            let pin=if p.left==source&&p.left_hash==hash&&p.left_instance==instance{
                PairPeerPin{id:p.right.clone(),hash:p.right_hash.clone(),instance:p.right_instance.clone(),ip:p.right_ip,epoch:p.right_epoch.clone(),generation:Some(p.generation)}
            }else if p.right==source&&p.right_hash==hash&&p.right_instance==instance{
                PairPeerPin{id:p.left.clone(),hash:p.left_hash.clone(),instance:p.left_instance.clone(),ip:p.left_ip,epoch:p.left_epoch.clone(),generation:Some(p.generation)}
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
    pub(crate) fn revoke_pair(&self,source:&str,target:&str){let key=if source<target{(source.to_owned(),target.to_owned())}else{(target.to_owned(),source.to_owned())};self.0.lock().unwrap_or_else(|p|p.into_inner()).pairs.remove(&key);}
    pub(crate) fn pair_neighbors(&self,id:&str)->Vec<String>{
        let hub=self.0.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        let mut pairs:Vec<_>=hub.pairs.values().filter(|p|p.expires>now&&(p.left==id||p.right==id))
            .filter(|p|hub.allowed_pair(&p.left,&p.right,now)).collect();
        pairs.sort_by_key(|p|std::cmp::Reverse(p.expires));
        pairs.into_iter().map(|p|if p.left==id{p.right.clone()}else{p.left.clone()}).collect()
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
                Self::route_record(&hub, source, hash, instance, lane, &record, Instant::now())
            };
            let Some(route) = route else {
                continue;
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
            if current.generation != route.generation || !current.output.same_channel(&route.output)
            {
                continue;
            }
            let mut forwarded = Vec::with_capacity(1 + source.len() + current.packet.len());
            forwarded.push(source.len() as u8);
            forwarded.extend_from_slice(source.as_bytes());
            forwarded.extend_from_slice(current.packet);
            permit.send(QueuedPacket { bytes: forwarded, _budget: budget });
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
        if !hub.allowed_pair(source, target, now) { return None; }
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
            expires: a.expires.min(b.expires),
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
    let mut response = ws
        .read_buffer_size(8192)
        .write_buffer_size(8192)
        .max_write_buffer_size(65536)
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |socket| {
            serve(
                app, socket, id, hash, instance, lane, lanes, batch, prefixes,
            )
        });
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
                let mut output=packet.bytes;
                if batch {
                    let mut records=vec![output];
                    while records.len()<32 {
                        match packets.try_recv(){Ok(packet)=>records.push(packet.bytes),Err(_)=>break}
                    }
                    let Ok(encoded)=porthub_mesh::batch::encode(&records,prefixes) else {break;};
                    output=encoded;
                }
                if !matches!(tokio::time::timeout(Duration::from_secs(3),socket.send(Message::Binary(output.into()))).await,Ok(Ok(()))){break;}
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
        let old=PairPeerPin{id:"b".into(),hash:"hash-b".into(),instance:"instance-b".into(),ip:remote,epoch:Some(b.clone()),generation:None};
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
        assert!(hub.publish_pair_admitted("b",&b,"hash-b","instance-b",target_read,&PairPeerPin{id:"a".into(),hash:"hash-a".into(),instance:"instance-a".into(),ip,epoch:Some(a.clone()),generation:None}));
        assert!(!hub.retire_pair_admitted("a","hash-a","instance-a",later,&observed));
        let observed=hub.observe_pairs("a","hash-a","instance-a",later).remove("b").unwrap();
        assert!(hub.retire_pair_admitted("a","hash-a","instance-a",later,&observed));
        assert!(!hub.pair_allowed("a","b"));assert!(hub.pair_allowed("a","c"));
        assert!(hub.admission_snapshot("b","hash-b","instance-b").is_none(),"target in-flight read must not reintroduce retired authority");
        assert!(!hub.publish_pair_admitted("b",&b,"hash-b","instance-b",target_read,&PairPeerPin{id:"a".into(),hash:"hash-a".into(),instance:"instance-a".into(),ip,epoch:Some(a.clone()),generation:None}));
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
        output.send(QueuedPacket { bytes: vec![0], _budget: hub.1.clone().acquire_owned().await.unwrap() }).await.unwrap();
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

        output.send(QueuedPacket { bytes: vec![0], _budget: hub.1.clone().acquire_owned().await.unwrap() }).await.unwrap();
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

}
