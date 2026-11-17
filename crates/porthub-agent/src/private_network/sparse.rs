//! Bounded sparse identity control/cache. Packet misses only enqueue intent; they never await HTTP.
use porthub_network::policy::{Lookup, PairLease, PeerInfo, Snapshot, MAX_PAIR_LEASES};
use std::{
    collections::{BTreeMap, HashSet},
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
const MAX_INTENTS: usize = 256;
#[derive(Clone)]
pub struct Handle {
    exit_picker: super::exit_picker::Handle,
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    revoked: Arc<AtomicBool>,
    demand: Arc<Notify>,
}
pub struct Control {
    handle: Handle,
    sequence: u64,
}
struct Cached {
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    stream_masks: Option<StreamMasks>,
    _retirement_owner:Option<super::authority_event::Owner>,
    _exit_retirement_owner:Option<super::authority_event::Owner>,
    exit_authority:Option<super::authority_event::Authority<()>>,
    private_active:bool,
    exit_active:bool,
    authority: Option<super::authority_event::Authority<()>>,
    lease: PairLease,
    deadline: Instant,
    last_used: Instant,
}
impl Cached {
    fn private_valid(&self,now:Instant)->bool {self.private_active&&self.deadline>now&&self.authority.as_ref().is_none_or(|a|a.check().is_ok())}
    fn exit_valid(&self,now:Instant)->bool {self.exit_active&&self.deadline>now&&self.exit_authority.as_ref().is_none_or(|a|a.check().is_ok())}
    fn valid(&self,now:Instant)->bool {self.private_valid(now)||self.exit_valid(now)}
    fn metadata_authority(&self,now:Instant)->Option<&super::authority_event::Authority<()>> {
        if self.private_valid(now){self.authority.as_ref()}else{self.exit_authority.as_ref()}
    }
}
struct Intent {
    used: Instant,
    sent: Option<Instant>,
    retry_after: Instant,
}
#[derive(Default)]
struct State {
    authority: Option<super::authority_event::Authority<()>>,
    epoch: Option<String>,
    exit_epoch:Option<String>,
    own:Option<(String,String,Ipv4Addr,String,String)>,
    deadline: Option<Instant>,
    cache: BTreeMap<String, Cached>,
    wanted: BTreeMap<Lookup, Intent>,
}
pub fn channel() -> (Handle, Control) {
    let handle = Handle {
        exit_picker: Default::default(),
        state: Default::default(),
        changed: Default::default(),
        revoked: Default::default(),
        demand: Default::default(),
    };
    (
        handle.clone(),
        Control {
            handle,
            sequence: 0,
        },
    )
}
// A routine renewal is not retirement. Keep its revocation domain only when
// identity/assignment/epoch/exact ACL is unchanged; each queued request still
// retains its own ORIGINAL expiry witness. Publication revision orders replies;
// it is not a permission/identity epoch. No grant/range expansion is needed.
fn same_pair_authority(a:&PairLease,b:&PairLease)->bool {
    let identity=|a:&PeerInfo,b:&PeerInfo|a.id==b.id&&a.ip==b.ip&&a.fingerprint==b.fingerprint&&a.instance==b.instance;
    a.workspace==b.workspace&&a.self_==b.self_&&a.epoch==b.epoch&&identity(&a.local,&b.local)&&identity(&a.peer,&b.peer)
        &&a.grants.len()==b.grants.len()&&a.grants.iter().zip(&b.grants).all(|(a,b)|a.source==b.source&&a.destination==b.destination&&a.protocol==b.protocol&&a.ports.len()==b.ports.len()&&a.ports.iter().zip(&b.ports).all(|(a,b)|a.start==b.start&&a.end==b.end))
        &&match (serde_json::to_vec(&a.acl),serde_json::to_vec(&b.acl)){(Ok(a),Ok(b))=>a==b,_=>false}
}

fn same_exit_authority(a:&PairLease,b:&PairLease)->bool {
    let identity=|a:&PeerInfo,b:&PeerInfo|a.id==b.id&&a.ip==b.ip&&a.fingerprint==b.fingerprint&&a.instance==b.instance;
    a.workspace==b.workspace&&a.self_==b.self_&&identity(&a.local,&b.local)&&identity(&a.peer,&b.peer)
        &&a.exit.as_ref().zip(b.exit.as_ref()).is_some_and(|(a,b)|a.epoch==b.epoch&&a.route_id==b.route_id&&a.client==b.client&&a.router==b.router&&a.traffic_mode==b.traffic_mode)
}
#[cfg(all(feature="private-sparse",feature="private-stream"))]
#[derive(Clone)]
pub(crate) struct StreamMasks {
    pub outgoing:porthub_network::policy::pair_acl::CompiledPortMask,
    pub incoming:porthub_network::policy::pair_acl::CompiledPortMask,
    pub outgoing_any:bool,
    pub incoming_any:bool,
}
#[cfg(all(feature="private-sparse",feature="private-stream"))]
impl StreamMasks {
    fn compile(lease:&PairLease)->Option<Self>{
        use porthub_network::policy::pair_acl::PairAcl;
        let acl=match &lease.acl{Some(acl)=>acl.clone(),None=>PairAcl::from_grants(&lease.self_,&lease.peer.id,&lease.grants).ok()?}.compile().ok()?;
        let outgoing=acl.tcp(false);let incoming=acl.tcp(true);
        Some(Self{outgoing_any:outgoing.any(),incoming_any:incoming.any(),outgoing,incoming})
    }
}
/// One locked cache read binds policy bytes and BOTH original witnesses.
/// Fields are private: callers cannot relabel a permit from another peer.
#[cfg(feature="private-sparse")]
pub(crate) struct BoundPairAuthority {lease:PairLease,permit:porthub_mesh::udp::SendPermit,
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    masks:Option<StreamMasks>,
}
#[cfg(feature="private-sparse")]
impl BoundPairAuthority {
    pub(crate) fn lease(&self)->&PairLease{&self.lease}
    #[cfg(all(feature="private-sparse",feature="private-stream"))]
    pub(crate) fn masks(&self)->Option<StreamMasks>{self.masks.clone()}
    pub(crate) fn permit(&self)->porthub_mesh::udp::SendPermit{self.permit.clone()}
}

/// Exit packets cannot borrow ordinary private-stream masks or retirement.
#[cfg(feature="private-sparse")]
pub(crate) struct BoundExitAuthority {lease:PairLease,permit:porthub_mesh::udp::SendPermit}
#[cfg(feature="private-sparse")]
impl BoundExitAuthority {
    pub(crate) fn lease(&self)->&PairLease{&self.lease}
    pub(crate) fn permit(&self)->porthub_mesh::udp::SendPermit{self.permit.clone()}
}
impl Handle {
    pub(crate) fn exit_picker(&self)->super::exit_picker::Handle { self.exit_picker.clone() }
    pub fn revoke_all(&self) {
        self.revoked.store(true, Ordering::SeqCst);
        self.exit_picker.revoke();
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.deadline = None;
        s.epoch = None;s.exit_epoch=None;s.own=None;
        s.cache.clear();
        s.wanted.clear();
        drop(s);
        self.changed.notify_waiters();
        self.demand.notify_waiters();
    }
    #[cfg(feature="private-sparse")]
    pub(crate) fn bound_pair_authority(&self,id:&str)->Option<BoundPairAuthority>{
        let state=self.state.lock().unwrap_or_else(|p|p.into_inner());
        if self.revoked()||state.deadline.is_none_or(|d|d<=Instant::now()){return None;}
        let base=state.authority.as_ref()?.clone();base.check().ok()?;base.remaining().ok()??;
        let cached=state.cache.get(id)?;
        if !cached.private_valid(Instant::now())||cached.lease.peer.id!=id||state.epoch.as_deref()!=Some(cached.lease.epoch.as_str())||cached.lease.self_!=cached.lease.local.id{return None;}
        let pair=cached.authority.as_ref()?.clone();pair.check().ok()?;pair.remaining().ok()??;
        let mut lease=cached.lease.clone();lease.exit=None; // Private-only authority view, never relabelled.
        let permit=porthub_mesh::udp::SendPermit::bounded(||true,move||Some(base.remaining().ok()??.min(pair.remaining().ok()??)));
        Some(BoundPairAuthority{lease,permit,
            #[cfg(all(feature="private-sparse",feature="private-stream"))]
            masks:cached.stream_masks.clone(),
        })
    }
    #[cfg(feature="private-sparse")]
    pub(crate) fn bound_exit_pair_authority(&self,id:&str)->Option<BoundExitAuthority>{
        let state=self.state.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if self.revoked()||state.deadline.is_none_or(|d|d<=now){return None;}
        let base=state.authority.as_ref()?.clone();base.check().ok()?;base.remaining().ok()??;
        let cached=state.cache.get(id)?;
        if !cached.exit_valid(now)||cached.lease.peer.id!=id||cached.lease.self_!=cached.lease.local.id
            ||state.exit_epoch.as_deref()!=Some(cached.lease.exit.as_ref()?.epoch.as_str()){return None;}
        let pair=cached.exit_authority.as_ref()?.clone();pair.check().ok()?;pair.remaining().ok()??;
        let permit=porthub_mesh::udp::SendPermit::bounded(||true,move||Some(base.remaining().ok()??.min(pair.remaining().ok()??)));
        let mut lease=cached.lease.clone();lease.grants.clear();lease.acl=None;
        Some(BoundExitAuthority{lease,permit})
    }
    pub(crate) fn exit_pair_authority(&self,id:&str)->Option<super::authority_event::Authority<()>> {
        let state=self.state.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if self.revoked()||state.deadline.is_none_or(|d|d<=now)||state.authority.as_ref().is_some_and(|a|a.check().is_err()){return None;}
        let cached=state.cache.get(id)?;
        if !cached.exit_valid(now)||state.exit_epoch.as_deref()!=Some(cached.lease.exit.as_ref()?.epoch.as_str()){return None;}
        let authority=cached.exit_authority.as_ref()?;authority.check().ok()?;Some(authority.clone())
    }
    /// Path measurements need a live authenticated peer, not application-port access.
    pub(crate) fn metadata_authority(&self,id:&str)->Option<super::authority_event::Authority<()>> {
        let state=self.state.lock().unwrap_or_else(|p|p.into_inner());let now=Instant::now();
        if self.revoked()||state.deadline.is_none_or(|d|d<=now)||state.authority.as_ref().is_some_and(|a|a.check().is_err()){return None;}
        let cached=state.cache.get(id)?;if !cached.valid(now){return None;}
        cached.metadata_authority(now).cloned()
    }
    pub(crate) fn pair_authority(&self,id:&str)->Option<super::authority_event::Authority<()>> {
        let s=self.state.lock().unwrap_or_else(|p|p.into_inner());
        if self.revoked()||s.authority.as_ref().is_some_and(|a|a.check().is_err()){return None;}
        let cached=s.cache.get(id)?;
        if !cached.private_valid(Instant::now())||s.epoch.as_deref()!=Some(cached.lease.epoch.as_str()){return None;}
        let authority=cached.authority.as_ref()?;authority.check().ok()?;Some(authority.clone())
    }
    pub(crate) fn authority_ttl(&self)->Option<u32> {
        let s=self.state.lock().unwrap_or_else(|p|p.into_inner());
        if self.revoked(){return None;}
        let left=match &s.authority {Some(authority)=>authority.remaining().ok()?.map(|left|left.as_secs()).unwrap_or(5),None=>5};
        (left>0).then_some(left.min(5) as u32)
    }
    pub(crate) fn authority_valid(&self)->bool {
        let s=self.state.lock().unwrap_or_else(|p|p.into_inner());
        !self.revoked() && s.authority.as_ref().is_none_or(|a|a.check().is_ok())
    }
    pub fn revoked(&self) -> bool {
        self.revoked.load(Ordering::SeqCst)
    }
    pub fn update_base(&self, snapshot: &Snapshot) { self.update_base_inner(snapshot,None); }
    pub(crate) fn update_base_authority(&self,snapshot:&Snapshot,authority:super::authority_event::Authority<()>) { self.update_base_inner(snapshot,Some(authority)); }
    fn update_base_inner(&self, snapshot: &Snapshot, authority:Option<super::authority_event::Authority<()>>) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if self.revoked() {
            return;
        }
        let epoch = snapshot.sparse.as_ref().map(|s| s.epoch.clone());
        let exit_epoch=snapshot.sparse.as_ref().and_then(|s|s.exit_epoch.clone());
        let own=snapshot.peers.iter().find(|p|p.id==snapshot.self_).map(|p|(snapshot.workspace.clone(),snapshot.self_.clone(),p.ip,p.fingerprint.clone(),p.instance.clone()));
        if s.own!=own||own.is_none(){s.cache.clear();}
        let now=Instant::now();
        for cached in s.cache.values_mut(){
            if epoch.as_deref()!=Some(cached.lease.epoch.as_str()) {
                cached.private_active=false;cached.authority=None;cached._retirement_owner=None;
                #[cfg(all(feature="private-sparse",feature="private-stream"))] {cached.stream_masks=None;}
            }
            if exit_epoch.as_deref().is_none_or(|epoch|cached.lease.exit.as_ref().is_none_or(|exit|exit.epoch!=epoch)) {
                cached.exit_active=false;cached.exit_authority=None;cached._exit_retirement_owner=None;
            }
        }
        s.cache.retain(|_,cached|cached.valid(now));s.exit_epoch=exit_epoch;s.own=own;
        s.epoch = epoch;
        s.authority = authority;
        s.deadline = snapshot
            .expires_at
            .signed_duration_since(chrono::Utc::now())
            .to_std()
            .ok()
            .map(|left| Instant::now() + left);
        if s.epoch.is_none() {
            s.cache.clear();
            s.wanted.clear();
        }
        drop(s);
        self.changed.notify_waiters();
    }
    fn peer(&self, select: impl Fn(&PeerInfo) -> bool) -> Option<PeerInfo> {
        let mut s = self.state.try_lock().ok()?;
        let now = Instant::now();
        if s.epoch.is_none() || s.deadline.is_none_or(|d| d <= now) || s.authority.as_ref().is_some_and(|a|a.check().is_err()) {
            return None;
        }
        let hit = s
            .cache
            .values_mut()
            .find(|c| select(&c.lease.peer) && c.valid(now))?;
        hit.last_used = now;
        Some(hit.lease.peer.clone())
    }
    pub fn dns_ttl(&self, ip: Ipv4Addr) -> Option<u32> {
        let s = self.state.try_lock().ok()?;
        let now = Instant::now();
        if s.authority.as_ref().is_some_and(|a|a.check().is_err()){return None;}
        let base = s.deadline?;
        let peer = s
            .cache
            .values()
            .find(|c| c.lease.peer.ip == ip && c.valid(now))?;
        let mut remaining=peer.deadline.min(base).checked_duration_since(now)?;
        for authority in [s.authority.as_ref(),peer.metadata_authority(now)].into_iter().flatten(){
            if let Some(left)=authority.remaining().ok()? {remaining=remaining.min(left);}
        }
        let remaining=remaining.as_secs();
        (remaining > 0).then_some(remaining.min(5) as u32)
    }
    pub fn by_ip(&self, ip: Ipv4Addr) -> Option<PeerInfo> {
        self.peer(|p| p.ip == ip)
    }
    pub fn by_id(&self, id: &str) -> Option<PeerInfo> {
        self.peer(|p| p.id == id)
    }
    pub fn enabled(&self) -> bool {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        !self.revoked() && s.epoch.is_some()
    }
    pub fn leases(&self) -> Vec<PairLease> {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if s.authority.as_ref().is_some_and(|a|a.check().is_err()){return Vec::new();}
        let now = Instant::now();
        s.cache
            .values()
            .filter(|c| c.private_valid(now))
            .map(|c| {let mut lease=c.lease.clone();if !c.exit_valid(now){lease.exit=None;}lease})
            .collect()
    }
    pub fn peers(&self) -> Vec<PeerInfo> {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if s.epoch.is_none() || s.deadline.is_none_or(|d| d <= now) || s.authority.as_ref().is_some_and(|a|a.check().is_err()) {
            return Vec::new();
        }
        s.cache
            .values()
            .filter(|p| p.valid(now))
            .map(|p| p.lease.peer.clone())
            .collect()
    }
    /// Usage affects renewal eligibility only, never locally extends authority.
    pub fn touch_peer(&self, id: &str) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            return false;
        };
        let now = Instant::now();
        if self.revoked() || state.deadline.is_none_or(|d| d <= now) || state.authority.as_ref().is_some_and(|a|a.check().is_err()) {
            return false;
        }
        let Some(cached) = state.cache.get_mut(id).filter(|c| c.valid(now)) else {
            return false;
        };
        cached.last_used = now;
        true
    }
    pub fn request_ip(&self, ip: Ipv4Addr) -> bool {
        ip.is_private()
            && self.request(Lookup {
                kind: "ip".into(),
                value: ip.to_string(),
            })
    }
    pub fn request_peer(&self, id: &str) -> bool {
        !id.is_empty()
            && id.len() <= 60
            && self.request(Lookup {
                kind: "peer".into(),
                value: id.into(),
            })
    }
    pub fn request(&self, query: Lookup) -> bool {
        let Ok(mut s) = self.state.try_lock() else {
            return false;
        };
        let now = Instant::now();
        if s.epoch.is_none() || s.deadline.is_none_or(|d| d <= now) || s.authority.as_ref().is_some_and(|a|a.check().is_err()) {
            return false;
        }
        if !s.wanted.contains_key(&query) && s.wanted.len() >= MAX_INTENTS {
            return false;
        }
        s.wanted
            .entry(query)
            .and_modify(|i| i.used = now)
            .or_insert(Intent {
                used: now,
                sent: None,
                retry_after: now,
            });
        drop(s);
        self.demand.notify_one();
        true
    }
    /// Called only by the packet owner AFTER Engine and native /32 route installation succeed.
    pub fn installed(&self, query: &Lookup, lease: PairLease) {self.installed_inner(query,lease,None);}
    pub(crate) fn installed_authority(&self,query:&Lookup,lease:PairLease,authority:super::authority_event::Authority<()>) {self.installed_inner(query,lease,Some(authority));}
    fn installed_inner(&self, query: &Lookup, lease: PairLease, authority:Option<super::authority_event::Authority<()>>) {
        // Compile once at publication, before acquiring the cache lock. Packet
        // owners clone immutable bitmaps but always sample fresh authorities.
        #[cfg(all(feature="private-sparse",feature="private-stream"))]
        let stream_masks=StreamMasks::compile(&lease);
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if self.revoked()
            || s.epoch.as_deref() != Some(&lease.epoch)
            || lease.self_!=lease.local.id
            || s.own.as_ref().is_none_or(|own|own.0!=lease.workspace||own.1!=lease.self_||own.2!=lease.local.ip||own.3!=lease.local.fingerprint||own.4!=lease.local.instance)
            || lease.exit.as_ref().is_some_and(|exit|s.exit_epoch.as_deref()!=Some(exit.epoch.as_str()))
            || s.deadline.is_none_or(|d| d <= now)
            || s.authority.as_ref().is_some_and(|a|a.check().is_err())
            || authority.as_ref().is_some_and(|a|a.check().is_err())
        {
            return;
        }
        let Ok(left) = lease
            .expires_at
            .signed_duration_since(chrono::Utc::now())
            .to_std()
        else {
            return;
        };
        s.cache.retain(|_, c| c.valid(now));
        if !s.cache.contains_key(&lease.peer.id) && s.cache.len() >= MAX_PAIR_LEASES {
            return;
        }
        let used = s
            .cache
            .get(&lease.peer.id)
            .map(|c| c.last_used)
            .unwrap_or(now);
        let mut previous=s.cache.remove(&lease.peer.id);
        let retained_owner=if authority.is_some(){previous.as_mut().filter(|cached|cached.private_active&&same_pair_authority(&cached.lease,&lease)).and_then(|cached|cached._retirement_owner.take())}else{None};
        let retained_exit_owner=if authority.is_some(){previous.as_mut().filter(|cached|cached.exit_active&&same_exit_authority(&cached.lease,&lease)).and_then(|cached|cached._exit_retirement_owner.take())}else{None};
        let exit_retirement_owner=retained_exit_owner.or_else(||if lease.exit.is_some(){authority.as_ref().map(|_|super::authority_event::Owner::new())}else{None});
        let exit_authority=authority.clone().zip(exit_retirement_owner.as_ref()).map(|(authority,owner)|authority.retired_with(owner.domain()));
        let retirement_owner=retained_owner.or_else(||authority.as_ref().map(|_|super::authority_event::Owner::new()));
        let authority=authority.zip(retirement_owner.as_ref()).map(|(authority,owner)|authority.retired_with(owner.domain()));
        s.cache.insert(
            lease.peer.id.clone(),
            Cached {
                #[cfg(all(feature="private-sparse",feature="private-stream"))]
                stream_masks,
                _retirement_owner:retirement_owner,
                _exit_retirement_owner:exit_retirement_owner,
                exit_authority,private_active:true,exit_active:lease.exit.is_some(),
                authority,
                lease,
                deadline: now + left,
                last_used: used,
            },
        );
        s.wanted.remove(query);
        drop(s);
        self.changed.notify_waiters();
    }
    pub fn cached_query(&self, query: &Lookup) -> Option<PeerInfo> {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if s.authority.as_ref().is_some_and(|a|a.check().is_err()){return None;}
        let now = Instant::now();
        s.cache
            .values()
            .find(|c| {
                c.valid(now)
                    && match query.kind.as_str() {
                        "peer" => c.lease.peer.id == query.value,
                        "ip" => c.lease.peer.ip.to_string() == query.value,
                        "name" => {
                            let name = query.value.trim_end_matches('.');
                            c.lease.peer.hostname.eq_ignore_ascii_case(name)
                                || c.lease
                                    .peer
                                    .aliases
                                    .iter()
                                    .any(|a| a.eq_ignore_ascii_case(name))
                        }
                        _ => false,
                    }
            })
            .map(|c| c.lease.peer.clone())
    }
    pub fn retire(&self, id: &str) {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .cache
            .remove(id);
        self.changed.notify_waiters();
    }
    pub fn unavailable(&self, query: &Lookup) {
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(i) = s.wanted.get_mut(query) {
            i.retry_after = Instant::now() + Duration::from_secs(2);
        }
        drop(s);
        self.changed.notify_waiters();
    }
    pub async fn resolve_name(&self, name: &str) -> Option<PeerInfo> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let query = Lookup {
            kind: "name".into(),
            value: name.clone(),
        };
        let wait = async {
            loop {
                let notified = self.changed.notified();
                if let Some(peer) = self.peer(|p| {
                    p.hostname.eq_ignore_ascii_case(&name)
                        || p.aliases.iter().any(|a| a.eq_ignore_ascii_case(&name))
                }) {
                    return Some(peer);
                }
                if !self.request(query.clone()) {
                    return None;
                }
                notified.await;
            }
        };
        tokio::time::timeout(Duration::from_secs(3), wait)
            .await
            .ok()
            .flatten()
    }
}
/// This helper is shared by the native packet owner and no-device lifecycle regressions.
/// Only an authenticated authoritative denial retires a pair; overload/temporary failures do not.
pub fn apply_denial(
    handle: &Handle,
    policy: &mut porthub_network::policy::Engine,
    response: &porthub_network::policy::PairResponse,
) -> Option<PeerInfo> {
    if response.status != "unavailable" && response.status != "policy_capacity" {
        return None;
    }
    let peer = handle.cached_query(&response.query)?;
    policy.revoke_pair(&peer.id);
    handle.retire(&peer.id);
    Some(peer)
}
impl Control {
    pub async fn demand(&self) {
        self.handle.demand.notified().await;
    }
    pub fn urgent(&self) -> bool {
        let s = self.handle.state.lock().unwrap_or_else(|p| p.into_inner());
        !s.wanted.is_empty() || s.cache.values().any(|c| c.deadline > Instant::now())
    }
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }
    pub fn batch(&mut self) -> anyhow::Result<serde_json::Value> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("sparse sequence exhausted"))?;
        let mut s = self.handle.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        s.cache.retain(|_, c| c.valid(now));
        s.wanted
            .retain(|_, i| now.saturating_duration_since(i.used) < Duration::from_secs(30));
        let mut renew: Vec<_> = s
            .cache
            .values()
            .filter(|c| {
                now.saturating_duration_since(c.last_used) < Duration::from_secs(30)
                    && c.deadline <= now + Duration::from_secs(10)
            })
            .map(|c| {
                (
                    c.deadline,
                    Lookup {
                        kind: "peer".into(),
                        value: c.lease.peer.id.clone(),
                    },
                )
            })
            .collect();
        renew.sort_by_key(|p| p.0);
        let mut misses: Vec<_> = s
            .wanted
            .iter()
            .filter(|(_, i)| {
                i.retry_after <= now
                    && i.sent
                        .is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(1))
            })
            .map(|(q, i)| (i.sent, q.clone()))
            .collect();
        misses.sort_by_key(|p| p.0);
        let mut wanted = Vec::new();
        let mut seen = HashSet::new();
        // Give due renewals most slots, while reserving bounded progress for cold new destinations.
        for (_, q) in renew
            .into_iter()
            .take(if misses.is_empty() { 16 } else { 12 })
        {
            if seen.insert(q.clone()) {
                wanted.push(q);
            }
        }
        for (_, q) in misses {
            if wanted.len() >= 16 {
                break;
            }
            if seen.insert(q.clone()) {
                if let Some(i) = s.wanted.get_mut(&q) {
                    i.sent = Some(now);
                }
                wanted.push(q);
            }
        }
        Ok(serde_json::json!({"protocol":1,"sequence":self.sequence,"wanted":wanted}))
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base(epoch: &str) -> Snapshot {
        serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),"sparse":{"protocol":1,"epoch":epoch},"peers":[{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"}],"grants":[]})).unwrap()
    }
    fn lease(epoch: &str) -> PairLease {
        serde_json::from_value(serde_json::json!({"workspace":"w","self":"a","epoch":epoch,"revision":1,"expires_at":chrono::Utc::now()+chrono::Duration::seconds(15),"local":{"id":"a","ip":"10.203.0.2","fingerprint":"local","instance":"local-instance","hostname":"a.phub"},"peer":{"id":"b","ip":"10.203.1.2","fingerprint":"remote","instance":"remote-instance","hostname":"b.phub","aliases":["alias.phub"]},"grants":[{"source":"a","destination":"b","protocol":"any","ports":[]}]})).unwrap()
    }
    #[cfg(feature="private-sparse")]
    #[test]
    fn refreshed_base_cannot_extend_pair_dns_or_identity_across_simulated_suspend() {
        use std::sync::atomic::AtomicU64;
        struct Clock(AtomicU64);
        impl super::super::authority_clock::SuspendClock for Clock {
            fn elapsed_since_boot(&self)->anyhow::Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}
        }
        let clock=Arc::new(Clock(AtomicU64::new(0)));
        let witness=||super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap();
        let epoch="a".repeat(64);let base=base(&epoch);let pair=lease(&epoch);
        let (h,_)=channel();
        h.update_base_authority(&base,super::super::authority_event::Authority::new((),Some(witness()),base.expires_at));
        let query=Lookup{kind:"name".into(),value:"b.phub".into()};
        h.installed_authority(&query,pair.clone(),super::super::authority_event::Authority::new((),Some(witness()),pair.expires_at));
        assert!(h.by_id("b").is_some());assert!(h.dns_ttl(pair.peer.ip).is_some());
        clock.0.store(10000,Ordering::SeqCst);
        h.update_base_authority(&base,super::super::authority_event::Authority::new((),Some(witness()),base.expires_at));
        clock.0.store(14999,Ordering::SeqCst);
        assert!(h.by_id("b").is_some());assert!(h.dns_ttl(pair.peer.ip).is_none(),"DNS must not cache beyond request lifetime");
        clock.0.store(15000,Ordering::SeqCst);
        assert!(h.authority_valid());assert!(h.by_id("b").is_none());assert!(h.by_ip(pair.peer.ip).is_none());
        assert!(h.cached_query(&query).is_none());assert!(h.dns_ttl(pair.peer.ip).is_none());
        assert!(h.peers().is_empty());assert!(h.leases().is_empty());assert!(!h.touch_peer("b"));
        let mut zone=super::super::dns::Zone::default();zone.set_sparse(h.clone());zone.update(&base).unwrap();
        use hickory_proto::{op::{Message,MessageType,OpCode,Query,ResponseCode},rr::{Name,RecordType}};
        let mut question=Message::new(1,MessageType::Query,OpCode::Query);
        question.add_query(Query::query(Name::from_ascii("a.phub").unwrap(),RecordType::A));let bytes=question.to_vec().unwrap();
        assert_eq!(Message::from_vec(&zone.answer(&bytes).unwrap()).unwrap().answers.len(),1);
        clock.0.store(25000,Ordering::SeqCst);
        let response=Message::from_vec(&zone.answer(&bytes).unwrap()).unwrap();
        assert_eq!(response.metadata.response_code,ResponseCode::ServFail);assert!(response.answers.is_empty());
        assert!(!h.authority_valid());assert!(!h.request_peer("b"));
    }
    #[cfg(feature="private-sparse")]
    #[test]
    fn actual_pair_cache_retirement_revokes_old_queued_permit_without_reviving_on_reinstall() {
        let (handle,_)=channel();let epoch="a".repeat(64);let base=base(&epoch);let pair=lease(&epoch);
        let witness=||super::super::authority_event::request_start(None).unwrap();
        let expiry=pair.expires_at;
        let authority=||super::super::authority_event::Authority::new((),witness(),expiry);
        handle.update_base_authority(&base,authority());let query=Lookup{kind:"peer".into(),value:"b".into()};
        handle.installed_authority(&query,pair.clone(),authority());let old=handle.pair_authority("b").unwrap();assert!(old.check().is_ok());
        handle.retire("b");assert!(old.check().is_err());
        handle.installed_authority(&query,pair,authority());assert!(handle.pair_authority("b").unwrap().check().is_ok());assert!(old.check().is_err());
    }
    #[cfg(feature="private-sparse")]
    #[test]
    fn ordinary_identical_pair_renewal_preserves_domain_but_never_extends_old_request_window() {
        struct Clock(std::sync::atomic::AtomicU64);
        impl super::super::authority_clock::SuspendClock for Clock {fn elapsed_since_boot(&self)->anyhow::Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}}
        let clock=Arc::new(Clock(std::sync::atomic::AtomicU64::new(0)));
        let expiry=chrono::Utc::now()+chrono::Duration::seconds(30);
        let authority=||super::super::authority_event::Authority::new((),Some(super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap()),expiry);
        let(handle,_)=channel();let epoch="a".repeat(64);handle.update_base_authority(&base(&epoch),authority());
        let pair=lease(&epoch);let query=Lookup{kind:"peer".into(),value:"b".into()};
        handle.installed_authority(&query,pair.clone(),authority());let old=handle.pair_authority("b").unwrap();
        clock.0.store(10000,Ordering::SeqCst);handle.update_base_authority(&base(&epoch),authority());handle.installed_authority(&query,{let mut renewed=pair.clone();renewed.revision+=1;renewed},authority());
        assert!(old.check().is_ok(),"identical renewal must not spuriously retire live operations");
        clock.0.store(15000,Ordering::SeqCst);assert!(old.check().is_err());let fresh=handle.pair_authority("b").unwrap();assert!(fresh.check().is_ok());
        let mut changed=pair;changed.grants.clear();handle.installed_authority(&query,changed,authority());assert!(fresh.check().is_err(),"changed ACL retires the old domain");
    }
    #[cfg(feature="private-sparse")]
    struct ExitClock(std::sync::atomic::AtomicU64);
    #[cfg(feature="private-sparse")]
    impl super::super::authority_clock::SuspendClock for ExitClock {
        fn elapsed_since_boot(&self)->anyhow::Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}
    }
    #[cfg(feature="private-sparse")]
    fn exit_base(private:&str,exit:&str)->Snapshot {
        let mut snapshot=base(private);snapshot.sparse.as_mut().unwrap().exit_epoch=Some(exit.into());
        snapshot.sparse.as_mut().unwrap().capture_pools=vec!["10.203.0.0/16".parse().unwrap()];snapshot
    }
    #[cfg(feature="private-sparse")]
    fn exit_lease(private:&str,exit:&str)->PairLease {
        let mut pair=lease(private);pair.exit=Some(porthub_network::policy::ExitPair{epoch:exit.into(),route_id:"exit-route".into(),client:"a".into(),router:"b".into(),traffic_mode:porthub_mesh::exit_policy::TrafficMode::InternetOnly});pair
    }
    #[cfg(feature="private-sparse")]
    #[test]
    fn cached_permission_classes_retire_independently_and_epoch_roundtrip_never_revives_old_permits() {
        let clock=Arc::new(ExitClock(std::sync::atomic::AtomicU64::new(0)));
        let authority=|expiry|super::super::authority_event::Authority::new((),Some(super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap()),expiry);
        let a="a".repeat(64);let b="b".repeat(64);let e="e".repeat(64);let f="f".repeat(64);let(handle,_)=channel();
        let query=Lookup{kind:"peer".into(),value:"b".into()};let snapshot=exit_base(&a,&e);let pair=exit_lease(&a,&e);
        handle.update_base_authority(&snapshot,authority(snapshot.expires_at));handle.installed_authority(&query,pair.clone(),authority(pair.expires_at));
        let old_private=handle.bound_pair_authority("b").unwrap();let old_exit=handle.bound_exit_pair_authority("b").unwrap();
        assert!(old_private.lease().exit.is_none());assert!(old_exit.lease().grants.is_empty()&&old_exit.lease().acl.is_none());
        assert!(old_private.permit().valid()&&old_exit.permit().valid());
        let original_deadline=handle.state.lock().unwrap().cache["b"].deadline;
        clock.0.store(10000,Ordering::SeqCst);let changed=exit_base(&b,&e);handle.update_base_authority(&changed,authority(changed.expires_at));
        assert_eq!(handle.state.lock().unwrap().cache["b"].deadline,original_deadline);
        assert!(!old_private.permit().valid());assert!(old_exit.permit().valid());
        assert!(handle.bound_pair_authority("b").is_none());assert_eq!(handle.bound_exit_pair_authority("b").unwrap().lease().epoch,a,"cached immutable lease was relabelled");
        assert!(handle.by_id("b").is_some());assert!(handle.leases().is_empty());
        handle.update_base_authority(&snapshot,authority(snapshot.expires_at));assert!(handle.bound_pair_authority("b").is_none(),"ordinary epoch roundtrip revived retired bytes");
        handle.update_base_authority(&changed,authority(changed.expires_at));
        let renewed=exit_lease(&b,&e);handle.installed_authority(&query,renewed.clone(),authority(renewed.expires_at));
        let fresh_private=handle.bound_pair_authority("b").unwrap();let fresh_exit=handle.bound_exit_pair_authority("b").unwrap();
        assert!(old_exit.permit().valid(),"unchanged genuine exit renewal retired old queued receipt before its deadline");
        let changed_exit=exit_base(&b,&f);handle.update_base_authority(&changed_exit,authority(changed_exit.expires_at));
        assert!(fresh_private.permit().valid());assert!(!fresh_exit.permit().valid()&&!old_exit.permit().valid());
        assert!(handle.leases()[0].exit.is_none(),"inactive exit poisoned private validator view");
        handle.update_base_authority(&changed,authority(changed.expires_at));assert!(handle.bound_exit_pair_authority("b").is_none(),"exit epoch roundtrip revived retired bytes");
        let mut new_source=changed;new_source.peers[0].instance="replacement-source".into();handle.update_base_authority(&new_source,authority(new_source.expires_at));
        assert!(!fresh_private.permit().valid());assert!(handle.by_id("b").is_none());
        handle.installed_authority(&query,renewed.clone(),authority(renewed.expires_at));assert!(handle.by_id("b").is_none(),"old source receipt was republished under replacement source");
    }
    #[cfg(feature="private-sparse")]
    #[test]
    fn exit_receipt_retains_original_suspend_clock_across_new_private_base() {
        let clock=Arc::new(ExitClock(std::sync::atomic::AtomicU64::new(0)));
        let authority=|expiry|super::super::authority_event::Authority::new((),Some(super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap()),expiry);
        let a="a".repeat(64);let b="b".repeat(64);let e="e".repeat(64);let(handle,mut control)=channel();
        let snapshot=exit_base(&a,&e);let pair=exit_lease(&a,&e);let query=Lookup{kind:"peer".into(),value:"b".into()};
        handle.update_base_authority(&snapshot,authority(snapshot.expires_at));handle.installed_authority(&query,pair.clone(),authority(pair.expires_at));
        let queued=handle.bound_exit_pair_authority("b").unwrap();
        clock.0.store(10000,Ordering::SeqCst);let changed=exit_base(&b,&e);handle.update_base_authority(&changed,authority(changed.expires_at));
        assert!(queued.permit().valid());assert!(handle.dns_ttl(pair.peer.ip).is_some());assert!(handle.touch_peer("b"));
        clock.0.store(15000,Ordering::SeqCst);
        assert!(handle.authority_valid());assert!(!queued.permit().valid());assert!(handle.bound_exit_pair_authority("b").is_none());
        assert!(handle.by_id("b").is_none()&&handle.dns_ttl(pair.peer.ip).is_none());
        control.batch().unwrap();assert!(handle.state.lock().unwrap().cache.is_empty());
    }
    #[cfg(feature="private-sparse")]
    #[test]
    fn publication_revision_is_not_revocation_but_changed_peer_identity_is() {
        let pair=lease(&"a".repeat(64));
        let mut renewed=pair.clone();renewed.revision+=1;
        assert!(same_pair_authority(&pair,&renewed));
        for field in 0..3 {
            let mut replaced=renewed.clone();
            match field {0=>replaced.peer.fingerprint="replacement".into(),1=>replaced.peer.instance="replacement".into(),_=>replaced.peer.ip="10.203.1.3".parse().unwrap()}
            assert!(!same_pair_authority(&pair,&replaced));
        }
        renewed.grants.clear();assert!(!same_pair_authority(&pair,&renewed));
    }
    #[cfg(feature="private-sparse")]
    #[test]
    fn bound_pair_view_cannot_mix_new_metadata_with_old_or_other_peer_authority(){
        struct Clock(std::sync::atomic::AtomicU64);impl super::super::authority_clock::SuspendClock for Clock{fn elapsed_since_boot(&self)->anyhow::Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}}
        let clock=Arc::new(Clock(std::sync::atomic::AtomicU64::new(0)));let expiry=chrono::Utc::now()+chrono::Duration::seconds(60);let authority=||super::super::authority_event::Authority::new((),Some(super::super::authority_clock::RequestWindow::start(clock.clone()).unwrap()),expiry);
        let (handle,_)=channel();let epoch="a".repeat(64);let query=Lookup{kind:"peer".into(),value:"b".into()};handle.update_base_authority(&base(&epoch),authority());handle.installed_authority(&query,lease(&epoch),authority());
        let old=handle.bound_pair_authority("b").unwrap();assert_eq!(old.lease().peer.id,"b");assert!(handle.bound_pair_authority("foreign").is_none());
        clock.0.store(10000,Ordering::SeqCst);let mut changed=lease(&epoch);changed.peer.instance="new-instance".into();handle.update_base_authority(&base(&epoch),authority());handle.installed_authority(&query,changed,authority());
        assert!(!old.permit().valid());let fresh=handle.bound_pair_authority("b").unwrap();assert_eq!(fresh.lease().peer.instance,"new-instance");clock.0.store(15000,Ordering::SeqCst);assert!(fresh.permit().valid());clock.0.store(25000,Ordering::SeqCst);assert!(!fresh.permit().valid());assert!(handle.bound_pair_authority("b").is_none());
    }
    #[test]
    fn miss_intents_deduplicate_and_stop_at_a_hard_bound() {
        let (h, mut c) = channel();
        h.update_base(&base(&"a".repeat(64)));
        for i in 0..256 {
            assert!(h.request_peer(&format!("peer-{i}")));
        }
        assert!(!h.request_peer("overflow"));
        assert!(h.request_peer("peer-0"));
        assert_eq!(c.batch().unwrap()["wanted"].as_array().unwrap().len(), 16);
        assert_eq!(h.state.lock().unwrap().wanted.len(), 256);
    }
    #[test]
    fn base_refresh_cannot_extend_pair_and_old_epoch_completion_is_discarded() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        h.update_base(&base(&epoch));
        let q = Lookup {
            kind: "name".into(),
            value: "b.phub".into(),
        };
        h.installed(&q, lease(&epoch));
        let deadline = h.state.lock().unwrap().cache["b"].deadline;
        h.update_base(&base(&epoch));
        assert_eq!(h.state.lock().unwrap().cache["b"].deadline, deadline);
        h.update_base(&base(&"b".repeat(64)));
        h.installed(&q, lease(&epoch));
        assert!(h.by_id("b").is_none());
    }
    #[test]
    fn expired_pair_has_no_dns_answer_or_route_identity_even_if_base_is_valid() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        h.update_base(&base(&epoch));
        h.installed(
            &Lookup {
                kind: "peer".into(),
                value: "b".into(),
            },
            lease(&epoch),
        );
        assert_eq!(h.by_ip("10.203.1.2".parse().unwrap()).unwrap().id, "b");
        h.state.lock().unwrap().cache.get_mut("b").unwrap().deadline =
            Instant::now() - Duration::from_secs(1);
        assert!(h.by_id("b").is_none());
        assert!(h.dns_ttl("10.203.1.2".parse().unwrap()).is_none());
    }
    #[tokio::test]
    async fn names_wait_for_packet_owner_installation_and_accept_no_early_answer() {
        let epoch = "a".repeat(64);
        let (h, mut c) = channel();
        h.update_base(&base(&epoch));
        let resolve = h.clone();
        let task = tokio::spawn(async move { resolve.resolve_name("alias.phub.").await });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        let batch = c.batch().unwrap();
        assert_eq!(batch["wanted"][0]["kind"], "name");
        h.installed(
            &Lookup {
                kind: "name".into(),
                value: "alias.phub".into(),
            },
            lease(&epoch),
        );
        assert_eq!(task.await.unwrap().unwrap().id, "b");
    }
    #[test]
    fn active_flow_usage_renews_eligibility_without_extending_deadline_and_revoke_is_terminal() {
        let epoch = "a".repeat(64);
        let (h, mut control) = channel();
        let base = base(&epoch);
        h.update_base(&base);
        let query = Lookup {
            kind: "peer".into(),
            value: "b".into(),
        };
        let lease = lease(&epoch);
        h.installed(&query, lease.clone());
        let deadline = {
            let mut state = h.state.lock().unwrap();
            let cached = state.cache.get_mut("b").unwrap();
            cached.last_used = Instant::now() - Duration::from_secs(31);
            cached.deadline = Instant::now() + Duration::from_secs(5);
            cached.deadline
        };
        assert!(control.batch().unwrap()["wanted"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(h.touch_peer("b"));
        assert_eq!(h.state.lock().unwrap().cache["b"].deadline, deadline);
        assert_eq!(control.batch().unwrap()["wanted"][0]["value"], "b");
        h.revoke_all();
        h.update_base(&base);
        h.installed(&query, lease);
        assert!(!h.enabled());
        assert!(!h.touch_peer("b"));
        assert!(h.peers().is_empty());
        assert!(h.by_id("b").is_none());
    }
    #[test]
    fn authoritative_denial_retires_only_matching_pair_but_busy_and_invalid_do_not() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        let base = base(&epoch);
        h.update_base(&base);
        let pair = lease(&epoch);
        let mut engine = porthub_network::policy::Engine::default();
        engine.apply(base).unwrap();
        engine.install_pair(pair.clone()).unwrap();
        let query = Lookup {
            kind: "peer".into(),
            value: "b".into(),
        };
        h.installed(&query, pair.clone());
        for status in ["busy", "invalid"] {
            let response = porthub_network::policy::PairResponse {
                query: query.clone(),
                status: status.into(),
                lease: None,
            };
            assert!(apply_denial(&h, &mut engine, &response).is_none());
            assert!(engine.pair_peer("b").is_some());
        }
        for status in ["unavailable", "policy_capacity"] {
            engine.install_pair(pair.clone()).unwrap();
            h.installed(&query, pair.clone());
            let response = porthub_network::policy::PairResponse {
                query: query.clone(),
                status: status.into(),
                lease: None,
            };
            assert_eq!(apply_denial(&h, &mut engine, &response).unwrap().id, "b");
            assert!(engine.pair_peer("b").is_none());
            assert!(engine.valid_lease());
        }
    }
    #[tokio::test]
    async fn whole_source_revocation_clears_cache_and_wakes_waiting_name_without_extending_ttl() {
        let epoch = "a".repeat(64);
        let (h, _) = channel();
        h.update_base(&base(&epoch));
        h.installed(
            &Lookup {
                kind: "peer".into(),
                value: "b".into(),
            },
            lease(&epoch),
        );
        let handle = h.clone();
        let waiting = tokio::spawn(async move { handle.resolve_name("unknown.phub").await });
        tokio::task::yield_now().await;
        h.revoke_all();
        assert!(h.revoked());
        assert!(h.peers().is_empty());
        assert!(!h.request_peer("b"));
        assert!(tokio::time::timeout(Duration::from_millis(100), waiting)
            .await
            .unwrap()
            .unwrap()
            .is_none());
    }
}
