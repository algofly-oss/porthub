//! Profile-bound native ownership contracts. An adapter name is never ownership.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

/// A stale NRPT rule must never point at an address that can become a LAN host
/// after the TUN disappears. Binding is exclusive; collisions fail, never reuse.
pub(super) fn dns_endpoint(own: Ipv4Addr) -> Ipv4Addr {
    let bytes = own.octets();
    Ipv4Addr::new(127, bytes[1], bytes[2], bytes[3])
}

// Preserve the prior maximum baseline by itself; do not spend peer capacity on
// the OS's own interface rows. Peer caps themselves remain unchanged.
pub(super) const MAX_BASELINE_ROUTES: usize = 320;
pub(super) const MAX_LEGACY_HOSTS: usize = porthub_network::policy::MAX_SNAPSHOT_PEERS - 1;
pub(super) const MAX_SPARSE_HOSTS: usize = porthub_network::policy::MAX_PAIR_LEASES;
pub(super) const MAX_HOST_CLAIMS: usize = if MAX_LEGACY_HOSTS > MAX_SPARSE_HOSTS {
    MAX_LEGACY_HOSTS
} else {
    MAX_SPARSE_HOSTS
};
pub(super) const MAX_CAPTURE_CLAIMS: usize = porthub_network::capture_routes::MAX_CAPTURE_PREFIXES;
pub(super) const MAX_EXPLICIT_CLAIMS: usize = MAX_HOST_CLAIMS + 2 * MAX_CAPTURE_CLAIMS;
pub(super) const MAX_ROUTES: usize = MAX_BASELINE_ROUTES + MAX_EXPLICIT_CLAIMS;
pub(super) const MAX_LEDGER_BYTES: usize = 512 * 1024;
#[derive(Clone, Copy, Debug)]
pub(super) enum HostAdmission {
    Legacy,
    Sparse,
}
impl HostAdmission {
    pub fn limit(self) -> usize {
        match self {
            Self::Legacy => MAX_LEGACY_HOSTS,
            Self::Sparse => MAX_SPARSE_HOSTS,
        }
    }
}
pub(super) struct HostRoutePlan {
    pub wanted: BTreeSet<Ipv4Addr>,
    pub removals: Vec<Ipv4Addr>,
    pub additions: Vec<Ipv4Addr>,
}
pub(super) fn plan_hosts(
    own: Ipv4Addr,
    peers: &[Ipv4Addr],
    admission: HostAdmission,
    current: impl IntoIterator<Item = Ipv4Addr>,
) -> Result<HostRoutePlan> {
    ensure!(
        own.is_private()
            && peers.len() <= admission.limit() + 1
            && peers.iter().all(Ipv4Addr::is_private),
        "private host route input exceeds existing policy capacity or is invalid"
    );
    let wanted: BTreeSet<_> = peers.iter().copied().filter(|ip| *ip != own).collect();
    ensure!(
        wanted.len() <= admission.limit(),
        "private host routes exceed existing policy capacity"
    );
    let current: BTreeSet<_> = current.into_iter().collect();
    ensure!(
        current.len() <= MAX_EXPLICIT_CLAIMS && current.iter().all(Ipv4Addr::is_private),
        "owned host route recovery exceeds bounded ledger capacity"
    );
    Ok(HostRoutePlan {
        removals: current.difference(&wanted).copied().collect(),
        additions: wanted.difference(&current).copied().collect(),
        wanted,
    })
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RouteStamp {
    pub address: IpAddr,
    pub prefix: u8,
    pub gateway: Option<IpAddr>,
    pub metric: u32,
}
impl RouteStamp {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.prefix <= if self.address.is_ipv4() { 32 } else { 128 },
            "invalid owned route prefix"
        );
        ensure!(
            self.gateway
                .is_none_or(|g| g.is_ipv4() == self.address.is_ipv4()),
            "owned route family mismatch"
        );
        Ok(())
    }
}
/// A capture prefix owns a separately Create-acknowledged broadcast companion.
/// Derivation describes identity, never authority over an existing native row.
pub(super) fn capture_child(parent: &RouteStamp) -> Result<RouteStamp> {
    let IpAddr::V4(address) = parent.address else { anyhow::bail!("capture is not IPv4") };
    ensure!(address.is_private() && (1..32).contains(&parent.prefix) && parent.metric == 0 && parent.gateway.is_none(), "invalid capture parent");
    ensure!(porthub_mesh::lan_routes::Network::from_address(address,parent.prefix)?.address()==address,"noncanonical capture parent");
    Ok(RouteStamp { address: Ipv4Addr::from(u32::from(address) | (u32::MAX >> parent.prefix)).into(), prefix:32, gateway:None, metric:256 })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdapterRecord {
    pub version: u8,
    pub binding: String,
    pub guid: String,
    pub name: String,
    pub own: Ipv4Addr,
    pub mtu: u16,
    // None means creation/configuration did not reach a verified checkpoint.
    // Such a live adapter is not guessed into ownership after an interrupted start.
    pub baseline: Option<BTreeSet<RouteStamp>>,
    pub routes: BTreeSet<RouteStamp>,
    #[serde(default)]
    pub pending: BTreeSet<RouteStamp>,
    #[serde(default)]
    pub retiring: BTreeSet<RouteStamp>,
}
/// A native removal is allowed only after the old ownership claim was durably
/// retired. This token is not cloneable and cannot be constructed by backends.
pub(super) struct RetiredRoute(RouteStamp);
impl RetiredRoute {
    pub fn into_stamp(self) -> RouteStamp {
        self.0
    }
}

fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl AdapterRecord {
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate(&self.binding, &self.name, self.own, self.mtu)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_LEDGER_BYTES,
            "native ownership ledger exceeds byte budget"
        );
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_LEDGER_BYTES,
            "native ownership ledger exceeds byte budget"
        );
        let record: Self = serde_json::from_slice(bytes)?;
        record.validate(&record.binding, &record.name, record.own, record.mtu)?;
        Ok(record)
    }
    pub fn validate(&self, binding: &str, name: &str, own: Ipv4Addr, mtu: u16) -> Result<()> {
        ensure!(
            self.version == 2 && hex(&self.binding, 64) && self.binding == binding,
            "native ownership schema/profile mismatch; exact old owned cleanup is required"
        );
        ensure!(
            hex(&self.guid, 32) && self.guid != "0".repeat(32),
            "invalid owned adapter GUID"
        );
        ensure!(
            self.name == name
                && name.len() == 10
                && name.starts_with("ph")
                && name[2..].bytes().all(|b| b.is_ascii_hexdigit()),
            "owned adapter name mismatch"
        );
        ensure!(
            self.own == own && own.is_private() && self.mtu == mtu,
            "owned adapter configuration changed; clean owned teardown is required"
        );
        let baseline = self.baseline.as_ref();
        ensure!(
            baseline.map_or(0, BTreeSet::len) <= MAX_BASELINE_ROUTES,
            "native baseline exceeds its existing admission bound"
        );
        ensure!(
            self.pending.len() <= 1 || (self.pending.len()==2 && self.pending.iter().any(|parent|capture_child(parent).is_ok_and(|child|self.pending.contains(&child)))),
            "native route writer permits only one in-flight add intent"
        );
        ensure!(
            self.routes.len() + self.pending.len() + self.retiring.len() <= MAX_EXPLICIT_CLAIMS,
            "explicit native route claims exceed existing peer/capture capacity"
        );
        ensure!(
            self.routes.is_disjoint(&self.pending)
                && self.routes.is_disjoint(&self.retiring)
                && self.pending.is_disjoint(&self.retiring),
            "native route claim phases overlap"
        );
        ensure!(
            baseline.is_none_or(|b| b.is_disjoint(&self.routes)
                && b.is_disjoint(&self.pending)
                && b.is_disjoint(&self.retiring)),
            "explicit native claims overlap kernel baseline"
        );
        let mut capture_rows = 0; let mut child_rows = 0; let mut host_rows = 0;
        for row in self
            .routes
            .iter()
            .chain(self.pending.iter())
            .chain(self.retiring.iter())
        {
            let IpAddr::V4(address) = row.address else {
                anyhow::bail!("explicit route claim is not an agent-created IPv4 route");
            };
            ensure!(
                address.is_private()
                    && (1..=32).contains(&row.prefix)
                    && row.gateway.is_none()
                    && (row.metric == 0 || (row.metric == 256 && self.routes.iter().chain(self.pending.iter()).chain(self.retiring.iter()).any(|parent|capture_child(parent).is_ok_and(|child|child==*row)))),
                "explicit route claim differs from agent-created direct route"
            );
            ensure!(
                porthub_mesh::lan_routes::Network::from_address(address, row.prefix)?.address()
                    == address,
                "explicit route prefix is not canonical"
            );
            if row.prefix < 32 { capture_rows += 1; } else if row.metric == 256 { child_rows += 1; } else { host_rows += 1; }
        }
        ensure!(
            capture_rows <= MAX_CAPTURE_CLAIMS && child_rows <= MAX_CAPTURE_CLAIMS && host_rows <= MAX_HOST_CLAIMS,
            "capture route claims exceed existing prefix capacity"
        );
        for route in self
            .routes
            .iter()
            .chain(self.pending.iter())
            .chain(self.retiring.iter())
            .chain(self.baseline.iter().flatten())
        {
            route.validate()?;
        }
        Ok(())
    }
    /// Caller must have obtained a fresh, complete native adapter inventory and
    /// proved both this alias and GUID absent before persisting this new intent.
    pub fn reset_absent(&mut self, own: Ipv4Addr, mtu: u16) -> Result<()> {
        ensure!(
            own.is_private() && mtu >= 576,
            "invalid owned adapter rebind"
        );
        self.own = own;
        self.mtu = mtu;
        self.baseline = None;
        self.routes.clear();
        self.pending.clear();
        self.retiring.clear();
        Ok(())
    }
    /// Restart may continue deletion only for still-CONFIRMED explicit rows.
    /// Live retiring/unacknowledged rows remain ambiguous and are never adopted.
    pub fn recovery_routes(&self,guid:&str,addresses:&[IpAddr],mtu:u16,native:&BTreeSet<RouteStamp>)->Result<Vec<RouteStamp>> {
        self.recover(guid,addresses,mtu,native)?;
        ensure!(self.pending.is_disjoint(native),"live unacknowledged route intent requires exact owned recovery");
        Ok(self.routes.intersection(native).cloned().collect())
    }
    /// Caller holds the owned lease and exact pin with a fresh stopped inventory
    /// (stop_checked or missing native AF_INET plus source absence). A cleared
    /// Windows IPv4 interface has no IP-layer MTU to compare; do not pretend its
    /// link-layer MTU is the former configured IPv4 MTU. Active recover() stays
    /// strict. Every IPv4 address (including our old source) is forbidden here.
    pub fn stopped_recovery_routes(&self,guid:&str,addresses:&[IpAddr],native:&BTreeSet<RouteStamp>)->Result<Vec<RouteStamp>> {
        ensure!(self.guid==guid,"stopped adapter GUID changed; preserved");
        let baseline=self.baseline.as_ref().ok_or_else(||anyhow::anyhow!("stopped adapter lacks verified baseline"))?;
        ensure!(addresses.iter().all(|ip|matches!(ip,IpAddr::V6(v6)if v6.is_unicast_link_local())),"stopped adapter contains a source or foreign address; preserved");
        ensure!(native.iter().all(|row|!self.retiring.contains(row)&&(baseline.contains(row)||self.routes.contains(row))),"stopped adapter contains an unowned or retired route; preserved");
        ensure!(self.pending.is_disjoint(native),"stopped adapter has a live unacknowledged intent; preserved");
        Ok(self.routes.intersection(native).cloned().collect())
    }
    /// Native AF_INET observation: only ERROR_NOT_FOUND maps to None. A present
    /// IPv4 interface always retains the configured-MTU check, even if addressless.
    pub fn recover_ipv4_state(&self,guid:&str,addresses:&[IpAddr],mtu:Option<u16>,native:&BTreeSet<RouteStamp>)->Result<()> {
        if let Some(mtu)=mtu {self.recover(guid,addresses,mtu,native)}
        else {self.stopped_recovery_routes(guid,addresses,native).map(|_|())}
    }
    /// After our address/configuration Create ACK and exact-pin readback, accept
    /// only the new own /32 or previously verified kernel-baseline templates.
    /// Never turn arbitrary rows found during reopen into a new baseline.
    pub fn confirm_reopened_source(&mut self,guid:&str,addresses:&[IpAddr],mtu:u16,native:&BTreeSet<RouteStamp>,prior_baseline:&BTreeSet<RouteStamp>,prior_own:Ipv4Addr,persist:impl FnOnce(&AdapterRecord)->Result<()>)->Result<()> {
        ensure!(addresses.contains(&IpAddr::V4(self.own)),"reopened own source was not observed");
        let own_row=RouteStamp{address:self.own.into(),prefix:32,gateway:None,metric:256};
        let allowed=|row:&RouteStamp|self.baseline.as_ref().is_some_and(|b|b.contains(row))||row==&own_row||(prior_baseline.contains(row)&&!(prior_own!=self.own&&row.address==IpAddr::V4(prior_own)&&row.prefix==32));
        ensure!(native.iter().all(|row|self.routes.contains(row)||allowed(row)),"reopened adapter contains an unacknowledged native row; preserved");
        let mut next=self.clone();next.baseline=Some(native.iter().filter(|row|!self.routes.contains(*row)&&allowed(row)).cloned().collect());
        next.recover(guid,addresses,mtu,native)?;self.commit(next,persist)
    }
    /// Reuse an exact protected adapter only AFTER its old source is absent
    /// and every explicit owned route has disappeared. Baseline rows are merely
    /// retained from the OLD verified set, never adopted from an arbitrary row.
    pub fn rebind_cleared_source(&mut self,guid:&str,addresses:&[IpAddr],mtu:Option<u16>,native:&BTreeSet<RouteStamp>,own:Ipv4Addr,persist:impl FnOnce(&AdapterRecord)->Result<()>)->Result<()> {
        self.recover_ipv4_state(guid,addresses,mtu,native)?;
        ensure!(own.is_private()&&own!=self.own,"invalid fresh native source");
        ensure!(addresses.iter().all(|ip|matches!(ip,IpAddr::V6(v6)if v6.is_unicast_link_local())),"old or foreign source remains on adapter");
        ensure!(self.pending.is_empty()&&native.iter().all(|row|self.baseline.as_ref().is_some_and(|baseline|baseline.contains(row))),"live or ambiguous explicit route prevents source rebind");
        let mut next=self.clone();next.own=own;next.baseline=Some(native.clone());next.routes.clear();next.retiring.clear();
        self.commit(next,persist)
    }
    fn commit(
        &mut self,
        next: AdapterRecord,
        persist: impl FnOnce(&AdapterRecord) -> Result<()>,
    ) -> Result<()> {
        next.validate(&next.binding, &next.name, next.own, next.mtu)?;
        persist(&next)?;
        *self = next;
        Ok(())
    }
    /// A successful full native observation must invalidate missing explicit
    /// claims before callers prune caches or take an unchanged/wanted-empty exit.
    pub fn observe_missing(
        &mut self,
        native: &BTreeSet<RouteStamp>,
        persist: impl FnOnce(&AdapterRecord) -> Result<()>,
    ) -> Result<usize> {
        let baseline = self
            .baseline
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native baseline is unverified"))?;
        ensure!(
            native.iter().all(|row| !self.retiring.contains(row)
                && (baseline.contains(row) || self.routes.contains(row))),
            "native inventory contains an unowned or retired route"
        );
        let missing: BTreeSet<_> = self.routes.difference(native).cloned().collect();
        let expired = self.retiring.iter().any(|row| !native.contains(row));
        if missing.is_empty() && !expired {
            return Ok(0);
        }
        ensure!(
            missing.iter().all(|row| !baseline.contains(row)),
            "explicit ownership overlaps native baseline"
        );
        let mut next = self.clone();
        // Previous absent diagnostics can expire; neither their presence nor
        // absence can ever make a native row into confirmed ownership again.
        next.retiring.retain(|row| native.contains(row));
        for row in &missing {
            next.routes.remove(row);
            next.retiring.insert(row.clone());
        }
        self.commit(next, persist)?;
        Ok(missing.len())
    }
    /// Joint intent precedes either Create. Existing children may be shared ONLY
    /// when already ACK-owned by another confirmed parent, never by shape.
    pub fn reserve_capture(&mut self,parent:RouteStamp,persist:impl FnOnce(&AdapterRecord)->Result<()>) -> Result<(RouteStamp,bool)> {
        let child=capture_child(&parent)?;
        ensure!(self.pending.is_empty() && !self.routes.contains(&parent),"capture writer already active or parent owned");
        ensure!([&parent,&child].iter().all(|row|!self.retiring.contains(*row)&&!self.baseline.as_ref().is_some_and(|b|b.contains(*row))),"capture overlaps baseline or retirement");
        let shared=self.routes.contains(&child);
        ensure!(!shared || self.routes.iter().any(|p|capture_child(p).is_ok_and(|c|c==child)),"orphan child cannot authorize sharing");
        let mut next=self.clone();next.pending.insert(parent);if !shared {next.pending.insert(child.clone());}
        self.commit(next,persist)?;Ok((child,!shared))
    }
    pub fn confirm_created(&mut self,row:RouteStamp,native:&BTreeSet<RouteStamp>,persist:impl FnOnce(&AdapterRecord)->Result<()>) -> Result<()> {
        ensure!(native.contains(&row) && native.iter().all(|r|r==&row||self.routes.contains(r)||self.baseline.as_ref().is_some_and(|b|b.contains(r))),"Create readback contains changed or unacknowledged rows");
        self.confirm_route(row,persist)
    }
    /// Also used after a failed Create/readback/checkpoint. Only successful local
    /// Create ACKs and already durable ACKs grant cleanup authority.
    pub fn retire_capture_attempt(&mut self,parent:&RouteStamp,created:&BTreeSet<RouteStamp>,persist:impl FnOnce(&AdapterRecord)->Result<()>) -> Result<Vec<RetiredRoute>> {
        let child=capture_child(parent)?;let pair=BTreeSet::from([parent.clone(),child.clone()]);
        ensure!(created.is_subset(&pair) && self.pending.iter().all(|r|pair.contains(r)),"unrelated capture intent");
        let shared=self.routes.iter().chain(self.pending.iter()).any(|p|p!=parent && capture_child(p).is_ok_and(|c|c==child));
        let mut next=self.clone();let mut permits=Vec::new();
        for row in [parent.clone(),child.clone()] { if row==child && shared {continue;}
            let acknowledged=created.contains(&row)||self.routes.contains(&row);
            next.pending.remove(&row);next.routes.remove(&row);next.retiring.insert(row.clone());
            if acknowledged {permits.push(RetiredRoute(row));}
        }
        self.commit(next,persist)?;Ok(permits)
    }
    pub fn retire_capture(&mut self,parent:&RouteStamp,persist:impl FnOnce(&AdapterRecord)->Result<()>) -> Result<Vec<RetiredRoute>> {
        let child=capture_child(parent)?;ensure!(self.routes.contains(parent)&&self.routes.contains(&child),"capture lacks ACK-owned parent/child");
        self.retire_capture_attempt(parent,&BTreeSet::new(),persist)
    }
    /// Caller proved all returned cleanup rows absent; retain a shared child's
    /// confirmed claim while any other parent still references it.
    pub fn finish_capture(&mut self,parent:&RouteStamp,persist:impl FnOnce(&AdapterRecord)->Result<()>) -> Result<()> {
        let child=capture_child(parent)?;let mut next=self.clone();ensure!(next.retiring.remove(parent),"capture retirement missing");
        next.retiring.remove(&child);self.commit(next,persist)
    }
    pub fn reserve_route(
        &mut self,
        route: RouteStamp,
        persist: impl FnOnce(&AdapterRecord) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            !self.routes.contains(&route),
            "cannot reserve an already confirmed route"
        );
        ensure!(
            !self
                .baseline
                .as_ref()
                .is_some_and(|base| base.contains(&route)),
            "cannot reserve an existing native baseline route"
        );
        let mut next = self.clone();
        next.retiring.remove(&route);
        next.pending.insert(route);
        self.commit(next, persist)
    }
    pub fn confirm_route(
        &mut self,
        route: RouteStamp,
        persist: impl FnOnce(&AdapterRecord) -> Result<()>,
    ) -> Result<()> {
        let mut next = self.clone();
        ensure!(
            next.pending.remove(&route),
            "owned route has no prior intent"
        );
        next.retiring.remove(&route);
        next.routes.insert(route);
        self.commit(next, persist)
    }
    pub fn cancel_route(
        &mut self,
        route: &RouteStamp,
        persist: impl FnOnce(&AdapterRecord) -> Result<()>,
    ) -> Result<()> {
        let mut next = self.clone();
        ensure!(
            next.pending.remove(route),
            "owned route has no prior intent"
        );
        next.retiring.insert(route.clone());
        self.commit(next, persist)
    }

    pub fn retire_route(
        &mut self,
        route: &RouteStamp,
        persist: impl FnOnce(&AdapterRecord) -> Result<()>,
    ) -> Result<RetiredRoute> {
        ensure!(
            self.routes.contains(route),
            "cannot retire an unowned native route"
        );
        ensure!(
            !self
                .baseline
                .as_ref()
                .is_some_and(|base| base.contains(route)),
            "explicit route overlaps native baseline; refusing ambiguous removal"
        );
        let mut next = self.clone();
        next.routes.remove(route);
        next.pending.remove(route);
        next.retiring.insert(route.clone());
        // Do not modify memory or issue a native delete if persistence fails.
        persist(&next)?;
        *self = next;
        Ok(RetiredRoute(route.clone()))
    }

    pub fn finish_retirement(
        &mut self,
        route: &RouteStamp,
        persist: impl FnOnce(&AdapterRecord) -> Result<()>,
    ) -> Result<()> {
        ensure!(
            self.retiring.contains(route),
            "route has no pending retirement checkpoint"
        );
        let mut next = self.clone();
        next.retiring.remove(route);
        persist(&next)?;
        *self = next;
        Ok(())
    }

    pub fn recover(
        &self,
        guid: &str,
        addresses: &[IpAddr],
        mtu: u16,
        native: &BTreeSet<RouteStamp>,
    ) -> Result<()> {
        ensure!(
            self.guid == guid,
            "same-name adapter is foreign; it was not modified"
        );
        let baseline=self.baseline.as_ref().ok_or_else(||anyhow::anyhow!("owned adapter startup was interrupted before verification; explicit owned repair is required"))?;
        ensure!(
            mtu == self.mtu
                && addresses.iter().all(|ip| *ip == IpAddr::V4(self.own)
                    || matches!(ip,IpAddr::V6(v6) if v6.is_unicast_link_local())),
            "owned adapter was changed externally; it was not modified"
        );
        ensure!(native.iter().all(|r|!self.retiring.contains(r)&&(baseline.contains(r)||self.routes.contains(r))),"owned adapter has an unrecorded, unacknowledged or changed native route; it was not modified");
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> AdapterRecord {
        AdapterRecord {
            version: 2,
            binding: "a".repeat(64),
            guid: "b".repeat(32),
            name: "ph12345678".into(),
            own: "10.203.0.2".parse().unwrap(),
            mtu: 1380,
            baseline: Some(BTreeSet::new()),
            routes: BTreeSet::new(),
            pending: BTreeSet::new(),
            retiring: BTreeSet::new(),
        }
    }
    fn capture(network:&str,prefix:u8)->RouteStamp{RouteStamp{address:network.parse().unwrap(),prefix,gateway:None,metric:0}}
    fn born(r:&mut AdapterRecord,parent:RouteStamp,native:&mut BTreeSet<RouteStamp>){
        let (child,create)=r.reserve_capture(parent.clone(),|_|Ok(())).unwrap();
        if create{assert!(native.insert(child.clone()));r.confirm_created(child,native,|_|Ok(())).unwrap();}
        assert!(native.insert(parent.clone()));r.confirm_created(parent,native,|_|Ok(())).unwrap();
    }
    fn remove_capture(r:&mut AdapterRecord,parent:&RouteStamp,native:&mut BTreeSet<RouteStamp>){
        let permits=r.retire_capture(parent,|_|Ok(())).unwrap();for p in permits{native.remove(&p.into_stamp());}
        r.finish_capture(parent,|_|Ok(())).unwrap();r.recover(&r.guid,&[],1380,native).unwrap();
    }
    fn stamp(address:Ipv4Addr)->RouteStamp{RouteStamp{address:address.into(),prefix:32,gateway:None,metric:0}}
    #[test]
    fn native_ipv4_missing_row_is_distinct_from_present_wrong_mtu(){
        let r=record();assert!(r.recover_ipv4_state(&r.guid,&[],None,&BTreeSet::new()).is_ok());
        assert!(r.recover_ipv4_state(&r.guid,&[],Some(65535),&BTreeSet::new()).is_err());
        assert!(r.recover_ipv4_state(&r.guid,&[r.own.into()],None,&BTreeSet::new()).is_err());
    }
    #[test]
    fn stopped_restart_and_source_rebind_validate_real_recreated_configuration(){
        for changed in [false,true]{let mut r=record();let old=r.own;let own_row=RouteStamp{address:old.into(),prefix:32,gateway:None,metric:256};let multicast=RouteStamp{address:"224.0.0.0".parse().unwrap(),prefix:4,gateway:None,metric:256};r.baseline=Some(BTreeSet::from([own_row,multicast.clone()]));let prior=r.baseline.clone().unwrap();let guid=r.guid.clone();
            r.recover_ipv4_state(&guid,&[],None,&BTreeSet::new()).unwrap();
            if changed{r.rebind_cleared_source(&guid,&[],None,&BTreeSet::new(),"10.204.0.2".parse().unwrap(),|_|Ok(())).unwrap();}
            let born=RouteStamp{address:r.own.into(),prefix:32,gateway:None,metric:256};let native=BTreeSet::from([born,multicast]);let addresses=[r.own.into()];
            let before=r.encode().unwrap();assert!(r.confirm_reopened_source(&guid,&addresses,65535,&native,&prior,old,|_|Ok(())).is_err());assert_eq!(r.encode().unwrap(),before);
            let mut foreign=native.clone();foreign.insert(stamp("10.99.0.2".parse().unwrap()));assert!(r.confirm_reopened_source(&guid,&addresses,1380,&foreign,&prior,old,|_|Ok(())).is_err());assert_eq!(r.encode().unwrap(),before);
            r.confirm_reopened_source(&guid,&addresses,1380,&native,&prior,old,|_|Ok(())).unwrap();r.recover(&guid,&addresses,1380,&native).unwrap();
        }
    }
    #[test]
    fn stopped_recovery_requires_source_absence_and_preserves_active_mtu_guard(){
        let mut r=record();let row=stamp("10.203.1.2".parse().unwrap());r.routes.insert(row.clone());let native=BTreeSet::from([row.clone()]);
        assert!(r.recover(&r.guid,&[],65535,&native).is_err());
        assert_eq!(r.stopped_recovery_routes(&r.guid,&[],&native).unwrap(),vec![row]);
        for address in [IpAddr::V4(r.own),"10.203.9.9".parse().unwrap(),"2001:db8::1".parse().unwrap(),"::1".parse().unwrap()]{assert!(r.stopped_recovery_routes(&r.guid,&[address],&native).is_err());}
        assert!(r.stopped_recovery_routes(&r.guid,&["fe80::1".parse().unwrap()],&native).is_ok());
        assert!(r.stopped_recovery_routes(&"f".repeat(32),&[],&native).is_err());
        r.baseline=None;assert!(r.stopped_recovery_routes(&r.guid,&[],&native).is_err());
    }
    #[test]
    fn stopped_recovery_never_adopts_changed_foreign_pending_or_retired_rows(){
        let mut r=record();let row=stamp("10.203.1.2".parse().unwrap());r.routes.insert(row.clone());
        for foreign in [stamp("10.203.1.3".parse().unwrap()),RouteStamp{metric:1,..row.clone()},RouteStamp{gateway:Some("10.203.1.1".parse().unwrap()),..row.clone()}]{assert!(r.stopped_recovery_routes(&r.guid,&[],&BTreeSet::from([foreign])).is_err());}
        r.routes.clear();r.pending.insert(row.clone());assert!(r.stopped_recovery_routes(&r.guid,&[],&BTreeSet::from([row.clone()])).is_err());
        r.pending.clear();r.retiring.insert(row.clone());assert!(r.stopped_recovery_routes(&r.guid,&[],&BTreeSet::from([row])).is_err());
    }
    #[test]fn windows_actual_broadcast_companions_require_joint_create_acks(){
        let mut r=record();let mut native=BTreeSet::new();
        for network in ["10.254.253.0","10.254.254.0"]{let p=capture(network,24);let c=capture_child(&p).unwrap();
            let foreign=BTreeSet::from([p.clone(),c.clone()]);assert!(r.recover(&r.guid,&[],1380,&foreign).is_err());born(&mut r,p,&mut native);}
        r.recover(&r.guid,&[],1380,&native).unwrap();assert_eq!(r.routes.len(),4);
        for parent in [capture("10.254.253.0",24),capture("10.254.254.0",24)]{remove_capture(&mut r,&parent,&mut native);}
        assert!(native.is_empty());assert!(r.routes.is_empty());
    }
    #[test]fn shared_broadcast_retained_until_last_parent_in_both_removal_orders(){
        for reverse in [false,true]{let mut r=record();let mut native=BTreeSet::new();let a=capture("10.0.1.0",24);let b=capture("10.0.0.0",23);let child=capture_child(&a).unwrap();assert_eq!(capture_child(&b).unwrap(),child);
            born(&mut r,a.clone(),&mut native);born(&mut r,b.clone(),&mut native);assert_eq!(native.len(),3);
            let (first,last)=if reverse{(&b,&a)}else{(&a,&b)};remove_capture(&mut r,first,&mut native);assert!(native.contains(&child));assert!(r.routes.contains(&child));remove_capture(&mut r,last,&mut native);assert!(native.is_empty());
        }
    }
    #[test]fn capture_foreign_child_crash_pending_and_failed_checkpoint_never_authorize_adoption(){
        let mut r=record();let p=capture("10.254.253.0",24);let child=capture_child(&p).unwrap();r.baseline.as_mut().unwrap().insert(child.clone());assert!(r.reserve_capture(p.clone(),|_|Ok(())).is_err());
        let mut r=record();let before=r.encode().unwrap();assert!(r.reserve_capture(p.clone(),|_|anyhow::bail!("disk")).is_err());assert_eq!(r.encode().unwrap(),before);
        r.reserve_capture(p.clone(),|_|Ok(())).unwrap();let unacked=BTreeSet::from([child.clone()]);let reopened=AdapterRecord::decode(&r.encode().unwrap()).unwrap();assert!(reopened.recover(&r.guid,&[],1380,&unacked).is_err());
        // Local successful ACK can roll back even when its durable confirmation failed.
        assert!(r.confirm_created(child.clone(),&unacked,|_|anyhow::bail!("disk")).is_err());let permits=r.retire_capture_attempt(&p,&unacked,|_|Ok(())).unwrap();assert_eq!(permits.len(),1);assert_eq!(permits.into_iter().next().unwrap().into_stamp(),child);r.finish_capture(&p,|_|Ok(())).unwrap();
    }
    #[test]fn capture_crash_after_each_create_is_not_inferred_from_native_shape(){
        let mut r=record();let parent=capture("10.254.253.0",24);let (child,_)=r.reserve_capture(parent.clone(),|_|Ok(())).unwrap();let mut native=BTreeSet::from([child.clone()]);
        r.confirm_created(child.clone(),&native,|_|Ok(())).unwrap();
        // A durable child ACK is cleanup authority, but not a parent ACK.
        r.recover(&r.guid,&[],1380,&native).unwrap();native.insert(parent.clone());
        assert!(r.recover(&r.guid,&[],1380,&native).is_err());assert!(r.confirm_created(parent.clone(),&native,|_|anyhow::bail!("checkpoint")).is_err());
        let before=r.encode().unwrap();assert!(r.retire_capture_attempt(&parent,&native,|_|anyhow::bail!("retire")).is_err());assert_eq!(r.encode().unwrap(),before);
        let permits=r.retire_capture_attempt(&parent,&native,|_|Ok(())).unwrap();assert_eq!(permits.len(),2);for row in permits{native.remove(&row.into_stamp());}r.finish_capture(&parent,|_|Ok(())).unwrap();assert!(native.is_empty());
    }
    #[test]fn add_before_remove_expansion_keeps_shared_child_and_new_cover(){
        let mut r=record();let old=capture("10.0.1.0",24);let new=capture("10.0.0.0",23);let mut native=BTreeSet::new();born(&mut r,old.clone(),&mut native);
        born(&mut r,new.clone(),&mut native);remove_capture(&mut r,&old,&mut native);
        assert!(native.contains(&new));assert!(native.contains(&capture_child(&new).unwrap()));assert_eq!(native.len(),2);
    }
    #[test]fn shared_parent_failure_rolls_back_only_new_parent_and_changed_readback_rejects(){
        let mut r=record();let a=capture("10.0.1.0",24);let b=capture("10.0.0.0",23);let mut native=BTreeSet::new();born(&mut r,a.clone(),&mut native);let child=capture_child(&a).unwrap();let (_,create)=r.reserve_capture(b.clone(),|_|Ok(())).unwrap();assert!(!create);
        let permits=r.retire_capture_attempt(&b,&BTreeSet::new(),|_|Ok(())).unwrap();assert!(permits.is_empty());r.finish_capture(&b,|_|Ok(())).unwrap();r.recover(&r.guid,&[],1380,&native).unwrap();assert!(native.contains(&child));
        let mut r=record();let (c,_)=r.reserve_capture(a,|_|Ok(())).unwrap();let changed=BTreeSet::from([RouteStamp{metric:257,..c.clone()}]);assert!(r.confirm_created(c,&changed,|_|Ok(())).is_err());
    }
    #[test]
    fn names_and_unverified_intents_never_authorize_recovery() {
        let mut r = record();
        assert!(r
            .recover(&"c".repeat(32), &[], 1380, &BTreeSet::new())
            .is_err());
        r.baseline = None;
        assert!(r.recover(&r.guid, &[], 1380, &BTreeSet::new()).is_err());
    }
    #[test]
    fn absent_adapter_rebind_preserves_identity_and_forgets_old_native_claims() {
        let mut r = record();
        let guid = r.guid.clone();
        r.reset_absent("10.204.0.2".parse().unwrap(), 1380).unwrap();
        assert_eq!(r.guid, guid);
        assert!(
            r.baseline.is_none()
                && r.routes.is_empty()
                && r.pending.is_empty()
                && r.retiring.is_empty()
        );
        assert_eq!(r.own, "10.204.0.2".parse::<Ipv4Addr>().unwrap());
    }
    #[test]
    fn absent_pending_route_recovers_but_live_unacknowledged_row_is_never_adopted() {
        let mut r=record();let guid=r.guid.clone();let row=RouteStamp{address:"10.203.1.2".parse().unwrap(),prefix:32,gateway:None,metric:0};r.reserve_route(row.clone(),|_|Ok(())).unwrap();
        assert!(r.recovery_routes(&guid,&[],1380,&BTreeSet::from([row.clone()])).is_err());
        assert!(r.recovery_routes(&guid,&[],1380,&BTreeSet::new()).unwrap().is_empty());
        r.cancel_route(&row,|_|Ok(())).unwrap();r.observe_missing(&BTreeSet::new(),|_|Ok(())).unwrap();
        r.rebind_cleared_source(&guid,&[],Some(1380),&BTreeSet::new(),"10.204.0.2".parse().unwrap(),|_|Ok(())).unwrap();
        assert!(r.pending.is_empty()&&r.retiring.is_empty());
    }
    #[test]
    fn source_stop_crash_recovers_confirmed_routes_before_fresh_rebind_without_adopting_foreign() {
        let mut r=record();let guid=r.guid.clone();let row=RouteStamp{address:"10.203.1.2".parse().unwrap(),prefix:32,gateway:None,metric:0};r.routes.insert(row.clone());
        let mut native=BTreeSet::from([row.clone()]);let next="10.204.0.2".parse().unwrap();
        assert!(r.rebind_cleared_source(&guid,&[],Some(1380),&native,next,|_|Ok(())).is_err());
        let mut foreign=native.clone();foreign.insert(RouteStamp{metric:1,..row.clone()});
        assert!(r.recovery_routes(&guid,&[],1380,&foreign).is_err());
        for row in r.recovery_routes(&guid,&[],1380,&native).unwrap(){
            let permit=r.retire_route(&row,|_|Ok(())).unwrap();let exact=permit.into_stamp();assert!(native.remove(&exact));r.finish_retirement(&exact,|_|Ok(())).unwrap();
        }
        r.rebind_cleared_source(&guid,&[],Some(1380),&native,next,|_|Ok(())).unwrap();assert_eq!(r.own,next);
    }
    #[test]
    fn cleared_source_rebind_requires_exact_guid_absence_and_durable_checkpoint() {
        let mut r=record();let guid=r.guid.clone();let next="10.204.0.2".parse().unwrap();let before=r.encode().unwrap();
        for addresses in [vec![IpAddr::V4(r.own)],vec!["192.168.1.2".parse().unwrap()]] {
            assert!(r.rebind_cleared_source(&guid,&addresses,Some(1380),&BTreeSet::new(),next,|_|Ok(())).is_err());assert_eq!(r.encode().unwrap(),before);
        }
        assert!(r.rebind_cleared_source(&"f".repeat(32),&[],Some(1380),&BTreeSet::new(),next,|_|Ok(())).is_err());
        assert!(r.rebind_cleared_source(&guid,&[],Some(1380),&BTreeSet::new(),next,|_|anyhow::bail!("injected fsync failure")).is_err());assert_eq!(r.encode().unwrap(),before);
        r.rebind_cleared_source(&guid,&[],Some(1380),&BTreeSet::new(),next,|_|Ok(())).unwrap();assert_eq!(r.guid,guid);assert_eq!(r.own,next);
    }
    #[test]
    fn stale_unshipped_schema_cannot_silently_reauthorize_old_claims() {
        let mut r = record();
        r.version = 1;
        assert!(r.validate(&r.binding, &r.name, r.own, r.mtu).is_err());
    }

    #[test]
    fn protected_identity_and_exact_configuration_are_required() {
        let r = record();
        r.validate(&r.binding, &r.name, r.own, 1380).unwrap();
        assert!(r.validate(&"d".repeat(64), &r.name, r.own, 1380).is_err());
        assert!(r
            .validate(&r.binding, &r.name, "10.204.0.2".parse().unwrap(), 1380)
            .is_err());
        assert!(r
            .recover(
                &r.guid,
                &["10.203.0.99".parse().unwrap()],
                1380,
                &BTreeSet::new()
            )
            .is_err());
    }
    #[test]
    fn stale_owned_subset_recovers_but_foreign_route_or_metric_does_not() {
        let mut r = record();
        let route = RouteStamp {
            address: "10.203.1.2".parse().unwrap(),
            prefix: 32,
            gateway: None,
            metric: 0,
        };
        r.routes.insert(route.clone());
        r.recover(&r.guid, &[], 1380, &BTreeSet::from([route.clone()]))
            .unwrap();
        let mut changed = route;
        changed.metric = 5;
        assert!(r
            .recover(&r.guid, &[], 1380, &BTreeSet::from([changed]))
            .is_err());
        r.recover(&r.guid, &[], 1380, &BTreeSet::new()).unwrap();
    }
}

#[cfg(test)]
mod intent_tests {
    use super::*;
    #[test]
    fn an_unacknowledged_route_intent_is_not_an_owned_native_route() {
        let route = RouteStamp {
            address: "10.203.1.2".parse().unwrap(),
            prefix: 32,
            gateway: None,
            metric: 0,
        };
        let record = AdapterRecord {
            version: 2,
            binding: "a".repeat(64),
            guid: "b".repeat(32),
            name: "ph12345678".into(),
            own: "10.203.0.2".parse().unwrap(),
            mtu: 1380,
            baseline: Some(BTreeSet::new()),
            routes: BTreeSet::new(),
            pending: BTreeSet::from([route.clone()]),
            retiring: BTreeSet::new(),
        };
        assert!(record
            .recover(&record.guid, &[], 1380, &BTreeSet::from([route]))
            .is_err());
        record
            .recover(&record.guid, &[], 1380, &BTreeSet::new())
            .unwrap();
    }
}

#[cfg(test)]
mod dns_endpoint_tests {
    #[test]
    fn endpoint_stays_loopback_after_private_route_or_address_teardown() {
        for raw in ["10.203.0.2", "172.21.228.93", "192.168.0.169"] {
            let own = raw.parse().unwrap();
            let endpoint = super::dns_endpoint(own);
            assert!(endpoint.is_loopback());
            assert_ne!(endpoint, own);
            assert_eq!(endpoint, super::dns_endpoint(own));
        }
    }
}

#[cfg(test)]
mod retirement_tests {
    use super::*;
    fn fixture() -> (AdapterRecord, RouteStamp) {
        let route = RouteStamp {
            address: "10.203.0.0".parse().unwrap(),
            prefix: 16,
            gateway: None,
            metric: 0,
        };
        let r = AdapterRecord {
            version: 2,
            binding: "a".repeat(64),
            guid: "b".repeat(32),
            name: "ph12345678".into(),
            own: "10.204.0.2".parse().unwrap(),
            mtu: 1380,
            baseline: Some(BTreeSet::new()),
            routes: BTreeSet::from([route.clone()]),
            pending: BTreeSet::new(),
            retiring: BTreeSet::new(),
        };
        (r, route)
    }
    #[test]
    fn successful_retirement_cannot_adopt_a_later_identical_foreign_prefix_on_restart() {
        let (mut r, route) = fixture();
        let mut disk = Vec::new();
        let permit = r
            .retire_route(&route, |next| {
                disk = serde_json::to_vec(next)?;
                Ok(())
            })
            .unwrap();
        assert_eq!(permit.into_stamp(), route);
        // Native delete acknowledged, then its tombstone checkpoint succeeds.
        r.finish_retirement(&route, |next| {
            disk = serde_json::to_vec(next)?;
            Ok(())
        })
        .unwrap();
        let restarted: AdapterRecord = serde_json::from_slice(&disk).unwrap();
        assert!(restarted.retiring.is_empty());
        assert!(restarted
            .recover(&restarted.guid, &[], 1380, &BTreeSet::from([route]))
            .is_err());
    }
    #[test]
    fn crash_or_delete_failure_after_retirement_never_restores_the_old_claim() {
        let (mut r, route) = fixture();
        let mut disk = Vec::new();
        let _permit = r
            .retire_route(&route, |next| {
                disk = serde_json::to_vec(next)?;
                Ok(())
            })
            .unwrap(); /* no native delete, or native delete fails */
        let restarted: AdapterRecord = serde_json::from_slice(&disk).unwrap();
        assert!(restarted
            .recover(&restarted.guid, &[], 1380, &BTreeSet::from([route]))
            .is_err());
    }
    #[test]
    fn completed_removal_checkpoint_failure_keeps_a_nonauthorizing_tombstone() {
        let (mut r, route) = fixture();
        let mut disk = Vec::new();
        let _permit = r
            .retire_route(&route, |next| {
                disk = serde_json::to_vec(next)?;
                Ok(())
            })
            .unwrap();
        assert!(r
            .finish_retirement(&route, |_| anyhow::bail!("injected final fsync failure"))
            .is_err());
        assert!(r.retiring.contains(&route));
        let restarted: AdapterRecord = serde_json::from_slice(&disk).unwrap();
        restarted
            .recover(&restarted.guid, &[], 1380, &BTreeSet::new())
            .unwrap();
        assert!(restarted
            .recover(&restarted.guid, &[], 1380, &BTreeSet::from([route]))
            .is_err());
    }

    #[test]
    fn persistence_failure_keeps_the_claim_and_produces_no_native_removal_permit() {
        let (mut r, route) = fixture();
        assert!(r
            .retire_route(&route, |_| anyhow::bail!("injected fsync failure"))
            .is_err());
        assert!(r.routes.contains(&route));
        r.recover(&r.guid, &[], 1380, &BTreeSet::from([route]))
            .unwrap();
    }
}

#[cfg(test)]
mod observed_missing_tests {
    use super::*;
    fn fixture() -> (AdapterRecord, RouteStamp, RouteStamp) {
        let b = RouteStamp {
            address: "10.203.0.0".parse().unwrap(),
            prefix: 16,
            gateway: None,
            metric: 0,
        };
        let c = RouteStamp {
            address: "10.204.1.2".parse().unwrap(),
            prefix: 32,
            gateway: None,
            metric: 0,
        };
        let r = AdapterRecord {
            version: 2,
            binding: "a".repeat(64),
            guid: "b".repeat(32),
            name: "ph12345678".into(),
            own: "10.205.0.2".parse().unwrap(),
            mtu: 1380,
            baseline: Some(BTreeSet::new()),
            routes: BTreeSet::from([b.clone(), c.clone()]),
            pending: BTreeSet::new(),
            retiring: BTreeSet::new(),
        };
        (r, b, c)
    }
    #[test]
    fn external_removal_then_wanted_empty_reconcile_cannot_adopt_identical_foreign_row_on_restart()
    {
        let (mut r, b, _) = fixture();
        let mut cache = r.routes.clone();
        let native = BTreeSet::new();
        let mut disk = Vec::new();
        assert_eq!(
            r.observe_missing(&native, |next| {
                disk = serde_json::to_vec(next)?;
                Ok(())
            })
            .unwrap(),
            2
        );
        cache.retain(|row| native.contains(row));
        assert!(cache.is_empty()); /* wanted is empty: same fast-return boundary as actual reconcile_sparse */
        let restarted: AdapterRecord = serde_json::from_slice(&disk).unwrap();
        assert!(!restarted.routes.contains(&b));
        assert!(restarted.retiring.contains(&b));
        assert!(restarted
            .recover(&restarted.guid, &[], 1380, &BTreeSet::from([b]))
            .is_err());
    }
    #[test]
    fn failed_observation_persistence_leaves_record_and_cache_unpruned() {
        let (mut r, b, c) = fixture();
        let cache = r.routes.clone();
        assert!(r
            .observe_missing(&BTreeSet::new(), |_| anyhow::bail!(
                "injected journal failure"
            ))
            .is_err());
        assert_eq!(r.routes, cache);
        assert!(r.routes.contains(&b) && r.routes.contains(&c) && r.retiring.is_empty());
    }
    #[test]
    fn retained_wanted_route_requires_fresh_native_add_ack_to_repair() {
        let (mut r, b, c) = fixture();
        let native = BTreeSet::from([c.clone()]);
        r.observe_missing(&native, |_| Ok(())).unwrap();
        assert!(!r.routes.contains(&b) && r.routes.contains(&c));
        r.reserve_route(b.clone(), |_| Ok(())).unwrap();
        let repaired = BTreeSet::from([b.clone(), c]);
        assert!(r.recover(&r.guid, &[], 1380, &repaired).is_err());
        r.confirm_route(b, |_| Ok(())).unwrap();
        r.recover(&r.guid, &[], 1380, &repaired).unwrap();
    }
    #[test]
    fn failed_repair_does_not_reinstate_missing_ownership() {
        let (mut r, b, c) = fixture();
        r.observe_missing(&BTreeSet::from([c]), |_| Ok(())).unwrap();
        r.reserve_route(b.clone(), |_| Ok(())).unwrap();
        r.cancel_route(&b, |_| Ok(())).unwrap();
        assert!(!r.routes.contains(&b));
        assert!(r.retiring.contains(&b));
        assert!(r.recover(&r.guid, &[], 1380, &BTreeSet::from([b])).is_err());
    }
    #[test]
    fn absent_diagnostic_expiry_does_not_reauthorize_row_or_write_forever() {
        let (mut r, b, _) = fixture();
        let mut writes = 0;
        r.observe_missing(&BTreeSet::new(), |_| {
            writes += 1;
            Ok(())
        })
        .unwrap();
        r.observe_missing(&BTreeSet::new(), |_| {
            writes += 1;
            Ok(())
        })
        .unwrap();
        r.observe_missing(&BTreeSet::new(), |_| {
            writes += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(writes, 2);
        assert!(r.retiring.is_empty());
        assert!(r.recover(&r.guid, &[], 1380, &BTreeSet::from([b])).is_err());
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    fn own() -> Ipv4Addr {
        "10.250.0.1".parse().unwrap()
    }
    fn hosts(base: u32, count: usize) -> Vec<Ipv4Addr> {
        (0..count)
            .map(|i| Ipv4Addr::from(base + i as u32))
            .collect()
    }
    fn stamp(address: Ipv4Addr) -> RouteStamp {
        RouteStamp {
            address: address.into(),
            prefix: 32,
            gateway: None,
            metric: 0,
        }
    }
    fn record() -> AdapterRecord {
        AdapterRecord {
            version: 2,
            binding: "a".repeat(64),
            guid: "b".repeat(32),
            name: "ph12345678".into(),
            own: own(),
            mtu: 1380,
            baseline: Some(BTreeSet::new()),
            routes: BTreeSet::new(),
            pending: BTreeSet::new(),
            retiring: BTreeSet::new(),
        }
    }
    fn valid(r: &AdapterRecord) -> Result<()> {
        r.validate(&r.binding, &r.name, r.own, r.mtu)
    }
    #[test]
    fn existing_full_4096_identity_and_256_pair_host_contracts_are_unchanged() {
        assert_eq!(porthub_network::policy::MAX_SNAPSHOT_PEERS, 4096);
        assert_eq!(MAX_LEGACY_HOSTS, 4095);
        assert_eq!(MAX_SPARSE_HOSTS, 256);
        let legacy = hosts(0x0a010000, MAX_LEGACY_HOSTS);
        let mut with_self = legacy.clone();
        with_self.push(own());
        assert_eq!(
            plan_hosts(own(), &with_self, HostAdmission::Legacy, [])
                .unwrap()
                .wanted
                .len(),
            4095
        );
        assert!(plan_hosts(own(), &hosts(0x0a010000, 4096), HostAdmission::Legacy, []).is_err());
        assert_eq!(
            plan_hosts(own(), &legacy[..256], HostAdmission::Sparse, [])
                .unwrap()
                .wanted
                .len(),
            256
        );
        assert!(plan_hosts(own(), &legacy[..257], HostAdmission::Sparse, []).is_err());
    }
    #[test]
    fn full_replacement_and_cross_mode_handover_use_removal_before_add_without_double_budget() {
        let legacy = hosts(0x0a010000, MAX_LEGACY_HOSTS);
        let replacement = hosts(0x0a020000, MAX_LEGACY_HOSTS);
        let plan = plan_hosts(
            own(),
            &replacement,
            HostAdmission::Legacy,
            legacy.iter().copied(),
        )
        .unwrap();
        let mut physical: BTreeSet<_> = legacy.iter().copied().collect();
        let mut peak = physical.len();
        for ip in plan.removals {
            physical.remove(&ip);
        }
        for ip in plan.additions {
            physical.insert(ip);
            peak = peak.max(physical.len());
        }
        assert_eq!(peak, MAX_LEGACY_HOSTS);
        assert_eq!(physical, plan.wanted);
        let sparse = plan_hosts(
            own(),
            &replacement[..256],
            HostAdmission::Sparse,
            physical.iter().copied(),
        )
        .unwrap();
        for ip in sparse.removals {
            physical.remove(&ip);
        }
        for ip in sparse.additions {
            physical.insert(ip);
        }
        assert_eq!(physical.len(), 256);
        let restored = plan_hosts(
            own(),
            &replacement,
            HostAdmission::Legacy,
            physical.iter().copied(),
        )
        .unwrap();
        for ip in restored.removals {
            physical.remove(&ip);
        }
        for ip in restored.additions {
            physical.insert(ip);
        }
        assert_eq!(physical.len(), 4095);
    }
    #[test]
    fn maximum_common_ledger_fits_purpose_specific_byte_bound_with_no_mode_relabel() {
        let mut r = record();
        // Every IPv4 host text below uses a long private representation. Baseline
        // rows exercise full-length IPv6/gateway text and maximum metric fields.
        for i in 0..MAX_LEGACY_HOSTS {
            r.routes.insert(stamp(Ipv4Addr::new(
                192,
                168,
                100 + (i / 156) as u8,
                100 + (i % 156) as u8,
            )));
        }
        for i in 0..MAX_CAPTURE_CLAIMS {
            r.routes.insert(RouteStamp {
                address: Ipv4Addr::new(172, 16, 100 + i as u8, 128).into(),
                prefix: 25,
                gateway: None,
                metric: 0,
            });
        }
        let children:Vec<_>=r.routes.iter().filter(|r|r.prefix<32).map(|r|capture_child(r).unwrap()).collect();r.routes.extend(children);
        for i in 0..MAX_BASELINE_ROUTES {
            r.baseline.as_mut().unwrap().insert(RouteStamp {
                address: std::net::Ipv6Addr::new(
                    0xfe80,
                    0xffff,
                    0xffff,
                    0xffff,
                    0xffff,
                    0xffff,
                    0xffff,
                    0x1000 + i as u16,
                )
                .into(),
                prefix: 128,
                gateway: Some(
                    std::net::Ipv6Addr::new(
                        0xfe80, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
                    )
                    .into(),
                ),
                metric: u32::MAX,
            });
        }
        valid(&r).unwrap();
        assert_eq!(
            r.routes.len() + r.baseline.as_ref().unwrap().len(),
            MAX_ROUTES
        );
        let bytes = r.encode().unwrap();
        assert!(bytes.len() > 65536);
        assert!(bytes.len() <= MAX_LEDGER_BYTES);
        // Conservative per-entry JSON maxima include all fixed keys/punctuation.
        assert!(MAX_BASELINE_ROUTES * 192 + MAX_EXPLICIT_CLAIMS * 96 + 4096 <= MAX_LEDGER_BYTES);
        let mut forged = serde_json::to_value(&r).unwrap();
        forged["mode"] = serde_json::json!("legacy");
        forged["max_hosts"] = serde_json::json!(65536);
        assert!(AdapterRecord::decode(&serde_json::to_vec(&forged).unwrap()).is_err());
        let recovered = AdapterRecord::decode(&bytes).unwrap();
        valid(&recovered).unwrap();
        let mut boundary = bytes.clone();
        boundary.resize(MAX_LEDGER_BYTES, b' ');
        AdapterRecord::decode(&boundary).unwrap();
        boundary.push(b' ');
        assert!(AdapterRecord::decode(&boundary)
            .unwrap_err()
            .to_string()
            .contains("byte budget"));
        let mut native = recovered.routes.clone();
        native.extend(recovered.baseline.as_ref().unwrap().iter().cloned());
        recovered
            .recover(&recovered.guid, &[own().into()], 1380, &native)
            .unwrap();
        assert!(recovered
            .validate(
                &"f".repeat(64),
                &recovered.name,
                recovered.own,
                recovered.mtu
            )
            .is_err());
        eprintln!(
            "maximum ledger: {} rows, {} serialized bytes, {} byte limit",
            MAX_ROUTES,
            bytes.len(),
            MAX_LEDGER_BYTES
        );
    }
    #[test]
    fn explicit_baseline_phase_and_shape_overflows_fail_closed() {
        let mut r = record();
        r.routes = hosts(0x0a010000, MAX_EXPLICIT_CLAIMS + 1)
            .into_iter()
            .map(stamp)
            .collect();
        assert!(valid(&r).is_err());
        r = record();
        r.baseline = Some(
            hosts(0x0b010000, MAX_BASELINE_ROUTES + 1)
                .into_iter()
                .map(stamp)
                .collect(),
        );
        assert!(valid(&r).is_err());
        r = record();
        let a = stamp("10.1.1.1".parse().unwrap());
        r.routes.insert(a.clone());
        r.pending.insert(a);
        assert!(valid(&r).is_err());
        r = record();
        r.pending = hosts(0x0a010000, 2).into_iter().map(stamp).collect();
        assert!(valid(&r).is_err());
        r = record();
        let mut foreign = stamp("10.1.1.1".parse().unwrap());
        foreign.metric = 1;
        r.routes.insert(foreign);
        assert!(valid(&r).is_err());
    }
    #[test]
    fn full_sparse_bound_repairs_retired_rows_without_spending_extra_slots() {
        let mut r = record();
        let source = hosts(0x0a010000, MAX_SPARSE_HOSTS);
        r.routes = source.iter().copied().map(stamp).collect();
        valid(&r).unwrap();
        r.observe_missing(&BTreeSet::new(), |_| Ok(())).unwrap();
        assert_eq!(r.retiring.len(), 256);
        for ip in source {
            let row = stamp(ip);
            r.reserve_route(row.clone(), |_| Ok(())).unwrap();
            r.confirm_route(row, |_| Ok(())).unwrap();
        }
        assert_eq!(r.routes.len(), 256);
        assert!(r.pending.is_empty() && r.retiring.is_empty());
        valid(&r).unwrap();
    }
}
