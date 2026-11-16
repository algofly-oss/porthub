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

pub(super) const MAX_ROUTES: usize = 320;
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
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl AdapterRecord {
    pub fn validate(&self, binding: &str, name: &str, own: Ipv4Addr, mtu: u16) -> Result<()> {
        ensure!(
            self.version == 1 && hex(&self.binding, 64) && self.binding == binding,
            "native ownership profile binding mismatch"
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
        ensure!(
            self.routes.len()
                + self.pending.len()
                + self.baseline.as_ref().map_or(0, BTreeSet::len)
                <= MAX_ROUTES,
            "owned route journal exceeds bound"
        );
        for route in self
            .routes
            .iter()
            .chain(self.pending.iter())
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
        ensure!(native.iter().all(|r|baseline.contains(r)||self.routes.contains(r)),"owned adapter has an unrecorded, unacknowledged or changed native route; it was not modified");
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> AdapterRecord {
        AdapterRecord {
            version: 1,
            binding: "a".repeat(64),
            guid: "b".repeat(32),
            name: "ph12345678".into(),
            own: "10.203.0.2".parse().unwrap(),
            mtu: 1380,
            baseline: Some(BTreeSet::new()),
            routes: BTreeSet::new(),
            pending: BTreeSet::new(),
        }
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
        assert!(r.baseline.is_none() && r.routes.is_empty() && r.pending.is_empty());
        assert_eq!(r.own, "10.204.0.2".parse::<Ipv4Addr>().unwrap());
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
            version: 1,
            binding: "a".repeat(64),
            guid: "b".repeat(32),
            name: "ph12345678".into(),
            own: "10.203.0.2".parse().unwrap(),
            mtu: 1380,
            baseline: Some(BTreeSet::new()),
            routes: BTreeSet::new(),
            pending: BTreeSet::from([route.clone()]),
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
