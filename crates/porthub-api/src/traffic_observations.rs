//! Accepted-policy packet observations are distinct from legacy connection attempts.
use serde_json::Value;
use std::{collections::BTreeSet, net::IpAddr};
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Accepted {
    pub ips: BTreeSet<String>,
    pub window: f64,
    pub families: BTreeSet<String>,
}
impl Accepted {
    pub fn parse(value: &Value) -> Option<Self> {
        let window = value["accepted_incoming_ips_window_seconds"].as_f64()?;
        if !window.is_finite() || window <= 0. || window > 300. {
            return None;
        }
        let raw_families = value["accepted_incoming_ips_address_families"].as_array()?;
        if raw_families.is_empty() || raw_families.len() > 2 {
            return None;
        }
        let families = raw_families
            .iter()
            .map(|v| v.as_str().map(str::to_owned))
            .collect::<Option<BTreeSet<_>>>()?;
        if families.iter().any(|v| v != "ipv4" && v != "ipv6") {
            return None;
        }
        let raw = value["accepted_incoming_ips"].as_array()?;
        if raw.len() > 8192 {
            return None;
        }
        let mut ips = BTreeSet::new();
        for raw in raw {
            let ip: IpAddr = raw.as_str()?.parse().ok()?;
            if !families.contains(if ip.is_ipv4() { "ipv4" } else { "ipv6" }) {
                return None;
            }
            ips.insert(ip.to_string());
        }
        Some(Self {
            ips,
            window,
            families,
        })
    }
    pub fn attach(&self, value: &mut Value) {
        value["accepted_incoming_ips"] = serde_json::json!(self.ips);
        value["accepted_incoming_ips_window_seconds"] = serde_json::json!(self.window);
        value["accepted_incoming_ips_address_families"] = serde_json::json!(self.families);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn normalize_merges_only_compatible_provenance_and_preserves_unknown() {
        let a = json!({"timestamp":100,"accepted_incoming_ips":["192.0.2.1"],"accepted_incoming_ips_window_seconds":5,"accepted_incoming_ips_address_families":["ipv4"]});
        let mut b = a.clone();
        b["accepted_incoming_ips"] = json!(["192.0.2.2"]);
        let merged = crate::inventory_traffic::normalize(&[a.clone(), b.clone()]);
        assert_eq!(
            merged[0]["accepted_incoming_ips"],
            json!(["192.0.2.1", "192.0.2.2"])
        );
        b["accepted_incoming_ips_window_seconds"] = json!(10);
        assert!(
            crate::inventory_traffic::normalize(&[a.clone(), b])[0]["accepted_incoming_ips"]
                .is_null()
        );
        assert!(crate::inventory_traffic::normalize(&[
            a,
            json!({"timestamp":100,"incoming_ips":["192.0.2.9"]})
        ])[0]["accepted_incoming_ips"]
            .is_null());
    }
    #[test]
    fn legacy_invalid_and_empty_observations_remain_distinct() {
        assert!(Accepted::parse(&json!({"incoming_ips":["192.0.2.1"]})).is_none());
        let mut v = json!({"accepted_incoming_ips":[],"accepted_incoming_ips_window_seconds":5,"accepted_incoming_ips_address_families":["ipv4"]});
        assert!(Accepted::parse(&v).unwrap().ips.is_empty());
        v["accepted_incoming_ips"] = json!(["::1"]);
        assert!(Accepted::parse(&v).is_none());
        v["accepted_incoming_ips_address_families"] = json!(["ipv4", "ipv6"]);
        assert!(Accepted::parse(&v).is_some());
        v["accepted_incoming_ips_window_seconds"] = json!(301);
        assert!(Accepted::parse(&v).is_none());
    }
}
