//! Negotiated sparse lookup model and stable authorization generation.
//! A sync revision changes on every heartbeat and must never serve as this generation.
use crate::error::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::Ipv4Addr};

pub use porthub_network::policy::Lookup;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: u32,
    pub sequence: u64,
    #[serde(default)]
    pub wanted: Vec<Lookup>,
}
impl Request {
    pub fn validate(&self) -> ApiResult<()> {
        if self.protocol != 1 || self.sequence == 0 || self.wanted.len() > 16 {
            return Err(ApiError::bad_request(
                "Unsupported or oversized sparse private request",
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for q in &self.wanted {
            let valid = match q.kind.as_str() {
                "ip" => q.value.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_private()),
                "peer" => {
                    !q.value.is_empty()
                        && q.value.len() <= 60
                        && q.value
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                }
                "name" => {
                    !q.value.is_empty()
                        && q.value.len() <= 254
                        && q.value
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b".-_".contains(&c))
                }
                _ => false,
            };
            if !valid || !seen.insert((q.kind.clone(), q.value.to_ascii_lowercase())) {
                return Err(ApiError::bad_request(
                    "Invalid or repeated sparse private lookup",
                ));
            }
        }
        Ok(())
    }
}

/// Inputs must be the authoritative tenant-scoped active inventory, not client advertisements.
/// Exclude heartbeat/revision/path telemetry, include credentials/address/owner/policy bindings.
pub fn epoch(
    machines: &[Value],
    books: &[Value],
    groups: &HashMap<String, Value>,
    peers: &[Value],
    preferences: &Value,
) -> String {
    let mut machines = machines.to_vec();
    machines.sort_by_key(|m| m["_id"].to_string());
    let mut books = books.to_vec();
    books.sort_by_key(|b| b["_id"].to_string());
    let groups: std::collections::BTreeMap<_, _> = groups.iter().collect();
    let mut peers:Vec<_>=peers.iter().map(|p|json!({"id":p["_id"],"workspace":p["workspace_id"],"owner":p["owner_id"],"machine":p["machine_id"],"ip":p["ip"],"credential":p["credential_hash"],"enabled":p["enabled"]})).collect();
    peers.sort_by_key(|p| p["id"].to_string());
    format!("{:x}",Sha256::digest(serde_json::to_vec(&json!({"machines":machines,"books":books,"groups":groups,"peers":peers,"preferences":preferences})).expect("typed private authority")))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn heartbeat_and_process_restart_do_not_rotate_policy_but_credentials_and_membership_do() {
        let mut peer = json!({"_id":"a","ip":"10.203.0.2","credential_hash":"secret-digest","enabled":true,"revision":1,"fingerprint":"one","instance":"one"});
        let groups = HashMap::new();
        let initial = epoch(&[], &[], &groups, &[peer.clone()], &Value::Null);
        peer["revision"] = json!(99);
        peer["last_seen_at"] = json!("later");
        peer["fingerprint"] = json!("two");
        peer["instance"] = json!("two");
        assert_eq!(
            initial,
            epoch(&[], &[], &groups, &[peer.clone()], &Value::Null)
        );
        peer["credential_hash"] = json!("rotated");
        assert_ne!(initial, epoch(&[], &[], &groups, &[peer], &Value::Null));
        assert_ne!(initial, epoch(&[], &[], &groups, &[], &Value::Null));
    }
    #[test]
    fn lookup_limits_and_foreign_shapes_fail_closed() {
        assert!(Request {
            protocol: 1,
            sequence: 1,
            wanted: vec![Lookup {
                kind: "ip".into(),
                value: "8.8.8.8".into()
            }]
        }
        .validate()
        .is_err());
        assert!(Request {
            protocol: 1,
            sequence: 0,
            wanted: vec![]
        }
        .validate()
        .is_err());
        assert!(Request {
            protocol: 1,
            sequence: 1,
            wanted: (0..17)
                .map(|i| Lookup {
                    kind: "peer".into(),
                    value: format!("peer-{i}")
                })
                .collect()
        }
        .validate()
        .is_err());
        assert!(Request {
            protocol: 1,
            sequence: 1,
            wanted: vec![Lookup {
                kind: "ip".into(),
                value: "10.203.1.2".into()
            }]
        }
        .validate()
        .is_ok());
    }
}

/// Local authorization generation: routing/name metadata and unrelated machines cannot reset flows.
pub fn local_epoch(
    machine: &Value,
    manifest: &[Value],
    groups: &HashMap<String, Value>,
    peer: &Value,
) -> String {
    let owner = peer["owner_id"].as_str().unwrap_or_default();
    let groups = groups
        .iter()
        .map(|(id, g)| {
            let mut g = g.clone();
            g["user_ids"] = Value::Array(
                g["user_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|v| v.as_str() == Some(owner))
                    .cloned()
                    .collect(),
            );
            (id.clone(), g)
        })
        .collect();
    let mut selected = serde_json::Map::new();
    for key in [
        "_id",
        "user_id",
        "private_owner_id",
        "private_owner_revoked",
        "enabled",
        "group_id",
        "group_ids",
    ] {
        if let Some(value) = machine.get(key) {
            selected.insert(key.into(), value.clone());
        }
    }
    epoch(
        &[Value::Object(selected)],
        manifest,
        &groups,
        &[peer.clone()],
        &Value::Null,
    )
}
