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
                    // Enrolled IDs are owner:ObjectId + machine:ObjectId. The
                    // resolver also reuses lease.peer.id for normal renewal.
                    !q.value.is_empty() && q.value.len()<=60 && match q.value.split_once(':') {
                        Some((owner,machine))=>[owner,machine].iter().all(|part|part.len()==24&&part.bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase())),
                        None=>q.value.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'-'),
                    }
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
    #[test]
    fn actual_enrollment_objectid_pairs_are_valid_cold_peer_queries(){
        let request=|value:&str|Request{protocol:1,sequence:1,wanted:vec![Lookup{kind:"peer".into(),value:value.into()}]};
        assert!(request("0123456789abcdef01234567:89abcdef0123456789abcdef").validate().is_ok());
        assert!(request("legacy-peer-42").validate().is_ok());
        for invalid in ["owner:machine","0123456789abcdef01234567:","0123456789abcdef01234567:89abcdef0123456789abcde:","0123456789abcdef01234567:89ABCDEF0123456789abcdef","0123456789abcdef01234567:89abcdef0123456789abcdef:extra"] {
            assert!(request(invalid).validate().is_err(),"malformed peer identifier accepted");
        }
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

/// Prepared binding for negotiated exit-pair publication. Not advertised or used
/// by current sync until the corresponding runtime intent/lease path is wired.
/// Independent of ordinary rule books: exit edits must not revoke private ACLs,
/// and private rule edits must not independently revoke valid exit permissions.
/// Caller supplies only current enabled routes from this authenticated workspace.
pub fn local_exit_epoch(machine:&Value,peer:&Value,routes:&[Value])->String {
    let mut routes:Vec<_>=routes.iter().map(|route|{
        let mut selected=serde_json::Map::new();
        for key in ["_id","workspace_id","enabled","created_at","routing_selectors","distribution_selectors","selection","traffic_mode","tor_enabled","tor_circuit_groups","allow_direct_fallback"] {
            if let Some(value)=route.get(key){selected.insert(key.into(),value.clone());}
        }
        Value::Object(selected)
    }).collect();
    routes.sort_by_key(|route|route["_id"].to_string());
    format!("{:x}",Sha256::digest(serde_json::to_vec(&json!({"exit_pair_protocol":1,"identity_epoch":local_epoch(machine,&[],&HashMap::new(),peer),"local_exit_capabilities":{"lan_exit":peer["lan_exit"],"tor_exit":peer["tor_exit"],"protocol":peer["exit_pair_protocol"]},"exit_routes":routes})).expect("typed exit epoch")))
}
#[cfg(test)]
mod exit_epoch_tests {
    use super::*;
    #[test]
    fn exit_epoch_binds_rules_selection_modes_roles_and_membership() {
        let machine=json!({"_id":"m","user_id":"o","group_ids":["g"]});
        let peer=json!({"_id":"o:m","owner_id":"o","workspace_id":"o","machine_id":"m","credential_hash":"credential","ip":"10.1.0.1","enabled":true});
        let route=json!({"_id":"r","workspace_id":"o","enabled":true,"created_at":1,"routing_selectors":[{"kind":"machine","id":"router"}],"distribution_selectors":[{"kind":"group","id":"g"}],"selection":"sticky","traffic_mode":"internet_only","tor_enabled":false,"tor_circuit_groups":4,"allow_direct_fallback":false});
        let hash=|m:&Value,r:Value|local_exit_epoch(m,&peer,&[r]);let original=hash(&machine,route.clone());
        for (field,value) in [("enabled",json!(false)),("created_at",json!(2)),("routing_selectors",json!([])),("distribution_selectors",json!([])),("selection",json!("round_robin")),("traffic_mode",json!("lan_only")),("tor_enabled",json!(true)),("tor_circuit_groups",json!(8)),("allow_direct_fallback",json!(true))] {
            let mut changed=route.clone();changed[field]=value;assert_ne!(original,hash(&machine,changed),"exit field {field} did not revoke old binding");
        }
        for field in ["lan_exit","tor_exit","exit_pair_protocol"] {
            let mut changed=peer.clone();changed[field]=json!(1);
            assert_ne!(original,local_exit_epoch(&machine,&changed,&[route.clone()]),"local capability {field} was not bound");
        }
        let mut removed=machine.clone();removed["group_ids"]=json!([]);assert_ne!(original,hash(&removed,route.clone()));
        let mut cosmetic=route.clone();cosmetic["name"]=json!("Renamed");cosmetic["updated_at"]=json!(42);assert_eq!(original,hash(&machine,cosmetic));
        assert_ne!(original,local_epoch(&machine,&[],&HashMap::new(),&peer));
    }
    #[test]
    fn exit_epoch_ignores_cursor_order_but_preserves_selector_priority() {
        let a=json!({"_id":"a","routing_selectors":[{"kind":"machine","id":"first"},{"kind":"machine","id":"second"}]});let b=json!({"_id":"b"});
        let hash=|routes:&[Value]|local_exit_epoch(&json!({}),&json!({}),routes);
        assert_eq!(hash(&[a.clone(),b.clone()]),hash(&[b.clone(),a.clone()]));
        let mut reordered=a.clone();reordered["routing_selectors"].as_array_mut().unwrap().reverse();assert_ne!(hash(&[a,b.clone()]),hash(&[reordered,b]));
    }
}
