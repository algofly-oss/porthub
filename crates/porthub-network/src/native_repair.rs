//! Authenticated native collision report. This is a repair request, never a
//! route grant or permission to choose another machine's address.
use anyhow::{ensure,Result};
use serde::{Deserialize,Serialize};
use std::{collections::BTreeSet,net::Ipv4Addr};
use porthub_mesh::lan_routes::Network;
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request{pub protocol:u8,pub nonce:String,pub source:Ipv4Addr,pub blocked:Vec<Network>}
impl Request{
    pub fn validate(&self)->Result<()>{
        ensure!(self.protocol==1&&self.source.is_private()&&self.nonce.len()==32&&self.nonce.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"invalid native repair identity");
        ensure!(!self.blocked.is_empty()&&self.blocked.len()<=crate::capture_routes::MAX_CAPTURE_PREFIXES,"native repair scope exceeds capture budget");
        let mut seen=BTreeSet::new();for pool in &self.blocked{ensure!(seen.insert(pool.to_string()),"duplicate native repair pool");}Ok(())
    }
}
#[cfg(test)]mod tests{use super::*;
    #[test]fn exact_bounded_request_never_accepts_foreign_or_unversioned_shape(){
        let mut r=Request{protocol:1,nonce:"a".repeat(32),source:"10.203.0.2".parse().unwrap(),blocked:vec!["10.203.0.0/24".parse().unwrap()]};assert!(r.validate().is_ok());
        r.protocol=2;assert!(r.validate().is_err());r.protocol=1;r.blocked.push(r.blocked[0]);assert!(r.validate().is_err());r.blocked.pop();r.source="192.0.2.2".parse().unwrap();assert!(r.validate().is_err());
        assert!(serde_json::from_value::<Request>(serde_json::json!({"protocol":1,"nonce":"a".repeat(32),"source":"10.203.0.2","blocked":["10.203.0.0/24"],"new_ip":"10.204.0.2"})).is_err());
    }
}
