//! Isolated Linux firewall worker. Kernel changes are confined to its own table.
pub mod kernel;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Policy {
    pub is_public: bool,
    pub allowed_ips: Vec<std::net::Ipv4Addr>,
}
pub mod store;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Sample {
    pub timestamp: i64,
    pub interval_seconds: f64,
    pub in_bytes: i64,
    pub out_bytes: i64,
    pub drop_bytes: i64,
    pub incoming_ips: Vec<String>,
    pub outgoing_ips: Vec<String>,
    pub blocked_ips: Vec<String>,
}

pub mod service;
