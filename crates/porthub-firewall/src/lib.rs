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
    /// Packet sources allowed by PortHub's own policy. None means legacy or
    /// unavailable telemetry; these are not application-delivery confirmations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_incoming_ips: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_incoming_ips_window_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_incoming_ips_address_families: Option<Vec<String>>,
    pub outgoing_ips: Vec<String>,
    pub blocked_ips: Vec<String>,
}

pub mod service;
