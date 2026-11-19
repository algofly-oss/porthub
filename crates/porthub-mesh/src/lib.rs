//! Private IP packet transport: ICE connectivity plus certificate-pinned DTLS.
//! The protocol core owns neither sockets nor background timers.
pub const MAX_PACKET: usize = 1380;
/// Marker for negotiated batches on the authenticated gateway packet relay.
pub const RELAY_BATCH_MAGIC: &[u8; 4] = batch::LEGACY;
pub mod batch;
pub mod control_packet;
pub mod underlay;
pub mod dns_policy;
pub mod exit_policy;
pub mod lan_routes;
pub mod protocol;
pub mod relay;
#[cfg(feature = "streams")]
pub mod streams;
pub mod stun;
pub mod udp;
pub use protocol::{Description, Identity, Kind, Peer, State};
pub use porthub_io::configure_tcp;

pub mod traffic_report;

pub mod relay_origin;
