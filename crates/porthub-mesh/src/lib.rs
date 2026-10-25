//! Private IP packet transport: ICE connectivity plus certificate-pinned DTLS.
//! The protocol core owns neither sockets nor background timers.
pub const MAX_PACKET: usize = 1380;
/// Marker for negotiated batches on the authenticated gateway packet relay.
pub const RELAY_BATCH_MAGIC: &[u8; 4] = b"PHB1";
pub mod protocol;
pub mod relay;
pub mod stun;
pub mod udp;
pub use protocol::{Description, Identity, Kind, Peer, State};
