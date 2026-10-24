//! Private IP packet transport: ICE connectivity plus certificate-pinned DTLS.
//! The protocol core owns neither sockets nor background timers.
pub const MAX_PACKET: usize = 1380;
pub mod protocol;
pub mod relay;
pub mod stun;
pub mod udp;
pub use protocol::{Description, Identity, Kind, Peer, State};
