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
pub mod protocol;
pub mod relay;
#[cfg(feature = "streams")]
pub mod streams;
pub mod stun;
pub mod udp;
pub use protocol::{Description, Identity, Kind, Peer, State};
/// Prefer Linux BBR where available, retaining the kernel default otherwise.
/// The optional override affects only PortHub sockets, never host defaults.
pub fn configure_tcp(stream: &tokio::net::TcpStream) {
    #[cfg(target_os = "linux")]
    {
        let algorithm = std::env::var("PORTHUB_TCP_CONGESTION").unwrap_or_else(|_| "bbr".into());
        if matches!(algorithm.as_str(), "bbr" | "cubic") {
            // Unsupported kernels retain their existing congestion control.
            let _ = socket2::SockRef::from(stream).set_tcp_congestion(algorithm.as_bytes());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = stream;
}
