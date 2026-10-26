//! Private control envelopes carried inside authenticated peer/relay transports.
//! Source and destination must also be checked against the authenticated peer
//! and current policy by the consumer; the envelope is not authentication.
use anyhow::{ensure, Result};
use bytes::Bytes;
use std::net::Ipv4Addr;
pub const EXIT: u8 = 252;
pub const STREAM: u8 = 253;
pub const PROBE: u8 = 254;
pub struct Envelope {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub payload: Bytes,
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair) as u32)
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
pub fn encode(
    protocol: u8,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: &[u8],
) -> Result<Bytes> {
    ensure!(
        matches!(protocol, EXIT | STREAM | PROBE)
            && source.is_private()
            && destination.is_private()
            && source != destination
            && !payload.is_empty()
            && payload.len() <= crate::MAX_PACKET - 20,
        "invalid private control envelope"
    );
    let mut packet = vec![0; 20 + payload.len()];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..].copy_from_slice(payload);
    Ok(packet.into())
}
pub fn decode(protocol: u8, packet: Bytes) -> Option<Envelope> {
    if !matches!(protocol, EXIT | STREAM | PROBE)
        || !(21..=crate::MAX_PACKET).contains(&packet.len())
        || packet[0] != 0x45
        || packet[9] != protocol
        || packet[6] & 0x3f != 0
        || packet[7] != 0
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        || checksum(&packet[..20]) != 0
    {
        return None;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if !source.is_private() || !destination.is_private() || source == destination {
        return None;
    }
    Some(Envelope {
        source,
        destination,
        payload: packet.slice(20..),
    })
}
