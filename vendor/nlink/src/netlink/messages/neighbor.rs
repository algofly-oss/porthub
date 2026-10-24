//! Strongly-typed neighbor message.

use std::net::IpAddr;

use winnow::{prelude::*, token::take};

use crate::netlink::{
    error::Result,
    parse::{FromNetlink, PResult, ToNetlink, parse_ip_addr},
    types::neigh::{NdMsg, NeighborState},
};

/// Attribute IDs for NDA_* constants.
mod attr_ids {
    pub const NDA_DST: u16 = 1;
    pub const NDA_LLADDR: u16 = 2;
    pub const NDA_CACHEINFO: u16 = 3;
    pub const NDA_PROBES: u16 = 4;
    pub const NDA_VLAN: u16 = 5;
    pub const NDA_PORT: u16 = 6;
    pub const NDA_VNI: u16 = 7;
    pub const NDA_IFINDEX: u16 = 8;
    pub const NDA_MASTER: u16 = 9;
}

/// Strongly-typed neighbor message with all attributes parsed.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct NeighborMessage {
    /// Fixed-size header.
    pub(crate) header: NdMsg,
    /// Destination address (NDA_DST).
    pub(crate) destination: Option<IpAddr>,
    /// Link-layer address (NDA_LLADDR).
    pub(crate) lladdr: Option<Vec<u8>>,
    /// Number of probes (NDA_PROBES).
    pub(crate) probes: Option<u32>,
    /// VLAN ID (NDA_VLAN).
    pub(crate) vlan: Option<u16>,
    /// Port (NDA_PORT).
    pub(crate) port: Option<u16>,
    /// VNI (NDA_VNI).
    pub(crate) vni: Option<u32>,
    /// Interface index (NDA_IFINDEX).
    pub(crate) ifindex_attr: Option<u32>,
    /// Master device index (NDA_MASTER).
    pub(crate) master: Option<u32>,
    /// Cache info.
    pub(crate) cache_info: Option<NeighborCacheInfo>,
}

/// Neighbor cache information.
#[derive(Debug, Clone, Copy, Default)]
pub struct NeighborCacheInfo {
    /// Time since confirmed.
    pub confirmed: u32,
    /// Time since used.
    pub used: u32,
    /// Time since updated.
    pub updated: u32,
    /// Reference count.
    pub refcnt: u32,
}

impl NeighborMessage {
    /// Create a new empty neighbor message.
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Accessor methods
    // =========================================================================

    /// Get the address family.
    pub fn family(&self) -> u8 {
        self.header.ndm_family
    }

    /// Get the interface index.
    pub fn ifindex(&self) -> u32 {
        self.header.ndm_ifindex as u32
    }

    /// Get the neighbor state.
    pub fn state(&self) -> NeighborState {
        NeighborState::from(self.header.ndm_state)
    }

    /// Get the neighbor flags.
    pub fn flags(&self) -> u8 {
        self.header.ndm_flags
    }

    /// Get the destination address.
    pub fn destination(&self) -> Option<&IpAddr> {
        self.destination.as_ref()
    }

    /// Get the link-layer address as bytes.
    pub fn lladdr(&self) -> Option<&[u8]> {
        self.lladdr.as_deref()
    }

    /// Get the number of probes.
    pub fn probes(&self) -> Option<u32> {
        self.probes
    }

    /// Get the VLAN ID.
    pub fn vlan(&self) -> Option<u16> {
        self.vlan
    }

    /// Get the port.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Get the VNI.
    pub fn vni(&self) -> Option<u32> {
        self.vni
    }

    /// Get the master device index.
    pub fn master(&self) -> Option<u32> {
        self.master
    }

    /// Get the cache info.
    pub fn cache_info(&self) -> Option<&NeighborCacheInfo> {
        self.cache_info.as_ref()
    }

    /// Format the link-layer address as a MAC string.
    pub fn mac_address(&self) -> Option<String> {
        let lladdr = self.lladdr.as_ref()?;
        if lladdr.len() == 6 {
            Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                lladdr[0], lladdr[1], lladdr[2], lladdr[3], lladdr[4], lladdr[5]
            ))
        } else {
            None
        }
    }

    // =========================================================================
    // Boolean checks
    // =========================================================================

    /// Check if this is an IPv4 neighbor.
    pub fn is_ipv4(&self) -> bool {
        self.header.ndm_family == libc::AF_INET as u8
    }

    /// Check if this is an IPv6 neighbor.
    pub fn is_ipv6(&self) -> bool {
        self.header.ndm_family == libc::AF_INET6 as u8
    }

    /// Check if the neighbor is reachable.
    pub fn is_reachable(&self) -> bool {
        self.header.ndm_state & 0x02 != 0 // NUD_REACHABLE
    }

    /// Check if the neighbor is permanent.
    pub fn is_permanent(&self) -> bool {
        self.header.ndm_state & 0x80 != 0 // NUD_PERMANENT
    }

    /// Check if the neighbor is stale.
    pub fn is_stale(&self) -> bool {
        self.header.ndm_state & 0x04 != 0 // NUD_STALE
    }

    /// Check if the neighbor is incomplete.
    pub fn is_incomplete(&self) -> bool {
        self.header.ndm_state & 0x01 != 0 // NUD_INCOMPLETE
    }

    /// Check if the neighbor failed.
    pub fn is_failed(&self) -> bool {
        self.header.ndm_state & 0x20 != 0 // NUD_FAILED
    }

    /// Check if this is a router (for IPv6).
    pub fn is_router(&self) -> bool {
        self.header.ndm_flags & 0x80 != 0 // NTF_ROUTER
    }

    /// Check if this is a proxy entry.
    pub fn is_proxy(&self) -> bool {
        self.header.ndm_flags & 0x08 != 0 // NTF_PROXY
    }
}

impl FromNetlink for NeighborMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // RTM_GETNEIGH requires an NdMsg header
        let header = NdMsg::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (12 bytes)
        if input.len() < NdMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(NdMsg::SIZE).parse_next(input)?;
        let header = *NdMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = NeighborMessage {
            header,
            ..Default::default()
        };

        // Parse attributes
        while !input.is_empty() && input.len() >= 4 {
            // 0.19 N9 — nla_len/nla_type are host-order, not LE.
            let len_bytes: &[u8] = take(2usize).parse_next(input)?;
            let type_bytes: &[u8] = take(2usize).parse_next(input)?;
            let len = u16::from_ne_bytes(len_bytes.try_into().unwrap()) as usize;
            let attr_type = u16::from_ne_bytes(type_bytes.try_into().unwrap());

            if len < 4 {
                break;
            }

            let payload_len = len.saturating_sub(4);
            if input.len() < payload_len {
                break;
            }

            let attr_data: &[u8] = take(payload_len).parse_next(input)?;

            // Align to 4 bytes
            let aligned = (len + 3) & !3;
            let padding = aligned.saturating_sub(len);
            if input.len() >= padding {
                let _: &[u8] = take(padding).parse_next(input)?;
            }

            // Match attribute type
            match attr_type & 0x3FFF {
                attr_ids::NDA_DST => {
                    if let Some(addr) = parse_dst(attr_data, header.ndm_family) {
                        msg.destination = Some(addr);
                    }
                }
                attr_ids::NDA_LLADDR => {
                    msg.lladdr = Some(attr_data.to_vec());
                }
                attr_ids::NDA_PROBES if attr_data.len() >= 4 => {
                    msg.probes = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::NDA_VLAN if attr_data.len() >= 2 => {
                    msg.vlan = Some(u16::from_ne_bytes(attr_data[..2].try_into().unwrap()));
                }
                attr_ids::NDA_PORT if attr_data.len() >= 2 => {
                    msg.port = Some(u16::from_be_bytes(attr_data[..2].try_into().unwrap()));
                }
                attr_ids::NDA_VNI if attr_data.len() >= 4 => {
                    msg.vni = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::NDA_IFINDEX if attr_data.len() >= 4 => {
                    msg.ifindex_attr = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::NDA_MASTER if attr_data.len() >= 4 => {
                    msg.master = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::NDA_CACHEINFO if attr_data.len() >= 16 => {
                    msg.cache_info = Some(NeighborCacheInfo {
                        confirmed: u32::from_ne_bytes(attr_data[0..4].try_into().unwrap()),
                        used: u32::from_ne_bytes(attr_data[4..8].try_into().unwrap()),
                        updated: u32::from_ne_bytes(attr_data[8..12].try_into().unwrap()),
                        refcnt: u32::from_ne_bytes(attr_data[12..16].try_into().unwrap()),
                    });
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

impl ToNetlink for NeighborMessage {
    fn netlink_len(&self) -> usize {
        let mut len = NdMsg::SIZE;

        if let Some(dst) = self.destination {
            len += nla_size(if dst.is_ipv4() { 4 } else { 16 });
        }
        if let Some(ref lladdr) = self.lladdr {
            len += nla_size(lladdr.len());
        }
        if self.vlan.is_some() {
            len += nla_size(2);
        }
        // 0.19 N5 — account for the new emit branches.
        if self.probes.is_some() {
            len += nla_size(4);
        }
        if self.port.is_some() {
            len += nla_size(2);
        }
        if self.vni.is_some() {
            len += nla_size(4);
        }
        if self.ifindex_attr.is_some() {
            len += nla_size(4);
        }
        if self.master.is_some() {
            len += nla_size(4);
        }
        if self.cache_info.is_some() {
            len += nla_size(16);
        }

        len
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();

        // Write header
        buf.extend_from_slice(self.header.as_bytes());

        // Write attributes
        if let Some(ref dst) = self.destination {
            write_attr_ip(buf, attr_ids::NDA_DST, dst);
        }
        if let Some(ref lladdr) = self.lladdr {
            write_attr_bytes(buf, attr_ids::NDA_LLADDR, lladdr);
        }
        if let Some(vlan) = self.vlan {
            write_attr_u16(buf, attr_ids::NDA_VLAN, vlan);
        }
        // 0.19 N5 — NDA_PROBES / _PORT / _VNI / _IFINDEX / _MASTER /
        // _CACHEINFO were parsed but never emitted. Blocked typed
        // VXLAN FDB programming via NeighborMessage; users had to
        // drop to raw MessageBuilder.
        if let Some(probes) = self.probes {
            write_attr_u32(buf, attr_ids::NDA_PROBES, probes);
        }
        if let Some(port) = self.port {
            // NDA_PORT travels big-endian (it's a UDP port — matches
            // the BE parse on the read side at line 264).
            write_attr_u16_be(buf, attr_ids::NDA_PORT, port);
        }
        if let Some(vni) = self.vni {
            write_attr_u32(buf, attr_ids::NDA_VNI, vni);
        }
        if let Some(ifindex_attr) = self.ifindex_attr {
            write_attr_u32(buf, attr_ids::NDA_IFINDEX, ifindex_attr);
        }
        if let Some(master) = self.master {
            write_attr_u32(buf, attr_ids::NDA_MASTER, master);
        }
        if let Some(ref ci) = self.cache_info {
            write_attr_cache_info(buf, attr_ids::NDA_CACHEINFO, ci);
        }

        Ok(buf.len() - start)
    }
}

/// Decode `NDA_DST`.
///
/// An ARP or ND entry's family says how wide the address is. An FDB entry
/// (`AF_BRIDGE`) carries the VXLAN remote it points at, in either family,
/// and only the length tells which (`vxlan_nla_put_addr` writes 4 or 16
/// bytes). This used to decode by family alone, so the remote of every FDB
/// entry read as absent (`FdbEntry::dst()` was always `None`).
fn parse_dst(data: &[u8], family: u8) -> Option<IpAddr> {
    if family == libc::AF_INET as u8 || family == libc::AF_INET6 as u8 {
        return parse_ip_addr(data, family).ok();
    }
    match data.len() {
        4 => <[u8; 4]>::try_from(data).ok().map(IpAddr::from),
        16 => <[u8; 16]>::try_from(data).ok().map(IpAddr::from),
        _ => None,
    }
}

/// Calculate aligned attribute size.
fn nla_size(payload_len: usize) -> usize {
    (4 + payload_len + 3) & !3
}

fn write_attr_u16(buf: &mut Vec<u8>, attr_type: u16, value: u16) {
    let len: u16 = 6;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_ne_bytes());
    buf.push(0); // padding
    buf.push(0);
}

/// Write a u16 attribute in big-endian. 0.19 N5 — used for
/// `NDA_PORT` which carries a UDP port (VXLAN remote dest port).
fn write_attr_u16_be(buf: &mut Vec<u8>, attr_type: u16, value: u16) {
    let len: u16 = 6;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_be_bytes());
    buf.push(0); // padding
    buf.push(0);
}

fn write_attr_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    let len: u16 = 8;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_ne_bytes());
}

/// Write an `NDA_CACHEINFO` attribute — 4×u32 (`ndm_cacheinfo`).
/// 0.19 N5.
fn write_attr_cache_info(buf: &mut Vec<u8>, attr_type: u16, ci: &NeighborCacheInfo) {
    let len: u16 = 4 + 16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&ci.confirmed.to_ne_bytes());
    buf.extend_from_slice(&ci.used.to_ne_bytes());
    buf.extend_from_slice(&ci.updated.to_ne_bytes());
    buf.extend_from_slice(&ci.refcnt.to_ne_bytes());
}

fn write_attr_bytes(buf: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    let len = 4 + value.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(value);
    // Padding
    let aligned = (len + 3) & !3;
    for _ in 0..(aligned - len) {
        buf.push(0);
    }
}

fn write_attr_ip(buf: &mut Vec<u8>, attr_type: u16, addr: &IpAddr) {
    let octets = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let len = 4 + octets.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&octets);
    // Padding
    let aligned = (len + 3) & !3;
    for _ in 0..(aligned - len) {
        buf.push(0);
    }
}

/// Builder for constructing NeighborMessage.
#[derive(Debug, Clone, Default)]
pub struct NeighborMessageBuilder {
    msg: NeighborMessage,
}

impl NeighborMessageBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn ifindex(mut self, index: u32) -> Self {
        self.msg.header.ndm_ifindex = index as i32;
        self
    }

    /// Set the destination address.
    pub fn destination(mut self, addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => self.msg.header.ndm_family = libc::AF_INET as u8,
            IpAddr::V6(_) => self.msg.header.ndm_family = libc::AF_INET6 as u8,
        }
        self.msg.destination = Some(addr);
        self
    }

    /// Set the link-layer address.
    pub fn lladdr(mut self, addr: Vec<u8>) -> Self {
        self.msg.lladdr = Some(addr);
        self
    }

    /// Set the neighbor state.
    pub fn state(mut self, state: NeighborState) -> Self {
        self.msg.header.ndm_state = state as u16;
        self
    }

    /// Set the neighbor flags.
    pub fn flags(mut self, flags: u8) -> Self {
        self.msg.header.ndm_flags = flags;
        self
    }

    /// Mark as permanent.
    pub fn permanent(mut self) -> Self {
        self.msg.header.ndm_state |= 0x80; // NUD_PERMANENT
        self
    }

    /// Set VLAN ID.
    pub fn vlan(mut self, vlan: u16) -> Self {
        self.msg.vlan = Some(vlan);
        self
    }

    /// Set the probe count (`NDA_PROBES`). 0.19 N5.
    pub fn probes(mut self, n: u32) -> Self {
        self.msg.probes = Some(n);
        self
    }

    /// Set the UDP port (`NDA_PORT`). Serialised big-endian on
    /// the wire (VXLAN-style). 0.19 N5.
    pub fn port(mut self, udp_port: u16) -> Self {
        self.msg.port = Some(udp_port);
        self
    }

    /// Set the VXLAN VNI (`NDA_VNI`). 0.19 N5.
    ///
    /// Combined with [`Self::port`] and [`Self::master`] this lets
    /// callers express a complete VXLAN FDB entry through the
    /// typed API.
    pub fn vni(mut self, vni: u32) -> Self {
        self.msg.vni = Some(vni);
        self
    }

    /// Set the alternative interface-index attribute (`NDA_IFINDEX`).
    /// Distinct from the header's `ndm_ifindex` — used when the
    /// neighbor is reached via a different interface than the
    /// containing message implies. 0.19 N5.
    pub fn ifindex_attr(mut self, ifindex: u32) -> Self {
        self.msg.ifindex_attr = Some(ifindex);
        self
    }

    /// Set the master device index (`NDA_MASTER`) — typically the
    /// bridge this FDB entry belongs to. 0.19 N5.
    pub fn master(mut self, ifindex: u32) -> Self {
        self.msg.master = Some(ifindex);
        self
    }

    /// Set the cache info (`NDA_CACHEINFO`). Mostly useful for
    /// replay / test fixtures; the kernel computes its own. 0.19 N5.
    pub fn cache_info(mut self, info: NeighborCacheInfo) -> Self {
        self.msg.cache_info = Some(info);
        self
    }

    /// Build the message.
    pub fn build(self) -> NeighborMessage {
        self.msg
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_builder() {
        let msg = NeighborMessageBuilder::new()
            .ifindex(2)
            .destination(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .lladdr(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .permanent()
            .build();

        assert_eq!(msg.ifindex(), 2);
        assert!(msg.is_ipv4());
        assert!(msg.is_permanent());
        assert_eq!(msg.mac_address(), Some("00:11:22:33:44:55".to_string()));
    }

    /// 0.19 N5 — verify every emitted attribute survives a
    /// `write_to → parse` round-trip. Pre-fix, `probes`, `port`,
    /// `vni`, `ifindex_attr`, `master`, and `cache_info` were
    /// silently dropped on the write side. This blocked
    /// expressing complete VXLAN FDB entries through
    /// `NeighborMessageBuilder` — users had to drop to raw
    /// `MessageBuilder`. Test asserts the typed builder can now
    /// program a full VXLAN FDB entry end-to-end.
    #[test]
    fn write_to_preserves_all_attrs_roundtrip() {
        let original = NeighborMessageBuilder::new()
            .ifindex(2)
            .destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
            .lladdr(vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .vlan(100)
            .probes(0)
            .port(4789) // VXLAN UDP port
            .vni(4096)
            .ifindex_attr(3)
            .master(7)
            .cache_info(NeighborCacheInfo {
                confirmed: 1,
                used: 2,
                updated: 3,
                refcnt: 1,
            })
            .permanent()
            .build();

        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();

        let parsed = NeighborMessage::parse(&mut buf.as_slice()).unwrap();

        assert_eq!(parsed.probes, Some(0));
        assert_eq!(parsed.port, Some(4789), "NDA_PORT must round-trip BE-encoded");
        assert_eq!(parsed.vni, Some(4096));
        assert_eq!(parsed.ifindex_attr, Some(3));
        assert_eq!(parsed.master, Some(7));
        let ci = parsed.cache_info.as_ref().expect("NDA_CACHEINFO");
        assert_eq!(ci.confirmed, 1);
        assert_eq!(ci.used, 2);
        assert_eq!(ci.updated, 3);
        assert_eq!(ci.refcnt, 1);
        // Spot-check pre-existing fields.
        assert_eq!(parsed.vlan, Some(100));
        assert_eq!(parsed.destination, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    /// An FDB entry (`AF_BRIDGE`) carries a VXLAN remote of either family
    /// in `NDA_DST`; only its length says which.
    #[test]
    fn an_fdb_entry_s_remote_is_decoded_by_length() {
        for dst in [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
        ] {
            let mut msg = NeighborMessageBuilder::new()
                .ifindex(2)
                .destination(dst)
                .lladdr(vec![0; 6])
                .build();
            msg.header.ndm_family = libc::AF_BRIDGE as u8;
            let mut buf = Vec::new();
            msg.write_to(&mut buf).unwrap();
            assert_eq!(buf.len(), msg.netlink_len());
            let parsed = NeighborMessage::parse(&mut buf.as_slice()).unwrap();
            assert_eq!(parsed.destination, Some(dst));
        }
    }
}
