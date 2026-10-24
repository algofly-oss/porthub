//! Strongly-typed routing rule message.

use std::net::IpAddr;

use winnow::{prelude::*, token::take};
use zerocopy::FromBytes;

use crate::netlink::{
    attr::NLA_TYPE_MASK,
    parse::{FromNetlink, PResult, parse_ip_addr},
    types::rule::{FibRuleAction, FibRuleHdr, FibRulePortRange, FibRuleUidRange},
};

/// Attribute IDs for FRA_* constants.
mod attr_ids {
    pub const FRA_DST: u16 = 1;
    pub const FRA_SRC: u16 = 2;
    pub const FRA_IIFNAME: u16 = 3;
    pub const FRA_GOTO: u16 = 4;
    pub const FRA_PRIORITY: u16 = 6;
    pub const FRA_FWMARK: u16 = 10;
    pub const FRA_FLOW: u16 = 11;
    pub const FRA_TUN_ID: u16 = 12;
    pub const FRA_SUPPRESS_IFGROUP: u16 = 13;
    pub const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
    pub const FRA_TABLE: u16 = 15;
    pub const FRA_FWMASK: u16 = 16;
    pub const FRA_OIFNAME: u16 = 17;
    pub const FRA_L3MDEV: u16 = 19;
    pub const FRA_UID_RANGE: u16 = 20;
    pub const FRA_PROTOCOL: u16 = 21;
    pub const FRA_IP_PROTO: u16 = 22;
    pub const FRA_SPORT_RANGE: u16 = 23;
    pub const FRA_DPORT_RANGE: u16 = 24;
}

/// Strongly-typed routing rule message with all attributes parsed.
///
/// Fields are `pub(crate)`; consumers read via the per-field accessor
/// methods (see [`Self::priority`], [`Self::source`], etc.). The
/// struct is `#[non_exhaustive]` so the kernel can grow new attribute
/// fields without it being a breaking change.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RuleMessage {
    /// Fixed-size header.
    pub(crate) header: FibRuleHdr,
    /// Rule priority (FRA_PRIORITY).
    pub(crate) priority: u32,
    /// Source address (FRA_SRC).
    pub(crate) source: Option<IpAddr>,
    /// Destination address (FRA_DST).
    pub(crate) destination: Option<IpAddr>,
    /// Input interface name (FRA_IIFNAME).
    pub(crate) iifname: Option<String>,
    /// Output interface name (FRA_OIFNAME).
    pub(crate) oifname: Option<String>,
    /// Firewall mark (FRA_FWMARK).
    pub(crate) fwmark: Option<u32>,
    /// Firewall mark mask (FRA_FWMASK).
    pub(crate) fwmask: Option<u32>,
    /// Routing table ID (FRA_TABLE, overrides header.table).
    pub(crate) table: u32,
    /// Goto target rule priority (FRA_GOTO).
    pub(crate) goto: Option<u32>,
    /// Flow classification ID (FRA_FLOW).
    pub(crate) flow: Option<u32>,
    /// Tunnel ID (FRA_TUN_ID).
    pub(crate) tun_id: Option<u64>,
    /// Suppress interface group (FRA_SUPPRESS_IFGROUP).
    pub(crate) suppress_ifgroup: Option<u32>,
    /// Suppress prefix length (FRA_SUPPRESS_PREFIXLEN).
    pub(crate) suppress_prefixlen: Option<u32>,
    /// L3 master device (FRA_L3MDEV).
    pub(crate) l3mdev: Option<u8>,
    /// UID range (FRA_UID_RANGE).
    pub(crate) uid_range: Option<FibRuleUidRange>,
    /// Rule protocol (FRA_PROTOCOL).
    pub(crate) protocol: Option<u8>,
    /// IP protocol for port matching (FRA_IP_PROTO).
    pub(crate) ip_proto: Option<u8>,
    /// Source port range (FRA_SPORT_RANGE).
    pub(crate) sport_range: Option<FibRulePortRange>,
    /// Destination port range (FRA_DPORT_RANGE).
    pub(crate) dport_range: Option<FibRulePortRange>,
}

impl RuleMessage {
    /// Create a new empty rule message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the address family as the raw `AF_*` byte (kernel wire form).
    pub fn family(&self) -> u8 {
        self.header.family
    }

    /// Get the address family as a typed [`crate::AddressFamily`] (Plan 227).
    ///
    /// Prefer this over the raw [`Self::family`] in new code — the typed
    /// form lets the caller compare against `AddressFamily::v4()` /
    /// `AddressFamily::v6()` without remembering `AF_*` magic numbers,
    /// and gracefully exposes unmodelled bytes via
    /// [`crate::AddressFamily::is_known`].
    pub fn family_typed(&self) -> crate::AddressFamily {
        crate::AddressFamily::from_raw(self.header.family)
    }

    /// Check if this is an IPv4 rule.
    pub fn is_ipv4(&self) -> bool {
        self.header.family == libc::AF_INET as u8
    }

    /// Check if this is an IPv6 rule.
    pub fn is_ipv6(&self) -> bool {
        self.header.family == libc::AF_INET6 as u8
    }

    /// Get the source prefix length.
    pub fn src_len(&self) -> u8 {
        self.header.src_len
    }

    /// Get the destination prefix length.
    pub fn dst_len(&self) -> u8 {
        self.header.dst_len
    }

    /// Get the rule action.
    pub fn action(&self) -> FibRuleAction {
        FibRuleAction::from(self.header.action)
    }

    /// Check if this is a table lookup rule.
    pub fn is_lookup(&self) -> bool {
        self.action() == FibRuleAction::ToTbl
    }

    /// Check if this is a blackhole rule.
    pub fn is_blackhole(&self) -> bool {
        self.action() == FibRuleAction::Blackhole
    }

    /// Check if this is an unreachable rule.
    pub fn is_unreachable(&self) -> bool {
        self.action() == FibRuleAction::Unreachable
    }

    /// Check if this is a prohibit rule.
    pub fn is_prohibit(&self) -> bool {
        self.action() == FibRuleAction::Prohibit
    }

    /// Whether the rule matches what its selectors do not (`ip rule …
    /// not`, `FIB_RULE_INVERT`).
    pub fn is_invert(&self) -> bool {
        self.header.flags & crate::netlink::rule::FIB_RULE_INVERT != 0
    }

    /// Get the routing table ID.
    pub fn table_id(&self) -> u32 {
        self.table
    }

    /// Check if this is a default rule (priority 0, 32766, or 32767).
    pub fn is_default(&self) -> bool {
        self.priority == 0 || self.priority == 32766 || self.priority == 32767
    }

    // -------- Per-field accessors -----------------
    //
    // As of 0.21 the fields themselves are `pub(crate)` and these
    // accessors are the public surface. The 0.20.1 transition shipped
    // the accessors additively (with pub fields still visible); 0.21
    // closes the convention by demoting field visibility and adding
    // #[non_exhaustive] to the struct.

    /// Rule priority (FRA_PRIORITY). Returns `0` when the kernel
    /// did not set the attribute.
    pub fn priority(&self) -> u32 {
        self.priority
    }

    /// Source address (FRA_SRC), if present.
    pub fn source(&self) -> Option<IpAddr> {
        self.source
    }

    /// Destination address (FRA_DST), if present.
    pub fn destination(&self) -> Option<IpAddr> {
        self.destination
    }

    /// Input interface name (FRA_IIFNAME), if present.
    pub fn iifname(&self) -> Option<&str> {
        self.iifname.as_deref()
    }

    /// Output interface name (FRA_OIFNAME), if present.
    pub fn oifname(&self) -> Option<&str> {
        self.oifname.as_deref()
    }

    /// Firewall mark (FRA_FWMARK), if present.
    pub fn fwmark(&self) -> Option<u32> {
        self.fwmark
    }

    /// Firewall mark mask (FRA_FWMASK), if present.
    pub fn fwmask(&self) -> Option<u32> {
        self.fwmask
    }

    /// Routing table ID. Returns the 32-bit `FRA_TABLE` override
    /// when present, else the 8-bit `header.table`.
    pub fn table(&self) -> u32 {
        self.table
    }

    /// Goto target rule priority (FRA_GOTO), if present.
    pub fn goto(&self) -> Option<u32> {
        self.goto
    }

    /// Flow classification ID (FRA_FLOW), if present.
    pub fn flow(&self) -> Option<u32> {
        self.flow
    }

    /// Tunnel ID (FRA_TUN_ID), if present.
    pub fn tun_id(&self) -> Option<u64> {
        self.tun_id
    }

    /// Suppress interface group (FRA_SUPPRESS_IFGROUP), if present.
    pub fn suppress_ifgroup(&self) -> Option<u32> {
        self.suppress_ifgroup
    }

    /// Suppress prefix length (FRA_SUPPRESS_PREFIXLEN), if present.
    pub fn suppress_prefixlen(&self) -> Option<u32> {
        self.suppress_prefixlen
    }

    /// L3 master device flag (FRA_L3MDEV), if present.
    pub fn l3mdev(&self) -> Option<u8> {
        self.l3mdev
    }

    /// UID range (FRA_UID_RANGE), if present.
    pub fn uid_range(&self) -> Option<FibRuleUidRange> {
        self.uid_range
    }

    /// Rule protocol (FRA_PROTOCOL), if present.
    pub fn protocol(&self) -> Option<u8> {
        self.protocol
    }

    /// IP protocol for port matching (FRA_IP_PROTO), if present.
    pub fn ip_proto(&self) -> Option<u8> {
        self.ip_proto
    }

    /// Source port range (FRA_SPORT_RANGE), if present.
    pub fn sport_range(&self) -> Option<FibRulePortRange> {
        self.sport_range
    }

    /// Destination port range (FRA_DPORT_RANGE), if present.
    pub fn dport_range(&self) -> Option<FibRulePortRange> {
        self.dport_range
    }
}

impl FromNetlink for RuleMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // RTM_GETRULE requires a FibRuleHdr header
        let header = FibRuleHdr::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse the fixed header
        let header_bytes: &[u8] = take(FibRuleHdr::SIZE).parse_next(input)?;
        let header = *FibRuleHdr::ref_from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = RuleMessage {
            table: header.table as u32,
            header,
            ..Default::default()
        };

        // Parse attributes
        while input.len() >= 4 {
            // 0.19 N9 — `struct nlattr` `nla_len` / `nla_type` are
            // kernel native-endian. Pre-fix used `le_u16` which is
            // silently broken on big-endian platforms (s390x,
            // sparc64). winnow 1.0 has no `ne_u16` primitive so we
            // take 2 bytes and decode with `from_ne_bytes`.
            let len_bytes: &[u8] = take(2usize).parse_next(input)?;
            let type_bytes: &[u8] = take(2usize).parse_next(input)?;
            let attr_len = u16::from_ne_bytes(len_bytes.try_into().unwrap());
            let attr_type = u16::from_ne_bytes(type_bytes.try_into().unwrap());

            if attr_len < 4 {
                break;
            }

            let data_len = (attr_len as usize).saturating_sub(4);
            if input.len() < data_len {
                break;
            }

            let attr_data: &[u8] = take(data_len).parse_next(input)?;

            // Skip to alignment
            let padding = (4 - (attr_len as usize % 4)) % 4;
            if input.len() >= padding {
                let _ = take(padding).parse_next(input)?;
            }

            // 0.19 N9 — mask off both NLA_F_NESTED (0x8000) AND
            // NLA_F_NET_BYTEORDER (0x4000) via the canonical
            // `NLA_TYPE_MASK` (0x3fff). Pre-fix used `0x7fff`
            // which left bit 14 set, so any future kernel attr
            // shipped with NET_BYTEORDER set would silently miss
            // every match arm.
            let attr_type_masked = attr_type & NLA_TYPE_MASK;

            match attr_type_masked {
                attr_ids::FRA_PRIORITY if attr_data.len() >= 4 => {
                    msg.priority = u32::from_ne_bytes(attr_data[..4].try_into().unwrap());
                }
                attr_ids::FRA_SRC => {
                    if let Ok(addr) = parse_ip_addr(attr_data, msg.header.family) {
                        msg.source = Some(addr);
                    }
                }
                attr_ids::FRA_DST => {
                    if let Ok(addr) = parse_ip_addr(attr_data, msg.header.family) {
                        msg.destination = Some(addr);
                    }
                }
                attr_ids::FRA_IIFNAME => {
                    msg.iifname = parse_string(attr_data);
                }
                attr_ids::FRA_OIFNAME => {
                    msg.oifname = parse_string(attr_data);
                }
                attr_ids::FRA_FWMARK if attr_data.len() >= 4 => {
                    msg.fwmark = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::FRA_FWMASK if attr_data.len() >= 4 => {
                    msg.fwmask = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::FRA_TABLE if attr_data.len() >= 4 => {
                    msg.table = u32::from_ne_bytes(attr_data[..4].try_into().unwrap());
                }
                attr_ids::FRA_GOTO if attr_data.len() >= 4 => {
                    msg.goto = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::FRA_FLOW if attr_data.len() >= 4 => {
                    msg.flow = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::FRA_TUN_ID if attr_data.len() >= 8 => {
                    msg.tun_id = Some(u64::from_be_bytes(attr_data[..8].try_into().unwrap()));
                }
                attr_ids::FRA_SUPPRESS_IFGROUP if attr_data.len() >= 4 => {
                    msg.suppress_ifgroup =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::FRA_SUPPRESS_PREFIXLEN if attr_data.len() >= 4 => {
                    msg.suppress_prefixlen =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::FRA_L3MDEV if !attr_data.is_empty() => {
                    msg.l3mdev = Some(attr_data[0]);
                }
                attr_ids::FRA_UID_RANGE => {
                    if let Some(range) = FibRuleUidRange::from_bytes(attr_data) {
                        msg.uid_range = Some(*range);
                    }
                }
                attr_ids::FRA_PROTOCOL if !attr_data.is_empty() => {
                    msg.protocol = Some(attr_data[0]);
                }
                attr_ids::FRA_IP_PROTO if !attr_data.is_empty() => {
                    msg.ip_proto = Some(attr_data[0]);
                }
                attr_ids::FRA_SPORT_RANGE => {
                    if let Some(range) = FibRulePortRange::from_bytes(attr_data) {
                        msg.sport_range = Some(*range);
                    }
                }
                attr_ids::FRA_DPORT_RANGE => {
                    if let Some(range) = FibRulePortRange::from_bytes(attr_data) {
                        msg.dport_range = Some(*range);
                    }
                }
                _ => {}
            }
        }

        Ok(msg)
    }
}

/// Parse a null-terminated string from attribute data.
fn parse_string(data: &[u8]) -> Option<String> {
    // Find null terminator
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    std::str::from_utf8(&data[..end]).ok().map(String::from)
}

#[cfg(test)]
mod plan_231_tests {
    //! Plan 231 — accessor parity between the pub fields and the new
    //! per-field accessor methods.
    //!
    //! The fields stay `pub` (additivity in a patch release prohibits
    //! flipping their visibility), but every load-bearing field gets an
    //! accessor sibling. New code should prefer the accessors.

    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn accessor_round_trip_matches_field_state() {
        let mut r = RuleMessage::new();
        r.header.family = libc::AF_INET as u8;
        r.priority = 1000;
        r.source = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        r.iifname = Some("eth0".into());
        r.fwmark = Some(0x42);
        r.table = 100;

        assert_eq!(r.priority(), 1000);
        assert_eq!(r.family(), libc::AF_INET as u8);
        assert_eq!(r.family_typed(), crate::AddressFamily::v4());
        assert_eq!(r.source(), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))));
        assert_eq!(r.iifname(), Some("eth0"));
        assert_eq!(r.fwmark(), Some(0x42));
        assert_eq!(r.table(), 100);
    }

    #[test]
    fn family_typed_handles_unknown_byte() {
        let mut r = RuleMessage::new();
        r.header.family = 99;
        let af = r.family_typed();
        assert!(!af.is_known());
        assert_eq!(af.as_u8(), 99);
    }

    #[test]
    fn family_typed_v6() {
        let mut r = RuleMessage::new();
        r.header.family = libc::AF_INET6 as u8;
        assert_eq!(r.family_typed(), crate::AddressFamily::v6());
        assert!(r.is_ipv6());
    }

    #[test]
    fn accessors_default_to_none_for_optional_fields() {
        let r = RuleMessage::new();
        assert!(r.source().is_none());
        assert!(r.destination().is_none());
        assert!(r.iifname().is_none());
        assert!(r.oifname().is_none());
        assert!(r.fwmark().is_none());
        assert!(r.fwmask().is_none());
        assert!(r.goto().is_none());
        assert!(r.flow().is_none());
        assert!(r.tun_id().is_none());
        assert!(r.suppress_ifgroup().is_none());
        assert!(r.suppress_prefixlen().is_none());
        assert!(r.l3mdev().is_none());
        assert!(r.uid_range().is_none());
        assert!(r.protocol().is_none());
        assert!(r.ip_proto().is_none());
        assert!(r.sport_range().is_none());
        assert!(r.dport_range().is_none());
    }

    #[test]
    fn accessor_returns_match_field_reads() {
        // Catalogue test: every accessor returns the same value the
        // direct pub-field read does. This is the additive convention's
        // contract: the field stays the source of truth; the accessor
        // is sugar.
        let mut r = RuleMessage::new();
        r.priority = 50;
        r.source = Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        r.destination = Some(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        r.iifname = Some("a".into());
        r.oifname = Some("b".into());
        r.fwmark = Some(1);
        r.fwmask = Some(2);
        r.table = 99;
        r.goto = Some(3);
        r.flow = Some(4);
        r.tun_id = Some(5);
        r.suppress_ifgroup = Some(6);
        r.suppress_prefixlen = Some(7);
        r.l3mdev = Some(8);
        r.protocol = Some(9);
        r.ip_proto = Some(10);

        assert_eq!(r.priority(), r.priority);
        assert_eq!(r.source(), r.source);
        assert_eq!(r.destination(), r.destination);
        assert_eq!(r.iifname(), r.iifname.as_deref());
        assert_eq!(r.oifname(), r.oifname.as_deref());
        assert_eq!(r.fwmark(), r.fwmark);
        assert_eq!(r.fwmask(), r.fwmask);
        assert_eq!(r.table(), r.table);
        assert_eq!(r.goto(), r.goto);
        assert_eq!(r.flow(), r.flow);
        assert_eq!(r.tun_id(), r.tun_id);
        assert_eq!(r.suppress_ifgroup(), r.suppress_ifgroup);
        assert_eq!(r.suppress_prefixlen(), r.suppress_prefixlen);
        assert_eq!(r.l3mdev(), r.l3mdev);
        assert_eq!(r.protocol(), r.protocol);
        assert_eq!(r.ip_proto(), r.ip_proto);
    }
}
