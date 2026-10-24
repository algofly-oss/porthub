//! Ethernet protocol numbers — ethertypes — as tc(8) names them (#515).
//!
//! [`EthProto`] is what a TC filter is installed under (`tc filter add …
//! protocol ip`), what flower matches as `eth_type`, and what a VLAN
//! carries. It parses the way iproute2's `ll_proto_a2n` does: a name from
//! its table, case-insensitively, or a number in any base `strtoul` reads
//! (`0x` hex, a leading `0` octal, decimal otherwise). Before 0.32 the
//! filter API took a bare `u16`, the same constants were defined in five
//! places, and flower's parser read a bare number as hex where tc reads it
//! as decimal.

use core::{fmt, str::FromStr};

use super::error::{Error, Result};

/// An Ethernet protocol number (ethertype), in host byte order.
///
/// ```
/// use nlink::EthProto;
///
/// assert_eq!("ip".parse::<EthProto>()?, EthProto::IP);
/// assert_eq!("0x86dd".parse::<EthProto>()?, EthProto::IPV6);
/// assert_eq!("2048".parse::<EthProto>()?, EthProto::IP, "decimal, as tc reads it");
/// assert_eq!(EthProto::VLAN_8021Q.to_string(), "802.1Q");
/// assert_eq!(EthProto::new(0x1234).to_string(), "0x1234");
/// # Ok::<(), nlink::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EthProto(u16);

impl EthProto {
    /// Every protocol (`ETH_P_ALL`): a filter that sees all traffic.
    pub const ALL: Self = Self(0x0003);
    /// IPv4 (`ETH_P_IP`).
    pub const IP: Self = Self(0x0800);
    /// ARP (`ETH_P_ARP`).
    pub const ARP: Self = Self(0x0806);
    /// Transparent Ethernet bridging (`ETH_P_TEB`).
    pub const TEB: Self = Self(0x6558);
    /// Reverse ARP (`ETH_P_RARP`).
    pub const RARP: Self = Self(0x8035);
    /// An 802.1Q VLAN tag (`ETH_P_8021Q`).
    pub const VLAN_8021Q: Self = Self(0x8100);
    /// IPv6 (`ETH_P_IPV6`).
    pub const IPV6: Self = Self(0x86DD);
    /// MPLS unicast (`ETH_P_MPLS_UC`).
    pub const MPLS_UC: Self = Self(0x8847);
    /// MPLS multicast (`ETH_P_MPLS_MC`).
    pub const MPLS_MC: Self = Self(0x8848);
    /// An 802.1ad (QinQ) service tag (`ETH_P_8021AD`).
    pub const VLAN_8021AD: Self = Self(0x88A8);
    /// LLDP (`ETH_P_LLDP`).
    pub const LLDP: Self = Self(0x88CC);

    /// A protocol by number.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// The number, in host byte order.
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// The name tc(8) prints for it, when it has one.
    pub fn name(self) -> Option<&'static str> {
        NAMES.iter().find(|(_, p)| *p == self).map(|(n, _)| *n)
    }
}

/// tc(8)'s names (iproute2 `lib/ll_proto.c`) for the protocols above, in
/// the spelling it prints.
const NAMES: &[(&str, EthProto)] = &[
    ("all", EthProto::ALL),
    ("ip", EthProto::IP),
    ("arp", EthProto::ARP),
    ("teb", EthProto::TEB),
    ("rarp", EthProto::RARP),
    ("802.1Q", EthProto::VLAN_8021Q),
    ("ipv6", EthProto::IPV6),
    ("mpls_uc", EthProto::MPLS_UC),
    ("mpls_mc", EthProto::MPLS_MC),
    ("802.1ad", EthProto::VLAN_8021AD),
    ("lldp", EthProto::LLDP),
];

impl fmt::Display for EthProto {
    /// tc(8)'s name, or `0x` and four hex digits.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "0x{:04x}", self.0),
        }
    }
}

impl FromStr for EthProto {
    type Err = Error;

    /// A name, case-insensitively — tc's, plus `vlan` and `ipv4` — or a
    /// number as `strtoul(s, NULL, 0)` reads it.
    fn from_str(s: &str) -> Result<Self> {
        let lower = s.to_ascii_lowercase();
        if let Some((_, p)) = NAMES.iter().find(|(n, _)| n.eq_ignore_ascii_case(&lower)) {
            return Ok(*p);
        }
        match lower.as_str() {
            "vlan" => return Ok(Self::VLAN_8021Q),
            "ipv4" => return Ok(Self::IP),
            _ => {}
        }
        let parsed = if let Some(hex) = lower.strip_prefix("0x") {
            u16::from_str_radix(hex, 16)
        } else if lower.len() > 1
            && let Some(oct) = lower.strip_prefix('0')
        {
            u16::from_str_radix(oct, 8)
        } else {
            lower.parse()
        };
        parsed
            .map(Self)
            .map_err(|_| Error::invalid_message(format!("unknown ethernet protocol `{s}`")))
    }
}

impl From<u16> for EthProto {
    fn from(raw: u16) -> Self {
        Self(raw)
    }
}

impl From<EthProto> for u16 {
    fn from(p: EthProto) -> u16 {
        p.0
    }
}

impl PartialEq<u16> for EthProto {
    fn eq(&self, other: &u16) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers_parse_as_tc_reads_them() {
        for (text, want) in [
            ("all", EthProto::ALL),
            ("IP", EthProto::IP),
            ("ipv4", EthProto::IP),
            ("802.1q", EthProto::VLAN_8021Q),
            ("vlan", EthProto::VLAN_8021Q),
            ("802.1AD", EthProto::VLAN_8021AD),
            ("0x88cc", EthProto::LLDP),
            ("2048", EthProto::IP),
            ("04000", EthProto::IP),
            ("0", EthProto::new(0)),
        ] {
            assert_eq!(text.parse::<EthProto>().unwrap(), want, "{text}");
        }
        for bad in ["", "ipx-ish", "0x10000", "65536", "09"] {
            assert!(bad.parse::<EthProto>().is_err(), "{bad}");
        }
    }

    #[test]
    fn display_round_trips() {
        for (_, p) in NAMES {
            assert_eq!(p.to_string().parse::<EthProto>().unwrap(), *p);
        }
        assert_eq!(EthProto::new(0xabcd).to_string(), "0xabcd");
        assert_eq!("0xabcd".parse::<EthProto>().unwrap(), EthProto::new(0xabcd));
    }
}
