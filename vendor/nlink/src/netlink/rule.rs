//! Routing rule management.
//!
//! This module provides a builder for creating and deleting routing rules.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::rule::RuleBuilder;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Add a rule to lookup table 100 for traffic from 10.0.0.0/8
//! conn.add_rule(
//!     RuleBuilder::v4()
//!         .priority(100)
//!         .from_prefix("10.0.0.0", 8)
//!         .table(100)
//! ).await?;
//!
//! // Add a rule to blackhole traffic to 192.168.99.0/24
//! conn.add_rule(
//!     RuleBuilder::v4()
//!         .priority(200)
//!         .to_prefix("192.168.99.0", 24)
//!         .blackhole()
//! ).await?;
//!
//! // Delete a rule by priority
//! conn.del_rule(
//!     RuleBuilder::v4()
//!         .priority(100)
//! ).await?;
//! # Ok(())
//! # }
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{
    builder::MessageBuilder,
    error::Result,
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST, NlMsgType},
    types::rule::{FibRuleAction, FibRuleHdr, FraAttr},
};

/// Address family constants.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// `FIB_RULE_INVERT` (`linux/fib_rules.h`): the rule matches what its
/// selectors do not.
pub(crate) const FIB_RULE_INVERT: u32 = 0x2;

/// Builder for routing rules.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct RuleBuilder {
    family: u8,
    priority: Option<u32>,
    src: Option<IpAddr>,
    src_len: u8,
    dst: Option<IpAddr>,
    dst_len: u8,
    iif: Option<String>,
    oif: Option<String>,
    fwmark: Option<u32>,
    fwmask: Option<u32>,
    /// Unset: main for an add that looks a table up, none otherwise, and
    /// none for a delete — which then matches any table (#667).
    table: Option<u32>,
    /// Unset: a lookup for an add, any action for a delete (#667).
    action: Option<FibRuleAction>,
    ipproto: Option<u8>,
    sport: Option<(u16, u16)>,
    dport: Option<(u16, u16)>,
    protocol: Option<u8>,
    invert: bool,
    suppress_prefixlen: Option<u32>,
}

impl RuleBuilder {
    /// Create a new rule builder for the given address family.
    pub fn new(family: u8) -> Self {
        Self {
            family,
            priority: None,
            src: None,
            src_len: 0,
            dst: None,
            dst_len: 0,
            iif: None,
            oif: None,
            fwmark: None,
            fwmask: None,
            table: None,
            action: None,
            ipproto: None,
            sport: None,
            dport: None,
            protocol: None,
            invert: false,
            suppress_prefixlen: None,
        }
    }

    /// Create a new IPv4 rule builder.
    pub fn v4() -> Self {
        Self::new(AF_INET)
    }

    /// Create a new IPv6 rule builder.
    pub fn v6() -> Self {
        Self::new(AF_INET6)
    }

    /// Set the rule priority.
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set the source prefix using an IP address and prefix length.
    pub fn from_addr(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.src = Some(addr);
        self.src_len = prefix_len;
        self
    }

    /// Set the source prefix from a string address and prefix length.
    pub fn from_prefix(self, addr: &str, prefix_len: u8) -> Self {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            self.from_addr(ip, prefix_len)
        } else {
            self
        }
    }

    /// Set the IPv4 source prefix.
    pub fn from_v4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.src = Some(IpAddr::V4(addr));
        self.src_len = prefix_len;
        self
    }

    /// Set the IPv6 source prefix.
    pub fn from_v6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        self.src = Some(IpAddr::V6(addr));
        self.src_len = prefix_len;
        self
    }

    /// Set the destination prefix using an IP address and prefix length.
    pub fn to_addr(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.dst = Some(addr);
        self.dst_len = prefix_len;
        self
    }

    /// Set the destination prefix from a string address and prefix length.
    pub fn to_prefix(self, addr: &str, prefix_len: u8) -> Self {
        if let Ok(ip) = addr.parse::<IpAddr>() {
            self.to_addr(ip, prefix_len)
        } else {
            self
        }
    }

    /// Set the IPv4 destination prefix.
    pub fn to_v4(mut self, addr: Ipv4Addr, prefix_len: u8) -> Self {
        self.dst = Some(IpAddr::V4(addr));
        self.dst_len = prefix_len;
        self
    }

    /// Set the IPv6 destination prefix.
    pub fn to_v6(mut self, addr: Ipv6Addr, prefix_len: u8) -> Self {
        self.dst = Some(IpAddr::V6(addr));
        self.dst_len = prefix_len;
        self
    }

    /// Set the input interface name.
    pub fn iif(mut self, name: &str) -> Self {
        self.iif = Some(name.to_string());
        self
    }

    /// Set the output interface name.
    pub fn oif(mut self, name: &str) -> Self {
        self.oif = Some(name.to_string());
        self
    }

    /// Set the fwmark to match.
    pub fn fwmark(mut self, mark: u32) -> Self {
        self.fwmark = Some(mark);
        self
    }

    /// Set the fwmark and mask to match.
    pub fn fwmark_mask(mut self, mark: u32, mask: u32) -> Self {
        self.fwmark = Some(mark);
        self.fwmask = Some(mask);
        self
    }

    /// Set the routing table to lookup.
    pub fn table(mut self, table: u32) -> Self {
        self.table = Some(table);
        self.action = Some(FibRuleAction::ToTbl);
        self
    }

    /// Set the action to blackhole (drop packets silently).
    pub fn blackhole(mut self) -> Self {
        self.action = Some(FibRuleAction::Blackhole);
        self
    }

    /// Set the action to unreachable (return ICMP unreachable).
    pub fn unreachable(mut self) -> Self {
        self.action = Some(FibRuleAction::Unreachable);
        self
    }

    /// Set the action to prohibit (return ICMP prohibited).
    pub fn prohibit(mut self) -> Self {
        self.action = Some(FibRuleAction::Prohibit);
        self
    }

    /// The routing protocol the rule carries (`FRA_PROTOCOL`, `ip rule …
    /// protocol`): who installed it. Part of a rule's identity — the
    /// kernel keeps a rule with another protocol as another rule, and a
    /// delete that names one removes only that one (#516). Unset, the
    /// kernel stores 0 (`unspec`), as `ip rule add` does.
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Match what the selectors do not (`ip rule add not …`,
    /// `FIB_RULE_INVERT`).
    pub fn invert(mut self) -> Self {
        self.invert = true;
        self
    }

    /// Ignore a table lookup whose route has this prefix length or less
    /// (`suppress_prefixlength`): `0` skips the table's default route, as
    /// `wg-quick` does with `table main suppress_prefixlength 0`.
    pub fn suppress_prefixlen(mut self, len: u32) -> Self {
        self.suppress_prefixlen = Some(len);
        self
    }

    /// Set the IP protocol to match (6=TCP, 17=UDP, etc.).
    pub fn ipproto(mut self, proto: u8) -> Self {
        self.ipproto = Some(proto);
        self
    }

    /// Match TCP traffic.
    pub fn tcp(self) -> Self {
        self.ipproto(6)
    }

    /// Match UDP traffic.
    pub fn udp(self) -> Self {
        self.ipproto(17)
    }

    /// Set the source port range to match.
    pub fn sport(mut self, start: u16, end: u16) -> Self {
        self.sport = Some((start, end));
        self
    }

    /// Set a single source port to match.
    pub fn sport_eq(self, port: u16) -> Self {
        self.sport(port, port)
    }

    /// Set the destination port range to match.
    pub fn dport(mut self, start: u16, end: u16) -> Self {
        self.dport = Some((start, end));
        self
    }

    /// Set a single destination port to match.
    pub fn dport_eq(self, port: u16) -> Self {
        self.dport(port, port)
    }

    /// Build the netlink message for adding this rule.
    pub fn build(&self) -> Result<MessageBuilder> {
        self.build_internal(NlMsgType::RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL)
    }

    /// [`build`](Self::build) without `NLM_F_EXCL`, which the kernel checks
    /// leniently: a rule that leaves a selector out (a TOS, realms) "exists"
    /// when one with it does (#793).
    pub(crate) fn build_alongside(&self) -> Result<MessageBuilder> {
        self.build_internal(NlMsgType::RTM_NEWRULE, NLM_F_CREATE)
    }

    /// Build the netlink message for deleting this rule.
    pub fn build_delete(&self) -> Result<MessageBuilder> {
        self.build_internal(NlMsgType::RTM_DELRULE, 0)
    }

    fn build_internal(&self, msg_type: u16, create_flags: u16) -> Result<MessageBuilder> {
        let flags = NLM_F_REQUEST | NLM_F_ACK | create_flags;

        let mut builder = MessageBuilder::new(msg_type, flags);

        // Build header
        let mut hdr = FibRuleHdr::new().with_family(self.family);
        hdr.src_len = self.src_len;
        hdr.dst_len = self.dst_len;
        // An add looks the main table up unless told otherwise, as `ip rule
        // add` does; a drop rule has no table. A delete sends only what was
        // set: the kernel's `rule_find` matches the action and table when
        // they are non-zero, so `lookup main` found nothing else (#667).
        let (action, table) = if create_flags & NLM_F_CREATE != 0 {
            let action = self.action.unwrap_or(FibRuleAction::ToTbl);
            let table = match action {
                FibRuleAction::ToTbl => self.table.unwrap_or(254),
                _ => self.table.unwrap_or(0),
            };
            (action as u8, table)
        } else {
            (self.action.map_or(0, |a| a as u8), self.table.unwrap_or(0))
        };
        hdr.action = action;
        if self.invert {
            hdr.flags |= FIB_RULE_INVERT;
        }
        hdr.table = if table <= 255 {
            table as u8
        } else {
            0
        };

        builder.append(&hdr);

        // Add priority
        if let Some(prio) = self.priority {
            builder.append_attr_u32(FraAttr::Priority as u16, prio);
        }

        // Add source
        if let Some(addr) = self.src {
            match addr {
                IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Src as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Src as u16, &v6.octets());
                }
            }
        }

        // Add destination
        if let Some(addr) = self.dst {
            match addr {
                IpAddr::V4(v4) => {
                    builder.append_attr(FraAttr::Dst as u16, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(FraAttr::Dst as u16, &v6.octets());
                }
            }
        }

        // Add input interface
        if let Some(ref iif) = self.iif {
            builder.append_attr_str(FraAttr::Iifname as u16, iif);
        }

        // Add output interface
        if let Some(ref oif) = self.oif {
            builder.append_attr_str(FraAttr::Oifname as u16, oif);
        }

        // Add fwmark
        if let Some(mark) = self.fwmark {
            builder.append_attr_u32(FraAttr::Fwmark as u16, mark);
            if let Some(mask) = self.fwmask {
                builder.append_attr_u32(FraAttr::Fwmask as u16, mask);
            }
        }

        // Add table if > 255
        if table > 255 {
            builder.append_attr_u32(FraAttr::Table as u16, table);
        }

        if let Some(protocol) = self.protocol {
            builder.append_attr(FraAttr::Protocol as u16, &[protocol]);
        }

        if let Some(len) = self.suppress_prefixlen {
            builder.append_attr_u32(FraAttr::SuppressPrefixlen as u16, len);
        }

        // Add IP protocol
        if let Some(proto) = self.ipproto {
            builder.append_attr(FraAttr::IpProto as u16, &[proto]);
        }

        // Add sport
        if let Some((start, end)) = self.sport {
            // `struct fib_rule_port_range`'s __u16 fields are kernel-native —
            // the kernel compares them against `ntohs(fl4->fl4_sport)`. This
            // was hand-packed little-endian, which is right on x86 by accident
            // and wrong on any big-endian host (#278).
            let mut range_bytes = [0u8; 4];
            range_bytes[..2].copy_from_slice(&start.to_ne_bytes());
            range_bytes[2..].copy_from_slice(&end.to_ne_bytes());
            builder.append_attr(FraAttr::Sport as u16, &range_bytes);
        }

        // Add dport
        if let Some((start, end)) = self.dport {
            // `struct fib_rule_port_range`'s __u16 fields are kernel-native —
            // the kernel compares them against `ntohs(fl4->fl4_sport)`. This
            // was hand-packed little-endian, which is right on x86 by accident
            // and wrong on any big-endian host (#278).
            let mut range_bytes = [0u8; 4];
            range_bytes[..2].copy_from_slice(&start.to_ne_bytes());
            range_bytes[2..].copy_from_slice(&end.to_ne_bytes());
            builder.append_attr(FraAttr::Dport as u16, &range_bytes);
        }

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `(action, table)` from the `fib_rule_hdr` after the 16-byte
    /// `nlmsghdr`: family, dst_len, src_len, tos, table, res1, res2, action.
    fn action_and_table(b: MessageBuilder) -> (u8, u8) {
        let bytes = b.finish();
        (bytes[16 + 7], bytes[16 + 4])
    }

    /// An add looks the main table up by default and a drop rule has no
    /// table; a delete sends only what was set, so it matches any rule at
    /// the priority (#667).
    #[test]
    fn action_and_table_are_sent_as_ip_rule_sends_them() {
        let add = |r: RuleBuilder| action_and_table(r.build().unwrap());
        let del = |r: RuleBuilder| action_and_table(r.build_delete().unwrap());
        assert_eq!(add(RuleBuilder::v4().priority(1)), (FibRuleAction::ToTbl as u8, 254));
        assert_eq!(add(RuleBuilder::v4().table(100)), (FibRuleAction::ToTbl as u8, 100));
        assert_eq!(add(RuleBuilder::v4().prohibit()), (FibRuleAction::Prohibit as u8, 0));
        assert_eq!(del(RuleBuilder::v4().priority(1)), (0, 0));
        assert_eq!(del(RuleBuilder::v4().table(100)), (FibRuleAction::ToTbl as u8, 100));
        assert_eq!(del(RuleBuilder::v4().blackhole()), (FibRuleAction::Blackhole as u8, 0));
    }
}
