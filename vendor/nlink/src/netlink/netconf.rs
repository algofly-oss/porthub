//! Per-interface IP configuration as the kernel's netconf messages report
//! it (#523): forwarding, `rp_filter`, proxy neighbours and the rest, for an
//! interface, for `all` and for `default`.
//!
//! The kernel sends `RTM_NEWNETCONF` to the `RTNLGRP_IPV4_NETCONF` and
//! `RTNLGRP_IPV6_NETCONF` groups when one of these changes — through
//! `/proc/sys` too — so a watcher sees sysctl drift as it happens
//! ([`NetworkEvent::NewNetconf`](super::events::NetworkEvent::NewNetconf),
//! [`RtnetlinkGroup::Ipv4Netconf`](super::RtnetlinkGroup::Ipv4Netconf)).
//! [`Connection::get_netconf`] dumps the current values.
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::netconf::NetconfDevice;
//!
//! let conn = Connection::<Route>::new()?;
//! for nc in conn.get_netconf(nlink::AddressFamily::v4()).await? {
//!     if nc.device() == Some(NetconfDevice::All) {
//!         println!("forwarding: {:?}", nc.forwarding());
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::Result;
use super::message::{NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgType};
use super::protocol::Route;
use crate::util::AddressFamily;

/// `NETCONFA_*` (`linux/netconf.h`).
mod netconfa {
    pub const IFINDEX: u16 = 1;
    pub const FORWARDING: u16 = 2;
    pub const RP_FILTER: u16 = 3;
    pub const MC_FORWARDING: u16 = 4;
    pub const PROXY_NEIGH: u16 = 5;
    pub const IGNORE_ROUTES_WITH_LINKDOWN: u16 = 6;
    pub const INPUT: u16 = 7;
    pub const BC_FORWARDING: u16 = 8;
}

/// `NETCONFA_IFINDEX_ALL`: the `all` settings.
const IFINDEX_ALL: i32 = -1;
/// `NETCONFA_IFINDEX_DEFAULT`: the `default` settings, which new interfaces
/// start from.
const IFINDEX_DEFAULT: i32 = -2;

/// Whose settings a netconf message carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NetconfDevice {
    /// An interface's.
    Index(u32),
    /// The `all` settings (`net.ipv4.conf.all`).
    All,
    /// The `default` settings, which new interfaces start from.
    Default,
}

/// A netconf message (#523): one interface's — or `all`'s, or `default`'s —
/// IP configuration, as much of it as the message carries. A notification
/// carries what changed, or everything for a new interface; a dump
/// carries everything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct NetconfMessage {
    pub(crate) family: u8,
    pub(crate) device: Option<NetconfDevice>,
    pub(crate) forwarding: Option<i32>,
    pub(crate) rp_filter: Option<i32>,
    pub(crate) mc_forwarding: Option<i32>,
    pub(crate) proxy_neigh: Option<i32>,
    pub(crate) ignore_routes_with_linkdown: Option<i32>,
    pub(crate) input: Option<i32>,
    pub(crate) bc_forwarding: Option<i32>,
}

impl NetconfMessage {
    /// Parse a netconf message's payload: the 4-byte `struct netconfmsg`
    /// (the family, padded), then the attributes. A malformed attribute
    /// ends the walk; what came before it stands.
    pub fn parse(payload: &[u8]) -> Option<Self> {
        let family = *payload.first()?;
        let mut msg = Self {
            family,
            ..Self::default()
        };
        let mut rest = payload.get(4..)?;
        while rest.len() >= 4 {
            let len = usize::from(u16::from_ne_bytes([rest[0], rest[1]]));
            let kind = u16::from_ne_bytes([rest[2], rest[3]]) & 0x3fff;
            if len < 4 || len > rest.len() {
                break;
            }
            let value = rest[4..len]
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(i32::from_ne_bytes);
            match kind {
                netconfa::IFINDEX => {
                    msg.device = value.map(|v| match v {
                        IFINDEX_ALL => NetconfDevice::All,
                        IFINDEX_DEFAULT => NetconfDevice::Default,
                        v => NetconfDevice::Index(v as u32),
                    })
                }
                netconfa::FORWARDING => msg.forwarding = value,
                netconfa::RP_FILTER => msg.rp_filter = value,
                netconfa::MC_FORWARDING => msg.mc_forwarding = value,
                netconfa::PROXY_NEIGH => msg.proxy_neigh = value,
                netconfa::IGNORE_ROUTES_WITH_LINKDOWN => msg.ignore_routes_with_linkdown = value,
                netconfa::INPUT => msg.input = value,
                netconfa::BC_FORWARDING => msg.bc_forwarding = value,
                _ => {}
            }
            rest = &rest[((len + 3) & !3).min(rest.len())..];
        }
        Some(msg)
    }

    /// The address family: `AF_INET` or `AF_INET6`.
    pub fn family(&self) -> u8 {
        self.family
    }

    /// Whose settings these are.
    pub fn device(&self) -> Option<NetconfDevice> {
        self.device
    }

    /// The interface's index, for an interface's settings.
    pub fn ifindex(&self) -> Option<u32> {
        match self.device {
            Some(NetconfDevice::Index(i)) => Some(i),
            _ => None,
        }
    }

    /// `forwarding`.
    pub fn forwarding(&self) -> Option<i32> {
        self.forwarding
    }

    /// `rp_filter` (IPv4): 0 off, 1 strict, 2 loose.
    pub fn rp_filter(&self) -> Option<i32> {
        self.rp_filter
    }

    /// `mc_forwarding`.
    pub fn mc_forwarding(&self) -> Option<i32> {
        self.mc_forwarding
    }

    /// `proxy_arp` (IPv4) or `proxy_ndp` (IPv6).
    pub fn proxy_neigh(&self) -> Option<i32> {
        self.proxy_neigh
    }

    /// `ignore_routes_with_linkdown`.
    pub fn ignore_routes_with_linkdown(&self) -> Option<i32> {
        self.ignore_routes_with_linkdown
    }

    /// `disable_ipv6`'s inverse for IPv6: whether input is accepted.
    pub fn input(&self) -> Option<i32> {
        self.input
    }

    /// `bc_forwarding` (IPv4).
    pub fn bc_forwarding(&self) -> Option<i32> {
        self.bc_forwarding
    }
}

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Every interface's netconf in `family` (IPv4 or IPv6), with the `all`
    /// and `default` settings (#523).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_netconf"))]
    pub async fn get_netconf(&self, family: AddressFamily) -> Result<Vec<NetconfMessage>> {
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETNETCONF, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append_bytes(&[family.as_u8(), 0, 0, 0]);
        let responses = self.send_dump(builder).await?;
        Ok(responses
            .iter()
            .filter_map(|data| data.get(NLMSG_HDRLEN..).and_then(NetconfMessage::parse))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: u16, value: i32) -> Vec<u8> {
        let mut a = 8u16.to_ne_bytes().to_vec();
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(&value.to_ne_bytes());
        a
    }

    /// The device and each setting the message carries; one it does not
    /// carry stays unset, and `all` and `default` are their own (#523).
    #[test]
    fn a_netconf_message_parses() {
        let mut payload = vec![libc::AF_INET as u8, 0, 0, 0];
        payload.extend(attr(netconfa::IFINDEX, 7));
        payload.extend(attr(netconfa::FORWARDING, 1));
        payload.extend(attr(netconfa::RP_FILTER, 2));
        let msg = NetconfMessage::parse(&payload).expect("parses");
        assert_eq!(msg.device(), Some(NetconfDevice::Index(7)));
        assert_eq!(msg.ifindex(), Some(7));
        assert_eq!((msg.forwarding(), msg.rp_filter(), msg.proxy_neigh()), (Some(1), Some(2), None));

        for (raw, want) in [(-1, NetconfDevice::All), (-2, NetconfDevice::Default)] {
            let mut payload = vec![libc::AF_INET6 as u8, 0, 0, 0];
            payload.extend(attr(netconfa::IFINDEX, raw));
            assert_eq!(NetconfMessage::parse(&payload).unwrap().device(), Some(want));
        }
        // A truncated attribute ends the walk, and what came before stands.
        let mut payload = vec![libc::AF_INET as u8, 0, 0, 0];
        payload.extend(attr(netconfa::FORWARDING, 1));
        payload.extend([12, 0, 2, 0, 1]);
        assert_eq!(NetconfMessage::parse(&payload).unwrap().forwarding(), Some(1));
        assert!(NetconfMessage::parse(&[]).is_none());
    }
}
