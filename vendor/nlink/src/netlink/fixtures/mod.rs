//! Netlink message fixtures for testing.
//!
//! This module contains pre-captured netlink messages for testing
//! message parsing without requiring network access.
//!
//! The fixtures are provided as functions that return Vec<u8> to ensure
//! proper alignment for the parser.

/// Link message for loopback interface.
/// Captured from: ip link show lo
pub fn link_loopback() -> Vec<u8> {
    vec![
        // ifinfomsg: family=0, pad=0, type=772 (ARPHRD_LOOPBACK), index=1, flags=0x49 (UP|LOOPBACK|RUNNING), change=0
        0x00, 0x00, // family, pad
        0x04, 0x03, // type = 772 (ARPHRD_LOOPBACK)
        0x01, 0x00, 0x00, 0x00, // index = 1
        0x49, 0x00, 0x00, 0x00, // flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING
        0x00, 0x00, 0x00, 0x00, // change = 0
        // IFLA_IFNAME = "lo"
        0x07, 0x00, // len = 7
        0x03, 0x00, // type = IFLA_IFNAME (3)
        b'l', b'o', 0x00, 0x00, // "lo\0" + padding
        // IFLA_MTU = 65536
        0x08, 0x00, // len = 8
        0x04, 0x00, // type = IFLA_MTU (4)
        0x00, 0x00, 0x01, 0x00, // mtu = 65536
        // IFLA_TXQLEN = 1000
        0x08, 0x00, // len = 8
        0x0d, 0x00, // type = IFLA_TXQLEN (13)
        0xe8, 0x03, 0x00, 0x00, // txqlen = 1000
        // IFLA_OPERSTATE = 0 (UNKNOWN)
        0x05, 0x00, // len = 5
        0x10, 0x00, // type = IFLA_OPERSTATE (16)
        0x00, 0x00, 0x00, 0x00, // operstate = 0 + padding
    ]
}

/// Address message for IPv4 loopback address 127.0.0.1/8.
pub fn addr_loopback_v4() -> Vec<u8> {
    vec![
        // ifaddrmsg: family=AF_INET, prefixlen=8, flags=0x80 (IFA_F_PERMANENT), scope=RT_SCOPE_HOST, index=1
        0x02, // family = AF_INET
        0x08, // prefixlen = 8
        0x80, // flags = IFA_F_PERMANENT
        0xfe, // scope = RT_SCOPE_HOST (254)
        0x01, 0x00, 0x00, 0x00, // index = 1
        // IFA_ADDRESS = 127.0.0.1
        0x08, 0x00, // len = 8
        0x01, 0x00, // type = IFA_ADDRESS (1)
        0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
        // IFA_LOCAL = 127.0.0.1
        0x08, 0x00, // len = 8
        0x02, 0x00, // type = IFA_LOCAL (2)
        0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
        // IFA_LABEL = "lo"
        0x07, 0x00, // len = 7
        0x03, 0x00, // type = IFA_LABEL (3)
        b'l', b'o', 0x00, 0x00, // "lo\0" + padding
    ]
}

/// Address message for IPv6 loopback address ::1/128.
pub fn addr_loopback_v6() -> Vec<u8> {
    vec![
        // ifaddrmsg: family=AF_INET6, prefixlen=128, flags=0x80 (IFA_F_PERMANENT), scope=RT_SCOPE_HOST, index=1
        0x0a, // family = AF_INET6
        0x80, // prefixlen = 128
        0x80, // flags = IFA_F_PERMANENT
        0xfe, // scope = RT_SCOPE_HOST (254)
        0x01, 0x00, 0x00, 0x00, // index = 1
        // IFA_ADDRESS = ::1
        0x14, 0x00, // len = 20
        0x01, 0x00, // type = IFA_ADDRESS (1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ::1 (first 8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // ::1 (last 8 bytes)
    ]
}

/// Route message for default route via gateway.
pub fn route_default_v4() -> Vec<u8> {
    vec![
        // rtmsg: family=AF_INET, dst_len=0, src_len=0, tos=0, table=RT_TABLE_MAIN, protocol=RTPROT_STATIC, scope=RT_SCOPE_UNIVERSE, type=RTN_UNICAST
        0x02, // family = AF_INET
        0x00, // dst_len = 0 (default route)
        0x00, // src_len = 0
        0x00, // tos = 0
        0xfe, // table = RT_TABLE_MAIN (254)
        0x04, // protocol = RTPROT_STATIC (4)
        0x00, // scope = RT_SCOPE_UNIVERSE (0)
        0x01, // type = RTN_UNICAST (1)
        0x00, 0x00, 0x00, 0x00, // flags = 0
        // RTA_GATEWAY = 192.168.1.1
        0x08, 0x00, // len = 8
        0x05, 0x00, // type = RTA_GATEWAY (5)
        0xc0, 0xa8, 0x01, 0x01, // 192.168.1.1
        // RTA_OIF = 2
        0x08, 0x00, // len = 8
        0x04, 0x00, // type = RTA_OIF (4)
        0x02, 0x00, 0x00, 0x00, // oif = 2
    ]
}

/// TC message for fq_codel qdisc.
pub fn tc_qdisc_fq_codel() -> Vec<u8> {
    vec![
        // tcmsg: family=0, pad=0,0,0, ifindex=2, handle=0, parent=0xffffffff (TC_H_ROOT)
        0x00, // family
        0x00, 0x00, 0x00, // padding
        0x02, 0x00, 0x00, 0x00, // ifindex = 2
        0x00, 0x00, 0x00, 0x00, // handle = 0
        0xff, 0xff, 0xff, 0xff, // parent = TC_H_ROOT
        0x00, 0x00, 0x00, 0x00, // info = 0
        // TCA_KIND = "fq_codel"
        0x0d, 0x00, // len = 13
        0x01, 0x00, // type = TCA_KIND (1)
        b'f', b'q', b'_', b'c', b'o', b'd', b'e', b'l', 0x00, // "fq_codel\0"
        0x00, 0x00, 0x00, // padding to 4-byte boundary
    ]
}

/// Neighbor (ARP) message.
pub fn neighbor_arp() -> Vec<u8> {
    vec![
        // ndmsg: family=AF_INET, pad=0,0,0, ifindex=2, state=NUD_REACHABLE, flags=0, type=0
        0x02, // family = AF_INET
        0x00, 0x00, 0x00, // padding
        0x02, 0x00, 0x00, 0x00, // ifindex = 2
        0x02, 0x00, // state = NUD_REACHABLE (0x02)
        0x00, // flags = 0
        0x00, // type = 0
        // NDA_DST = 192.168.1.1
        0x08, 0x00, // len = 8
        0x01, 0x00, // type = NDA_DST (1)
        0xc0, 0xa8, 0x01, 0x01, // 192.168.1.1
        // NDA_LLADDR = aa:bb:cc:dd:ee:ff
        0x0a, 0x00, // len = 10
        0x02, 0x00, // type = NDA_LLADDR (2)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // MAC address
        0x00, 0x00, // padding
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{
        messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage},
        parse::FromNetlink,
    };

    #[test]
    fn test_parse_link_loopback() {
        let data = link_loopback();
        let link = LinkMessage::from_bytes(&data).expect("failed to parse link message");

        assert_eq!(link.ifindex(), 1);
        assert_eq!(link.name.as_deref(), Some("lo"));
        assert_eq!(link.mtu, Some(65536));
        assert!(link.is_up());
        assert!(link.is_loopback());
    }

    #[test]
    fn test_parse_addr_loopback_v4() {
        let data = addr_loopback_v4();
        let addr = AddressMessage::from_bytes(&data).expect("failed to parse address message");

        assert_eq!(addr.ifindex(), 1);
        assert_eq!(addr.prefix_len(), 8);
        assert_eq!(addr.family(), 2); // AF_INET
        assert!(addr.is_ipv4());
        assert!(addr.is_permanent());

        // Check the address
        if let Some(local) = &addr.local {
            assert_eq!(local.to_string(), "127.0.0.1");
        } else {
            panic!("expected local address");
        }
    }

    #[test]
    fn test_parse_addr_loopback_v6() {
        let data = addr_loopback_v6();
        let addr = AddressMessage::from_bytes(&data).expect("failed to parse address message");

        assert_eq!(addr.ifindex(), 1);
        assert_eq!(addr.prefix_len(), 128);
        assert_eq!(addr.family(), 10); // AF_INET6
        assert!(addr.is_ipv6());
        assert!(addr.is_permanent());

        // Check the address
        if let Some(address) = &addr.address {
            assert_eq!(address.to_string(), "::1");
        } else {
            panic!("expected address");
        }
    }

    #[test]
    fn test_parse_route_default_v4() {
        let data = route_default_v4();
        let route = RouteMessage::from_bytes(&data).expect("failed to parse route message");

        assert_eq!(route.dst_len(), 0); // default route
        assert_eq!(route.family(), 2); // AF_INET
        assert_eq!(route.table_id(), 254); // RT_TABLE_MAIN

        // Check gateway
        if let Some(ref gw) = route.gateway {
            assert_eq!(gw.to_string(), "192.168.1.1");
        } else {
            panic!("expected gateway");
        }

        // Check output interface
        assert_eq!(route.oif, Some(2));
    }

    #[test]
    fn test_parse_tc_qdisc_fq_codel() {
        let data = tc_qdisc_fq_codel();
        let tc = TcMessage::from_bytes(&data).expect("failed to parse tc message");

        assert_eq!(tc.ifindex(), 2);
        assert_eq!(tc.kind(), Some("fq_codel"));
        assert_eq!(tc.parent(), crate::TcHandle::ROOT);
    }

    #[test]
    fn test_parse_neighbor_arp() {
        let data = neighbor_arp();
        let neigh = NeighborMessage::from_bytes(&data).expect("failed to parse neighbor message");

        assert_eq!(neigh.ifindex(), 2);
        assert_eq!(neigh.family(), 2); // AF_INET

        // Check destination IP
        if let Some(dst) = &neigh.destination {
            assert_eq!(dst.to_string(), "192.168.1.1");
        } else {
            panic!("expected destination");
        }

        // Check MAC address
        assert!(neigh.lladdr.is_some());
    }
}
