//! Socket information structures.
//!
//! This module provides strongly-typed representations of socket information
//! returned by the kernel's SOCK_DIAG interface.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use super::types::{
    AddressFamily, CcInfo, MemInfo, Protocol, SocketState, TcpInfo, TcpState, Timer,
};

/// Common socket information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SocketInfo {
    /// TCP/UDP/SCTP socket over IPv4/IPv6.
    Inet(Box<InetSocket>),
    /// Unix domain socket.
    Unix(UnixSocket),
    /// Netlink socket.
    Netlink(NetlinkSocket),
    /// Packet (raw) socket.
    Packet(PacketSocket),
}

impl SocketInfo {
    /// Get the socket state.
    pub fn state(&self) -> SocketState {
        match self {
            SocketInfo::Inet(s) => s.state,
            SocketInfo::Unix(s) => s.state,
            SocketInfo::Netlink(_) => SocketState::Close,
            SocketInfo::Packet(_) => SocketState::Close,
        }
    }

    /// Get the inode number.
    pub fn inode(&self) -> u32 {
        match self {
            SocketInfo::Inet(s) => s.inode,
            SocketInfo::Unix(s) => s.inode,
            SocketInfo::Netlink(s) => s.inode,
            SocketInfo::Packet(s) => s.inode,
        }
    }

    /// Get the socket UID.
    pub fn uid(&self) -> Option<u32> {
        match self {
            SocketInfo::Inet(s) => Some(s.uid),
            SocketInfo::Unix(s) => s.uid,
            SocketInfo::Netlink(s) => Some(s.portid),
            SocketInfo::Packet(s) => Some(s.uid),
        }
    }

    /// Get the Inet socket if this is an Inet variant.
    pub fn as_inet(&self) -> Option<&InetSocket> {
        match self {
            SocketInfo::Inet(s) => Some(s),
            _ => None,
        }
    }
}

/// Internet (TCP/UDP/SCTP) socket information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InetSocket {
    /// Address family (IPv4 or IPv6).
    pub family: AddressFamily,
    /// Protocol (TCP, UDP, etc.).
    pub protocol: Protocol,
    /// Socket state.
    pub state: SocketState,
    /// Local address and port.
    pub local: SocketAddr,
    /// Remote address and port.
    pub remote: SocketAddr,
    /// Interface index (0 = any).
    pub interface: u32,
    /// Socket cookie (unique identifier).
    pub cookie: u64,
    /// Timer information.
    pub timer: Timer,
    /// Receive queue size.
    pub recv_q: u32,
    /// Send queue size.
    pub send_q: u32,
    /// Socket owner UID.
    pub uid: u32,
    /// Inode number.
    pub inode: u32,
    /// Reference count.
    pub refcnt: u32,
    /// Socket mark.
    pub mark: Option<u32>,
    /// Cgroup ID.
    pub cgroup_id: Option<u64>,
    /// TCP-specific information.
    pub tcp_info: Option<TcpInfo>,
    /// Memory information.
    pub mem_info: Option<MemInfo>,
    /// Congestion control algorithm.
    pub congestion: Option<String>,
    /// Congestion-control–specific state (BBR / DCTCP / vegas),
    /// when requested via `with_cc_info()` and the socket's CC
    /// algorithm exposes one (#163).
    pub cc_info: Option<CcInfo>,
    /// Type of service.
    pub tos: Option<u8>,
    /// Traffic class (IPv6).
    pub tclass: Option<u8>,
    /// Shutdown state (read/write).
    pub shutdown: Option<u8>,
    /// IPv6 only flag.
    pub v6only: Option<bool>,
}

impl InetSocket {
    /// Create a new InetSocket with minimal information.
    pub fn new(
        family: AddressFamily,
        protocol: Protocol,
        state: TcpState,
        local: SocketAddr,
        remote: SocketAddr,
    ) -> Self {
        Self {
            family,
            protocol,
            state: SocketState::Tcp(state),
            local,
            remote,
            interface: 0,
            cookie: 0,
            timer: Timer::Off,
            recv_q: 0,
            send_q: 0,
            uid: 0,
            inode: 0,
            refcnt: 0,
            mark: None,
            cgroup_id: None,
            tcp_info: None,
            mem_info: None,
            congestion: None,
            cc_info: None,
            tos: None,
            tclass: None,
            shutdown: None,
            v6only: None,
        }
    }

    /// Check if this is a listening socket.
    pub fn is_listening(&self) -> bool {
        matches!(self.state, SocketState::Tcp(TcpState::Listen))
    }

    /// Check if this is a connected socket.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, SocketState::Tcp(TcpState::Established))
    }

    /// Get the netid string for output.
    pub fn netid(&self) -> &'static str {
        match (self.protocol, self.family) {
            (Protocol::Tcp, AddressFamily::Inet) => "tcp",
            (Protocol::Tcp, AddressFamily::Inet6) => "tcp6",
            (Protocol::Udp, AddressFamily::Inet) => "udp",
            (Protocol::Udp, AddressFamily::Inet6) => "udp6",
            (Protocol::Sctp, AddressFamily::Inet) => "sctp",
            (Protocol::Sctp, AddressFamily::Inet6) => "sctp6",
            (Protocol::Dccp, AddressFamily::Inet) => "dccp",
            (Protocol::Dccp, AddressFamily::Inet6) => "dccp6",
            (Protocol::Mptcp, AddressFamily::Inet) => "mptcp",
            (Protocol::Mptcp, AddressFamily::Inet6) => "mptcp6",
            (Protocol::Raw, AddressFamily::Inet) => "raw",
            (Protocol::Raw, AddressFamily::Inet6) => "raw6",
            _ => "unknown",
        }
    }
}

impl Default for InetSocket {
    fn default() -> Self {
        Self::new(
            AddressFamily::Inet,
            Protocol::Tcp,
            TcpState::Unknown,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
    }
}

/// Unix socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum UnixType {
    /// Stream socket (SOCK_STREAM).
    Stream = libc::SOCK_STREAM as u8,
    /// Datagram socket (SOCK_DGRAM).
    Dgram = libc::SOCK_DGRAM as u8,
    /// Seqpacket socket (SOCK_SEQPACKET).
    Seqpacket = libc::SOCK_SEQPACKET as u8,
}

impl UnixType {
    /// Parse from raw value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value as i32 {
            libc::SOCK_STREAM => Some(Self::Stream),
            libc::SOCK_DGRAM => Some(Self::Dgram),
            libc::SOCK_SEQPACKET => Some(Self::Seqpacket),
            _ => None,
        }
    }

    /// Get the netid string.
    pub fn netid(&self) -> &'static str {
        match self {
            Self::Stream => "u_str",
            Self::Dgram => "u_dgr",
            Self::Seqpacket => "u_seq",
        }
    }
}

/// Unix domain socket information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnixSocket {
    /// Socket type.
    pub socket_type: UnixType,
    /// Socket state.
    pub state: SocketState,
    /// Socket path (None for abstract or unnamed).
    pub path: Option<String>,
    /// Abstract name (starts with @).
    pub abstract_name: Option<String>,
    /// Inode number.
    pub inode: u32,
    /// Socket cookie.
    pub cookie: u64,
    /// Peer inode (for connected sockets).
    pub peer_inode: Option<u32>,
    /// VFS device.
    pub vfs_dev: Option<u32>,
    /// VFS inode.
    pub vfs_inode: Option<u32>,
    /// Receive queue size.
    pub recv_q: Option<u32>,
    /// Send queue size.
    pub send_q: Option<u32>,
    /// Pending connections (for listening sockets).
    pub pending_connections: Option<Vec<u32>>,
    /// Socket owner UID.
    pub uid: Option<u32>,
    /// Memory information.
    pub mem_info: Option<MemInfo>,
    /// Shutdown state.
    pub shutdown: Option<u8>,
}

impl UnixSocket {
    /// Create a new UnixSocket with minimal information.
    pub fn new(socket_type: UnixType, state: SocketState, inode: u32) -> Self {
        Self {
            socket_type,
            state,
            path: None,
            abstract_name: None,
            inode,
            cookie: 0,
            peer_inode: None,
            vfs_dev: None,
            vfs_inode: None,
            recv_q: None,
            send_q: None,
            pending_connections: None,
            uid: None,
            mem_info: None,
            shutdown: None,
        }
    }

    /// Get the socket name for display.
    pub fn name(&self) -> String {
        if let Some(ref path) = self.path {
            path.clone()
        } else if let Some(ref name) = self.abstract_name {
            format!("@{}", name)
        } else {
            String::new()
        }
    }

    /// Get the netid string.
    pub fn netid(&self) -> &'static str {
        self.socket_type.netid()
    }
}

/// Netlink socket information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetlinkSocket {
    /// Netlink protocol (NETLINK_ROUTE, etc.).
    pub protocol: u8,
    /// Port ID.
    pub portid: u32,
    /// Destination port ID.
    pub dst_portid: u32,
    /// Destination group.
    pub dst_group: u32,
    /// Subscribed groups bitmask.
    pub groups: u32,
    /// Inode number.
    pub inode: u32,
    /// Socket cookie.
    pub cookie: u64,
    /// Receive queue size.
    pub recv_q: Option<u32>,
    /// Send queue size.
    pub send_q: Option<u32>,
    /// Memory information.
    pub mem_info: Option<MemInfo>,
}

impl NetlinkSocket {
    /// Get the protocol name.
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            0 => "route",
            1 => "unused",
            2 => "usersock",
            3 => "firewall",
            4 => "sock_diag",
            5 => "nflog",
            6 => "xfrm",
            7 => "selinux",
            8 => "iscsi",
            9 => "audit",
            10 => "fib_lookup",
            11 => "connector",
            12 => "netfilter",
            13 => "ip6_fw",
            14 => "dnrtmsg",
            15 => "kobject_uevent",
            16 => "generic",
            18 => "scsitransport",
            19 => "ecryptfs",
            20 => "rdma",
            21 => "crypto",
            22 => "smc",
            _ => "unknown",
        }
    }
}

/// Packet (raw) socket information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSocket {
    /// Socket type (SOCK_RAW or SOCK_DGRAM).
    pub socket_type: u8,
    /// Protocol (ETH_P_*).
    pub protocol: u16,
    /// Interface index.
    pub interface: u32,
    /// Inode number.
    pub inode: u32,
    /// Socket cookie.
    pub cookie: u64,
    /// Socket owner UID.
    pub uid: u32,
    /// Receive queue size.
    pub recv_q: Option<u32>,
    /// Send queue size.
    pub send_q: Option<u32>,
    /// Fanout ID (if in fanout group).
    pub fanout: Option<u32>,
    /// Memory information.
    pub mem_info: Option<MemInfo>,
}

impl PacketSocket {
    /// Get the netid string.
    pub fn netid(&self) -> &'static str {
        match self.socket_type as i32 {
            libc::SOCK_RAW => "p_raw",
            libc::SOCK_DGRAM => "p_dgr",
            _ => "packet",
        }
    }

    /// Get the protocol name.
    pub fn protocol_name(&self) -> &'static str {
        match self.protocol {
            0x0003 => "802.3", // ETH_P_802_3
            0x0004 => "ax25",
            0x0800 => "ip",
            0x0806 => "arp",
            0x8035 => "rarp",
            0x86DD => "ipv6",
            0x8863 => "pppoe_disc",
            0x8864 => "pppoe_sess",
            0x888E => "802.1x",
            0x88A8 => "802.1ad",
            0x88CC => "lldp",
            _ => "unknown",
        }
    }
}

/// Parse an IPv4 address from 4 bytes (network byte order).
pub fn parse_ipv4(data: &[u8]) -> Ipv4Addr {
    if data.len() >= 4 {
        Ipv4Addr::new(data[0], data[1], data[2], data[3])
    } else {
        Ipv4Addr::UNSPECIFIED
    }
}

/// Parse an IPv6 address from 16 bytes.
pub fn parse_ipv6(data: &[u8]) -> Ipv6Addr {
    if data.len() >= 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&data[..16]);
        Ipv6Addr::from(octets)
    } else {
        Ipv6Addr::UNSPECIFIED
    }
}

/// Parse a port from 2 bytes (network byte order).
pub fn parse_port(data: &[u8]) -> u16 {
    if data.len() >= 2 {
        u16::from_be_bytes([data[0], data[1]])
    } else {
        0
    }
}
