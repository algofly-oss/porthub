//! Strongly-typed link message.

use winnow::{prelude::*, token::take};

use crate::netlink::{
    error::Result,
    parse::{FromNetlink, PResult, ToNetlink, parse_string_from_bytes},
    types::link::{IfInfoMsg, LinkStats64, OperState},
};

/// Attribute IDs for IFLA_* constants.
mod attr_ids {
    pub const IFLA_ADDRESS: u16 = 1;
    pub const IFLA_BROADCAST: u16 = 2;
    pub const IFLA_IFNAME: u16 = 3;
    pub const IFLA_MTU: u16 = 4;
    pub const IFLA_LINK: u16 = 5;
    pub const IFLA_QDISC: u16 = 6;
    pub const IFLA_IFALIAS: u16 = 20;
    pub const IFLA_MASTER: u16 = 10;
    pub const IFLA_TXQLEN: u16 = 13;
    pub const IFLA_OPERSTATE: u16 = 16;
    pub const IFLA_LINKINFO: u16 = 18;
    pub const IFLA_STATS64: u16 = 23;
    pub const IFLA_GROUP: u16 = 27;
    pub const IFLA_PROMISCUITY: u16 = 30;
    pub const IFLA_NUM_TX_QUEUES: u16 = 31;
    pub const IFLA_NUM_RX_QUEUES: u16 = 32;
    pub const IFLA_CARRIER: u16 = 33;
    pub const IFLA_LINK_NETNSID: u16 = 37;
    pub const IFLA_MIN_MTU: u16 = 50;
    pub const IFLA_MAX_MTU: u16 = 51;
    pub const IFLA_PERM_ADDRESS: u16 = 54;
    pub const IFLA_PROTO_DOWN: u16 = 39;
    pub const IFLA_AF_SPEC: u16 = 26;
    pub const IFLA_PROP_LIST: u16 = 52;
    pub const IFLA_ALT_IFNAME: u16 = 53;
    // Plan 190 §2.3c — GSO/GRO/TSO caps.
    pub const IFLA_GSO_MAX_SEGS: u16 = 40;
    pub const IFLA_GSO_MAX_SIZE: u16 = 41;
    pub const IFLA_GRO_MAX_SIZE: u16 = 58;
    pub const IFLA_TSO_MAX_SIZE: u16 = 59;
    pub const IFLA_TSO_MAX_SEGS: u16 = 60;
    pub const IFLA_GSO_IPV4_MAX_SIZE: u16 = 63;
    pub const IFLA_GRO_IPV4_MAX_SIZE: u16 = 64;
}

/// Nested IFLA_INFO_* attribute IDs.
mod info_ids {
    pub const IFLA_INFO_KIND: u16 = 1;
    pub const IFLA_INFO_DATA: u16 = 2;
    pub const IFLA_INFO_SLAVE_KIND: u16 = 4;
    pub const IFLA_INFO_SLAVE_DATA: u16 = 5;
}

/// Strongly-typed link message with all attributes parsed.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LinkMessage {
    /// Fixed-size header.
    pub(crate) header: IfInfoMsg,
    /// Interface name (IFLA_IFNAME).
    pub(crate) name: Option<String>,
    /// Hardware address (IFLA_ADDRESS).
    pub(crate) address: Option<Vec<u8>>,
    /// Broadcast address (IFLA_BROADCAST).
    pub(crate) broadcast: Option<Vec<u8>>,
    /// Permanent hardware address (IFLA_PERM_ADDRESS).
    pub(crate) perm_address: Option<Vec<u8>>,
    /// MTU (IFLA_MTU).
    pub(crate) mtu: Option<u32>,
    /// Minimum MTU (IFLA_MIN_MTU).
    pub(crate) min_mtu: Option<u32>,
    /// Maximum MTU (IFLA_MAX_MTU).
    pub(crate) max_mtu: Option<u32>,
    /// Link index for stacked devices (IFLA_LINK).
    pub(crate) link: Option<u32>,
    /// The namespace `link` is an ifindex in, when it is not this one
    /// (IFLA_LINK_NETNSID).
    pub(crate) link_netnsid: Option<i32>,
    /// Qdisc name (IFLA_QDISC).
    pub(crate) qdisc: Option<String>,
    /// Interface alias (IFLA_IFALIAS), `ip link set dev X alias Y`.
    pub(crate) alias: Option<String>,
    /// Master device index (IFLA_MASTER).
    pub(crate) master: Option<u32>,
    /// Transmit queue length (IFLA_TXQLEN).
    pub(crate) txqlen: Option<u32>,
    /// Operational state (IFLA_OPERSTATE).
    pub(crate) operstate: Option<OperState>,
    /// Group (IFLA_GROUP).
    pub(crate) group: Option<u32>,
    /// Promiscuity count (IFLA_PROMISCUITY).
    pub(crate) promiscuity: Option<u32>,
    /// Number of TX queues (IFLA_NUM_TX_QUEUES).
    pub(crate) num_tx_queues: Option<u32>,
    /// Number of RX queues (IFLA_NUM_RX_QUEUES).
    pub(crate) num_rx_queues: Option<u32>,
    /// Carrier state (IFLA_CARRIER).
    pub(crate) carrier: Option<bool>,
    /// Link info (IFLA_LINKINFO).
    pub(crate) link_info: Option<LinkInfo>,
    /// Statistics (IFLA_STATS64).
    pub(crate) stats: Option<LinkStats>,
    /// GSO max segments per packet (IFLA_GSO_MAX_SEGS). Plan 190 §2.3c.
    pub(crate) gso_max_segs: Option<u32>,
    /// GSO max bytes per packet (IFLA_GSO_MAX_SIZE). Plan 190 §2.3c.
    pub(crate) gso_max_size: Option<u32>,
    /// GRO max bytes per packet (IFLA_GRO_MAX_SIZE). Plan 190 §2.3c.
    pub(crate) gro_max_size: Option<u32>,
    /// TSO max bytes (IFLA_TSO_MAX_SIZE). Plan 190 §2.3c.
    pub(crate) tso_max_size: Option<u32>,
    /// TSO max segments (IFLA_TSO_MAX_SEGS). Plan 190 §2.3c.
    pub(crate) tso_max_segs: Option<u32>,
    /// IPv4-specific GSO max bytes (IFLA_GSO_IPV4_MAX_SIZE,
    /// kernel 6.6+). Plan 190 §2.3c.
    pub(crate) gso_ipv4_max_size: Option<u32>,
    /// IPv4-specific GRO max bytes (IFLA_GRO_IPV4_MAX_SIZE,
    /// kernel 6.6+). Plan 190 §2.3c.
    pub(crate) gro_ipv4_max_size: Option<u32>,
    /// Protodown (IFLA_PROTO_DOWN): held down by a control plane.
    pub(crate) proto_down: Option<bool>,
    /// Alternative names (IFLA_PROP_LIST / IFLA_ALT_IFNAME).
    pub(crate) altnames: Vec<String>,
    /// The IPv4 and IPv6 parts of IFLA_AF_SPEC: devconf, address
    /// generation mode, token (#516).
    pub(crate) inet: Option<crate::netlink::devconf::InetAfSpec>,
}

/// Link type information from IFLA_LINKINFO.
#[derive(Debug, Clone, Default)]
pub struct LinkInfo {
    /// Link type kind (e.g., "vlan", "bridge", "bond").
    pub(crate) kind: Option<String>,
    /// Slave kind for bonded interfaces.
    pub(crate) slave_kind: Option<String>,
    /// Raw type-specific data.
    pub(crate) data: Option<Vec<u8>>,
    /// Raw slave-specific data.
    pub(crate) slave_data: Option<Vec<u8>>,
}

impl LinkInfo {
    /// Get the link type kind (e.g., "vlan", "bridge", "bond").
    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    /// Get the slave kind for bonded interfaces.
    pub fn slave_kind(&self) -> Option<&str> {
        self.slave_kind.as_deref()
    }

    /// Get the raw type-specific data.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Get the raw slave-specific data.
    pub fn slave_data(&self) -> Option<&[u8]> {
        self.slave_data.as_deref()
    }
}

/// Link statistics (parsed `rtnl_link_stats64`).
///
/// `#[non_exhaustive]` with `pub(crate)` fields + public accessors —
/// the message-accessor convention (Plan 231): the struct mirrors a
/// kernel layout that grows over time (`rtnl_link_stats64` has more
/// counters than the subset modelled here), so the fields stay hidden
/// behind accessors and new ones can be added without breaking
/// downstream readers. Read via `rx_packets()` / `tx_bytes()` / … .
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct LinkStats {
    pub(crate) rx_packets: u64,
    pub(crate) tx_packets: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_errors: u64,
    pub(crate) tx_errors: u64,
    pub(crate) rx_dropped: u64,
    pub(crate) tx_dropped: u64,
    pub(crate) multicast: u64,
    pub(crate) collisions: u64,
}

impl From<&LinkStats64> for LinkStats {
    fn from(s: &LinkStats64) -> Self {
        Self {
            rx_packets: s.rx_packets,
            tx_packets: s.tx_packets,
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            rx_errors: s.rx_errors,
            tx_errors: s.tx_errors,
            rx_dropped: s.rx_dropped,
            tx_dropped: s.tx_dropped,
            multicast: s.multicast,
            collisions: s.collisions,
        }
    }
}

impl LinkStats {
    /// Get the number of received packets.
    pub fn rx_packets(&self) -> u64 {
        self.rx_packets
    }

    /// Get the number of transmitted packets.
    pub fn tx_packets(&self) -> u64 {
        self.tx_packets
    }

    /// Get the number of received bytes.
    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes
    }

    /// Get the number of transmitted bytes.
    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes
    }

    /// Get the number of receive errors.
    pub fn rx_errors(&self) -> u64 {
        self.rx_errors
    }

    /// Get the number of transmit errors.
    pub fn tx_errors(&self) -> u64 {
        self.tx_errors
    }

    /// Get the number of dropped received packets.
    pub fn rx_dropped(&self) -> u64 {
        self.rx_dropped
    }

    /// Get the number of dropped transmitted packets.
    pub fn tx_dropped(&self) -> u64 {
        self.tx_dropped
    }

    /// Get the number of multicast packets.
    pub fn multicast(&self) -> u64 {
        self.multicast
    }

    /// Get the number of collisions.
    pub fn collisions(&self) -> u64 {
        self.collisions
    }

    /// Get total packets (rx + tx).
    pub fn total_packets(&self) -> u64 {
        self.rx_packets + self.tx_packets
    }

    /// Get total bytes (rx + tx).
    pub fn total_bytes(&self) -> u64 {
        self.rx_bytes + self.tx_bytes
    }

    /// Get total errors (rx + tx).
    pub fn total_errors(&self) -> u64 {
        self.rx_errors + self.tx_errors
    }

    /// Get total dropped (rx + tx).
    pub fn total_dropped(&self) -> u64 {
        self.rx_dropped + self.tx_dropped
    }
}

impl LinkMessage {
    /// Create a new empty link message.
    pub fn new() -> Self {
        Self::default()
    }

    // =========================================================================
    // Accessor methods
    // =========================================================================

    /// Get the interface index.
    pub fn ifindex(&self) -> u32 {
        self.header.ifi_index as u32
    }

    /// Get the interface name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the interface name, or a default placeholder.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// for link in conn.get_links().await? {
    ///     println!("{}: {}", link.ifindex(), link.name_or("?"));
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn name_or<'a>(&'a self, default: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(default)
    }

    /// Get the hardware address as bytes.
    pub fn address(&self) -> Option<&[u8]> {
        self.address.as_deref()
    }

    /// Get the broadcast address as bytes.
    pub fn broadcast(&self) -> Option<&[u8]> {
        self.broadcast.as_deref()
    }

    /// Get the permanent hardware address as bytes.
    pub fn perm_address(&self) -> Option<&[u8]> {
        self.perm_address.as_deref()
    }

    /// Get the MTU.
    pub fn mtu(&self) -> Option<u32> {
        self.mtu
    }

    /// Get the minimum MTU.
    pub fn min_mtu(&self) -> Option<u32> {
        self.min_mtu
    }

    /// Get the maximum MTU.
    pub fn max_mtu(&self) -> Option<u32> {
        self.max_mtu
    }

    /// Get the link index for stacked devices (e.g., VLAN parent).
    pub fn link(&self) -> Option<u32> {
        self.link
    }

    /// Get the qdisc name.
    pub fn qdisc(&self) -> Option<&str> {
        self.qdisc.as_deref()
    }

    /// The interface's alias (`IFLA_IFALIAS`), if it has one.
    pub fn alias(&self) -> Option<&str> {
        self.alias.as_deref()
    }

    /// Whether a control plane holds the link down (`IFLA_PROTO_DOWN`,
    /// `ip link set … protodown on`). `None` from a kernel or device that
    /// does not report it.
    pub fn proto_down(&self) -> Option<bool> {
        self.proto_down
    }

    /// The link's alternative names (`ip link property add … altname`).
    pub fn altnames(&self) -> &[String] {
        &self.altnames
    }

    /// An IPv4 per-device setting (`/proc/sys/net/ipv4/conf/<dev>/<name>`),
    /// from the dump's `IFLA_AF_SPEC` (#516). `None` for a device with no
    /// IPv4 configuration, or a kernel that did not report it.
    pub fn ipv4_devconf(&self, d: crate::netlink::devconf::Ipv4Devconf) -> Option<u32> {
        self.inet.as_ref()?.ipv4(d)
    }

    /// An IPv6 per-device setting (`/proc/sys/net/ipv6/conf/<dev>/<name>`),
    /// from the dump's `IFLA_AF_SPEC` (#516).
    pub fn ipv6_devconf(&self, d: crate::netlink::devconf::Ipv6Devconf) -> Option<i32> {
        self.inet.as_ref()?.ipv6(d)
    }

    /// An IPv6 per-device setting by its `DEVCONF_*` id
    /// (`linux/ipv6.h`), from the dump's `IFLA_AF_SPEC`.
    pub fn ipv6_devconf_raw(&self, id: usize) -> Option<i32> {
        self.inet.as_ref()?.ipv6_conf.as_ref()?.get(id).copied()
    }

    /// How the kernel makes the link's IPv6 link-local address.
    pub fn addr_gen_mode(&self) -> Option<crate::netlink::devconf::AddrGenMode> {
        crate::netlink::devconf::AddrGenMode::from_u8(self.inet.as_ref()?.addr_gen_mode?)
    }

    /// The link's IPv6 interface identifier token (`ip token`); `None`
    /// when unset (`::`).
    pub fn ipv6_token(&self) -> Option<std::net::Ipv6Addr> {
        self.inet
            .as_ref()?
            .ipv6_token
            .filter(|t| !t.is_unspecified())
    }

    /// Get the master device index.
    pub fn master(&self) -> Option<u32> {
        self.master
    }

    /// Get the transmit queue length.
    pub fn txqlen(&self) -> Option<u32> {
        self.txqlen
    }

    /// Get the operational state.
    pub fn operstate(&self) -> Option<OperState> {
        self.operstate
    }

    /// Get the interface group.
    pub fn group(&self) -> Option<u32> {
        self.group
    }

    // Plan 190 §2.3c — GSO/GRO/TSO cap accessors.

    /// Get the GSO max segments per packet (IFLA_GSO_MAX_SEGS).
    pub fn gso_max_segs(&self) -> Option<u32> {
        self.gso_max_segs
    }

    /// Get the GSO max bytes per packet (IFLA_GSO_MAX_SIZE).
    pub fn gso_max_size(&self) -> Option<u32> {
        self.gso_max_size
    }

    /// Get the GRO max bytes per packet (IFLA_GRO_MAX_SIZE).
    pub fn gro_max_size(&self) -> Option<u32> {
        self.gro_max_size
    }

    /// Get the TSO max bytes (IFLA_TSO_MAX_SIZE).
    pub fn tso_max_size(&self) -> Option<u32> {
        self.tso_max_size
    }

    /// Get the TSO max segments (IFLA_TSO_MAX_SEGS).
    pub fn tso_max_segs(&self) -> Option<u32> {
        self.tso_max_segs
    }

    /// Get the IPv4-specific GSO max bytes
    /// (IFLA_GSO_IPV4_MAX_SIZE; kernel 6.6+).
    pub fn gso_ipv4_max_size(&self) -> Option<u32> {
        self.gso_ipv4_max_size
    }

    /// Get the IPv4-specific GRO max bytes
    /// (IFLA_GRO_IPV4_MAX_SIZE; kernel 6.6+).
    pub fn gro_ipv4_max_size(&self) -> Option<u32> {
        self.gro_ipv4_max_size
    }

    /// Get the promiscuity count.
    pub fn promiscuity(&self) -> Option<u32> {
        self.promiscuity
    }

    /// Get the number of TX queues.
    pub fn num_tx_queues(&self) -> Option<u32> {
        self.num_tx_queues
    }

    /// Get the number of RX queues.
    pub fn num_rx_queues(&self) -> Option<u32> {
        self.num_rx_queues
    }

    /// Get the carrier state.
    pub fn carrier(&self) -> Option<bool> {
        self.carrier
    }

    /// Get the link info.
    pub fn link_info(&self) -> Option<&LinkInfo> {
        self.link_info.as_ref()
    }

    /// Get the statistics.
    pub fn stats(&self) -> Option<&LinkStats> {
        self.stats.as_ref()
    }

    /// Get the interface flags.
    pub fn flags(&self) -> u32 {
        self.header.ifi_flags
    }

    /// Get the link type kind (e.g., "vlan", "bridge", "veth").
    pub fn kind(&self) -> Option<&str> {
        self.link_info.as_ref()?.kind.as_deref()
    }

    /// Format the hardware address as a MAC string.
    pub fn mac_address(&self) -> Option<String> {
        let addr = self.address.as_ref()?;
        if addr.len() == 6 {
            Some(format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
            ))
        } else {
            None
        }
    }

    // =========================================================================
    // Boolean checks
    // =========================================================================

    /// Check if the interface is up.
    pub fn is_up(&self) -> bool {
        self.header.ifi_flags & 0x1 != 0 // IFF_UP
    }

    /// Check if the interface is running (lower layer up).
    pub fn is_running(&self) -> bool {
        self.header.ifi_flags & 0x40 != 0 // IFF_RUNNING
    }

    /// Check if the interface is a loopback.
    pub fn is_loopback(&self) -> bool {
        self.header.ifi_flags & 0x8 != 0 // IFF_LOOPBACK
    }

    /// Check if the interface supports broadcast.
    pub fn is_broadcast(&self) -> bool {
        self.header.ifi_flags & 0x2 != 0 // IFF_BROADCAST
    }

    /// Check if the interface is point-to-point.
    pub fn is_pointopoint(&self) -> bool {
        self.header.ifi_flags & 0x10 != 0 // IFF_POINTOPOINT
    }

    /// Check if the carrier is present.
    pub fn has_carrier(&self) -> bool {
        self.carrier.unwrap_or(false)
    }

    // =========================================================================
    // Statistics convenience methods
    // =========================================================================

    /// Get total bytes transferred (rx + tx), or 0 if stats not available.
    ///
    /// This is a convenience method that delegates to `stats().total_bytes()`.
    pub fn total_bytes(&self) -> u64 {
        self.stats.as_ref().map(|s| s.total_bytes()).unwrap_or(0)
    }

    /// Get total packets transferred (rx + tx), or 0 if stats not available.
    ///
    /// This is a convenience method that delegates to `stats().total_packets()`.
    pub fn total_packets(&self) -> u64 {
        self.stats.as_ref().map(|s| s.total_packets()).unwrap_or(0)
    }

    /// Get total errors (rx + tx), or 0 if stats not available.
    ///
    /// This is a convenience method that delegates to `stats().total_errors()`.
    pub fn total_errors(&self) -> u64 {
        self.stats.as_ref().map(|s| s.total_errors()).unwrap_or(0)
    }

    /// Get total dropped packets (rx + tx), or 0 if stats not available.
    ///
    /// This is a convenience method that delegates to `stats().total_dropped()`.
    pub fn total_dropped(&self) -> u64 {
        self.stats.as_ref().map(|s| s.total_dropped()).unwrap_or(0)
    }

    /// Get received bytes, or 0 if stats not available.
    pub fn rx_bytes(&self) -> u64 {
        self.stats.as_ref().map(|s| s.rx_bytes()).unwrap_or(0)
    }

    /// Get transmitted bytes, or 0 if stats not available.
    pub fn tx_bytes(&self) -> u64 {
        self.stats.as_ref().map(|s| s.tx_bytes()).unwrap_or(0)
    }

    /// Get received packets, or 0 if stats not available.
    pub fn rx_packets(&self) -> u64 {
        self.stats.as_ref().map(|s| s.rx_packets()).unwrap_or(0)
    }

    /// Get transmitted packets, or 0 if stats not available.
    pub fn tx_packets(&self) -> u64 {
        self.stats.as_ref().map(|s| s.tx_packets()).unwrap_or(0)
    }

    /// Get receive errors, or 0 if stats not available.
    pub fn rx_errors(&self) -> u64 {
        self.stats.as_ref().map(|s| s.rx_errors()).unwrap_or(0)
    }

    /// Get transmit errors, or 0 if stats not available.
    pub fn tx_errors(&self) -> u64 {
        self.stats.as_ref().map(|s| s.tx_errors()).unwrap_or(0)
    }

    /// Get dropped received packets, or 0 if stats not available.
    pub fn rx_dropped(&self) -> u64 {
        self.stats.as_ref().map(|s| s.rx_dropped()).unwrap_or(0)
    }

    /// Get dropped transmitted packets, or 0 if stats not available.
    pub fn tx_dropped(&self) -> u64 {
        self.stats.as_ref().map(|s| s.tx_dropped()).unwrap_or(0)
    }
}

impl FromNetlink for LinkMessage {
    fn write_dump_header(buf: &mut Vec<u8>) {
        // RTM_GETLINK requires an IfInfoMsg header
        let header = IfInfoMsg::new();
        buf.extend_from_slice(header.as_bytes());
    }

    fn parse(input: &mut &[u8]) -> PResult<Self> {
        // Parse fixed header (16 bytes)
        if input.len() < IfInfoMsg::SIZE {
            return Err(winnow::error::ErrMode::Cut(
                winnow::error::ContextError::new(),
            ));
        }

        let header_bytes: &[u8] = take(IfInfoMsg::SIZE).parse_next(input)?;
        let header = *IfInfoMsg::from_bytes(header_bytes)
            .map_err(|_| winnow::error::ErrMode::Cut(winnow::error::ContextError::new()))?;

        let mut msg = LinkMessage {
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

            // Match attribute type (mask out flags)
            match attr_type & 0x3FFF {
                attr_ids::IFLA_IFNAME => {
                    msg.name = Some(parse_string_from_bytes(attr_data));
                }
                attr_ids::IFLA_IFALIAS => {
                    let alias = parse_string_from_bytes(attr_data);
                    msg.alias = (!alias.is_empty()).then_some(alias);
                }
                attr_ids::IFLA_ADDRESS => {
                    msg.address = Some(attr_data.to_vec());
                }
                attr_ids::IFLA_BROADCAST => {
                    msg.broadcast = Some(attr_data.to_vec());
                }
                attr_ids::IFLA_PERM_ADDRESS => {
                    msg.perm_address = Some(attr_data.to_vec());
                }
                attr_ids::IFLA_MTU if attr_data.len() >= 4 => {
                    msg.mtu = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_MIN_MTU if attr_data.len() >= 4 => {
                    msg.min_mtu = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_MAX_MTU if attr_data.len() >= 4 => {
                    msg.max_mtu = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_LINK if attr_data.len() >= 4 => {
                    msg.link = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_LINK_NETNSID if attr_data.len() >= 4 => {
                    msg.link_netnsid =
                        Some(i32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_QDISC => {
                    msg.qdisc = Some(parse_string_from_bytes(attr_data));
                }
                attr_ids::IFLA_MASTER if attr_data.len() >= 4 => {
                    msg.master = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_TXQLEN if attr_data.len() >= 4 => {
                    msg.txqlen = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_OPERSTATE if !attr_data.is_empty() => {
                    msg.operstate = Some(OperState::from(attr_data[0]));
                }
                attr_ids::IFLA_GROUP if attr_data.len() >= 4 => {
                    msg.group = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_PROMISCUITY if attr_data.len() >= 4 => {
                    msg.promiscuity = Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_NUM_TX_QUEUES if attr_data.len() >= 4 => {
                    msg.num_tx_queues =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_NUM_RX_QUEUES if attr_data.len() >= 4 => {
                    msg.num_rx_queues =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_CARRIER if !attr_data.is_empty() => {
                    msg.carrier = Some(attr_data[0] != 0);
                }
                attr_ids::IFLA_LINKINFO => {
                    msg.link_info = Some(parse_link_info(attr_data));
                }
                attr_ids::IFLA_STATS64 => {
                    if let Some(stats) = LinkStats64::from_bytes(attr_data) {
                        msg.stats = Some(LinkStats::from(&stats));
                    }
                }
                // Plan 190 §2.3c — GSO/GRO/TSO cap parsing.
                // accept-larger-than-expected per CLAUDE.md §"Parser robustness" rule 1.
                // A bridge-family dump's AF_SPEC holds IFLA_BRIDGE_*, whose
                // ids overlap AF_INET's.
                attr_ids::IFLA_AF_SPEC if msg.header.ifi_family != libc::AF_BRIDGE as u8 => {
                    msg.inet = Some(crate::netlink::devconf::InetAfSpec::parse(attr_data));
                }
                attr_ids::IFLA_PROTO_DOWN if !attr_data.is_empty() => {
                    msg.proto_down = Some(attr_data[0] != 0);
                }
                attr_ids::IFLA_PROP_LIST => {
                    msg.altnames = crate::netlink::attr::AttrIter::new(attr_data)
                        .filter(|(t, _)| t & 0x3FFF == attr_ids::IFLA_ALT_IFNAME)
                        .map(|(_, p)| String::from_utf8_lossy(p).trim_end_matches('\0').to_string())
                        .collect();
                }
                attr_ids::IFLA_GSO_MAX_SEGS if attr_data.len() >= 4 => {
                    msg.gso_max_segs =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_GSO_MAX_SIZE if attr_data.len() >= 4 => {
                    msg.gso_max_size =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_GRO_MAX_SIZE if attr_data.len() >= 4 => {
                    msg.gro_max_size =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_TSO_MAX_SIZE if attr_data.len() >= 4 => {
                    msg.tso_max_size =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_TSO_MAX_SEGS if attr_data.len() >= 4 => {
                    msg.tso_max_segs =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_GSO_IPV4_MAX_SIZE if attr_data.len() >= 4 => {
                    msg.gso_ipv4_max_size =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                attr_ids::IFLA_GRO_IPV4_MAX_SIZE if attr_data.len() >= 4 => {
                    msg.gro_ipv4_max_size =
                        Some(u32::from_ne_bytes(attr_data[..4].try_into().unwrap()));
                }
                _ => {} // Ignore unknown attributes
            }
        }

        Ok(msg)
    }
}

/// Parse IFLA_LINKINFO nested attributes.
fn parse_link_info(data: &[u8]) -> LinkInfo {
    let mut info = LinkInfo::default();
    let mut input = data;

    while !input.is_empty() && input.len() >= 4 {
        let len = u16::from_ne_bytes(input[..2].try_into().unwrap()) as usize;
        let attr_type = u16::from_ne_bytes(input[2..4].try_into().unwrap());

        if len < 4 || input.len() < len {
            break;
        }

        let payload = &input[4..len];

        match attr_type & 0x3FFF {
            info_ids::IFLA_INFO_KIND => {
                info.kind = Some(parse_string_from_bytes(payload));
            }
            info_ids::IFLA_INFO_DATA => {
                info.data = Some(payload.to_vec());
            }
            info_ids::IFLA_INFO_SLAVE_KIND => {
                info.slave_kind = Some(parse_string_from_bytes(payload));
            }
            info_ids::IFLA_INFO_SLAVE_DATA => {
                info.slave_data = Some(payload.to_vec());
            }
            _ => {}
        }

        let aligned = (len + 3) & !3;
        if input.len() <= aligned {
            break;
        }
        input = &input[aligned..];
    }

    info
}

impl ToNetlink for LinkMessage {
    fn netlink_len(&self) -> usize {
        let mut len = IfInfoMsg::SIZE;

        if let Some(ref name) = self.name {
            len += nla_size(name.len() + 1);
        }
        if let Some(ref addr) = self.address {
            len += nla_size(addr.len());
        }
        if self.mtu.is_some() {
            len += nla_size(4);
        }
        if self.master.is_some() {
            len += nla_size(4);
        }
        if self.txqlen.is_some() {
            len += nla_size(4);
        }

        len
    }

    fn write_to(&self, buf: &mut Vec<u8>) -> Result<usize> {
        let start = buf.len();

        // Write header
        buf.extend_from_slice(self.header.as_bytes());

        // Write attributes
        if let Some(ref name) = self.name {
            write_attr_str(buf, attr_ids::IFLA_IFNAME, name);
        }
        if let Some(ref addr) = self.address {
            write_attr_bytes(buf, attr_ids::IFLA_ADDRESS, addr);
        }
        if let Some(mtu) = self.mtu {
            write_attr_u32(buf, attr_ids::IFLA_MTU, mtu);
        }
        if let Some(master) = self.master {
            write_attr_u32(buf, attr_ids::IFLA_MASTER, master);
        }
        if let Some(txqlen) = self.txqlen {
            write_attr_u32(buf, attr_ids::IFLA_TXQLEN, txqlen);
        }

        Ok(buf.len() - start)
    }
}

/// Calculate aligned attribute size.
fn nla_size(payload_len: usize) -> usize {
    (4 + payload_len + 3) & !3
}

fn write_attr_u32(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
    let len: u16 = 8;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(&value.to_ne_bytes());
}

fn write_attr_str(buf: &mut Vec<u8>, attr_type: u16, value: &str) {
    let payload_len = value.len() + 1;
    let len = 4 + payload_len;
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&attr_type.to_ne_bytes());
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
    // Padding
    let aligned = (len + 3) & !3;
    for _ in 0..(aligned - len) {
        buf.push(0);
    }
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

/// Builder for constructing LinkMessage.
#[derive(Debug, Clone, Default)]
pub struct LinkMessageBuilder {
    msg: LinkMessage,
}

impl LinkMessageBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the interface index.
    pub fn ifindex(mut self, index: i32) -> Self {
        self.msg.header.ifi_index = index;
        self
    }

    /// Set the interface flags.
    pub fn flags(mut self, flags: u32) -> Self {
        self.msg.header.ifi_flags = flags;
        self
    }

    /// Set the change mask.
    pub fn change(mut self, change: u32) -> Self {
        self.msg.header.ifi_change = change;
        self
    }

    /// Set the interface name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.msg.name = Some(name.into());
        self
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.msg.mtu = Some(mtu);
        self
    }

    /// Set the hardware address.
    pub fn address(mut self, addr: Vec<u8>) -> Self {
        self.msg.address = Some(addr);
        self
    }

    /// Set the master device index.
    pub fn master(mut self, master: u32) -> Self {
        self.msg.master = Some(master);
        self
    }

    /// Set the TX queue length.
    pub fn txqlen(mut self, txqlen: u32) -> Self {
        self.msg.txqlen = Some(txqlen);
        self
    }

    /// Build the message.
    pub fn build(self) -> LinkMessage {
        self.msg
    }
}

// =========================================================================
// Bond info types
// =========================================================================

/// Constants for IFLA_BOND_* attributes (from IFLA_INFO_DATA).
mod bond_info_ids {
    pub const IFLA_BOND_MODE: u16 = 1;
    pub const IFLA_BOND_ACTIVE_SLAVE: u16 = 2;
    pub const IFLA_BOND_MIIMON: u16 = 3;
    pub const IFLA_BOND_UPDELAY: u16 = 4;
    pub const IFLA_BOND_DOWNDELAY: u16 = 5;
    pub const IFLA_BOND_USE_CARRIER: u16 = 6;
    pub const IFLA_BOND_ARP_INTERVAL: u16 = 7;
    pub const IFLA_BOND_ARP_VALIDATE: u16 = 9;
    pub const IFLA_BOND_PRIMARY: u16 = 11;
    pub const IFLA_BOND_XMIT_HASH_POLICY: u16 = 14;
    pub const IFLA_BOND_ALL_SLAVES_ACTIVE: u16 = 17;
    pub const IFLA_BOND_MIN_LINKS: u16 = 18;
    pub const IFLA_BOND_AD_LACP_RATE: u16 = 21;
    pub const IFLA_BOND_AD_INFO: u16 = 23;
}

/// Constants for IFLA_BOND_AD_INFO_* attributes.
mod bond_ad_info_ids {
    pub const IFLA_BOND_AD_INFO_AGGREGATOR: u16 = 1;
    pub const IFLA_BOND_AD_INFO_NUM_PORTS: u16 = 2;
    pub const IFLA_BOND_AD_INFO_ACTOR_KEY: u16 = 3;
    pub const IFLA_BOND_AD_INFO_PARTNER_KEY: u16 = 4;
    pub const IFLA_BOND_AD_INFO_PARTNER_MAC: u16 = 5;
}

/// Constants for IFLA_BOND_SLAVE_* attributes (from IFLA_INFO_SLAVE_DATA).
mod bond_slave_ids {
    pub const IFLA_BOND_SLAVE_STATE: u16 = 1;
    pub const IFLA_BOND_SLAVE_MII_STATUS: u16 = 2;
    pub const IFLA_BOND_SLAVE_LINK_FAILURE_COUNT: u16 = 3;
    pub const IFLA_BOND_SLAVE_PERM_HWADDR: u16 = 4;
    pub const IFLA_BOND_SLAVE_QUEUE_ID: u16 = 5;
    pub const IFLA_BOND_SLAVE_AD_AGGREGATOR_ID: u16 = 6;
    pub const IFLA_BOND_SLAVE_PRIO: u16 = 9;
}

/// Bond device configuration as reported by the kernel.
///
/// Parsed from `IFLA_INFO_DATA` when `kind() == Some("bond")`.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// let link = conn.get_link_by_name("bond0").await?.unwrap();
/// if let Some(info) = link.bond_info() {
///     println!("Mode: {:?}, miimon: {}ms", info.mode, info.miimon);
///     if let Some(ad) = &info.ad_info {
///         println!("LACP aggregator: {}", ad.aggregator_id);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct BondInfo {
    /// Bond mode.
    pub mode: u8,
    /// MII monitoring interval in milliseconds.
    pub miimon: u32,
    /// Updelay in milliseconds.
    pub updelay: u32,
    /// Downdelay in milliseconds.
    pub downdelay: u32,
    /// Transmit hash policy.
    pub xmit_hash_policy: u8,
    /// Minimum number of active links.
    pub min_links: u32,
    /// LACP rate (only for 802.3ad mode).
    pub lacp_rate: Option<u8>,
    /// 802.3ad aggregation info.
    pub ad_info: Option<BondAdInfo>,
    /// Primary slave ifindex.
    pub primary: Option<u32>,
    /// Active slave ifindex.
    pub active_slave: Option<u32>,
    /// Use carrier detection.
    pub use_carrier: bool,
    /// All slaves active mode.
    pub all_slaves_active: bool,
    /// ARP monitoring interval in milliseconds.
    pub arp_interval: u32,
    /// ARP validation mode.
    pub arp_validate: Option<u32>,
}

impl BondInfo {
    /// Get the bond mode as a typed enum.
    pub fn bond_mode(&self) -> Option<crate::netlink::link::BondMode> {
        crate::netlink::link::BondMode::try_from(self.mode).ok()
    }

    /// Get the transmit hash policy as a typed enum.
    pub fn hash_policy(&self) -> Option<crate::netlink::link::XmitHashPolicy> {
        crate::netlink::link::XmitHashPolicy::try_from(self.xmit_hash_policy).ok()
    }
}

/// 802.3ad (LACP) aggregation info.
#[derive(Debug, Clone)]
pub struct BondAdInfo {
    /// Aggregator ID.
    pub aggregator_id: u16,
    /// Number of ports in the aggregate.
    pub num_ports: u16,
    /// Actor key.
    pub actor_key: u16,
    /// Partner key.
    pub partner_key: u16,
    /// Partner MAC address.
    pub partner_mac: [u8; 6],
}

/// Bond slave status as reported by the kernel.
///
/// Parsed from `IFLA_INFO_SLAVE_DATA` when `slave_kind == "bond"`.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// let links = conn.get_links().await?;
/// for link in &links {
///     if let Some(slave) = link.bond_slave_info() {
///         println!("{}: state={:?}, mii={:?}, failures={}",
///             link.name_or("?"), slave.state, slave.mii_status,
///             slave.link_failure_count);
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct BondSlaveInfo {
    /// Slave state (active or backup).
    pub state: BondSlaveState,
    /// MII link status.
    pub mii_status: MiiStatus,
    /// Number of link failures detected.
    pub link_failure_count: u32,
    /// Permanent hardware address.
    pub perm_hwaddr: Option<[u8; 6]>,
    /// Queue ID for traffic distribution.
    pub queue_id: Option<u16>,
    /// 802.3ad aggregator ID.
    pub ad_aggregator_id: Option<u16>,
    /// Slave priority.
    pub prio: Option<i32>,
}

/// Bond slave state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BondSlaveState {
    /// Active slave (transmitting traffic).
    Active,
    /// Backup slave (standby).
    Backup,
}

/// MII link status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MiiStatus {
    /// Link is up.
    Up,
    /// Link is down.
    Down,
}

impl LinkMessage {
    /// Get bond configuration if this is a bond interface.
    ///
    /// Returns `None` if the interface is not a bond.
    pub fn bond_info(&self) -> Option<BondInfo> {
        let link_info = self.link_info.as_ref()?;
        if link_info.kind.as_deref() != Some("bond") {
            return None;
        }
        let data = link_info.data.as_deref()?;
        Some(parse_bond_info(data))
    }

    /// Get bond slave info if this interface is a bond slave.
    ///
    /// Returns `None` if the interface is not enslaved to a bond.
    pub fn bond_slave_info(&self) -> Option<BondSlaveInfo> {
        let link_info = self.link_info.as_ref()?;
        if link_info.slave_kind.as_deref() != Some("bond") {
            return None;
        }
        let data = link_info.slave_data.as_deref()?;
        Some(parse_bond_slave_info(data))
    }

    /// Check if this interface is a bond slave.
    pub fn is_bond_slave(&self) -> bool {
        self.link_info
            .as_ref()
            .and_then(|i| i.slave_kind.as_deref())
            == Some("bond")
    }
}

/// Parse a u32 from a byte slice (native endian).
fn parse_u32_ne(data: &[u8]) -> Option<u32> {
    if data.len() >= 4 {
        Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
    } else {
        None
    }
}

/// Parse a u16 from a byte slice (native endian).
fn parse_u16_ne(data: &[u8]) -> Option<u16> {
    if data.len() >= 2 {
        Some(u16::from_ne_bytes([data[0], data[1]]))
    } else {
        None
    }
}

/// Parse bond info from raw IFLA_INFO_DATA bytes.
fn parse_bond_info(data: &[u8]) -> BondInfo {
    let mut info = BondInfo {
        mode: 0,
        miimon: 0,
        updelay: 0,
        downdelay: 0,
        xmit_hash_policy: 0,
        min_links: 0,
        lacp_rate: None,
        ad_info: None,
        primary: None,
        active_slave: None,
        use_carrier: true,
        all_slaves_active: false,
        arp_interval: 0,
        arp_validate: None,
    };

    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u16::from_ne_bytes([data[pos], data[pos + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[pos + 2], data[pos + 3]]) & 0x3FFF;

        if len < 4 || pos + len > data.len() {
            break;
        }

        let payload = &data[pos + 4..pos + len];

        match attr_type {
            bond_info_ids::IFLA_BOND_MODE if !payload.is_empty() => {
                info.mode = payload[0];
            }
            bond_info_ids::IFLA_BOND_MIIMON => {
                if let Some(v) = parse_u32_ne(payload) {
                    info.miimon = v;
                }
            }
            bond_info_ids::IFLA_BOND_UPDELAY => {
                if let Some(v) = parse_u32_ne(payload) {
                    info.updelay = v;
                }
            }
            bond_info_ids::IFLA_BOND_DOWNDELAY => {
                if let Some(v) = parse_u32_ne(payload) {
                    info.downdelay = v;
                }
            }
            bond_info_ids::IFLA_BOND_USE_CARRIER if !payload.is_empty() => {
                info.use_carrier = payload[0] != 0;
            }
            bond_info_ids::IFLA_BOND_ARP_INTERVAL => {
                if let Some(v) = parse_u32_ne(payload) {
                    info.arp_interval = v;
                }
            }
            bond_info_ids::IFLA_BOND_ARP_VALIDATE => {
                info.arp_validate = parse_u32_ne(payload);
            }
            bond_info_ids::IFLA_BOND_PRIMARY => {
                info.primary = parse_u32_ne(payload);
            }
            bond_info_ids::IFLA_BOND_ACTIVE_SLAVE => {
                info.active_slave = parse_u32_ne(payload);
            }
            bond_info_ids::IFLA_BOND_XMIT_HASH_POLICY if !payload.is_empty() => {
                info.xmit_hash_policy = payload[0];
            }
            bond_info_ids::IFLA_BOND_ALL_SLAVES_ACTIVE if !payload.is_empty() => {
                info.all_slaves_active = payload[0] != 0;
            }
            bond_info_ids::IFLA_BOND_MIN_LINKS => {
                if let Some(v) = parse_u32_ne(payload) {
                    info.min_links = v;
                }
            }
            bond_info_ids::IFLA_BOND_AD_LACP_RATE if !payload.is_empty() => {
                info.lacp_rate = Some(payload[0]);
            }
            bond_info_ids::IFLA_BOND_AD_INFO => {
                info.ad_info = Some(parse_bond_ad_info(payload));
            }
            _ => {}
        }

        pos += (len + 3) & !3;
    }

    info
}

/// Parse IFLA_BOND_AD_INFO nested attributes.
fn parse_bond_ad_info(data: &[u8]) -> BondAdInfo {
    let mut info = BondAdInfo {
        aggregator_id: 0,
        num_ports: 0,
        actor_key: 0,
        partner_key: 0,
        partner_mac: [0; 6],
    };

    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u16::from_ne_bytes([data[pos], data[pos + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[pos + 2], data[pos + 3]]) & 0x3FFF;

        if len < 4 || pos + len > data.len() {
            break;
        }

        let payload = &data[pos + 4..pos + len];

        match attr_type {
            bond_ad_info_ids::IFLA_BOND_AD_INFO_AGGREGATOR => {
                if let Some(v) = parse_u16_ne(payload) {
                    info.aggregator_id = v;
                }
            }
            bond_ad_info_ids::IFLA_BOND_AD_INFO_NUM_PORTS => {
                if let Some(v) = parse_u16_ne(payload) {
                    info.num_ports = v;
                }
            }
            bond_ad_info_ids::IFLA_BOND_AD_INFO_ACTOR_KEY => {
                if let Some(v) = parse_u16_ne(payload) {
                    info.actor_key = v;
                }
            }
            bond_ad_info_ids::IFLA_BOND_AD_INFO_PARTNER_KEY => {
                if let Some(v) = parse_u16_ne(payload) {
                    info.partner_key = v;
                }
            }
            bond_ad_info_ids::IFLA_BOND_AD_INFO_PARTNER_MAC if payload.len() >= 6 => {
                info.partner_mac.copy_from_slice(&payload[..6]);
            }
            _ => {}
        }

        pos += (len + 3) & !3;
    }

    info
}

/// Parse bond slave info from raw IFLA_INFO_SLAVE_DATA bytes.
fn parse_bond_slave_info(data: &[u8]) -> BondSlaveInfo {
    let mut info = BondSlaveInfo {
        state: BondSlaveState::Backup,
        mii_status: MiiStatus::Down,
        link_failure_count: 0,
        perm_hwaddr: None,
        queue_id: None,
        ad_aggregator_id: None,
        prio: None,
    };

    let mut pos = 0;
    while pos + 4 <= data.len() {
        let len = u16::from_ne_bytes([data[pos], data[pos + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([data[pos + 2], data[pos + 3]]) & 0x3FFF;

        if len < 4 || pos + len > data.len() {
            break;
        }

        let payload = &data[pos + 4..pos + len];

        match attr_type {
            bond_slave_ids::IFLA_BOND_SLAVE_STATE if !payload.is_empty() => {
                info.state = if payload[0] == 0 {
                    BondSlaveState::Active
                } else {
                    BondSlaveState::Backup
                };
            }
            bond_slave_ids::IFLA_BOND_SLAVE_MII_STATUS if !payload.is_empty() => {
                info.mii_status = if payload[0] == 0 {
                    MiiStatus::Up
                } else {
                    MiiStatus::Down
                };
            }
            bond_slave_ids::IFLA_BOND_SLAVE_LINK_FAILURE_COUNT => {
                if let Some(v) = parse_u32_ne(payload) {
                    info.link_failure_count = v;
                }
            }
            bond_slave_ids::IFLA_BOND_SLAVE_PERM_HWADDR if payload.len() >= 6 => {
                let mut addr = [0u8; 6];
                addr.copy_from_slice(&payload[..6]);
                info.perm_hwaddr = Some(addr);
            }
            bond_slave_ids::IFLA_BOND_SLAVE_QUEUE_ID => {
                info.queue_id = parse_u16_ne(payload);
            }
            bond_slave_ids::IFLA_BOND_SLAVE_AD_AGGREGATOR_ID => {
                info.ad_aggregator_id = parse_u16_ne(payload);
            }
            bond_slave_ids::IFLA_BOND_SLAVE_PRIO if payload.len() >= 4 => {
                info.prio = Some(i32::from_ne_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]));
            }
            _ => {}
        }

        pos += (len + 3) & !3;
    }

    info
}

/// What [`Connection::wait_link`](crate::Connection::wait_link) waits for
/// (#524).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LinkCond {
    /// `IFF_UP`, the administrative state.
    /// [`set_link_up`](crate::Connection::set_link_up) sets it before it
    /// returns, so this is for waiting on someone else's change.
    AdminUp,
    /// `IFF_RUNNING`: the driver says the link can pass traffic — it has a
    /// carrier, and is not dormant.
    Running,
    /// `IFLA_OPERSTATE` is `UP` (RFC 2863). A device that does not track
    /// its operational state reports `UNKNOWN`, which is not `UP`: wait
    /// for [`Running`](Self::Running) there.
    OperUp,
    /// `IFLA_CARRIER` is 1: the physical (or virtual) link is there.
    Carrier,
}

impl LinkCond {
    /// Whether `link` meets the condition.
    pub fn holds(self, link: &LinkMessage) -> bool {
        match self {
            Self::AdminUp => link.is_up(),
            Self::Running => link.is_running(),
            Self::OperUp => link.operstate() == Some(OperState::Up),
            Self::Carrier => link.carrier() == Some(true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder() {
        let msg = LinkMessageBuilder::new()
            .ifindex(1)
            .name("eth0")
            .mtu(1500)
            .build();

        assert_eq!(msg.ifindex(), 1);
        assert_eq!(msg.name, Some("eth0".to_string()));
        assert_eq!(msg.mtu, Some(1500));
    }

    // -------- Plan 190 §2.3c — GSO/GRO/TSO cap parsing --------

    fn append_u32_attr(buf: &mut Vec<u8>, attr_type: u16, value: u32) {
        // 4 header bytes + 4 payload bytes; aligned to 4
        buf.extend_from_slice(&8u16.to_ne_bytes());
        buf.extend_from_slice(&attr_type.to_ne_bytes());
        buf.extend_from_slice(&value.to_ne_bytes());
    }

    #[test]
    fn parser_extracts_all_gso_gro_tso_caps() {
        // 16-byte zero header + 7 u32 attrs.
        let mut buf = vec![0u8; IfInfoMsg::SIZE];
        append_u32_attr(&mut buf, attr_ids::IFLA_GSO_MAX_SEGS, 32);
        append_u32_attr(&mut buf, attr_ids::IFLA_GSO_MAX_SIZE, 65536);
        append_u32_attr(&mut buf, attr_ids::IFLA_GRO_MAX_SIZE, 65536);
        append_u32_attr(&mut buf, attr_ids::IFLA_TSO_MAX_SIZE, 65535);
        append_u32_attr(&mut buf, attr_ids::IFLA_TSO_MAX_SEGS, 16);
        append_u32_attr(&mut buf, attr_ids::IFLA_GSO_IPV4_MAX_SIZE, 16384);
        append_u32_attr(&mut buf, attr_ids::IFLA_GRO_IPV4_MAX_SIZE, 16384);

        let mut input = buf.as_slice();
        let msg = LinkMessage::parse(&mut input).expect("parse should succeed");

        assert_eq!(msg.gso_max_segs(), Some(32));
        assert_eq!(msg.gso_max_size(), Some(65536));
        assert_eq!(msg.gro_max_size(), Some(65536));
        assert_eq!(msg.tso_max_size(), Some(65535));
        assert_eq!(msg.tso_max_segs(), Some(16));
        assert_eq!(msg.gso_ipv4_max_size(), Some(16384));
        assert_eq!(msg.gro_ipv4_max_size(), Some(16384));
    }

    #[test]
    fn parser_skips_gso_caps_when_absent() {
        let buf = vec![0u8; IfInfoMsg::SIZE];
        let mut input = buf.as_slice();
        let msg = LinkMessage::parse(&mut input).expect("parse should succeed");
        // All 7 caps must be None when the dump omits them
        // (pre-6.6 kernels, older NIC drivers).
        assert!(msg.gso_max_size().is_none());
        assert!(msg.gso_ipv4_max_size().is_none());
        assert!(msg.gro_ipv4_max_size().is_none());
    }

    #[test]
    fn ifla_attr_enum_recognizes_new_ipv4_codes() {
        use crate::netlink::types::link::IflaAttr;
        // Plan 190 §2.3c numeric pins.
        assert_eq!(IflaAttr::from(63), IflaAttr::GsoIpv4MaxSize);
        assert_eq!(IflaAttr::from(64), IflaAttr::GroIpv4MaxSize);
        assert_eq!(IflaAttr::GsoIpv4MaxSize as u16, 63);
        assert_eq!(IflaAttr::GroIpv4MaxSize as u16, 64);
    }
}
