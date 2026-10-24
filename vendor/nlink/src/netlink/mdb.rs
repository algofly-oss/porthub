//! Bridge multicast database (MDB) management.
//!
//! The MDB holds the bridge's snooped/static multicast group → port
//! mappings (`bridge mdb`). This module exposes a typed read path and
//! a typed add/delete builder over `RTM_{GET,NEW,DEL}MDB`.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # use std::net::IpAddr;
//! use std::net::Ipv4Addr;
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::mdb::MdbEntryBuilder;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // List MDB entries for a bridge.
//! for e in conn.get_mdb("br0").await? {
//!     println!("port={} group={} vid={}", e.port_ifindex, e.group, e.vid);
//! }
//!
//! // Statically program a group on a port.
//! conn.add_mdb(
//!     MdbEntryBuilder::new("br0", "swp1", IpAddr::V4(Ipv4Addr::new(239, 1, 1, 1)))
//!         .vid(10)
//!         .permanent(),
//! ).await?;
//! # Ok(())
//! # }
//! ```

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use zerocopy::{FromBytes, IntoBytes};

use super::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgType},
    protocol::Route,
    types::mdb::{
        BrMdbEntry, BrPortMsg, MDB_FLAGS_BLOCKED, MDB_FLAGS_FAST_LEAVE, MDB_FLAGS_OFFLOAD,
        MDB_FLAGS_STAR_EXCL, MDB_PERMANENT, MDB_TEMPORARY, eth_p, mdba, mdba_mdb, mdba_mdb_entry,
        mdba_set,
    },
};

/// AF_BRIDGE address family.
const AF_BRIDGE: u8 = 7;
/// NLM_F_CREATE flag.
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_EXCL flag.
const NLM_F_EXCL: u16 = 0x200;

/// A multicast group address — either an IP group or an L2 MAC group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdbGroup {
    /// IPv4 / IPv6 multicast group.
    Ip(IpAddr),
    /// Layer-2 multicast MAC address.
    Mac([u8; 6]),
}

impl From<IpAddr> for MdbGroup {
    fn from(ip: IpAddr) -> Self {
        MdbGroup::Ip(ip)
    }
}
impl From<Ipv4Addr> for MdbGroup {
    fn from(ip: Ipv4Addr) -> Self {
        MdbGroup::Ip(IpAddr::V4(ip))
    }
}
impl From<Ipv6Addr> for MdbGroup {
    fn from(ip: Ipv6Addr) -> Self {
        MdbGroup::Ip(IpAddr::V6(ip))
    }
}
impl From<[u8; 6]> for MdbGroup {
    fn from(mac: [u8; 6]) -> Self {
        MdbGroup::Mac(mac)
    }
}

impl FromStr for MdbGroup {
    type Err = Error;

    /// Parse a group: an IPv4/IPv6 multicast address, or a 6-octet
    /// colon- or dash-separated MAC. IP forms are tried first (an IPv6
    /// literal also contains colons), then the MAC form.
    fn from_str(s: &str) -> Result<Self> {
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(MdbGroup::Ip(ip));
        }
        let parts: Vec<&str> = if s.contains(':') {
            s.split(':').collect()
        } else {
            s.split('-').collect()
        };
        if parts.len() == 6 {
            let mut mac = [0u8; 6];
            for (i, p) in parts.iter().enumerate() {
                mac[i] = u8::from_str_radix(p, 16).map_err(|_| {
                    Error::invalid_message(format!("mdb group: invalid MAC octet `{p}`"))
                })?;
            }
            return Ok(MdbGroup::Mac(mac));
        }
        Err(Error::invalid_message(format!(
            "mdb group: `{s}` is neither an IP multicast address nor a MAC"
        )))
    }
}

impl fmt::Display for MdbGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MdbGroup::Ip(ip) => write!(f, "{ip}"),
            MdbGroup::Mac(m) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
        }
    }
}

/// A parsed MDB entry from a `get_mdb` dump.
#[derive(Debug, Clone)]
pub struct MdbEntry {
    /// Bridge interface index this entry belongs to.
    pub bridge_ifindex: u32,
    /// Port interface index the group is programmed on.
    pub port_ifindex: u32,
    /// Multicast group address.
    pub group: MdbGroup,
    /// VLAN ID (0 = no VLAN).
    pub vid: u16,
    /// `true` if the entry is static (permanent).
    pub permanent: bool,
    /// Raw entry flags (`MDB_FLAGS_*`).
    pub flags: u8,
}

impl MdbEntry {
    /// `true` if the entry is offloaded to hardware.
    pub fn is_offloaded(&self) -> bool {
        self.flags & MDB_FLAGS_OFFLOAD != 0
    }
    /// `true` if fast-leave is set.
    pub fn is_fast_leave(&self) -> bool {
        self.flags & MDB_FLAGS_FAST_LEAVE != 0
    }
    /// `true` if the (*,G) exclude flag is set.
    pub fn is_star_excl(&self) -> bool {
        self.flags & MDB_FLAGS_STAR_EXCL != 0
    }
    /// `true` if the source is blocked.
    pub fn is_blocked(&self) -> bool {
        self.flags & MDB_FLAGS_BLOCKED != 0
    }
}

/// Builder for an MDB add/delete request.
///
/// The `bridge` is the bridge device, `port` is the member port the
/// group is (de)programmed on.
pub struct MdbEntryBuilder {
    bridge: InterfaceRef,
    port: InterfaceRef,
    group: MdbGroup,
    vid: u16,
    permanent: bool,
}

impl MdbEntryBuilder {
    /// Create a new builder for `group` on `port` of `bridge`.
    pub fn new(
        bridge: impl Into<InterfaceRef>,
        port: impl Into<InterfaceRef>,
        group: impl Into<MdbGroup>,
    ) -> Self {
        Self {
            bridge: bridge.into(),
            port: port.into(),
            group: group.into(),
            vid: 0,
            permanent: false,
        }
    }

    /// Set the VLAN ID (0 = no VLAN, the default).
    pub fn vid(mut self, vid: u16) -> Self {
        self.vid = vid;
        self
    }

    /// Mark the entry permanent (static). Defaults to temporary.
    pub fn permanent(mut self) -> Self {
        self.permanent = true;
        self
    }

    /// Mark the entry temporary (the default).
    pub fn temporary(mut self) -> Self {
        self.permanent = false;
        self
    }

    /// Encode the `br_mdb_entry` for the given resolved port index.
    fn to_entry(&self, port_ifindex: u32) -> BrMdbEntry {
        let mut entry = BrMdbEntry {
            ifindex: port_ifindex,
            state: if self.permanent {
                MDB_PERMANENT
            } else {
                MDB_TEMPORARY
            },
            vid: self.vid,
            ..Default::default()
        };
        match self.group {
            MdbGroup::Ip(IpAddr::V4(ip)) => {
                entry.addr[0..4].copy_from_slice(&ip.octets());
                entry.proto = eth_p::ETH_P_IP.to_be();
            }
            MdbGroup::Ip(IpAddr::V6(ip)) => {
                entry.addr.copy_from_slice(&ip.octets());
                entry.proto = eth_p::ETH_P_IPV6.to_be();
            }
            MdbGroup::Mac(mac) => {
                entry.addr[0..6].copy_from_slice(&mac);
                entry.proto = 0;
            }
        }
        entry
    }
}

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// List all MDB entries for a bridge.
    ///
    /// Accepts an interface name or index. For namespace-aware code
    /// prefer [`get_mdb_by_index`](Connection::get_mdb_by_index).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_mdb"))]
    pub async fn get_mdb(&self, bridge: impl Into<InterfaceRef>) -> Result<Vec<MdbEntry>> {
        let bridge_idx = self.resolve_interface(&bridge.into()).await?;
        self.get_mdb_by_index(bridge_idx).await
    }

    /// List all MDB entries for a bridge by interface index.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_mdb_by_index"))]
    pub async fn get_mdb_by_index(&self, bridge_idx: u32) -> Result<Vec<MdbEntry>> {
        let bpm = BrPortMsg::new().with_family(AF_BRIDGE);
        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETMDB, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&bpm);

        let responses = self.send_dump(builder).await?;

        let mut entries = Vec::new();
        for response in responses {
            if response.len() < NLMSG_HDRLEN + BrPortMsg::SIZE {
                continue;
            }
            let payload = &response[NLMSG_HDRLEN..];
            // Accept-larger: read the fixed prefix, ignore trailing.
            let Ok((bpm, _)) = BrPortMsg::read_from_prefix(payload) else {
                continue;
            };
            let attrs = &payload[BrPortMsg::SIZE..];
            parse_mdb_attrs(bpm.ifindex, attrs, &mut entries);
        }

        Ok(entries
            .into_iter()
            .filter(|e| e.bridge_ifindex == bridge_idx)
            .collect())
    }

    /// Add (statically program) an MDB group on a bridge port.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_mdb"))]
    pub async fn add_mdb(&self, entry: MdbEntryBuilder) -> Result<()> {
        self.modify_mdb(entry, NlMsgType::RTM_NEWMDB, NLM_F_CREATE | NLM_F_EXCL)
            .await
            .map_err(|e| e.with_context("add_mdb"))
    }

    /// Delete an MDB group from a bridge port.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_mdb"))]
    pub async fn del_mdb(&self, entry: MdbEntryBuilder) -> Result<()> {
        self.modify_mdb(entry, NlMsgType::RTM_DELMDB, 0)
            .await
            .map_err(|e| e.with_context("del_mdb"))
    }

    async fn modify_mdb(
        &self,
        entry: MdbEntryBuilder,
        cmd: u16,
        extra_flags: u16,
    ) -> Result<()> {
        let bridge_idx = self.resolve_interface(&entry.bridge).await?;
        let port_idx = self.resolve_interface(&entry.port).await?;

        let bpm = BrPortMsg::new()
            .with_family(AF_BRIDGE)
            .with_ifindex(bridge_idx);
        let mdb_entry = entry.to_entry(port_idx);

        let mut builder =
            MessageBuilder::new(cmd, NLM_F_REQUEST | NLM_F_ACK | extra_flags);
        builder.append(&bpm);
        builder.append_attr(mdba_set::MDBA_SET_ENTRY, mdb_entry.as_bytes());

        self.send_ack(builder).await
    }
}

/// Walk a response's attributes (`MDBA_MDB` → `MDBA_MDB_ENTRY` →
/// `MDBA_MDB_ENTRY_INFO`) and append each parsed entry.
fn parse_mdb_attrs(bridge_ifindex: u32, attrs: &[u8], out: &mut Vec<MdbEntry>) {
    for (kind, payload) in AttrIter::new(attrs) {
        if kind != mdba::MDBA_MDB {
            continue;
        }
        // MDBA_MDB → list of MDBA_MDB_ENTRY (one per group).
        for (kind, group_payload) in AttrIter::new(payload) {
            if kind != mdba_mdb::MDBA_MDB_ENTRY {
                continue;
            }
            // MDBA_MDB_ENTRY → list of MDBA_MDB_ENTRY_INFO (one per port).
            for (kind, info) in AttrIter::new(group_payload) {
                if kind != mdba_mdb_entry::MDBA_MDB_ENTRY_INFO {
                    continue;
                }
                if let Some(e) = parse_mdb_entry_info(bridge_ifindex, info) {
                    out.push(e);
                }
            }
        }
    }
}

/// Parse the post-`nlmsghdr` payload of an `RTM_NEWMDB` / `RTM_DELMDB`
/// notification (`struct br_port_msg` + attributes) into the first
/// contained [`MdbEntry`]. Notifications carry exactly one entry
/// (`br_mdb_notify`); a malformed or empty payload yields `None`.
pub(crate) fn parse_mdb_event_payload(payload: &[u8]) -> Option<MdbEntry> {
    let (bpm, _) = BrPortMsg::read_from_prefix(payload).ok()?;
    let attrs = payload.get(BrPortMsg::SIZE..)?;
    let mut entries = Vec::with_capacity(1);
    parse_mdb_attrs(bpm.ifindex, attrs, &mut entries);
    entries.into_iter().next()
}

/// Decode a single `br_mdb_entry` payload into an [`MdbEntry`].
fn parse_mdb_entry_info(bridge_ifindex: u32, info: &[u8]) -> Option<MdbEntry> {
    // Accept-larger-than-expected: the kernel may grow br_mdb_entry.
    let (entry, _) = BrMdbEntry::read_from_prefix(info).ok()?;
    let proto = u16::from_be(entry.proto);
    let group = match proto {
        eth_p::ETH_P_IP => {
            let octets: [u8; 4] = entry.addr[0..4].try_into().ok()?;
            MdbGroup::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        eth_p::ETH_P_IPV6 => MdbGroup::Ip(IpAddr::V6(Ipv6Addr::from(entry.addr))),
        _ => {
            let mac: [u8; 6] = entry.addr[0..6].try_into().ok()?;
            MdbGroup::Mac(mac)
        }
    };
    Some(MdbEntry {
        bridge_ifindex,
        port_ifindex: entry.ifindex,
        group,
        vid: entry.vid,
        permanent: entry.state == MDB_PERMANENT,
        flags: entry.flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_display() {
        assert_eq!(
            MdbGroup::Ip(IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3))).to_string(),
            "239.1.2.3"
        );
        assert_eq!(
            MdbGroup::Mac([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]).to_string(),
            "01:00:5e:00:00:01"
        );
    }

    #[test]
    fn group_from_str() {
        assert_eq!(
            "239.1.2.3".parse::<MdbGroup>().unwrap(),
            MdbGroup::Ip(IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3)))
        );
        assert!(matches!(
            "ff02::1".parse::<MdbGroup>().unwrap(),
            MdbGroup::Ip(IpAddr::V6(_))
        ));
        assert_eq!(
            "01:00:5e:00:00:01".parse::<MdbGroup>().unwrap(),
            MdbGroup::Mac([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01])
        );
        assert_eq!(
            "01-00-5e-00-00-02".parse::<MdbGroup>().unwrap(),
            MdbGroup::Mac([0x01, 0x00, 0x5e, 0x00, 0x00, 0x02])
        );
        assert!("not-a-group".parse::<MdbGroup>().is_err());
        assert!("01:00:5e:zz:00:01".parse::<MdbGroup>().is_err());
    }

    #[test]
    fn builder_encodes_ipv4_group() {
        let b = MdbEntryBuilder::new(
            InterfaceRef::Index(10),
            InterfaceRef::Index(20),
            Ipv4Addr::new(239, 1, 1, 1),
        )
        .vid(100)
        .permanent();
        let e = b.to_entry(20);
        assert_eq!(e.ifindex, 20);
        assert_eq!(e.vid, 100);
        assert_eq!(e.state, MDB_PERMANENT);
        assert_eq!(&e.addr[0..4], &[239, 1, 1, 1]);
        assert_eq!(u16::from_be(e.proto), eth_p::ETH_P_IP);
    }

    #[test]
    fn builder_encodes_mac_group() {
        let mac = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x05];
        let e = MdbEntryBuilder::new(InterfaceRef::Index(1), InterfaceRef::Index(2), mac).to_entry(2);
        assert_eq!(&e.addr[0..6], &mac);
        assert_eq!(e.proto, 0);
        assert_eq!(e.state, MDB_TEMPORARY);
    }

    /// Round-trip: encode an entry, wrap it in the MDBA nest hierarchy,
    /// and confirm the parser recovers it.
    #[test]
    fn parse_roundtrip_through_nest() {
        let built = MdbEntryBuilder::new(
            InterfaceRef::Index(5),
            InterfaceRef::Index(7),
            Ipv4Addr::new(239, 9, 9, 9),
        )
        .vid(42)
        .permanent()
        .to_entry(7);

        // Build MDBA_MDB { MDBA_MDB_ENTRY { MDBA_MDB_ENTRY_INFO } }.
        let mut b = MessageBuilder::new(0, 0);
        let mdb = b.nest_start(mdba::MDBA_MDB);
        let grp = b.nest_start(mdba_mdb::MDBA_MDB_ENTRY);
        b.append_attr(mdba_mdb_entry::MDBA_MDB_ENTRY_INFO, built.as_bytes());
        b.nest_end(grp);
        b.nest_end(mdb);

        // Strip the 16-byte nlmsghdr the builder prepends.
        let attrs = &b.as_bytes()[16..];
        let mut out = Vec::new();
        parse_mdb_attrs(5, attrs, &mut out);
        assert_eq!(out.len(), 1);
        let e = &out[0];
        assert_eq!(e.bridge_ifindex, 5);
        assert_eq!(e.port_ifindex, 7);
        assert_eq!(e.vid, 42);
        assert!(e.permanent);
        assert_eq!(e.group, MdbGroup::Ip(IpAddr::V4(Ipv4Addr::new(239, 9, 9, 9))));
    }

    /// #165 — an RTM_NEWMDB/DELMDB notification payload
    /// (br_port_msg + MDBA nest) decodes into its single entry.
    #[test]
    fn parse_event_payload_recovers_entry() {
        let built = MdbEntryBuilder::new(
            InterfaceRef::Index(3),
            InterfaceRef::Index(9),
            Ipv4Addr::new(239, 1, 2, 3),
        )
        .vid(10)
        .to_entry(9);

        let mut b = MessageBuilder::new(0, 0);
        let bpm = BrPortMsg::new().with_family(AF_BRIDGE).with_ifindex(3);
        b.append(&bpm);
        let mdb = b.nest_start(mdba::MDBA_MDB);
        let grp = b.nest_start(mdba_mdb::MDBA_MDB_ENTRY);
        b.append_attr(mdba_mdb_entry::MDBA_MDB_ENTRY_INFO, built.as_bytes());
        b.nest_end(grp);
        b.nest_end(mdb);

        let payload = &b.as_bytes()[16..];
        let e = parse_mdb_event_payload(payload).expect("event payload should parse");
        assert_eq!(e.bridge_ifindex, 3);
        assert_eq!(e.port_ifindex, 9);
        assert_eq!(e.vid, 10);
        assert_eq!(e.group, MdbGroup::Ip(IpAddr::V4(Ipv4Addr::new(239, 1, 2, 3))));

        // Malformed / truncated payloads yield None, never panic.
        assert!(parse_mdb_event_payload(&[]).is_none());
        assert!(parse_mdb_event_payload(&payload[..4]).is_none());
    }
}
