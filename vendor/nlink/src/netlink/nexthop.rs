//! Nexthop objects and groups (Linux 5.3+).
//!
//! This module provides support for Linux nexthop objects and nexthop groups,
//! which offer a modern, efficient way to configure ECMP and weighted multipath
//! routing.
//!
//! # Benefits over legacy RTA_MULTIPATH
//!
//! - **Efficiency**: Nexthops are shared objects, reducing memory
//! - **Atomic updates**: Change nexthop once, all routes using it are updated
//! - **Resilient hashing**: Optional resilient groups maintain flow affinity
//! - **Better ECMP**: More control over load balancing behavior
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::nexthop::{NexthopBuilder, NexthopGroupBuilder};
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Create individual nexthops
//! conn.add_nexthop(
//!     NexthopBuilder::new(1)
//!         .gateway("192.168.1.1".parse()?)
//!         .dev("eth0")
//! ).await?;
//!
//! conn.add_nexthop(
//!     NexthopBuilder::new(2)
//!         .gateway("192.168.2.1".parse()?)
//!         .dev("eth1")
//! ).await?;
//!
//! // Create ECMP group
//! conn.add_nexthop_group(
//!     NexthopGroupBuilder::new(100)
//!         .member(1, 1)  // nexthop 1, weight 1
//!         .member(2, 1)  // nexthop 2, weight 1
//! ).await?;
//!
//! // List nexthops
//! let nexthops = conn.get_nexthops().await?;
//! for nh in &nexthops {
//!     println!("NH {}: {:?} via ifindex {:?}", nh.id(), nh.gateway(), nh.ifindex());
//! }
//!
//! // Cleanup
//! conn.del_nexthop_group(100).await?;
//! conn.del_nexthop(1).await?;
//! conn.del_nexthop(2).await?;
//! # Ok(())
//! # }
//! ```

use std::net::IpAddr;

use super::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    interface_ref::InterfaceRef,
    message::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN, NlMsgType},
    protocol::Route,
    types::nexthop::{NexthopGrp, NhMsg, nha, nha_res_group, nhf, nhg_type},
};

/// NLM_F_CREATE flag
const NLM_F_CREATE: u16 = 0x400;
/// NLM_F_REPLACE flag
const NLM_F_REPLACE: u16 = 0x100;

/// Nexthop group types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NexthopGroupType {
    /// Multipath group with hash-threshold algorithm (default).
    #[default]
    Multipath,
    /// Resilient group that maintains flow affinity during changes.
    Resilient,
}

impl From<u16> for NexthopGroupType {
    fn from(val: u16) -> Self {
        match val {
            nhg_type::RES => Self::Resilient,
            _ => Self::Multipath,
        }
    }
}

impl From<NexthopGroupType> for u16 {
    fn from(val: NexthopGroupType) -> Self {
        match val {
            NexthopGroupType::Multipath => nhg_type::MPATH,
            NexthopGroupType::Resilient => nhg_type::RES,
        }
    }
}

/// Resilient group parameters.
#[derive(Debug, Clone, Default)]
pub struct ResilientParams {
    /// Number of hash buckets.
    pub buckets: u16,
    /// Idle timer in seconds.
    pub idle_timer: u32,
    /// Unbalanced timer in seconds.
    pub unbalanced_timer: u32,
}

/// A nexthop group member entry.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NexthopGroupMember {
    /// Nexthop ID.
    pub(crate) id: u32,
    /// The weight, as `ip nexthop` shows it: 1 and up. The wire carries it
    /// minus one (#672).
    pub(crate) weight: u16,
}

impl NexthopGroupMember {
    /// Construct a new group-member descriptor. Used by builders
    /// (the parser path goes through `Nexthop::parse`).
    pub fn new(id: u32, weight: u16) -> Self {
        Self { id, weight }
    }

    /// Nexthop ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// The weight, as `ip nexthop` shows it: 1 and up. Until 0.32 this
    /// was the wire value, one less (#672).
    pub fn weight(&self) -> u16 {
        self.weight
    }
}

/// Nexthop information.
///
/// Represents a single nexthop object which can be used by routes
/// either directly or as part of a nexthop group.
///
/// Fields are `pub(crate)`; consumers read via the per-field
/// accessor methods. The struct is `#[non_exhaustive]` so the
/// kernel can grow new nexthop attribute fields without it being
/// a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Nexthop {
    /// Nexthop ID.
    pub(crate) id: u32,
    /// Gateway address.
    pub(crate) gateway: Option<IpAddr>,
    /// Output interface index.
    pub(crate) ifindex: Option<u32>,
    /// Address family (AF_INET or AF_INET6).
    pub(crate) family: u8,
    /// Nexthop flags (see nhf module).
    pub(crate) flags: u32,
    /// Protocol that installed this nexthop.
    pub(crate) protocol: u8,
    /// Scope.
    pub(crate) scope: u8,
    /// Is this a blackhole nexthop?
    pub(crate) blackhole: bool,
    /// Is this an FDB nexthop?
    pub(crate) fdb: bool,
    /// Group members (only set if this is a group).
    pub(crate) group: Option<Vec<NexthopGroupMember>>,
    /// Group type (only set if this is a group).
    pub(crate) group_type: Option<NexthopGroupType>,
    /// Resilient group parameters (only set for resilient groups).
    pub(crate) resilient: Option<ResilientParams>,
    /// The encapsulation's type (`NHA_ENCAP_TYPE`), when it has one.
    pub(crate) encap_type: Option<u16>,
}

impl Nexthop {
    /// Nexthop ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Gateway address, if set.
    pub fn gateway(&self) -> Option<IpAddr> {
        self.gateway
    }

    /// Output interface index, if set.
    pub fn ifindex(&self) -> Option<u32> {
        self.ifindex
    }

    /// Address family (`AF_INET` / `AF_INET6`).
    pub fn family(&self) -> u8 {
        self.family
    }

    /// Nexthop flags (see `nhf` module).
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Protocol that installed the nexthop (`RTPROT_*`).
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Route scope byte.
    pub fn scope(&self) -> u8 {
        self.scope
    }

    /// `true` if the nexthop is a blackhole.
    pub fn is_blackhole(&self) -> bool {
        self.blackhole
    }

    /// `true` if the nexthop is an FDB nexthop (used by VXLAN).
    pub fn is_fdb(&self) -> bool {
        self.fdb
    }

    /// Group members, if this nexthop is a group.
    pub fn group(&self) -> Option<&[NexthopGroupMember]> {
        self.group.as_deref()
    }

    /// Group type, if this nexthop is a group.
    pub fn group_type(&self) -> Option<NexthopGroupType> {
        self.group_type
    }

    /// Resilient-group parameters, if this nexthop is a resilient
    /// group.
    pub fn resilient(&self) -> Option<&ResilientParams> {
        self.resilient.as_ref()
    }

    /// Parse a nexthop from a netlink message.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let nhmsg = NhMsg::from_bytes(data)?;
        let attrs_data = &data[NhMsg::SIZE..];

        let mut id = 0u32;
        let mut gateway: Option<IpAddr> = None;
        let mut ifindex: Option<u32> = None;
        let mut blackhole = false;
        let mut fdb = false;
        let mut group: Option<Vec<NexthopGroupMember>> = None;
        let mut group_type: Option<NexthopGroupType> = None;
        let mut resilient: Option<ResilientParams> = None;
        let mut encap_type: Option<u16> = None;

        for (attr_type, payload) in AttrIter::new(attrs_data) {
            match attr_type {
                nha::ID if payload.len() >= 4 => {
                    id = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
                }
                nha::GATEWAY => {
                    gateway = match payload.len() {
                        4 => Some(IpAddr::from(<[u8; 4]>::try_from(payload).unwrap())),
                        16 => Some(IpAddr::from(<[u8; 16]>::try_from(payload).unwrap())),
                        _ => None,
                    };
                }
                nha::OIF if payload.len() >= 4 => {
                    ifindex = Some(u32::from_ne_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]));
                }
                nha::BLACKHOLE => {
                    blackhole = true;
                }
                nha::FDB => {
                    fdb = true;
                }
                nha::GROUP => {
                    let mut members = Vec::new();
                    let mut offset = 0;
                    while offset + NexthopGrp::SIZE <= payload.len() {
                        if let Some(grp) = NexthopGrp::from_bytes(&payload[offset..]) {
                            members.push(NexthopGroupMember {
                                id: grp.id,
                                weight: grp.weight(),
                            });
                        }
                        offset += NexthopGrp::SIZE;
                    }
                    if !members.is_empty() {
                        group = Some(members);
                    }
                }
                nha::ENCAP_TYPE if payload.len() >= 2 => {
                    encap_type = Some(u16::from_ne_bytes([payload[0], payload[1]]));
                }
                nha::GROUP_TYPE if payload.len() >= 2 => {
                    let gt = u16::from_ne_bytes([payload[0], payload[1]]);
                    group_type = Some(NexthopGroupType::from(gt));
                }
                nha::RES_GROUP => {
                    let mut params = ResilientParams::default();
                    for (res_type, res_payload) in AttrIter::new(payload) {
                        match res_type {
                            nha_res_group::BUCKETS if res_payload.len() >= 2 => {
                                params.buckets =
                                    u16::from_ne_bytes([res_payload[0], res_payload[1]]);
                            }
                            nha_res_group::IDLE_TIMER if res_payload.len() >= 4 => {
                                params.idle_timer = u32::from_ne_bytes([
                                    res_payload[0],
                                    res_payload[1],
                                    res_payload[2],
                                    res_payload[3],
                                ]);
                            }
                            nha_res_group::UNBALANCED_TIMER if res_payload.len() >= 4 => {
                                params.unbalanced_timer = u32::from_ne_bytes([
                                    res_payload[0],
                                    res_payload[1],
                                    res_payload[2],
                                    res_payload[3],
                                ]);
                            }
                            _ => {}
                        }
                    }
                    resilient = Some(params);
                }
                _ => {}
            }
        }

        Ok(Self {
            id,
            gateway,
            ifindex,
            family: nhmsg.nh_family,
            flags: nhmsg.nh_flags,
            protocol: nhmsg.nh_protocol,
            scope: nhmsg.nh_scope,
            blackhole,
            fdb,
            group,
            group_type,
            resilient,
            encap_type,
        })
    }

    /// The type of its encapsulation (`NHA_ENCAP_TYPE`, an
    /// `LWTUNNEL_ENCAP_*`: 1 is MPLS), when it has one (#783).
    pub fn encap_type(&self) -> Option<u16> {
        self.encap_type
    }

    /// Check if this nexthop is a group.
    pub fn is_group(&self) -> bool {
        self.group.is_some()
    }

    /// Check if the nexthop has the on-link flag.
    pub fn is_onlink(&self) -> bool {
        self.flags & nhf::ONLINK != 0
    }

    /// Check if the nexthop is dead.
    pub fn is_dead(&self) -> bool {
        self.flags & nhf::DEAD != 0
    }

    /// Check if the link is down.
    pub fn is_linkdown(&self) -> bool {
        self.flags & nhf::LINKDOWN != 0
    }
}

/// Builder for individual nexthop objects.
///
/// # Example
///
/// ```no_run
/// # use std::net::IpAddr;
/// use nlink::netlink::nexthop::NexthopBuilder;
/// use std::net::Ipv4Addr;
///
/// // Simple gateway nexthop
/// let nh = NexthopBuilder::new(1)
///     .gateway(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
///     .dev("eth0");
///
/// // Blackhole nexthop
/// let blackhole = NexthopBuilder::new(2)
///     .blackhole();
///
/// // On-link nexthop (no ARP resolution needed)
/// let onlink = NexthopBuilder::new(3)
///     .gateway(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
///     .dev("eth0")
///     .onlink();
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct NexthopBuilder {
    id: u32,
    gateway: Option<IpAddr>,
    dev: Option<InterfaceRef>,
    blackhole: bool,
    onlink: bool,
    fdb: bool,
    ipv6: bool,
    protocol: Option<u8>,
}

impl NexthopBuilder {
    /// Create a new nexthop builder with the given ID.
    ///
    /// The ID must be unique and is used to reference this nexthop
    /// from routes and nexthop groups.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            gateway: None,
            dev: None,
            blackhole: false,
            onlink: false,
            fdb: false,
            ipv6: false,
            protocol: None,
        }
    }

    /// An IPv6 nexthop, for one with no gateway to say so: a blackhole, or
    /// a device alone. Without a gateway it is IPv4 otherwise, as with `ip
    /// nexthop` (#673).
    pub fn ipv6(mut self) -> Self {
        self.ipv6 = true;
        self
    }

    /// Set the gateway (next-hop) address.
    pub fn gateway(mut self, gw: IpAddr) -> Self {
        self.gateway = Some(gw);
        self
    }

    /// Set the output device by name.
    ///
    /// The device name will be resolved to an interface index via netlink.
    pub fn dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(InterfaceRef::Name(dev.into()));
        self
    }

    /// Set the output interface by index.
    ///
    /// Use this instead of `dev()` when you already have the interface index.
    pub fn ifindex(mut self, ifindex: u32) -> Self {
        self.dev = Some(InterfaceRef::Index(ifindex));
        self
    }

    /// Get the device reference.
    pub fn device_ref(&self) -> Option<&InterfaceRef> {
        self.dev.as_ref()
    }

    /// Make this a blackhole nexthop.
    ///
    /// Packets routed through a blackhole nexthop are silently discarded.
    pub fn blackhole(mut self) -> Self {
        self.blackhole = true;
        self
    }

    /// Set the on-link flag.
    ///
    /// Indicates that the gateway is directly reachable without ARP resolution.
    pub fn onlink(mut self) -> Self {
        self.onlink = true;
        self
    }

    /// Mark as an FDB nexthop.
    ///
    /// FDB nexthops can be used with bridge FDB entries for EVPN/VXLAN.
    pub fn fdb(mut self) -> Self {
        self.fdb = true;
        self
    }

    /// Set the routing protocol.
    ///
    /// Common values: 4 (RTPROT_STATIC), 2 (RTPROT_KERNEL).
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Write the netlink message with resolved interface index.
    pub(crate) fn write_to(&self, builder: &mut MessageBuilder, ifindex: Option<u32>) {
        // Determine address family
        // The kernel takes `AF_UNSPEC` only for a group: a blackhole or a
        // device alone sent it failed "Invalid address family" (#673).
        let family = match &self.gateway {
            Some(IpAddr::V4(_)) => libc::AF_INET as u8,
            Some(IpAddr::V6(_)) => libc::AF_INET6 as u8,
            None if self.ipv6 => libc::AF_INET6 as u8,
            None => libc::AF_INET as u8,
        };

        let mut nh_flags = 0u32;
        if self.onlink {
            nh_flags |= nhf::ONLINK;
        }

        let nhmsg = NhMsg::new()
            .with_family(family)
            .with_protocol(self.protocol.unwrap_or(4)) // RTPROT_STATIC
            .with_flags(nh_flags);

        builder.append(&nhmsg);

        // Add nexthop ID
        builder.append_attr_u32(nha::ID, self.id);

        // Add gateway
        if let Some(ref gw) = self.gateway {
            match gw {
                IpAddr::V4(v4) => {
                    builder.append_attr(nha::GATEWAY, &v4.octets());
                }
                IpAddr::V6(v6) => {
                    builder.append_attr(nha::GATEWAY, &v6.octets());
                }
            }
        }

        // Add output interface
        if let Some(idx) = ifindex {
            builder.append_attr_u32(nha::OIF, idx);
        }

        // Add blackhole flag
        if self.blackhole {
            builder.append_attr(nha::BLACKHOLE, &[]);
        }

        // Add FDB flag
        if self.fdb {
            builder.append_attr(nha::FDB, &[]);
        }
    }
}

/// `clock_t` ticks per second on Linux (`USER_HZ`).
///
/// Netlink attributes documented as `clock_t` in the UAPI headers are in these
/// units. It is 100 on every Linux ABI nlink targets.
const USER_HZ: u32 = 100;

/// Builder for nexthop groups.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::nexthop::NexthopGroupBuilder;
///
/// // Simple ECMP group (equal weights)
/// let ecmp = NexthopGroupBuilder::new(100)
///     .member(1, 1)
///     .member(2, 1);
///
/// // Weighted multipath (2:1 ratio)
/// let weighted = NexthopGroupBuilder::new(101)
///     .member(1, 2)  // Gets ~67% of traffic
///     .member(2, 1); // Gets ~33% of traffic
///
/// // Resilient group (maintains flow affinity)
/// let resilient = NexthopGroupBuilder::new(102)
///     .resilient()
///     .member(1, 1)
///     .member(2, 1)
///     .buckets(128)
///     .idle_timer(120);
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct NexthopGroupBuilder {
    id: u32,
    group_type: NexthopGroupType,
    members: Vec<(u32, u16)>, // (nexthop_id, weight)
    buckets: Option<u16>,
    idle_timer: Option<u32>,
    unbalanced_timer: Option<u32>,
    protocol: Option<u8>,
}

impl NexthopGroupBuilder {
    /// Create a new nexthop group builder with the given ID.
    ///
    /// By default, creates a multipath (hash-threshold) group.
    pub fn new(id: u32) -> Self {
        Self {
            id,
            group_type: NexthopGroupType::Multipath,
            members: Vec::new(),
            buckets: None,
            idle_timer: None,
            unbalanced_timer: None,
            protocol: None,
        }
    }

    /// Set the group type to multipath (default).
    pub fn multipath(mut self) -> Self {
        self.group_type = NexthopGroupType::Multipath;
        self
    }

    /// Set the group type to resilient.
    ///
    /// Resilient groups maintain flow affinity when members are added/removed,
    /// only rehashing flows that were using the changed member.
    pub fn resilient(mut self) -> Self {
        self.group_type = NexthopGroupType::Resilient;
        self
    }

    /// Add a member to the group.
    ///
    /// - `nexthop_id`: ID of an existing nexthop object
    /// - `weight`: its share, as `ip nexthop … group <id>,<weight>` takes
    ///   it: 1 and up (0 is 1); more than 256 needs kernel 6.12. It used to
    ///   go on the wire as given, which the kernel weighs one more (#672).
    pub fn member(mut self, nexthop_id: u32, weight: u16) -> Self {
        self.members.push((nexthop_id, weight));
        self
    }

    /// Set the number of hash buckets for resilient groups.
    ///
    /// More buckets = finer-grained load distribution but more memory.
    /// Typical values: 32, 64, 128, 256.
    pub fn buckets(mut self, buckets: u16) -> Self {
        self.buckets = Some(buckets);
        self
    }

    /// Set the idle timer in seconds for resilient groups.
    ///
    /// After this time of inactivity, a bucket can be reassigned.
    ///
    /// `NHA_RES_GROUP_IDLE_TIMER` is documented in `nexthop.h` as
    /// `clock_t as u32` — USER_HZ ticks, not seconds — so the value is
    /// converted here. Passing seconds straight through made a declared
    /// 60-second timer arrive as 0.6 s (#265). Same conversion, and same
    /// reason, as `BridgeLink::ageing_time`.
    pub fn idle_timer(mut self, seconds: u32) -> Self {
        self.idle_timer = Some(seconds.saturating_mul(USER_HZ));
        self
    }

    /// Set the unbalanced timer in seconds for resilient groups.
    ///
    /// Maximum time the group can remain unbalanced before forced rebalancing.
    pub fn unbalanced_timer(mut self, seconds: u32) -> Self {
        self.unbalanced_timer = Some(seconds.saturating_mul(USER_HZ));
        self
    }

    /// Set the routing protocol.
    pub fn protocol(mut self, protocol: u8) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Build the netlink message.
    fn build(&self, msg_type: u16, flags: u16) -> Result<MessageBuilder> {
        if self.members.is_empty() {
            return Err(Error::invalid_message(
                "nexthop group must have at least one member",
            ));
        }

        let nhmsg = NhMsg::new()
            .with_family(libc::AF_UNSPEC as u8)
            .with_protocol(self.protocol.unwrap_or(4)); // RTPROT_STATIC

        let mut builder = MessageBuilder::new(msg_type, flags);
        builder.append(&nhmsg);

        // Add group ID
        builder.append_attr_u32(nha::ID, self.id);

        // Add group type
        let gt: u16 = self.group_type.into();
        builder.append_attr(nha::GROUP_TYPE, &gt.to_ne_bytes());

        // Add group members
        let mut grp_data = Vec::with_capacity(self.members.len() * NexthopGrp::SIZE);
        for (nh_id, weight) in &self.members {
            let grp = NexthopGrp::with_weight(*nh_id, *weight);
            grp_data.extend_from_slice(grp.as_bytes());
        }
        builder.append_attr(nha::GROUP, &grp_data);

        // Add resilient group parameters if applicable
        if self.group_type == NexthopGroupType::Resilient
            && (self.buckets.is_some()
                || self.idle_timer.is_some()
                || self.unbalanced_timer.is_some())
        {
            let res_token = builder.nest_start(nha::RES_GROUP);
            if let Some(buckets) = self.buckets {
                builder.append_attr(nha_res_group::BUCKETS, &buckets.to_ne_bytes());
            }
            if let Some(idle) = self.idle_timer {
                builder.append_attr(nha_res_group::IDLE_TIMER, &idle.to_ne_bytes());
            }
            if let Some(unbal) = self.unbalanced_timer {
                builder.append_attr(nha_res_group::UNBALANCED_TIMER, &unbal.to_ne_bytes());
            }
            builder.nest_end(res_token);
        }

        Ok(builder)
    }
}

// ============================================================================
// Connection methods
// ============================================================================

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Resolve NexthopBuilder interface reference.
    async fn resolve_nexthop_interface(&self, builder: &NexthopBuilder) -> Result<Option<u32>> {
        match builder.device_ref() {
            Some(iface) => Ok(Some(self.resolve_interface(iface).await?)),
            None => Ok(None),
        }
    }
    /// Get all nexthops (including groups).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// let nexthops = conn.get_nexthops().await?;
    /// for nh in &nexthops {
    ///     if nh.is_group() {
    ///         println!("Group {}: {:?}", nh.id(), nh.group());
    ///     } else {
    ///         println!("NH {}: {:?} via {:?}", nh.id(), nh.gateway(), nh.ifindex());
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_nexthops"))]
    pub async fn get_nexthops(&self) -> Result<Vec<Nexthop>> {
        let nhmsg = NhMsg::new().with_family(libc::AF_UNSPEC as u8);

        let mut builder =
            MessageBuilder::new(NlMsgType::RTM_GETNEXTHOP, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&nhmsg);

        let responses = self.send_dump(builder).await?;

        let mut nexthops = Vec::new();
        for data in responses {
            // Skip the netlink header (16 bytes)
            if data.len() > NLMSG_HDRLEN
                && let Ok(nh) = Nexthop::parse(&data[NLMSG_HDRLEN..])
            {
                nexthops.push(nh);
            }
        }

        Ok(nexthops)
    }

    /// Get a specific nexthop by ID.
    ///
    /// Returns `None` if the nexthop doesn't exist.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_nexthop"))]
    pub async fn get_nexthop(&self, id: u32) -> Result<Option<Nexthop>> {
        let nhmsg = NhMsg::new().with_family(libc::AF_UNSPEC as u8);

        let mut builder = MessageBuilder::new(NlMsgType::RTM_GETNEXTHOP, NLM_F_REQUEST);
        builder.append(&nhmsg);
        builder.append_attr_u32(nha::ID, id);

        match self.send_request(builder).await {
            Ok(data) => {
                if data.len() > NLMSG_HDRLEN {
                    Ok(Some(Nexthop::parse(&data[NLMSG_HDRLEN..])?))
                } else {
                    Ok(None)
                }
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Add a nexthop.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::nexthop::NexthopBuilder;
    ///
    /// conn.add_nexthop(
    ///     NexthopBuilder::new(1)
    ///         .gateway("192.168.1.1".parse()?)
    ///         .dev("eth0")
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_nexthop"))]
    pub async fn add_nexthop(&self, nh_builder: NexthopBuilder) -> Result<()> {
        let ifindex = self.resolve_nexthop_interface(&nh_builder).await?;
        let mut msg = MessageBuilder::new(
            NlMsgType::RTM_NEWNEXTHOP,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        nh_builder.write_to(&mut msg, ifindex);
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("add_nexthop"))
    }

    /// Replace a nexthop (add or update).
    ///
    /// If the nexthop exists, it's updated. If it doesn't exist, it's created.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_nexthop"))]
    pub async fn replace_nexthop(&self, nh_builder: NexthopBuilder) -> Result<()> {
        let ifindex = self.resolve_nexthop_interface(&nh_builder).await?;
        let mut msg = MessageBuilder::new(
            NlMsgType::RTM_NEWNEXTHOP,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        );
        nh_builder.write_to(&mut msg, ifindex);
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("replace_nexthop"))
    }

    /// Delete a nexthop by ID.
    ///
    /// Note: Deleting a nexthop that is in use by routes or groups will fail.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_nexthop"))]
    pub async fn del_nexthop(&self, id: u32) -> Result<()> {
        let nhmsg = NhMsg::new().with_family(libc::AF_UNSPEC as u8);

        let mut builder = MessageBuilder::new(NlMsgType::RTM_DELNEXTHOP, NLM_F_REQUEST | NLM_F_ACK);
        builder.append(&nhmsg);
        builder.append_attr_u32(nha::ID, id);

        self.send_ack(builder)
            .await
            .map_err(|e| e.with_context("del_nexthop"))
    }

    /// Delete a nexthop if it exists (#718). `Ok(true)` when it was
    /// deleted, `Ok(false)` when there was no nexthop `id`: the kernel
    /// answers that with `ENOENT`. One still in use is an error, as for
    /// [`del_nexthop`](Self::del_nexthop).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_nexthop_if_exists"))]
    pub async fn del_nexthop_if_exists(&self, id: u32) -> Result<bool> {
        match self.del_nexthop(id).await {
            Ok(()) => Ok(true),
            Err(e) if e.is_not_found() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Add a nexthop group.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::netlink::nexthop::NexthopGroupBuilder;
    ///
    /// // ECMP group with equal weights
    /// conn.add_nexthop_group(
    ///     NexthopGroupBuilder::new(100)
    ///         .member(1, 1)
    ///         .member(2, 1)
    /// ).await?;
    ///
    /// // Weighted multipath (2:1 ratio)
    /// conn.add_nexthop_group(
    ///     NexthopGroupBuilder::new(101)
    ///         .member(1, 2)
    ///         .member(2, 1)
    /// ).await?;
    ///
    /// // Resilient group with custom parameters
    /// conn.add_nexthop_group(
    ///     NexthopGroupBuilder::new(102)
    ///         .resilient()
    ///         .member(1, 1)
    ///         .member(2, 1)
    ///         .buckets(128)
    ///         .idle_timer(120)
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_nexthop_group"))]
    pub async fn add_nexthop_group(&self, builder: NexthopGroupBuilder) -> Result<()> {
        let msg = builder.build(
            NlMsgType::RTM_NEWNEXTHOP,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        )?;
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("add_nexthop_group"))
    }

    /// Replace a nexthop group (add or update).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "replace_nexthop_group"))]
    pub async fn replace_nexthop_group(&self, builder: NexthopGroupBuilder) -> Result<()> {
        let msg = builder.build(
            NlMsgType::RTM_NEWNEXTHOP,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        )?;
        self.send_ack(msg)
            .await
            .map_err(|e| e.with_context("replace_nexthop_group"))
    }

    /// Delete a nexthop group by ID.
    ///
    /// Note: Deleting a group that is in use by routes will fail.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_nexthop_group"))]
    pub async fn del_nexthop_group(&self, id: u32) -> Result<()> {
        // Groups and individual nexthops share the same ID space,
        // so we use the same delete operation
        self.del_nexthop(id).await
    }

    /// Get only nexthop groups (not individual nexthops).
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_nexthop_groups"))]
    pub async fn get_nexthop_groups(&self) -> Result<Vec<Nexthop>> {
        let nhmsg = NhMsg::new().with_family(libc::AF_UNSPEC as u8);

        let mut builder =
            MessageBuilder::new(NlMsgType::RTM_GETNEXTHOP, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append(&nhmsg);
        // Add NHA_GROUPS flag to request only groups
        builder.append_attr(nha::GROUPS, &[]);

        let responses = self.send_dump(builder).await?;

        let mut groups = Vec::new();
        for data in responses {
            // Skip the netlink header (16 bytes)
            if data.len() > NLMSG_HDRLEN
                && let Ok(nh) = Nexthop::parse(&data[NLMSG_HDRLEN..])
                && nh.is_group()
            {
                groups.push(nh);
            }
        }

        Ok(groups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nexthop_builder() {
        let nh = NexthopBuilder::new(42)
            .gateway("192.168.1.1".parse().unwrap())
            .ifindex(5)
            .onlink();

        assert_eq!(nh.id, 42);
        assert!(nh.gateway.is_some());
        assert_eq!(nh.dev, Some(InterfaceRef::Index(5)));
        assert!(nh.onlink);
    }

    #[test]
    fn test_nexthop_builder_blackhole() {
        let nh = NexthopBuilder::new(1).blackhole();

        assert!(nh.blackhole);
        assert!(nh.gateway.is_none());
    }

    #[test]
    fn test_nexthop_group_builder() {
        let grp = NexthopGroupBuilder::new(100)
            .member(1, 1)
            .member(2, 2)
            .resilient()
            .buckets(128)
            .idle_timer(120);

        assert_eq!(grp.id, 100);
        assert_eq!(grp.members.len(), 2);
        assert_eq!(grp.group_type, NexthopGroupType::Resilient);
        assert_eq!(grp.buckets, Some(128));

        // `NHA_RES_GROUP_IDLE_TIMER` is `clock_t as u32` (USER_HZ ticks), so
        // 120 seconds is 12000 on the wire. This assertion used to read
        // `Some(120)`, pinning the unconverted value — which is how the unit
        // bug survived (#265).
        assert_eq!(grp.idle_timer, Some(120 * USER_HZ));
        assert_ne!(
            grp.idle_timer,
            Some(120),
            "regression: seconds passed through as ticks again"
        );
    }

    /// The conversion is the whole point, so pin it independently of any one
    /// caller: a timer set in seconds must arrive as USER_HZ ticks.
    #[test]
    fn resilient_group_timers_are_clock_t_ticks_not_seconds() {
        let grp = NexthopGroupBuilder::new(1)
            .resilient()
            .idle_timer(60)
            .unbalanced_timer(5);

        assert_eq!(grp.idle_timer, Some(6_000));
        assert_eq!(grp.unbalanced_timer, Some(500));
    }

    #[test]
    fn test_group_type_conversion() {
        assert_eq!(u16::from(NexthopGroupType::Multipath), nhg_type::MPATH);
        assert_eq!(u16::from(NexthopGroupType::Resilient), nhg_type::RES);

        assert_eq!(
            NexthopGroupType::from(nhg_type::MPATH),
            NexthopGroupType::Multipath
        );
        assert_eq!(
            NexthopGroupType::from(nhg_type::RES),
            NexthopGroupType::Resilient
        );
    }
}
