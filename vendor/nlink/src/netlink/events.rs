//! Network event types for Route protocol monitoring.
//!
//! This module provides the [`NetworkEvent`] enum representing events
//! received from the kernel via RTNetlink multicast groups.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route, RtnetlinkGroup, NetworkEvent};
//! use tokio_stream::StreamExt;
//!
//! let conn = Connection::<Route>::new()?;
//! conn.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Tc])?;
//!
//! let mut events = conn.events().await;
//! while let Some(event) = events.next().await {
//!     match event? {
//!         NetworkEvent::NewLink(link) => {
//!             println!("New link: {}", link.name_or("?"));
//!         }
//!         NetworkEvent::DelLink(link) => {
//!             println!("Deleted link: {}", link.name_or("?"));
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "serde")]
pub mod view;

use super::{
    fdb::FdbEntry,
    mdb::MdbEntry,
    messages::{
        AddressMessage, LinkMessage, NeighborMessage, NsIdMessage, RouteMessage, RuleMessage,
        TcMessage,
    },
    nexthop::Nexthop,
    resync_ext::{GapDelta, ObjectKey},
};

/// Network events that can be received from the kernel.
///
/// These events are generated when network configuration changes occur.
/// Use [`Connection<Route>::subscribe`](super::Connection::subscribe) to select
/// which event types to receive, then use [`Connection::events`](super::Connection::events)
/// to get a stream of events.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NetworkEvent {
    // Link events
    /// A new link was created or an existing link changed.
    NewLink(LinkMessage),
    /// A link was deleted.
    DelLink(LinkMessage),

    // Address events
    /// A new address was added.
    NewAddress(AddressMessage),
    /// An address was removed.
    DelAddress(AddressMessage),

    // Route events
    /// A new route was added.
    NewRoute(RouteMessage),
    /// A route was removed.
    DelRoute(RouteMessage),

    // Neighbor events
    /// A new neighbor entry was added.
    NewNeighbor(NeighborMessage),
    /// A neighbor entry was removed.
    DelNeighbor(NeighborMessage),

    // FDB (bridge forwarding database) events
    /// A new FDB entry was added or learned.
    NewFdb(FdbEntry),
    /// An FDB entry was removed.
    DelFdb(FdbEntry),

    // Traffic control events
    /// A new qdisc was added or changed.
    NewQdisc(TcMessage),
    /// A qdisc was deleted.
    DelQdisc(TcMessage),
    /// A new class was added or changed.
    NewClass(TcMessage),
    /// A class was deleted.
    DelClass(TcMessage),
    /// A new filter was added or changed.
    NewFilter(TcMessage),
    /// A filter was deleted.
    DelFilter(TcMessage),
    /// A new action was added or changed.
    NewAction(TcMessage),
    /// An action was deleted.
    DelAction(TcMessage),

    // Policy-routing rule events (RTM_NEWRULE / RTM_DELRULE).
    // Subscribe via `RtnetlinkGroup::{Ipv4Rule, Ipv6Rule}`.
    /// A new policy-routing rule was added.
    NewRule(RuleMessage),
    /// A policy-routing rule was removed.
    DelRule(RuleMessage),

    // Nexthop-object events (RTM_NEWNEXTHOP / RTM_DELNEXTHOP).
    // Subscribe via `RtnetlinkGroup::Nexthop`.
    /// A new nexthop object was added or changed.
    NewNexthop(Nexthop),
    /// A nexthop object was removed.
    DelNexthop(Nexthop),

    // Network-namespace ID events (RTM_NEWNSID / RTM_DELNSID).
    // Subscribe via `RtnetlinkGroup::NsId`.
    /// A network-namespace ID was assigned.
    NewNsId(NsIdMessage),
    /// A network-namespace ID was released.
    DelNsId(NsIdMessage),

    // Bridge multicast-database events (RTM_NEWMDB / RTM_DELMDB).
    // Subscribe via `RtnetlinkGroup::Mdb`.
    /// A bridge MDB entry was added or learned.
    NewMdb(MdbEntry),
    /// A bridge MDB entry was removed.
    DelMdb(MdbEntry),

    // Netconf events (RTM_NEWNETCONF / RTM_DELNETCONF): an interface's
    // forwarding, rp_filter and the rest — `/proc/sys` changes included.
    // Subscribe via `RtnetlinkGroup::{Ipv4Netconf, Ipv6Netconf}` (#523).
    /// An interface's IP configuration changed, or a new one has its own.
    NewNetconf(super::netconf::NetconfMessage),
    /// An interface's IP configuration went with it.
    DelNetconf(super::netconf::NetconfMessage),
}

impl NetworkEvent {
    /// The object this event is about, for
    /// [`with_gap_deltas`](super::resync_ext::ResyncStreamExt::with_gap_deltas)
    /// (#523): a link by ifindex, an address by device and prefix, a route
    /// by table, prefixes, TOS and metric, and so on. `None` for an
    /// action, which nothing here tracks.
    pub fn object_key(&self) -> Option<ObjectKey> {
        use std::fmt::Write;
        fn ip(a: Option<&std::net::IpAddr>) -> String {
            a.map_or_else(|| "-".to_string(), |a| a.to_string())
        }
        let key = match self {
            Self::NewLink(m) | Self::DelLink(m) => ObjectKey::new("link", m.ifindex().to_string()),
            Self::NewAddress(m) | Self::DelAddress(m) => ObjectKey::new(
                "address",
                format!("{} {}/{}", m.ifindex(), ip(m.local().or(m.address())), m.prefix_len()),
            ),
            Self::NewRoute(m) | Self::DelRoute(m) => ObjectKey::new(
                "route",
                format!(
                    "{} table {} {}/{} from {}/{} tos {} metric {}",
                    m.family(),
                    m.table_id(),
                    ip(m.destination()),
                    m.dst_len(),
                    ip(m.source()),
                    m.src_len(),
                    m.header.rtm_tos,
                    m.priority().unwrap_or(0)
                ),
            ),
            Self::NewNeighbor(m) | Self::DelNeighbor(m) => ObjectKey::new(
                if m.is_proxy() { "proxy-neighbour" } else { "neighbour" },
                format!("{} {}", m.ifindex(), ip(Some(m.destination()?))),
            ),
            Self::NewFdb(m) | Self::DelFdb(m) => {
                let mut id = format!("{} {}", m.ifindex(), m.mac_str());
                if let Some(vlan) = m.vlan() {
                    let _ = write!(id, " vlan {vlan}");
                }
                if let Some(dst) = m.dst() {
                    let _ = write!(id, " dst {dst}");
                }
                if let Some(vni) = m.vni() {
                    let _ = write!(id, " vni {vni}");
                }
                id.push_str(if m.is_master() { " master" } else { " self" });
                ObjectKey::new("fdb", id)
            }
            Self::NewQdisc(m) | Self::DelQdisc(m) => ObjectKey::new(
                "qdisc",
                format!("{} parent {} handle {}", m.ifindex(), m.parent(), m.handle()),
            ),
            Self::NewClass(m) | Self::DelClass(m) => {
                ObjectKey::new("class", format!("{} {}", m.ifindex(), m.handle()))
            }
            Self::NewFilter(m) | Self::DelFilter(m) => ObjectKey::new(
                "filter",
                format!(
                    "{} parent {} chain {} info {:#x} handle {:#x}",
                    m.ifindex(),
                    m.parent(),
                    m.chain().unwrap_or(0),
                    m.info(),
                    m.handle_raw()
                ),
            ),
            Self::NewAction(_) | Self::DelAction(_) => return None,
            Self::NewRule(m) | Self::DelRule(m) => ObjectKey::new(
                "rule",
                format!(
                    "{} pref {} from {}/{} to {}/{} iif {:?} oif {:?} fwmark {:?}/{:?} \
                     table {} action {:?} invert {} proto {:?} sport {:?} dport {:?} \
                     uid {:?} l3mdev {:?} goto {:?}",
                    m.family(),
                    m.priority(),
                    ip(m.source().as_ref()),
                    m.src_len(),
                    ip(m.destination().as_ref()),
                    m.dst_len(),
                    m.iifname(),
                    m.oifname(),
                    m.fwmark(),
                    m.fwmask(),
                    m.table(),
                    m.action(),
                    m.is_invert(),
                    m.ip_proto(),
                    m.sport_range(),
                    m.dport_range(),
                    m.uid_range(),
                    m.l3mdev(),
                    m.goto()
                ),
            ),
            Self::NewNexthop(m) | Self::DelNexthop(m) => ObjectKey::new("nexthop", m.id().to_string()),
            Self::NewNsId(m) | Self::DelNsId(m) => ObjectKey::new("nsid", m.nsid()?.to_string()),
            Self::NewMdb(m) | Self::DelMdb(m) => ObjectKey::new(
                "mdb",
                format!(
                    "{} port {} {:?} vid {}",
                    m.bridge_ifindex, m.port_ifindex, m.group, m.vid
                ),
            ),
            Self::NewNetconf(m) | Self::DelNetconf(m) => {
                ObjectKey::new("netconf", format!("{} {:?}", m.family(), m.device()))
            }
        };
        Some(key)
    }

    /// Returns true if this is a "new" event (add or change).
    pub fn is_new(&self) -> bool {
        matches!(
            self,
            NetworkEvent::NewLink(_)
                | NetworkEvent::NewAddress(_)
                | NetworkEvent::NewRoute(_)
                | NetworkEvent::NewNeighbor(_)
                | NetworkEvent::NewFdb(_)
                | NetworkEvent::NewQdisc(_)
                | NetworkEvent::NewClass(_)
                | NetworkEvent::NewFilter(_)
                | NetworkEvent::NewAction(_)
                | NetworkEvent::NewRule(_)
                | NetworkEvent::NewNexthop(_)
                | NetworkEvent::NewNsId(_)
                | NetworkEvent::NewMdb(_)
                | NetworkEvent::NewNetconf(_)
        )
    }

    /// Returns true if this is a "delete" event.
    pub fn is_del(&self) -> bool {
        !self.is_new()
    }

    /// Returns the interface index associated with this event, if any.
    pub fn ifindex(&self) -> Option<u32> {
        match self {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Some(m.ifindex()),
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Some(m.ifindex()),
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Some(m.ifindex()),
            NetworkEvent::NewFdb(m) | NetworkEvent::DelFdb(m) => Some(m.ifindex),
            NetworkEvent::NewQdisc(m)
            | NetworkEvent::DelQdisc(m)
            | NetworkEvent::NewClass(m)
            | NetworkEvent::DelClass(m)
            | NetworkEvent::NewFilter(m)
            | NetworkEvent::DelFilter(m)
            | NetworkEvent::NewAction(m)
            | NetworkEvent::DelAction(m) => Some(m.ifindex()),
            NetworkEvent::NewNexthop(m) | NetworkEvent::DelNexthop(m) => m.ifindex(),
            NetworkEvent::NewMdb(m) | NetworkEvent::DelMdb(m) => Some(m.port_ifindex),
            NetworkEvent::NewNetconf(m) | NetworkEvent::DelNetconf(m) => m.ifindex(),
            NetworkEvent::NewRoute(_)
            | NetworkEvent::DelRoute(_)
            | NetworkEvent::NewRule(_)
            | NetworkEvent::DelRule(_)
            | NetworkEvent::NewNsId(_)
            | NetworkEvent::DelNsId(_) => None,
        }
    }

    /// Returns "new" or "del" based on the event type.
    ///
    /// Useful for display/logging purposes.
    pub fn action(&self) -> &'static str {
        if self.is_new() { "new" } else { "del" }
    }

    /// Returns the inner NetconfMessage if this is a netconf event (#523).
    pub fn as_netconf(&self) -> Option<&super::netconf::NetconfMessage> {
        match self {
            NetworkEvent::NewNetconf(m) | NetworkEvent::DelNetconf(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner LinkMessage if this is a link event.
    pub fn as_link(&self) -> Option<&LinkMessage> {
        match self {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner LinkMessage if this is a link event.
    pub fn into_link(self) -> Option<LinkMessage> {
        match self {
            NetworkEvent::NewLink(m) | NetworkEvent::DelLink(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner AddressMessage if this is an address event.
    pub fn as_address(&self) -> Option<&AddressMessage> {
        match self {
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner AddressMessage if this is an address event.
    pub fn into_address(self) -> Option<AddressMessage> {
        match self {
            NetworkEvent::NewAddress(m) | NetworkEvent::DelAddress(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner RouteMessage if this is a route event.
    pub fn as_route(&self) -> Option<&RouteMessage> {
        match self {
            NetworkEvent::NewRoute(m) | NetworkEvent::DelRoute(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner RouteMessage if this is a route event.
    pub fn into_route(self) -> Option<RouteMessage> {
        match self {
            NetworkEvent::NewRoute(m) | NetworkEvent::DelRoute(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner NeighborMessage if this is a neighbor event.
    pub fn as_neighbor(&self) -> Option<&NeighborMessage> {
        match self {
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner NeighborMessage if this is a neighbor event.
    pub fn into_neighbor(self) -> Option<NeighborMessage> {
        match self {
            NetworkEvent::NewNeighbor(m) | NetworkEvent::DelNeighbor(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner FdbEntry if this is an FDB event.
    pub fn as_fdb(&self) -> Option<&FdbEntry> {
        match self {
            NetworkEvent::NewFdb(m) | NetworkEvent::DelFdb(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner FdbEntry if this is an FDB event.
    pub fn into_fdb(self) -> Option<FdbEntry> {
        match self {
            NetworkEvent::NewFdb(m) | NetworkEvent::DelFdb(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner TcMessage if this is a TC event (qdisc, class, filter, or action).
    pub fn as_tc(&self) -> Option<&TcMessage> {
        match self {
            NetworkEvent::NewQdisc(m)
            | NetworkEvent::DelQdisc(m)
            | NetworkEvent::NewClass(m)
            | NetworkEvent::DelClass(m)
            | NetworkEvent::NewFilter(m)
            | NetworkEvent::DelFilter(m)
            | NetworkEvent::NewAction(m)
            | NetworkEvent::DelAction(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner TcMessage if this is a TC event.
    pub fn into_tc(self) -> Option<TcMessage> {
        match self {
            NetworkEvent::NewQdisc(m)
            | NetworkEvent::DelQdisc(m)
            | NetworkEvent::NewClass(m)
            | NetworkEvent::DelClass(m)
            | NetworkEvent::NewFilter(m)
            | NetworkEvent::DelFilter(m)
            | NetworkEvent::NewAction(m)
            | NetworkEvent::DelAction(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner RuleMessage if this is a policy-routing rule event.
    pub fn as_rule(&self) -> Option<&RuleMessage> {
        match self {
            NetworkEvent::NewRule(m) | NetworkEvent::DelRule(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner RuleMessage if this is a rule event.
    pub fn into_rule(self) -> Option<RuleMessage> {
        match self {
            NetworkEvent::NewRule(m) | NetworkEvent::DelRule(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner Nexthop if this is a nexthop-object event.
    pub fn as_nexthop(&self) -> Option<&Nexthop> {
        match self {
            NetworkEvent::NewNexthop(m) | NetworkEvent::DelNexthop(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner Nexthop if this is a nexthop event.
    pub fn into_nexthop(self) -> Option<Nexthop> {
        match self {
            NetworkEvent::NewNexthop(m) | NetworkEvent::DelNexthop(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner NsIdMessage if this is a namespace-ID event.
    pub fn as_nsid(&self) -> Option<&NsIdMessage> {
        match self {
            NetworkEvent::NewNsId(m) | NetworkEvent::DelNsId(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner NsIdMessage if this is a namespace-ID event.
    pub fn into_nsid(self) -> Option<NsIdMessage> {
        match self {
            NetworkEvent::NewNsId(m) | NetworkEvent::DelNsId(m) => Some(m),
            _ => None,
        }
    }

    /// Returns the inner MdbEntry if this is a bridge MDB event.
    pub fn as_mdb(&self) -> Option<&MdbEntry> {
        match self {
            NetworkEvent::NewMdb(m) | NetworkEvent::DelMdb(m) => Some(m),
            _ => None,
        }
    }

    /// Consumes self and returns the inner MdbEntry if this is a bridge MDB event.
    pub fn into_mdb(self) -> Option<MdbEntry> {
        match self {
            NetworkEvent::NewMdb(m) | NetworkEvent::DelMdb(m) => Some(m),
            _ => None,
        }
    }
}

impl GapDelta for NetworkEvent {
    fn is_removal(&self) -> bool {
        self.is_del()
    }

    fn removal(&self) -> Option<Self> {
        let removal = match self {
            Self::NewLink(m) => Self::DelLink(m.clone()),
            Self::NewAddress(m) => Self::DelAddress(m.clone()),
            Self::NewRoute(m) => Self::DelRoute(m.clone()),
            Self::NewNeighbor(m) => Self::DelNeighbor(m.clone()),
            Self::NewFdb(m) => Self::DelFdb(m.clone()),
            Self::NewQdisc(m) => Self::DelQdisc(m.clone()),
            Self::NewClass(m) => Self::DelClass(m.clone()),
            Self::NewFilter(m) => Self::DelFilter(m.clone()),
            Self::NewAction(m) => Self::DelAction(m.clone()),
            Self::NewRule(m) => Self::DelRule(m.clone()),
            Self::NewNexthop(m) => Self::DelNexthop(m.clone()),
            Self::NewNsId(m) => Self::DelNsId(m.clone()),
            Self::NewMdb(m) => Self::DelMdb(m.clone()),
            Self::NewNetconf(m) => Self::DelNetconf(m.clone()),
            _ => return None,
        };
        Some(removal)
    }
}
