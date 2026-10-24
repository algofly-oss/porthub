//! A deleted link read back as declarations, so an undo can put it back
//! (#745).
//!
//! Deleting a link — to recreate it, or because the previous config
//! declared it and this one does not — takes with it the links stacked on
//! it, everything on them, and the master of the ports it had. The diff
//! reads all of that from the dumps it already holds, as declarations:
//! each link as the [`DeclaredLink`] that creates it, its addresses,
//! routes, neighbours, FDB entries and nexthop objects, its TC tree as a
//! [`PreservedTc`]. The inverse of the deletion,
//! [`Step::RestoreLink`](super::Step::RestoreLink), creates the links again
//! and puts the rest back.
//!
//! A link is read back as far as a declaration says: its kind and the kind
//! parameters a declaration has, its state, MTU, MAC, master, alias and the
//! other attributes, a bridge's options, a bridge port's options and VLANs.
//! Each is checked against the comparison the diff runs, so a link that
//! does not read back exactly is not put back as something else. A kind
//! parameter no declaration has — a VXLAN's TTL, a VLAN's QoS map — comes
//! back as the kernel's default, as it does when the apply recreates a
//! link, and so does a MAC the kernel picked for a bridge no port gave one
//! to: set, it would stop following the ports. What cannot be put back at
//! all — a kind no declaration has, a veth
//! whose peer is in another namespace, an address with a lifetime, a BPF
//! filter — leaves the deletion without an inverse, and
//! [`LinkRecreate::unrestorable`](super::LinkRecreate::unrestorable) says
//! why.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::kind::{
    InfoData, LinkExtras, compare, fdb_entry_is_users, kernel_bond_mode, kernel_macvlan_mode,
    lower_name, nexthop_devices, route_through,
};
use super::preserve::{PreservedTc, TcObject};
use super::types::{
    BridgeOptions, DeclaredAddress, DeclaredFdb, DeclaredLink, DeclaredLinkType,
    DeclaredNeighbour, DeclaredNexthop, DeclaredRoute, ErspanParams, Ip6tnlParams, IpvlanIsolation,
    IpvlanMode, LinkAttrs, LinkState, MacvlanMode, MasterSpec, PortOptions, PortVlan, TunnelParams,
};
use crate::netlink::{
    link::{
        AdSelect, ErspanDirection, ErspanVersion, Ip6tnlMode, LacpRate, NetkitMode, NetkitPolicy,
        NetkitScrub, VlanProtocol, XmitHashPolicy, bond_attr, macvlan, netkit, vlan, vrf_attr,
        vxlan,
    },
    messages::{AddressMessage, LinkMessage, RouteMessage, TcMessage},
    nexthop::NexthopGroupType,
    types::{
        addr::Scope,
        neigh::{ntf, nud},
        route::RouteProtocol,
    },
};

/// What deleting a link takes with it, read back as declarations: what an
/// undo puts back (#745). The inverse of a
/// [`DeleteForRecreate`](super::Step::DeleteForRecreate) or
/// [`RemoveLink`](super::Step::RemoveLink) step.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LinkRestore {
    /// The deleted links as they were, lower devices first: the link, and
    /// the links the kernel deleted with it. The second end of a pair is
    /// declared as an existing device: it comes back with the first.
    pub links: Vec<DeclaredLink>,
    /// The ports the deleted links released, with the master, state and
    /// bridge port options they had.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub ports: Vec<DeclaredLink>,
    /// Nexthop objects, members before the groups they are in.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub nexthops: Vec<RestoredNexthop>,
    /// Addresses.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub addresses: Vec<DeclaredAddress>,
    /// Routes.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub routes: Vec<RestoredRoute>,
    /// Permanent and proxy neighbours.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub neighbours: Vec<DeclaredNeighbour>,
    /// FDB entries.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub fdb: Vec<DeclaredFdb>,
    /// The links' TC trees: qdiscs, classes and filters.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub tc: Vec<PreservedTc>,
}

/// A route put back, with who added it.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RestoredRoute {
    /// The route.
    pub route: DeclaredRoute,
    /// Who added it (`ip route`'s `proto`), by number.
    #[cfg_attr(feature = "schemars", schemars(with = "u8"))]
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "super::kind::serialize_protocol",
            deserialize_with = "super::kind::deserialize_protocol"
        )
    )]
    pub protocol: RouteProtocol,
}

/// A nexthop object put back, with who added it.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RestoredNexthop {
    /// The nexthop.
    pub nexthop: DeclaredNexthop,
    /// Who added it, by number, as for a route.
    pub protocol: u8,
}

impl std::fmt::Display for LinkRestore {
    /// `vx0 (vxlan) and vx0.10 (vlan), as they were, with 2 addresses and 1
    /// route`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let links: Vec<String> = self
            .links
            .iter()
            .filter_map(|l| Some(format!("{} ({})", l.name, l.link_type.kind()?)))
            .collect();
        write!(f, "{} as it was", and_list(&links))?;
        let n = |count: usize, one: &str, many: &str| {
            (count > 0).then(|| format!("{count} {}", if count == 1 { one } else { many }))
        };
        let tc: usize = self.tc.iter().map(PreservedTc::len).sum();
        let what: Vec<String> = [
            n(self.ports.len(), "port", "ports"),
            n(self.addresses.len(), "address", "addresses"),
            n(self.routes.len(), "route", "routes"),
            n(self.nexthops.len(), "nexthop", "nexthops"),
            n(self.neighbours.len(), "neighbour", "neighbours"),
            n(self.fdb.len(), "FDB entry", "FDB entries"),
            n(tc, "TC object", "TC objects"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if !what.is_empty() {
            write!(f, ", with {}", and_list(&what))?;
        }
        Ok(())
    }
}

fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The kernel state a deletion is read back from.
pub(super) struct Dumps<'a> {
    pub(super) links: &'a [LinkMessage],
    pub(super) addresses: &'a [AddressMessage],
    pub(super) routes: &'a [RouteMessage],
    pub(super) qdiscs: &'a [TcMessage],
    pub(super) extras: &'a LinkExtras,
    pub(super) names: &'a HashMap<u32, &'a str>,
}

/// Read back what deleting `closure` — a link and the links the kernel
/// deletes with it, lower devices first — takes with it: those links, the
/// `ports` they release, and what is on both, the `flushed` ports (a bond
/// closes them, a VRF unlinks them) losing their routes, IPv6 addresses,
/// neighbours and nexthop objects as a link going down does. `Err` lists
/// what cannot be put back.
///
/// `earlier` are the links the apply deletes before these. An undo puts
/// them back after these, so a port among them is theirs to put back, and
/// a master among them is not here yet: the port is left out, and the
/// master is put back with its ports.
pub(super) fn capture(
    live: &Dumps<'_>,
    closure: &[&LinkMessage],
    ports: &[&LinkMessage],
    flushed: &[u32],
    earlier: &HashSet<u32>,
) -> Result<LinkRestore, Vec<String>> {
    let mut why = Vec::new();
    let mut restore = LinkRestore::default();
    let names = live.names;
    let name_of = |ifindex: u32| names.get(&ifindex).copied().unwrap_or("?");
    let deleted: HashSet<u32> = closure.iter().map(|l| l.ifindex()).collect();

    // A pair is created from one end: the first one met, or a netkit's
    // primary, which a netkit pair is created as.
    let mut order: Vec<&LinkMessage> = closure.to_vec();
    for i in 0..order.len() {
        let l = order[i];
        if l.kind() != Some("netkit") || InfoData::of(l).u8(netkit::IFLA_NETKIT_PRIMARY) != Some(0) {
            continue;
        }
        if let Some(j) = order.iter().position(|p| Some(p.ifindex()) == l.link())
            && j > i
        {
            order.swap(i, j);
        }
    }
    let mut paired: HashSet<u32> = HashSet::new();
    for l in &order {
        if paired.contains(&l.ifindex()) {
            // The second end of a pair: configured, not created.
            restore.links.push(existing_link_from_live(l, live, earlier, &mut why));
            continue;
        }
        if let Some(link) = link_from_live(l, live, earlier, &mut why) {
            if matches!(link.link_type, DeclaredLinkType::Veth { .. } | DeclaredLinkType::Netkit { .. })
                && let Some(peer) = l.link()
            {
                paired.insert(peer);
            }
            restore.links.push(link);
        }
    }
    for p in ports.iter().filter(|p| !earlier.contains(&p.ifindex())) {
        restore.ports.push(existing_link_from_live(p, live, earlier, &mut why));
    }

    for l in closure {
        restore.tc.extend(tc_from_live(l.ifindex(), name_of(l.ifindex()), live, &mut why));
        // The VLANs of a bridge itself, as against its ports'.
        if l.kind() == Some("bridge") {
            let default_pvid = InfoData::of(l).u16_ne(BRIDGE_VLAN_DEFAULT_PVID).unwrap_or(1);
            let own: Vec<_> = live
                .extras
                .bridge_vlans
                .iter()
                .filter(|v| v.ifindex() == l.ifindex())
                .filter(|v| !(v.vid() == default_pvid && v.is_pvid() && v.is_untagged()))
                .map(|v| v.vid().to_string())
                .collect();
            if !own.is_empty() {
                why.push(format!(
                    "the VLANs of bridge {} itself ({}), which no declaration has",
                    name_of(l.ifindex()),
                    own.join(", ")
                ));
            }
        }
    }

    // What is on the deleted links goes in every family; the flushed ports
    // keep their IPv4 addresses.
    for a in live.addresses {
        let on_deleted = deleted.contains(&a.ifindex());
        let on_flushed = flushed.contains(&a.ifindex()) && a.is_ipv6();
        if on_deleted || on_flushed {
            restore.addresses.extend(address_from_live(a, name_of(a.ifindex()), &mut why));
        }
    }
    let gone: HashSet<u32> = deleted.iter().chain(flushed).copied().collect();
    restore.nexthops = nexthops_from_live(&gone, live, &mut why);
    let nh_devs = nexthop_devices(&live.extras.nexthops);
    for r in live.routes {
        if r.protocol() == RouteProtocol::Kernel
            || !gone.iter().any(|d| route_through(r, *d, &nh_devs).is_some())
        {
            continue;
        }
        let text = route_label(r, names);
        if r.protocol() == RouteProtocol::Ra {
            why.push(format!("route {text}, which the kernel learned from a router advertisement"));
            continue;
        }
        if let Some(lost) = super::diff::route_lost(r) {
            why.push(format!("route {text}: {lost}"));
            continue;
        }
        match super::diff::declared_from_live(r, names) {
            Some(route) => restore.routes.push(RestoredRoute {
                route,
                protocol: r.protocol(),
            }),
            None => why.push(format!("route {text}, of a type no declaration has")),
        }
    }
    for ifindex in &gone {
        neighbours_from_live(*ifindex, name_of(*ifindex), live, &mut restore.neighbours, &mut why);
    }
    restore.fdb = fdb_from_live(closure, live, &mut why);

    if why.is_empty() {
        Ok(restore)
    } else {
        why.sort();
        why.dedup();
        Err(why)
    }
}

/// `IFLA_BR_VLAN_DEFAULT_PVID`.
const BRIDGE_VLAN_DEFAULT_PVID: u16 = 39;

/// A deleted link as the declaration that creates it again, checked
/// against the comparison the diff runs; `None`, with why, when it does not
/// read back.
fn link_from_live(
    l: &LinkMessage,
    live: &Dumps<'_>,
    earlier: &HashSet<u32>,
    why: &mut Vec<String>,
) -> Option<DeclaredLink> {
    let name = l.name.as_deref().unwrap_or("?");
    let link_type = match kind_from_live(l, live.names) {
        Ok(t) => t,
        Err(e) => {
            why.push(e);
            return None;
        }
    };
    let mut link = DeclaredLink {
        name: name.to_string(),
        link_type,
        bridge: (l.kind() == Some("bridge")).then(|| bridge_from_live(l)),
        ..existing_link_from_live(l, live, earlier, why)
    };
    if link.unaddressable_mac().is_some() || random_bridge_mac(l) {
        link.address = None;
    }
    // What the diff would change, or recreate, about the link as read back:
    // nothing, or it is not what was there.
    let d = compare(&link, l, live.names);
    let mut off: Vec<String> = d.recreate.into_iter().chain(d.refuse).collect();
    off.extend(d.update.into_iter().flat_map(|u| u.changes));
    if !off.is_empty() {
        why.push(format!(
            "link {name} does not read back as its declaration: {}",
            off.join(", ")
        ));
        return None;
    }
    Some(link)
}

/// A link as an existing device, configured but not created: its state,
/// MTU, MAC, master, attributes and bridge port options.
fn existing_link_from_live(
    l: &LinkMessage,
    live: &Dumps<'_>,
    earlier: &HashSet<u32>,
    why: &mut Vec<String>,
) -> DeclaredLink {
    let name = l.name.as_deref().unwrap_or("?");
    let master = match l.master() {
        Some(m) if !earlier.contains(&m) => {
            MasterSpec::Name(live.names.get(&m).copied().unwrap_or("?").to_string())
        }
        _ => MasterSpec::Unmanaged,
    };
    // A bond gives the ports it enslaves its own MAC, and gives each its own
    // back when it releases it: a port's MAC is the bond's to set.
    let under_bond = l
        .master()
        .and_then(|m| live.links.iter().find(|x| x.ifindex() == m))
        .is_some_and(|m| m.kind() == Some("bond"));
    // A port of a master put back after it is configured as one by the
    // master's restore.
    let port = port_from_live(l, live).filter(|_| !matches!(master, MasterSpec::Unmanaged));
    if let Some(port) = &port {
        let (off, _) = super::kind::port_changes(port, l);
        if !off.is_empty() {
            why.push(format!(
                "the bridge port options of {name} do not read back: {}",
                off.join(", ")
            ));
        }
    }
    DeclaredLink {
        name: name.to_string(),
        link_type: DeclaredLinkType::Physical,
        state: if l.is_up() { LinkState::Up } else { LinkState::Down },
        mtu: l.mtu,
        master,
        address: l
            .address()
            .and_then(|a| <[u8; 6]>::try_from(a).ok())
            .filter(|_| !under_bond),
        attrs: attrs_from_live(l),
        bridge: None,
        port,
    }
}

/// Whether a bridge's MAC is the one the kernel picked at random when it
/// was created: no port gave it one and no one set it, which its bridge id
/// says, being all zeros. Set again, it would stop following the ports;
/// the kernel picks a new one instead, as when the apply recreates a link.
fn random_bridge_mac(l: &LinkMessage) -> bool {
    /// `IFLA_BR_BRIDGE_ID`: a `struct ifla_bridge_id`, priority then MAC.
    const BRIDGE_ID: u16 = 11;
    l.kind() == Some("bridge")
        && InfoData::of(l)
            .0
            .get(&BRIDGE_ID)
            .and_then(|id| id.get(2..8))
            .is_some_and(|mac| Some(mac) != l.address())
}

/// What a link carries besides kind, state, MTU, master and MAC. Not
/// `mc_forwarding`, which a multicast routing daemon holds, or `mtu6`,
/// which follows the MTU.
fn attrs_from_live(l: &LinkMessage) -> LinkAttrs {
    use crate::netlink::devconf::{Ipv4Devconf, Ipv6Devconf};
    const IFF_PROMISC: u32 = libc::IFF_PROMISC as u32;
    LinkAttrs {
        txqlen: l.txqlen(),
        alias: l.alias().map(str::to_string),
        group: l.group(),
        gso_max_size: l.gso_max_size(),
        gso_max_segs: l.gso_max_segs(),
        gro_max_size: l.gro_max_size(),
        promisc: Some(l.flags() & IFF_PROMISC != 0),
        protodown: l.proto_down(),
        altnames: (!l.altnames().is_empty()).then(|| l.altnames().to_vec()),
        ipv4_conf: Ipv4Devconf::ALL
            .into_iter()
            .filter(|d| *d != Ipv4Devconf::McForwarding)
            .filter_map(|d| Some((d.name().to_string(), l.ipv4_devconf(d)?)))
            .collect(),
        ipv6_conf: Ipv6Devconf::ALL
            .into_iter()
            .filter(|d| *d != Ipv6Devconf::Mtu6)
            .filter_map(|d| Some((d.name().to_string(), l.ipv6_devconf(d)?)))
            .collect(),
        addr_gen_mode: l.addr_gen_mode(),
        ipv6_token: l.ipv6_token().filter(|t| !t.is_unspecified()),
    }
}

/// A bridge's options, every one a declaration has.
fn bridge_from_live(l: &LinkMessage) -> BridgeOptions {
    const FORWARD_DELAY: u16 = 1;
    const HELLO_TIME: u16 = 2;
    const MAX_AGE: u16 = 3;
    const AGEING_TIME: u16 = 4;
    const STP_STATE: u16 = 5;
    const PRIORITY: u16 = 6;
    const VLAN_FILTERING: u16 = 7;
    let data = InfoData::of(l);
    // Kept in 1/100 s.
    let time = |t| data.u32(t).map(|cs| std::time::Duration::from_millis(u64::from(cs) * 10));
    BridgeOptions {
        vlan_filtering: data.u8(VLAN_FILTERING).map(|v| v != 0),
        vlan_default_pvid: data.u16_ne(BRIDGE_VLAN_DEFAULT_PVID),
        stp: data.u32(STP_STATE).map(|v| v != 0),
        priority: data.u16_ne(PRIORITY),
        ageing_time: time(AGEING_TIME),
        forward_delay: time(FORWARD_DELAY),
        hello_time: time(HELLO_TIME),
        max_age: time(MAX_AGE),
    }
}

/// A bridge port's options and VLANs; `None` for a link that is no bridge
/// port.
fn port_from_live(l: &LinkMessage, live: &Dumps<'_>) -> Option<PortOptions> {
    use crate::netlink::types::link::brport::*;
    if l.link_info().and_then(|i| i.slave_kind()) != Some("bridge") {
        return None;
    }
    let data = InfoData::slave_of(l);
    let flag = |t| data.u8(t).map(|v| v != 0);
    let vlans: Vec<PortVlan> = live
        .extras
        .bridge_vlans
        .iter()
        .filter(|v| v.ifindex() == l.ifindex())
        .map(|v| PortVlan::new(v.vid(), v.is_pvid(), v.is_untagged()))
        .collect();
    Some(PortOptions {
        learning: flag(IFLA_BRPORT_LEARNING),
        flood: flag(IFLA_BRPORT_UNICAST_FLOOD),
        mcast_flood: flag(IFLA_BRPORT_MCAST_FLOOD),
        bcast_flood: flag(IFLA_BRPORT_BCAST_FLOOD),
        isolated: flag(IFLA_BRPORT_ISOLATED),
        neigh_suppress: flag(IFLA_BRPORT_NEIGH_SUPPRESS),
        hairpin: flag(IFLA_BRPORT_MODE),
        proxy_arp: flag(IFLA_BRPORT_PROXYARP),
        bpdu_guard: flag(IFLA_BRPORT_GUARD),
        root_block: flag(IFLA_BRPORT_PROTECT),
        cost: data.u32(IFLA_BRPORT_COST),
        priority: data.u16_ne(IFLA_BRPORT_PRIORITY),
        vlans: Some(vlans),
    })
}

/// A live link's kind and kind parameters, as a declaration gives them.
fn kind_from_live(l: &LinkMessage, names: &HashMap<u32, &str>) -> Result<DeclaredLinkType, String> {
    let name = l.name.as_deref().unwrap_or("?");
    let Some(kind) = l.kind() else {
        return Err(format!("link {name}, a device with no link kind, which cannot be created again"));
    };
    let data = InfoData::of(l);
    let missing = |what: &str| format!("link {name} ({kind}): its {what} was not dumped");
    let lower = || {
        lower_name(l, names)
            .map(str::to_string)
            .ok_or_else(|| format!("link {name} ({kind}): its lower device is in another namespace"))
    };
    // A device named by ifindex in the kind's data; 0 is none.
    let dev = |t: u16| -> Result<Option<String>, String> {
        match data.u32(t).filter(|i| *i != 0) {
            None => Ok(None),
            Some(i) => names
                .get(&i)
                .map(|n| Some(n.to_string()))
                .ok_or_else(|| format!("link {name} ({kind}): its underlay, ifindex {i}, is not in this namespace")),
        }
    };
    let v4 = |t: u16| data.ipv4(t).filter(|a| !a.is_unspecified());
    let v6 = |t: u16| data.ipv6(t).filter(|a| !a.is_unspecified());
    let either = |t4: u16, t6: u16| v4(t4).map(IpAddr::V4).or_else(|| v6(t6).map(IpAddr::V6));
    // The other end of a pair, here.
    let peer = || {
        if l.link_netnsid.is_some() {
            return Err(format!(
                "link {name} ({kind}): its peer is in another namespace, with what is on it there"
            ));
        }
        l.link()
            .and_then(|i| names.get(&i))
            .map(|n| n.to_string())
            .ok_or_else(|| missing("peer"))
    };
    Ok(match kind {
        "dummy" => DeclaredLinkType::Dummy,
        "ifb" => DeclaredLinkType::Ifb,
        "ovpn" => DeclaredLinkType::Ovpn,
        "bridge" => DeclaredLinkType::Bridge,
        "veth" => DeclaredLinkType::Veth {
            peer: peer()?,
            peer_netns: None,
            peer_address: None,
            peer_mtu: None,
            peer_state: LinkState::Unchanged,
        },
        "vlan" => DeclaredLinkType::Vlan {
            parent: lower()?,
            vlan_id: data.u16_ne(vlan::IFLA_VLAN_ID).ok_or_else(|| missing("VLAN id"))?,
            protocol: match data.u16_be(vlan::IFLA_VLAN_PROTOCOL) {
                None | Some(0x8100) => None,
                Some(0x88a8) => Some(VlanProtocol::Dot1ad),
                Some(p) => return Err(format!("link {name} (vlan): protocol {p:#06x}, which no declaration has")),
            },
        },
        "vxlan" => DeclaredLinkType::Vxlan {
            vni: data.u32(vxlan::IFLA_VXLAN_ID).ok_or_else(|| missing("VNI"))?,
            remote: either(vxlan::IFLA_VXLAN_GROUP, vxlan::IFLA_VXLAN_GROUP6),
            local: either(vxlan::IFLA_VXLAN_LOCAL, vxlan::IFLA_VXLAN_LOCAL6),
            port: data.u16_be(vxlan::IFLA_VXLAN_PORT),
            underlay_dev: dev(vxlan::IFLA_VXLAN_LINK)?,
        },
        "macvlan" | "macvtap" => {
            let have = data.u32(macvlan::IFLA_MACVLAN_MODE).ok_or_else(|| missing("mode"))?;
            let mode = [
                MacvlanMode::Private,
                MacvlanMode::Vepa,
                MacvlanMode::Bridge,
                MacvlanMode::Passthru,
                MacvlanMode::Source,
            ]
            .into_iter()
            .find(|m| kernel_macvlan_mode(*m) as u32 == have)
            .ok_or_else(|| format!("link {name} ({kind}): mode {have}, which no declaration has"))?;
            let parent = lower()?;
            if kind == "macvlan" {
                DeclaredLinkType::Macvlan { parent, mode }
            } else {
                DeclaredLinkType::Macvtap { parent, mode }
            }
        }
        "ipvlan" => {
            const MODE: u16 = 1;
            const FLAGS: u16 = 2;
            DeclaredLinkType::Ipvlan {
                parent: lower()?,
                mode: match data.u16_ne(MODE) {
                    Some(0) => IpvlanMode::L2,
                    Some(1) => IpvlanMode::L3,
                    Some(2) => IpvlanMode::L3s,
                    other => return Err(format!("link {name} (ipvlan): mode {other:?}, which no declaration has")),
                },
                isolation: match data.u16_ne(FLAGS).unwrap_or(0) {
                    0 => IpvlanIsolation::Bridge,
                    1 => IpvlanIsolation::Private,
                    2 => IpvlanIsolation::Vepa,
                    f => return Err(format!("link {name} (ipvlan): flags {f:#x}, which no declaration has")),
                },
            }
        }
        "gre" | "gretap" | "ipip" | "sit" | "vti" => {
            const GRE_KEY: u16 = 0x2000;
            // link, local, remote, ttl, and the keys in and out with their
            // flags: IFLA_GRE_*, IFLA_IPTUN_* (no key) and IFLA_VTI_* (no
            // flags, no TTL).
            let (link, local, remote, ttl, key) = match kind {
                "gre" | "gretap" => {
                    let keyed = data.u16_be(2).is_some_and(|f| f & GRE_KEY != 0);
                    (1, 6, 7, Some(8), keyed.then(|| data.u32_be(4)).flatten())
                }
                "vti" => (1, 4, 5, None, data.u32_be(2).filter(|k| *k != 0)),
                _ => (1, 2, 3, Some(4), None),
            };
            let p = TunnelParams {
                local: v4(local),
                remote: v4(remote),
                ttl: ttl.and_then(|t| data.u8(t)).filter(|t| *t != 0),
                key,
                underlay_dev: dev(link)?,
            };
            match kind {
                "gre" => DeclaredLinkType::Gre(p),
                "gretap" => DeclaredLinkType::Gretap(p),
                "ipip" => DeclaredLinkType::Ipip(p),
                "sit" => DeclaredLinkType::Sit(p),
                _ => DeclaredLinkType::Vti(p),
            }
        }
        "ip6tnl" => {
            let proto = data.u8(9).ok_or_else(|| missing("mode"))?;
            DeclaredLinkType::Ip6tnl(Ip6tnlParams {
                local: v6(2),
                remote: v6(3),
                hoplimit: data.u8(4),
                encap_limit: data.u8(6),
                mode: Ip6tnlMode::from_proto(proto)
                    .ok_or_else(|| format!("link {name} (ip6tnl): proto {proto}, which no declaration has"))?,
                key: None,
                underlay_dev: dev(1)?,
            })
        }
        "ip6gre" | "ip6gretap" => {
            const GRE_KEY: u16 = 0x2000;
            let keyed = data.u16_be(2).is_some_and(|f| f & GRE_KEY != 0);
            let p = Ip6tnlParams {
                local: v6(6),
                remote: v6(7),
                hoplimit: data.u8(8),
                encap_limit: data.u8(11),
                key: keyed.then(|| data.u32_be(4)).flatten(),
                underlay_dev: dev(1)?,
                ..Ip6tnlParams::default()
            };
            if kind == "ip6gre" {
                DeclaredLinkType::Ip6gre(p)
            } else {
                DeclaredLinkType::Ip6gretap(p)
            }
        }
        "vti6" => DeclaredLinkType::Vti6(Ip6tnlParams {
            local: v6(4),
            remote: v6(5),
            key: data.u32_be(2).filter(|k| *k != 0),
            underlay_dev: dev(1)?,
            ..Ip6tnlParams::default()
        }),
        "erspan" | "ip6erspan" => {
            let version = match data.u8(22) {
                Some(1) => ErspanVersion::V1 {
                    index: data.u32(21).unwrap_or(0),
                },
                Some(2) => ErspanVersion::V2 {
                    direction: if data.u8(23) == Some(1) {
                        ErspanDirection::Egress
                    } else {
                        ErspanDirection::Ingress
                    },
                    hwid: data.u16_ne(24).and_then(|h| u8::try_from(h).ok()).unwrap_or(0),
                },
                other => return Err(format!("link {name} ({kind}): version {other:?}, which no declaration has")),
            };
            let session = data.u32_be(4).ok_or_else(|| missing("session"))?;
            let (local, remote) = if kind == "erspan" {
                (v4(6).map(IpAddr::V4), v4(7).map(IpAddr::V4))
            } else {
                (v6(6).map(IpAddr::V6), v6(7).map(IpAddr::V6))
            };
            let p = ErspanParams {
                session: u16::try_from(session)
                    .map_err(|_| format!("link {name} ({kind}): session {session}, which no declaration has"))?,
                version,
                local,
                remote,
                ttl: data.u8(8),
                underlay_dev: dev(1)?,
            };
            if kind == "erspan" {
                DeclaredLinkType::Erspan(p)
            } else {
                DeclaredLinkType::Ip6erspan(p)
            }
        }
        "xfrm" => DeclaredLinkType::Xfrm {
            if_id: data.u32(2).ok_or_else(|| missing("if_id"))?,
            underlay_dev: dev(1)?,
        },
        "geneve" => DeclaredLinkType::Geneve {
            vni: data.u32(1).ok_or_else(|| missing("VNI"))?,
            remote: either(2, 7),
            ttl: data.u8(3),
            tos: data.u8(4),
            port: data.u16_be(5),
        },
        "macsec" => {
            let sci = data
                .0
                .get(&1)
                .and_then(|p| <[u8; 8]>::try_from(p.get(..8)?).ok())
                .map(u64::from_be_bytes);
            let on = |t: u16| data.u8(t).map(|v| v != 0);
            DeclaredLinkType::Macsec {
                parent: lower()?,
                sci,
                port: None,
                encrypt: on(7),
                protect: on(8),
                include_sci: on(9),
                replay_window: (data.u8(12) == Some(1)).then(|| data.u32(5)).flatten(),
            }
        }
        "bareudp" => DeclaredLinkType::Bareudp {
            port: data.u16_be(1).ok_or_else(|| missing("port"))?,
            ethertype: data.u16_be(2).ok_or_else(|| missing("ethertype"))?,
            srcport_min: data.u16_ne(3),
            multiproto: data.0.contains_key(&4),
        },
        "bond" => {
            let have = data.u8(bond_attr::IFLA_BOND_MODE).ok_or_else(|| missing("mode"))?;
            let mode = [
                super::types::BondMode::BalanceRr,
                super::types::BondMode::ActiveBackup,
                super::types::BondMode::BalanceXor,
                super::types::BondMode::Broadcast,
                super::types::BondMode::Ieee802_3ad,
                super::types::BondMode::BalanceTlb,
                super::types::BondMode::BalanceAlb,
            ]
            .into_iter()
            .find(|m| kernel_bond_mode(*m) as u8 == have)
            .ok_or_else(|| format!("link {name} (bond): mode {have}, which no declaration has"))?;
            // `bond_opt_check_mode`: the 802.3ad options are refused in any
            // other mode, and a delay without MII monitoring.
            let lacp = mode == super::types::BondMode::Ieee802_3ad;
            let miimon = data.u32(bond_attr::IFLA_BOND_MIIMON);
            let monitored = miimon.is_some_and(|m| m != 0);
            DeclaredLinkType::Bond {
                mode,
                miimon,
                xmit_hash_policy: data
                    .u8(bond_attr::IFLA_BOND_XMIT_HASH_POLICY)
                    .and_then(|v| XmitHashPolicy::try_from(v).ok()),
                min_links: data.u32(bond_attr::IFLA_BOND_MIN_LINKS),
                ad_select: lacp
                    .then(|| match data.u8(bond_attr::IFLA_BOND_AD_SELECT) {
                        Some(0) => Some(AdSelect::Stable),
                        Some(1) => Some(AdSelect::Bandwidth),
                        Some(2) => Some(AdSelect::Count),
                        _ => None,
                    })
                    .flatten(),
                lacp_rate: lacp
                    .then(|| match data.u8(bond_attr::IFLA_BOND_AD_LACP_RATE) {
                        Some(0) => Some(LacpRate::Slow),
                        Some(1) => Some(LacpRate::Fast),
                        _ => None,
                    })
                    .flatten(),
                downdelay: monitored.then(|| data.u32(bond_attr::IFLA_BOND_DOWNDELAY)).flatten(),
                updelay: monitored.then(|| data.u32(bond_attr::IFLA_BOND_UPDELAY)).flatten(),
                resend_igmp: data.u32(bond_attr::IFLA_BOND_RESEND_IGMP),
            }
        }
        "vrf" => DeclaredLinkType::Vrf {
            table: data.u32(vrf_attr::IFLA_VRF_TABLE).ok_or_else(|| missing("table"))?,
        },
        "netkit" => {
            let policy = |t| match data.u32(t) {
                Some(0) => Some(NetkitPolicy::Forward),
                Some(2) => Some(NetkitPolicy::Blackhole),
                _ => None,
            };
            let scrub = |t| match data.u32(t) {
                Some(0) => Some(NetkitScrub::None),
                Some(1) => Some(NetkitScrub::Default),
                _ => None,
            };
            DeclaredLinkType::Netkit {
                peer: peer()?,
                mode: match data.u32(netkit::IFLA_NETKIT_MODE) {
                    Some(0) => Some(NetkitMode::L2),
                    Some(1) => Some(NetkitMode::L3),
                    _ => None,
                },
                primary_policy: policy(netkit::IFLA_NETKIT_POLICY),
                peer_policy: policy(netkit::IFLA_NETKIT_PEER_POLICY),
                scrub: scrub(netkit::IFLA_NETKIT_SCRUB),
                peer_scrub: scrub(netkit::IFLA_NETKIT_PEER_SCRUB),
            }
        }
        other => return Err(format!("link {name}, of kind {other}, which no declaration has")),
    })
}

/// An address as the declaration that adds it again: its peer, label,
/// metric and flags. One with a lifetime is a daemon's, or the kernel's
/// from a router advertisement, and one with a scope other than global
/// has no declaration; an IPv6 link-local address the kernel makes itself.
fn address_from_live(a: &AddressMessage, dev: &str, why: &mut Vec<String>) -> Option<DeclaredAddress> {
    let addr = *a.primary_address()?;
    if let IpAddr::V6(v6) = addr
        && v6.segments()[0] & 0xffc0 == 0xfe80
    {
        return None;
    }
    let text = format!("address {addr}/{} on {dev}", a.prefix_len());
    if !a.is_permanent() {
        why.push(format!("{text}, which has a lifetime: a daemon's, or learned"));
        return None;
    }
    if a.scope() != Scope::Universe {
        why.push(format!("{text}, of a scope no declaration has"));
        return None;
    }
    super::diff::address_from_live(dev, a)
}

/// The nexthop objects deleting `gone` takes: the ones on it, and every
/// group with a member there, which the kernel shrinks or deletes. Members
/// first.
fn nexthops_from_live(gone: &HashSet<u32>, live: &Dumps<'_>, why: &mut Vec<String>) -> Vec<RestoredNexthop> {
    let all = &live.extras.nexthops;
    let lost: HashSet<u32> = all
        .iter()
        .filter(|n| n.ifindex().is_some_and(|i| gone.contains(&i)))
        .map(|n| n.id())
        .collect();
    let groups = all.iter().filter(|n| {
        n.group()
            .is_some_and(|members| members.iter().any(|m| lost.contains(&m.id())))
    });
    let mut out = Vec::new();
    for n in all.iter().filter(|n| lost.contains(&n.id())).chain(groups) {
        if n.is_fdb() {
            why.push(format!("nexthop {}, an FDB nexthop, which no declaration has", n.id()));
            continue;
        }
        if n.group_type() == Some(NexthopGroupType::Resilient) {
            why.push(format!("nexthop {}, a resilient group, which no declaration has", n.id()));
            continue;
        }
        if n.encap_type().is_some() {
            why.push(format!("nexthop {}, with an encap, which no declaration has", n.id()));
            continue;
        }
        out.push(RestoredNexthop {
            nexthop: super::diff::nexthop_from_live(n, live.names),
            protocol: n.protocol(),
        });
    }
    out
}

/// The permanent and proxy neighbours on a link. One a controller learned
/// externally, or one with flags a declaration does not have, cannot be put
/// back.
fn neighbours_from_live(
    ifindex: u32,
    dev: &str,
    live: &Dumps<'_>,
    out: &mut Vec<DeclaredNeighbour>,
    why: &mut Vec<String>,
) {
    let extras = live.extras;
    for n in extras.neighbours.iter().filter(|n| n.ifindex() == ifindex) {
        let Some(dst) = n.destination().copied() else { continue };
        let state = n.header.ndm_state;
        let flags = n.header.ndm_flags;
        let ext_learned = flags & ntf::EXT_LEARNED != 0;
        if state & nud::PERMANENT == 0 && !ext_learned {
            continue;
        }
        let lladdr = n.lladdr().map(<[u8; 6]>::try_from);
        match lladdr {
            _ if ext_learned => why.push(format!("neighbour {dst} dev {dev}, which a controller learned")),
            _ if flags & ntf::ROUTER != 0 => {
                why.push(format!("neighbour {dst} dev {dev}, a router, which no declaration has"))
            }
            Some(Err(_)) => {
                why.push(format!("neighbour {dst} dev {dev}, whose address is not a MAC"))
            }
            lladdr => out.push(DeclaredNeighbour {
                dev: dev.to_string(),
                destination: dst,
                lladdr: lladdr.and_then(Result::ok),
                proxy: false,
            }),
        }
    }
    for p in extras.proxies.iter().filter(|p| p.ifindex() == ifindex) {
        if let Some(dst) = p.destination() {
            out.push(DeclaredNeighbour {
                dev: dev.to_string(),
                destination: *dst,
                lladdr: None,
                proxy: true,
            });
        }
    }
}

/// The FDB entries the deleted links take: theirs, and every entry in a
/// deleted bridge's database. One made by the kernel or the bridge is not
/// put back; one a declaration cannot say (an entry on a device's own
/// table without a remote, a remote's port, VNI or interface, one learned
/// externally) cannot be. Nor can an entry elsewhere that sends through a
/// deleted link: it is left naming its old ifindex.
fn fdb_from_live(closure: &[&LinkMessage], live: &Dumps<'_>, why: &mut Vec<String>) -> Vec<DeclaredFdb> {
    let by_index: HashMap<u32, &LinkMessage> = live.links.iter().map(|l| (l.ifindex(), l)).collect();
    let link_macs: HashSet<&[u8]> = live
        .links
        .iter()
        .filter_map(|l| l.address())
        .filter(|a| a.iter().any(|b| *b != 0))
        .collect();
    let deleted: HashSet<u32> = closure.iter().map(|l| l.ifindex()).collect();
    let name_of = |i: u32| live.names.get(&i).copied().unwrap_or("?");
    let mut out: Vec<DeclaredFdb> = Vec::new();
    for e in &live.extras.fdb {
        let on = deleted.contains(&e.ifindex()) || e.master().is_some_and(|m| deleted.contains(&m));
        let via = e.ifindex_attr.is_some_and(|i| deleted.contains(&i)) && !on;
        if !(on || via) || !fdb_entry_is_users(e, &by_index, &link_macs) {
            continue;
        }
        let Some(mac) = e.lladdr().and_then(|m| <[u8; 6]>::try_from(m).ok()) else {
            continue;
        };
        let text = format!("fdb entry {} dev {}", super::kind::mac_str(&mac), name_of(e.ifindex()));
        let self_entry = e.header.ndm_flags & ntf::SELF != 0;
        let dst = e.destination().copied();
        let undeclarable = if via {
            Some("which sends through a deleted link")
        } else if e.header.ndm_flags & ntf::EXT_LEARNED != 0 {
            Some("which a controller learned")
        } else if self_entry && dst.is_none() {
            Some("in the device's own table, without a remote")
        } else if e.port().is_some() || e.vni().is_some() || e.ifindex_attr.is_some() {
            Some("with a remote port, VNI or interface")
        } else {
            None
        };
        if let Some(reason) = undeclarable {
            why.push(format!("{text}, {reason}"));
            continue;
        }
        let entry = DeclaredFdb {
            dev: name_of(e.ifindex()).to_string(),
            mac,
            vlan: e.vlan(),
            dst,
            local: dst.is_none() && e.header.ndm_state & nud::PERMANENT != 0,
        };
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    out
}

/// A deleted link's TC tree, every object of it: its qdiscs (not the
/// kernel's default, which comes back with the link), the classes users
/// make, and its filters.
fn tc_from_live(ifindex: u32, dev: &str, live: &Dumps<'_>, why: &mut Vec<String>) -> Option<PreservedTc> {
    let mut tree = PreservedTc {
        dev: dev.to_string(),
        ..PreservedTc::default()
    };
    for q in live
        .qdiscs
        .iter()
        .filter(|q| q.ifindex() == ifindex && q.handle().major() != 0)
    {
        match TcObject::qdisc(q) {
            Some(o) => tree.qdiscs.push(o),
            None => why.push(format!(
                "qdisc {} on {dev}, which does not read back as a declaration",
                q.kind().unwrap_or("?")
            )),
        }
    }
    // A prio's bands, an mq's queues and the flows fq_codel lists come back
    // with their qdisc, and so does HFSC's root class.
    for c in live.extras.classes.iter().filter(|c| {
        c.ifindex() == ifindex
            && matches!(c.kind(), Some("htb" | "hfsc" | "drr" | "qfq" | "cbq"))
            && c.handle().minor() != 0
    }) {
        tree.classes.push(TcObject::from_live(c));
    }
    for f in live.extras.filters.iter().filter(|f| f.ifindex() == ifindex) {
        if !super::preserve::replayable_filter(f) {
            why.push(format!(
                "filter {} pref {} on {dev}, whose BPF program is named by id",
                f.kind().unwrap_or("?"),
                f.priority().as_u16()
            ));
            continue;
        }
        if super::preserve::automatic_u32_table(f) {
            continue;
        }
        for target in super::preserve::mirred_targets(f) {
            match live.names.get(&target) {
                Some(n) => {
                    tree.targets.insert(target, n.to_string());
                }
                None => why.push(format!(
                    "filter {} pref {} on {dev}, which redirects to ifindex {target}, not in this namespace",
                    f.kind().unwrap_or("?"),
                    f.priority().as_u16()
                )),
            }
        }
        tree.filters.push(TcObject::from_live(f));
    }
    (!tree.is_empty()).then_some(tree)
}

/// A route the way `ip route` names it, for a reason it cannot be put back.
fn route_label(r: &RouteMessage, names: &HashMap<u32, &str>) -> String {
    let dst = r.destination.unwrap_or(if r.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    });
    let mut s = format!("{dst}/{} table {}", r.dst_len(), r.table_id());
    if let Some(dev) = r.oif().and_then(|i| names.get(&i)) {
        s.push_str(&format!(" dev {dev}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::config::NetworkConfig;
    use crate::netlink::config::types::BondMode;

    /// Each link of `cfg` as the kernel would dump it, and the names, with
    /// a veth's or netkit's peer as its `IFLA_LINK`, as a dump has it.
    fn synthesized(cfg: &NetworkConfig) -> (Vec<LinkMessage>, HashMap<u32, String>) {
        let mut index: HashMap<String, u32> = cfg
            .links
            .iter()
            .enumerate()
            .map(|(i, l)| (l.name.clone(), i as u32 + 1))
            .collect();
        for l in &cfg.links {
            if let DeclaredLinkType::Veth { peer, .. } | DeclaredLinkType::Netkit { peer, .. } = &l.link_type {
                let next = index.len() as u32 + 1;
                index.entry(peer.clone()).or_insert(next);
            }
        }
        let links = cfg
            .links
            .iter()
            .map(|l| {
                let mut live = super::super::kind::synthesize(l, &index)
                    .unwrap_or_else(|| panic!("{} synthesizes", l.name));
                if let DeclaredLinkType::Veth { peer, .. } | DeclaredLinkType::Netkit { peer, .. } =
                    &l.link_type
                {
                    live.link = index.get(peer).copied();
                }
                live
            })
            .collect();
        let names = index.into_iter().map(|(n, i)| (i, n)).collect();
        (links, names)
    }

    /// Every kind a declaration has reads back as the declaration that made
    /// it, each parameter set off its default where it has one (#745). An
    /// equality, not just an empty comparison: `compare` leaves out what a
    /// declaration leaves unset, and so would not see a parameter read
    /// back wrong.
    #[test]
    fn every_kind_reads_back_as_its_declaration() {
        use crate::netlink::link::{ErspanDirection, ErspanVersion, Ip6tnlMode};
        let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        let cfg = NetworkConfig::new()
            .link("lower", |l| l.dummy())
            .link("d0", |l| l.dummy())
            .link("ifb0", |l| l.ifb())
            .link("ovpn0", |l| l.ovpn())
            .link("br0", |l| l.bridge())
            .link("ve0", |l| l.veth("ve1"))
            .link("vl0", |l| l.vlan("lower", 42).vlan_protocol(VlanProtocol::Dot1ad))
            .link("vl1", |l| l.vlan("lower", 43))
            .link("vx0", |l| {
                l.vxlan(100)
                    .vxlan_remote(v4("10.0.0.2").into())
                    .vxlan_local(v4("10.0.0.1").into())
                    .vxlan_port(4789)
                    .vxlan_underlay_dev("lower")
            })
            .link("vx6", |l| l.vxlan(101).vxlan_local(v6("fd00::1").into()).vxlan_port(8472))
            .link("mv0", |l| l.macvlan("lower").macvlan_mode(MacvlanMode::Private))
            .link("mt0", |l| l.macvtap("lower").macvtap_mode(MacvlanMode::Vepa))
            .link("iv0", |l| {
                l.ipvlan("lower")
                    .ipvlan_mode(IpvlanMode::L3)
                    .ipvlan_isolation(IpvlanIsolation::Private)
            })
            .link("gre0", |l| {
                l.gre()
                    .tunnel_local(v4("10.1.0.1"))
                    .tunnel_remote(v4("10.1.0.2"))
                    .tunnel_ttl(64)
                    .tunnel_key(7)
                    .tunnel_underlay_dev("lower")
            })
            .link("gt0", |l| l.gretap().tunnel_remote(v4("10.1.0.3")).tunnel_key(8))
            .link("ipip0", |l| l.ipip().tunnel_local(v4("10.1.0.1")).tunnel_ttl(10))
            .link("sit0", |l| l.sit().tunnel_remote(v4("10.1.0.4")))
            .link("vti0", |l| l.vti().tunnel_remote(v4("10.1.0.5")).tunnel_key(9))
            .link("t6", |l| {
                l.ip6tnl()
                    .ip6tnl_local(v6("fd01::1"))
                    .ip6tnl_remote(v6("fd01::2"))
                    .ip6tnl_hoplimit(32)
                    .ip6tnl_encap_limit(2)
                    .ip6tnl_mode(Ip6tnlMode::Ip6ip6)
                    .tunnel_underlay_dev("lower")
            })
            .link("g6", |l| l.ip6gre().ip6tnl_remote(v6("fd01::3")).ip6tnl_hoplimit(9).ip6tnl_encap_limit(4).tunnel_key(11))
            .link("gt6", |l| l.ip6gretap().ip6tnl_local(v6("fd01::4")).ip6tnl_hoplimit(64).ip6tnl_encap_limit(4))
            .link("vti6", |l| l.vti6().ip6tnl_remote(v6("fd01::5")).tunnel_key(12))
            .link("es0", |l| {
                l.erspan(5)
                    .erspan_local(v4("10.2.0.1"))
                    .erspan_remote(v4("10.2.0.2"))
                    .erspan_ttl(20)
                    .erspan_version(ErspanVersion::V2 {
                        direction: ErspanDirection::Egress,
                        hwid: 3,
                    })
            })
            .link("es6", |l| {
                l.ip6erspan(6)
                    .erspan_remote(v6("fd02::2"))
                    .erspan_ttl(30)
                    .erspan_version(ErspanVersion::V1 { index: 77 })
            })
            .link("xf0", |l| l.xfrm(9).tunnel_underlay_dev("lower"))
            .link("gn0", |l| {
                l.geneve(9)
                    .geneve_remote(v4("10.3.0.2").into())
                    .geneve_ttl(5)
                    .geneve_tos(3)
                    .geneve_port(6082)
            })
            .link("ms0", |l| {
                l.macsec("lower")
                    .macsec_sci(0x0011_2233_4455_0001)
                    .macsec_encrypt(true)
                    .macsec_protect(true)
                    .macsec_include_sci(true)
                    .macsec_replay_window(32)
            })
            .link("bu0", |l| l.bareudp(6635, 0x8847).bareudp_srcport_min(1000).bareudp_multiproto(true))
            .link("bo0", |l| {
                l.bond()
                    .bond_mode(BondMode::Ieee802_3ad)
                    .miimon(100)
                    .xmit_hash_policy(XmitHashPolicy::Layer34)
                    .min_links(1)
                    .bond_ad_select(AdSelect::Bandwidth)
                    .bond_lacp_rate(LacpRate::Fast)
                    .bond_downdelay(200)
                    .bond_updelay(300)
                    .bond_resend_igmp(2)
            })
            .link("bo1", |l| l.bond().bond_mode(BondMode::ActiveBackup))
            .link("vrf0", |l| l.vrf(10))
            .link("nk0", |l| {
                l.netkit("nk1")
                    .netkit_mode(NetkitMode::L2)
                    .netkit_primary_policy(NetkitPolicy::Blackhole)
                    .netkit_peer_policy(NetkitPolicy::Forward)
                    .netkit_scrub(NetkitScrub::None)
                    .netkit_peer_scrub(NetkitScrub::Default)
            });
        let (links, names) = synthesized(&cfg);
        let names: HashMap<u32, &str> = names.iter().map(|(i, n)| (*i, n.as_str())).collect();
        for (declared, live) in cfg.links.iter().zip(&links) {
            let back = kind_from_live(live, &names)
                .unwrap_or_else(|e| panic!("{}: {e}", declared.name));
            assert_eq!(back, declared.link_type, "{}", declared.name);
        }
    }

    /// A bridge's options read back as they were declared, the timers
    /// through the kernel's hundredths of a second.
    #[test]
    fn bridge_options_read_back() {
        use std::time::Duration;
        let cfg = NetworkConfig::new().link("br0", |l| {
            l.bridge().bridge_options(|b| {
                b.vlan_filtering(true)
                    .vlan_default_pvid(7)
                    .stp(true)
                    .priority(4096)
                    .ageing_time(Duration::from_secs(120))
                    .forward_delay(Duration::from_secs(4))
                    .hello_time(Duration::from_secs(1))
                    .max_age(Duration::from_secs(10))
            })
        });
        let (links, _) = synthesized(&cfg);
        assert_eq!(Some(bridge_from_live(&links[0])), cfg.links[0].bridge);
    }

    /// A kind no declaration has, and a lower device in another namespace,
    /// say so rather than read back as something else.
    #[test]
    fn what_has_no_declaration_says_why() {
        let cfg = NetworkConfig::new().link("lower", |l| l.dummy()).link("v0", |l| l.vlan("lower", 5));
        let (mut links, names) = synthesized(&cfg);
        let names: HashMap<u32, &str> = names.iter().map(|(i, n)| (*i, n.as_str())).collect();
        links[1].link_netnsid = Some(3);
        let why = kind_from_live(&links[1], &names).unwrap_err();
        assert!(why.contains("another namespace"), "{why}");
        links[0].link_info.as_mut().unwrap().kind = Some("wireguard".into());
        let why = kind_from_live(&links[0], &names).unwrap_err();
        assert!(why.contains("of kind wireguard, which no declaration has"), "{why}");
    }
}
