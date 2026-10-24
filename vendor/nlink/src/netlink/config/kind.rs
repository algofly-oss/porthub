//! Link-kind parameters: what the kernel holds for a declared link's kind
//! (a VLAN's id, a VXLAN's VNI, a bond's mode, …), compared with the
//! declaration, and what an apply has to do when they differ.
//!
//! Until #417 the diff compared a link's MTU, MAC, master and state and
//! nothing about its kind, so a changed VNI, VLAN id or bond mode on an
//! existing link was an empty diff and the kernel kept the old value.
//!
//! A parameter that differs is either changed in place — an
//! `RTM_NEWLINK` carrying only `IFLA_LINKINFO`, which `rtnl_newlink` hands
//! to the kind's `changelink` — or, where that `changelink` refuses or
//! silently ignores it, by deleting the link and creating it again. Which
//! is which was read from the kernel source (v6.12) per parameter:
//!
//! | Parameter | Kernel | Here |
//! |---|---|---|
//! | VLAN id, protocol | `vlan_changelink` applies only `IFLA_VLAN_FLAGS` and the QoS maps; it ignores `IFLA_VLAN_ID`/`IFLA_VLAN_PROTOCOL` and returns 0 | recreate |
//! | VLAN / macvlan lower device | nothing changes `IFLA_LINK` on a live link | recreate |
//! | VXLAN VNI, port | `vxlan_nl2conf`: "Cannot change VNI", "Cannot change port" (EOPNOTSUPP) | recreate |
//! | VXLAN remote, local, same family | `vxlan_nl2conf` takes them | in place |
//! | VXLAN address family | `vxlan_nl2conf`: "New group address family does not match old group" (EOPNOTSUPP) | recreate |
//! | VXLAN lower device, set or moved | `vxlan_changelink` moves it (`netdev_adjacent_change_*`) | in place |
//! | VXLAN lower device, removed | `vxlan_config_apply` only assigns `remote_ifindex` when there is a new lower device, so the old one stays | recreate |
//! | bond mode | `BOND_OPT_MODE` is `BOND_OPTFLAG_NOSLAVES \| BOND_OPTFLAG_IFDOWN` | recreate |
//! | bond `lacp_rate`, `ad_select` | `BOND_OPTFLAG_IFDOWN`: EBUSY on a bond that is up | recreate |
//! | bond `miimon`, `updelay`, `downdelay`, `xmit_hash_policy`, `min_links`, `resend_igmp` | no flags | in place |
//! | macvlan mode | `macvlan_changelink` takes it, except into or out of passthru (EINVAL) | in place / recreate |
//! | VRF table | `vrf_link_ops` has no `changelink`, so `rtnl_newlink` answers EOPNOTSUPP | recreate |
//! | netkit policies | `netkit_change_link` takes them on the primary | in place |
//! | netkit mode, scrub | `netkit_change_link`: "cannot be changed after device creation" (EACCES) | refused |
//! | the kind itself | — | recreate |
//!
//! A recreate deletes the link, and the kernel takes with it everything
//! that hangs off it: its addresses, the routes through it, its qdiscs,
//! the links stacked on it (a VLAN or macvlan on its lower device, a
//! VXLAN on its underlay — `vlan_device_event`, `macvlan_device_event`,
//! `vxlan_handle_lowerdev_unregister`), and its ports, which are released
//! (`bond_uninit` → `__bond_release_one`, which closes each one). The
//! diff therefore treats a recreated link as absent, so that what the
//! config declares on it — addresses, routes, qdiscs, stacked links,
//! ports — is put back by the same apply. What the config does *not*
//! declare cannot be put back, so a recreate that would destroy any of it
//! is refused, naming what it would destroy, the way an in-place HTB
//! `default_class` edit is (#402). A netkit pair is never recreated: its
//! peer usually lives in another namespace, which no declaration here
//! describes.
//!
//! Some of what a deleted link takes with it cannot be declared at all,
//! so wherever it exists it blocks the recreate (#426): FDB entries a user
//! or a controller added (a VXLAN's head-end replication list, a bridge's
//! static entries), permanent and proxy neighbours (`neigh_ifdown`),
//! nexthop objects (`nexthop_flush_dev`), and multipath and nexthop-object
//! routes through the link, whose dump carries no `RTA_OIF` for it (an
//! IPv4 multipath route goes whole: `fib_sync_down_dev` counts every
//! nexthop dead on NETDEV_UNREGISTER). The kernel's own FDB entries are
//! told apart by what makes them: a device's unicast and multicast address
//! lists (`ndo_dflt_fdb_dump` — the stack's multicast joins, and the MACs
//! of links stacked on it), a bridge port's or bridge's own MAC, and a
//! VXLAN's default remote (`__vxlan_dev_create`).
//!
//! The ports of a deleted bond or VRF stay, but leaving it flushes them as
//! a link going down does — `__bond_release_one` closes the port, and an
//! L3-master change makes `fib_netdev_event` and `addrconf_notify` flush
//! its routes, IPv6 addresses and neighbours — so what of that the config
//! does not declare blocks too; except routes in the deleted VRF's own
//! table, which nothing reaches once the VRF is gone.
//!
//! An optional parameter left undeclared is compared against the
//! kernel's default where that default is fixed in the kernel (a VLAN's
//! 802.1Q, no VXLAN remote/local/underlay, netkit's L3 mode and forward
//! policies), so a knob dropped from a declaration is reset rather than
//! left as it was. Where the default comes from a module parameter (the
//! VXLAN port — `vxlan`'s `udp_port`, 8472 unless set — and every bond
//! option), an undeclared parameter is not compared.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::diff::{PlanOptions, purgeable_address, purgeable_route};
use super::types::{
    DeclaredFdb, DeclaredLink, DeclaredLinkType, DeclaredNeighbour, NetworkConfig, QdiscParent,
};
use crate::netlink::{
    attr::AttrIter,
    connection::Connection,
    error::Result,
    link::{
        BondMode as KernelBondMode, MacvlanMode as KernelMacvlanMode, NetkitMode, NetkitPolicy,
        NetkitScrub, VlanProtocol, bond_attr, macvlan, netkit, vlan, vrf_attr, vxlan,
    },
    messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, TcMessage},
    nexthop::Nexthop,
    protocol::Route,
    types::{
        addr::Scope,
        neigh::{ntf, nud},
        route::RouteProtocol,
    },
};

/// A veth's or netkit's peer the apply renames to the name its pair
/// declares (#804). The peer is down for the rename, which the kernel
/// refuses on a running device, and comes back up after it.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LinkRename {
    /// The name it has.
    pub from: String,
    /// The name it is given.
    pub to: String,
    /// The veth or netkit link whose peer it is.
    pub peer_of: String,
}

impl std::fmt::Display for LinkRename {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "~ link {} -> {} (peer of {})", self.from, self.to, self.peer_of)
    }
}

/// A link the apply deletes and creates again, because a declared
/// parameter cannot be changed on a live link.
///
/// The recreated link itself is also in
/// [`ConfigDiff::links_to_add`](super::ConfigDiff::links_to_add), and what
/// the config declares on it — addresses, routes, qdiscs, ports, links
/// stacked on it — in the other `*_to_add` / `links_to_modify` lists, since
/// deleting the link deletes them.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinkRecreate {
    /// The link.
    pub name: String,
    /// Why: the parameters that differ (`vxlan vni 100 -> 200`), or the
    /// link it is stacked on.
    pub reason: String,
    /// What deleting the link would destroy that the config does not
    /// declare, and so cannot restore, or why it cannot be recreated at
    /// all. Non-empty means the apply refuses, with
    /// [`ErrorDetail::NotSupported`](crate::ErrorDetail::NotSupported), rather than
    /// recreate the link; nothing else in the diff depends on it then.
    /// Typed since 0.32 (#513); each blocker's `Display` is the text the
    /// list held before.
    pub blocked_by: Vec<Blocker>,
    /// What the recreated link loses that the config does not declare and
    /// the kernel does not keep: its alias, and a MAC address the kernel
    /// picks again (#513). Its sysctls (`net.ipv4.conf.<link>.*`,
    /// `net.ipv6.conf.<link>.*`) return to their defaults too.
    pub resets: Vec<String>,
    /// What the recreate destroys that the caller owns
    /// ([`Owned`]) or the [`RecreatePolicy`] lets go: for the caller to put
    /// back (#513).
    pub destroys: Vec<Blocker>,
    /// The link's TC tree that the config does not declare, kept to be put
    /// back after the recreate, with
    /// [`PlanOptions::preserve_undeclared_tc`](super::PlanOptions::preserve_undeclared_tc)
    /// (#645).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub preserved_tc: Option<super::preserve::PreservedTc>,
    /// What the recreate deletes, read back as declarations: what its
    /// inverse puts back (#745). On the recreated link the others were
    /// stacked on; `None` on those, and when something cannot be put back.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub restore: Option<Box<super::restore::LinkRestore>>,
    /// What the recreate deletes that no declaration can put back, which
    /// leaves it without an inverse (#745).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub unrestorable: Vec<String>,
}

/// How sure an offline prediction is (#513).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Certainty {
    /// The declarations alone decide it: the link is recreated.
    Certain,
    /// The previous config left a parameter to a module parameter's
    /// default (the VXLAN port, a bond option), which only the kernel
    /// knows: the link is recreated if that default differs from what the
    /// new config declares.
    IfKernelDefaultDiffers,
}

/// A link [`NetworkConfig::diff_against`] predicts is recreated (#513).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct OfflineRecreate {
    /// The link.
    pub name: String,
    /// Why: the parameters that differ, or the link it is stacked on.
    pub reason: String,
    /// How sure the prediction is.
    pub certainty: Certainty,
}

/// What changing from one config to another recreates, predicted without
/// a kernel (#513). See [`NetworkConfig::diff_against`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct OfflineDiff {
    /// The links recreated, lower devices first.
    pub recreates: Vec<OfflineRecreate>,
}

impl OfflineDiff {
    /// True when nothing is recreated.
    pub fn is_empty(&self) -> bool {
        self.recreates.is_empty()
    }
}

impl std::fmt::Display for OfflineDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lines: Vec<String> = self
            .recreates
            .iter()
            .map(|r| match r.certainty {
                Certainty::Certain => format!("-/+ link {} (recreate: {})", r.name, r.reason),
                Certainty::IfKernelDefaultDiffers => {
                    format!("-/+? link {} (recreate if: {})", r.name, r.reason)
                }
            })
            .collect();
        f.write_str(&lines.join("\n"))
    }
}

/// The recreates going from `previous` to `config`, decided by the same
/// [`compare`] a live diff runs, against the link the kernel would hold
/// for `previous`: its declaration encoded as `create_link` sends it and
/// read back as a dump. Nothing about the live state can be known, so
/// only recreates are predicted, not what would block them (#513).
pub(crate) fn diff_against(config: &NetworkConfig, previous: &NetworkConfig) -> OfflineDiff {
    // An ifindex for every name either config mentions, so parents and
    // underlays resolve as they do in a dump.
    let mut index: HashMap<String, u32> = HashMap::new();
    let mentioned = previous
        .links
        .iter()
        .chain(config.links.iter())
        .flat_map(|l| {
            std::iter::once(l.name.as_str())
                .chain(super::diff::declared_lower(l))
                .chain(l.master.name())
        });
    for name in mentioned {
        let next = index.len() as u32 + 1;
        index.entry(name.to_string()).or_insert(next);
    }
    let names: HashMap<u32, &str> = index.iter().map(|(n, i)| (*i, n.as_str())).collect();

    let synthesize = |prev: &DeclaredLink| synthesize(prev, &index);

    let mut recreates: Vec<OfflineRecreate> = Vec::new();
    for link in &config.links {
        let Some(prev) = previous.links.iter().find(|p| p.name == link.name) else {
            continue;
        };
        if prev.link_type.kind().is_none() || link.link_type.kind().is_none() {
            continue;
        }
        let Some(live) = synthesize(prev) else {
            continue;
        };
        let d = compare(link, &live, &names);
        if !d.recreate.is_empty() || !d.refuse.is_empty() {
            let mut reasons = d.refuse.clone();
            reasons.extend(d.recreate);
            recreates.push(OfflineRecreate {
                name: link.name.clone(),
                reason: reasons.join(", "),
                certainty: Certainty::Certain,
            });
        } else if let Some(reason) = undeclared_module_default(link, prev) {
            recreates.push(OfflineRecreate {
                name: link.name.clone(),
                reason,
                certainty: Certainty::IfKernelDefaultDiffers,
            });
        }
    }
    // The links stacked on a recreated one go with it, as surely as it does.
    loop {
        let mut grew = false;
        for link in &config.links {
            if recreates.iter().any(|r| r.name == link.name) {
                continue;
            }
            let Some(lower) = super::diff::declared_lower(link) else {
                continue;
            };
            let Some(certainty) = recreates
                .iter()
                .find(|r| r.name == lower)
                .map(|r| r.certainty)
            else {
                continue;
            };
            if previous.links.iter().any(|p| p.name == link.name) {
                recreates.push(OfflineRecreate {
                    name: link.name.clone(),
                    reason: format!("it is stacked on {lower}, which is recreated"),
                    certainty,
                });
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    OfflineDiff { recreates }
}

/// The link the kernel holds for a declaration: encoded as `create_link`
/// sends it, with `index` for the ifindexes of the links it names, and read
/// back as a dump. What the kernel dumps for a parameter left out is its
/// fixed default, which `compare` takes as declared (#513).
pub(super) fn synthesize(prev: &DeclaredLink, index: &HashMap<String, u32>) -> Option<LinkMessage> {
    use crate::netlink::interface_ref::InterfaceRef;
    let mut prev = prev.clone();
    // What the kernel dumps for a parameter left out: its fixed
    // default, which `compare` takes as declared.
    match &mut prev.link_type {
        DeclaredLinkType::Vlan { protocol, .. } => {
            protocol.get_or_insert(crate::netlink::link::VlanProtocol::Dot1q);
        }
        DeclaredLinkType::Netkit {
            mode,
            primary_policy,
            peer_policy,
            ..
        } => {
            mode.get_or_insert(crate::netlink::link::NetkitMode::L3);
            primary_policy.get_or_insert(crate::netlink::link::NetkitPolicy::Forward);
            peer_policy.get_or_insert(crate::netlink::link::NetkitPolicy::Forward);
        }
        _ => {}
    }
    let link_config = super::apply::link_config(&prev)?;
    let parent = link_config.parent_ref().and_then(|r| match r {
        InterfaceRef::Name(n) => index.get(n.as_str()).copied(),
        InterfaceRef::Index(i) => Some(*i),
    });
    let mut b = crate::netlink::builder::MessageBuilder::new(
        crate::netlink::message::NlMsgType::RTM_NEWLINK,
        0,
    );
    b.append(
        &crate::netlink::types::link::IfInfoMsg::new().with_index(index[&prev.name] as i32),
    );
    link_config.write_to(&mut b, parent);
    let bytes = b.finish();
    <LinkMessage as crate::netlink::parse::FromNetlink>::from_bytes(&bytes[16..]).ok()
}

/// A recreating parameter the new config declares and the previous one
/// left to a module parameter's default, which only the kernel knows.
fn undeclared_module_default(new: &DeclaredLink, prev: &DeclaredLink) -> Option<String> {
    match (&new.link_type, &prev.link_type) {
        (
            DeclaredLinkType::Vxlan { port: Some(p), .. },
            DeclaredLinkType::Vxlan { port: None, .. },
        ) => Some(format!(
            "vxlan port was the module default (vxlan udp_port, 8472 unless set), now {p}"
        )),
        (
            DeclaredLinkType::Bond {
                lacp_rate: Some(_), ..
            },
            DeclaredLinkType::Bond {
                lacp_rate: None, ..
            },
        ) => Some("bond lacp_rate was the module default, now declared".to_string()),
        (
            DeclaredLinkType::Bond {
                ad_select: Some(_), ..
            },
            DeclaredLinkType::Bond {
                ad_select: None, ..
            },
        ) => Some("bond ad_select was the module default, now declared".to_string()),
        _ => None,
    }
}

/// What a diff does with a recreate (or a removal) that would destroy what
/// the config does not declare (#513).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum RecreatePolicy {
    /// Refuse it: the apply fails before anything changes, naming what
    /// would be lost. The default.
    #[default]
    Refuse,
    /// Let it through: what it destroys is reported in
    /// [`ApplyResult::destroyed`](super::ApplyResult::destroyed), for the
    /// caller to put back.
    Allow,
    /// Let it through when every blocker passes the filter: "the TC on
    /// these devices", "routes a routing daemon re-learns". Otherwise
    /// refuse it, as [`Refuse`](Self::Refuse) does.
    AllowDestroying(BlockerFilter),
}

impl RecreatePolicy {
    /// Whether a deletion that would destroy `blockers` goes ahead.
    pub(crate) fn allows(&self, blockers: &[Blocker]) -> bool {
        match self {
            Self::Refuse => blockers.is_empty(),
            Self::Allow => true,
            Self::AllowDestroying(filter) => blockers.iter().all(|b| filter.allows(b)),
        }
    }
}

/// The blockers a [`RecreatePolicy::AllowDestroying`] lets go.
///
/// ```
/// use nlink::netlink::config::{Blocker, BlockerFilter, RecreatePolicy};
/// use nlink::netlink::types::route::RouteProtocol;
///
/// // FRR re-learns its routes; anything else still refuses the recreate.
/// let policy = RecreatePolicy::AllowDestroying(BlockerFilter::new(|b| {
///     matches!(b, Blocker::Route { protocol, .. }
///         if matches!(protocol, RouteProtocol::Zebra | RouteProtocol::Bgp | RouteProtocol::Ospf))
/// }));
/// # let _ = policy;
/// ```
#[derive(Clone)]
pub struct BlockerFilter(std::sync::Arc<dyn Fn(&Blocker) -> bool + Send + Sync>);

impl BlockerFilter {
    /// A filter that lets a blocker go when `f` says so.
    pub fn new(f: impl Fn(&Blocker) -> bool + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(f))
    }

    /// Whether this blocker may be destroyed.
    pub fn allows(&self, blocker: &Blocker) -> bool {
        (self.0)(blocker)
    }
}

impl std::fmt::Debug for BlockerFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlockerFilter(..)")
    }
}

/// State the caller manages itself, next to a `NetworkConfig` (#513): never
/// a reason to refuse a recreate or removal, never purged. A recreate that
/// takes it with the link reports it in
/// [`ApplyResult::destroyed`](super::ApplyResult::destroyed), for the caller
/// to put back.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Owned {
    /// The root qdisc of `dev`, and the TC tree under it: classes, leaf
    /// qdiscs, filters.
    RootQdisc {
        /// The device.
        dev: String,
    },
    /// The ingress or clsact qdisc of `dev`, and its filters.
    IngressQdisc {
        /// The device.
        dev: String,
    },
    /// Every route in this table.
    RouteTable {
        /// The table.
        table: u32,
    },
}

impl Owned {
    /// Whether this covers `blocker`.
    pub(crate) fn covers(&self, blocker: &Blocker) -> bool {
        match (self, blocker) {
            (
                Self::RootQdisc { dev } | Self::IngressQdisc { dev },
                Blocker::Qdisc { dev: d, .. },
            )
            | (
                Self::RootQdisc { dev } | Self::IngressQdisc { dev },
                Blocker::Class { dev: d, .. },
            )
            | (
                Self::RootQdisc { dev } | Self::IngressQdisc { dev },
                Blocker::Filter { dev: d, .. },
            ) => dev == d,
            (Self::RouteTable { table }, Blocker::Route { table: t, .. }) => table == t,
            _ => false,
        }
    }
}

/// A link the previous config declared and this one does not, which the
/// apply deletes (#512), with the links the kernel deletes along with it.
///
/// Only a link the previous config gave a kind, still in the kernel with
/// that kind: never a physical or kindless device, and never a link of the
/// same name another actor made since. Deleting it would also destroy what
/// it carries; what no config declared there refuses the removal, as it
/// refuses a recreate.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinkRemoval {
    /// The link.
    pub name: String,
    /// Its kind.
    pub link_kind: String,
    /// The removed link it is stacked on, for one the kernel deletes with
    /// it.
    pub stacked_on: Option<String>,
    /// What deleting it would destroy that no config declares. Non-empty
    /// means the apply refuses, with
    /// [`ErrorDetail::NotSupported`](crate::ErrorDetail::NotSupported).
    pub blocked_by: Vec<Blocker>,
    /// What deleting it destroys that the caller owns or the
    /// [`RecreatePolicy`] lets go (#513).
    pub destroys: Vec<Blocker>,
    /// What deleting it takes, read back as declarations: what its inverse
    /// puts back (#745). On the removed link the others were stacked on;
    /// `None` on those, and when something cannot be put back.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub restore: Option<Box<super::restore::LinkRestore>>,
    /// What deleting it takes that no declaration can put back, which
    /// leaves the removal without an inverse (#745).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub unrestorable: Vec<String>,
}

impl LinkRemoval {
    /// True when the apply will refuse this removal (see
    /// [`blocked_by`](Self::blocked_by)).
    pub fn is_refused(&self) -> bool {
        !self.blocked_by.is_empty()
    }
}

impl std::fmt::Display for LinkRemoval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "- link {} ({}", self.name, self.link_kind)?;
        if let Some(lower) = &self.stacked_on {
            write!(f, ", stacked on {lower}")?;
        }
        f.write_str(")")?;
        if !self.blocked_by.is_empty() {
            let blockers: Vec<String> = self.blocked_by.iter().map(ToString::to_string).collect();
            write!(
                f,
                " refused: deleting it would destroy what no config declares: {}",
                blockers.join(", ")
            )?;
        }
        Ok(())
    }
}

/// One reason a link cannot be recreated (#513): something deleting it
/// would destroy that the config does not declare, or a link that cannot
/// be recreated at all.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Blocker {
    /// An address the config does not declare, on the link or on one the
    /// kernel deletes or flushes with it.
    Address {
        /// The device it is on.
        dev: String,
        /// The address.
        address: IpAddr,
        /// Its prefix length.
        prefix_len: u8,
    },
    /// A route the config does not declare through the link.
    Route {
        /// The device it goes through.
        dev: String,
        /// Its destination.
        destination: IpAddr,
        /// Its prefix length.
        prefix_len: u8,
        /// Its table.
        table: u32,
        /// The nexthop object it uses, if any.
        nhid: Option<u32>,
        /// How it goes through the device, when not as its output
        /// device (`"via a nexthop object on"`, …).
        through: Option<String>,
        /// Who added it (`ip route`'s `proto`): a routing daemon re-learns
        /// its own routes, so a [`RecreatePolicy`] may let those go.
        #[cfg_attr(feature = "schemars", schemars(with = "u8"))]
        #[cfg_attr(
            feature = "serde",
            serde(serialize_with = "serialize_protocol", deserialize_with = "deserialize_protocol")
        )]
        protocol: RouteProtocol,
    },
    /// A qdisc the config does not declare, or one under a class, which
    /// it cannot declare.
    Qdisc {
        /// The device it is on.
        dev: String,
        /// Its kind.
        qdisc: String,
        /// Its handle and parent, for one under a class.
        under: Option<(crate::TcHandle, crate::TcHandle)>,
    },
    /// A class someone made (HTB, HFSC, DRR, QFQ, CBQ).
    Class {
        /// The device it is on.
        dev: String,
        /// Its qdisc's kind.
        qdisc: String,
        /// Its handle.
        handle: crate::TcHandle,
    },
    /// A filter.
    Filter {
        /// The device it is on.
        dev: String,
        /// Its kind.
        filter: String,
        /// Its priority.
        priority: u16,
        /// Its parent.
        parent: crate::TcHandle,
    },
    /// An FDB entry a user or a controller made.
    Fdb {
        /// How `bridge fdb` would name it.
        entry: String,
        /// The link it sends through, when it is on another device: it
        /// would point at the deleted link's old ifindex.
        via: Option<String>,
    },
    /// A permanent or externally learned neighbour.
    Neighbour {
        /// The device it is on.
        dev: String,
        /// Its address.
        destination: IpAddr,
        /// Permanent rather than externally learned.
        permanent: bool,
    },
    /// A proxy neighbour.
    ProxyNeighbour {
        /// The device it is on.
        dev: String,
        /// Its address.
        destination: IpAddr,
    },
    /// A nexthop object.
    Nexthop {
        /// The device it is on.
        dev: String,
        /// Its id.
        id: u32,
        /// Its gateway, if any.
        via: Option<IpAddr>,
    },
    /// A link stacked on the recreated one, which the kernel deletes with
    /// it, and which the config does not create.
    StackedLink {
        /// The link.
        name: String,
        /// Its kind.
        link_kind: String,
        /// The link it is on.
        lower: String,
        /// The config declares it, but as an existing device, not one to
        /// create.
        declared_existing: bool,
    },
    /// A port the kernel releases when its master is deleted.
    Port {
        /// The port.
        name: String,
        /// Its master.
        master: String,
    },
    /// A veth's or vxcan's peer in another namespace, which the kernel
    /// deletes with it and nothing here can declare.
    ForeignNetnsPeer {
        /// The link whose peer it is.
        link: String,
        /// The peer's namespace, as this one numbers it.
        netnsid: i32,
    },
    /// The link cannot be recreated at all: a device with no link kind,
    /// a pair whose peer a recreate would delete, ….
    Unsupported {
        /// Why.
        reason: String,
    },
}

impl std::fmt::Display for Blocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address {
                dev,
                address,
                prefix_len,
            } => write!(f, "address {address}/{prefix_len} on {dev}"),
            Self::Route {
                dev,
                destination,
                prefix_len,
                table,
                nhid,
                through,
                ..
            } => {
                let nhid = nhid.map(|id| format!(" nhid {id}")).unwrap_or_default();
                match through {
                    None => write!(
                        f,
                        "route {destination}/{prefix_len}{nhid} dev {dev} table {table}"
                    ),
                    Some(how) => {
                        write!(
                            f,
                            "route {destination}/{prefix_len}{nhid} table {table}, {how} {dev}"
                        )
                    }
                }
            }
            Self::Qdisc { dev, qdisc, under } => match under {
                None => write!(f, "qdisc {qdisc} on {dev}"),
                Some((handle, parent)) => {
                    write!(f, "qdisc {qdisc} {handle} on {dev} (under {parent})")
                }
            },
            Self::Class { dev, qdisc, handle } => write!(f, "class {qdisc} {handle} on {dev}"),
            Self::Filter {
                dev,
                filter,
                priority,
                parent,
            } => write!(
                f,
                "filter {filter} pref {priority} on {dev} (parent {parent})"
            ),
            Self::Fdb { entry, via } => match via {
                None => f.write_str(entry),
                Some(link) => write!(
                    f,
                    "{entry} via {link}, which would point at the deleted {link}"
                ),
            },
            Self::Neighbour {
                dev,
                destination,
                permanent,
            } => {
                let what = if *permanent {
                    "permanent"
                } else {
                    "externally learned"
                };
                write!(f, "neighbour {destination} dev {dev} ({what})")
            }
            Self::ProxyNeighbour { dev, destination } => {
                write!(f, "proxy neighbour {destination} dev {dev}")
            }
            Self::Nexthop { dev, id, via } => {
                let via = via.map(|g| format!(" via {g}")).unwrap_or_default();
                write!(f, "nexthop id {id}{via} dev {dev}")
            }
            Self::StackedLink {
                name,
                link_kind,
                lower,
                declared_existing,
            } => {
                write!(
                    f,
                    "link {name} ({link_kind} on {lower}), which the kernel deletes with it"
                )?;
                if *declared_existing {
                    f.write_str(
                        " and the config declares as an existing device, not one to create",
                    )?;
                }
                Ok(())
            }
            Self::Port { name, master } => {
                write!(
                    f,
                    "link {name}, a port of {master}, which the kernel releases"
                )
            }
            Self::ForeignNetnsPeer { link, netnsid } => write!(
                f,
                "the peer of {link}, in another namespace (netnsid {netnsid}), which the kernel \
                 deletes with it"
            ),
            Self::Unsupported { reason } => f.write_str(reason),
        }
    }
}

impl LinkRecreate {
    /// True when the apply will refuse this recreate (see
    /// [`blocked_by`](Self::blocked_by)).
    pub fn is_refused(&self) -> bool {
        !self.blocked_by.is_empty()
    }
}

impl std::fmt::Display for LinkRecreate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.blocked_by.is_empty() {
            write!(f, "-/+ link {} (recreate: {})", self.name, self.reason)?;
            match &self.preserved_tc {
                Some(tc) => write!(f, ", keeping its TC tree: {tc}"),
                None => Ok(()),
            }
        } else {
            write!(
                f,
                "-/+ link {} (recreate refused: {}; it would destroy what the config does not \
                 declare: {})",
                self.name,
                self.reason,
                self.blocked_by
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

/// An in-place change of a live link's kind parameters.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub(crate) struct KindUpdate {
    /// `IFLA_INFO_KIND` — the kernel matches it against the live link.
    pub(crate) kind: String,
    /// The `IFLA_INFO_DATA` attributes to send: only the ones that change.
    pub(crate) attrs: Vec<KindAttr>,
    /// One `name old -> new` line per changed parameter.
    pub(crate) changes: Vec<String>,
    /// The live values the change replaces, as attributes, for its inverse
    /// (#649): `None` where one cannot be sent back (it was the kernel's
    /// default, which no attribute expresses).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) was: Option<Vec<KindAttr>>,
}

/// One `IFLA_INFO_DATA` attribute of a [`KindUpdate`]: the attribute's id
/// and its value, as the kernel's UAPI numbers it, so a plan read back
/// sends the same (#649).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
pub(crate) enum KindAttr {
    U8(u16, u8),
    U16(u16, u16),
    U32(u16, u32),
    Bytes(u16, Vec<u8>),
    /// A link's ifindex, resolved by name when the change is applied — the
    /// link may be created by the same apply.
    Ifindex(u16, String),
}

/// How a declared link's kind parameters differ from the live link's.
#[derive(Debug, Default)]
pub(super) struct KindDiff {
    /// Parameters the kernel cannot change on a live link.
    pub(super) recreate: Vec<String>,
    /// Parameters that cannot change, where a recreate is refused too.
    pub(super) refuse: Vec<String>,
    /// Parameters changed in place.
    pub(super) update: Option<KindUpdate>,
}

impl KindAttr {
    /// Its `IFLA_INFO_DATA` attribute id.
    pub(crate) fn id(&self) -> u16 {
        match self {
            Self::U8(t, _) | Self::U16(t, _) | Self::U32(t, _) | Self::Bytes(t, _) | Self::Ifindex(t, _) => *t,
        }
    }
}

/// The live value of attribute `id` as a [`KindAttr`] of the same shape as
/// `like`, for an inverse (#649): an ifindex as the link's name.
fn live_attr(like: &KindAttr, id: u16, data: &InfoData<'_>, names: &HashMap<u32, &str>) -> Option<KindAttr> {
    let raw = data.0.get(&id)?;
    Some(match like {
        KindAttr::Ifindex(..) => {
            let idx = u32::from_ne_bytes(raw.get(..4)?.try_into().ok()?);
            KindAttr::Ifindex(id, names.get(&idx)?.to_string())
        }
        _ => KindAttr::Bytes(id, raw.to_vec()),
    })
}

/// The live values of the attributes an incremental change sends (#649):
/// its inverse sends them back. `None` when one is absent.
fn was_attrs(attrs: &[KindAttr], data: &InfoData<'_>, names: &HashMap<u32, &str>) -> Option<Vec<KindAttr>> {
    attrs
        .iter()
        .map(|a| match a.id() {
            0 => None,
            id => live_attr(a, id, data, names),
        })
        .collect()
}

/// The live values of a set a kind rebuilds its configuration from (#649):
/// each of `ids` present in the dump, the link `link` by name. Sending
/// them back puts the configuration back.
fn live_set(data: &InfoData<'_>, ids: &[u16], link: Option<u16>, names: &HashMap<u32, &str>) -> Vec<KindAttr> {
    let mut set: Vec<KindAttr> = ids
        .iter()
        .filter_map(|&id| live_attr(&KindAttr::Bytes(id, Vec::new()), id, data, names))
        .collect();
    if let Some(id) = link {
        set.extend(live_attr(&KindAttr::Ifindex(id, String::new()), id, data, names));
    }
    set
}

impl KindDiff {
    fn update(&mut self, kind: &'static str, attr: KindAttr, change: String) {
        let u = self.update.get_or_insert_with(|| KindUpdate {
            kind: kind.to_string(),
            attrs: Vec::new(),
            changes: Vec::new(),
            was: None,
        });
        u.attrs.push(attr);
        u.changes.push(change);
    }
}

/// A live link's `IFLA_INFO_DATA`, by attribute type.
pub(super) struct InfoData<'a>(pub(super) HashMap<u16, &'a [u8]>);

impl<'a> InfoData<'a> {
    pub(super) fn of(link: &'a LinkMessage) -> Self {
        let data = link.link_info().and_then(|i| i.data()).unwrap_or(&[]);
        Self(AttrIter::new(data).collect())
    }

    /// The link's `IFLA_INFO_SLAVE_DATA`: a bridge port's options.
    pub(super) fn slave_of(link: &'a LinkMessage) -> Self {
        let data = link.link_info().and_then(|i| i.slave_data()).unwrap_or(&[]);
        Self(AttrIter::new(data).collect())
    }

    pub(super) fn u8(&self, t: u16) -> Option<u8> {
        self.0.get(&t).and_then(|p| p.first().copied())
    }

    pub(super) fn u16_ne(&self, t: u16) -> Option<u16> {
        let p = self.0.get(&t)?;
        Some(u16::from_ne_bytes(p.get(..2)?.try_into().ok()?))
    }

    pub(super) fn u16_be(&self, t: u16) -> Option<u16> {
        let p = self.0.get(&t)?;
        Some(u16::from_be_bytes(p.get(..2)?.try_into().ok()?))
    }

    pub(super) fn u32(&self, t: u16) -> Option<u32> {
        let p = self.0.get(&t)?;
        Some(u32::from_ne_bytes(p.get(..4)?.try_into().ok()?))
    }

    pub(super) fn u32_be(&self, t: u16) -> Option<u32> {
        let p = self.0.get(&t)?;
        Some(u32::from_be_bytes(p.get(..4)?.try_into().ok()?))
    }

    pub(super) fn ipv4(&self, t: u16) -> Option<Ipv4Addr> {
        let p = self.0.get(&t)?;
        let octets: [u8; 4] = p.get(..4)?.try_into().ok()?;
        Some(Ipv4Addr::from(octets))
    }

    pub(super) fn ipv6(&self, t: u16) -> Option<Ipv6Addr> {
        let p = self.0.get(&t)?;
        let octets: [u8; 16] = p.get(..16)?.try_into().ok()?;
        Some(Ipv6Addr::from(octets))
    }
}

/// The attribute a VXLAN endpoint goes in, by family.
fn vxlan_attr(what: &str, v6: bool) -> u16 {
    match (what, v6) {
        ("local", false) => vxlan::IFLA_VXLAN_LOCAL,
        ("local", true) => vxlan::IFLA_VXLAN_LOCAL6,
        (_, false) => vxlan::IFLA_VXLAN_GROUP,
        (_, true) => vxlan::IFLA_VXLAN_GROUP6,
    }
}

fn vlan_protocol_name(p: u16) -> String {
    match p {
        0x8100 => "802.1Q".to_string(),
        0x88a8 => "802.1ad".to_string(),
        other => format!("{other:#06x}"),
    }
}

fn bond_mode_name(m: u8) -> String {
    match KernelBondMode::try_from(m) {
        Ok(mode) => format!("{mode:?}"),
        Err(_) => m.to_string(),
    }
}

fn or_none(v: Option<impl std::fmt::Display>) -> String {
    v.map_or_else(|| "none".to_string(), |v| v.to_string())
}

pub(super) fn kernel_macvlan_mode(mode: super::types::MacvlanMode) -> KernelMacvlanMode {
    use super::types::MacvlanMode as M;
    match mode {
        M::Private => KernelMacvlanMode::Private,
        M::Vepa => KernelMacvlanMode::Vepa,
        M::Bridge => KernelMacvlanMode::Bridge,
        M::Passthru => KernelMacvlanMode::Passthru,
        M::Source => KernelMacvlanMode::Source,
    }
}

pub(super) fn kernel_bond_mode(mode: super::types::BondMode) -> KernelBondMode {
    use super::types::BondMode as M;
    match mode {
        M::BalanceRr => KernelBondMode::BalanceRr,
        M::ActiveBackup => KernelBondMode::ActiveBackup,
        M::BalanceXor => KernelBondMode::BalanceXor,
        M::Broadcast => KernelBondMode::Broadcast,
        M::Ieee802_3ad => KernelBondMode::Lacp,
        M::BalanceTlb => KernelBondMode::BalanceTlb,
        M::BalanceAlb => KernelBondMode::BalanceAlb,
    }
}

/// The name of the link `live`'s `IFLA_LINK` names, when that is a link in
/// this namespace. `None` for a lower device in another namespace — a
/// declaration made here cannot name it.
pub(super) fn lower_name<'n>(live: &LinkMessage, names: &HashMap<u32, &'n str>) -> Option<&'n str> {
    if live.link_netnsid.is_some() {
        return None;
    }
    live.link().and_then(|i| names.get(&i).copied())
}

/// Compare a declared link's kind parameters with the live link's.
pub(super) fn compare(declared: &DeclaredLink, live: &LinkMessage, names: &HashMap<u32, &str>) -> KindDiff {
    let mut d = KindDiff::default();
    let Some(want_kind) = declared.link_type.kind() else {
        // `Physical`: an existing device, configured but never created, so
        // nothing about its kind is declared.
        return d;
    };
    match live.kind() {
        Some(have) if have == want_kind => {}
        Some(have) => {
            d.recreate.push(format!("kind {have} -> {want_kind}"));
            return d;
        }
        None => {
            d.refuse.push(format!(
                "it is a device with no link kind (a physical NIC?), declared as {want_kind}"
            ));
            return d;
        }
    }
    let data = InfoData::of(live);

    match &declared.link_type {
        DeclaredLinkType::Vlan {
            parent,
            vlan_id,
            protocol,
        } => {
            if let Some(have) = data.u16_ne(vlan::IFLA_VLAN_ID)
                && have != *vlan_id
            {
                d.recreate.push(format!("vlan id {have} -> {vlan_id}"));
            }
            // `vlan_newlink` defaults an absent protocol to 802.1Q.
            let want = protocol.unwrap_or(VlanProtocol::Dot1q).as_u16();
            if let Some(have) = data.u16_be(vlan::IFLA_VLAN_PROTOCOL)
                && have != want
            {
                d.recreate.push(format!(
                    "vlan protocol {} -> {}",
                    vlan_protocol_name(have),
                    vlan_protocol_name(want)
                ));
            }
            if let Some(have) = lower_name(live, names)
                && have != parent.as_str()
            {
                d.recreate.push(format!("vlan parent {have} -> {parent}"));
            }
        }
        DeclaredLinkType::Vxlan {
            vni,
            remote,
            local,
            port,
            underlay_dev,
        } => {
            if let Some(have) = data.u32(vxlan::IFLA_VXLAN_ID)
                && have != *vni
            {
                d.recreate.push(format!("vxlan vni {have} -> {vni}"));
            }
            if let (Some(want), Some(have)) = (port, data.u16_be(vxlan::IFLA_VXLAN_PORT))
                && have != *want
            {
                d.recreate.push(format!("vxlan port {have} -> {want}"));
            }
            let have_underlay = data
                .u32(vxlan::IFLA_VXLAN_LINK)
                .map(|i| names.get(&i).map_or_else(|| format!("ifindex {i}"), |n| n.to_string()));
            match (underlay_dev.as_deref(), have_underlay.as_deref()) {
                (Some(want), Some(have)) if want == have => {}
                (Some(want), have) => d.update(
                    "vxlan",
                    KindAttr::Ifindex(vxlan::IFLA_VXLAN_LINK, want.to_string()),
                    format!("vxlan underlay {} -> {want}", or_none(have)),
                ),
                (None, Some(have)) => d.recreate.push(format!("vxlan underlay {have} -> none")),
                (None, None) => {}
            }
            // The endpoints, either family (#418). `vxlan_nl2conf` takes a
            // new remote or local on a live link only in the family it has
            // ("New group address family does not match old group",
            // EOPNOTSUPP), and the kernel keeps both in one family
            // (`vxlan_config_validate`), so a declared family that differs
            // from the live one recreates the link.
            let have_remote = data
                .ipv4(vxlan::IFLA_VXLAN_GROUP)
                .map(IpAddr::V4)
                .or_else(|| data.ipv6(vxlan::IFLA_VXLAN_GROUP6).map(IpAddr::V6));
            let have_local = data
                .ipv4(vxlan::IFLA_VXLAN_LOCAL)
                .map(IpAddr::V4)
                .or_else(|| data.ipv6(vxlan::IFLA_VXLAN_LOCAL6).map(IpAddr::V6));
            // Neither dumped: the kernel assumed IPv4 at creation ("Unless
            // IPv6 is explicitly requested, assume IPv4").
            let have_v6 = have_local.or(have_remote).is_some_and(|a| a.is_ipv6());
            let want_v6 = local.or(*remote).map(|a| a.is_ipv6());
            if let Some(want_v6) = want_v6
                && want_v6 != have_v6
            {
                let family = |v6: bool| if v6 { "IPv6" } else { "IPv4" };
                d.recreate.push(format!(
                    "vxlan address family {} -> {}",
                    family(have_v6),
                    family(want_v6)
                ));
            } else {
                let endpoints = [
                    (*remote, have_remote, "remote"),
                    (*local, have_local, "local"),
                ];
                for (want, have, what) in endpoints {
                    if want == have {
                        continue;
                    }
                    // The unspecified address of the link's family clears
                    // it, as `ip link set ... type vxlan remote 0.0.0.0`
                    // does.
                    let (attr, bytes) = match want {
                        Some(IpAddr::V4(a)) => (vxlan_attr(what, false), a.octets().to_vec()),
                        Some(IpAddr::V6(a)) => (vxlan_attr(what, true), a.octets().to_vec()),
                        None if have_v6 => {
                            (vxlan_attr(what, true), Ipv6Addr::UNSPECIFIED.octets().to_vec())
                        }
                        None => (vxlan_attr(what, false), Ipv4Addr::UNSPECIFIED.octets().to_vec()),
                    };
                    d.update(
                        "vxlan",
                        KindAttr::Bytes(attr, bytes),
                        format!("vxlan {what} {} -> {}", or_none(have), or_none(want)),
                    );
                }
            }
        }
        DeclaredLinkType::Gre(p) | DeclaredLinkType::Gretap(p) => {
            let kind = if matches!(declared.link_type, DeclaredLinkType::Gre(_)) { "gre" } else { "gretap" };
            compare_tunnel(kind, p, &data, names, TunnelIds::GRE, &mut d);
        }
        DeclaredLinkType::Ipip(p) | DeclaredLinkType::Sit(p) => {
            let kind = if matches!(declared.link_type, DeclaredLinkType::Ipip(_)) { "ipip" } else { "sit" };
            compare_tunnel(kind, p, &data, names, TunnelIds::IPTUN, &mut d);
        }
        DeclaredLinkType::Vti(p) => compare_tunnel("vti", p, &data, names, TunnelIds::VTI, &mut d),
        // `ip6_tnl_changelink` rebuilds the whole configuration from the
        // request, so a change sends every declared parameter.
        DeclaredLinkType::Ip6tnl(p) => {
            const LINK: u16 = 1;
            const LOCAL: u16 = 2;
            const REMOTE: u16 = 3;
            const TTL: u16 = 4;
            const ENCAP_LIMIT: u16 = 6;
            const PROTO: u16 = 9;
            let addr = |t| data.ipv6(t).filter(|a| !a.is_unspecified());
            let have_dev = data
                .u32(LINK)
                .filter(|i| *i != 0)
                .and_then(|i| names.get(&i).copied());
            let show = |v: Option<String>| v.unwrap_or_else(|| "none".into());
            let mut changes = Vec::new();
            let mut note = |what: &str, have: String, want: String| {
                if have != want {
                    changes.push(format!("ip6tnl {what} {have} -> {want}"));
                }
            };
            note("local", show(addr(LOCAL).map(|a| a.to_string())), show(p.local.map(|a| a.to_string())));
            note("remote", show(addr(REMOTE).map(|a| a.to_string())), show(p.remote.map(|a| a.to_string())));
            // Unset is the kernel's, not compared.
            if let Some(want) = p.hoplimit {
                note("hoplimit", show(data.u8(TTL).map(|v| v.to_string())), want.to_string());
            }
            if let Some(want) = p.encap_limit {
                note("encaplimit", show(data.u8(ENCAP_LIMIT).map(|v| v.to_string())), want.to_string());
            }
            let have_mode = data.u8(PROTO).map(|v| {
                crate::netlink::link::Ip6tnlMode::from_proto(v)
                    .map_or_else(|| format!("proto {v}"), |m| format!("{m:?}").to_lowercase())
            });
            note("mode", show(have_mode), format!("{:?}", p.mode).to_lowercase());
            note("dev", show(have_dev.map(str::to_string)), show(p.underlay_dev.clone()));
            if !changes.is_empty() {
                let mut attrs = vec![KindAttr::U8(PROTO, p.mode.proto())];
                if let Some(a) = p.local {
                    attrs.push(KindAttr::Bytes(LOCAL, a.octets().to_vec()));
                }
                if let Some(a) = p.remote {
                    attrs.push(KindAttr::Bytes(REMOTE, a.octets().to_vec()));
                }
                if let Some(v) = p.hoplimit {
                    attrs.push(KindAttr::U8(TTL, v));
                }
                if let Some(v) = p.encap_limit {
                    attrs.push(KindAttr::U8(ENCAP_LIMIT, v));
                }
                if let Some(dev) = &p.underlay_dev {
                    attrs.push(KindAttr::Ifindex(LINK, dev.clone()));
                }
                let mut changes = changes.into_iter();
                let mut attrs = attrs.into_iter();
                d.update("ip6tnl", attrs.next().expect("the mode"), changes.next().expect("not empty"));
                let u = d.update.as_mut().expect("set above");
                u.attrs.extend(attrs);
                u.changes.extend(changes);
                u.was = Some(live_set(&data, &[LOCAL, REMOTE, TTL, ENCAP_LIMIT, PROTO], Some(LINK), names));
            }
        }
        // `ip6gre_netlink_parms` rebuilds the whole configuration from the
        // request, as ip6tnl's does: a change sends every declared
        // parameter (#516).
        DeclaredLinkType::Ip6gre(p) | DeclaredLinkType::Ip6gretap(p) => {
            let kind = if matches!(declared.link_type, DeclaredLinkType::Ip6gre(_)) { "ip6gre" } else { "ip6gretap" };
            const LINK: u16 = 1;
            const IFLAGS: u16 = 2;
            const OFLAGS: u16 = 3;
            const IKEY: u16 = 4;
            const OKEY: u16 = 5;
            const LOCAL: u16 = 6;
            const REMOTE: u16 = 7;
            const TTL: u16 = 8;
            const ENCAP_LIMIT: u16 = 11;
            const GRE_KEY: u16 = 0x2000;
            let addr = |t| data.ipv6(t).filter(|a| !a.is_unspecified());
            let have_dev = data.u32(LINK).filter(|i| *i != 0).and_then(|i| names.get(&i).copied());
            let keyed = data
                .0
                .get(&IFLAGS)
                .and_then(|f| f.get(..2))
                .is_some_and(|f| u16::from_be_bytes([f[0], f[1]]) & GRE_KEY != 0);
            let have_key = keyed.then(|| data.u32_be(IKEY)).flatten();
            let okeyed = data
                .0
                .get(&OFLAGS)
                .and_then(|f| f.get(..2))
                .is_some_and(|f| u16::from_be_bytes([f[0], f[1]]) & GRE_KEY != 0);
            let have_okey = okeyed.then(|| data.u32_be(OKEY)).flatten();
            let show = |v: Option<String>| v.unwrap_or_else(|| "none".into());
            let mut changes = Vec::new();
            let mut note = |what: &str, have: String, want: String| {
                if have != want {
                    changes.push(format!("{kind} {what} {have} -> {want}"));
                }
            };
            note("local", show(addr(LOCAL).map(|a| a.to_string())), show(p.local.map(|a| a.to_string())));
            note("remote", show(addr(REMOTE).map(|a| a.to_string())), show(p.remote.map(|a| a.to_string())));
            if let Some(want) = p.hoplimit {
                note("hoplimit", show(data.u8(TTL).map(|v| v.to_string())), want.to_string());
            }
            if let Some(want) = p.encap_limit {
                note("encaplimit", show(data.u8(ENCAP_LIMIT).map(|v| v.to_string())), want.to_string());
            }
            note("key", keys_text(have_key, have_okey), show(p.key.map(|k| k.to_string())));
            note("dev", show(have_dev.map(str::to_string)), show(p.underlay_dev.clone()));
            if !changes.is_empty() {
                let mut attrs = Vec::new();
                if let Some(a) = p.local {
                    attrs.push(KindAttr::Bytes(LOCAL, a.octets().to_vec()));
                }
                if let Some(a) = p.remote {
                    attrs.push(KindAttr::Bytes(REMOTE, a.octets().to_vec()));
                }
                if let Some(v) = p.hoplimit {
                    attrs.push(KindAttr::U8(TTL, v));
                }
                if let Some(v) = p.encap_limit {
                    attrs.push(KindAttr::U8(ENCAP_LIMIT, v));
                }
                if let Some(k) = p.key {
                    attrs.push(KindAttr::Bytes(IFLAGS, GRE_KEY.to_be_bytes().to_vec()));
                    attrs.push(KindAttr::Bytes(OFLAGS, GRE_KEY.to_be_bytes().to_vec()));
                    attrs.push(KindAttr::Bytes(IKEY, k.to_be_bytes().to_vec()));
                    attrs.push(KindAttr::Bytes(OKEY, k.to_be_bytes().to_vec()));
                }
                if let Some(dev) = &p.underlay_dev {
                    attrs.push(KindAttr::Ifindex(LINK, dev.clone()));
                }
                let mut changes = changes.into_iter();
                let first = changes.next().expect("not empty");
                let mut attrs = attrs.into_iter();
                match attrs.next() {
                    Some(attr) => d.update(kind, attr, first),
                    // Everything back to the kernel's defaults.
                    None => d.update(kind, KindAttr::Bytes(0, Vec::new()), first),
                }
                let u = d.update.as_mut().expect("set above");
                u.attrs.extend(attrs);
                u.changes.extend(changes);
                u.was = Some(live_set(
                    &data,
                    &[LOCAL, REMOTE, TTL, ENCAP_LIMIT, IFLAGS, OFLAGS, IKEY, OKEY],
                    Some(LINK),
                    names,
                ));
            }
        }
        DeclaredLinkType::Vti6(p) => compare_vti6(p, &data, names, &mut d),
        DeclaredLinkType::Erspan(p) => compare_erspan("erspan", p, &data, names, &mut d),
        DeclaredLinkType::Ip6erspan(p) => compare_erspan("ip6erspan", p, &data, names, &mut d),
        // `xfrmi_change` refuses a new underlay (EINVAL), so that
        // recreates; the if_id changes in place, sent with the underlay it
        // has (checked on 6.12).
        DeclaredLinkType::Xfrm { if_id, underlay_dev } => {
            const LINK: u16 = 1;
            const IF_ID: u16 = 2;
            let have_id = data.u32(IF_ID).unwrap_or(0);
            let have_dev = data
                .u32(LINK)
                .filter(|i| *i != 0)
                .and_then(|i| names.get(&i).copied());
            if have_dev != underlay_dev.as_deref() {
                d.recreate.push(format!(
                    "xfrm dev {} -> {}",
                    have_dev.unwrap_or("none"),
                    underlay_dev.as_deref().unwrap_or("none")
                ));
            } else if have_id != *if_id {
                d.update("xfrm", KindAttr::U32(IF_ID, *if_id), format!("xfrm if_id {have_id} -> {if_id}"));
                if let Some(dev) = underlay_dev {
                    d.update.as_mut().expect("set above").attrs.push(KindAttr::Ifindex(LINK, dev.clone()));
                }
            }
        }
        // `geneve_changelink` refuses a VNI, port or address-family change
        // ("not supported"): those recreate. The rest change in place, from
        // the current configuration (checked on 6.12).
        DeclaredLinkType::Geneve {
            vni,
            remote,
            ttl,
            tos,
            port,
        } => {
            const ID: u16 = 1;
            const REMOTE: u16 = 2;
            const TTL: u16 = 3;
            const TOS: u16 = 4;
            const PORT: u16 = 5;
            const REMOTE6: u16 = 7;
            if let Some(have) = data.u32(ID)
                && have != *vni
            {
                d.recreate.push(format!("geneve vni {have} -> {vni}"));
            }
            let want_port = port.unwrap_or(6081);
            if let Some(have) = data.u16_be(PORT)
                && have != want_port
            {
                d.recreate.push(format!("geneve port {have} -> {want_port}"));
            }
            let have_remote: Option<IpAddr> = data
                .ipv4(REMOTE)
                .filter(|a| !a.is_unspecified())
                .map(IpAddr::V4)
                .or_else(|| {
                    data.0
                        .get(&REMOTE6)
                        .and_then(|p| <[u8; 16]>::try_from(p.get(..16)?).ok())
                        .map(|b| IpAddr::V6(Ipv6Addr::from(b)))
                        .filter(|a| !a.is_unspecified())
                });
            if have_remote != *remote {
                let change = format!(
                    "geneve remote {} -> {}",
                    have_remote.map_or("none".into(), |a| a.to_string()),
                    remote.map_or("none".into(), |a| a.to_string())
                );
                match (have_remote, remote) {
                    (Some(IpAddr::V4(_)), Some(IpAddr::V4(a))) => {
                        d.update("geneve", KindAttr::Bytes(REMOTE, a.octets().to_vec()), change)
                    }
                    (Some(IpAddr::V6(_)), Some(IpAddr::V6(a))) => {
                        d.update("geneve", KindAttr::Bytes(REMOTE6, a.octets().to_vec()), change)
                    }
                    _ => d.recreate.push(change),
                }
            }
            for (name, attr, want) in [("ttl", TTL, ttl), ("tos", TOS, tos)] {
                if let Some(want) = want
                    && data.u8(attr) != Some(*want)
                {
                    d.update(
                        "geneve",
                        KindAttr::U8(attr, *want),
                        format!("geneve {name} {} -> {want}", data.u8(attr).unwrap_or(0)),
                    );
                }
            }
        }
        // `macsec_changelink` refuses the SCI and port (EINVAL): those
        // recreate. The rest change in place, one attribute at a time.
        DeclaredLinkType::Macsec {
            parent,
            sci,
            port,
            encrypt,
            protect,
            include_sci,
            replay_window,
        } => {
            const SCI: u16 = 1;
            const WINDOW: u16 = 5;
            const ENCRYPT: u16 = 7;
            const PROTECT: u16 = 8;
            const INC_SCI: u16 = 9;
            const REPLAY_PROTECT: u16 = 12;
            if let Some(have) = lower_name(live, names)
                && have != parent.as_str()
            {
                d.recreate.push(format!("macsec parent {have} -> {parent}"));
            }
            let have_sci = data.0.get(&SCI).and_then(|p| <[u8; 8]>::try_from(p.get(..8)?).ok()).map(u64::from_be_bytes);
            if let (Some(want), Some(have)) = (sci, have_sci)
                && *want != have
            {
                d.recreate.push(format!("macsec sci {have:016x} -> {want:016x}"));
            }
            if let (Some(want), Some(have)) = (port, have_sci)
                && sci.is_none()
                && *want != (have & 0xffff) as u16
            {
                d.recreate.push(format!("macsec port {} -> {want}", have & 0xffff));
            }
            for (name, attr, want) in [
                ("encrypt", ENCRYPT, encrypt),
                ("protect", PROTECT, protect),
                ("include_sci", INC_SCI, include_sci),
            ] {
                if let Some(want) = want
                    && data.u8(attr).map(|v| v != 0) != Some(*want)
                {
                    d.update("macsec", KindAttr::U8(attr, u8::from(*want)), format!("macsec {name} -> {want}"));
                }
            }
            if let Some(want) = replay_window
                && (data.u8(REPLAY_PROTECT) != Some(1) || data.u32(WINDOW) != Some(*want))
            {
                d.update("macsec", KindAttr::U8(REPLAY_PROTECT, 1), format!("macsec replay window -> {want}"));
                d.update.as_mut().expect("set above").attrs.push(KindAttr::U32(WINDOW, *want));
            }
        }
        // No changelink: every difference recreates.
        DeclaredLinkType::Bareudp {
            port,
            ethertype,
            srcport_min,
            multiproto,
        } => {
            const PORT: u16 = 1;
            const ETHERTYPE: u16 = 2;
            const SRCPORT_MIN: u16 = 3;
            const MULTIPROTO: u16 = 4;
            if let Some(have) = data.u16_be(PORT)
                && have != *port
            {
                d.recreate.push(format!("bareudp port {have} -> {port}"));
            }
            if let Some(have) = data.u16_be(ETHERTYPE)
                && have != *ethertype
            {
                d.recreate.push(format!("bareudp ethertype {have:#06x} -> {ethertype:#06x}"));
            }
            if let Some(want) = srcport_min
                && data.u16_ne(SRCPORT_MIN) != Some(*want)
            {
                d.recreate.push(format!("bareudp srcport_min -> {want}"));
            }
            if data.0.contains_key(&MULTIPROTO) != *multiproto {
                d.recreate.push(format!("bareudp multiproto -> {multiproto}"));
            }
        }
        DeclaredLinkType::Ipvlan {
            parent,
            mode,
            isolation,
        } => {
            const IFLA_IPVLAN_MODE: u16 = 1;
            const IFLA_IPVLAN_FLAGS: u16 = 2;
            if let Some(have) = lower_name(live, names)
                && have != parent.as_str()
            {
                d.recreate.push(format!("ipvlan parent {have} -> {parent}"));
            }
            // Both change in place (`ipvlan_nl_changelink`, #516).
            let want = *mode as u16;
            if let Some(have) = data.u16_ne(IFLA_IPVLAN_MODE)
                && have != want
            {
                d.update(
                    "ipvlan",
                    KindAttr::U16(IFLA_IPVLAN_MODE, want),
                    format!("ipvlan mode {have} -> {want} ({mode:?})"),
                );
            }
            let want = *isolation as u16;
            if let Some(have) = data.u16_ne(IFLA_IPVLAN_FLAGS)
                && have != want
            {
                d.update(
                    "ipvlan",
                    KindAttr::U16(IFLA_IPVLAN_FLAGS, want),
                    format!("ipvlan isolation {have} -> {want} ({isolation:?})"),
                );
            }
        }
        DeclaredLinkType::Macvlan { parent, mode } | DeclaredLinkType::Macvtap { parent, mode } => {
            let kind = declared.link_type.kind().unwrap_or("macvlan");
            if let Some(have) = lower_name(live, names)
                && have != parent.as_str()
            {
                d.recreate.push(format!("{kind} parent {have} -> {parent}"));
            }
            let want = kernel_macvlan_mode(*mode) as u32;
            if let Some(have) = data.u32(macvlan::IFLA_MACVLAN_MODE)
                && have != want
            {
                let passthru = KernelMacvlanMode::Passthru as u32;
                let change = format!("{kind} mode {have} -> {want} ({mode:?})");
                if (have == passthru) != (want == passthru) {
                    d.recreate.push(change);
                } else {
                    let kind = if kind == "macvtap" { "macvtap" } else { "macvlan" };
                    d.update(kind, KindAttr::U32(macvlan::IFLA_MACVLAN_MODE, want), change);
                }
            }
        }
        DeclaredLinkType::Bond {
            mode,
            miimon,
            xmit_hash_policy,
            min_links,
            ad_select,
            lacp_rate,
            downdelay,
            updelay,
            resend_igmp,
        } => {
            let want_mode = kernel_bond_mode(*mode) as u8;
            if let Some(have) = data.u8(bond_attr::IFLA_BOND_MODE)
                && have != want_mode
            {
                d.recreate.push(format!(
                    "bond mode {} -> {}",
                    bond_mode_name(have),
                    bond_mode_name(want_mode)
                ));
            }
            let down_only = [
                (lacp_rate.map(|v| v as u8), bond_attr::IFLA_BOND_AD_LACP_RATE, "lacp_rate"),
                (ad_select.map(|v| v as u8), bond_attr::IFLA_BOND_AD_SELECT, "ad_select"),
            ];
            for (want, attr, what) in down_only {
                if let (Some(want), Some(have)) = (want, data.u8(attr))
                    && have != want
                {
                    d.recreate.push(format!("bond {what} {have} -> {want}"));
                }
            }

            let live_miimon = data.u32(bond_attr::IFLA_BOND_MIIMON);
            if let (Some(want), Some(have)) = (miimon, live_miimon)
                && have != *want
            {
                d.update(
                    "bond",
                    KindAttr::U32(bond_attr::IFLA_BOND_MIIMON, *want),
                    format!("bond miimon {have} -> {want}"),
                );
            }
            // The kernel keeps a delay as a count of miimon intervals
            // (`_bond_option_delay_set`: `value / miimon`) and dumps it
            // multiplied back, so a delay that is not a multiple of miimon
            // comes back rounded down — and one that is comes back changed
            // when miimon changes.
            let miimon_ms = miimon.or(live_miimon).unwrap_or(0);
            let delays = [
                (updelay, bond_attr::IFLA_BOND_UPDELAY, "updelay"),
                (downdelay, bond_attr::IFLA_BOND_DOWNDELAY, "downdelay"),
            ];
            for (want, attr, what) in delays {
                let Some(want) = want else { continue };
                let stored = want
                    .checked_div(miimon_ms)
                    .map_or(*want, |intervals| intervals * miimon_ms);
                let have = data.u32(attr);
                if have != Some(stored) {
                    d.update(
                        "bond",
                        KindAttr::U32(attr, *want),
                        format!("bond {what} {} -> {want}", or_none(have)),
                    );
                }
            }
            if let (Some(want), Some(have)) = (
                xmit_hash_policy,
                data.u8(bond_attr::IFLA_BOND_XMIT_HASH_POLICY),
            ) && have != *want as u8
            {
                d.update(
                    "bond",
                    KindAttr::U8(bond_attr::IFLA_BOND_XMIT_HASH_POLICY, *want as u8),
                    format!("bond xmit_hash_policy {have} -> {want:?}"),
                );
            }
            let counts = [
                (min_links, bond_attr::IFLA_BOND_MIN_LINKS, "min_links"),
                (resend_igmp, bond_attr::IFLA_BOND_RESEND_IGMP, "resend_igmp"),
            ];
            for (want, attr, what) in counts {
                if let (Some(want), Some(have)) = (want, data.u32(attr))
                    && have != *want
                {
                    d.update(
                        "bond",
                        KindAttr::U32(attr, *want),
                        format!("bond {what} {have} -> {want}"),
                    );
                }
            }
        }
        DeclaredLinkType::Vrf { table } => {
            if let Some(have) = data.u32(vrf_attr::IFLA_VRF_TABLE)
                && have != *table
            {
                d.recreate.push(format!("vrf table {have} -> {table}"));
            }
        }
        DeclaredLinkType::Netkit {
            peer,
            mode,
            primary_policy,
            peer_policy,
            scrub,
            peer_scrub,
        } => {
            // `netkit_new_link` defaults: L3, forward both ways, default
            // scrubbing both ways.
            let fixed = [
                (
                    mode.unwrap_or(NetkitMode::L3) as u32,
                    netkit::IFLA_NETKIT_MODE,
                    "netkit mode",
                ),
                (
                    scrub.unwrap_or(NetkitScrub::Default) as u32,
                    netkit::IFLA_NETKIT_SCRUB,
                    "netkit scrub",
                ),
                (
                    peer_scrub.unwrap_or(NetkitScrub::Default) as u32,
                    netkit::IFLA_NETKIT_PEER_SCRUB,
                    "netkit peer scrub",
                ),
            ];
            for (want, attr, what) in fixed {
                if let Some(have) = data.u32(attr)
                    && have != want
                {
                    d.refuse.push(format!(
                        "{what} {have} -> {want} cannot be changed on a live pair \
                         (netkit_change_link), and recreating it would delete its peer {peer}"
                    ));
                }
            }
            // Settings change only through the primary.
            if data.u8(netkit::IFLA_NETKIT_PRIMARY) != Some(0) {
                let policies = [
                    (primary_policy, netkit::IFLA_NETKIT_POLICY, "netkit policy"),
                    (peer_policy, netkit::IFLA_NETKIT_PEER_POLICY, "netkit peer policy"),
                ];
                for (want, attr, what) in policies {
                    let want = want.unwrap_or(NetkitPolicy::Forward) as u32;
                    if let Some(have) = data.u32(attr)
                        && have != want
                    {
                        d.update(
                            "netkit",
                            KindAttr::U32(attr, want),
                            format!("{what} {have} -> {want}"),
                        );
                    }
                }
            }
        }
        // A bridge's declared options, changed in place (`br_changelink`,
        // #516). The timers are kept in 1/100 s (`clock_t`).
        DeclaredLinkType::Bridge => {
            const FORWARD_DELAY: u16 = 1;
            const HELLO_TIME: u16 = 2;
            const MAX_AGE: u16 = 3;
            const AGEING_TIME: u16 = 4;
            const STP_STATE: u16 = 5;
            const PRIORITY: u16 = 6;
            const VLAN_FILTERING: u16 = 7;
            const VLAN_DEFAULT_PVID: u16 = 39;
            if let Some(b) = &declared.bridge {
                if let Some(want) = b.vlan_filtering
                    && data.u8(VLAN_FILTERING).map(|v| v != 0) != Some(want)
                {
                    d.update(
                        "bridge",
                        KindAttr::U8(VLAN_FILTERING, u8::from(want)),
                        format!("vlan_filtering -> {}", u8::from(want)),
                    );
                }
                if let Some(want) = b.vlan_default_pvid
                    && data.u16_ne(VLAN_DEFAULT_PVID) != Some(want)
                {
                    d.update(
                        "bridge",
                        KindAttr::U16(VLAN_DEFAULT_PVID, want),
                        format!("vlan_default_pvid -> {want}"),
                    );
                }
                if let Some(want) = b.stp
                    && data.u32(STP_STATE).map(|v| v != 0) != Some(want)
                {
                    d.update(
                        "bridge",
                        KindAttr::U32(STP_STATE, u32::from(want)),
                        format!("stp_state -> {}", u32::from(want)),
                    );
                }
                if let Some(want) = b.priority
                    && data.u16_ne(PRIORITY) != Some(want)
                {
                    d.update("bridge", KindAttr::U16(PRIORITY, want), format!("priority -> {want}"));
                }
                for (name, attr, want) in [
                    ("ageing_time", AGEING_TIME, b.ageing_time),
                    ("forward_delay", FORWARD_DELAY, b.forward_delay),
                    ("hello_time", HELLO_TIME, b.hello_time),
                    ("max_age", MAX_AGE, b.max_age),
                ] {
                    let Some(want) = want.map(|t| u32::try_from(t.as_millis() / 10).unwrap_or(u32::MAX))
                    else {
                        continue;
                    };
                    if data.u32(attr) != Some(want) {
                        d.update("bridge", KindAttr::U32(attr, want), format!("{name} -> {want}cs"));
                    }
                }
            }
        }
        DeclaredLinkType::Dummy
        | DeclaredLinkType::Veth { .. }
        | DeclaredLinkType::Ifb
        | DeclaredLinkType::Ovpn
        | DeclaredLinkType::Physical => {}
    }
    // What a change replaces, for its inverse (#649). A kind whose parms
    // rebuild the configuration from the request has recorded its whole
    // live set already; the others change the attributes they are sent.
    if let Some(update) = d.update.as_mut()
        && update.was.is_none()
        && !REBUILDS.contains(&update.kind.as_str())
    {
        update.was = was_attrs(&update.attrs, &data, names);
    }
    d
}

/// The kinds whose `changelink` rebuilds the configuration from the
/// request, zeroing what it is not sent: their diffs send the whole
/// declared set, and their inverses the whole live one.
const REBUILDS: [&str; 11] = [
    "gre", "gretap", "ipip", "sit", "vti", "ip6tnl", "ip6gre", "ip6gretap", "vti6", "erspan", "ip6erspan",
];

/// What the kind parameters of a config ask of the live links.
#[derive(Debug, Default)]
pub(crate) struct KindPlan {
    /// Links to delete and create again, in deletion order, and the ones
    /// refused.
    pub(crate) recreate: Vec<LinkRecreate>,
    /// The ifindexes the apply deletes: the recreated links and the links
    /// the kernel deletes with them.
    pub(crate) gone: HashSet<u32>,
    /// Ports of a deleted master, which the kernel releases: ifindex, and
    /// whether it closes them on the way out (a bond does).
    pub(crate) released: HashMap<u32, bool>,
    /// Ports whose routes the kernel flushes as they leave the deleted
    /// master and join the new one: a bond closes them, a VRF cycles them.
    pub(crate) cycled: HashSet<u32>,
    /// Deleted links that were up, so an undeclared state comes back up.
    pub(crate) was_up: HashSet<String>,
    /// In-place changes, by link name.
    pub(crate) updates: HashMap<String, KindUpdate>,
    /// Links the previous config declared and this one does not, and the
    /// ones stacked on them, in deletion order; and the ones refused (#512).
    pub(crate) remove: Vec<LinkRemoval>,
    /// Peers here renamed to the name their pair declares (#804).
    pub(crate) renames: Vec<LinkRename>,
}

/// What hangs off the links beyond the four dumps every diff takes (links,
/// addresses, routes, qdiscs), and a recreate destroys with them. Read
/// only when the plan recreates a link ([`recreates_any`]).
#[derive(Debug, Default, Clone)]
pub(crate) struct LinkExtras {
    /// The `AF_BRIDGE` neighbour dump: every device's FDB entries.
    pub(crate) fdb: Vec<NeighborMessage>,
    /// ARP and ND entries.
    pub(crate) neighbours: Vec<NeighborMessage>,
    /// Proxy entries, which the neighbour dump leaves out.
    pub(crate) proxies: Vec<NeighborMessage>,
    /// Nexthop objects.
    pub(crate) nexthops: Vec<Nexthop>,
    /// TC classes and filters, on the links with a qdisc of their own: no
    /// declaration describes either (#472).
    pub(crate) classes: Vec<TcMessage>,
    pub(crate) filters: Vec<TcMessage>,
    /// Every bridge port's VLANs, which a deleted bridge takes and an undo
    /// puts back (#745).
    pub(crate) bridge_vlans: Vec<crate::netlink::bridge_vlan::BridgeVlanEntry>,
}

impl LinkExtras {
    pub(crate) async fn read(conn: &Connection<Route>, qdiscs: &[TcMessage]) -> Result<Self> {
        let nexthops = match conn.get_nexthops().await {
            Ok(nexthops) => nexthops,
            // A kernel without nexthop objects (before 5.3) has no
            // RTM_GETNEXTHOP handler, and no nexthop objects either.
            Err(e) if e.is_not_supported() => Vec::new(),
            Err(e) => return Err(e),
        };
        // A link with only the kernel's default qdisc (handle 0:) has no
        // classes or filters to lose.
        let mut tc_links: Vec<u32> = qdiscs
            .iter()
            .filter(|q| q.handle().major() != 0)
            .map(|q| q.ifindex())
            .collect();
        tc_links.sort_unstable();
        tc_links.dedup();
        let (mut classes, mut filters) = (Vec::new(), Vec::new());
        for ifindex in tc_links {
            classes.extend(conn.get_classes_by_index(ifindex).await?);
            filters.extend(conn.get_filters_by_index(ifindex).await?);
        }
        Ok(Self {
            fdb: conn.get_bridge_neighbors().await?,
            neighbours: conn.get_neighbors().await?,
            proxies: conn.get_proxy_neighbors().await?,
            nexthops,
            classes,
            filters,
            bridge_vlans: conn.get_bridge_vlans_dump().await?,
        })
    }
}

/// True when some declared link has a parameter the kernel cannot change
/// on it, so the plan recreates (or refuses to recreate) it.
pub(crate) fn recreates_any(config: &NetworkConfig, links: &[LinkMessage]) -> bool {
    let names: HashMap<u32, &str> = links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (l.ifindex(), n)))
        .collect();
    config.links.iter().any(|link| {
        links
            .iter()
            .find(|l| l.name.as_deref() == Some(link.name.as_str()))
            .is_some_and(|live| {
                let d = compare(link, live, &names);
                !d.recreate.is_empty() || !d.refuse.is_empty()
            })
    })
}

/// The links the previous config declared with a kind and this one does
/// not, still in the kernel with that kind: what the apply deletes (#512).
pub(crate) fn removed_links<'a>(
    config: &NetworkConfig,
    opts: &PlanOptions,
    links: &'a [LinkMessage],
) -> Vec<&'a LinkMessage> {
    let declared = |name: &str| config.links.iter().any(|d| d.name == name);
    let mut removed: Vec<&LinkMessage> = Vec::new();
    if let Some(previous) = opts.previous.as_deref() {
        removed.extend(
            previous
                .links
                .iter()
                .filter(|l| !declared(&l.name))
                .filter_map(|l| {
                    let kind = l.link_type.kind()?;
                    links
                        .iter()
                        .find(|live| live.name.as_deref() == Some(l.name.as_str()))
                        .filter(|live| live.kind() == Some(kind))
                }),
        );
    }
    // With purge, an undeclared link carrying the config's owner tag.
    if opts.purge {
        for live in links.iter().filter(|l| tagged(config, l)) {
            let name = live.name.as_deref().unwrap_or_default();
            if !declared(name) && !removed.iter().any(|r| r.ifindex() == live.ifindex()) {
                removed.push(live);
            }
        }
    }
    removed
}

/// Whether `link` carries `config`'s owner tag (#512).
pub(crate) fn tagged(config: &NetworkConfig, link: &LinkMessage) -> bool {
    config
        .owner
        .as_deref()
        .is_some_and(|owner| link.alias() == Some(owner))
}

/// Whether a diff of `config` deletes a link, by recreating it or by
/// removing it: what a deletion would destroy is read then (#426, #512).
pub(crate) fn deletes_any(
    config: &NetworkConfig,
    opts: &PlanOptions,
    links: &[LinkMessage],
) -> bool {
    recreates_any(config, links) || !removed_links(config, opts, links).is_empty()
}

/// `downed`, and the VLANs the kernel takes down with them, transitively:
/// `vlan_device_event` closes every up VLAN on a lower device that goes
/// down, unless it was created with `loose_binding`, and opens them all
/// again when the lower device comes back up.
pub(crate) fn with_vlans_on(links: &[LinkMessage], downed: &HashSet<u32>) -> HashSet<u32> {
    let mut out = downed.clone();
    let mut queue: VecDeque<u32> = downed.iter().copied().collect();
    while let Some(lower) = queue.pop_front() {
        for l in links {
            let follows = l.kind() == Some("vlan")
                && l.link() == Some(lower)
                && l.link_netnsid.is_none()
                && l.is_up()
                && !loose_binding(l);
            if follows && out.insert(l.ifindex()) {
                queue.push_back(l.ifindex());
            }
        }
    }
    out
}

/// `IFLA_VLAN_FLAGS` is a `struct ifla_vlan_flags { flags, mask }`.
fn loose_binding(vlan_link: &LinkMessage) -> bool {
    InfoData::of(vlan_link)
        .u32(vlan::IFLA_VLAN_FLAGS)
        .is_some_and(|flags| flags & vlan::VLAN_FLAG_LOOSE_BINDING != 0)
}

/// The devices each nexthop object sends through: its own, or for a group
/// its members' (the kernel does not nest groups).
pub(super) fn nexthop_devices(nexthops: &[Nexthop]) -> HashMap<u32, Vec<u32>> {
    let own: HashMap<u32, u32> = nexthops
        .iter()
        .filter_map(|nh| nh.ifindex().map(|dev| (nh.id(), dev)))
        .collect();
    nexthops
        .iter()
        .map(|nh| {
            let devs = match nh.group() {
                Some(members) => members.iter().filter_map(|m| own.get(&m.id()).copied()).collect(),
                None => nh.ifindex().into_iter().collect(),
            };
            (nh.id(), devs)
        })
        .collect()
}

/// How a route goes through `dev`, if it does: its own output interface,
/// one of its multipath nexthops, or the nexthop object it uses. The last
/// two dump no `RTA_OIF` (a nexthop object's only while
/// `nexthop_compat_mode` is on), so checking `oif` alone missed them.
pub(super) fn route_through(
    r: &RouteMessage,
    dev: u32,
    nh_devs: &HashMap<u32, Vec<u32>>,
) -> Option<&'static str> {
    if r.nh_id()
        .and_then(|id| nh_devs.get(&id))
        .is_some_and(|devs| devs.contains(&dev))
    {
        return Some("through a nexthop object on");
    }
    if r.oif() == Some(dev) {
        return Some("");
    }
    r.multipath()
        .is_some_and(|hops| hops.iter().any(|h| h.ifindex == dev))
        .then_some("with a multipath nexthop on")
}

fn route_label(r: &RouteMessage, name: &str, how: &str) -> Blocker {
    let destination = r.destination.unwrap_or(if r.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    });
    Blocker::Route {
        dev: name.to_string(),
        destination,
        prefix_len: r.dst_len(),
        table: r.table_id(),
        nhid: r.nh_id(),
        through: (!how.is_empty()).then(|| how.to_string()),
        protocol: r.protocol(),
    }
}

#[cfg(feature = "serde")]
pub(super) fn deserialize_protocol<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<RouteProtocol, D::Error> {
    <u8 as serde::Deserialize>::deserialize(d).map(RouteProtocol::from)
}

#[cfg(feature = "serde")]
pub(super) fn serialize_protocol<S: serde::Serializer>(
    p: &RouteProtocol,
    s: S,
) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_u8(p.number())
}

pub(super) fn mac_str(mac: &[u8]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// True for an FDB entry the kernel did not make itself — one a user or a
/// controller added, which nothing puts back once its link is deleted.
///
/// Only entries that stay count: `permanent`, `static` (NUD_NOARP) and
/// externally learned ones. A learned entry ages out and is learned again.
/// Of the rest, the kernel's own are:
/// - on a VXLAN, its default remote: the all-zeros entry
///   `__vxlan_dev_create` adds for the remote it was created with, which
///   `vxlan_fdb_info` dumps without `NDA_PORT` or `NDA_VNI`;
/// - any other `self` entry is the device's unicast or multicast address
///   list (`ndo_dflt_fdb_dump`): the stack's multicast joins, and the MACs
///   of links stacked on it (`dev_uc_add` by a macvlan, a VLAN or a bond's
///   upper with its own address). A user can add a unicast one
///   (`bridge fdb add MAC dev X self permanent`), and that is told apart by
///   being no link's MAC; a multicast one cannot be told apart;
/// - in a bridge's database, a port's or the bridge's own MAC, which the
///   bridge adds as a `local` entry, dumped as permanent (`fdb_to_nud`).
pub(super) fn fdb_entry_is_users(
    e: &NeighborMessage,
    by_index: &HashMap<u32, &LinkMessage>,
    link_macs: &HashSet<&[u8]>,
) -> bool {
    let Some(mac) = e.lladdr().filter(|m| m.len() == 6) else {
        return false;
    };
    let state = e.header.ndm_state;
    let flags = e.header.ndm_flags;
    let ext_learned = flags & ntf::EXT_LEARNED != 0;
    if state & (nud::PERMANENT | nud::NOARP) == 0 && !ext_learned {
        return false;
    }
    let dev = by_index.get(&e.ifindex());
    if flags & ntf::SELF != 0 {
        if let Some(vx) = dev.filter(|d| d.kind() == Some("vxlan")) {
            let data = InfoData::of(vx);
            let default_remote = data
                .ipv4(vxlan::IFLA_VXLAN_GROUP)
                .map(IpAddr::V4)
                .or_else(|| data.ipv6(vxlan::IFLA_VXLAN_GROUP6).map(IpAddr::V6));
            let is_default = mac.iter().all(|b| *b == 0)
                && e.port().is_none()
                && e.vni().is_none()
                && default_remote.is_some()
                && e.destination().copied() == default_remote;
            return !is_default;
        }
        let multicast = mac[0] & 1 != 0;
        return !multicast && !link_macs.contains(mac);
    }
    let own_mac = dev.and_then(|d| d.address()) == Some(mac);
    !(state & nud::PERMANENT != 0 && !ext_learned && own_mac)
}

fn fdb_label(e: &NeighborMessage, names: &HashMap<u32, &str>) -> String {
    let mac = e.lladdr().map(mac_str).unwrap_or_default();
    let dev = names.get(&e.ifindex()).copied().unwrap_or("?");
    let mut s = format!("fdb entry {mac} dev {dev}");
    if let Some(dst) = e.destination() {
        s.push_str(&format!(" dst {dst}"));
    }
    // Not the VLAN: one `bridge fdb add` without one makes an entry per
    // VLAN of the port as well as the untagged one, and it is one thing to
    // remove.
    if let Some(master) = e.master() {
        s.push_str(&format!(" master {}", names.get(&master).copied().unwrap_or("?")));
    }
    s
}

/// What deleting or flushing one link destroys that no config declares:
/// its user-made neighbours and proxy entries, and its nexthop objects. A
/// neighbour this config or the previous one declares is not: the apply
/// puts it back, or meant to remove it (#516).
fn undeclarable_on(
    ifindex: u32,
    name: &str,
    extras: &LinkExtras,
    declared: &[&DeclaredNeighbour],
    declared_nexthops: &HashSet<u32>,
    blocked_by: &mut Vec<Blocker>,
) {
    let is_declared = |dst: &IpAddr, proxy: bool| {
        declared
            .iter()
            .any(|n| n.dev == name && n.destination == *dst && n.proxy == proxy)
    };
    for n in extras.neighbours.iter().filter(|n| n.ifindex() == ifindex) {
        let permanent = n.header.ndm_state & nud::PERMANENT != 0;
        let ext_learned = n.header.ndm_flags & ntf::EXT_LEARNED != 0;
        if !(permanent || ext_learned) {
            continue;
        }
        let Some(dst) = n.destination() else { continue };
        if permanent && is_declared(dst, false) {
            continue;
        }
        blocked_by.push(Blocker::Neighbour {
            dev: name.to_string(),
            destination: *dst,
            permanent,
        });
    }
    for p in extras.proxies.iter().filter(|p| p.ifindex() == ifindex) {
        if let Some(dst) = p.destination()
            && !is_declared(dst, true)
        {
            blocked_by.push(Blocker::ProxyNeighbour {
                dev: name.to_string(),
                destination: *dst,
            });
        }
    }
    for nh in extras
        .nexthops
        .iter()
        .filter(|nh| nh.ifindex() == Some(ifindex) && !declared_nexthops.contains(&nh.id()))
    {
        blocked_by.push(Blocker::Nexthop {
            dev: name.to_string(),
            id: nh.id(),
            via: nh.gateway(),
        });
    }
}

/// The kernel state [`plan`] reads.
pub(crate) struct Live<'a> {
    pub(crate) links: &'a [LinkMessage],
    pub(crate) addresses: &'a [AddressMessage],
    pub(crate) routes: &'a [RouteMessage],
    pub(crate) qdiscs: &'a [TcMessage],
    pub(crate) extras: &'a LinkExtras,
    /// The id here of each namespace a veth peer is declared in (#516).
    pub(crate) netns_ids: &'a HashMap<crate::netlink::namespace::NetnsRef, Option<u32>>,
}

/// Compare every declared link's kind parameters with the live links, and
/// work out what a recreate takes with it.
pub(crate) fn plan(config: &NetworkConfig, opts: &PlanOptions, live: Live<'_>) -> KindPlan {
    let Live {
        links,
        addresses,
        routes,
        qdiscs,
        extras,
        netns_ids,
    } = live;
    let mut plan = KindPlan::default();
    let names: HashMap<u32, &str> = links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (l.ifindex(), n)))
        .collect();
    let by_name: HashMap<&str, &LinkMessage> = links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (n, l)))
        .collect();
    let by_index: HashMap<u32, &LinkMessage> = links.iter().map(|l| (l.ifindex(), l)).collect();
    // Tunnels and loopback have an all-zeros address, which is no MAC.
    let link_macs: HashSet<&[u8]> = links
        .iter()
        .filter_map(|l| l.address())
        .filter(|a| a.iter().any(|b| *b != 0))
        .collect();
    let nh_devs = nexthop_devices(&extras.nexthops);
    let declared: HashMap<&str, &DeclaredLink> =
        config.links.iter().map(|l| (l.name.as_str(), l)).collect();
    let declared_neighbours: Vec<&DeclaredNeighbour> = config
        .neighbours
        .iter()
        .chain(opts.previous.iter().flat_map(|p| p.neighbours.iter()))
        .collect();
    // Nexthop objects this config or the previous one declares: put back,
    // or meant to go (#516).
    let declared_nexthops: HashSet<u32> = config
        .nexthops
        .iter()
        .chain(opts.previous.iter().flat_map(|p| p.nexthops.iter()))
        .map(|n| n.id)
        .collect();
    // FDB entries this config or the previous one declares: put back, or
    // meant to go (#516). Declared without a VLAN, an entry is one per VLAN
    // of the port as well as the untagged one.
    let declared_fdb: Vec<&DeclaredFdb> = config
        .fdb
        .iter()
        .chain(opts.previous.iter().flat_map(|p| p.fdb.iter()))
        .collect();
    let fdb_declared = |e: &NeighborMessage| {
        let dev = names.get(&e.ifindex()).copied();
        declared_fdb.iter().any(|d| {
            Some(d.dev.as_str()) == dev
                && e.lladdr() == Some(&d.mac[..])
                && (d.vlan.is_none() || e.vlan() == d.vlan)
                && e.destination().copied() == d.dst
        })
    };
    // What a purging apply deletes anyway does not hold a recreate back:
    // refusing over it made an edit that changes a VLAN id and drops one of
    // its addresses take two applies (#471).
    let address_scope = opts.purge_address_scope(config);
    let purged_address = |name: &str, a: &AddressMessage| {
        opts.purge && address_scope.contains(name) && purgeable_address(a)
    };
    let route_tables = opts.purge_table_scope(config);
    let purged_route = |r: &RouteMessage| opts.purge && purgeable_route(r, &route_tables, config);

    let mut seeds = Vec::new();
    for link in &config.links {
        let Some(live) = by_name.get(link.name.as_str()) else {
            continue;
        };
        let mut d = compare(link, live, &names);
        // A veth peer kept in a declared namespace (#516).
        if live.kind() == Some("veth")
            && let Some(want) = link.peer_netns()
        {
            let want_id = if want.is_default() { None } else { netns_ids.get(want).copied().flatten() };
            let have = live.link_netnsid.and_then(|id| u32::try_from(id).ok());
            if have != want_id || (!want.is_default() && want_id.is_none()) {
                let here = |id: Option<u32>| id.map_or("here".to_string(), |id| format!("in namespace id {id}"));
                d.recreate.push(format!("veth peer {} -> in {want}", here(have)));
            }
        }
        // The peer's name, when the peer is here (#793): renamed in place
        // (#804), unless another link has the name, when the pair is made
        // again. A peer elsewhere may have been renamed there, by a CNI for
        // one, and is left alone.
        if let DeclaredLinkType::Veth { peer, .. } | DeclaredLinkType::Netkit { peer, .. } =
            &link.link_type
            && link.peer_netns().is_none_or(|n| n.is_default())
            && live.link_netnsid.is_none()
            && let Some(have) = live.link().and_then(|i| names.get(&i))
            && *have != peer.as_str()
        {
            if by_name.contains_key(peer.as_str()) {
                d.recreate.push(format!("peer {have} -> {peer}"));
            } else {
                plan.renames.push(LinkRename {
                    from: have.to_string(),
                    to: peer.clone(),
                    peer_of: link.name.clone(),
                });
            }
        }
        if !d.recreate.is_empty() || !d.refuse.is_empty() {
            let mut reasons = d.refuse.clone();
            reasons.extend(d.recreate.iter().cloned());
            seeds.push((*live, reasons.join(", "), d.refuse, false));
        } else if let Some(update) = d.update {
            plan.updates.insert(link.name.clone(), update);
        }
    }

    // What the kernel deletes along with a link: the links whose IFLA_LINK
    // is it (VLANs, macvlans, a veth's peer, …) and the VXLANs whose
    // underlay it is.
    let stacked_on = |lower: u32| -> Vec<&LinkMessage> {
        links
            .iter()
            .filter(|l| l.ifindex() != lower)
            .filter(|l| {
                (l.link() == Some(lower) && l.link_netnsid.is_none())
                    || (l.kind() == Some("vxlan")
                        && InfoData::of(l).u32(vxlan::IFLA_VXLAN_LINK) == Some(lower))
            })
            .collect()
    };
    let declared_routes: HashSet<(IpAddr, u8, u32)> = config
        .routes
        .iter()
        .map(|r| {
            (
                super::diff::kernel_destination(r.destination, r.prefix_len),
                r.prefix_len,
                r.table.unwrap_or(254),
            )
        })
        .collect();
    let name_of = |ifindex: u32| names.get(&ifindex).copied().unwrap_or("?");
    let route_key = |r: &RouteMessage| {
        let dst = r.destination.unwrap_or(if r.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        });
        (dst, r.dst_len(), r.table_id())
    };

    // Links the previous config declared and this one does not (#512).
    for live in removed_links(config, opts, links) {
        seeds.push((live, "no longer declared".to_string(), Vec::new(), true));
    }
    // What the previous config declared is the config's own: deleting it
    // with a removed link is the point, not a loss.
    let previous = opts.previous.as_deref();
    // A tagged link is the config's, and so is what is on it (#512).
    let tagged_name = |name: &str| by_name.get(name).is_some_and(|l| tagged(config, l));
    let previously_declared_link = |name: &str| {
        previous.is_some_and(|p| p.links.iter().any(|l| l.name == name)) || tagged_name(name)
    };
    let previously_declared_address = |name: &str, addr: IpAddr, len: u8| {
        tagged_name(name)
            || previous.is_some_and(|p| {
                p.addresses
                    .iter()
                    .any(|d| d.dev == name && d.address == addr && d.prefix_len == len)
            })
    };
    let previous_routes: HashSet<(IpAddr, u8, u32)> = previous
        .iter()
        .flat_map(|p| p.routes.iter())
        .map(|r| {
            (
                super::diff::kernel_destination(r.destination, r.prefix_len),
                r.prefix_len,
                r.table.unwrap_or(254),
            )
        })
        .collect();
    let previously_declared_qdisc = |name: &str, parent: QdiscParent| {
        tagged_name(name)
            || previous.is_some_and(|p| {
                p.qdiscs
                    .iter()
                    .any(|d| d.dev == name && d.effective_parent() == parent)
            })
    };

    let dumps = super::restore::Dumps {
        links,
        addresses,
        routes,
        qdiscs,
        extras,
        names: &names,
    };
    for (seed, reason, refuse, remove) in seeds {
        if plan.gone.contains(&seed.ifindex()) {
            continue;
        }
        // The seed and everything stacked on it, transitively, parents
        // first.
        let mut closure: Vec<(&LinkMessage, Option<u32>)> = vec![(seed, None)];
        let mut seen: HashSet<u32> = HashSet::from([seed.ifindex()]);
        let mut queue: VecDeque<u32> = VecDeque::from([seed.ifindex()]);
        while let Some(lower) = queue.pop_front() {
            for l in stacked_on(lower) {
                if seen.insert(l.ifindex()) {
                    closure.push((l, Some(lower)));
                    queue.push_back(l.ifindex());
                }
            }
        }
        let members: HashSet<u32> = seen;

        let mut blocked_by: Vec<Blocker> = refuse
            .into_iter()
            .map(|reason| Blocker::Unsupported { reason })
            .collect();
        let mut preserved: HashMap<String, super::preserve::PreservedTc> = HashMap::new();
        for (l, lower) in &closure {
            let name = name_of(l.ifindex());
            // A veth's (or vxcan's) peer in another namespace is not in the
            // closure — nothing here can declare it — and the kernel
            // deletes it with the link all the same (#471).
            // A veth whose peer's namespace the config declares is put back
            // there whole (#516).
            let peer_declared = declared.get(name).is_some_and(|d| d.peer_netns().is_some());
            if matches!(l.kind(), Some("veth" | "vxcan"))
                && !peer_declared
                && let Some(netnsid) = l.link_netnsid
            {
                blocked_by.push(Blocker::ForeignNetnsPeer {
                    link: name.to_string(),
                    netnsid,
                });
            }
            if let Some(lower) = lower {
                let kind = l.kind().unwrap_or("link");
                let stacked = |declared_existing| Blocker::StackedLink {
                    name: name.to_string(),
                    link_kind: kind.to_string(),
                    lower: name_of(*lower).to_string(),
                    declared_existing,
                };
                match declared.get(name) {
                    // Removed too: the previous config declared it.
                    None if remove && previously_declared_link(name) => {}
                    None => blocked_by.push(stacked(false)),
                    Some(d) if d.link_type.kind().is_none() => blocked_by.push(stacked(true)),
                    Some(_) => {}
                }
            }
            for a in addresses.iter().filter(|a| a.ifindex() == l.ifindex()) {
                let Some(addr) = a.address else { continue };
                if a.scope() != Scope::Universe || purged_address(name, a) {
                    continue;
                }
                let is_declared =
                    config.addresses.iter().any(|d| {
                        d.dev == name && d.address == addr && d.prefix_len == a.prefix_len()
                    }) || (remove && previously_declared_address(name, addr, a.prefix_len()));
                if !is_declared {
                    blocked_by.push(Blocker::Address {
                        dev: name.to_string(),
                        address: addr,
                        prefix_len: a.prefix_len(),
                    });
                }
            }
            for r in routes {
                if r.protocol() == RouteProtocol::Kernel
                    || declared_routes.contains(&route_key(r))
                    || (remove && (previous_routes.contains(&route_key(r)) || tagged_name(name)))
                    || purged_route(r)
                {
                    continue;
                }
                if let Some(how) = route_through(r, l.ifindex(), &nh_devs) {
                    blocked_by.push(route_label(r, name, how));
                }
            }
            // What a declared TC tree owns, it puts back; what the previous
            // config's owned, the purge removes (#514).
            let trees: Vec<&super::tc_tree::DeclaredTc> = config
                .tc
                .iter()
                .chain(previous.iter().flat_map(|p| p.tc.iter()))
                .filter(|t| t.dev == name)
                .collect();
            // With `preserve_undeclared_tc`, what can be replayed is kept
            // rather than refusing the recreate (#645).
            let preserving = opts.preserve_undeclared_tc && !remove;
            let mut kept = super::preserve::PreservedTc {
                dev: name.to_string(),
                ..Default::default()
            };
            for q in qdiscs.iter().filter(|q| q.ifindex() == l.ifindex()) {
                // A qdisc with handle 0: is the kernel's default for the
                // device, recreated with it.
                if q.handle().major() == 0 {
                    continue;
                }
                let parent = if q.is_root() {
                    QdiscParent::Root
                } else if q.parent().is_ingress() {
                    QdiscParent::Ingress
                } else {
                    // A qdisc under a class — an HTB leaf, say. A declared
                    // root never covers one: it was ignored, and the
                    // recreate took it (#472). A TC tree that owns the
                    // class puts it back, or removes it (#514).
                    if trees.iter().any(|t| t.owns_leaf(q.parent())) {
                        continue;
                    }
                    if let Some(o) = preserving.then(|| super::preserve::TcObject::qdisc(q)).flatten()
                    {
                        kept.qdiscs.push(o);
                        continue;
                    }
                    blocked_by.push(Blocker::Qdisc {
                        dev: name.to_string(),
                        qdisc: q.kind().unwrap_or("?").to_string(),
                        under: Some((q.handle(), q.parent())),
                    });
                    continue;
                };
                let is_declared = config
                    .qdiscs
                    .iter()
                    .any(|d| d.dev == name && d.effective_parent() == parent)
                    || (remove && previously_declared_qdisc(name, parent));
                let kept_qdisc = (!is_declared && preserving)
                    .then(|| super::preserve::TcObject::qdisc(q))
                    .flatten();
                if let Some(o) = kept_qdisc {
                    kept.qdiscs.push(o);
                } else if !is_declared {
                    blocked_by.push(Blocker::Qdisc {
                        dev: name.to_string(),
                        qdisc: q.kind().unwrap_or("?").to_string(),
                        under: None,
                    });
                }
            }
            // Classes users make, and every filter — a `RateLimiter`'s tree,
            // an IFB redirect. A declared root or ingress qdisc came back
            // after the recreate, bare (#472). A prio's bands, an mq's
            // queues and the flows fq_codel lists are its own, and come
            // back with it.
            for c in extras.classes.iter().filter(|c| {
                c.ifindex() == l.ifindex()
                    && matches!(c.kind(), Some("htb" | "hfsc" | "drr" | "qfq" | "cbq"))
                    && !trees.iter().any(|t| t.owns_class(c.handle()))
            }) {
                if preserving {
                    // HFSC's root class comes back with its qdisc.
                    if c.handle().minor() != 0 {
                        kept.classes.push(super::preserve::TcObject::from_live(c));
                    }
                    continue;
                }
                blocked_by.push(Blocker::Class {
                    dev: name.to_string(),
                    qdisc: c.kind().unwrap_or("?").to_string(),
                    handle: c.handle(),
                });
            }
            for f in extras.filters.iter().filter(|f| {
                f.ifindex() == l.ifindex() && !trees.iter().any(|t| t.owns_filter(f.parent()))
            }) {
                if preserving && super::preserve::replayable_filter(f) {
                    if !super::preserve::automatic_u32_table(f) {
                        for target in super::preserve::mirred_targets(f) {
                            kept.targets.insert(target, name_of(target).to_string());
                        }
                        kept.filters.push(super::preserve::TcObject::from_live(f));
                    }
                    continue;
                }
                blocked_by.push(Blocker::Filter {
                    dev: name.to_string(),
                    filter: f.kind().unwrap_or("?").to_string(),
                    priority: f.priority().as_u16(),
                    parent: f.parent(),
                });
            }
            if !kept.is_empty() {
                preserved.insert(name.to_string(), kept);
            }
            // The link's FDB entries, and — for a bridge — every entry in
            // its database, whichever port it is on.
            for e in extras.fdb.iter().filter(|e| {
                e.ifindex() == l.ifindex() || e.master() == Some(l.ifindex())
            }) {
                if fdb_entry_is_users(e, &by_index, &link_macs) && !fdb_declared(e) {
                    blocked_by.push(Blocker::Fdb {
                        entry: fdb_label(e, &names),
                        via: None,
                    });
                }
            }
            // Entries on another device that send *through* this one — a
            // VXLAN remote with `via` (`NDA_IFINDEX`, the rdst's
            // remote_ifindex). Deleting the link leaves them naming its old
            // ifindex: `bridge fdb` shows `via if10`, and the new link is
            // never used (#438). Entries on a device recreated with it go
            // anyway.
            for e in extras.fdb.iter().filter(|e| {
                e.ifindex_attr == Some(l.ifindex()) && !members.contains(&e.ifindex())
            }) {
                if fdb_entry_is_users(e, &by_index, &link_macs) {
                    blocked_by.push(Blocker::Fdb {
                        entry: fdb_label(e, &names),
                        via: Some(name.to_string()),
                    });
                }
            }
            undeclarable_on(l.ifindex(), name, extras, &declared_neighbours, &declared_nexthops, &mut blocked_by);
        }

        // The ports of every deleted master, which the kernel releases.
        let ports: Vec<(&LinkMessage, &LinkMessage)> = closure
            .iter()
            .flat_map(|(l, _)| {
                links
                    .iter()
                    .filter(|p| p.master() == Some(l.ifindex()) && !members.contains(&p.ifindex()))
                    .map(move |p| (*l, p))
            })
            .collect();
        for (master, port) in &ports {
            let port_name = name_of(port.ifindex());
            if !declared.contains_key(port_name) && !(remove && previously_declared_link(port_name))
            {
                blocked_by.push(Blocker::Port {
                    name: port_name.to_string(),
                    master: name_of(master.ifindex()).to_string(),
                });
            }
        }
        // The ports a bond closes or a VRF unlinks on the way out, and the
        // VLANs on them, lose their routes, IPv6 addresses, neighbours and
        // nexthop objects, as a link going down does. What the config
        // declares there is put back; what it does not is gone — except the
        // routes in a deleted VRF's own table, which nothing reaches once
        // the VRF is gone.
        let flushing: HashSet<u32> = ports
            .iter()
            .filter(|(m, _)| matches!(m.kind(), Some("bond" | "vrf")))
            .map(|(_, p)| p.ifindex())
            .collect();
        let old_tables: HashSet<u32> = closure
            .iter()
            .filter(|(l, _)| l.kind() == Some("vrf"))
            .filter_map(|(l, _)| InfoData::of(l).u32(vrf_attr::IFLA_VRF_TABLE))
            .collect();
        let mut flushed: Vec<u32> = with_vlans_on(links, &flushing).into_iter().collect();
        flushed.sort_unstable();
        for &ifindex in &flushed {
            let name = name_of(ifindex);
            for a in addresses.iter().filter(|a| a.ifindex() == ifindex) {
                let Some(addr) = a.address.filter(|a| a.is_ipv6()) else { continue };
                if a.scope() != Scope::Universe || purged_address(name, a) {
                    continue;
                }
                let is_declared =
                    config.addresses.iter().any(|d| {
                        d.dev == name && d.address == addr && d.prefix_len == a.prefix_len()
                    }) || (remove && previously_declared_address(name, addr, a.prefix_len()));
                if !is_declared {
                    blocked_by.push(Blocker::Address {
                        dev: name.to_string(),
                        address: addr,
                        prefix_len: a.prefix_len(),
                    });
                }
            }
            for r in routes {
                if r.protocol() == RouteProtocol::Kernel
                    || declared_routes.contains(&route_key(r))
                    || (remove && (previous_routes.contains(&route_key(r)) || tagged_name(name)))
                    || old_tables.contains(&r.table_id())
                    || purged_route(r)
                {
                    continue;
                }
                if let Some(how) = route_through(r, ifindex, &nh_devs) {
                    blocked_by.push(route_label(r, name, how));
                }
            }
            undeclarable_on(ifindex, name, extras, &declared_neighbours, &declared_nexthops, &mut blocked_by);
        }

        // A bridge entry is dumped once per VLAN as well as once without.
        let mut seen_reasons = HashSet::new();
        blocked_by.retain(|b| seen_reasons.insert(b.clone()));
        // What the caller owns is never a reason to refuse; it is reported
        // as destroyed. So is what the policy lets go (#513). A kind that
        // cannot be recreated at all stays a refusal under any policy.
        let (mut destroys, mut blocked_by): (Vec<Blocker>, Vec<Blocker>) = blocked_by
            .into_iter()
            .partition(|b| opts.owned.iter().any(|o| o.covers(b)));
        let unsupported = blocked_by
            .iter()
            .any(|b| matches!(b, Blocker::Unsupported { .. }));
        if !unsupported && opts.recreate_policy.allows(&blocked_by) {
            destroys.append(&mut blocked_by);
        }

        // What the deletion takes, read back for its inverse (#745). A link
        // an earlier seed's deletion took is that one's to put back.
        let read_back = |gone: &HashSet<u32>| {
            let deleting: Vec<&LinkMessage> = closure
                .iter()
                .map(|(l, _)| *l)
                .filter(|l| !gone.contains(&l.ifindex()))
                .collect();
            let released: Vec<&LinkMessage> = ports.iter().map(|(_, p)| *p).collect();
            match super::restore::capture(&dumps, &deleting, &released, &flushed, gone) {
                Ok(r) => (Some(Box::new(r)), Vec::new()),
                Err(why) => (None, why),
            }
        };

        if remove {
            let refused = !blocked_by.is_empty();
            let (restore, unrestorable) = if refused { (None, Vec::new()) } else { read_back(&plan.gone) };
            plan.remove.push(LinkRemoval {
                name: name_of(seed.ifindex()).to_string(),
                link_kind: seed.kind().unwrap_or("link").to_string(),
                stacked_on: None,
                blocked_by,
                destroys: if refused { Vec::new() } else { destroys },
                restore,
                unrestorable,
            });
            if refused {
                continue;
            }
            for (l, lower) in &closure {
                plan.gone.insert(l.ifindex());
                if let Some(lower) = lower {
                    plan.remove.push(LinkRemoval {
                        name: name_of(l.ifindex()).to_string(),
                        link_kind: l.kind().unwrap_or("link").to_string(),
                        stacked_on: Some(name_of(*lower).to_string()),
                        blocked_by: Vec::new(),
                        destroys: Vec::new(),
                        restore: None,
                        unrestorable: Vec::new(),
                    });
                }
            }
            for (master, port) in &ports {
                let closes = master.kind() == Some("bond");
                plan.released.insert(port.ifindex(), closes);
                if flushing.contains(&port.ifindex()) {
                    plan.cycled.insert(port.ifindex());
                }
            }
            continue;
        }

        if !blocked_by.is_empty() {
            plan.recreate.push(LinkRecreate {
                name: name_of(seed.ifindex()).to_string(),
                reason,
                blocked_by,
                resets: Vec::new(),
                destroys: Vec::new(),
                preserved_tc: None,
                restore: None,
                unrestorable: Vec::new(),
            });
            continue;
        }
        // The seed's entry, first in the closure, carries what it destroys
        // and what puts it all back.
        let mut destroys = Some(destroys);
        let mut read = Some(read_back(&plan.gone));

        for (l, lower) in &closure {
            let name = name_of(l.ifindex());
            plan.gone.insert(l.ifindex());
            if l.is_up() {
                plan.was_up.insert(name.to_string());
            }
            let reason = match lower {
                None => reason.clone(),
                Some(lower) => {
                    format!("it is stacked on {}, which is recreated", name_of(*lower))
                }
            };
            let mut resets = Vec::new();
            if let Some(alias) = l.alias() {
                resets.push(format!("alias {alias:?}"));
            }
            if declared.get(name).is_none_or(|d| d.address.is_none())
                && let Some(mac) = l.address().filter(|m| m.len() == 6)
            {
                resets.push(format!(
                    "MAC address {} (the kernel picks a new one)",
                    mac_str(mac)
                ));
            }
            plan.recreate.push(LinkRecreate {
                name: name.to_string(),
                reason,
                blocked_by: Vec::new(),
                resets,
                destroys: destroys.take().unwrap_or_default(),
                preserved_tc: preserved.remove(name),
                restore: read.as_mut().and_then(|(r, _)| r.take()),
                unrestorable: read.take().map(|(_, why)| why).unwrap_or_default(),
            });
        }
        for (master, port) in &ports {
            let closes = master.kind() == Some("bond");
            plan.released.insert(port.ifindex(), closes);
            if flushing.contains(&port.ifindex()) {
                plan.cycled.insert(port.ifindex());
            }
        }
    }

    // A recreated link needs no in-place change.
    plan.updates.retain(|name, _| {
        by_name
            .get(name.as_str())
            .is_none_or(|l| !plan.gone.contains(&l.ifindex()))
    });
    plan
}

/// Record a whole-set update: the first change line carries the attributes,
/// the rest are notes. With no attributes left (everything back to the
/// kernel's defaults) an empty one stands in, as for ip6gre.
fn update_all(d: &mut KindDiff, kind: &'static str, attrs: Vec<KindAttr>, changes: Vec<String>) {
    let mut changes = changes.into_iter();
    let Some(first) = changes.next() else {
        return;
    };
    let mut attrs = attrs.into_iter();
    match attrs.next() {
        Some(attr) => d.update(kind, attr, first),
        None => d.update(kind, KindAttr::Bytes(0, Vec::new()), first),
    }
    let u = d.update.as_mut().expect("set above");
    u.attrs.extend(attrs);
    u.changes.extend(changes);
}

/// A vti6's declared parameters against the live link's (#680).
/// `vti6_netlink_parms` rebuilds the configuration from the request, so a
/// change sends them all. Its key has no flag: 0 is none.
fn compare_vti6(
    p: &super::types::Ip6tnlParams,
    data: &InfoData<'_>,
    names: &HashMap<u32, &str>,
    d: &mut KindDiff,
) {
    // IFLA_VTI_*.
    const LINK: u16 = 1;
    const IKEY: u16 = 2;
    const OKEY: u16 = 3;
    const LOCAL: u16 = 4;
    const REMOTE: u16 = 5;
    let addr = |t| data.ipv6(t).filter(|a| !a.is_unspecified());
    let have_key = data.u32_be(IKEY).filter(|k| *k != 0);
    let have_okey = data.u32_be(OKEY).filter(|k| *k != 0);
    let have_dev = data.u32(LINK).filter(|i| *i != 0).and_then(|i| names.get(&i).copied());
    let show = |v: Option<String>| v.unwrap_or_else(|| "none".into());
    let mut changes = Vec::new();
    let mut note = |what: &str, have: String, want: String| {
        if have != want {
            changes.push(format!("vti6 {what} {have} -> {want}"));
        }
    };
    note("local", show(addr(LOCAL).map(|a| a.to_string())), show(p.local.map(|a| a.to_string())));
    note("remote", show(addr(REMOTE).map(|a| a.to_string())), show(p.remote.map(|a| a.to_string())));
    note("key", keys_text(have_key, have_okey), show(p.key.map(|k| k.to_string())));
    note("dev", show(have_dev.map(str::to_string)), show(p.underlay_dev.clone()));
    if changes.is_empty() {
        return;
    }
    let mut attrs = Vec::new();
    if let Some(a) = p.local {
        attrs.push(KindAttr::Bytes(LOCAL, a.octets().to_vec()));
    }
    if let Some(a) = p.remote {
        attrs.push(KindAttr::Bytes(REMOTE, a.octets().to_vec()));
    }
    if let Some(k) = p.key {
        attrs.push(KindAttr::Bytes(IKEY, k.to_be_bytes().to_vec()));
        attrs.push(KindAttr::Bytes(OKEY, k.to_be_bytes().to_vec()));
    }
    if let Some(dev) = &p.underlay_dev {
        attrs.push(KindAttr::Ifindex(LINK, dev.clone()));
    }
    update_all(d, "vti6", attrs, changes);
    if let Some(u) = d.update.as_mut() {
        u.was = Some(live_set(data, &[IKEY, OKEY, LOCAL, REMOTE], Some(LINK), names));
    }
}

/// An erspan's or ip6erspan's declared parameters against the live link's
/// (#680). `ipgre_netlink_parms`/`ip6gre_netlink_parms` rebuild the
/// configuration from the request, so a change sends them all, with the
/// `GRE_SEQ | GRE_KEY` flags `erspan_validate` requires.
fn compare_erspan(
    kind: &'static str,
    p: &super::types::ErspanParams,
    data: &InfoData<'_>,
    names: &HashMap<u32, &str>,
    d: &mut KindDiff,
) {
    use crate::netlink::link::{ErspanDirection, ErspanVersion};
    // IFLA_GRE_*.
    const LINK: u16 = 1;
    const IFLAGS: u16 = 2;
    const OFLAGS: u16 = 3;
    const IKEY: u16 = 4;
    const OKEY: u16 = 5;
    const LOCAL: u16 = 6;
    const REMOTE: u16 = 7;
    const TTL: u16 = 8;
    const ERSPAN_INDEX: u16 = 21;
    const ERSPAN_VER: u16 = 22;
    const ERSPAN_DIR: u16 = 23;
    const ERSPAN_HWID: u16 = 24;
    const FLAGS: u16 = 0x1000 | 0x2000;
    let v6 = kind == "ip6erspan";
    let addr = |t| -> Option<std::net::IpAddr> {
        if v6 {
            data.ipv6(t).filter(|a| !a.is_unspecified()).map(Into::into)
        } else {
            data.ipv4(t).filter(|a| !a.is_unspecified()).map(Into::into)
        }
    };
    let have_dev = data.u32(LINK).filter(|i| *i != 0).and_then(|i| names.get(&i).copied());
    let have_version = match data.u8(ERSPAN_VER) {
        Some(1) => Some(ErspanVersion::V1 {
            index: data.u32(ERSPAN_INDEX).unwrap_or(0),
        }),
        Some(2) => Some(ErspanVersion::V2 {
            direction: if data.u8(ERSPAN_DIR) == Some(1) {
                ErspanDirection::Egress
            } else {
                ErspanDirection::Ingress
            },
            hwid: data.u16_ne(ERSPAN_HWID).and_then(|h| u8::try_from(h).ok()).unwrap_or(0),
        }),
        _ => None,
    };
    let show = |v: Option<String>| v.unwrap_or_else(|| "none".into());
    let mut changes = Vec::new();
    let mut note = |what: &str, have: String, want: String| {
        if have != want {
            changes.push(format!("{kind} {what} {have} -> {want}"));
        }
    };
    note("local", show(addr(LOCAL).map(|a| a.to_string())), show(p.local.map(|a| a.to_string())));
    note("remote", show(addr(REMOTE).map(|a| a.to_string())), show(p.remote.map(|a| a.to_string())));
    if let Some(want) = p.ttl {
        note("ttl", show(data.u8(TTL).map(|v| v.to_string())), want.to_string());
    }
    // The session is the key both ways: the output key is compared too
    // (#782).
    note("session", keys_text(data.u32_be(IKEY), data.u32_be(OKEY)), p.session.to_string());
    note("version", show(have_version.map(|v| format!("{v:?}"))), format!("{:?}", p.version));
    note("dev", show(have_dev.map(str::to_string)), show(p.underlay_dev.clone()));
    if changes.is_empty() {
        return;
    }
    let ip = |a: std::net::IpAddr| match a {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    let mut attrs = vec![
        KindAttr::Bytes(IFLAGS, FLAGS.to_be_bytes().to_vec()),
        KindAttr::Bytes(OFLAGS, FLAGS.to_be_bytes().to_vec()),
        KindAttr::Bytes(IKEY, u32::from(p.session).to_be_bytes().to_vec()),
        KindAttr::Bytes(OKEY, u32::from(p.session).to_be_bytes().to_vec()),
    ];
    match p.version {
        ErspanVersion::V1 { index } => {
            attrs.push(KindAttr::U8(ERSPAN_VER, 1));
            attrs.push(KindAttr::U32(ERSPAN_INDEX, index));
        }
        ErspanVersion::V2 { direction, hwid } => {
            attrs.push(KindAttr::U8(ERSPAN_VER, 2));
            attrs.push(KindAttr::U8(ERSPAN_DIR, direction as u8));
            attrs.push(KindAttr::U16(ERSPAN_HWID, u16::from(hwid)));
        }
    }
    if let Some(a) = p.local {
        attrs.push(KindAttr::Bytes(LOCAL, ip(a)));
    }
    if let Some(a) = p.remote {
        attrs.push(KindAttr::Bytes(REMOTE, ip(a)));
    }
    if let Some(t) = p.ttl {
        attrs.push(KindAttr::U8(TTL, t));
    }
    if let Some(dev) = &p.underlay_dev {
        attrs.push(KindAttr::Ifindex(LINK, dev.clone()));
    }
    update_all(d, kind, attrs, changes);
    if let Some(u) = d.update.as_mut() {
        let set = [IFLAGS, OFLAGS, IKEY, OKEY, LOCAL, REMOTE, TTL, ERSPAN_INDEX, ERSPAN_VER, ERSPAN_DIR, ERSPAN_HWID];
        u.was = Some(live_set(data, &set, Some(LINK), names));
    }
}

/// A tunnel's keys as `ip -d link` would name them: one key, when it is the
/// same both ways, as a declared key is (#782).
fn keys_text(ikey: Option<u32>, okey: Option<u32>) -> String {
    match (ikey, okey) {
        (i, o) if i == o => i.map_or_else(|| "none".to_string(), |k| k.to_string()),
        (i, o) => format!("ikey {} okey {}", or_none(i), or_none(o)),
    }
}

/// Where an IPv4 tunnel family keeps each parameter in `IFLA_INFO_DATA`.
struct TunnelIds {
    link: u16,
    local: u16,
    remote: u16,
    ttl: Option<u16>,
    /// The key attributes, in and out, and the GRE flags that say a key is
    /// there; vti has no flags.
    keys: Option<TunnelKeyIds>,
}

/// A tunnel family's key attributes, in and out, and its flag attributes.
type TunnelKeyIds = (u16, u16, Option<(u16, u16)>);

impl TunnelIds {
    /// `IFLA_GRE_*`.
    const GRE: Self = Self {
        link: 1,
        local: 6,
        remote: 7,
        ttl: Some(8),
        keys: Some((4, 5, Some((2, 3)))),
    };
    /// `IFLA_IPTUN_*`: ipip and sit.
    const IPTUN: Self = Self {
        link: 1,
        local: 2,
        remote: 3,
        ttl: Some(4),
        keys: None,
    };
    /// `IFLA_VTI_*`.
    const VTI: Self = Self {
        link: 1,
        local: 4,
        remote: 5,
        ttl: None,
        keys: Some((2, 3, None)),
    };
}

/// A tunnel's declared parameters against the live link's (#516). Any
/// difference sends them all: the kernel's tunnel `changelink` rebuilds
/// the configuration from the request, zeroing what it is not sent. A key
/// and its GRE flag are big-endian.
fn compare_tunnel(
    kind: &'static str,
    p: &super::types::TunnelParams,
    data: &InfoData<'_>,
    names: &HashMap<u32, &str>,
    ids: TunnelIds,
    d: &mut KindDiff,
) {
    const GRE_KEY: u16 = 0x2000;
    let (ids_ttl, ids_keys, ids_link) = (ids.ttl, ids.keys, ids.link);
    let have_local = data.ipv4(ids.local).filter(|a| !a.is_unspecified());
    let have_remote = data.ipv4(ids.remote).filter(|a| !a.is_unspecified());
    let have_ttl = ids.ttl.and_then(|t| data.u8(t)).filter(|t| *t != 0);
    // Each way's key: a GRE key is there when its flags say so, a VTI key
    // when it is not 0.
    let key_of = |key: u16, flags: Option<u16>| {
        let keyed = match flags {
            Some(flags) => data.0.get(&flags).and_then(|f| f.get(..2)).is_some_and(|f| {
                u16::from_be_bytes([f[0], f[1]]) & GRE_KEY != 0
            }),
            None => data.u32_be(key).is_some_and(|k| k != 0),
        };
        keyed.then(|| data.u32_be(key)).flatten()
    };
    let have_key = ids.keys.and_then(|(ikey, _, flags)| key_of(ikey, flags.map(|(i, _)| i)));
    let have_okey = ids.keys.and_then(|(_, okey, flags)| key_of(okey, flags.map(|(_, o)| o)));
    let have_dev = data
        .u32(ids.link)
        .filter(|i| *i != 0)
        .and_then(|i| names.get(&i).copied());
    let mut changes = Vec::new();
    let mut note = |what: &str, have: String, want: String| {
        if have != want {
            changes.push(format!("{kind} {what} {have} -> {want}"));
        }
    };
    let show = |v: Option<String>| v.unwrap_or_else(|| "none".into());
    note("local", show(have_local.map(|a| a.to_string())), show(p.local.map(|a| a.to_string())));
    note("remote", show(have_remote.map(|a| a.to_string())), show(p.remote.map(|a| a.to_string())));
    // An unset TTL is the kernel's (0, inherit; sit's is 64): not compared.
    if ids.ttl.is_some() && p.ttl.is_some() {
        note("ttl", show(have_ttl.map(|t| t.to_string())), show(p.ttl.map(|t| t.to_string())));
    }
    if ids.keys.is_some() {
        note("key", keys_text(have_key, have_okey), show(p.key.map(|k| k.to_string())));
    }
    note("dev", show(have_dev.map(str::to_string)), show(p.underlay_dev.clone()));
    if changes.is_empty() {
        return;
    }
    let mut attrs = Vec::new();
    if let Some(a) = p.local {
        attrs.push(KindAttr::Bytes(ids.local, a.octets().to_vec()));
    }
    if let Some(a) = p.remote {
        attrs.push(KindAttr::Bytes(ids.remote, a.octets().to_vec()));
    }
    if let (Some(t), Some(attr)) = (p.ttl, ids.ttl) {
        attrs.push(KindAttr::U8(attr, t));
    }
    if let (Some(k), Some((ikey, okey, flags))) = (p.key, ids.keys) {
        if let Some((iflags, oflags)) = flags {
            attrs.push(KindAttr::Bytes(iflags, GRE_KEY.to_be_bytes().to_vec()));
            attrs.push(KindAttr::Bytes(oflags, GRE_KEY.to_be_bytes().to_vec()));
        }
        attrs.push(KindAttr::Bytes(ikey, k.to_be_bytes().to_vec()));
        attrs.push(KindAttr::Bytes(okey, k.to_be_bytes().to_vec()));
    }
    if let Some(dev) = &p.underlay_dev {
        attrs.push(KindAttr::Ifindex(ids.link, dev.clone()));
    }
    let mut changes = changes.into_iter();
    // The first change line carries the whole set; the rest are notes.
    if let Some(first) = changes.next() {
        let mut attrs = attrs.into_iter();
        match attrs.next() {
            Some(attr) => d.update(kind, attr, first),
            // Everything back to the kernel's defaults: an empty data nest.
            None => d.update(kind, KindAttr::Bytes(0, Vec::new()), first),
        }
        for attr in attrs {
            d.update.as_mut().expect("set above").attrs.push(attr);
        }
    }
    if let Some(u) = d.update.as_mut() {
        u.changes.extend(changes);
        // The whole live set, for the inverse (#649).
        let mut ids = vec![ids.local, ids.remote];
        ids.extend(ids_ttl);
        if let Some((ikey, okey, flags)) = ids_keys {
            ids.extend([ikey, okey]);
            ids.extend(flags.into_iter().flat_map(|(i, o)| [i, o]));
        }
        u.was = Some(live_set(data, &ids, Some(ids_link), names));
    }
}

/// How a bridge port differs from its declared options (#516): the changes,
/// and the config that makes them. Read from the dump's slave data, which a
/// link enslaved to a bridge carries.
pub(crate) fn port_changes(
    declared: &super::types::PortOptions,
    live: &LinkMessage,
) -> (Vec<String>, Option<crate::netlink::link::BridgePortConfig>) {
    use crate::netlink::types::link::brport::*;
    let data = InfoData::slave_of(live);
    let is_bridge_port = live.link_info().and_then(|i| i.slave_kind()) == Some("bridge");
    let mut lines = Vec::new();
    let mut want = super::types::PortOptions::default();
    let mut flag = |name: &str, attr: u16, decl: Option<bool>, slot: &mut Option<bool>| {
        if let Some(on) = decl
            && (!is_bridge_port || data.u8(attr).map(|v| v != 0) != Some(on))
        {
            lines.push(format!("{name} {}", if on { "on" } else { "off" }));
            *slot = Some(on);
        }
    };
    flag("learning", IFLA_BRPORT_LEARNING, declared.learning, &mut want.learning);
    flag("flood", IFLA_BRPORT_UNICAST_FLOOD, declared.flood, &mut want.flood);
    flag("mcast_flood", IFLA_BRPORT_MCAST_FLOOD, declared.mcast_flood, &mut want.mcast_flood);
    flag("bcast_flood", IFLA_BRPORT_BCAST_FLOOD, declared.bcast_flood, &mut want.bcast_flood);
    flag("isolated", IFLA_BRPORT_ISOLATED, declared.isolated, &mut want.isolated);
    flag("neigh_suppress", IFLA_BRPORT_NEIGH_SUPPRESS, declared.neigh_suppress, &mut want.neigh_suppress);
    flag("hairpin", IFLA_BRPORT_MODE, declared.hairpin, &mut want.hairpin);
    flag("proxy_arp", IFLA_BRPORT_PROXYARP, declared.proxy_arp, &mut want.proxy_arp);
    flag("bpdu_guard", IFLA_BRPORT_GUARD, declared.bpdu_guard, &mut want.bpdu_guard);
    flag("root_block", IFLA_BRPORT_PROTECT, declared.root_block, &mut want.root_block);
    if let Some(cost) = declared.cost
        && (!is_bridge_port || data.u32(IFLA_BRPORT_COST) != Some(cost))
    {
        lines.push(format!("cost {cost}"));
        want.cost = Some(cost);
    }
    if let Some(prio) = declared.priority
        && (!is_bridge_port || data.u16_ne(IFLA_BRPORT_PRIORITY) != Some(prio))
    {
        lines.push(format!("port priority {prio}"));
        want.priority = Some(prio);
    }
    let config = (!lines.is_empty()).then(|| want.to_config());
    (lines, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::messages::LinkInfo;

    /// One netlink attribute: header, payload, padding.
    fn attr(t: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut out = Vec::with_capacity((len + 3) & !3);
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&t.to_ne_bytes());
        out.extend_from_slice(payload);
        out.resize((len + 3) & !3, 0);
        out
    }

    fn live(kind: &str, data: Vec<u8>) -> LinkMessage {
        LinkMessage {
            name: Some("l0".into()),
            link_info: Some(LinkInfo {
                kind: Some(kind.into()),
                data: Some(data),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn declared(cfg: NetworkConfig) -> DeclaredLink {
        cfg.links.into_iter().next().expect("one link")
    }

    #[test]
    fn a_truncated_attribute_reads_as_absent() {
        let link = live("bond", attr(bond_attr::IFLA_BOND_MIIMON, &[1, 0]));
        let data = InfoData::of(&link);
        assert_eq!(data.u32(bond_attr::IFLA_BOND_MIIMON), None);
        assert_eq!(data.u8(bond_attr::IFLA_BOND_MODE), None);
    }

    #[test]
    fn a_vni_change_recreates_and_a_remote_change_does_not() {
        let mut data = attr(vxlan::IFLA_VXLAN_ID, &100u32.to_ne_bytes());
        data.extend(attr(vxlan::IFLA_VXLAN_GROUP, &[10, 0, 0, 2]));
        let link = live("vxlan", data);
        let names = HashMap::new();

        let vni = declared(NetworkConfig::new().link("l0", |l| {
            l.vxlan(200).vxlan_remote(Ipv4Addr::new(10, 0, 0, 2).into())
        }));
        let d = compare(&vni, &link, &names);
        assert_eq!(d.recreate, vec!["vxlan vni 100 -> 200".to_string()]);
        assert!(d.update.is_none());

        let remote = declared(NetworkConfig::new().link("l0", |l| {
            l.vxlan(100).vxlan_remote(Ipv4Addr::new(10, 0, 0, 3).into())
        }));
        let d = compare(&remote, &link, &names);
        assert!(d.recreate.is_empty(), "{:?}", d.recreate);
        let update = d.update.expect("an in-place change");
        assert_eq!(update.kind, "vxlan");
        assert!(matches!(
            update.attrs.as_slice(),
            [KindAttr::Bytes(t, b)] if *t == vxlan::IFLA_VXLAN_GROUP && b == &[10, 0, 0, 3]
        ));
    }

    /// IPv6 endpoints are read back and compared (#418); a change within
    /// the family is made in place, a change of family recreates.
    #[test]
    fn vxlan_ipv6_endpoints_are_compared() {
        let local: Ipv6Addr = "fd00::1".parse().unwrap();
        let mut data = attr(vxlan::IFLA_VXLAN_ID, &7u32.to_ne_bytes());
        data.extend(attr(vxlan::IFLA_VXLAN_LOCAL6, &local.octets()));
        let link = live("vxlan", data);
        let names = HashMap::new();
        let vx = |local: &str| {
            declared(NetworkConfig::new().link("l0", |l| {
                l.vxlan(7).vxlan_local(local.parse().unwrap())
            }))
        };

        let d = compare(&vx("fd00::1"), &link, &names);
        assert!(d.recreate.is_empty() && d.update.is_none(), "{d:?}");

        let d = compare(&vx("fd00::5"), &link, &names);
        assert!(d.recreate.is_empty(), "{d:?}");
        let update = d.update.expect("an in-place change");
        assert!(matches!(
            update.attrs.as_slice(),
            [KindAttr::Bytes(t, b)] if *t == vxlan::IFLA_VXLAN_LOCAL6 && b.len() == 16
        ));

        let d = compare(&vx("10.0.0.1"), &link, &names);
        assert_eq!(d.recreate, vec!["vxlan address family IPv6 -> IPv4".to_string()]);
    }

    /// The kernel stores a bond delay as a count of miimon intervals.
    #[test]
    fn bond_delays_compare_as_the_kernel_rounds_them() {
        let mut data = attr(bond_attr::IFLA_BOND_MODE, &[1]);
        data.extend(attr(bond_attr::IFLA_BOND_MIIMON, &100u32.to_ne_bytes()));
        data.extend(attr(bond_attr::IFLA_BOND_UPDELAY, &100u32.to_ne_bytes()));
        let link = live("bond", data);
        let names = HashMap::new();
        let bond = |miimon: u32, updelay: u32| {
            declared(NetworkConfig::new().link("l0", |l| {
                l.bond()
                    .bond_mode(super::super::types::BondMode::ActiveBackup)
                    .miimon(miimon)
                    .bond_updelay(updelay)
            }))
        };

        let d = compare(&bond(100, 150), &link, &names);
        assert!(d.recreate.is_empty() && d.update.is_none(), "{d:?}");

        let d = compare(&bond(250, 500), &link, &names);
        assert!(d.recreate.is_empty(), "{d:?}");
        let update = d.update.expect("miimon and updelay change in place");
        assert_eq!(
            update.changes,
            vec![
                "bond miimon 100 -> 250".to_string(),
                "bond updelay 100 -> 500".to_string()
            ]
        );
    }

    fn link_at(ifindex: i32, name: &str, kind: &str, data: Vec<u8>, mac: [u8; 6]) -> LinkMessage {
        let mut l = live(kind, data);
        l.header.ifi_index = ifindex;
        l.header.ifi_flags = libc::IFF_UP as u32;
        l.name = Some(name.into());
        l.address = Some(mac.to_vec());
        l
    }

    fn fdb(ifindex: u32, mac: [u8; 6], state: u16, flags: u8) -> NeighborMessage {
        let mut e = crate::netlink::messages::NeighborMessageBuilder::new()
            .ifindex(ifindex)
            .lladdr(mac.to_vec())
            .build();
        e.header.ndm_family = libc::AF_BRIDGE as u8;
        e.header.ndm_state = state;
        e.header.ndm_flags = flags;
        e
    }

    /// The kernel's own FDB entries do not block a recreate; one a user
    /// added does (#426).
    #[test]
    fn fdb_entries_the_kernel_makes_are_told_from_the_ones_a_user_adds() {
        const OWN: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
        const UPPER: [u8; 6] = [0x02, 0, 0, 0, 0, 2];
        const OTHER: [u8; 6] = [0x02, 0, 0, 0, 0, 9];
        const ZEROS: [u8; 6] = [0; 6];
        let remote = Ipv4Addr::new(10, 1, 0, 2);
        let mut vx_data = attr(vxlan::IFLA_VXLAN_ID, &100u32.to_ne_bytes());
        vx_data.extend(attr(vxlan::IFLA_VXLAN_GROUP, &remote.octets()));
        let links = [
            link_at(2, "d0", "dummy", Vec::new(), OWN),
            link_at(3, "vx0", "vxlan", vx_data, OWN),
            link_at(4, "mv0", "macvlan", Vec::new(), UPPER),
        ];
        let by_index: HashMap<u32, &LinkMessage> = links.iter().map(|l| (l.ifindex(), l)).collect();
        let macs: HashSet<&[u8]> = links.iter().filter_map(|l| l.address()).collect();
        let users = |e: NeighborMessage| fdb_entry_is_users(&e, &by_index, &macs);
        let perm = nud::PERMANENT | nud::NOARP;
        let with_dst = |mut e: NeighborMessage, dst: Ipv4Addr| {
            e.destination = Some(IpAddr::V4(dst));
            e
        };

        // A device's address lists: multicast joins, a stacked link's MAC.
        assert!(!users(fdb(2, [0x33, 0x33, 0, 0, 0, 1], nud::PERMANENT, ntf::SELF)));
        assert!(!users(fdb(2, UPPER, nud::PERMANENT, ntf::SELF)));
        // `bridge fdb add MAC dev d0 self permanent`.
        assert!(users(fdb(2, OTHER, nud::PERMANENT, ntf::SELF)));
        // A VXLAN's default remote, and a second remote appended to it.
        let default = fdb(3, ZEROS, nud::PERMANENT | nud::REACHABLE, ntf::SELF);
        assert!(!users(with_dst(default, remote)));
        let appended = fdb(3, ZEROS, perm, ntf::SELF);
        assert!(users(with_dst(appended, Ipv4Addr::new(192, 0, 2, 1))));
        // The same remote on another port is not the default either.
        let mut other_port = with_dst(fdb(3, ZEROS, perm, ntf::SELF), remote);
        other_port.port = Some(4791);
        assert!(users(other_port));
        // Learned entries age out; externally learned ones stay.
        assert!(!users(with_dst(fdb(3, OTHER, nud::REACHABLE, ntf::SELF), remote)));
        assert!(users(with_dst(
            fdb(3, OTHER, nud::REACHABLE, ntf::SELF | ntf::EXT_LEARNED),
            remote
        )));
        // A bridge's database: the port's own MAC is the kernel's local
        // entry; a static or another permanent one is a user's.
        let in_bridge = |mac, state| {
            let mut e = fdb(2, mac, state, 0);
            e.master = Some(9);
            e
        };
        assert!(!users(in_bridge(OWN, nud::PERMANENT)));
        assert!(users(in_bridge(OTHER, nud::PERMANENT)));
        assert!(users(in_bridge(OTHER, nud::NOARP)));
        assert!(!users(in_bridge(OTHER, nud::REACHABLE)));
    }

    /// A multipath route and a nexthop-object route dump no `RTA_OIF` for
    /// the link they go through (#426).
    #[test]
    fn a_route_goes_through_a_link_by_oif_multipath_or_nexthop_object() {
        use crate::netlink::messages::{ParsedNextHop, RouteMessageBuilder};
        let nh = |id, ifindex, group: Option<Vec<u32>>| Nexthop {
            id,
            gateway: None,
            ifindex,
            family: libc::AF_INET as u8,
            flags: 0,
            protocol: 0,
            scope: 0,
            blackhole: false,
            fdb: false,
            encap_type: None,
            group: group.map(|ids| {
                ids.into_iter()
                    .map(|id| crate::netlink::nexthop::NexthopGroupMember { id, weight: 1 })
                    .collect()
            }),
            group_type: None,
            resilient: None,
        };
        let nh_devs = nexthop_devices(&[nh(5, Some(2), None), nh(6, Some(3), None), nh(7, None, Some(vec![5, 6]))]);
        let hop = |ifindex| ParsedNextHop {
            ifindex,
            weight: 1,
            flags: 0,
            gateway: None,
            encap_type: None,
            flow: None,
        };

        let single = RouteMessageBuilder::new().oif(2).build();
        assert_eq!(route_through(&single, 2, &nh_devs), Some(""));
        assert_eq!(route_through(&single, 3, &nh_devs), None);
        let multipath = RouteMessageBuilder::new().multipath(vec![hop(3), hop(2)]).build();
        assert!(route_through(&multipath, 2, &nh_devs).is_some());
        assert!(route_through(&multipath, 4, &nh_devs).is_none());
        // `nexthop_compat_mode` off: the id is all the route carries.
        let object = RouteMessageBuilder::new().nh_id(5).build();
        assert!(route_through(&object, 2, &nh_devs).is_some());
        assert!(route_through(&object, 3, &nh_devs).is_none());
        let group = RouteMessageBuilder::new().nh_id(7).build();
        assert!(route_through(&group, 3, &nh_devs).is_some());
    }

    /// A VLAN goes down with its lower device unless it was created with
    /// `loose_binding`, and a VLAN that is down already has nothing to
    /// lose.
    #[test]
    fn vlans_follow_their_lower_device_down() {
        let flags = |f: u32| {
            let mut payload = f.to_ne_bytes().to_vec();
            payload.extend(u32::MAX.to_ne_bytes());
            attr(vlan::IFLA_VLAN_FLAGS, &payload)
        };
        let vlan_on = |ifindex, lower, f| {
            let mut l = link_at(ifindex, "v", "vlan", flags(f), [0x02, 0, 0, 0, 0, ifindex as u8]);
            l.link = Some(lower);
            l
        };
        let mut down = vlan_on(6, 2, 1);
        down.header.ifi_flags = 0;
        let links = [
            link_at(2, "d0", "dummy", Vec::new(), [0x02, 0, 0, 0, 0, 2]),
            vlan_on(3, 2, vlan::VLAN_FLAG_REORDER_HDR),
            vlan_on(4, 3, vlan::VLAN_FLAG_REORDER_HDR),
            vlan_on(5, 2, vlan::VLAN_FLAG_LOOSE_BINDING),
            down,
        ];
        let got = with_vlans_on(&links, &HashSet::from([2]));
        assert_eq!(got, HashSet::from([2, 3, 4]));
    }

    /// Offline predictions, from declarations alone (#513).
    #[test]
    fn offline_predictions() {
        use crate::netlink::link::VlanProtocol;
        let recreated =
            |before: &NetworkConfig, after: &NetworkConfig| -> Vec<(String, Certainty)> {
                after
                    .diff_against(before)
                    .recreates
                    .into_iter()
                    .map(|r| (r.name, r.certainty))
                    .collect()
            };
        let vx = |vni: u32, port: Option<u16>| {
            NetworkConfig::new()
                .link("d0", |l| l.dummy())
                .link("vx0", move |l| {
                    let l = l.vxlan(vni).vxlan_underlay_dev("d0");
                    match port {
                        Some(p) => l.vxlan_port(p),
                        None => l,
                    }
                })
                .link("v1", |l| l.vlan("vx0", 5))
        };
        // A VNI change recreates the VXLAN and the VLAN stacked on it.
        assert_eq!(
            recreated(&vx(100, Some(4789)), &vx(200, Some(4789))),
            [
                ("vx0".to_string(), Certainty::Certain),
                ("v1".to_string(), Certainty::Certain)
            ]
        );
        // A port the previous config left to the module default is a
        // maybe; so is what is stacked on it.
        assert_eq!(
            recreated(&vx(100, None), &vx(100, Some(4789))),
            [
                ("vx0".to_string(), Certainty::IfKernelDefaultDiffers),
                ("v1".to_string(), Certainty::IfKernelDefaultDiffers)
            ]
        );
        // Nothing that changes in place recreates.
        assert!(
            vx(100, Some(4789))
                .diff_against(&vx(100, Some(4789)))
                .is_empty()
        );
        let mtu = |m: u32| NetworkConfig::new().link("d0", move |l| l.dummy().mtu(m));
        assert!(mtu(1500).diff_against(&mtu(9000)).is_empty());
        // A VLAN's protocol left out is 802.1Q, which the kernel dumps.
        let vlan = |p: Option<VlanProtocol>| {
            NetworkConfig::new()
                .link("d0", |l| l.dummy())
                .link("v1", move |l| {
                    let l = l.vlan("d0", 10);
                    match p {
                        Some(p) => l.vlan_protocol(p),
                        None => l,
                    }
                })
        };
        assert!(
            vlan(Some(VlanProtocol::Dot1q))
                .diff_against(&vlan(None))
                .is_empty()
        );
        assert_eq!(
            recreated(&vlan(None), &vlan(Some(VlanProtocol::Dot1ad))),
            [("v1".to_string(), Certainty::Certain)]
        );
        // A link new in this config is created, not recreated.
        assert!(vlan(None).diff_against(&NetworkConfig::new()).is_empty());
    }

    /// The policy and caller ownership decide which blockers go (#513).
    #[test]
    fn policy_and_ownership_decide_what_goes() {
        let addr = Blocker::Address {
            dev: "v1".into(),
            address: "10.0.0.9".parse().unwrap(),
            prefix_len: 24,
        };
        let zebra = Blocker::Route {
            dev: "v1".into(),
            destination: "10.1.0.0".parse().unwrap(),
            prefix_len: 16,
            table: 100,
            nhid: None,
            through: None,
            protocol: RouteProtocol::Zebra,
        };
        let netem = Blocker::Qdisc {
            dev: "v1".into(),
            qdisc: "netem".into(),
            under: None,
        };
        assert!(RecreatePolicy::Refuse.allows(&[]));
        assert!(!RecreatePolicy::Refuse.allows(std::slice::from_ref(&addr)));
        assert!(RecreatePolicy::Allow.allows(&[addr.clone(), zebra.clone()]));
        let routes_only = RecreatePolicy::AllowDestroying(BlockerFilter::new(|b| {
            matches!(
                b,
                Blocker::Route {
                    protocol: RouteProtocol::Zebra,
                    ..
                }
            )
        }));
        assert!(routes_only.allows(std::slice::from_ref(&zebra)));
        assert!(!routes_only.allows(&[zebra.clone(), addr.clone()]));

        assert!(Owned::RootQdisc { dev: "v1".into() }.covers(&netem));
        assert!(!Owned::RootQdisc { dev: "v2".into() }.covers(&netem));
        assert!(Owned::RouteTable { table: 100 }.covers(&zebra));
        assert!(!Owned::RouteTable { table: 100 }.covers(&addr));
    }

    /// Each blocker shows the text the untyped list held (#513).
    #[test]
    fn blockers_show_what_they_used_to_say() {
        use crate::TcHandle;
        let cases = [
            (
                Blocker::Route {
                    dev: "v1".into(),
                    destination: "10.1.0.0".parse().unwrap(),
                    prefix_len: 16,
                    table: 254,
                    nhid: None,
                    through: None,
                    protocol: RouteProtocol::Boot,
                },
                "route 10.1.0.0/16 dev v1 table 254",
            ),
            (
                Blocker::Route {
                    dev: "v1".into(),
                    destination: "10.1.0.0".parse().unwrap(),
                    prefix_len: 16,
                    table: 254,
                    nhid: Some(7),
                    through: Some("via a nexthop on".into()),
                    protocol: RouteProtocol::Boot,
                },
                "route 10.1.0.0/16 nhid 7 table 254, via a nexthop on v1",
            ),
            (
                Blocker::Qdisc {
                    dev: "d0".into(),
                    qdisc: "netem".into(),
                    under: Some((TcHandle::new(0x10, 0), TcHandle::new(1, 1))),
                },
                "qdisc netem 10: on d0 (under 1:1)",
            ),
            (
                Blocker::Filter {
                    dev: "d0".into(),
                    filter: "flower".into(),
                    priority: 100,
                    parent: TcHandle::major_only(1),
                },
                "filter flower pref 100 on d0 (parent 1:)",
            ),
            (
                Blocker::Neighbour {
                    dev: "d0".into(),
                    destination: "10.0.0.2".parse().unwrap(),
                    permanent: false,
                },
                "neighbour 10.0.0.2 dev d0 (externally learned)",
            ),
            (
                Blocker::Nexthop {
                    dev: "d0".into(),
                    id: 3,
                    via: Some("10.0.0.1".parse().unwrap()),
                },
                "nexthop id 3 via 10.0.0.1 dev d0",
            ),
            (
                Blocker::StackedLink {
                    name: "v1".into(),
                    link_kind: "vlan".into(),
                    lower: "d0".into(),
                    declared_existing: true,
                },
                "link v1 (vlan on d0), which the kernel deletes with it and the config declares \
                 as an existing device, not one to create",
            ),
            (
                Blocker::Port {
                    name: "d1".into(),
                    master: "br0".into(),
                },
                "link d1, a port of br0, which the kernel releases",
            ),
            (
                Blocker::Fdb {
                    entry: "fdb entry 02:00:00:00:00:01 dev vx0".into(),
                    via: Some("d0".into()),
                },
                "fdb entry 02:00:00:00:00:01 dev vx0 via d0, which would point at the deleted d0",
            ),
        ];
        for (blocker, text) in cases {
            assert_eq!(blocker.to_string(), text);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_blocker_serializes_with_its_kind() {
        let b = Blocker::Address {
            dev: "v1".into(),
            address: "10.0.0.9".parse().unwrap(),
            prefix_len: 24,
        };
        assert_eq!(
            serde_json::to_value(&b).unwrap(),
            serde_json::json!({"kind": "address", "dev": "v1", "address": "10.0.0.9", "prefix-len": 24})
        );
    }

    #[test]
    fn a_refused_recreate_says_what_it_would_destroy() {
        let r = LinkRecreate {
            name: "vx0".into(),
            reason: "vxlan vni 100 -> 200".into(),
            blocked_by: vec![Blocker::Address {
                dev: "vx0".into(),
                address: "10.0.0.9".parse().unwrap(),
                prefix_len: 24,
            }],
            resets: Vec::new(),
            destroys: Vec::new(),
            preserved_tc: None,
            restore: None,
            unrestorable: Vec::new(),
        };
        assert!(r.is_refused());
        let shown = r.to_string();
        assert!(
            shown.contains("vni 100 -> 200") && shown.contains("10.0.0.9/24"),
            "{shown}"
        );
        let ok = LinkRecreate {
            blocked_by: Vec::new(),
            ..r
        };
        assert!(!ok.is_refused());
        assert_eq!(ok.to_string(), "-/+ link vx0 (recreate: vxlan vni 100 -> 200)");
    }
}
