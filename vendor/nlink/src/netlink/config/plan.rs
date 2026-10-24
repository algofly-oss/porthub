//! The apply as a list of steps (#518).
//!
//! [`ConfigDiff::plan`](super::ConfigDiff::plan) turns a diff into a
//! [`Plan`]: every kernel call the apply makes, in the order it makes
//! them, including the ones a diff only implies — an MTU raised before a
//! link stacked on it is created, a bridge MTU pinned again after its
//! ports moved it, a VLAN taken down again after its lower device came up,
//! an old IPv6 prefix removed right before the address is added at the new
//! one. The apply *is* the plan: [`Plan::apply`] runs `steps` in order, and
//! [`ConfigDiff::apply`](super::ConfigDiff::apply) is `plan().apply()`, so
//! what is printed is what runs.
//!
//! Each step that changed something is recorded in
//! [`ApplyResult::journal`](super::ApplyResult::journal) with its
//! [`inverse`](Step::inverse) where one can be known, and
//! [`ApplyResult::undo`](super::ApplyResult::undo) is the plan that puts
//! those back.

use std::fmt;

use super::{
    DeclaredAddress, DeclaredFdb, DeclaredLink, DeclaredNeighbour, DeclaredNexthop, DeclaredQdisc,
    DeclaredRule, DeclaredRoute, LinkChanges, LinkRecreate,
    LinkRemoval, RouteConflict,
    diff::route_text,
    tc_tree::DeclaredTc,
};
use crate::netlink::types::route::RouteProtocol;

/// One kernel change of an apply, or a refusal that stops it (#518).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", tag = "step"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Step {
    /// A declared link that does not exist, and that nothing in the plan
    /// creates (#475): the apply fails here.
    MissingLink {
        /// The link.
        name: String,
    },
    /// A declared route whose place holds a route the config does not own
    /// (#469): the apply fails here rather than replace it.
    RefuseRoute(RouteConflict),
    /// A declared nexthop whose id another tool's holds, or that would turn
    /// a nexthop into a group or back (#516): the apply fails here.
    RefuseNexthop(super::NexthopConflict),
    /// A link the previous config declared, whose deletion would destroy
    /// what no config declares (#512): the apply fails here.
    RefuseRemoval(LinkRemoval),
    /// A link whose recreate would destroy what the config does not
    /// declare (#417): the apply fails here.
    RefuseRecreate(LinkRecreate),
    /// Rename a veth's or netkit's peer to the name its pair declares
    /// (#804), down for the rename and up again after it.
    RenameLink(super::LinkRename),
    /// Delete a link to create it again: a kind parameter it cannot change
    /// live (#417). The create is a later step.
    DeleteForRecreate(LinkRecreate),
    /// Delete a link the previous config declared and this one does not
    /// (#512).
    RemoveLink(LinkRemoval),
    /// Delete a link: the inverse of [`Self::CreateLink`].
    DeleteLink {
        /// The link.
        name: String,
    },
    /// Create a deleted link again as it was, with the links the kernel
    /// deleted with it, and put back what was on them and the ports they
    /// had (#745): the inverse of [`Self::DeleteForRecreate`] and
    /// [`Self::RemoveLink`].
    RestoreLink(Box<super::LinkRestore>),
    /// Raise a link's MTU before a link stacked on it is created: the
    /// kernel refuses an MTU above the lower device's at create (#473).
    RaiseMtuFirst {
        /// The lower link.
        link: String,
        /// Its declared MTU.
        mtu: u32,
    },
    /// Create a declared link.
    CreateLink(DeclaredLink),
    /// Change a link in place: state, MTU, master, MAC, kind parameters.
    ModifyLink {
        /// The link.
        name: String,
        /// What changes.
        changes: LinkChanges,
        /// The MTU was set by an earlier [`Self::RaiseMtuFirst`].
        mtu_already_set: bool,
    },
    /// Change a veth's peer in the namespace it lives in: its state, MTU
    /// and MAC (#680).
    ModifyVethPeer(super::VethPeerChange),
    /// Set the namespace's VRF strict mode (#680): off before links are
    /// created, on after.
    SetVrfStrictMode {
        /// On or off.
        on: bool,
    },
    /// Set a bridge's declared MTU again if the port changes before moved
    /// it (`br_mtu_auto_adjust`). Not counted as a change of its own.
    PinBridgeMtu {
        /// The bridge.
        bridge: String,
        /// Its declared MTU.
        mtu: u32,
    },
    /// Take a declared-down VLAN down again if its lower device came up
    /// before (`vlan_device_event`, #436). Not counted as a change of its
    /// own.
    HoldVlanDown {
        /// The VLAN.
        vlan: String,
    },
    /// Add a declared address.
    AddAddress {
        /// The address.
        address: DeclaredAddress,
        /// Why, when it is there now: a link change in this apply flushes
        /// it (#649).
        reason: Option<String>,
    },
    /// Change an address's metric, lifetimes or (IPv6) flags in place
    /// (#516).
    ChangeAddress(DeclaredAddress),
    /// Delete an address.
    DeleteAddress {
        /// The address.
        address: DeclaredAddress,
        /// Why, when it is not a purge: the IPv6 address re-added next at
        /// another prefix, which the kernel knows by address alone (#461).
        reason: Option<String>,
    },
    /// Install a route with `NLM_F_REPLACE`: added, or overwriting the one
    /// in its place.
    ReplaceRoute {
        /// The route it overwrites, if one is there.
        before: Option<DeclaredRoute>,
        /// The route installed.
        after: DeclaredRoute,
        /// Why, when it is there now: a link change in this apply flushes
        /// it (#649).
        reason: Option<String>,
        /// The protocol `after` is installed with: the plan's when unset, as
        /// for a declared route; an undo's, the one the route had (#783).
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none", with = "opt_protocol")
        )]
        #[cfg_attr(feature = "schemars", schemars(with = "Option<u8>"))]
        protocol: Option<RouteProtocol>,
        /// The protocol of the route it overwrites, which the inverse puts
        /// it back with (#783).
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none", with = "opt_protocol")
        )]
        #[cfg_attr(feature = "schemars", schemars(with = "Option<u8>"))]
        before_protocol: Option<RouteProtocol>,
        /// What the route it overwrites has that `before` cannot say (a
        /// metric past the six a declaration has, realms, a non-MPLS
        /// encap, …), which leaves the step without an inverse (#783).
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
        lost: Option<String>,
    },
    /// Delete a route.
    DeleteRoute {
        /// The route.
        route: DeclaredRoute,
        /// The protocol it has, which the inverse puts it back with (#783).
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none", with = "opt_protocol")
        )]
        #[cfg_attr(feature = "schemars", schemars(with = "Option<u8>"))]
        protocol: Option<RouteProtocol>,
        /// What the route has that `route` cannot say, which leaves the
        /// step without an inverse (#783).
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
        lost: Option<String>,
    },
    /// Install a neighbour with `NLM_F_REPLACE` (#516): added, or
    /// overwriting the entry in its place.
    SetNeighbour {
        /// The permanent entry it overwrites, if one is there.
        before: Option<DeclaredNeighbour>,
        /// The neighbour installed.
        after: DeclaredNeighbour,
    },
    /// Delete a neighbour the previous config declared (#516).
    DeleteNeighbour(DeclaredNeighbour),
    /// Install an FDB entry (#516): a bridge entry with `NLM_F_REPLACE`, a
    /// VXLAN remote of an all-zeros or multicast MAC with `NLM_F_APPEND`.
    SetFdb {
        /// The entry it overwrites, if one is there.
        before: Option<DeclaredFdb>,
        /// The entry installed.
        after: DeclaredFdb,
    },
    /// Delete an FDB entry the previous config declared (#516).
    DeleteFdb(DeclaredFdb),
    /// Add a rule, with the config's protocol (#516).
    AddRule(DeclaredRule),
    /// Install a nexthop object with `NLM_F_REPLACE` (#516).
    SetNexthop {
        /// The nexthop it overwrites, if one is there.
        before: Option<DeclaredNexthop>,
        /// The nexthop installed.
        after: DeclaredNexthop,
    },
    /// Delete a nexthop the previous config declared (#516).
    DeleteNexthop(DeclaredNexthop),
    /// Delete a rule the previous config declared: the one with the
    /// config's protocol (#516).
    DeleteRule(DeclaredRule),
    /// Delete a qdisc the previous config declared; the kernel's default
    /// comes back (#512).
    DeleteQdisc {
        /// The qdisc.
        qdisc: DeclaredQdisc,
        /// What it has under it, which goes with it (#783).
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "super::Underneath::is_nothing"))]
        underneath: super::Underneath,
    },
    /// Replace a qdisc with the declared one.
    ReplaceQdisc {
        /// The live qdisc it replaces, as a declaration, where its kind
        /// can be read back (#649): what the inverse puts back.
        before: Option<DeclaredQdisc>,
        /// The qdisc installed.
        after: DeclaredQdisc,
        /// What the live qdisc has under it, which a replace by another
        /// kind or at another handle destroys (#783). A replace in place
        /// keeps it, and this is [`Nothing`](super::Underneath::Nothing).
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "super::Underneath::is_nothing"))]
        underneath: super::Underneath,
    },
    /// Add a declared qdisc.
    AddQdisc(DeclaredQdisc),
    /// Put back a recreated link's TC tree that the config does not
    /// declare, kept with
    /// [`PlanOptions::preserve_undeclared_tc`](super::PlanOptions::preserve_undeclared_tc)
    /// (#645): after the declared qdiscs, before the declared trees.
    RestoreTc(super::preserve::PreservedTc),
    /// Delete a device's root and ingress qdiscs, and with them its classes
    /// and filters (#745): the inverse of [`Self::RestoreTc`].
    ClearTc {
        /// The device.
        dev: String,
    },
    /// Diff a declared TC tree again, against the device as the steps
    /// before left it, and apply the difference (#514).
    TcTree {
        /// The device.
        dev: String,
        /// What the diff found, one line each; the apply diffs again.
        planned: Vec<String>,
        /// The tree.
        tree: Box<DeclaredTc>,
        /// The tree the previous config declared on the device, whose
        /// classes and filters this one no longer declares go.
        #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
        previous: Option<Box<DeclaredTc>>,
    },
}

impl Step {
    /// Whether the apply fails at this step.
    pub fn is_refusal(&self) -> bool {
        matches!(
            self,
            Self::MissingLink { .. }
                | Self::RefuseRoute(_)
                | Self::RefuseNexthop(_)
                | Self::RefuseRemoval(_)
                | Self::RefuseRecreate(_)
        )
    }

    /// The step that undoes this one, when it can be known from the plan:
    /// an address or route added or removed, a link created, a qdisc the
    /// previous config declared, a link's state, MTU, master or MAC, a link
    /// deleted and what went with it (#745).
    ///
    /// `None` for what cannot be put back from the plan alone: a deleted
    /// link with something no declaration can say
    /// ([`LinkRecreate::unrestorable`](super::LinkRecreate::unrestorable)),
    /// a kind parameter that had the kernel's default, a replaced qdisc
    /// whose kind does not read back, a TC tree without the previous one,
    /// a refusal.
    pub fn inverse(&self) -> Option<Step> {
        Some(match self {
            Self::CreateLink(link) => Self::DeleteLink {
                name: link.name.clone(),
            },
            Self::RenameLink(r) => Self::RenameLink(super::LinkRename {
                from: r.to.clone(),
                to: r.from.clone(),
                peer_of: r.peer_of.clone(),
            }),
            Self::DeleteForRecreate(r) => Self::RestoreLink(r.restore.clone()?),
            Self::RemoveLink(r) => Self::RestoreLink(r.restore.clone()?),
            Self::RestoreTc(tc) => Self::ClearTc { dev: tc.dev.clone() },
            Self::ModifyLink { name, changes, .. } => Self::ModifyLink {
                name: name.clone(),
                changes: invert_link_changes(changes)?,
                mtu_already_set: false,
            },
            Self::AddAddress { address, .. } => Self::DeleteAddress {
                address: address.clone(),
                reason: None,
            },
            Self::DeleteAddress { address, .. } => Self::AddAddress {
                address: address.clone(),
                reason: None,
            },
            // What a declaration cannot say is not put back (#783).
            Self::ReplaceRoute { lost: Some(_), .. } | Self::DeleteRoute { lost: Some(_), .. } => {
                return None;
            }
            Self::ReplaceRoute {
                before,
                after,
                protocol,
                before_protocol,
                ..
            } => match before {
                Some(before) => Self::ReplaceRoute {
                    before: Some(after.clone()),
                    after: before.clone(),
                    reason: None,
                    protocol: *before_protocol,
                    before_protocol: *protocol,
                    lost: None,
                },
                None => Self::DeleteRoute {
                    route: after.clone(),
                    protocol: *protocol,
                    lost: None,
                },
            },
            Self::DeleteRoute { route, protocol, .. } => Self::ReplaceRoute {
                before: None,
                after: route.clone(),
                reason: None,
                protocol: *protocol,
                before_protocol: None,
                lost: None,
            },
            Self::AddQdisc(q) => Self::DeleteQdisc {
                qdisc: q.clone(),
                underneath: super::Underneath::Nothing,
            },
            // A qdisc that took a tree with it puts the tree back, itself
            // first; one that took what cannot be put back has no inverse
            // (#783).
            Self::DeleteQdisc {
                underneath: super::Underneath::Tree { tree },
                ..
            }
            | Self::ReplaceQdisc {
                underneath: super::Underneath::Tree { tree },
                ..
            } => Self::RestoreTc((**tree).clone()),
            Self::DeleteQdisc {
                underneath: super::Underneath::Lost { .. },
                ..
            }
            | Self::ReplaceQdisc {
                underneath: super::Underneath::Lost { .. },
                ..
            } => return None,
            // Removing what a kernel-default declaration replaced, whose kind
            // did not read back: nothing to put back.
            Self::DeleteQdisc { qdisc: q, .. }
                if q.qdisc_type == crate::netlink::tc_spec::QdiscSpec::KernelDefault =>
            {
                return None;
            }
            // The qdisc it replaced; the kernel's default root comes back
            // when the declared one goes (#649).
            Self::ReplaceQdisc {
                before: Some(before),
                after,
                ..
            } => {
                if before.qdisc_type == crate::netlink::tc_spec::QdiscSpec::KernelDefault {
                    Self::DeleteQdisc {
                        qdisc: after.clone(),
                        underneath: super::Underneath::Nothing,
                    }
                } else {
                    Self::ReplaceQdisc {
                        before: Some(after.clone()),
                        after: before.clone(),
                        underneath: super::Underneath::Nothing,
                    }
                }
            }
            Self::DeleteQdisc { qdisc: q, .. } => Self::AddQdisc(q.clone()),
            Self::SetNeighbour { before, after } => match before {
                Some(before) => Self::SetNeighbour {
                    before: Some(after.clone()),
                    after: before.clone(),
                },
                None => Self::DeleteNeighbour(after.clone()),
            },
            Self::DeleteNeighbour(n) => Self::SetNeighbour {
                before: None,
                after: n.clone(),
            },
            Self::SetFdb { before, after } => match before {
                Some(before) => Self::SetFdb {
                    before: Some(after.clone()),
                    after: before.clone(),
                },
                None => Self::DeleteFdb(after.clone()),
            },
            Self::DeleteFdb(e) => Self::SetFdb {
                before: None,
                after: e.clone(),
            },
            Self::AddRule(r) => Self::DeleteRule(r.clone()),
            Self::SetNexthop { before, after } => match before {
                Some(before) => Self::SetNexthop {
                    before: Some(after.clone()),
                    after: before.clone(),
                },
                None => Self::DeleteNexthop(after.clone()),
            },
            Self::DeleteNexthop(n) => Self::SetNexthop {
                before: None,
                after: n.clone(),
            },
            Self::DeleteRule(r) => Self::AddRule(r.clone()),
            Self::SetVrfStrictMode { on } => Self::SetVrfStrictMode { on: !on },
            // The previous config's tree, with this one's to remove what it
            // added (#649). Without a previous tree the state before is not
            // known: what the step changed in place cannot be put back.
            Self::TcTree {
                dev,
                tree,
                previous: Some(previous),
                ..
            } => Self::TcTree {
                dev: dev.clone(),
                planned: Vec::new(),
                tree: previous.clone(),
                previous: Some(tree.clone()),
            },
            Self::ModifyVethPeer(c) => Self::ModifyVethPeer(super::VethPeerChange {
                changes: invert_link_changes(&c.changes)?,
                ..c.clone()
            }),
            _ => return None,
        })
    }

    /// Why the step is in the plan, where the plan knows more than its
    /// kind says.
    pub fn reason(&self) -> Option<String> {
        match self {
            Self::DeleteForRecreate(r) => Some(r.reason.clone()),
            Self::RemoveLink(_) => Some("the previous config declared it".into()),
            Self::RaiseMtuFirst { .. } => {
                Some("a link created on it needs the MTU at create".into())
            }
            Self::PinBridgeMtu { .. } => {
                Some("ports joining or leaving move a bridge's MTU".into())
            }
            Self::HoldVlanDown { .. } => {
                Some("a lower device coming up brings its VLANs up".into())
            }
            Self::DeleteAddress { reason, .. } | Self::AddAddress { reason, .. } => reason.clone(),
            Self::ReplaceRoute {
                reason: Some(reason),
                ..
            } => Some(reason.clone()),
            Self::ReplaceRoute {
                before: Some(before),
                ..
            } => Some(format!("replaces {}", route_text(before))),
            _ => None,
        }
    }

    /// Whether the step is a kernel side effect the plan corrects, rather
    /// than a change of its own: not counted, and skipped in a dry run.
    pub(crate) fn is_consequence(&self) -> bool {
        matches!(
            self,
            Self::RaiseMtuFirst { .. } | Self::PinBridgeMtu { .. } | Self::HoldVlanDown { .. }
        )
    }
}

/// The inverse of a link change, from what the link had; `None` for a
/// kind-parameter change, or a link this apply creates.
fn invert_link_changes(changes: &LinkChanges) -> Option<LinkChanges> {
    if changes.port_update.is_some() || changes.port_vlans.is_some() {
        return None;
    }
    let was = changes.was.as_ref()?;
    // A kind change goes back to the attributes it replaced, where they
    // could be read (#649).
    let kind_update = match &changes.kind_update {
        Some(u) => Some(super::kind::KindUpdate {
            kind: u.kind.clone(),
            attrs: u.was.clone()?,
            changes: u.changes.iter().map(|c| format!("undo {c}")).collect(),
            was: Some(u.attrs.clone()),
        }),
        None => None,
    };
    let master_moved = changes.set_master.is_some() || changes.unset_master;
    Some(LinkChanges {
        set_up: changes.set_down && was.up,
        set_down: changes.set_up && !was.up,
        set_mtu: changes.set_mtu.and(was.mtu),
        set_master: if master_moved { was.master.clone() } else { None },
        unset_master: master_moved && was.master.is_none(),
        set_address: changes.set_address.and(was.address),
        set_txqlen: changes.set_txqlen.and(was.txqlen),
        set_alias: changes
            .set_alias
            .as_ref()
            .map(|_| was.alias.clone().unwrap_or_default()),
        set_group: changes.set_group.map(|_| was.group.unwrap_or(0)),
        set_gso_max_size: changes.set_gso_max_size.and(was.gso_max_size),
        set_gso_max_segs: changes.set_gso_max_segs.and(was.gso_max_segs),
        set_gro_max_size: changes.set_gro_max_size.and(was.gro_max_size),
        set_promisc: changes.set_promisc.map(|_| was.promisc),
        set_protodown: changes.set_protodown.map(|_| was.protodown.unwrap_or(false)),
        add_altnames: changes.del_altnames.clone(),
        del_altnames: changes.add_altnames.clone(),
        set_ipv4_conf: changes
            .set_ipv4_conf
            .iter()
            .filter_map(|(d, _)| was.ipv4_conf.iter().find(|(w, _)| w == d).copied())
            .collect(),
        set_ipv6_conf: changes
            .set_ipv6_conf
            .iter()
            .filter_map(|(d, _)| was.ipv6_conf.iter().find(|(w, _)| w == d).copied())
            .collect(),
        set_addr_gen_mode: changes.set_addr_gen_mode.and(was.addr_gen_mode),
        // `::` clears a token (`inet6_set_iftoken`).
        set_ipv6_token: changes
            .set_ipv6_token
            .map(|_| was.ipv6_token.unwrap_or(std::net::Ipv6Addr::UNSPECIFIED)),
        set_kind_params: kind_update.as_ref().map_or_else(Vec::new, |u| u.changes.clone()),
        kind_update,
        ..LinkChanges::default()
    })
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLink { name } => write!(
                f,
                "! link {name} (missing: it does not exist, and the config does not create it)"
            ),
            Self::RefuseRoute(conflict) => write!(f, "{conflict}"),
            Self::ModifyVethPeer(change) => write!(f, "{change}"),
            Self::SetVrfStrictMode { on } => write!(f, "~ net.vrf.strict_mode -> {}", u8::from(*on)),
            Self::RefuseNexthop(conflict) => write!(f, "{conflict}"),
            Self::RefuseRemoval(removal) => write!(f, "{removal}"),
            Self::RefuseRecreate(recreate) => write!(f, "{recreate}"),
            Self::RenameLink(rename) => write!(f, "{rename}"),
            Self::DeleteForRecreate(recreate) => write!(
                f,
                "- link {} (to recreate it: {})",
                recreate.name, recreate.reason
            ),
            Self::RemoveLink(removal) => write!(f, "{removal}"),
            Self::DeleteLink { name } => write!(f, "- link {name}"),
            Self::RestoreLink(restore) => write!(f, "+ link {restore}"),
            Self::ClearTc { dev } => write!(f, "- tc {dev} (its qdiscs, classes and filters)"),
            Self::RaiseMtuFirst { link, mtu } => {
                write!(f, "~ link {link} mtu {mtu} (before the links created on it)")
            }
            Self::CreateLink(link) => write!(
                f,
                "+ link {} ({})",
                link.name,
                link.link_type.kind().unwrap_or("physical")
            ),
            Self::ModifyLink { name, changes, .. } => {
                write!(f, "~ link {name} ({})", changes.summary())
            }
            Self::PinBridgeMtu { bridge, mtu } => {
                write!(f, "~ link {bridge} mtu {mtu} (if its ports moved it)")
            }
            Self::HoldVlanDown { vlan } => {
                write!(f, "~ link {vlan} down (if its lower device brought it up)")
            }
            Self::AddAddress { address: a, .. } => {
                write!(f, "+ address {}/{} on {}", a.address, a.prefix_len, a.dev)
            }
            Self::ChangeAddress(a) => {
                write!(f, "~ address {}/{} on {}", a.address, a.prefix_len, a.dev)
            }
            Self::DeleteAddress { address: a, .. } => {
                write!(f, "- address {}/{} on {}", a.address, a.prefix_len, a.dev)
            }
            Self::ReplaceRoute { before, after, .. } => match before {
                Some(before) => write!(
                    f,
                    "~ route {} (replacing {})",
                    route_text(after),
                    route_text(before)
                ),
                None => write!(f, "+ route {}", route_text(after)),
            },
            Self::DeleteRoute { route, .. } => write!(f, "- route {}", route_text(route)),
            Self::SetNeighbour { before, after } => {
                let replaced: Vec<(DeclaredNeighbour, DeclaredNeighbour)> =
                    before.iter().map(|b| (after.clone(), b.clone())).collect();
                f.write_str(&super::diff::neighbour_line(after, &replaced))
            }
            Self::DeleteNeighbour(n) => write!(f, "- {n}"),
            Self::SetFdb { before, after } => {
                let replaced: Vec<(DeclaredFdb, DeclaredFdb)> =
                    before.iter().map(|b| (after.clone(), b.clone())).collect();
                f.write_str(&super::diff::fdb_line(after, &replaced))
            }
            Self::DeleteFdb(e) => write!(f, "- {e}"),
            Self::AddRule(r) => write!(f, "+ {r}"),
            Self::SetNexthop { before, after } => {
                let replaced: Vec<(DeclaredNexthop, DeclaredNexthop)> =
                    before.iter().map(|b| (after.clone(), b.clone())).collect();
                f.write_str(&super::diff::nexthop_line(after, &replaced))
            }
            Self::DeleteNexthop(n) => write!(f, "- {n}"),
            Self::DeleteRule(r) => write!(f, "- {r}"),
            Self::DeleteQdisc { qdisc: q, .. } => write!(
                f,
                "- qdisc {} on {} ({:?})",
                q.qdisc_type.kind(),
                q.dev,
                q.effective_parent()
            ),
            Self::ReplaceQdisc { after: q, before, .. } => {
                write!(f, "~ qdisc {} on {} ({:?})", q.qdisc_type.kind(), q.dev, q.parent)?;
                match before {
                    Some(b) => write!(f, " (replacing {})", b.qdisc_type.kind()),
                    None => Ok(()),
                }
            }
            Self::AddQdisc(q) => {
                write!(f, "+ qdisc {} on {} ({:?})", q.qdisc_type.kind(), q.dev, q.parent)
            }
            Self::RestoreTc(tc) => write!(f, "+ restore {tc} (kept across its recreate)"),
            Self::TcTree { dev, planned, .. } if planned.is_empty() => {
                write!(f, "~ tc {dev} (diffed again after the qdiscs)")
            }
            Self::TcTree { planned, .. } => f.write_str(&planned.join("\n")),
        }
    }
}

/// An apply's steps, in the order it runs them (#518). From
/// [`ConfigDiff::plan`](super::ConfigDiff::plan); run with
/// [`Plan::apply`].
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[must_use = "a plan does nothing until applied"]
pub struct Plan {
    /// The steps, in order.
    pub steps: Vec<Step>,
    /// The protocol routes are installed with (#512), by number. Serialized
    /// so a plan read back installs them the same way (#649).
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none", with = "opt_protocol")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Option<u8>"))]
    pub(crate) routes_protocol: Option<RouteProtocol>,
    /// The owner tag a created link gets as its alias (#512).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub(crate) owner: Option<String>,
}

impl Plan {
    /// A plan of `steps`, for routes installed with protocol `boot` and
    /// links created without an owner tag.
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps,
            ..Self::default()
        }
    }

    /// Whether it has nothing to do.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

/// One numbered line per step: what an apply will do, in order.
impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.steps.is_empty() {
            return f.write_str("No changes needed");
        }
        let lines: Vec<String> = self
            .steps
            .iter()
            .enumerate()
            .map(|(i, step)| match step.reason() {
                Some(why) => format!("{:>3}. {step}  # {why}", i + 1),
                None => format!("{:>3}. {step}", i + 1),
            })
            .collect();
        f.write_str(&lines.join("\n"))
    }
}

/// A step that changed something, with what undoes it (#518).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JournalEntry {
    /// The step.
    pub step: Step,
    /// Its inverse, when one can be known ([`Step::inverse`]).
    pub inverse: Option<Step>,
}

impl super::ConfigDiff {
    /// The apply as steps, in the order it runs them (#518). See
    /// [`plan`](super::plan).
    pub fn plan(&self) -> Plan {
        let mut steps = Vec::new();
        if self.is_empty() {
            return Plan::default();
        }
        steps.extend(self.links_missing.iter().map(|name| Step::MissingLink {
            name: name.clone(),
        }));
        steps.extend(self.routes_refused.iter().cloned().map(Step::RefuseRoute));
        steps.extend(self.nexthops_refused.iter().cloned().map(Step::RefuseNexthop));
        steps.extend(
            self.links_to_remove
                .iter()
                .filter(|r| r.is_refused())
                .cloned()
                .map(Step::RefuseRemoval),
        );
        // Before anything that names the peer by the name it is given.
        steps.extend(self.links_to_rename.iter().cloned().map(Step::RenameLink));
        for recreate in &self.links_to_recreate {
            steps.push(if recreate.is_refused() {
                Step::RefuseRecreate(recreate.clone())
            } else {
                Step::DeleteForRecreate(recreate.clone())
            });
        }
        steps.extend(
            self.links_to_remove
                .iter()
                .filter(|r| !r.is_refused())
                .cloned()
                .map(Step::RemoveLink),
        );
        steps.extend(self.mtus_first.iter().map(|(link, mtu)| Step::RaiseMtuFirst {
            link: link.clone(),
            mtu: *mtu,
        }));
        // Off before the creates, so a VRF can share a table; on after,
        // once every VRF is in place (#680).
        if self.vrf_strict_mode == Some(false) {
            steps.push(Step::SetVrfStrictMode { on: false });
        }
        steps.extend(self.links_to_add.iter().cloned().map(Step::CreateLink));
        for (name, changes) in &self.links_to_modify {
            steps.push(Step::ModifyLink {
                name: name.clone(),
                changes: changes.clone(),
                mtu_already_set: self.mtus_first.iter().any(|(n, _)| n == name),
            });
        }
        steps.extend(self.veth_peers_to_modify.iter().cloned().map(Step::ModifyVethPeer));
        steps.extend(self.bridge_mtus.iter().map(|(bridge, mtu)| Step::PinBridgeMtu {
            bridge: bridge.clone(),
            mtu: *mtu,
        }));
        steps.extend(self.vlans_held_down.iter().map(|vlan| Step::HoldVlanDown {
            vlan: vlan.clone(),
        }));
        if self.vrf_strict_mode == Some(true) {
            steps.push(Step::SetVrfStrictMode { on: true });
        }
        // An address deleted to be added again is deleted right before the
        // add: an IPv6 address re-prefixed, which the kernel knows by the
        // address alone (#461), and an IPv4 address whose label or flags
        // only a recreate changes (#516).
        let re_prefixed = |old: &DeclaredAddress, new: &DeclaredAddress| {
            old.dev == new.dev
                && old.address == new.address
                && (new.address.is_ipv6()
                    || (old.prefix_len == new.prefix_len && old.attrs.peer == new.attrs.peer))
        };
        for address in &self.addresses_to_add {
            for old in self
                .addresses_to_remove
                .iter()
                .filter(|old| re_prefixed(old, address))
            {
                let reason = if old.prefix_len == address.prefix_len {
                    "re-added: only a recreate makes that change".to_string()
                } else {
                    format!(
                        "re-added at /{}: the kernel knows an address by itself alone",
                        address.prefix_len
                    )
                };
                steps.push(Step::DeleteAddress {
                    address: old.clone(),
                    reason: Some(reason),
                });
            }
            steps.push(Step::AddAddress {
                address: address.clone(),
                reason: self
                    .addresses_readded
                    .iter()
                    .find(|(a, _)| a == address)
                    .map(|(_, why)| why.clone()),
            });
        }
        steps.extend(self.addresses_to_change.iter().cloned().map(Step::ChangeAddress));
        for n in &self.nexthops_to_set {
            steps.push(Step::SetNexthop {
                before: self.nexthops_replaced.iter().find(|(d, _)| d == n).map(|(_, b)| b.clone()),
                after: n.clone(),
            });
        }
        for n in &self.neighbours_to_set {
            steps.push(Step::SetNeighbour {
                before: self
                    .neighbours_replaced
                    .iter()
                    .find(|(d, _)| d == n)
                    .map(|(_, before)| before.clone()),
                after: n.clone(),
            });
        }
        for e in &self.fdb_to_set {
            steps.push(Step::SetFdb {
                before: self.fdb_replaced.iter().find(|(d, _)| d == e).map(|(_, b)| b.clone()),
                after: e.clone(),
            });
        }
        for route in &self.routes_to_add {
            let before = self
                .routes_replaced
                .iter()
                .find(|(r, _)| r == route)
                .map(|(_, before)| before.clone());
            steps.push(Step::ReplaceRoute {
                before_protocol: before.as_ref().and_then(|b| self.protocol_of(b)),
                lost: before.as_ref().and_then(|b| self.lost_of(b)),
                before,
                protocol: None,
                after: route.clone(),
                reason: self
                    .routes_readded
                    .iter()
                    .find(|(r, _)| r == route)
                    .map(|(_, why)| why.clone()),
            });
        }
        // A rule after the routes of the table it looks up, so traffic it
        // steers there finds them.
        steps.extend(self.rules_to_add.iter().cloned().map(Step::AddRule));
        steps.extend(self.qdiscs_to_remove.iter().map(|q| Step::DeleteQdisc {
            qdisc: q.clone(),
            underneath: self.underneath_of(q),
        }));
        for q in &self.qdiscs_to_replace {
            steps.push(Step::ReplaceQdisc {
                before: self.qdiscs_replaced.iter().find(|(d, _)| d == q).map(|(_, b)| b.clone()),
                after: q.clone(),
                underneath: self.underneath_of(q),
            });
        }
        steps.extend(self.qdiscs_to_add.iter().cloned().map(Step::AddQdisc));
        steps.extend(
            self.links_to_recreate
                .iter()
                .filter(|r| !r.is_refused())
                .filter_map(|r| r.preserved_tc.clone())
                .map(Step::RestoreTc),
        );
        for (tree, previous) in &self.tc_declared {
            let planned = self
                .tc
                .iter()
                .find(|t| t.dev == tree.dev())
                .map(|t| t.to_string().lines().map(str::to_string).collect())
                .unwrap_or_default();
            steps.push(Step::TcTree {
                dev: tree.dev().to_string(),
                planned,
                tree: Box::new(tree.clone()),
                previous: previous.clone().map(Box::new),
            });
        }
        steps.extend(self.routes_to_remove.iter().map(|route| Step::DeleteRoute {
            route: route.clone(),
            protocol: self.protocol_of(route),
            lost: self.lost_of(route),
        }));
        steps.extend(self.nexthops_to_remove.iter().cloned().map(Step::DeleteNexthop));
        steps.extend(
            self.addresses_to_remove
                .iter()
                .filter(|old| !self.addresses_to_add.iter().any(|new| re_prefixed(old, new)))
                .map(|address| Step::DeleteAddress {
                    address: address.clone(),
                    reason: None,
                }),
        );
        steps.extend(self.neighbours_to_remove.iter().cloned().map(Step::DeleteNeighbour));
        steps.extend(self.fdb_to_remove.iter().cloned().map(Step::DeleteFdb));
        steps.extend(self.rules_to_remove.iter().cloned().map(Step::DeleteRule));
        Plan {
            steps,
            routes_protocol: self.routes_protocol,
            owner: self.owner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::config::{ConfigDiff, DeclaredRouteType, diff::LinkWas};

    fn addr(dev: &str, a: &str, plen: u8) -> DeclaredAddress {
        DeclaredAddress::plain(dev, a.parse().unwrap(), plen)
    }

    fn route(dst: &str, plen: u8, via: &str) -> DeclaredRoute {
        DeclaredRoute {
            destination: dst.parse().unwrap(),
            prefix_len: plen,
            gateway: Some(via.parse().unwrap()),
            dev: None,
            metric: None,
            table: Some(254),
            route_type: DeclaredRouteType::Unicast,
            attrs: Default::default(),
        }
    }

    /// #649: a plan reads back as it was written, everything an apply and
    /// an undo use included: a kind update's attributes, a port's options,
    /// what a link had, the reasons, the owner tag and route protocol.
    #[cfg(feature = "serde")]
    #[test]
    fn a_plan_reads_back_as_written() {
        use crate::netlink::config::kind::{KindAttr, KindUpdate};
        use crate::netlink::link::BridgePortConfig;
        let changes = LinkChanges {
            set_mtu: Some(1400),
            set_kind_params: vec!["vxlan ttl 0 -> 1".into()],
            kind_update: Some(KindUpdate {
                kind: "vxlan".into(),
                attrs: vec![
                    KindAttr::U8(5, 1),
                    KindAttr::Bytes(6, vec![10, 0, 0, 1]),
                    KindAttr::Ifindex(1, "d0".into()),
                ],
                changes: vec!["vxlan ttl 0 -> 1".into()],
                was: Some(vec![KindAttr::Bytes(5, vec![0])]),
            }),
            port_update: Some(BridgePortConfig::new().cost(5)),
            was: Some(LinkWas {
                up: true,
                mtu: Some(1500),
                ..LinkWas::default()
            }),
            ..LinkChanges::default()
        };
        let mut plan = Plan::new(vec![
            Step::ModifyLink {
                name: "vx0".into(),
                changes,
                mtu_already_set: false,
            },
            Step::AddAddress {
                address: addr("d0", "fd00::1", 64),
                reason: Some("re-add: flushed when d0 goes down".into()),
            },
            Step::ReplaceRoute {
                before: None,
                after: route("10.1.0.0", 16, "10.0.0.2"),
                reason: Some("re-add: flushed when d0 goes down".into()),
                protocol: None,
                before_protocol: None,
                lost: None,
            },
            Step::SetVrfStrictMode { on: true },
        ]);
        plan.owner = Some("lab".into());
        plan.routes_protocol = Some(RouteProtocol::Static);
        let json = serde_json::to_string(&plan).unwrap();
        let back: Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        assert_eq!(back.to_string(), plan.to_string());
        assert_eq!((back.owner.as_deref(), back.routes_protocol), (Some("lab"), Some(RouteProtocol::Static)));
        let Some(Step::ModifyLink { changes, .. }) = back.steps.first() else {
            panic!("{back}");
        };
        let update = changes.kind_update.as_ref().expect("the kind update reads back");
        assert_eq!(update.attrs.len(), 3);
        assert_eq!(changes.port_update.as_ref().and_then(|p| p.cost), Some(5));
        assert_eq!(
            back.steps[0].inverse().map(|s| s.to_string()),
            plan.steps[0].inverse().map(|s| s.to_string()),
            "the undo needs what the link had"
        );
        assert_eq!(back.steps[1].reason(), plan.steps[1].reason());

        // A TC tree step reads back with its tree and the previous one
        // (#645).
        let declared = |rate| {
            crate::netlink::config::NetworkConfig::new()
                .tc("d0", |t| {
                    t.class(
                        crate::TcHandle::major_only(1),
                        crate::TcHandle::new(1, 1),
                        crate::netlink::tc::HtbClassConfig::new(crate::util::Rate::mbit(rate)),
                    )
                })
                .tc_trees()[0]
                .clone()
        };
        let tree = Plan::new(vec![Step::TcTree {
            dev: "d0".into(),
            planned: vec!["~ class htb 1:1 on d0".into()],
            tree: Box::new(declared(20)),
            previous: Some(Box::new(declared(10))),
        }]);
        let json = serde_json::to_string(&tree).unwrap();
        let back: Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        let Step::TcTree { tree, previous, .. } = &back.steps[0] else {
            panic!("{back:?}")
        };
        assert_eq!(**tree, declared(20));
        assert_eq!(previous.as_deref(), Some(&declared(10)));
    }

    /// A neighbour set over another is undone by setting the other back;
    /// one added, by deleting it; one deleted, by adding it (#516).
    #[test]
    fn neighbour_steps_invert_and_print() {
        let n = |m: u8| DeclaredNeighbour {
            dev: "d0".into(),
            destination: "10.0.0.2".parse().unwrap(),
            lladdr: Some([2, 0, 0, 0, 0, m]),
            proxy: false,
        };
        let replace = Step::SetNeighbour {
            before: Some(n(1)),
            after: n(2),
        };
        assert_eq!(
            replace.to_string(),
            "~ neighbour 10.0.0.2 lladdr 02:00:00:00:00:02 dev d0 (replacing lladdr 02:00:00:00:00:01)"
        );
        assert!(matches!(
            replace.inverse(),
            Some(Step::SetNeighbour { before: Some(b), after: a }) if b == n(2) && a == n(1)
        ));
        let add = Step::SetNeighbour { before: None, after: n(1) };
        assert_eq!(add.to_string(), "+ neighbour 10.0.0.2 lladdr 02:00:00:00:00:01 dev d0");
        assert!(matches!(add.inverse(), Some(Step::DeleteNeighbour(d)) if d == n(1)));
        assert!(matches!(
            Step::DeleteNeighbour(n(1)).inverse(),
            Some(Step::SetNeighbour { before: None, after }) if after == n(1)
        ));
    }

    /// An FDB entry's steps invert as a neighbour's do (#516).
    #[test]
    fn fdb_steps_invert_and_print() {
        let e = |local: bool| DeclaredFdb {
            dev: "p0".into(),
            mac: [2, 0, 0, 0, 0, 1],
            vlan: None,
            dst: None,
            local,
        };
        let change = Step::SetFdb {
            before: Some(e(false)),
            after: e(true),
        };
        assert_eq!(change.to_string(), "~ fdb 02:00:00:00:00:01 dev p0 local (was static)");
        assert!(matches!(
            change.inverse(),
            Some(Step::SetFdb { before: Some(b), after: a }) if b == e(true) && a == e(false)
        ));
        let add = Step::SetFdb { before: None, after: e(false) };
        assert_eq!(add.to_string(), "+ fdb 02:00:00:00:00:01 dev p0 static");
        assert!(matches!(add.inverse(), Some(Step::DeleteFdb(d)) if d == e(false)));
        assert!(matches!(
            Step::DeleteFdb(e(false)).inverse(),
            Some(Step::SetFdb { before: None, after }) if after == e(false)
        ));
    }

    /// A nexthop's steps invert as a neighbour's do (#516).
    #[test]
    fn nexthop_steps_invert_and_print() {
        let cfg = crate::netlink::config::NetworkConfig::new()
            .nexthop(1, |n| n.via("10.0.0.2".parse().unwrap()).dev("d0"))
            .nexthop(9, |n| n.via("10.0.0.3".parse().unwrap()).dev("d0"));
        let (a, b) = (cfg.nexthops()[0].clone(), {
            let mut b = cfg.nexthops()[1].clone();
            b.id = 1;
            b
        });
        let change = Step::SetNexthop { before: Some(a.clone()), after: b.clone() };
        assert_eq!(change.to_string(), "~ nexthop 1 via 10.0.0.3 dev d0 (replacing via 10.0.0.2 dev d0)");
        assert!(matches!(
            change.inverse(),
            Some(Step::SetNexthop { before: Some(x), after: y }) if x == b && y == a
        ));
        let add = Step::SetNexthop { before: None, after: a.clone() };
        assert_eq!(add.to_string(), "+ nexthop 1 via 10.0.0.2 dev d0");
        assert!(matches!(add.inverse(), Some(Step::DeleteNexthop(d)) if d == a));
        assert!(matches!(
            Step::DeleteNexthop(a.clone()).inverse(),
            Some(Step::SetNexthop { before: None, after }) if after == a
        ));
    }

    /// A rule added is undone by deleting it, and the other way round (#516).
    #[test]
    fn rule_steps_invert() {
        let cfg = crate::netlink::config::NetworkConfig::new().rule(100, |r| r.table(100));
        let r = cfg.rules()[0].clone();
        assert_eq!(Step::AddRule(r.clone()).to_string(), "+ rule 100 lookup 100");
        assert!(matches!(Step::AddRule(r.clone()).inverse(), Some(Step::DeleteRule(d)) if d == r));
        assert!(matches!(Step::DeleteRule(r.clone()).inverse(), Some(Step::AddRule(a)) if a == r));
    }

    /// The steps come in the order the apply runs them, the hidden ones
    /// included, and print that way.
    #[test]
    fn a_plan_lists_every_step_in_apply_order() {
        let mut d = ConfigDiff::default();
        d.routes_to_remove.push(route("10.9.0.0", 16, "10.0.0.9"));
        d.addresses_to_remove.push(addr("d0", "2001:db8::1", 48));
        d.addresses_to_remove.push(addr("d0", "10.0.0.7", 24));
        d.addresses_to_add.push(addr("d0", "2001:db8::1", 64));
        let new = route("10.1.0.0", 16, "10.0.0.2");
        d.routes_replaced.push((new.clone(), route("10.1.0.0", 16, "10.0.0.1")));
        d.routes_to_add.push(new);
        d.mtus_first.push(("d0".into(), 9000));
        d.bridge_mtus.push(("br0".into(), 1500));
        d.links_missing.push("eth9".into());

        let plan = d.plan();
        let kinds: Vec<&str> = plan
            .steps
            .iter()
            .map(|s| match s {
                Step::MissingLink { .. } => "missing",
                Step::RaiseMtuFirst { .. } => "mtu-first",
                Step::PinBridgeMtu { .. } => "pin",
                Step::DeleteAddress { reason: Some(_), .. } => "del-addr-early",
                Step::AddAddress { .. } => "add-addr",
                Step::ReplaceRoute { .. } => "route",
                Step::DeleteRoute { .. } => "del-route",
                Step::DeleteAddress { .. } => "del-addr",
                _ => "other",
            })
            .collect();
        assert_eq!(
            kinds,
            [
                "missing",
                "mtu-first",
                "pin",
                "del-addr-early",
                "add-addr",
                "route",
                "del-route",
                "del-addr"
            ]
        );
        let shown = plan.to_string();
        assert!(shown.contains("  1. ! link eth9"), "{shown}");
        assert!(
            shown.contains("~ route 10.1.0.0/16 via 10.0.0.2 (replacing 10.1.0.0/16 via 10.0.0.1)"),
            "{shown}"
        );
        assert!(shown.contains("- address 2001:db8::1/48 on d0  # re-added at /64"), "{shown}");
        // The diff says the same of the route: a change, not an addition.
        assert!(d.to_string().contains("~ route 10.1.0.0/16 via 10.0.0.2 (replacing"), "{d}");
        assert!(ConfigDiff::default().plan().is_empty());
    }

    #[test]
    fn inverses_undo_what_can_be_undone() {
        let r = route("10.1.0.0", 16, "10.0.0.2");
        let old = route("10.1.0.0", 16, "10.0.0.1");
        let Some(Step::ReplaceRoute { before, after, protocol, .. }) = (Step::ReplaceRoute {
            before: Some(old.clone()),
            after: r.clone(),
            reason: None,
            protocol: None,
            before_protocol: Some(RouteProtocol::Static),
            lost: None,
        })
        .inverse() else {
            panic!("a replace's inverse is a replace");
        };
        // The route it overwrote goes back with its own protocol (#783).
        assert_eq!((before, after, protocol), (Some(r.clone()), old.clone(), Some(RouteProtocol::Static)));
        assert!(matches!(
            Step::ReplaceRoute {
                before: None,
                after: r.clone(),
                reason: None,
                protocol: None,
                before_protocol: None,
                lost: None,
            }
            .inverse(),
            Some(Step::DeleteRoute { route: x, .. }) if x == r
        ));
        assert!(matches!(
            Step::DeleteRoute { route: r.clone(), protocol: Some(RouteProtocol::Zebra), lost: None }.inverse(),
            Some(Step::ReplaceRoute { protocol: Some(RouteProtocol::Zebra), .. })
        ));
        // What a declaration cannot say leaves no inverse (#783).
        let lost = Some("it has rto_min, which no declaration has".to_string());
        assert!(Step::DeleteRoute { route: r.clone(), protocol: None, lost: lost.clone() }.inverse().is_none());
        assert!(
            Step::ReplaceRoute {
                before: Some(old.clone()),
                after: r.clone(),
                reason: None,
                protocol: None,
                before_protocol: None,
                lost,
            }
            .inverse()
            .is_none()
        );
        assert!(matches!(
            Step::AddAddress { address: addr("d0", "10.0.0.1", 24), reason: None }.inverse(),
            Some(Step::DeleteAddress { .. })
        ));

        let changes = LinkChanges {
            set_down: true,
            set_mtu: Some(1500),
            unset_master: true,
            was: Some(LinkWas {
                up: true,
                mtu: Some(1400),
                master: Some("br0".into()),
                ..LinkWas::default()
            }),
            ..LinkChanges::default()
        };
        let Some(Step::ModifyLink { changes: back, .. }) = (Step::ModifyLink {
            name: "d0".into(),
            changes,
            mtu_already_set: false,
        })
        .inverse() else {
            panic!("a link change's inverse is a link change");
        };
        assert!(back.set_up && !back.set_down);
        assert_eq!(back.set_mtu, Some(1400));
        assert_eq!(back.set_master.as_deref(), Some("br0"));

        // A kind change, a link this apply creates: nothing to go back to.
        let fresh = LinkChanges {
            set_up: true,
            ..LinkChanges::default()
        };
        assert!(Step::ModifyLink { name: "p0".into(), changes: fresh, mtu_already_set: false }
            .inverse()
            .is_none());
        assert!(Step::MissingLink { name: "x".into() }.inverse().is_none());
    }
}

/// [`Plan::routes_protocol`] as its number.
#[cfg(feature = "serde")]
mod opt_protocol {
    use crate::netlink::types::route::RouteProtocol;

    pub(super) fn serialize<S: serde::Serializer>(
        p: &Option<RouteProtocol>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        serde::Serialize::serialize(&p.map(|p| p.number()), s)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> Result<Option<RouteProtocol>, D::Error> {
        let n: Option<u8> = serde::Deserialize::deserialize(d)?;
        Ok(n.map(RouteProtocol::from))
    }
}
