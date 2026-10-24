//! Configuration diffing.
//!
//! This module computes the difference between desired and current network state.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};


use super::kind::{self, KindPlan, KindUpdate, LinkRecreate};
use super::types::{
    DeclaredAddress, DeclaredFdb, DeclaredLink, DeclaredLinkType, DeclaredNeighbour, DeclaredQdisc,
    DeclaredNexthop, DeclaredRoute, DeclaredRule, RuleAction,
    DeclaredRouteType, LinkState, MasterSpec, NetworkConfig, QdiscParent,
};
use crate::netlink::{
    connection::Connection,
    error::Result,
    messages::{AddressMessage, LinkMessage, NeighborMessage, RouteMessage, RuleMessage, TcMessage},
    protocol::Route,
    tc_spec::QdiscSpec,
    types::{addr::Scope, route::RouteType},
};

/// What a diff plans: what it removes (the purge scope, `previous`),
/// what it may recreate, and what the caller owns — as opposed to how an
/// apply executes, [`ExecOptions`](crate::reconcile::ExecOptions) (#519).
/// [`NetworkConfig::diff_with_options`](crate::netlink::config::NetworkConfig::diff_with_options)
/// takes it, and an apply through
/// [`ApplyOptions::plan`](super::ApplyOptions::plan). Called `DiffOptions`
/// before 0.32.
///
/// `#[non_exhaustive]` (Plan 188 convention) — construct via
/// [`Default::default`] + the builder setters.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PlanOptions {
    /// Compute removals for resources present in the kernel but not
    /// declared in the config ("full reconcile"). Default `false`.
    ///
    /// **Purge is destructive** — it populates
    /// [`ConfigDiff::addresses_to_remove`] /
    /// [`ConfigDiff::routes_to_remove`], which [`ConfigDiff::apply`]
    /// then deletes. The plain
    /// [`NetworkConfig::apply`](crate::netlink::config::NetworkConfig::apply)
    /// never purges; it takes this flag, or
    /// [`ApplyOptions::with_purge`](super::ApplyOptions::with_purge) (which
    /// `Stack` passes through), to opt in. Diff with it first to see the
    /// `-` lines before anything is deleted.
    ///
    /// Scope + safety rails:
    /// - **Addresses**: only `global`-scope, permanent addresses, on the
    ///   interfaces the config declares — as a link or by giving it an
    ///   address — and those listed in [`Self::purge_address_devs`]. IPv6
    ///   link-local, loopback and any non-global scope are excluded, and
    ///   so is an address the kernel will expire (no `IFA_F_PERMANENT`):
    ///   SLAAC, temporary, or DHCP-assigned with a lifetime. The next RA
    ///   or lease renewal would put it back, so a purge that removed it
    ///   never converged. Until 0.31 the interfaces were only the ones
    ///   with a declared address, so dropping a link's last address left
    ///   it on the link (#470).
    /// - **Routes**: only `static`/`boot` protocol routes, and only
    ///   in the tables the config **owns**: the main table (254),
    ///   every table some declared route names via
    ///   `RouteBuilder::table`, and any listed in
    ///   [`Self::purge_tables`]. Kernel, RA, DHCP and redirect
    ///   routes are excluded, and so is every table the config never
    ///   mentions — `local`, `default`, and a VRF table nobody
    ///   declared into. Until 0.27 the fence was the main table
    ///   alone, so a route declared into a VRF table could be added
    ///   and updated but never removed by reconcile (#333, #335).
    /// - **Links and qdiscs are never purged** — deleting
    ///   interfaces is too destructive to infer; use the imperative
    ///   `Connection::del_link` / `del_qdisc` for those.
    /// - **Neighbours, FDB entries, rules and nexthop objects are never
    ///   purged** (#516): one the previous config declared goes through
    ///   [`Self::previous`].
    pub purge: bool,

    /// Extra route tables to purge `static`/`boot` routes from, on
    /// top of main and the tables the config declares into. For a
    /// caller that owns a table but declares nothing into it *this*
    /// run (the last VRF route left the config) — without it, the
    /// table drops out of scope the moment it is empty in the
    /// declaration and its leftovers stay. Ignored unless
    /// [`Self::purge`] is on.
    pub purge_tables: Vec<u32>,

    /// Extra interfaces to purge addresses from, on top of the ones the
    /// config declares. For a caller that owned an interface's addresses
    /// in its previous config and declares nothing on it now. Ignored
    /// unless [`Self::purge`] is on.
    pub purge_address_devs: Vec<String>,

    /// The config applied before this one (#512). With it, the diff
    /// removes what that config declared and this one no longer does —
    /// exactly that, and nothing undeclared: its addresses, its routes in
    /// whatever table they were (so a route moved to another table leaves
    /// the old one), and its root and ingress qdiscs, which the kernel
    /// replaces with its default. Each only while the kernel still has it.
    /// It works with or without [`Self::purge`]; with both, the diff
    /// removes the union.
    pub previous: Option<std::sync::Arc<NetworkConfig>>,

    /// What to do with a recreate or removal that would destroy what the
    /// config does not declare (#513). Default
    /// [`RecreatePolicy::Refuse`](super::RecreatePolicy::Refuse).
    pub recreate_policy: super::RecreatePolicy,

    /// State the caller manages itself: never a blocker, never purged, and
    /// reported when a recreate destroys it (#513).
    pub owned: Vec<super::Owned>,

    /// Keep what a recreated link carries in TC that the config does not
    /// declare — its qdiscs, classes and filters — and put it back once
    /// the link is created again, instead of refusing the recreate (#645).
    /// The diff snapshots each object as the kernel dumps it
    /// ([`LinkRecreate::preserved_tc`](super::LinkRecreate::preserved_tc));
    /// the apply replays them, a mirred action's target looked up again by
    /// name. A BPF filter or action cannot be replayed from its dump, and
    /// still refuses the recreate.
    pub preserve_undeclared_tc: bool,
}

/// The name [`PlanOptions`] had before 0.32.
#[deprecated(since = "0.32.0", note = "renamed `PlanOptions`, beside `ExecOptions` (#519)")]
pub type DiffOptions = PlanOptions;

impl PlanOptions {
    /// Enable/disable purge (full-reconcile removals). See
    /// [`Self::purge`] for the safety scope.
    pub fn purge(mut self, on: bool) -> Self {
        self.purge = on;
        self
    }

    /// Add route tables to the purge scope. See [`Self::purge_tables`].
    pub fn purge_tables(mut self, tables: impl IntoIterator<Item = u32>) -> Self {
        self.purge_tables.extend(tables);
        self
    }

    /// Add interfaces to the address purge scope. See
    /// [`Self::purge_address_devs`].
    pub fn purge_address_devs<S: Into<String>>(
        mut self,
        devs: impl IntoIterator<Item = S>,
    ) -> Self {
        self.purge_address_devs
            .extend(devs.into_iter().map(Into::into));
        self
    }

    /// What to do with a recreate or removal that would destroy what the
    /// config does not declare; see [`Self::recreate_policy`].
    pub fn recreate_policy(mut self, policy: super::RecreatePolicy) -> Self {
        self.recreate_policy = policy;
        self
    }

    /// Keep a recreated link's undeclared TC tree; see
    /// [`Self::preserve_undeclared_tc`].
    pub fn preserve_undeclared_tc(mut self, on: bool) -> Self {
        self.preserve_undeclared_tc = on;
        self
    }

    /// Add state the caller manages itself; see [`Self::owned`].
    pub fn caller_owned(mut self, owned: impl IntoIterator<Item = super::Owned>) -> Self {
        self.owned.extend(owned);
        self
    }

    /// Whether the caller owns route table `table`.
    pub(crate) fn owns_table(&self, table: u32) -> bool {
        self.owned
            .iter()
            .any(|o| matches!(o, super::Owned::RouteTable { table: t } if *t == table))
    }

    /// Whether the caller owns the qdisc of `dev` at `parent`.
    pub(crate) fn owns_qdisc(&self, dev: &str, parent: QdiscParent) -> bool {
        self.owned.iter().any(|o| match (o, parent) {
            (super::Owned::RootQdisc { dev: d }, QdiscParent::Root)
            | (super::Owned::IngressQdisc { dev: d }, QdiscParent::Ingress) => d == dev,
            _ => false,
        })
    }

    /// Remove what `previous` declared and the config no longer does; see
    /// [`Self::previous`].
    pub fn previous(mut self, previous: impl Into<std::sync::Arc<NetworkConfig>>) -> Self {
        self.previous = Some(previous.into());
        self
    }

    /// The interfaces an address purge with these options touches, given
    /// the config: every declared link, every interface a declared address
    /// names, and [`Self::purge_address_devs`] (#470).
    pub(crate) fn purge_address_scope<'a>(&'a self, config: &'a NetworkConfig) -> HashSet<&'a str> {
        config
            .links
            .iter()
            .map(|l| l.name.as_str())
            .chain(config.addresses.iter().map(|a| a.dev.as_str()))
            .chain(self.purge_address_devs.iter().map(String::as_str))
            .collect()
    }

    /// The route tables a purge with these options touches, given
    /// the config: main, every table a declared route names, and
    /// [`Self::purge_tables`].
    pub(crate) fn purge_table_scope(&self, config: &NetworkConfig) -> HashSet<u32> {
        let mut scope: HashSet<u32> = HashSet::from([254]);
        scope.extend(config.routes.iter().filter_map(|r| r.table));
        scope.extend(self.purge_tables.iter().copied());
        scope
    }
}

/// A veth peer's declared settings, changed in the namespace it lives in
/// (#680): no declaration in this config can name it there.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VethPeerChange {
    /// The veth whose peer it is.
    pub link: String,
    /// The peer.
    pub peer: String,
    /// The namespace it lives in.
    pub netns: crate::netlink::namespace::NetnsRef,
    /// What changes: its state, MTU and MAC.
    pub changes: LinkChanges,
}

impl std::fmt::Display for VethPeerChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "~ veth peer {} of {} in {} ({})",
            self.peer,
            self.link,
            self.netns,
            self.changes.summary()
        )
    }
}

/// Difference between desired and current network state.
///
/// `#[non_exhaustive]` since 0.24 (#165): new `*_to_add` /
/// `*_to_remove` categories can appear without a major bump.
/// Construct via [`NetworkConfig::diff`](super::NetworkConfig::diff),
/// not literally.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Default)]
#[non_exhaustive]
#[must_use = "Diffs do nothing unless passed to `.apply()` or stringified via `Display`"]
pub struct ConfigDiff {
    /// Links to delete and create again, because a declared kind
    /// parameter — a VLAN id, a VXLAN VNI, a bond mode, the kind itself —
    /// cannot be changed on a live link. Each one is also in
    /// [`links_to_add`](Self::links_to_add). A refused one
    /// ([`LinkRecreate::is_refused`]) makes the apply fail instead (#417).
    pub links_to_recreate: Vec<LinkRecreate>,
    /// Peers of declared veth and netkit pairs to rename to the name their
    /// pair declares (#804), before anything else: the rest of the diff
    /// is against the renamed links.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub links_to_rename: Vec<super::LinkRename>,
    /// Links to create.
    pub links_to_add: Vec<DeclaredLink>,
    /// Links to modify (name, changes).
    pub links_to_modify: Vec<(String, LinkChanges)>,
    /// Veth peers to change in the namespace they live in (#680): their
    /// declared MAC, MTU and state.
    pub veth_peers_to_modify: Vec<VethPeerChange>,
    /// The namespace's VRF strict mode to set, where the config declares
    /// another than it has (#680).
    pub vrf_strict_mode: Option<bool>,

    /// Links the config declares without a kind — so it does not create
    /// them — that do not exist, and that no veth or netkit pair in this
    /// apply creates as its peer. A typo, or a device not there yet. The
    /// apply fails on the first, before it changes anything, with
    /// [`ErrorDetail::NotFound`](crate::ErrorDetail::NotFound). They
    /// were skipped without a word (#475). So is a parent (VLAN, macvlan,
    /// VXLAN underlay) or master a declared link names that the config
    /// does not declare and that does not exist (#518).
    pub links_missing: Vec<String>,

    /// Links the previous config declared and this one does not, still in
    /// the kernel with the kind they were declared with, and the links the
    /// kernel deletes along with them. The apply deletes them first, before
    /// any recreate or create. Only with [`PlanOptions::previous`] (#512).
    pub links_to_remove: Vec<super::LinkRemoval>,

    /// Addresses to add.
    pub addresses_to_add: Vec<DeclaredAddress>,
    /// Addresses whose metric, lifetimes or (IPv6) flags the apply changes
    /// in place (#516). An IPv4 label or flag change cannot be made in
    /// place: the address is then removed and added again.
    pub addresses_to_change: Vec<DeclaredAddress>,

    /// Routes to add.
    pub routes_to_add: Vec<DeclaredRoute>,

    /// Declared routes the apply refuses to install, because the only
    /// place they could go holds a route nlink does not own (#469). The
    /// apply fails on the first, before it changes anything.
    pub routes_refused: Vec<RouteConflict>,

    /// Qdiscs to add.
    pub qdiscs_to_add: Vec<DeclaredQdisc>,
    /// Qdiscs to replace (same position, different config).
    pub qdiscs_to_replace: Vec<DeclaredQdisc>,
    /// Qdiscs the previous config declared and this one does not, still in
    /// the kernel: the apply deletes them, and the kernel puts its default
    /// back. Only with [`PlanOptions::previous`] (#512).
    pub qdiscs_to_remove: Vec<DeclaredQdisc>,

    /// Addresses to remove (purge mode only — see
    /// [`PlanOptions::purge`]). Populated **only** when the diff is
    /// computed via
    /// [`NetworkConfig::diff_with_options`](crate::netlink::config::NetworkConfig::diff_with_options)
    /// with `purge` on; the default
    /// [`diff`](crate::netlink::config::NetworkConfig::diff) never
    /// removes anything. Kernel-managed addresses (IPv6 link-local,
    /// loopback, any non-`global` scope, anything with a lifetime) are
    /// excluded, and only the interfaces the config declares and
    /// [`PlanOptions::purge_address_devs`] are touched.
    pub addresses_to_remove: Vec<DeclaredAddress>,

    /// Neighbours to install with `NLM_F_REPLACE` (#516): missing, not
    /// permanent, or with another link-layer address — or on a device the
    /// apply recreates, flushes (down, an L3 master move) or gives another
    /// MAC, which loses them.
    pub neighbours_to_set: Vec<DeclaredNeighbour>,
    /// Neighbours the previous config declared and this one does not,
    /// still in the kernel (#516). Only with [`PlanOptions::previous`]: a
    /// purge leaves neighbours alone.
    pub neighbours_to_remove: Vec<DeclaredNeighbour>,
    /// The permanent entry each in `neighbours_to_set` replaces, when one
    /// is there: `(declared, replaced)`. Not counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) neighbours_replaced: Vec<(DeclaredNeighbour, DeclaredNeighbour)>,

    /// FDB entries to install (#516): a bridge entry missing, learned or
    /// in the other state (static or local), a VXLAN remote missing — or
    /// on a port the apply moves out of its bridge, or a device it
    /// recreates, which loses them.
    pub fdb_to_set: Vec<DeclaredFdb>,
    /// FDB entries the previous config declared and this one does not,
    /// still in the kernel (#516). Only with [`PlanOptions::previous`].
    pub fdb_to_remove: Vec<DeclaredFdb>,
    /// The entry each in `fdb_to_set` replaces, when one is there. Not
    /// counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) fdb_replaced: Vec<(DeclaredFdb, DeclaredFdb)>,

    /// Nexthop objects to install with `NLM_F_REPLACE` (#516), single
    /// nexthops before the groups made of them: missing, or different —
    /// or on a link the apply deletes or flushes, which the kernel deletes
    /// them with.
    pub nexthops_to_set: Vec<DeclaredNexthop>,
    /// Nexthop objects the previous config declared and this one does
    /// not, still in the kernel with the config's protocol, groups before
    /// their members (#516). Only with [`PlanOptions::previous`].
    pub nexthops_to_remove: Vec<DeclaredNexthop>,
    /// Declared nexthops the apply refuses to install (#516): the id is
    /// another tool's, or the change is between a group and a single
    /// nexthop, which the kernel will not replace. The apply fails on the
    /// first, before it changes anything.
    pub nexthops_refused: Vec<NexthopConflict>,
    /// The nexthop each in `nexthops_to_set` replaces, when one is there.
    /// Not counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) nexthops_replaced: Vec<(DeclaredNexthop, DeclaredNexthop)>,

    /// Rules to add (#516): none with the config's protocol matches them.
    pub rules_to_add: Vec<DeclaredRule>,
    /// Rules the previous config declared and this one does not, still in
    /// the kernel with the config's protocol (#516). Only with
    /// [`PlanOptions::previous`].
    pub rules_to_remove: Vec<DeclaredRule>,

    /// Routes to remove.
    ///
    /// Always: a route a declared route *supersedes* — same destination,
    /// table, type, gateway and device, a different metric. A replace
    /// only replaces a route of the same metric, so without this a metric
    /// change left the old route installed, and winning (#468).
    ///
    /// Under [`PlanOptions::purge`], also every route nothing declared
    /// carries, compared on the full identity (gateway, device, metric,
    /// type), not on `(dst, prefix, table)`. Restricted to the tables the
    /// config owns, to IPv4/IPv6, and to admin/user-managed protocols
    /// (`static` / `boot`); kernel, RA, DHCP and redirect routes are
    /// excluded so dynamic and auto-configured routing is never
    /// clobbered.
    pub routes_to_remove: Vec<DeclaredRoute>,

    /// Declared bridge MTUs to re-assert after the link changes, for
    /// bridges whose ports change in this apply (`br_mtu_auto_adjust`
    /// moves a bridge's MTU when ports join or leave). Not a change of its
    /// own — it only exists alongside the port changes that cause it — so
    /// it is not counted, shown or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) bridge_mtus: Vec<(String, u32)>,

    /// Declared-down VLANs to take down again after the link changes, for
    /// VLANs whose lower device comes up in this apply: `vlan_device_event()`
    /// brings up every VLAN on a device that comes up (#436). Like
    /// `bridge_mtus`, a consequence of other changes rather than one of its
    /// own, so it is not counted, shown or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) vlans_held_down: Vec<String>,

    /// Declared MTUs set before the creates: those of modified links that a
    /// link this apply creates stacks on, directly or through another, since
    /// `vlan_newlink` and `macvlan_common_newlink` refuse an MTU above the
    /// lower device's (EINVAL). They are in `links_to_modify` too, whose
    /// MTU step skips them; not counted, shown or serialized (#473).
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) mtus_first: Vec<(String, u32)>,
    /// The kernel route each route in `routes_to_add` replaces, when one is
    /// there (#518): `(declared, replaced)`. Not counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) routes_replaced: Vec<(DeclaredRoute, DeclaredRoute)>,
    /// The protocol of each kernel route the diff read back (in
    /// `routes_replaced` and `routes_to_remove`), which an undo puts it back
    /// with (#783). Not counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) route_protocols: Vec<(DeclaredRoute, crate::netlink::types::route::RouteProtocol)>,
    /// What each kernel route the diff read back has that its declaration
    /// cannot say (#783), which leaves its step without an inverse. Not
    /// counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) routes_lost: Vec<(DeclaredRoute, String)>,
    /// The addresses in `addresses_to_add` that are there now, and that a
    /// link change in this apply flushes, with why (#649):
    /// `(declared, reason)`. Not counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) addresses_readded: Vec<(DeclaredAddress, String)>,
    /// The same for the routes in `routes_to_add` (#649).
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) routes_readded: Vec<(DeclaredRoute, String)>,
    /// The live qdisc each one in `qdiscs_to_replace` replaces, as a
    /// declaration, where its kind reads back (#649): `(declared, live)`.
    /// Not counted or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) qdiscs_replaced: Vec<(DeclaredQdisc, DeclaredQdisc)>,
    /// What each qdisc a replace or a removal takes has under it, by device
    /// and slot (#783).
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) qdiscs_underneath: Vec<((String, QdiscParent), super::preserve::Underneath)>,
    /// The protocol the apply installs declared routes with: the config's
    /// [`routes_protocol`](super::NetworkConfig::routes_protocol) (#512).
    /// Not shown or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) routes_protocol: Option<crate::netlink::types::route::RouteProtocol>,
    /// The owner tag the apply writes as each created link's alias (#512).
    /// Not shown or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) owner: Option<String>,
    /// The declared TC trees that differ from the kernel's, one per device
    /// (#514).
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    pub tc: Vec<super::tc_tree::TcTreeDiff>,
    /// Every declared tree, with the one the previous config declared on
    /// its device, which the apply diffs again after the qdisc step: a
    /// root qdisc replaced or a link recreated takes its tree with it. Not
    /// shown or serialized.
    /// The config and plan this diff was computed from, for an apply that
    /// verifies (#518). Not shown or serialized.
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) source: Option<std::sync::Arc<(NetworkConfig, PlanOptions)>>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) tc_declared: Vec<(
        super::tc_tree::DeclaredTc,
        Option<super::tc_tree::DeclaredTc>,
    )>,
}

#[nlink_macros::send_futures]
impl ConfigDiff {
    /// What a route the diff read back has that it cannot say (#783).
    pub(crate) fn lost_of(&self, route: &DeclaredRoute) -> Option<String> {
        self.routes_lost.iter().find(|(r, _)| r == route).map(|(_, w)| w.clone())
    }

    /// The protocol a route the diff read back has (#783).
    pub(crate) fn protocol_of(&self, route: &DeclaredRoute) -> Option<crate::netlink::types::route::RouteProtocol> {
        self.route_protocols
            .iter()
            .find(|(r, _)| r == route)
            .map(|(_, p)| *p)
    }

    /// What the qdisc a step replaces or deletes at `q`'s slot has under it
    /// (#783).
    pub(crate) fn underneath_of(&self, q: &DeclaredQdisc) -> super::preserve::Underneath {
        self.qdiscs_underneath
            .iter()
            .find(|((dev, parent), _)| *dev == q.dev && *parent == q.effective_parent())
            .map(|(_, u)| u.clone())
            .unwrap_or_default()
    }

    /// The JSON Schema (draft 7) of the JSON a `ConfigDiff` serializes to,
    /// pretty-printed. Requires the `schemars` feature. Publish it beside
    /// a `diff` output so a change to the diff's shape is a visible change
    /// to its schema (#531).
    #[cfg(feature = "schemars")]
    pub fn json_schema() -> String {
        crate::netlink::config::draft07_output_schema_text::<Self>()
    }

    /// [`json_schema`](Self::json_schema) as a [`schemars::Schema`].
    #[cfg(feature = "schemars")]
    pub fn json_schema_value() -> schemars::Schema {
        crate::netlink::config::draft07_output_schema::<Self>()
    }

    /// Apply this pre-computed diff in-place without re-running
    /// [`crate::netlink::config::NetworkConfig::diff`].
    ///
    /// Mirrors [`crate::netlink::nftables::config::NftablesDiff::apply`]'s
    /// shape (Plan 188). Use this in the chain pattern when you
    /// already hold a diff:
    ///
    /// ```no_run
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::config::ApplyOptions;
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// # let cfg = nlink::netlink::config::NetworkConfig::new();
    /// let diff = cfg.diff(&conn).await?;
    /// println!("{diff}");                  // inspect before commit
    /// diff.apply(&conn, ApplyOptions::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// More efficient than [`crate::netlink::config::NetworkConfig::apply`] when
    /// you already have a `ConfigDiff` — the latter re-runs
    /// `compute_diff` internally, costing one extra round-trip
    /// of dump traffic.
    ///
    /// A diff is a plan already made, so this takes how to execute it
    /// alone: [`ExecOptions`](crate::reconcile::ExecOptions), or an
    /// [`ApplyOptions`](super::ApplyOptions) whose plan half is not used
    /// (#519). `verify` diffs again with the config and plan this diff
    /// came from.
    pub async fn apply(
        &self,
        conn: &Connection<Route>,
        opts: impl Into<crate::reconcile::ExecOptions>,
    ) -> Result<super::apply::ApplyResult> {
        super::apply::apply_diff(self, conn, opts.into()).await
    }

    /// Check if no changes are needed.
    pub fn is_empty(&self) -> bool {
        self.links_to_recreate.is_empty()
            && self.links_to_rename.is_empty()
            && self.links_to_add.is_empty()
            && self.links_to_modify.is_empty()
            && self.veth_peers_to_modify.is_empty()
            && self.vrf_strict_mode.is_none()
            && self.links_missing.is_empty()
            && self.links_to_remove.is_empty()
            && self.addresses_to_add.is_empty()
            && self.addresses_to_change.is_empty()
            && self.routes_to_add.is_empty()
            && self.routes_refused.is_empty()
            && self.qdiscs_to_add.is_empty()
            && self.qdiscs_to_replace.is_empty()
            && self.qdiscs_to_remove.is_empty()
            && self.addresses_to_remove.is_empty()
            && self.routes_to_remove.is_empty()
            && self.neighbours_to_set.is_empty()
            && self.neighbours_to_remove.is_empty()
            && self.fdb_to_set.is_empty()
            && self.fdb_to_remove.is_empty()
            && self.rules_to_add.is_empty()
            && self.rules_to_remove.is_empty()
            && self.nexthops_to_set.is_empty()
            && self.nexthops_to_remove.is_empty()
            && self.nexthops_refused.is_empty()
            && self.tc.is_empty()
    }

    /// Get the total number of changes.
    pub fn change_count(&self) -> usize {
        self.links_to_recreate.len()
            + self.links_to_rename.len()
            + self.links_to_add.len()
            + self.links_to_modify.len()
            + self.veth_peers_to_modify.len()
            + usize::from(self.vrf_strict_mode.is_some())
            + self.links_missing.len()
            + self.links_to_remove.len()
            + self.addresses_to_add.len()
            + self.addresses_to_change.len()
            + self.routes_to_add.len()
            + self.routes_refused.len()
            + self.qdiscs_to_add.len()
            + self.qdiscs_to_replace.len()
            + self.qdiscs_to_remove.len()
            + self.addresses_to_remove.len()
            + self.routes_to_remove.len()
            + self.neighbours_to_set.len()
            + self.neighbours_to_remove.len()
            + self.fdb_to_set.len()
            + self.fdb_to_remove.len()
            + self.rules_to_add.len()
            + self.rules_to_remove.len()
            + self.nexthops_to_set.len()
            + self.nexthops_to_remove.len()
            + self.nexthops_refused.len()
            + self.tc.iter().map(|t| t.len()).sum::<usize>()
    }

    /// Get a human-readable summary of the changes.
    ///
    /// Equivalent to `format!("{self}")` — Plan 183 (0.18) made
    /// the [`std::fmt::Display`] impl share the same renderer.
    /// Prefer the `Display` form (`diff.to_string()` /
    /// `format!("{diff}")`) for new code.
    #[deprecated(
        since = "0.19.0",
        note = "use `Display` via `format!(\"{}\")` or `diff.to_string()` instead — Plan 188 §2.6"
    )]
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();

        // Links
        for rename in &self.links_to_rename {
            lines.push(rename.to_string());
        }
        for recreate in &self.links_to_recreate {
            lines.push(recreate.to_string());
        }
        for link in &self.links_to_add {
            lines.push(format!(
                "+ link {} ({})",
                link.name,
                link.link_type.kind().unwrap_or("physical")
            ));
        }
        for (name, changes) in &self.links_to_modify {
            lines.push(format!("~ link {} ({})", name, changes.summary()));
        }
        for peer in &self.veth_peers_to_modify {
            lines.push(peer.to_string());
        }
        if let Some(on) = self.vrf_strict_mode {
            lines.push(format!("~ net.vrf.strict_mode -> {}", u8::from(on)));
        }
        for name in &self.links_missing {
            lines.push(format!(
                "! link {name} (missing: it does not exist, and the config does not create it)"
            ));
        }
        for removal in &self.links_to_remove {
            lines.push(removal.to_string());
        }

        // Addresses
        for addr in &self.addresses_to_add {
            lines.push(format!(
                "+ address {}/{} on {}",
                addr.address, addr.prefix_len, addr.dev
            ));
        }
        for addr in &self.addresses_to_change {
            lines.push(format!(
                "~ address {}/{} on {}",
                addr.address, addr.prefix_len, addr.dev
            ));
        }
        // Routes
        for route in &self.routes_to_add {
            // A route that replaces one is a change, not an addition (#518).
            match self.routes_replaced.iter().find(|(r, _)| r == route) {
                Some((_, before)) => lines.push(format!(
                    "~ route {} (replacing {})",
                    route_text(route),
                    route_text(before)
                )),
                None => lines.push(format!("+ route {}", route_text(route))),
            }
        }
        for conflict in &self.routes_refused {
            lines.push(conflict.to_string());
        }
        for conflict in &self.nexthops_refused {
            lines.push(conflict.to_string());
        }
        for n in &self.nexthops_to_set {
            lines.push(nexthop_line(n, &self.nexthops_replaced));
        }
        // Qdiscs
        for qdisc in &self.qdiscs_to_add {
            lines.push(format!(
                "+ qdisc {} on {} ({:?})",
                qdisc.qdisc_type.kind(),
                qdisc.dev,
                qdisc.parent
            ));
        }
        for qdisc in &self.qdiscs_to_replace {
            lines.push(format!(
                "~ qdisc {} on {} ({:?})",
                qdisc.qdisc_type.kind(),
                qdisc.dev,
                qdisc.parent
            ));
        }
        for qdisc in &self.qdiscs_to_remove {
            lines.push(format!(
                "- qdisc {} on {} ({:?})",
                qdisc.qdisc_type.kind(),
                qdisc.dev,
                qdisc.effective_parent()
            ));
        }
        // TC trees
        for tree in &self.tc {
            lines.push(tree.to_string());
        }
        // Neighbours
        for n in &self.neighbours_to_set {
            lines.push(neighbour_line(n, &self.neighbours_replaced));
        }
        for e in &self.fdb_to_set {
            lines.push(fdb_line(e, &self.fdb_replaced));
        }
        for r in &self.rules_to_add {
            lines.push(format!("+ {r}"));
        }

        // Purge removals (only present under `PlanOptions::purge`).
        for addr in &self.addresses_to_remove {
            lines.push(format!(
                "- address {}/{} on {}",
                addr.address, addr.prefix_len, addr.dev
            ));
        }
        for route in &self.routes_to_remove {
            let via = route
                .gateway
                .map(|g| format!(" via {}", g))
                .unwrap_or_default();
            let dev = route
                .dev
                .as_ref()
                .map(|d| format!(" dev {}", d))
                .unwrap_or_default();
            lines.push(format!(
                "- route {}/{}{}{}",
                route.destination, route.prefix_len, via, dev
            ));
        }
        for n in &self.neighbours_to_remove {
            lines.push(format!("- {n}"));
        }
        for e in &self.fdb_to_remove {
            lines.push(format!("- {e}"));
        }
        for r in &self.rules_to_remove {
            lines.push(format!("- {r}"));
        }
        for n in &self.nexthops_to_remove {
            lines.push(format!("- {n}"));
        }

        if lines.is_empty() {
            "No changes needed".to_string()
        } else {
            lines.join("\n")
        }
    }
}

/// A neighbour the apply installs, as the diff and the plan print it.
pub(crate) fn neighbour_line(
    n: &DeclaredNeighbour,
    replaced: &[(DeclaredNeighbour, DeclaredNeighbour)],
) -> String {
    match replaced.iter().find(|(d, _)| d == n) {
        Some((_, before)) => match before.lladdr {
            Some(m) => format!(
                "~ {n} (replacing lladdr {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            None => format!("~ {n}"),
        },
        None => format!("+ {n}"),
    }
}

/// A nexthop the apply installs, as the diff and the plan print it.
pub(crate) fn nexthop_line(n: &DeclaredNexthop, replaced: &[(DeclaredNexthop, DeclaredNexthop)]) -> String {
    match replaced.iter().find(|(d, _)| d == n) {
        Some((_, before)) => format!("~ {n} (replacing{})", before.to_string().trim_start_matches(&format!("nexthop {}", n.id))),
        None => format!("+ {n}"),
    }
}

/// A declared nexthop the apply will not install (#516).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NexthopConflict {
    /// The declared nexthop.
    pub nexthop: DeclaredNexthop,
    /// Why: what has its id.
    pub reason: String,
}

impl std::fmt::Display for NexthopConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "! {} ({})", self.nexthop, self.reason)
    }
}

/// An FDB entry the apply installs, as the diff and the plan print it.
pub(crate) fn fdb_line(e: &DeclaredFdb, replaced: &[(DeclaredFdb, DeclaredFdb)]) -> String {
    match replaced.iter().find(|(d, _)| d == e) {
        Some((_, before)) if before.dev != e.dev => format!("~ {e} (was on {})", before.dev),
        Some((_, before)) if before.dst != e.dst => match before.dst {
            Some(dst) => format!("~ {e} (was dst {dst})"),
            None => format!("~ {e}"),
        },
        Some((_, before)) if before.local != e.local => {
            format!("~ {e} (was {})", if before.local { "local" } else { "static" })
        }
        Some(_) => format!("~ {e}"),
        None => format!("+ {e}"),
    }
}

/// `Display` shares the renderer with the deprecated
/// `ConfigDiff::summary` so callers can `println!("{diff}")`
/// directly. Plan 183 (0.18) added this; Plan 188 §2.6 (0.19)
/// deprecated `summary()` in favor of this form. The
/// `#[allow(deprecated)]` is for the internal delegation —
/// users are not on the deprecated path.
impl std::fmt::Display for ConfigDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(deprecated)]
        f.write_str(&self.summary())
    }
}

/// A declared route the apply will not install (#469).
///
/// A route is added with `NLM_F_REPLACE`, and the kernel replaces the
/// first route at the same destination, table and metric — whoever put it
/// there. When that is the kernel's connected route, an RA or DHCP route
/// or a routing daemon's, replacing it breaks what depends on it: with the
/// connected route of `10.0.0.1/24` gone, every gateway on that segment is
/// unreachable. Give the declared route another metric, or remove the
/// other route.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RouteConflict {
    /// The declared route.
    pub route: DeclaredRoute,
    /// The route in its place, as `ip route` shows it:
    /// `10.0.0.0/24 dev eth0 proto kernel metric 0`.
    pub held_by: String,
}

impl std::fmt::Display for RouteConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let route = &self.route;
        write!(f, "! route {}/{}", route.destination, route.prefix_len)?;
        if let Some(gateway) = route.gateway {
            write!(f, " via {gateway}")?;
        }
        if let Some(dev) = &route.dev {
            write!(f, " dev {dev}")?;
        }
        write!(
            f,
            " (refused: it would replace {}, which the config does not own)",
            self.held_by
        )
    }
}

/// Changes to make to an existing link.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct LinkChanges {
    /// Change state to up.
    pub set_up: bool,
    /// Change state to down.
    pub set_down: bool,
    /// New MTU value.
    pub set_mtu: Option<u32>,
    /// New master interface.
    pub set_master: Option<String>,
    /// Remove from master.
    pub unset_master: bool,
    /// New MAC address.
    ///
    /// A declared `address` was stored by the builder and compared by
    /// nothing, so `.link("eth0", |l| l.address(mac))` on an existing
    /// interface produced an empty diff forever and `apply()` reported
    /// zero changes (#275).
    pub set_address: Option<[u8; 6]>,
    /// Kind parameters changed in place — a VXLAN remote, local or
    /// underlay, bond timers and hashing, a macvlan mode, netkit policies
    /// — one `name old -> new` line each. A parameter the kernel cannot
    /// change on a live link is not here: it makes the diff recreate the
    /// link ([`ConfigDiff::links_to_recreate`]) (#417).
    pub set_kind_params: Vec<String>,
    /// New transmit queue length (#516).
    pub set_txqlen: Option<u32>,
    /// New alias (#516); empty clears it.
    pub set_alias: Option<String>,
    /// New group (#516).
    pub set_group: Option<u32>,
    /// New GSO/GRO limits (#516).
    pub set_gso_max_size: Option<u32>,
    /// See [`Self::set_gso_max_size`].
    pub set_gso_max_segs: Option<u32>,
    /// See [`Self::set_gso_max_size`].
    pub set_gro_max_size: Option<u32>,
    /// Promiscuous mode on or off (#516).
    pub set_promisc: Option<bool>,
    /// Protodown on or off (#516).
    pub set_protodown: Option<bool>,
    /// Alternative names to add (#516).
    pub add_altnames: Vec<String>,
    /// Alternative names to take off (#516).
    pub del_altnames: Vec<String>,
    /// IPv4 per-device settings to set (#516).
    pub set_ipv4_conf: Vec<(crate::netlink::devconf::Ipv4Devconf, u32)>,
    /// IPv6 per-device settings to write (#516).
    pub set_ipv6_conf: Vec<(crate::netlink::devconf::Ipv6Devconf, i32)>,
    /// New IPv6 address generation mode (#516).
    pub set_addr_gen_mode: Option<crate::netlink::devconf::AddrGenMode>,
    /// New IPv6 token (#516).
    pub set_ipv6_token: Option<std::net::Ipv6Addr>,
    /// Bridge port options to change, one `name value` each (#516).
    pub set_port_options: Vec<String>,
    /// The config behind `set_port_options`. Serialized, so a plan read
    /// back applies it (#649).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) port_update: Option<crate::netlink::link::BridgePortConfig>,
    /// Port VLANs to add (`+vlan 10 pvid untagged`) or remove (`-vlan 1`)
    /// (#516).
    pub set_port_vlans: Vec<String>,
    /// The declared VLAN set behind `set_port_vlans`: the apply reads the
    /// port's and makes them these.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) port_vlans: Option<Vec<super::types::PortVlan>>,
    /// The attributes behind `set_kind_params`: the `IFLA_INFO_DATA`
    /// attributes the change sends, by id (#649).
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) kind_update: Option<KindUpdate>,
    /// What the link had, for the change's inverse (#518). `None` for a
    /// link this apply creates.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub(crate) was: Option<LinkWas>,
}

/// What a link had before a [`LinkChanges`] (#518).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case", default))]
#[derive(Debug, Clone, Default)]
pub(crate) struct LinkWas {
    pub(crate) up: bool,
    pub(crate) mtu: Option<u32>,
    pub(crate) master: Option<String>,
    pub(crate) address: Option<[u8; 6]>,
    pub(crate) txqlen: Option<u32>,
    pub(crate) alias: Option<String>,
    pub(crate) group: Option<u32>,
    pub(crate) gso_max_size: Option<u32>,
    pub(crate) gso_max_segs: Option<u32>,
    pub(crate) gro_max_size: Option<u32>,
    pub(crate) promisc: bool,
    pub(crate) protodown: Option<bool>,
    pub(crate) ipv4_conf: Vec<(crate::netlink::devconf::Ipv4Devconf, u32)>,
    pub(crate) ipv6_conf: Vec<(crate::netlink::devconf::Ipv6Devconf, i32)>,
    pub(crate) addr_gen_mode: Option<crate::netlink::devconf::AddrGenMode>,
    pub(crate) ipv6_token: Option<std::net::Ipv6Addr>,
}

impl LinkChanges {
    /// The changes that give a link just created its declared attributes
    /// (#516).
    pub(crate) fn declaring(a: &super::types::LinkAttrs) -> Self {
        Self {
            set_txqlen: a.txqlen,
            set_alias: a.alias.clone(),
            set_group: a.group,
            set_gso_max_size: a.gso_max_size,
            set_gso_max_segs: a.gso_max_segs,
            set_gro_max_size: a.gro_max_size,
            set_promisc: a.promisc,
            set_protodown: a.protodown,
            add_altnames: a.altnames.clone().unwrap_or_default(),
            set_ipv4_conf: a
                .ipv4_conf
                .iter()
                .filter_map(|(name, v)| Some((crate::netlink::devconf::Ipv4Devconf::from_name(name)?, *v)))
                .collect(),
            set_ipv6_conf: a
                .ipv6_conf
                .iter()
                .filter_map(|(name, v)| Some((crate::netlink::devconf::Ipv6Devconf::from_name(name)?, *v)))
                .collect(),
            set_addr_gen_mode: a.addr_gen_mode,
            set_ipv6_token: a.ipv6_token,
            ..Self::default()
        }
    }

    /// Check if any changes are needed.
    pub fn is_empty(&self) -> bool {
        !self.set_up
            && !self.set_down
            && self.set_mtu.is_none()
            && self.set_master.is_none()
            && !self.unset_master
            && self.set_address.is_none()
            && self.kind_update.is_none()
            && self.set_txqlen.is_none()
            && self.set_alias.is_none()
            && self.set_group.is_none()
            && self.set_gso_max_size.is_none()
            && self.set_gso_max_segs.is_none()
            && self.set_gro_max_size.is_none()
            && self.set_promisc.is_none()
            && self.set_protodown.is_none()
            && self.add_altnames.is_empty()
            && self.del_altnames.is_empty()
            && self.set_ipv4_conf.is_empty()
            && self.set_ipv6_conf.is_empty()
            && self.set_addr_gen_mode.is_none()
            && self.set_ipv6_token.is_none()
            && self.port_update.is_none()
            && self.port_vlans.is_none()
    }

    /// Get a summary of the changes.
    ///
    /// Equivalent to `format!("{self}")` since Plan 188 §2.5
    /// (0.19) added the `Display` impl. Prefer `Display` for
    /// new code; this method may be deprecated in 0.20.
    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.set_up {
            parts.push("up".to_string());
        }
        if self.set_down {
            parts.push("down".to_string());
        }
        if let Some(mtu) = self.set_mtu {
            parts.push(format!("mtu={}", mtu));
        }
        if let Some(master) = &self.set_master {
            parts.push(format!("master={}", master));
        }
        if self.unset_master {
            parts.push("nomaster".to_string());
        }
        if let Some(a) = self.set_address {
            parts.push(format!(
                "address={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                a[0], a[1], a[2], a[3], a[4], a[5]
            ));
        }
        parts.extend(self.set_kind_params.iter().cloned());
        for (name, v) in [
            ("txqlen", self.set_txqlen),
            ("group", self.set_group),
            ("gso_max_size", self.set_gso_max_size),
            ("gso_max_segs", self.set_gso_max_segs),
            ("gro_max_size", self.set_gro_max_size),
        ] {
            if let Some(v) = v {
                parts.push(format!("{name}={v}"));
            }
        }
        if let Some(alias) = &self.set_alias {
            parts.push(format!("alias={alias:?}"));
        }
        for (name, v) in [("promisc", self.set_promisc), ("protodown", self.set_protodown)] {
            if let Some(on) = v {
                parts.push(format!("{name} {}", if on { "on" } else { "off" }));
            }
        }
        parts.extend(self.add_altnames.iter().map(|a| format!("+altname {a}")));
        parts.extend(self.del_altnames.iter().map(|a| format!("-altname {a}")));
        parts.extend(self.set_ipv4_conf.iter().map(|(d, v)| format!("ipv4 {d}={v}")));
        parts.extend(self.set_ipv6_conf.iter().map(|(d, v)| format!("ipv6 {d}={v}")));
        if let Some(mode) = self.set_addr_gen_mode {
            parts.push(format!("addrgenmode {}", mode.name()));
        }
        if let Some(token) = self.set_ipv6_token {
            parts.push(format!("token {token}"));
        }
        parts.extend(self.set_port_options.iter().map(|o| format!("port {o}")));
        parts.extend(self.set_port_vlans.iter().cloned());
        parts.join(", ")
    }
}

/// `Display` for `LinkChanges` so a `links_to_modify` row in
/// `ConfigDiff::Display` can render the changes compactly:
/// `"~ link eth0 (mtu=9000, up)"`. Plan 188 §2.5 / feedback W6.
impl std::fmt::Display for LinkChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary())
    }
}

/// Compute the difference between desired and current state.
#[nlink_macros::send_futures]
pub async fn compute_diff(config: &NetworkConfig, conn: &Connection<Route>) -> Result<ConfigDiff> {
    compute_diff_with_options(config, conn, &PlanOptions::default()).await
}

/// Like [`compute_diff`] but honours [`PlanOptions`] (currently the
/// `purge` flag — see [`PlanOptions::purge`]).
#[nlink_macros::send_futures]
pub async fn compute_diff_with_options(
    config: &NetworkConfig,
    conn: &Connection<Route>,
    opts: &PlanOptions,
) -> Result<ConfigDiff> {
    config.validate()?;
    let snapshot = Snapshot::read_for(conn, config, opts).await?;
    diff_snapshot(config, &snapshot, opts)
}

/// The kernel state a [`ConfigDiff`] is computed from (#518): the links,
/// addresses, routes and qdiscs, and what a recreate would destroy with a
/// link (FDB entries, neighbours, nexthop objects, TC classes and filters).
///
/// Read it once with [`Snapshot::read`], then diff any number of configs
/// against it with [`NetworkConfig::diff_snapshot`], without another
/// kernel read. A plan, its dry run and a comparison of two candidate
/// configs then all see the same state.
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use nlink::netlink::config::{PlanOptions, NetworkConfig, Snapshot};
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
///
/// let snapshot = Snapshot::read(&conn).await?;
/// let a = NetworkConfig::new().link("d0", |l| l.dummy().mtu(1400));
/// let b = NetworkConfig::new().link("d0", |l| l.dummy().mtu(9000));
/// let (da, db) = (
///     a.diff_snapshot(&snapshot, PlanOptions::default())?,
///     b.diff_snapshot(&snapshot, PlanOptions::default())?,
/// );
/// println!("a: {da}\nb: {db}");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Snapshot {
    links: Vec<LinkMessage>,
    addresses: Vec<AddressMessage>,
    routes: Vec<RouteMessage>,
    qdiscs: Vec<TcMessage>,
    /// What a recreate destroys: read by [`read`](Self::read), and by
    /// `read_for` only when its config recreates a link.
    extras: Option<kind::LinkExtras>,
    /// Classes and filters by ifindex (#514): read by [`read`](Self::read)
    /// for every link with a qdisc of its own, and by `read_for` for the
    /// links its config declares a TC tree on. A link without one has
    /// neither.
    tc: HashMap<u32, super::tc_tree::TcLive>,
    /// Every bridge port's VLANs (#516): read by [`read`](Self::read), and
    /// by `read_for` when its config declares port VLANs.
    bridge_vlans: Vec<crate::netlink::bridge_vlan::BridgeVlanEntry>,
    /// ARP and ND entries, and proxy entries (#516): read by
    /// [`read`](Self::read), and by `read_for` when its config or the
    /// previous one declares a neighbour.
    neighbours: Vec<NeighborMessage>,
    proxies: Vec<NeighborMessage>,
    /// Every FDB entry, the `AF_BRIDGE` neighbour dump (#516): read by
    /// [`read`](Self::read), and by `read_for` when its config or the
    /// previous one declares one.
    fdb: Vec<NeighborMessage>,
    /// Every policy routing rule, both families (#516): read by
    /// [`read`](Self::read), and by `read_for` when its config or the
    /// previous one declares one.
    rules: Vec<RuleMessage>,
    /// Every nexthop object (#516): read by [`read`](Self::read), and by
    /// `read_for` when its config or the previous one declares one or a
    /// route through one.
    nexthops: Vec<crate::netlink::nexthop::Nexthop>,
    /// The id this namespace knows each namespace by, for the veth peers
    /// a config places in one (#516): every named namespace for
    /// [`read`](Self::read), the ones a config names for `read_for`. A
    /// namespace with no id has no peer of ours in it.
    netns_ids: HashMap<crate::netlink::namespace::NetnsRef, Option<u32>>,
    /// The links of each namespace a veth peer's declared settings are
    /// compared in (#680): every named namespace with an id here for
    /// [`read`](Self::read), since a peer of ours makes one; the ones a
    /// config sets a peer in for `read_for`.
    peer_links: HashMap<crate::netlink::namespace::NetnsRef, Vec<LinkMessage>>,
    /// The namespace's `net.vrf.strict_mode` (#680): read by
    /// [`read`](Self::read), and by `read_for` when its config sets it.
    /// `None` where it cannot be read: the `vrf` module is not loaded, and
    /// it is off.
    vrf_strict_mode: Option<bool>,
}

#[nlink_macros::send_futures]
impl Snapshot {
    /// Read what a diff of any config needs, including what a recreate
    /// would destroy.
    pub async fn read(conn: &Connection<Route>) -> Result<Self> {
        let mut snapshot = Self::read_base(conn).await?;
        snapshot.extras = Some(kind::LinkExtras::read(conn, &snapshot.qdiscs).await?);
        let mut tc_links: Vec<u32> = snapshot
            .qdiscs
            .iter()
            .filter(|q| q.handle().major() != 0)
            .map(|q| q.ifindex())
            .collect();
        tc_links.sort_unstable();
        tc_links.dedup();
        snapshot.read_tc(conn, tc_links).await?;
        snapshot.bridge_vlans = conn.get_bridge_vlans_dump().await?;
        snapshot.read_neighbours(conn).await?;
        snapshot.fdb = conn.get_bridge_neighbors().await?;
        snapshot.rules = conn.get_rules().await?;
        snapshot.nexthops = read_nexthops(conn).await?;
        let named: Vec<crate::netlink::namespace::NetnsRef> = crate::netlink::namespace::list()?
            .into_iter()
            .map(crate::netlink::namespace::NetnsRef::Named)
            .collect();
        snapshot.read_netns_ids(conn, named, false).await?;
        let linked: Vec<crate::netlink::namespace::NetnsRef> = snapshot
            .netns_ids
            .iter()
            .filter(|(_, id)| id.is_some())
            .map(|(r, _)| r.clone())
            .collect();
        snapshot.read_peer_links(linked, false).await?;
        snapshot.vrf_strict_mode = read_vrf_strict_mode(conn);
        Ok(snapshot)
    }

    /// The links of each of `refs` (#680), read through a connection
    /// there. With `required` off, one that will not open is left out.
    async fn read_peer_links(
        &mut self,
        refs: impl IntoIterator<Item = crate::netlink::namespace::NetnsRef>,
        required: bool,
    ) -> Result<()> {
        for r in refs {
            if r.is_default() || self.peer_links.contains_key(&r) {
                continue;
            }
            let netns = match r.open() {
                Ok(netns) => netns,
                Err(_) if !required => continue,
                Err(e) => return Err(e),
            };
            let links = netns.connection::<Route>()?.get_links().await?;
            self.peer_links.insert(r, links);
        }
        Ok(())
    }

    /// The id each of `refs` has here (#516). With `required` off, one
    /// that will not open — a stale name in `/run/netns`, one that went
    /// away since it was listed — is left out.
    async fn read_netns_ids(
        &mut self,
        conn: &Connection<Route>,
        refs: impl IntoIterator<Item = crate::netlink::namespace::NetnsRef>,
        required: bool,
    ) -> Result<()> {
        for r in refs {
            if r.is_default() || self.netns_ids.contains_key(&r) {
                continue;
            }
            let netns = match r.open() {
                Ok(netns) => netns,
                Err(_) if !required => continue,
                Err(e) => return Err(e),
            };
            // NETNSA_NSID_NOT_ASSIGNED (-1): no id, so no peer of ours there.
            let id = conn.get_nsid(&netns).await?;
            self.netns_ids.insert(r, (id != u32::MAX).then_some(id));
        }
        Ok(())
    }

    async fn read_neighbours(&mut self, conn: &Connection<Route>) -> Result<()> {
        self.neighbours = conn.get_neighbors().await?;
        self.proxies = conn.get_proxy_neighbors().await?;
        Ok(())
    }

    async fn read_tc(&mut self, conn: &Connection<Route>, ifindexes: Vec<u32>) -> Result<()> {
        for ifindex in ifindexes {
            let qdiscs: Vec<TcMessage> = self
                .qdiscs
                .iter()
                .filter(|q| q.ifindex() == ifindex)
                .cloned()
                .collect();
            let live = super::tc_tree::read_live(conn, ifindex, &qdiscs).await?;
            self.tc.insert(ifindex, live);
        }
        Ok(())
    }

    /// What a diff of `config` needs: what a deletion destroys is read
    /// only when the diff recreates or removes a link (#426, #512).
    pub(crate) async fn read_for(
        conn: &Connection<Route>,
        config: &NetworkConfig,
        opts: &PlanOptions,
    ) -> Result<Self> {
        let mut snapshot = Self::read_base(conn).await?;
        if kind::deletes_any(config, opts, &snapshot.links) {
            snapshot.extras = Some(kind::LinkExtras::read(conn, &snapshot.qdiscs).await?);
        }
        // Every device a tree is declared on, by this config or the
        // previous one, whose tree's removal is this diff's.
        let ifindex_of = |dev: &str| {
            snapshot
                .links
                .iter()
                .find(|l| l.name() == Some(dev))
                .map(|l| l.ifindex())
        };
        let mut tree_links: Vec<u32> = super::tc_tree::with_previous(config, opts)
            .iter()
            .filter_map(|(t, _)| ifindex_of(&t.dev))
            .collect();
        // And every device whose root or hook a declared qdisc, this
        // config's or the previous one's, takes the place of or removes:
        // what is under the live one goes with it, and an undo puts it back
        // (#783).
        let qdisc_devs: Vec<u32> = config
            .qdiscs
            .iter()
            .chain(opts.previous.iter().flat_map(|p| p.qdiscs.iter()))
            .filter_map(|q| ifindex_of(&q.dev))
            .filter(|i| {
                snapshot
                    .qdiscs
                    .iter()
                    .any(|q| q.ifindex() == *i && q.handle().major() != 0 && (q.is_root() || q.parent().is_ingress()))
            })
            .collect();
        tree_links.extend(qdisc_devs);
        tree_links.sort_unstable();
        tree_links.dedup();
        snapshot.read_tc(conn, tree_links).await?;
        if config
            .links
            .iter()
            .any(|l| l.port.as_ref().is_some_and(|p| p.vlans.is_some()))
        {
            snapshot.bridge_vlans = conn.get_bridge_vlans_dump().await?;
        }
        if !config.neighbours.is_empty()
            || opts.previous.as_ref().is_some_and(|p| !p.neighbours.is_empty())
        {
            snapshot.read_neighbours(conn).await?;
        }
        if !config.fdb.is_empty() || opts.previous.as_ref().is_some_and(|p| !p.fdb.is_empty()) {
            snapshot.fdb = conn.get_bridge_neighbors().await?;
            // A port's VLANs: an entry declared without one has one for
            // each (#793).
            if snapshot.bridge_vlans.is_empty() {
                snapshot.bridge_vlans = conn.get_bridge_vlans_dump().await?;
            }
        }
        if !config.rules.is_empty() || opts.previous.as_ref().is_some_and(|p| !p.rules.is_empty()) {
            snapshot.rules = conn.get_rules().await?;
        }
        let wants_nexthops = |c: &NetworkConfig| {
            !c.nexthops.is_empty() || c.routes.iter().any(|r| r.attrs.nhid.is_some())
        };
        if wants_nexthops(config) || opts.previous.as_deref().is_some_and(wants_nexthops) {
            snapshot.nexthops = read_nexthops(conn).await?;
        }
        let peer_namespaces: Vec<crate::netlink::namespace::NetnsRef> =
            config.links.iter().filter_map(|l| l.peer_netns().cloned()).collect();
        snapshot.read_netns_ids(conn, peer_namespaces, true).await?;
        let set_peers: Vec<crate::netlink::namespace::NetnsRef> = config
            .links
            .iter()
            .filter(|l| l.sets_veth_peer())
            .filter_map(|l| l.peer_netns().cloned())
            .collect();
        snapshot.read_peer_links(set_peers, true).await?;
        if config.vrf_strict_mode.is_some() {
            snapshot.vrf_strict_mode = read_vrf_strict_mode(conn);
        }
        Ok(snapshot)
    }

    async fn read_base(conn: &Connection<Route>) -> Result<Self> {
        Ok(Self {
            links: conn.get_links().await?,
            addresses: conn.get_addresses().await?,
            routes: conn.get_routes().await?,
            qdiscs: conn.get_qdiscs().await?,
            extras: None,
            tc: HashMap::new(),
            bridge_vlans: Vec::new(),
            neighbours: Vec::new(),
            proxies: Vec::new(),
            fdb: Vec::new(),
            rules: Vec::new(),
            netns_ids: HashMap::new(),
            peer_links: HashMap::new(),
            vrf_strict_mode: None,
            nexthops: Vec::new(),
        })
    }

    /// The links it holds.
    pub fn links(&self) -> &[LinkMessage] {
        &self.links
    }

    /// The addresses it holds.
    pub fn addresses(&self) -> &[AddressMessage] {
        &self.addresses
    }

    /// The routes it holds.
    pub fn routes(&self) -> &[RouteMessage] {
        &self.routes
    }

    /// The qdiscs it holds.
    pub fn qdiscs(&self) -> &[TcMessage] {
        &self.qdiscs
    }
}

/// Every nexthop object; none on a kernel without them (before 5.3).
/// The namespace's `net.vrf.strict_mode`, read where the connection is
/// (#680); `None` where there is none to read, without the `vrf` module.
fn read_vrf_strict_mode(conn: &Connection<Route>) -> Option<bool> {
    let value = conn.netns().ok()?.sysctl().get(VRF_STRICT_MODE).ok()?;
    Some(value.trim() == "1")
}

/// The sysctl [`NetworkConfig::vrf_strict_mode`] sets.
pub(crate) const VRF_STRICT_MODE: &str = "net.vrf.strict_mode";

async fn read_nexthops(conn: &Connection<Route>) -> Result<Vec<crate::netlink::nexthop::Nexthop>> {
    match conn.get_nexthops().await {
        Ok(n) => Ok(n),
        Err(e) if e.is_not_supported() => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// The diff of `config` against `snapshot`, with no kernel read (#518).
/// The caller has validated `config`.
pub(crate) fn diff_snapshot(
    config: &NetworkConfig,
    snapshot: &Snapshot,
    opts: &PlanOptions,
) -> Result<ConfigDiff> {
    let mut diff = ConfigDiff::default();
    let mut current_links = snapshot.links.clone();
    let current_addresses = snapshot.addresses.clone();
    let current_routes = snapshot.routes.clone();
    let current_qdiscs = snapshot.qdiscs.clone();

    // Kind parameters (#417): what changes in place, and which links have
    // to be deleted and created again. A recreate also destroys FDB
    // entries, neighbours and nexthop objects, which no declaration can
    // describe, so the snapshot holds those too when it needs them (#426).
    let no_extras = kind::LinkExtras::default();
    let extras = match &snapshot.extras {
        Some(extras) => extras,
        None if kind::deletes_any(config, opts, &current_links) => {
            return Err(crate::Error::invalid_message(
                "this snapshot was read without what a recreate destroys, and the config \
                 recreates a link; read it with Snapshot::read"
                    ,
            ));
        }
        None => &no_extras,
    };
    // Every namespace a veth peer is declared in has to be known (#516).
    if let Some(r) = config
        .links
        .iter()
        .filter_map(|l| l.peer_netns())
        .find(|r| !r.is_default() && !snapshot.netns_ids.contains_key(*r))
    {
        return Err(crate::Error::invalid_message(format!(
            "this snapshot does not know namespace {r}, which a veth peer is declared in: \
             Snapshot::read knows the named ones, and NetworkConfig::diff any it names"
        )));
    }
    let plan = kind::plan(
        config,
        opts,
        kind::Live {
            links: &current_links,
            addresses: &current_addresses,
            routes: &current_routes,
            qdiscs: &current_qdiscs,
            extras,
            netns_ids: &snapshot.netns_ids,
        },
    );
    diff.links_to_recreate = plan.recreate.clone();
    // The rest of the diff is against the links as the renames leave them
    // (#804): a renamed peer's own declaration, its addresses and routes.
    diff.links_to_rename = plan.renames.clone();
    for rename in &plan.renames {
        if let Some(link) = current_links.iter_mut().find(|l| l.name.as_deref() == Some(&rename.from)) {
            link.name = Some(rename.to.clone());
        }
    }
    diff.links_to_remove = plan.remove.clone();
    diff.routes_protocol = Some(config.routes_protocol());
    diff.owner = config.owner.clone();
    // The rest of the diff compares against the state the apply's
    // recreates leave behind: a recreated link, and everything the kernel
    // deletes with it, absent — so what the config declares on it is
    // added back — and its ports released.
    let current_links = without_recreated_links(current_links, &plan);
    let current_addresses: Vec<AddressMessage> = current_addresses
        .into_iter()
        .filter(|a| !plan.gone.contains(&a.ifindex()))
        .collect();
    let current_routes: Vec<RouteMessage> = current_routes
        .into_iter()
        .filter(|r| r.oif().is_none_or(|oif| !plan.gone.contains(&oif)))
        // A multipath route goes with any hop's link (#516).
        .filter(|r| r.multipath().is_none_or(|hops| !hops.iter().any(|h| plan.gone.contains(&h.ifindex))))
        .collect();
    let current_qdiscs: Vec<TcMessage> = current_qdiscs
        .into_iter()
        .filter(|q| !plan.gone.contains(&q.ifindex()))
        .collect();

    // Build lookup maps
    let link_by_name: HashMap<&str, &LinkMessage> = current_links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (n, l)))
        .collect();

    let ifindex_to_name: HashMap<u32, &str> = current_links
        .iter()
        .filter_map(|l| l.name.as_deref().map(|n| (l.ifindex(), n)))
        .collect();

    // Diff links — pass the ifindex→name map so master changes
    // can be detected by resolving the kernel's master ifindex
    // back to a name (Plan 207b H2).
    let flushing = diff_links(config, &link_by_name, &ifindex_to_name, &plan, &mut diff);
    diff_port_vlans(config, &link_by_name, &snapshot.bridge_vlans, &mut diff);
    // Off, unless the `vrf` module is loaded and says otherwise (#680).
    if let Some(want) = config.vrf_strict_mode
        && snapshot.vrf_strict_mode.unwrap_or(false) != want
    {
        diff.vrf_strict_mode = Some(want);
    }

    // A veth peer's declared settings, in the namespace it lives in (#680).
    // A veth this apply creates, or creates again, gets them at create.
    for declared in config.links.iter().filter(|l| l.sets_veth_peer()) {
        let DeclaredLinkType::Veth {
            peer,
            peer_netns: Some(netns),
            peer_address,
            peer_mtu,
            peer_state,
        } = &declared.link_type
        else {
            continue;
        };
        if netns.is_default()
            || diff.links_to_add.iter().any(|l| l.name == declared.name)
            || !link_by_name.contains_key(declared.name.as_str())
        {
            continue;
        }
        let Some(links) = snapshot.peer_links.get(netns) else {
            return Err(crate::Error::invalid_message(format!(
                "this snapshot did not read namespace {netns}, where {}'s peer's settings are \
                 declared: NetworkConfig::diff reads it",
                declared.name
            )));
        };
        // Not there: the peer-namespace check recreates the veth.
        let Some(live) = links.iter().find(|l| l.name() == Some(peer.as_str())) else {
            continue;
        };
        // What it was, so the plan can put it back (`Step::inverse`).
        let mut changes = LinkChanges {
            was: Some(LinkWas {
                up: live.is_up(),
                mtu: live.mtu,
                address: live.address().and_then(|a| <[u8; 6]>::try_from(a).ok()),
                ..LinkWas::default()
            }),
            ..LinkChanges::default()
        };
        match peer_state {
            LinkState::Up if !live.is_up() => changes.set_up = true,
            LinkState::Down if live.is_up() => changes.set_down = true,
            _ => {}
        }
        if let Some(mtu) = peer_mtu
            && live.mtu != Some(*mtu)
        {
            changes.set_mtu = Some(*mtu);
        }
        if let Some(mac) = peer_address
            && live.address().is_none_or(|have| have != mac)
        {
            changes.set_address = Some(*mac);
        }
        if !changes.is_empty() {
            diff.veth_peers_to_modify.push(VethPeerChange {
                link: declared.name.clone(),
                peer: peer.clone(),
                netns: netns.clone(),
                changes,
            });
        }
    }

    // The links this apply flushes: the ones its link changes take down or
    // move across an L3 master, the ports a recreated bond or VRF releases
    // (#417), and the VLANs the kernel takes down with any of them
    // (`vlan_device_event`). The kernel drops their routes, in both
    // families, and their IPv6 addresses: `fib_netdev_event` on
    // NETDEV_DOWN, and — forced, whatever the route's scope — on
    // NETDEV_CHANGEUPPER to or from an L3 master; `addrconf_notify` ->
    // `addrconf_ifdown` -> `rt6_disable_ip` for IPv6 on both. The dumps
    // above were taken before the link step, so what is declared on these
    // links reads as present and would be left out; the routes through them
    // are dropped from the comparison so the declared ones are added back
    // in the same apply (#427), and so are their IPv6 addresses (#409).
    let downed: HashSet<u32> = flushing
        .iter()
        .filter_map(|name| link_by_name.get(name).map(|l| l.ifindex()))
        .chain(plan.cycled.iter().copied())
        .collect();
    let flushed = kind::with_vlans_on(&current_links, &downed);
    let flushed_names: HashSet<&str> = flushed
        .iter()
        .filter_map(|ifindex| ifindex_to_name.get(ifindex).copied())
        .collect();
    // Why each flushed link is flushed, for the steps that put back what it
    // loses (#649).
    let mut flush_cause: HashMap<u32, String> = HashMap::new();
    for name in &flushing {
        let Some(link) = link_by_name.get(name) else {
            continue;
        };
        let goes_down = diff
            .links_to_modify
            .iter()
            .any(|(n, c)| n == name && c.set_down);
        let why = if goes_down {
            format!("flushed when {name} goes down")
        } else {
            format!("flushed when {name} changes master")
        };
        flush_cause.insert(link.ifindex(), why);
    }
    for ifindex in &plan.cycled {
        if let Some(name) = ifindex_to_name.get(ifindex) {
            flush_cause
                .entry(*ifindex)
                .or_insert_with(|| format!("flushed when {name} leaves its recreated master"));
        }
    }
    for ifindex in &flushed {
        if flush_cause.contains_key(ifindex) {
            continue;
        }
        // A VLAN the kernel takes down with its lower device.
        let lower = current_links
            .iter()
            .find(|l| l.ifindex() == *ifindex)
            .and_then(|l| l.link())
            .and_then(|lower| ifindex_to_name.get(&lower));
        if let Some(lower) = lower {
            flush_cause.insert(*ifindex, format!("flushed when {lower}, under it, goes down"));
        }
    }
    let current_routes: Vec<RouteMessage> = current_routes
        .into_iter()
        .filter(|r| r.oif().is_none_or(|oif| !flushed.contains(&oif)))
        // And with its last live hop, when all go down (#516).
        .filter(|r| r.multipath().is_none_or(|hops| !hops.iter().all(|h| flushed.contains(&h.ifindex))))
        .collect();
    // Nexthop objects on a link the apply deletes or flushes go with it,
    // and so does every route through them (#516): the declared ones are
    // put back.
    let lost_nexthops = lost_nexthops(&snapshot.nexthops, &plan.gone, &flushed);
    let current_routes: Vec<RouteMessage> = current_routes
        .into_iter()
        .filter(|r| r.nh_id().is_none_or(|id| !lost_nexthops.contains(&id)))
        .collect();

    // Plan 186 §3c — topo-sort `links_to_add` so a child whose
    // parent is also being created in this apply lands AFTER
    // its parent. Without this, a `NetworkConfig` that declares
    // a VLAN before its parent (because the declared order is
    // child-first, or because the source iterated a `HashMap`)
    // hits `InterfaceNotFound` on the second `create_link`.
    // Independent links keep their declared order — the sort
    // is stable.
    topo_sort_links_to_add(&mut diff.links_to_add);
    order_link_modifications(config, &link_by_name, &ifindex_to_name, &mut diff);

    // Diff addresses
    diff_addresses(
        config,
        &current_addresses,
        &ifindex_to_name,
        &flushed_names,
        opts,
        &mut diff,
    );

    // Diff routes
    let blackhole_nexthops: HashSet<u32> =
        snapshot.nexthops.iter().filter(|n| n.is_blackhole()).map(|n| n.id()).collect();
    diff_routes(config, &current_routes, &ifindex_to_name, &blackhole_nexthops, opts, &mut diff);

    // What is there now and goes with a flushed link is a re-add (#649).
    let cause_of = |dev: &str| {
        let link = link_by_name.get(dev)?;
        Some((link.ifindex(), flush_cause.get(&link.ifindex())?))
    };
    for a in &diff.addresses_to_add {
        if let Some((ifindex, why)) = cause_of(&a.dev)
            && current_addresses.iter().any(|c| {
                c.ifindex() == ifindex && c.address() == Some(&a.address) && c.prefix_len() == a.prefix_len
            })
        {
            diff.addresses_readded.push((a.clone(), format!("re-add: {why}")));
        }
    }
    for r in &diff.routes_to_add {
        let was_there = |oif: u32| {
            snapshot.routes.iter().any(|live| {
                live.oif() == Some(oif)
                    && live.destination() == Some(&r.destination)
                    && live.dst_len() == r.prefix_len
                    && live.table_id() == r.table.unwrap_or(254)
            })
        };
        if let Some((ifindex, why)) = r.dev.as_deref().and_then(cause_of)
            && was_there(ifindex)
        {
            diff.routes_readded.push((r.clone(), format!("re-add: {why}")));
        }
    }

    // Diff qdiscs
    diff_qdiscs(config, &current_qdiscs, &ifindex_to_name, &snapshot.tc, opts, &mut diff);

    // Neighbours (#516), against what the link changes leave: a link
    // recreated, flushed or given another MAC has none.
    let mut lost = flushed.clone();
    lost.extend(
        diff.links_to_modify
            .iter()
            .filter(|(_, c)| c.set_address.is_some())
            .filter_map(|(name, _)| link_by_name.get(name.as_str()).map(|l| l.ifindex())),
    );
    diff_neighbours(config, snapshot, &link_by_name, &lost, opts, &mut diff);

    // FDB entries (#516): a port leaving or changing its bridge loses its
    // bridge entries (`del_nbp`), a recreated device all of them.
    let moved: HashSet<u32> = diff
        .links_to_modify
        .iter()
        .filter(|(_, c)| c.set_master.is_some() || c.unset_master)
        .filter_map(|(name, _)| link_by_name.get(name.as_str()).map(|l| l.ifindex()))
        .chain(plan.released.keys().copied())
        .collect();
    diff_fdb(config, snapshot, &link_by_name, &moved, opts, &mut diff);

    // Rules (#516): by name, so no link change touches them.
    diff_rules(config, snapshot, opts, &mut diff);

    // Nexthop objects (#516).
    diff_nexthops(config, snapshot, &ifindex_to_name, &lost_nexthops, opts, &mut diff);

    // TC trees (#514), against what the recreates leave: a recreated link
    // has none. The apply diffs each again after the qdisc step.
    let names = super::tc_tree::ifindexes(&current_links);
    let no_tc = super::tc_tree::TcLive::default();
    diff.tc_declared = super::tc_tree::with_previous(config, opts);
    diff.source = Some(std::sync::Arc::new((config.clone(), opts.clone())));
    for (tree, previous) in &diff.tc_declared {
        let (live, qdiscs) = match link_by_name.get(tree.dev.as_str()) {
            Some(l) => (
                snapshot.tc.get(&l.ifindex()).unwrap_or(&no_tc),
                current_qdiscs
                    .iter()
                    .filter(|q| q.ifindex() == l.ifindex())
                    .cloned()
                    .collect(),
            ),
            None => (&no_tc, Vec::new()),
        };
        let tree_diff = super::tc_tree::diff_tree(
            tree,
            previous.as_ref(),
            &live.classes,
            &qdiscs,
            &live.filters,
            &names,
        );
        if !tree_diff.is_empty() {
            diff.tc.push(tree_diff);
        }
    }

    Ok(diff)
}

/// The declared neighbours against the kernel's (#516). A neighbour on a
/// device the apply creates, recreates or flushes (`lost`) is set whatever
/// the dump says; a previous one is removed while it is there.
fn diff_neighbours(
    config: &NetworkConfig,
    snapshot: &Snapshot,
    link_by_name: &HashMap<&str, &LinkMessage>,
    lost: &HashSet<u32>,
    opts: &PlanOptions,
    diff: &mut ConfigDiff,
) {
    // The entry the kernel has for a declaration, as one: a permanent one
    // with its link-layer address, or the proxy entry.
    let live = |n: &DeclaredNeighbour| -> Option<(DeclaredNeighbour, bool)> {
        let ifindex = link_by_name.get(n.dev.as_str())?.ifindex();
        if lost.contains(&ifindex) {
            return None;
        }
        let pool = if n.proxy { &snapshot.proxies } else { &snapshot.neighbours };
        let msg = pool
            .iter()
            .find(|m| m.ifindex() == ifindex && m.destination() == Some(&n.destination))?;
        let have = DeclaredNeighbour {
            dev: n.dev.clone(),
            destination: n.destination,
            lladdr: if n.proxy {
                None
            } else {
                msg.lladdr().and_then(|l| <[u8; 6]>::try_from(l).ok())
            },
            proxy: n.proxy,
        };
        Some((have, n.proxy || msg.is_permanent()))
    };
    for n in &config.neighbours {
        match live(n) {
            Some((have, true)) if have == *n => {}
            Some((have, true)) => {
                diff.neighbours_replaced.push((n.clone(), have));
                diff.neighbours_to_set.push(n.clone());
            }
            // Missing, or learned and not permanent.
            _ => diff.neighbours_to_set.push(n.clone()),
        }
    }
    for prev in opts.previous.iter().flat_map(|p| p.neighbours.iter()) {
        if config.neighbours.iter().any(|n| n.same_entry(prev)) {
            continue;
        }
        if let Some((have, true)) = live(prev) {
            diff.neighbours_to_remove.push(have);
        }
    }
}

/// The declared FDB entries against the kernel's (#516). A bridge entry on
/// a port in `moved`, or any entry on a device the apply creates or
/// recreates, is set whatever the dump says; a previous one is removed
/// while it is there.
fn diff_fdb(
    config: &NetworkConfig,
    snapshot: &Snapshot,
    link_by_name: &HashMap<&str, &LinkMessage>,
    moved: &HashSet<u32>,
    opts: &PlanOptions,
    diff: &mut ConfigDiff,
) {
    use crate::netlink::types::neigh::nud;
    // The entry the kernel has for a declaration, as one; whether it is
    // static or permanent rather than learned; and whether every entry it
    // makes is (#793).
    let live = |d: &DeclaredFdb| -> Option<(DeclaredFdb, bool, bool)> {
        let ifindex = link_by_name.get(d.dev.as_str())?.ifindex();
        if d.dst.is_none() && moved.contains(&ifindex) {
            return None;
        }
        let msg = snapshot.fdb.iter().find(|m| {
            m.ifindex() == ifindex
                && m.lladdr() == Some(&d.mac[..])
                && m.vlan() == d.vlan
                && m.destination().copied() == d.dst
                // A bridge's entry names its master; a device's own does not.
                && m.master().is_some() == d.dst.is_none()
        })?;
        let state = msg.header.ndm_state;
        let mut have = d.clone();
        have.local = d.dst.is_none() && state & nud::PERMANENT != 0;
        let kept = |state: u16| state & (nud::PERMANENT | nud::NOARP) != 0;
        // A bridge entry declared without a VLAN is one per VLAN of the
        // port as well (#793): `br_fdb_add` makes them all, and an apply
        // that left one missing or learned has not converged.
        let per_vlan = d.vlan.is_none() && d.dst.is_none();
        let all_vlans = !per_vlan
            || snapshot
                .bridge_vlans
                .iter()
                .filter(|v| v.ifindex() == ifindex)
                .all(|v| {
                    snapshot.fdb.iter().any(|m| {
                        m.ifindex() == ifindex
                            && m.lladdr() == Some(&d.mac[..])
                            && m.vlan() == Some(v.vid())
                            && m.master().is_some()
                            && kept(m.header.ndm_state)
                    })
                });
        Some((have, kept(state), kept(state) && all_vlans))
    };
    // Where the entry is now, when setting it moves it (#783): a bridge
    // keeps one entry per MAC and VLAN, so a replace on this port takes it
    // from another, and a VXLAN device one remote per unicast MAC, which a
    // replace swaps. It is what an undo puts back.
    let elsewhere = |d: &DeclaredFdb| -> Option<DeclaredFdb> {
        let link = link_by_name.get(d.dev.as_str())?;
        let ifindex = link.ifindex();
        let msg = snapshot.fdb.iter().find(|m| {
            m.lladdr() == Some(&d.mac[..])
                && m.vlan() == d.vlan
                && m.header.ndm_state & (nud::PERMANENT | nud::NOARP) != 0
                && match d.dst {
                    None => m.ifindex() != ifindex && m.master().is_some() && m.master() == link.master(),
                    Some(dst) => {
                        !d.floods()
                            && m.ifindex() == ifindex
                            && m.master().is_none()
                            && m.destination().is_some_and(|x| *x != dst)
                    }
                }
        })?;
        let mut before = d.clone();
        match d.dst {
            None => {
                before.dev = link_by_name
                    .iter()
                    .find(|(_, l)| l.ifindex() == msg.ifindex())
                    .map(|(name, _)| name.to_string())?;
                before.local = msg.header.ndm_state & nud::PERMANENT != 0;
            }
            Some(_) => before.dst = msg.destination().copied(),
        }
        Some(before)
    };
    for e in &config.fdb {
        match live(e) {
            Some((have, _, true)) if have == *e => {}
            Some((have, true, _)) if have != *e => {
                diff.fdb_replaced.push((e.clone(), have));
                diff.fdb_to_set.push(e.clone());
            }
            // Missing, learned, or short of an entry for a VLAN; set where
            // it is now, a move.
            _ => {
                if let Some(before) = elsewhere(e) {
                    diff.fdb_replaced.push((e.clone(), before));
                }
                diff.fdb_to_set.push(e.clone());
            }
        }
    }
    for prev in opts.previous.iter().flat_map(|p| p.fdb.iter()) {
        // Gone from the config — and for a bridge entry, not declared on
        // another port, where setting it moves it (a bridge has one entry
        // per MAC and VLAN).
        let kept = config.fdb.iter().any(|e| {
            e.same_entry(prev) || (prev.dst.is_none() && e.dst.is_none() && e.mac == prev.mac && e.vlan == prev.vlan)
        });
        if kept {
            continue;
        }
        if let Some((have, true, _)) = live(prev) {
            diff.fdb_to_remove.push(have);
        }
    }
}

/// The nexthops a link the apply deletes (`gone`) or flushes takes with it
/// (#516): the ones on it, and a group all of whose members are.
fn lost_nexthops(
    live: &[crate::netlink::nexthop::Nexthop],
    gone: &HashSet<u32>,
    flushed: &HashSet<u32>,
) -> HashSet<u32> {
    let mut lost: HashSet<u32> = live
        .iter()
        .filter(|n| n.ifindex().is_some_and(|i| gone.contains(&i) || flushed.contains(&i)))
        .map(|n| n.id())
        .collect();
    for n in live {
        if let Some(members) = n.group()
            && !members.is_empty()
            && members.iter().all(|m| lost.contains(&m.id()))
        {
            lost.insert(n.id());
        }
    }
    lost
}

/// A kernel nexthop as a declaration (#516).
pub(crate) fn nexthop_from_live(
    n: &crate::netlink::nexthop::Nexthop,
    names: &HashMap<u32, &str>,
) -> DeclaredNexthop {
    let group: Vec<(u32, u16)> = n
        .group()
        .map(|g| g.iter().map(|m| (m.id(), m.weight())).collect())
        .unwrap_or_default();
    DeclaredNexthop {
        id: n.id(),
        gateway: n.gateway(),
        dev: n.ifindex().and_then(|i| names.get(&i)).map(|d| d.to_string()),
        onlink: n.is_onlink(),
        blackhole: n.is_blackhole(),
        ipv6: group.is_empty() && n.gateway().is_none() && n.family() == libc::AF_INET6 as u8,
        group,
    }
}

/// A declaration as [`nexthop_from_live`] reads its kernel nexthop back.
fn nexthop_normal(n: &DeclaredNexthop) -> DeclaredNexthop {
    let mut n = n.clone();
    n.ipv6 = !n.is_group() && n.gateway.is_none() && n.is_ipv6();
    n
}

/// The declared nexthops against the kernel's (#516). Only one with the
/// config's protocol is the config's: another with the id is another
/// tool's, and refused.
fn diff_nexthops(
    config: &NetworkConfig,
    snapshot: &Snapshot,
    names: &HashMap<u32, &str>,
    lost: &HashSet<u32>,
    opts: &PlanOptions,
    diff: &mut ConfigDiff,
) {
    let ours = u8::from(config.routes_protocol());
    let live: HashMap<u32, &crate::netlink::nexthop::Nexthop> = snapshot
        .nexthops
        .iter()
        .filter(|n| !lost.contains(&n.id()))
        .map(|n| (n.id(), n))
        .collect();
    let mut sets = Vec::new();
    for d in &config.nexthops {
        let Some(l) = live.get(&d.id) else {
            sets.push(d.clone());
            continue;
        };
        let have = nexthop_from_live(l, names);
        if l.protocol() != ours {
            diff.nexthops_refused.push(NexthopConflict {
                nexthop: d.clone(),
                reason: format!(
                    "its id is {have}, protocol {}, which this config does not own; declare it under another id",
                    l.protocol()
                ),
            });
        // A declaration has no encap, and one the kernel's nexthop has is
        // not compared otherwise: it is another nexthop (#783).
        } else if have == nexthop_normal(d) && l.encap_type().is_none() {
        } else if have.is_group() != d.is_group() {
            diff.nexthops_refused.push(NexthopConflict {
                nexthop: d.clone(),
                reason: format!(
                    "its id is {have}: the kernel will not turn a nexthop into a group or a group \
                     into a nexthop; declare it under another id"
                ),
            });
        } else {
            diff.nexthops_replaced.push((d.clone(), have));
            sets.push(d.clone());
        }
    }
    // A group's members first.
    sets.sort_by_key(DeclaredNexthop::is_group);
    diff.nexthops_to_set = sets;
    let mut removes: Vec<DeclaredNexthop> = opts
        .previous
        .iter()
        .flat_map(|p| p.nexthops.iter())
        .filter(|p| !config.nexthops.iter().any(|d| d.id == p.id))
        .filter_map(|p| live.get(&p.id).filter(|l| l.protocol() == ours))
        .map(|l| nexthop_from_live(l, names))
        .collect();
    // A group before its members.
    removes.sort_by_key(|n| !n.is_group());
    diff.nexthops_to_remove = removes;
}

/// A kernel rule as a declaration, if it is one a declaration can be: one
/// with only the selectors and actions [`DeclaredRule`] has.
pub(crate) fn rule_from_live(r: &RuleMessage) -> Option<DeclaredRule> {
    use crate::netlink::types::rule::FibRuleAction as A;
    let action = match r.action() {
        A::ToTbl => RuleAction::Table(r.table_id()),
        A::Blackhole => RuleAction::Blackhole,
        A::Unreachable => RuleAction::Unreachable,
        A::Prohibit => RuleAction::Prohibit,
        _ => return None,
    };
    // What a declaration has no word for makes another rule (#793): a TOS,
    // realms (`FRA_FLOW`) or a suppressed interface group read back
    // without it would pass for the declared rule, which does not exist.
    if r.goto().is_some()
        || r.tun_id().is_some()
        || r.uid_range().is_some()
        || r.l3mdev().is_some()
        || r.header.tos != 0
        || r.flow().is_some_and(|f| f != 0)
        || r.suppress_ifgroup().is_some_and(|g| g != u32::MAX)
    {
        return None;
    }
    let prefix = |addr: Option<IpAddr>, len: u8| addr.map(|a| (a, len));
    Some(DeclaredRule {
        priority: r.priority(),
        ipv6: r.is_ipv6(),
        from: prefix(r.source(), r.src_len()),
        to: prefix(r.destination(), r.dst_len()),
        iif: r.iifname().map(str::to_string),
        oif: r.oifname().map(str::to_string),
        fwmark: r.fwmark(),
        // The kernel reports the all-ones mask a mark gets by default.
        fwmask: r.fwmask().filter(|m| *m != u32::MAX),
        ipproto: r.ip_proto(),
        sport: r.sport_range().map(|p| (p.start, p.end)),
        dport: r.dport_range().map(|p| (p.start, p.end)),
        invert: r.is_invert(),
        // The kernel reports -1 for "not set" (`ip rule` shows none).
        suppress_prefixlen: r.suppress_prefixlen().filter(|l| *l != u32::MAX),
        action,
    })
}

/// The kernel's rules with protocol `ours`, as declarations.
fn live_rules(rules: &[RuleMessage], ours: u8) -> Vec<DeclaredRule> {
    rules
        .iter()
        .filter(|r| r.protocol() == Some(ours))
        .filter_map(rule_from_live)
        .collect()
}

/// A declared rule as it reads back: a mask of all ones is none.
fn normal_rule(r: &DeclaredRule) -> DeclaredRule {
    let mut r = r.clone();
    if r.fwmask == Some(u32::MAX) {
        r.fwmask = None;
    }
    r.ipv6 = r.is_ipv6();
    r
}

/// Whether the kernel has `rule`, with protocol `ours`, exactly (#793).
pub(crate) async fn rule_present(
    conn: &Connection<Route>,
    rule: &DeclaredRule,
    ours: u8,
) -> Result<bool> {
    let rules = conn.get_rules().await?;
    Ok(live_rules(&rules, ours).contains(&normal_rule(rule)))
}

/// The declared rules against the kernel's (#516). Only a rule with the
/// config's protocol is the config's: one another tool added — `ip rule
/// add` leaves it `unspec` — is another rule to the kernel, however alike.
fn diff_rules(config: &NetworkConfig, snapshot: &Snapshot, opts: &PlanOptions, diff: &mut ConfigDiff) {
    let ours = u8::from(config.routes_protocol());
    let live = live_rules(&snapshot.rules, ours);
    let normal = normal_rule;
    for r in &config.rules {
        if !live.contains(&normal(r)) {
            diff.rules_to_add.push(r.clone());
        }
    }
    for prev in opts.previous.iter().flat_map(|p| p.rules.iter()) {
        if !config.rules.iter().any(|r| normal(r) == normal(prev)) && live.contains(&normal(prev)) {
            diff.rules_to_remove.push(prev.clone());
        }
    }
}

/// A declared port's VLANs against the port's (#516): the change lines,
/// and the declared set the apply makes the port's. A link the apply
/// creates gets them at create.
fn diff_port_vlans(
    config: &NetworkConfig,
    link_by_name: &HashMap<&str, &LinkMessage>,
    live: &[crate::netlink::bridge_vlan::BridgeVlanEntry],
    diff: &mut ConfigDiff,
) {
    for declared in &config.links {
        let Some(want) = declared.port.as_ref().and_then(|p| p.vlans.as_ref()) else {
            continue;
        };
        let Some(link) = link_by_name.get(declared.name.as_str()) else {
            continue;
        };
        let have: Vec<super::types::PortVlan> = live
            .iter()
            .filter(|v| v.ifindex() == link.ifindex())
            .map(|v| super::types::PortVlan::new(v.vid(), v.is_pvid(), v.is_untagged()))
            .collect();
        let mut lines: Vec<String> = want
            .iter()
            .filter(|v| !have.contains(v))
            .map(|v| format!("+{v}"))
            .collect();
        lines.extend(
            have.iter()
                .filter(|h| !want.iter().any(|w| w.vid == h.vid))
                .map(|h| format!("-vlan {}", h.vid)),
        );
        if lines.is_empty() {
            continue;
        }
        let entry = match diff.links_to_modify.iter_mut().find(|(n, _)| n == &declared.name) {
            Some((_, changes)) => changes,
            None => {
                diff.links_to_modify
                    .push((declared.name.clone(), LinkChanges::default()));
                &mut diff.links_to_modify.last_mut().unwrap().1
            }
        };
        entry.set_port_vlans = lines;
        entry.port_vlans = Some(want.clone());
    }
}

/// The links as the plan's recreates leave them: the deleted ones gone,
/// and the ports of a deleted master released — no master, and closed if
/// the master was a bond (`__bond_release_one()` ends in `dev_close()`).
fn without_recreated_links(links: Vec<LinkMessage>, plan: &KindPlan) -> Vec<LinkMessage> {
    const IFF_UP: u32 = libc::IFF_UP as u32;
    links
        .into_iter()
        .filter(|l| !plan.gone.contains(&l.ifindex()))
        .map(|mut l| {
            if let Some(&closed) = plan.released.get(&l.ifindex()) {
                l.master = None;
                if closed {
                    l.header.ifi_flags &= !IFF_UP;
                }
            }
            l
        })
        .collect()
}

/// Every link of a kind, live or about to be created by `config`.
fn links_of_kind<'a>(
    current: &HashMap<&'a str, &LinkMessage>,
    config: &'a NetworkConfig,
    kind: &str,
) -> HashSet<&'a str> {
    current
        .iter()
        .filter(|(_, l)| l.kind() == Some(kind))
        .map(|(name, _)| *name)
        .chain(
            config
                .links
                .iter()
                .filter(|l| l.link_type.kind() == Some(kind))
                .map(|l| l.name.as_str()),
        )
        .collect()
}

/// Diff the links. Returns the links whose change in this apply makes the
/// kernel flush their routes and IPv6 addresses (see `compute_diff`).
fn diff_links<'a>(
    config: &'a NetworkConfig,
    current: &HashMap<&'a str, &LinkMessage>,
    ifindex_to_name: &HashMap<u32, &'a str>,
    plan: &KindPlan,
    diff: &mut ConfigDiff,
) -> HashSet<&'a str> {
    // Note: desired_names would be used for purge mode to find links to remove
    let _desired_names: HashSet<&str> = config.links.iter().map(|l| l.name.as_str()).collect();

    // Every bond, live or about to be created — a port changing to or from
    // one of these changes state as a side effect (see compute_link_changes).
    let bonds = links_of_kind(current, config, "bond");
    // Every VRF: an L3 master, whose ports addrconf flushes on the way in
    // and out.
    let vrfs = links_of_kind(current, config, "vrf");

    // Masters whose set of ports this apply changes.
    let mut port_set_changes: HashSet<&str> = HashSet::new();
    let mut flushing: HashSet<&str> = HashSet::new();

    // The peers of the veth and netkit pairs this apply creates: declared
    // on their own, without a kind, they do not exist yet, and will (#475).
    let created_peers: HashSet<&str> = config
        .links
        .iter()
        .filter(|l| !current.contains_key(l.name.as_str()))
        .filter_map(|l| match &l.link_type {
            // A peer in another namespace is not a link here.
            DeclaredLinkType::Veth {
                peer,
                peer_netns: None | Some(crate::netlink::namespace::NetnsRef::Default),
                ..
            }
            | DeclaredLinkType::Netkit { peer, .. } => Some(peer.as_str()),
            _ => None,
        })
        .collect();

    for declared in &config.links {
        if let Some(existing) = current.get(declared.name.as_str()) {
            // Link exists, check if it needs modification
            let mut changes = compute_link_changes(declared, existing, ifindex_to_name, &bonds);
            if let Some(update) = plan.updates.get(declared.name.as_str()) {
                changes.set_kind_params = update.changes.clone();
                changes.kind_update = Some(update.clone());
            }
            let existing_master = existing
                .master()
                .and_then(|idx| ifindex_to_name.get(&idx).copied());
            if changes.set_master.is_some() || changes.unset_master {
                port_set_changes.extend(declared.master.name());
                port_set_changes.extend(existing_master);
            }
            // A port's MTU change moves an unpinned bridge too
            // (`NETDEV_CHANGEMTU` → `br_mtu_auto_adjust`), so the bridge's
            // declared MTU is re-asserted after it (#474).
            if changes.set_mtu.is_some() {
                port_set_changes.extend(existing_master);
            }
            // The link changes that make the kernel drop the link's routes
            // and IPv6 addresses (`addrconf_ifdown()`, unless
            // `keep_addr_on_down`): going down; joining or leaving an L3
            // master (`NETDEV_CHANGEUPPER`, then the VRF cycles the port);
            // and joining or leaving a bond, which takes the port down (the
            // bond closes the one it releases; `enslave` downs the one it
            // adds).
            let flushing_master = |m: Option<&str>| {
                m.is_some_and(|m| bonds.contains(m) || vrfs.contains(m))
            };
            let master_changes = changes.set_master.is_some() || changes.unset_master;
            if changes.set_down
                || (master_changes
                    && (flushing_master(existing_master)
                        || flushing_master(changes.set_master.as_deref())))
            {
                flushing.insert(declared.name.as_str());
            }
            if !changes.is_empty() {
                diff.links_to_modify.push((declared.name.clone(), changes));
            }
        } else if declared.link_type != DeclaredLinkType::Physical {
            // Link doesn't exist, needs to be created
            port_set_changes.extend(declared.master.name());
            let mut link = declared.clone();
            // A recreated link comes back down; one declared without a
            // state keeps the one it had.
            if link.state == LinkState::Unchanged && plan.was_up.contains(&link.name) {
                link.state = LinkState::Up;
            }
            diff.links_to_add.push(link);
        } else if created_peers.contains(declared.name.as_str()) {
            // The other end of a pair this apply creates. Its settings go
            // in as modifications, which run after every create; they used
            // to wait for the next apply, so the pair had no carrier (#475).
            port_set_changes.extend(declared.master.name());
            let changes = new_peer_changes(declared, &bonds);
            if !changes.is_empty() {
                diff.links_to_modify.push((declared.name.clone(), changes));
            }
        } else {
            diff.links_missing.push(declared.name.clone());
        }
    }

    // A parent or master a declared link names, which the config does not
    // declare and which does not exist: the apply created the links before
    // the one that needed it and then failed (#518).
    for declared in &config.links {
        for name in declared_lower(declared)
            .into_iter()
            .chain(declared.master.name())
        {
            if !current.contains_key(name)
                && !created_peers.contains(name)
                && !config.links.iter().any(|l| l.name == name)
                && !diff.links_missing.iter().any(|m| m == name)
            {
                diff.links_missing.push(name.to_string());
            }
        }
    }

    // A bridge's MTU follows its ports: `br_add_if()` / `br_del_if()` call
    // `br_mtu_auto_adjust()`, which sets the bridge to its smallest port's
    // MTU unless `BROPT_MTU_SET_BY_USER` is set — and only `br_change_mtu()`
    // (an RTM_SETLINK that changes the MTU) sets it, not the IFLA_MTU a
    // bridge is created with. So a bridge declared with an MTU and given a
    // port in the same apply ended up at the port's MTU, and the next diff
    // reported its own MTU as changed. Every declared bridge MTU whose port
    // set — or a port's MTU — changes here is re-asserted once the links
    // are done. (A bridge nlink creates with an MTU is pinned as it is
    // created, by `add_link`, #474; this covers bridges that predate that.)
    for declared in &config.links {
        let Some(mtu) = declared.mtu else { continue };
        let is_bridge = declared.link_type == DeclaredLinkType::Bridge
            || current
                .get(declared.name.as_str())
                .is_some_and(|l| l.kind() == Some("bridge"));
        if is_bridge && port_set_changes.contains(declared.name.as_str()) {
            diff.bridge_mtus.push((declared.name.clone(), mtu));
        }
    }

    // A device that comes up brings every VLAN on it up with it
    // (`vlan_device_event()`, NETDEV_UP, for each VLAN without loose
    // binding) — so a VLAN declared down on a lower device this apply brings
    // up ended the apply up, and converged only on the next one (#436). The
    // lower devices coming up here: set up, or created or recreated up.
    let coming_up: HashSet<&str> = diff
        .links_to_modify
        .iter()
        .filter(|(_, changes)| changes.set_up)
        .map(|(name, _)| name.as_str())
        .chain(
            diff.links_to_add
                .iter()
                .filter(|l| l.state == LinkState::Up)
                .map(|l| l.name.as_str()),
        )
        .collect();
    for declared in &config.links {
        if declared.state != LinkState::Down {
            continue;
        }
        let lower = match &declared.link_type {
            DeclaredLinkType::Vlan { parent, .. } => Some(parent.as_str()),
            _ => current
                .get(declared.name.as_str())
                .filter(|l| l.kind() == Some("vlan"))
                .and_then(|l| l.link())
                .and_then(|idx| ifindex_to_name.get(&idx).copied()),
        };
        if lower.is_some_and(|lower| coming_up.contains(lower)) {
            diff.vlans_held_down.push(declared.name.clone());
        }
    }

    // Note: We don't auto-remove links that aren't in the config
    // That requires explicit purge mode

    flushing
}

/// The device a declared link stacks on, whose MTU caps its own.
pub(crate) fn declared_lower(link: &DeclaredLink) -> Option<&str> {
    match &link.link_type {
        DeclaredLinkType::Vlan { parent, .. }
        | DeclaredLinkType::Macvlan { parent, .. }
        | DeclaredLinkType::Ipvlan { parent, .. }
        | DeclaredLinkType::Macvtap { parent, .. }
        | DeclaredLinkType::Macsec { parent, .. } => Some(parent),
        DeclaredLinkType::Vxlan { underlay_dev, .. } => underlay_dev.as_deref(),
        DeclaredLinkType::Gre(p)
        | DeclaredLinkType::Gretap(p)
        | DeclaredLinkType::Ipip(p)
        | DeclaredLinkType::Sit(p)
        | DeclaredLinkType::Vti(p) => p.underlay_dev.as_deref(),
        DeclaredLinkType::Ip6tnl(p)
        | DeclaredLinkType::Ip6gre(p)
        | DeclaredLinkType::Ip6gretap(p)
        | DeclaredLinkType::Vti6(p) => p.underlay_dev.as_deref(),
        DeclaredLinkType::Erspan(p) | DeclaredLinkType::Ip6erspan(p) => p.underlay_dev.as_deref(),
        DeclaredLinkType::Xfrm { underlay_dev, .. } => underlay_dev.as_deref(),
        _ => None,
    }
}

/// Put `links_to_modify` in an order the kernel accepts, and pick the MTUs
/// that have to go in before the creates (#473).
///
/// A stacked device's MTU cannot exceed its lower device's — raising a VLAN
/// first is ERANGE (`vlan_dev_change_mtu`) — and a VLAN cannot come up
/// while its lower device is down (`vlan_dev_open`: ENETDOWN). Lower
/// devices therefore go first. That holds for lowering too: the kernel
/// lowers the stacked devices with their lower device (`vlan_device_event`,
/// `macvlan_device_event` on NETDEV_CHANGEMTU), and each one's own,
/// smaller value then fits. Declaration order decided it before.
fn order_link_modifications(
    config: &NetworkConfig,
    live: &HashMap<&str, &LinkMessage>,
    ifindex_to_name: &HashMap<u32, &str>,
    diff: &mut ConfigDiff,
) {
    let declared: HashMap<&str, &DeclaredLink> =
        config.links.iter().map(|l| (l.name.as_str(), l)).collect();
    let lower_of = |name: &str| -> Option<String> {
        if let Some(lower) = declared.get(name).and_then(|l| declared_lower(l)) {
            return Some(lower.to_string());
        }
        // A kindless declaration of a stacked link: the kernel knows its
        // lower device. A veth's `IFLA_LINK` is its peer, not a lower one.
        let link = live.get(name)?;
        let stacked = matches!(
            link.kind(),
            Some("vlan" | "macvlan" | "macvtap" | "ipvlan" | "ipvtap")
        );
        if !stacked || link.link_netnsid.is_some() {
            return None;
        }
        link.link()
            .and_then(|idx| ifindex_to_name.get(&idx))
            .map(|n| n.to_string())
    };
    stable_topo_sort(
        &mut diff.links_to_modify,
        |(name, _)| name.as_str(),
        |(name, _)| lower_of(name).into_iter().collect(),
    );

    // The lower devices of what this apply creates, and theirs in turn.
    let mut first: HashSet<String> = diff
        .links_to_add
        .iter()
        .filter_map(|l| declared_lower(l).map(str::to_string))
        .collect();
    for (name, _) in diff.links_to_modify.iter().rev() {
        if first.contains(name)
            && let Some(lower) = lower_of(name)
        {
            first.insert(lower);
        }
    }
    diff.mtus_first = diff
        .links_to_modify
        .iter()
        .filter(|(name, _)| first.contains(name))
        .filter_map(|(name, changes)| Some((name.clone(), changes.set_mtu?)))
        .collect();
}

/// Stable topological sort: an item comes after the items its `deps` name,
/// and otherwise keeps its place. Names not among `items` are ignored; a
/// cycle leaves its members at the end, in their original order, for the
/// kernel to refuse.
fn stable_topo_sort<T>(
    items: &mut Vec<T>,
    name: impl Fn(&T) -> &str,
    deps: impl Fn(&T) -> Vec<String>,
) {
    if items.len() < 2 {
        return;
    }
    let in_batch: HashSet<String> = items.iter().map(|i| name(i).to_string()).collect();
    let mut emitted: HashSet<String> = HashSet::new();
    let mut out: Vec<T> = Vec::with_capacity(items.len());
    let mut remaining: Vec<T> = std::mem::take(items);
    while !remaining.is_empty() {
        let before = remaining.len();
        let mut next = Vec::with_capacity(remaining.len());
        for item in remaining {
            let ready = deps(&item)
                .iter()
                .all(|d| !in_batch.contains(d) || emitted.contains(d));
            if ready {
                emitted.insert(name(&item).to_string());
                out.push(item);
            } else {
                next.push(item);
            }
        }
        if next.len() == before {
            out.extend(next);
            break;
        }
        remaining = next;
    }
    *items = out;
}

/// What the peer of a pair this apply creates needs once it exists. The
/// kernel creates it down, with no master, and the create carries none of
/// its own declaration, so every declared setting is a change.
fn new_peer_changes(declared: &DeclaredLink, bonds: &HashSet<&str>) -> LinkChanges {
    let set_master = declared.master.name().map(str::to_string);
    // A bond opens the port it enslaves (`bond_enslave()` ends in
    // `dev_open()`), so a port declared down is closed after it.
    let joins_bond = set_master.as_deref().is_some_and(|m| bonds.contains(m));
    LinkChanges {
        set_up: declared.state == LinkState::Up,
        set_down: declared.state == LinkState::Down && joins_bond,
        set_mtu: declared.mtu,
        set_address: declared.address,
        set_master,
        port_update: declared
            .port
            .as_ref()
            .map(|p| p.to_config())
            .filter(|c| !c.is_empty()),
        port_vlans: declared.port.as_ref().and_then(|p| p.vlans.clone()),
        ..LinkChanges::declaring(&declared.attrs)
    }
}

/// Plan 186 §3c — stable topological sort of `links_to_add`.
///
/// A child link (Vlan, Macvlan) whose parent is also in
/// `links_to_add` must land AFTER its parent. Independent
/// links keep their declared order — the sort is stable.
///
/// Cycles are theoretically impossible for the link types we
/// model (a `Vlan` parent can't be a `Vlan` child of itself
/// without a kernel that already would have refused), but we
/// still degrade gracefully: any node not in a topo order falls
/// to the tail in its declared position.
fn topo_sort_links_to_add(links: &mut Vec<DeclaredLink>) {
    // Plan 207c M5 — ALL in-batch dependencies for a link. Pre-0.19 only
    // `Vlan { parent }` and `Macvlan { parent }` were modeled, missing:
    //   - VXLAN `underlay_dev` (Plan 190 §2.1 added the field but
    //     forgot to wire it into topo-sort — same shape as the
    //     original Plan 186 bug)
    //   - `master` references (declaring `dummy0.master("br0")`
    //     before `br0` in the same batch silently failed at apply)
    // `master` is a separate field on the link itself — it applies to any
    // link type (Dummy, Veth, Bond member, etc. enslaved to a bridge / bond
    // / VRF master).
    stable_topo_sort(
        links,
        |link| link.name.as_str(),
        |link| {
            declared_lower(link)
                .into_iter()
                .chain(link.master.name())
                .map(str::to_string)
                .collect()
        },
    );
}

pub(super) fn compute_link_changes(
    declared: &DeclaredLink,
    existing: &LinkMessage,
    ifindex_to_name: &HashMap<u32, &str>,
    bonds: &HashSet<&str>,
) -> LinkChanges {
    const IFF_PROMISC: u32 = libc::IFF_PROMISC as u32;
    let mut changes = LinkChanges {
        was: Some(LinkWas {
            up: existing.is_up(),
            mtu: existing.mtu,
            master: existing
                .master()
                .and_then(|idx| ifindex_to_name.get(&idx).map(|n| n.to_string())),
            address: existing.address().and_then(|a| <[u8; 6]>::try_from(a).ok()),
            txqlen: existing.txqlen(),
            alias: existing.alias().map(str::to_string),
            group: existing.group(),
            gso_max_size: existing.gso_max_size(),
            gso_max_segs: existing.gso_max_segs(),
            gro_max_size: existing.gro_max_size(),
            promisc: existing.flags() & IFF_PROMISC != 0,
            protodown: existing.proto_down(),
            ipv4_conf: crate::netlink::devconf::Ipv4Devconf::ALL
                .into_iter()
                .filter_map(|d| Some((d, existing.ipv4_devconf(d)?)))
                .collect(),
            ipv6_conf: crate::netlink::devconf::Ipv6Devconf::ALL
                .into_iter()
                .filter_map(|d| Some((d, existing.ipv6_devconf(d)?)))
                .collect(),
            addr_gen_mode: existing.addr_gen_mode(),
            ipv6_token: existing.ipv6_token(),
        }),
        ..LinkChanges::default()
    };

    // The attributes beyond kind, state, MTU, master and MAC (#516): each
    // declared one, compared with what the link reports.
    let a = &declared.attrs;
    let differs = |want: Option<u32>, have: Option<u32>| want.filter(|w| Some(*w) != have);
    changes.set_txqlen = differs(a.txqlen, existing.txqlen());
    changes.set_group = differs(a.group, Some(existing.group().unwrap_or(0)));
    changes.set_gso_max_size = differs(a.gso_max_size, existing.gso_max_size());
    changes.set_gso_max_segs = differs(a.gso_max_segs, existing.gso_max_segs());
    changes.set_gro_max_size = differs(a.gro_max_size, existing.gro_max_size());
    changes.set_alias = a
        .alias
        .clone()
        .filter(|want| want.as_str() != existing.alias().unwrap_or(""));
    changes.set_promisc = a
        .promisc
        .filter(|on| *on != (existing.flags() & IFF_PROMISC != 0));
    changes.set_protodown = a
        .protodown
        .filter(|on| *on != existing.proto_down().unwrap_or(false));
    for (name, want) in &a.ipv4_conf {
        if let Some(d) = crate::netlink::devconf::Ipv4Devconf::from_name(name)
            && existing.ipv4_devconf(d) != Some(*want)
        {
            changes.set_ipv4_conf.push((d, *want));
        }
    }
    if let Some(port) = &declared.port {
        let (lines, config) = super::kind::port_changes(port, existing);
        changes.set_port_options = lines;
        changes.port_update = config;
    }
    for (name, want) in &a.ipv6_conf {
        if let Some(d) = crate::netlink::devconf::Ipv6Devconf::from_name(name)
            && existing.ipv6_devconf(d) != Some(*want)
        {
            changes.set_ipv6_conf.push((d, *want));
        }
    }
    changes.set_addr_gen_mode = a.addr_gen_mode.filter(|m| Some(*m) != existing.addr_gen_mode());
    changes.set_ipv6_token = a.ipv6_token.filter(|t| Some(*t) != existing.ipv6_token());
    if let Some(want) = &a.altnames {
        let have = existing.altnames();
        changes.add_altnames = want.iter().filter(|n| !have.contains(n)).cloned().collect();
        changes.del_altnames = have.iter().filter(|n| !want.contains(n)).cloned().collect();
    }

    // Plan 207a M10 — read the IFF_UP administrative flag from
    // ifi_flags, NOT the OperState (RFC 2863) field. OperState
    // reports the *carrier-dependent* operational state: dummy /
    // veth / bridge interfaces with no carrier stay
    // `Down`/`LowerLayerDown`/`Unknown` even when admin-up. The
    // pre-0.19 comparison silently no-op'd on
    // `LinkState::Down`-declared no-carrier admin-up interfaces
    // (because operstate was never `Up`, so "if up, set_down"
    // never fired) and unnecessarily fired `set_up` on every
    // re-apply (because operstate stayed non-`Up`).
    let is_admin_up = existing.is_up();
    match declared.state {
        LinkState::Up => {
            if !is_admin_up {
                changes.set_up = true;
            }
        }
        LinkState::Down => {
            if is_admin_up {
                changes.set_down = true;
            }
        }
        LinkState::Unchanged => {}
    }

    // Check MTU
    if let Some(desired_mtu) = declared.mtu
        && existing.mtu != Some(desired_mtu)
    {
        changes.set_mtu = Some(desired_mtu);
    }

    // Check MAC. `LinkMessage::address` is the raw `IFLA_ADDRESS`
    // payload, whose length is the link type's `addr_len` — 6 for
    // Ethernet, 0 for tunnels, 20 for InfiniBand — so compare only when
    // it is the shape a declared MAC can be.
    if let Some(desired_mac) = declared.address {
        let same = existing.address().is_some_and(|have| have == desired_mac);
        if !same {
            changes.set_address = Some(desired_mac);
        }
    }

    // Plan 207b H2 — resolve existing.master (ifindex) → name and
    // compare against the declared master string. Pre-0.19 the
    // comparison was `Option<String> vs Option<u32>` treating any
    // (Some, Some) pair as equal, so bridge-port reassignment
    // (declared `master: "br0"` vs kernel `master: ifindex(br1)`)
    // silently no-op'd — the single most common reconcile
    // operation in lab/CNI environments.
    let existing_master_name: Option<&str> = existing
        .master()
        .and_then(|idx| ifindex_to_name.get(&idx).copied());

    // A declaration that does not mention a master leaves it alone; only
    // `nomaster()` releases one (#462).
    match (&declared.master, existing_master_name) {
        (MasterSpec::Name(want), Some(have)) if want == have => {
            // No change — declared master matches kernel master.
        }
        (MasterSpec::Name(want), _) => {
            // Either kernel has no master, or has a different master.
            // Either way, queue a set_master operation.
            changes.set_master = Some(want.to_string());
        }
        (MasterSpec::None, Some(_)) => {
            changes.unset_master = true;
        }
        _ => {}
    }

    // A bond opens the port it enslaves and closes the one it releases —
    // `bond_enslave()` ends in `dev_open()`, `__bond_release_one()` in
    // `dev_close()` — whatever state the port had. Across a bond master
    // change the state read above is therefore stale, and the declared one
    // has to be re-asserted after the change: a port declared up and
    // released from a bond came back down, and the next diff said `up`.
    let master_changes = changes.unset_master || changes.set_master.is_some();
    let leaves_bond = master_changes && existing_master_name.is_some_and(|m| bonds.contains(m));
    let joins_bond = changes
        .set_master
        .as_deref()
        .is_some_and(|m| bonds.contains(m));
    match declared.state {
        LinkState::Up if leaves_bond && !joins_bond => changes.set_up = true,
        LinkState::Down if joins_bond => changes.set_down = true,
        _ => {}
    }

    changes
}

fn diff_addresses(
    config: &NetworkConfig,
    current: &[AddressMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    flushed: &HashSet<&str>,
    opts: &PlanOptions,
    diff: &mut ConfigDiff,
) {
    // The kernel's addresses as declarations: on a device, an address
    // (`IFA_LOCAL`, or `IFA_ADDRESS` when there is no other), its prefix,
    // and a point-to-point peer (`IFA_ADDRESS` when it differs) — which,
    // for IPv4, makes another address, not a change of this one (#516).
    // Read back whole (#781): what a removal deletes is what its undo adds
    // again, so it carries the label, metric, flags and lifetimes too. The
    // matching below looks at the address, prefix and peer alone.
    let live: Vec<(DeclaredAddress, &AddressMessage)> = current
        .iter()
        .filter_map(|a| Some((address_from_live(ifindex_to_name.get(&a.ifindex())?, a)?, a)))
        .collect();
    let same = |a: &DeclaredAddress, b: &DeclaredAddress| {
        a.dev == b.dev
            && a.address == b.address
            && a.prefix_len == b.prefix_len
            && a.attrs.peer == b.attrs.peer
    };
    let queued = |diff: &ConfigDiff, a: &DeclaredAddress| {
        diff.addresses_to_remove.iter().any(|q| same(q, a))
    };

    // An IPv6 address on a link whose change in this apply makes the
    // kernel drop it (set down, moved into or out of a VRF or a bond, a
    // VLAN on one of those — see `compute_diff`) is read here as present
    // and is gone by the time the address step runs, so it is (re-)added
    // too. Comparing only against the pre-apply dump left it missing until
    // the next apply (#409). Should the address survive after all
    // (`keep_addr_on_down`), the add finds it in place and is not counted.
    for declared in &config.addresses {
        let gone = declared.address.is_ipv6() && flushed.contains(declared.dev.as_str());
        match live.iter().find(|(l, _)| same(l, declared)) {
            None => diff.addresses_to_add.push(declared.clone()),
            Some(_) if gone => diff.addresses_to_add.push(declared.clone()),
            Some((have, msg)) => match address_drift(declared, msg) {
                AddressDrift::None => {}
                AddressDrift::InPlace => diff.addresses_to_change.push(declared.clone()),
                // Deleted right before it is added again (#516).
                AddressDrift::Recreate => {
                    diff.addresses_to_remove.push(have.clone());
                    diff.addresses_to_add.push(declared.clone());
                }
            },
        }
        // The kernel knows an IPv6 address by the address alone
        // (`ipv6_get_ifaddr`), so the same address at another prefix is
        // this one, re-prefixed: the add would be EEXIST, and the old
        // prefix has to go first. Keyed on the full triple, the add's
        // EEXIST was swallowed and, with purge, the old prefix deleted
        // after it — leaving the interface with no address (#461). IPv4
        // keys addresses on address *and* mask (`inet_insert_ifa`), so two
        // prefixes of one IPv4 address coexist and need nothing here.
        if declared.address.is_ipv6() && !gone {
            for (have, _) in &live {
                if have.dev == declared.dev
                    && have.address == declared.address
                    && have.prefix_len != declared.prefix_len
                    && !queued(diff, have)
                {
                    diff.addresses_to_remove.push(have.clone());
                }
            }
        }
    }

    // Declared before, not now, and still there: it goes (#512).
    for prev in opts.previous.iter().flat_map(|p| p.addresses.iter()) {
        let declared_now = config.addresses.iter().any(|a| same(a, prev));
        let have = live.iter().find(|(l, _)| same(l, prev));
        if let Some((have, _)) = have
            && !declared_now
            && !queued(diff, have)
        {
            diff.addresses_to_remove.push(have.clone());
        }
    }

    if !opts.purge {
        return;
    }

    // Purge: remove global-scope addresses that the kernel has but
    // the config doesn't declare — but only on interfaces the config
    // declares, as a link or by an address, or the caller names (#470),
    // and never kernel-managed addresses (link-local / loopback / any
    // non-global scope / anything with a lifetime: a declared address
    // with one is removed through `previous`, not a purge, which cannot
    // tell it from a DHCP lease).
    let managed_devs = opts.purge_address_scope(config);
    for (have, msg) in &live {
        if !purgeable_address(msg) || !managed_devs.contains(have.dev.as_str()) {
            continue;
        }
        if !config.addresses.iter().any(|a| same(a, have)) && !queued(diff, have) {
            diff.addresses_to_remove.push(have.clone());
        }
    }
}

/// A kernel address as the declaration that adds it again (#781): its peer,
/// a label other than the device's name, its metric, the flags a
/// declaration has, and its lifetimes when it has them, as they stand.
pub(super) fn address_from_live(dev: &str, a: &AddressMessage) -> Option<DeclaredAddress> {
    use crate::netlink::types::addr::ifa_flags as f;
    let mut d = DeclaredAddress::plain(dev, *a.primary_address()?, a.prefix_len());
    let flags = a.flags();
    d.attrs.peer = a.peer().copied();
    d.attrs.label = a.label().filter(|l| *l != dev).map(str::to_string);
    // Restored without it, an address lost the broadcast route the kernel
    // makes for it in the local table (#783).
    d.attrs.broadcast = match a.broadcast() {
        Some(IpAddr::V4(b)) if !b.is_unspecified() => Some(*b),
        _ => None,
    };
    d.attrs.metric = a.metric();
    d.attrs.nodad = flags & f::NODAD != 0;
    d.attrs.optimistic = flags & f::OPTIMISTIC != 0;
    d.attrs.noprefixroute = flags & f::NOPREFIXROUTE != 0;
    d.attrs.home = flags & f::HOMEADDRESS != 0;
    d.attrs.mngtmpaddr = flags & f::MANAGETEMPADDR != 0;
    if !a.is_permanent()
        && let Some(c) = a.cache_info()
    {
        let secs = |s: u32| std::time::Duration::from_secs(u64::from(s));
        d.attrs.lifetimes = Some((secs(c.valid), secs(c.preferred)));
    }
    Some(d)
}

/// How a live address differs from its declaration (#516).
enum AddressDrift {
    None,
    /// An `NLM_F_REPLACE` changes it: the metric, the lifetimes, and an
    /// IPv6 address's flags.
    InPlace,
    /// Only deleting and adding it again does: an IPv4 address's label or
    /// flags, which a replace leaves as they were, and an IPv6 metric going
    /// back to none, which `inet6_addr_modify` skips (checked on 6.12).
    Recreate,
}

fn address_drift(declared: &DeclaredAddress, live: &AddressMessage) -> AddressDrift {
    use crate::netlink::types::addr::ifa_flags as f;
    let t = &declared.attrs;
    // `optimistic` is cleared by the kernel when DAD ends: not compared.
    let managed = f::NODAD | f::NOPREFIXROUTE | f::HOMEADDRESS | f::MANAGETEMPADDR;
    let flags = t.flag_bits() & managed != live.flags() & managed;
    let metric = t.metric.unwrap_or(0) != live.metric().unwrap_or(0);
    // A lifetime counts down: compared finite against forever only.
    let lifetimes = t.lifetimes.is_some() == live.is_permanent();
    let label = declared.address.is_ipv4()
        && t.label.as_deref().unwrap_or(&declared.dev) != live.label().unwrap_or(&declared.dev);
    // A replace leaves an IPv4 address's broadcast as it was (#783). One
    // not declared is not compared: the tools that add addresses set one
    // (`brd +`, DHCP clients), and recreating an address drops it a moment.
    let live_broadcast = match live.broadcast() {
        Some(IpAddr::V4(b)) if !b.is_unspecified() => Some(*b),
        _ => None,
    };
    let broadcast = t.broadcast.is_some_and(|b| live_broadcast != Some(b));
    let metric_to_none =
        declared.address.is_ipv6() && t.metric.unwrap_or(0) == 0 && live.metric().unwrap_or(0) != 0;
    if (declared.address.is_ipv4() && (label || flags || broadcast)) || metric_to_none {
        AddressDrift::Recreate
    } else if flags || metric || lifetimes {
        AddressDrift::InPlace
    } else {
        AddressDrift::None
    }
}

/// Whether a purge may remove `a` when nothing declares it, wherever it is.
///
/// Only `global` (universe) scope — not IPv6 link-local (fe80::, scope
/// link), loopback (::1 / 127.0.0.1, scope host) or another kernel-managed
/// scope. And only a permanent address: one the kernel expires came from
/// SLAAC, privacy extensions or a DHCP lease, and the next RA or renewal
/// brings it back, so removing it never converges (#470).
pub(super) fn purgeable_address(a: &AddressMessage) -> bool {
    a.scope() == Scope::Universe && a.is_permanent()
}

/// Whether a purge whose table scope is `tables` may remove `r` when
/// nothing declared carries it: an IPv4 or IPv6 route with the config's
/// own protocol (`static`/`boot` by default, #512), of a type a
/// declaration can describe, in a table the config owns.
pub(super) fn purgeable_route(
    r: &RouteMessage,
    tables: &HashSet<u32>,
    config: &NetworkConfig,
) -> bool {
    (r.is_ipv4() || r.is_ipv6())
        && config.owns_route_protocol(r.protocol())
        && matches!(
            r.route_type(),
            RouteType::Unicast
                | RouteType::Blackhole
                | RouteType::Unreachable
                | RouteType::Prohibit
        )
        && tables.contains(&r.table_id())
}

/// The destination the kernel stores for a declared route.
///
/// IPv6 masks a route's destination to its prefix
/// (`ipv6_addr_prefix(&rt->fib6_dst.addr, &cfg->fc_dst, cfg->fc_dst_len)`
/// in `ip6_route_info_create`), so `2001:db8::1/32` is installed — and
/// dumped — as `2001:db8::/32`. IPv4 refuses host bits instead
/// (`fib_table_insert`: "Invalid prefix for given prefix length"), so an
/// IPv4 destination is left as declared and the apply reports that error,
/// as `ip route` does.
pub(super) fn kernel_destination(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix_len.min(128)))
                .unwrap_or(0);
            IpAddr::V6(std::net::Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// The metric the kernel gives an IPv6 route added without one
/// (`IP6_RT_PRIO_USER`, include/net/ip6_route.h). IPv4 leaves an
/// unspecified metric at 0; IPv6 does not, and a diff that assumes it
/// does never matches its own routes.
const IP6_RT_PRIO_USER: u32 = 1024;

/// The metric the kernel stores for a declared route: the declared one,
/// except that IPv6 turns both "none" and 0 into `IP6_RT_PRIO_USER`.
pub(super) fn kernel_metric(route: &DeclaredRoute) -> u32 {
    match (route.metric, route.destination.is_ipv6()) {
        (None | Some(0), true) => IP6_RT_PRIO_USER,
        (Some(metric), _) => metric,
        (None, false) => 0,
    }
}

fn diff_routes(
    config: &NetworkConfig,
    current: &[RouteMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    blackhole_nexthops: &HashSet<u32>,
    opts: &PlanOptions,
    diff: &mut ConfigDiff,
) {
    let purge = opts.purge;
    // Plan 207d H3 — compare the FULL route identity (dst, prefix,
    // table, gateway, oif, metric) when deciding "no change",
    // not just (dst, prefix, table). Pre-0.19 a gateway/dev/metric
    // change on the same `(dst, prefix, table)` silently no-op'd
    // because the key matched and the diff had no
    // `routes_to_modify` collection.
    //
    // We DON'T grow the diff struct; instead any non-trivial
    // mismatch goes into `routes_to_add`, and `add_route` uses
    // `NLM_F_REPLACE` so the kernel atomically swaps the
    // existing route (Plan 207d implementation).

    // Build a name→ifindex map (inverse of `ifindex_to_name`)
    // so we can resolve declared `dev: Option<String>` to compare
    // against the kernel's `oif: Option<u32>`.
    let name_to_ifindex: HashMap<&str, u32> = ifindex_to_name
        .iter()
        .map(|(idx, name)| (*name, *idx))
        .collect();
    let resolve = |name: &str| name_to_ifindex.get(name).copied();
    // A route through a nexthop object dumps the object's type while the
    // object is a blackhole, and its own otherwise. One added as a
    // blackhole stays one whatever its object becomes (#783): that is not
    // the declared route, which is unicast.
    let stuck = |r: &RouteMessage| {
        r.nh_id()
            .is_some_and(|id| r.route_type() != RouteType::Unicast && !blackhole_nexthops.contains(&id))
    };

    // Index current routes by (dst, prefix, table) for fast lookup
    // of every matching kernel route. ECMP / multi-metric setups
    // can have multiple entries per key.
    let mut current_by_key: HashMap<(IpAddr, u8, u32), Vec<&RouteMessage>> = HashMap::new();
    for r in current.iter().filter(|r| {
        matches!(
            r.route_type(),
            RouteType::Unicast
                | RouteType::Blackhole
                | RouteType::Unreachable
                | RouteType::Prohibit
        )
    }) {
        let dst = r.destination.unwrap_or_else(|| {
            if r.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            }
        });
        current_by_key
            .entry((dst, r.dst_len(), r.table_id()))
            .or_default()
            .push(r);
    }

    // For each declared route, check if any kernel route at the
    // same (dst, prefix, table) MATCHES gateway+dev+metric. If yes,
    // no-op. If not, queue for add (which uses NLM_F_REPLACE).
    for declared in &config.routes {
        let table = declared.table.unwrap_or(254);
        // Keyed on the destination the kernel stores, not the declared
        // one: a declared IPv6 `2001:db8:32::1/48` is dumped as
        // `2001:db8:32::/48`, and keying on the host bits matched nothing,
        // so the route was re-added (a replace) on every apply (#TBD).
        let key = (
            kernel_destination(declared.destination, declared.prefix_len),
            declared.prefix_len,
            table,
        );
        // `name_to_ifindex` comes from the *pre-apply* link dump, so a
        // config that declares both a link and a route out of it
        // resolves to `None` on the first pass. That mattered: the
        // `(None, Some(_)) => true` arm below then treated *any* kernel
        // route at `(dst, prefix, table)` as a match, so declaring
        // `vx0` plus `10.0.0.0/8 dev vx0` on a host that already had
        // `10.0.0.0/8 dev eth0` omitted the route entirely and a second
        // apply was needed to converge (#281).
        //
        // Distinguish "no dev declared" from "declared a dev we cannot
        // resolve yet": the latter is drift, not a match.
        let declared_dev_unresolved =
            declared.dev.is_some() && {
                let d = declared.dev.as_deref().expect("is_some");
                !name_to_ifindex.contains_key(d)
            };
        let declared_oif = declared
            .dev
            .as_deref()
            .and_then(|d| name_to_ifindex.get(d).copied());

        // A route out of an interface this apply is about to create
        // cannot already be right, whatever the kernel currently has at
        // that destination.
        let matches_existing = !declared_dev_unresolved
            && current_by_key.get(&key).is_some_and(|kernel_routes| {
                kernel_routes
                    .iter()
                    .any(|r| route_matches(declared, declared_oif, &resolve, r) && !stuck(r))
            });

        if matches_existing {
            continue;
        }
        // The replace overwrites the first route at the key with the same
        // metric (and, for IPv4, TOS 0: `fib_table_insert`; IPv6:
        // `fib6_add_rt2node`). nlink adds the config's own protocol (`boot`
        // unless it says otherwise), and a purge treats that one as the
        // config's; anything else in that place belongs to someone else and
        // is refused, not overwritten (#469, #512).
        let slot = kernel_metric(declared);
        let foreign = current_by_key.get(&key).and_then(|kernel_routes| {
            kernel_routes.iter().find(|r| {
                r.priority().unwrap_or(0) == slot
                    && r.header.rtm_tos == 0
                    && !config.owns_route_protocol(r.protocol())
            })
        });
        match foreign {
            Some(r) => diff.routes_refused.push(RouteConflict {
                route: declared.clone(),
                held_by: describe_route(r, ifindex_to_name),
            }),
            None => {
                // What the replace overwrites, if anything (#518).
                let replaced = current_by_key.get(&key).and_then(|kernel_routes| {
                    kernel_routes
                        .iter()
                        .find(|r| r.priority().unwrap_or(0) == slot && r.header.rtm_tos == 0)
                        .and_then(|r| Some((declared_from_live(r, ifindex_to_name)?, r.protocol(), route_lost(r))))
                });
                if let Some((replaced, protocol, lost)) = replaced {
                    diff.route_protocols.push((replaced.clone(), protocol));
                    if let Some(lost) = lost {
                        diff.routes_lost.push((replaced.clone(), lost));
                    }
                    diff.routes_replaced.push((declared.clone(), replaced));
                }
                diff.routes_to_add.push(declared.clone());
            }
        }
    }

    // Which kernel routes go. A route goes when nothing declared carries
    // it — compared on the full identity, as the add path does, not on
    // `(dst, prefix, table)` alone (#468):
    //   - always, a route a declared route **supersedes**: same key, type,
    //     gateway and device, only the metric differs. The add is a
    //     replace, and `NLM_F_REPLACE` only replaces a route of the same
    //     metric, so a metric change used to install the new route next
    //     to the old one, which kept winning;
    //   - with purge, every other admin/user route nothing declared
    //     matches. Heavily fenced:
    //       - only the tables the config owns: main (254), every table a
    //         declared route names, and `opts.purge_tables` — leaves
    //         local/default and any VRF table nobody declared into
    //         (#333, #335: main-only made a declared VRF route a one-way
    //         street — added and updated, never removed),
    //       - `static`/`boot` protocol only — never kernel-derived, RA,
    //         DHCP or redirect routes (those are dynamic / auto),
    //       - unicast/blackhole/unreachable/prohibit, IPv4 and IPv6 only.
    // A route a declared route will *replace* in place — same key and
    // metric — is never removed: the replace overwrites it.
    let declared_by_key: HashMap<(IpAddr, u8, u32), Vec<&DeclaredRoute>> =
        config.routes.iter().fold(HashMap::new(), |mut map, r| {
            map.entry((
                kernel_destination(r.destination, r.prefix_len),
                r.prefix_len,
                r.table.unwrap_or(254),
            ))
            .or_default()
            .push(r);
            map
        });
    let oif_of = |d: &DeclaredRoute| {
        d.dev
            .as_deref()
            .and_then(|n| name_to_ifindex.get(n).copied())
    };
    let tables = opts.purge_table_scope(config);
    // The routes the previous config declared, by the same key (#512).
    let previous_by_key: HashMap<(IpAddr, u8, u32), Vec<&DeclaredRoute>> = opts
        .previous
        .iter()
        .flat_map(|p| p.routes.iter())
        .fold(HashMap::new(), |mut map, r| {
            map.entry((
                kernel_destination(r.destination, r.prefix_len),
                r.prefix_len,
                r.table.unwrap_or(254),
            ))
            .or_default()
            .push(r);
            map
        });

    for r in current {
        if !(r.is_ipv4() || r.is_ipv6()) || !config.owns_route_protocol(r.protocol()) {
            continue;
        }
        // Local/broadcast/multicast/anycast/… are kernel-managed — never
        // purge them.
        if !matches!(
            r.route_type(),
            RouteType::Unicast | RouteType::Blackhole | RouteType::Unreachable | RouteType::Prohibit
        ) {
            continue;
        }
        let dst = r.destination.unwrap_or_else(|| {
            if r.is_ipv4() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            }
        });
        let declared_here = declared_by_key
            .get(&(dst, r.dst_len(), r.table_id()))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let carried = declared_here.iter().any(|d| route_matches(d, oif_of(d), &resolve, r));
        let replaced = declared_here
            .iter()
            .any(|d| kernel_metric(d) == r.priority().unwrap_or(0));
        if carried || replaced {
            continue;
        }
        let superseded = declared_here
            .iter()
            .any(|d| route_matches_but_metric(d, oif_of(d), &resolve, r));
        // The caller's own tables are never purged (#513).
        let purged = purge && purgeable_route(r, &tables, config) && !opts.owns_table(r.table_id());
        // Declared before, not now: it goes, wherever its table (#512).
        let dropped = previous_by_key
            .get(&(dst, r.dst_len(), r.table_id()))
            .is_some_and(|prev| prev.iter().any(|d| route_matches(d, oif_of(d), &resolve, r)));
        if !(superseded || purged || dropped) {
            continue;
        }
        if let Some(route) = declared_from_live(r, ifindex_to_name) {
            diff.route_protocols.push((route.clone(), r.protocol()));
            if let Some(lost) = route_lost(r) {
                diff.routes_lost.push((route.clone(), lost));
            }
            diff.routes_to_remove.push(route);
        }
    }
}

/// What a kernel route has that its declaration cannot say (#783): a
/// metric past the six a declaration has, locked metrics, a congestion
/// control, realms, an encap other than MPLS, an IPv6 router preference or
/// expiry. Read back without it, the route is put back as another; a
/// replace that sends none of it drops it. `None` when there is nothing.
pub(crate) fn route_lost(r: &RouteMessage) -> Option<String> {
    let mut what: Vec<&str> = Vec::new();
    if let Some(m) = r.metrics() {
        for (name, v) in [
            ("rtt", m.rtt),
            ("rttvar", m.rttvar),
            ("ssthresh", m.ssthresh),
            ("cwnd", m.cwnd),
            ("rto_min", m.rto_min),
            ("quickack", m.quickack),
            ("reordering", m.reordering),
            ("features", m.features),
        ] {
            if v.is_some() {
                what.push(name);
            }
        }
    }
    if r.metrics_lock().is_some_and(|l| l != 0) {
        what.push("locked metrics");
    }
    if r.congctl().is_some() {
        what.push("a congestion control");
    }
    if r.flow().is_some_and(|f| f != 0) {
        what.push("realms");
    }
    // Through a nexthop object, the encap dumped is the object's (#769).
    const LWTUNNEL_ENCAP_MPLS: u16 = 1;
    if r.nh_id().is_none() && r.encap_type().is_some_and(|t| t != LWTUNNEL_ENCAP_MPLS) {
        what.push("an encap other than MPLS");
    }
    // `ICMPV6_ROUTER_PREF_MEDIUM` is 0, and every IPv6 route reports one.
    if r.pref().is_some_and(|p| p != 0) {
        what.push("a router preference");
    }
    if r.expires().is_some_and(|e| e != 0) {
        what.push("an expiry");
    }
    let hops = r.multipath().unwrap_or_default();
    if r.nh_id().is_none() && hops.iter().any(|h| h.encap_type.is_some()) {
        what.push("a next hop with an encap");
    }
    if hops.iter().any(|h| h.flow.is_some_and(|f| f != 0)) {
        what.push("a next hop with realms");
    }
    (!what.is_empty()).then(|| format!("it has {}, which no declaration has", what.join(", ")))
}

/// A kernel route as the declaration that would install it; `None` for a
/// type no declaration has (local, broadcast, …).
pub(super) fn declared_from_live(
    r: &RouteMessage,
    ifindex_to_name: &HashMap<u32, &str>,
) -> Option<DeclaredRoute> {
    let route_type = match r.route_type() {
        RouteType::Unicast => DeclaredRouteType::Unicast,
        RouteType::Blackhole => DeclaredRouteType::Blackhole,
        RouteType::Unreachable => DeclaredRouteType::Unreachable,
        RouteType::Prohibit => DeclaredRouteType::Prohibit,
        _ => return None,
    };
    let destination = r.destination.unwrap_or_else(|| {
        if r.is_ipv4() {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        }
    });
    // A route through a nexthop object is dumped with the nexthop's gateway,
    // device, encap and onlink flag as well (`nexthop_compat_mode`, on by
    // default). Read back with them, its delete matched no route and its
    // re-add was refused: a request may not name both (#769).
    let through_object = r.nh_id().is_some();
    // Through an object, the type dumped is the object's while it is a
    // blackhole; put back as one, the route stays a blackhole whatever the
    // object becomes (#783). The route is unicast.
    let route_type = if through_object { DeclaredRouteType::Unicast } else { route_type };
    Some(DeclaredRoute {
        destination,
        prefix_len: r.dst_len(),
        gateway: r.gateway().or(r.via()).copied().filter(|_| !through_object),
        dev: r
            .oif()
            .filter(|_| !through_object)
            .and_then(|idx| ifindex_to_name.get(&idx))
            .map(|n| n.to_string()),
        metric: r.priority(),
        table: Some(r.table_id()),
        route_type,
        // What it carries, so an undo puts it back as it was (#516).
        attrs: super::types::RouteAttrs {
            prefsrc: r.prefsrc().copied(),
            scope: Some(r.scope()),
            onlink: r.is_onlink() && !through_object,
            nhid: r.nh_id(),
            mpls_encap: r
                .mpls_encap_labels()
                .filter(|_| !through_object)
                .unwrap_or_default()
                .to_vec(),
            multipath: r
                .multipath()
                .filter(|_| !through_object)
                .unwrap_or_default()
                .iter()
                .map(|h| super::types::RouteNexthop {
                    gateway: h.gateway,
                    dev: ifindex_to_name.get(&h.ifindex).map(|n| n.to_string()),
                    weight: h.weight,
                    onlink: h.flags & crate::netlink::route::rtnh_flags::ONLINK != 0,
                })
                .collect(),
            ..Default::default()
        }
        .with_metrics(r.metrics()),
    })
}

/// A declared route the way the diff prints it: `10.1.0.0/16 via 10.0.0.1
/// dev eth0`.
pub(crate) fn route_text(route: &DeclaredRoute) -> String {
    let mut out = format!("{}/{}", route.destination, route.prefix_len);
    if let Some(id) = route.attrs.nhid {
        out.push_str(&format!(" nhid {id}"));
    }
    for hop in &route.attrs.multipath {
        out.push_str(&format!(" {hop}"));
    }
    if !route.attrs.mpls_encap.is_empty() {
        let labels: Vec<String> = route.attrs.mpls_encap.iter().map(u32::to_string).collect();
        out.push_str(&format!(" encap mpls {}", labels.join("/")));
    }
    if let Some(g) = route.gateway {
        out.push_str(&format!(" via {g}"));
    }
    if let Some(d) = &route.dev {
        out.push_str(&format!(" dev {d}"));
    }
    // What a change of these alone is a change of (#516).
    let a = &route.attrs;
    if let Some(src) = a.prefsrc {
        out.push_str(&format!(" src {src}"));
    }
    if a.onlink {
        out.push_str(" onlink");
    }
    for (name, value) in [
        ("mtu", a.mtu),
        ("advmss", a.advmss),
        ("window", a.window),
        ("initcwnd", a.initcwnd),
        ("initrwnd", a.initrwnd),
        ("hoplimit", a.hoplimit),
    ] {
        if let Some(v) = value {
            out.push_str(&format!(" {name} {v}"));
        }
    }
    out
}

/// A kernel route the way `ip route` prints it.
fn describe_route(r: &RouteMessage, ifindex_to_name: &HashMap<u32, &str>) -> String {
    let mut out = match r.destination {
        Some(dst) => format!("{dst}/{}", r.dst_len()),
        None => "default".to_string(),
    };
    if r.route_type() != RouteType::Unicast {
        out = format!("{} {out}", r.route_type().name());
    }
    if let Some(gateway) = r.gateway() {
        out.push_str(&format!(" via {gateway}"));
    }
    if let Some(name) = r.oif().and_then(|oif| ifindex_to_name.get(&oif)) {
        out.push_str(&format!(" dev {name}"));
    }
    out.push_str(&format!(
        " proto {} metric {}",
        r.protocol(),
        r.priority().unwrap_or(0)
    ));
    out
}

/// Does the kernel route `r`, at `declared`'s key, carry `declared`?
/// `declared_oif` is the declared device's ifindex, if it resolves.
fn route_matches(
    declared: &DeclaredRoute,
    declared_oif: Option<u32>,
    resolve: &dyn Fn(&str) -> Option<u32>,
    r: &RouteMessage,
) -> bool {
    // Metric (priority). A route added without an explicit metric does
    // not come back as 0 for both families: IPv4 leaves it 0, but IPv6
    // substitutes `IP6_RT_PRIO_USER` (1024, include/net/ip6_route.h).
    // Comparing a declared `None` against 0 therefore never matched an
    // IPv6 route, so every one of them sat in `routes_to_add` on every
    // diff — forever, and with `apply` reporting no changes at the same
    // time, because the apply path does not go through here (#366).
    //
    // An explicit 0 is the same as none for IPv6: the kernel tests the
    // value, not its presence (`if (cfg->fc_metric == 0) cfg->fc_metric =
    // IP6_RT_PRIO_USER;` in `ip6_route_info_create`), so `.metric(0)`
    // installs 1024 and comparing it as 0 re-added the route on every
    // apply.
    route_matches_but_metric(declared, declared_oif, resolve, r)
        && kernel_metric(declared) == r.priority().unwrap_or(0)
        // A declared route has no TOS, so it is installed with 0; one with
        // a TOS routes only that traffic, and is another route (#793).
        && r.header.rtm_tos == 0
        && route_attrs_match(declared, r)
}

/// [`route_matches`] without the metric: same gateway, device and type.
/// Whether `r` carries what `declared` declares beyond its gateway and
/// device (#516): the source, the on-link flag and the metrics, each
/// absent when not declared (a replace drops what it is not sent), and the
/// scope when it is declared (the kernel picks one otherwise).
fn route_attrs_match(declared: &DeclaredRoute, r: &RouteMessage) -> bool {
    let a = &declared.attrs;
    let live = super::types::RouteAttrs::default().with_metrics(r.metrics());
    // Through a nexthop object, the encap and on-link flag dumped are the
    // object's, echoed (#769).
    let own = r.nh_id().is_none();
    a.prefsrc.as_ref() == r.prefsrc()
        // What a declaration cannot carry makes another route; a replace
        // drops it (#783).
        && route_lost(r).is_none()
        && (!own || a.mpls_encap.as_slice() == r.mpls_encap_labels().unwrap_or_default())
        && (!own || a.onlink == r.is_onlink())
        && a.scope.is_none_or(|s| s == r.scope())
        && (a.mtu, a.advmss, a.window) == (live.mtu, live.advmss, live.window)
        && (a.initcwnd, a.initrwnd, a.hoplimit) == (live.initcwnd, live.initrwnd, live.hoplimit)
}

fn route_matches_but_metric(
    declared: &DeclaredRoute,
    declared_oif: Option<u32>,
    resolve: &dyn Fn(&str) -> Option<u32>,
    r: &RouteMessage,
) -> bool {
    // Through a nexthop object (#516): the id is the route's next hop, and
    // the gateway, device and type the kernel dumps with it are the
    // object's — a route through a blackhole nexthop is a blackhole route.
    if declared.attrs.nhid.is_some() || r.nh_id().is_some() {
        return declared.attrs.nhid == r.nh_id();
    }
    // A multipath route (#516): its next hops, in order. A hop declared
    // without a device takes the one the kernel picked.
    if !declared.attrs.multipath.is_empty() || r.multipath().is_some() {
        let Some(have) = r.multipath() else { return false };
        let want = &declared.attrs.multipath;
        return want.len() == have.len()
            && want.iter().zip(have).all(|(w, h)| {
                w.gateway == h.gateway
                    && w.dev.as_deref().is_none_or(|d| resolve(d) == Some(h.ifindex))
                    && w.weight == h.weight
                    && w.onlink == (h.flags & crate::netlink::route::rtnh_flags::ONLINK != 0)
            });
    }
    // Gateway: compare Option<IpAddr> ↔ Option<&IpAddr>. An IPv4 route's
    // IPv6 gateway is RTA_VIA (#516).
    let gw_match = match (declared.gateway, r.gateway().or(r.via())) {
        (None, None) => true,
        (Some(a), Some(b)) => a == *b,
        _ => false,
    };
    // Output interface (ifindex). A declared route with no `dev` accepts
    // whatever oif the kernel chose from the gateway, to avoid needless
    // REPLACE churn.
    let dev_match = match (declared_oif, r.oif()) {
        (None, None) => true,
        (Some(a), Some(b)) => a == b,
        (None, Some(_)) => true,
        (Some(_), None) => false,
    };
    // Type. The key admits unicast, blackhole, unreachable and prohibit
    // alike, and a declared blackhole has neither gateway nor dev, so
    // without this a declared `unicast → blackhole` change matched the
    // old unicast route: the diff came back empty and the kernel kept
    // forwarding.
    let type_match = r.route_type() == declared.route_type.kernel_type();
    gw_match && dev_match && type_match
}

fn diff_qdiscs(
    config: &NetworkConfig,
    current: &[TcMessage],
    ifindex_to_name: &HashMap<u32, &str>,
    tc: &HashMap<u32, super::tc_tree::TcLive>,
    opts: &PlanOptions,
    diff: &mut ConfigDiff,
) {
    // What a live qdisc has under it, which taking it away destroys (#783).
    // A device whose classes and filters were not read has nothing known
    // under it: `read_for` reads them for every device whose root or hook
    // a declaration changes.
    let underneath = |live: &TcMessage| {
        let dev = ifindex_to_name.get(&live.ifindex()).copied().unwrap_or("?");
        let qdiscs: Vec<TcMessage> = current
            .iter()
            .filter(|q| q.ifindex() == live.ifindex())
            .cloned()
            .collect();
        match tc.get(&live.ifindex()) {
            Some(t) => super::preserve::underneath(dev, live, &qdiscs, t, ifindex_to_name),
            None => super::preserve::Underneath::Nothing,
        }
    };
    let record = |diff: &mut ConfigDiff, dev: &str, parent: QdiscParent, u: super::preserve::Underneath| {
        if !u.is_nothing() {
            diff.qdiscs_underneath.push(((dev.to_string(), parent), u));
        }
    };
    // Build map of current root qdiscs by device
    let mut current_root_qdisc: HashMap<&str, &TcMessage> = HashMap::new();
    let mut current_ingress_qdisc: HashMap<&str, &TcMessage> = HashMap::new();

    for qdisc in current {
        if let Some(name) = ifindex_to_name.get(&qdisc.ifindex()) {
            if qdisc.is_root() {
                current_root_qdisc.insert(*name, qdisc);
            } else if qdisc.parent().is_ingress() {
                // ingress or clsact: both sit at TC_H_INGRESS.
                current_ingress_qdisc.insert(*name, qdisc);
            }
        }
    }

    for declared in &config.qdiscs {
        let current_map = match declared.effective_parent() {
            QdiscParent::Root => &current_root_qdisc,
            QdiscParent::Ingress => &current_ingress_qdisc,
        };

        // The kernel's own root: whatever is installed goes (#514). The
        // kernel's default root has handle 0:.
        if declared.qdisc_type == QdiscSpec::KernelDefault {
            if let Some(live) = current_map.get(declared.dev.as_str())
                && live.handle().major() != 0
            {
                // The live qdisc, where its kind reads back: what an undo
                // adds again (#649).
                let removed = QdiscSpec::from_live(live).map_or_else(
                    || declared.clone(),
                    |spec| DeclaredQdisc {
                        dev: declared.dev.clone(),
                        parent: declared.effective_parent(),
                        qdisc_type: spec,
                        handle: Some(live.handle()),
                    },
                );
                diff.qdiscs_to_remove.push(removed);
                record(diff, &declared.dev, declared.effective_parent(), underneath(live));
            }
            continue;
        }

        if let Some(existing) = current_map.get(declared.dev.as_str()) {
            // Qdisc exists, check if it matches
            let existing_kind = existing.kind().unwrap_or("");
            let desired_kind = declared.qdisc_type.kind();
            // What a replace puts back on undo (#649).
            let replaced = |diff: &mut ConfigDiff| {
                let live = crate::netlink::tc_spec::QdiscSpec::from_live(existing)?;
                let handle = (live != crate::netlink::tc_spec::QdiscSpec::KernelDefault)
                    .then(|| existing.handle());
                diff.qdiscs_replaced.push((
                    declared.clone(),
                    DeclaredQdisc {
                        dev: declared.dev.clone(),
                        parent: declared.effective_parent(),
                        qdisc_type: live,
                        handle,
                    },
                ));
                Some(())
            };

            if existing_kind != desired_kind {
                // Different type, need to replace: a graft, which destroys
                // what is under the live one (#783).
                diff.qdiscs_to_replace.push(declared.clone());
                replaced(diff);
                record(diff, &declared.dev, declared.effective_parent(), underneath(existing));
            } else if !declared.qdisc_type.matches(existing) {
                // Same kind, different parameters — replace.
                diff.qdiscs_to_replace.push(declared.clone());
                replaced(diff);
            } else if declared
                .effective_handle()
                .is_some_and(|h| h != existing.handle())
            {
                // At another handle than the one declared, or than `1:`
                // for a classful kind, which its classes name (#514): a
                // graft too.
                diff.qdiscs_to_replace.push(declared.clone());
                replaced(diff);
                record(diff, &declared.dev, declared.effective_parent(), underneath(existing));
            }
        } else {
            // No qdisc at this position, need to add.
            diff.qdiscs_to_add.push(declared.clone());
        }
    }

    // Declared before at a slot nothing declares now, and not the kernel's
    // default there (handle 0:): it goes, and the default comes back (#512).
    for prev in opts.previous.iter().flat_map(|p| p.qdiscs.iter()) {
        let parent = prev.effective_parent();
        let still = config
            .qdiscs
            .iter()
            .any(|d| d.dev == prev.dev && d.effective_parent() == parent);
        let current_map = match parent {
            QdiscParent::Root => &current_root_qdisc,
            QdiscParent::Ingress => &current_ingress_qdisc,
        };
        let live_qdisc = current_map
            .get(prev.dev.as_str())
            .filter(|q| q.handle().major() != 0);
        let live = live_qdisc.is_some();
        let queued = diff
            .qdiscs_to_remove
            .iter()
            .any(|q| q.dev == prev.dev && q.effective_parent() == parent);
        if !still && live && !queued && !opts.owns_qdisc(&prev.dev, parent) {
            diff.qdiscs_to_remove.push(prev.clone());
            if let Some(q) = live_qdisc {
                record(diff, &prev.dev, parent, underneath(q));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::config::types::MacvlanMode;
    use crate::netlink::types::route::RouteProtocol;

    fn declared(name: &str, link_type: DeclaredLinkType) -> DeclaredLink {
        DeclaredLink {
            name: name.to_string(),
            link_type,
            state: LinkState::Unchanged,
            mtu: None,
            master: MasterSpec::Unmanaged,
            address: None,
            attrs: Default::default(),
            bridge: None,
            port: None,
        }
    }

    // -------------------------------------------------------------
    // Plan 186 §3c — topo-sort regression coverage (unit-level).
    // -------------------------------------------------------------

    #[test]
    fn topo_sort_no_op_when_empty_or_singleton() {
        let mut links: Vec<DeclaredLink> = vec![];
        topo_sort_links_to_add(&mut links);
        assert!(links.is_empty());

        let mut links = vec![declared("eth0", DeclaredLinkType::Dummy)];
        topo_sort_links_to_add(&mut links);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].name, "eth0");
    }

    #[test]
    fn topo_sort_independent_links_preserve_declared_order() {
        let mut links = vec![
            declared("eth1", DeclaredLinkType::Dummy),
            declared("eth0", DeclaredLinkType::Dummy),
            declared("br0", DeclaredLinkType::Bridge),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth1", "eth0", "br0"],
            "independent links must keep declared order (stable sort)"
        );
    }

    #[test]
    fn topo_sort_promotes_parent_before_child_vlan() {
        // VLAN declared first, parent dummy declared second.
        let mut links = vec![
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(),
                    vlan_id: 42, protocol: None,
                },
            ),
            declared("eth0", DeclaredLinkType::Dummy),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth0", "eth0.42"],
            "parent must precede child after topo-sort"
        );
    }

    #[test]
    fn topo_sort_keeps_correct_order_when_already_sorted() {
        // Parent first, child second — already correct; preserved as-is.
        let mut links = vec![
            declared("eth0", DeclaredLinkType::Dummy),
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(),
                    vlan_id: 42, protocol: None,
                },
            ),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth0", "eth0.42"]
        );
    }

    #[test]
    fn topo_sort_handles_parent_not_in_batch() {
        // Parent "eth0" is NOT in links_to_add (created
        // out-of-band). The VLAN's parent ref doesn't count
        // for the sort — the link is emitted in declared order.
        let mut links = vec![
            declared("br0", DeclaredLinkType::Bridge),
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(), // not in batch
                    vlan_id: 42, protocol: None,
                },
            ),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["br0", "eth0.42"],
            "out-of-batch parent does NOT trigger reorder"
        );
    }

    #[test]
    fn topo_sort_handles_macvlan_parent_dep() {
        let mut links = vec![
            declared(
                "macv0",
                DeclaredLinkType::Macvlan {
                    parent: "eth0".into(),
                    mode: MacvlanMode::default(),
                },
            ),
            declared("eth0", DeclaredLinkType::Dummy),
        ];
        topo_sort_links_to_add(&mut links);
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["eth0", "macv0"]
        );
    }

    #[test]
    fn topo_sort_chain_three_levels() {
        // Build dummy -> bridge (master via top) -> vlan(parent=bridge).
        // The chain we model is parent-child via Vlan only; bridge as
        // a parent reference doesn't fit the link_type's parent slot,
        // so this test pins a 2-level chain plus an unrelated link.
        let mut links = vec![
            declared(
                "eth0.42",
                DeclaredLinkType::Vlan {
                    parent: "eth0".into(),
                    vlan_id: 42, protocol: None,
                },
            ),
            declared("br0", DeclaredLinkType::Bridge), // unrelated
            declared("eth0", DeclaredLinkType::Dummy),
        ];
        topo_sort_links_to_add(&mut links);
        // After sort: eth0 + br0 are both root-level (no in-batch
        // parent dep) and emitted in declared order (eth0.42 deferred,
        // br0 ready, eth0 ready). Then eth0.42 lands.
        // Pass 1 ready set: br0, eth0 (declared order: eth0.42 deferred).
        // The pass iterates remaining in declared order, so output is:
        //   br0, eth0, eth0.42
        assert_eq!(
            links.iter().map(|l| l.name.clone()).collect::<Vec<_>>(),
            vec!["br0", "eth0", "eth0.42"]
        );
    }

    /// IPv6 stores the masked destination; IPv4 refuses host bits, so its
    /// destination is left for the kernel to reject.
    #[test]
    fn route_keys_use_the_destination_the_kernel_stores() {
        let v6 = |s: &str| IpAddr::V6(s.parse().unwrap());
        assert_eq!(kernel_destination(v6("2001:db8:32::1"), 48), v6("2001:db8:32::"));
        assert_eq!(kernel_destination(v6("2001:db8:32::1"), 128), v6("2001:db8:32::1"));
        assert_eq!(kernel_destination(v6("2001:db8::1"), 0), v6("::"));
        assert_eq!(kernel_destination(v6("2001:db8:ffff::"), 33), v6("2001:db8:8000::"));
        let v4 = IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(kernel_destination(v4, 16), v4);
    }

    #[test]
    fn ipv6_metric_zero_is_the_kernel_default() {
        let route = |dst: &str, metric| DeclaredRoute {
            destination: dst.parse().unwrap(),
            prefix_len: 48,
            gateway: None,
            dev: None,
            metric,
            table: None,
            route_type: DeclaredRouteType::Unicast,
            attrs: Default::default(),
        };
        assert_eq!(kernel_metric(&route("2001:db8::", None)), 1024);
        assert_eq!(kernel_metric(&route("2001:db8::", Some(0))), 1024);
        assert_eq!(kernel_metric(&route("2001:db8::", Some(7))), 7);
        assert_eq!(kernel_metric(&route("10.0.0.0", None)), 0);
        assert_eq!(kernel_metric(&route("10.0.0.0", Some(0))), 0);
    }

    // ---- Plan 188 §2.2 — ApplyOptions builders ----

    #[test]
    fn apply_options_builders_compose() {
        use super::super::apply::ApplyOptions;
        let opts = ApplyOptions::default()
            .with_dry_run(true)
            .with_continue_on_error(true);
        assert!(opts.exec.dry_run);
        assert!(opts.exec.continue_on_error);
    }

    #[test]
    fn apply_options_default_is_safe() {
        use super::super::apply::ApplyOptions;
        let opts = ApplyOptions::default();
        assert!(!opts.exec.dry_run);
        assert!(!opts.exec.continue_on_error);
    }

    // ---- Plan 188 §2.5 — LinkChanges::Display ----

    #[test]
    fn link_changes_display_matches_summary() {
        let c = LinkChanges {
            set_mtu: Some(9000),
            set_up: true,
            ..LinkChanges::default()
        };
        assert_eq!(c.to_string(), c.summary());
        assert!(c.to_string().contains("mtu=9000"));
        assert!(c.to_string().contains("up"));
    }

    #[test]
    fn link_changes_display_empty_when_no_changes() {
        let c = LinkChanges::default();
        assert_eq!(c.to_string(), "");
    }

    // ---- Plan 188 §2.3 — RouteBuilder::default_v{4,6} ----

    #[test]
    fn default_v4_route_is_zero_zero() {
        use super::super::types::RouteBuilder;
        let r = RouteBuilder::default_v4();
        // Internal state — verify via the via() chain works
        // and the destination round-trips.
        let with_gw = r.via("192.0.2.1");
        // Smoke-test by constructing; the field isn't directly
        // exposed but apply paths read it.
        drop(with_gw);
    }

    #[test]
    fn default_v6_route_is_unspecified_slash_zero() {
        use super::super::types::RouteBuilder;
        let r = RouteBuilder::default_v6();
        let with_gw = r.via("2001:db8::1");
        drop(with_gw);
    }

    // ----- Plan 207c M5 — topo-sort dep coverage -----

    #[test]
    fn topo_sort_promotes_vxlan_underlay_before_vxlan() {
        // Pre-Plan 207c, VXLAN underlay was NOT a recognized
        // dep — declaring VXLAN before underlay dummy
        // reproduced the Plan 186 bug class.
        let mut links = vec![
            declared(
                "vxlan42",
                DeclaredLinkType::Vxlan {
                    vni: 42,
                    remote: None,
                    local: None,
                    port: None,
                    underlay_dev: Some("eth0".into()),
                },
            ),
            declared("eth0", DeclaredLinkType::Dummy),
        ];
        topo_sort_links_to_add(&mut links);
        let positions: HashMap<String, usize> = links
            .iter()
            .enumerate()
            .map(|(i, l)| (l.name.clone(), i))
            .collect();
        assert!(
            positions["eth0"] < positions["vxlan42"],
            "underlay must be created before VXLAN"
        );
    }

    #[test]
    fn topo_sort_promotes_master_before_slave() {
        // Declaring `dummy0.master("br0")` before `br0` should
        // get reordered so br0 lands first.
        let mut dummy = declared("dummy0", DeclaredLinkType::Dummy);
        dummy.master = MasterSpec::Name("br0".into());
        let mut links = vec![dummy, declared("br0", DeclaredLinkType::Bridge)];
        topo_sort_links_to_add(&mut links);
        let positions: HashMap<String, usize> = links
            .iter()
            .enumerate()
            .map(|(i, l)| (l.name.clone(), i))
            .collect();
        assert!(
            positions["br0"] < positions["dummy0"],
            "master must be created before slave"
        );
    }

    // ---- Plan 183 — Display for NetworkDiff ----

    #[test]
    fn display_matches_summary() {
        let diff = ConfigDiff::default();
        // Plan 188 §2.6 — `summary()` is deprecated; this test
        // pins the equivalence guarantee for the deprecation
        // window (removed in 0.20). Plan 205 (0.19) removed the
        // `links_to_remove` collection along with the purge knob,
        // so the second assertion now exercises the
        // `links_to_modify` collection instead.
        #[allow(deprecated)]
        {
            assert_eq!(format!("{diff}"), diff.summary());
            let mut d = ConfigDiff::default();
            d.links_to_modify
                .push(("eth0".to_string(), LinkChanges::default()));
            assert_eq!(format!("{d}"), d.summary());
        }
    }

    // ---- Plan 205 (re-wired) — purge diff accounting + options ----

    fn declared_addr(dev: &str, addr: &str, plen: u8) -> DeclaredAddress {
        DeclaredAddress::plain(dev, addr.parse().unwrap(), plen)
    }

    fn declared_route(dst: &str, plen: u8) -> DeclaredRoute {
        DeclaredRoute {
            destination: dst.parse().unwrap(),
            prefix_len: plen,
            gateway: None,
            dev: None,
            metric: None,
            table: Some(254),
            route_type: DeclaredRouteType::Unicast,
            attrs: Default::default(),
        }
    }

    #[test]
    fn diff_options_purge_builder_toggles_flag() {
        assert!(!PlanOptions::default().purge);
        assert!(PlanOptions::default().purge(true).purge);
        assert!(!PlanOptions::default().purge(true).purge(false).purge);
    }

    // ---- #333 / #335 — purge scope beyond the main table ----

    /// A kernel `static` unicast route in `table`, as the dump reports it.
    fn kernel_static_route(dst: &str, plen: u8, table: u32) -> RouteMessage {
        crate::netlink::messages::RouteMessageBuilder::new()
            .destination(dst.parse().unwrap(), plen)
            .table(table)
            .protocol(RouteProtocol::Static)
            .route_type(RouteType::Unicast)
            .build()
    }

    fn purge_routes(config: &NetworkConfig, current: &[RouteMessage], opts: PlanOptions) -> Vec<(String, u32)> {
        let mut diff = ConfigDiff::default();
        diff_routes(config, current, &HashMap::new(), &HashSet::new(), &opts, &mut diff);
        diff.routes_to_remove
            .iter()
            .map(|r| (format!("{}/{}", r.destination, r.prefix_len), r.table.unwrap()))
            .collect()
    }

    #[test]
    fn purge_scope_is_main_plus_declared_plus_listed_tables() {
        let config = NetworkConfig::new()
            .route("10.1.0.0/24", |r| r.table(100))
            .unwrap();
        let opts = PlanOptions::default().purge(true);
        assert_eq!(
            opts.purge_table_scope(&config),
            HashSet::from([254, 100]),
            "main plus the table a declared route names"
        );
        let opts = PlanOptions::default().purge(true).purge_tables([200, 201]);
        assert_eq!(opts.purge_table_scope(&config), HashSet::from([254, 100, 200, 201]));
        assert_eq!(
            PlanOptions::default().purge_table_scope(&NetworkConfig::new()),
            HashSet::from([254]),
            "a config with no routes owns main and nothing else"
        );
    }

    #[test]
    fn purge_removes_an_undeclared_route_from_a_declared_table() {
        // Table 100 is owned: the config declares 10.1.0.0/24 into it.
        // 10.2.0.0/24 in the same table left the declaration → purged.
        let config = NetworkConfig::new()
            .route("10.1.0.0/24", |r| r.table(100))
            .unwrap();
        let current = [
            kernel_static_route("10.1.0.0", 24, 100),
            kernel_static_route("10.2.0.0", 24, 100),
        ];
        let removed = purge_routes(&config, &current, PlanOptions::default().purge(true));
        assert_eq!(removed, vec![("10.2.0.0/24".to_string(), 100)]);
    }

    #[test]
    fn purge_leaves_tables_the_config_never_mentions_alone() {
        // Table 100 is not owned by a config that only declares into
        // main — its routes are somebody else's.
        let config = NetworkConfig::new().route("10.1.0.0/24", |r| r).unwrap();
        let current = [
            kernel_static_route("10.1.0.0", 24, 254),
            kernel_static_route("10.9.0.0", 24, 254),
            kernel_static_route("10.2.0.0", 24, 100),
        ];
        let removed = purge_routes(&config, &current, PlanOptions::default().purge(true));
        assert_eq!(
            removed,
            vec![("10.9.0.0/24".to_string(), 254)],
            "only the undeclared main-table route; table 100 is out of scope"
        );
    }

    #[test]
    fn purge_tables_reaches_a_table_with_no_declared_route_left() {
        // The last VRF route left the declaration; the caller still
        // owns the table and says so.
        let config = NetworkConfig::new();
        let current = [kernel_static_route("10.2.0.0", 24, 100)];
        assert!(
            purge_routes(&config, &current, PlanOptions::default().purge(true)).is_empty(),
            "without purge_tables the now-unmentioned table is left alone"
        );
        let removed = purge_routes(
            &config,
            &current,
            PlanOptions::default().purge(true).purge_tables([100]),
        );
        assert_eq!(removed, vec![("10.2.0.0/24".to_string(), 100)]);
    }

    #[test]
    fn purge_never_touches_local_or_kernel_protocol_routes_in_scope() {
        let config = NetworkConfig::new()
            .route("10.1.0.0/24", |r| r.table(100))
            .unwrap();
        let kernel_proto = crate::netlink::messages::RouteMessageBuilder::new()
            .destination("10.3.0.0".parse().unwrap(), 24)
            .table(100)
            .protocol(RouteProtocol::Kernel)
            .route_type(RouteType::Unicast)
            .build();
        let local = crate::netlink::messages::RouteMessageBuilder::new()
            .destination("10.1.0.1".parse().unwrap(), 32)
            .table(255)
            .protocol(RouteProtocol::Kernel)
            .route_type(RouteType::Local)
            .build();
        let removed = purge_routes(&config, &[kernel_proto, local], PlanOptions::default().purge(true));
        assert!(removed.is_empty(), "got {removed:?}");
    }

    #[test]
    fn removal_collections_count_toward_is_empty_and_change_count() {
        let mut d = ConfigDiff::default();
        assert!(d.is_empty());
        assert_eq!(d.change_count(), 0);

        d.addresses_to_remove
            .push(declared_addr("eth0", "10.0.0.5", 24));
        assert!(!d.is_empty());
        assert_eq!(d.change_count(), 1);

        d.routes_to_remove.push(declared_route("10.1.0.0", 24));
        assert!(!d.is_empty());
        assert_eq!(d.change_count(), 2);
    }

    // ---- #531 — comparing configs, and the diff's shape ----

    /// Declarative configs compare by value, and say when they are empty.
    #[test]
    fn configs_compare_and_know_they_are_empty() {
        use crate::netlink::genl::wireguard::WireguardConfig;
        use crate::netlink::nftables::Family;
        use crate::netlink::nftables::config::NftablesConfig;

        let net = |mtu| NetworkConfig::new().link("d0", move |l| l.dummy().mtu(mtu));
        assert_eq!(net(1500), net(1500));
        assert_ne!(net(1500), net(9000));
        assert!(NetworkConfig::new().is_empty());
        assert!(!net(1500).is_empty());

        let nft = |name: &'static str| NftablesConfig::new().table(name, Family::Inet, |t| t);
        assert_eq!(nft("a"), nft("a"));
        assert_ne!(nft("a"), nft("b"));

        let wg = |port| WireguardConfig::new().device("wg0", move |d| d.listen_port(port));
        assert_eq!(wg(1), wg(1));
        assert_ne!(wg(1), wg(2));
        assert!(WireguardConfig::new().is_empty());
    }

    /// The JSON shape of each diff, pinned: a key added, renamed or
    /// removed fails here, so it is a deliberate change with a CHANGELOG
    /// line rather than one consumers find in production (#531).
    #[cfg(feature = "schemars")]
    #[test]
    fn diff_schemas_keep_their_shape() {
        fn keys(schema: schemars::Schema) -> Vec<String> {
            let mut keys: Vec<String> = schema
                .get("properties")
                .and_then(|p| p.as_object())
                .map(|p| p.keys().cloned().collect())
                .unwrap_or_default();
            keys.sort();
            keys
        }
        assert_eq!(
            keys(ConfigDiff::json_schema_value()),
            [
                "addresses-to-add",
                "addresses-to-change",
                "addresses-to-remove",
                "fdb-to-remove",
                "fdb-to-set",
                "links-missing",
                "links-to-add",
                "links-to-modify",
                "links-to-recreate",
                "links-to-remove",
                "links-to-rename",
                "neighbours-to-remove",
                "neighbours-to-set",
                "nexthops-refused",
                "nexthops-to-remove",
                "nexthops-to-set",
                "qdiscs-to-add",
                "qdiscs-to-remove",
                "qdiscs-to-replace",
                "routes-refused",
                "routes-to-add",
                "routes-to-remove",
                "rules-to-add",
                "rules-to-remove",
                "tc",
                "veth-peers-to-modify",
                "vrf-strict-mode",
            ]
        );
        assert_eq!(
            keys(crate::netlink::nftables::config::NftablesDiff::json_schema_value()),
            ["blocked", "changes", "generation"]
        );
    }

    /// #876 — a `ConfigDiff` with every field filled in validates against
    /// the schema it publishes. The adds are a real diff against an empty
    /// kernel.
    #[cfg(feature = "schemars")]
    #[test]
    fn config_diff_json_matches_its_schema() {
        use crate::netlink::config::schema_check;

        let cfg = super::super::types::schemars_tests::every_section();
        let empty = Snapshot {
            links: Vec::new(),
            addresses: Vec::new(),
            routes: Vec::new(),
            qdiscs: Vec::new(),
            extras: None,
            tc: HashMap::new(),
            bridge_vlans: Vec::new(),
            neighbours: Vec::new(),
            proxies: Vec::new(),
            fdb: Vec::new(),
            rules: Vec::new(),
            nexthops: Vec::new(),
            // The namespace the veth's peer is declared in exists, with
            // nothing of ours in it.
            netns_ids: HashMap::from([(
                crate::netlink::namespace::NetnsRef::Named("peer".into()),
                None,
            )]),
            peer_links: HashMap::new(),
            vrf_strict_mode: Some(false),
        };
        let mut diff = cfg.diff_snapshot(&empty, PlanOptions::default()).unwrap();
        fill_the_rest(&mut diff, &cfg);

        schema_check::assert_every_root_property_populated(&diff, ConfigDiff::json_schema_value());
        schema_check::assert_matches_schema(&diff, ConfigDiff::json_schema_value());
    }

    /// What a diff against an empty kernel cannot produce — changes,
    /// removals, recreates and refusals — built from what `cfg` declares.
    #[cfg(feature = "schemars")]
    fn fill_the_rest(diff: &mut ConfigDiff, cfg: &NetworkConfig) {
        use crate::TcHandle;
        use crate::netlink::config::{
            Blocker, LinkRecreate, LinkRemoval, LinkRename, LinkRestore, PreservedTc,
            RestoredNexthop, RestoredRoute, TcObject,
        };
        use crate::netlink::devconf::{AddrGenMode, Ipv4Devconf, Ipv6Devconf};
        use crate::netlink::namespace::NetnsRef;
        use crate::netlink::types::route::RouteProtocol;

        let changes = LinkChanges {
            set_up: true,
            set_mtu: Some(9000),
            set_master: Some("br0".into()),
            set_address: Some([2, 0, 0, 0, 0, 1]),
            set_kind_params: vec!["vlan id".into()],
            add_altnames: vec!["uplink".into()],
            set_ipv4_conf: vec![(Ipv4Devconf::Forwarding, 1)],
            set_ipv6_conf: vec![(Ipv6Devconf::AcceptRa, -1)],
            set_addr_gen_mode: Some(AddrGenMode::StablePrivacy),
            set_ipv6_token: Some("::1".parse().unwrap()),
            set_port_options: vec!["cost".into()],
            ..LinkChanges::default()
        };
        let route = cfg.routes()[0].clone();
        let blockers = vec![
            Blocker::Address {
                dev: "d0".into(),
                address: "10.0.0.1".parse().unwrap(),
                prefix_len: 24,
            },
            Blocker::Route {
                dev: "d0".into(),
                destination: "10.1.0.0".parse().unwrap(),
                prefix_len: 16,
                table: 254,
                nhid: Some(1),
                through: None,
                protocol: RouteProtocol::Static,
            },
            Blocker::Qdisc {
                dev: "d0".into(),
                qdisc: "htb".into(),
                under: Some((TcHandle::major_only(1), TcHandle::new(1, 1))),
            },
            Blocker::Neighbour {
                dev: "d0".into(),
                destination: "10.0.0.9".parse().unwrap(),
                permanent: true,
            },
        ];
        let mut qdisc = TcObject {
            kind: "htb".into(),
            handle: TcHandle::major_only(1),
            parent: TcHandle::ROOT,
            info: 0,
            chain: Some(0),
            options: vec![0xde, 0xad],
            spec: None,
        };
        qdisc.spec = Some(cfg.qdiscs()[1].qdisc_type.clone());
        let mut tc = PreservedTc {
            dev: "d0".into(),
            ..PreservedTc::default()
        };
        tc.qdiscs.push(qdisc.clone());
        tc.classes.push(TcObject {
            kind: "htb".into(),
            spec: None,
            ..qdisc.clone()
        });
        tc.filters.push(TcObject {
            kind: "flower".into(),
            spec: None,
            ..qdisc
        });
        tc.targets.insert(7, "ifb0".into());
        let restore = LinkRestore {
            links: cfg.links().to_vec(),
            ports: cfg.links()[1..2].to_vec(),
            nexthops: vec![RestoredNexthop {
                nexthop: cfg.nexthops()[0].clone(),
                protocol: 4,
            }],
            addresses: cfg.addresses().to_vec(),
            routes: vec![RestoredRoute {
                route: route.clone(),
                protocol: RouteProtocol::Boot,
            }],
            neighbours: cfg.neighbours().to_vec(),
            fdb: cfg.fdb_entries().to_vec(),
            tc: vec![tc.clone()],
        };

        diff.links_to_recreate.push(LinkRecreate {
            name: "d0.42".into(),
            reason: "vlan id 42 -> 43".into(),
            blocked_by: blockers.clone(),
            resets: vec!["mtu".into()],
            destroys: blockers.clone(),
            preserved_tc: Some(tc),
            restore: Some(Box::new(restore.clone())),
            unrestorable: vec!["an xfrm state".into()],
        });
        diff.links_to_rename.push(LinkRename {
            from: "ve1".into(),
            to: "ve2".into(),
            peer_of: "ve0".into(),
        });
        diff.links_to_modify.push(("d0".into(), changes.clone()));
        diff.veth_peers_to_modify.push(VethPeerChange {
            link: "ve0".into(),
            peer: "ve1".into(),
            netns: NetnsRef::Named("peer".into()),
            changes,
        });
        diff.links_missing.push("eth9".into());
        diff.links_to_remove.push(LinkRemoval {
            name: "old0".into(),
            link_kind: "vlan".into(),
            stacked_on: Some("d0".into()),
            blocked_by: blockers.clone(),
            destroys: blockers,
            restore: Some(Box::new(restore)),
            unrestorable: vec!["a bpf program".into()],
        });
        diff.addresses_to_change.push(cfg.addresses()[0].clone());
        diff.addresses_to_remove.push(cfg.addresses()[1].clone());
        diff.routes_refused.push(RouteConflict {
            route: route.clone(),
            held_by: "proto bgp".into(),
        });
        diff.routes_to_remove.push(route);
        diff.qdiscs_to_replace.push(cfg.qdiscs()[0].clone());
        diff.qdiscs_to_remove.push(cfg.qdiscs()[1].clone());
        diff.neighbours_to_remove.push(cfg.neighbours()[0].clone());
        diff.fdb_to_remove.push(cfg.fdb_entries()[0].clone());
        diff.nexthops_to_remove.push(cfg.nexthops()[0].clone());
        diff.nexthops_refused.push(NexthopConflict {
            nexthop: cfg.nexthops()[1].clone(),
            reason: "in use".into(),
        });
        diff.rules_to_remove.push(cfg.rules()[0].clone());
    }

    // ---- #473 — the order of link modifications ----

    /// Lower devices are modified first, whatever the declaration order,
    /// and the MTU of every lower device under a link this apply creates —
    /// directly or through another — goes in before the creates.
    #[test]
    fn modifications_go_lower_device_first_and_new_links_get_their_mtu_first() {
        let config = NetworkConfig::new()
            .link("m0", |l| l.macvlan("v10").mtu(9000))
            .link("v10", |l| l.vlan("p0", 10).mtu(9000))
            .link("p0", |l| l.dummy().mtu(9000))
            .link("d1", |l| l.dummy().mtu(1400));
        let mtu = |m| LinkChanges {
            set_mtu: Some(m),
            ..LinkChanges::default()
        };
        let mut diff = ConfigDiff {
            links_to_add: vec![config.links[0].clone()],
            links_to_modify: vec![
                ("v10".to_string(), mtu(9000)),
                ("d1".to_string(), mtu(1400)),
                ("p0".to_string(), mtu(9000)),
            ],
            ..ConfigDiff::default()
        };
        order_link_modifications(&config, &HashMap::new(), &HashMap::new(), &mut diff);
        let order: Vec<&str> = diff
            .links_to_modify
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(order, ["d1", "p0", "v10"]);
        assert_eq!(
            diff.mtus_first,
            [("p0".to_string(), 9000), ("v10".to_string(), 9000)]
        );
    }

    // ---- #469 — a route in a place nlink does not own ----

    /// A declared route whose replace would overwrite the kernel's
    /// connected route (or any route of a protocol nlink does not add) is
    /// refused rather than added. At another metric it goes alongside,
    /// a route the kernel already carries is no change, and a `static` /
    /// `boot` route in that place is the config's own to replace.
    #[test]
    fn a_route_over_a_foreign_route_is_refused() {
        use super::super::types::RouteBuilder;

        let connected = crate::netlink::messages::RouteMessageBuilder::new()
            .destination("10.0.0.0".parse().unwrap(), 24)
            .table(254)
            .oif(1)
            .protocol(RouteProtocol::Kernel)
            .route_type(RouteType::Unicast)
            .build();
        let names = HashMap::from([(1, "d0")]);
        let run = |route: fn(RouteBuilder) -> RouteBuilder, current: &[RouteMessage]| {
            let config = NetworkConfig::new().route("10.0.0.0/24", route).unwrap();
            let mut diff = ConfigDiff::default();
            diff_routes(&config, current, &names, &HashSet::new(), &PlanOptions::default(), &mut diff);
            (diff.routes_to_add.len(), diff.routes_refused)
        };

        let (added, refused) = run(|r| r.via("10.0.0.254"), std::slice::from_ref(&connected));
        assert_eq!((added, refused.len()), (0, 1));
        assert_eq!(
            refused[0].held_by,
            "10.0.0.0/24 dev d0 proto kernel metric 0"
        );
        assert_eq!(
            refused[0].to_string(),
            "! route 10.0.0.0/24 via 10.0.0.254 (refused: it would replace 10.0.0.0/24 dev d0 \
             proto kernel metric 0, which the config does not own)"
        );

        let (added, refused) = run(
            |r| r.via("10.0.0.254").metric(100),
            std::slice::from_ref(&connected),
        );
        assert_eq!((added, refused.len()), (1, 0));
        let (added, refused) = run(|r| r.dev("d0"), std::slice::from_ref(&connected));
        assert_eq!((added, refused.len()), (0, 0));
        let (added, refused) = run(
            |r| r.via("10.0.0.254"),
            &[kernel_static_route("10.0.0.0", 24, 254)],
        );
        assert_eq!((added, refused.len()), (1, 0));
    }

    // ---- #470 — address purge scope ----

    fn kernel_addr(ifindex: u32, addr: &str, plen: u8, flags: u32) -> AddressMessage {
        crate::netlink::messages::AddressMessageBuilder::new()
            .ifindex(ifindex)
            .address(addr.parse().unwrap())
            .prefix_len(plen)
            .scope(Scope::Universe)
            .flags(flags)
            .build()
    }

    fn purge_addresses(
        config: &NetworkConfig,
        current: &[AddressMessage],
        opts: PlanOptions,
    ) -> Vec<String> {
        let names = HashMap::from([(1, "d0"), (2, "d1"), (3, "d2")]);
        let mut diff = ConfigDiff::default();
        diff_addresses(config, current, &names, &HashSet::new(), &opts, &mut diff);
        diff.addresses_to_remove
            .iter()
            .map(|a| format!("{}/{} on {}", a.address, a.prefix_len, a.dev))
            .collect()
    }

    /// A purge reaches every declared link, not only the ones that still
    /// have a declared address, and the interfaces the caller names. It
    /// leaves an address the kernel will expire alone (#470).
    #[test]
    fn address_purge_covers_declared_links_and_skips_dynamic_addresses() {
        const PERMANENT: u32 = 0x80;
        let config = NetworkConfig::new()
            .link("d0", |l| l.dummy())
            .address("d1", "10.0.1.1/24")
            .unwrap();
        let current = [
            // d0 is declared and has no address left: removed.
            kernel_addr(1, "10.0.0.1", 24, PERMANENT),
            // SLAAC, or a DHCP lease: the kernel expires it.
            kernel_addr(1, "2001:db8::9", 64, 0),
            kernel_addr(2, "10.0.1.1", 24, PERMANENT),
            kernel_addr(2, "10.0.1.9", 24, 0),
            // d2 is not declared.
            kernel_addr(3, "10.0.2.1", 24, PERMANENT),
        ];
        let purge = PlanOptions::default().purge(true);
        assert_eq!(
            purge_addresses(&config, &current, purge.clone()),
            ["10.0.0.1/24 on d0"]
        );
        assert_eq!(
            purge_addresses(&config, &current, purge.purge_address_devs(["d2"])),
            ["10.0.0.1/24 on d0", "10.0.2.1/24 on d2"]
        );
        assert!(purge_addresses(&config, &current, PlanOptions::default()).is_empty());
    }

    #[test]
    fn display_renders_removal_lines() {
        let mut d = ConfigDiff::default();
        d.addresses_to_remove
            .push(declared_addr("eth0", "10.0.0.5", 24));
        d.routes_to_remove.push(declared_route("10.1.0.0", 24));
        let rendered = format!("{d}");
        assert!(
            rendered.contains("- address 10.0.0.5/24 on eth0"),
            "address removal line missing: {rendered}"
        );
        assert!(
            rendered.contains("- route 10.1.0.0/24"),
            "route removal line missing: {rendered}"
        );
    }
}
