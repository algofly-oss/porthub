//! Typed request + reply structs for the `net_shaper` family.
//!
//! Mostly `#[derive(GenlMessage)]` from `nlink-macros`. The one
//! exception is [`NetShaperCapsReply`] — the kernel encodes
//! capability flags as zero-payload presence-attrs, which the
//! macros don't yet model, so the parse is hand-written. All
//! emit paths and every other reply ride the derive.

use crate::macros::{GenlMessage, NetlinkAttrs, __rt};
use crate::netlink::attr::{AttrIter, NLA_F_NESTED};
use crate::netlink::MessageBuilder;
use crate::{Error, Result};

use super::types::{
    NetShaperAttr, NetShaperCapsAttr, NetShaperCmd, NetShaperHandleAttr, NetShaperMetric,
    NetShaperScope,
};

/// Emit a [`NetShaperHandle`] as a nested attribute of type `attr`
/// (e.g. `NET_SHAPER_A_HANDLE` or `NET_SHAPER_A_PARENT`). The inner
/// scope/id attrs come from the handle's derived `write_attrs`.
fn emit_handle_nest(b: &mut MessageBuilder, attr: u16, h: &NetShaperHandle) -> Result<()> {
    let nest = b.nest_start(attr | NLA_F_NESTED);
    h.write_attrs(b)?;
    b.nest_end(nest);
    Ok(())
}

// ============================================================
// Nested attribute group: handle (also reused for "parent")
// ============================================================

/// A `handle` / `parent` block — scopes a shaper and identifies
/// it within that scope. Wire shape: nested attribute group
/// (`NLA_F_NESTED`) inside `NET_SHAPER_A_HANDLE` or
/// `NET_SHAPER_A_PARENT`.
#[derive(NetlinkAttrs, Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NetShaperHandle {
    /// Shaper scope ([`NetShaperScope`]).
    #[genl_attr(NetShaperHandleAttr::Scope, repr = "u32")]
    pub scope: Option<NetShaperScope>,
    /// Shaper ID within the scope. For `Netdev` scope this is
    /// always 0; for `Queue` it's the TX queue index; for `Node`
    /// it's an arbitrary kernel-assigned ID.
    #[genl_attr(NetShaperHandleAttr::Id)]
    pub id: Option<u32>,
}

impl NetShaperHandle {
    /// Construct a handle with a fully-specified scope + id.
    pub fn new(scope: NetShaperScope, id: u32) -> Self {
        Self {
            scope: Some(scope),
            id: Some(id),
        }
    }

    /// Handle for the netdev-scope root shaper. The kernel
    /// requires id = 0 at this scope.
    pub const fn netdev() -> Self {
        Self {
            scope: Some(NetShaperScope::Netdev),
            id: Some(0),
        }
    }

    /// Handle for a single TX queue.
    pub fn queue(index: u32) -> Self {
        Self::new(NetShaperScope::Queue, index)
    }

    /// Handle for an intermediate scheduler node (kernel-assigned
    /// ID, returned by the `group` operation).
    pub fn node(id: u32) -> Self {
        Self::new(NetShaperScope::Node, id)
    }
}

// ============================================================
// GET — request + reply
// ============================================================

/// `NET_SHAPER_CMD_GET` request — read a single shaper (when
/// `handle.is_some()`) or dump every shaper on the interface
/// (when `handle.is_none()`).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetShaperCmd::Get)]
pub struct NetShaperGetRequest {
    /// Target interface ifindex.
    #[genl_attr(NetShaperAttr::Ifindex)]
    pub ifindex: u32,
    /// Handle of the shaper to read. `None` = dump all on this
    /// interface.
    #[genl_attr(NetShaperAttr::Handle, nested)]
    pub handle: Option<NetShaperHandle>,
}

impl NetShaperGetRequest {
    /// Single-shaper request by handle.
    pub fn by_handle(ifindex: u32, handle: NetShaperHandle) -> Self {
        Self {
            ifindex,
            handle: Some(handle),
        }
    }

    /// Dump every shaper on the interface.
    pub fn dump(ifindex: u32) -> Self {
        Self {
            ifindex,
            handle: None,
        }
    }
}

/// `NET_SHAPER_CMD_GET` reply — a single shaper's full state.
/// Also the streamed body during a dump.
///
/// Every scheduling field is `Option<T>` because the kernel
/// only emits attributes the driver has actually set; a driver
/// that exposes shapers without per-queue burst caps simply
/// omits the `BURST` attribute.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetShaperCmd::Get)]
#[non_exhaustive]
pub struct NetShaperReply {
    /// Interface ifindex.
    #[genl_attr(NetShaperAttr::Ifindex)]
    pub ifindex: u32,
    /// Handle identifying this shaper.
    #[genl_attr(NetShaperAttr::Handle, nested)]
    pub handle: Option<NetShaperHandle>,
    /// Parent shaper's handle (`None` for the netdev-scope root).
    #[genl_attr(NetShaperAttr::Parent, nested)]
    pub parent: Option<NetShaperHandle>,
    /// Metric used for `bw_min` / `bw_max` (bits/sec vs
    /// packets/sec).
    #[genl_attr(NetShaperAttr::Metric, repr = "u32")]
    pub metric: Option<NetShaperMetric>,
    /// Guaranteed bandwidth in `metric` units.
    #[genl_attr(NetShaperAttr::BwMin)]
    pub bw_min: Option<u64>,
    /// Peak bandwidth in `metric` units.
    #[genl_attr(NetShaperAttr::BwMax)]
    pub bw_max: Option<u64>,
    /// Maximum burst size in bytes.
    #[genl_attr(NetShaperAttr::Burst)]
    pub burst: Option<u64>,
    /// Scheduling priority (driver-specific semantics).
    #[genl_attr(NetShaperAttr::Priority)]
    pub priority: Option<u32>,
    /// Round-robin weight (driver-specific semantics).
    #[genl_attr(NetShaperAttr::Weight)]
    pub weight: Option<u32>,
}

// ============================================================
// SET — request (reply is empty)
// ============================================================

/// `NET_SHAPER_CMD_SET` request — create or modify a shaper.
///
/// Unset fields stay `None` and are omitted from the wire
/// request — the kernel preserves prior values for omitted
/// attributes on an existing shaper, or applies driver defaults
/// when creating one.
///
/// Build with [`Self::new`] + chained setters.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetShaperCmd::Set)]
pub struct NetShaperSetRequest {
    /// Target interface ifindex.
    #[genl_attr(NetShaperAttr::Ifindex)]
    pub ifindex: u32,
    /// Handle of the shaper to set (required).
    #[genl_attr(NetShaperAttr::Handle, nested)]
    pub handle: Option<NetShaperHandle>,
    /// Metric for `bw_min` / `bw_max`.
    #[genl_attr(NetShaperAttr::Metric, repr = "u32")]
    pub metric: Option<NetShaperMetric>,
    /// Guaranteed bandwidth.
    #[genl_attr(NetShaperAttr::BwMin)]
    pub bw_min: Option<u64>,
    /// Peak bandwidth.
    #[genl_attr(NetShaperAttr::BwMax)]
    pub bw_max: Option<u64>,
    /// Maximum burst size in bytes.
    #[genl_attr(NetShaperAttr::Burst)]
    pub burst: Option<u64>,
    /// Scheduling priority.
    #[genl_attr(NetShaperAttr::Priority)]
    pub priority: Option<u32>,
    /// Round-robin weight.
    #[genl_attr(NetShaperAttr::Weight)]
    pub weight: Option<u32>,
}

impl NetShaperSetRequest {
    /// Start a set request for the shaper identified by
    /// `(ifindex, handle)`.
    pub fn new(ifindex: u32, handle: NetShaperHandle) -> Self {
        Self {
            ifindex,
            handle: Some(handle),
            ..Self::default()
        }
    }

    /// Set the scheduling metric (bps vs pps).
    #[must_use]
    pub fn metric(mut self, metric: NetShaperMetric) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Set the guaranteed bandwidth (units = `metric`).
    #[must_use]
    pub fn bw_min(mut self, bw: u64) -> Self {
        self.bw_min = Some(bw);
        self
    }

    /// Set the peak bandwidth (units = `metric`).
    #[must_use]
    pub fn bw_max(mut self, bw: u64) -> Self {
        self.bw_max = Some(bw);
        self
    }

    /// Set the maximum burst size in bytes.
    #[must_use]
    pub fn burst(mut self, bytes: u64) -> Self {
        self.burst = Some(bytes);
        self
    }

    /// Set the scheduling priority.
    #[must_use]
    pub fn priority(mut self, prio: u32) -> Self {
        self.priority = Some(prio);
        self
    }

    /// Set the round-robin weight.
    #[must_use]
    pub fn weight(mut self, weight: u32) -> Self {
        self.weight = Some(weight);
        self
    }
}

// ============================================================
// DELETE — request (reply is empty)
// ============================================================

/// `NET_SHAPER_CMD_DELETE` request — remove a shaper.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetShaperCmd::Delete)]
pub struct NetShaperDeleteRequest {
    /// Target interface ifindex.
    #[genl_attr(NetShaperAttr::Ifindex)]
    pub ifindex: u32,
    /// Handle of the shaper to remove (required).
    #[genl_attr(NetShaperAttr::Handle, nested)]
    pub handle: Option<NetShaperHandle>,
}

impl NetShaperDeleteRequest {
    /// Construct a delete request.
    pub fn new(ifindex: u32, handle: NetShaperHandle) -> Self {
        Self {
            ifindex,
            handle: Some(handle),
        }
    }
}

// ============================================================
// GROUP — request (reply is the node's binding: ifindex + handle)
// ============================================================

/// A leaf shaper to attach under a group node, used in
/// [`NetShaperGroupRequest`].
///
/// On the wire this is a `NET_SHAPER_A_LEAVES` nest carrying a
/// `leaf-info` block. `leaf-info` is `subset-of: net-shaper`, so it
/// reuses the net-shaper attribute IDs — `handle` (nested),
/// `priority`, and `weight`. The leaf's handle must be `Queue` scope.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetShaperLeaf {
    /// The leaf shaper's handle (must be `Queue` scope).
    pub handle: NetShaperHandle,
    /// Optional per-leaf scheduling priority.
    pub priority: Option<u32>,
    /// Optional per-leaf round-robin weight.
    pub weight: Option<u32>,
}

impl NetShaperLeaf {
    /// A leaf identified by its handle.
    pub fn new(handle: NetShaperHandle) -> Self {
        Self {
            handle,
            ..Self::default()
        }
    }

    /// A leaf for the TX queue at `index` (the common case — leaves
    /// must be `Queue` scope).
    pub fn queue(index: u32) -> Self {
        Self::new(NetShaperHandle::queue(index))
    }

    /// Set the leaf's scheduling priority.
    #[must_use]
    pub fn priority(mut self, priority: u32) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set the leaf's round-robin weight.
    #[must_use]
    pub fn weight(mut self, weight: u32) -> Self {
        self.weight = Some(weight);
        self
    }

    /// Emit this leaf as a `NET_SHAPER_A_LEAVES` nest.
    fn write_leaf(&self, b: &mut MessageBuilder) -> Result<()> {
        let nest = b.nest_start(NetShaperAttr::Leaves as u16 | NLA_F_NESTED);
        // leaf-info is subset-of net-shaper → reuse net-shaper IDs.
        emit_handle_nest(b, NetShaperAttr::Handle as u16, &self.handle)?;
        if let Some(p) = self.priority {
            __rt::emit_u32_attr(b, NetShaperAttr::Priority as u16, p);
        }
        if let Some(w) = self.weight {
            __rt::emit_u32_attr(b, NetShaperAttr::Weight as u16, w);
        }
        b.nest_end(nest);
        Ok(())
    }
}

/// `NET_SHAPER_CMD_GROUP` request — create or update a scheduling
/// group: attach the given `leaves` (queue-scope shapers) under a
/// node shaper identified by `handle`.
///
/// Semantics (from the kernel `net_shaper` spec):
/// - The node `handle` must be `Node` or `Netdev` scope; leaves must
///   be `Queue` scope.
/// - For a `Node`-scope node with no `id`, the kernel **creates** a
///   new node and returns its handle; with an `id`, that node must
///   already exist and the leaves are **added** to it (preexisting
///   leaves are retained).
/// - `parent` defaults to the leaves' common parent; specify it
///   explicitly when the leaves don't share one.
/// - Optional node shaping attributes (`metric` / `bw_*` / `burst` /
///   `priority` / `weight`) apply to the node shaper.
/// - Atomic: on failure nothing is applied.
///
/// The reply is the node's full identifier (ifindex + handle), which
/// [`Connection::group_shapers`](crate::netlink::Connection::group_shapers)
/// returns as a [`NetShaperHandle`].
///
/// Hand-written `GenlMessage` (the derive doesn't model the repeated
/// nested `leaves` attribute).
#[derive(Debug, Clone, Default)]
pub struct NetShaperGroupRequest {
    /// Target interface ifindex.
    pub ifindex: u32,
    /// Parent handle for the node (optional — see struct docs).
    pub parent: Option<NetShaperHandle>,
    /// The node handle. `None` or `Node`-scope-without-id requests a
    /// freshly-created node.
    pub handle: Option<NetShaperHandle>,
    /// Node metric (bps vs pps).
    pub metric: Option<NetShaperMetric>,
    /// Node guaranteed bandwidth.
    pub bw_min: Option<u64>,
    /// Node peak bandwidth.
    pub bw_max: Option<u64>,
    /// Node maximum burst (bytes).
    pub burst: Option<u64>,
    /// Node scheduling priority.
    pub priority: Option<u32>,
    /// Node round-robin weight.
    pub weight: Option<u32>,
    /// Leaves to attach under the node.
    pub leaves: Vec<NetShaperLeaf>,
}

impl NetShaperGroupRequest {
    /// Start a group request on `ifindex`. Add leaves with
    /// [`leaf`](Self::leaf) / [`leaves`](Self::leaves) and optionally
    /// pin the node handle with [`node`](Self::node).
    pub fn new(ifindex: u32) -> Self {
        Self {
            ifindex,
            ..Self::default()
        }
    }

    /// Pin the node handle (omit to have the kernel allocate one).
    #[must_use]
    pub fn node(mut self, handle: NetShaperHandle) -> Self {
        self.handle = Some(handle);
        self
    }

    /// Set the node's parent handle.
    #[must_use]
    pub fn parent(mut self, parent: NetShaperHandle) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Set the node metric (bps vs pps).
    #[must_use]
    pub fn metric(mut self, metric: NetShaperMetric) -> Self {
        self.metric = Some(metric);
        self
    }

    /// Set the node guaranteed bandwidth.
    #[must_use]
    pub fn bw_min(mut self, bw: u64) -> Self {
        self.bw_min = Some(bw);
        self
    }

    /// Set the node peak bandwidth.
    #[must_use]
    pub fn bw_max(mut self, bw: u64) -> Self {
        self.bw_max = Some(bw);
        self
    }

    /// Set the node maximum burst (bytes).
    #[must_use]
    pub fn burst(mut self, bytes: u64) -> Self {
        self.burst = Some(bytes);
        self
    }

    /// Set the node scheduling priority.
    #[must_use]
    pub fn priority(mut self, prio: u32) -> Self {
        self.priority = Some(prio);
        self
    }

    /// Set the node round-robin weight.
    #[must_use]
    pub fn weight(mut self, weight: u32) -> Self {
        self.weight = Some(weight);
        self
    }

    /// Add one leaf shaper under the node.
    #[must_use]
    pub fn leaf(mut self, leaf: NetShaperLeaf) -> Self {
        self.leaves.push(leaf);
        self
    }

    /// Add several leaf shapers under the node.
    #[must_use]
    pub fn leaves(mut self, leaves: impl IntoIterator<Item = NetShaperLeaf>) -> Self {
        self.leaves.extend(leaves);
        self
    }
}

impl GenlMessage for NetShaperGroupRequest {
    const CMD: u8 = NetShaperCmd::Group as u8;

    fn to_bytes(&self, b: &mut MessageBuilder) -> Result<()> {
        __rt::emit_u32_attr(b, NetShaperAttr::Ifindex as u16, self.ifindex);
        if let Some(parent) = &self.parent {
            emit_handle_nest(b, NetShaperAttr::Parent as u16, parent)?;
        }
        if let Some(handle) = &self.handle {
            emit_handle_nest(b, NetShaperAttr::Handle as u16, handle)?;
        }
        if let Some(metric) = self.metric {
            __rt::emit_u32_attr(b, NetShaperAttr::Metric as u16, metric as u32);
        }
        if let Some(v) = self.bw_min {
            __rt::emit_u64_attr(b, NetShaperAttr::BwMin as u16, v);
        }
        if let Some(v) = self.bw_max {
            __rt::emit_u64_attr(b, NetShaperAttr::BwMax as u16, v);
        }
        if let Some(v) = self.burst {
            __rt::emit_u64_attr(b, NetShaperAttr::Burst as u16, v);
        }
        if let Some(v) = self.priority {
            __rt::emit_u32_attr(b, NetShaperAttr::Priority as u16, v);
        }
        if let Some(v) = self.weight {
            __rt::emit_u32_attr(b, NetShaperAttr::Weight as u16, v);
        }
        for leaf in &self.leaves {
            leaf.write_leaf(b)?;
        }
        Ok(())
    }

    fn from_bytes(_payload: &[u8]) -> Result<Self> {
        // The group *reply* is a node binding (ifindex + handle),
        // parsed as a NetShaperReply by `group_shapers`. The request
        // type is never received.
        Err(Error::invalid_message(
            "NetShaperGroupRequest is a request type; the group reply is parsed as NetShaperReply"
                ,
        ))
    }
}

// ============================================================
// CAP-GET — request + (hand-written) reply
// ============================================================

/// `NET_SHAPER_CMD_CAP_GET` request — query which shaper
/// features the driver supports at a given scope (`do` form)
/// or every scope (`dump` form, scope omitted).
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetShaperCmd::CapGet)]
pub struct NetShaperCapsGetRequest {
    /// Target interface ifindex.
    #[genl_attr(NetShaperCapsAttr::Ifindex)]
    pub ifindex: u32,
    /// Scope to query. `None` = dump (one reply per
    /// supported scope).
    #[genl_attr(NetShaperCapsAttr::Scope, repr = "u32")]
    pub scope: Option<NetShaperScope>,
}

impl NetShaperCapsGetRequest {
    /// Caps for a single scope.
    pub fn for_scope(ifindex: u32, scope: NetShaperScope) -> Self {
        Self {
            ifindex,
            scope: Some(scope),
        }
    }

    /// Dump caps across every scope the driver exposes.
    pub fn dump(ifindex: u32) -> Self {
        Self {
            ifindex,
            scope: None,
        }
    }
}

/// `NET_SHAPER_CMD_CAP_GET` reply — supported features per
/// `(ifindex, scope)`. The `support_*` bools mirror the
/// `NET_SHAPER_A_CAPS_SUPPORT_*` flag attributes — `true` means
/// the kernel emitted the (zero-payload) flag, `false` means it
/// didn't.
///
/// Hand-implemented `GenlMessage` because the macros don't yet
/// model presence-flag attributes ("flag" in YNL terms).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NetShaperCapsReply {
    /// Interface ifindex.
    pub ifindex: u32,
    /// Scope these caps describe.
    pub scope: Option<NetShaperScope>,
    /// Driver supports bits/sec as a metric.
    pub support_metric_bps: bool,
    /// Driver supports packets/sec as a metric.
    pub support_metric_pps: bool,
    /// Driver supports nesting shapers under a parent.
    pub support_nesting: bool,
    /// Driver supports `bw_min`.
    pub support_bw_min: bool,
    /// Driver supports `bw_max`.
    pub support_bw_max: bool,
    /// Driver supports `burst`.
    pub support_burst: bool,
    /// Driver supports `priority`.
    pub support_priority: bool,
    /// Driver supports `weight`.
    pub support_weight: bool,
}

impl GenlMessage for NetShaperCapsReply {
    const CMD: u8 = NetShaperCmd::CapGet as u8;

    fn to_bytes(&self, _builder: &mut MessageBuilder) -> Result<()> {
        // The reply struct is read-only — the kernel emits it; we
        // never send one. Send-path callers should use
        // `NetShaperCapsGetRequest` instead.
        Err(Error::invalid_message(
            "NetShaperCapsReply is read-only; build a NetShaperCapsGetRequest to query caps",
        ))
    }

    fn from_bytes(payload: &[u8]) -> Result<Self> {
        let mut out = Self::default();
        for (ty, body) in AttrIter::new(payload) {
            if ty == NetShaperCapsAttr::Ifindex as u16 {
                out.ifindex = __rt::parse_u32_attr(body)?;
            } else if ty == NetShaperCapsAttr::Scope as u16 {
                let raw = __rt::parse_u32_attr(body)?;
                out.scope = NetShaperScope::try_from(raw).ok();
            } else if ty == NetShaperCapsAttr::SupportMetricBps as u16 {
                out.support_metric_bps = true;
            } else if ty == NetShaperCapsAttr::SupportMetricPps as u16 {
                out.support_metric_pps = true;
            } else if ty == NetShaperCapsAttr::SupportNesting as u16 {
                out.support_nesting = true;
            } else if ty == NetShaperCapsAttr::SupportBwMin as u16 {
                out.support_bw_min = true;
            } else if ty == NetShaperCapsAttr::SupportBwMax as u16 {
                out.support_bw_max = true;
            } else if ty == NetShaperCapsAttr::SupportBurst as u16 {
                out.support_burst = true;
            } else if ty == NetShaperCapsAttr::SupportPriority as u16 {
                out.support_priority = true;
            } else if ty == NetShaperCapsAttr::SupportWeight as u16 {
                out.support_weight = true;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macros::__rt;

    /// Helper: build a NET_SHAPER attribute payload from a
    /// closure that appends attrs to a builder, then return the
    /// trailing bytes (the post-netlink-header slice that the
    /// `GenlMessage::from_bytes` path receives).
    fn payload(write: impl FnOnce(&mut MessageBuilder)) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        write(&mut b);
        b.as_bytes()[start..].to_vec()
    }

    #[test]
    fn get_request_by_handle_emits_ifindex_and_nested_handle() {
        let req = NetShaperGetRequest::by_handle(3, NetShaperHandle::queue(7));
        let body = payload(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(ty, _)| ty).collect();
        assert!(attrs.contains(&(NetShaperAttr::Ifindex as u16)));
        assert!(attrs.contains(&(NetShaperAttr::Handle as u16)));
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn get_request_dump_emits_only_ifindex() {
        let req = NetShaperGetRequest::dump(2);
        let body = payload(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(ty, _)| ty).collect();
        assert_eq!(attrs, vec![NetShaperAttr::Ifindex as u16]);
    }

    #[test]
    fn set_request_builder_chains_optional_fields() {
        let req = NetShaperSetRequest::new(4, NetShaperHandle::queue(1))
            .metric(NetShaperMetric::Bps)
            .bw_max(1_000_000_000)
            .burst(1 << 16)
            .priority(5);
        let body = payload(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(ty, _)| ty).collect();
        // ifindex + handle + metric + bw_max + burst + priority
        assert_eq!(attrs.len(), 6);
        for required in [
            NetShaperAttr::Ifindex,
            NetShaperAttr::Handle,
            NetShaperAttr::Metric,
            NetShaperAttr::BwMax,
            NetShaperAttr::Burst,
            NetShaperAttr::Priority,
        ] {
            assert!(attrs.contains(&(required as u16)), "missing {required:?}");
        }
        // No unset fields emitted
        assert!(!attrs.contains(&(NetShaperAttr::BwMin as u16)));
        assert!(!attrs.contains(&(NetShaperAttr::Weight as u16)));
    }

    #[test]
    fn delete_request_emits_two_attrs() {
        let req = NetShaperDeleteRequest::new(1, NetShaperHandle::queue(0));
        let body = payload(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(ty, _)| ty).collect();
        assert_eq!(attrs.len(), 2);
    }

    #[test]
    fn caps_reply_parses_flag_presence() {
        // Synthesize a kernel reply: ifindex + scope + 3 of the
        // 8 support flags set.
        let body = payload(|b| {
            __rt::emit_u32_attr(b, NetShaperCapsAttr::Ifindex as u16, 7);
            __rt::emit_u32_attr(
                b,
                NetShaperCapsAttr::Scope as u16,
                NetShaperScope::Queue as u32,
            );
            __rt::emit_flag_attr(b, NetShaperCapsAttr::SupportMetricBps as u16);
            __rt::emit_flag_attr(b, NetShaperCapsAttr::SupportBwMax as u16);
            __rt::emit_flag_attr(b, NetShaperCapsAttr::SupportPriority as u16);
        });
        let reply = NetShaperCapsReply::from_bytes(&body).expect("parse");
        assert_eq!(reply.ifindex, 7);
        assert_eq!(reply.scope, Some(NetShaperScope::Queue));
        assert!(reply.support_metric_bps);
        assert!(!reply.support_metric_pps);
        assert!(reply.support_bw_max);
        assert!(!reply.support_bw_min);
        assert!(reply.support_priority);
        assert!(!reply.support_weight);
        assert!(!reply.support_nesting);
        assert!(!reply.support_burst);
    }

    #[test]
    fn caps_reply_to_bytes_is_read_only() {
        let r = NetShaperCapsReply::default();
        let mut b = MessageBuilder::new(0, 0);
        assert!(r.to_bytes(&mut b).is_err());
    }

    #[test]
    fn handle_helpers_set_expected_scope_and_id() {
        let h = NetShaperHandle::netdev();
        assert_eq!(h.scope, Some(NetShaperScope::Netdev));
        assert_eq!(h.id, Some(0));

        let q = NetShaperHandle::queue(5);
        assert_eq!(q.scope, Some(NetShaperScope::Queue));
        assert_eq!(q.id, Some(5));

        let n = NetShaperHandle::node(42);
        assert_eq!(n.scope, Some(NetShaperScope::Node));
        assert_eq!(n.id, Some(42));
    }

    #[test]
    fn reply_parses_full_state() {
        // Build a nested handle attribute manually.
        let mut handle_payload = MessageBuilder::new(0, 0);
        let h_start = handle_payload.len();
        __rt::emit_u32_attr(
            &mut handle_payload,
            NetShaperHandleAttr::Scope as u16,
            NetShaperScope::Queue as u32,
        );
        __rt::emit_u32_attr(&mut handle_payload, NetShaperHandleAttr::Id as u16, 3);
        let handle_bytes = handle_payload.as_bytes()[h_start..].to_vec();

        let body = payload(|b| {
            __rt::emit_u32_attr(b, NetShaperAttr::Ifindex as u16, 9);
            __rt::emit_bytes_attr(b, NetShaperAttr::Handle as u16, &handle_bytes);
            __rt::emit_u32_attr(
                b,
                NetShaperAttr::Metric as u16,
                NetShaperMetric::Bps as u32,
            );
            __rt::emit_u64_attr(b, NetShaperAttr::BwMax as u16, 5_000_000_000);
            __rt::emit_u32_attr(b, NetShaperAttr::Priority as u16, 1);
        });

        let reply = NetShaperReply::from_bytes(&body).expect("parse");
        assert_eq!(reply.ifindex, 9);
        assert_eq!(
            reply.handle,
            Some(NetShaperHandle::new(NetShaperScope::Queue, 3))
        );
        assert_eq!(reply.parent, None);
        assert_eq!(reply.metric, Some(NetShaperMetric::Bps));
        assert_eq!(reply.bw_max, Some(5_000_000_000));
        assert_eq!(reply.priority, Some(1));
        assert_eq!(reply.weight, None);
    }

    #[test]
    fn leaf_builder_sets_priority_and_weight() {
        let leaf = NetShaperLeaf::queue(3).priority(7).weight(11);
        assert_eq!(leaf.handle, NetShaperHandle::queue(3));
        assert_eq!(leaf.priority, Some(7));
        assert_eq!(leaf.weight, Some(11));
    }

    #[test]
    fn group_request_emits_node_attrs_and_one_leaves_nest_per_leaf() {
        let req = NetShaperGroupRequest::new(9)
            .bw_max(1_000_000_000)
            .metric(NetShaperMetric::Bps)
            .leaf(NetShaperLeaf::queue(0))
            .leaf(NetShaperLeaf::queue(1).priority(2));
        let body = payload(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(ty, _)| ty).collect();

        // ifindex + bw_max + metric + 2 leaves (no node handle pinned).
        assert!(attrs.contains(&(NetShaperAttr::Ifindex as u16)));
        assert!(attrs.contains(&(NetShaperAttr::BwMax as u16)));
        assert!(attrs.contains(&(NetShaperAttr::Metric as u16)));
        assert!(!attrs.contains(&(NetShaperAttr::Handle as u16)));
        let leaves = attrs
            .iter()
            .filter(|&&t| t == NetShaperAttr::Leaves as u16)
            .count();
        assert_eq!(leaves, 2, "one LEAVES nest per leaf");
    }

    #[test]
    fn group_request_leaf_nest_carries_handle_and_scheduling() {
        // A single leaf with priority+weight; decode its LEAVES nest
        // and confirm the leaf-info shape (handle nest reusing the
        // net-shaper IDs, plus priority/weight).
        let req = NetShaperGroupRequest::new(1).leaf(NetShaperLeaf::queue(5).priority(3).weight(9));
        let body = payload(|b| req.to_bytes(b).unwrap());

        let leaf_payload = __rt::attr_iter(&body)
            .find(|(ty, _)| *ty == NetShaperAttr::Leaves as u16)
            .map(|(_, p)| p.to_vec())
            .expect("a LEAVES nest");

        let mut saw_handle = false;
        let mut saw_priority = None;
        let mut saw_weight = None;
        for (ty, p) in __rt::attr_iter(&leaf_payload) {
            if ty == NetShaperAttr::Handle as u16 {
                saw_handle = true;
                // The handle nest itself carries scope + id.
                let inner: Vec<u16> = __rt::attr_iter(p).map(|(t, _)| t).collect();
                assert!(inner.contains(&(NetShaperHandleAttr::Scope as u16)));
                assert!(inner.contains(&(NetShaperHandleAttr::Id as u16)));
            } else if ty == NetShaperAttr::Priority as u16 {
                saw_priority = Some(__rt::parse_u32_attr(p).unwrap());
            } else if ty == NetShaperAttr::Weight as u16 {
                saw_weight = Some(__rt::parse_u32_attr(p).unwrap());
            }
        }
        assert!(saw_handle, "leaf carries a nested handle");
        assert_eq!(saw_priority, Some(3));
        assert_eq!(saw_weight, Some(9));
    }

    #[test]
    fn group_request_pins_node_handle_and_parent_when_set() {
        let req = NetShaperGroupRequest::new(2)
            .node(NetShaperHandle::node(7))
            .parent(NetShaperHandle::netdev())
            .leaf(NetShaperLeaf::queue(0));
        let body = payload(|b| req.to_bytes(b).unwrap());
        let attrs: Vec<u16> = __rt::attr_iter(&body).map(|(ty, _)| ty).collect();
        assert!(attrs.contains(&(NetShaperAttr::Handle as u16)));
        assert!(attrs.contains(&(NetShaperAttr::Parent as u16)));
    }

    #[test]
    fn group_request_from_bytes_is_request_only() {
        assert!(NetShaperGroupRequest::from_bytes(&[]).is_err());
    }
}
