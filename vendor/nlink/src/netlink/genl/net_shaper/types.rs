//! `net_shaper` command + attribute + value enums.
//!
//! Direct translation of the kernel UAPI in
//! `include/uapi/linux/net_shaper.h` (kernel 6.13+), expressed
//! via the `nlink-macros` typed-codec derives.
//!
//! The family is a generic-netlink interface to in-kernel TX
//! hardware shapers — per-NIC, per-queue, or per-shaper-group
//! rate-limiting, prioritization, and weighted scheduling. The
//! kernel auto-generates this header from
//! `Documentation/netlink/specs/net_shaper.yaml`; constants here
//! are 1-based throughout.

use crate::macros::{GenlAttribute, GenlCommand, GenlEnum};

// ============================================================
// Commands (NET_SHAPER_CMD_*)
// ============================================================

/// `net_shaper` command codes. Sent in the GENL header's `cmd`
/// byte.
///
/// Wire: `u8` per the kernel UAPI.
#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
#[non_exhaustive]
pub enum NetShaperCmd {
    /// `NET_SHAPER_CMD_GET` — read one shaper (with handle) or
    /// dump all shapers on an interface (without handle).
    Get = 1,
    /// `NET_SHAPER_CMD_SET` — create or modify a shaper's
    /// metric / bandwidth / burst / priority / weight. Admin
    /// permission required.
    Set = 2,
    /// `NET_SHAPER_CMD_DELETE` — remove a shaper. Admin
    /// permission required.
    Delete = 3,
    /// `NET_SHAPER_CMD_GROUP` — atomically create a parent
    /// shaper and reparent existing leaf shapers under it.
    /// Admin permission required.
    Group = 4,
    /// `NET_SHAPER_CMD_CAP_GET` — query which shaper features
    /// the interface supports at a given scope.
    CapGet = 5,
}

// ============================================================
// Top-level attribute set (NET_SHAPER_A_*)
// ============================================================

/// Outer `net_shaper` attribute kinds — used on requests and
/// non-caps replies.
///
/// Wire: `u16` per the kernel UAPI.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum NetShaperAttr {
    /// `NET_SHAPER_A_HANDLE` — nested [`NetShaperHandleAttr`]
    /// group (scope + id) identifying the target shaper.
    Handle = 1,
    /// `NET_SHAPER_A_METRIC` — scheduling metric
    /// ([`NetShaperMetric`]: bits/sec vs packets/sec).
    Metric = 2,
    /// `NET_SHAPER_A_BW_MIN` — guaranteed bandwidth (u64,
    /// units per `metric`).
    BwMin = 3,
    /// `NET_SHAPER_A_BW_MAX` — peak bandwidth (u64,
    /// units per `metric`).
    BwMax = 4,
    /// `NET_SHAPER_A_BURST` — maximum burst size (u64, bytes).
    Burst = 5,
    /// `NET_SHAPER_A_PRIORITY` — scheduling priority (u32).
    Priority = 6,
    /// `NET_SHAPER_A_WEIGHT` — round-robin weight (u32).
    Weight = 7,
    /// `NET_SHAPER_A_IFINDEX` — interface index (u32).
    Ifindex = 8,
    /// `NET_SHAPER_A_PARENT` — nested [`NetShaperHandleAttr`]
    /// group identifying the parent shaper (None if root).
    Parent = 9,
    /// `NET_SHAPER_A_LEAVES` — repeated nested leaf-info groups,
    /// used only by the `group` operation. **Not yet exposed
    /// via the typed Connection API** — the macro stack doesn't
    /// support `Vec<NetlinkAttrs>` yet; the `group` command is
    /// deferred.
    Leaves = 10,
}

// ============================================================
// Handle nested-group attributes (NET_SHAPER_A_HANDLE_*)
// ============================================================

/// Attribute kinds inside a `handle` / `parent` nested block.
///
/// Wire: `u16`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum NetShaperHandleAttr {
    /// `NET_SHAPER_A_HANDLE_SCOPE` — shaper scope
    /// ([`NetShaperScope`]).
    Scope = 1,
    /// `NET_SHAPER_A_HANDLE_ID` — shaper ID within the scope
    /// (u32, max `NET_SHAPER_MAX_HANDLE_ID` = 0x3fffffe).
    Id = 2,
}

// ============================================================
// Capabilities attribute set (NET_SHAPER_A_CAPS_*)
// ============================================================

/// `net_shaper` capabilities attribute kinds — used on the
/// `cap-get` reply only. The `support-*` attributes are flag
/// attributes (no payload); their presence indicates support.
///
/// Wire: `u16`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum NetShaperCapsAttr {
    /// `NET_SHAPER_A_CAPS_IFINDEX` — interface index (u32).
    Ifindex = 1,
    /// `NET_SHAPER_A_CAPS_SCOPE` — scope these caps describe
    /// ([`NetShaperScope`]).
    Scope = 2,
    /// `NET_SHAPER_A_CAPS_SUPPORT_METRIC_BPS` — flag.
    SupportMetricBps = 3,
    /// `NET_SHAPER_A_CAPS_SUPPORT_METRIC_PPS` — flag.
    SupportMetricPps = 4,
    /// `NET_SHAPER_A_CAPS_SUPPORT_NESTING` — flag: can stack
    /// shapers under a parent.
    SupportNesting = 5,
    /// `NET_SHAPER_A_CAPS_SUPPORT_BW_MIN` — flag.
    SupportBwMin = 6,
    /// `NET_SHAPER_A_CAPS_SUPPORT_BW_MAX` — flag.
    SupportBwMax = 7,
    /// `NET_SHAPER_A_CAPS_SUPPORT_BURST` — flag.
    SupportBurst = 8,
    /// `NET_SHAPER_A_CAPS_SUPPORT_PRIORITY` — flag.
    SupportPriority = 9,
    /// `NET_SHAPER_A_CAPS_SUPPORT_WEIGHT` — flag.
    SupportWeight = 10,
}

// ============================================================
// Value enums
// ============================================================

/// `enum net_shaper_scope` — where in the NIC stack a shaper
/// applies.
///
/// Wire: `u32`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum NetShaperScope {
    /// `NET_SHAPER_SCOPE_UNSPEC` — never sent by the kernel;
    /// included for completeness.
    Unspec = 0,
    /// `NET_SHAPER_SCOPE_NETDEV` — shaper acts on the whole
    /// interface (root of the hierarchy).
    Netdev = 1,
    /// `NET_SHAPER_SCOPE_QUEUE` — shaper acts on a single TX
    /// queue (`id` = queue index).
    Queue = 2,
    /// `NET_SHAPER_SCOPE_NODE` — intermediate scheduler node
    /// (used as a `parent` for multiple queue or sub-node
    /// shapers).
    Node = 3,
}

/// `enum net_shaper_metric` — what `bw-min` / `bw-max` measure.
///
/// Wire: `u32`.
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum NetShaperMetric {
    /// `NET_SHAPER_METRIC_BPS` — bits per second.
    Bps = 0,
    /// `NET_SHAPER_METRIC_PPS` — packets per second.
    Pps = 1,
}

/// Maximum value the kernel accepts for a handle's `id` field.
/// Beyond this returns `Error::is_invalid_argument()`.
pub const NET_SHAPER_MAX_HANDLE_ID: u32 = 0x3ff_fffe;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_discriminants_match_uapi() {
        assert_eq!(NetShaperCmd::Get as u8, 1);
        assert_eq!(NetShaperCmd::Set as u8, 2);
        assert_eq!(NetShaperCmd::Delete as u8, 3);
        assert_eq!(NetShaperCmd::Group as u8, 4);
        assert_eq!(NetShaperCmd::CapGet as u8, 5);
    }

    #[test]
    fn attr_discriminants_match_uapi() {
        assert_eq!(NetShaperAttr::Handle as u16, 1);
        assert_eq!(NetShaperAttr::Leaves as u16, 10);
        assert_eq!(NetShaperHandleAttr::Scope as u16, 1);
        assert_eq!(NetShaperHandleAttr::Id as u16, 2);
        assert_eq!(NetShaperCapsAttr::Ifindex as u16, 1);
        assert_eq!(NetShaperCapsAttr::SupportWeight as u16, 10);
    }

    #[test]
    fn scope_and_metric_discriminants_match_uapi() {
        assert_eq!(NetShaperScope::Netdev as u32, 1);
        assert_eq!(NetShaperScope::Node as u32, 3);
        assert_eq!(NetShaperMetric::Bps as u32, 0);
        assert_eq!(NetShaperMetric::Pps as u32, 1);
    }
}
