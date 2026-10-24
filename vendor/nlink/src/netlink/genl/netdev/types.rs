//! `netdev` command, attribute and value enums.
//!
//! The kernel UAPI in `include/uapi/linux/netdev.h`, generated from
//! `Documentation/netlink/specs/netdev.yaml` (vendored under
//! `third_party/ynl-specs/`), expressed with the `nlink-macros` derives.

use crate::macros::{GenlAttribute, GenlCommand, GenlEnum};

/// `netdev` command codes (`NETDEV_CMD_*`).
#[derive(GenlCommand, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_command(repr = "u8")]
#[non_exhaustive]
pub enum NetdevCmd {
    /// `NETDEV_CMD_DEV_GET` — a device's XDP and AF_XDP features.
    DevGet = 1,
    /// `NETDEV_CMD_DEV_ADD_NTF`.
    DevAddNtf = 2,
    /// `NETDEV_CMD_DEV_DEL_NTF`.
    DevDelNtf = 3,
    /// `NETDEV_CMD_DEV_CHANGE_NTF`.
    DevChangeNtf = 4,
    /// `NETDEV_CMD_PAGE_POOL_GET`.
    PagePoolGet = 5,
    /// `NETDEV_CMD_PAGE_POOL_ADD_NTF`.
    PagePoolAddNtf = 6,
    /// `NETDEV_CMD_PAGE_POOL_DEL_NTF`.
    PagePoolDelNtf = 7,
    /// `NETDEV_CMD_PAGE_POOL_CHANGE_NTF`.
    PagePoolChangeNtf = 8,
    /// `NETDEV_CMD_PAGE_POOL_STATS_GET`.
    PagePoolStatsGet = 9,
    /// `NETDEV_CMD_QUEUE_GET` — a device's RX and TX queues.
    QueueGet = 10,
    /// `NETDEV_CMD_NAPI_GET` — a device's NAPI instances.
    NapiGet = 11,
    /// `NETDEV_CMD_QSTATS_GET` — per-device or per-queue statistics.
    QstatsGet = 12,
    /// `NETDEV_CMD_BIND_RX`.
    BindRx = 13,
}

/// `NETDEV_A_DEV_*`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum NetdevDevAttr {
    /// `NETDEV_A_DEV_IFINDEX` (u32).
    Ifindex = 1,
    /// `NETDEV_A_DEV_PAD`.
    Pad = 2,
    /// `NETDEV_A_DEV_XDP_FEATURES` — [`XdpFeatures`] (u64).
    XdpFeatures = 3,
    /// `NETDEV_A_DEV_XDP_ZC_MAX_SEGS` (u32).
    XdpZcMaxSegs = 4,
    /// `NETDEV_A_DEV_XDP_RX_METADATA_FEATURES` (u64).
    XdpRxMetadataFeatures = 5,
    /// `NETDEV_A_DEV_XSK_FEATURES` (u64).
    XskFeatures = 6,
}

/// `NETDEV_A_QUEUE_*`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum NetdevQueueAttr {
    /// `NETDEV_A_QUEUE_ID` (u32).
    Id = 1,
    /// `NETDEV_A_QUEUE_IFINDEX` (u32).
    Ifindex = 2,
    /// `NETDEV_A_QUEUE_TYPE` — [`NetdevQueueType`] (u32).
    Type = 3,
    /// `NETDEV_A_QUEUE_NAPI_ID` (u32).
    NapiId = 4,
    /// `NETDEV_A_QUEUE_DMABUF` (u32).
    Dmabuf = 5,
}

/// `NETDEV_A_NAPI_*`.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum NetdevNapiAttr {
    /// `NETDEV_A_NAPI_IFINDEX` (u32).
    Ifindex = 1,
    /// `NETDEV_A_NAPI_ID` (u32).
    Id = 2,
    /// `NETDEV_A_NAPI_IRQ` (u32).
    Irq = 3,
    /// `NETDEV_A_NAPI_PID` — the NAPI kthread's pid, when threaded (u32).
    Pid = 4,
}

/// `NETDEV_A_QSTATS_*`. The counters are `uint`s: 4 bytes on the wire
/// when the value fits, 8 when it does not.
#[derive(GenlAttribute, Debug, Clone, Copy, PartialEq, Eq)]
#[genl_attribute(repr = "u16")]
#[non_exhaustive]
pub enum NetdevQstatsAttr {
    /// `NETDEV_A_QSTATS_IFINDEX` (u32).
    Ifindex = 1,
    /// `NETDEV_A_QSTATS_QUEUE_TYPE` — [`NetdevQueueType`].
    QueueType = 2,
    /// `NETDEV_A_QSTATS_QUEUE_ID` (u32).
    QueueId = 3,
    /// `NETDEV_A_QSTATS_SCOPE` — [`QSTATS_SCOPE_QUEUE`] for per-queue
    /// statistics; absent for the device's totals.
    Scope = 4,
    /// `NETDEV_A_QSTATS_RX_PACKETS`.
    RxPackets = 8,
    /// `NETDEV_A_QSTATS_RX_BYTES`.
    RxBytes = 9,
    /// `NETDEV_A_QSTATS_TX_PACKETS`.
    TxPackets = 10,
    /// `NETDEV_A_QSTATS_TX_BYTES`.
    TxBytes = 11,
    /// `NETDEV_A_QSTATS_RX_ALLOC_FAIL`.
    RxAllocFail = 12,
    /// `NETDEV_A_QSTATS_RX_HW_DROPS`.
    RxHwDrops = 13,
    /// `NETDEV_A_QSTATS_RX_HW_DROP_OVERRUNS`.
    RxHwDropOverruns = 14,
    /// `NETDEV_A_QSTATS_RX_CSUM_COMPLETE`.
    RxCsumComplete = 15,
    /// `NETDEV_A_QSTATS_RX_CSUM_UNNECESSARY`.
    RxCsumUnnecessary = 16,
    /// `NETDEV_A_QSTATS_RX_CSUM_NONE`.
    RxCsumNone = 17,
    /// `NETDEV_A_QSTATS_RX_CSUM_BAD`.
    RxCsumBad = 18,
    /// `NETDEV_A_QSTATS_RX_HW_GRO_PACKETS`.
    RxHwGroPackets = 19,
    /// `NETDEV_A_QSTATS_RX_HW_GRO_BYTES`.
    RxHwGroBytes = 20,
    /// `NETDEV_A_QSTATS_RX_HW_GRO_WIRE_PACKETS`.
    RxHwGroWirePackets = 21,
    /// `NETDEV_A_QSTATS_RX_HW_GRO_WIRE_BYTES`.
    RxHwGroWireBytes = 22,
    /// `NETDEV_A_QSTATS_RX_HW_DROP_RATELIMITS`.
    RxHwDropRatelimits = 23,
    /// `NETDEV_A_QSTATS_TX_HW_DROPS`.
    TxHwDrops = 24,
    /// `NETDEV_A_QSTATS_TX_HW_DROP_ERRORS`.
    TxHwDropErrors = 25,
    /// `NETDEV_A_QSTATS_TX_CSUM_NONE`.
    TxCsumNone = 26,
    /// `NETDEV_A_QSTATS_TX_NEEDS_CSUM`.
    TxNeedsCsum = 27,
    /// `NETDEV_A_QSTATS_TX_HW_GSO_PACKETS`.
    TxHwGsoPackets = 28,
    /// `NETDEV_A_QSTATS_TX_HW_GSO_BYTES`.
    TxHwGsoBytes = 29,
    /// `NETDEV_A_QSTATS_TX_HW_GSO_WIRE_PACKETS`.
    TxHwGsoWirePackets = 30,
    /// `NETDEV_A_QSTATS_TX_HW_GSO_WIRE_BYTES`.
    TxHwGsoWireBytes = 31,
    /// `NETDEV_A_QSTATS_TX_HW_DROP_RATELIMITS`.
    TxHwDropRatelimits = 32,
    /// `NETDEV_A_QSTATS_TX_STOP`.
    TxStop = 33,
    /// `NETDEV_A_QSTATS_TX_WAKE`.
    TxWake = 34,
}

/// `NETDEV_QSTATS_SCOPE_QUEUE`: ask for per-queue statistics.
pub const QSTATS_SCOPE_QUEUE: u32 = 1;

/// A queue's direction (`enum netdev_queue_type`).
#[derive(GenlEnum, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[genl_enum(repr = "u32")]
#[non_exhaustive]
pub enum NetdevQueueType {
    /// `NETDEV_QUEUE_TYPE_RX`.
    Rx = 0,
    /// `NETDEV_QUEUE_TYPE_TX`.
    Tx = 1,
}

/// The XDP actions and features a device supports (`enum netdev_xdp_act`,
/// a bitmask).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct XdpFeatures(pub u64);

impl XdpFeatures {
    /// `NETDEV_XDP_ACT_BASIC`: `XDP_PASS`, `XDP_DROP`, `XDP_ABORTED`,
    /// `XDP_TX`.
    pub const BASIC: u64 = 1;
    /// `NETDEV_XDP_ACT_REDIRECT`.
    pub const REDIRECT: u64 = 2;
    /// `NETDEV_XDP_ACT_NDO_XMIT`: a redirect target.
    pub const NDO_XMIT: u64 = 4;
    /// `NETDEV_XDP_ACT_XSK_ZEROCOPY`.
    pub const XSK_ZEROCOPY: u64 = 8;
    /// `NETDEV_XDP_ACT_HW_OFFLOAD`.
    pub const HW_OFFLOAD: u64 = 16;
    /// `NETDEV_XDP_ACT_RX_SG`: non-linear frames on receive.
    pub const RX_SG: u64 = 32;
    /// `NETDEV_XDP_ACT_NDO_XMIT_SG`: non-linear frames as a redirect
    /// target.
    pub const NDO_XMIT_SG: u64 = 64;

    /// Whether every bit of `bits` is set.
    pub fn contains(self, bits: u64) -> bool {
        self.0 & bits == bits
    }
}
