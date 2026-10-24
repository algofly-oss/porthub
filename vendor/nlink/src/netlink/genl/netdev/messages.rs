//! `netdev` requests and replies, `#[derive(GenlMessage)]`.

use crate::macros::GenlMessage;

use super::types::{
    NetdevCmd, NetdevDevAttr, NetdevNapiAttr, NetdevQstatsAttr, NetdevQueueAttr, NetdevQueueType,
    XdpFeatures,
};

/// `NETDEV_CMD_DEV_GET` for one device, or (with no ifindex) a dump of
/// every device.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::DevGet)]
pub struct NetdevDevGetRequest {
    /// The device; `None` for a dump.
    #[genl_attr(NetdevDevAttr::Ifindex)]
    pub ifindex: Option<u32>,
}

/// A device's XDP and AF_XDP features.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::DevGet)]
#[non_exhaustive]
pub struct NetdevDevReply {
    /// The device.
    #[genl_attr(NetdevDevAttr::Ifindex)]
    pub ifindex: Option<u32>,
    /// `NETDEV_XDP_ACT_*` bits; see [`xdp_features`](Self::xdp_features).
    #[genl_attr(NetdevDevAttr::XdpFeatures)]
    pub xdp_features_bits: Option<u64>,
    /// The most fragments an AF_XDP zero-copy frame may span.
    #[genl_attr(NetdevDevAttr::XdpZcMaxSegs)]
    pub xdp_zc_max_segs: Option<u32>,
    /// `NETDEV_XDP_RX_METADATA_*` bits: what an XDP program can read.
    #[genl_attr(NetdevDevAttr::XdpRxMetadataFeatures)]
    pub xdp_rx_metadata_features: Option<u64>,
    /// `NETDEV_XSK_FLAGS_*` bits: AF_XDP TX metadata support.
    #[genl_attr(NetdevDevAttr::XskFeatures)]
    pub xsk_features: Option<u64>,
}

impl NetdevDevReply {
    /// The XDP features, typed.
    pub fn xdp_features(&self) -> XdpFeatures {
        XdpFeatures(self.xdp_features_bits.unwrap_or(0))
    }
}

/// `NETDEV_CMD_QUEUE_GET`: one queue, or with only an ifindex a dump of
/// the device's queues.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::QueueGet)]
pub struct NetdevQueueGetRequest {
    /// The device.
    #[genl_attr(NetdevQueueAttr::Ifindex)]
    pub ifindex: Option<u32>,
    /// The queue's index within its type.
    #[genl_attr(NetdevQueueAttr::Id)]
    pub id: Option<u32>,
    /// RX or TX.
    #[genl_attr(NetdevQueueAttr::Type, repr = "u32")]
    pub queue_type: Option<NetdevQueueType>,
}

/// A device queue.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::QueueGet)]
#[non_exhaustive]
pub struct NetdevQueueReply {
    /// Its index within its type.
    #[genl_attr(NetdevQueueAttr::Id)]
    pub id: Option<u32>,
    /// The device.
    #[genl_attr(NetdevQueueAttr::Ifindex)]
    pub ifindex: Option<u32>,
    /// RX or TX.
    #[genl_attr(NetdevQueueAttr::Type, repr = "u32")]
    pub queue_type: Option<NetdevQueueType>,
    /// The NAPI instance serving it, if any.
    #[genl_attr(NetdevQueueAttr::NapiId)]
    pub napi_id: Option<u32>,
    /// The dmabuf bound to it for devmem TCP, if any.
    #[genl_attr(NetdevQueueAttr::Dmabuf)]
    pub dmabuf: Option<u32>,
}

/// `NETDEV_CMD_NAPI_GET`: one NAPI instance by id, or with only an
/// ifindex a dump of the device's.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::NapiGet)]
pub struct NetdevNapiGetRequest {
    /// The device, for a dump.
    #[genl_attr(NetdevNapiAttr::Ifindex)]
    pub ifindex: Option<u32>,
    /// The NAPI instance.
    #[genl_attr(NetdevNapiAttr::Id)]
    pub id: Option<u32>,
}

/// A NAPI instance.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::NapiGet)]
#[non_exhaustive]
pub struct NetdevNapiReply {
    /// The device.
    #[genl_attr(NetdevNapiAttr::Ifindex)]
    pub ifindex: Option<u32>,
    /// Its id, which `SO_INCOMING_NAPI_ID` reports on a socket.
    #[genl_attr(NetdevNapiAttr::Id)]
    pub id: Option<u32>,
    /// The interrupt it is scheduled from, if any.
    #[genl_attr(NetdevNapiAttr::Irq)]
    pub irq: Option<u32>,
    /// The pid of its kthread, when it runs threaded.
    #[genl_attr(NetdevNapiAttr::Pid)]
    pub pid: Option<u32>,
}

/// `NETDEV_CMD_QSTATS_GET`: a dump of statistics, per device or per queue.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::QstatsGet)]
pub struct NetdevQstatsGetRequest {
    /// One device; `None` for every device.
    #[genl_attr(NetdevQstatsAttr::Ifindex)]
    pub ifindex: Option<u32>,
    /// [`QSTATS_SCOPE_QUEUE`](super::QSTATS_SCOPE_QUEUE) for one reply per
    /// queue; `None` for one per device.
    #[genl_attr(NetdevQstatsAttr::Scope)]
    pub scope: Option<u32>,
}

/// Statistics of a device, or of one of its queues. A driver reports what
/// it counts; what it does not is `None`.
#[derive(GenlMessage, Debug, Default, Clone)]
#[genl_message(cmd = NetdevCmd::QstatsGet)]
#[non_exhaustive]
pub struct NetdevQstatsReply {
    /// The device.
    #[genl_attr(NetdevQstatsAttr::Ifindex)]
    pub ifindex: Option<u32>,
    /// The queue's type, per queue.
    #[genl_attr(NetdevQstatsAttr::QueueType, repr = "u32")]
    pub queue_type: Option<NetdevQueueType>,
    /// The queue's index, per queue.
    #[genl_attr(NetdevQstatsAttr::QueueId)]
    pub queue_id: Option<u32>,
    /// Packets received.
    #[genl_attr(NetdevQstatsAttr::RxPackets)]
    pub rx_packets: Option<u64>,
    /// Bytes received.
    #[genl_attr(NetdevQstatsAttr::RxBytes)]
    pub rx_bytes: Option<u64>,
    /// Packets sent.
    #[genl_attr(NetdevQstatsAttr::TxPackets)]
    pub tx_packets: Option<u64>,
    /// Bytes sent.
    #[genl_attr(NetdevQstatsAttr::TxBytes)]
    pub tx_bytes: Option<u64>,
    /// Receive buffer allocations that failed.
    #[genl_attr(NetdevQstatsAttr::RxAllocFail)]
    pub rx_alloc_fail: Option<u64>,
    /// Packets the device dropped on receive.
    #[genl_attr(NetdevQstatsAttr::RxHwDrops)]
    pub rx_hw_drops: Option<u64>,
    /// Of those, for lack of buffers.
    #[genl_attr(NetdevQstatsAttr::RxHwDropOverruns)]
    pub rx_hw_drop_overruns: Option<u64>,
    /// Packets received with `CHECKSUM_COMPLETE`.
    #[genl_attr(NetdevQstatsAttr::RxCsumComplete)]
    pub rx_csum_complete: Option<u64>,
    /// Packets received with `CHECKSUM_UNNECESSARY`.
    #[genl_attr(NetdevQstatsAttr::RxCsumUnnecessary)]
    pub rx_csum_unnecessary: Option<u64>,
    /// Packets received with no checksum help.
    #[genl_attr(NetdevQstatsAttr::RxCsumNone)]
    pub rx_csum_none: Option<u64>,
    /// Packets received with a bad checksum.
    #[genl_attr(NetdevQstatsAttr::RxCsumBad)]
    pub rx_csum_bad: Option<u64>,
    /// Packets the device dropped on send.
    #[genl_attr(NetdevQstatsAttr::TxHwDrops)]
    pub tx_hw_drops: Option<u64>,
    /// Times the queue was stopped.
    #[genl_attr(NetdevQstatsAttr::TxStop)]
    pub tx_stop: Option<u64>,
    /// Times the queue was woken.
    #[genl_attr(NetdevQstatsAttr::TxWake)]
    pub tx_wake: Option<u64>,
}
