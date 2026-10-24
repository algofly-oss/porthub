//! `Connection<Netdev>` helper methods.

use crate::macros::GenlTypedDumpStream;
use crate::netlink::{connection::Connection, error::Result};

use super::Netdev;
use super::messages::{
    NetdevDevGetRequest, NetdevDevReply, NetdevNapiGetRequest, NetdevNapiReply,
    NetdevQstatsGetRequest, NetdevQstatsReply, NetdevQueueGetRequest, NetdevQueueReply,
};
use super::types::{NetdevQueueType, QSTATS_SCOPE_QUEUE};

#[nlink_macros::send_futures]
impl Connection<Netdev> {
    /// The XDP and AF_XDP features of the device `ifindex`.
    pub async fn get_netdev(&self, ifindex: u32) -> Result<NetdevDevReply> {
        self.send_typed(NetdevDevGetRequest {
            ifindex: Some(ifindex),
        })
        .await
    }

    /// Every device's XDP and AF_XDP features.
    pub async fn dump_netdevs(&self) -> Result<GenlTypedDumpStream<'_, Netdev, NetdevDevReply>> {
        self.dump_typed_stream(NetdevDevGetRequest::default()).await
    }

    /// The queue `id` of `queue_type` on `ifindex`.
    pub async fn get_queue(
        &self,
        ifindex: u32,
        queue_type: NetdevQueueType,
        id: u32,
    ) -> Result<NetdevQueueReply> {
        self.send_typed(NetdevQueueGetRequest {
            ifindex: Some(ifindex),
            id: Some(id),
            queue_type: Some(queue_type),
        })
        .await
    }

    /// The RX and TX queues of `ifindex`.
    pub async fn dump_queues(
        &self,
        ifindex: u32,
    ) -> Result<GenlTypedDumpStream<'_, Netdev, NetdevQueueReply>> {
        self.dump_typed_stream(NetdevQueueGetRequest {
            ifindex: Some(ifindex),
            ..Default::default()
        })
        .await
    }

    /// The NAPI instance `id`.
    pub async fn get_napi(&self, id: u32) -> Result<NetdevNapiReply> {
        self.send_typed(NetdevNapiGetRequest {
            id: Some(id),
            ..Default::default()
        })
        .await
    }

    /// The NAPI instances of `ifindex`. A device with none (a veth with
    /// neither GRO nor XDP) has an empty dump.
    pub async fn dump_napis(
        &self,
        ifindex: u32,
    ) -> Result<GenlTypedDumpStream<'_, Netdev, NetdevNapiReply>> {
        self.dump_typed_stream(NetdevNapiGetRequest {
            ifindex: Some(ifindex),
            ..Default::default()
        })
        .await
    }

    /// Queue statistics: of `ifindex`, or of every device that keeps them;
    /// one reply per device, or `per_queue` one per queue. A device whose
    /// driver keeps none (veth, `lo`) is left out of the dump of every
    /// device, and asking for it is `is_not_supported()`.
    pub async fn dump_qstats(
        &self,
        ifindex: Option<u32>,
        per_queue: bool,
    ) -> Result<GenlTypedDumpStream<'_, Netdev, NetdevQstatsReply>> {
        self.dump_typed_stream(NetdevQstatsGetRequest {
            ifindex,
            scope: per_queue.then_some(QSTATS_SCOPE_QUEUE),
        })
        .await
    }
}
