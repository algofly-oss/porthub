//! Drop a device's traffic without touching its qdiscs (#515).
//!
//! [`Connection::block`] adds a clsact hook to the device, if it has none,
//! and a `matchall` filter with a `gact drop` action on its ingress or
//! egress side, ahead of any other filter there. The device's root qdisc,
//! and the tree under it, stay as they are: a lab that blocks a link to
//! simulate a partition, then heals it, finds its prio, TBF or HTB setup
//! where it left it. Replacing the root with a 100 %-loss netem, the usual
//! way, destroyed that tree.
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::netlink::block::Direction;
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//!
//! conn.block("eth0", Direction::Egress).await?;
//! assert!(conn.is_blocked("eth0", Direction::Egress).await?);
//! conn.unblock("eth0", Direction::Egress).await?;
//! # Ok(())
//! # }
//! ```

use super::{
    action::{ActionList, GactAction},
    connection::Connection,
    error::{Error, Result},
    eth_proto::EthProto,
    filter::MatchallFilter,
    interface_ref::InterfaceRef,
    protocol::Route,
    tc::ClsactConfig,
};
use crate::{FilterPriority, TcHandle};

/// The priority of the blocking filter: 1, ahead of every other filter on
/// the hook, so nothing classifies a packet before it is dropped. A filter
/// of another kind already at priority 1 for every protocol makes
/// [`Connection::block`] fail; the kernel refuses two kinds at one
/// priority and protocol.
pub const BLOCK_PRIORITY: FilterPriority = FilterPriority::new(1);

/// Which way [`Connection::block`] drops traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Direction {
    /// What the device receives.
    Ingress,
    /// What the device sends.
    Egress,
}

impl Direction {
    /// The clsact hook for this direction.
    fn hook(self) -> TcHandle {
        match self {
            Self::Ingress => TcHandle::CLSACT_INGRESS,
            Self::Egress => TcHandle::CLSACT_EGRESS,
        }
    }
}

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Drop everything `dev` receives or sends, without touching its root
    /// qdisc (#515).
    ///
    /// Adds a clsact qdisc if the device has none, and a `matchall` filter
    /// with a `gact drop` action at [`BLOCK_PRIORITY`] on the hook for
    /// `direction`. Blocking a blocked direction does nothing.
    ///
    /// # Errors
    ///
    /// Not supported when the device has a plain `ingress` qdisc, which
    /// has no egress side and which this would have to replace; a kernel
    /// error when something else holds [`BLOCK_PRIORITY`] on the hook.
    pub async fn block(&self, dev: impl Into<InterfaceRef>, direction: Direction) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        if self.blocking_filter(ifindex, direction).await? {
            return Ok(());
        }
        let qdiscs = self.get_qdiscs_by_index(ifindex).await?;
        if qdiscs.iter().any(|q| q.kind() == Some("ingress")) {
            return Err(Error::not_supported(format!(
                "block: ifindex {ifindex} has an ingress qdisc; blocking needs a clsact, which \
                 would replace it and its filters"
            )));
        }
        if !qdiscs.iter().any(|q| q.kind() == Some("clsact")) {
            self.add_qdisc_by_index(ifindex, ClsactConfig::new())
                .await?;
        }
        let filter = MatchallFilter::new().actions(ActionList::new().with(GactAction::drop()));
        self.add_filter_by_index_full(
            ifindex,
            direction.hook(),
            None,
            EthProto::ALL,
            BLOCK_PRIORITY,
            filter,
        )
        .await
        .map_err(|e| e.with_context("block"))
    }

    /// Undo [`block`](Self::block): delete the blocking filter. The clsact
    /// qdisc stays, as do any other filters on it. Unblocking a direction
    /// that is not blocked does nothing.
    pub async fn unblock(&self, dev: impl Into<InterfaceRef>, direction: Direction) -> Result<()> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        if !self.blocking_filter(ifindex, direction).await? {
            return Ok(());
        }
        self.del_filter_by_index(ifindex, direction.hook(), EthProto::ALL, BLOCK_PRIORITY)
            .await
            .map_err(|e| e.with_context("unblock"))
    }

    /// Whether [`block`](Self::block) is in place on `dev` for `direction`.
    pub async fn is_blocked(
        &self,
        dev: impl Into<InterfaceRef>,
        direction: Direction,
    ) -> Result<bool> {
        let ifindex = self.resolve_interface(&dev.into()).await?;
        self.blocking_filter(ifindex, direction).await
    }

    /// Whether the hook holds the blocking filter: a matchall at
    /// [`BLOCK_PRIORITY`] for every protocol.
    async fn blocking_filter(&self, ifindex: u32, direction: Direction) -> Result<bool> {
        let qdiscs = self.get_qdiscs_by_index(ifindex).await?;
        if !qdiscs.iter().any(|q| q.kind() == Some("clsact")) {
            return Ok(false);
        }
        let filters = self.get_filters_by_index(ifindex).await?;
        Ok(filters.iter().any(|f| {
            f.parent() == direction.hook()
                && f.kind() == Some("matchall")
                && f.priority() == BLOCK_PRIORITY
                && f.protocol() == EthProto::ALL
        }))
    }
}
