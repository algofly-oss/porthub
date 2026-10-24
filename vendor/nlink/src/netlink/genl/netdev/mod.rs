//! `netdev` Generic Netlink family — what a device's datapath can do and
//! how it is laid out (#166).
//!
//! The `netdev` family (kernel 6.3+, grown since) reports per-device
//! facts that rtnetlink does not carry:
//!
//! - **features:** the XDP actions a device supports, its XDP receive
//!   metadata and AF_XDP flags ([`dump_netdevs`], [`get_netdev`]);
//! - **queues:** each RX and TX queue, and the NAPI instance serving it
//!   ([`dump_queues`]);
//! - **NAPI:** each NAPI instance, its interrupt and, when it runs
//!   threaded, its kthread ([`dump_napis`]);
//! - **statistics:** per-device or per-queue counters a driver keeps in
//!   the standard set ([`dump_qstats`]).
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::netlink::Connection;
//! use nlink::netlink::genl::netdev::{Netdev, XdpFeatures};
//! use tokio_stream::StreamExt;
//!
//! let conn = Connection::<Netdev>::new_async().await?;
//! let mut devs = conn.dump_netdevs().await?;
//! while let Some(dev) = devs.next().await {
//!     let dev = dev?;
//!     if dev.xdp_features().contains(XdpFeatures::REDIRECT) {
//!         println!("ifindex {:?} can redirect", dev.ifindex);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Reading is unprivileged. The page-pool and dmabuf-binding commands are
//! not modelled.
//!
//! [`dump_netdevs`]: crate::netlink::Connection::dump_netdevs
//! [`get_netdev`]: crate::netlink::Connection::get_netdev
//! [`dump_queues`]: crate::netlink::Connection::dump_queues
//! [`dump_napis`]: crate::netlink::Connection::dump_napis
//! [`dump_qstats`]: crate::netlink::Connection::dump_qstats

use crate::macros::genl_family;

pub mod connection;
pub mod messages;
pub mod types;

pub use messages::{
    NetdevDevGetRequest, NetdevDevReply, NetdevNapiGetRequest, NetdevNapiReply,
    NetdevQstatsGetRequest, NetdevQstatsReply, NetdevQueueGetRequest, NetdevQueueReply,
};
pub use types::{
    NetdevCmd, NetdevDevAttr, NetdevNapiAttr, NetdevQstatsAttr, NetdevQueueAttr,
    NetdevQueueType, QSTATS_SCOPE_QUEUE, XdpFeatures,
};

/// `netdev` Generic Netlink family marker. Construct with
/// [`Connection::<Netdev>::new_async()`](crate::netlink::Connection):
/// the family id is resolved against the kernel's `netdev` registration.
#[genl_family(name = "netdev", version = 1)]
pub struct Netdev;
