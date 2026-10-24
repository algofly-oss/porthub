//! MPTCP (Multipath TCP) endpoint configuration via Generic Netlink.
//!
//! This module provides support for managing MPTCP endpoints, which allow
//! TCP connections to use multiple paths for bandwidth aggregation and failover.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! # let eth1_ifindex: u32 = 3;
//! use nlink::netlink::{Connection, Mptcp};
//! use nlink::netlink::genl::mptcp::{MptcpEndpointBuilder, MptcpLimits};
//!
//! // Create MPTCP connection (async for GENL family resolution)
//! let conn = Connection::<Mptcp>::new_async().await?;
//!
//! // Add endpoint for second interface
//! conn.add_endpoint(
//!     MptcpEndpointBuilder::new("192.168.2.1".parse()?)
//!         .id(1)
//!         .ifindex(eth1_ifindex)   // resolve via a Connection<Route> in the same netns
//!         .subflow()
//!         .signal()
//! ).await?;
//!
//! // Set limits
//! conn.set_limits(
//!     MptcpLimits::new()
//!         .subflows(4)
//!         .add_addr_accepted(4)
//! ).await?;
//!
//! // List endpoints
//! for ep in conn.get_endpoints().await? {
//!     println!("Endpoint {}: {}", ep.id, ep.address);
//! }
//! # Ok(())
//! # }
//! ```

mod connection;
mod types;

pub use types::{
    MptcpAddress, MptcpAnnounceBuilder, MptcpEndpoint, MptcpEndpointBuilder, MptcpFlags,
    MptcpLimits, MptcpSubflowBuilder,
};

/// MPTCP Path Manager Generic Netlink family name.
pub const MPTCP_PM_GENL_NAME: &str = "mptcp_pm";

/// MPTCP Path Manager Generic Netlink version.
pub const MPTCP_PM_GENL_VERSION: u8 = 1;
