//! Socket diagnostics library for Linux.
//!
//! This module provides a strongly-typed, async API for querying socket information
//! via the NETLINK_SOCK_DIAG protocol. It is the foundation for implementing
//! tools like `ss` (socket statistics).
//!
//! # Features
//!
//! - Query TCP, UDP, Unix, and other socket types
//! - Filter by state, port, address, and other criteria
//! - Retrieve detailed socket information (memory, TCP info, etc.)
//! - Async/await support with Tokio
//! - Namespace support via `Connection::new_in(ns)`
//!
//! # Example
//!
//! ```no_run
//! use nlink::netlink::{Connection, SockDiag};
//! use nlink::sockdiag::{SocketFilter, TcpState};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let conn = Connection::<SockDiag>::new()?;
//!
//!     // Query all TCP sockets in LISTEN state
//!     let filter = SocketFilter::tcp()
//!         .states(&[TcpState::Listen])
//!         .build();
//!
//!     let sockets = conn.query(&filter).await?;
//!     for sock in sockets {
//!         println!("{:?}", sock);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Namespace Support
//!
//! Query sockets in other namespaces:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, SockDiag, namespace};
//!
//! // Query sockets in a named namespace
//! let conn: Connection<SockDiag> = Connection::new_in("myns")?;
//! let sockets = conn.query_tcp().await?;
//!
//! // Or by PID
//! let conn: Connection<SockDiag> = Connection::new_in(namespace::NetnsRef::Pid(1234))?;
//! # Ok(())
//! # }
//! ```
//!
//! # Socket Types
//!
//! The library supports querying multiple socket families:
//!
//! - [`InetSocket`] - TCP/UDP over IPv4 and IPv6
//! - [`UnixSocket`] - Unix domain sockets
//! - [`NetlinkSocket`] - Netlink protocol sockets
//! - [`PacketSocket`] - Raw packet sockets
//!
//! Each socket type has its own query method and response structure.
//!
//! # Bandwidth measurement constraints (#171)
//!
//! Polling sock_diag can yield per-socket **TCP goodput** — see
//! [`SocketRateTracker`] — but three constraints are architectural,
//! not implementation gaps:
//!
//! - **TCP only.** `tcp_info` carries cumulative byte counters
//!   (`bytes_acked`/`bytes_received`, and `bytes_sent`/
//!   `bytes_retrans` on 4.19+). **UDP has none**: `udp_diag` reports
//!   only `idiag_rqueue`/`idiag_wqueue`, which are instantaneous
//!   queue depths — never diff them for a rate.
//! - **Goodput ≠ wire throughput.** The TCP counters measure
//!   application payload (no headers, no retransmits); don't compare
//!   them against interface byte counters.
//! - **Short flows are missed.** Sockets opened and closed between
//!   polls are invisible; kernel 6.5+ BPF socket iterators are the
//!   event-driven successor for that.

pub mod bytecode;
pub mod error;
pub mod expr;
pub mod filter;
pub mod procmap;
pub mod rate;
pub mod socket;
pub mod types;

pub use bytecode::{CompiledFilter, compile_filter};
pub use error::{Error, Result};
pub use expr::{Comparison, FilterExpr};
// The builders and `FilterKind` are part of the API's construction path, not
// implementation detail: without them a `SocketFilter` cannot be taken apart
// and `InetFilter` cannot be built at all (#317).
pub use filter::{
    FilterKind, InetFilter, InetFilterBuilder, NetlinkFilter, NetlinkFilterBuilder,
    PacketFilter, PacketFilterBuilder, SocketFilter, UnixFilter, UnixFilterBuilder,
};
pub use procmap::{CgroupPathMap, ProcessRef, SocketOwnerMap};
pub use rate::{SocketRate, SocketRateTracker};
pub use socket::{InetSocket, NetlinkSocket, PacketSocket, SocketInfo, UnixSocket};
pub use types::{
    AddressFamily, BbrInfo, CcInfo, DctcpInfo, DestroyError, DestroyResult, InetExtension,
    Protocol, SocketState, SocketSummary, TcpInfo, TcpState, TcpSummary, UnixShow, VegasInfo,
};
