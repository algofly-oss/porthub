//! Strongly-typed netlink message structures.
//!
//! This module provides high-level message types that automatically
//! parse and serialize netlink attributes.
//!
//! # Example
//!
//! ```no_run
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::messages::AddressMessage;
//! use nlink::netlink::parse::FromNetlink;
//!
//! // Parse from raw netlink data — `data` is one message's payload, as
//! // handed out by `MessageIter`.
//! # let data: Vec<u8> = Vec::new();
//! let msg = AddressMessage::from_bytes(&data)?;
//! println!("Address: {:?}", msg.address());
//! println!("Interface: {}", msg.ifindex());
//! # Ok(())
//! # }
//! ```

mod address;
mod link;
mod neighbor;
mod nsid;
mod route;
mod rule;
mod tc;

pub use address::*;
pub use link::*;
pub use neighbor::*;
pub use nsid::*;
pub use route::*;
pub use rule::*;
pub use tc::*;
