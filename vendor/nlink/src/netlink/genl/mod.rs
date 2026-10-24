//! Generic Netlink (GENL) support.
//!
//! This module provides infrastructure for working with Generic Netlink families,
//! which are used by kernel subsystems like WireGuard and MACsec for configuration.
//!
//! Generic Netlink extends the standard netlink protocol with:
//! - Dynamic family ID allocation (resolved via control family)
//! - Family-specific commands and attributes
//! - Multicast group support per family
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │ WireguardConnection / MacsecConnection  │
//! │ (Family-specific high-level API)        │
//! └────────────────┬────────────────────────┘
//!                  │
//! ┌────────────────▼────────────────────────┐
//! │ Connection<Generic>                     │
//! │ (Generic GENL operations, family cache) │
//! └────────────────┬────────────────────────┘
//!                  │
//! ┌────────────────▼────────────────────────┐
//! │ NetlinkSocket (Protocol::Generic)       │
//! └─────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use nlink::netlink::{Connection, Generic};
//!
//! # async fn example() -> nlink::Result<()> {
//! let conn = Connection::<Generic>::new()?;
//!
//! // Resolve a family ID
//! let family = conn.get_family("wireguard").await?;
//! println!("WireGuard family ID: {}", family.id);
//! # Ok(())
//! # }
//! ```

mod connection;
mod header;

pub use connection::FamilyInfo;
pub use header::{GENL_HDRLEN, GenlMsgHdr};

pub mod devlink;
pub mod dpll;
pub mod ethtool;
pub mod hwsim;
pub mod macsec;
pub mod mptcp;
pub mod net_shaper;
pub mod netdev;
pub mod nl80211;
pub mod ovpn;
pub mod wireguard;

// Control family constants (fixed, not dynamically assigned)
pub const GENL_ID_CTRL: u16 = 0x10;

/// Control family commands
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtrlCmd {
    Unspec = 0,
    NewFamily = 1,
    DelFamily = 2,
    GetFamily = 3,
    NewOps = 4,
    DelOps = 5,
    GetOps = 6,
    NewMcastGrp = 7,
    DelMcastGrp = 8,
    GetMcastGrp = 9,
    GetPolicy = 10,
}

/// Control family attributes
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtrlAttr {
    Unspec = 0,
    FamilyId = 1,
    FamilyName = 2,
    Version = 3,
    HdrSize = 4,
    MaxAttr = 5,
    Ops = 6,
    McastGroups = 7,
    Policy = 8,
    OpPolicy = 9,
    Op = 10,
}

/// Control family multicast group attributes
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CtrlAttrMcastGrp {
    Unspec = 0,
    Name = 1,
    Id = 2,
}
