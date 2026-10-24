//! Bridge multicast database (MDB) wire types and constants.
//!
//! Mirrors the kernel's `struct br_port_msg` / `struct br_mdb_entry`
//! and the `MDBA_*` netlink attribute enums (`linux/if_bridge.h`).

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Bridge port message header (`struct br_port_msg`).
///
/// The C struct is `{ __u8 family; __u32 ifindex; }`; the compiler
/// pads `family` out to the `__u32` alignment, so the on-wire size is
/// 8 bytes with `ifindex` at offset 4. The explicit padding field
/// reproduces that layout for zerocopy.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct BrPortMsg {
    /// Address family (always `AF_BRIDGE`).
    pub family: u8,
    /// Padding to align `ifindex`.
    pub pad: [u8; 3],
    /// Bridge interface index (0 in a dump request = all bridges).
    pub ifindex: u32,
}

impl BrPortMsg {
    /// Size of this structure on the wire.
    pub const SIZE: usize = std::mem::size_of::<Self>();

    /// Create a new bridge-port message.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the address family.
    pub fn with_family(mut self, family: u8) -> Self {
        self.family = family;
        self
    }

    /// Set the bridge interface index.
    pub fn with_ifindex(mut self, ifindex: u32) -> Self {
        self.ifindex = ifindex;
        self
    }
}

/// Bridge MDB entry (`struct br_mdb_entry`).
///
/// The kernel struct embeds an anonymous `addr` sub-struct holding a
/// 16-byte union (`ip4` / `ip6` / `mac_addr`) followed by a `__be16
/// proto`. We flatten the union into a fixed 16-byte `addr` field
/// (large enough for an IPv6 group) plus the `proto` discriminator;
/// the trailing 2 bytes of explicit padding reproduce the C struct's
/// 28-byte size.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct BrMdbEntry {
    /// Port interface index this group is programmed on.
    pub ifindex: u32,
    /// Entry state (`MDB_TEMPORARY` / `MDB_PERMANENT`).
    pub state: u8,
    /// Entry flags (`MDB_FLAGS_*`).
    pub flags: u8,
    /// VLAN ID (0 = no VLAN).
    pub vid: u16,
    /// Group address union: IPv4 in the first 4 bytes, IPv6 across
    /// all 16, or a multicast MAC in the first 6.
    pub addr: [u8; 16],
    /// Address protocol (`ETH_P_IP` / `ETH_P_IPV6`, network order;
    /// 0 for an L2 MAC group).
    pub proto: u16,
    /// Padding to the kernel's 28-byte struct size.
    pub _pad: u16,
}

impl BrMdbEntry {
    /// Size of this structure on the wire.
    pub const SIZE: usize = std::mem::size_of::<Self>();
}

// Lock the wire layout to the kernel's struct sizes (if_bridge.h):
// `struct br_port_msg` is 8 bytes (u8 family padded to u32 ifindex),
// `struct br_mdb_entry` is 28 bytes (u32 + u8 + u8 + u16 + 16-byte
// union + __be16 proto + 2 pad).
const _: () = assert!(BrPortMsg::SIZE == 8);
const _: () = assert!(BrMdbEntry::SIZE == 28);

/// Entry state — temporary (ages out).
pub const MDB_TEMPORARY: u8 = 0;
/// Entry state — permanent (static).
pub const MDB_PERMANENT: u8 = 1;

/// Entry flag — programmed in hardware.
pub const MDB_FLAGS_OFFLOAD: u8 = 1 << 0;
/// Entry flag — fast leave.
pub const MDB_FLAGS_FAST_LEAVE: u8 = 1 << 1;
/// Entry flag — (*,G) exclude.
pub const MDB_FLAGS_STAR_EXCL: u8 = 1 << 2;
/// Entry flag — blocked source.
pub const MDB_FLAGS_BLOCKED: u8 = 1 << 3;

/// Top-level MDB attributes (`MDBA_*`).
pub mod mdba {
    /// Nested list of MDB groups.
    pub const MDBA_MDB: u16 = 1;
    /// Nested list of multicast routers.
    pub const MDBA_ROUTER: u16 = 2;
}

/// Attributes nested under `MDBA_MDB` (`MDBA_MDB_*`).
pub mod mdba_mdb {
    /// One group's entry list.
    pub const MDBA_MDB_ENTRY: u16 = 1;
}

/// Attributes nested under `MDBA_MDB_ENTRY` (`MDBA_MDB_ENTRY_*`).
pub mod mdba_mdb_entry {
    /// A `struct br_mdb_entry` payload.
    pub const MDBA_MDB_ENTRY_INFO: u16 = 1;
}

/// Attributes for the add/del request body (`MDBA_SET_ENTRY*`).
pub mod mdba_set {
    /// A `struct br_mdb_entry` to add or delete.
    pub const MDBA_SET_ENTRY: u16 = 1;
}

/// Ethernet protocol numbers used in the `proto` discriminator
/// (network order is applied at encode time).
pub mod eth_p {
    /// IPv4.
    pub const ETH_P_IP: u16 = 0x0800;
    /// IPv6.
    pub const ETH_P_IPV6: u16 = 0x86DD;
}
