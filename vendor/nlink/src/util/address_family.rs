//! The [`AddressFamily`] newtype for `AF_*` address-family bytes.
//!
//! Used at routing-rule (`rule.rs`) boundaries and adjacent netlink surfaces
//! that speak `AF_*` constants directly. Closes the raw-`u8` family footgun
//! at the type level — `flush_rules(AddressFamily::v4())` cannot be
//! silently mis-called with an unmodelled byte the way the pre-0.21
//! `flush_rules(4_u8)` could.
//!
//! Distinct from [`crate::netlink::nftables::types::Family`] — that type
//! speaks `NFPROTO_*` (NFPROTO_INET=1 has no libc equivalent). Mixing the
//! two is a wire-format error; the asymmetric naming is the cost of keeping
//! both visible in the same crate's public namespace.
//!
//! # Example
//!
//! ```
//! use nlink::util::AddressFamily;
//!
//! let v4 = AddressFamily::v4();
//! assert_eq!(u8::from(v4), 2); // AF_INET
//!
//! let v6 = AddressFamily::v6();
//! assert_eq!(u8::from(v6), 10); // AF_INET6
//!
//! // Parse a raw byte returned from the kernel:
//! assert_eq!(AddressFamily::from_raw(2), AddressFamily::v4());
//! ```

use core::fmt;

/// IP address family newtype wrapping the raw `AF_*` byte.
///
/// Construct via the named constructors (`AddressFamily::v4()`,
/// `AddressFamily::v6()`, …) — they map to the canonical libc
/// `AF_*` constants. `From<AddressFamily> for u8` lifts the byte
/// back out for transport.
///
/// Unrecognised raw bytes round-trip via [`Self::from_raw`] without
/// rejection — the kernel can grow new families and a parser
/// reading historical traffic should not refuse to construct.
/// Use [`Self::is_known`] to discriminate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressFamily(u8);

impl AddressFamily {
    // Canonical libc constants. Verified against `<sys/socket.h>`
    // and `include/uapi/linux/socket.h` (the kernel UAPI values
    // exactly match the libc ones).
    const AF_UNSPEC: u8 = 0;
    const AF_INET: u8 = 2;
    const AF_BRIDGE: u8 = 7;
    const AF_INET6: u8 = 10;
    const AF_PACKET: u8 = 17;
    const AF_MPLS: u8 = 28;

    /// `AF_UNSPEC` (0). The "no filter" form — used by
    /// `get_rules_typed(AddressFamily::unspec())` to dump every
    /// family in one call.
    pub const fn unspec() -> Self {
        Self(Self::AF_UNSPEC)
    }

    /// `AF_INET` (2). IPv4.
    pub const fn v4() -> Self {
        Self(Self::AF_INET)
    }

    /// Alias for [`Self::v4`] matching the user-task naming.
    pub const fn ipv4() -> Self {
        Self::v4()
    }

    /// `AF_INET6` (10). IPv6.
    pub const fn v6() -> Self {
        Self(Self::AF_INET6)
    }

    /// Alias for [`Self::v6`] matching the user-task naming.
    pub const fn ipv6() -> Self {
        Self::v6()
    }

    /// `AF_BRIDGE` (7). Used by FDB / bridge VLAN rules.
    pub const fn bridge() -> Self {
        Self(Self::AF_BRIDGE)
    }

    /// `AF_MPLS` (28).
    pub const fn mpls() -> Self {
        Self(Self::AF_MPLS)
    }

    /// `AF_PACKET` (17). Rare at the rule layer but accepted by
    /// some `RTM_*` dumps.
    pub const fn packet() -> Self {
        Self(Self::AF_PACKET)
    }

    /// Wrap a raw `AF_*` byte without rejection. Use when reading
    /// kernel-supplied bytes whose meaning may not match any of
    /// the modelled constructors yet.
    pub const fn from_raw(raw: u8) -> Self {
        Self(raw)
    }

    /// The wire byte as the kernel sees it.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Returns true if the wrapped byte matches one of the
    /// modelled `AF_*` constants (V4, V6, Bridge, Mpls, Packet,
    /// or Unspec). Useful for "is this a value I recognised, or
    /// did the kernel return something I don't model yet?"
    pub const fn is_known(self) -> bool {
        matches!(
            self.0,
            Self::AF_UNSPEC
                | Self::AF_INET
                | Self::AF_BRIDGE
                | Self::AF_INET6
                | Self::AF_PACKET
                | Self::AF_MPLS
        )
    }
}

impl From<AddressFamily> for u8 {
    fn from(f: AddressFamily) -> u8 {
        f.0
    }
}

impl fmt::Display for AddressFamily {
    /// Format using the canonical AF_* mnemonic when known,
    /// `AF_<raw>` otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Self::AF_UNSPEC => f.write_str("AF_UNSPEC"),
            Self::AF_INET => f.write_str("AF_INET"),
            Self::AF_BRIDGE => f.write_str("AF_BRIDGE"),
            Self::AF_INET6 => f.write_str("AF_INET6"),
            Self::AF_PACKET => f.write_str("AF_PACKET"),
            Self::AF_MPLS => f.write_str("AF_MPLS"),
            other => write!(f, "AF_{}", other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_map_to_canonical_bytes() {
        assert_eq!(u8::from(AddressFamily::unspec()), 0);
        assert_eq!(u8::from(AddressFamily::v4()), 2);
        assert_eq!(u8::from(AddressFamily::bridge()), 7);
        assert_eq!(u8::from(AddressFamily::v6()), 10);
        assert_eq!(u8::from(AddressFamily::packet()), 17);
        assert_eq!(u8::from(AddressFamily::mpls()), 28);
    }

    #[test]
    fn aliases_match_canonical_forms() {
        assert_eq!(AddressFamily::ipv4(), AddressFamily::v4());
        assert_eq!(AddressFamily::ipv6(), AddressFamily::v6());
    }

    #[test]
    fn from_raw_roundtrip() {
        for raw in [0u8, 2, 7, 10, 17, 28, 99, 255] {
            assert_eq!(AddressFamily::from_raw(raw).as_u8(), raw);
        }
    }

    #[test]
    fn is_known_classification() {
        assert!(AddressFamily::v4().is_known());
        assert!(AddressFamily::v6().is_known());
        assert!(AddressFamily::unspec().is_known());
        assert!(!AddressFamily::from_raw(99).is_known());
        assert!(!AddressFamily::from_raw(255).is_known());
    }

    #[test]
    fn display_known_uses_mnemonic() {
        assert_eq!(AddressFamily::v4().to_string(), "AF_INET");
        assert_eq!(AddressFamily::v6().to_string(), "AF_INET6");
    }

    #[test]
    fn display_unknown_falls_back_to_number() {
        assert_eq!(AddressFamily::from_raw(99).to_string(), "AF_99");
    }
}
