//! The [`Packets`] newtype for packet counts (#643).
//!
//! Used at TC API boundaries for the limits the kernel counts in packets:
//! a `pfifo`'s or `fq_codel`'s `limit`, `fq`'s `flow_limit`, HTB's direct
//! queue, netem's slot. [`Bytes`](crate::util::Bytes) is its counterpart
//! for the limits counted in bytes, so a byte count cannot be passed where
//! the kernel counts packets, or the other way round.
//!
//! # Example
//!
//! ```
//! use nlink::Packets;
//!
//! let p = Packets::new(1000);
//! assert_eq!(p.as_u32(), 1000);
//! // tc(8) writes a packet limit with a `p`, and reads it with or without.
//! assert_eq!(p.to_string(), "1000p");
//! assert_eq!("1000p".parse::<Packets>().unwrap(), p);
//! assert_eq!("1000".parse::<Packets>().unwrap(), p);
//! ```
//!
//! A byte count is not a packet count: `pfifo` counts packets, so its
//! limit does not take [`Bytes`](crate::util::Bytes),
//!
//! ```compile_fail
//! use nlink::{Bytes, netlink::tc::PfifoConfig};
//! let _ = PfifoConfig::new().limit(Bytes::kib(64));
//! ```
//!
//! and `bfifo` counts bytes, so its limit does not take `Packets`:
//!
//! ```compile_fail
//! use nlink::{Packets, netlink::tc::BfifoConfig};
//! let _ = BfifoConfig::new().limit(Packets::new(64));
//! ```

use core::{fmt, str::FromStr};

/// A packet count.
///
/// Stored as `u32`, the width of every kernel field that holds one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Packets(u32);

impl Packets {
    /// No packets.
    pub const ZERO: Self = Self(0);
    /// The most a kernel field can hold.
    pub const MAX: Self = Self(u32::MAX);

    /// Construct from a count of packets.
    #[inline]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }

    /// The count, as the kernel field takes it.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Parse a tc-style packet count: `"1000"` or `"1000p"`.
    pub fn parse(s: &str) -> Result<Self, PacketsParseError> {
        let t = s.trim();
        let digits = t.strip_suffix('p').unwrap_or(t);
        digits
            .parse::<u32>()
            .map(Self)
            .map_err(|_| PacketsParseError::Invalid(s.to_string()))
    }
}

impl FromStr for Packets {
    type Err = PacketsParseError;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<u32> for Packets {
    #[inline]
    fn from(n: u32) -> Self {
        Self(n)
    }
}

impl From<Packets> for u32 {
    #[inline]
    fn from(p: Packets) -> Self {
        p.0
    }
}

impl fmt::Display for Packets {
    /// As tc(8) writes a packet limit: `1000p`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}p", self.0)
    }
}

/// A string that is not a packet count.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PacketsParseError {
    /// Not a number of packets, with or without a `p`.
    #[error("invalid packet count: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packets_round_trip_through_u32_and_text() {
        let p: Packets = 64u32.into();
        assert_eq!(p, Packets::new(64));
        assert_eq!(u32::from(p), 64);
        for s in ["64", "64p", " 64p "] {
            assert_eq!(s.parse::<Packets>().unwrap(), p, "{s}");
        }
        assert_eq!(p.to_string().parse::<Packets>().unwrap(), p);
    }

    #[test]
    fn what_is_not_a_packet_count_is_refused() {
        for s in ["", "p", "64k", "64kb", "-1", "4294967296", "1.5"] {
            assert!(s.parse::<Packets>().is_err(), "{s}");
        }
    }
}
