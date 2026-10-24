//! The [`Bytes`] newtype for byte-count values.
//!
//! Used at TC API boundaries for burst sizes, queue limits, MTU
//! contributions, and other kernel-side byte counts.
//!
//! Decimal-base by default (kb = 1000) matching `tc(8)` defaults; use
//! the `kib`/`mib`/`gib` constructors for binary base.
//!
//! # Example
//!
//! ```
//! use nlink::util::Bytes;
//!
//! let b = Bytes::kib(32);
//! assert_eq!(b.as_u64(), 32 * 1024);
//!
//! // Note: parse() follows tc(8) where "kb" means 1024 bytes (binary).
//! let parsed: Bytes = "32kb".parse().unwrap();
//! assert_eq!(parsed, Bytes::new(32 * 1024));
//! ```

use core::{fmt, str::FromStr};

/// A byte count.
///
/// Stored as `u64`. Use the `kb`/`mb`/`gb` constructors for decimal base
/// or `kib`/`mib`/`gib` for binary base.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Bytes(u64);

impl Bytes {
    pub const ZERO: Self = Self(0);
    pub const MAX: Self = Self(u64::MAX);

    /// Construct from a raw byte count.
    #[inline]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// Decimal kilobytes (1 kb = 1000 bytes).
    #[inline]
    pub const fn kb(n: u64) -> Self {
        Self(n * 1_000)
    }

    /// Decimal megabytes (1 mb = 1_000_000 bytes).
    #[inline]
    pub const fn mb(n: u64) -> Self {
        Self(n * 1_000_000)
    }

    /// Decimal gigabytes.
    #[inline]
    pub const fn gb(n: u64) -> Self {
        Self(n * 1_000_000_000)
    }

    /// Binary kibibytes (1 kib = 1024 bytes).
    #[inline]
    pub const fn kib(n: u64) -> Self {
        Self(n * 1024)
    }

    /// Binary mebibytes (1 mib = 1024² bytes).
    #[inline]
    pub const fn mib(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }

    /// Binary gibibytes.
    #[inline]
    pub const fn gib(n: u64) -> Self {
        Self(n * 1024 * 1024 * 1024)
    }

    /// Parse a tc-style size string (e.g., `"32kb"`, `"1mb"`, `"64k"`).
    ///
    /// Accepted units (case-insensitive):
    /// - bare number, `b` — bytes
    /// - `k`, `kb` — 1024 bytes (matches `tc(8)` convention)
    /// - `m`, `mb` — 1024² bytes
    /// - `g`, `gb` — 1024³ bytes
    /// - `t`, `tb` — 1024⁴ bytes
    /// - `kbit` — 1000 bits / 8 = 125 bytes
    /// - `mbit` — 1_000_000 bits / 8
    /// - `gbit` — 1_000_000_000 bits / 8
    pub fn parse(s: &str) -> Result<Self, BytesParseError> {
        let n = crate::util::parse::get_size(s.trim())
            .map_err(|_| BytesParseError::Invalid(s.to_string()))?;
        Ok(Self(n))
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Saturating conversion to `u32`. Used for kernel TC byte fields
    /// like `burst`/`limit` that are 32-bit.
    #[inline]
    pub fn as_u32_saturating(self) -> u32 {
        self.0.try_into().unwrap_or(u32::MAX)
    }

    #[inline]
    pub const fn saturating_add(self, other: Bytes) -> Bytes {
        Bytes(self.0.saturating_add(other.0))
    }

    #[inline]
    pub const fn saturating_sub(self, other: Bytes) -> Bytes {
        Bytes(self.0.saturating_sub(other.0))
    }

    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::Add for Bytes {
    type Output = Bytes;
    #[inline]
    fn add(self, rhs: Bytes) -> Bytes {
        self.saturating_add(rhs)
    }
}

impl core::ops::Sub for Bytes {
    type Output = Bytes;
    #[inline]
    fn sub(self, rhs: Bytes) -> Bytes {
        self.saturating_sub(rhs)
    }
}

impl core::ops::Mul<u64> for Bytes {
    type Output = Bytes;
    #[inline]
    fn mul(self, rhs: u64) -> Bytes {
        Bytes(self.0.saturating_mul(rhs))
    }
}

/// `Bytes / Duration -> Rate`.
impl core::ops::Div<core::time::Duration> for Bytes {
    type Output = crate::util::Rate;
    #[inline]
    fn div(self, d: core::time::Duration) -> crate::util::Rate {
        let secs = d.as_secs_f64();
        if secs > 0.0 {
            crate::util::Rate::bytes_per_sec((self.0 as f64 / secs) as u64)
        } else {
            crate::util::Rate::ZERO
        }
    }
}

impl core::iter::Sum for Bytes {
    fn sum<I: Iterator<Item = Bytes>>(iter: I) -> Bytes {
        iter.fold(Bytes::ZERO, |acc, b| acc.saturating_add(b))
    }
}

impl<'a> core::iter::Sum<&'a Bytes> for Bytes {
    fn sum<I: Iterator<Item = &'a Bytes>>(iter: I) -> Bytes {
        iter.copied().sum()
    }
}

impl FromStr for Bytes {
    type Err = BytesParseError;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A bare `u64` is interpreted as a byte count (the storage unit),
/// mirroring [`Bytes::new`]. Lossless and unambiguous — unlike
/// [`Rate`](crate::Rate), where bytes-vs-bits ambiguity is the whole
/// reason no bare-integer `From` is offered.
impl From<u64> for Bytes {
    #[inline]
    fn from(n: u64) -> Self {
        Bytes::new(n)
    }
}

/// Extract the byte count. Lossless inverse of [`From<u64>`].
impl From<Bytes> for u64 {
    #[inline]
    fn from(b: Bytes) -> Self {
        b.as_u64()
    }
}

impl fmt::Display for Bytes {
    /// Format as the largest binary unit that represents the count
    /// without loss, otherwise as bare bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        const KIB: u64 = 1024;
        const MIB: u64 = KIB * 1024;
        const GIB: u64 = MIB * 1024;
        if n == 0 {
            return f.write_str("0b");
        }
        if n.is_multiple_of(GIB) {
            write!(f, "{}gib", n / GIB)
        } else if n.is_multiple_of(MIB) {
            write!(f, "{}mib", n / MIB)
        } else if n.is_multiple_of(KIB) {
            write!(f, "{}kib", n / KIB)
        } else {
            write!(f, "{}b", n)
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BytesParseError {
    #[error("invalid size string: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;

    #[test]
    fn bytes_u64_from_round_trips() {
        let b: Bytes = 4096u64.into();
        assert_eq!(b, Bytes::new(4096));
        let n: u64 = b.into();
        assert_eq!(n, 4096);
    }

    #[test]
    fn bytes_construction() {
        assert_eq!(Bytes::new(1000).as_u64(), 1000);
        assert_eq!(Bytes::kb(1).as_u64(), 1000);
        assert_eq!(Bytes::mb(1).as_u64(), 1_000_000);
        assert_eq!(Bytes::kib(1).as_u64(), 1024);
        assert_eq!(Bytes::mib(1).as_u64(), 1024 * 1024);
        assert_eq!(Bytes::gib(1).as_u64(), 1024u64.pow(3));
    }

    #[test]
    fn bytes_parse() {
        // tc convention: k/m/g are binary
        assert_eq!(Bytes::parse("32k").unwrap(), Bytes::new(32 * 1024));
        assert_eq!(Bytes::parse("1m").unwrap(), Bytes::new(1024 * 1024));
        assert_eq!(Bytes::parse("32kb").unwrap(), Bytes::new(32 * 1024));
    }

    #[test]
    fn bytes_parse_rejects_garbage() {
        assert!(Bytes::parse("garbage").is_err());
        assert!(Bytes::parse("").is_err());
    }

    #[test]
    fn bytes_fromstr() {
        let b: Bytes = "32k".parse().unwrap();
        assert_eq!(b, Bytes::new(32 * 1024));
    }

    #[test]
    fn bytes_display_largest_clean_unit() {
        assert_eq!(Bytes::ZERO.to_string(), "0b");
        assert_eq!(Bytes::new(1).to_string(), "1b");
        assert_eq!(Bytes::kib(1).to_string(), "1kib");
        assert_eq!(Bytes::kib(32).to_string(), "32kib");
        assert_eq!(Bytes::mib(1).to_string(), "1mib");
        assert_eq!(Bytes::gib(1).to_string(), "1gib");
        assert_eq!(Bytes::new(1500).to_string(), "1500b");
    }

    #[test]
    fn bytes_arithmetic() {
        assert_eq!(Bytes::kb(1) + Bytes::kb(1), Bytes::kb(2));
        assert_eq!(Bytes::kb(2) - Bytes::kb(1), Bytes::kb(1));
        assert_eq!(Bytes::kb(1) * 3u64, Bytes::kb(3));
        assert_eq!(Bytes::MAX + Bytes::new(1), Bytes::MAX);
        assert_eq!(Bytes::ZERO - Bytes::new(1), Bytes::ZERO);
    }

    #[test]
    fn bytes_div_duration_yields_rate() {
        let r = Bytes::mb(1) / Duration::from_secs(1);
        // 1_000_000 bytes/sec = 8 mbit/sec
        assert_eq!(r, crate::util::Rate::mbit(8));
    }

    #[test]
    fn bytes_sum_iterator() {
        let bs = [Bytes::kb(10), Bytes::kb(20), Bytes::kb(30)];
        let total: Bytes = bs.iter().sum();
        assert_eq!(total, Bytes::kb(60));
    }

    #[test]
    fn bytes_u32_saturating() {
        assert_eq!(Bytes::MAX.as_u32_saturating(), u32::MAX);
        assert_eq!(Bytes::new(1500).as_u32_saturating(), 1500);
    }

    #[test]
    fn bytes_ord() {
        assert!(Bytes::mb(1) > Bytes::kb(999));
        let mut bs = [Bytes::mb(1), Bytes::kb(1), Bytes::gb(1)];
        bs.sort();
        assert_eq!(bs, [Bytes::kb(1), Bytes::mb(1), Bytes::gb(1)]);
    }
}
