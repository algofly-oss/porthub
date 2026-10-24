//! Rate conversion utilities and the [`Rate`] newtype.
//!
//! This module provides:
//!
//! - The [`Rate`] type — a strongly-typed bandwidth value internally stored
//!   as bytes per second (matching the kernel's `tc_ratespec.rate` semantics).
//!   Use this in new code and at API boundaries.
//! - Free functions for converting between rate units (`mbps_to_bytes`,
//!   `bytes_to_mbps`, etc.) — present for compatibility; prefer `Rate`.
//!
//! # Example
//!
//! ```
//! use nlink::util::Rate;
//!
//! // Rates can be constructed in any unit; storage is always bytes/sec.
//! let r = Rate::mbit(100);
//! assert_eq!(r.as_bytes_per_sec(), 12_500_000);
//! assert_eq!(r.as_bits_per_sec(), 100_000_000);
//!
//! // Round-trip via tc-style strings.
//! let parsed: Rate = "100mbit".parse().unwrap();
//! assert_eq!(parsed, Rate::mbit(100));
//! ```

/// Convert kilobits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::kbps_to_bytes;
///
/// assert_eq!(kbps_to_bytes(1000), 125_000); // 1 Mbps
/// assert_eq!(kbps_to_bytes(100), 12_500);   // 100 Kbps
/// ```
#[inline]
pub const fn kbps_to_bytes(kbps: u64) -> u64 {
    kbps * 1000 / 8
}

/// Convert megabits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::mbps_to_bytes;
///
/// assert_eq!(mbps_to_bytes(1), 125_000);       // 1 Mbps
/// assert_eq!(mbps_to_bytes(100), 12_500_000);  // 100 Mbps
/// assert_eq!(mbps_to_bytes(1000), 125_000_000); // 1 Gbps
/// ```
#[inline]
pub const fn mbps_to_bytes(mbps: u64) -> u64 {
    mbps * 1_000_000 / 8
}

/// Convert gigabits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::gbps_to_bytes;
///
/// assert_eq!(gbps_to_bytes(1), 125_000_000);      // 1 Gbps
/// assert_eq!(gbps_to_bytes(10), 1_250_000_000);   // 10 Gbps
/// assert_eq!(gbps_to_bytes(100), 12_500_000_000); // 100 Gbps
/// ```
#[inline]
pub const fn gbps_to_bytes(gbps: u64) -> u64 {
    gbps * 1_000_000_000 / 8
}

/// Convert bytes per second to kilobits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_kbps;
///
/// assert_eq!(bytes_to_kbps(125_000), 1000); // 1 Mbps = 1000 Kbps
/// assert_eq!(bytes_to_kbps(12_500), 100);   // 100 Kbps
/// ```
#[inline]
pub const fn bytes_to_kbps(bps: u64) -> u64 {
    bps * 8 / 1000
}

/// Convert bytes per second to megabits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_mbps;
///
/// assert_eq!(bytes_to_mbps(125_000), 1);        // 1 Mbps
/// assert_eq!(bytes_to_mbps(12_500_000), 100);   // 100 Mbps
/// assert_eq!(bytes_to_mbps(125_000_000), 1000); // 1 Gbps
/// ```
#[inline]
pub const fn bytes_to_mbps(bps: u64) -> u64 {
    bps * 8 / 1_000_000
}

/// Convert bytes per second to gigabits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_gbps;
///
/// assert_eq!(bytes_to_gbps(125_000_000), 1);       // 1 Gbps
/// assert_eq!(bytes_to_gbps(1_250_000_000), 10);    // 10 Gbps
/// assert_eq!(bytes_to_gbps(12_500_000_000), 100);  // 100 Gbps
/// ```
#[inline]
pub const fn bytes_to_gbps(bps: u64) -> u64 {
    bps * 8 / 1_000_000_000
}

/// Convert bits per second to bytes per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bits_to_bytes;
///
/// assert_eq!(bits_to_bytes(1_000_000), 125_000); // 1 Mbps
/// assert_eq!(bits_to_bytes(8), 1);               // 8 bps = 1 Bps
/// ```
#[inline]
pub const fn bits_to_bytes(bps: u64) -> u64 {
    bps / 8
}

/// Convert bytes per second to bits per second.
///
/// # Example
///
/// ```
/// use nlink::util::rate::bytes_to_bits;
///
/// assert_eq!(bytes_to_bits(125_000), 1_000_000); // 1 Mbps
/// assert_eq!(bytes_to_bits(1), 8);               // 1 Bps = 8 bps
/// ```
#[inline]
pub const fn bytes_to_bits(bps: u64) -> u64 {
    bps * 8
}

// ============================================================================
// Rate newtype
// ============================================================================

use core::{fmt, str::FromStr, time::Duration};

/// A bandwidth rate.
///
/// Stored internally as **bytes per second** to match the kernel's
/// `tc_ratespec.rate` semantics. Construction methods take values in
/// whatever unit is convenient; accessors return either bytes or bits
/// per second, explicitly named.
///
/// # Example
///
/// ```
/// use nlink::util::Rate;
///
/// let r = Rate::mbit(100);
/// assert_eq!(r.as_bytes_per_sec(), 12_500_000);
///
/// // Construct from the unit you have:
/// assert_eq!(Rate::bytes_per_sec(12_500_000), Rate::mbit(100));
/// assert_eq!(Rate::bits_per_sec(100_000_000), Rate::mbit(100));
///
/// // Parse tc-style strings:
/// let parsed: Rate = "100mbit".parse().unwrap();
/// assert_eq!(parsed, Rate::mbit(100));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Rate(u64);

impl Rate {
    /// Zero — no bandwidth.
    pub const ZERO: Self = Self(0);

    /// Maximum representable rate.
    pub const MAX: Self = Self(u64::MAX);

    /// Construct from bytes per second.
    #[inline]
    pub const fn bytes_per_sec(bps: u64) -> Self {
        Self(bps)
    }

    /// Construct from bits per second. Truncates fractional bytes.
    #[inline]
    pub const fn bits_per_sec(bits_per_sec: u64) -> Self {
        Self(bits_per_sec / 8)
    }

    /// Construct from kilobits per second (1 kbit = 1000 bits).
    #[inline]
    pub const fn kbit(n: u64) -> Self {
        Self(n * 1_000 / 8)
    }

    /// Construct from megabits per second (1 mbit = 1_000_000 bits).
    #[inline]
    pub const fn mbit(n: u64) -> Self {
        Self(n * 1_000_000 / 8)
    }

    /// Construct from gigabits per second (1 gbit = 1_000_000_000 bits).
    #[inline]
    pub const fn gbit(n: u64) -> Self {
        Self(n * 1_000_000_000 / 8)
    }

    /// Construct from kibibits per second (1 kibit = 1024 bits).
    #[inline]
    pub const fn kibit(n: u64) -> Self {
        Self(n * 1024 / 8)
    }

    /// Construct from mebibits per second (1 mibit = 1024² bits).
    #[inline]
    pub const fn mibit(n: u64) -> Self {
        Self(n * 1024 * 1024 / 8)
    }

    /// Construct from gibibits per second (1 gibit = 1024³ bits).
    #[inline]
    pub const fn gibit(n: u64) -> Self {
        Self(n * 1024 * 1024 * 1024 / 8)
    }

    /// Construct from kibibytes per second.
    #[inline]
    pub const fn kib_per_sec(n: u64) -> Self {
        Self(n * 1024)
    }

    /// Construct from mebibytes per second.
    #[inline]
    pub const fn mib_per_sec(n: u64) -> Self {
        Self(n * 1024 * 1024)
    }

    /// Parse a tc-style rate string (e.g., `"100mbit"`, `"1gbit"`,
    /// `"500kbit"`, `"1.5gibit"`, `"100"` for bare bits/sec).
    ///
    /// Accepted units (case-insensitive):
    /// - `bit`, `bps` — bits per second
    /// - `kbit`, `kbps`, `k` — 1000 bits/sec
    /// - `mbit`, `mbps`, `m` — 1_000_000 bits/sec
    /// - `gbit`, `gbps`, `g` — 1_000_000_000 bits/sec
    /// - `tbit`, `tbps`, `t` — 1_000_000_000_000 bits/sec
    /// - `kibit`, `kibps` — 1024 bits/sec
    /// - `mibit`, `mibps` — 1024² bits/sec
    /// - `gibit`, `gibps` — 1024³ bits/sec
    /// - `tibit`, `tibps` — 1024⁴ bits/sec
    ///
    /// All units are interpreted as **bits** per second on input
    /// (matching `tc(8)` convention) and converted to bytes/sec
    /// internally.
    pub fn parse(s: &str) -> Result<Self, RateParseError> {
        let bits_per_sec = crate::util::parse::get_rate(s.trim())
            .map_err(|_| RateParseError::Invalid(s.to_string()))?;
        Ok(Self::bits_per_sec(bits_per_sec))
    }

    /// Get the rate as bytes per second.
    #[inline]
    pub const fn as_bytes_per_sec(self) -> u64 {
        self.0
    }

    /// Get the rate as bits per second (saturating).
    #[inline]
    pub const fn as_bits_per_sec(self) -> u64 {
        self.0.saturating_mul(8)
    }

    /// Get the rate as bytes per second, saturating to `u32`.
    /// Useful for kernel TC structures whose rate fields are 32-bit
    /// (HFSC service curves, DRR/QFQ extras).
    #[inline]
    pub fn as_u32_bytes_per_sec_saturating(self) -> u32 {
        self.0.try_into().unwrap_or(u32::MAX)
    }

    /// Saturating addition.
    #[inline]
    pub const fn saturating_add(self, other: Rate) -> Rate {
        Rate(self.0.saturating_add(other.0))
    }

    /// Saturating subtraction.
    #[inline]
    pub const fn saturating_sub(self, other: Rate) -> Rate {
        Rate(self.0.saturating_sub(other.0))
    }

    /// Returns true if the rate is zero.
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::Add for Rate {
    type Output = Rate;
    #[inline]
    fn add(self, rhs: Rate) -> Rate {
        self.saturating_add(rhs)
    }
}

impl core::ops::Sub for Rate {
    type Output = Rate;
    #[inline]
    fn sub(self, rhs: Rate) -> Rate {
        self.saturating_sub(rhs)
    }
}

impl core::ops::Mul<u64> for Rate {
    type Output = Rate;
    #[inline]
    fn mul(self, rhs: u64) -> Rate {
        Rate(self.0.saturating_mul(rhs))
    }
}

impl core::ops::Mul<Rate> for u64 {
    type Output = Rate;
    #[inline]
    fn mul(self, rhs: Rate) -> Rate {
        rhs * self
    }
}

/// `Rate * Duration -> Bytes`. Saturates on overflow.
impl core::ops::Mul<Duration> for Rate {
    type Output = crate::util::Bytes;
    #[inline]
    fn mul(self, d: Duration) -> crate::util::Bytes {
        // u128 intermediate to avoid overflow for "100 Gbps for 1 hour";
        // checked_div is irrelevant — divisor is a non-zero const.
        #[allow(clippy::suspicious_arithmetic_impl)]
        let bytes = (self.0 as u128).saturating_mul(d.as_nanos()) / 1_000_000_000;
        crate::util::Bytes::new(bytes.try_into().unwrap_or(u64::MAX))
    }
}

impl core::ops::Mul<Rate> for Duration {
    type Output = crate::util::Bytes;
    #[inline]
    fn mul(self, r: Rate) -> crate::util::Bytes {
        r * self
    }
}

impl core::iter::Sum for Rate {
    fn sum<I: Iterator<Item = Rate>>(iter: I) -> Rate {
        iter.fold(Rate::ZERO, |acc, r| acc.saturating_add(r))
    }
}

impl<'a> core::iter::Sum<&'a Rate> for Rate {
    fn sum<I: Iterator<Item = &'a Rate>>(iter: I) -> Rate {
        iter.copied().sum()
    }
}

impl FromStr for Rate {
    type Err = RateParseError;
    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Rate {
    /// Format as the smallest tc-style unit that represents the rate
    /// without loss. Round-trips with [`Rate::parse`].
    ///
    /// Examples:
    /// - `Rate::mbit(100).to_string() == "100mbit"`
    /// - `Rate::gbit(1).to_string() == "1gbit"`
    /// - `Rate::kbit(1).to_string() == "1kbit"`
    /// - `Rate::bytes_per_sec(1).to_string() == "8bit"`
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bits = self.as_bits_per_sec();
        if bits == 0 {
            return f.write_str("0bit");
        }
        if bits.is_multiple_of(1_000_000_000) {
            write!(f, "{}gbit", bits / 1_000_000_000)
        } else if bits.is_multiple_of(1_000_000) {
            write!(f, "{}mbit", bits / 1_000_000)
        } else if bits.is_multiple_of(1_000) {
            write!(f, "{}kbit", bits / 1_000)
        } else {
            write!(f, "{}bit", bits)
        }
    }
}

/// Error type for [`Rate::parse`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RateParseError {
    #[error("invalid rate string: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kbps_to_bytes() {
        assert_eq!(kbps_to_bytes(0), 0);
        assert_eq!(kbps_to_bytes(8), 1000);
        assert_eq!(kbps_to_bytes(1000), 125_000);
        assert_eq!(kbps_to_bytes(10_000), 1_250_000);
    }

    #[test]
    fn test_mbps_to_bytes() {
        assert_eq!(mbps_to_bytes(0), 0);
        assert_eq!(mbps_to_bytes(1), 125_000);
        assert_eq!(mbps_to_bytes(100), 12_500_000);
        assert_eq!(mbps_to_bytes(1000), 125_000_000);
    }

    #[test]
    fn test_gbps_to_bytes() {
        assert_eq!(gbps_to_bytes(0), 0);
        assert_eq!(gbps_to_bytes(1), 125_000_000);
        assert_eq!(gbps_to_bytes(10), 1_250_000_000);
        assert_eq!(gbps_to_bytes(100), 12_500_000_000);
    }

    #[test]
    fn test_bytes_to_kbps() {
        assert_eq!(bytes_to_kbps(0), 0);
        assert_eq!(bytes_to_kbps(125), 1);
        assert_eq!(bytes_to_kbps(125_000), 1000);
        assert_eq!(bytes_to_kbps(1_250_000), 10_000);
    }

    #[test]
    fn test_bytes_to_mbps() {
        assert_eq!(bytes_to_mbps(0), 0);
        assert_eq!(bytes_to_mbps(125_000), 1);
        assert_eq!(bytes_to_mbps(12_500_000), 100);
        assert_eq!(bytes_to_mbps(125_000_000), 1000);
    }

    #[test]
    fn test_bytes_to_gbps() {
        assert_eq!(bytes_to_gbps(0), 0);
        assert_eq!(bytes_to_gbps(125_000_000), 1);
        assert_eq!(bytes_to_gbps(1_250_000_000), 10);
        assert_eq!(bytes_to_gbps(12_500_000_000), 100);
    }

    #[test]
    fn test_roundtrip() {
        // Test that conversions roundtrip correctly for aligned values
        assert_eq!(bytes_to_mbps(mbps_to_bytes(100)), 100);
        assert_eq!(bytes_to_gbps(gbps_to_bytes(10)), 10);
        assert_eq!(bytes_to_kbps(kbps_to_bytes(1000)), 1000);
    }

    #[test]
    fn test_bits_bytes() {
        assert_eq!(bits_to_bytes(8), 1);
        assert_eq!(bits_to_bytes(1_000_000), 125_000);
        assert_eq!(bytes_to_bits(1), 8);
        assert_eq!(bytes_to_bits(125_000), 1_000_000);
    }

    // ========================================================================
    // Rate newtype
    // ========================================================================

    #[test]
    fn rate_construction_units() {
        assert_eq!(Rate::bytes_per_sec(12_500_000), Rate::mbit(100));
        assert_eq!(Rate::bits_per_sec(100_000_000), Rate::mbit(100));
        assert_eq!(Rate::kbit(1000), Rate::mbit(1));
        assert_eq!(Rate::gbit(1), Rate::mbit(1000));
        assert_eq!(Rate::mbit(1000), Rate::gbit(1));
    }

    #[test]
    fn rate_binary_units() {
        assert_eq!(Rate::kibit(1).as_bits_per_sec(), 1024);
        assert_eq!(Rate::mibit(1).as_bits_per_sec(), 1024 * 1024);
        assert_eq!(Rate::gibit(1).as_bits_per_sec(), 1024u64.pow(3));
        assert_eq!(Rate::kib_per_sec(1).as_bytes_per_sec(), 1024);
        assert_eq!(Rate::mib_per_sec(1).as_bytes_per_sec(), 1024 * 1024);
    }

    #[test]
    fn rate_accessors() {
        let r = Rate::mbit(100);
        assert_eq!(r.as_bytes_per_sec(), 12_500_000);
        assert_eq!(r.as_bits_per_sec(), 100_000_000);
    }

    #[test]
    fn rate_parse_basic() {
        assert_eq!(Rate::parse("100mbit").unwrap(), Rate::mbit(100));
        assert_eq!(Rate::parse("1gbit").unwrap(), Rate::gbit(1));
        assert_eq!(Rate::parse("500kbit").unwrap(), Rate::kbit(500));
    }

    /// tc(8) matches suffixes case-insensitively, so `mbps` hits the `MBps`
    /// entry — mega**bytes** per second. This assertion used to read
    /// `== Rate::mbit(100)`, pinning the 8x bug instead of catching it (#203).
    #[test]
    fn rate_parse_bps_family_is_bytes() {
        assert_eq!(Rate::parse("100mbps").unwrap(), Rate::mbit(800));
        assert_eq!(
            Rate::parse("100mbps").unwrap().as_bytes_per_sec(),
            100_000_000,
            "100mbps is 100 megabytes/sec",
        );
        assert_eq!(Rate::parse("1kbps").unwrap(), Rate::kbit(8));
    }

    #[test]
    fn rate_parse_with_whitespace() {
        assert_eq!(Rate::parse(" 100mbit ").unwrap(), Rate::mbit(100));
    }

    #[test]
    fn rate_parse_rejects_garbage() {
        assert!(Rate::parse("definitely-not-a-rate").is_err());
        assert!(Rate::parse("").is_err());
    }

    #[test]
    fn rate_fromstr_works() {
        let r: Rate = "100mbit".parse().unwrap();
        assert_eq!(r, Rate::mbit(100));
    }

    #[test]
    fn rate_display_smallest_unit() {
        assert_eq!(Rate::ZERO.to_string(), "0bit");
        assert_eq!(Rate::mbit(100).to_string(), "100mbit");
        assert_eq!(Rate::gbit(1).to_string(), "1gbit");
        assert_eq!(Rate::kbit(500).to_string(), "500kbit");
        // 1 byte/sec = 8 bits/sec, not a clean tc unit
        assert_eq!(Rate::bytes_per_sec(1).to_string(), "8bit");
    }

    #[test]
    fn rate_display_parse_roundtrip() {
        for r in [
            Rate::ZERO,
            Rate::kbit(1),
            Rate::kbit(500),
            Rate::mbit(1),
            Rate::mbit(100),
            Rate::gbit(1),
            Rate::gbit(10),
        ] {
            let s = r.to_string();
            let parsed: Rate = s.parse().unwrap();
            assert_eq!(parsed, r, "roundtrip failed for {r:?} via {s:?}");
        }
    }

    #[test]
    fn rate_arithmetic() {
        assert_eq!(Rate::mbit(50) + Rate::mbit(50), Rate::mbit(100));
        assert_eq!(Rate::mbit(100) - Rate::mbit(50), Rate::mbit(50));
        assert_eq!(Rate::mbit(50) * 2u64, Rate::mbit(100));
        assert_eq!(2u64 * Rate::mbit(50), Rate::mbit(100));
    }

    #[test]
    fn rate_arithmetic_saturates() {
        assert_eq!(Rate::MAX + Rate::mbit(1), Rate::MAX);
        assert_eq!(Rate::ZERO - Rate::mbit(1), Rate::ZERO);
        assert_eq!(Rate::MAX * 2u64, Rate::MAX);
    }

    #[test]
    fn rate_times_duration_yields_bytes() {
        // 8 mbit/sec * 1 sec = 1 megabyte (1_000_000 bytes)
        let bytes = Rate::mbit(8) * Duration::from_secs(1);
        assert_eq!(bytes.as_u64(), 1_000_000);

        // 1 gbit/sec * 8 sec = 1 gigabyte
        let bytes = Rate::gbit(1) * Duration::from_secs(8);
        assert_eq!(bytes.as_u64(), 1_000_000_000);

        // 100 mbit/sec * 100ms = 1.25 MB
        let bytes = Rate::mbit(100) * Duration::from_millis(100);
        assert_eq!(bytes.as_u64(), 1_250_000);
    }

    #[test]
    fn rate_sum_iterator() {
        let rates = [Rate::mbit(10), Rate::mbit(20), Rate::mbit(30)];
        let total: Rate = rates.iter().sum();
        assert_eq!(total, Rate::mbit(60));
    }

    #[test]
    fn rate_u32_saturating() {
        assert_eq!(Rate::MAX.as_u32_bytes_per_sec_saturating(), u32::MAX);
        assert_eq!(
            Rate::bytes_per_sec(1000).as_u32_bytes_per_sec_saturating(),
            1000
        );
    }

    #[test]
    fn rate_is_zero() {
        assert!(Rate::ZERO.is_zero());
        assert!(!Rate::mbit(1).is_zero());
    }

    #[test]
    fn rate_ord() {
        assert!(Rate::mbit(100) > Rate::mbit(50));
        assert!(Rate::ZERO < Rate::mbit(1));
        let mut rates = [Rate::mbit(100), Rate::mbit(50), Rate::mbit(10)];
        rates.sort();
        assert_eq!(rates, [Rate::mbit(10), Rate::mbit(50), Rate::mbit(100)]);
    }
}
