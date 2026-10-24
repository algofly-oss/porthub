//! The [`Percent`] newtype for percentage values.
//!
//! Used at TC API boundaries for netem loss/duplication/corruption
//! probabilities and similar fields. Construction clamps to `0.0..=100.0`;
//! arithmetic saturates.
//!
//! # Example
//!
//! ```
//! use nlink::util::Percent;
//!
//! let p = Percent::new(1.5);
//! assert_eq!(p.as_percent(), 1.5);
//!
//! // Construction clamps:
//! assert_eq!(Percent::new(150.0).as_percent(), 100.0);
//! assert_eq!(Percent::new(-1.0).as_percent(), 0.0);
//!
//! // Convert to a fraction or to the kernel's 32-bit probability form:
//! assert_eq!(Percent::new(50.0).as_fraction(), 0.5);
//! // 50% rounds to ~u32::MAX / 2 (within 1 due to f64 precision):
//! assert!(Percent::new(50.0).as_kernel_probability().abs_diff(u32::MAX / 2) <= 1);
//! ```

use core::{fmt, str::FromStr};

/// A percentage value in `0.0..=100.0`.
///
/// `Eq` / `Hash` are deliberately not implemented (float comparison).
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Default)]
pub struct Percent(f64);

impl Percent {
    pub const ZERO: Self = Self(0.0);
    pub const HUNDRED: Self = Self(100.0);

    /// Construct a percentage, clamping to `[0, 100]`. NaN is 0 %: it
    /// used to stay NaN, which the kernel encoding wrote as 0 % while the
    /// value compared unequal to itself (#598).
    pub fn new(value: f64) -> Self {
        if value.is_nan() {
            return Self::ZERO;
        }
        Self(value.clamp(0.0, 100.0))
    }

    /// Construct from a fraction in `[0, 1]`. `Percent::from_fraction(0.5) == 50%`.
    pub fn from_fraction(f: f64) -> Self {
        Self::new(f * 100.0)
    }

    /// Get the percentage as `f64` in `[0, 100]`.
    #[inline]
    pub const fn as_percent(self) -> f64 {
        self.0
    }

    /// Get the percentage as a fraction in `[0, 1]`.
    #[inline]
    pub fn as_fraction(self) -> f64 {
        self.0 / 100.0
    }

    /// Convert to the kernel's 32-bit probability representation
    /// (used in netem qopt fields). `Percent::HUNDRED -> u32::MAX`.
    ///
    /// Rounded to nearest, as tc(8) does (`rint`), so nlink and `tc` put
    /// the same value in the kernel, and a probability read back converts
    /// to the raw value it came from. This truncated before 0.32: 1 %
    /// became 42949672 where tc writes 42949673, and about 8 % of values
    /// read back one unit short, so a netem of 1.2 % loss never matched its
    /// own echo (#633).
    pub fn as_kernel_probability(self) -> u32 {
        ((self.0 / 100.0) * (u32::MAX as f64)).round() as u32
    }

    /// Returns true if exactly zero.
    #[inline]
    pub fn is_zero(self) -> bool {
        self.0 == 0.0
    }
}

impl fmt::Display for Percent {
    /// Format as `"<value>%"` with reasonable precision.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.fract() == 0.0 {
            write!(f, "{}%", self.0 as u64)
        } else {
            write!(f, "{}%", self.0)
        }
    }
}

/// Extract the percentage as an `f64` in `0.0..=100.0`. Lossless.
///
/// There is deliberately **no** `From<f64> for Percent`: the inbound
/// direction clamps to `0..=100`, which a `From` impl shouldn't do
/// silently. Use [`Percent::new`] (clamps) or
/// [`Percent::from_fraction`] explicitly.
impl From<Percent> for f64 {
    #[inline]
    fn from(p: Percent) -> Self {
        p.as_percent()
    }
}

impl FromStr for Percent {
    type Err = PercentParseError;

    /// Parse a **percentage**: `"50"`, `"50%"`, `"1.5%"`, `"0.5"`.
    ///
    /// The number is always read as a percent, never as a fraction — a bare
    /// number in `tc(8)` is a percentage, and this follows it. So `"0.5"` is
    /// **half of one percent**, not 50%.
    ///
    /// For a 0.0..=1.0 fraction, use [`Percent::from_fraction`]:
    /// `Percent::from_fraction(0.5) == Percent::new(50.0)`.
    ///
    /// (This doc-string used to claim `"0.5"` was "treated as a fraction",
    /// which the code never did — a 100x trap for anyone who believed it.
    /// The code was right and the doc was wrong; #221.)
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s.strip_suffix('%').unwrap_or(s);
        let value: f64 = s
            .parse()
            .map_err(|_| PercentParseError::Invalid(s.to_string()))?;
        if !value.is_finite() {
            return Err(PercentParseError::Invalid(s.to_string()));
        }
        Ok(Self::new(value))
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PercentParseError {
    #[error("invalid percent string: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NaN is not in `0..=100`; `clamp` keeps it NaN, which wrote as 0 %
    /// while comparing unequal to itself. It is 0 % now, said so (#598).
    /// #633: the values `tc qdisc … netem loss X` put in the kernel, read
    /// from the qopt on Linux 6.12 with iproute2 6.15. tc rounds to
    /// nearest; this truncated.
    #[test]
    fn kernel_probability_rounds_as_tc_does() {
        for (pct, tc) in [
            (1.0, 42_949_673),
            (1.2, 51_539_608),
            (0.3, 12_884_902),
            (33.333333, 1_431_655_751),
            (50.0, 2_147_483_648),
            (0.0, 0),
            (100.0, u32::MAX),
        ] {
            assert_eq!(Percent::new(pct).as_kernel_probability(), tc, "{pct} %");
        }
    }

    /// A probability read back is `raw / u32::MAX * 100`; converting that
    /// back must give `raw` again, or a value never matches its echo.
    #[test]
    fn kernel_probability_survives_a_read_back() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let raw = (x >> 32) as u32;
            let read = f64::from(raw) / f64::from(u32::MAX) * 100.0;
            assert_eq!(Percent::new(read).as_kernel_probability(), raw);
        }
    }

    #[test]
    fn nan_is_zero() {
        let p = Percent::new(f64::NAN);
        assert_eq!(p.as_percent(), 0.0);
        assert!(p.is_zero());
        assert_eq!(p, p);
        assert_eq!(Percent::from_fraction(f64::NAN).as_percent(), 0.0);
    }

    #[test]
    fn percent_construction_clamps() {
        assert_eq!(Percent::new(50.0).as_percent(), 50.0);
        assert_eq!(Percent::new(150.0).as_percent(), 100.0);
        assert_eq!(Percent::new(-1.0).as_percent(), 0.0);
    }

    #[test]
    fn percent_into_f64_extracts_value() {
        let f: f64 = Percent::new(12.5).into();
        assert_eq!(f, 12.5);
    }

    #[test]
    fn percent_from_fraction() {
        assert_eq!(Percent::from_fraction(0.5).as_percent(), 50.0);
        assert_eq!(Percent::from_fraction(1.0).as_percent(), 100.0);
        assert_eq!(Percent::from_fraction(2.0).as_percent(), 100.0); // clamped
    }

    #[test]
    fn percent_accessors() {
        let p = Percent::new(25.0);
        assert_eq!(p.as_percent(), 25.0);
        assert_eq!(p.as_fraction(), 0.25);
    }

    #[test]
    fn percent_kernel_probability() {
        assert_eq!(Percent::ZERO.as_kernel_probability(), 0);
        assert_eq!(Percent::HUNDRED.as_kernel_probability(), u32::MAX);
        // 50% should be approximately u32::MAX / 2
        let mid = Percent::new(50.0).as_kernel_probability();
        assert!(mid.abs_diff(u32::MAX / 2) <= 1);
    }

    #[test]
    fn percent_display_integer() {
        assert_eq!(Percent::ZERO.to_string(), "0%");
        assert_eq!(Percent::new(50.0).to_string(), "50%");
        assert_eq!(Percent::HUNDRED.to_string(), "100%");
    }

    #[test]
    fn percent_display_fractional() {
        assert_eq!(Percent::new(1.5).to_string(), "1.5%");
        assert_eq!(Percent::new(0.25).to_string(), "0.25%");
    }

    #[test]
    fn percent_fromstr_with_suffix() {
        let p: Percent = "50%".parse().unwrap();
        assert_eq!(p.as_percent(), 50.0);
    }

    #[test]
    fn percent_fromstr_no_suffix() {
        let p: Percent = "50".parse().unwrap();
        assert_eq!(p.as_percent(), 50.0);
    }

    #[test]
    fn percent_fromstr_fractional() {
        let p: Percent = "1.5".parse().unwrap();
        assert_eq!(p.as_percent(), 1.5);
    }

    #[test]
    fn percent_fromstr_clamps() {
        let p: Percent = "150%".parse().unwrap();
        assert_eq!(p.as_percent(), 100.0);
    }

    #[test]
    fn percent_fromstr_rejects_garbage() {
        assert!("abc".parse::<Percent>().is_err());
        assert!("".parse::<Percent>().is_err());
        assert!("nan".parse::<Percent>().is_err());
        assert!("inf".parse::<Percent>().is_err());
    }

    #[test]
    fn percent_is_zero() {
        assert!(Percent::ZERO.is_zero());
        assert!(!Percent::new(0.001).is_zero());
    }
}
