//! Strongly-typed traffic-control handle and filter priority.
//!
//! This module hosts [`TcHandle`] (a typed wrapper for the
//! `(major, minor)` u32-packed value the kernel uses for qdisc, class,
//! and filter handles) and [`FilterPriority`] (a typed wrapper for the
//! `u16` priority field on filters with band conventions documented at
//! the type level).
//!
//! These are the public-API types; the lower-level
//! [`crate::netlink::types::tc::tc_handle`] module of constants and free
//! functions remains as the underlying implementation but is no longer
//! the recommended interface.
//!
//! # Example
//!
//! ```
//! use nlink::TcHandle;
//!
//! let h = TcHandle::new(1, 10);
//! assert_eq!(h.major(), 1);
//! assert_eq!(h.minor(), 10);
//! assert_eq!(h.to_string(), "1:a");
//!
//! let parsed: TcHandle = "1:a".parse().unwrap();
//! assert_eq!(parsed, h);
//!
//! assert_eq!(TcHandle::ROOT.to_string(), "root");
//! assert!(TcHandle::ROOT.is_root());
//! ```

use core::{fmt, str::FromStr};

use super::types::tc::tc_handle as raw;

/// A traffic-control handle: a packed `(major, minor)` `u16` pair plus
/// the special values `ROOT`, `INGRESS`, `CLSACT`, `UNSPEC`.
///
/// Internally `(major as u32) << 16 | minor as u32`, matching the
/// kernel's encoding. Round-trips with `tc(8)` notation via
/// [`FromStr`] and [`fmt::Display`].
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcHandle(u32);

impl TcHandle {
    /// Root qdisc handle (kernel constant `TC_H_ROOT`).
    pub const ROOT: Self = Self(raw::ROOT);

    /// Ingress qdisc handle (kernel constant `TC_H_INGRESS`).
    pub const INGRESS: Self = Self(raw::INGRESS);

    /// Clsact qdisc handle (kernel constant `TC_H_CLSACT`).
    ///
    /// `TC_H_CLSACT` is an alias of `TC_H_INGRESS`, so this equals
    /// [`INGRESS`](Self::INGRESS). It is the parent a clsact **qdisc**
    /// is installed under; the parent a *filter* attaches to is
    /// [`CLSACT_INGRESS`](Self::CLSACT_INGRESS) or
    /// [`CLSACT_EGRESS`](Self::CLSACT_EGRESS).
    pub const CLSACT: Self = Self(raw::CLSACT);

    /// Parent of a filter on the clsact **ingress** hook
    /// (`TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS)`).
    pub const CLSACT_INGRESS: Self = Self(raw::CLSACT_INGRESS);

    /// Parent of a filter on the clsact **egress** hook
    /// (`TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS)`).
    pub const CLSACT_EGRESS: Self = Self(raw::CLSACT_EGRESS);

    /// Unspecified handle (`0`).
    pub const UNSPEC: Self = Self(raw::UNSPEC);

    /// Construct from major and minor.
    #[inline]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self(raw::make(major, minor))
    }

    /// Construct a major-only handle (e.g. `"1:"`). Equivalent to
    /// `TcHandle::new(major, 0)`.
    #[inline]
    pub const fn major_only(major: u16) -> Self {
        Self::new(major, 0)
    }

    /// Construct from the raw `u32` the kernel uses. Public so consumers
    /// reading raw netlink dumps can wrap, but kept distinct from
    /// [`new`](Self::new) to discourage accidental misuse of arbitrary
    /// integers.
    #[inline]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Get the raw `u32` for kernel APIs.
    #[inline]
    pub const fn as_raw(self) -> u32 {
        self.0
    }

    /// Get the major number.
    #[inline]
    pub const fn major(self) -> u16 {
        raw::major(self.0)
    }

    /// Get the minor number.
    #[inline]
    pub const fn minor(self) -> u16 {
        raw::minor(self.0)
    }

    /// Whether this handle's major is `ffff`, which belongs to the
    /// `ingress`/`clsact` qdisc (`TC_H_INGRESS`); the kernel never
    /// allocates it to another qdisc. A qdisc given it anywhere else
    /// cannot coexist with an ingress or clsact qdisc on the device (#485),
    /// and nlink refuses to add one there.
    #[inline]
    pub const fn is_reserved_major(self) -> bool {
        self.major() == 0xFFFF
    }

    #[inline]
    pub const fn is_root(self) -> bool {
        self.0 == raw::ROOT
    }

    #[inline]
    pub const fn is_ingress(self) -> bool {
        self.0 == raw::INGRESS
    }

    /// True for the clsact/ingress qdisc parent.
    ///
    /// `TC_H_CLSACT == TC_H_INGRESS`, so this is the same predicate as
    /// [`is_ingress`](Self::is_ingress). Which of the two qdiscs is
    /// actually installed there is a property of the qdisc kind, not of
    /// the handle.
    #[inline]
    pub const fn is_clsact(self) -> bool {
        self.0 == raw::CLSACT
    }

    /// True for either clsact hook's filter parent.
    #[inline]
    pub const fn is_clsact_hook(self) -> bool {
        self.0 == raw::CLSACT_INGRESS || self.0 == raw::CLSACT_EGRESS
    }

    #[inline]
    pub const fn is_unspec(self) -> bool {
        self.0 == raw::UNSPEC
    }
}

impl fmt::Display for TcHandle {
    /// Format using `tc(8)` notation: `"root"`, `"ingress"`, `"clsact"`,
    /// `"none"`, `"1:"` (major-only), or `"1:a"` (major:minor in hex).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&raw::format(self.0))
    }
}

impl FromStr for TcHandle {
    type Err = TcHandleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        raw::parse(s)
            .map(Self)
            .ok_or_else(|| TcHandleParseError::Invalid(s.to_string()))
    }
}

/// A raw `u32` is the packed `major:minor` handle, mirroring
/// [`TcHandle::from_raw`]. Lossless and unambiguous.
impl From<u32> for TcHandle {
    #[inline]
    fn from(raw: u32) -> Self {
        TcHandle::from_raw(raw)
    }
}

/// Unpack to the raw `u32` handle. Lossless inverse of [`From<u32>`].
impl From<TcHandle> for u32 {
    #[inline]
    fn from(h: TcHandle) -> Self {
        h.as_raw()
    }
}

/// Error type for [`TcHandle::from_str`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TcHandleParseError {
    #[error("invalid TC handle: {0}")]
    Invalid(String),
}

// ============================================================================
// FilterPriority
// ============================================================================

/// A traffic-control filter priority.
///
/// Lower values are evaluated first. Conventional bands (documentation
/// only, not enforced):
///
/// | Range       | Use                                         |
/// |-------------|---------------------------------------------|
/// | `1..=49`    | Operator-installed filters                  |
/// | `50..=99`   | Reserved for future library use             |
/// | `100..=199` | nlink recipe helpers                        |
/// | `200..=999` | Application-specific                        |
/// | `1000..`    | System / catch-alls                         |
///
/// `PerPeerImpairer` installs at `100 + i`, so past 100 rules it continues
/// above `199`. `PerHostLimiter` takes four priorities per rule from
/// `100 + 4 * i`, so past 25 rules it does too. Each owns the qdisc it
/// installs under, and tells its own filters by the class they send to,
/// not by their band (#491), so the bands matter only for filters you add
/// beside theirs: the operator band is yours.
/// Before 0.30 `PerHostLimiter` sat at `i + 1` and `i + 101/201/301`, in the
/// operator band (#434).
/// Outside callers can use [`FilterPriority::new`] for any value or the
/// [`recipe`](Self::recipe), [`app`](Self::app), [`system`](Self::system)
/// constructors as documentation-bearing shortcuts.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FilterPriority(u16);

impl FilterPriority {
    /// Start of the operator-installed band.
    pub const OPERATOR_BAND_START: u16 = 1;
    /// Start of the reserved band.
    pub const RESERVED_BAND_START: u16 = 50;
    /// Start of the recipe-helper band.
    pub const RECIPE_BAND_START: u16 = 100;
    /// Start of the application band.
    pub const APP_BAND_START: u16 = 200;
    /// Start of the system band.
    pub const SYSTEM_BAND_START: u16 = 1000;

    /// Construct from any `u16`.
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Get the underlying `u16` value.
    #[inline]
    pub const fn as_u16(self) -> u16 {
        self.0
    }

    /// Construct a recipe-band priority from an offset (`offset = 0` →
    /// `100`, `offset = 5` → `105`). Saturates at `APP_BAND_START - 1`.
    #[inline]
    pub const fn recipe(offset: u16) -> Self {
        let v = Self::RECIPE_BAND_START.saturating_add(offset);
        Self(if v >= Self::APP_BAND_START {
            Self::APP_BAND_START - 1
        } else {
            v
        })
    }

    /// Construct an application-band priority from an offset.
    /// Saturates at `SYSTEM_BAND_START - 1`.
    #[inline]
    pub const fn app(offset: u16) -> Self {
        let v = Self::APP_BAND_START.saturating_add(offset);
        Self(if v >= Self::SYSTEM_BAND_START {
            Self::SYSTEM_BAND_START - 1
        } else {
            v
        })
    }

    /// Construct a system-band priority from an offset (no upper cap).
    #[inline]
    pub const fn system(offset: u16) -> Self {
        Self(Self::SYSTEM_BAND_START.saturating_add(offset))
    }
}

impl fmt::Display for FilterPriority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for FilterPriority {
    type Err = core::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Self)
    }
}

impl From<u16> for FilterPriority {
    /// Compatibility conversion from raw `u16`.
    #[inline]
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// Extract the raw priority value. Lossless inverse of
/// [`From<u16>`](FilterPriority).
impl PartialEq<u16> for FilterPriority {
    fn eq(&self, other: &u16) -> bool {
        self.as_u16() == *other
    }
}

impl From<FilterPriority> for u16 {
    #[inline]
    fn from(p: FilterPriority) -> Self {
        p.as_u16()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // TcHandle
    // ========================================================================

    #[test]
    fn tc_handle_construction_packs_correctly() {
        let h = TcHandle::new(1, 10);
        assert_eq!(h.as_raw(), 0x0001_000A);
        assert_eq!(h.major(), 1);
        assert_eq!(h.minor(), 10);
    }

    #[test]
    fn tc_handle_u32_from_round_trips() {
        let h: TcHandle = 0x0001_000Au32.into();
        assert_eq!(h, TcHandle::new(1, 10));
        let raw: u32 = h.into();
        assert_eq!(raw, 0x0001_000A);
    }

    #[test]
    fn filter_priority_u16_round_trips() {
        let p: FilterPriority = 120u16.into();
        let v: u16 = p.into();
        assert_eq!(v, 120);
    }

    #[test]
    fn tc_handle_major_only() {
        let h = TcHandle::major_only(1);
        assert_eq!(h.as_raw(), 0x0001_0000);
        assert_eq!(h.major(), 1);
        assert_eq!(h.minor(), 0);
    }

    #[test]
    fn tc_handle_constants() {
        // Values re-derived from `linux/pkt_sched.h`:
        //   TC_H_ROOT       (0xFFFFFFFFU)
        //   TC_H_INGRESS    (0xFFFFFFF1U)
        //   TC_H_CLSACT     TC_H_INGRESS
        //   TC_H_MIN_INGRESS        0xFFF2U
        //   TC_H_MIN_EGRESS         0xFFF3U
        // The old assertion said CLSACT == 0xFFFF_FFF2, pinning the
        // transcription bug in place: that value is
        // TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS), a *filter* parent.
        assert_eq!(TcHandle::ROOT.as_raw(), 0xFFFF_FFFF);
        assert_eq!(TcHandle::INGRESS.as_raw(), 0xFFFF_FFF1);
        assert_eq!(TcHandle::CLSACT.as_raw(), 0xFFFF_FFF1);
        assert_eq!(TcHandle::CLSACT, TcHandle::INGRESS);
        assert_eq!(TcHandle::CLSACT_INGRESS.as_raw(), 0xFFFF_FFF2);
        assert_eq!(TcHandle::CLSACT_EGRESS.as_raw(), 0xFFFF_FFF3);
        assert_eq!(TcHandle::UNSPEC.as_raw(), 0);
        assert!(TcHandle::ROOT.is_root());
        assert!(TcHandle::INGRESS.is_ingress());
        assert!(TcHandle::CLSACT.is_clsact());
        assert!(TcHandle::CLSACT_INGRESS.is_clsact_hook());
        assert!(TcHandle::CLSACT_EGRESS.is_clsact_hook());
        assert!(!TcHandle::CLSACT.is_clsact_hook());
        assert!(TcHandle::UNSPEC.is_unspec());
    }

    #[test]
    fn tc_handle_display_basic() {
        assert_eq!(TcHandle::new(1, 10).to_string(), "1:a");
        assert_eq!(TcHandle::major_only(1).to_string(), "1:");
        assert_eq!(TcHandle::ROOT.to_string(), "root");
        assert_eq!(TcHandle::INGRESS.to_string(), "ingress");
        // CLSACT *is* INGRESS; `tc(8)` prints this parent as "ingress".
        assert_eq!(TcHandle::CLSACT.to_string(), "ingress");
        assert_eq!(TcHandle::CLSACT_INGRESS.to_string(), "clsact-ingress");
        assert_eq!(TcHandle::CLSACT_EGRESS.to_string(), "clsact-egress");
        assert_eq!(TcHandle::UNSPEC.to_string(), "none");
    }

    #[test]
    fn tc_handle_fromstr_basic() {
        assert_eq!("1:a".parse::<TcHandle>().unwrap(), TcHandle::new(1, 10));
        assert_eq!("1:".parse::<TcHandle>().unwrap(), TcHandle::major_only(1));
        assert_eq!("root".parse::<TcHandle>().unwrap(), TcHandle::ROOT);
        assert_eq!("ingress".parse::<TcHandle>().unwrap(), TcHandle::INGRESS);
        // `tc(8)` accepts both spellings for TC_H_INGRESS.
        assert_eq!("clsact".parse::<TcHandle>().unwrap(), TcHandle::CLSACT);
        assert_eq!("clsact".parse::<TcHandle>().unwrap(), TcHandle::INGRESS);
        assert_eq!(
            "clsact-ingress".parse::<TcHandle>().unwrap(),
            TcHandle::CLSACT_INGRESS
        );
        assert_eq!(
            "clsact-egress".parse::<TcHandle>().unwrap(),
            TcHandle::CLSACT_EGRESS
        );
        assert_eq!("none".parse::<TcHandle>().unwrap(), TcHandle::UNSPEC);
    }

    #[test]
    fn tc_handle_fromstr_rejects_garbage() {
        assert!("".parse::<TcHandle>().is_err());
        assert!("1".parse::<TcHandle>().is_err());
        assert!("1:zzzz".parse::<TcHandle>().is_err());
        assert!("zzzz:1".parse::<TcHandle>().is_err());
    }

    #[test]
    fn tc_handle_display_parse_roundtrip() {
        for h in [
            TcHandle::ROOT,
            TcHandle::INGRESS,
            TcHandle::CLSACT,
            TcHandle::CLSACT_INGRESS,
            TcHandle::CLSACT_EGRESS,
            TcHandle::UNSPEC,
            TcHandle::new(1, 10),
            TcHandle::new(0xff, 0xff),
            TcHandle::major_only(1),
            TcHandle::major_only(0xffff),
        ] {
            let s = h.to_string();
            let parsed: TcHandle = s.parse().unwrap();
            assert_eq!(parsed, h, "roundtrip failed for {h:?} via {s:?}");
        }
    }

    #[test]
    fn tc_handle_from_raw() {
        let h = TcHandle::from_raw(0x0001_000A);
        assert_eq!(h, TcHandle::new(1, 10));
    }

    #[test]
    fn tc_handle_ord() {
        assert!(TcHandle::new(1, 1) < TcHandle::new(1, 2));
        assert!(TcHandle::new(1, 0xff) < TcHandle::new(2, 0));
    }

    // ========================================================================
    // FilterPriority
    // ========================================================================

    #[test]
    fn filter_priority_new() {
        assert_eq!(FilterPriority::new(100).as_u16(), 100);
        assert_eq!(FilterPriority::new(0).as_u16(), 0);
        assert_eq!(FilterPriority::new(u16::MAX).as_u16(), u16::MAX);
    }

    #[test]
    fn filter_priority_recipe_band() {
        assert_eq!(FilterPriority::recipe(0).as_u16(), 100);
        assert_eq!(FilterPriority::recipe(5).as_u16(), 105);
        // saturates at APP_BAND_START - 1
        assert_eq!(FilterPriority::recipe(99).as_u16(), 199);
        assert_eq!(FilterPriority::recipe(100).as_u16(), 199);
        assert_eq!(FilterPriority::recipe(u16::MAX).as_u16(), 199);
    }

    #[test]
    fn filter_priority_app_band() {
        assert_eq!(FilterPriority::app(0).as_u16(), 200);
        assert_eq!(FilterPriority::app(5).as_u16(), 205);
        assert_eq!(FilterPriority::app(799).as_u16(), 999);
        assert_eq!(FilterPriority::app(800).as_u16(), 999);
    }

    #[test]
    fn filter_priority_system_band() {
        assert_eq!(FilterPriority::system(0).as_u16(), 1000);
        assert_eq!(FilterPriority::system(5).as_u16(), 1005);
        assert_eq!(FilterPriority::system(u16::MAX).as_u16(), u16::MAX);
    }

    #[test]
    fn filter_priority_from_u16() {
        let p: FilterPriority = 42u16.into();
        assert_eq!(p.as_u16(), 42);
    }

    #[test]
    fn filter_priority_display_fromstr_roundtrip() {
        let p = FilterPriority::new(100);
        assert_eq!(p.to_string(), "100");
        let parsed: FilterPriority = "100".parse().unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn filter_priority_ord() {
        assert!(FilterPriority::new(50) < FilterPriority::new(100));
    }
}
