//! Sealed trait that formalizes the `parse_params` contract used
//! across every typed TC config (qdiscs, classes, filters, actions).
//!
//! See [`ParseParams`] for the contract and the
//! ["TC API conventions"](https://github.com/.../CLAUDE.md#tc-api-conventions)
//! section of `CLAUDE.md` for the broader pattern.
//!
//! # Why a trait at all?
//!
//! Every typed config already has an inherent `pub fn parse_params`
//! method — the trait doesn't change behaviour. It exists so:
//!
//! 1. The contract (strict rejection, kind-prefixed error messages,
//!    return shape) is declared in one place rather than implied by
//!    convention across 25 inherent methods.
//! 2. Generic dispatch (`fn run<C: ParseParams>(p: &[&str]) -> Result<C>`)
//!    becomes possible — relevant for the bin's typed-dispatch macros
//!    and for any downstream consumer building their own DSL on top.
//! 3. The set of types that participate is closed (sealed trait), so
//!    third-party consumers can't accidentally diverge from the
//!    contract by impl'ing `ParseParams` for their own types with
//!    looser semantics.
//!
//! Inherent methods stay; the trait simply forwards to them. Existing
//! callers (every test, every recipe) keep working unchanged.

use crate::Result;

mod sealed {
    pub trait Sealed {}
}

/// Parse a `tc(8)`-style token slice into a typed config.
///
/// # Contract
///
/// Implementations **must**:
///
/// - Return `Err(`[`Error::invalid_message`]`)` for unknown tokens,
///   missing values, and unparseable inner values. Silent skipping
///   is a bug — the typed parsers exist precisely because the old
///   string-args builders swallowed unknown tokens.
/// - Begin every error message with the kind name
///   (`"htb: invalid r2q `foo` (expected unsigned integer)"`,
///   `"flower: `classid` requires a value"`,
///   `"netem: unknown token `nonsense`"`).
/// - Accept tokens in any order (keyword-style). Positional
///   optional args are consumed greedily up to the next keyword via
///   a per-config `is_keyword` helper.
/// - Honour `tc(8)` aliases (`classid`/`flowid`,
///   `burst`/`buffer`/`maxburst`) at the same arm.
/// - Reject "kernel-accepts-but-typed-config-doesn't-model"
///   tokens with a clear error pointing at the typed builder
///   method or the legacy fallback. **Never silently fall back.**
///
/// # Sealed
///
/// This trait is sealed via a private supertrait. Third-party crates
/// can use the trait but cannot implement it. The contract is
/// intentionally narrow; extending it across foreign types invites
/// drift.
///
/// # Example
///
/// ```no_run
/// # fn example() -> nlink::Result<()> {
/// use nlink::ParseParams;
/// use nlink::netlink::tc::HtbQdiscConfig;
///
/// let cfg: HtbQdiscConfig = ParseParams::parse_params(&["default", "10"])?;
/// # Ok(())
/// # }
/// ```
///
/// [`Error::invalid_message`]: crate::Error::invalid_message
pub trait ParseParams: Sized + sealed::Sealed {
    /// Parse `params` into `Self`. See the trait-level docs for the
    /// full error-shape and rejection contract.
    fn parse_params(params: &[&str]) -> Result<Self>;
}

/// Generates the sealing impl + the trait impl for each listed type.
/// Each trait impl forwards to the inherent `parse_params` method,
/// which every listed type already exposes.
macro_rules! impl_parse_params {
    ($($ty:path),+ $(,)?) => {
        $(
            impl sealed::Sealed for $ty {}
            impl ParseParams for $ty {
                fn parse_params(params: &[&str]) -> Result<Self> {
                    <$ty>::parse_params(params)
                }
            }
        )+
    };
}

impl_parse_params! {
    // Qdisc configs (35, two of them deprecated and listed below) — see
    // crates/nlink/src/netlink/tc.rs.
    crate::netlink::tc::BfifoConfig,
    crate::netlink::tc::CakeConfig,
    crate::netlink::tc::CbsConfig,
    crate::netlink::tc::ChokeConfig,
    crate::netlink::tc::ClsactConfig,
    crate::netlink::tc::CodelConfig,
    crate::netlink::tc::DrrConfig,
    crate::netlink::tc::EtfConfig,
    crate::netlink::tc::EtsConfig,
    crate::netlink::tc::FqConfig,
    crate::netlink::tc::FqCodelConfig,
    crate::netlink::tc::FqPieConfig,
    crate::netlink::tc::GredConfig,
    crate::netlink::tc::HfscConfig,
    crate::netlink::tc::HhfConfig,
    crate::netlink::tc::HtbQdiscConfig,
    crate::netlink::tc::IngressConfig,
    crate::netlink::tc::MqConfig,
    crate::netlink::tc::MqprioConfig,
    crate::netlink::tc::MultiqConfig,
    crate::netlink::tc::NetemConfig,
    crate::netlink::tc::PfifoConfig,
    crate::netlink::tc::PfifoFastConfig,
    crate::netlink::tc::PieConfig,
    crate::netlink::tc::PlugConfig,
    crate::netlink::tc::PrioConfig,
    crate::netlink::tc::QfqConfig,
    crate::netlink::tc::RedConfig,
    crate::netlink::tc::SfbConfig,
    crate::netlink::tc::SfqConfig,
    crate::netlink::tc::SkbprioConfig,
    crate::netlink::tc::TaprioConfig,
    crate::netlink::tc::TbfConfig,
    // Class configs (4) — added in 0.15.0 to close the class side at
    // typed-first parity with qdisc/filter/action. The legacy stringly-
    // typed `Connection::add_class(kind, &[&str])` and its silent-skip
    // dispatcher were deleted in the same release; bins/tc class now
    // routes through these per the dispatch! macro pattern.
    crate::netlink::tc::DrrClassConfig,
    crate::netlink::tc::HfscClassConfig,
    crate::netlink::tc::HtbClassConfig,
    crate::netlink::tc::QfqClassConfig,
    // Filter configs (11 — full filter side typed-first as of Plan 138 +
    // Plan 133 PR C; rsvp added under the #115 coverage epic).
    crate::netlink::filter::BasicFilter,
    crate::netlink::filter::BpfFilter,
    crate::netlink::filter::CgroupFilter,
    crate::netlink::filter::FlowFilter,
    crate::netlink::filter::FlowerFilter,
    crate::netlink::filter::FwFilter,
    crate::netlink::filter::MatchallFilter,
    crate::netlink::filter::RouteFilter,
    crate::netlink::filter::RsvpFilter,
    crate::netlink::filter::TcindexFilter,
    crate::netlink::filter::U32Filter,
    // Action configs (19) — Plan 139 PR B closed the original 14
    // typed-first; mpls + skbmod added in the #29 epic; ctinfo + ife +
    // gate added under the #115 coverage epic; pedit's `munge` DSL
    // parser landed under the #137 backlog.
    crate::netlink::action::BpfAction,
    crate::netlink::action::ConnmarkAction,
    crate::netlink::action::CsumAction,
    crate::netlink::action::CtAction,
    crate::netlink::action::CtinfoAction,
    crate::netlink::action::GactAction,
    crate::netlink::action::GateAction,
    crate::netlink::action::IfeAction,
    crate::netlink::action::MirredAction,
    crate::netlink::action::MplsAction,
    crate::netlink::action::NatAction,
    crate::netlink::action::PeditAction,
    crate::netlink::action::PoliceAction,
    crate::netlink::action::SampleAction,
    crate::netlink::action::SimpleAction,
    crate::netlink::action::SkbeditAction,
    crate::netlink::action::SkbmodAction,
    crate::netlink::action::TunnelKeyAction,
    crate::netlink::action::VlanAction,
}

// Retired by the kernel in Linux 6.8 (#347). Deprecated, still dispatchable
// for callers on older kernels — the sealed trait keeps the contract
// type-checked until the types go.
#[allow(deprecated)]
impl sealed::Sealed for crate::netlink::tc::AtmConfig {}
#[allow(deprecated)]
impl ParseParams for crate::netlink::tc::AtmConfig {
    fn parse_params(params: &[&str]) -> Result<Self> {
        <crate::netlink::tc::AtmConfig>::parse_params(params)
    }
}
#[allow(deprecated)]
impl sealed::Sealed for crate::netlink::tc::DsmarkConfig {}
#[allow(deprecated)]
impl ParseParams for crate::netlink::tc::DsmarkConfig {
    fn parse_params(params: &[&str]) -> Result<Self> {
        <crate::netlink::tc::DsmarkConfig>::parse_params(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::tc::HtbQdiscConfig;

    #[test]
    fn trait_dispatch_matches_inherent() {
        let via_trait = <HtbQdiscConfig as ParseParams>::parse_params(&["default", "10"])
            .expect("htb default 10 should parse via trait");
        let via_inherent =
            HtbQdiscConfig::parse_params(&["default", "10"]).expect("inherent parse");
        // No PartialEq on these configs, so compare a discriminating field.
        assert_eq!(via_trait.default_class, via_inherent.default_class);
    }

    #[test]
    fn trait_propagates_strict_errors() {
        let err = <HtbQdiscConfig as ParseParams>::parse_params(&["nonsense"])
            .expect_err("strict parser must reject unknown tokens");
        let msg = err.to_string();
        assert!(msg.contains("htb"), "error must be kind-prefixed: {msg}");
    }

    /// Generic dispatch to prove the trait is usable in a generic
    /// position — this is the whole point of the formalization.
    #[test]
    fn generic_dispatch_compiles() {
        fn parse<C: ParseParams>(params: &[&str]) -> Result<C> {
            C::parse_params(params)
        }
        let _: HtbQdiscConfig = parse(&["default", "10"]).expect("htb default 10");
    }
}
