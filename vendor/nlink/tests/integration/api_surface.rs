//! Public API reachability and the two subsystems that had no entry
//! point — #276, #280.
//!
//! These are compile-time assertions as much as tests: every type below
//! appeared in a public signature or a public field while living in a
//! private module, so a downstream crate could *see* it and not *name*
//! it. The sharpest was `Error::validation`, whose argument type was
//! unnameable — a public constructor nobody outside the crate could
//! call.
//!
//! The integration test target is a separate crate, so it sees exactly
//! what a downstream user sees.

use nlink::{Result, ValidationErrorInfo};

#[test]
fn validation_error_info_is_nameable_and_the_constructor_callable() {
    // `Error::validation` takes `impl IntoIterator<Item = ValidationErrorInfo>`
    // and `ValidationErrorInfo` was not re-exported, so this could not
    // be written at all from outside the crate (#280).
    let errs = vec![
        ValidationErrorInfo::new("mtu", "must be at least 68"),
        ValidationErrorInfo::new("name", "too long"),
    ];
    let e = nlink::Error::validation(errs);
    let shown = e.to_string();
    assert!(shown.contains("mtu"), "got {shown}");
    assert!(shown.contains("name"), "got {shown}");
}

#[test]
fn config_apply_and_diff_types_are_nameable() {
    use nlink::netlink::config::{ApplyError, LinkChanges};

    // The point is that these signatures can be *written* downstream.
    // `ApplyError` is a field of `ApplyResult`, which is `Serialize`
    // under the `serde` feature — so it was in the JSON ABI while being
    // unnameable in Rust (#280).
    fn _report(_errs: &[ApplyError]) {}
    fn _explain(_changes: &LinkChanges) {}

    let changes = LinkChanges::default();
    assert!(changes.is_empty());
}

#[cfg(feature = "tuntap")]
#[test]
fn tuntap_enumeration_is_reachable() {
    // `list_devices` was the feature's only enumeration API and its
    // return type was unnameable, so both carried `#[allow(dead_code)]`
    // — the compiler already knew (#280).
    fn _names(devs: &[nlink::tuntap::TunTapInfo]) -> Vec<&str> {
        devs.iter().map(|d| d.name.as_str()).collect()
    }
    // Enumerating needs no privilege and an empty list is a fine answer.
    let _ = nlink::tuntap::list_devices();
}

/// `dump_stream` on a dispatcher-mode connection was documented as
/// returning `Error::NotSupported`. It never did — `DumpStream::new`
/// handles dispatcher mode explicitly and there is a passing test for
/// it. Readers avoided a working feature and anyone who wrote
/// `if e.is_not_supported()` around it has dead code (#276).
#[tokio::test]
async fn dump_stream_works_in_dispatcher_mode() -> Result<()> {
    use tokio_stream::StreamExt;

    let conn = nlink::Connection::<nlink::Route>::new()?.with_dispatcher();
    let mut stream = conn.stream_links().await?;
    let mut seen = 0usize;
    while let Some(link) = stream.next().await {
        link?;
        seen += 1;
    }
    assert!(
        seen > 0,
        "a link dump must yield at least `lo`; the docs claimed this \
         path returns Error::NotSupported (#276)"
    );
    Ok(())
}

/// #317 — `destroy_matching` takes an `&InetFilter`, and no public API
/// produced one.
///
/// `SocketFilter::tcp()` returns an `InetFilterBuilder` that was not
/// re-exported, and its `build()` yields a `SocketFilter` wrapping the
/// filter in a `FilterKind` that was not re-exported either — so there was
/// no way in and no way back out. A struct literal compiled only because
/// every field happens to be `pub`, which is not a guarantee anyone stated
/// and which `#[non_exhaustive]` would have removed.
///
/// This test's value is that it compiles, in a crate that is not `nlink`.
#[cfg(feature = "sockdiag")]
#[test]
fn an_inet_filter_can_be_built_without_a_struct_literal() {
    use nlink::sockdiag::{FilterKind, InetFilterBuilder, Protocol, SocketFilter, TcpState};

    // The direct route, for `destroy_matching`.
    let filter = SocketFilter::tcp().states(&[TcpState::TimeWait]).build_inet();
    assert_eq!(filter.protocol, Protocol::Tcp);
    assert_ne!(filter.states, 0, "the state mask should carry TimeWait");

    // The builder is nameable, so a caller can hold one in a signature.
    fn _takes(_b: InetFilterBuilder) {}

    // And a built `SocketFilter` can be taken apart again.
    let wrapped = SocketFilter::tcp().build();
    assert!(matches!(wrapped.kind, FilterKind::Inet(_)));
}
