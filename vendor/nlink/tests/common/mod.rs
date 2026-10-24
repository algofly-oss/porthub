//! Common test utilities for integration tests.
//!
//! Thin shim over `nlink::lab` so existing integration tests keep
//! working without import changes while the shared helpers live in
//! the public `lab` module.

pub mod converge;
pub mod counters;
pub mod events;
pub mod nft;
pub mod topo;
pub mod traffic;

use std::time::Duration;

pub use nlink::lab::LabNamespace as TestNamespace;

/// How long one test body, or one step of a convergence case, may take.
pub const STEP_TIMEOUT: Duration = Duration::from_secs(30);

/// Run `body`, failing with `Error::timeout()` after [`STEP_TIMEOUT`]
/// instead of hanging the suite.
pub async fn with_timeout<T>(body: impl Future<Output = nlink::Result<T>>) -> nlink::Result<T> {
    match tokio::time::timeout(STEP_TIMEOUT, body).await {
        Ok(result) => result,
        Err(_elapsed) => Err(nlink::Error::timeout()),
    }
}

/// Skip the test if not running as root.
///
/// Use this at the beginning of integration tests that require root privileges.
///
/// Per Plan 174 — also initializes a `tracing-subscriber` (via
/// [`nlink::lab::init_test_tracing`]) so the lib's
/// `#[tracing::instrument]` spans surface in CI logs. It is
/// `nlink::require_root!()`, so `NLINK_TEST_STRICT_ROOT=1` makes the skip a
/// failure here too (#885).
#[macro_export]
macro_rules! require_root {
    () => {
        ::nlink::require_root!();
    };
}

/// Skip the test if not running as root (for non-Result functions).
#[macro_export]
macro_rules! require_root_void {
    () => {
        ::nlink::require_root_void!();
    };
}
