//! Integration tests for operation timeouts (Plan 032; updated for
//! Plan 171's default-30s change in 0.17).

use std::time::Duration;

use nlink::{Route, netlink::Connection};

#[tokio::test]
async fn test_default_timeout_is_30s() {
    // Plan 171: every fresh Connection ships with a 30s default
    // operation timeout. The pre-Plan-171 assertion was
    // `None` — flipped here as part of the 0.17 cycle's
    // "close the hidden hang class" theme.
    let conn = Connection::<Route>::new().unwrap();
    assert_eq!(conn.operation_timeout(), Some(Duration::from_secs(30)));
}

#[tokio::test]
async fn test_timeout_is_chainable() {
    let conn = Connection::<Route>::new()
        .unwrap()
        .timeout(Duration::from_secs(5));
    assert_eq!(conn.operation_timeout(), Some(Duration::from_secs(5)));

    let conn = conn.no_timeout();
    assert_eq!(conn.operation_timeout(), None);
}

#[tokio::test]
async fn test_timeout_operations_succeed() -> nlink::Result<()> {
    require_root!();

    // 10 seconds is generous — kernel responds in microseconds
    let conn = Connection::<Route>::new()?.timeout(Duration::from_secs(10));

    let links = conn.get_links().await?;
    assert!(!links.is_empty(), "should have at least loopback");

    Ok(())
}

#[tokio::test]
async fn test_very_short_timeout() -> nlink::Result<()> {
    require_root!();

    // 1 nanosecond — should almost certainly time out
    let conn = Connection::<Route>::new()?.timeout(Duration::from_nanos(1));

    let result = conn.get_links().await;
    // May succeed on very fast systems, but if it fails it must be a timeout
    if let Err(e) = result {
        assert!(e.is_timeout(), "expected timeout, got: {e}");
    }

    Ok(())
}

#[tokio::test]
async fn test_explicit_no_timeout_works() -> nlink::Result<()> {
    require_root!();

    // Plan 171: opt out of the default 30s. Real ops still
    // succeed; this test asserts that .no_timeout() doesn't
    // break anything (the lib's recv loop runs without the
    // tokio::time::timeout wrap when timeout is None).
    let conn = Connection::<Route>::new()?.no_timeout();
    let links = conn.get_links().await?;
    assert!(!links.is_empty());

    Ok(())
}
