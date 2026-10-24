//! Plan 194 — concurrent stress + interleaved-request
//! regression coverage. 0.19 F1 fix extended.
//!
//! Three bug-shapes audited by the 0.19 consolidation-pass
//! research agent against the Rust netlink ecosystem
//! (`rtnetlink` issues #131 + #132):
//!
//! 1. **Sequence-number routing failure** — two simultaneously
//!    outstanding requests on the same socket getting each
//!    other's replies (rtnetlink #131). nlink's defense in
//!    0.19: the F1 fix added `request_lock` on `Connection<P>`
//!    so concurrent shared-`Arc<Connection>` callers serialize
//!    cleanly. This test spawns 16 concurrent dumps on a
//!    shared `Arc<Connection>` and verifies each sees the
//!    expected dummy link in its own result set.
//!
//! 2. **Concurrent namespace creation race** — `setns(2)` +
//!    bind-mount sequence non-atomic under parallel
//!    invocation (rtnetlink #132). nlink's defense: every
//!    `LabNamespace::new` is hermetic. This test spawns 16
//!    concurrent namespaces, each with a uniquely-named
//!    dummy, and verifies each namespace's dump returns
//!    only its own dummy.
//!
//! 3. **ACK-style concurrent requests** — the F1 fix is
//!    symmetric across dumps and ack-only requests but the
//!    failure shape is different (ACKs are tiny so the
//!    cross-task consumption window is narrow). This test
//!    spawns 16 concurrent `add_link` calls and asserts all
//!    succeed and the final dump sees all dummies.

use std::sync::Arc;

use nlink::Result;
use nlink::netlink::{
    Route,
    link::DummyLink,
};

use crate::common::TestNamespace;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_dumps_on_shared_connection_route_correctly() -> Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("seq-routing")?;
    let conn = Arc::new(nlink::Connection::<Route>::new_in(ns.name())?);

    // Pre-create a known dummy so each dump returns at least
    // one link.
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Spawn 16 concurrent get_links calls. If seq routing is
    // broken, some tasks see other tasks' responses (wrong
    // link names, mismatched ordering, partial dumps).
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move { c.get_links().await }));
    }

    for h in handles {
        let links = h.await.expect("task panicked")?;
        assert!(
            links.iter().any(|l| l.name() == Some("dummy0")),
            "every concurrent dump must see dummy0 (seq routing)"
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_namespaces_dont_corrupt_each_other() -> Result<()> {
    nlink::require_root!();

    let count = 16;
    let mut handles = Vec::with_capacity(count);
    for i in 0..count {
        handles.push(tokio::spawn(async move {
            let ns_name = format!("stress-{i}");
            let ns = TestNamespace::new(&ns_name)?;
            let conn = nlink::Connection::<Route>::new_in(ns.name())?;
            let iface_name = format!("d{i}");
            conn.add_link(DummyLink::new(&iface_name)).await?;
            let links = conn.get_links().await?;
            // Filter to our test-iface naming convention — `d<N>`
            // for an unsigned <N>. Loopback (`lo`) is excluded.
            let ours: Vec<String> = links
                .iter()
                .filter_map(|l| l.name().map(|s| s.to_string()))
                .filter(|n| n.starts_with('d') && n[1..].chars().all(|c| c.is_ascii_digit()))
                .collect();
            assert_eq!(
                ours.len(),
                1,
                "ns {i} must see only its own dummy; saw {ours:?}",
            );
            assert_eq!(ours[0], iface_name);
            // Keep the LabNamespace alive until the join_all
            // resolves so concurrent operations can't see each
            // other's torn-down state.
            Ok::<TestNamespace, nlink::Error>(ns)
        }));
    }

    // Join all 16 — surface the first error (task panic OR
    // assertion OR nlink error).
    for h in handles {
        h.await.expect("task panicked")?;
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_ack_requests_on_shared_connection_succeed() -> Result<()> {
    nlink::require_root!();

    // F1 fix coverage — ack-style request path. Even though
    // ACK responses are tiny (16 bytes header + 4 bytes errno),
    // concurrent senders on a shared connection without the
    // request lock would still race: task A's recv could
    // consume task B's ACK, leaving B blocked until the 30s
    // operation timeout (Plan 171) fires.
    let ns = TestNamespace::new("ack-routing")?;
    let conn = Arc::new(nlink::Connection::<Route>::new_in(ns.name())?);

    // Spawn 16 concurrent add_link calls — each creates a
    // uniquely-named dummy and waits for the kernel's ACK.
    let mut handles = Vec::with_capacity(16);
    for i in 0..16 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move {
            c.add_link(DummyLink::new(format!("ack{i}"))).await
        }));
    }

    for h in handles {
        h.await.expect("task panicked")?;
    }

    // Confirm all 16 dummies are visible — proves every ACK
    // landed without misrouting (a misrouted ACK would leave
    // either the create or the subsequent dump stuck).
    let links = conn.get_links().await?;
    for i in 0..16 {
        let name = format!("ack{i}");
        assert!(
            links.iter().any(|l| l.name() == Some(&name)),
            "expected dummy {name} to exist after concurrent add_link"
        );
    }

    Ok(())
}

/// A link dump torn by links coming and going is re-dumped, not returned
/// as an error: the kernel marks such a dump `NLM_F_DUMP_INTR`, and
/// nlink used to hand that straight to the caller — one concurrent change
/// anywhere in the namespace aborted a whole reconcile — and leave the
/// rest of the torn dump in the socket for the next request (#494).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dump_torn_by_concurrent_changes_is_redumped() -> nlink::Result<()> {
    use nlink::netlink::link::DummyLink;
    require_root!();
    nlink::require_modules!("dummy");

    let ns = crate::common::TestNamespace::new("dumpintr")?;
    let conn = ns.connection()?;
    // Enough links that a dump spans many reads.
    for i in 0..400 {
        conn.add_link(DummyLink::new(format!("d{i}"))).await?;
    }
    let churn = ns.connection()?;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let churning = {
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut n = 0u32;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let name = format!("x{}", n % 8);
                let _ = churn.add_link(DummyLink::new(&name)).await;
                let _ = churn.del_link(name.as_str()).await;
                n += 1;
            }
        })
    };
    let mut result = Ok(());
    for _ in 0..60 {
        if let Err(e) = conn.get_links().await {
            result = Err(e);
            break;
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    churning.await.expect("churn task");
    result?;
    // Nothing of a torn dump is left for the next request.
    let links = conn.get_links().await?;
    assert!(links.len() >= 400, "{} links", links.len());
    Ok(())
}
