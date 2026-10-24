//! Plan 234 (0.21) — Dispatcher integration coverage.
//!
//! Validates the dispatcher foundation end-to-end against a real
//! netlink socket (root-gated). Three classes of test, mapping to
//! Plan 234 §6:
//!
//! 1. **Wiring correctness** — every `Connection::new` /
//!    `from_parts` installs a dispatcher on its socket; the
//!    `dispatcher()` accessor returns the same instance the
//!    socket-side ENOBUFS path fans into.
//! 2. **Synthetic ENOBUFS routing** — multiple multicast
//!    subscribers all receive `ResyncMarker::ResyncStart` when the
//!    socket's `synth_enobufs_for_test()` fires, simulating the
//!    real kernel-side overflow path without the multi-minute
//!    flood the integration test would otherwise need.
//! 3. **Per-family smoke checks** — the dispatcher is wired the
//!    same way for every Connection<P> variant (Route, Generic,
//!    Netfilter, Nftables, Wireguard, Macsec, Mptcp, Ethtool,
//!    Nl80211, Devlink, DPLL, NetShaper). The per-family tests
//!    instantiate the family-resolved Connection where possible
//!    and assert the dispatcher is reachable. Failures here
//!    surface a Plan 235 (GENL command unification) gap before
//!    that follow-up lands.
//!
//! All tests are `require_root!()`-gated and skip cleanly when
//! run as a regular user. The synthetic-ENOBUFS test is the
//! exception — it works without root because it uses the
//! `synth_enobufs_for_test()` injection point that doesn't touch
//! the kernel.

use std::sync::Arc;
use std::time::Duration;

use nlink::Result;
use nlink::netlink::{
    Connection, Generic, Route,
    dispatcher::DispatcherEvent,
    resync::ResyncMarker,
};

// ============================================================================
// §6 — Wiring correctness
// ============================================================================

/// Plan 234 §6 — every Connection construction path installs the
/// dispatcher so the socket-side recv loop can fan ENOBUFS.
///
/// No root required — `Connection::<Route>::new()` doesn't need
/// privileges (the bind happens in the calling process's netns; the
/// socket isn't yet used to mutate anything).
#[tokio::test]
async fn connection_new_installs_dispatcher_on_socket() {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Route>::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: cannot create Route connection: {e}");
            return;
        }
    };

    let dispatcher = conn.dispatcher();
    // Subscribe so the active count is non-zero.
    let _rx = dispatcher.subscribe_multicast(7);
    assert_eq!(dispatcher.active_group_count(), 1);

    // Confirm the socket sees the same dispatcher instance.
    let installed = conn
        .socket()
        .dispatcher_for_test()
        .expect("Connection::new must call socket.install_dispatcher");
    assert_eq!(
        installed.active_group_count(),
        1,
        "socket's dispatcher must be the same instance as Connection's"
    );
}

/// Plan 234 §6 — Generic family construction path also installs
/// the dispatcher.
#[tokio::test]
async fn connection_generic_new_installs_dispatcher_on_socket() {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Generic>::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: cannot create Generic connection: {e}");
            return;
        }
    };
    let dispatcher = conn.dispatcher();
    let _rx = dispatcher.subscribe_multicast(1);
    assert_eq!(
        conn.socket()
            .dispatcher_for_test()
            .expect("dispatcher must be installed on socket")
            .active_group_count(),
        1
    );
}

// ============================================================================
// §6.3 — Synthetic ENOBUFS recovery
// ============================================================================

/// Plan 234 §6.3 — the synthetic ENOBUFS injection fans
/// `ResyncMarker::ResyncStart` to every active multicast
/// subscriber.
///
/// No root required: the test uses `synth_enobufs_for_test()` so
/// it doesn't depend on the kernel emitting a real ENOBUFS.
#[tokio::test]
async fn synthetic_enobufs_fans_out_resync_start_to_all_subscribers() {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Route>::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skip: {e}");
            return;
        }
    };
    let mut rx1 = conn.dispatcher().subscribe_multicast(1);
    let mut rx2 = conn.dispatcher().subscribe_multicast(2);
    let mut rx3 = conn.dispatcher().subscribe_multicast(3);

    conn.socket().synth_enobufs_for_test();

    for (i, rx) in [&mut rx1, &mut rx2, &mut rx3].iter_mut().enumerate() {
        match rx.recv().await {
            Ok(DispatcherEvent::Resync(ResyncMarker::ResyncStart)) => {}
            other => panic!(
                "subscriber {i} expected ResyncStart, got {other:?}"
            ),
        }
    }
}

// ============================================================================
// §6.1.1 — Per-family smoke
// ============================================================================

// Each per-family test asserts the dispatcher is installed and
// reachable for that family's Connection<P>. They do NOT exercise
// the full "100 requests + multicast subscriber" load described in
// Plan 234 §6.1.1 — that requires a real kernel-side family to be
// loaded, which the CI runner doesn't guarantee. These tests are
// the wiring half; the load half lands when Plan 235 (GENL command
// unification) does, because the round-trip helpers will all share
// the same plumbing.

macro_rules! per_family_dispatcher_test {
    ($name:ident, $marker:ty, $construct:expr, $why_skip:literal) => {
        #[tokio::test]
        async fn $name() {
            nlink::lab::init_test_tracing();
            let conn: Connection<$marker> = match $construct {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        concat!("skip ", stringify!($name), ": ", $why_skip, " ({})"),
                        e
                    );
                    return;
                }
            };
            let dispatcher = conn.dispatcher();
            let _rx = dispatcher.subscribe_multicast(1);
            assert_eq!(
                conn.socket()
                    .dispatcher_for_test()
                    .expect("dispatcher installed on socket")
                    .active_group_count(),
                1
            );
        }
    };
}

// Generic GENL families — async constructor. If the running kernel
// doesn't have the family loaded, new_async() returns
// FamilyNotFound and the test skips gracefully.

per_family_dispatcher_test!(
    wireguard_connection_has_dispatcher,
    nlink::netlink::Wireguard,
    Connection::<nlink::netlink::Wireguard>::new_async().await,
    "wireguard kernel module absent"
);

per_family_dispatcher_test!(
    macsec_connection_has_dispatcher,
    nlink::netlink::Macsec,
    Connection::<nlink::netlink::Macsec>::new_async().await,
    "macsec kernel module absent"
);

per_family_dispatcher_test!(
    mptcp_connection_has_dispatcher,
    nlink::netlink::Mptcp,
    Connection::<nlink::netlink::Mptcp>::new_async().await,
    "mptcp_pm kernel module absent"
);

per_family_dispatcher_test!(
    ethtool_connection_has_dispatcher,
    nlink::netlink::Ethtool,
    Connection::<nlink::netlink::Ethtool>::new_async().await,
    "ethtool family unavailable"
);

per_family_dispatcher_test!(
    nl80211_connection_has_dispatcher,
    nlink::netlink::Nl80211,
    Connection::<nlink::netlink::Nl80211>::new_async().await,
    "nl80211 family unavailable"
);

per_family_dispatcher_test!(
    devlink_connection_has_dispatcher,
    nlink::netlink::Devlink,
    Connection::<nlink::netlink::Devlink>::new_async().await,
    "devlink family unavailable"
);

per_family_dispatcher_test!(
    dpll_connection_has_dispatcher,
    nlink::netlink::Dpll,
    Connection::<nlink::netlink::Dpll>::new_async().await,
    "DPLL family unavailable"
);

// ============================================================================
// §6.2 — Stress: requests with active multicast subscriber
// ============================================================================

/// Plan 234 §6.2 — the dispatcher infrastructure must coexist with
/// concurrent request paths on a shared `Arc<Connection>`. The full
/// pipelining work (where the F1 mutex retires) is the next batch;
/// this test confirms that even with a multicast subscriber holding
/// the dispatcher's broadcast channel, concurrent unicast requests
/// still complete correctly through the F1 mutex.
///
/// 16 concurrent `get_links()` calls + 1 dispatcher subscriber.
/// Today they serialize through the F1 mutex — the test asserts
/// correctness, not pipelining throughput (which is the follow-up's
/// regression target).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_coexist_with_dispatcher_subscriber() -> Result<()> {
    nlink::lab::init_test_tracing();
    let conn = match Connection::<Route>::new() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("skip: {e}");
            return Ok(());
        }
    };

    // Subscribe to a dispatcher channel — proof that the dispatcher
    // state coexists with concurrent requests.
    let mut rx = conn.dispatcher().subscribe_multicast(7);

    // 16 concurrent get_links — should all complete without
    // hanging or returning wrong data.
    let mut handles = Vec::with_capacity(16);
    for _ in 0..16 {
        let c = conn.clone();
        handles.push(tokio::spawn(async move { c.get_links().await }));
    }
    for h in handles {
        let _links = h.await.expect("task panicked")?;
    }

    // Dispatcher subscriber should still be live — emit a
    // synthetic ENOBUFS and confirm we see the marker.
    conn.socket().synth_enobufs_for_test();
    match rx.recv().await {
        Ok(DispatcherEvent::Resync(ResyncMarker::ResyncStart)) => {}
        other => panic!("expected ResyncStart, got {other:?}"),
    }
    Ok(())
}

// ============================================================================
// #219 — shutdown must actually reach the driver.
// ============================================================================

/// Dropping a dispatcher-mode `Connection` closes its fd.
///
/// This is the end-to-end check that shutdown reaches the driver at all, over a
/// churn loop that would accumulate fds if it didn't.
///
/// **It does not, on its own, pin #219.** That bug is a lost-wakeup race:
/// `shutdown()` signalled with `Notify::notify_waiters()`, which stores no
/// permit and wakes only tasks *already registered* as waiters, and the driver
/// is unregistered for the whole of `route_buffer` and between `select!`
/// iterations. In the steady state this loop exercises, the driver is parked in
/// `notified()` when the drop lands — which is precisely the case
/// `notify_waiters` handles — so this test passes either way. Verified by
/// reintroducing the bug.
///
/// The race itself is pinned deterministically by
/// `dispatcher::tests::shutdown_signalled_with_no_waiter_is_not_lost`, which
/// signals with no waiter registered and fails under `notify_waiters`.
///
/// Unprivileged: opening an `NETLINK_ROUTE` socket needs no capability.
#[tokio::test]
async fn dropping_a_dispatcher_connection_closes_its_fd() -> Result<()> {
    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .expect("/proc/self/fd")
            .count()
    }

    // Warm up: the first connection may allocate thread-local and runtime fds
    // that are not returned, which would read as a leak.
    {
        let conn = Connection::<Route>::new()?.with_dispatcher();
        let _ = conn.get_links().await?;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;

    let baseline = open_fds();

    for _ in 0..20 {
        let conn = Connection::<Route>::new()?.with_dispatcher();
        // Drive a request so the driver task is actually spawned (it starts
        // lazily) and is mid-loop when the connection drops.
        let _ = conn.get_links().await?;
        drop(conn);
    }

    // The driver exits asynchronously, so give the runtime a moment to reap the
    // tasks before counting. Poll rather than sleep-and-hope.
    for _ in 0..40 {
        if open_fds() <= baseline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!(
        "fd leak: {} open fds after 20 create/drop cycles, was {baseline} before — \
         the shutdown signal is not reaching the driver, so it loops forever \
         holding its socket",
        open_fds(),
    );
}

// ============================================================================
// #465 — multicast is what the socket address says, not seq 0
// ============================================================================

fn is_new_address(ip: std::net::Ipv4Addr) -> impl FnMut(&nlink::netlink::NetworkEvent) -> bool {
    let ip = std::net::IpAddr::V4(ip);
    move |e| matches!(e, nlink::netlink::NetworkEvent::NewAddress(a) if a.address() == Some(&ip))
}

/// A change made by another process reaches a dispatcher-mode `events()`
/// stream. An address notification carries the seq of the request that
/// caused it — `ip`'s, not 0 — and the dispatcher dropped every such frame
/// as "unregistered" (#465). (Link notifications come from the netdev
/// notifier with seq 0, which is why a link test never showed it.)
#[tokio::test]
async fn dispatcher_events_see_changes_made_by_another_process() -> nlink::Result<()> {
    use crate::common::events::expect_event;
    use nlink::netlink::RtnetlinkGroup;
    require_root!();
    nlink::require_module!("dummy");

    let ns = crate::common::TestNamespace::new("disp-foreign")?;
    ns.exec("ip", &["link", "add", "d0", "type", "dummy"])?;
    let conn = ns.connection()?.with_dispatcher();
    conn.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events().await;
    ns.exec("ip", &["addr", "add", "10.65.0.1/24", "dev", "d0"])?;
    expect_event(
        &mut events,
        std::time::Duration::from_secs(5),
        "NewAddress 10.65.0.1 made by ip",
        is_new_address(std::net::Ipv4Addr::new(10, 65, 0, 1)),
    )
    .await?;
    Ok(())
}

/// A connection subscribed to a group gets the notification of its own
/// request, carrying that request's seq. In mutex mode it was read as the
/// reply — "data on an ack-only request" — and in dispatcher mode it was
/// routed to the request and lost to `events()` (#465).
#[tokio::test]
async fn a_subscribed_connection_gets_its_reply_and_its_own_event() -> nlink::Result<()> {
    use crate::common::events::expect_event;
    use nlink::netlink::RtnetlinkGroup;
    use nlink::netlink::addr::Ipv4Address;
    use std::net::Ipv4Addr;
    require_root!();
    nlink::require_module!("dummy");

    let ns = crate::common::TestNamespace::new("disp-own")?;
    ns.exec("ip", &["link", "add", "d0", "type", "dummy"])?;

    let mutex = ns.connection()?;
    mutex.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;
    mutex
        .add_address(Ipv4Address::new("d0", Ipv4Addr::new(10, 66, 0, 1), 24))
        .await?;

    let disp = ns.connection()?.with_dispatcher();
    disp.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;
    let mut events = disp.events().await;
    let ip = Ipv4Addr::new(10, 66, 0, 2);
    disp.add_address(Ipv4Address::new("d0", ip, 24)).await?;
    expect_event(
        &mut events,
        std::time::Duration::from_secs(5),
        "NewAddress 10.66.0.2 from this connection's own request",
        is_new_address(ip),
    )
    .await?;
    Ok(())
}

// ============================================================================
// #466 — overruns reach events(), and every request goes through the driver
// ============================================================================

/// A dispatcher-mode `events()` consumer that falls behind is told, as a
/// mutex-mode socket would tell it: ENOBUFS, so a resync wrapper re-dumps.
/// The listener channel was unbounded — a slow consumer meant unbounded
/// memory and no overrun, ever (#466).
#[tokio::test]
async fn a_slow_dispatcher_consumer_gets_enobufs() -> nlink::Result<()> {
    use nlink::netlink::RtnetlinkGroup;
    use nlink::netlink::link::DummyLink;
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_module!("dummy");

    let ns = crate::common::TestNamespace::new("disp-overrun")?;
    let conn = ns.connection()?.with_dispatcher();
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;
    // Far more notifications than a listener may queue, while nothing
    // reads them.
    let other = ns.connection()?;
    for i in 0..700 {
        let name = format!("o{i}");
        other.add_link(DummyLink::new(name.as_str())).await?;
        other.del_link(name.as_str()).await?;
    }
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), events.next())
        .await
        .expect("an item")
        .expect("the stream is live");
    match first {
        Err(e) => assert!(e.is_no_buffer_space(), "{e:?}"),
        Ok(event) => panic!("expected ENOBUFS for the overrun, got an event: {event:?}"),
    }
    Ok(())
}

/// nftables requests on a dispatcher-mode connection whose driver is
/// running. They read the socket themselves, racing the driver's recv —
/// timing out, or losing frames to it (#466).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nftables_requests_work_beside_the_dispatcher_driver() -> nlink::Result<()> {
    use nlink::netlink::Nftables;
    use nlink::netlink::nftables::types::Family;
    require_root!();
    nlink::require_module!("nf_tables");

    let ns = crate::common::TestNamespace::new("disp-nft")?;
    let conn = ns
        .connection_for::<Nftables>()?
        .timeout(std::time::Duration::from_secs(3))
        .with_dispatcher();
    conn.subscribe_all()?;
    let _events = conn.events().await;
    for i in 0..40 {
        conn.add_table(format!("t{i}").as_str(), Family::Inet)
            .await?;
        let tables = conn.list_tables().await?;
        assert_eq!(tables.len(), i + 1);
    }
    Ok(())
}

/// Back-to-back empty dumps on a dispatcher connection (#870). An empty
/// dump ends inside the request's `sendmsg`: the kernel queues its
/// `NLMSG_DONE`, wakes the driver and only then clears `cb_running`. A
/// driver that takes the DONE in between continues a dump that is no
/// longer there, and the kernel leaves an `EINVAL` in `sk_err` for its
/// next receive — which killed the driver, one run of 200 000 dumps in two
/// on two CPUs. The receive now tries again; the DONE is still queued.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn back_to_back_empty_dumps_keep_the_driver() -> nlink::Result<()> {
    use nlink::netlink::Nftables;
    require_root!();
    nlink::require_module!("nf_tables");

    let ns = crate::common::TestNamespace::new("disp-b2b")?;
    let conn = ns.connection_for::<Nftables>()?.with_dispatcher();
    for i in 0..50_000 {
        if let Err(e) = conn.list_tables().await {
            panic!("dump {i}: {e}");
        }
    }
    Ok(())
}
