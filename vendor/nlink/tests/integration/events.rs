//! Event monitoring integration tests.
//!
//! Every test subscribes first and makes its change on a second
//! connection. rtnetlink queues the notification on the subscribed socket
//! before it acknowledges the change, so by the time that call returns the
//! event is waiting — and one that never arrives is a bug, not timing.
//! The tests wait for it with `expect_event`, which fails instead of
//! shrugging. (They used to accept a missed event "due to timing", which
//! meant no event bug could ever fail them.)

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use nlink::{
    Result,
    netlink::{
        NetworkEvent, RtnetlinkGroup,
        addr::{Ipv4Address, Ipv6Address},
        link::DummyLink,
        tc::NetemConfig,
    },
};

use crate::common::TestNamespace;
use crate::common::events::{expect_event, expect_event_without};

/// Long enough for a loaded CI box; the event is already queued.
const WITHIN: Duration = Duration::from_secs(5);

fn new_link(name: &'static str) -> impl FnMut(&NetworkEvent) -> bool {
    move |e| matches!(e, NetworkEvent::NewLink(l) if l.name() == Some(name))
}

fn new_address(ip: IpAddr) -> impl FnMut(&NetworkEvent) -> bool {
    move |e| matches!(e, NetworkEvent::NewAddress(a) if a.address() == Some(&ip))
}

#[tokio::test]
async fn test_link_events() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("linkev")?;
    let conn = ns.connection()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    ns.connection()?.add_link(DummyLink::new("dummy0")).await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    Ok(())
}

/// An address event arrives, and nothing from a group the socket did not
/// join arrives before it: the link was flipped up first, and its NewLink
/// must not leak onto an `Ipv4Addr`-only subscription.
#[tokio::test]
async fn test_address_events() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("addrev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events().await;

    let conn2 = ns.connection()?;
    conn2.set_link_up("dummy0").await?;
    let ip = Ipv4Addr::new(192, 168, 1, 1);
    conn2
        .add_address(Ipv4Address::new("dummy0", ip, 24))
        .await?;

    expect_event_without(
        &mut events,
        WITHIN,
        "NewAddress 192.168.1.1",
        new_address(ip.into()),
        |e| matches!(e, NetworkEvent::NewLink(_)),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_tc_events() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "sch_netem");

    let ns = TestNamespace::new("tcev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    conn.subscribe(&[RtnetlinkGroup::Tc])?;
    let mut events = conn.events().await;

    let netem = NetemConfig::new().delay(Duration::from_millis(10)).build();
    ns.connection()?.add_qdisc("dummy0", netem).await?;

    expect_event(&mut events, WITHIN, "NewQdisc netem", |e| {
        matches!(e, NetworkEvent::NewQdisc(tc) if tc.kind() == Some("netem"))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_subscribe_all() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("suball")?;
    let conn = ns.connection()?;
    conn.subscribe_all()?;
    let mut events = conn.events().await;

    ns.connection()?.add_link(DummyLink::new("dummy0")).await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    Ok(())
}

/// One socket, three groups: each delivers its own event.
#[tokio::test]
async fn test_multiple_subscriptions() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("multisub")?;
    let conn = ns.connection()?;
    conn.subscribe(&[
        RtnetlinkGroup::Link,
        RtnetlinkGroup::Ipv4Addr,
        RtnetlinkGroup::Ipv4Route,
    ])?;
    let mut events = conn.events().await;

    let conn2 = ns.connection()?;
    conn2.add_link(DummyLink::new("dummy0")).await?;
    conn2.set_link_up("dummy0").await?;
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    conn2
        .add_address(Ipv4Address::new("dummy0", ip, 24))
        .await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    expect_event(&mut events, WITHIN, "NewAddress 10.0.0.1", new_address(ip.into())).await?;
    expect_event(&mut events, WITHIN, "a NewRoute for the address", |e| {
        matches!(e, NetworkEvent::NewRoute(_))
    })
    .await?;
    Ok(())
}

/// Bringing a link down announces it down. A NewLink that still says up
/// (linkwatch can report late) is skipped, not taken as the answer.
#[tokio::test]
async fn test_link_down_event() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("linkdown")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    ns.connection()?.set_link_down("dummy0").await?;

    expect_event(&mut events, WITHIN, "NewLink dummy0, down", |e| {
        matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("dummy0") && !l.is_up())
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_del_link_event() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("dellinkev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    ns.connection()?.del_link("dummy0").await?;

    expect_event(&mut events, WITHIN, "DelLink dummy0", |e| {
        matches!(e, NetworkEvent::DelLink(l) if l.name() == Some("dummy0"))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_del_address_event() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("deladdrev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    let ip = Ipv4Addr::new(10, 0, 0, 1);
    conn.add_address(Ipv4Address::new("dummy0", ip, 24)).await?;
    conn.subscribe(&[RtnetlinkGroup::Ipv4Addr])?;
    let mut events = conn.events().await;

    ns.connection()?.del_address("dummy0", ip.into(), 24).await?;

    let expected: IpAddr = ip.into();
    expect_event(&mut events, WITHIN, "DelAddress 10.0.0.1", |e| {
        matches!(e, NetworkEvent::DelAddress(a) if a.address() == Some(&expected))
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_owned_event_stream() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("ownedstream")?;
    let conn = ns.connection()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut stream = conn.into_events().await;

    ns.connection()?.add_link(DummyLink::new("dummy0")).await?;

    expect_event(&mut stream, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;

    // The connection comes back out of the stream.
    let _conn = stream.into_connection();
    Ok(())
}

/// The stream keeps delivering: three links, three events, in order.
#[tokio::test]
async fn test_event_stream_continues() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("streamcont")?;
    let conn = ns.connection()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;
    let mut events = conn.events().await;

    let conn2 = ns.connection()?;
    for name in ["dummy0", "dummy1", "dummy2"] {
        conn2.add_link(DummyLink::new(name)).await?;
    }

    expect_event(&mut events, WITHIN, "NewLink dummy0", new_link("dummy0")).await?;
    expect_event(&mut events, WITHIN, "NewLink dummy1", new_link("dummy1")).await?;
    expect_event(&mut events, WITHIN, "NewLink dummy2", new_link("dummy2")).await?;
    Ok(())
}

/// The event for the address added, not the link-local one or a DAD
/// update for something else.
#[tokio::test]
async fn test_ipv6_address_events() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("addr6ev")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    conn.subscribe(&[RtnetlinkGroup::Ipv6Addr])?;
    let mut events = conn.events().await;

    let ip: Ipv6Addr = "fd00::1".parse().unwrap();
    ns.connection()?
        .add_address(Ipv6Address::new("dummy0", ip, 64))
        .await?;

    expect_event(&mut events, WITHIN, "NewAddress fd00::1", new_address(ip.into())).await?;
    Ok(())
}

/// After an overflow the watch-cache equals a fresh dump. The resync took
/// its snapshot without draining the socket, then delivered the frames
/// queued before the overflow on top of it — the `NewLink` of a link whose
/// `DelLink` the overflow had dropped, kept forever (#464).
#[tokio::test]
async fn a_resynced_mirror_equals_a_fresh_dump() -> Result<()> {
    use nlink::netlink::resync::ResyncMarker;
    use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent};
    use nlink::netlink::Route;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("resync-drain")?;
    let name = ns.name().to_string();
    let factory: ConnectionFactory<Route> = Arc::new(move || {
        let name = name.clone();
        Box::pin(async move { nlink::Connection::<Route>::new_in(&name) })
    });
    let conn = ns.connection()?;
    conn.socket().set_rcvbuf(1024)?;
    let mut stream = conn.into_events_with_resync(factory).await?;

    // A burst the tiny buffer cannot hold, read nothing meanwhile: links
    // that come and go, and some that stay.
    let other = ns.connection()?;
    // It starts with a link that goes again: what the full buffer holds is
    // that link's NewLink, and the DelLink is what the overflow drops.
    for i in 1..=300 {
        let name = format!("t{i}");
        other.add_link(DummyLink::new(name.as_str())).await?;
        if i % 10 != 0 {
            other.del_link(name.as_str()).await?;
        }
    }

    let mut mirror: BTreeSet<String> = BTreeSet::new();
    let mut resyncs = 0;
    loop {
        let next = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
        let Ok(Some(item)) = next else { break };
        match item? {
            ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
                resyncs += 1;
                mirror.clear();
            }
            ResyncedEvent::Event(NetworkEvent::NewLink(l))
            | ResyncedEvent::Resynced(NetworkEvent::NewLink(l)) => {
                mirror.extend(l.name().map(str::to_string));
            }
            ResyncedEvent::Event(NetworkEvent::DelLink(l)) => {
                if let Some(n) = l.name() {
                    mirror.remove(n);
                }
            }
            _ => {}
        }
    }
    assert!(
        resyncs > 0,
        "the burst should have overflowed the 1 KiB buffer"
    );
    let fresh: BTreeSet<String> = ns
        .connection()?
        .get_links()
        .await?
        .iter()
        .filter_map(|l| l.name().map(str::to_string))
        .collect();
    assert_eq!(mirror, fresh);
    Ok(())
}

/// The resync stream starts with the state as it is, and that snapshot
/// holds everything the stream subscribes to that the kernel can dump —
/// qdiscs, rules and nexthops included. It held links, addresses, routes
/// and neighbours only, so a mirror of the rest was emptied by the first
/// overflow; and there was no initial snapshot at all (#503).
#[tokio::test]
async fn the_rtnetlink_snapshot_covers_what_the_stream_subscribes_to() -> Result<()> {
    use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent};
    use nlink::netlink::Route;
    use std::sync::Arc;
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_modules!("dummy", "sch_netem");

    let ns = TestNamespace::new("resync-full")?;
    ns.exec("ip", &["link", "add", "d0", "type", "dummy"])?;
    ns.exec("ip", &["link", "set", "d0", "up"])?;
    ns.exec("ip", &["nexthop", "add", "id", "7", "dev", "d0"])?;
    ns.exec("ip", &["rule", "add", "pref", "1234", "table", "100"])?;
    ns.exec(
        "tc",
        &["qdisc", "add", "dev", "d0", "root", "netem", "delay", "1ms"],
    )?;

    let name = ns.name().to_string();
    let factory: ConnectionFactory<Route> = Arc::new(move || {
        let name = name.clone();
        Box::pin(async move { nlink::Connection::<Route>::new_in(&name) })
    });
    let mut stream = ns.connection()?.into_events_with_resync(factory).await?;
    let first = stream.next().await.expect("an item")?;
    assert!(first.is_initial_sync_start(), "{first:?}");
    let (mut qdisc, mut rule, mut nexthop) = (false, false, false);
    loop {
        match stream.next().await.expect("the initial sync ends")? {
            ResyncedEvent::Resynced(NetworkEvent::NewQdisc(q)) if q.kind() == Some("netem") => {
                qdisc = true;
            }
            ResyncedEvent::Resynced(NetworkEvent::NewRule(r)) if r.priority() == 1234 => {
                rule = true
            }
            ResyncedEvent::Resynced(NetworkEvent::NewNexthop(n)) if n.id() == 7 => nexthop = true,
            item if item.is_resync_end() => break,
            _ => {}
        }
    }
    assert!(
        qdisc && rule && nexthop,
        "qdisc={qdisc} rule={rule} nexthop={nexthop}"
    );
    Ok(())
}

/// Whether `b`'s end of the pair still exists.
async fn peer_end_exists(b: &TestNamespace, b_if: &str) -> Result<bool> {
    let conn = b.connection()?;
    Ok(conn.get_link_by_name(b_if).await?.is_some())
}

/// #504: a socket keeps its namespace alive, so deleting the namespace
/// left the stream idling forever — and the namespace with it, interfaces
/// and all: here, the far end of a veth into it. The stream now ends with
/// `NamespaceDeleted` once the marker is gone, and dropping it frees the
/// namespace, which takes the veth's far end down with it.
#[tokio::test]
async fn an_event_stream_ends_when_its_namespace_is_deleted() -> Result<()> {
    use nlink::netlink::namespace;
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_module!("veth");

    let pair = crate::common::topo::NsPair::new("nsdel", 61).await?;
    let conn = pair.a.connection()?;
    conn.subscribe_all()?;
    let mut stream = conn.into_events().await;

    // A live namespace does not end the stream: three checks pass.
    let quiet = tokio::time::Instant::now() + Duration::from_millis(3200);
    while let Ok(Some(item)) = tokio::time::timeout_at(quiet, stream.next()).await {
        if let Err(e) = item {
            panic!("the stream failed while its namespace was live: {e}");
        }
    }

    namespace::delete(pair.a.name())?;
    // Still pinned by the stream: the veth's far end is still there.
    assert!(
        peer_end_exists(&pair.b, pair.b_if).await?,
        "the stream should still pin the namespace"
    );

    let end = tokio::time::Instant::now() + WITHIN;
    let ended = loop {
        match tokio::time::timeout_at(end, stream.next()).await {
            Ok(Some(Err(e))) if e.is_namespace_deleted() => break true,
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => panic!("unexpected error: {e}"),
            Ok(None) | Err(_) => break false,
        }
    };
    assert!(
        ended,
        "no NamespaceDeleted within {WITHIN:?} of the deletion"
    );
    assert!(
        stream.next().await.is_none(),
        "the stream ends after the error"
    );

    // Dropping the stream closes the last socket in the namespace — with
    // the test's own handle, which holds it open as any `Netns` does (#520)
    // — and the kernel frees it, the veth's far end with it.
    drop(stream);
    let (b, b_if) = (pair.b, pair.b_if);
    drop(pair.a);
    let gone_by = tokio::time::Instant::now() + WITHIN;
    while peer_end_exists(&b, b_if).await? {
        assert!(
            tokio::time::Instant::now() < gone_by,
            "the namespace was not freed after the stream dropped"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// A forwarding change made through `/proc/sys` arrives as a netconf event
/// for its interface, and `get_netconf` dumps `all`, `default` and every
/// interface (#523). Sysctl drift was invisible to a watcher.
#[tokio::test]
async fn a_sysctl_change_arrives_as_a_netconf_event() -> Result<()> {
    use nlink::netlink::RtnetlinkGroup;
    use nlink::netlink::netconf::NetconfDevice;
    nlink::require_root!();
    nlink::require_modules!("dummy");
    nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");

    let ns = TestNamespace::new("netconf")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    let ifindex = conn.get_link_by_name("d0").await?.expect("d0").ifindex();
    let dump = conn.get_netconf(nlink::AddressFamily::v4()).await?;
    // A new namespace takes its forwarding from the host's, so whatever
    // it is, it is there for all three.
    let forwarding = |device| dump.iter().find(|n| n.device() == Some(device)).and_then(|n| n.forwarding());
    for device in [NetconfDevice::All, NetconfDevice::Default, NetconfDevice::Index(ifindex)] {
        assert!(forwarding(device).is_some(), "{device:?}: {dump:?}");
    }
    let flipped = 1 - forwarding(NetconfDevice::Index(ifindex)).expect("d0's");

    let watch = ns.connection()?;
    watch.subscribe(&[RtnetlinkGroup::Ipv4Netconf])?;
    let mut events = watch.events().await;
    ns.exec("sysctl", &["-w", &format!("net.ipv4.conf.d0.forwarding={flipped}")])?;
    crate::common::events::expect_event(
        &mut events,
        std::time::Duration::from_secs(5),
        "d0's forwarding flipped",
        |e: &NetworkEvent| {
            e.as_netconf()
                .is_some_and(|m| m.ifindex() == Some(ifindex) && m.forwarding() == Some(flipped))
        },
    )
    .await?;
    Ok(())
}

/// Each event carries who caused it (#523): an address this connection
/// added comes with its port id and the request's sequence number; the
/// carrier loss the kernel reports on a veth whose peer went down comes
/// with port id 0. (Not every notification names its requester: the
/// kernel reports a new link with port id 0 even when a request made it.)
#[tokio::test]
async fn an_event_says_who_caused_it() -> Result<()> {
    use nlink::netlink::EventMeta;
    use nlink::netlink::link::VethLink;
    nlink::require_root!();
    nlink::require_modules!("dummy", "veth");

    let ns = TestNamespace::new("event-meta")?;
    let conn = ns.connection()?;
    let watch = ns.connection()?;
    watch.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
    let mut events = watch.events().await.with_meta();

    conn.add_link(DummyLink::new("m0")).await?;
    conn.add_address(Ipv4Address::new("m0", Ipv4Addr::new(10, 93, 0, 1), 24)).await?;
    let (meta, _) = expect_event(&mut events, Duration::from_secs(5), "m0's address", |(_, e): &(EventMeta, NetworkEvent)| {
        matches!(e, NetworkEvent::NewAddress(a) if a.address() == Some(&IpAddr::V4(Ipv4Addr::new(10, 93, 0, 1))))
    })
    .await?;
    assert_eq!(meta.portid, conn.socket().pid());
    assert!(!meta.is_kernel() && meta.seq != 0, "{meta:?}");

    conn.add_link(VethLink::new("v0", "v1")).await?;
    conn.set_link_up("v0").await?;
    conn.set_link_up("v1").await?;
    conn.set_link_down("v1").await?;
    let (meta, _) = expect_event(&mut events, Duration::from_secs(5), "v0 losing carrier, from the kernel", |(m, e): &(EventMeta, NetworkEvent)| {
        m.is_kernel() && matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("v0"))
    })
    .await?;
    assert_eq!((meta.portid, meta.seq), (0, 0));
    Ok(())
}

/// A factory for `ns` that fails its first `failures` calls.
fn flaky_factory(
    ns: &TestNamespace,
    failures: u32,
) -> (
    nlink::netlink::resync::ConnectionFactory<nlink::netlink::Route>,
    std::sync::Arc<std::sync::atomic::AtomicU32>,
) {
    use std::sync::atomic::Ordering;
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let counted = calls.clone();
    let name = ns.name().to_string();
    let factory: nlink::netlink::resync::ConnectionFactory<nlink::netlink::Route> =
        std::sync::Arc::new(move || {
            let n = counted.fetch_add(1, Ordering::SeqCst);
            let name = name.clone();
            Box::pin(async move {
                if n < failures {
                    return Err(nlink::Error::invalid_message(format!("attempt {n} fails")));
                }
                nlink::Connection::new_in(&name)
            })
        });
    (factory, calls)
}

/// #523: a restarting stream reports each failure and tries again, and
/// once a connection comes up it starts as a resync stream does — the
/// initial snapshot, then live events.
#[tokio::test]
async fn a_restarting_stream_starts_again_after_failures() -> Result<()> {
    use nlink::netlink::Connection;
    use nlink::netlink::resync::{Backoff, ResyncedEvent};
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("restart")?;
    let (factory, calls) = flaky_factory(&ns, 2);
    let backoff = Backoff::new(Duration::from_millis(10), Duration::from_millis(50));
    let mut stream = Connection::events_restarting(factory, backoff);

    let mut next = async || {
        tokio::time::timeout(WITHIN, stream.next())
            .await
            .expect("an item")
            .expect("the stream goes on")
    };
    for n in 0..2 {
        let err = next().await.expect_err("the factory fails");
        assert!(err.to_string().contains(&format!("attempt {n}")), "{err}");
    }
    assert!(next().await?.is_initial_sync_start());
    while !next().await?.is_resync_end() {}

    ns.connection()?.add_link(DummyLink::new("d0")).await?;
    loop {
        if let ResyncedEvent::Event(NetworkEvent::NewLink(l)) = next().await?
            && l.name() == Some("d0")
        {
            break;
        }
    }
    // Two failures, the stream's connection, and the snapshot's.
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 4);
    Ok(())
}

/// #523: no restart brings back a deleted namespace, so the restarting
/// stream ends with `NamespaceDeleted` instead of retrying forever.
#[tokio::test]
async fn a_restarting_stream_ends_when_its_namespace_is_deleted() -> Result<()> {
    use nlink::netlink::Connection;
    use nlink::netlink::namespace;
    use nlink::netlink::resync::Backoff;
    use tokio_stream::StreamExt;
    require_root!();

    let ns = TestNamespace::new("restart-del")?;
    let (factory, _) = flaky_factory(&ns, 0);
    let backoff = Backoff::new(Duration::from_millis(10), Duration::from_millis(50));
    let mut stream = Connection::events_restarting(factory, backoff);
    let first = stream.next().await.expect("an item")?;
    assert!(first.is_initial_sync_start(), "{first:?}");
    while !stream.next().await.expect("an item")?.is_resync_end() {}

    namespace::delete(ns.name())?;
    let end = tokio::time::Instant::now() + WITHIN;
    let err = loop {
        match tokio::time::timeout_at(end, stream.next()).await {
            Ok(Some(Ok(_))) => continue,
            Ok(Some(Err(e))) => break e,
            Ok(None) => panic!("the stream ended without an error"),
            Err(_) => panic!("nothing within {WITHIN:?} of the deletion"),
        }
    };
    assert!(err.is_namespace_deleted(), "{err}");
    let after = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
    assert!(
        matches!(after, Ok(None)),
        "the stream should end, not restart: {after:?}"
    );
    Ok(())
}

/// #523: a link deleted while the socket was overflowing is in no event —
/// the overflow dropped its `DelLink` — and a snapshot only says what
/// exists. `with_gap_deltas` reports it as a `Resynced(DelLink)`, so a
/// mirror that applies events as they come, and never clears itself,
/// still ends equal to the kernel.
#[tokio::test]
async fn gap_deltas_report_a_link_deleted_during_an_overflow() -> Result<()> {
    use nlink::netlink::resync::ResyncedEvent;
    use nlink::netlink::resync_ext::ResyncStreamExt;
    use std::collections::BTreeSet;
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("gap")?;
    let other = ns.connection()?;
    other.add_link(DummyLink::new("gone")).await?;
    let (factory, _) = flaky_factory(&ns, 0);
    let conn = ns.connection()?;
    conn.socket().set_rcvbuf(1024)?;
    let mut stream = conn
        .into_events_with_resync(factory)
        .await?
        .with_gap_deltas(NetworkEvent::object_key);

    let mut mirror: BTreeSet<String> = BTreeSet::new();
    let mut gap_del = false;
    let mut apply = |item: ResyncedEvent<NetworkEvent>, mirror: &mut BTreeSet<String>| {
        match item {
            ResyncedEvent::Event(NetworkEvent::NewLink(l))
            | ResyncedEvent::Resynced(NetworkEvent::NewLink(l)) => {
                mirror.extend(l.name().map(str::to_string));
            }
            ResyncedEvent::Event(NetworkEvent::DelLink(l)) => {
                mirror.remove(l.name().unwrap_or_default());
            }
            ResyncedEvent::Resynced(NetworkEvent::DelLink(l)) => {
                gap_del |= l.name() == Some("gone");
                mirror.remove(l.name().unwrap_or_default());
            }
            _ => {}
        }
    };
    // The initial snapshot, read in full before the burst.
    loop {
        let item = stream.next().await.expect("an item")?;
        let end = item.is_resync_end();
        apply(item, &mut mirror);
        if end {
            break;
        }
    }
    assert!(mirror.contains("gone"), "{mirror:?}");

    // Overflow the 1 KiB buffer, reading nothing, then delete the link:
    // its DelLink has nowhere to go.
    for i in 1..=100 {
        other.add_link(DummyLink::new(format!("t{i}").as_str())).await?;
    }
    other.del_link("gone").await?;

    loop {
        let next = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
        let Ok(Some(item)) = next else { break };
        apply(item?, &mut mirror);
    }
    assert!(gap_del, "no Resynced(DelLink) for the link deleted in the gap");
    let fresh: BTreeSet<String> = ns
        .connection()?
        .get_links()
        .await?
        .iter()
        .filter_map(|l| l.name().map(str::to_string))
        .collect();
    assert_eq!(mirror, fresh);
    Ok(())
}

/// Wait for the first item of `key` matching `want`, from a watch.
async fn watch_until<K: Clone + std::hash::Hash + Eq + Unpin + std::fmt::Debug>(
    watch: &mut nlink::facade::watch::MultiNsWatch<K>,
    mut want: impl FnMut(&K, &nlink::facade::watch::NsEvent) -> bool,
) -> (K, nlink::facade::watch::NsEvent) {
    use tokio_stream::StreamExt;
    let end = tokio::time::Instant::now() + WITHIN;
    loop {
        match tokio::time::timeout_at(end, watch.next()).await {
            Ok(Some((key, event))) if want(&key, &event) => return (key, event),
            Ok(Some(_)) => {}
            Ok(None) => panic!("the watch ended"),
            Err(_) => panic!("no matching item within {WITHIN:?}"),
        }
    }
}

/// #523: one stream for many namespaces and both families. Each
/// namespace's events come under its key; a deleted namespace yields
/// `Gone` and leaves the watch, and the others go on.
#[tokio::test]
async fn a_multi_namespace_watch_follows_namespaces_until_they_go() -> Result<()> {
    use nlink::facade::watch::{Families, MultiNsWatch, NsEvent};
    use nlink::netlink::namespace::{self, Netns};
    use nlink::netlink::nftables::{Family, NftablesEvent};
    use nlink::netlink::resync::{Backoff, ResyncMarker, ResyncedEvent};
    use nlink::netlink::Nftables;
    require_root!();
    nlink::require_modules!("dummy", "nf_tables");

    let a = TestNamespace::new("mnw-a")?;
    let b = TestNamespace::new("mnw-b")?;
    let mut watch = MultiNsWatch::new(Families::ROUTE | Families::NFTABLES)
        .backoff(Backoff::new(Duration::from_millis(10), Duration::from_millis(50)));
    watch.add("a", &Netns::open(a.name())?)?;
    watch.add("b", &Netns::open(b.name())?)?;
    assert_eq!(watch.len(), 2);

    // Four initial snapshots: two namespaces, two families each.
    let mut ends = std::collections::BTreeSet::new();
    while ends.len() < 4 {
        let (key, event) = watch_until(&mut watch, |_, _| true).await;
        match event {
            NsEvent::Route(ResyncedEvent::Marker(ResyncMarker::ResyncEnd)) => {
                ends.insert((key, "route"));
            }
            NsEvent::Nftables(ResyncedEvent::Marker(ResyncMarker::ResyncEnd)) => {
                ends.insert((key, "nftables"));
            }
            NsEvent::Error(e) | NsEvent::Gone(e) => panic!("{key}: {e}"),
            _ => {}
        }
    }

    a.connection()?.add_link(DummyLink::new("d0")).await?;
    let (key, _) = watch_until(&mut watch, |_, e| {
        matches!(e, NsEvent::Route(ResyncedEvent::Event(NetworkEvent::NewLink(l))) if l.name() == Some("d0"))
    })
    .await;
    assert_eq!(key, "a");

    b.connection_for::<Nftables>()?.add_table("t", Family::Inet).await?;
    let (key, _) = watch_until(&mut watch, |_, e| {
        matches!(e, NsEvent::Nftables(ResyncedEvent::Event(NftablesEvent::NewTable(t))) if t.name == "t")
    })
    .await;
    assert_eq!(key, "b");

    namespace::delete(b.name())?;
    let (key, event) = watch_until(&mut watch, |_, e| matches!(e, NsEvent::Gone(_))).await;
    assert_eq!(key, "b");
    let NsEvent::Gone(why) = event else { unreachable!() };
    assert!(why.is_namespace_deleted(), "{why}");
    assert!(!watch.contains(&"b"), "a gone namespace leaves the watch");
    assert_eq!(watch.len(), 1);

    // The other namespace is still watched.
    a.connection()?.add_link(DummyLink::new("d1")).await?;
    let (key, _) = watch_until(&mut watch, |_, e| {
        matches!(e, NsEvent::Route(ResyncedEvent::Event(NetworkEvent::NewLink(l))) if l.name() == Some("d1"))
    })
    .await;
    assert_eq!(key, "a");
    Ok(())
}

/// #523: the control messages of a notification say which group it was
/// sent to and, on a connection listening to every namespace, which
/// namespace it happened in — by the id the listener's namespace gave it.
#[tokio::test]
async fn an_event_says_which_group_and_namespace_it_came_from() -> Result<()> {
    use nlink::netlink::EventMeta;
    nlink::require_root!();
    // NETLINK_LISTEN_ALL_NSID needs CAP_NET_BROADCAST, which the rootless
    // CI container is not granted.
    nlink::require_host_root!();
    nlink::require_module!("dummy");

    let a = TestNamespace::new("meta-nsid-a")?;
    let b = TestNamespace::new("meta-nsid-b")?;
    let watch = a.connection()?;
    let b_fd = std::fs::File::open(format!("/var/run/netns/{}", b.name()))?;
    watch.set_nsid(&b_fd, 42).await?;
    watch.listen_all_nsid(true)?;
    watch.subscribe(&[RtnetlinkGroup::Link, RtnetlinkGroup::Ipv4Addr])?;
    let mut events = watch.events().await.with_meta();

    a.connection()?.add_link(DummyLink::new("in-a")).await?;
    let (meta, _) = expect_event(&mut events, WITHIN, "a's own link", |(_, e): &(EventMeta, NetworkEvent)| {
        matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("in-a"))
    })
    .await?;
    assert_eq!((meta.group, meta.nsid), (Some(1), None), "RTNLGRP_LINK, here: {meta:?}");

    let conn_b = b.connection()?;
    conn_b.add_link(DummyLink::new("in-b")).await?;
    let (meta, _) = expect_event(&mut events, WITHIN, "b's link, seen from a", |(_, e): &(EventMeta, NetworkEvent)| {
        matches!(e, NetworkEvent::NewLink(l) if l.name() == Some("in-b"))
    })
    .await?;
    assert_eq!((meta.group, meta.nsid), (Some(1), Some(42)), "{meta:?}");

    conn_b
        .add_address(Ipv4Address::new("in-b", Ipv4Addr::new(10, 94, 0, 1), 24))
        .await?;
    let (meta, _) = expect_event(&mut events, WITHIN, "b's address", |(_, e): &(EventMeta, NetworkEvent)| {
        matches!(e, NetworkEvent::NewAddress(_))
    })
    .await?;
    assert_eq!((meta.group, meta.nsid), (Some(5), Some(42)), "RTNLGRP_IPV4_IFADDR: {meta:?}");
    Ok(())
}
