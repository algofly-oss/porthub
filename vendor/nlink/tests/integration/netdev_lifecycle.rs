//! #253 — the rtnetlink + uevent netdev lifecycle join, against a
//! real kernel.
//!
//! The unit tests in `netlink::netdev` pin the join's *logic* by
//! feeding both sides by hand. What they cannot pin is that the two
//! sockets deliver what the join assumes: that a net uevent inside a
//! namespace carries `IFINDEX=` and `INTERFACE=`, that it reaches a
//! socket opened in that namespace at all, and that the ifindex it
//! names is the one rtnetlink reports. Those are kernel facts, and
//! they are what this file checks.

use std::time::Duration;

use nlink::{
    Result,
    netlink::{
        Connection, KobjectUevent, RtnetlinkGroup,
        link::VethLink,
        netdev::{NetdevEvent, NetdevInfo, NetdevLifecycle},
        reflector::Store,
        uevent_filter::UeventFilter,
    },
};
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

/// How long to wait for both halves of a device to arrive. The
/// rtnetlink half is immediate; the uevent half goes through the
/// kernel's uevent worker, so it can lag by a scheduling quantum or
/// two under load.
const SETTLE: Duration = Duration::from_secs(5);

#[tokio::test]
async fn netdev_lifecycle_joins_uevents_with_rtnetlink() -> Result<()> {
    require_root!();
    nlink::require_module!("veth");

    let ns = TestNamespace::new("netdevlc")?;

    let links = ns.connection()?;
    links.subscribe(&[RtnetlinkGroup::Link])?;

    // Opened *in the namespace*: net uevents are delivered to the
    // netns of the listening socket, so a host-side socket would see
    // nothing for these devices.
    let uevents = Connection::<KobjectUevent>::in_namespace(ns.name())?;
    let compiled = uevents.attach_filter(&UeventFilter::new().subsystem("net").build())?;
    assert!(
        compiled.is_exact(),
        "a subsystem-only filter should lower entirely into the kernel"
    );

    let store: Store<u32, NetdevInfo> = Store::new();
    let mut lifecycle = NetdevLifecycle::new(links.events().await, uevents.events().await)
        .with_store(store.clone());

    // A third connection: the two above are holding their event
    // streams, which take the connection lock for their lifetime.
    let ctl = ns.connection()?;
    ctl.add_link(VethLink::new("lcvet0", "lcvet1")).await?;
    // A kind that sets DEVTYPE=, to pin what the uevent side really
    // carries (#328): devtype yes, driver no.
    ctl.add_link(nlink::netlink::link::BridgeLink::new("lcbr0")).await?;

    let mut added = Vec::new();
    let mut attributed = Vec::new();
    let mut bridge_devtype: Option<Option<String>> = None;
    let deadline = tokio::time::Instant::now() + SETTLE;

    while tokio::time::Instant::now() < deadline {
        let Ok(Some(event)) =
            tokio::time::timeout_at(deadline, lifecycle.next()).await
        else {
            break;
        };
        match event? {
            NetdevEvent::Added(info) | NetdevEvent::Changed(info) => {
                let Some(name) = info.name().map(str::to_string) else {
                    continue;
                };
                if name == "lcbr0" && info.is_fully_attributed() {
                    bridge_devtype = Some(info.devtype().map(str::to_string));
                    assert!(info.driver().is_none(), "no DRIVER= on a bridge either");
                }
                if !name.starts_with("lcvet") {
                    continue;
                }
                if !added.contains(&name) {
                    added.push(name.clone());
                }
                if info.is_fully_attributed() && !attributed.contains(&name) {
                    // The point of the join: rtnetlink's ifindex and
                    // name, plus the uevent's devpath, on one value.
                    assert!(
                        info.devpath().is_some_and(|p| p.ends_with(&name)),
                        "devpath {:?} does not name {name}",
                        info.devpath()
                    );
                    assert!(info.ifindex() > 0);
                    // What the kernel really sends for a net device:
                    // no DRIVER= (the driver binds to the bus parent,
                    // and a veth has none), no DEVTYPE= (veth does not
                    // set one). The recipe claimed DRIVER= until #328.
                    assert!(
                        info.driver().is_none(),
                        "net uevents carry no DRIVER=; got {:?}",
                        info.driver()
                    );
                    assert!(info.devtype().is_none(), "veth sets no DEVTYPE=");
                    attributed.push(name);
                }
            }
            _ => {}
        }
        if attributed.len() == 2 && bridge_devtype.is_some() {
            break;
        }
    }

    assert_eq!(
        bridge_devtype,
        Some(Some("bridge".to_string())),
        "DEVTYPE=bridge is what the uevent side does carry"
    );

    added.sort();
    assert_eq!(
        added,
        vec!["lcvet0".to_string(), "lcvet1".to_string()],
        "rtnetlink should announce both ends of the pair"
    );

    attributed.sort();
    assert_eq!(
        attributed,
        vec!["lcvet0".to_string(), "lcvet1".to_string()],
        "both ends should end up joined with their uevent annotation"
    );

    // The store mirrors what the stream yielded.
    for (_, info) in store.snapshot() {
        if info.name().is_some_and(|n| n.starts_with("lcvet")) {
            assert!(info.annotation().is_some());
        }
    }

    Ok(())
}

/// Removal must clear the annotation as well as the device, so a
/// recycled ifindex cannot inherit it. Checked here rather than only
/// in the unit tests because it depends on rtnetlink actually
/// emitting `RTM_DELLINK` for both ends of a veth pair.
#[tokio::test]
async fn removal_evicts_the_device_from_the_store() -> Result<()> {
    require_root!();
    nlink::require_module!("veth");

    let ns = TestNamespace::new("netdevrm")?;

    let links = ns.connection()?;
    links.subscribe(&[RtnetlinkGroup::Link])?;
    let uevents = Connection::<KobjectUevent>::in_namespace(ns.name())?;

    let store: Store<u32, NetdevInfo> = Store::new();
    let mut lifecycle = NetdevLifecycle::new(links.events().await, uevents.events().await)
        .with_store(store.clone());

    let ctl = ns.connection()?;
    ctl.add_link(VethLink::new("rmvet0", "rmvet1")).await?;

    let deadline = tokio::time::Instant::now() + SETTLE;
    let mut ifindex = None;
    while ifindex.is_none() && tokio::time::Instant::now() < deadline {
        let Ok(Some(event)) = tokio::time::timeout_at(deadline, lifecycle.next()).await else {
            break;
        };
        if let NetdevEvent::Added(info) = event?
            && info.name() == Some("rmvet0")
        {
            ifindex = Some(info.ifindex());
        }
    }
    let ifindex = ifindex.expect("rmvet0 should have been announced");
    assert!(store.contains_key(&ifindex));

    ctl.del_link("rmvet0").await?;

    let deadline = tokio::time::Instant::now() + SETTLE;
    let mut removed = false;
    while !removed && tokio::time::Instant::now() < deadline {
        let Ok(Some(event)) = tokio::time::timeout_at(deadline, lifecycle.next()).await else {
            break;
        };
        if let NetdevEvent::Removed { ifindex: gone, .. } = event?
            && gone == ifindex
        {
            removed = true;
        }
    }

    assert!(removed, "RTM_DELLINK for rmvet0 was never observed");
    assert!(
        !store.contains_key(&ifindex),
        "the store still holds the removed device"
    );

    Ok(())
}

/// #510: fed a resync stream, the join starts from the initial snapshot,
/// so a device that existed before it subscribed is in the store; a plain
/// stream could not be fed in, and would never have announced it.
#[tokio::test]
async fn a_resync_stream_announces_devices_that_predate_the_join() -> Result<()> {
    use nlink::netlink::{Route, resync::ConnectionFactory};
    use std::sync::Arc;
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("netdevrs")?;
    ns.exec("ip", &["link", "add", "early0", "type", "dummy"])?;

    let name = ns.name().to_string();
    let factory: ConnectionFactory<Route> = Arc::new(move || {
        let name = name.clone();
        Box::pin(async move { nlink::Connection::<Route>::new_in(&name) })
    });
    let links = ns.connection()?.into_events_with_resync(factory).await?;
    let uevents = Connection::<KobjectUevent>::in_namespace(ns.name())?;
    let store: Store<u32, NetdevInfo> = Store::new();
    let mut lifecycle =
        NetdevLifecycle::new(links, uevents.events().await).with_store(store.clone());

    let announced = |store: &Store<u32, NetdevInfo>, name: &str| {
        store.values().iter().any(|info| info.name() == Some(name))
    };
    let deadline = tokio::time::Instant::now() + SETTLE;
    while !(announced(&store, "lo") && announced(&store, "early0")) {
        let Ok(Some(event)) = tokio::time::timeout_at(deadline, lifecycle.next()).await else {
            break;
        };
        event?;
    }
    assert!(announced(&store, "lo"), "lo is in the initial snapshot");
    assert!(
        announced(&store, "early0"),
        "a device created before the join is in the initial snapshot"
    );

    // Live events still flow after the snapshot.
    ns.connection()?
        .add_link(nlink::netlink::link::DummyLink::new("late0"))
        .await?;
    let deadline = tokio::time::Instant::now() + SETTLE;
    while !announced(&store, "late0") {
        let Ok(Some(event)) = tokio::time::timeout_at(deadline, lifecycle.next()).await else {
            break;
        };
        event?;
    }
    assert!(
        announced(&store, "late0"),
        "a live NewLink after the snapshot"
    );
    Ok(())
}
