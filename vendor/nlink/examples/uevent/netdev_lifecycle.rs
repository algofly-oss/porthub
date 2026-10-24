//! Joined rtnetlink + uevent device lifecycle, with a watch-cache
//! (#253).
//!
//! rtnetlink knows a device's ifindex, flags, MTU and kind but nothing
//! about its driver or sysfs path; uevents know the driver and devpath
//! but carry no link attributes. Net uevents carry `IFINDEX=`, so the
//! two can be joined on a shared key — which is what
//! `NetdevLifecycle` does, mirroring the result into a `Store` keyed
//! by ifindex.
//!
//! Run with: cargo run -p nlink --example uevent_netdev_lifecycle
//!
//! Then, in another terminal:
//!   sudo ip link add dummy0 type dummy
//!   sudo ip link set dummy0 up
//!   sudo ip link del dummy0

use std::{sync::Arc, time::Duration};

use nlink::netlink::{
    Connection, KobjectUevent, NetworkEvent, Route, RtnetlinkGroup,
    netdev::{NetdevEvent, NetdevInfo, NetdevLifecycle},
    reflector::Store,
    resync::events_with_resync,
    uevent_filter::UeventFilter,
};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let links = Connection::<Route>::new()?;
    links.subscribe(&[RtnetlinkGroup::Link])?;
    // Snapshots of the links, on a second connection: one to start
    // from, and one after any overflow, so the cache keeps the right
    // set of devices (#510).
    let dumper = Arc::new(Connection::<Route>::new()?);
    let links = events_with_resync(links.events().await, move || {
        let dumper = dumper.clone();
        Box::pin(async move {
            let links = dumper.get_links().await?;
            Ok(links.into_iter().map(NetworkEvent::NewLink).collect())
        })
    })
    .initial_snapshot(true);

    let uevents = Connection::<KobjectUevent>::new()?;
    // Shed every non-net uevent kernel-side, so this process is not
    // woken for USB, block and thermal traffic it would only discard.
    let compiled = uevents.attach_filter(&UeventFilter::new().subsystem("net").build())?;
    println!(
        "uevent prefilter: {} instructions, rcvbuf {} bytes",
        compiled.len(),
        uevents.rcvbuf()?
    );

    // The store is cheap to clone and shares its map, so hand clones
    // to readers while this task drives the stream.
    let store: Store<u32, NetdevInfo> = Store::new();
    let mut lifecycle =
        NetdevLifecycle::new(links, uevents.events().await).with_store(store.clone());

    // A reader: prints the cache every few seconds, entirely
    // independent of the stream above.
    let reader = store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let mut devices = reader.snapshot();
            devices.sort_by_key(|(ifindex, _)| *ifindex);
            println!("\n--- cache: {} devices ---", devices.len());
            for (ifindex, info) in devices {
                println!(
                    "  {ifindex:>3} {:<16} driver={:<10} attributed={}",
                    info.name().unwrap_or("?"),
                    info.driver().unwrap_or("-"),
                    info.is_fully_attributed()
                );
            }
            println!();
        }
    });

    println!("watching netdev lifecycle; Ctrl+C to exit\n");

    while let Some(event) = lifecycle.next().await {
        match event? {
            NetdevEvent::Added(info) => println!(
                "ADDED    {:>3} {} driver={:?} devpath={:?}",
                info.ifindex(),
                info.name().unwrap_or("?"),
                info.driver(),
                info.devpath(),
            ),
            NetdevEvent::Changed(info) => println!(
                "CHANGED  {:>3} {} devtype={:?} devpath={:?} attributed={}",
                info.ifindex(),
                info.name().unwrap_or("?"),
                info.devtype(),
                info.devpath(),
                info.is_fully_attributed(),
            ),
            // No rtnetlink counterpart exists for these, so they can
            // arrive for a device no ADDED was printed for.
            NetdevEvent::DriverBound { ifindex, annotation } => {
                println!("BOUND    {ifindex:>3} driver={:?}", annotation.driver)
            }
            NetdevEvent::DriverUnbound { ifindex, annotation } => {
                println!("UNBOUND  {ifindex:>3} driver={:?}", annotation.driver)
            }
            NetdevEvent::Removed { ifindex, name } => {
                println!("REMOVED  {ifindex:>3} {}", name.unwrap_or_default())
            }
            other => println!("{other:?}"),
        }
    }

    Ok(())
}
