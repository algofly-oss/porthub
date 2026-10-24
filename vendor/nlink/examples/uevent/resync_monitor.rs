//! ENOBUFS-resilient uevent monitor via re-enumeration (#252).
//!
//! Uevents are the crate's only event source with no dump command, so
//! `events_with_resync` has nothing to put in its redump factory. The
//! kernel's substitute is `/sys/.../uevent`: writing an action there
//! re-broadcasts the device's uevent.
//!
//! Read the caveats in `nlink::util::uevent_trigger` before copying
//! this. Two of them are visible right here:
//!
//! * the trigger needs root, while *reading* uevents does not — so the
//!   recovery path is more privileged than the stream it repairs, and
//!   this example checks that at startup rather than at overflow time;
//! * `ResyncEnd` on this stream does **not** mean "state rebuilt". The
//!   re-announcements arrive afterwards as ordinary live events.
//!
//! Run with:
//!   cargo run -p nlink --example uevent_resync_monitor
//!
//! Then, as root: `udevadm trigger --subsystem-match=net` or
//! `ip link add dummy0 type dummy`.

use std::pin::pin;

use nlink::{
    netlink::{
        Connection, KobjectUevent,
        resync::{ResyncMarker, ResyncedEvent, events_with_resync},
        uevent_filter::UeventFilter,
    },
    util::uevent_trigger::{TriggerAction, UeventTrigger},
};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let trigger = UeventTrigger::new()
        .action(TriggerAction::Change)
        // Narrow on purpose: a write to a uevent file broadcasts to
        // every listener on the box, and udevd re-runs its whole rule
        // set for each device triggered. "class/net" is a few dozen
        // devices; "devices" is all of them.
        .build();

    if !trigger.can_trigger() {
        eprintln!(
            "warning: cannot write to sysfs uevent files — run as root, or \
             accept that a dropped uevent is unrecoverable"
        );
    }

    let filter = UeventFilter::new().subsystem("net").build();
    let conn = Connection::<KobjectUevent>::new()?;
    conn.attach_filter(&filter)?;
    println!("receive buffer: {} bytes", conn.rcvbuf()?);

    let events = conn.events().await;
    let mut stream = pin!(events_with_resync(
        events,
        nlink::util::uevent_trigger::resync_factory(trigger, "class/net"),
    ));

    println!("watching net uevents; Ctrl+C to exit\n");

    while let Some(item) = stream.next().await {
        match item? {
            ResyncedEvent::Event(event) => {
                if !filter.matches(&event) {
                    // The kernel program over-accepts by design.
                    continue;
                }
                println!("[{}] {}", event.action.to_uppercase(), event.devpath);
            }
            ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
                println!("-- ENOBUFS: events were dropped, requesting re-announcement --");
            }
            ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
                // NOT "state is rebuilt" — see the module docs. The
                // re-announced events come back through the live
                // stream above, racing with genuinely new ones.
                println!("-- re-announcement requested; replayed events follow inline --");
            }
            ResyncedEvent::Resynced(_) => {
                unreachable!("the uevent resync factory returns no dump items");
            }
            other => println!("-- unhandled resync item: {other:?} --"),
        }
    }

    Ok(())
}
