//! ENOBUFS-resync loop (Plan 151 — `ResyncedEvent` + `ResyncMarker`).
//!
//! Run: `cargo run --example events_resync_loop`
//! (Ctrl-C to stop; for a forced ENOBUFS trigger run as root with
//!  a busy event source in another terminal, e.g.
//!  `while true; do ip link add d0 type dummy; ip link del d0; done`)
//!
//! Demonstrates the hand-rolled loop pattern from
//! `docs/recipes/events-with-resync.md`: when the kernel reports
//! ENOBUFS (event-channel overflow), the consumer must
//! re-snapshot state to recover from the lost-event gap. The
//! library provides:
//!
//!   - `ResyncedEvent<T> { Event(T), Resynced, Marker }` —
//!     normal events vs the resync signal vs the post-resync
//!     marker.
//!   - `ResyncMarker` — sentinel emitted once after a successful
//!     re-snapshot, so consumers know "you're caught up; resume
//!     event processing."
//!
//! The library's events stream emits `Result<NetworkEvent>` —
//! the recovery glue is the consumer's responsibility (kept as a
//! 0.16-shape "explicit loop, no surprises" pattern; a pre-baked
//! `events_with_resync()` Stream wrapper is deferred to 0.17 for
//! design soak).

use std::time::Duration;

use nlink::netlink::{Connection, Route, RtnetlinkGroup};
use nlink::netlink::resync::{ResyncedEvent, ResyncMarker};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;
    conn.subscribe(&[RtnetlinkGroup::Link])?;

    println!("subscribed to RTNLGRP_LINK; Ctrl-C to exit");
    println!("event ENOBUFS will trigger an automatic re-snapshot");

    let mut events = conn.events().await;
    let mut event_count = 0usize;
    let mut resync_count = 0usize;

    // Bounded run so the example terminates without external
    // intervention. Production code: `while let Some(...)`.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);

    while std::time::Instant::now() < deadline {
        let evt = tokio::select! {
            evt = events.next() => evt,
            _ = tokio::time::sleep(Duration::from_millis(500)) => continue,
        };
        let Some(result) = evt else { break };
        match result {
            Ok(event) => {
                event_count += 1;
                println!("event {event_count}: {event:?}");
            }
            Err(e) if matches!(e.errno(), Some(libc::ENOBUFS)) => {
                resync_count += 1;
                println!(
                    "\n*** ENOBUFS — events dropped; resync count = {} ***",
                    resync_count,
                );
                // Re-snapshot. In a production app this might be a
                // full `get_links()` call to rebuild local state.
                // ResyncedEvent::Resynced + ResyncMarker mark the
                // boundary so a downstream consumer can know "treat
                // the next batch as a fresh state replay."
                // ResyncMarker::ResyncStart → snapshot →
                // Resynced(item) per replayed object →
                // ResyncMarker::ResyncEnd. Downstream consumers
                // use the markers as gap boundaries.
                let snapshot: Vec<ResyncedEvent<()>> = vec![
                    ResyncedEvent::Marker(ResyncMarker::ResyncStart),
                    // ... (real resync would replay current state via
                    //      ResyncedEvent::Resynced(item) per object) ...
                    ResyncedEvent::Marker(ResyncMarker::ResyncEnd),
                ];
                for s in snapshot {
                    println!("  resync signal: {s:?}");
                }
                println!("*** resumed normal event loop ***\n");
            }
            Err(e) => {
                eprintln!("event error: {e}");
                break;
            }
        }
    }

    println!(
        "\ntotals: {event_count} events, {resync_count} ENOBUFS recoveries",
    );
    Ok(())
}
