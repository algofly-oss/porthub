//! Reflector / watch-cache demo — `Store<K, V>` + `ReflectExt::reflect`.
//!
//! Keeps an in-memory [`Store`] continuously up to date from a
//! resync-aware event stream (the `kube-rs` reflector pattern), with
//! no extra dependency. This demo drives a **synthetic** stream so it
//! runs deterministically without root or a live netlink socket — it
//! shows the exact semantics (upsert / remove / atomic resync-snapshot
//! swap). The real wiring is one line; see the note at the end.
//!
//!   cargo run --example reflector_watch_cache

use nlink::netlink::reflector::ReflectExt;
use nlink::netlink::resync::{ResyncMarker, ResyncedEvent};
use nlink::{Store, StoreOp};
use tokio_stream::StreamExt;

/// A tiny domain payload standing in for a parsed kernel event. In a
/// real reflector this is `NetworkEvent` (which already encodes
/// add-vs-delete via its `NewLink` / `DelLink` / … variants). The
/// reflector stores the event value itself keyed by `K`, exactly like
/// a real `Store<u32, NetworkEvent>`.
#[derive(Clone, Debug)]
enum IfaceEvent {
    Added { index: u32, name: &'static str },
    Removed { index: u32 },
}

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let store: Store<u32, IfaceEvent> = Store::new();
    let reader = store.clone(); // clones share the backing map

    // A synthetic event sequence: two real-time adds, a remove, then an
    // ENOBUFS resync window whose redump is the new source of truth.
    let events = vec![
        Ok(ResyncedEvent::Event(IfaceEvent::Added { index: 1, name: "eth0" })),
        Ok(ResyncedEvent::Event(IfaceEvent::Added { index: 2, name: "eth1" })),
        Ok(ResyncedEvent::Event(IfaceEvent::Removed { index: 2 })),
        // --- overflow: redump replaces state, doesn't merge into it ---
        Ok(ResyncedEvent::Marker(ResyncMarker::ResyncStart)),
        Ok(ResyncedEvent::Resynced(IfaceEvent::Added { index: 1, name: "eth0" })),
        Ok(ResyncedEvent::Resynced(IfaceEvent::Added { index: 3, name: "wg0" })),
        Ok(ResyncedEvent::Marker(ResyncMarker::ResyncEnd)),
    ];

    // `reflect` updates the store from each item, then re-yields it
    // unchanged (pass-through) — so you can chain combinators or just
    // drain it to keep the cache fresh. Classify each event into a
    // `StoreOp`: the closure is where add-vs-delete is decided.
    let mut watch = tokio_stream::iter(events).reflect(store, |ev| match ev {
        // The matched event value is what gets stored under the key;
        // `Remove` deletes it. `reflect` clones the value into the
        // store and forwards the original event downstream.
        IfaceEvent::Added { index, .. } => StoreOp::Upsert(*index),
        IfaceEvent::Removed { index } => StoreOp::Remove(*index),
    });

    // Drain the pass-through stream (in real code: `tokio::spawn` it).
    while let Some(item) = watch.next().await {
        if let Ok(ResyncedEvent::Marker(m)) = &item {
            println!("-- marker: {m:?} (store now {} entries)", reader.len());
        }
    }

    // The cache reflects post-resync state: eth1 (removed pre-resync and
    // absent from the redump) is gone; wg0 (new in the redump) is present.
    println!("\nfinal cache ({} interfaces):", reader.len());
    for (idx, ev) in reader.snapshot() {
        if let IfaceEvent::Added { name, .. } = ev {
            println!("  if{idx} -> {name}");
        }
    }
    assert_eq!(reader.len(), 2);
    assert!(reader.contains_key(&1) && reader.contains_key(&3));
    assert!(!reader.contains_key(&2));

    println!(
        "\nReal wiring (root + a live socket):\n  \
         let store: Store<u32, NetworkEvent> = Store::new();\n  \
         let watch = conn.into_events_with_resync(factory)?\n      \
         .reflect(store.clone(), |ev| match ev {{\n          \
         NetworkEvent::NewLink(l) => StoreOp::Upsert(l.ifindex()),\n          \
         NetworkEvent::DelLink(l) => StoreOp::Remove(l.ifindex()),\n          \
         _ => StoreOp::Ignore,\n      \
         }});\n  \
         tokio::spawn(async move {{ let mut w = watch; while w.next().await.is_some() {{}} }});\n  \
         // …then read `store` from anywhere."
    );

    Ok(())
}
