//! Monitor namespace ID events via netlink.
//!
//! This example demonstrates how to receive RTM_NEWNSID/RTM_DELNSID
//! kernel events when namespace IDs are assigned or released, as
//! `NetworkEvent::{NewNsId, DelNsId}` on an ordinary event stream.
//!
//! Run with: cargo run -p nlink --example namespace_events
//!
//! Then in another terminal:
//!   sudo ip netns add test1
//!   sudo ip netns del test1

use nlink::{Connection, NetworkEvent, Route, RtnetlinkGroup};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> nlink::Result<()> {
    println!("Monitoring namespace ID events (Ctrl+C to stop)...\n");
    println!("Note: Events are triggered when namespace IDs are assigned,");
    println!("which happens when the kernel needs to track a namespace.\n");
    println!("{}", "-".repeat(50));

    let conn = Connection::<Route>::new()?;
    conn.subscribe(&[RtnetlinkGroup::NsId])?;
    let mut events = conn.events().await;

    while let Some(event) = events.next().await {
        match event? {
            NetworkEvent::NewNsId(m) => {
                println!("[+] New namespace ID: {:?}", m.nsid());
                if let Some(p) = m.pid() {
                    println!("    origin: PID {p}");
                }
                if let Some(f) = m.fd() {
                    println!("    origin: fd {f}");
                }
            }
            NetworkEvent::DelNsId(m) => {
                println!("[-] Deleted namespace ID: {:?}", m.nsid());
            }
            _ => {}
        }
    }

    Ok(())
}
