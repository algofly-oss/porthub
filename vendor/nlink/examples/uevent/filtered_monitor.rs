//! Monitor device hotplug events with a kernel-side prefilter (#251).
//!
//! Without a filter, a monitor interested in one subsystem is still
//! woken for every USB, block, input and thermal event on the box,
//! copies each one into userspace and parses it before discarding it.
//! `UeventFilter` lowers what it can into classic BPF and attaches it
//! with `SO_ATTACH_FILTER`, so the kernel drops the rest.
//!
//! Run with:
//!   cargo run -p nlink --example uevent_filtered_monitor -- [subsystem]
//!
//! Then provoke some events — `ip link add dummy0 type dummy` for the
//! default `net` subsystem, or plug in a USB device and pass `usb`.

use nlink::netlink::{Connection, KobjectUevent, uevent_filter::UeventFilter};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let subsystem = std::env::args().nth(1).unwrap_or_else(|| "net".to_string());

    let filter = UeventFilter::new()
        .subsystem(&subsystem)
        .action("add")
        .action("remove")
        .action("change")
        .build();

    let conn = Connection::<KobjectUevent>::new()?;

    // What the kernel actually granted. An unprivileged monitor is
    // capped at net.core.rmem_max; the figure is the kernel's
    // sk_rcvbuf, i.e. twice the accepted request.
    println!("receive buffer: {} bytes", conn.rcvbuf()?);

    let compiled = conn.attach_filter(&filter)?;
    println!(
        "attached filter: {} instructions, {}",
        compiled.len(),
        if compiled.is_exact() {
            "every criterion evaluated in-kernel"
        } else {
            "some criteria left to the userspace backstop"
        }
    );
    println!("watching subsystem={subsystem} for add/remove/change\n");

    loop {
        // recv_matching applies UeventFilter::matches to whatever the
        // kernel let through — the compiled program over-accepts by
        // design, so this is what makes the result exact.
        let event = conn.recv_matching(&filter).await?;

        println!(
            "[{}] {} ({})",
            event.action.to_uppercase(),
            event.devpath,
            event.subsystem
        );
        if let Some(devname) = event.devname() {
            println!("  device: {devname}");
        }
        if let Some(ifindex) = event.env.get("IFINDEX") {
            println!("  ifindex: {ifindex}");
        }
        println!();
    }
}
