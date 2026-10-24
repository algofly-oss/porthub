//! MPTCP path-manager wiring — #275.
//!
//! `MptcpEndpointBuilder::dev(name)` was documented as "the device name
//! will be resolved to an interface index" and resolved nothing: the
//! field had no read site and the writer emitted `IF_IDX` only from the
//! separate `ifindex`. An endpoint built the way the crate's own
//! example built one reached the kernel with **no interface binding**.
//!
//! The setter is gone rather than wired up — a `Connection<Mptcp>`
//! cannot resolve a name in its own netns, and resolving it in the
//! calling process's would bind the endpoint to a different interface
//! entirely. These tests pin the replacement, and settle the open
//! question about `MPTCP_PM_ADDR_ATTR_PORT`'s byte order by asking an
//! independent reader.

use std::net::Ipv4Addr;

use nlink::{
    Result,
    netlink::{Mptcp, genl::mptcp::MptcpEndpointBuilder, link::DummyLink},
};

use crate::common::TestNamespace;

#[tokio::test]
async fn endpoint_binds_to_the_interface_it_names() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("mptcppm")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("mp0")).await?;
    conn.set_link_up("mp0").await?;
    conn.add_address(nlink::netlink::addr::Ipv4Address::new(
        "mp0",
        Ipv4Addr::new(10, 9, 9, 1),
        24,
    ))
    .await?;

    // Resolved through a connection in *this* namespace, which is the
    // whole point of taking an index rather than a name.
    let want = conn
        .get_link_by_name("mp0")
        .await?
        .expect("mp0 exists")
        .ifindex();

    let mptcp: nlink::Connection<Mptcp> = match ns.connection_for_async().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Skipping test: MPTCP path manager unavailable ({e})");
            return Ok(());
        }
    };

    mptcp
        .add_endpoint(
            MptcpEndpointBuilder::new(Ipv4Addr::new(10, 9, 9, 1).into())
                .id(1)
                .ifindex(want)
                .port(8080)
                .signal(),
        )
        .await?;

    let endpoints = mptcp.get_endpoints().await?;
    let ep = endpoints
        .iter()
        .find(|e| e.address == std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 9, 1)))
        .expect("endpoint installed");

    assert_eq!(
        ep.ifindex,
        Some(want),
        "endpoint reached the kernel with no interface binding (#275)"
    );
    Ok(())
}

/// `MPTCP_PM_ADDR_ATTR_PORT` was flagged at medium confidence: nlink
/// writes it with `to_be_bytes` and reads it back with `from_be_bytes`,
/// so a byte swap would be **invisible to nlink alone** — it would
/// round-trip perfectly while the kernel held 36895 for a requested
/// 8080.
///
/// The only way to settle that is an independent reader, so this asks
/// `ip mptcp endpoint show` what the kernel actually stored.
#[tokio::test]
async fn endpoint_port_is_the_port_the_kernel_stores() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("mptcpport")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("mp0")).await?;
    conn.set_link_up("mp0").await?;
    conn.add_address(nlink::netlink::addr::Ipv4Address::new(
        "mp0",
        Ipv4Addr::new(10, 9, 8, 1),
        24,
    ))
    .await?;

    let mptcp: nlink::Connection<Mptcp> = match ns.connection_for_async().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Skipping test: MPTCP path manager unavailable ({e})");
            return Ok(());
        }
    };

    mptcp
        .add_endpoint(
            MptcpEndpointBuilder::new(Ipv4Addr::new(10, 9, 8, 1).into())
                .id(1)
                .port(8080)
                .signal(),
        )
        .await?;

    // nlink's own view — symmetric, so this proves nothing on its own.
    let endpoints = mptcp.get_endpoints().await?;
    let ep = endpoints
        .iter()
        .find(|e| e.address == std::net::IpAddr::V4(Ipv4Addr::new(10, 9, 8, 1)))
        .expect("endpoint installed");
    assert_eq!(ep.port, Some(8080), "port did not round-trip through nlink");

    // The independent reader.
    let shown = match ns.exec("ip", &["mptcp", "endpoint", "show"]) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("Skipping cross-check: `ip mptcp` unavailable ({e})");
            return Ok(());
        }
    };
    assert!(
        shown.contains("port 8080"),
        "iproute2 reads a different port than nlink asked for — nlink is \
         byte-swapping it symmetrically and only looks correct to itself. \
         `ip mptcp endpoint show` said: {shown}"
    );
    Ok(())
}
