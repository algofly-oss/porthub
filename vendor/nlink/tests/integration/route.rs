//! Route integration tests.
//!
//! Tests for route management using network namespaces.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nlink::{
    Connection, Result, Route,
    netlink::{
        addr::Ipv4Address,
        link::DummyLink,
        route::{Ipv4Route, Ipv6Route, NextHop, RouteMetrics},
        types::route::RouteType,
    },
};

use crate::common::TestNamespace;

/// Set up a namespace with a dummy interface and address.
async fn setup_routed_ns(name: &str) -> Result<(TestNamespace, Connection<Route>)> {
    let ns = TestNamespace::new(name)?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add IP address
    conn.add_address(Ipv4Address::new(
        "dummy0",
        Ipv4Addr::new(192, 168, 1, 1),
        24,
    ))
    .await?;

    Ok((ns, conn))
}

#[tokio::test]
async fn test_add_route_via_interface() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rtdev").await?;

    // Add route via interface
    conn.add_route(Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8).dev("dummy0"))
        .await?;

    // Verify route exists
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some(), "route should exist");

    Ok(())
}

#[tokio::test]
async fn test_add_route_via_gateway() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rtgw").await?;

    // Add route via gateway
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .gateway(Ipv4Addr::new(192, 168, 1, 254))
            .dev("dummy0"),
    )
    .await?;

    // Verify route exists with gateway
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());
    assert_eq!(route.unwrap().gateway(), Some(&gw));

    Ok(())
}

#[tokio::test]
async fn test_delete_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rtdel").await?;

    // Add route
    conn.add_route(Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8).dev("dummy0"))
        .await?;

    // Verify it exists
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    assert!(routes.iter().any(|r| r.destination() == Some(&target)));

    // Delete it. Use the symmetric Route-builder form (with the same
    // `dev` binding the add used) — the convenience `del_route_v4`
    // doesn't carry the device binding, and newer kernels return
    // ESRCH ("no matching route") rather than fuzzy-matching the
    // dst+prefix alone.
    conn.del_route(Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8).dev("dummy0"))
        .await?;

    // Verify it's gone
    let routes = conn.get_routes().await?;
    assert!(!routes.iter().any(|r| r.destination() == Some(&target)));

    Ok(())
}

#[tokio::test]
async fn test_blackhole_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("rtblack")?;
    let conn = ns.connection()?;

    // Add blackhole route
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 255, 0, 0), 16).route_type(RouteType::Blackhole),
    )
    .await?;

    // Verify route exists and is blackhole
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 255, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 16);
    assert!(route.is_some());
    assert_eq!(route.unwrap().route_type(), RouteType::Blackhole);

    Ok(())
}

#[tokio::test]
async fn test_unreachable_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("rtunreach")?;
    let conn = ns.connection()?;

    // Add unreachable route
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 254, 0, 0), 16).route_type(RouteType::Unreachable),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 254, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 16);
    assert!(route.is_some());
    assert_eq!(route.unwrap().route_type(), RouteType::Unreachable);

    Ok(())
}

#[tokio::test]
async fn test_prohibit_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("rtprohib")?;
    let conn = ns.connection()?;

    // Add prohibit route
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 253, 0, 0), 16).route_type(RouteType::Prohibit),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 253, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 16);
    assert!(route.is_some());
    assert_eq!(route.unwrap().route_type(), RouteType::Prohibit);

    Ok(())
}

#[tokio::test]
async fn test_default_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rtdefault").await?;

    // Add default route
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::UNSPECIFIED, 0)
            .gateway(Ipv4Addr::new(192, 168, 1, 254))
            .dev("dummy0"),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let default = routes.iter().find(|r| r.dst_len() == 0);
    assert!(default.is_some());
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254));
    assert_eq!(default.unwrap().gateway(), Some(&gw));

    Ok(())
}

#[tokio::test]
async fn test_ipv6_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("rtv6")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add IPv6 route
    conn.add_route(
        Ipv6Route::new(Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0), 48).dev("dummy0"),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V6("2001:db8:2::".parse::<Ipv6Addr>().unwrap());
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 48);
    assert!(route.is_some());

    Ok(())
}

#[tokio::test]
async fn test_route_with_source() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rtsrc").await?;

    // Add route with preferred source
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dev("dummy0")
            .prefsrc(Ipv4Addr::new(192, 168, 1, 1)),
    )
    .await?;

    // Verify source is set
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());
    let src = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(route.unwrap().prefsrc(), Some(&src));

    Ok(())
}

#[tokio::test]
async fn test_route_with_table() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rttable").await?;

    // Add route to custom table
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dev("dummy0")
            .table(100),
    )
    .await?;

    // Verify by deleting from the specific table.
    // get_routes() only returns main table by default, so a successful
    // del is the verification. The del must mirror the add's full key
    // (dest + prefix + dev + table) — newer kernels return ESRCH on
    // partial-key del.
    conn.del_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dev("dummy0")
            .table(100),
    )
    .await?;

    // If we got here without error, the route existed in table 100
    Ok(())
}

#[tokio::test]
async fn test_route_with_metrics() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rtmetric").await?;

    // Add route with MTU metric
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .dev("dummy0")
            .metrics(RouteMetrics::new().mtu(1400)),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());

    Ok(())
}

#[tokio::test]
async fn test_multipath_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("rtecmp")?;
    let conn = ns.connection()?;

    // Create two dummy interfaces
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.add_link(DummyLink::new("dummy1")).await?;
    conn.set_link_up("dummy0").await?;
    conn.set_link_up("dummy1").await?;

    // Add addresses
    conn.add_address(Ipv4Address::new(
        "dummy0",
        Ipv4Addr::new(192, 168, 1, 1),
        24,
    ))
    .await?;
    conn.add_address(Ipv4Address::new(
        "dummy1",
        Ipv4Addr::new(192, 168, 2, 1),
        24,
    ))
    .await?;

    // Add multipath route
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8).multipath(vec![
            NextHop::new()
                .gateway_v4(Ipv4Addr::new(192, 168, 1, 254))
                .dev("dummy0")
                .weight(1),
            NextHop::new()
                .gateway_v4(Ipv4Addr::new(192, 168, 2, 254))
                .dev("dummy1")
                .weight(1),
        ]))
    .await?;

    // Verify route exists
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 8);
    assert!(route.is_some());

    Ok(())
}

#[tokio::test]
async fn test_replace_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rtreplace").await?;

    // Add initial route
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .gateway(Ipv4Addr::new(192, 168, 1, 100))
            .dev("dummy0"),
    )
    .await?;

    // Replace with different gateway
    conn.replace_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 0), 8)
            .gateway(Ipv4Addr::new(192, 168, 1, 200))
            .dev("dummy0"),
    )
    .await?;

    // Verify only one route with new gateway
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0));
    let matching: Vec<_> = routes
        .iter()
        .filter(|r| r.destination() == Some(&target) && r.dst_len() == 8)
        .collect();

    assert_eq!(matching.len(), 1);
    let gw = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200));
    assert_eq!(matching[0].gateway(), Some(&gw));

    Ok(())
}

#[tokio::test]
async fn test_connected_route_auto_created() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("rtconn")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;

    // Add address - this should auto-create a connected route
    conn.add_address(Ipv4Address::new(
        "dummy0",
        Ipv4Addr::new(192, 168, 100, 1),
        24,
    ))
    .await?;

    // Verify connected route was created
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 0));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 24);
    assert!(route.is_some(), "connected route should be auto-created");

    Ok(())
}

#[tokio::test]
async fn test_host_route() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn) = setup_routed_ns("rthost").await?;

    // Add /32 host route
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 0, 0, 100), 32)
            .gateway(Ipv4Addr::new(192, 168, 1, 254))
            .dev("dummy0"),
    )
    .await?;

    // Verify
    let routes = conn.get_routes().await?;
    let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
    let route = routes
        .iter()
        .find(|r| r.destination() == Some(&target) && r.dst_len() == 32);
    assert!(route.is_some());

    Ok(())
}

/// A nexthop group's member weights are the ones `ip nexthop` shows, both
/// ways (#672). The wire carries each minus one: nlink sent `member(2, 3)`
/// as 3, which the kernel weighs 4, and read `ip nexthop`'s `1/2,3` back
/// as 0 and 2.
#[tokio::test]
async fn nexthop_group_weights_are_the_kernels() -> Result<()> {
    use nlink::netlink::nexthop::{NexthopBuilder, NexthopGroupBuilder};
    nlink::require_root!();

    let (ns, conn) = setup_routed_ns("nhweight").await?;
    for (id, gw) in [(1, "192.168.1.2"), (2, "192.168.1.3")] {
        conn.add_nexthop(NexthopBuilder::new(id).gateway(gw.parse().unwrap()).dev("dummy0"))
            .await?;
    }
    conn.add_nexthop_group(NexthopGroupBuilder::new(10).member(1, 1).member(2, 3))
        .await?;
    let shown = ns.exec("ip", &["-j", "nexthop", "show", "id", "10"])?;
    let shown: serde_json::Value = serde_json::from_str(&shown).expect("ip -j");
    assert_eq!(
        shown[0]["group"],
        serde_json::json!([{"id": 1}, {"id": 2, "weight": 3}]),
        "{shown}"
    );

    ns.exec("ip", &["nexthop", "add", "id", "11", "group", "1/2,3"])?;
    let read = conn.get_nexthop(11).await?.expect("nexthop 11");
    let weights: Vec<(u32, u32)> = read
        .group()
        .expect("a group")
        .iter()
        .map(|m| (m.id(), u32::from(m.weight())))
        .collect();
    assert_eq!(weights, [(1, 1), (2, 3)]);
    Ok(())
}

/// A blackhole nexthop and one with a device alone are created (#673).
/// `NexthopBuilder` sent `AF_UNSPEC` for both, which the kernel takes only
/// for a group: "Invalid address family" (EINVAL).
#[tokio::test]
async fn a_nexthop_without_a_gateway_is_created() -> Result<()> {
    use nlink::netlink::nexthop::NexthopBuilder;
    nlink::require_root!();

    let (ns, conn) = setup_routed_ns("nhnogw").await?;
    // A blackhole nexthop sits on the loopback device, which must be up.
    conn.set_link_up("lo").await?;
    conn.add_nexthop(NexthopBuilder::new(5).blackhole()).await?;
    conn.add_nexthop(NexthopBuilder::new(6).dev("dummy0")).await?;
    let shown = ns.exec("ip", &["-j", "nexthop", "show"])?;
    let shown: serde_json::Value = serde_json::from_str(&shown).expect("ip -j");
    let ids: Vec<u64> = shown.as_array().into_iter().flatten().filter_map(|n| n["id"].as_u64()).collect();
    assert_eq!(ids, [5, 6], "{shown}");
    Ok(())
}

/// A route with an MPLS encapsulation is added (#678). `MplsEncap` put a
/// TTL — 255 unless set — in the bottom label entry, and the kernel takes
/// a label stack only with TTL 0 there (`nla_get_labels`: "TTL in label
/// must be 0"); the TTL is `MPLS_IPTUNNEL_TTL`'s. Every one failed.
#[tokio::test]
async fn an_mpls_encap_route_is_added() -> Result<()> {
    use nlink::netlink::mpls::MplsEncap;
    nlink::require_root!();
    nlink::require_modules!("mpls_iptunnel");

    let (ns, conn) = setup_routed_ns("mplsencap").await?;
    conn.add_route(
        Ipv4Route::new(Ipv4Addr::new(10, 88, 0, 0), 16)
            .gateway(Ipv4Addr::new(192, 168, 1, 2))
            .dev("dummy0")
            .mpls_encap(MplsEncap::new().labels(&[100, 200]).ttl(32)),
    )
    .await?;
    // Text: iproute2 6.1's JSON puts the labels in the route's `dst`.
    let shown = ns.exec("ip", &["route", "show", "10.88.0.0/16"])?;
    assert!(shown.contains("encap mpls  100/200 ttl 32 via 192.168.1.2 dev dummy0"), "{shown}");
    Ok(())
}

/// An MPLS swap route is added and deleted (#678). Every MPLS route request
/// failed: an add and a delete both left `rtm_table` 0, where the kernel
/// takes only main ("MPLS only supports the main route table"), a delete
/// left `rtm_type` 0 where it takes only unicast, and the swap's
/// `RTA_NEWDST` stack carried TTL 255 in its bottom entry.
#[tokio::test]
async fn an_mpls_swap_route_is_added() -> Result<()> {
    use nlink::netlink::mpls::MplsRouteBuilder;
    nlink::require_root!();
    nlink::require_modules!("mpls_router");
    nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");

    let (ns, conn) = setup_routed_ns("mplsswap").await?;
    ns.exec("sysctl", &["-w", "net.mpls.platform_labels=1000"])?;
    conn.add_mpls_route(
        MplsRouteBuilder::swap(100, 200)
            .dev("dummy0")
            .via(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))),
    )
    .await?;
    let shown = ns.exec("ip", &["-f", "mpls", "route", "show"])?;
    assert!(shown.contains("100 as to 200 via inet 192.168.1.2 dev dummy0"), "{shown}");
    conn.del_mpls_route(100).await?;
    let shown = ns.exec("ip", &["-f", "mpls", "route", "show"])?;
    assert!(shown.trim().is_empty(), "{shown}");
    Ok(())
}
