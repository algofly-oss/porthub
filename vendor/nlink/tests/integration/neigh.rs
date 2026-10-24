//! Neighbor table integration tests.
//!
//! Regression test for the bug where `Neighbor::write_delete`
//! dropped `ndm_flags`, so the kernel's pneigh lookup failed to
//! match `NTF_PROXY` entries on delete. The proxy test reproduces
//! the ENOENT failure without the fix; the others are guards
//! against future drift in the unicast and ext_learned paths.

use std::net::Ipv6Addr;

use nlink::{
    Connection, Result, Route,
    netlink::{
        link::DummyLink,
        neigh::{Neighbor, ntf},
    },
};

use crate::common::TestNamespace;

/// Create a namespace, bring up `dummy0`, return `(ns, conn, ifindex)`.
async fn setup(ns_name: &str) -> Result<(TestNamespace, Connection<Route>, u32)> {
    let ns = TestNamespace::new(ns_name)?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    let ifindex = conn
        .get_link_by_name("dummy0")
        .await?
        .expect("dummy0 should exist")
        .ifindex();
    Ok((ns, conn, ifindex))
}

#[tokio::test]
async fn test_delete_proxy_ndp_entry_round_trip() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn, ifindex) = setup("neigh-proxy").await?;
    let target: Ipv6Addr = "fd00:abcd::1".parse().unwrap();

    // Proxy NDP entries live in the kernel's pneigh table, which the
    // bare RTM_GETNEIGH dump used by get_neighbors() doesn't surface
    // (the dump request would need NTF_PROXY set in its ndm_flags).
    // The bug being fixed is in the *delete* path, so the assertion
    // we care about is: a second delete after a successful add must
    // not ENOENT due to the kernel failing to match on ndm_flags.
    conn.add_neighbor(
        Neighbor::with_index_v6(ifindex, target)
            .proxy()
            .permanent(),
    )
    .await?;

    // Without the write_delete fix this returns ENOENT — ndm_flags
    // wasn't being propagated, so the kernel pneigh lookup missed.
    conn.del_neighbor(Neighbor::with_index_v6(ifindex, target).proxy())
        .await?;

    // Deleting again should now actually ENOENT (the entry is really
    // gone) — proves the previous delete reached the right table.
    match conn
        .del_neighbor(Neighbor::with_index_v6(ifindex, target).proxy())
        .await
    {
        Err(e) if e.is_not_found() => {}
        Err(e) => panic!("expected ENOENT on second delete, got: {e}"),
        Ok(()) => panic!("expected ENOENT on second delete, got Ok"),
    }

    Ok(())
}

#[tokio::test]
async fn test_delete_regular_neighbor_round_trip() -> Result<()> {
    // Guard, not a regression test: propagating ndm_flags on delete
    // must not break the common case where flags == 0.
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn, ifindex) = setup("neigh-reg").await?;
    let target: Ipv6Addr = "fd00:abcd::42".parse().unwrap();
    let lladdr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

    conn.add_neighbor(
        Neighbor::with_index_v6(ifindex, target)
            .lladdr(lladdr)
            .permanent(),
    )
    .await?;

    let neighbors = conn.get_neighbors().await?;
    assert!(
        neighbors
            .iter()
            .any(|n| n.ifindex() == ifindex && n.destination() == Some(&target.into())),
        "regular neighbor entry should be present after add"
    );

    conn.del_neighbor(Neighbor::with_index_v6(ifindex, target))
        .await?;

    let neighbors = conn.get_neighbors().await?;
    assert!(
        !neighbors
            .iter()
            .any(|n| n.ifindex() == ifindex && n.destination() == Some(&target.into())),
        "regular neighbor entry should be gone after delete"
    );

    Ok(())
}

#[tokio::test]
async fn test_delete_ext_learned_entry_round_trip() -> Result<()> {
    // Guard, not a regression test: the kernel's unicast neighbor
    // delete only matches on (family, ifindex, NDA_DST) — flags are
    // advisory there — so this passes even *without* the
    // write_delete fix. Kept so a future change to the unicast match
    // path can't silently break ext_learned round-trips.
    require_root!();
    nlink::require_module!("dummy");

    let (_ns, conn, ifindex) = setup("neigh-ext").await?;
    let target: Ipv6Addr = "fd00:abcd::1234".parse().unwrap();
    let lladdr = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

    conn.add_neighbor(
        Neighbor::with_index_v6(ifindex, target)
            .lladdr(lladdr)
            .extern_learn()
            .permanent(),
    )
    .await?;

    let neighbors = conn.get_neighbors().await?;
    assert!(
        neighbors.iter().any(|n| n.ifindex() == ifindex
            && n.destination() == Some(&target.into())
            && n.flags() & ntf::EXT_LEARNED != 0),
        "ext_learned entry should be present after add"
    );

    conn.del_neighbor(
        Neighbor::with_index_v6(ifindex, target).extern_learn(),
    )
    .await?;

    let neighbors = conn.get_neighbors().await?;
    assert!(
        !neighbors.iter().any(|n| n.ifindex() == ifindex
            && n.destination() == Some(&target.into())
            && n.flags() & ntf::EXT_LEARNED != 0),
        "ext_learned entry should be gone after delete"
    );

    Ok(())
}
