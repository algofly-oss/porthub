//! OVPN GENL family integration tests (Plan 197).
//!
//! Root-gated + module-gated (`ovpn`). The kernel `ovpn` module
//! ships in **Linux 6.16+** — older kernels skip cleanly.
//!
//! Each test runs in an isolated `LabNamespace`, creates an
//! `ovpn0` interface via RTNL, opens a `Connection<Ovpn>` against
//! that namespace, and exercises one slice of the GENL surface.

use nlink::netlink::{
    genl::ovpn::{
        OvpnCipherAlg, OvpnConfig, OvpnKeyConfig, OvpnKeySlot, OvpnKeyconf, OvpnKeydir,
        OvpnPeer, Ovpn,
    },
    link::OvpnLink,
    Connection, Route,
};

use crate::common::TestNamespace;

/// Helper — open RTNL + GENL connections inside the test namespace
/// and create `ovpn0`. Returns the resolved ifindex.
async fn setup_ovpn_iface(ns: &TestNamespace) -> nlink::Result<(Connection<Ovpn>, u32)> {
    let route: Connection<Route> = nlink::Connection::new_in(ns.name())?;
    route.add_link(OvpnLink::new("ovpn0")).await?;
    let link = route
        .get_link_by_name("ovpn0")
        .await?
        .expect("ovpn0 just created");
    let ifindex = link.ifindex();
    let ovpn: Connection<Ovpn> = nlink::Connection::new_in_async(ns.name()).await?;
    Ok((ovpn, ifindex))
}

fn placeholder_key(key_id: u32) -> OvpnKeyConfig {
    OvpnKeyConfig::new(
        key_id,
        OvpnCipherAlg::AesGcm,
        OvpnKeydir::new([0xAAu8; 32], [0xBBu8; 8]),
        OvpnKeydir::new([0xCCu8; 32], [0xDDu8; 8]),
    )
}

#[tokio::test]
async fn ovpn_family_resolves_when_module_loaded() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-family-resolve")?;
    let _genl: Connection<Ovpn> = nlink::Connection::new_in_async(ns.name()).await?;
    Ok(())
}

#[tokio::test]
async fn ovpn_peer_dump_on_fresh_interface_is_empty() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-empty-dump")?;
    let (ovpn, ifindex) = setup_ovpn_iface(&ns).await?;

    let peers = ovpn.peer_dump(ifindex).await?;
    assert!(
        peers.is_empty(),
        "fresh ovpn0 should have zero peers, got {} ({peers:?})",
        peers.len()
    );
    Ok(())
}

#[tokio::test]
async fn ovpn_config_apply_creates_peer_visible_in_dump() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-apply-peer")?;
    let (ovpn, ifindex) = setup_ovpn_iface(&ns).await?;

    let cfg = OvpnConfig::new().interface(ifindex, |b| {
        b.peer(42, |p| {
            p.remote("10.0.0.1:1194".parse().unwrap())
                .keepalive(20, 60)
                .vpn_ipv4("172.16.0.42".parse().unwrap())
        })
    });

    // Note: the config has no key declared, so we expect the
    // peer-add to succeed but key install to be skipped (empty
    // keys BTreeMap). This isolates the peer-side from the
    // key-side for the regression test.
    cfg.apply(&ovpn).await?;

    let peers = ovpn.peer_dump(ifindex).await?;
    assert_eq!(peers.len(), 1, "expected 1 peer after apply, got {peers:?}");
    let peer = &peers[0];
    assert_eq!(peer.id, Some(42));
    assert_eq!(
        peer.remote_socket(),
        Some("10.0.0.1:1194".parse().unwrap())
    );
    assert_eq!(peer.keepalive_interval, Some(20));
    assert_eq!(peer.keepalive_timeout, Some(60));

    // Idempotence: re-diff should be empty.
    let post = cfg.diff(&ovpn).await?;
    assert!(
        post.is_empty(),
        "expected empty post-apply diff, got: {post}"
    );

    Ok(())
}

#[tokio::test]
async fn ovpn_config_apply_removes_stale_peer() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-stale-peer")?;
    let (ovpn, ifindex) = setup_ovpn_iface(&ns).await?;

    // Imperatively install a peer.
    let mut peer = OvpnPeer::identity(7);
    peer.set_remote_v4("192.0.2.7:1194".parse().unwrap());
    peer.keepalive_interval = Some(10);
    peer.keepalive_timeout = Some(30);
    ovpn.peer_new(ifindex, peer).await?;

    // Now declare an empty config — peer 7 should be marked for removal.
    let cfg = OvpnConfig::new().interface(ifindex, |b| b);
    let diff = cfg.diff(&ovpn).await?;
    assert_eq!(diff.peers_to_remove.len(), 1);
    assert_eq!(diff.peers_to_remove[0], (ifindex, 7));

    diff.apply(&ovpn).await?;
    let peers = ovpn.peer_dump(ifindex).await?;
    assert!(peers.is_empty(), "expected zero peers after stale-cleanup");

    Ok(())
}

#[tokio::test]
async fn ovpn_key_install_then_get_metadata() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-key-get")?;
    let (ovpn, ifindex) = setup_ovpn_iface(&ns).await?;

    // Install a peer first (keys need a peer to attach to).
    let mut peer = OvpnPeer::identity(5);
    peer.set_remote_v4("198.51.100.5:1194".parse().unwrap());
    ovpn.peer_new(ifindex, peer).await?;

    // Install a primary key.
    let keyconf = OvpnKeyconf::new(
        5,
        OvpnKeySlot::Primary,
        3,
        OvpnCipherAlg::AesGcm,
        OvpnKeydir::new([0u8; 32], [0u8; 8]),
        OvpnKeydir::new([0u8; 32], [0u8; 8]),
    );
    ovpn.key_new(ifindex, keyconf).await?;

    // Read back metadata. Key bytes are write-only; we just check
    // (cipher_alg, key_id, slot) round-trip.
    let meta = ovpn.key_get(ifindex, 5, OvpnKeySlot::Primary).await?;
    assert_eq!(meta.peer_id, Some(5));
    assert_eq!(meta.slot, Some(OvpnKeySlot::Primary));
    assert_eq!(meta.cipher_alg, Some(OvpnCipherAlg::AesGcm));
    assert_eq!(meta.key_id, Some(3));
    // Encrypt/decrypt dirs are absent on the GET reply (write-only).
    assert!(meta.encrypt_dir.is_none());
    assert!(meta.decrypt_dir.is_none());

    Ok(())
}

#[tokio::test]
async fn ovpn_key_swap_atomically_promotes_secondary() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-key-swap")?;
    let (ovpn, ifindex) = setup_ovpn_iface(&ns).await?;

    let mut peer = OvpnPeer::identity(11);
    peer.set_remote_v4("203.0.113.11:1194".parse().unwrap());
    ovpn.peer_new(ifindex, peer).await?;

    // Install primary (key_id=1) + secondary (key_id=2).
    let primary = OvpnKeyconf::new(
        11,
        OvpnKeySlot::Primary,
        1,
        OvpnCipherAlg::AesGcm,
        OvpnKeydir::new([1u8; 32], [1u8; 8]),
        OvpnKeydir::new([1u8; 32], [1u8; 8]),
    );
    let secondary = OvpnKeyconf::new(
        11,
        OvpnKeySlot::Secondary,
        2,
        OvpnCipherAlg::Chacha20Poly1305,
        OvpnKeydir::new([2u8; 32], [2u8; 8]),
        OvpnKeydir::new([2u8; 32], [2u8; 8]),
    );
    ovpn.key_new(ifindex, primary).await?;
    ovpn.key_new(ifindex, secondary).await?;

    let pre = ovpn.key_get(ifindex, 11, OvpnKeySlot::Primary).await?;
    assert_eq!(pre.key_id, Some(1));

    ovpn.key_swap(ifindex, 11).await?;

    let post_primary = ovpn.key_get(ifindex, 11, OvpnKeySlot::Primary).await?;
    let post_secondary = ovpn.key_get(ifindex, 11, OvpnKeySlot::Secondary).await?;
    assert_eq!(
        post_primary.key_id,
        Some(2),
        "secondary should have become primary"
    );
    assert_eq!(
        post_secondary.key_id,
        Some(1),
        "primary should have become secondary"
    );

    Ok(())
}

#[tokio::test]
async fn ovpn_peer_del_removes_peer() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-peer-del")?;
    let (ovpn, ifindex) = setup_ovpn_iface(&ns).await?;

    let mut peer = OvpnPeer::identity(99);
    peer.set_remote_v4("198.51.100.99:1194".parse().unwrap());
    ovpn.peer_new(ifindex, peer).await?;

    assert_eq!(ovpn.peer_dump(ifindex).await?.len(), 1);
    ovpn.peer_del(ifindex, 99).await?;
    assert_eq!(ovpn.peer_dump(ifindex).await?.len(), 0);

    Ok(())
}

#[tokio::test]
async fn ovpn_config_apply_with_key_drives_full_lifecycle() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("ovpn");

    let ns = TestNamespace::new("ovpn-full-lifecycle")?;
    let (ovpn, ifindex) = setup_ovpn_iface(&ns).await?;

    let cfg = OvpnConfig::new().interface(ifindex, |b| {
        b.peer(77, |p| {
            p.remote("192.0.2.77:1194".parse().unwrap())
                .keepalive(15, 45)
                .vpn_ipv4("172.16.0.77".parse().unwrap())
                .key(OvpnKeySlot::Primary, placeholder_key(4))
        })
    });

    // 1. Apply.
    cfg.apply(&ovpn).await?;

    // 2. Peer is present.
    let peers = ovpn.peer_dump(ifindex).await?;
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].id, Some(77));

    // 3. Key metadata matches.
    let meta = ovpn.key_get(ifindex, 77, OvpnKeySlot::Primary).await?;
    assert_eq!(meta.cipher_alg, Some(OvpnCipherAlg::AesGcm));
    assert_eq!(meta.key_id, Some(4));

    // 4. Idempotent re-apply.
    let diff2 = cfg.diff(&ovpn).await?;
    assert!(diff2.is_empty(), "expected empty diff on re-apply: {diff2}");

    Ok(())
}
