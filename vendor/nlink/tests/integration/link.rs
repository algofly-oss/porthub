//! Link integration tests.
//!
//! Tests for link creation, modification, and deletion using network namespaces.

use nlink::{
    Result,
    netlink::link::{
        BondLink, BondMode, BridgeLink, DummyLink, GreLink, GretapLink, IfbLink, IpipLink,
        IpvlanLink, LacpRate, MacvlanLink, MacvlanMode, NetkitLink, NetkitMode, NetkitPolicy,
        SitLink, VethLink, VlanLink, VrfLink, XmitHashPolicy,
    },
};

use crate::common::TestNamespace;

#[tokio::test]
async fn test_create_dummy_interface() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("dummy")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0"));
    assert!(dummy.is_some(), "dummy0 should exist");

    // Verify type
    let dummy = dummy.unwrap();
    assert_eq!(dummy.kind(), Some("dummy"));

    // Bring it up
    conn.set_link_up("dummy0").await?;

    // Verify it's up
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(dummy.is_up(), "dummy0 should be up");

    // Delete it
    conn.del_link("dummy0").await?;

    // Verify it's gone
    let links = conn.get_links().await?;
    assert!(
        !links.iter().any(|l| l.name() == Some("dummy0")),
        "dummy0 should be deleted"
    );

    Ok(())
}

#[tokio::test]
async fn test_create_veth_pair() -> Result<()> {
    require_root!();
    nlink::require_modules!("veth");

    let ns = TestNamespace::new("veth")?;
    let conn = ns.connection()?;

    // Create veth pair
    conn.add_link(VethLink::new("veth0", "veth1")).await?;

    // Verify both ends exist
    let links = conn.get_links().await?;
    assert!(
        links.iter().any(|l| l.name() == Some("veth0")),
        "veth0 should exist"
    );
    assert!(
        links.iter().any(|l| l.name() == Some("veth1")),
        "veth1 should exist"
    );

    // Verify they're linked
    let veth0 = links.iter().find(|l| l.name() == Some("veth0")).unwrap();
    let veth1 = links.iter().find(|l| l.name() == Some("veth1")).unwrap();
    assert_eq!(veth0.link(), Some(veth1.ifindex()));
    assert_eq!(veth1.link(), Some(veth0.ifindex()));

    // Delete one (should delete the pair)
    conn.del_link("veth0").await?;

    // Verify both are gone
    let links = conn.get_links().await?;
    assert!(
        !links.iter().any(|l| l.name() == Some("veth0")),
        "veth0 should be deleted"
    );
    assert!(
        !links.iter().any(|l| l.name() == Some("veth1")),
        "veth1 should be deleted"
    );

    Ok(())
}

#[tokio::test]
async fn test_create_bridge() -> Result<()> {
    require_root!();
    nlink::require_modules!("bridge");

    let ns = TestNamespace::new("bridge")?;
    let conn = ns.connection()?;

    // Create a bridge
    conn.add_link(BridgeLink::new("br0").stp(false)).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let br = links.iter().find(|l| l.name() == Some("br0"));
    assert!(br.is_some(), "br0 should exist");
    assert_eq!(br.unwrap().kind(), Some("bridge"));

    // Create dummy interfaces to add to bridge
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.add_link(DummyLink::new("dummy1")).await?;

    // Add interfaces to bridge
    conn.set_link_master("dummy0", "br0").await?;
    conn.set_link_master("dummy1", "br0").await?;

    // Verify they're attached
    let links = conn.get_links().await?;
    let br = links.iter().find(|l| l.name() == Some("br0")).unwrap();
    let dummy0 = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    let dummy1 = links.iter().find(|l| l.name() == Some("dummy1")).unwrap();

    assert_eq!(dummy0.master(), Some(br.ifindex()));
    assert_eq!(dummy1.master(), Some(br.ifindex()));

    // Remove from bridge
    conn.set_link_nomaster("dummy0").await?;

    let links = conn.get_links().await?;
    let dummy0 = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert_eq!(dummy0.master(), None);

    Ok(())
}

#[tokio::test]
async fn test_create_vlan() -> Result<()> {
    require_root!();
    nlink::require_modules!("8021q");

    let ns = TestNamespace::new("vlan")?;
    let conn = ns.connection()?;

    // Create parent interface
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.set_link_up("eth0").await?;

    // Create VLAN
    conn.add_link(VlanLink::new("eth0.100", "eth0", 100))
        .await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let vlan = links.iter().find(|l| l.name() == Some("eth0.100"));
    assert!(vlan.is_some(), "eth0.100 should exist");
    assert_eq!(vlan.unwrap().kind(), Some("vlan"));

    // Bring it up
    conn.set_link_up("eth0.100").await?;

    // Delete
    conn.del_link("eth0.100").await?;

    let links = conn.get_links().await?;
    assert!(!links.iter().any(|l| l.name() == Some("eth0.100")));

    Ok(())
}

#[tokio::test]
async fn test_create_macvlan() -> Result<()> {
    require_root!();
    nlink::require_modules!("macvlan");

    let ns = TestNamespace::new("macvlan")?;
    let conn = ns.connection()?;

    // Create parent interface
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.set_link_up("eth0").await?;

    // Create macvlan in bridge mode
    conn.add_link(MacvlanLink::new("macvlan0", "eth0").mode(MacvlanMode::Bridge))
        .await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let macvlan = links.iter().find(|l| l.name() == Some("macvlan0"));
    assert!(macvlan.is_some(), "macvlan0 should exist");
    assert_eq!(macvlan.unwrap().kind(), Some("macvlan"));

    Ok(())
}

#[tokio::test]
async fn test_create_ipvlan() -> Result<()> {
    require_root!();
    nlink::require_modules!("ipvlan");

    let ns = TestNamespace::new("ipvlan")?;
    let conn = ns.connection()?;

    // Create parent interface
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.set_link_up("eth0").await?;

    // Create ipvlan
    conn.add_link(IpvlanLink::new("ipvlan0", "eth0")).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let ipvlan = links.iter().find(|l| l.name() == Some("ipvlan0"));
    assert!(ipvlan.is_some(), "ipvlan0 should exist");
    assert_eq!(ipvlan.unwrap().kind(), Some("ipvlan"));

    Ok(())
}

#[tokio::test]
async fn test_create_ifb() -> Result<()> {
    require_root!();
    nlink::require_modules!("ifb");

    let ns = TestNamespace::new("ifb")?;
    let conn = ns.connection()?;

    // Create IFB interface
    conn.add_link(IfbLink::new("ifb0")).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let ifb = links.iter().find(|l| l.name() == Some("ifb0"));
    assert!(ifb.is_some(), "ifb0 should exist");
    assert_eq!(ifb.unwrap().kind(), Some("ifb"));

    Ok(())
}

#[tokio::test]
async fn test_create_vrf() -> Result<()> {
    require_root!();
    nlink::require_modules!("vrf");

    let ns = TestNamespace::new("vrf")?;
    let conn = ns.connection()?;

    // Create VRF with routing table 100
    conn.add_link(VrfLink::new("vrf0", 100)).await?;

    // Verify it exists
    let links = conn.get_links().await?;
    let vrf = links.iter().find(|l| l.name() == Some("vrf0"));
    assert!(vrf.is_some(), "vrf0 should exist");
    assert_eq!(vrf.unwrap().kind(), Some("vrf"));

    // Create dummy and add to VRF
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_master("dummy0", "vrf0").await?;

    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    let vrf = links.iter().find(|l| l.name() == Some("vrf0")).unwrap();
    assert_eq!(dummy.master(), Some(vrf.ifindex()));

    Ok(())
}

#[tokio::test]
async fn test_set_mtu() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("mtu")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Set MTU
    conn.set_link_mtu("dummy0", 9000).await?;

    // Verify
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert_eq!(dummy.mtu(), Some(9000));

    Ok(())
}

#[tokio::test]
async fn test_rename_interface() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("rename")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("oldname")).await?;

    // Rename (interface must be down)
    conn.set_link_down("oldname").await?;
    conn.set_link_name("oldname", "newname").await?;

    // Verify
    let links = conn.get_links().await?;
    assert!(!links.iter().any(|l| l.name() == Some("oldname")));
    assert!(links.iter().any(|l| l.name() == Some("newname")));

    Ok(())
}

#[tokio::test]
async fn test_set_mac_address() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("mac")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_down("dummy0").await?;

    // Set MAC address
    let new_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    conn.set_link_address("dummy0", new_mac).await?;

    // Verify
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert_eq!(dummy.address(), Some(new_mac.as_slice()));

    Ok(())
}

#[tokio::test]
async fn test_get_link_by_name() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("getlink")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Get by name
    let link = conn.get_link_by_name("dummy0").await?;
    assert!(link.is_some(), "dummy0 should exist");
    assert_eq!(link.unwrap().name(), Some("dummy0"));

    // Get non-existent should return None
    let result = conn.get_link_by_name("nonexistent").await?;
    assert!(result.is_none());

    Ok(())
}

#[tokio::test]
async fn test_get_link_by_index() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("getidx")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Get by name first to get index
    let link = conn
        .get_link_by_name("dummy0")
        .await?
        .expect("dummy0 should exist");
    let ifindex = link.ifindex();

    // Get by index
    let link2 = conn
        .get_link_by_index(ifindex)
        .await?
        .expect("link should exist");
    assert_eq!(link2.name(), Some("dummy0"));
    assert_eq!(link2.ifindex(), ifindex);

    Ok(())
}

#[tokio::test]
async fn test_veth_between_namespaces() -> Result<()> {
    require_root!();
    nlink::require_modules!("veth");

    let ns1 = TestNamespace::new("veth-ns1")?;
    let ns2 = TestNamespace::new("veth-ns2")?;

    // Create veth pair between namespaces
    ns1.connect_to(&ns2, "veth0", "veth1")?;

    // Verify in ns1
    let conn1 = ns1.connection()?;
    let links1 = conn1.get_links().await?;
    assert!(links1.iter().any(|l| l.name() == Some("veth0")));
    assert!(!links1.iter().any(|l| l.name() == Some("veth1")));

    // Verify in ns2
    let conn2 = ns2.connection()?;
    let links2 = conn2.get_links().await?;
    assert!(links2.iter().any(|l| l.name() == Some("veth1")));
    assert!(!links2.iter().any(|l| l.name() == Some("veth0")));

    Ok(())
}

#[tokio::test]
async fn test_interface_flags() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("flags")?;
    let conn = ns.connection()?;

    // Create dummy interface
    conn.add_link(DummyLink::new("dummy0")).await?;

    // Initially should be down
    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(!dummy.is_up());

    // Bring up
    conn.set_link_up("dummy0").await?;

    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(dummy.is_up());

    // Bring down
    conn.set_link_down("dummy0").await?;

    let links = conn.get_links().await?;
    let dummy = links.iter().find(|l| l.name() == Some("dummy0")).unwrap();
    assert!(!dummy.is_up());

    Ok(())
}

#[tokio::test]
async fn test_loopback_exists() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("lo")?;
    let conn = ns.connection()?;

    // Loopback should exist in every namespace
    let links = conn.get_links().await?;
    let lo = links.iter().find(|l| l.name() == Some("lo"));
    assert!(lo.is_some(), "loopback should exist");

    let lo = lo.unwrap();
    assert!(lo.is_loopback());

    Ok(())
}

#[tokio::test]
async fn test_gre_tunnel() -> Result<()> {
    require_root!();
    nlink::require_modules!("ip_gre", "dummy");

    let ns = TestNamespace::new("gre")?;
    let conn = ns.connection()?;

    // Create GRE tunnel with key, bound to an underlay device
    conn.add_link(DummyLink::new("under0")).await?;
    conn.add_link(
        GreLink::new("gre1")
            .local(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .remote(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .ttl(64)
            .key(100)
            .link("under0"),
    )
    .await?;

    let link = conn.get_link_by_name("gre1").await?;
    assert!(link.is_some(), "gre1 should exist");
    assert_eq!(link.unwrap().kind(), Some("gre"));

    // The key is the one asked for (#516): keys and their GRE_KEY flag are
    // big-endian on the wire, and native-endian ones read as no key.
    let shown = ns.exec("ip", &["-d", "-j", "link", "show", "gre1"])?;
    let shown: serde_json::Value = serde_json::from_str(&shown).expect("ip -j");
    let data = &shown[0]["linkinfo"]["info_data"];
    assert_eq!(data["ikey"], "0.0.0.100", "{data}");
    assert_eq!(data["okey"], "0.0.0.100", "{data}");
    // And bound to its underlay: through IFLA_GRE_LINK, which `.link()`
    // did not send (#516).
    assert_eq!(data["link"], "under0", "{data}");

    // Delete it
    conn.del_link("gre1").await?;
    let link = conn.get_link_by_name("gre1").await?;
    assert!(link.is_none(), "gre1 should be deleted");

    Ok(())
}

/// `Ip6tnlLink` and `XfrmLink` (#516): every parameter reaches the kernel,
/// each tunnel bound to its underlay through its own link attribute.
#[tokio::test]
async fn test_ip6tnl_and_xfrm_links() -> Result<()> {
    use nlink::netlink::link::{Ip6tnlLink, Ip6tnlMode, XfrmLink};
    require_root!();
    nlink::require_modules!("dummy", "ip6_tunnel", "xfrm_interface");

    let ns = TestNamespace::new("ip6tnl")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("under0")).await?;
    conn.add_link(
        Ip6tnlLink::new("t61")
            .local("fd00::1".parse().unwrap())
            .remote("fd00::2".parse().unwrap())
            .hoplimit(20)
            .encap_limit(3)
            .mode(Ip6tnlMode::Ipip6)
            .mtu(1400)
            .link("under0"),
    )
    .await?;
    conn.add_link(XfrmLink::new("xf1", 0x2a).link("under0")).await?;

    let show = |dev: &str| -> serde_json::Value {
        let out = ns.exec("ip", &["-d", "-j", "link", "show", dev]).expect("ip");
        serde_json::from_str::<serde_json::Value>(&out).expect("ip -j")[0].clone()
    };
    let t6 = show("t61");
    let data = &t6["linkinfo"]["info_data"];
    assert_eq!(t6["linkinfo"]["info_kind"], "ip6tnl", "{t6}");
    assert_eq!(
        (&data["local"], &data["remote"], &data["ttl"], &data["encap_limit"], &data["proto"], &data["link"]),
        (
            &"fd00::1".into(),
            &"fd00::2".into(),
            &20.into(),
            &3.into(),
            &"ipip6".into(),
            &"under0".into()
        ),
        "{data}"
    );
    assert_eq!(t6["mtu"], 1400, "{t6}");
    let xf = show("xf1");
    assert_eq!(xf["linkinfo"]["info_kind"], "xfrm", "{xf}");
    assert_eq!(xf["linkinfo"]["info_data"]["if_id"], "0x2a", "{xf}");
    assert_eq!(xf["link"], "under0", "{xf}");
    Ok(())
}

#[tokio::test]
async fn test_gretap_tunnel() -> Result<()> {
    require_root!();
    nlink::require_modules!("ip_gre");

    let ns = TestNamespace::new("gretap")?;
    let conn = ns.connection()?;

    // Create GRETAP (L2) tunnel
    conn.add_link(
        GretapLink::new("gretap1")
            .local(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .remote(std::net::Ipv4Addr::new(10, 0, 0, 2)),
    )
    .await?;

    let link = conn.get_link_by_name("gretap1").await?;
    assert!(link.is_some(), "gretap1 should exist");
    assert_eq!(link.unwrap().kind(), Some("gretap"));

    Ok(())
}

#[tokio::test]
async fn test_ipip_tunnel() -> Result<()> {
    require_root!();
    nlink::require_modules!("ipip");

    let ns = TestNamespace::new("ipip")?;
    let conn = ns.connection()?;

    // Create IPIP tunnel with PMTU discovery
    conn.add_link(
        IpipLink::new("ipip1")
            .local(std::net::Ipv4Addr::new(10, 0, 0, 1))
            .remote(std::net::Ipv4Addr::new(10, 0, 0, 2))
            .ttl(64)
            .pmtudisc(true),
    )
    .await?;

    let link = conn.get_link_by_name("ipip1").await?;
    assert!(link.is_some(), "ipip1 should exist");
    assert_eq!(link.unwrap().kind(), Some("ipip"));

    // Delete it
    conn.del_link("ipip1").await?;
    let link = conn.get_link_by_name("ipip1").await?;
    assert!(link.is_none(), "ipip1 should be deleted");

    Ok(())
}

#[tokio::test]
async fn test_sit_tunnel() -> Result<()> {
    require_root!();
    nlink::require_modules!("sit");

    let ns = TestNamespace::new("sit")?;
    let conn = ns.connection()?;

    // SIT tunnels are keyed by `(local, remote)`, and loading the
    // module auto-creates the fallback `sit0` with both unset. Asking
    // for an unparameterised tunnel therefore asks for a *duplicate of
    // sit0*, and the kernel answers EEXIST — `ip link add sit1 type
    // sit` fails the same way. Give it endpoints.
    //
    // These tests had never run: they are gated on
    // `require_modules!("sit")`, and `has_module` only looked at
    // `/sys/module`, so they skipped and reported `ok` (#273, #300).
    conn.add_link(
        SitLink::new("sit1")
            .local(std::net::Ipv4Addr::new(192, 0, 2, 2))
            .remote(std::net::Ipv4Addr::new(192, 0, 2, 1))
            .ttl(64),
    )
    .await?;

    let link = conn.get_link_by_name("sit1").await?;
    assert!(link.is_some(), "sit1 should exist");
    assert_eq!(link.unwrap().kind(), Some("sit"));

    Ok(())
}

#[tokio::test]
async fn test_sit_isatap() -> Result<()> {
    require_root!();
    nlink::require_modules!("sit");

    let ns = TestNamespace::new("isatap")?;
    let conn = ns.connection()?;

    // Endpoints for the same reason as `test_sit_tunnel` above.
    conn.add_link(
        SitLink::new("isatap0")
            .local(std::net::Ipv4Addr::new(192, 0, 2, 4))
            .remote(std::net::Ipv4Addr::new(192, 0, 2, 3))
            .isatap(),
    )
    .await?;

    let link = conn.get_link_by_name("isatap0").await?;
    assert!(link.is_some(), "isatap0 should exist");
    assert_eq!(link.unwrap().kind(), Some("sit"));

    Ok(())
}

#[tokio::test]
async fn test_bond_lacp() -> Result<()> {
    require_root!();
    nlink::require_modules!("bonding");

    let ns = TestNamespace::new("bond-lacp")?;
    let conn = ns.connection()?;

    // Create LACP bond with typed enums
    conn.add_link(
        BondLink::new("bond0")
            .mode(BondMode::Lacp)
            .miimon(100)
            .lacp_rate(LacpRate::Fast)
            .xmit_hash_policy(XmitHashPolicy::Layer34)
            .min_links(1),
    )
    .await?;

    let link = conn.get_link_by_name("bond0").await?;
    assert!(link.is_some(), "bond0 should exist");
    assert_eq!(link.unwrap().kind(), Some("bond"));

    Ok(())
}

#[tokio::test]
async fn test_bond_active_backup_with_slaves() -> Result<()> {
    require_root!();
    nlink::require_modules!("bonding", "veth");

    let ns = TestNamespace::new("bond-ab")?;
    let conn = ns.connection()?;

    // Create active-backup bond
    conn.add_link(
        BondLink::new("bond0")
            .mode(BondMode::ActiveBackup)
            .miimon(100),
    )
    .await?;

    // Create dummy slaves
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.add_link(DummyLink::new("eth1")).await?;

    // Enslave to bond
    conn.set_link_down("eth0").await?;
    conn.set_link_down("eth1").await?;
    conn.set_link_master("eth0", "bond0").await?;
    conn.set_link_master("eth1", "bond0").await?;

    // Verify they are attached
    let links = conn.get_links().await?;
    let bond = links.iter().find(|l| l.name() == Some("bond0")).unwrap();
    let eth0 = links.iter().find(|l| l.name() == Some("eth0")).unwrap();
    let eth1 = links.iter().find(|l| l.name() == Some("eth1")).unwrap();

    assert_eq!(eth0.master(), Some(bond.ifindex()));
    assert_eq!(eth1.master(), Some(bond.ifindex()));

    Ok(())
}

#[tokio::test]
async fn test_enslave_convenience() -> Result<()> {
    require_root!();
    nlink::require_modules!("bonding", "veth");

    let ns = TestNamespace::new("enslave")?;
    let conn = ns.connection()?;

    // Create bond and two dummy interfaces
    conn.add_link(BondLink::new("bond0").mode(BondMode::BalanceRr))
        .await?;
    conn.add_link(DummyLink::new("eth0")).await?;
    conn.add_link(DummyLink::new("eth1")).await?;

    // enslave() handles down/master/up automatically
    conn.enslave("eth0", "bond0").await?;
    conn.enslave("eth1", "bond0").await?;

    // Verify slaves are attached
    let links = conn.get_links().await?;
    let bond = links.iter().find(|l| l.name() == Some("bond0")).unwrap();
    let eth0 = links.iter().find(|l| l.name() == Some("eth0")).unwrap();
    let eth1 = links.iter().find(|l| l.name() == Some("eth1")).unwrap();
    assert_eq!(eth0.master(), Some(bond.ifindex()));
    assert_eq!(eth1.master(), Some(bond.ifindex()));

    // Verify slaves are up (enslave brings them back up)
    assert!(eth0.is_up(), "eth0 should be up after enslave");
    assert!(eth1.is_up(), "eth1 should be up after enslave");

    Ok(())
}

#[tokio::test]
async fn test_create_netkit_pair() -> Result<()> {
    require_root!();
    nlink::require_modules!("netkit");

    let ns = TestNamespace::new("netkit-pair")?;
    let conn = ns.connection()?;

    // Create a netkit pair in L3 mode with forward policy.
    conn.add_link(
        NetkitLink::new("nk0", "nk1")
            .mode(NetkitMode::L3)
            .policy(NetkitPolicy::Forward),
    )
    .await?;

    let links = conn.get_links().await?;
    assert!(
        links.iter().any(|l| l.name() == Some("nk0")),
        "primary netkit interface nk0 should exist"
    );
    assert!(
        links.iter().any(|l| l.name() == Some("nk1")),
        "peer netkit interface nk1 should exist"
    );

    // Verify kind reports as "netkit".
    let nk0 = links.iter().find(|l| l.name() == Some("nk0")).unwrap();
    assert_eq!(nk0.kind(), Some("netkit"));

    // Delete the pair (deleting one half removes the other).
    conn.del_link("nk0").await?;

    let links = conn.get_links().await?;
    assert!(
        !links.iter().any(|l| l.name() == Some("nk0")),
        "nk0 should be deleted"
    );
    assert!(
        !links.iter().any(|l| l.name() == Some("nk1")),
        "peer nk1 should also be deleted (pair removal is symmetric)"
    );

    Ok(())
}

/// A bridge created with an MTU keeps it when a port with a smaller MTU
/// joins. The kernel treats a bridge MTU as the user's only after an
/// RTM_SETLINK that changes it, so the IFLA_MTU it was created with gave
/// way to the port's (#474).
#[tokio::test]
async fn a_bridge_created_with_an_mtu_keeps_it() -> Result<()> {
    require_root!();
    nlink::require_modules!("bridge", "dummy");

    let ns = TestNamespace::new("brmtu")?;
    let conn = ns.connection()?;
    conn.add_link(BridgeLink::new("br0").mtu(9000)).await?;
    conn.add_link(DummyLink::new("d0").mtu(1500)).await?;
    conn.set_link_master("d0", "br0").await?;
    assert_eq!(link_mtu(&conn, "br0").await?, Some(9000));
    conn.set_link_mtu("d0", 1400).await?;
    assert_eq!(link_mtu(&conn, "br0").await?, Some(9000));

    // An existing, unpinned bridge: pin it.
    conn.add_link(BridgeLink::new("br1")).await?;
    conn.add_link(DummyLink::new("d1").mtu(1500)).await?;
    conn.set_link_master("d1", "br1").await?;
    conn.pin_bridge_mtu("br1", 1500).await?;
    conn.set_link_mtu("d1", 1400).await?;
    let br1 = link_mtu(&conn, "br1").await?;
    assert_eq!(br1, Some(1500), "a pinned bridge does not follow its port");
    Ok(())
}

async fn link_mtu(conn: &nlink::Connection<nlink::Route>, name: &str) -> Result<Option<u32>> {
    Ok(conn.get_link_by_name(name).await?.and_then(|l| l.mtu()))
}

/// #495: a name lookup is one `RTM_GETLINK`, and so finds a link by its
/// alternative names too — a short one through `IFLA_IFNAME`, which the
/// kernel looks up in the same table, and one longer than 15 bytes
/// through `IFLA_ALT_IFNAME`. Searching a full dump by primary name, as
/// it used to, found neither.
#[tokio::test]
async fn a_link_is_found_by_its_alternative_names() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("altname")?;
    let conn = ns.connection()?;
    conn.add_link(nlink::netlink::link::DummyLink::new("d0"))
        .await?;
    let long = "dummy-with-a-long-alternative-name";
    ns.exec(
        "ip",
        &["link", "property", "add", "dev", "d0", "altname", "alt0"],
    )?;
    ns.exec(
        "ip",
        &["link", "property", "add", "dev", "d0", "altname", long],
    )?;
    let d0 = conn.get_link_by_name("d0").await?.expect("d0").ifindex();

    for name in ["alt0", long] {
        let found = conn.get_link_by_name(name).await?;
        assert_eq!(found.map(|l| l.ifindex()), Some(d0), "{name}");
    }
    // Every name-taking method resolves through it.
    conn.set_link_up(long).await?;
    let up = conn.get_link_by_index(d0).await?.expect("d0");
    assert!(up.is_up(), "set_link_up by a long altname");
    Ok(())
}

// ============================================================================
// #524 — waiting for a link and for duplicate address detection
// ============================================================================

/// `wait_link` waits for the condition asked for. A veth whose peer is
/// down is up (`IFF_UP`) at once but has no carrier, so the carrier wait
/// times out; once the peer comes up it has a carrier and runs.
#[tokio::test]
async fn wait_link_waits_for_a_carrier() -> Result<()> {
    use nlink::LinkCond;
    use std::time::Duration;
    require_root!();
    nlink::require_modules!("veth");

    let ns = TestNamespace::new("wait-carrier")?;
    let conn = ns.connection()?;
    conn.add_link(VethLink::new("va", "vb")).await?;
    conn.set_link_up("va").await?;
    conn.wait_link("va", LinkCond::AdminUp, Duration::from_secs(1))
        .await?;
    let err = conn
        .wait_link("va", LinkCond::Carrier, Duration::from_millis(300))
        .await
        .expect_err("no carrier while the peer is down");
    assert!(err.is_timeout(), "{err}");

    conn.set_link_up("vb").await?;
    let link = conn
        .wait_link("va", LinkCond::Carrier, Duration::from_secs(5))
        .await?;
    assert_eq!(link.carrier(), Some(true));
    conn.wait_link("va", LinkCond::Running, Duration::from_secs(5))
        .await?;
    Ok(())
}

/// An IPv6 address is tentative until duplicate address detection is
/// done; `wait_addresses_settled` waits it out. Tests that pinged right
/// after configuring an address shelled out to `ip -6 addr` to grep for
/// "tentative" (#524).
#[tokio::test]
async fn ipv6_addresses_settle() -> Result<()> {
    use nlink::netlink::addr::Ipv6Address;
    use std::time::Duration;
    require_root!();
    nlink::require_modules!("veth");

    let pair = crate::common::topo::NsPair::new("wait-dad", 92).await?;
    let conn = pair.a.connection()?;
    let addr: std::net::Ipv6Addr = "fd00:92::10".parse().unwrap();
    conn.add_address(Ipv6Address::with_index(pair.a_ifindex, addr, 64))
        .await?;
    let tentative = |addresses: &[nlink::netlink::messages::AddressMessage]| {
        addresses
            .iter()
            .any(|a| a.address() == Some(&std::net::IpAddr::from(addr)) && a.is_tentative())
    };
    assert!(tentative(
        &conn.get_addresses_by_index(pair.a_ifindex).await?
    ));
    conn.wait_addresses_settled(Some(pair.a_ifindex.into()), Duration::from_secs(10))
        .await?;
    assert!(!tentative(
        &conn.get_addresses_by_index(pair.a_ifindex).await?
    ));
    Ok(())
}

/// An address the other end of the link already has fails DAD, and the
/// wait says so instead of timing out.
#[tokio::test]
async fn a_duplicate_ipv6_address_fails_the_wait() -> Result<()> {
    use nlink::netlink::addr::Ipv6Address;
    use std::time::Duration;
    require_root!();
    nlink::require_modules!("veth");

    let pair = crate::common::topo::NsPair::new("wait-dupe", 93).await?;
    // b's address is configured without DAD (`nodad`) and is in use.
    pair.a
        .connection()?
        .add_address(Ipv6Address::with_index(pair.a_ifindex, pair.b_addr6, 64))
        .await?;
    let err = pair
        .a
        .connection()?
        .wait_addresses_settled(Some(pair.a_ifindex.into()), Duration::from_secs(10))
        .await
        .expect_err("DAD finds b's address");
    assert!(err.is_dad_failed(), "{err}");
    match err.detail() {
        nlink::ErrorDetail::DadFailed { addresses } => {
            assert_eq!(*addresses, [std::net::IpAddr::from(pair.b_addr6)]);
        }
        other => panic!("{other}"),
    }
    Ok(())
}

// ============================================================================
// #517 — master, up, alias and namespace at creation
// ============================================================================

/// A link takes its master, its up state and an alias in the one
/// `add_link`. The alias is read back through `ip`, and is set after the
/// create because the kernel ignores `IFLA_IFALIAS` on one.
#[tokio::test]
async fn a_link_is_created_enslaved_up_and_tagged() -> Result<()> {
    use nlink::netlink::link::LinkCreateExt;
    require_root!();
    nlink::require_modules!("dummy", "bridge");

    let ns = TestNamespace::new("create-opts")?;
    let conn = ns.connection()?;
    conn.add_link(BridgeLink::new("br0")).await?;
    conn.add_link(
        DummyLink::new("d0")
            .mtu(1400)
            .master("br0")
            .up()
            .alias("lab:d0"),
    )
    .await?;

    let d0 = conn.get_link_by_name("d0").await?.expect("d0 exists");
    let br0 = conn.get_link_by_name("br0").await?.expect("br0 exists");
    assert!(d0.is_up());
    assert_eq!(d0.master(), Some(br0.ifindex()));
    assert_eq!(d0.mtu(), Some(1400));
    assert_eq!(d0.alias(), Some("lab:d0"));
    let shown = ns.exec("ip", &["-j", "-d", "link", "show", "dev", "d0"])?;
    assert!(shown.contains(r#""ifalias":"lab:d0""#), "{shown}");

    conn.set_link_alias("d0", "").await?;
    assert_eq!(
        conn.get_link_by_name("d0").await?.expect("d0").alias(),
        None
    );
    Ok(())
}

/// A link created in another namespace goes straight there — with no
/// window in the creating one — and finds its master there.
#[tokio::test]
async fn a_link_is_created_in_another_namespace() -> Result<()> {
    use nlink::netlink::link::LinkCreateExt;
    require_root!();
    nlink::require_modules!("dummy", "bridge");

    let here = TestNamespace::new("create-here")?;
    let there = TestNamespace::new("create-there")?;
    let there_conn = there.connection()?;
    there_conn.add_link(BridgeLink::new("brt")).await?;

    let fd = std::fs::File::open(format!("/var/run/netns/{}", there.name()))?;
    let conn = here.connection()?;
    conn.add_link(
        DummyLink::new("dt")
            .netns(&fd)
            .master("brt")
            .up()
            .alias("moved"),
    )
    .await?;

    assert!(
        conn.get_link_by_name("dt").await?.is_none(),
        "dt stayed here"
    );
    let dt = there_conn
        .get_link_by_name("dt")
        .await?
        .expect("dt is there");
    let brt = there_conn.get_link_by_name("brt").await?.expect("brt");
    assert!(dt.is_up());
    assert_eq!(dt.master(), Some(brt.ifindex()));
    assert_eq!(dt.alias(), Some("moved"));
    Ok(())
}

/// `get_bridge_vlans_all` returns the VLANs of a bridge's ports, not just
/// its own: the filter kept only the bridge's entries before matching
/// ports by master, so every port's were dropped. And `get_bridge_vlans`
/// returns a port's (#516).
#[tokio::test]
async fn bridge_vlans_all_includes_the_ports() -> Result<()> {
    use nlink::netlink::bridge_vlan::BridgeVlanBuilder;
    require_root!();
    nlink::require_modules!("dummy", "bridge");

    let ns = TestNamespace::new("brvlan-all")?;
    let conn = ns.connection()?;
    conn.add_link(BridgeLink::new("br0").vlan_filtering(true)).await?;
    conn.add_link(DummyLink::new("d0")).await?;
    conn.set_link_master("d0", "br0").await?;
    conn.add_bridge_vlan(BridgeVlanBuilder::new(10).dev("d0")).await?;

    let d0 = conn.get_link_by_name("d0").await?.expect("d0").ifindex();
    let vids: Vec<u16> = conn
        .get_bridge_vlans_all("br0")
        .await?
        .iter()
        .filter(|v| v.ifindex() == d0)
        .map(|v| v.vid())
        .collect();
    assert!(vids.contains(&10), "d0's VLANs: {vids:?}");

    // One port's, by name and by index, likewise.
    let own: Vec<u16> = conn.get_bridge_vlans("d0").await?.iter().map(|v| v.vid()).collect();
    assert!(own.contains(&10), "get_bridge_vlans(d0): {own:?}");
    Ok(())
}

/// A Geneve flow label reaches the kernel as given (#516): it is
/// big-endian on the wire, and a native-endian one was another label.
#[tokio::test]
async fn a_geneve_flow_label_is_the_one_asked_for() -> Result<()> {
    use nlink::netlink::link::GeneveLink;
    require_root!();
    nlink::require_modules!("geneve");

    let ns = TestNamespace::new("geneve-label")?;
    let conn = ns.connection()?;
    conn.add_link(
        GeneveLink::new("gn0", 5)
            .remote6("fd00::2".parse().unwrap())
            .label(0x12345),
    )
    .await?;
    let shown = ns.exec("ip", &["-d", "-j", "link", "show", "gn0"])?;
    let shown: serde_json::Value = serde_json::from_str(&shown).expect("ip -j");
    let data = &shown[0]["linkinfo"]["info_data"];
    assert_eq!(data["label"], "0x12345", "{data}");
    Ok(())
}

/// A MACsec link's SCI and port reach the kernel as given (#516): both are
/// big-endian on the wire (iproute2 sends the SCI with `get_be64`, the
/// kernel reads the port with `nla_get_be16`). `0x0200000000010001` is MAC
/// 02:00:00:00:00:01, port 1.
#[tokio::test]
async fn a_macsec_sci_and_port_are_the_ones_asked_for() -> Result<()> {
    use nlink::netlink::link::MacsecLink;
    require_root!();
    nlink::require_modules!("dummy", "macsec");

    let ns = TestNamespace::new("macsec-sci")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    conn.add_link(MacsecLink::new("ms0", "d0").sci(0x0200_0000_0001_0001)).await?;
    conn.add_link(MacsecLink::new("ms1", "d0").port(7)).await?;
    let data = |dev: &str| -> serde_json::Value {
        let shown = ns.exec("ip", &["-d", "-j", "link", "show", dev]).expect("ip");
        let v: serde_json::Value = serde_json::from_str(&shown).expect("ip -j");
        v[0]["linkinfo"]["info_data"].clone()
    };
    assert_eq!(data("ms0")["sci"], "0200000000010001");
    // The port is the SCI's last 16 bits when the kernel derives it.
    let sci = data("ms1")["sci"].as_str().unwrap_or_default().to_string();
    assert!(sci.ends_with("0007"), "port 7 in SCI {sci}");
    Ok(())
}

/// The MACsec Generic Netlink API reads and writes an SCI as the kernel
/// and `ip macsec` do: big-endian, MAC then port (#516). Its commands are
/// `GENL_ADMIN_PERM`, checked against the initial user namespace.
#[tokio::test]
async fn the_macsec_genl_api_reads_and_writes_the_sci_as_the_kernel_does() -> Result<()> {
    use nlink::netlink::link::MacsecLink;
    require_root!();
    nlink::require_host_root!();
    nlink::require_modules!("dummy", "macsec");

    let ns = TestNamespace::new("macsec-genl")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    conn.add_link(MacsecLink::new("ms0", "d0").sci(0x0200_0000_0001_0001)).await?;
    let genl = ns.connection_for_async::<nlink::netlink::Macsec>().await?;
    assert_eq!(genl.get_device("ms0").await?.sci, 0x0200_0000_0001_0001);
    genl.add_rx_sc("ms0", 0x0200_0000_0002_0001).await?;
    let shown = ns.exec("ip", &["macsec", "show", "ms0"])?;
    assert!(shown.contains("0200000000020001"), "{shown}");
    Ok(())
}

/// #526: `Batch::execute_all` returns the failing operation's error, so
/// its errno answers the predicates. It returned a string of it, which
/// answered none of them.
#[tokio::test]
async fn a_failed_batch_operation_keeps_its_errno() -> Result<()> {
    require_root!();
    let ns = TestNamespace::new("batch-errno")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    let err = conn
        .batch()
        .add_link(DummyLink::new("d0"))
        .execute_all()
        .await
        .expect_err("d0 exists");
    assert!(err.is_already_exists(), "{err}");
    assert_eq!(err.context(), ["batch operation 0"]);
    Ok(())
}
