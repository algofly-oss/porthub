//! Bridge FDB integration tests.

use nlink::{
    Connection, Result, Route,
    netlink::link::{BridgeLink, DummyLink},
};

use crate::common::TestNamespace;

/// A bridge `br0` with an up dummy port `p0`.
async fn bridge_with_port(ns_name: &str) -> Result<(TestNamespace, Connection<Route>)> {
    let ns = TestNamespace::new(ns_name)?;
    let conn = ns.connection()?;
    conn.add_link(BridgeLink::new("br0")).await?;
    conn.add_link(DummyLink::new("p0")).await?;
    conn.set_link_master("p0", "br0").await?;
    conn.set_link_up("br0").await?;
    conn.set_link_up("p0").await?;
    Ok((ns, conn))
}

/// `bridge -j fdb show dev p0`, as `(mac, state)` pairs for the bridge's
/// entries.
fn port_entries(ns: &TestNamespace) -> Result<Vec<(String, String)>> {
    let out = ns.exec("bridge", &["-j", "fdb", "show", "dev", "p0"])?;
    let all: serde_json::Value = serde_json::from_str(&out).expect("bridge -j");
    Ok(all
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["master"] == "br0")
        .map(|e| (e["mac"].as_str().unwrap_or("").to_string(), e["state"].as_str().unwrap_or("").to_string()))
        .collect())
}

/// `flush_fdb` removes the dynamic entries and keeps the static and
/// permanent ones, as it says (#663). A static entry is `NUD_NOARP`, which
/// `is_dynamic()` took for dynamic, so the flush deleted it.
#[tokio::test]
async fn flush_fdb_keeps_static_and_permanent_entries() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("bridge", "dummy");

    let (ns, conn) = bridge_with_port("fdbflush").await?;
    for (mac, state) in [
        ("02:00:00:00:66:01", "static"),
        ("02:00:00:00:66:02", "permanent"),
        ("02:00:00:00:66:03", "dynamic"),
    ] {
        ns.exec("bridge", &["fdb", "add", mac, "dev", "p0", "master", state])?;
    }
    conn.flush_fdb("br0").await?;

    let left = port_entries(&ns)?;
    let has = |mac: &str| left.iter().any(|(m, _)| m == mac);
    assert!(has("02:00:00:00:66:01"), "the static entry was flushed: {left:?}");
    assert!(has("02:00:00:00:66:02"), "the permanent entry was flushed: {left:?}");
    assert!(!has("02:00:00:00:66:03"), "the dynamic entry stayed: {left:?}");
    Ok(())
}

/// `FdbEntryBuilder::static_()` makes the entry `bridge fdb` calls
/// `static`, and the default one it calls `permanent`; `get_fdb` reads
/// each back as what it is (#663).
#[tokio::test]
async fn the_builder_makes_static_and_permanent_entries() -> Result<()> {
    use nlink::netlink::fdb::FdbEntryBuilder;
    nlink::require_root!();
    nlink::require_modules!("bridge", "dummy");

    let (ns, conn) = bridge_with_port("fdbstate").await?;
    conn.add_fdb(FdbEntryBuilder::new([2, 0, 0, 0, 0x66, 0x11]).dev("p0").static_())
        .await?;
    conn.add_fdb(FdbEntryBuilder::new([2, 0, 0, 0, 0x66, 0x12]).dev("p0")).await?;

    let shown = port_entries(&ns)?;
    let state = |mac: &str| shown.iter().find(|(m, _)| m == mac).map(|(_, s)| s.as_str());
    assert_eq!(state("02:00:00:00:66:11"), Some("static"), "{shown:?}");
    assert_eq!(state("02:00:00:00:66:12"), Some("permanent"), "{shown:?}");

    let entries = conn.get_fdb("br0").await?;
    let read = |mac: [u8; 6]| entries.iter().find(|e| e.mac() == mac).expect("listed");
    let s = read([2, 0, 0, 0, 0x66, 0x11]);
    assert!(s.is_static() && !s.is_dynamic(), "{s:?}");
    assert!(read([2, 0, 0, 0, 0x66, 0x12]).is_permanent());
    Ok(())
}

/// A VXLAN remote goes in the device's own table: `self_()`. Without it the
/// kernel looks for a bridge the device is a port of, and with none it is
/// `EOPNOTSUPP` — which the module's own example did (#663).
#[tokio::test]
async fn a_vxlan_remote_goes_in_the_devices_own_table() -> Result<()> {
    use nlink::netlink::fdb::FdbEntryBuilder;
    use nlink::netlink::link::VxlanLink;
    nlink::require_root!();
    nlink::require_modules!("vxlan");

    let ns = TestNamespace::new("fdbvxlan")?;
    let conn = ns.connection()?;
    conn.add_link(VxlanLink::new("vx0", 5).port(4789).local(std::net::Ipv4Addr::new(10, 0, 0, 1)))
        .await?;
    let remote = |last: u8| FdbEntryBuilder::new([0; 6]).dev("vx0").dst(std::net::Ipv4Addr::new(10, 0, 0, last).into());
    let err = conn.add_fdb(remote(2)).await.expect_err("not a bridge port");
    assert!(err.is_not_supported(), "{err}");
    conn.add_fdb(remote(3).self_()).await?;
    let shown = ns.exec("bridge", &["fdb", "show", "dev", "vx0"])?;
    assert!(shown.contains("00:00:00:00:00:00 dst 10.0.0.3 self permanent"), "{shown}");
    Ok(())
}
