//! `nlink::blocking::Connection` (#533): netlink from code that cannot
//! `.await`.

use nlink::netlink::link::DummyLink;
use nlink::netlink::namespace::NetnsRef;
use nlink::{Result, Route};

use crate::common::TestNamespace;

/// Deletes a link when dropped, through a blocking connection.
struct LinkGuard {
    conn: nlink::blocking::Connection<Route>,
    name: &'static str,
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        assert!(self.conn.del_link_if_exists(self.name).expect("delete"));
    }
}

/// A `Drop` inside a tokio runtime deletes the link it guards: the call
/// runs on the blocking connection's own runtime, where
/// `Runtime::block_on` on this thread would panic ("Cannot start a runtime
/// from within a runtime").
#[tokio::test]
async fn a_drop_inside_a_runtime_deletes_what_it_guards() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("blocking-drop")?;
    ns.connection()?.add_link(DummyLink::new("g0")).await?;
    {
        let conn = nlink::blocking::Connection::<Route>::in_netns(NetnsRef::Named(ns.name().to_string()))?;
        assert!(conn.get_links()?.iter().any(|l| l.name() == Some("g0")));
        let _guard = LinkGuard { conn, name: "g0" };
    }
    assert!(ns.connection()?.get_link_by_name("g0").await?.is_none());
    Ok(())
}

/// With no runtime at all, a call works, and `run` takes any async work.
#[test]
fn a_call_without_a_runtime() -> Result<()> {
    nlink::require_root!();

    let ns = TestNamespace::new("blocking-sync")?;
    let conn = nlink::blocking::Connection::<Route>::in_netns(NetnsRef::Named(ns.name().to_string()))?;
    let mtu = conn.run(|c| Box::pin(async move { Ok::<_, nlink::Error>(c.get_link_by_name("lo").await?.and_then(|l| l.mtu())) }))?;
    assert_eq!(mtu, Some(65536));
    assert!(!conn.del_link_if_exists("nope0")?);
    Ok(())
}

/// The nftables helpers read a table's rules and delete it.
#[test]
fn nftables_rules_are_read_and_a_table_deleted() -> Result<()> {
    use nlink::netlink::nftables::Family;
    nlink::require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("blocking-nft")?;
    ns.exec("nft", &["add", "table", "inet", "t"])?;
    ns.exec("nft", &["add", "chain", "inet", "t", "c"])?;
    ns.exec("nft", &["add", "rule", "inet", "t", "c", "counter"])?;
    let conn = nlink::blocking::Connection::<nlink::Nftables>::in_netns(NetnsRef::Named(ns.name().to_string()))?;
    assert!(conn.list_tables()?.iter().any(|t| t.name == "t"));
    assert_eq!(conn.list_rules("t", Family::Inet)?.len(), 1);
    assert!(conn.del_table_if_exists("t", Family::Inet)?);
    assert!(!conn.del_table_if_exists("t", Family::Inet)?);
    Ok(())
}
