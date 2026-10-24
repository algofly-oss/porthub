//! `Stack::plan_in` → `StackPlan` → `StackPlan::apply` (#519): one diff of
//! every layer, applied as it was planned.

use std::net::{IpAddr, Ipv4Addr};

use nlink::ExecOptions;
use nlink::facade::Stack;
use nlink::netlink::Nftables;
use nlink::netlink::addr::Ipv4Address;
use nlink::netlink::config::{ApplyOptions, NetworkConfig, PlanOptions};
use nlink::netlink::namespace::NamespaceSpec;
use nlink::netlink::nftables::{Family, config::NftablesConfig};
use nlink::reconcile::ReconcileOptions;

use crate::common::{TestNamespace, with_timeout};

fn v4(conn_addrs: &[nlink::netlink::messages::AddressMessage]) -> Vec<IpAddr> {
    conn_addrs
        .iter()
        .filter(|a| a.is_ipv4())
        .filter_map(|a| a.address().copied())
        .collect()
}

/// The apply applies the plan, not a fresh diff: an address added after a
/// purging plan was made is not swept up by it — and `verify`, which plans
/// every layer again, catches it.
#[tokio::test]
async fn a_stack_plan_applies_what_it_planned_and_verify_sees_the_rest() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("dummy", "nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("stackplan")?;
        let spec = || NamespaceSpec::Named(ns.name());
        let stack = Stack::new()
            .network(
                NetworkConfig::new()
                    .link("d0", |l| l.dummy().up())
                    .address("d0", "10.64.0.1/24")?,
            )
            .nftables(NftablesConfig::new().table("plan", Family::Inet, |t| t));

        let plan = stack
            .plan_in(spec(), PlanOptions::default().purge(true))
            .await?;
        let shown = plan.to_string();
        assert!(shown.contains("network:\n") && shown.contains("nftables:\n"), "{shown}");
        assert_eq!(plan.change_count(), 3, "link, address, table: {shown}");

        // Applied as planned: everything converges.
        let report = plan.apply(spec(), ExecOptions::new().with_verify(true)).await?;
        assert_eq!(report.change_count(), 3, "{report:?}");
        assert!(stack.plan_in(spec(), PlanOptions::default()).await?.is_empty());

        // A plan made, then the kernel changed under it.
        let plan = stack
            .plan_in(spec(), PlanOptions::default().purge(true))
            .await?;
        assert!(plan.is_empty(), "{plan}");
        let conn = ns.connection()?;
        conn.add_address(Ipv4Address::new("d0", Ipv4Addr::new(10, 64, 0, 9), 24))
            .await?;

        // The plan had nothing to remove, so the stray address stays...
        let report = plan.apply(spec(), ExecOptions::new()).await?;
        assert!(report.is_noop(), "{report:?}");
        assert!(v4(&conn.get_addresses_by_name("d0").await?).contains(&IpAddr::V4(Ipv4Addr::new(10, 64, 0, 9))));

        // ...and verify, planning again, finds it.
        let err = plan
            .apply(spec(), ExecOptions::new().with_verify(true))
            .await
            .expect_err("the stray address is left");
        let nlink::ErrorDetail::StackNotConverged { remaining } = err.detail() else {
            panic!("not StackNotConverged: {err}");
        };
        assert!(remaining.to_string().contains("10.64.0.9"), "{remaining}");
        assert_eq!(err.kind(), nlink::ErrorKind::NotConverged);

        // A purging apply of the stack plans again and removes it.
        let report = stack
            .apply_in_with(spec(), ApplyOptions::default().with_purge(true))
            .await?;
        assert_eq!(report.change_count(), 1, "{report:?}");
        Ok(())
    })
    .await
}

/// A firewall commit the ruleset moved under is refused (`ERESTART`, #482),
/// so a stale plan does not overwrite what another writer did; the stack's
/// reconcile plans again and goes through.
#[tokio::test]
async fn a_stale_firewall_plan_is_refused_and_the_reconcile_replans() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("stackstale")?;
        let spec = || NamespaceSpec::Named(ns.name());
        let stack = Stack::new().nftables(NftablesConfig::new().table("mine", Family::Inet, |t| t));

        let plan = stack.plan_in(spec(), PlanOptions::default()).await?;
        let nft = ns.connection_for::<Nftables>()?;
        nft.add_table("theirs", Family::Inet).await?;

        let err = plan
            .apply(spec(), ExecOptions::new())
            .await
            .expect_err("the ruleset moved since the plan");
        assert!(err.is_restart(), "{err}");

        let report = stack
            .apply_reconcile_in(spec(), ReconcileOptions::default(), ApplyOptions::default())
            .await?;
        assert_eq!((report.nftables, report.attempts), (Some(1), 1), "{report:?}");
        let tables: Vec<String> = nft.list_tables().await?.into_iter().map(|t| t.name).collect();
        assert!(tables.contains(&"mine".into()) && tables.contains(&"theirs".into()), "{tables:?}");
        Ok(())
    })
    .await
}

/// A network declaration on the WireGuard link the plan creates — its MTU —
/// lands in the same apply: the network layer, planned while the link did
/// not exist, is planned again once step 0 has made it.
#[tokio::test]
async fn a_layer_planned_before_its_wireguard_link_existed_is_planned_again() -> nlink::Result<()> {
    nlink::require_root!();
    // Creating a WireGuard link is checked against the initial user
    // namespace (#357).
    nlink::require_host_root!();
    nlink::require_modules!("wireguard");

    with_timeout(async {
        use nlink::netlink::genl::wireguard::WireguardConfig;

        let ns = TestNamespace::new("stackwg")?;
        let spec = || NamespaceSpec::Named(ns.name());
        let stack = Stack::new()
            .network(NetworkConfig::new().link("wgp0", |l| l.mtu(1380)))
            .wireguard(WireguardConfig::new().device("wgp0", |d| d.listen_port(51998)));

        let plan = stack.plan_in(spec(), PlanOptions::default()).await?;
        assert_eq!(plan.wireguard_devices, ["wgp0"]);
        let report = plan.apply(spec(), ExecOptions::new().with_verify(true)).await?;
        assert_eq!(report.wireguard_devices_created, ["wgp0"]);

        let conn = ns.connection()?;
        let link = conn.get_link_by_name("wgp0").await?.expect("wgp0 exists");
        assert_eq!(link.mtu(), Some(1380));
        assert!(stack.plan_in(spec(), PlanOptions::default()).await?.is_empty());
        Ok(())
    })
    .await
}
