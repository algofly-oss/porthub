//! The `netdev` Generic Netlink family (#166), read on veths and `lo` and
//! checked against what iproute2 and rtnetlink say about the same devices.

use nlink::netlink::genl::netdev::{Netdev, NetdevQueueType, XdpFeatures};
use nlink::netlink::link::VethLink;
use nlink::netlink::{Connection, Ethtool, Route};
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

/// Collect a typed dump.
async fn all<T, S>(mut stream: S) -> nlink::Result<Vec<T>>
where
    S: tokio_stream::Stream<Item = nlink::Result<T>> + Unpin,
{
    let mut out = Vec::new();
    while let Some(item) = stream.next().await {
        out.push(item?);
    }
    Ok(out)
}

/// A namespace with a veth pair `ve0`/`ve1`, and its `netdev` connection.
async fn veth_ns(name: &str) -> nlink::Result<(TestNamespace, Connection<Netdev>, u32)> {
    let ns = TestNamespace::new(name)?;
    let route: Connection<Route> = ns.connection()?;
    route.add_link(VethLink::new("ve0", "ve1")).await?;
    route.set_link_up("ve0").await?;
    route.set_link_up("ve1").await?;
    let ve0 = route.get_link_by_name("ve0").await?.expect("ve0").ifindex();
    let netdev: Connection<Netdev> = Connection::new_in_async(ns.name()).await?;
    Ok((ns, netdev, ve0))
}

/// Whether the kernel has the `netdev` family (6.3+). A kernel without it
/// is not a failure of nlink's, and says so.
async fn has_netdev_family() -> bool {
    match Connection::<Netdev>::new_async().await {
        Ok(_) => true,
        Err(e) if e.is_not_found() => {
            eprintln!("skipping: no netdev family (kernel < 6.3)");
            false
        }
        Err(e) => panic!("netdev family: {e}"),
    }
}

/// #166: every device in the namespace is in the features dump, with the
/// ifindexes rtnetlink gives; a veth does basic XDP and redirects, `lo`
/// does no XDP at all.
#[tokio::test]
async fn devices_report_their_xdp_features() -> nlink::Result<()> {
    require_root!();
    nlink::require_module!("veth");
    if !has_netdev_family().await {
        return Ok(());
    }

    let (ns, netdev, ve0) = veth_ns("gnl-dev").await?;
    let route: Connection<Route> = ns.connection()?;
    let mut have: Vec<u32> = all(netdev.dump_netdevs().await?)
        .await?
        .iter()
        .filter_map(|d| d.ifindex)
        .collect();
    let mut want: Vec<u32> = route.get_links().await?.iter().map(|l| l.ifindex()).collect();
    have.sort();
    want.sort();
    assert_eq!(have, want, "the dump covers every link");

    // veth_setup: basic XDP, redirect and non-linear frames, nothing in
    // hardware; its XDP metadata ops give a timestamp and a hash.
    let veth = netdev.get_netdev(ve0).await?;
    assert_eq!(veth.ifindex, Some(ve0));
    let features = veth.xdp_features();
    assert!(
        features.contains(XdpFeatures::BASIC | XdpFeatures::REDIRECT | XdpFeatures::RX_SG)
            && !features.contains(XdpFeatures::HW_OFFLOAD),
        "{:#x}",
        features.0
    );
    assert_eq!(veth.xdp_rx_metadata_features.map(|m| m & 3), Some(3));
    let lo = route.get_link_by_name("lo").await?.expect("lo").ifindex();
    let lo = netdev.get_netdev(lo).await?;
    assert_eq!((lo.xdp_features().0, lo.xdp_rx_metadata_features), (0, Some(0)));
    Ok(())
}

/// #166: a veth's queues are the ones it has in use, and follow its
/// channel count as ethtool changes it: 2 RX and 2 TX, then 3 and 3.
#[tokio::test]
async fn a_devices_queues_follow_its_channels() -> nlink::Result<()> {
    require_root!();
    nlink::require_module!("veth");
    if !has_netdev_family().await {
        return Ok(());
    }

    let (ns, netdev, ve0) = veth_ns("gnl-queue").await?;
    let ethtool: Connection<Ethtool> = Connection::new_in_async(ns.name()).await?;
    for count in [2u32, 3] {
        ethtool.set_channels("ve0", |c| c.rx(count).tx(count)).await?;
        let mut have: Vec<String> = all(netdev.dump_queues(ve0).await?)
            .await?
            .iter()
            .map(|q| {
                assert_eq!(q.ifindex, Some(ve0));
                let kind = match q.queue_type {
                    Some(NetdevQueueType::Rx) => "rx",
                    Some(NetdevQueueType::Tx) => "tx",
                    other => panic!("queue type {other:?}"),
                };
                format!("{kind}-{}", q.id.expect("queue id"))
            })
            .collect();
        have.sort();
        let mut want: Vec<String> = (0..count)
            .flat_map(|i| [format!("rx-{i}"), format!("tx-{i}")])
            .collect();
        want.sort();
        assert_eq!(have, want, "{count} channels");
    }
    let rx2 = netdev.get_queue(ve0, NetdevQueueType::Rx, 2).await?;
    assert_eq!((rx2.id, rx2.queue_type), (Some(2), Some(NetdevQueueType::Rx)));
    Ok(())
}

/// #166: a veth has no NAPI instance until GRO is on, and none once it is
/// off again; while it is on, each instance reads back by its id.
#[tokio::test]
async fn gro_gives_a_veth_napi_instances() -> nlink::Result<()> {
    require_root!();
    nlink::require_module!("veth");
    if !has_netdev_family().await {
        return Ok(());
    }

    let (ns, netdev, ve0) = veth_ns("gnl-napi").await?;
    assert!(all(netdev.dump_napis(ve0).await?).await?.is_empty(), "no NAPI without GRO");

    let ethtool: Connection<Ethtool> = Connection::new_in_async(ns.name()).await?;
    ethtool.set_features("ve0", |f| f.enable("rx-gro")).await?;
    let napis = all(netdev.dump_napis(ve0).await?).await?;
    assert!(!napis.is_empty(), "GRO on: NAPI instances");
    for napi in &napis {
        assert_eq!(napi.ifindex, Some(ve0));
        let id = napi.id.expect("napi id");
        assert_eq!(netdev.get_napi(id).await?.id, Some(id));
    }
    ethtool.set_features("ve0", |f| f.disable("rx-gro")).await?;
    assert!(all(netdev.dump_napis(ve0).await?).await?.is_empty(), "GRO off: none");
    Ok(())
}

/// #166: veth and `lo` keep no statistics in the standard set: asking
/// for a veth's is `EOPNOTSUPP`, and the dump of every device leaves them
/// out. On the host, a NIC whose driver keeps them reports at least as
/// many packets as sysfs had a moment earlier.
#[tokio::test]
async fn queue_statistics_are_the_drivers() -> nlink::Result<()> {
    require_root!();
    nlink::require_module!("veth");
    if !has_netdev_family().await {
        return Ok(());
    }

    let (_ns, netdev, ve0) = veth_ns("gnl-qstats").await?;
    let veth = match netdev.dump_qstats(Some(ve0), false).await {
        Ok(stream) => all(stream).await,
        Err(e) => Err(e),
    };
    assert!(veth.as_ref().is_err_and(|e| e.is_not_supported()), "{veth:?}");
    assert!(all(netdev.dump_qstats(None, false).await?).await?.is_empty());
    assert!(all(netdev.dump_qstats(None, true).await?).await?.is_empty());

    nlink::require_host_root!();
    let host: Connection<Netdev> = Connection::new_async().await?;
    for dev in all(host.dump_qstats(None, false).await?).await? {
        let ifindex = dev.ifindex.expect("ifindex");
        let route = Connection::<Route>::new()?;
        let Some(link) = route.get_link_by_index(ifindex).await? else {
            continue;
        };
        let name = link.name().unwrap_or_default().to_string();
        let sysfs = std::fs::read_to_string(format!("/sys/class/net/{name}/statistics/rx_packets"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok());
        let now = all(host.dump_qstats(Some(ifindex), false).await?).await?;
        if let (Some(before), Some(after)) = (sysfs, now.first().and_then(|q| q.rx_packets)) {
            assert!(after >= before, "{name}: qstats {after} < sysfs {before}");
        }
    }
    Ok(())
}
