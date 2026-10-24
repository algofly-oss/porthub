//! Topologies for traffic tests: two namespaces and a wire between them.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nlink::lab::LabVeth;
use nlink::netlink::addr::{Ipv4Address, Ipv6Address};
use nlink::netlink::types::link::OperState;

use super::TestNamespace;
use super::traffic::lo_up;

/// Two namespaces joined by a veth pair, addressed and up.
///
/// `a` holds `veth-a` with `10.<net>.0.1/24` and `fd00:<net>::1/64`; `b`
/// holds `veth-b` with `.2` / `::2`. IPv6 is added `nodad`, and `new`
/// returns only once both ends report operstate UP: a veth's carrier
/// comes up asynchronously, and IPv6 sent before it is lost. `lo` is up on
/// both sides.
pub struct NsPair {
    pub a: TestNamespace,
    pub b: TestNamespace,
    pub a_if: &'static str,
    pub b_if: &'static str,
    pub a_ifindex: u32,
    pub b_ifindex: u32,
    pub a_addr: Ipv4Addr,
    pub b_addr: Ipv4Addr,
    pub a_addr6: Ipv6Addr,
    pub b_addr6: Ipv6Addr,
}

impl NsPair {
    /// Create the pair. `net` picks the subnets, so tests that run side
    /// by side never share one.
    pub async fn new(prefix: &str, net: u8) -> nlink::Result<Self> {
        let a = TestNamespace::new(&format!("{prefix}-a"))?;
        let b = TestNamespace::new(&format!("{prefix}-b"))?;
        let (a_if, b_if) = ("veth-a", "veth-b");
        LabVeth::new(a_if, b_if).peer_in(&b).create_in(&a).await?;

        let a_addr = Ipv4Addr::new(10, net, 0, 1);
        let b_addr = Ipv4Addr::new(10, net, 0, 2);
        let a_addr6 = Ipv6Addr::new(0xfd00, net as u16, 0, 0, 0, 0, 0, 1);
        let b_addr6 = Ipv6Addr::new(0xfd00, net as u16, 0, 0, 0, 0, 0, 2);

        let mut ifindexes = [0u32; 2];
        for (i, (ns, dev, v4, v6)) in [(&a, a_if, a_addr, a_addr6), (&b, b_if, b_addr, b_addr6)]
            .into_iter()
            .enumerate()
        {
            let conn = ns.connection()?;
            let ifindex = conn
                .get_link_by_name(dev)
                .await?
                .unwrap_or_else(|| panic!("{dev} exists in {}", ns.name()))
                .ifindex();
            conn.add_address(Ipv4Address::with_index(ifindex, v4, 24))
                .await?;
            conn.add_address(Ipv6Address::with_index(ifindex, v6, 64).nodad())
                .await?;
            conn.set_link_up_by_index(ifindex).await?;
            lo_up(ns).await?;
            ifindexes[i] = ifindex;
        }
        for (ns, ifindex) in [(&a, ifindexes[0]), (&b, ifindexes[1])] {
            wait_oper_up(ns, ifindex).await?;
        }

        Ok(Self {
            a,
            b,
            a_if,
            b_if,
            a_ifindex: ifindexes[0],
            b_ifindex: ifindexes[1],
            a_addr,
            b_addr,
            a_addr6,
            b_addr6,
        })
    }
}

/// Poll until `ifindex` in `ns` reports operstate UP, for up to 5 s.
async fn wait_oper_up(ns: &TestNamespace, ifindex: u32) -> nlink::Result<()> {
    let conn = ns.connection()?;
    for _ in 0..250 {
        let link = conn.get_link_by_index(ifindex).await?;
        if link.and_then(|l| l.operstate()) == Some(OperState::Up) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Err(nlink::Error::invalid_message(format!(
        "link {ifindex} in {} never reached operstate UP",
        ns.name()
    )))
}
