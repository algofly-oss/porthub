//! #480 — `reject` checked on traffic: a client is refused, not left to
//! time out, in every table family.

use std::{
    io::ErrorKind,
    net::{SocketAddr, TcpStream, UdpSocket},
    time::Duration,
};

use nlink::netlink::nftables::types::{BaseChain, Chain, Family, FilterHook, Priority, Rule};
use nlink::netlink::{Connection, Nftables};

use crate::common::TestNamespace;
use crate::common::traffic::{in_ns, lo_up};

/// A `family` table `t` whose input chain applies `rule`.
async fn input_rule(conn: &Connection<Nftables>, family: Family, rule: Rule) -> nlink::Result<()> {
    conn.add_table("t", family).await?;
    conn.add_chain(
        Chain::new("t", "in")?
            .family(family)
            .base(BaseChain::filter(FilterHook::Input, Priority::Filter)),
    )
    .await?;
    conn.add_rule(rule.family(family)).await
}

/// What a UDP datagram to `to` gets back within a second: `ConnectionRefused`
/// when an ICMP unreachable came, `WouldBlock`/`TimedOut` when nothing did.
fn udp_answer(ns: &TestNamespace, to: SocketAddr) -> ErrorKind {
    in_ns(ns, move || {
        let bind: SocketAddr = if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
            .parse()
            .unwrap();
        let socket = UdpSocket::bind(bind).expect("bind");
        socket.connect(to).expect("connect");
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        socket.send(b"nlink").expect("send");
        let mut buf = [0u8; 16];
        match socket.recv(&mut buf) {
            Ok(_) => ErrorKind::Other,
            Err(e) => e.kind(),
        }
    })
}

/// What a TCP connect to `to` gets within a second.
fn tcp_answer(ns: &TestNamespace, to: SocketAddr) -> ErrorKind {
    in_ns(ns, move || {
        match TcpStream::connect_timeout(&to, Duration::from_secs(1)) {
            Ok(_) => ErrorKind::Other,
            Err(e) => e.kind(),
        }
    })
}

/// #480: `reject()` sent ICMPX in every family, and the `ip`/`ip6` reject
/// expressions drop what they don't handle — so the client hung until its
/// timeout. Refused now, as in `inet`.
#[tokio::test]
async fn reject_refuses_in_every_family() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_reject_ipv4", "nft_reject_ipv6");

    for (family, addr) in [
        (Family::Ip, "127.0.0.1:5555"),
        (Family::Ip6, "[::1]:5555"),
        (Family::Inet, "127.0.0.1:5555"),
        (Family::Inet, "[::1]:5555"),
    ] {
        let ns = TestNamespace::new("nft-reject")?;
        lo_up(&ns).await?;
        let conn = ns.connection_for::<Nftables>()?;
        let rule = Rule::new("t", "in").match_l4proto(17).reject();
        input_rule(&conn, family, rule).await?;
        assert_eq!(
            udp_answer(&ns, addr.parse().unwrap()),
            ErrorKind::ConnectionRefused,
            "{family:?} {addr}: the reject should come back as an ICMP unreachable"
        );
    }
    Ok(())
}

/// #480: a TCP reset gets `nft`'s `meta l4proto tcp` guard, so a UDP
/// packet is not silently dropped by a rule that cannot reset it; and the
/// reset itself refuses the connection. Across a veth: on loopback the
/// RST would come back through the same input chain and be dropped.
#[tokio::test]
async fn reject_tcp_reset_is_guarded_and_resets() -> nlink::Result<()> {
    use crate::common::topo::NsPair;
    require_root!();
    nlink::require_modules!("nf_tables", "nft_reject_ipv4", "veth");

    let pair = NsPair::new("nft-rst", 65).await?;
    let conn = pair.b.connection_for::<Nftables>()?;
    input_rule(&conn, Family::Ip, Rule::new("t", "in").reject_tcp_reset()).await?;
    let to = |port| SocketAddr::new(pair.b_addr.into(), port);
    assert_eq!(tcp_answer(&pair.a, to(5556)), ErrorKind::ConnectionRefused);
    // UDP is not the rule's: with no listener, b's stack answers port
    // unreachable itself. Unguarded, the rule dropped it and nothing came.
    assert_eq!(udp_answer(&pair.a, to(5557)), ErrorKind::ConnectionRefused);
    Ok(())
}
