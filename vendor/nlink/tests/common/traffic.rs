//! Sending real packets from inside a test namespace.
//!
//! A namespace is entered per thread, so every helper here runs its
//! sockets on a thread of its own that exits afterwards instead of
//! restoring the caller's namespace.

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use nlink::netlink::{Connection, Route, namespace};

use super::TestNamespace;

/// Run `f` on a fresh thread inside `ns` and return what it returns.
pub fn in_ns<T: Send + 'static>(ns: &TestNamespace, f: impl FnOnce() -> T + Send + 'static) -> T {
    let name = ns.name().to_string();
    std::thread::spawn(move || {
        let _ns = namespace::enter(&name).expect("enter test netns");
        f()
    })
    .join()
    .expect("thread in test netns panicked")
}

/// Bring `lo` up inside `ns`, so locally generated traffic can flow.
pub async fn lo_up(ns: &TestNamespace) -> nlink::Result<()> {
    let route: Connection<Route> = ns.connection()?;
    let lo = route
        .get_link_by_name("lo")
        .await?
        .expect("every netns has a loopback device");
    route.set_link_up_by_index(lo.ifindex()).await
}

fn resolve<A: ToSocketAddrs>(targets: &[A]) -> Vec<SocketAddr> {
    targets
        .iter()
        .flat_map(|t| t.to_socket_addrs().expect("a literal socket address"))
        .collect()
}

fn wildcard(target: &SocketAddr) -> &'static str {
    if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
}

/// Send `count` 5-byte UDP datagrams from inside `ns` to each of
/// `targets`, in order, and return how many `sendto` accepted.
///
/// Each target gets its own socket bound to its family's wildcard, so
/// the kernel picks the source address the route says. A send can fail
/// on purpose — an nftables `output` drop returns `EPERM` — so a caller
/// that needs every datagram out asserts on the count.
pub fn send_udp<A: ToSocketAddrs>(ns: &TestNamespace, targets: &[A], count: usize) -> usize {
    let targets = resolve(targets);
    in_ns(ns, move || {
        let mut sent = 0;
        for target in &targets {
            let socket = UdpSocket::bind(wildcard(target)).expect("bind");
            for _ in 0..count {
                if socket.send_to(b"nlink", target).is_ok() {
                    sent += 1;
                }
            }
        }
        sent
    })
}

/// Send `count` TCP SYNs from inside `ns` to each of `targets`: one per
/// connection attempt, each abandoned after `wait`.
///
/// The SYN goes out inside `connect(2)`. Nothing has to listen: a refused
/// or timed-out attempt has sent its SYN all the same, and closing a
/// socket in `SYN_SENT` sends nothing more. Keep `wait` under the first
/// retransmission (1 s) when the count matters.
pub fn send_tcp_syns<A: ToSocketAddrs>(
    ns: &TestNamespace,
    targets: &[A],
    count: usize,
    wait: Duration,
) {
    let targets = resolve(targets);
    in_ns(ns, move || {
        for target in &targets {
            for _ in 0..count {
                let _ = TcpStream::connect_timeout(target, wait);
            }
        }
    })
}

/// Send `count` UDP datagrams from `from` to `dst` in `to`, and return
/// how many arrived at a socket bound to `dst` in `to`.
///
/// The receiver is bound before the first send and drains until 500 ms
/// pass without a datagram, so a packet the path drops is simply not
/// counted.
pub fn deliver_udp(
    from: &TestNamespace,
    to: &TestNamespace,
    dst: SocketAddr,
    count: usize,
) -> usize {
    let (bound_tx, bound_rx) = std::sync::mpsc::channel();
    let to_name = to.name().to_string();
    let receiver = std::thread::spawn(move || {
        let _ns = namespace::enter(&to_name).expect("enter receiving netns");
        let socket = UdpSocket::bind(dst).expect("bind receiver");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("set receive timeout");
        bound_tx.send(()).expect("signal bound");
        let mut buf = [0u8; 64];
        let mut received = 0;
        while socket.recv_from(&mut buf).is_ok() {
            received += 1;
        }
        received
    });
    bound_rx.recv().expect("receiver thread bound its socket");
    send_udp(from, &[dst], count);
    receiver.join().expect("receiver thread panicked")
}

/// Ping `dst` from inside `ns` `count` times; `true` when any reply
/// came back.
pub fn ping(ns: &TestNamespace, dst: IpAddr, count: u32) -> bool {
    let count = count.to_string();
    let dst = dst.to_string();
    ns.exec("ping", &["-c", &count, "-i", "0.2", "-W", "1", &dst])
        .is_ok()
}
