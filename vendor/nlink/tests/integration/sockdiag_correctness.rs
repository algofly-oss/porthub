//! Live-kernel checks for the sockdiag correctness fixes
//! (#197, #204, #223, #225).
//!
//! **These are deliberately not root-gated.** `NETLINK_SOCK_DIAG` lets an
//! unprivileged process dump its own sockets, so every claim below can be
//! checked against a real kernel by any user — including the maintainer, who
//! runs `cargo test` unprivileged. The four fixes here are all of the form
//! "the filter said one thing and the dump did another", which is exactly the
//! class a unit test on nlink's own encoder cannot catch: it needs the kernel
//! on the other end.
//!
//! (The only privileged bit is `InetFilter::mark`, which the kernel only
//! reports to a dumper with `CAP_NET_ADMIN`. It is not asserted here.)

use std::net::TcpListener;

use nlink::netlink::{Connection, SockDiag};
use nlink::sockdiag::{
    FilterExpr, InetFilter, Protocol, SocketFilter, SocketInfo, TcpState, filter::FilterKind,
};

fn inet_filter(f: InetFilter) -> SocketFilter {
    SocketFilter {
        kind: FilterKind::Inet(f),
    }
}

fn base() -> InetFilter {
    InetFilter {
        protocol: Protocol::Tcp,
        states: TcpState::all_mask(),
        ..Default::default()
    }
}

fn has_port(sockets: &[SocketInfo], port: u16) -> bool {
    sockets
        .iter()
        .any(|s| s.as_inet().is_some_and(|i| i.local.port() == port))
}

/// **#204.** A `/0` prefix must not blow up the dump path.
///
/// `ip_matches` built its mask with `u32::MAX << (32 - prefix_len)`, so a
/// prefix of 0 shifted by the full width: a **panic** in a debug build (which
/// is what `cargo test` builds), and in release a shift count masked back to 0,
/// leaving `mask = u32::MAX` — turning "any address" into an exact match on
/// `0.0.0.0` and returning nothing. `src 0.0.0.0/0` is a legitimate ss filter
/// and reaches this straight from user input.
#[tokio::test]
async fn a_zero_prefix_filter_does_not_panic_and_matches_everything() -> nlink::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::<SockDiag>::new()?;
    let all = conn
        .query(&inet_filter(InetFilter {
            expr: Some(FilterExpr::parse("src 0.0.0.0/0").expect("`/0` parses")),
            ..base()
        }))
        .await?;

    assert!(
        has_port(&all, port),
        "`src 0.0.0.0/0` means *any* source address, so it must keep our \
         :{port} listener (#204)"
    );

    drop(listener);
    Ok(())
}

/// **#223.** `local_addr` was read by nothing at all.
///
/// The builder was documented, the field was set, and no code path — kernel
/// side or client side — ever looked at it. `SocketFilter::tcp().local_addr(..)`
/// returned **every** TCP socket on the box.
#[tokio::test]
async fn the_local_addr_filter_actually_filters() -> nlink::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::<SockDiag>::new()?;

    // Matching address: our listener is there.
    let hit = conn
        .query(&inet_filter(InetFilter {
            local_addr: Some("127.0.0.1".parse().unwrap()),
            ..base()
        }))
        .await?;
    assert!(
        has_port(&hit, port),
        "a local_addr filter for 127.0.0.1 dropped our loopback listener"
    );
    assert!(
        hit.iter()
            .all(|s| s.as_inet().is_none_or(|i| i.local.ip().is_loopback())),
        "the local_addr filter leaked a non-loopback socket"
    );

    // Non-matching address: nothing of ours comes back. Before the fix this
    // returned every TCP socket on the host.
    let miss = conn
        .query(&inet_filter(InetFilter {
            local_addr: Some("10.255.255.1".parse().unwrap()),
            ..base()
        }))
        .await?;
    assert!(
        !has_port(&miss, port),
        "local_addr was ignored: a filter for 10.255.255.1 still returned our \
         127.0.0.1 listener (#223)"
    );

    drop(listener);
    Ok(())
}

/// **#223.** Same for `interface` — an ifindex that exists nowhere must match
/// nothing.
#[tokio::test]
async fn the_interface_filter_actually_filters() -> nlink::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::<SockDiag>::new()?;
    let sockets = conn
        .query(&inet_filter(InetFilter {
            interface: Some(9999), // no such ifindex
            ..base()
        }))
        .await?;

    assert!(
        !has_port(&sockets, port),
        "the interface filter was ignored (#223)"
    );

    drop(listener);
    Ok(())
}

/// **#197.** `rcvbuf` / `sndbuf` were structurally unfillable.
///
/// They live only in `INET_DIAG_SKMEMINFO`, and no builder requested it — so
/// they read as a flat `0` forever, and downstream dashboards graphed a clean,
/// believable, permanently-zero line. Now `with_sk_mem_info()` requests the
/// attribute, and the fields are `Option<u32>` so "you never asked" is a
/// different answer from "zero".
#[tokio::test]
async fn sk_mem_info_populates_the_buffer_sizes() -> nlink::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::<SockDiag>::new()?;

    let with_sk = conn
        .query(
            &SocketFilter::tcp()
                .all_states()
                .with_sk_mem_info()
                .local_addr("127.0.0.1".parse().unwrap())
                .build(),
        )
        .await?;
    let sock = with_sk
        .iter()
        .find_map(|s| s.as_inet().filter(|i| i.local.port() == port))
        .expect("our listener must be in the dump");
    let mem = sock
        .mem_info
        .as_ref()
        .expect("with_sk_mem_info() must produce a MemInfo");

    let rcvbuf = mem.rcvbuf.expect("SKMEMINFO carries sk_rcvbuf");
    let sndbuf = mem.sndbuf.expect("SKMEMINFO carries sk_sndbuf");
    assert!(
        rcvbuf > 0 && sndbuf > 0,
        "the kernel reported a zero-sized buffer, which no live socket has: \
         rcvbuf={rcvbuf} sndbuf={sndbuf}"
    );

    // And without the extension, the fields say "not requested" rather than
    // lying with a zero.
    let without = conn
        .query(
            &SocketFilter::tcp()
                .all_states()
                .with_mem_info()
                .local_addr("127.0.0.1".parse().unwrap())
                .build(),
        )
        .await?;
    let sock = without
        .iter()
        .find_map(|s| s.as_inet().filter(|i| i.local.port() == port))
        .expect("our listener must be in the dump");
    let mem = sock.mem_info.as_ref().expect("MEMINFO must produce a MemInfo");
    assert_eq!(
        mem.rcvbuf, None,
        "INET_DIAG_MEMINFO cannot carry a buffer size — a value here is invented"
    );
    assert_eq!(mem.sndbuf, None);

    drop(listener);
    Ok(())
}

/// **#225.** An MPTCP query must not be a mislabelled TCP dump.
///
/// `IPPROTO_MPTCP` is 262 and does not fit `inet_diag_req_v2.sdiag_protocol`
/// (a `__u8`). nlink sent the truncated byte — 262 & 0xff == 6 == plain TCP —
/// and never emitted the `INET_DIAG_REQ_PROTOCOL` attribute the kernel added
/// for exactly this. So `SocketFilter::mptcp()` returned **every TCP socket on
/// the box**, each one stamped `Protocol::Mptcp`.
///
/// Our plain TCP listener is the probe: it must not appear in an MPTCP dump.
#[tokio::test]
async fn an_mptcp_query_does_not_return_plain_tcp_sockets() -> nlink::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let conn = Connection::<SockDiag>::new()?;
    let sockets = match conn
        .query(&inet_filter(InetFilter {
            protocol: Protocol::Mptcp,
            ..base()
        }))
        .await
    {
        Ok(s) => s,
        // No MPTCP support built in: the kernel rejects the dump outright,
        // which is itself proof it dispatched on 262 and not on TCP.
        Err(e) if e.is_not_supported() || e.is_invalid_argument() => return Ok(()),
        Err(e) => return Err(e),
    };

    assert!(
        !has_port(&sockets, port),
        "an MPTCP dump returned our plain TCP listener — sdiag_protocol was \
         truncated to 6 and INET_DIAG_REQ_PROTOCOL was never sent (#225)"
    );

    drop(listener);
    Ok(())
}

/// A unix filter's inode picks out that socket (#776). The dump's
/// `udiag_ino` is the kernel's for an exact lookup (`unix_diag_get_exact`,
/// which also needs the cookie); `unix_diag_dump` ignores it, and nothing
/// checked the replies, so `.inode(n)` returned every unix socket.
#[tokio::test]
async fn the_unix_inode_filter_actually_filters() -> nlink::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener;

    let dir = std::env::temp_dir().join(format!("nlink-unix-ino-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let a = UnixListener::bind(dir.join("a")).expect("bind a");
    let _b = UnixListener::bind(dir.join("b")).expect("bind b");
    // A socket's inode is the one its fd links to: `socket:[N]`.
    let link = std::fs::read_link(format!("/proc/self/fd/{}", a.as_raw_fd())).expect("fd link");
    let inode: u32 = link
        .to_string_lossy()
        .trim_start_matches("socket:[")
        .trim_end_matches(']')
        .parse()
        .expect("socket inode");

    let conn = Connection::<SockDiag>::new()?;
    let found = conn.query(&SocketFilter::unix().inode(inode).build()).await?;
    let inodes: Vec<u32> = found
        .iter()
        .filter_map(|s| match s {
            SocketInfo::Unix(u) => Some(u.inode),
            _ => None,
        })
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(inodes, [inode], "{} sockets came back", found.len());
    Ok(())
}
