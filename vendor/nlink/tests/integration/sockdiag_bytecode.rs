//! Sockdiag `INET_DIAG_REQ_BYTECODE` integration tests.
//!
//! These validate the bytecode compiler against a **real kernel**: the
//! kernel audits every program (`inet_diag_bc_audit`) and rejects a
//! malformed one with `EINVAL`, so a query that succeeds proves the
//! program is structurally valid, and the returned set proves the
//! semantics. Byte-layout correctness is pinned by the unit tests in
//! `sockdiag::bytecode`; this is the on-kernel behaviour check.
//!
//! Gated with `require_root!()` so it skips cleanly for the non-root
//! maintainer and runs under the privileged CI.

use std::net::TcpListener;

use nlink::{
    netlink::{Connection, SockDiag},
    sockdiag::{
        InetFilter, Protocol, SocketFilter, SocketInfo, TcpState, bytecode, filter::FilterKind,
    },
};

fn sport_query(port: u16) -> SocketFilter {
    // local_port drives the INET_DIAG_REQ_BYTECODE pre-filter in the
    // inet dump path (sport == port).
    SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            local_port: Some(port),
            ..Default::default()
        }),
    }
}

#[tokio::test]
async fn bytecode_sport_filter_matches_kernel_side() -> nlink::Result<()> {
    require_root!();

    // A listening socket whose source port we target via local_port.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    // Sanity: the port lowers to a valid bytecode program.
    assert!(
        bytecode::for_ports(Some(port), None).is_some(),
        "exact sport should compile to bytecode"
    );

    let conn = Connection::<SockDiag>::new()?;

    // Run a kernel-filtered dump. If the program were malformed the
    // kernel bc-audit would reject the query with EINVAL here.
    let filtered = conn.query(&sport_query(port)).await?;

    // The kernel pre-filter must keep our listener...
    let saw_listener = filtered.iter().any(|s| match s {
        SocketInfo::Inet(i) => i.local.port() == port,
        _ => false,
    });
    assert!(
        saw_listener,
        "kernel-filtered dump should include our :{port} listener"
    );

    // ...and exclude every socket with a different source port — the
    // whole point is that the kernel dropped them before userspace.
    let other_ports = filtered
        .iter()
        .filter(|s| matches!(s, SocketInfo::Inet(i) if i.local.port() != port))
        .count();
    assert_eq!(
        other_ports, 0,
        "bytecode dump leaked {other_ports} sockets with a non-:{port} sport"
    );

    drop(listener);
    Ok(())
}

// ============================================================================
// #163 — full compiler: expressions, host conds, or/not, state hoist,
// CC-info structs. A successful dump proves audit-validity (the kernel
// EINVALs malformed programs); the returned set proves semantics.
// ============================================================================

use nlink::sockdiag::{CcInfo, FilterExpr};

fn expr_query(expr: &str) -> SocketFilter {
    SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            expr: Some(FilterExpr::parse(expr).expect("expr parses")),
            ..Default::default()
        }),
    }
}

fn inet_ports(sockets: &[SocketInfo]) -> Vec<u16> {
    sockets
        .iter()
        .filter_map(|s| s.as_inet().map(|i| i.local.port()))
        .collect()
}

#[tokio::test]
async fn expr_or_of_two_sports_keeps_both_and_leaks_nothing() -> nlink::Result<()> {
    require_root!();

    let a = TcpListener::bind("127.0.0.1:0").expect("bind a");
    let b = TcpListener::bind("127.0.0.1:0").expect("bind b");
    let (pa, pb) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());

    let conn = Connection::<SockDiag>::new()?;
    let got = conn
        .query(&expr_query(&format!("sport = :{pa} or sport = :{pb}")))
        .await?;
    let ports = inet_ports(&got);
    assert!(ports.contains(&pa), "listener A kept");
    assert!(ports.contains(&pb), "listener B kept");
    assert!(
        ports.iter().all(|p| *p == pa || *p == pb),
        "no other sport leaked: {ports:?}"
    );
    Ok(())
}

#[tokio::test]
async fn expr_not_sport_excludes_target() -> nlink::Result<()> {
    require_root!();

    let a = TcpListener::bind("127.0.0.1:0").expect("bind a");
    let b = TcpListener::bind("127.0.0.1:0").expect("bind b");
    let (pa, pb) = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());

    let conn = Connection::<SockDiag>::new()?;
    let got = conn.query(&expr_query(&format!("not sport = :{pa}"))).await?;
    let ports = inet_ports(&got);
    assert!(!ports.contains(&pa), "negated port excluded");
    assert!(ports.contains(&pb), "other listener kept");
    Ok(())
}

#[tokio::test]
async fn expr_src_hostcond_includes_and_excludes() -> nlink::Result<()> {
    require_root!();

    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    let conn = Connection::<SockDiag>::new()?;

    // src 127.0.0.1 keeps the loopback listener.
    let got = conn
        .query(&expr_query(&format!("src 127.0.0.1 and sport = :{port}")))
        .await?;
    assert!(inet_ports(&got).contains(&port), "loopback src kept");

    // A src the listener doesn't have excludes it.
    let got = conn
        .query(&expr_query(&format!("src 203.0.113.1 and sport = :{port}")))
        .await?;
    assert!(
        !inet_ports(&got).contains(&port),
        "foreign src excluded the listener"
    );
    Ok(())
}

#[tokio::test]
async fn expr_v6_hostcond_matches_loopback() -> nlink::Result<()> {
    require_root!();

    let l = TcpListener::bind("[::1]:0").expect("bind v6");
    let port = l.local_addr().unwrap().port();
    let conn = Connection::<SockDiag>::new()?;
    let got = conn
        .query(&expr_query(&format!("src ::1 and sport = :{port}")))
        .await?;
    assert!(inet_ports(&got).contains(&port), "v6 loopback listener kept");
    Ok(())
}

#[tokio::test]
async fn expr_state_hoists_into_header_mask() -> nlink::Result<()> {
    require_root!();

    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    let conn = Connection::<SockDiag>::new()?;

    // state listen and sport = :P → the state half rides in
    // idiag_states, the port half in bytecode.
    let got = conn
        .query(&expr_query(&format!("state listening and sport = :{port}")))
        .await?;
    assert!(inet_ports(&got).contains(&port), "listener kept");

    // state established and sport = :P → the listener must NOT appear.
    let got = conn
        .query(&expr_query(&format!("state established and sport = :{port}")))
        .await?;
    assert!(
        !inet_ports(&got).contains(&port),
        "listener filtered out by hoisted state mask"
    );
    Ok(())
}

#[tokio::test]
async fn cc_info_struct_matches_congestion_name() -> nlink::Result<()> {
    require_root!();

    // An established loopback pair so tcp_info/CC state exists.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let _client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let (_server, _) = listener.accept().expect("accept");

    let conn = Connection::<SockDiag>::new()?;
    let filter = SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            expr: Some(FilterExpr::parse(&format!("dport = :{port}")).unwrap()),
            // CC name + CC-info struct + tcp_info.
            extensions: nlink::sockdiag::InetExtension::Cong.mask()
                | nlink::sockdiag::InetExtension::VegasInfo.mask()
                | nlink::sockdiag::InetExtension::Info.mask(),
            ..Default::default()
        }),
    };
    let got = conn.query(&filter).await?;
    assert!(!got.is_empty(), "established pair visible");

    for s in got.iter().filter_map(|s| s.as_inet()) {
        // cc_info variant, when present, must agree with the CC name.
        match (&s.congestion, &s.cc_info) {
            (Some(name), Some(CcInfo::Bbr(_))) => assert_eq!(name, "bbr"),
            (Some(name), Some(CcInfo::Dctcp(_))) => assert_eq!(name, "dctcp"),
            (Some(name), Some(CcInfo::Vegas(_))) => assert_eq!(name, "vegas"),
            // cubic/reno have no diag get_info → cc_info None; any
            // (name, None) combination is fine.
            _ => {}
        }
    }
    Ok(())
}

/// #166: the `tcp_info` fields kernels appended after `snd_wnd` read back.
/// An idle loopback pair's advertised receive window is `ss -ti`'s
/// `rcv_wnd` (where this `ss` prints it), and a fresh pair has seen no RTO
/// and no rehash.
#[tokio::test]
async fn tcp_info_reads_the_receive_window_and_rto_counters() -> nlink::Result<()> {
    use std::io::{Read, Write};
    require_root!();

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let (mut server, _) = listener.accept().expect("accept");
    client.write_all(&[0u8; 1000]).expect("send");
    let mut buf = [0u8; 1000];
    server.read_exact(&mut buf).expect("receive");

    let conn = Connection::<SockDiag>::new()?;
    let filter = SocketFilter {
        kind: FilterKind::Inet(InetFilter {
            protocol: Protocol::Tcp,
            states: TcpState::all_mask(),
            local_port: Some(port),
            extensions: nlink::sockdiag::InetExtension::Info.mask(),
            ..Default::default()
        }),
    };
    let got = conn.query(&filter).await?;
    let info = got
        .iter()
        .filter_map(|s| s.as_inet())
        .find(|s| s.state == nlink::sockdiag::SocketState::Tcp(TcpState::Established))
        .and_then(|s| s.tcp_info.clone())
        .expect("the server side's tcp_info");
    assert!(info.rcv_wnd > 0, "{info:?}");
    assert_eq!((info.total_rto, info.total_rto_time, info.rehash), (0, 0, 0));

    let ss = std::process::Command::new("ss")
        .args(["-tin", "state", "established", "sport", &format!("= :{port}")])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    if let Some(shown) = ss.split_whitespace().find_map(|w| w.strip_prefix("rcv_wnd:")) {
        assert_eq!(shown.parse::<u32>().ok(), Some(info.rcv_wnd), "{ss}");
    }
    drop(client);
    Ok(())
}

/// Every ss(8) filter expression selects, through nlink's `FilterExpr`, the
/// sockets ss selects with it. ss takes `state` as arguments before its
/// expression, where `FilterExpr` takes it inside one, so a row gives
/// both. The sockets are a namespace's own: listeners on 127.0.0.1 and
/// ::1, and an established pair.
#[tokio::test]
async fn every_ss_expression_selects_what_ss_selects() -> nlink::Result<()> {
    use std::net::{SocketAddr, TcpStream};

    use crate::common::{
        TestNamespace,
        traffic::{in_ns, lo_up},
    };
    require_root!();

    let ns = TestNamespace::new("ss-parity")?;
    lo_up(&ns).await?;
    // Kept open for the length of the test.
    let _sockets = in_ns(&ns, || {
        let l1 = TcpListener::bind("127.0.0.1:8001").expect("bind 8001");
        let l2 = TcpListener::bind("127.0.0.1:8002").expect("bind 8002");
        let l3 = TcpListener::bind("127.0.0.1:9000").expect("bind 9000");
        let l6 = TcpListener::bind("[::1]:8003").expect("bind ::1");
        let client = TcpStream::connect("127.0.0.1:8001").expect("connect");
        let (server, _) = l1.accept().expect("accept");
        (l1, l2, l3, l6, client, server)
    });

    // (ss's arguments after -Htan, nlink's expression)
    let rows: &[(&[&str], &str)] = &[
        (&["sport = :8001"], "sport = :8001"),
        (&["dport = :8001"], "dport = :8001"),
        (&["sport > :8001"], "sport > :8001"),
        (&["sport >= :8002"], "sport >= :8002"),
        (&["sport < :8002"], "sport < :8002"),
        (&["sport <= :8002"], "sport <= :8002"),
        (&["sport != :8001"], "sport != :8001"),
        (&["sport eq :8001"], "sport eq :8001"),
        (&["sport gt :8001"], "sport gt :8001"),
        (&["sport ne :8001"], "sport ne :8001"),
        (&["( sport = :8001 or sport = :8002 )"], "( sport = :8001 or sport = :8002 )"),
        (&["not sport = :8001"], "not sport = :8001"),
        (&["sport = :8001 and dport = :0"], "sport = :8001 and dport = :0"),
        (&["src 127.0.0.1"], "src 127.0.0.1"),
        (&["src 127.0.0.0/8"], "src 127.0.0.0/8"),
        (&["dst 127.0.0.1"], "dst 127.0.0.1"),
        (&["src [::1]"], "src [::1]"),
        (&["src 127.0.0.1:8001"], "src 127.0.0.1:8001"),
        (&["dst 127.0.0.1:8001"], "dst 127.0.0.1:8001"),
        (&["sport = :8001 or src [::1]"], "sport = :8001 or src [::1]"),
        (&["src *:8001"], "src *:8001"),
        (&["src 127.0.0.0/8:8002"], "src 127.0.0.0/8:8002"),
        (&["src [::1]:8003"], "src [::1]:8003"),
        (&["dst [::1]:8003"], "dst [::1]:8003"),
        (&["state", "listening"], "state listening"),
        (&["state", "established"], "state established"),
        (&["state", "established", "dport = :8001"], "state established and dport = :8001"),
    ];

    let conn: Connection<SockDiag> = ns.connection_for()?;
    // A socket as `local peer`, a wildcard peer port as `*`.
    let show = |local: SocketAddr, peer: SocketAddr| {
        let port = |a: SocketAddr| if a.port() == 0 { "*".to_string() } else { a.port().to_string() };
        let ip = |a: SocketAddr| match a {
            SocketAddr::V4(v4) => v4.ip().to_string(),
            SocketAddr::V6(v6) => format!("[{}]", v6.ip()),
        };
        format!("{}:{} {}:{}", ip(local), port(local), ip(peer), port(peer))
    };
    let mut failed = Vec::new();
    for (ss_args, expr) in rows {
        let mut args = vec!["-Htan"];
        args.extend(*ss_args);
        let out = match ns.exec("ss", &args) {
            Ok(out) => out,
            Err(e) => {
                failed.push(format!("{expr}: ss refused it: {e}"));
                continue;
            }
        };
        // The local and peer addresses are the last two columns: ss
        // leaves out the State one when it is given a single state.
        let mut theirs: Vec<String> = out
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split_whitespace().collect();
                Some(format!("{} {}", f.get(f.len().checked_sub(2)?)?, f.last()?))
            })
            .collect();
        let filter = match FilterExpr::parse(expr) {
            Ok(e) => SocketFilter {
                kind: FilterKind::Inet(InetFilter {
                    protocol: Protocol::Tcp,
                    states: TcpState::all_mask(),
                    expr: Some(e),
                    ..Default::default()
                }),
            },
            Err(e) => {
                failed.push(format!("{expr}: nlink refused it: {e}"));
                continue;
            }
        };
        let mut ours: Vec<String> = match conn.query(&filter).await {
            Ok(sockets) => sockets.iter().filter_map(|s| s.as_inet().map(|i| show(i.local, i.remote))).collect(),
            Err(e) => {
                failed.push(format!("{expr}: the kernel refused nlink's: {e}"));
                continue;
            }
        };
        theirs.sort();
        ours.sort();
        if theirs != ours {
            failed.push(format!("{expr}:\n  ss:    {theirs:?}\n  nlink: {ours:?}"));
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n"));
    Ok(())
}
