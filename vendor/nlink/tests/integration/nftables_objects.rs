//! Named stateful objects — counters, quotas, limits, conntrack helpers —
//! and object maps, checked on traffic; declared objects keep their live
//! state across applies, a quota is updated in place and a changed limit is
//! recreated without moving the rules that use it.

use std::net::Ipv4Addr;

use nlink::netlink::nftables::config::{Change, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, Chain, CtState, Family, FilterHook, LimitUnit, PacketField, Priority, Rule, Set,
    SetDataType, SetElement,
};
use nlink::netlink::nftables::{
    CtHelperObject, LimitExpr, NftablesEvent, Object, ObjectConfig, ObjectState, ObjectType,
    QuotaExpr, RuleExpr,
};
use nlink::netlink::{Connection, Nftables};
use tokio_stream::StreamExt;

use crate::common::converge::assert_transition;
use crate::common::counters::rule_packets;
use crate::common::traffic::{in_ns, lo_up, send_udp};
use crate::common::{TestNamespace, with_timeout};

async fn ip_table_with_output(conn: &Connection<Nftables>) -> nlink::Result<()> {
    conn.add_table("t", Family::Ip).await?;
    conn.add_chain(
        Chain::new("t", "out")?
            .family(Family::Ip)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await
}

async fn object(conn: &Connection<Nftables>, name: &str) -> nlink::Result<ObjectState> {
    let objects = conn.list_objects_in("t", Family::Ip).await?;
    Ok(objects
        .into_iter()
        .find(|o| o.name == name)
        .expect("object exists")
        .state)
}

fn packets(state: &ObjectState) -> u64 {
    match state {
        ObjectState::Counter { packets, .. } => *packets,
        other => panic!("not a counter: {other:?}"),
    }
}

/// `counter name "c"` counts into the shared counter; `reset_object`
/// returns the count and zeroes it in one step. The object is notified.
#[tokio::test]
async fn a_named_counter_counts_and_resets() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-obj-counter")?;
    let conn = ns.connection_for::<Nftables>()?;
    let watcher = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        watcher.subscribe_all()?;
        let mut events = watcher.events().await;
        ip_table_with_output(&conn).await?;
        conn.add_object(&Object::counter("t", "c").family(Family::Ip))
            .await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_l4proto(17)
                .counter_named("c"),
        )
        .await?;
        loop {
            match events.next().await {
                Some(Ok(NftablesEvent::NewObject(o))) => {
                    assert_eq!((o.name.as_str(), o.object_type()), ("c", Some(ObjectType::Counter)));
                    break;
                }
                Some(Ok(_)) => {}
                Some(Err(e)) => return Err(e),
                None => panic!("event stream ended"),
            }
        }
        send_udp(&ns, &["127.0.0.1:9"], 4);
        assert_eq!(packets(&object(&conn, "c").await?), 4);
        let before = conn
            .reset_object("t", "c", ObjectType::Counter, Family::Ip)
            .await?
            .expect("the counter exists");
        assert_eq!(packets(&before.state), 4);
        assert_eq!(packets(&object(&conn, "c").await?), 0);
        assert!(
            conn.reset_object("t", "nope", ObjectType::Counter, Family::Ip)
                .await?
                .is_none()
        );
        Ok(())
    })
    .await
}

/// `counter name ip daddr map @per_ip`: one counter per destination,
/// picked by an object map — ipset's per-element `counters`.
#[tokio::test]
async fn an_object_map_counts_each_destination_in_its_own_counter() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-obj-map")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        ip_table_with_output(&conn).await?;
        for name in ["c2", "c3"] {
            conn.add_object(&Object::counter("t", name).family(Family::Ip))
                .await?;
        }
        let map = Set::new("t", "per_ip")
            .family(Family::Ip)
            .map(SetDataType::Object(ObjectType::Counter));
        conn.add_set(map.clone()).await?;
        conn.add_set_elements(
            &map,
            &[
                SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2)).object("c2"),
                SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 3)).object("c3"),
            ],
        )
        .await?;
        conn.add_rule(
            Rule::new("t", "out")
                .family(Family::Ip)
                .match_l4proto(17)
                .objref_from_map(PacketField::Ip4Daddr, "per_ip"),
        )
        .await?;
        for (target, count) in [("127.0.0.2:9", 2), ("127.0.0.3:9", 3), ("127.0.0.4:9", 5)] {
            send_udp(&ns, &[target], count);
        }
        assert_eq!(packets(&object(&conn, "c2").await?), 2);
        assert_eq!(packets(&object(&conn, "c3").await?), 3);
        let elements = conn.list_set_elements("t", "per_ip", Family::Ip).await?;
        assert!(elements.iter().any(|e| e == &SetElement::ipv4(Ipv4Addr::new(127, 0, 0, 2)).object("c2")));
        Ok(())
    })
    .await
}

/// `quota until 100 bytes` matches 33-byte datagrams until the third has
/// used 99 of them; `quota over` matches the rest. A named quota reports
/// itself used up.
#[tokio::test]
async fn quotas_match_until_used_up_and_over_after() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota");

    let ns = TestNamespace::new("nft-obj-quota")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        ip_table_with_output(&conn).await?;
        conn.add_object(&Object::quota("t", "q", QuotaExpr::new(100)).family(Family::Ip))
            .await?;
        for rule in [
            Rule::new("t", "out").match_l4proto(17).quota_until(100).counter(),
            Rule::new("t", "out").match_l4proto(17).quota_over(100).counter(),
            Rule::new("t", "out").match_l4proto(17).quota_named("q").counter(),
        ] {
            conn.add_rule(rule.family(Family::Ip)).await?;
        }
        send_udp(&ns, &["127.0.0.1:9"], 10);
        let rules = conn.list_rules("t", Family::Ip).await?;
        let counts: Vec<u64> = rules.iter().map(|r| r.counter().unwrap().0).collect();
        assert_eq!(counts, [3, 7, 3]);
        match object(&conn, "q").await? {
            ObjectState::Quota {
                bytes, consumed, depleted, ..
            } => assert_eq!((bytes, consumed, depleted), (100, 100, true)),
            other => panic!("not a quota: {other:?}"),
        }
        Ok(())
    })
    .await
}

fn declared(quota: u64, rate: u64) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .object("web", ObjectConfig::Counter)
        .object("budget", ObjectConfig::Quota(QuotaExpr::new(quota)))
        // Burst 0 is the kernel's default, which it stores (and dumps) as 5.
        .object(
            "rate",
            ObjectConfig::Limit(LimitExpr::packets(rate, LimitUnit::Second).burst(0)),
        )
        .rule_keyed("out", "first", |r| r.match_l4proto(6).counter())
        .rule_keyed("out", "web", |r| r.match_l4proto(17).counter_named("web"))
        .rule_keyed("out", "budget", |r| r.match_l4proto(17).quota_named("budget"))
        .rule_keyed("out", "rate", |r| r.match_l4proto(17).limit_named("rate"))
        // The rule's own quota: the kernel echoes its consumption.
        .rule_keyed("out", "cap", |r| r.match_l4proto(17).quota_over(1 << 40))
        // An object map naming a declared counter.
        .set("per_ip", |s| {
            s.map(SetDataType::Object(ObjectType::Counter))
                .element(SetElement::ipv4(Ipv4Addr::LOCALHOST).object("web"))
        })
        .rule_keyed("out", "per_ip", |r| {
            r.match_l4proto(17).objref_from_map(PacketField::Ip4Daddr, "per_ip")
        })
        .rule_keyed("out", "last", |r| r.match_l4proto(1).counter())
    })
}

/// Declared objects converge and keep their live state: re-applying after
/// traffic leaves the counter counting, a changed quota keeps what it has
/// used, and a changed limit is recreated with the rule that uses it moved
/// back to its place.
#[tokio::test]
async fn declared_objects_converge_and_keep_their_state() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota", "nft_limit");

    let ns = TestNamespace::new("nft-obj-decl")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        lo_up(&ns).await?;
        let first = declared(1_000_000, 1000);
        first.diff(&conn).await?.apply(&conn).await?;
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        send_udp(&ns, &["127.0.0.1:9"], 3);
        let again = first.diff(&conn).await?;
        assert!(again.is_empty(), "traffic must not make a diff: {again}");
        // Counted by name and again through the map.
        assert_eq!(packets(&object(&conn, "web").await?), 6);

        // A bigger quota: updated in place, its consumption kept.
        let bigger = declared(2_000_000, 1000);
        let diff = bigger.diff(&conn).await?;
        let objects: Vec<_> = diff.objects().collect();
        assert!(matches!(objects[..], [Change::Update { .. }]), "{diff}");
        diff.apply(&conn).await?;
        match object(&conn, "budget").await? {
            ObjectState::Quota { bytes, consumed, .. } => {
                assert_eq!((bytes, consumed), (2_000_000, 99));
            }
            other => panic!("not a quota: {other:?}"),
        }
        assert_eq!(packets(&object(&conn, "web").await?), 6);

        // A new rate: the limit is recreated, and the rule using it moves
        // out of the way and back to the same place.
        let order = |rules: &[nlink::netlink::nftables::types::RuleInfo]| -> Vec<String> {
            rules.iter().filter_map(|r| r.key.clone()).collect()
        };
        let before = order(&conn.list_rules("t", Family::Ip).await?);
        let faster = declared(2_000_000, 2000);
        let diff = faster.diff(&conn).await?;
        let objects: Vec<_> = diff.objects().collect();
        let [Change::Recreate { cascade, .. }] = objects[..] else {
            panic!("the limit is recreated: {diff}");
        };
        let cascade: Vec<_> = cascade.iter().map(|c| (c.kind(), c.op())).collect();
        assert_eq!(
            cascade,
            [("rule", "update")],
            "the rule using it moves with it: {diff}"
        );
        diff.apply(&conn).await?;
        assert_eq!(order(&conn.list_rules("t", Family::Ip).await?), before);
        match object(&conn, "rate").await? {
            ObjectState::Limit(limit) => assert_eq!(limit.rate, 2000),
            other => panic!("not a limit: {other:?}"),
        }
        let again = faster.diff(&conn).await?;
        assert!(again.is_empty(), "second diff must be empty: {again}");
        Ok(())
    })
    .await
}

// ============================================================================
// #483 — what a recreate has to move out of the way
// ============================================================================

/// `ip t` with an output chain, an object map `m` of `object_type` holding
/// `127.0.0.1 -> target`, and a rule that uses the map.
fn object_map(
    object_type: ObjectType,
    target: &'static str,
    extra: impl Fn(
        nlink::netlink::nftables::config::DeclaredTableBuilder,
    ) -> nlink::netlink::nftables::config::DeclaredTableBuilder
    + 'static,
    interval: bool,
) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        extra(t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        }))
        .set("m", move |s| {
            let s = s
                .map(SetDataType::Object(object_type))
                .element(SetElement::ipv4(Ipv4Addr::LOCALHOST).object(target));
            if interval { s.interval() } else { s }
        })
        .rule_keyed("out", "per-ip", |r| {
            r.match_l4proto(17)
                .objref_from_map(PacketField::Ip4Daddr, "m")
        })
    })
}

/// An object map recreated under a rule that uses it (`counter name ip
/// daddr map @m`), and a limit recreated while an object map's element
/// names it: both were EBUSY on every apply. The rule was not seen as
/// bound to the map, and nothing released the element's hold on the
/// object (#483).
#[tokio::test]
async fn object_maps_and_their_objects_recreate() -> nlink::Result<()> {
    use crate::common::converge::{assert_converges, case};
    require_root!();
    nlink::require_modules!("nf_tables", "nft_limit");

    let counted = |interval: bool| {
        object_map(
            ObjectType::Counter,
            "c",
            |t| t.object("c", ObjectConfig::Counter),
            interval,
        )
    };
    let limited = |rate: u64| {
        object_map(
            ObjectType::Limit,
            "l",
            move |t| {
                t.object(
                    "l",
                    ObjectConfig::Limit(LimitExpr::packets(rate, LimitUnit::Second).burst(0)),
                )
            },
            false,
        )
    };
    let cases = vec![
        case(
            "map-recreated-under-its-rule",
            vec![counted(false), counted(true)],
        ),
        case("object-recreated-in-a-map", vec![limited(10), limited(20)]),
    ];
    assert_converges("nft-objmap-rec", cases).await
}

/// Element changes to a constant set a rule is bound to are EBUSY, so the
/// set is recreated with the rule moved out of the way (#483).
#[tokio::test]
async fn a_bound_constant_set_takes_new_elements() -> nlink::Result<()> {
    use crate::common::converge::{assert_converges, case};
    require_root!();
    nlink::require_modules!("nf_tables");

    let constant = |last: &'static [u8]| {
        NftablesConfig::new().table("t", Family::Ip, move |t| {
            t.chain("out", |c| {
                c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
            })
            .set("k", move |s| {
                last.iter().fold(
                    s.key_type(nlink::netlink::nftables::types::SetKeyType::Ipv4Addr)
                        .constant(),
                    |s, l| s.ipv4(Ipv4Addr::new(127, 0, 0, *l)),
                )
            })
            .rule_keyed("out", "k", |r| {
                r.match_in_set(PacketField::Ip4Daddr, "k").counter()
            })
        })
    };
    let cases = vec![case(
        "constant-set",
        vec![constant(&[1]), constant(&[1, 2])],
    )];
    assert_converges("nft-const-set", cases).await
}

// ============================================================================
// #703 — conntrack helper objects
// ============================================================================

/// #703: ct helper objects as nft writes them decode typed, and nlink
/// installs the same objects and rules: `nft` lists the two tables alike.
#[tokio::test]
async fn ct_helpers_read_and_write_as_nft_does() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_ct", "nf_conntrack_ftp", "nf_conntrack_tftp");

    let ns = TestNamespace::new("nft-cthelper")?;
    let script = "table inet a {
 ct helper ftp-std { type \"ftp\" protocol tcp; }
 ct helper tftp4 { type \"tftp\" protocol udp; l3proto ip; }
 chain pre {
  type filter hook prerouting priority 0;
  tcp dport 21 ct helper set \"ftp-std\"
  udp dport 69 ct helper set \"tftp4\"
 }
}
";
    let file = std::env::temp_dir().join(format!("nlink-cthelper-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let conn = ns.connection_for::<Nftables>()?;
    let ftp = CtHelperObject::new("ftp", 6);
    let tftp4 = CtHelperObject::new("tftp", 17).family(2);
    conn.add_table("b", Family::Inet).await?;
    conn.add_object(&Object::ct_helper("b", "ftp-std", ftp.clone()).family(Family::Inet))
        .await?;
    conn.add_object(&Object::ct_helper("b", "tftp4", tftp4.clone()).family(Family::Inet))
        .await?;
    conn.add_chain(
        Chain::new("b", "pre")?
            .family(Family::Inet)
            .base(BaseChain::filter(FilterHook::Prerouting, Priority::Filter)),
    )
    .await?;
    let rule = || Rule::new("b", "pre").family(Family::Inet);
    conn.add_rule(rule().match_tcp_dport(21).set_ct_helper("ftp-std")).await?;
    conn.add_rule(rule().match_udp_dport(69).set_ct_helper("tftp4")).await?;

    let listed = |table: &str| -> nlink::Result<String> {
        let out = ns.exec("nft", &["list", "table", "inet", table])?;
        Ok(out.replacen(&format!("table inet {table}"), "table inet T", 1))
    };
    assert_eq!(listed("b")?, listed("a")?, "nlink's table b, nft's table a");

    let mut helpers: Vec<(String, ObjectState)> = conn
        .list_objects_in("a", Family::Inet)
        .await?
        .into_iter()
        .map(|o| (o.name, o.state))
        .collect();
    helpers.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(
        helpers,
        [
            ("ftp-std".to_string(), ObjectState::CtHelper(ftp)),
            ("tftp4".to_string(), ObjectState::CtHelper(tftp4)),
        ]
    );
    let unknown = conn
        .list_rules("a", Family::Inet)
        .await?
        .iter()
        .flat_map(|r| r.expressions())
        .filter(|e| matches!(e, RuleExpr::Unknown { .. }))
        .count();
    assert_eq!(unknown, 0, "`ct helper set` decodes typed");
    Ok(())
}

/// An FTP control connection to 127.0.0.1:21 whose server announces a
/// passive data port, then a connection to that port. With the ftp helper
/// on the control connection, the kernel expects the data connection, which
/// arrives `ct state related`. The helper reads a line only after one it has
/// seen end in that direction, so the server greets first, as servers do.
fn ftp_passive_exchange(ns: &TestNamespace) {
    in_ns(ns, || {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};

        let control = TcpListener::bind("127.0.0.1:21").expect("bind 21");
        let data = TcpListener::bind("127.0.0.1:0").expect("bind data");
        let port = data.local_addr().expect("data port").port();
        let mut client = TcpStream::connect("127.0.0.1:21").expect("connect 21");
        let (mut server, _) = control.accept().expect("accept control");
        let mut buf = [0u8; 128];
        server.write_all(b"220 ready\r\n").expect("send 220");
        let _ = client.read(&mut buf).expect("read 220");
        client.write_all(b"PASV\r\n").expect("send PASV");
        let _ = server.read(&mut buf).expect("read PASV");
        let reply = format!(
            "227 Entering Passive Mode (127,0,0,1,{},{}).\r\n",
            port >> 8,
            port & 0xff
        );
        server.write_all(reply.as_bytes()).expect("send 227");
        let _ = client.read(&mut buf).expect("read 227");
        let _data_client = TcpStream::connect(("127.0.0.1", port)).expect("connect data");
        let _ = data.accept().expect("accept data");
    })
}

/// An inet table whose output chain assigns the ftp helper `ftp-std`, for
/// both families or for `l3proto`, and counts related packets.
fn ftp_helper(l3proto: Option<u8>) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Inet, move |t| {
        let helper = CtHelperObject::new("ftp", 6);
        let helper = match l3proto {
            Some(family) => helper.family(family),
            None => helper,
        };
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .object("ftp-std", ObjectConfig::CtHelper(helper))
        .rule_keyed("out", "related", |r| r.match_ct_state(CtState::RELATED).counter())
        .rule_keyed("out", "ftp", |r| r.match_tcp_dport(21).set_ct_helper("ftp-std"))
    })
}

/// #703: a declared ct helper converges, the rule assigning it makes an
/// FTP data connection related, and a helper changed in place (both
/// families → IPv4 only) is recreated with its rule and still works.
#[tokio::test]
async fn a_declared_ct_helper_makes_ftp_data_related() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_ct", "nf_conntrack_ftp");

    let ns = TestNamespace::new("nft-cthelper-ftp")?;
    lo_up(&ns).await?;
    let steps = [ftp_helper(None), ftp_helper(Some(2))];
    assert_transition(&ns, &steps, false, async |i, conn| {
        let related = async || {
            rule_packets(conn, "t", Family::Inet, "out", 0)
                .await
                .map_err(|e| e.to_string())
        };
        let before = related().await?;
        ftp_passive_exchange(&ns);
        let after = related().await?;
        match conn.list_objects_in("t", Family::Inet).await {
            Ok(objects) if objects.len() == 1 => {}
            other => return Err(format!("objects: {other:?}")),
        }
        if after > before {
            Ok(())
        } else {
            Err(format!("step {}: no related packet ({before} -> {after})", i + 1))
        }
    })
    .await
}

// ============================================================================
// #703 — secmark objects
// ============================================================================

/// #703: a secmark object and the rule that sets it, as nft writes them,
/// decode typed, and nlink installs the same: `nft` lists the two tables
/// alike. The context is AppArmor's `unconfined`, which every AppArmor
/// kernel knows.
#[tokio::test]
async fn secmark_reads_and_writes_as_nft_does() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "apparmor");

    let ns = TestNamespace::new("nft-secmark")?;
    let script = "table inet a {
 secmark s1 { \"unconfined\" }
 chain out {
  type filter hook output priority 0;
  meta l4proto udp meta secmark set \"s1\"
 }
}
";
    let file = std::env::temp_dir().join(format!("nlink-secmark-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;

    let conn = ns.connection_for::<Nftables>()?;
    conn.add_table("b", Family::Inet).await?;
    let unconfined = ObjectConfig::Secmark("unconfined".to_string());
    conn.add_object(&Object::new("b", "s1", unconfined).family(Family::Inet)).await?;
    conn.add_chain(
        Chain::new("b", "out")?
            .family(Family::Inet)
            .base(BaseChain::filter(FilterHook::Output, Priority::Filter)),
    )
    .await?;
    conn.add_rule(
        Rule::new("b", "out")
            .family(Family::Inet)
            .match_l4proto(17)
            .set_secmark("s1"),
    )
    .await?;

    let listed = |table: &str| -> nlink::Result<String> {
        let out = ns.exec("nft", &["list", "table", "inet", table])?;
        Ok(out.replacen(&format!("table inet {table}"), "table inet T", 1))
    };
    assert_eq!(listed("b")?, listed("a")?, "nlink's table b, nft's table a");
    let objects = conn.list_objects_in("a", Family::Inet).await?;
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].state, ObjectState::Secmark("unconfined".to_string()));
    let unknown = conn
        .list_rules("a", Family::Inet)
        .await?
        .iter()
        .flat_map(|r| r.expressions())
        .filter(|e| matches!(e, RuleExpr::Unknown { .. }))
        .count();
    assert_eq!(unknown, 0, "`meta secmark set` decodes typed");
    Ok(())
}

/// #703: a declared secmark object marks what its rule marks: `meta secmark
/// != 0` counts the three datagrams after the rule that sets it, and none
/// before. Re-applying changes nothing.
#[tokio::test]
async fn a_declared_secmark_marks_packets() -> nlink::Result<()> {
    use nlink::netlink::nftables::types::MetaKey;
    use nlink::netlink::nftables::{CmpOp, Expr, Register};
    require_root!();
    nlink::require_modules!("nf_tables", "apparmor");

    let ns = TestNamespace::new("nft-secmark-tr")?;
    lo_up(&ns).await?;
    let conn = ns.connection_for::<Nftables>()?;
    let marked = |r: Rule| {
        r.match_l4proto(17)
            .expr(Expr::Meta { dreg: Register::R0, key: MetaKey::Secmark })
            .expr(Expr::Cmp { sreg: Register::R0, op: CmpOp::Neq, data: vec![0; 4] })
            .counter()
    };
    let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
        t.chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
        .object("s1", ObjectConfig::Secmark("unconfined".to_string()))
        .rule_keyed("out", "before", marked)
        .rule_keyed("out", "set", |r| r.match_l4proto(17).set_secmark("s1"))
        .rule_keyed("out", "after", marked)
    });
    cfg.diff(&conn).await?.apply(&conn).await?;
    let again = cfg.diff(&conn).await?;
    assert!(again.is_empty(), "second diff must be empty: {again}");

    send_udp(&ns, &["127.0.0.1:9"], 3);
    assert_eq!(rule_packets(&conn, "t", Family::Inet, "out", 0).await?, 0);
    assert_eq!(rule_packets(&conn, "t", Family::Inet, "out", 2).await?, 3);
    Ok(())
}
