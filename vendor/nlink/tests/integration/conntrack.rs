//! Conntrack integration tests (Plan 137 PRs A+B un-park).
//!
//! All tests are gated with `require_root!()` + `require_module!`
//! so the suite skips cleanly when run as a regular user or on a
//! kernel without conntrack support. Under sudo + with the
//! `nf_conntrack` / `nf_conntrack_netlink` modules loaded (or
//! built in), each test runs in an isolated `LabNamespace`.
//!
//! Mirrors the assertions from `examples/netfilter/conntrack.rs
//! --apply` and `examples/netfilter/conntrack_events.rs --apply`,
//! which were the manual-validation channel before this file
//! existed.

use std::{net::Ipv4Addr, time::Duration};

use nlink::{
    ErrorKind,
    netlink::{
        Connection, Netfilter,
        netfilter::{
            ConntrackBuilder, ConntrackEvent, ConntrackFilter, ConntrackGroup, ConntrackStatus,
            ConntrackTuple, IpProtocol, TcpConntrackState,
        },
        types::AddressFamily,
    },
};
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

/// Open a namespace-scoped Netfilter connection.
fn nf_in_ns(ns: &TestNamespace) -> nlink::Result<Connection<Netfilter>> {
    nlink::Connection::new_in(ns.name())
}

#[tokio::test]
async fn ct_inject_and_query_tcp_entry() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-inject-query")?;
    let nf = nf_in_ns(&ns)?;

    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40000, 80);

    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig)
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;

    let entries = nf.get_conntrack().await?;
    let injected = entries
        .iter()
        .find(|e| {
            e.proto == IpProtocol::Tcp
                && e.orig.src_port == Some(40000)
                && e.orig.dst_port == Some(80)
        })
        .expect("injected TCP entry should appear in dump");
    assert_eq!(injected.mark, Some(0x42), "mark must round-trip");
    assert_eq!(
        injected.tcp_state,
        Some(TcpConntrackState::Established),
        "tcp_state must round-trip"
    );
    assert!(injected.id.is_some(), "kernel always assigns an id");

    Ok(())
}

/// `CTA_TIMEOUT` is whole seconds, and the kernel expires an entry whose
/// timeout is 0 at once. A sub-second `timeout` was truncated to 0, so the
/// entry it added was gone before anything could see it (#603).
#[tokio::test]
async fn ct_sub_second_timeout_is_one_second() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-subsec")?;
    let nf = nf_in_ns(&ns)?;
    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40001, 53);
    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Udp)
            .orig(orig)
            .timeout(Duration::from_millis(500)),
    )
    .await?;

    let entries = nf.get_conntrack().await?;
    let added = entries
        .iter()
        .find(|e| e.proto == IpProtocol::Udp && e.orig.src_port == Some(40001))
        .expect("a 500 ms entry should still be there right after the add");
    assert!(
        added.timeout.is_some_and(|t| t <= 1),
        "timeout {:?}",
        added.timeout
    );
    Ok(())
}

#[tokio::test]
async fn ct_update_changes_mark_in_place() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-update")?;
    let nf = nf_in_ns(&ns)?;

    let orig =
        ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)).ports(40001, 81);

    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig.clone())
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(120))
            .mark(0x42)
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;

    nf.update_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(orig)
            .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
            .timeout(Duration::from_secs(60))
            .mark(0x99)
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;

    let entries = nf.get_conntrack().await?;
    let updated = entries
        .iter()
        .find(|e| {
            e.proto == IpProtocol::Tcp
                && e.orig.src_port == Some(40001)
                && e.orig.dst_port == Some(81)
        })
        .expect("updated entry should still appear in dump");
    assert_eq!(updated.mark, Some(0x99), "mark must reflect update");

    Ok(())
}

/// A UDP entry `10.0.0.1:sport -> 10.0.0.2:dport`, or the same between
/// `fd00::1` and `fd00::2`, ready for `add_conntrack`.
fn udp_entry(v6: bool, sport: u16, dport: u16) -> ConntrackBuilder {
    let builder = if v6 {
        ConntrackBuilder::new_v6(IpProtocol::Udp).orig(
            ConntrackTuple::v6("fd00::1".parse().unwrap(), "fd00::2".parse().unwrap())
                .ports(sport, dport),
        )
    } else {
        ConntrackBuilder::new_v4(IpProtocol::Udp).orig(
            ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                .ports(sport, dport),
        )
    };
    builder
        .status(ConntrackStatus::CONFIRMED)
        .timeout(Duration::from_secs(120))
}

/// Every entry in the namespace, both families, as `(family, dport, zone)`,
/// sorted.
async fn ct_inventory(
    nf: &Connection<Netfilter>,
) -> nlink::Result<Vec<(AddressFamily, u16, Option<u16>)>> {
    let mut all = nf.get_conntrack().await?;
    all.extend(nf.get_conntrack_v6().await?);
    let mut v: Vec<_> = all
        .iter()
        .map(|e| (e.family, e.orig.dst_port.unwrap_or(0), e.zone))
        .collect();
    v.sort_by_key(|&(f, port, zone)| (u8::from(f), port, zone));
    Ok(v)
}

/// Deleting one entry leaves every other one: another entry of its
/// family, an entry of the other family, and the same tuple in another
/// zone (#878). `del_conntrack_by_id` sent the id alone, which the kernel
/// takes for a flush, and the test it had held only the entry it deleted.
#[tokio::test]
async fn ct_delete_entry_removes_only_that_entry() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-del-entry")?;
    let nf = nf_in_ns(&ns)?;

    nf.add_conntrack(udp_entry(false, 40002, 82)).await?;
    nf.add_conntrack(udp_entry(false, 40002, 83)).await?;
    nf.add_conntrack(udp_entry(false, 40002, 82).zone(7))
        .await?;
    nf.add_conntrack(udp_entry(true, 40002, 82)).await?;

    let (v4, v6) = (AddressFamily::Inet, AddressFamily::Inet6);
    assert_eq!(
        ct_inventory(&nf).await?,
        [
            (v4, 82, None),
            (v4, 82, Some(7)),
            (v4, 83, None),
            (v6, 82, None)
        ],
        "a dump reads each entry's family and zone"
    );

    // The zone-7 twin, then the IPv6 entry, each from the dump.
    let zoned = nf
        .get_conntrack()
        .await?
        .into_iter()
        .find(|e| e.zone == Some(7))
        .expect("the zone-7 entry is in the dump");
    nf.del_conntrack_entry(&zoned).await?;
    assert_eq!(
        ct_inventory(&nf).await?,
        [(v4, 82, None), (v4, 83, None), (v6, 82, None)],
        "only the zone-7 entry is gone"
    );

    let v6_entry = nf.get_conntrack_v6().await?.pop().expect("the IPv6 entry");
    nf.del_conntrack_entry(&v6_entry).await?;
    assert_eq!(
        ct_inventory(&nf).await?,
        [(v4, 82, None), (v4, 83, None)],
        "only the IPv6 entry is gone"
    );

    Ok(())
}

/// The delete carries the entry's id, and the kernel checks it: an entry
/// replaced by another flow with the same tuple is not deleted in its
/// place.
#[tokio::test]
async fn ct_delete_entry_checks_the_id() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-del-id")?;
    let nf = nf_in_ns(&ns)?;
    nf.add_conntrack(udp_entry(false, 40003, 84)).await?;

    let entry = nf.get_conntrack().await?.pop().expect("the entry");
    let mut stale = entry.clone();
    stale.id = Some(entry.id.expect("the kernel reports an id").wrapping_add(1));
    let err = nf.del_conntrack_entry(&stale).await.unwrap_err();
    assert!(err.is_not_found(), "a mismatched id is ENOENT: {err}");
    assert_eq!(nf.get_conntrack().await?.len(), 1, "the entry survives");

    nf.del_conntrack_entry(&entry).await?;
    assert!(nf.get_conntrack().await?.is_empty());

    Ok(())
}

/// A delete with no tuple is refused before it is sent: ctnetlink takes
/// one for a flush of the whole table (#878).
#[tokio::test]
async fn ct_delete_without_a_tuple_is_refused() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-del-empty")?;
    let nf = nf_in_ns(&ns)?;
    nf.add_conntrack(udp_entry(false, 40004, 85)).await?;
    nf.add_conntrack(udp_entry(true, 40004, 85)).await?;

    let err = nf
        .del_conntrack(ConntrackBuilder::new_v4(IpProtocol::Udp))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Invalid, "{err}");
    assert_eq!(ct_inventory(&nf).await?.len(), 2, "nothing was flushed");

    // A partial tuple is sent, and the kernel takes it for a lookup, not
    // a flush: `CTA_TUPLE_ORIG` is there, so it parses the tuple and
    // refuses it.
    let partial = ConntrackTuple {
        dst_port: Some(85),
        ..ConntrackTuple::default()
    };
    let err = nf
        .del_conntrack(ConntrackBuilder::new_v4(IpProtocol::Udp).orig(partial))
        .await
        .unwrap_err();
    assert_eq!(
        ct_inventory(&nf).await?.len(),
        2,
        "a partial tuple flushed nothing ({err})"
    );

    Ok(())
}

/// Each family's flush leaves the other family's entries (#880). With
/// nfgenmsg version 0 the kernel ignored the family and flushed both, and
/// `ct_flush_empties_table` seeds IPv4 only, so it could not tell.
#[tokio::test]
async fn ct_flush_is_per_family() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-flush-family")?;
    let nf = nf_in_ns(&ns)?;
    let seed = async |v4: bool, v6: bool| -> nlink::Result<()> {
        for port in [86, 87] {
            if v4 {
                nf.add_conntrack(udp_entry(false, 40005, port)).await?;
            }
            if v6 {
                nf.add_conntrack(udp_entry(true, 40005, port)).await?;
            }
        }
        Ok(())
    };
    let families = async || -> nlink::Result<Vec<AddressFamily>> {
        Ok(ct_inventory(&nf)
            .await?
            .into_iter()
            .map(|(f, ..)| f)
            .collect())
    };
    let (v4, v6) = (AddressFamily::Inet, AddressFamily::Inet6);

    seed(true, true).await?;
    nf.flush_conntrack().await?;
    assert_eq!(families().await?, [v6, v6], "flush_conntrack leaves IPv6");

    seed(true, false).await?;
    nf.flush_conntrack_v6().await?;
    assert_eq!(
        families().await?,
        [v4, v4],
        "flush_conntrack_v6 leaves IPv4"
    );

    seed(false, true).await?;
    nf.flush_conntrack_all().await?;
    assert!(
        families().await?.is_empty(),
        "flush_conntrack_all leaves nothing"
    );

    Ok(())
}

/// Every entry, as (family, protocol, source port, destination port, zone),
/// sorted.
async fn ct_flows(
    nf: &Connection<Netfilter>,
) -> nlink::Result<Vec<(AddressFamily, u8, u16, u16, u16)>> {
    let mut all = nf.get_conntrack().await?;
    all.extend(nf.get_conntrack_v6().await?);
    let mut v: Vec<_> = all
        .iter()
        .map(|e| {
            let (sport, dport) = (e.orig.src_port.unwrap_or(0), e.orig.dst_port.unwrap_or(0));
            (
                e.family,
                e.proto.number(),
                sport,
                dport,
                e.zone.unwrap_or(0),
            )
        })
        .collect();
    v.sort_by_key(|&(f, p, s, d, z)| (u8::from(f), p, s, d, z));
    Ok(v)
}

/// Two UDP flows to port 5000 in zone 0, and one entry beside them for
/// each criterion of the filter: another port, another protocol, another
/// zone, the other family.
async fn seed_for_filters(nf: &Connection<Netfilter>) -> nlink::Result<()> {
    nf.flush_conntrack_all().await?;
    nf.add_conntrack(udp_entry(false, 40000, 5000)).await?;
    nf.add_conntrack(udp_entry(false, 40001, 5000)).await?;
    nf.add_conntrack(udp_entry(false, 40000, 5001)).await?;
    nf.add_conntrack(
        ConntrackBuilder::new_v4(IpProtocol::Tcp)
            .orig(
                ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                    .ports(40000, 5000),
            )
            .status(ConntrackStatus::CONFIRMED)
            .timeout(Duration::from_secs(120))
            .tcp_state(TcpConntrackState::Established),
    )
    .await?;
    nf.add_conntrack(udp_entry(false, 40000, 5000).zone(7))
        .await?;
    nf.add_conntrack(udp_entry(true, 40000, 5000)).await?;
    Ok(())
}

const V4: AddressFamily = AddressFamily::Inet;
const V6: AddressFamily = AddressFamily::Inet6;
const UDP: u8 = 17;
const TCP: u8 = 6;

/// #882: a filtered flush, `conntrack -D -p udp --dport 5000` in zone 0,
/// deletes the matching flows and leaves the rest: another port, another
/// protocol, another zone, and the other family when the filter names one.
///
/// `flush_conntrack_matching` is one filtered flush per family on 6.12+,
/// and `del_conntrack_matching` deletes entry by entry, which is what the
/// flush falls back to on an older kernel. Both are run.
#[tokio::test]
async fn ct_flush_matching_leaves_every_other_entry() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-filter")?;
    let nf = nf_in_ns(&ns)?;
    let video = ConntrackFilter::new()
        .proto(IpProtocol::Udp)
        .orig_dst_port(5000)
        .zone(0);
    let video_v4 = video.clone().family(AddressFamily::Inet);

    seed_for_filters(&nf).await?;
    let mut listed: Vec<_> = nf
        .get_conntrack_matching(&video_v4)
        .await?
        .iter()
        .map(|e| e.orig.src_port)
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        [Some(40000), Some(40001)],
        "the dump lists the two v4 flows"
    );

    let others_v4 = [
        (V4, UDP, 40000, 5000, 7),
        (V4, UDP, 40000, 5001, 0),
        (V4, TCP, 40000, 5000, 0),
        (V6, UDP, 40000, 5000, 0),
    ];
    let mut others_v4 = others_v4.to_vec();
    others_v4.sort_by_key(|&(f, p, s, d, z)| (u8::from(f), p, s, d, z));

    nf.flush_conntrack_matching(&video_v4).await?;
    assert_eq!(ct_flows(&nf).await?, others_v4, "flush_conntrack_matching");

    seed_for_filters(&nf).await?;
    assert_eq!(nf.del_conntrack_matching(&video_v4).await?, 2);
    assert_eq!(ct_flows(&nf).await?, others_v4, "del_conntrack_matching");

    // With no family, both families' flows go.
    seed_for_filters(&nf).await?;
    nf.flush_conntrack_matching(&video).await?;
    let left = ct_flows(&nf).await?;
    assert_eq!(left.len(), 3, "{left:?}");
    assert!(!left.contains(&(V6, UDP, 40000, 5000, 0)), "{left:?}");

    // A mark, masked.
    seed_for_filters(&nf).await?;
    nf.update_conntrack(udp_entry(false, 40000, 5001).mark(0x1f))
        .await?;
    nf.flush_conntrack_matching(&ConntrackFilter::new().mark(0x10, 0xf0))
        .await?;
    let left = ct_flows(&nf).await?;
    assert_eq!(left.len(), 5, "only the marked flow goes: {left:?}");
    assert!(!left.contains(&(V4, UDP, 40000, 5001, 0)), "{left:?}");
    Ok(())
}

/// #882: an IPv6 address filter keeps to the address. The kernel's own
/// comparison of one is inverted, so nlink compares it.
#[tokio::test]
async fn ct_filter_compares_ipv6_addresses() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-filter-v6")?;
    let nf = nf_in_ns(&ns)?;
    let from = |src: &str| {
        ConntrackBuilder::new_v6(IpProtocol::Udp)
            .orig(
                ConntrackTuple::v6(src.parse().unwrap(), "fd00::2".parse().unwrap())
                    .ports(40000, 5000),
            )
            .status(ConntrackStatus::CONFIRMED)
            .timeout(Duration::from_secs(120))
    };
    nf.add_conntrack(from("fd00::1")).await?;
    nf.add_conntrack(from("fd00::3")).await?;
    let one = ConntrackFilter::new()
        .proto(IpProtocol::Udp)
        .orig_src("fd00::1".parse::<std::net::IpAddr>().unwrap());

    let listed = nf.get_conntrack_matching(&one).await?;
    assert_eq!(listed.len(), 1, "{listed:?}");
    assert_eq!(listed[0].orig.src_ip, Some("fd00::1".parse().unwrap()));

    nf.flush_conntrack_matching(&one).await?;
    let left = nf.get_conntrack_v6().await?;
    assert_eq!(left.len(), 1, "{left:?}");
    assert_eq!(
        left[0].orig.src_ip,
        Some("fd00::3".parse().unwrap()),
        "the other address stays"
    );
    Ok(())
}

/// #882: a flush with an empty filter would be a flush of everything, and
/// is refused.
#[tokio::test]
async fn ct_flush_matching_refuses_an_empty_filter() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-filter-empty")?;
    let nf = nf_in_ns(&ns)?;
    nf.add_conntrack(udp_entry(false, 40000, 5000)).await?;
    let err = nf
        .flush_conntrack_matching(&ConntrackFilter::new())
        .await
        .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Invalid, "{err}");
    assert_eq!(nf.get_conntrack().await?.len(), 1, "nothing was sent");
    Ok(())
}

#[tokio::test]
async fn ct_flush_empties_table() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-flush")?;
    let nf = nf_in_ns(&ns)?;

    // Inject a couple of entries to flush.
    for port in 40010u16..40013 {
        nf.add_conntrack(
            ConntrackBuilder::new_v4(IpProtocol::Tcp)
                .orig(
                    ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
                        .ports(port, 90),
                )
                .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
                .timeout(Duration::from_secs(60))
                .tcp_state(TcpConntrackState::Established),
        )
        .await?;
    }

    let before = nf.get_conntrack().await?;
    assert!(before.len() >= 3, "expected at least 3 entries pre-flush");

    nf.flush_conntrack().await?;

    let after = nf.get_conntrack().await?;
    assert!(
        after.is_empty(),
        "flush_conntrack must wipe the table; found {} entries",
        after.len()
    );

    Ok(())
}

#[tokio::test]
async fn ct_subscribe_observes_new_event() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-events")?;
    // Two namespace-scoped connections: one to mutate, one to subscribe.
    let nf_mut: Connection<Netfilter> = nlink::Connection::new_in(ns.name())?;
    let nf_sub: Connection<Netfilter> = nlink::Connection::new_in(ns.name())?;

    nf_sub.subscribe(&[ConntrackGroup::New])?;
    let mut events = nf_sub.events().await;

    let orig = ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .ports(50001, 443);

    nf_mut
        .add_conntrack(
            ConntrackBuilder::new_v4(IpProtocol::Tcp)
                .orig(orig)
                .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
                .timeout(Duration::from_secs(60))
                .tcp_state(TcpConntrackState::Established),
        )
        .await?;

    // Drain up to one event with a generous timeout; the multicast
    // delivery is fast in practice but CI variance warrants a buffer.
    let event = tokio::time::timeout(Duration::from_secs(3), events.next())
        .await
        .expect("event stream must yield within 3s")
        .expect("event stream did not end");
    let event = event?;
    match event {
        ConntrackEvent::New(entry) => {
            assert_eq!(
                entry.orig.dst_port,
                Some(443),
                "received NEW event must be for the just-injected entry"
            );
        }
        other => panic!("expected ConntrackEvent::New, got {:?}", other),
    }

    Ok(())
}

/// Verify that an explicit `del_conntrack` fires a Destroy
/// multicast event.
///
/// **`#[ignore]` on CI.** Repeated CI runs across multiple kernel
/// paths (`flush_conntrack` and `del_conntrack`) and multiple
/// subscription-register sleep values (100ms, 250ms, 1s) all
/// showed **zero events** arriving in 30s on the GHA kernel,
/// while the companion `ct_subscribe_observes_new_event` (same
/// subscribe mechanism, NEW group, fired by `add_conntrack`)
/// works fine. Diagnosis: synthetic ctnetlink-injected entries
/// don't reliably generate visible Destroy events to a sibling
/// subscription socket on every kernel build/config; real
/// packet-flow-derived entries do. The lib code is fine — the
/// other conntrack tests (`ct_del_by_id_removes_entry`,
/// `ct_flush_empties_table`) prove the delete/flush operations
/// actually work; only the *event-on-destroy* assertion is the
/// flaky one, and only on a manually-injected entry.
///
/// To run locally (against a kernel where the event path is
/// reliable):
///
/// ```bash
/// sudo cargo test -p nlink --features lab --test integration -- \
///     --ignored ct_subscribe_observes_destroy_event_on_del
/// ```
#[tokio::test]
#[ignore = "synthetic-entry destroy events are kernel-build-dependent; \
           companion tests cover the delete and the subscription \
           mechanism independently. Run with --ignored locally to \
           verify on a kernel where it works."]
async fn ct_subscribe_observes_destroy_event_on_del() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_conntrack");
    nlink::require_module!("nf_conntrack_netlink");

    let ns = TestNamespace::new("ct-events-destroy")?;

    // Make sure conntrack events are enabled inside the namespace.
    // Defaults to "1" on most kernels but some configs leave it
    // off; ignore failure (sysctl may not exist, may be read-only).
    // If the path doesn't exist at all the kernel was built without
    // CONFIG_NF_CONNTRACK_EVENTS — skip cleanly.
    if std::path::Path::new("/proc/sys/net/netfilter/nf_conntrack_events").exists() {
        let _ = nlink::netlink::namespace::set_sysctl(
            ns.name(),
            "net.netfilter.nf_conntrack_events",
            "1",
        );
    } else {
        eprintln!(
            "Skipping test: /proc/sys/net/netfilter/nf_conntrack_events not present \
             (kernel built without CONFIG_NF_CONNTRACK_EVENTS?)"
        );
        return Ok(());
    }

    let nf_mut: Connection<Netfilter> = nlink::Connection::new_in(ns.name())?;
    let nf_sub: Connection<Netfilter> = nlink::Connection::new_in(ns.name())?;

    // Inject first so there's something to destroy.
    let orig = ConntrackTuple::v4(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2))
        .ports(50002, 8080);
    let entry = ConntrackBuilder::new_v4(IpProtocol::Tcp)
        .orig(orig)
        .status(ConntrackStatus::CONFIRMED | ConntrackStatus::SEEN_REPLY)
        .timeout(Duration::from_secs(60))
        .tcp_state(TcpConntrackState::Established);
    nf_mut.add_conntrack(entry.clone()).await?;

    // Subscribe to ALL conntrack groups so the per-event diagnostic
    // print shows everything that arrives — useful breadcrumb if
    // this ever times out again.
    nf_sub.subscribe_all()?;
    let mut events = nf_sub.events().await;

    // Small sleep so the multicast subscription is fully registered
    // before triggering the event. (Race window is real for the
    // sub/op pair; 250ms is plenty for the targeted del path.)
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Targeted delete by tuple: kernel matches the entry, removes
    // it, and fires Destroy through a well-defined event path.
    // Reliable across kernels — unlike flush, which the kernel may
    // optimize differently for synthetic entries.
    nf_mut.del_conntrack(entry).await?;

    // Drain until we see Destroy for our port. 5s is generous for
    // a targeted delete; bumped from earlier 30s flush variant
    // because the path is much more deterministic.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut event_count = 0usize;
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("timed out waiting for ConntrackEvent::Destroy after {event_count} events");
        }
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let ev = match tokio::time::timeout(remaining, events.next()).await {
            Ok(Some(Ok(ev))) => ev,
            Ok(Some(Err(e))) => return Err(e),
            Ok(None) => panic!("event stream ended unexpectedly"),
            Err(_) => {
                panic!("timed out waiting for ConntrackEvent::Destroy after {event_count} events")
            }
        };
        event_count += 1;
        eprintln!("conntrack event #{event_count}: {ev:?}");
        if let ConntrackEvent::Destroy(entry) = ev
            && entry.orig.dst_port == Some(8080)
        {
            return Ok(());
        }
    }
}
