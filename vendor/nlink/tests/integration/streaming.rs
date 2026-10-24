//! Plan 149 streaming dump API — `stream_links` parity round-trip.
//!
//! Mirrors §5.2 of `plans/166-0.17-integration-test-backfill-plan.md`.
//! The acceptance check is that the streaming path observes the same
//! interfaces as the eager `get_links()` path — i.e. the
//! `DumpStream::poll_next` parser is wire-equivalent to the bulk
//! parser used by the eager API.

use nlink::netlink::link::DummyLink;
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

#[tokio::test]
async fn stream_links_yields_all_populated_links() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("stream-links")?;
    let conn = ns.connection()?;

    for i in 0..5 {
        conn.add_link(DummyLink::new(format!("d{i}"))).await?;
    }

    // Streaming dump.
    let mut count = 0usize;
    let mut stream = conn.stream_links().await?;
    while let Some(item) = stream.next().await {
        item?;
        count += 1;
    }

    // Lab namespace ships loopback + our 5 dummies. The kernel may
    // surface additional links (qdisc-installed ifb on some
    // configs), so assert a lower bound, not equality.
    assert!(
        count >= 6,
        "stream_links should observe loopback + 5 dummies (≥ 6); got {count}"
    );
    Ok(())
}

#[tokio::test]
async fn stream_links_matches_eager_dump_count() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("stream-vs-eager")?;
    let conn = ns.connection()?;

    for i in 0..3 {
        conn.add_link(DummyLink::new(format!("d{i}"))).await?;
    }

    let eager = conn.get_links().await?;

    let mut streamed = 0usize;
    let mut stream = conn.stream_links().await?;
    while let Some(item) = stream.next().await {
        item?;
        streamed += 1;
    }

    assert_eq!(
        streamed,
        eager.len(),
        "streaming dump must parse the same frame count as the eager dump"
    );
    Ok(())
}

/// One interface's TC classes and filters stream as the eager getters read
/// them (#778). The old `stream_classes()`/`stream_filters()` sent no
/// interface, which a class or filter dump needs, and always ended empty.
#[tokio::test]
async fn tc_classes_and_filters_stream_per_interface() -> nlink::Result<()> {
    use nlink::TcHandle;
    require_root!();
    nlink::require_modules!("dummy", "sch_htb", "sch_ingress", "cls_matchall");

    let ns = TestNamespace::new("stream-tc")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("d0")).await?;
    let tc = |args: &str| ns.exec("tc", &args.split_whitespace().collect::<Vec<_>>()).map(drop);
    tc("qdisc add dev d0 root handle 1: htb default 10")?;
    tc("class add dev d0 parent 1: classid 1:1 htb rate 100mbit")?;
    tc("class add dev d0 parent 1:1 classid 1:10 htb rate 10mbit")?;
    tc("filter add dev d0 parent 1: prio 1 protocol ip matchall classid 1:10")?;
    tc("filter add dev d0 parent 1: prio 2 protocol ip matchall classid 1:1")?;
    tc("qdisc add dev d0 clsact")?;
    tc("filter add dev d0 ingress prio 3 protocol all matchall action pass")?;
    let d0 = conn.get_link_by_name("d0").await?.expect("d0").ifindex();

    let mut streamed = Vec::new();
    let mut stream = conn.stream_classes_by_index(d0).await?;
    while let Some(c) = stream.next().await {
        streamed.push(c?.handle());
    }
    drop(stream);
    let eager: Vec<TcHandle> = conn.get_classes_by_index(d0).await?.iter().map(|c| c.handle()).collect();
    assert_eq!(streamed, eager);
    assert!(streamed.contains(&TcHandle::new(1, 0x10)), "{streamed:?}");

    for (parent, prios) in [(None, vec![1, 2]), (Some(TcHandle::CLSACT_INGRESS), vec![3])] {
        let mut streamed = Vec::new();
        let mut stream = conn.stream_filters_by_index(d0, parent).await?;
        while let Some(f) = stream.next().await {
            let f = f?;
            // The classifier that heads each priority is not a filter.
            if f.handle_raw() != 0 {
                streamed.push(f.priority().as_u16());
            }
        }
        assert_eq!(streamed, prios, "under {parent:?}");
    }
    Ok(())
}
