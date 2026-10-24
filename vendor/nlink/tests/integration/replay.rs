//! Record a connection's traffic against a real kernel, then replay it with
//! no kernel behind it (#168): the replayed calls return what the recorded
//! ones did.

use nlink::netlink::genl::netdev::Netdev;
use nlink::netlink::link::DummyLink;
use nlink::netlink::{Connection, Route};
use nlink::replay::{Fixture, Recorder};
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

/// The names and indexes of a link listing.
fn names(links: &[nlink::netlink::messages::LinkMessage]) -> Vec<(u32, String)> {
    let mut out: Vec<(u32, String)> = links
        .iter()
        .map(|l| (l.ifindex(), l.name().unwrap_or_default().to_string()))
        .collect();
    out.sort();
    out
}

/// #168: list the links, add one, list them again — recorded in a
/// namespace, saved, read back, and replayed by a connection that has no
/// kernel behind it: each call returns what it returned live, the link
/// added included. A replay that is asked for something the recording
/// does not have says so; one past its end does not hang.
#[tokio::test]
async fn a_route_session_replays_as_it_was_recorded() -> nlink::Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("replay-route")?;
    let recorder = Recorder::new();
    let live = recorder.connection_in::<Route>(ns.netns())?;
    let before = live.get_links().await?;
    live.add_link(DummyLink::new("rp0")).await?;
    let after = live.get_links().await?;
    assert_eq!(after.len(), before.len() + 1);

    // `scripts/regen-replay-fixtures.sh` keeps this recording as the
    // fixture the library's own tests replay without root.
    if std::env::var_os("NLINK_REPLAY_REGEN").is_some() {
        recorder
            .fixture()
            .save(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/route-links.nlreplay"))?;
    }
    let file = std::env::temp_dir().join(format!("nlink-replay-{}.nlreplay", std::process::id()));
    recorder.fixture().save(&file)?;
    let fixture = Fixture::load(&file);
    let _ = std::fs::remove_file(&file);
    let fixture = fixture?;
    assert_eq!(fixture, recorder.fixture());

    let replayed = fixture.connection::<Route>()?;
    // Live sequence numbers that are not the recorded ones: what comes
    // back must carry them, or the connection takes it for a stale reply.
    for _ in 0..5 {
        replayed.socket().next_seq();
    }
    assert_eq!(names(&replayed.get_links().await?), names(&before));
    replayed.add_link(DummyLink::new("rp0")).await?;
    assert_eq!(names(&replayed.get_links().await?), names(&after));
    // Past the end: an error, not a wait.
    let more = tokio::time::timeout(std::time::Duration::from_secs(5), replayed.get_links()).await;
    assert!(matches!(more, Ok(Err(_))), "{more:?}");

    // A different request than the one recorded is refused.
    let replayed = fixture.connection::<Route>()?;
    assert!(replayed.add_link(DummyLink::new("other")).await.is_err());
    Ok(())
}

/// #168: a Generic Netlink family resolves its id from the recording too,
/// and its dump replays: the netdev family's device list.
#[tokio::test]
async fn a_genl_family_replays_with_its_resolution() -> nlink::Result<()> {
    require_root!();
    if Connection::<Netdev>::new_async().await.is_err() {
        eprintln!("skipping: no netdev family (kernel < 6.3)");
        return Ok(());
    }

    let ns = TestNamespace::new("replay-genl")?;
    let recorder = Recorder::new();
    let live = recorder.connection_async_in::<Netdev>(ns.netns()).await?;
    let mut devs = live.dump_netdevs().await?;
    let mut recorded = Vec::new();
    while let Some(dev) = devs.next().await {
        recorded.push(dev?.ifindex);
    }
    drop(devs);
    assert!(!recorded.is_empty(), "lo at least");

    let replayed = recorder.fixture().connection_async::<Netdev>().await?;
    let mut devs = replayed.dump_netdevs().await?;
    let mut got = Vec::new();
    while let Some(dev) = devs.next().await {
        got.push(dev?.ifindex);
    }
    assert_eq!(got, recorded);
    Ok(())
}
