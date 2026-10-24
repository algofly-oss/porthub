//! Plan 158 syscall batching — `syscall_batch` feature must not
//! change the observable dump output vs. the un-batched path.
//!
//! Mirrors §5.5 of `plans/166-0.17-integration-test-backfill-plan.md`.
//! The check is parity, not perf: same set of links, same order, same
//! count. This guards against batch buffer-reuse bugs that would
//! corrupt the parsed stream.
//!
//! The file is *not* `cfg(feature = "syscall_batch")`-gated: the
//! eager and streaming dump paths must give the same count
//! regardless of the feature flag. The CI runner is responsible for
//! invoking with `--features lab,syscall_batch` once Plan 140 lands.

use nlink::netlink::link::DummyLink;
use tokio_stream::StreamExt;

use crate::common::TestNamespace;

#[tokio::test]
async fn batch_and_eager_dumps_observe_same_link_count() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("dummy");

    let ns = TestNamespace::new("batch-parity")?;
    let conn = ns.connection()?;

    // Populate enough links to span at least one syscall batch
    // (32 frames per `recvmmsg` on the streaming path).
    for i in 0..40 {
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
        eager.len(),
        streamed,
        "syscall_batch parity: eager + streaming dumps must observe \
         identical link counts (eager={}, streaming={})",
        eager.len(),
        streamed,
    );
    Ok(())
}
