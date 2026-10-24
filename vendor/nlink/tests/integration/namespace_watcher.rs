//! `NamespaceWatcher` lifecycle integration tests (#183).
//!
//! Drives a real create → event → delete → event round-trip through the
//! inotify-backed watcher. The unit test in `namespace_watcher.rs` covers
//! the unprivileged half of #183 (recv parks instead of erroring); this
//! covers the privileged half (events actually arrive).

use nlink::{
    Result,
    netlink::{
        namespace,
        namespace_watcher::{NamespaceEvent, NamespaceWatcher},
    },
};

/// Drain events until `pred` matches or the deadline passes. Unrelated
/// namespace churn from concurrent tests is skipped, not failed on.
async fn wait_for_event(
    watcher: &mut NamespaceWatcher,
    mut pred: impl FnMut(&NamespaceEvent) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, watcher.recv()).await {
            Err(_elapsed) => return false,
            Ok(Ok(Some(event))) if pred(&event) => return true,
            Ok(Ok(Some(_unrelated))) => continue,
            Ok(Ok(None)) | Ok(Err(_)) => return false,
        }
    }
}

#[tokio::test]
async fn test_watcher_observes_create_and_delete() -> Result<()> {
    require_root!();

    let name = format!("nlink-watch-{}", std::process::id());
    let mut watcher = NamespaceWatcher::new().await?;

    namespace::create(&name)?;
    let saw_created = wait_for_event(&mut watcher, |e| {
        matches!(e, NamespaceEvent::Created { name: n } if *n == name)
    })
    .await;

    // Delete before asserting so a failed assertion can't leak the netns.
    namespace::delete(&name)?;
    assert!(saw_created, "watcher should observe Created {{ {name} }}");

    let saw_deleted = wait_for_event(&mut watcher, |e| {
        matches!(e, NamespaceEvent::Deleted { name: n } if *n == name)
    })
    .await;
    assert!(saw_deleted, "watcher should observe Deleted {{ {name} }}");

    Ok(())
}

/// #510: `Created` fired on the marker's `IN_CREATE`, before the namespace
/// was mounted over it — so a `connection_for(name)` in response raced into
/// `NamespaceNotFound`, and a marker nobody ever mounted got a `Created` at
/// all. `list_and_watch` listed such stale markers too. And the event
/// stream was not a `Stream`.
#[tokio::test]
async fn created_means_the_namespace_is_there() -> Result<()> {
    use nlink::netlink::Route;
    require_root!();

    let pid = std::process::id();
    let run = std::path::Path::new(namespace::NETNS_RUN_DIR);
    std::fs::create_dir_all(run)?;
    let stale = format!("nlink-stale-{pid}");
    std::fs::write(run.join(&stale), b"")?;

    let (listed, watcher) = NamespaceWatcher::list_and_watch().await?;
    let mut events = watcher.into_stream();
    let late_stale = format!("nlink-stale2-{pid}");
    std::fs::write(run.join(&late_stale), b"")?;
    let real = format!("nlink-real-{pid}");
    namespace::create(&real)?;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let outcome = loop {
        // Through the `Stream` impl, not the inherent `next`.
        let next = tokio_stream::StreamExt::next(&mut events);
        match tokio::time::timeout_at(deadline, next).await {
            Ok(Some(Ok(NamespaceEvent::Created { name }))) if name == late_stale => {
                break Err("Created for a marker with no namespace".to_string());
            }
            Ok(Some(Ok(NamespaceEvent::Created { name }))) if name == real => {
                break nlink::Connection::<Route>::new_in(&real)
                    .map(|_| ())
                    .map_err(|e| format!("Created, but not there yet: {e}"));
            }
            Ok(Some(Ok(_unrelated))) => continue,
            other => break Err(format!("no Created for {real}: {other:?}")),
        }
    };

    namespace::delete(&real)?;
    let _ = std::fs::remove_file(run.join(&stale));
    let _ = std::fs::remove_file(run.join(&late_stale));
    assert!(
        !listed.contains(&stale),
        "a stale marker is not a namespace: {listed:?}"
    );
    outcome.map_err(nlink::Error::invalid_message)
}
