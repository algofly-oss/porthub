//! Path-based namespace lifecycle integration tests.
//!
//! Covers `namespace::create_path` / `delete_path` — persisting a netns at an
//! arbitrary, application-owned bind-mount path instead of the `ip netns`
//! convention `/var/run/netns/<name>`.

use std::path::PathBuf;

use nlink::{Connection, Result, Route, netlink::namespace};

/// A unique scratch directory under the system temp dir, removed on drop.
/// Deliberately *outside* `/var/run/netns` to exercise the
/// application-owned-directory path that distinguishes `create_path`.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("nlink-ns-path-{tag}-{}", std::process::id()));
        Self(dir)
    }

    fn join(&self, leaf: &str) -> PathBuf {
        self.0.join(leaf)
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn test_create_path_round_trip() -> Result<()> {
    require_root!();

    let scratch = ScratchDir::new("rt");
    // Nested leaf so create_path must materialize the parent directory.
    let ns_path = scratch.join("nested/myns");

    namespace::create_path(&ns_path)?;

    assert!(ns_path.exists(), "marker file should exist after create_path");
    assert!(
        ns_path.parent().unwrap().exists(),
        "parent directory should have been created"
    );

    // A path-created netns must be openable via the path-based connection
    // helper — the loopback interface is always present in a fresh netns.
    let conn = Connection::<Route>::new_in(ns_path.as_path())?;
    let links = conn.get_links().await?;
    assert!(
        links.iter().any(|l| l.name() == Some("lo")),
        "fresh netns should contain a loopback interface"
    );
    drop(conn);

    namespace::delete_path(&ns_path)?;
    assert!(
        !ns_path.exists(),
        "marker file should be gone after delete_path"
    );

    Ok(())
}

#[tokio::test]
async fn test_is_namespace_path_tracks_lifecycle() -> Result<()> {
    require_root!();

    let scratch = ScratchDir::new("isns");
    let ns_path = scratch.join("myns");

    assert!(!namespace::is_namespace_path(&ns_path), "absent → false");

    namespace::create_path(&ns_path)?;
    assert!(
        namespace::is_namespace_path(&ns_path),
        "live bind-mount → true"
    );

    namespace::delete_path(&ns_path)?;
    assert!(!namespace::is_namespace_path(&ns_path), "deleted → false");

    Ok(())
}

// Root-free cases (already-exists rejection, missing-path not-found,
// stale-marker → false) live as unit tests in `namespace.rs`; this file
// covers only the privileged round-trips above.

/// #186 — `list()` reports every entry under the run dir, stale marker
/// files included; `list_live()` keeps only names with an nsfs mount
/// behind them.
#[tokio::test]
async fn list_live_drops_a_stale_marker_that_list_still_reports() -> Result<()> {
    require_root!();
    use nlink::netlink::namespace::{self, NETNS_RUN_DIR};

    let ns = crate::common::TestNamespace::new("list-live")?;
    let marker_name = "nlink-stale-marker-test";
    let marker = std::path::PathBuf::from(NETNS_RUN_DIR).join(marker_name);
    std::fs::write(&marker, b"")?;

    let all = namespace::list();
    let live = namespace::list_live();
    let _ = std::fs::remove_file(&marker);

    let all = all?;
    let live = live?;
    assert!(all.iter().any(|n| n == marker_name), "list() sees the marker: {all:?}");
    assert!(all.iter().any(|n| n == ns.name()), "list() sees the live namespace");
    assert!(
        !live.iter().any(|n| n == marker_name),
        "list_live() must drop the unmounted marker: {live:?}"
    );
    assert!(
        live.iter().any(|n| n == ns.name()),
        "list_live() keeps the live namespace: {live:?}"
    );

    // And a borrowed namespace fd works as a target.
    let fd = namespace::open(ns.name())?;
    let conn = nlink::Connection::<nlink::Route>::new_in(std::os::fd::AsFd::as_fd(&fd))?;
    assert!(conn.get_links().await?.iter().any(|l| l.name() == Some("lo")));
    Ok(())
}
