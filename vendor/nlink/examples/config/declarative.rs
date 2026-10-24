//! Declarative `NetworkConfig` end-to-end — the rtnetlink mirror
//! of `examples/nftables/declarative.rs`.
//!
//! Replaces the earlier orphan that was written against a struct-
//! based API (`LinkConfig`, `AddressConfig`, `RouteConfig`,
//! `QdiscConfig`) that the `nlink::netlink::config` module never
//! exposed. The actual API is closure-based:
//! `NetworkConfig::new().link(name, |b| b.dummy().up()).address(...).route(...)`.
//!
//! Demonstrates the canonical workflow:
//!   1. Declare desired state (links + addresses + routes + qdiscs).
//!   2. `cfg.diff(&conn).await?` — compute the diff against the
//!      kernel.
//!   3. `cfg.apply(&conn).await?` — converge.
//!   4. Re-diff — should be empty (idempotent).
//!   5. Mutate the config, re-diff (shows the delta), re-apply.
//!   6. Tear down with `apply_with_options(..., purge=true)`.
//!
//! Run as root (needs `CAP_NET_ADMIN`):
//!   sudo -E cargo run --example config_declarative
//!
//! Build only:
//!   cargo build --example config_declarative

use nlink::netlink::{
    Connection, Route,
    config::NetworkConfig,
};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Route>::new()?;

    // -- Step 1: declare desired state ----------------------------
    //
    // Two dummy links — one with an address, one bare. A route
    // through the addressed dummy. A netem qdisc on it for
    // demonstration. The whole config is a single chained
    // expression.
    let cfg = NetworkConfig::new()
        .link("declarative_dummy0", |l| l.dummy().mtu(9000).up())
        .link("declarative_dummy1", |l| l.dummy().up())
        .address("declarative_dummy0", "10.99.0.1/24")?
        .route("10.99.1.0/24", |r| r.via("10.99.0.254"))?
        .qdisc("declarative_dummy0", |q| q.netem().delay_ms(10));

    // -- Step 2: diff against current kernel state ----------------
    let diff = match cfg.diff(&conn).await {
        Ok(d) => d,
        Err(e) if e.is_permission_denied() => {
            eprintln!(
                "EPERM: declarative apply requires CAP_NET_ADMIN; \
                 re-run with sudo for the full demo (build-only \
                 succeeded — the API surface is exercised)."
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    println!(
        "initial diff: +{} links, +{} addrs, +{} routes, +{} qdiscs",
        diff.links_to_add.len(),
        diff.addresses_to_add.len(),
        diff.routes_to_add.len(),
        diff.qdiscs_to_add.len(),
    );

    // -- Step 3: apply --------------------------------------------
    let report = cfg.apply(&conn).await?;
    println!("\napplied {} change(s)", report.changes_made);
    if !report.is_success() {
        eprintln!("apply surfaced {} error(s):", report.errors.len());
        for e in &report.errors {
            eprintln!("  {e}");
        }
    }

    // -- Step 4: re-diff — should be empty (idempotent) -----------
    let reapply = cfg.diff(&conn).await?;
    assert!(
        reapply.is_empty(),
        "idempotent re-apply should produce empty diff; got: \
         +{} links, +{} addrs, +{} routes, +{} qdiscs",
        reapply.links_to_add.len(),
        reapply.addresses_to_add.len(),
        reapply.routes_to_add.len(),
        reapply.qdiscs_to_add.len(),
    );
    println!("reapply diff: empty — idempotent ✓");

    // -- Step 5: mutate (add another route), re-diff, re-apply ----
    let updated = NetworkConfig::new()
        .link("declarative_dummy0", |l| l.dummy().mtu(9000).up())
        .link("declarative_dummy1", |l| l.dummy().up())
        .address("declarative_dummy0", "10.99.0.1/24")?
        .route("10.99.1.0/24", |r| r.via("10.99.0.254"))?
        .route("10.99.2.0/24", |r| r.via("10.99.0.254"))? // <-- new
        .qdisc("declarative_dummy0", |q| q.netem().delay_ms(10));
    let mut_diff = updated.diff(&conn).await?;
    println!(
        "\nafter +1 route: +{} routes (expected 1)",
        mut_diff.routes_to_add.len(),
    );
    let report = updated.apply(&conn).await?;
    println!("applied {} change(s)", report.changes_made);

    // -- Step 6: teardown ----------------------------------------
    //
    // A declarative reconcile only *adds* by default; an empty
    // `NetworkConfig::new().apply(...)` is a no-op. Plan 205 (0.23)
    // re-wired an opt-in purge — `ApplyOptions::default().with_purge(true)`
    // (or `PlanOptions::purge(true)` on a diff) — but it is
    // deliberately scoped to **global-scope addresses on managed
    // interfaces** and **`static`/`boot` main-table routes**, and it
    // **never removes links or qdiscs**. So purge can't tear down the
    // dummy links this demo created, and running it here (host netns,
    // empty config) would also strip undeclared host routes — exactly
    // why purge is opt-in and fenced. See `docs/library.md` §"Purge —
    // full reconcile" for the safe pattern.
    //
    // For this demo we tear down the interfaces we created via the
    // imperative API (deleting a link also drops its addresses and
    // connected routes), which is the right tool for link teardown.
    for name in ["declarative_dummy0", "declarative_dummy1"] {
        match conn.del_link(name).await {
            Ok(()) => println!("removed {name}"),
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
    }
    println!("\nteardown complete — demo complete");
    Ok(())
}
