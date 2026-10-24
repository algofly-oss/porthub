//! Plan 157 declarative `NftablesConfig` — diff + atomic apply +
//! `apply_reconcile`. Six §4.6 scenarios per the original Plan 157
//! design matrix, mirrored in §5.4 of Plan 166.
//!
//! All tests root-gated via `require_root!()`; module-gated on
//! `nf_tables`. The lab namespace is fresh per test, so the
//! starting state is always "no tables we own."
//!
//! ## Per-test 30-second timeout (Plan 167 Phase 3 follow-up)
//!
//! The first CI run of these tests hung indefinitely on the
//! `apply_reconcile_*` test (workflow run `26402630370` —
//! 22 min before manual cancel, no test output after start).
//! `nft_dump()` and `Transaction::commit` use `recv_msg().await`
//! loops with no operation timeout (per CLAUDE.md:
//! "Operation timeouts are opt-in via Connection::timeout
//! (Duration); default is none"), so a missing DONE marker or
//! seq mismatch under the GHA container's kernel hangs forever.
//!
//! **That root cause was #199, fixed in 0.25.0**: `Transaction`
//! numbered its inner messages from its own counter starting at
//! 1, unrelated to the socket's, so `send_batch`'s seq filter
//! discarded the kernel's mid-batch NLMSGERR and then waited
//! forever for a BATCH_END ACK the aborted batch never sent.
//! The 30-second wrapper stays as a belt-and-braces guard so a
//! future regression of the same shape fails fast instead of
//! burning a CI job. The budget is ~30x the typical successful
//! test (≤1s under root in a freshly-spawned namespace).

use std::time::Duration;

use nlink::netlink::nftables::config::{
    Change, NftChange, NftDiffOptions, NftablesConfig, ReconcileOptions,
};
use nlink::netlink::nftables::types::{
    BaseChain, ChainType, Devices, Family, FilterHook, Hook, NatHook, Policy, Priority, SetKeyType,
};
use nlink::netlink::Nftables;

use crate::common::converge::{assert_converges, assert_transition, case};
use crate::common::{TestNamespace, nft, with_timeout};

/// Build a canonical "filter / input" config with N keyed rules.
fn cfg_with_n_rules(n: usize) -> NftablesConfig {
    NftablesConfig::new().table("filter_rec", Family::Inet, |mut t| {
        t = t.chain("input", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop))
        });
        for i in 0..n {
            let port = 1000 + i as u16;
            t = t.rule_keyed("input", format!("k{i}"), move |r| {
                r.match_tcp_dport(port).accept()
            });
        }
        t
    })
}

#[tokio::test]
async fn reconcile_empty_to_full_applies_everything() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-empty-to-full")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = cfg_with_n_rules(3);
        let diff = cfg.diff(&nft).await?;
        assert_eq!(nft::count(&diff, "table", "add"), 1, "one new table");
        assert_eq!(nft::count(&diff, "chain", "add"), 1, "one new chain");
        assert_eq!(nft::count(&diff, "rule", "add"), 3, "three new rules");

        let applied = diff.apply(&nft).await?;
        assert!(applied >= 5, "apply count should cover table+chain+rules");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_idempotent_reapply_yields_empty_diff() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-idempotent")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = cfg_with_n_rules(2);
        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "second diff after no kernel state change must be empty; got {}",
            again
        );
        Ok(())
    })
    .await
}

/// #362: a masquerade rule diffed as changed on every reconcile,
/// forever.
///
/// `Expr::Masquerade` rendered only NFTA_EXPR_NAME, but
/// `nft_expr_dump` opens an NFTA_EXPR_DATA nest for every expression
/// with a `dump` callback and closes it whatever the callback wrote —
/// so the kernel echoed an empty 4-byte nest the encoder never
/// produced. No TLV normalisation can reconcile "one side has an
/// attribute the other does not", so the rule landed in
/// `rules_to_replace` every time.
///
/// It hid because `apply` converges anyway (re-issuing the rule is
/// idempotent and keeps its handle), so nothing downstream broke
/// visibly — the *applier* was right and the *diff* was wrong. The
/// existing idempotency test above only ever used `match_tcp_dport`
/// rules, so no NAT expression was in an is-empty assertion at all.
///
/// A portless `redirect` had the same omission and is covered here
/// with it.
#[tokio::test]
async fn reconcile_nat_exprs_without_attributes_are_idempotent() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-nat-dataless")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = NftablesConfig::new().table("nat_dataless", Family::Inet, |t| {
            t.chain("postrouting", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .chain("prerouting", |c| {
                c.base(BaseChain::nat(NatHook::Prerouting, Priority::DstNat))
            })
            .rule_keyed("postrouting", "masq", |r| {
                r.match_saddr_v4("10.0.0.0".parse().unwrap(), 8).masquerade()
            })
            .rule_keyed("prerouting", "redir", |r| {
                r.match_tcp_dport(8080).redirect(None)
            })
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "a NAT expression with no attributes of its own must still \
             round-trip: the kernel echoes an empty NFTA_EXPR_DATA nest \
             for it (#362). Second diff: {again}"
        );
        // Belt and braces: a third diff after the (no-op) apply of the
        // second, in case apply itself perturbs the rule.
        again.apply(&nft).await?;
        let third = cfg.diff(&nft).await?;
        assert!(third.is_empty(), "third diff must be empty too: {third}");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_add_one_rule_in_existing_chain() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-add-rule")?;
        let nft = ns.connection_for::<Nftables>()?;

        cfg_with_n_rules(1).diff(&nft).await?.apply(&nft).await?;
        let bigger = cfg_with_n_rules(2);
        let diff = bigger.diff(&nft).await?;
        assert_eq!(
            nft::count(&diff, "table", "add"),
            0,
            "table already present"
        );
        assert_eq!(
            nft::count(&diff, "chain", "add"),
            0,
            "chain already present"
        );
        assert_eq!(
            nft::count(&diff, "rule", "add"),
            1,
            "only the new rule should be added"
        );
        diff.apply(&nft).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_replace_one_rule_emits_replace_op() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-replace")?;
        let nft = ns.connection_for::<Nftables>()?;

        cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;

        // Same keys, different port for "k0".
        let mutated = NftablesConfig::new().table("filter_rec", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop))
            })
            .rule_keyed("input", "k0", |r| r.match_tcp_dport(9000).accept())
            .rule_keyed("input", "k1", |r| r.match_tcp_dport(1001).accept())
        });

        let diff = mutated.diff(&nft).await?;
        assert_eq!(
            nft::replaced(&diff).len(),
            1,
            "one rule changed — should be a single in-place replace"
        );
        assert_eq!(nft::count(&diff, "rule", "add"), 0, "no new rules expected");
        diff.apply(&nft).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_delete_one_rule_emits_delete_op() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-del-rule")?;
        let nft = ns.connection_for::<Nftables>()?;

        cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;

        let smaller = cfg_with_n_rules(1);
        let diff = smaller.diff(&nft).await?;
        assert_eq!(
            nft::count(&diff, "rule", "remove"),
            1,
            "one rule absent from desired state → one delete"
        );
        diff.apply(&nft).await?;
        Ok(())
    })
    .await
}

/// Teardown-by-empty-config, which since #190 requires opting into purge.
///
/// `diff()` no longer proposes any table deletion — it could not tell our
/// table from Docker's, and deleting a table cascades to everything inside it.
/// `diff_with_options(.., purge_tables(true))` is the explicit opt-in.
#[tokio::test]
async fn reconcile_cascade_delete_table_via_empty_config() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-cascade")?;
        let nft = ns.connection_for::<Nftables>()?;

        cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;

        // Without the opt-in, an empty config is a no-op on tables.
        let teardown = NftablesConfig::new();
        assert!(
            teardown.diff(&nft).await?.tables().next().is_none(),
            "plain diff() must never propose a table deletion (#190)"
        );

        // With it, the table we own is dropped.
        let diff = teardown
            .diff_with_options(&nft, &NftDiffOptions::default().purge_tables(true))
            .await?;
        assert_eq!(
            nft::count(&diff, "table", "remove"),
            1,
            "purge_tables(true) must propose dropping the table"
        );
        diff.apply(&nft).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn apply_reconcile_succeeds_in_one_attempt_when_uncontended() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-reconcile-once")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = cfg_with_n_rules(2);
        // A dry run commits nothing, through either reconcile (#532).
        let dry = ReconcileOptions::default().with_dry_run(true);
        let report = cfg.apply_reconcile(&nft, dry).await?;
        assert!(report.dry_run && report.changes_made >= 4, "{report:?}");
        let report = cfg.diff(&nft).await?.apply_reconcile(&nft, dry).await?;
        assert!(report.dry_run && report.changes_made >= 4, "{report:?}");
        assert!(nft.list_tables().await?.is_empty(), "a dry run commits nothing");

        let diff = cfg.diff(&nft).await?;
        let report = diff
            .apply_reconcile(&nft, ReconcileOptions::default())
            .await?;
        assert_eq!(report.attempts, 1, "no contention → single attempt");
        assert!(report.changes_made >= 4, "expected table+chain+2 rules");
        Ok(())
    })
    .await
}

// ============================================================================
// Plan 180 — chain_type + device on DeclaredChain
// ============================================================================

/// Declared NAT chain round-trips through the kernel with
/// `chain_type = Nat`. Without it, the kernel rejects
/// `masquerade`/`snat`/`dnat` verdicts with `EOPNOTSUPP`
/// inside the batch.
#[tokio::test]
async fn nat_chain_chain_type_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");

    with_timeout(async {
        let ns = TestNamespace::new("nat-chain-type")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = nlink::netlink::nftables::config::NftablesConfig::new().table(
            "nat-test",
            Family::Inet,
            |t| {
                t.chain("postrouting", |c| {
                    c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
                })
            },
        );

        cfg.diff(&nft).await?.apply(&nft).await?;

        // Dump back and verify chain_type came through.
        let chains = nft.list_chains().await?;
        let pr = chains
            .iter()
            .find(|c| c.name == "postrouting" && c.table == "nat-test")
            .expect("postrouting chain must exist after apply");
        assert_eq!(
            pr.chain_type,
            Some(ChainType::Nat),
            "expected chain_type=Nat in dump; got {:?}",
            pr.chain_type
        );

        // Idempotence: re-diff yields zero changes (the 0.17
        // body-bytes contract; guard it for this code path too).
        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "re-diff after no kernel change must be empty; got {}",
            again
        );

        Ok(())
    })
    .await
}

/// Declared netdev chain bound to a device round-trips with
/// `device` set on dump. Without `NFTA_HOOK_DEV` in the
/// apply request, the kernel rejects the chain creation.
#[tokio::test]
async fn netdev_chain_device_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "dummy");

    with_timeout(async {
        let ns = TestNamespace::new("netdev-chain-dev")?;
        // Create the dummy interface the chain will bind to.
        ns.add_dummy("dummy0")?;
        ns.link_up("dummy0")?;

        let nft = ns.connection_for::<Nftables>()?;
        let cfg = nlink::netlink::nftables::config::NftablesConfig::new().table(
            "ft",
            Family::Netdev,
            |t| {
                t.chain("ingress", |c| {
                    c.base(BaseChain::filter(
                        FilterHook::ingress("dummy0"),
                        Priority::Filter,
                    ))
                })
            },
        );

        cfg.diff(&nft).await?.apply(&nft).await?;

        let chains = nft.list_chains().await?;
        let ing = chains
            .iter()
            .find(|c| c.name == "ingress" && c.table == "ft")
            .expect("ingress chain must exist");
        assert_eq!(
            ing.device.as_deref(),
            Some("dummy0"),
            "expected device=dummy0 in dump; got {:?}",
            ing.device
        );

        Ok(())
    })
    .await
}

// ============================================================================
// Plan 181 — list_*_in filter family
// ============================================================================

/// Server-side `(table, family)` filter mirrors what
/// `list_rules(table, family)` has always done. Build two
/// tables in the same family each with a chain/flowtable/set,
/// then verify `list_*_in("t1", family)` returns only t1's
/// entities while the unfiltered `list_*()` sees both.
#[tokio::test]
async fn list_in_filters_match_only_target_table() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("list-in")?;
        let nft = ns.connection_for::<Nftables>()?;

        // Build two minimal tables in the Inet family. Each has
        // one chain; t1 also gets a set so the set-filter assertion
        // is meaningful (set creation is more involved than chain
        // creation; one set is enough).
        let cfg = nlink::netlink::nftables::config::NftablesConfig::new()
            .table("li-t1", Family::Inet, |t| {
                t.chain("c1", |c| {
                    c.base(
                        BaseChain::filter(FilterHook::Input, Priority::Filter)
                            .policy(Policy::Accept),
                    )
                })
            })
            .table("li-t2", Family::Inet, |t| {
                t.chain("c2", |c| {
                    c.base(
                        BaseChain::filter(FilterHook::Forward, Priority::Filter)
                            .policy(Policy::Accept),
                    )
                })
            });
        cfg.diff(&nft).await?.apply(&nft).await?;

        // Tables — unfiltered sees both; family-filtered to Inet
        // still sees both; the family filter alone doesn't narrow
        // when both targets share family.
        let tables_all = nft.list_tables().await?;
        let tables_inet = nft.list_tables_in(Family::Inet).await?;
        let our_inet_count = tables_inet
            .iter()
            .filter(|t| t.name == "li-t1" || t.name == "li-t2")
            .count();
        assert_eq!(our_inet_count, 2, "both our Inet tables visible");
        let our_all_count = tables_all
            .iter()
            .filter(|t| t.name == "li-t1" || t.name == "li-t2")
            .count();
        assert_eq!(our_all_count, 2, "both our tables visible via list_tables()");

        // Chains — list_chains_in narrows to one table.
        let chains_t1 = nft.list_chains_in("li-t1", Family::Inet).await?;
        let chains_t2 = nft.list_chains_in("li-t2", Family::Inet).await?;
        assert!(
            chains_t1.iter().any(|c| c.name == "c1"),
            "c1 must be in t1 dump; got {:?}",
            chains_t1.iter().map(|c| &c.name).collect::<Vec<_>>()
        );
        assert!(
            !chains_t1.iter().any(|c| c.name == "c2"),
            "c2 must NOT leak into t1 dump"
        );
        assert!(
            chains_t2.iter().any(|c| c.name == "c2"),
            "c2 must be in t2 dump"
        );

        // Flowtables — none declared; both list paths return empty
        // (smoke-check that the filter doesn't error on no matches).
        let fts_t1 = nft.list_flowtables_in("li-t1", Family::Inet).await?;
        assert!(fts_t1.is_empty(), "no flowtables in t1");

        // Sets — none declared either; smoke-check the filter
        // shape on the set-listing path. (Set creation requires
        // imperative add_set + element wrangling that's out of
        // scope for this list_*_in test.)
        let sets_t1 = nft.list_sets_in("li-t1", Family::Inet).await?;
        assert!(sets_t1.is_empty(), "no sets in t1");

        Ok(())
    })
    .await
}

/// Plan 185 — driving the wrapper end-to-end through a real
/// `ENOBUFS` overflow. Shrinks the multicast subscriber's
/// `SO_RCVBUF` to a tiny value, opens a second mutator
/// connection that floods the kernel with rule add/delete in a
/// tight loop, then drains the resync stream slowly. The wrapper
/// must observe the ENOBUFS, invoke the factory, walk the
/// snapshot, and emit
/// `Marker(ResyncStart) → Resynced(...) → Marker(ResyncEnd)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn into_events_with_resync_recovers_from_enobufs() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    use std::sync::Arc;

    use nlink::netlink::nftables::NftablesEvent;
    use nlink::netlink::resync::{ConnectionFactory, ResyncMarker, ResyncedEvent};
    use tokio_stream::StreamExt;

    with_timeout(async {
        let ns = TestNamespace::new("nft-resync")?;
        let ns_name = ns.name().to_string();

        // Seed config: one table + one chain. The rules we churn
        // through during the flood live in this chain.
        let cfg = NftablesConfig::new().table("flood", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(
                    BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Accept),
                )
            })
        });
        let seed = ns.connection_for::<Nftables>()?;
        cfg.diff(&seed).await?.apply(&seed).await?;
        drop(seed);

        // Subscriber connection — set a tiny rcvbuf via the
        // SO_RCVBUFFORCE helper landed in this same plan, so the
        // flood overflows it in a handful of mutations rather
        // than minutes.
        let event_conn = ns.connection_for::<Nftables>()?;
        event_conn.socket().set_rcvbuf(256)?;

        // Factory: open fresh Nftables connections inside the
        // same namespace for the resync snapshot dump.
        let factory: ConnectionFactory<Nftables> = {
            let ns_name = ns_name.clone();
            Arc::new(move || {
                let ns_name = ns_name.clone();
                Box::pin(async move { nlink::Connection::new_in(&ns_name) })
            })
        };

        let mut stream = event_conn.into_events_with_resync(factory).await?;

        // Mutator task: tight rule add/delete loop. Runs until
        // we cancel via the abort handle. Uses get_rule + handle
        // tracking via the integration test's existing churn
        // pattern.
        let mut_ns = ns_name.clone();
        let mutator = tokio::spawn(async move {
            let nft = nlink::Connection::<Nftables>::new_in(&mut_ns)?;
            for i in 0..2_000u32 {
                use nlink::netlink::nftables::Rule;
                let rule = Rule::new("flood", "input")
                    .family(Family::Inet)
                    .accept()
                    .comment(&format!("r{i}"));
                let _ = nft.add_rule(rule).await;
                // No delete — we want the kernel to emit more
                // mcast events than the subscriber drains. The
                // table is torn down with the netns at test exit.
            }
            Ok::<_, nlink::Error>(())
        });

        // Drain the stream slowly. Look for the resync marker
        // sequence. Bail after a generous deadline so a
        // mis-behaving kernel doesn't hang the suite.
        let mut saw_start = false;
        let mut snapshot_count = 0usize;
        let mut saw_end = false;
        // The stream opens with its initial snapshot (#503); the resync
        // this test chases is the one after the overflow.
        let mut in_initial = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);

        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                item = stream.next() => {
                    let Some(item) = item else { break };
                    match item? {
                        ResyncedEvent::Marker(ResyncMarker::InitialSyncStart) => {
                            in_initial = true;
                        }
                        ResyncedEvent::Resynced(_) if in_initial => {}
                        ResyncedEvent::Marker(ResyncMarker::ResyncEnd) if in_initial => {
                            in_initial = false;
                        }
                        ResyncedEvent::Marker(ResyncMarker::ResyncStart) => {
                            saw_start = true;
                        }
                        ResyncedEvent::Resynced(ev) => {
                            assert!(
                                saw_start,
                                "Resynced item before ResyncStart marker"
                            );
                            snapshot_count += 1;
                            // The snapshot must contain our seed
                            // table + chain.
                            match ev {
                                NftablesEvent::NewTable(t) => {
                                    assert_eq!(t.name, "flood");
                                }
                                NftablesEvent::NewChain(_)
                                | NftablesEvent::NewRule(_)
                                | NftablesEvent::NewFlowtable(_)
                                | NftablesEvent::NewSet(_)
                                | NftablesEvent::NewSetElements(_)
                                | NftablesEvent::NewObject(_) => {}
                                other => panic!(
                                    "snapshot must emit only New* variants; got {other:?}"
                                ),
                            }
                        }
                        ResyncedEvent::Marker(ResyncMarker::ResyncEnd) => {
                            assert!(saw_start, "ResyncEnd before ResyncStart");
                            saw_end = true;
                            break;
                        }
                        ResyncedEvent::Event(_) => {
                            // Live event; ignored — we're chasing
                            // the resync sequence.
                        }
                        _ => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    // Slow consumer — gives the mutator room to
                    // flood the subscriber's tiny rcvbuf.
                }
            }
            // Throttle the consumer so the mutator gets ahead.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        mutator.abort();

        assert!(saw_start, "wrapper must emit ResyncMarker::ResyncStart on ENOBUFS");
        assert!(saw_end, "wrapper must emit ResyncMarker::ResyncEnd after snapshot");
        assert!(
            snapshot_count >= 2,
            "snapshot must include at least the seed table + chain; got {snapshot_count}"
        );

        Ok(())
    })
    .await
}

/// Plan 185 — `into_events_with_resync` walks the ruleset
/// snapshot via a fresh `Connection<Nftables>` from the factory
/// and yields the snapshot as `Resynced(...)` items between
/// `ResyncStart` / `ResyncEnd` markers when the multicast stream
/// reports `ENOBUFS`.
///
/// Driving an actual ENOBUFS in CI is flaky (it requires
/// outpacing the kernel's send buffer), so this test asserts the
/// *snapshot* shape end-to-end: build a ruleset, point the
/// factory at a freshly-constructed connection, and verify the
/// snapshot enumerates every table/chain/set we declared. The
/// state-machine logic itself is exercised by the lib's
/// `events_with_resync` unit tests + the Plan 151 recipe.
#[tokio::test]
async fn nftables_snapshot_walks_ruleset() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("nft-snap")?;
        let nft = ns.connection_for::<Nftables>()?;

        // Build a 2-table ruleset so the snapshot has something
        // structural to enumerate.
        let cfg = NftablesConfig::new()
            .table("snap-t1", Family::Inet, |t| {
                t.chain("input", |c| {
                    c.base(
                        BaseChain::filter(FilterHook::Input, Priority::Filter)
                            .policy(Policy::Accept),
                    )
                })
            })
            .table("snap-t2", Family::Inet, |t| {
                t.chain("fwd", |c| {
                    c.base(
                        BaseChain::filter(FilterHook::Forward, Priority::Filter)
                            .policy(Policy::Accept),
                    )
                })
            });
        cfg.diff(&nft).await?.apply(&nft).await?;

        // Build the snapshot directly (skips the multicast
        // subscribe path). The factory pattern is what
        // into_events_with_resync would use internally.
        let snapshot =
            nlink::netlink::nftables::resync::nftables_snapshot(&nft).await?;

        use nlink::netlink::nftables::NftablesEvent;
        let mut tables: Vec<&str> = snapshot
            .iter()
            .filter_map(|e| match e {
                NftablesEvent::NewTable(t)
                    if t.name == "snap-t1" || t.name == "snap-t2" =>
                {
                    Some(t.name.as_str())
                }
                _ => None,
            })
            .collect();
        tables.sort();
        assert_eq!(
            tables,
            vec!["snap-t1", "snap-t2"],
            "snapshot must enumerate every declared table"
        );

        let mut chains: Vec<&str> = snapshot
            .iter()
            .filter_map(|e| match e {
                NftablesEvent::NewChain(c)
                    if c.table == "snap-t1" || c.table == "snap-t2" =>
                {
                    Some(c.name.as_str())
                }
                _ => None,
            })
            .collect();
        chains.sort();
        assert_eq!(
            chains,
            vec!["fwd", "input"],
            "snapshot must enumerate every declared chain"
        );

        Ok(())
    })
    .await
}

// ============================================================================
// Rule::{dnat,snat}_v6 — kernel acceptance + exact wire round-trip
// ============================================================================

/// An `ip6` DNAT rule built with `Rule::dnat_v6` is accepted by the
/// kernel *and* its dumped expression bytes match what nlink rendered.
///
/// The unit tests in `nftables::types` only assert the in-memory expr
/// layout (R0 holds the address, the register is marked in use). They
/// cannot prove the load-bearing claim `dnat_v6` makes about the wire
/// format: that the kernel accepts `Family::Ip6` in the NAT expr with the
/// 16-byte `R0` load. Routing the rule through the declarative diff path
/// gives a far stronger assertion than "expression_bytes is non-empty":
/// after applying, a second `diff` re-renders the declared rule to bytes
/// and byte-compares (normalized) against the kernel's dump. An empty
/// second diff means the kernel stored exactly the expr layout nlink
/// emitted — a register-layout disagreement would either be rejected at
/// apply (`EINVAL`) or surface as a non-empty re-diff.
#[tokio::test]
async fn dnat_v6_rule_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");

    with_timeout(async {
        use nlink::netlink::nftables::config::NftablesConfig;
        use std::net::Ipv6Addr;

        let ns = TestNamespace::new("dnat-v6")?;
        let nft = ns.connection_for::<Nftables>()?;

        let target: Ipv6Addr = "fd30::2".parse().unwrap();
        let cfg = NftablesConfig::new().table("nat6", Family::Ip6, |t| {
            t.chain("prerouting", |c| {
                c.base(BaseChain::nat(NatHook::Prerouting, Priority::DstNat))
            })
            .rule_keyed("prerouting", "dnat-v6", |r| {
                r.match_tcp_dport(80).dnat_v6(target, Some(8080))
            })
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel must store exactly the dnat_v6 expr nlink rendered; \
             re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// The SNAT counterpart to [`dnat_v6_rule_round_trips`]. SNAT and DNAT are
/// distinct kernel verdicts validated against different hooks, so a v6
/// SNAT on a `postrouting`/`SrcNat` chain is a separate acceptance path
/// from DNAT on prerouting — the structural unit test cannot stand in for
/// it. Same diff-idempotency assertion: an empty second diff proves the
/// kernel stored the exact `Family::Ip6` SNAT expr nlink emitted.
#[tokio::test]
async fn snat_v6_rule_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");

    with_timeout(async {
        use nlink::netlink::nftables::config::NftablesConfig;
        use std::net::Ipv6Addr;

        let ns = TestNamespace::new("snat-v6")?;
        let nft = ns.connection_for::<Nftables>()?;

        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("nat6", Family::Ip6, |t| {
            t.chain("postrouting", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .rule_keyed("postrouting", "snat-v6", |r| {
                r.match_saddr_v6("fd30::100".parse().unwrap(), 128)
                    .snat_v6(target, Some(8080))
            })
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel must store exactly the snat_v6 expr nlink rendered; \
             re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// Address matches in an `inet` chain must round-trip to an empty
/// re-diff (an empty re-diff is byte-equality against the kernel's
/// stored rule). Covers all four legs: v4/v6 × exact (`/32`, `/128`,
/// the nfproto guard) and prefix (`/24`, `/64`, the masked `Bitwise`
/// path); the v4 legs guard against the v4/v6 guard asymmetry.
#[tokio::test]
async fn inet_addr_matches_round_trip() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let ns = TestNamespace::new("inet-addr-rt")?;
        let nft = ns.connection_for::<Nftables>()?;

        let v4: Ipv4Addr = "10.1.2.3".parse().unwrap();
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("filter_addr", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .rule_keyed("input", "v4-exact", |r| r.match_saddr_v4(v4, 32).accept())
            .rule_keyed("input", "v4-prefix", |r| r.match_daddr_v4(v4, 24).accept())
            .rule_keyed("input", "v6-exact", |r| r.match_saddr_v6(v6, 128).accept())
            .rule_keyed("input", "v6-prefix", |r| r.match_daddr_v6(v6, 64).accept())
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel inserts a meta nfproto guard before inet addr matches; \
             nlink must render it too — re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// ICMP/ICMPv6 type matches in an `inet` chain must round-trip. Both
/// protocols are L3-version-specific, so `nft` prepends a `meta nfproto`
/// guard ahead of the `meta l4proto` match — the same asymmetry as the
/// address matchers, on a different matcher family.
#[tokio::test]
async fn inet_icmp_type_matches_round_trip() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("inet-icmp-rt")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = NftablesConfig::new().table("filter_icmp", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            })
            .rule_keyed("input", "icmp", |r| r.match_icmp_type(8).accept())
            .rule_keyed("input", "icmpv6", |r| r.match_icmpv6_type(128).accept())
        });

        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "kernel inserts a meta nfproto guard before inet icmp matches; \
             nlink must render it too — re-diff was non-empty: {again}"
        );

        Ok(())
    })
    .await
}

/// Addr-only SNAT (no port) must round-trip — guards the `NFTA_NAT_FLAGS`
/// derivation for the `MAP_IPS`-only case (flags=1). The snat/dnat
/// round-trip tests cover the addr+port case (flags=3).
#[tokio::test]
async fn snat_v6_addr_only_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");
    with_timeout(async {
        use std::net::Ipv6Addr;
        let ns = TestNamespace::new("snat-v6-addr")?;
        let nft = ns.connection_for::<Nftables>()?;
        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("n", Family::Ip6, |t| {
            t.chain("post", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .rule_keyed("post", "snat", |r| {
                r.match_saddr_v6("fd30::100".parse().unwrap(), 128)
                    .snat_v6(target, None)
            })
        });
        cfg.diff(&nft).await?.apply(&nft).await?;
        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "addr-only snat must round-trip (flags=MAP_IPS only); \
             re-diff was non-empty: {again}"
        );
        Ok(())
    })
    .await
}

/// Combine all three PR #10 fixes in one rule: a `Family::Inet`
/// postrouting chain with `chain_type=nat`, a prefix-masked source
/// match (`match_saddr_v6(.., 64)` — exercises the `bitwise OP`
/// emit) preceded by the `meta nfproto == ipv6` guard, then `snat_v6`
/// to a single address (exercises NAT MAX-regs + FLAGS=MAP_IPS).
/// All three fixes are load-bearing for the second `diff` to be empty.
#[tokio::test]
async fn inet_snat_with_prefix_source_round_trips() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nft_nat");
    with_timeout(async {
        use std::net::Ipv6Addr;
        let ns = TestNamespace::new("inet-snat-prefix-src")?;
        let nft = ns.connection_for::<Nftables>()?;
        let src_prefix: Ipv6Addr = "fd30:beef::".parse().unwrap();
        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let cfg = NftablesConfig::new().table("n", Family::Inet, |t| {
            t.chain("post", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .rule_keyed("post", "snat-prefix", |r| {
                r.match_saddr_v6(src_prefix, 64).snat_v6(target, None)
            })
        });
        cfg.diff(&nft).await?.apply(&nft).await?;
        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "inet-chain prefix-masked-source SNAT must round-trip — \
             requires all three fixes (nfproto guard + bitwise OP + \
             NAT MAX/FLAGS); re-diff was non-empty: {again}"
        );
        Ok(())
    })
    .await
}

// =============================================================================
// Plan 198 — declarative sets + element-level diff
// =============================================================================

/// A `filter_set` table holding an `allowed_v4` IPv4 set with the
/// given element octets (each `(a,b,c,d)`).
fn cfg_with_set(elems: &[(u8, u8, u8, u8)]) -> NftablesConfig {
    let elems: Vec<std::net::Ipv4Addr> = elems
        .iter()
        .map(|(a, b, c, d)| std::net::Ipv4Addr::new(*a, *b, *c, *d))
        .collect();
    NftablesConfig::new().table("filter_set", Family::Inet, move |t| {
        t.set("allowed_v4", move |mut s| {
            s = s.key_type(SetKeyType::Ipv4Addr);
            for ip in &elems {
                s = s.ipv4(*ip);
            }
            s
        })
    })
}

#[tokio::test]
async fn reconcile_empty_to_set_with_elements_applies() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-create")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)]);
        let diff = cfg.diff(&nft).await?;
        assert_eq!(nft::count(&diff, "table", "add"), 1, "one new table");
        assert_eq!(nft::count(&diff, "set", "add"), 1, "one new set");
        // Elements of a brand-new set are installed wholesale.
        assert_eq!(nft::elements(&diff, "add").len(), 1, "one element batch");
        assert_eq!(
            nft::elements(&diff, "add")[0].elements.len(),
            2,
            "two elements"
        );

        diff.apply(&nft).await?;

        // Kernel now reports both elements.
        let kernel = nft
            .list_set_elements("filter_set", "allowed_v4", Family::Inet)
            .await?;
        assert_eq!(kernel.len(), 2, "kernel set must hold both elements");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_set_idempotent_reapply_is_empty() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-idem")?;
        let nft = ns.connection_for::<Nftables>()?;

        let cfg = cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)]);
        cfg.diff(&nft).await?.apply(&nft).await?;

        let again = cfg.diff(&nft).await?;
        assert!(
            again.is_empty(),
            "set + elements must round-trip to an empty diff; got {again}"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_add_one_set_element() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-add-elem")?;
        let nft = ns.connection_for::<Nftables>()?;

        cfg_with_set(&[(10, 0, 0, 1)])
            .diff(&nft)
            .await?
            .apply(&nft)
            .await?;

        // Declare the same set with one extra element.
        let bigger = cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)]);
        let diff = bigger.diff(&nft).await?;
        assert_eq!(nft::count(&diff, "set", "add"), 0, "set already exists");
        assert_eq!(
            nft::elements(&diff, "add").len(),
            1,
            "exactly one element-add batch"
        );
        assert_eq!(
            nft::elements(&diff, "add")[0].elements.len(),
            1,
            "only the single new element is added (element-level diff)"
        );
        assert!(
            nft::elements(&diff, "remove").is_empty(),
            "nothing to remove"
        );
        diff.apply(&nft).await?;

        let kernel = nft
            .list_set_elements("filter_set", "allowed_v4", Family::Inet)
            .await?;
        assert_eq!(kernel.len(), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_remove_one_set_element() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-del-elem")?;
        let nft = ns.connection_for::<Nftables>()?;

        cfg_with_set(&[(10, 0, 0, 1), (10, 0, 0, 2)])
            .diff(&nft)
            .await?
            .apply(&nft)
            .await?;

        // Declare the same set with one element dropped.
        let smaller = cfg_with_set(&[(10, 0, 0, 1)]);
        let diff = smaller.diff(&nft).await?;
        assert!(nft::elements(&diff, "add").is_empty(), "nothing to add");
        assert_eq!(
            nft::elements(&diff, "remove").len(),
            1,
            "exactly one element-remove batch"
        );
        assert_eq!(
            nft::elements(&diff, "remove")[0].elements.len(),
            1,
            "only the undeclared element is removed"
        );
        diff.apply(&nft).await?;

        let kernel = nft
            .list_set_elements("filter_set", "allowed_v4", Family::Inet)
            .await?;
        assert_eq!(kernel.len(), 1, "kernel set must hold just the kept element");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn reconcile_delete_set_when_removed_from_config() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-set-delete")?;
        let nft = ns.connection_for::<Nftables>()?;

        cfg_with_set(&[(10, 0, 0, 1)])
            .diff(&nft)
            .await?
            .apply(&nft)
            .await?;

        // Same table, but the set is gone from the declaration.
        let no_set = NftablesConfig::new().table("filter_set", Family::Inet, |t| t);
        let diff = no_set.diff(&nft).await?;
        assert_eq!(
            nft::count(&diff, "set", "remove"),
            1,
            "the dropped set is deleted"
        );
        diff.apply(&nft).await?;

        let sets = nft.list_sets_in("filter_set", Family::Inet).await?;
        assert!(sets.is_empty(), "set must be gone after reconcile");
        Ok(())
    })
    .await
}

/// A declared chain policy change reaches the live chain, in place (#456).
/// #200 made the diff report it, but the apply sent it with `add_chain`'s
/// `NLM_F_EXCL` and the kernel refused it with `EEXIST`, so it never
/// applied. Sent as an update, the chain keeps its rules.
#[tokio::test]
async fn reconcile_changes_a_live_chain_policy() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-chain-policy")?;
        let nft = ns.connection_for::<Nftables>()?;
        let cfg = |policy: Policy| {
            NftablesConfig::new().table("filter_pol", Family::Inet, move |t| {
                t.chain("input", move |c| {
                    c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(policy))
                })
                .rule_keyed("input", "ssh", |r| r.match_tcp_dport(22).accept())
            })
        };
        cfg(Policy::Drop).diff(&nft).await?.apply(&nft).await?;
        let handle = |rules: &[nlink::netlink::nftables::RuleInfo]| {
            rules
                .iter()
                .find(|r| r.key.as_deref() == Some("ssh"))
                .map(|r| r.handle)
        };
        let before = handle(&nft.list_rules("filter_pol", Family::Inet).await?);
        assert!(before.is_some());

        let diff = cfg(Policy::Accept).diff(&nft).await?;
        assert_eq!(nft::count(&diff, "chain", "update"), 1, "{diff:?}");
        diff.apply(&nft).await?; // EEXIST before #456

        let chains = nft.list_chains_in("filter_pol", Family::Inet).await?;
        let input = chains.iter().find(|c| c.name == "input").expect("input chain");
        assert_eq!(input.policy, Some(Policy::Accept.to_u32()));
        assert!(
            cfg(Policy::Accept).diff(&nft).await?.is_empty(),
            "the policy change must converge"
        );
        assert_eq!(
            before,
            handle(&nft.list_rules("filter_pol", Family::Inet).await?),
            "an update keeps the chain's rules"
        );
        Ok(())
    })
    .await
}

// ============================================================================
// #478 — what an update cannot change on a live chain
// ============================================================================

/// `inet t` with chain `c` (a base chain on `hook` at `priority`, or a
/// regular one) holding two keyed rules, `exclusive` or not.
fn chain_c(base: Option<(FilterHook, Priority)>, exclusive: bool) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Inet, move |t| {
        t.chain("c", move |c| {
            let c = if exclusive { c.exclusive() } else { c };
            match base {
                Some((hook, priority)) => {
                    c.base(BaseChain::filter(hook, priority).policy(Policy::Accept))
                }
                None => c,
            }
        })
        .rule_keyed("c", "ssh", |r| r.match_tcp_dport(22).accept())
        .rule_keyed("c", "web", |r| r.match_tcp_dport(80).accept())
    })
}

/// A base chain's priority or hook change, and a base chain declared as a
/// regular one, recreate the chain and put its rules back in declared
/// order. Sent as an update, the first two were refused with `EEXIST` on
/// every apply; the last left a base chain and an empty diff (#478).
#[tokio::test]
async fn chain_changes_an_update_cannot_make_recreate_the_chain() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let steps = [
        chain_c(Some((FilterHook::Input, Priority::Filter)), false),
        chain_c(Some((FilterHook::Input, Priority::Custom(-10))), false),
        chain_c(Some((FilterHook::Forward, Priority::Custom(-10))), false),
        chain_c(None, false),
    ];
    let want = [
        (Some(Hook::Input.number(Family::Inet)), Some(0)),
        (Some(Hook::Input.number(Family::Inet)), Some(-10)),
        (Some(Hook::Forward.number(Family::Inet)), Some(-10)),
        (None, None),
    ];
    let ns = TestNamespace::new("nft-chain-recreate")?;
    assert_transition(&ns, &steps, false, async |i, nft| {
        let chains = nft
            .list_chains_in("t", Family::Inet)
            .await
            .map_err(|e| e.to_string())?;
        let c = chains
            .iter()
            .find(|c| c.name == "c")
            .ok_or("chain c is gone")?;
        if (c.hook, c.priority) != want[i] {
            return Err(format!(
                "want {:?}, chain c is {:?}",
                want[i],
                (c.hook, c.priority)
            ));
        }
        let rules = nft
            .list_rules("t", Family::Inet)
            .await
            .map_err(|e| e.to_string())?;
        let keys: Vec<&str> = rules.iter().filter_map(|r| r.key.as_deref()).collect();
        if keys != ["ssh", "web"] {
            return Err(format!("want the rules back in order: {keys:?}"));
        }
        Ok(())
    })
    .await
}

/// A rule nlink did not write in a chain that has to be recreated refuses
/// the recreate, which says so in the diff and changes nothing. An
/// exclusive chain deletes the rule instead.
#[tokio::test]
async fn a_chain_recreate_over_a_rule_nlink_did_not_write_is_refused() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("nft-chain-refuse")?;
        let nft = ns.connection_for::<Nftables>()?;
        chain_c(Some((FilterHook::Input, Priority::Filter)), false)
            .diff(&nft)
            .await?
            .apply(&nft)
            .await?;
        self::nft(&ns, "add rule inet t c tcp dport 8080 accept")?;

        let moved = chain_c(Some((FilterHook::Input, Priority::Custom(-10))), false);
        let diff = moved.diff(&nft).await?;
        assert!(
            matches!(
                diff.blocked.as_slice(),
                [nlink::netlink::nftables::config::Blocked::ChainRecreate { chain, rules, .. }]
                    if chain == "c" && rules.len() == 1
            ),
            "{diff}"
        );
        assert_eq!(nft::count(&diff, "chain", "recreate"), 0, "{diff}");
        assert!(diff.to_string().contains("recreate refused"), "{diff}");
        let err = diff.apply(&nft).await.expect_err("the recreate is refused");
        assert!(err.is_not_supported(), "{err}");
        assert_eq!(
            err.object(),
            Some(&nlink::ErrorObject::NftChain {
                family: "inet".into(),
                table: "t".into(),
                name: "c".into(),
            }),
            "the refusal names its chain (#718): {err}"
        );
        let chains = nft.list_chains_in("t", Family::Inet).await?;
        assert_eq!(
            chains
                .iter()
                .find(|c| c.name == "c")
                .and_then(|c| c.priority),
            Some(0),
            "the refused apply changed the chain"
        );

        let exclusive = chain_c(Some((FilterHook::Input, Priority::Custom(-10))), true);
        exclusive.diff(&nft).await?.apply(&nft).await?;
        assert!(exclusive.diff(&nft).await?.is_empty());
        let rules = nft.list_rules("t", Family::Inet).await?;
        assert_eq!(
            rules.len(),
            2,
            "the exclusive chain keeps only its own rules"
        );
        Ok(())
    })
    .await
}

// ============================================================================
// #484 — hooks per family, chains on several devices
// ============================================================================

/// An `arp` chain lands on the hook it declares. Hook numbers are per
/// family, and ARP's are `NF_ARP_IN = 0`, `NF_ARP_OUT = 1`: sent as the
/// inet numbers, an input chain filtered outgoing ARP and an output chain
/// was refused (#484).
#[tokio::test]
async fn arp_chains_land_on_their_hooks() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let cfg = NftablesConfig::new().table("t", Family::Arp, |t| {
        t.chain("in", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
        })
        .chain("out", |c| {
            c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
        })
    });
    let ns = TestNamespace::new("nft-arp-hooks")?;
    assert_transition(&ns, &[cfg], false, async |_, _| {
        for (chain, hook) in [("in", "input"), ("out", "output")] {
            let shown =
                nft(&ns, &format!("list chain arp t {chain}")).map_err(|e| e.to_string())?;
            if !shown.contains(&format!("hook {hook} ")) {
                return Err(format!("chain {chain} is not on {hook}:\n{shown}"));
            }
        }
        Ok(())
    })
    .await
}

/// A netdev chain moved to another device ends up on that device alone.
/// The kernel adds devices on an update, and dumps a chain on several of
/// them without `NFTA_HOOK_DEV`, so the chain was left on both and drifted
/// on every apply (#484).
#[tokio::test]
async fn a_netdev_chain_moves_to_the_declared_device() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "dummy");

    let on = |dev: &'static str| {
        NftablesConfig::new().table("t", Family::Netdev, move |t| {
            t.chain("c", move |c| {
                c.base(BaseChain::filter(
                    FilterHook::ingress(dev),
                    Priority::Filter,
                ))
            })
            .rule_keyed("c", "count", |r| r.counter())
        })
    };
    let ns = TestNamespace::new("nft-netdev-dev")?;
    for dev in ["d0", "d1"] {
        ns.exec("ip", &["link", "add", dev, "type", "dummy"])?;
    }
    assert_transition(&ns, &[on("d0"), on("d1")], false, async |i, nft_conn| {
        let want = ["d0", "d1"][i];
        let chains = nft_conn
            .list_chains_in("t", Family::Netdev)
            .await
            .map_err(|e| e.to_string())?;
        let c = chains
            .iter()
            .find(|c| c.name == "c")
            .ok_or("chain c is gone")?;
        if c.devices != [want] {
            return Err(format!("want the chain on {want} alone: {:?}", c.devices));
        }
        let shown = nft(&ns, "list chain netdev t c").map_err(|e| e.to_string())?;
        if !shown.contains(&format!("device \"{want}\"")) {
            return Err(format!("nft disagrees:\n{shown}"));
        }
        Ok(())
    })
    .await
}

// ============================================================================
// #479 — table flags and flowtables, changed in place
// ============================================================================

/// A table's dormant flag goes on and off in place, rules and all. The
/// update was sent with `NLM_F_EXCL` (`EEXIST`), and without its flags
/// attribute when clearing one (a silent no-op) (#479). Persist cannot be
/// changed on a live table, and the diff says so instead of trying.
#[tokio::test]
async fn table_flags_change_in_place() -> nlink::Result<()> {
    use nlink::netlink::nftables::{NFT_TABLE_F_DORMANT, NFT_TABLE_F_PERSIST};
    require_root!();
    nlink::require_modules!("nf_tables");

    let table = |flags: u32| {
        NftablesConfig::new().table("t", Family::Inet, move |t| {
            t.flags(flags)
                .chain("c", |c| c)
                .rule_keyed("c", "ok", |r| r.accept())
        })
    };
    let ns = TestNamespace::new("nft-table-flags")?;
    let steps = [table(0), table(NFT_TABLE_F_DORMANT), table(0)];
    assert_transition(&ns, &steps, false, async |i, nft_conn| {
        let tables = nft_conn.list_tables().await.map_err(|e| e.to_string())?;
        let t = tables
            .iter()
            .find(|t| t.name == "t")
            .ok_or("table t is gone")?;
        let want = [0, NFT_TABLE_F_DORMANT, 0][i];
        if t.flags != want {
            return Err(format!(
                "want flags {want:#x}, the table has {:#x}",
                t.flags
            ));
        }
        Ok(())
    })
    .await?;

    let nft_conn = ns.connection_for::<Nftables>()?;
    let diff = table(NFT_TABLE_F_PERSIST).diff(&nft_conn).await?;
    assert!(
        matches!(
            diff.blocked.as_slice(),
            [nlink::netlink::nftables::config::Blocked::TableFlags { from: 0, to, .. }]
                if *to == NFT_TABLE_F_PERSIST
        ),
        "{diff}"
    );
    let err = diff
        .apply(&nft_conn)
        .await
        .expect_err("persist cannot change");
    assert!(err.is_not_supported(), "{err}");
    Ok(())
}

/// A flowtable's devices and counter flag change in place, and a new
/// priority recreates it with the rule that offloads to it moved out of
/// the way. Every change used to go to `flowtables_to_add`, which the
/// kernel refused with `EEXIST`; a device could never be removed, and the
/// device list was compared in order (#479).
#[tokio::test]
async fn flowtable_changes_apply() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables", "nf_flow_table", "nft_flow_offload", "dummy");

    let ft = |devs: &'static [&'static str], counter: bool, priority: i32| {
        NftablesConfig::new().table("t", Family::Inet, move |t| {
            t.flowtable("ft", move |f| {
                let f = devs.iter().fold(f, |f, d| f.device(*d));
                f.counter(counter).priority(priority)
            })
            .chain("forward", |c| {
                c.base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
            })
            .rule_keyed("forward", "offload", |r| r.flow_offload("ft"))
        })
    };
    let ns = TestNamespace::new("nft-flowtable")?;
    for dev in ["d0", "d1", "d2"] {
        ns.exec("ip", &["link", "add", dev, "type", "dummy"])?;
    }
    let steps = [
        ft(&["d0", "d1"], false, 0),
        ft(&["d2", "d1"], false, 0),
        ft(&["d1", "d2"], true, 0),
        ft(&["d1", "d2"], false, 10),
    ];
    let want: [(&[&str], bool, i32); 4] = [
        (&["d0", "d1"], false, 0),
        (&["d1", "d2"], false, 0),
        (&["d1", "d2"], true, 0),
        (&["d1", "d2"], false, 10),
    ];
    assert_transition(&ns, &steps, false, async |i, nft_conn| {
        let fts = nft_conn
            .list_flowtables()
            .await
            .map_err(|e| e.to_string())?;
        let f = fts
            .iter()
            .find(|f| f.name == "ft")
            .ok_or("flowtable ft is gone")?;
        let mut devs = f.devs.clone();
        devs.sort();
        let counter = f.flags & nlink::netlink::nftables::NFT_FLOWTABLE_COUNTER != 0;
        let (want_devs, want_counter, want_priority) = want[i];
        if devs != want_devs || counter != want_counter || f.priority != want_priority {
            return Err(format!(
                "want {want:?}, the flowtable has {devs:?}, counter {counter}, priority {}",
                f.priority,
                want = want[i]
            ));
        }
        let shown = nft(&ns, "list flowtable inet t ft").map_err(|e| e.to_string())?;
        for dev in want_devs {
            if !shown.contains(dev) {
                return Err(format!("nft does not show {dev}:\n{shown}"));
            }
        }
        Ok(())
    })
    .await
}

// ============================================================================
// #460 — removing something a rule used
// ============================================================================

/// `ip t` with a base `input` chain holding `rules`, plus whatever `extra`
/// declares (objects, sets, more chains).
fn input_table(
    extra: impl FnOnce(
        nlink::netlink::nftables::config::DeclaredTableBuilder,
    ) -> nlink::netlink::nftables::config::DeclaredTableBuilder
    + 'static,
) -> NftablesConfig {
    NftablesConfig::new().table("t", Family::Ip, move |t| {
        extra(t.chain("input", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
        }))
    })
}

/// A rename of a named counter or set, dropping a chain whose rule used a
/// counter, and retargeting a jump to a chain that goes away: each one
/// removes something a rule still uses until the batch replaces or
/// deletes that rule. The deletes went first, so every one of these
/// failed with EBUSY, on every apply (#460).
#[tokio::test]
async fn removing_what_a_rule_used_converges_in_one_apply() -> nlink::Result<()> {
    use nlink::netlink::nftables::ObjectConfig;
    use nlink::netlink::nftables::types::ChainName;
    require_root!();
    nlink::require_modules!("nf_tables");

    let counted = |name: &'static str| {
        input_table(move |t| {
            t.object(name, ObjectConfig::Counter)
                .rule_keyed("input", "ssh", move |r| {
                    r.match_tcp_dport(22).counter_named(name).drop()
                })
        })
    };
    let blocked = |name: &'static str| {
        input_table(move |t| {
            t.set(name, |s| {
                s.key_type(SetKeyType::Ipv4Addr)
                    .ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1))
            })
            .rule_keyed("input", "deny", move |r| r.match_saddr_in_set(name).drop())
        })
    };
    let with_output = |output: bool| {
        input_table(move |t| {
            if !output {
                return t;
            }
            t.object("x", ObjectConfig::Counter)
                .chain("output", |c| {
                    c.base(BaseChain::filter(FilterHook::Output, Priority::Filter))
                })
                .rule_keyed("output", "count", |r| r.counter_named("x"))
        })
    };
    let jumping_to = |target: &'static str| {
        input_table(move |t| {
            t.chain(target, |c| c)
                .rule_keyed(target, "accept", |r| r.accept())
                .rule_keyed("input", "web", move |r| {
                    r.match_tcp_dport(80).jump(ChainName::new(target).unwrap())
                })
        })
    };

    let cases = vec![
        case("counter-renamed", vec![counted("a"), counted("b")]),
        case("set-renamed", vec![blocked("blocked"), blocked("deny")]),
        case(
            "chain-using-a-counter-dropped",
            vec![with_output(true), with_output(false)],
        ),
        case(
            "jump-retargeted",
            vec![jumping_to("web"), jumping_to("http")],
        ),
    ];
    assert_converges("nft-rm-used", cases).await
}

// ============================================================================
// #459 — what a rule nlink does not manage still uses
// ============================================================================

/// Run `nft <cmd>` inside `ns`: rules a person adds by hand, which nlink
/// did not write and must leave alone.
fn nft(ns: &TestNamespace, cmd: &str) -> nlink::Result<String> {
    let args: Vec<&str> = cmd.split_whitespace().collect();
    ns.exec("nft", &args)
}

/// Rules added by hand to a declared chain stay, and so must what they use:
/// the anonymous set behind an inline `{ 4001, 4002 }`, a chain they jump
/// to, a named counter they count into. The diff deleted all three, and
/// each delete was `EBUSY`, so every apply failed until someone removed the
/// rules (#459). An undeclared chain nothing uses still goes.
#[tokio::test]
async fn what_a_hand_added_rule_uses_is_kept() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-kept")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        let cfg = input_table(|t| t.rule_keyed("input", "ssh", |r| r.match_tcp_dport(22).accept()));
        cfg.diff(&conn).await?.apply(&conn).await?;
        for cmd in [
            "add rule ip t input tcp dport { 4001, 4002 } counter accept",
            "add chain ip t dbg",
            "add rule ip t input tcp dport 4003 jump dbg",
            "add counter ip t handmade",
            "add rule ip t input tcp dport 4004 counter name handmade",
            "add chain ip t unused",
        ] {
            nft(&ns, cmd)?;
        }

        let diff = cfg.diff(&conn).await?;
        let removes = |c: &nlink::netlink::nftables::config::NftChange| {
            matches!(c.op(), "remove" | "recreate")
        };
        assert!(
            !diff.changes.iter().any(|c| c.kind() == "set" && removes(c)),
            "{diff}"
        );
        assert!(
            !diff
                .changes
                .iter()
                .any(|c| c.kind() == "object" && removes(c)),
            "{diff}"
        );
        let deleted: Vec<&str> = diff
            .chains()
            .filter_map(|c| match c {
                Change::Remove(c) => Some(c.name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(deleted, ["unused"], "{diff}");
        let mut kept: Vec<String> = diff
            .blocked
            .iter()
            .filter_map(|b| match b {
                nlink::netlink::nftables::config::Blocked::InUse { item, rules } => {
                    Some(format!("{item} by {}", rules.len()))
                }
                _ => None,
            })
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            ["chain Ip t/dbg by 1", "object Ip t/handmade (Counter) by 1"],
            "{diff}"
        );

        diff.apply(&conn).await?;
        let again = cfg.diff(&conn).await?;
        assert!(again.is_empty(), "{again}");
        let rules = conn.list_rules("t", Family::Ip).await?;
        assert_eq!(
            rules.iter().filter(|r| r.chain == "input").count(),
            4,
            "{rules:?}"
        );
        Ok(())
    })
    .await
}

// ============================================================================
// #481 — a refused batch names every operation it refused
// ============================================================================

/// A batch with two bad operations — a rule for a chain that does not
/// exist, and a delete of a set a rule still uses — is refused with both
/// named, not one errno and a bare offset. And nothing in it is committed:
/// the table it also added is not there.
#[tokio::test]
async fn a_refused_batch_names_each_refused_operation() -> nlink::Result<()> {
    use nlink::netlink::nftables::types::{Chain, Rule, Set};
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-batch-err")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        conn.add_table("t", Family::Ip).await?;
        conn.add_chain(Chain::new("t", "c")?.family(Family::Ip))
            .await?;
        let set = Set::new("t", "s")
            .family(Family::Ip)
            .key_type(SetKeyType::Ipv4Addr);
        conn.add_set(set).await?;
        conn.add_rule(
            Rule::new("t", "c")
                .family(Family::Ip)
                .match_saddr_in_set("s")
                .drop(),
        )
        .await?;

        let err = conn
            .transaction()
            .add_table("other", Family::Ip)
            .add_rule(Rule::new("t", "nochain").family(Family::Ip).accept())
            .del_set("t", "s", Family::Ip)
            .commit(&conn)
            .await
            .expect_err("the batch has two bad operations");
        let shown = err.to_string();
        assert!(shown.contains("nothing committed"), "{shown}");
        assert!(
            shown.contains("op #1 add rule ip t/nochain: No such file or directory (errno 2)"),
            "{shown}"
        );
        assert!(
            shown.contains("op #2 delete set ip t/s: Device or resource busy (errno 16)"),
            "{shown}"
        );
        assert!(
            !shown.contains("os error"),
            "the errno is said once: {shown}"
        );
        // The predicates answer for the first failure.
        assert!(err.is_not_found(), "{shown}");
        let nlink::ErrorDetail::NftBatch { failures, .. } = err.detail() else {
            panic!("expected Error::NftBatch, got {err:?}");
        };
        assert_eq!(failures.len(), 2, "{shown}");
        // Each refused operation names its object, and the error the first
        // one's (#718).
        let rule = nlink::ErrorObject::NftRule {
            family: "ip".into(),
            table: "t".into(),
            chain: "nochain".into(),
            key: None,
        };
        assert_eq!(failures[0].object.as_ref(), Some(&rule), "{shown}");
        assert_eq!(
            failures[1].object,
            Some(nlink::ErrorObject::NftSet {
                family: "ip".into(),
                table: "t".into(),
                name: "s".into(),
            }),
            "{shown}"
        );
        assert_eq!(err.object(), Some(&rule), "{shown}");

        let tables = conn.list_tables().await?;
        assert!(
            !tables.iter().any(|t| t.name == "other"),
            "a refused batch commits nothing: {tables:?}"
        );
        Ok(())
    })
    .await
}

/// A batch refused in the middle, its last operation accepted. The kernel
/// answers the last operation after every error, and that ACK is what ends
/// the read: a commit no longer waits for BATCH_END's, which kernels before
/// 6.10 never send. Then every refused operation is named, on a dispatcher
/// connection too, where a drain that stopped at the first empty read could
/// stop before the driver routed the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_refused_mid_way_ends_on_its_last_ack() -> nlink::Result<()> {
    use nlink::netlink::nftables::types::Rule;
    require_root!();
    nlink::require_modules!("nf_tables");

    const REFUSED: usize = 16;
    let ns = TestNamespace::new("nft-batch-mid")?;
    for dispatched in [false, true] {
        let conn = ns.connection_for::<Nftables>()?;
        let conn = if dispatched { conn.with_dispatcher() } else { conn };
        with_timeout(async {
            let mut tx = conn.transaction();
            for i in 0..REFUSED {
                let chain = format!("c{i}");
                tx = tx.add_rule(Rule::new("absent", &chain).family(Family::Ip).accept());
            }
            let err = tx
                .add_table("last", Family::Ip)
                .commit(&conn)
                .await
                .expect_err("every rule names a table that does not exist");
            let nlink::ErrorDetail::NftBatch { failures, .. } = err.detail() else {
                panic!("expected Error::NftBatch, got {err:?}");
            };
            let indexes: Vec<_> = failures.iter().map(|f| f.index).collect();
            let expected: Vec<_> = (0..REFUSED).map(Some).collect();
            assert_eq!(indexes, expected, "dispatched: {dispatched}: {err}");
            assert!(
                !conn.list_tables().await?.iter().any(|t| t.name == "last"),
                "a refused batch commits nothing"
            );

            // Accepted, the same batch ends on the last ACK alone.
            conn.transaction()
                .add_table("first", Family::Ip)
                .add_table("last", Family::Ip)
                .commit(&conn)
                .await?;
            let tables = conn.list_tables().await?;
            assert!(tables.iter().any(|t| t.name == "last"), "dispatched: {dispatched}: {tables:?}");
            conn.transaction()
                .del_table("first", Family::Ip)
                .del_table("last", Family::Ip)
                .commit(&conn)
                .await?;
            Ok(())
        })
        .await?;
    }
    Ok(())
}

/// A failed commit says it is the commit's (#868). Every operation is
/// accepted, then the kernel refuses to commit an anonymous set no rule
/// uses, and reports it at the first operation's seq: it used to read as
/// that operation's refusal. Alone in its batch and behind another
/// operation, which take different paths to the answer, on a plain and a
/// dispatcher connection: alone, the error's seq is the operation's ACK's
/// too, and only reading what is queued after it tells them apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_commit_names_the_commit() -> nlink::Result<()> {
    use nlink::netlink::nftables::types::{Set, SetFlags};
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-commit-fail")?;
    ns.connection_for::<Nftables>()?.add_table("t", Family::Ip).await?;
    let unbound = || {
        Set::new("t", "__set0")
            .family(Family::Ip)
            .key_type(SetKeyType::Ipv4Addr)
            .flags(SetFlags::ANONYMOUS | SetFlags::CONSTANT)
    };
    for dispatched in [false, true] {
        let conn = ns.connection_for::<Nftables>()?;
        let conn = if dispatched { conn.with_dispatcher() } else { conn };
        for behind_another in [false, true] {
            with_timeout(async {
                let mut tx = conn.transaction();
                if behind_another {
                    tx = tx.add_table("other", Family::Ip);
                }
                let err = tx
                    .add_set(unbound())
                    .commit(&conn)
                    .await
                    .expect_err("the kernel does not commit an unbound anonymous set");
                let nlink::ErrorDetail::NftBatch { failures, .. } = err.detail() else {
                    panic!("expected Error::NftBatch, got {err:?}");
                };
                let shown = format!("dispatched {dispatched}, behind another {behind_another}: {err}");
                assert_eq!(failures.len(), 1, "{shown}");
                assert_eq!(failures[0].index, None, "{shown}");
                assert_eq!(failures[0].operation, "commit", "{shown}");
                assert_eq!(failures[0].errno, libc::EINVAL, "{shown}");
                assert!(shown.contains("commit: Invalid argument (errno 22)"), "{shown}");
                assert!(err.is_invalid_argument(), "{shown}");
                assert_eq!(err.object(), None, "{shown}");
                let tables = conn.list_tables().await?;
                assert!(
                    !tables.iter().any(|t| t.name == "other"),
                    "a failed commit commits nothing: {shown}: {tables:?}"
                );
                Ok(())
            })
            .await?;
        }
    }
    Ok(())
}

// ============================================================================
// #503 — the nftables snapshot holds named objects and set elements
// ============================================================================

/// The nftables resync stream starts with a snapshot, and it carries named
/// objects and set elements, which the live stream reports too. Without
/// them a mirror lost every named counter and set element on its first
/// overflow; without the initial snapshot it never had them (#503).
#[tokio::test]
async fn the_nftables_snapshot_holds_objects_and_elements() -> nlink::Result<()> {
    use nlink::netlink::nftables::NftablesEvent;
    use nlink::netlink::nftables::ObjectConfig;
    use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent};
    use std::sync::Arc;
    use tokio_stream::StreamExt;
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-snap")?;
    let conn = ns.connection_for::<Nftables>()?;
    let cfg = NftablesConfig::new().table("t", Family::Inet, |t| {
        t.object("hits", ObjectConfig::Counter).set("allow", |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .ipv4(std::net::Ipv4Addr::new(192, 0, 2, 1))
                .ipv4(std::net::Ipv4Addr::new(192, 0, 2, 2))
        })
    });
    cfg.diff(&conn).await?.apply(&conn).await?;

    let name = ns.name().to_string();
    let factory: ConnectionFactory<Nftables> = Arc::new(move || {
        let name = name.clone();
        Box::pin(async move { nlink::Connection::<Nftables>::new_in(&name) })
    });
    let mut stream = ns
        .connection_for::<Nftables>()?
        .into_events_with_resync(factory)
        .await?;
    let first = with_timeout(async { stream.next().await.expect("an item") }).await?;
    assert!(first.is_initial_sync_start(), "{first:?}");
    let (mut object, mut elements) = (false, 0);
    loop {
        let item = with_timeout(async { stream.next().await.expect("more") }).await?;
        match item {
            ResyncedEvent::Resynced(NftablesEvent::NewObject(o)) if o.name == "hits" => {
                object = true;
            }
            ResyncedEvent::Resynced(NftablesEvent::NewSetElements(e)) if e.set == "allow" => {
                elements = e.elements.len();
            }
            item if item.is_resync_end() => break,
            _ => {}
        }
    }
    assert!(object, "the named counter is in the snapshot");
    assert_eq!(elements, 2, "the set's elements are in the snapshot");
    Ok(())
}

/// #482: a diff took 3 + 2N dumps with no generation check, and its apply
/// committed whatever the ruleset had become. A diff now records the
/// generation it was taken at, and its apply is refused with ERESTART once
/// another writer has committed; `NftablesConfig::apply_reconcile` then
/// diffs again.
#[tokio::test]
async fn a_stale_diff_is_refused_and_reconcile_diffs_again() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-genid")?;
        let nft = ns.connection_for::<Nftables>()?;
        let cfg = cfg_with_n_rules(2);
        let diff = cfg.diff(&nft).await?;
        let taken_at = diff
            .generation
            .expect("a diff of the kernel carries its generation");

        // Another writer commits between the diff and the apply.
        ns.exec("nft", &["add", "table", "ip", "someone-else"])?;
        assert_ne!(nft.generation().await?, taken_at);

        let err = diff.apply(&nft).await.expect_err("the ruleset moved on");
        assert!(err.is_restart(), "{err}");
        let tables = nft.list_tables().await?;
        assert!(
            tables.iter().all(|t| t.name != "filter_rec"),
            "nothing of the refused batch may land"
        );

        let report = cfg
            .apply_reconcile(&nft, ReconcileOptions::default())
            .await?;
        assert_eq!(report.attempts, 1, "{report:?}");
        assert!(cfg.diff(&nft).await?.is_empty());
        Ok(())
    })
    .await
}

/// A commit moves the generation by exactly one. `apply` relies on it when
/// a diff grows a set — committed in a batch of its own first — and sends
/// the rest expecting the next generation.
#[tokio::test]
async fn one_commit_moves_the_generation_by_one() -> nlink::Result<()> {
    use nlink::netlink::nftables::types::Set;
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-genstep")?;
        let nft = ns.connection_for::<Nftables>()?;
        let before = nft.generation().await?;
        nft.add_table("t", Family::Ip).await?;
        assert_eq!(nft.generation().await?, before.wrapping_add(1));

        nft.add_set(
            Set::new("t", "s")
                .family(Family::Ip)
                .key_type(SetKeyType::Ipv4Addr)
                .size(10),
        )
        .await?;
        let cfg = NftablesConfig::new().table("t", Family::Ip, |t| {
            t.set("s", |s| s.key_type(SetKeyType::Ipv4Addr).size(20))
                .chain("c", |c| c)
                .rule_keyed("c", "k", |r| r.accept())
        });
        let diff = cfg.diff(&nft).await?;
        assert_eq!(nft::count(&diff, "set", "update"), 1, "{diff}");
        assert!(diff.change_count() > 1, "a set update and more: {diff}");
        diff.apply(&nft).await?;
        assert!(cfg.diff(&nft).await?.is_empty());
        Ok(())
    })
    .await
}

/// A table declared absent is deleted with what is in it, the next diff is
/// empty, and no other table is touched (#519). Declared and absent at
/// once is a validation error.
#[tokio::test]
async fn an_absent_table_is_deleted_and_stays_gone() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("rec-absent")?;
        let nft = ns.connection_for::<Nftables>()?;
        cfg_with_n_rules(2).diff(&nft).await?.apply(&nft).await?;
        nft.add_table("theirs", Family::Inet).await?;

        let gone = NftablesConfig::new().absent_table("filter_rec", Family::Inet);
        let diff = gone.diff(&nft).await?;
        let removed: Vec<_> = diff
            .tables()
            .filter_map(|c| match c {
                Change::Remove(t) => Some((t.family, t.name.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(removed, [(Family::Inet, "filter_rec")], "{diff}");
        diff.apply(&nft).await?;
        let tables: Vec<String> = nft.list_tables().await?.into_iter().map(|t| t.name).collect();
        assert_eq!(tables, ["theirs"], "only the absent table goes");
        assert!(gone.diff(&nft).await?.is_empty(), "absent stays absent");

        let both = cfg_with_n_rules(1).absent_table("filter_rec", Family::Inet);
        let err = both.diff(&nft).await.expect_err("declared and absent");
        assert!(err.to_string().contains("declared and declared absent"), "{err}");
        Ok(())
    })
    .await
}

/// #523: a table deleted while the subscriber was overflowing is in no
/// event, and the resync snapshot only says what exists.
/// `with_gap_deltas(NftablesEvent::object_key)` reports it as a
/// `Resynced(DelTable)` before the resync closes.
#[tokio::test]
async fn gap_deltas_report_a_table_deleted_during_an_overflow() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    use std::sync::Arc;

    use nlink::netlink::nftables::{NftablesEvent, Rule};
    use nlink::netlink::resync::{ConnectionFactory, ResyncedEvent};
    use nlink::netlink::resync_ext::ResyncStreamExt;
    use tokio_stream::StreamExt;

    with_timeout(async {
        let ns = TestNamespace::new("nft-gap")?;
        let cfg = NftablesConfig::new().table("keep", Family::Inet, |t| {
            t.chain("input", |c| {
                c.base(
                    BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Accept),
                )
            })
        });
        let other = ns.connection_for::<Nftables>()?;
        cfg.diff(&other).await?.apply(&other).await?;
        other.add_table("gone", Family::Inet).await?;

        let name = ns.name().to_string();
        let factory: ConnectionFactory<Nftables> = Arc::new(move || {
            let name = name.clone();
            Box::pin(async move { nlink::Connection::new_in(&name) })
        });
        let conn = ns.connection_for::<Nftables>()?;
        conn.socket().set_rcvbuf(256)?;
        let mut stream = conn
            .into_events_with_resync(factory)
            .await?
            .with_gap_deltas(NftablesEvent::object_key);
        while !stream.next().await.expect("an item")?.is_resync_end() {}

        // Overflow the buffer, reading nothing, then delete the table.
        for i in 0..200u32 {
            let rule = Rule::new("keep", "input")
                .family(Family::Inet)
                .accept()
                .comment(&format!("r{i}"));
            other.add_rule(rule).await?;
        }
        other.del_table("gone", Family::Inet).await?;

        let mut gone = false;
        loop {
            let next = tokio::time::timeout(Duration::from_secs(1), stream.next()).await;
            let Ok(Some(item)) = next else { break };
            if let ResyncedEvent::Resynced(NftablesEvent::DelTable(t)) = item?
                && t.name == "gone"
            {
                gone = true;
            }
        }
        assert!(gone, "no Resynced(DelTable) for the table deleted in the gap");
        Ok(())
    })
    .await
}

/// What a diff would do, without the kernel's handles: the same changes,
/// however the rules happen to be numbered.
fn diff_shape(d: &nlink::netlink::nftables::config::NftablesDiff) -> Vec<String> {
    // From and to, where nothing but a handle is the kernel's own.
    let mut shape = Vec::new();
    for change in d.changes.iter().flat_map(NftChange::flatten) {
        let line = match change {
            NftChange::Rule(c) => {
                let erase = |r: Option<&nlink::netlink::nftables::config::NftRule>| {
                    r.map(|r| {
                        let mut r = r.clone();
                        r.handle = None;
                        format!(
                            "{:?} {:?} {:?} {:?}",
                            r.key,
                            r.placement.is_some(),
                            r.spec,
                            r.nft
                        )
                    })
                };
                format!(
                    "{} rule {:?} -> {:?}",
                    change.op(),
                    erase(c.from()),
                    erase(c.to())
                )
            }
            NftChange::Set(Change::Recreate {
                from,
                to,
                reason,
                cascade,
            }) => format!(
                "recreate set {from:?} -> {to:?} ({reason}) with {}",
                cascade.len()
            ),
            other => {
                let mut text = format!("{other:?}");
                if let NftChange::Elements(_) = other {
                    text = format!("{} elements", other.op());
                }
                text
            }
        };
        shape.push(line);
    }
    shape.sort();
    shape
}

/// #527: the diff runs offline. With `before` applied, what the kernel
/// diff says `after` changes is what `after.diff_against(&before)` says
/// without the kernel — rule edits, removals and inserts, a policy, set
/// elements both ways, an object's quota, a set and a chain gone — and
/// each config diffs empty against its own simulated echo as it does
/// against the kernel's.
#[tokio::test]
async fn the_offline_diff_is_the_kernel_diff() -> nlink::Result<()> {
    use nlink::netlink::nftables::config::RulesetSnapshot;
    use nlink::netlink::nftables::object::ObjectConfig;
    use nlink::netlink::nftables::{QuotaExpr, SetElement};
    use std::net::Ipv4Addr;
    require_root!();
    nlink::require_modules!("nf_tables", "nft_quota");

    let ip = |n| Ipv4Addr::new(10, 0, 0, n);
    let config = |v2: bool| {
        NftablesConfig::new().table("t", Family::Inet, move |t| {
            let t = t
                .chain("input", move |c| {
                    c.base(
                        BaseChain::filter(FilterHook::Input, Priority::Filter).policy(if v2 {
                            Policy::Drop
                        } else {
                            Policy::Accept
                        }),
                    )
                })
                .set("hosts", move |s| {
                    let s = s.key_type(SetKeyType::Ipv4Addr).ipv4(ip(1)).ipv4(ip(2));
                    if v2 { s.ipv4(ip(3)) } else { s.ipv4(ip(4)) }
                })
                .object(
                    "budget",
                    ObjectConfig::Quota(QuotaExpr::new(if v2 { 2_000_000 } else { 1_000_000 })),
                )
                .rule_keyed("input", "ssh", move |r| {
                    r.match_tcp_dport(if v2 { 2222 } else { 22 }).accept()
                })
                .rule_keyed("input", "hosts", |r| r.match_saddr_in_set("hosts").accept());
            if v2 {
                t.rule_keyed("input", "dns", |r| r.match_udp_dport(53).accept())
            } else {
                t.chain("old", |c| c)
                    .set("gone", |s| s.key_type(SetKeyType::InetService).element(SetElement::port(80)))
                    .rule_keyed("input", "web", |r| r.match_tcp_dport(80).accept())
            }
        })
    };
    let (before, after) = (config(false), config(true));

    let ns = TestNamespace::new("nft-offline")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        before.diff(&conn).await?.apply(&conn).await?;
        let options = NftDiffOptions::default();
        let online = after.diff(&conn).await?;
        let offline = after.diff_against(&before, &options)?;
        assert_eq!(diff_shape(&online), diff_shape(&offline), "online:\n{online}\noffline:\n{offline}");
        assert!(online.change_count() >= 9, "the test should change plenty: {online}");

        for config in [&before, &after] {
            let echo = config.diff_snapshot(&RulesetSnapshot::from_config(config), &options)?;
            assert!(echo.is_empty(), "{echo}");
        }
        // The kernel's own snapshot, read once, diffs as diff() does.
        let snapshot = after.snapshot(&conn).await?;
        assert!(snapshot.generation.is_some());
        assert_eq!(diff_shape(&after.diff_snapshot(&snapshot, &options)?), diff_shape(&online));
        Ok(())
    })
    .await
}

/// #527: a shared table's diff deletes only what nlink's apply made. The
/// chain, set and counter `nft` added stay when the config stops declaring
/// nlink's own, which go; the ownership tag reads back, and `nft list`
/// shows nothing of it. An owned table deletes what `nft` added.
#[tokio::test]
async fn a_shared_table_keeps_what_another_tool_added() -> nlink::Result<()> {
    use nlink::netlink::nftables::config::TableMode;
    use nlink::netlink::nftables::object::ObjectConfig;
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-shared")?;
    let conn = ns.connection_for::<Nftables>()?;
    let config = |mode, ours: bool| {
        NftablesConfig::new().table("s", Family::Inet, move |t| {
            let t = t.mode(mode).chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            });
            if ours {
                t.chain("ours", |c| c)
                    .set("our_set", |s| s.key_type(SetKeyType::Ipv4Addr))
                    .object("our_counter", ObjectConfig::Counter)
            } else {
                t
            }
        })
    };
    let names = |d: &nlink::netlink::nftables::config::NftablesDiff| {
        let mut n: Vec<String> = d
            .changes
            .iter()
            .filter_map(|c| match c {
                NftChange::Chain(Change::Remove(c)) => Some(c.name.clone()),
                NftChange::Set(Change::Remove(s)) => Some(s.name.clone()),
                NftChange::Object(Change::Remove(o)) => Some(o.name.clone()),
                _ => None,
            })
            .collect();
        n.sort();
        n
    };
    with_timeout(async {
        config(TableMode::Shared, true).diff(&conn).await?.apply(&conn).await?;
        ns.exec("nft", &["add chain inet s theirs"])?;
        ns.exec("nft", &["add set inet s their_set { type ipv4_addr; }"])?;
        ns.exec("nft", &["add counter inet s their_counter"])?;

        let chains = conn.list_chains_in("s", Family::Inet).await?;
        let managed = |name: &str| chains.iter().find(|c| c.name == name).map(|c| c.managed);
        assert_eq!((managed("ours"), managed("theirs")), (Some(true), Some(false)));
        let listed = ns.exec("nft", &["list", "table", "inet", "s"])?;
        assert!(!listed.contains("nlink"), "{listed}");

        let shared = config(TableMode::Shared, false).diff(&conn).await?;
        assert_eq!(names(&shared), ["our_counter", "our_set", "ours"], "{shared}");
        shared.apply(&conn).await?;
        let again = config(TableMode::Shared, false).diff(&conn).await?;
        assert!(again.is_empty(), "{again}");

        let owned = config(TableMode::Owned, false).diff(&conn).await?;
        assert_eq!(names(&owned), ["their_counter", "their_set", "theirs"], "{owned}");
        Ok(())
    })
    .await
}

/// #721: a declared value whose bytes start like an empty attribute
/// (`04 00 05 00`, `ip daddr 4.0.5.0`) still changes. The normalizer used to
/// read such a value as a nest and drop it, so `4.0.5.0` and `4.0.6.0`
/// compared equal, and the change diffed empty and was never applied.
#[tokio::test]
async fn a_value_that_looks_like_an_attribute_still_changes() -> nlink::Result<()> {
    use std::net::Ipv4Addr;
    require_root!();
    nlink::require_modules!("nf_tables");

    let cfg = |addr: Ipv4Addr| {
        NftablesConfig::new().table("t", Family::Inet, |t| {
            t.chain("c", |c| c)
                .rule_keyed("c", "dst", move |r| r.match_daddr_v4(addr, 32).accept())
        })
    };
    let steps = [cfg(Ipv4Addr::new(4, 0, 5, 0)), cfg(Ipv4Addr::new(4, 0, 6, 0))];
    let want = ["4.0.5.0", "4.0.6.0"];
    let ns = TestNamespace::new("nft-721")?;
    assert_transition(&ns, &steps, false, async |i, _| {
        let shown = ns
            .exec("nft", &["list", "chain", "inet", "t", "c"])
            .map_err(|e| e.to_string())?;
        if !shown.contains(&format!("ip daddr {} accept", want[i])) {
            return Err(format!("want ip daddr {}:\n{shown}", want[i]));
        }
        Ok(())
    })
    .await
}

// ============================================================================
// #703 — netdev chains on several devices
// ============================================================================

/// #703: a netdev chain bound to two devices, as nft writes it (`devices =
/// { d0, d1 }`, NFTA_HOOK_DEVS), and nlink's: `nft` lists the two tables
/// alike, and both read back both devices.
#[tokio::test]
async fn a_netdev_chain_on_two_devices_reads_and_writes_as_nft_does() -> nlink::Result<()> {
    use nlink::netlink::link::DummyLink;
    use nlink::netlink::nftables::Chain;
    use nlink::netlink::Route;
    require_root!();
    nlink::require_modules!("nf_tables", "dummy");

    let ns = TestNamespace::new("nft-devs")?;
    let route: nlink::Connection<Route> = ns.connection()?;
    for dev in ["d0", "d1"] {
        route.add_link(DummyLink::new(dev)).await?;
        route.set_link_up(dev).await?;
    }
    let script = "table netdev a {
 chain c {
  type filter hook ingress devices = { d0, d1 } priority 0;
 }
}
";
    let file = std::env::temp_dir().join(format!("nlink-devs-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;
    let nft = ns.connection_for::<Nftables>()?;
    nft.add_table("b", Family::Netdev).await?;
    nft.add_chain(
        Chain::new("b", "c")?
            .family(Family::Netdev)
            .base(BaseChain::filter(
                FilterHook::ingress(["d0", "d1"]),
                Priority::Filter,
            )),
    )
    .await?;
    let listed = |table: &str| -> nlink::Result<String> {
        let out = ns.exec("nft", &["list", "table", "netdev", table])?;
        Ok(out.replacen(&format!("table netdev {table}"), "table netdev T", 1))
    };
    assert_eq!(listed("b")?, listed("a")?, "nlink's table b, nft's table a");
    for table in ["a", "b"] {
        let chains = nft.list_chains_in(table, Family::Netdev).await?;
        let mut devices = chains[0].devices.clone();
        devices.sort();
        assert_eq!(devices, ["d0", "d1"], "{table}");
    }
    Ok(())
}

/// `netdev t`: an ingress chain on `devices`, counting UDP from each of the
/// pair's veth and `lo`.
fn ingress_on(devices: &[&'static str], veth: &'static str) -> NftablesConfig {
    let devices = devices.to_vec();
    NftablesConfig::new().table("t", Family::Netdev, move |t| {
        t.chain("in", move |c| {
            let devices =
                Devices::try_from(devices.iter().map(|d| d.to_string()).collect::<Vec<_>>())
                    .expect("at least one device");
            c.base(BaseChain::filter(
                FilterHook::ingress(devices),
                Priority::Filter,
            ))
        })
        .rule_keyed("in", "veth", move |r| r.match_iif(veth).match_l4proto(17).counter())
        .rule_keyed("in", "lo", |r| r.match_iif("lo").match_l4proto(17).counter())
    })
}

/// #703: a declared netdev chain converges on one device, then on two —
/// a changed set of devices recreates it — and counts what comes in on
/// each: from the peer on the veth always, from itself on `lo` once `lo`
/// is one of its devices.
#[tokio::test]
async fn a_declared_netdev_chain_takes_a_second_device() -> nlink::Result<()> {
    use crate::common::counters::rule_packets;
    use crate::common::traffic::{lo_up, send_udp};
    require_root!();
    nlink::require_modules!("nf_tables", "veth");

    let pair = crate::common::topo::NsPair::new("nftdevs", 96).await?;
    lo_up(&pair.b).await?;
    let steps = [ingress_on(&[pair.b_if], pair.b_if), ingress_on(&[pair.b_if, "lo"], pair.b_if)];
    let b_addr = pair.b_addr;
    assert_transition(&pair.b, &steps, false, async |i, conn| {
        let count = async |nth| {
            rule_packets(conn, "t", Family::Netdev, "in", nth)
                .await
                .map_err(|e| e.to_string())
        };
        let (veth, lo) = (count(0).await?, count(1).await?);
        send_udp(&pair.a, &[format!("{b_addr}:9")], 3);
        send_udp(&pair.b, &["127.0.0.1:9"], 3);
        let got = (count(0).await? - veth, count(1).await? - lo);
        let want = (3, if i == 0 { 0 } else { 3 });
        if got == want {
            Ok(())
        } else {
            Err(format!("step {}: counted {got:?} (veth, lo), want {want:?}", i + 1))
        }
    })
    .await
}
