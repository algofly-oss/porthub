//! Live-kernel verification of the nftables safety fixes (#190, #195, #199).
//!
//! These three are the ones that hurt on a real host:
//!
//! - **#190** — `apply()` deleted every kernel table it did not declare.
//! - **#195** — rules installed in *reverse* declaration order.
//! - **#199** — a mid-batch kernel rejection was discarded, so the caller got
//!   an opaque 30-second timeout instead of the error.
//!
//! Each one is a claim about what the kernel ends up holding, so each is
//! checked by asking the kernel.

use std::time::Duration;

use nlink::netlink::nftables::config::{Change, NftDiffOptions, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, Chain, Family, FilterHook, Policy, Priority, Rule,
};
use nlink::netlink::Nftables;

use crate::common::{TestNamespace, with_timeout};

/// A config declaring exactly one table, and nothing else.
fn only_my_table() -> NftablesConfig {
    NftablesConfig::new().table("myapp", Family::Inet, |t| {
        t.chain("input", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Accept))
        })
    })
}

/// **The one that mattered (#190).** A table nlink did not declare must
/// survive an apply.
///
/// Before the fix, `diff()` scheduled *every* undeclared table for deletion
/// and `apply()` committed it in the atomic batch — and `NFT_MSG_DELTABLE`
/// cascades to all chains, rules and sets inside. On any host also running
/// Docker, firewalld, libvirt or kube-proxy, applying a config that declared
/// one table destroyed `ip nat`, `inet firewalld`, `ip6 filter` and everything
/// else, in a single commit, with no warning.
///
/// The lab namespace stands in for the host here: `foreign` is a table nlink
/// did not create and must not touch.
#[tokio::test]
async fn apply_does_not_delete_an_undeclared_table() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-noPurge")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        // A table created out-of-band — as Docker or firewalld would.
        conn.add_table("foreign", Family::Ip).await?;

        // Apply a config that says nothing about it.
        let diff = only_my_table().diff(&conn).await?;
        assert!(
            !diff.tables().any(|c| matches!(c, Change::Remove(_))),
            "diff() must never schedule a table deletion; it scheduled {diff}",
        );
        diff.apply(&conn).await?;

        let tables = conn.list_tables().await?;
        assert!(
            tables.iter().any(|t| t.name == "foreign"),
            "the foreign table was destroyed by an apply that never mentioned it",
        );
        assert!(
            tables.iter().any(|t| t.name == "myapp"),
            "the declared table was not created",
        );

        Ok(())
    })
    .await
}

/// Purge is still reachable — but only when asked for explicitly.
#[tokio::test]
async fn purge_is_opt_in_and_still_works() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-purge")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        conn.add_table("foreign", Family::Ip).await?;

        let diff = only_my_table()
            .diff_with_options(&conn, &NftDiffOptions::default().purge_tables(true))
            .await?;
        assert!(
            diff.tables()
                .any(|c| matches!(c, Change::Remove(t) if t.name == "foreign")),
            "purge_tables(true) must schedule the undeclared table for deletion",
        );
        diff.apply(&conn).await?;

        let tables = conn.list_tables().await?;
        assert!(
            !tables.iter().any(|t| t.name == "foreign"),
            "purge was requested but the foreign table survived",
        );

        Ok(())
    })
    .await
}

/// **Rule order (#195).** The kernel must hold rules in the order they were
/// declared.
///
/// `nf_tables_newrule()` appends to the chain tail only when `NLM_F_APPEND` is
/// set; without it, it *prepends*. nlink never set the flag (it was defined
/// and used nowhere), so rules landed in reverse. nftables is first-match-wins,
/// which inverts the policy exactly: a declared `[accept ssh, drop]` installed
/// as `[drop, accept]`, and **SSH was blocked**.
///
/// No test pinned rule order before now, which is why this survived.
#[tokio::test]
async fn rules_install_in_declaration_order() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-order")?;
    let conn = ns.connection_for::<Nftables>()?;

    with_timeout(async {
        conn.add_table("ordering", Family::Inet).await?;
        conn.add_chain(
            Chain::new("ordering", "input")?
                .family(Family::Inet)
                .base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop)),
        )
        .await?;

        // The exact shape from the issue: accept SSH, then drop everything.
        // Comments give each rule an identity we can assert the order of.
        conn.add_rule(
            Rule::new("ordering", "input")
                .family(Family::Inet)
                .comment("1-accept-ssh")
                .match_tcp_dport(22)
                .accept(),
        )
        .await?;
        conn.add_rule(
            Rule::new("ordering", "input")
                .family(Family::Inet)
                .comment("2-drop-all")
                .drop(),
        )
        .await?;

        let rules = conn.list_rules("ordering", Family::Inet).await?;
        assert_eq!(rules.len(), 2, "expected exactly the two rules we added");

        let order: Vec<_> = rules.iter().map(|r| r.comment_text.as_deref()).collect();
        assert_eq!(
            order,
            vec![Some("1-accept-ssh"), Some("2-drop-all")],
            "the kernel is holding the rules in REVERSE declaration order, so \
             the bare drop matches first and SSH is blocked (#195)",
        );

        Ok(())
    })
    .await
}

/// **Batch errors (#199).** A kernel rejection mid-batch must surface as that
/// error, promptly — not as a 30-second timeout.
///
/// `Transaction` numbered its inner messages from its own counter starting at
/// 1, unrelated to the socket's. `send_batch`'s `seq > end_seq { continue }`
/// filter therefore discarded the NLMSGERR for a rejected op. The kernel
/// aborted the batch, so the BATCH_END ACK never arrived, and the loop spun to
/// the 30s operation timeout with no indication of what failed.
///
/// Here the batch references a chain that does not exist, which the kernel
/// rejects. We assert we get *an error other than Timeout*, and that it
/// arrives fast.
#[tokio::test]
async fn a_rejected_batch_reports_the_kernel_error_not_a_timeout() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-batchErr")?;
    let conn = ns.connection_for::<Nftables>()?;

    conn.add_table("batch", Family::Inet).await?;

    // A rule in a chain that was never created — the kernel rejects this op.
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        conn.transaction()
            .add_rule(
                Rule::new("batch", "nonexistent")
                    .family(Family::Inet)
                    .accept(),
            )
            .commit(&conn),
    )
    .await;

    let inner = result.expect(
        "the batch hung: a mid-batch kernel error was discarded and the \
         BATCH_END ACK never came (#199)",
    );

    let err = inner.expect_err("the kernel should have rejected a rule in a missing chain");
    assert!(
        !matches!(err.detail(), nlink::ErrorDetail::Timeout),
        "expected the kernel's error, got a timeout — the error was discarded: {err}",
    );

    Ok(())
}

/// #703: each `destroy_*` delete removes what is there, and takes what is
/// already gone as deleted, where the `del_*` of it fails the batch with
/// ENOENT: a table with a chain, a rule, a set, a counter and a flowtable,
/// destroyed one by one, then destroyed again.
#[tokio::test]
async fn destroy_deletes_what_is_there_and_takes_the_gone_as_deleted() -> nlink::Result<()> {
    use nlink::netlink::nftables::connection::kernel_has_destroy;
    use nlink::netlink::nftables::types::Set;
    use nlink::netlink::nftables::{Flowtable, Object, ObjectType};
    require_root!();
    nlink::require_modules!("nf_tables", "nf_flow_table");
    assert!(kernel_has_destroy(), "NFT_MSG_DESTROY* needs kernel 6.3+");

    let ns = TestNamespace::new("nft-destroy")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        conn.add_table("t", Family::Inet).await?;
        conn.add_chain(
            Chain::new("t", "in")?
                .family(Family::Inet)
                .base(BaseChain::filter(FilterHook::Input, Priority::Filter)),
        )
        .await?;
        conn.add_rule(Rule::new("t", "in").family(Family::Inet).accept()).await?;
        conn.add_set(Set::new("t", "s").family(Family::Inet)).await?;
        conn.add_object(&Object::counter("t", "c").family(Family::Inet)).await?;
        conn.add_flowtable(&Flowtable::new(Family::Inet, "t", "ft")).await?;
        let handle = conn.list_rules("t", Family::Inet).await?[0].handle;

        let destroy = || {
            conn.transaction()
                .destroy_rule("t", "in", Family::Inet, handle)
                .destroy_chain("t", "in", Family::Inet)
                .destroy_set("t", "s", Family::Inet)
                .destroy_object("t", "c", ObjectType::Counter, Family::Inet)
                .destroy_flowtable(Family::Inet, "t", "ft")
        };
        destroy().commit(&conn).await?;
        assert!(conn.list_rules("t", Family::Inet).await?.is_empty());
        assert!(conn.list_chains_in("t", Family::Inet).await?.is_empty());
        assert!(conn.list_sets_in("t", Family::Inet).await?.is_empty());
        assert!(conn.list_objects_in("t", Family::Inet).await?.is_empty());
        assert!(conn.list_flowtables_in("t", Family::Inet).await?.is_empty());

        // All gone: destroying them again commits, deleting them does not.
        destroy().commit(&conn).await?;
        let deleted = conn
            .transaction()
            .del_set("t", "s", Family::Inet)
            .commit(&conn)
            .await;
        assert!(deleted.is_err_and(|e| e.is_not_found()), "a DELSET of a gone set is ENOENT");

        conn.transaction().destroy_table("t", Family::Inet).commit(&conn).await?;
        assert!(conn.list_tables_in(Family::Inet).await?.iter().all(|t| t.name != "t"));
        conn.transaction().destroy_table("t", Family::Inet).commit(&conn).await?;
        Ok(())
    })
    .await
}

/// The rules in chain `chain` of `inet t`, and how many of them count.
async fn rules_in(
    conn: &nlink::Connection<Nftables>,
    chain: &str,
) -> nlink::Result<(usize, usize)> {
    let rules: Vec<_> = conn
        .list_rules("t", Family::Inet)
        .await?
        .into_iter()
        .filter(|r| r.chain == chain)
        .collect();
    let counting = rules.iter().filter(|r| r.counter().is_some()).count();
    Ok((rules.len(), counting))
}

/// #886: `flush_chain` deletes every rule in one chain and leaves the other
/// chain's alone, on the connection and in a transaction. In a transaction
/// with the replacement rules after it, the chain ends with exactly those:
/// a chain's rules swapped in one batch, without listing their handles.
#[tokio::test]
async fn flush_chain_empties_one_chain_and_keeps_the_others() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    let ns = TestNamespace::new("nft-flush-chain")?;
    let conn = ns.connection_for::<Nftables>()?;
    with_timeout(async {
        conn.add_table("t", Family::Inet).await?;
        for chain in ["a", "b"] {
            conn.add_chain(Chain::new("t", chain)?.family(Family::Inet))
                .await?;
            for _ in 0..3 {
                conn.add_rule(
                    Rule::new("t", chain)
                        .family(Family::Inet)
                        .counter()
                        .accept(),
                )
                .await?;
            }
        }
        assert_eq!(rules_in(&conn, "a").await?, (3, 3));
        assert_eq!(rules_in(&conn, "b").await?, (3, 3));

        conn.flush_chain("t", "a", Family::Inet).await?;
        assert_eq!(rules_in(&conn, "a").await?, (0, 0), "a is flushed");
        assert_eq!(rules_in(&conn, "b").await?, (3, 3), "b is not a");

        conn.transaction()
            .flush_chain("t", "b", Family::Inet)
            .add_rule(Rule::new("t", "b").family(Family::Inet).accept())
            .add_rule(Rule::new("t", "b").family(Family::Inet).drop())
            .commit(&conn)
            .await?;
        assert_eq!(
            rules_in(&conn, "b").await?,
            (2, 0),
            "b holds the two new rules, no counters"
        );
        assert_eq!(rules_in(&conn, "a").await?, (0, 0));

        let err = conn
            .flush_chain("t", "missing", Family::Inet)
            .await
            .unwrap_err();
        assert!(err.is_not_found(), "a chain that is not there: {err}");

        conn.add_rule(Rule::new("t", "a").family(Family::Inet).accept())
            .await?;
        conn.transaction()
            .flush_table("t", Family::Inet)
            .commit(&conn)
            .await?;
        assert!(
            conn.list_rules("t", Family::Inet).await?.is_empty(),
            "flush_table empties both"
        );
        assert_eq!(
            conn.list_chains_in("t", Family::Inet).await?.len(),
            2,
            "and keeps the chains"
        );
        Ok(())
    })
    .await
}
