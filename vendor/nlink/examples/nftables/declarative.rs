//! Declarative `NftablesConfig` end-to-end (Plan 157 + 157b v2).
//!
//! Run as root (needs `CAP_NET_ADMIN`):
//!   `sudo -E cargo run --example nftables_declarative`
//!
//! Build only:
//!   `cargo build --example nftables_declarative`
//!
//! Demonstrates:
//!   1. Build an `NftablesConfig` with two `rule_keyed` rules and a
//!      declared `allowed_v4` set with two IPv4 elements.
//!   2. Compute the diff against the kernel (empty starting state
//!      → all-adds).
//!   3. Apply atomically (single NFNL_MSG_BATCH_BEGIN…END commit).
//!   4. Re-compute the diff (now empty — idempotent reapply).
//!   5. Mutate one rule's body (keep its handle_key) AND add a third
//!      IP to the set; the diff is one rule update in place plus one
//!      element add (element-level diff — only the new key is added,
//!      not the whole set).
//!   6. Tear down with `del_table`.
//!
//! Each keyed rule round-trips its key through `NFTA_RULE_USERDATA`
//! as `"nlink:<key>"` so `nft list ruleset` shows
//! `comment "nlink:ssh-allow"`.

use std::net::Ipv4Addr;

use nlink::netlink::nftables::config::{Change, NftablesConfig};
use nlink::netlink::nftables::types::{
    BaseChain, Family, FilterHook, Policy, Priority, SetKeyType,
};
use nlink::netlink::{Connection, Nftables};

#[tokio::main]
async fn main() -> nlink::Result<()> {
    let conn = Connection::<Nftables>::new()?;

    // -- Step 1: declare the desired state ----------------------
    let cfg = NftablesConfig::new().table("filter_demo", Family::Inet, |t| {
        t.chain("input", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop))
        })
        .rule_keyed("input", "ssh-allow", |r| r.match_tcp_dport(22).accept())
        .rule_keyed("input", "icmp-allow", |r| {
            r.match_l4proto(1 /* IPPROTO_ICMP */).accept()
        })
        .set("allowed_v4", |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .ipv4(Ipv4Addr::new(10, 0, 0, 1))
                .ipv4(Ipv4Addr::new(10, 0, 0, 2))
        })
    });

    // -- Step 2: diff against current kernel state --------------
    let diff = match cfg.diff(&conn).await {
        Ok(d) => d,
        Err(e) if e.is_permission_denied() => {
            eprintln!(
                "EPERM: nftables config diff requires CAP_NET_ADMIN; \
                 re-run with sudo (rule integrity end-to-end demo)",
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    println!("initial diff:\n{}", diff);

    // -- Step 3: apply atomically -------------------------------
    let applied = diff.apply(&conn).await?;
    println!("\napplied {applied} ops\n");

    // -- Step 4: re-diff — should be empty (idempotent) ---------
    let reapply_diff = cfg.diff(&conn).await?;
    assert!(
        reapply_diff.is_empty(),
        "idempotent re-apply should produce empty diff; got: {}",
        reapply_diff,
    );
    println!("reapply diff: {} (empty — idempotent ✓)\n", reapply_diff);

    // -- Step 5: mutate one rule, keep the key ------------------
    let updated = NftablesConfig::new().table("filter_demo", Family::Inet, |t| {
        t.chain("input", |c| {
            c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop))
        })
        .rule_keyed("input", "ssh-allow", |r| r.match_tcp_dport(2222).accept()) // new port
        .rule_keyed("input", "icmp-allow", |r| r.match_l4proto(1).accept())
        .set("allowed_v4", |s| {
            s.key_type(SetKeyType::Ipv4Addr)
                .ipv4(Ipv4Addr::new(10, 0, 0, 1))
                .ipv4(Ipv4Addr::new(10, 0, 0, 2))
                .ipv4(Ipv4Addr::new(10, 0, 0, 3)) // new element
        })
    });
    let mut_diff = updated.diff(&conn).await?;
    println!("after port change + new set element:\n{}", mut_diff);
    let replaced = mut_diff
        .rules()
        .filter(|c| matches!(c, Change::Update { to, .. } if to.placement.is_none()))
        .count();
    assert_eq!(
        replaced, 1,
        "expected exactly one in-place replace for the changed rule",
    );
    let added: Vec<_> = mut_diff
        .elements()
        .filter_map(|c| match c {
            Change::Add(e) => Some(e),
            _ => None,
        })
        .collect();
    assert_eq!(
        added.len(),
        1,
        "expected exactly one element add (only the new key)",
    );
    assert_eq!(
        added[0].elements.len(),
        1,
        "element diff should add just the single new key, not the whole set",
    );

    let applied = mut_diff.apply(&conn).await?;
    println!("\napplied {applied} ops (1 replace_rule via NLM_F_REPLACE + 1 set-element add)\n");

    // -- Step 6: cleanup ---------------------------------------
    let teardown = NftablesConfig::new(); // empty → delete everything we own
    let drop_diff = teardown.diff(&conn).await?;
    println!("teardown diff:\n{}", drop_diff);
    let applied = drop_diff.apply(&conn).await?;
    println!("\nteardown applied {applied} ops — demo complete");

    Ok(())
}
