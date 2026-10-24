//! Diagnostic tests narrowing where `cfg.diff()` hangs on a
//! fresh-namespace empty-dump (Plan 167 Phase 3 — step C).
//!
//! The first CI run of the Plan 166 nftables_reconcile suite
//! had all 7 tests timeout at 30s. The flowtable tests passed
//! (they add objects BEFORE dumping). The differentiating call
//! is `cfg.diff()`, which on an empty namespace runs three
//! kernel-wide dumps: `list_tables()`, `list_chains()`,
//! `list_flowtables()`. One of those hangs on this kernel for
//! an empty result set.
//!
//! This module runs each list call in isolation against a fresh
//! namespace + a 30s timeout, so the next CI run tells us
//! EXACTLY which call hangs. Module name `nftables_diag` sorts
//! alphabetically before `nftables_reconcile`, so these tests
//! run first.

use nlink::netlink::Nftables;

use crate::common::{TestNamespace, with_timeout};

#[tokio::test]
async fn diag_list_tables_on_empty_namespace() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("nft-diag-tables")?;
        let nft = ns.connection_for::<Nftables>()?;
        let tables = nft.list_tables().await?;
        assert!(
            tables.is_empty(),
            "fresh namespace must have zero tables; got {}",
            tables.len()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn diag_list_chains_on_empty_namespace() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("nft-diag-chains")?;
        let nft = ns.connection_for::<Nftables>()?;
        let chains = nft.list_chains().await?;
        assert!(
            chains.is_empty(),
            "fresh namespace must have zero chains; got {}",
            chains.len()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn diag_list_flowtables_on_empty_namespace() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    with_timeout(async {
        let ns = TestNamespace::new("nft-diag-flowtables")?;
        let nft = ns.connection_for::<Nftables>()?;
        let flowtables = nft.list_flowtables().await?;
        assert!(
            flowtables.is_empty(),
            "fresh namespace must have zero flowtables; got {}",
            flowtables.len()
        );
        Ok(())
    })
    .await
}

/// The full diff path — to confirm whether ANY single list call
/// is the issue, or the combination. If all three single-list
/// tests pass but this one times out, the bug is in `diff()`'s
/// composition (state held across the three dumps on one
/// Connection).
#[tokio::test]
async fn diag_cfg_diff_on_empty_namespace() -> nlink::Result<()> {
    require_root!();
    nlink::require_modules!("nf_tables");

    use nlink::netlink::nftables::config::NftablesConfig;

    with_timeout(async {
        let ns = TestNamespace::new("nft-diag-diff")?;
        let nft = ns.connection_for::<Nftables>()?;
        let cfg = NftablesConfig::new(); // empty config
        let diff = cfg.diff(&nft).await?;
        assert!(
            diff.is_empty(),
            "empty config against empty namespace must produce empty diff"
        );
        Ok(())
    })
    .await
}
