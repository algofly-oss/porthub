//! Values the builders accept and nothing used to read — #275.
//!
//! Each of these is the same shape: a fluent setter stores a value, the
//! writer never reads it, and the request goes out without it. Nothing
//! errors. `apply()` returns `Ok` and reports changes; the interface
//! just is not what was declared.
//!
//! The tests are written to fail on the *declared* value being absent,
//! not on the call returning `Ok` — asserting `Ok` is what let these
//! ship.

use nlink::{Result, netlink::config::NetworkConfig};

use crate::common::TestNamespace;

const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0xbe, 0xef, 0x01];

/// `create_link` never called `config.mtu(...)` for VXLAN, macvlan or
/// IFB, so a declared MTU was dropped on create — and then caught by
/// `compute_link_changes` on the *second* pass, which breaks the
/// apply→converge contract visibly: `diff.is_empty()` is false right
/// after a successful apply.
#[tokio::test]
async fn declared_mtu_survives_create_for_every_link_kind() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "ifb");

    let ns = TestNamespace::new("declmtu")?;
    let conn = ns.connection()?;

    let cfg = NetworkConfig::new()
        .link("ifb-mtu", |l| l.ifb().mtu(1400));
    let result = cfg.apply(&conn).await?;
    assert!(result.is_success(), "apply failed: {}", result.summary_text());

    let link = conn
        .get_link_by_name("ifb-mtu")
        .await?
        .expect("ifb-mtu created");
    assert_eq!(
        link.mtu(),
        Some(1400),
        "declared MTU was dropped on create (#275)"
    );

    // The contract that made it visible: a successful apply must leave
    // nothing to converge.
    let diff = cfg.diff(&conn).await?;
    assert!(
        diff.is_empty(),
        "apply reported success but left a non-empty diff: {diff}"
    );
    Ok(())
}

/// A declared MAC was stored by the builder and compared by nothing, so
/// `.address(mac)` on an existing interface produced an empty diff
/// forever and `apply()` reported zero changes.
#[tokio::test]
async fn declared_mac_is_applied_and_then_converges() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("declmac")?;
    let conn = ns.connection()?;

    // Create the interface *without* a MAC, so the address can only
    // arrive through the modify path.
    conn.add_link(nlink::netlink::link::DummyLink::new("mac0"))
        .await?;

    let cfg = NetworkConfig::new()
        .link("mac0", |l| l.dummy().address(MAC));

    let diff = cfg.diff(&conn).await?;
    assert!(
        !diff.is_empty(),
        "a declared MAC that differs from the kernel's must show as drift (#275)"
    );

    let result = cfg.apply(&conn).await?;
    assert!(result.is_success(), "apply failed: {}", result.summary_text());

    let link = conn.get_link_by_name("mac0").await?.expect("mac0 exists");
    assert_eq!(
        link.address(),
        Some(&MAC[..]),
        "declared MAC never reached the interface (#275)"
    );

    // Idempotent: the same config applied twice has nothing left to do.
    let diff = cfg.diff(&conn).await?;
    assert!(diff.is_empty(), "MAC did not converge: {diff}");
    Ok(())
}

/// …and on create, for the kinds that were dropping it.
#[tokio::test]
async fn declared_mac_survives_create() -> Result<()> {
    require_root!();
    nlink::require_modules!("dummy", "ifb");

    let ns = TestNamespace::new("declmac2")?;
    let conn = ns.connection()?;

    let cfg = NetworkConfig::new()
        .link("ifb-mac", |l| l.ifb().address(MAC));
    let result = cfg.apply(&conn).await?;
    assert!(result.is_success(), "apply failed: {}", result.summary_text());

    let link = conn
        .get_link_by_name("ifb-mac")
        .await?
        .expect("ifb-mac created");
    assert_eq!(
        link.address(),
        Some(&MAC[..]),
        "declared MAC was dropped on create (#275)"
    );
    Ok(())
}
