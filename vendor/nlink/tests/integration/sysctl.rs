//! Sysctl integration tests.
//!
//! Tests for sysctl read/write operations inside network namespaces.

use nlink::{
    Result,
    netlink::{namespace, sysctl},
};

use crate::common::TestNamespace;

#[tokio::test]
async fn test_sysctl_get_in_namespace() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("sysctl-get")?;

    // The intent of this test is to verify GET works in a netns,
    // not to assert a specific kernel default. `ip_forward`'s
    // "default" depends on what the host wrote to the all-namespace
    // template before our netns was created — vanilla kernels give
    // "0", but some distros/containers preset to "1". Accept either.
    let val = namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?;
    assert!(
        val == "0" || val == "1",
        "ip_forward should be 0 or 1, got {val:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_sysctl_set_roundtrip() -> Result<()> {
    require_root!();
    nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");

    let ns = TestNamespace::new("sysctl-set")?;

    // Set ip_forward to 1
    namespace::set_sysctl(ns.name(), "net.ipv4.ip_forward", "1")?;

    // Read it back
    let val = namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?;
    assert_eq!(val, "1");

    // Set it back to 0
    namespace::set_sysctl(ns.name(), "net.ipv4.ip_forward", "0")?;
    let val = namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?;
    assert_eq!(val, "0");

    Ok(())
}

#[tokio::test]
async fn test_sysctl_set_many() -> Result<()> {
    require_root!();
    nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");

    let ns = TestNamespace::new("sysctl-many")?;

    namespace::set_sysctls(
        ns.name(),
        &[
            ("net.ipv4.ip_forward", "1"),
            ("net.ipv6.conf.all.forwarding", "1"),
        ],
    )?;

    assert_eq!(
        namespace::get_sysctl(ns.name(), "net.ipv4.ip_forward")?,
        "1"
    );
    assert_eq!(
        namespace::get_sysctl(ns.name(), "net.ipv6.conf.all.forwarding")?,
        "1"
    );

    Ok(())
}

#[tokio::test]
async fn test_sysctl_invalid_key() -> Result<()> {
    require_root!();

    let ns = TestNamespace::new("sysctl-inv")?;

    // Non-existent key should error
    let result = namespace::get_sysctl(ns.name(), "net.ipv4.nonexistent_key_12345");
    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_sysctl_validate_key_rejects_traversal() {
    assert!(sysctl::get("net..ipv4").is_err());
    assert!(sysctl::get("/etc/passwd").is_err());
    assert!(sysctl::get("").is_err());
}

/// A device whose name has a dot in it is addressed with the slashed key:
/// the dotted form turned every `.` into a path separator (#477). And a
/// missing key is not-found, naming the key, rather than `InvalidMessage`.
#[tokio::test]
async fn a_dotted_device_name_is_addressable() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");
    nlink::require_writable_sysctl!("/proc/sys/net/ipv4/ip_forward");

    let ns = TestNamespace::new("sysctl-dots")?;
    ns.connection()?
        .add_link(nlink::netlink::link::DummyLink::new("d0.100"))
        .await?;
    let key = "net/ipv4/conf/d0.100/rp_filter";
    namespace::set_sysctl(ns.name(), key, "2")?;
    assert_eq!(namespace::get_sysctl(ns.name(), key)?, "2");

    let err = namespace::get_sysctl(ns.name(), "net.ipv4.conf.nosuchdev.rp_filter").unwrap_err();
    assert!(err.is_not_found(), "{err:?}");
    assert!(err.to_string().contains("nosuchdev"), "{err}");
    Ok(())
}
