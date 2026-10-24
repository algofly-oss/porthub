//! `NETLINK_EXT_ACK` end-to-end — #292.
//!
//! The crate advertises extended-ack parsing as a headline feature:
//! `errno = 22 (EINVAL)` is supposed to arrive as
//! `"attribute IFLA_MTU rejected: value 0 out of range"`. It never did.
//!
//! `NlMsgError::attrs` reads the TLVs at `sizeof(errno) + sizeof(nlmsghdr)`,
//! which is where they live only when the echoed request has been *capped*.
//! `netlink_ack()` caps it only if the socket asked:
//!
//! ```c
//! if (err && !(nlk->flags & NETLINK_F_CAP_ACK))
//!         payload += nlmsg_len(nlh);   /* echo the WHOLE request */
//! else
//!         flags |= NLM_F_CAPPED;
//! ```
//!
//! nlink set `NETLINK_EXT_ACK` and never `NETLINK_CAP_ACK`, so the kernel
//! echoed the whole request and the parser read request bytes instead of
//! attributes. Every `ext_ack` came back `None`.
//!
//! The unit tests could not catch it: they synthesise the *capped* payload,
//! a shape the kernel was never sending us.
//!
//! These tests need the kernel, because the layout is the kernel's.

use nlink::{Result, TcHandle, netlink::link::DummyLink};

use crate::common::TestNamespace;

/// A filter delete at the root of an interface with no qdisc. The
/// kernel rejects it with `EINVAL` **and** an explanation.
#[tokio::test]
async fn kernel_error_messages_reach_the_caller() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("extack")?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;

    let err = conn
        .del_filter(
            "dummy0",
            TcHandle::ROOT,
            nlink::EthProto::new(0x0800),
            nlink::FilterPriority::new(100),
        )
        .await
        .expect_err("deleting a filter with no qdisc must fail");

    assert!(
        err.is_invalid_argument(),
        "expected EINVAL, got {err:?}"
    );
    let ext = err.ext_ack().unwrap_or_else(|| {
        panic!(
            "no ext_ack. The kernel sent \"Parent Qdisc doesn't exists\" — \
             this is #292: the TLVs are being read at the capped offset \
             while the socket is receiving the uncapped layout. Error: {err:?}"
        )
    });
    assert!(
        ext.to_lowercase().contains("qdisc"),
        "ext_ack should name the missing parent qdisc, got {ext:?}"
    );

    // …and it must reach `Display`, which is what a user actually sees.
    let shown = err.to_string();
    assert!(
        shown.to_lowercase().contains("qdisc"),
        "ext_ack must be stitched into Display, got {shown:?}"
    );
    Ok(())
}

/// The same, on a request long enough that the two layouts cannot be
/// confused.
///
/// The first test's request is already 36 bytes, so uncapped its TLVs
/// would sit at payload offset 40 where nlink reads 20. This one adds a
/// second, larger shape so the test is about the plumbing rather than
/// one kernel string: a VLAN on loopback, which the kernel refuses with
/// "8021q: VLANs not supported on device". (It used VLAN id 4095 until
/// nlink began refusing that before sending, #598.)
#[tokio::test]
async fn ext_ack_survives_a_request_long_enough_to_matter() -> Result<()> {
    require_root!();
    nlink::require_modules!("8021q");

    let ns = TestNamespace::new("extack2")?;
    let conn = ns.connection()?;
    conn.set_link_up("lo").await?;
    let err = conn
        .add_link(nlink::netlink::link::VlanLink::new("lo.5", "lo", 5))
        .await
        .expect_err("a VLAN on loopback must be rejected");

    let ext = err.ext_ack().unwrap_or_else(|| {
        panic!(
            "no ext_ack on a multi-attribute request — the offset is off by \
             exactly the size of the echoed request (#292). Error: {err:?}"
        )
    });
    assert!(
        !ext.is_empty(),
        "ext_ack present but empty, got {ext:?}"
    );
    Ok(())
}
