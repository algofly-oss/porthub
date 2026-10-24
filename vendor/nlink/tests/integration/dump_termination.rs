//! `NLMSG_DONE` carries the dump's result code — #267.
//!
//! Nothing read it, so a dump that failed partway reported success with
//! a truncated or empty result set. `sockdiag.rs` was the sharpest
//! case: `NLMSG_DONE => return Ok(sockets)` turned a query the kernel
//! refused into "no sockets found".
//!
//! Unprivileged by design — `sock_diag` dumps your own sockets with no
//! capability, and it is the kernel's answer, not the privilege, that
//! these check.

use nlink::{Connection, Result, netlink::SockDiag, sockdiag::SocketFilter};

/// A protocol with no diag handler compiled in answers with
/// **`NLMSG_DONE`**, not `NLMSG_ERROR`, and reports the failure only in
/// the DONE payload. Measured on this kernel:
///
/// ```text
/// sdiag_protocol=6   (TCP)   -> SOCK_DIAG_BY_FAMILY reply, nlmsg_len=116
/// sdiag_protocol=33  (DCCP)  -> NLMSG_DONE nlmsg_len=20 payload i32 = -2
/// sdiag_protocol=132 (SCTP)  -> NLMSG_DONE nlmsg_len=20 payload i32 = -2
/// ```
///
/// That `-2` used to become `Ok(vec![])`.
#[tokio::test]
async fn a_dump_the_kernel_refuses_is_an_error_not_an_empty_list() -> Result<()> {
    let conn = Connection::<SockDiag>::new()?;

    // DCCP and SCTP diag are both rarely built in. At least one of
    // them must be refused, and the refusal must arrive as an `Err`.
    //
    // The obvious way to write this — "skip if nothing was refused" —
    // is exactly wrong, and mutation testing said so: with the fix
    // reverted, both queries return `Ok(0 sockets)`, the test decides
    // there is nothing to assert, and passes. A silent skip is
    // indistinguishable from a pass, and here it is indistinguishable
    // from the bug. So an unrefused query fails instead.
    let mut refused = 0;
    for (name, filter) in [
        ("dccp", SocketFilter::dccp().build()),
        ("sctp", SocketFilter::sctp().build()),
    ] {
        match conn.query(&filter).await {
            Ok(sockets) => {
                eprintln!("{name}: query succeeded with {} sockets", sockets.len());
            }
            Err(e) => {
                refused += 1;
                assert!(
                    e.is_not_found(),
                    "{name}: expected the kernel's ENOENT out of the DONE payload, got {e:?}"
                );
            }
        }
    }

    assert!(
        refused > 0,
        "neither DCCP nor SCTP was refused. Either this kernel has both diag \
         handlers built in — in which case pick a protocol it lacks — or the \
         NLMSG_DONE result code is being discarded again and a refused dump is \
         reading back as an empty list (#267)."
    );

    Ok(())
}

/// The ordinary path must be unaffected: a dump that succeeds still
/// terminates cleanly, with `DONE`'s payload being zero.
#[tokio::test]
async fn a_dump_that_succeeds_still_succeeds() -> Result<()> {
    let conn = Connection::<SockDiag>::new()?;
    // TCP diag is always there; this is the "payload i32 = 0" case,
    // and it must not be mistaken for a failure.
    conn.query_tcp().await?;
    Ok(())
}

/// And on the rtnetlink side, where a normal `RTM_GETLINK` dump ends
/// with `nlmsg_len = 20` and a zero payload.
#[tokio::test]
async fn a_link_dump_reads_its_zero_result_code_as_success() -> Result<()> {
    let conn = Connection::<nlink::Route>::new()?;
    let links = conn.get_links().await?;
    assert!(
        !links.is_empty(),
        "a link dump must return at least `lo`; an empty Ok here is the \
         shape #267 was about"
    );
    Ok(())
}
