//! #251 — uevent socket hardening against a real kernel.
//!
//! The unit tests in `netlink::uevent_filter` run the compiled
//! programs through an interpreter, which pins their *semantics*. What
//! only a kernel can tell us is whether the classic-BPF verifier
//! accepts them at all: a bad jump displacement, an instruction past
//! `BPF_MAXINSNS`, or an opcode the verifier dislikes all come back as
//! a flat `EINVAL` with nothing to interpret.
//!
//! Notably these do **not** need root. Reading uevents is unprivileged
//! and so is attaching a socket filter, so this file runs for the
//! non-root maintainer too — which is the point, since it is the
//! verifier and not the privilege that is under test.

use std::time::Duration;

use nlink::{
    Result,
    netlink::{
        Connection, KobjectUevent, link::DummyLink, uevent::UEVENT_GROUP,
        uevent_filter::UeventFilter,
    },
};

use crate::common::TestNamespace;

#[tokio::test]
async fn the_kernel_verifier_accepts_every_filter_shape() -> Result<()> {
    let shapes = [
        ("action only", UeventFilter::new().action("add").build()),
        (
            "several actions",
            UeventFilter::new()
                .action("add")
                .action("remove")
                .action("change")
                .action("bind")
                .action("unbind")
                .build(),
        ),
        (
            "subsystem only",
            UeventFilter::new().subsystem("net").build(),
        ),
        (
            "several subsystems of differing length",
            UeventFilter::new()
                .subsystem("net")
                .subsystem("block")
                .subsystem("power_supply")
                .build(),
        ),
        (
            "both gates",
            UeventFilter::new()
                .action("add")
                .action("remove")
                .subsystem("net")
                .build(),
        ),
        (
            "value lengths across every chunking remainder",
            UeventFilter::new()
                .subsystem("a")
                .subsystem("ab")
                .subsystem("abc")
                .subsystem("abcd")
                .build(),
        ),
    ];

    for (what, filter) in shapes {
        let conn = Connection::<KobjectUevent>::new()?;
        let compiled = conn.attach_filter(&filter).unwrap_or_else(|e| {
            panic!("kernel rejected the program for {what}: {e}");
        });
        assert!(!compiled.is_empty(), "{what} compiled to nothing");
        assert!(compiled.is_exact(), "{what} should lower entirely");
        conn.clear_filter()?;
    }

    Ok(())
}

/// A filter with nothing to lower must attach nothing rather than an
/// empty `sock_fprog`, which the kernel rejects.
#[tokio::test]
async fn a_userspace_only_filter_attaches_nothing() -> Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;
    let compiled = conn.attach_filter(&UeventFilter::new().devtype("disk").build())?;
    assert!(compiled.is_empty());
    assert!(!compiled.is_exact());
    // Detaching when nothing is attached is a documented no-op.
    conn.clear_filter()?;
    Ok(())
}

/// The receive buffer must actually grow past the system default.
/// Unprivileged callers are capped at `net.core.rmem_max`, so this
/// only asserts the floor: whatever we got is at least what the socket
/// would have had by default.
#[tokio::test]
async fn the_receive_buffer_is_sized_up_from_the_default() -> Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;
    let granted = conn.rcvbuf()?;

    let default = std::fs::read_to_string("/proc/sys/net/core/rmem_default")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok());

    if let Some(default) = default {
        assert!(
            granted >= default,
            "granted {granted} is below rmem_default {default}"
        );
    }
    assert!(granted > 0);
    Ok(())
}

/// `subscribe()` is the only public method here with no constructor
/// that needs it — everything that builds a `Connection<KobjectUevent>`
/// subscribes already. Its real use is the pause/resume pair with
/// `drop_membership`, so exercise that rather than ship an untested
/// method.
#[tokio::test]
async fn a_subscription_can_be_dropped_and_rejoined() -> Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;

    conn.socket().drop_membership(UEVENT_GROUP)?;
    conn.subscribe()?;
    // Idempotent: resuming an already-joined group must not error, or
    // a resume path would have to track its own state.
    conn.subscribe()?;

    // The socket still works after the round trip.
    assert!(conn.try_recv().is_ok());
    Ok(())
}

/// `attach_filter` takes a flat `struct sock_filter` stream, and the
/// kernel answers a malformed one with a bare `EINVAL`. Reject the
/// obvious shapes here so the caller gets a message naming the
/// problem.
#[tokio::test]
async fn attach_filter_rejects_a_malformed_program() -> Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;
    let socket = conn.socket();

    // Empty: the kernel rejects a zero-length sock_fprog.
    let err = socket.attach_filter(&[]).unwrap_err();
    assert!(format!("{err}").contains("non-empty"), "{err}");

    // Not a whole number of 8-byte instructions.
    let err = socket.attach_filter(&[0u8; 12]).unwrap_err();
    assert!(format!("{err}").contains("multiple of 8"), "{err}");

    Ok(())
}

/// Detaching when nothing is attached is `ENOENT`, which teardown
/// paths should not have to special-case.
#[tokio::test]
async fn detaching_without_a_filter_is_a_no_op() -> Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;
    conn.clear_filter()?;
    conn.clear_filter()?;
    Ok(())
}

/// A request below `net.core.rmem_max` needs no privilege and must be
/// granted in full. The kernel doubles what it is given, so the
/// readback is `2 * requested`.
#[tokio::test]
async fn an_uncapped_rcvbuf_request_is_granted_in_full() -> Result<()> {
    let Some(rmem_max) = std::fs::read_to_string("/proc/sys/net/core/rmem_max")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
    else {
        eprintln!("skipping: /proc/sys/net/core/rmem_max unreadable");
        return Ok(());
    };

    // Comfortably under the cap, so no SO_RCVBUFFORCE escalation and
    // no privilege is involved.
    let want = rmem_max / 4;
    let conn = Connection::<KobjectUevent>::with_rcvbuf(want)?;
    let granted = conn.rcvbuf()?;

    assert!(
        granted >= want,
        "asked for {want}, got {granted} (rmem_max {rmem_max})"
    );
    Ok(())
}

/// `try_recv` used to be a public method that returned
/// `not_supported` on every call. It must now answer the question it
/// documents — and on a quiet socket that answer is `None`, not an
/// error.
#[tokio::test]
async fn try_recv_reports_an_empty_socket_rather_than_failing() -> Result<()> {
    let conn = Connection::<KobjectUevent>::new()?;
    // Drop everything, so the socket is guaranteed quiet even on a
    // machine with hotplug traffic.
    conn.attach_filter(&UeventFilter::new().action("nlink-no-such-action").build())?;

    for _ in 0..3 {
        assert!(conn.try_recv()?.is_none());
    }
    Ok(())
}

/// The one test here that needs root, and the only one anywhere that
/// shows the filter *dropping*.
///
/// Everything above proves the verifier accepts the program; the
/// interpreter in the unit tests proves what it computes. Neither
/// shows that the kernel then withholds a frame — for that you need a
/// real uevent, which means creating a device, which means root.
///
/// Two sockets in one namespace: one filtered to a subsystem that
/// cannot exist, one unfiltered. Both subscribe before the device is
/// created, and `kobject_uevent` broadcasts synchronously to every
/// socket in the netns — so once the unfiltered socket has the event
/// queued, the filtered one would have it too if the program had
/// passed it.
#[tokio::test]
async fn the_kernel_withholds_a_non_matching_event() -> Result<()> {
    require_root!();
    nlink::require_module!("dummy");

    let ns = TestNamespace::new("uevfilt")?;

    let filtered = Connection::<KobjectUevent>::in_namespace(ns.name())?;
    let compiled =
        filtered.attach_filter(&UeventFilter::new().subsystem("nlink-no-such-bus").build())?;
    assert!(compiled.is_exact());

    let unfiltered = Connection::<KobjectUevent>::in_namespace(ns.name())?;

    ns.connection()?.add_link(DummyLink::new("dummy0")).await?;

    let saw_it = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event = unfiltered.recv().await?;
            if event.subsystem == "net"
                && event.env.get("INTERFACE").map(String::as_str) == Some("dummy0")
            {
                return Ok::<_, nlink::Error>(());
            }
        }
    })
    .await;
    assert!(
        matches!(saw_it, Ok(Ok(()))),
        "the unfiltered socket never saw a net uevent for dummy0, so this \
         test proves nothing about the filter"
    );

    assert!(
        filtered.try_recv()?.is_none(),
        "the filtered socket received an event the kernel should have dropped"
    );

    Ok(())
}
