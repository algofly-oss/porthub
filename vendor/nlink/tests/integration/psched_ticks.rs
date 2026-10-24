//! Live-kernel verification of the psched tick conversion (#191-#194, #218).
//!
//! The unit tests in `netlink::psched` and the `psched_wire_tests` modules pin
//! the *bytes nlink emits*, computed by hand from iproute2's algorithm. These
//! tests answer the other half of the question: **does the kernel accept
//! them, and does it read back what we wrote?**
//!
//! That distinction matters here more than usual. The tick bugs survived for
//! so long precisely because nlink's writer and reader were wrong in the same
//! direction and agreed with each other. A round-trip through the *kernel* is
//! the only oracle that cannot be fooled that way.

use nlink::{
    Bytes, Connection, Rate, Result, Route, TcHandle,
    netlink::{
        action::PoliceAction,
        link::DummyLink,
        tc::{HtbClassConfig, HtbQdiscConfig, TbfConfig},
        tc_options::{QdiscOptions, parse_htb_class_options, parse_qdisc_options},
    },
};

use crate::common::TestNamespace;

async fn setup(name: &str) -> Result<(TestNamespace, Connection<Route>)> {
    let ns = TestNamespace::new(name)?;
    let conn = ns.connection()?;
    conn.add_link(DummyLink::new("dummy0")).await?;
    conn.set_link_up("dummy0").await?;
    Ok((ns, conn))
}

/// TBF with a 32 KiB burst at 1 mbit must install and read back as 32 KiB.
///
/// Before the fix nlink wrote the raw byte count into `tc_tbf_qopt.buffer`,
/// which the kernel reads as psched ticks. At these settings that made the
/// bucket ~125x too small, so `tbf_enqueue()` dropped every packet over ~262
/// bytes — a total blackhole for normal traffic — and dmesg carried
/// `sch_tbf: burst 32768 is lower than device mtu`.
#[tokio::test]
async fn tbf_burst_survives_a_kernel_round_trip() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_tbf");

    let (_ns, conn) = setup("tbf-tick").await?;

    let tbf = TbfConfig::new()
        .rate(Rate::mbit(1))
        .burst(Bytes::kib(32))
        .limit(Bytes::kib(64))
        .build();
    conn.add_qdisc("dummy0", tbf).await?;

    let qdiscs = conn.get_qdiscs().await?;
    let opts = qdiscs
        .iter()
        .filter(|q| q.kind() == Some("tbf"))
        .find_map(|q| match parse_qdisc_options(q) {
            Some(QdiscOptions::Tbf(o)) => Some(o),
            _ => None,
        })
        .expect("tbf qdisc not installed");

    assert_eq!(opts.rate, 125_000, "rate reads back as bytes/sec");

    // The kernel does not echo TCA_TBF_BURST: this is the tick value
    // converted back, which at 1 mbit happens to be exact. At most rates it
    // is not (see psched::tbf_bucket_round_trip).
    assert_eq!(
        opts.burst, 32_768,
        "burst must round-trip as bytes, not as the tick value 4_096_000",
    );

    Ok(())
}

/// An HTB class must read back the burst it was given.
///
/// Before the fix the encoder wrote microseconds where the kernel wanted
/// ticks (a factor of 15.625 low), so a 100 mbit class ended up with a token
/// bucket below one MTU and could never burst a full-size packet. Every
/// `RateLimiter` / `PerHostLimiter` / `PerPeerImpairer` shape goes through
/// this path.
///
/// HTB has no byte-valued escape hatch — the kernel only reports the tick
/// value — so the read-back goes through `tc_calc_xmitsize()` and is subject
/// to one tick of quantization. Allow a small tolerance rather than pinning
/// an exact byte count.
#[tokio::test]
async fn htb_class_burst_survives_a_kernel_round_trip() -> Result<()> {
    require_root!();
    nlink::require_modules!("sch_htb");

    let (_ns, conn) = setup("htb-tick").await?;

    let htb = HtbQdiscConfig::new().default_class(0x10).build();
    conn.add_qdisc_full("dummy0", TcHandle::ROOT, Some(TcHandle::major_only(1)), htb)
        .await?;

    let burst = Bytes::kib(15);
    let cls = HtbClassConfig::new(Rate::mbit(100)).burst(burst).build();
    conn.add_class(
        "dummy0",
        TcHandle::major_only(1),
        TcHandle::new(1, 0x10),
        cls,
    )
    .await?;

    let classes = conn.get_classes().await?;
    let opts = classes
        .iter()
        .filter(|c| c.kind() == Some("htb"))
        .find_map(|c| parse_htb_class_options(c.raw_options()?))
        .expect("no htb class options in the dump");

    assert_eq!(opts.rate, 12_500_000, "rate reads back as bytes/sec");

    // One psched tick at 12.5 MB/s is 12_500_000 / 15.625 / 1e6 = 0.8 bytes,
    // so the quantization error is under a byte. Give it 64 for headroom.
    let want = burst.as_u32_saturating();
    assert!(
        opts.burst.abs_diff(want) <= 64,
        "burst read back as {} bytes, want ~{want} (the pre-fix value was ~980)",
        opts.burst,
    );

    Ok(())
}

/// A police action with a rate must install at all.
///
/// This is the question #194 could not answer without a root kernel.
/// `tcf_police_init()` calls `qdisc_get_rtab()` for any non-zero rate and
/// fails the action when it returns NULL — which it does both when
/// `TCA_POLICE_RATE` is absent *and* when the ratespec's `cell_log` is 0.
/// nlink emitted neither, so on a pre-fix tree this should fail outright with
/// EINVAL/ENOMEM rather than merely mis-shaping. That is what this pins.
#[tokio::test]
async fn police_with_a_rate_installs() -> Result<()> {
    require_root!();
    // The police rate table is CAP_NET_ADMIN in init_user_ns (#357).
    nlink::require_host_root!();
    nlink::require_modules!("act_police");

    let (_ns, conn) = setup("police-tick").await?;

    // rate 10mbit burst 100k — the exact shape from the issue.
    let police = PoliceAction::new()
        .rate(nlink::Rate::mbit(10))
        .burst(nlink::Bytes::kib(100))
        .build();

    conn.add_action(police)
        .await
        .expect("police with a rate must install — qdisc_get_rtab() needs TCA_POLICE_RATE");

    Ok(())
}
