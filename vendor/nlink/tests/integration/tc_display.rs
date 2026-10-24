//! #515: qdisc options print in tc(8) syntax, and the text is an input.
//!
//! Each case installs a qdisc with `tc` on one dummy, reads it back through
//! nlink and prints it. The text then goes through the kind's
//! `parse_params` onto a second dummy and through `tc` onto a third, and
//! `tc -d qdisc show` must print the same line for all three. A netem goes
//! through `NetemConfig::from` onto a fourth as well.

use nlink::{
    Connection, Result, Route, TcHandle,
    netlink::{
        link::DummyLink,
        tc::{
            CakeConfig, FqCodelConfig, FqPieConfig, HtbQdiscConfig, NetemConfig, PrioConfig,
            SfqConfig, TbfConfig,
        },
        tc_options::QdiscOptions,
    },
};

use crate::common::TestNamespace;

const DEVS: [&str; 4] = ["dummy0", "dummy1", "dummy2", "dummy3"];

/// `tc -d qdisc show dev <dev> root` without the handle and a netem seed,
/// which is random unless set and printed only by iproute2 6.3+.
fn line(ns: &TestNamespace, dev: &str) -> Result<String> {
    let shown = ns.exec("tc", &["-d", "qdisc", "show", "dev", dev, "root"])?;
    let line = shown
        .lines()
        .find(|l| l.starts_with("qdisc "))
        .unwrap_or_else(|| panic!("no root qdisc on {dev}: {shown}"));
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        match words[i] {
            "seed" => i += 2,
            _ if i == 2 => i += 1,
            w => {
                out.push(w);
                i += 1;
            }
        }
    }
    Ok(out.join(" "))
}

async fn add_parsed(conn: &Connection<Route>, dev: &str, kind: &str, p: &[&str]) -> Result<()> {
    match kind {
        "netem" => conn.add_qdisc(dev, NetemConfig::parse_params(p)?).await,
        "fq_codel" => conn.add_qdisc(dev, FqCodelConfig::parse_params(p)?).await,
        "fq_pie" => conn.add_qdisc(dev, FqPieConfig::parse_params(p)?).await,
        "tbf" => conn.add_qdisc(dev, TbfConfig::parse_params(p)?).await,
        "htb" => conn.add_qdisc(dev, HtbQdiscConfig::parse_params(p)?).await,
        "prio" => conn.add_qdisc(dev, PrioConfig::parse_params(p)?).await,
        "sfq" => conn.add_qdisc(dev, SfqConfig::parse_params(p)?).await,
        "cake" => conn.add_qdisc(dev, CakeConfig::parse_params(p)?).await,
        other => panic!("no case for {other}"),
    }
}

/// Install `tokens` with tc on dummy0 and return what nlink reads and
/// prints.
async fn reference(
    ns: &TestNamespace,
    conn: &Connection<Route>,
    kind: &str,
    tokens: &[&str],
) -> Result<(QdiscOptions, String)> {
    for dev in DEVS {
        conn.del_qdisc(dev, TcHandle::ROOT).await.ok();
    }
    let mut args = vec!["qdisc", "add", "dev", "dummy0", "root", kind];
    args.extend(tokens);
    ns.exec("tc", &args)?;
    let root = conn
        .get_root_qdisc_by_name("dummy0")
        .await?
        .expect("a root");
    let opts = root.options().expect("options");
    let text = opts.to_string();
    Ok((opts, text))
}

/// The text through tc onto `dev`, without the seed iproute2 6.1 cannot
/// take.
fn tc_add(ns: &TestNamespace, dev: &str, kind: &str, text: &str) -> Result<()> {
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut args = vec!["qdisc", "add", "dev", dev, "root", kind];
    let mut i = 0;
    while i < words.len() {
        if words[i] == "seed" {
            i += 2;
        } else {
            args.push(words[i]);
            i += 1;
        }
    }
    ns.exec("tc", &args)?;
    Ok(())
}

async fn setup(name: &str) -> Result<(TestNamespace, Connection<Route>)> {
    let ns = TestNamespace::new(name)?;
    let conn = ns.connection()?;
    for dev in DEVS {
        conn.add_link(DummyLink::new(dev)).await?;
        conn.set_link_up(dev).await?;
    }
    Ok((ns, conn))
}

#[tokio::test]
async fn qdisc_text_reinstalls_the_same_qdisc() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!(
        "sch_netem",
        "sch_fq_codel",
        "sch_fq_pie",
        "sch_tbf",
        "sch_htb",
        "sch_prio",
        "sch_sfq",
        "sch_cake"
    );

    let (ns, conn) = setup("tc-display").await?;
    let cases: &[(&str, &[&str])] = &[
        (
            "netem",
            &[
                "delay",
                "10ms",
                "2ms",
                "25%",
                "loss",
                "1.2%",
                "10%",
                "duplicate",
                "0.3%",
                "corrupt",
                "0.1%",
                "reorder",
                "5%",
                "50%",
                "gap",
                "3",
                "rate",
                "1mbit",
                "20",
                "53",
                "5",
                "slot",
                "1ms",
                "2ms",
                "packets",
                "5",
                "bytes",
                "3000",
                "ecn",
                "limit",
                "500",
            ],
        ),
        ("netem", &["loss", "gemodel", "1%", "30%", "50%", "0.1%"]),
        ("netem", &["loss", "state", "1%", "2%", "3%", "4%", "5%"]),
        ("netem", &["delay", "1500us"]),
        ("netem", &[]),
        (
            "fq_codel",
            &[
                "limit",
                "2000",
                "flows",
                "512",
                "target",
                "20ms",
                "interval",
                "200ms",
                "quantum",
                "1000",
                "ce_threshold",
                "3ms",
                "memory_limit",
                "16Mb",
                "noecn",
            ],
        ),
        ("fq_codel", &[]),
        (
            "fq_pie",
            &[
                "limit",
                "2000",
                "flows",
                "512",
                "target",
                "20ms",
                "tupdate",
                "30ms",
                "alpha",
                "3",
                "beta",
                "25",
                "quantum",
                "1000",
                "memory_limit",
                "16Mb",
                "ecn_prob",
                "20",
                "ecn",
                "bytemode",
                "dq_rate_estimator",
            ],
        ),
        ("fq_pie", &[]),
        (
            "tbf",
            &["rate", "10mbit", "burst", "32kb", "limit", "30000"],
        ),
        (
            "tbf",
            &[
                "rate", "10gbit", "burst", "32kb", "limit", "300000", "peakrate", "20gbit", "mtu",
                "9000",
            ],
        ),
        ("htb", &["default", "10", "r2q", "5", "direct_qlen", "100"]),
        ("htb", &[]),
        (
            "prio",
            &[
                "bands", "4", "priomap", "0", "1", "2", "3", "0", "1", "2", "3", "0", "1", "2",
                "3", "0", "1", "2", "3",
            ],
        ),
        ("prio", &[]),
        ("sfq", &["limit", "100", "quantum", "1000", "perturb", "10"]),
        ("sfq", &[]),
        (
            "cake",
            &[
                "bandwidth",
                "10mbit",
                "diffserv4",
                "dual-srchost",
                "nat",
                "wash",
                "ack-filter",
                "overhead",
                "18",
                "mpu",
                "64",
                "memlimit",
                "1Mb",
                "fwmark",
                "0xff",
                "ingress",
                "no-split-gso",
                "rtt",
                "50ms",
            ],
        ),
        (
            "cake",
            &[
                "autorate-ingress",
                "besteffort",
                "flowblind",
                "atm",
                "ack-filter-aggressive",
            ],
        ),
        ("cake", &[]),
    ];

    for &(kind, tokens) in cases {
        let (opts, text) = reference(&ns, &conn, kind, tokens).await?;
        let want = line(&ns, "dummy0")?;
        let words: Vec<&str> = text.split_whitespace().collect();
        add_parsed(&conn, "dummy1", kind, &words)
            .await
            .unwrap_or_else(|e| panic!("{kind} `{text}` through parse_params: {e}"));
        assert_eq!(
            line(&ns, "dummy1")?,
            want,
            "{kind} {tokens:?} printed as `{text}`"
        );
        tc_add(&ns, "dummy2", kind, &text)?;
        assert_eq!(
            line(&ns, "dummy2")?,
            want,
            "{kind} {tokens:?}: tc took `{text}`"
        );
        if let QdiscOptions::Netem(netem) = &opts {
            conn.add_qdisc("dummy3", NetemConfig::from(netem)).await?;
            assert_eq!(line(&ns, "dummy3")?, want, "{kind} {tokens:?} through From");
        }
    }
    Ok(())
}

/// A value that is not the kernel's default prints, and the text reads
/// back as the same qdisc (#806). The typed configs could not carry these,
/// so `parse_params` refused them; they can now.
#[tokio::test]
async fn qdisc_text_with_values_off_the_default_round_trips() -> Result<()> {
    nlink::require_root!();
    nlink::require_modules!("sch_sfq", "sch_fq_codel");

    let (ns, conn) = setup("tc-display-refused").await?;
    let cases: &[(&str, &[&str], &str)] = &[
        (
            "sfq",
            &["depth", "64", "divisor", "512", "flows", "64", "headdrop"],
            "depth 64 divisor 512 flows 64 headdrop",
        ),
        ("fq_codel", &["drop_batch", "32"], "drop_batch 32"),
    ];
    for &(kind, tokens, printed) in cases {
        let (_, text) = reference(&ns, &conn, kind, tokens).await?;
        assert!(
            text.contains(printed),
            "{kind}: `{printed}` not in `{text}`"
        );
        let words: Vec<&str> = text.split_whitespace().collect();
        add_parsed(&conn, "dummy1", kind, &words).await?;
        assert_eq!(
            line(&ns, "dummy1")?,
            line(&ns, "dummy0")?,
            "{kind}: `{text}` read back as another qdisc"
        );
    }
    Ok(())
}
