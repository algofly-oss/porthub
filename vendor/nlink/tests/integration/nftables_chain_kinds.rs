//! #708 (e): a base chain is a `BaseChain`, which only the hooks its type
//! has can build, and what depends on the table's family is checked before
//! anything is sent.
//!
//! The kernel is the oracle. For every family, chain type and hook, nft
//! creates the chain or is refused, and nlink must accept and refuse the
//! same. Every chain both accept nlink creates too: nft must list it as it
//! lists its own, and `ChainInfo::kind` must read back what was sent. Every
//! disagreement is collected, so one run shows them all.

use nlink::netlink::Nftables;
use nlink::netlink::nftables::config::NftablesConfig;
use nlink::netlink::nftables::{
    BaseChain, Chain, ChainKind, ChainType, Family, FilterHook, Hook, NatHook, Policy, Priority,
};

use crate::common::TestNamespace;
use crate::common::converge::{assert_converges, assert_transition, case};

const FAMILIES: [Family; 6] = [
    Family::Ip,
    Family::Ip6,
    Family::Inet,
    Family::Bridge,
    Family::Arp,
    Family::Netdev,
];
const TYPES: [ChainType; 3] = [ChainType::Filter, ChainType::Nat, ChainType::Route];
const HOOKS: [Hook; 7] = [
    Hook::Prerouting,
    Hook::Input,
    Hook::Forward,
    Hook::Output,
    Hook::Postrouting,
    Hook::Ingress,
    Hook::Egress,
];

/// The line of `nft list chain` that says what the chain is: `type filter
/// hook input priority filter; policy accept;`.
fn header(ns: &TestNamespace, family: Family, table: &str) -> nlink::Result<String> {
    let out = ns.exec("nft", &["list", "chain", family.name(), table, "c"])?;
    Ok(out
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("type "))
        .unwrap_or_default()
        .to_string())
}

/// One chain shape, put to nft and to nlink: whether both took it, or what
/// is wrong.
async fn compare(
    ns: &TestNamespace,
    nft: &nlink::Connection<Nftables>,
    n: usize,
    (family, ty, hook): (Family, ChainType, Hook),
    priority: i32,
    devices: &[&str],
) -> nlink::Result<Result<bool, String>> {
    let what = format!(
        "{family} {} {hook} priority {priority} {devices:?}",
        ty.as_str()
    );
    let ours = BaseChain::try_new(
        ty,
        hook,
        Priority::Custom(priority),
        devices.iter().copied(),
    )
    .and_then(|base| base.check_family(family).map(|()| base));
    let device = match devices {
        [] => String::new(),
        [one] => format!(" device {one}"),
        several => format!(" devices = {{ {} }}", several.join(", ")),
    };
    let (fam, theirs) = (family.name(), format!("n{n}"));
    let script = format!(
        "add table {fam} {theirs}; add chain {fam} {theirs} c {{ type {} hook {hook}{device} \
         priority {priority}; }}",
        ty.as_str()
    );
    let refused = ns.exec("nft", &[&script]).err();
    if refused.is_some() {
        ns.exec_ignore("nft", &["delete", "table", fam, &theirs]);
    }
    let base = match (ours, refused) {
        (Err(_), Some(_)) => return Ok(Ok(false)),
        (Ok(_), Some(e)) => return Ok(Err(format!("{what}: nlink takes it, nft refuses: {e}"))),
        (Err(e), None) => return Ok(Err(format!("{what}: nft takes it, nlink refuses: {e}"))),
        (Ok(base), None) => base,
    };
    let ours = format!("l{n}");
    nft.add_table(ours.as_str(), family).await?;
    nft.add_chain(
        Chain::new(ours.as_str(), "c")?
            .family(family)
            .base(base.clone()),
    )
    .await?;
    let (mine, nfts) = (header(ns, family, &ours)?, header(ns, family, &theirs)?);
    if mine != nfts {
        return Ok(Err(format!("{what}:\n   nft: {nfts}\n  ours: {mine}")));
    }
    let read = nft
        .list_chains_in(ours.as_str(), family)
        .await?
        .into_iter()
        .find(|c| c.name == "c")
        .and_then(|c| c.kind());
    // The kernel reports the policy it uses, which is accept.
    let sent = ChainKind::Base(base.policy(Policy::Accept));
    if read.as_ref() != Some(&sent) {
        return Ok(Err(format!("{what}: sent {sent:?}, read back {read:?}")));
    }
    Ok(Ok(true))
}

#[tokio::test]
async fn nlink_takes_the_chains_the_kernel_takes() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_chain_nat", "dummy");

    let ns = TestNamespace::new("nft-kinds")?;
    ns.exec("ip", &["link", "add", "d0", "type", "dummy"])?;
    ns.exec("ip", &["link", "add", "d1", "type", "dummy"])?;
    let nft = ns.connection_for::<Nftables>()?;

    let mut shapes = Vec::new();
    for family in FAMILIES {
        for ty in TYPES {
            for hook in HOOKS {
                let devices: &[&str] = match hook {
                    Hook::Ingress | Hook::Egress => &["d0"],
                    _ => &[],
                };
                // Above conntrack's, so it is never why a nat chain is refused.
                shapes.push(((family, ty, hook), 100, devices));
            }
        }
    }
    // Two devices; a device on a hook that takes none; a nat chain at
    // conntrack's priority, and just above it.
    shapes.push((
        (Family::Netdev, ChainType::Filter, Hook::Ingress),
        0,
        &["d0", "d1"],
    ));
    shapes.push((
        (Family::Inet, ChainType::Filter, Hook::Ingress),
        0,
        &["d0", "d1"],
    ));
    shapes.push(((Family::Inet, ChainType::Filter, Hook::Input), 0, &["d0"]));
    shapes.push(((Family::Ip, ChainType::Nat, Hook::Prerouting), -200, &[]));
    shapes.push(((Family::Ip, ChainType::Nat, Hook::Prerouting), -199, &[]));

    let mut wrong = Vec::new();
    let mut accepted = 0;
    for (n, (shape, priority, devices)) in shapes.iter().enumerate() {
        match compare(&ns, &nft, n, *shape, *priority, devices).await? {
            Ok(took) => accepted += usize::from(took),
            Err(why) => wrong.push(why),
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} chain shapes disagree with the kernel:\n{}",
        wrong.len(),
        shapes.len(),
        wrong.join("\n")
    );
    // ip, ip6, inet: 5 filter + 4 nat + 1 route, and inet's ingress; bridge
    // 5; arp 2; netdev 2; and three of the extra shapes.
    assert_eq!(accepted, 3 * 10 + 1 + 5 + 2 + 2 + 3, "chains both took");
    Ok(())
}

/// A table `k` of `family` with a regular chain and one chain of each kind.
fn every(family: Family, kinds: Vec<BaseChain>) -> NftablesConfig {
    NftablesConfig::new().table("k", family, move |t| {
        kinds
            .into_iter()
            .enumerate()
            .fold(t.chain("regular", |c| c), |t, (i, base)| {
                t.chain(format!("c{i}"), move |c| c.base(base))
            })
    })
}

/// One chain `c` in table `k`, of `family`.
fn one(family: Family, kind: Option<BaseChain>) -> NftablesConfig {
    NftablesConfig::new().table("k", family, move |t| {
        t.chain("c", move |c| match kind {
            Some(base) => c.base(base),
            None => c,
        })
    })
}

/// Every kind each family has converges, declared together: applied, it
/// diffs empty, and applies with nothing to do. So does a chain changed
/// from one kind to another: its type, its hook, its priority, regular to
/// base and back, its policy (#708).
#[tokio::test]
async fn every_chain_kind_converges() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_chain_nat");

    let filter = |hook| BaseChain::filter(hook, Priority::Filter);
    let l3 = || {
        vec![
            filter(FilterHook::Prerouting),
            filter(FilterHook::Input),
            filter(FilterHook::Forward),
            filter(FilterHook::Output).policy(Policy::Drop),
            filter(FilterHook::Postrouting),
            BaseChain::nat(NatHook::Prerouting, Priority::DstNat),
            BaseChain::nat(NatHook::Input, Priority::Custom(100)),
            BaseChain::nat(NatHook::Output, Priority::DstNat),
            BaseChain::nat(NatHook::Postrouting, Priority::SrcNat),
            BaseChain::route(Priority::Mangle),
        ]
    };
    let mut inet = l3();
    inet.push(filter(FilterHook::ingress("lo")));
    let bridge = vec![
        filter(FilterHook::Prerouting),
        filter(FilterHook::Input),
        filter(FilterHook::Forward),
        filter(FilterHook::Output),
        filter(FilterHook::Postrouting).policy(Policy::Drop),
    ];
    let arp = vec![filter(FilterHook::Input), filter(FilterHook::Output)];
    let netdev = vec![
        filter(FilterHook::ingress("lo")),
        filter(FilterHook::egress("lo")),
    ];

    let nat = |hook| BaseChain::nat(hook, Priority::SrcNat);
    assert_converges(
        "nft-kinds-conv",
        vec![
            case("ip", vec![every(Family::Ip, l3())]),
            case("ip6", vec![every(Family::Ip6, l3())]),
            case("inet", vec![every(Family::Inet, inet)]),
            case("bridge", vec![every(Family::Bridge, bridge)]),
            case("arp", vec![every(Family::Arp, arp)]),
            case("netdev", vec![every(Family::Netdev, netdev)]),
            case(
                "filter -> nat -> route",
                vec![
                    one(
                        Family::Ip,
                        Some(BaseChain::filter(FilterHook::Output, Priority::SrcNat)),
                    ),
                    one(Family::Ip, Some(nat(NatHook::Output))),
                    one(Family::Ip, Some(BaseChain::route(Priority::SrcNat))),
                ],
            ),
            case(
                "nat hook, then priority",
                vec![
                    one(Family::Inet, Some(nat(NatHook::Postrouting))),
                    one(Family::Inet, Some(nat(NatHook::Input))),
                    one(
                        Family::Inet,
                        Some(BaseChain::nat(NatHook::Input, Priority::Custom(101))),
                    ),
                ],
            ),
            case(
                "regular -> base -> regular",
                vec![
                    one(Family::Inet, None),
                    one(Family::Inet, Some(filter(FilterHook::Input))),
                    one(Family::Inet, None),
                ],
            ),
            case(
                "policy accept -> drop -> none",
                vec![
                    one(
                        Family::Inet,
                        Some(filter(FilterHook::Input).policy(Policy::Accept)),
                    ),
                    one(
                        Family::Inet,
                        Some(filter(FilterHook::Input).policy(Policy::Drop)),
                    ),
                    // A policy left out is not compared: drop stays.
                    one(Family::Inet, Some(filter(FilterHook::Input))),
                ],
            ),
            case(
                "netdev ingress -> egress",
                vec![
                    one(Family::Netdev, Some(filter(FilterHook::ingress("lo")))),
                    one(Family::Netdev, Some(filter(FilterHook::egress("lo")))),
                ],
            ),
        ],
    )
    .await
}

/// An inet ingress chain moved from one device to two converges at each
/// step, and the kernel lists the devices nlink declared.
#[tokio::test]
async fn an_inet_ingress_chain_converges_on_its_devices() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "dummy");

    let ns = TestNamespace::new("nft-kinds-ingress")?;
    ns.exec("ip", &["link", "add", "d0", "type", "dummy"])?;
    ns.exec("ip", &["link", "add", "d1", "type", "dummy"])?;
    let on = |devices: Vec<&'static str>| {
        let devices = nlink::netlink::nftables::Devices::try_from(
            devices.into_iter().map(String::from).collect::<Vec<_>>(),
        )
        .expect("a device");
        one(
            Family::Inet,
            Some(BaseChain::filter(
                FilterHook::ingress(devices),
                Priority::Filter,
            )),
        )
    };
    let steps = [on(vec!["d0"]), on(vec!["d0", "d1"]), on(vec!["d1"])];
    // nft quotes a lone device and, depending on its version, those of a
    // set.
    let want = ["device d0 ", "devices = { d0, d1 }", "device d1 "];
    assert_transition(&ns, &steps, false, async |i, _conn| {
        let line = header(&ns, Family::Inet, "k")
            .map_err(|e| e.to_string())?
            .replace('"', "");
        line.contains(want[i])
            .then_some(())
            .ok_or_else(|| format!("nft lists `{line}`, not {}", want[i]))
    })
    .await
}

/// What the deprecated setters write converges too: a hook alone is a
/// filter chain at priority 0, which the diff now compares as such, and
/// the old ingress spellings are the family's ingress (#708).
#[tokio::test]
#[allow(deprecated)]
async fn what_the_deprecated_setters_write_converges() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!("nf_tables", "nft_chain_nat");

    let legacy = |family, chain: fn(_) -> _| {
        NftablesConfig::new().table("k", family, move |t| t.chain("c", chain))
    };
    type Chain = fn(
        nlink::netlink::nftables::config::DeclaredChainBuilder,
    ) -> nlink::netlink::nftables::config::DeclaredChainBuilder;
    let shapes: [(Family, Chain); 5] = [
        (Family::Inet, |c| c.hook(Hook::Input)),
        (Family::Inet, |c| {
            c.hook(Hook::Postrouting)
                .chain_type(ChainType::Nat)
                .priority(Priority::SrcNat)
        }),
        (Family::Netdev, |c| c.hook(Hook::NetdevIngress).device("lo")),
        (Family::Inet, |c| {
            c.device("lo").hook(Hook::InetIngress).policy(Policy::Drop)
        }),
        (Family::Netdev, |c| c.hook(Hook::NetdevEgress).device("lo")),
    ];
    let cases = shapes
        .into_iter()
        .enumerate()
        .map(|(i, (family, chain))| case(format!("legacy {i}"), vec![legacy(family, chain)]))
        .collect();
    assert_converges("nft-kinds-old", cases).await
}
