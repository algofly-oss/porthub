//! #708: what the kernel holds reads back as the typed diff's values.
//!
//! A broad config is applied, and each table, chain, set, object, flowtable
//! and rule the kernel then holds is read back (`NftX::from_kernel`). It must
//! be what the same config says the kernel holds, read back from the
//! simulated echo `RulesetSnapshot::from_config` builds. That is what makes
//! a change's `from` and `to` comparable. Then sets nft makes with types
//! nlink has no name for read back as `SetKeyType::Other` and `Concat`.

use std::collections::BTreeMap;
use std::time::Duration;

use nlink::netlink::Nftables;
use nlink::netlink::nftables::config::{
    NftChain, NftFlowtable, NftObject, NftRule, NftSet, NftTable, NftablesConfig, RulesetSnapshot,
};
use nlink::netlink::nftables::object::{CtHelperObject, ObjectConfig, ObjectType};
use nlink::netlink::nftables::types::{
    BaseChain, Family, FilterHook, LimitUnit, NatHook, PacketField, Policy, Priority, SetDataType,
    SetKeyType, SetPolicy,
};
use nlink::netlink::nftables::{LimitExpr, QuotaExpr};

use crate::common::TestNamespace;

fn config() -> NftablesConfig {
    use SetKeyType::*;
    NftablesConfig::new().table("rb", Family::Inet, |t| {
        t.comment("read back")
            .chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop))
                    .comment("in")
            })
            .chain("post", |c| {
                c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
            })
            .chain("ing", |c| {
                c.base(BaseChain::filter(
                    FilterHook::ingress("lo"),
                    Priority::Filter,
                ))
            })
            .chain("side", |c| c.comment("regular"))
            .set("v4", |s| s.key_type(Ipv4Addr).size(64).comment("hosts"))
            .set("v6", |s| s.key_type(Ipv6Addr).policy(SetPolicy::Memory))
            .set("mac", |s| s.key_type(EtherAddr))
            .set("ports", |s| s.key_type(InetService).interval())
            .set("marks", |s| s.key_type(Mark))
            .set("protos", |s| s.key_type(InetProto))
            .set("pairs", |s| s.key_type(Concat(vec![Ipv4Addr, InetService])))
            .set("seen", |s| {
                s.key_type(Ipv4Addr)
                    .dynamic()
                    .timeout(Duration::from_secs(30))
                    .gc_interval(Duration::from_secs(5))
                    .counter()
            })
            .set("vm", |s| s.key_type(InetService).vmap())
            .set("mm", |s| s.key_type(Ipv4Addr).map(SetDataType::Value(Mark)))
            .set("cm", |s| {
                s.key_type(Ipv4Addr).map(SetDataType::Value(ClassId))
            })
            .set("om", |s| {
                s.key_type(Ipv4Addr)
                    .map(SetDataType::Object(ObjectType::Counter))
            })
            .object("c1", ObjectConfig::Counter)
            .object("q1", ObjectConfig::Quota(QuotaExpr::new(1_000_000).over()))
            .object(
                "l1",
                ObjectConfig::Limit(LimitExpr::packets(10, LimitUnit::Second)),
            )
            .object("ftp", ObjectConfig::CtHelper(CtHelperObject::new("ftp", 6)))
            .flowtable("ft", |f| f.device("lo"))
            .rule_keyed("input", "ssh", |r| {
                r.match_tcp_dport(22).counter().accept().comment("ssh")
            })
            .rule_keyed("input", "seen", |r| {
                r.update_in_set(PacketField::Ip4Saddr, "seen", None)
            })
            .rule_keyed("input", "vm", |r| r.vmap(PacketField::TcpDport, "vm"))
            .rule_keyed("side", "mark", |r| {
                r.set_mark_from_map(PacketField::Ip4Saddr, "mm")
            })
            .rule("post", |r| r.masquerade())
    })
}

/// A duration as the kernel keeps one, in jiffies: 20 ms steps are whole
/// jiffies at every `HZ`.
fn stepped(d: Option<Duration>) -> Option<u128> {
    d.map(|d| d.as_millis() - d.as_millis() % 20)
}

/// What `snapshot` holds, read back, by kind and name.
fn read_back(snapshot: &RulesetSnapshot) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for t in &snapshot.tables {
        out.insert(
            format!("table {}", t.name),
            format!("{:?}", NftTable::from_kernel(t)),
        );
    }
    for c in &snapshot.chains {
        out.insert(
            format!("chain {}", c.name),
            format!("{:?}", NftChain::from_kernel(c)),
        );
    }
    for s in snapshot.sets.iter().filter(|s| !s.name.starts_with("__")) {
        let mut set = NftSet::from_kernel(s);
        let (timeout, gc) = (stepped(set.timeout), stepped(set.gc_interval));
        set.timeout = None;
        set.gc_interval = None;
        out.insert(
            format!("set {}", s.name),
            format!("{set:?} timeout={timeout:?} gc={gc:?}"),
        );
    }
    for o in &snapshot.objects {
        out.insert(
            format!("object {}", o.name),
            format!("{:?}", NftObject::from_kernel(o)),
        );
    }
    for f in &snapshot.flowtables {
        out.insert(
            format!("flowtable {}", f.name),
            format!("{:?}", NftFlowtable::from_kernel(f)),
        );
    }
    for r in &snapshot.rules {
        let mut rule = NftRule::from_kernel(r);
        rule.handle = None;
        out.insert(format!("rule {}/{:?}", r.chain, r.key), format!("{rule:?}"));
    }
    out
}

#[tokio::test]
async fn kernel_read_backs_match_the_simulated_echo() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_modules!(
        "nf_tables",
        "nft_ct",
        "nft_nat",
        "nft_masq",
        "nft_limit",
        "nft_quota",
        "nf_flow_table",
        "nf_conntrack_ftp"
    );
    let ns = TestNamespace::new("nft-readback")?;
    let nft = ns.connection_for::<Nftables>()?;
    let cfg = config();
    cfg.diff(&nft).await?.apply(&nft).await?;
    let kernel = read_back(&cfg.snapshot(&nft).await?);
    let echo = read_back(&RulesetSnapshot::from_config(&cfg));
    let mut wrong = Vec::new();
    for name in kernel
        .keys()
        .chain(echo.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let (k, e) = (kernel.get(name), echo.get(name));
        if k != e {
            wrong.push(format!("{name}:\n  kernel {k:?}\n    echo {e:?}"));
        }
    }
    assert!(
        kernel.len() > 25,
        "the config reads back as only {} items",
        kernel.len()
    );
    assert!(
        wrong.is_empty(),
        "{} read-backs differ from the echo:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
    Ok(())
}

/// A set nft makes with a type nlink has no name for reads back as it is,
/// and a `typeof` concatenation as its fields.
#[tokio::test]
async fn sets_nft_makes_read_back_as_the_kernel_says() -> nlink::Result<()> {
    nlink::require_root!();
    nlink::require_module!("nf_tables");
    let ns = TestNamespace::new("nft-readback-nft")?;
    let script = "table inet x {\n  set names { type ifname; }\n  set pairs { typeof ip saddr . tcp dport; }\n  set bytes { type ipv4_addr . ifname; }\n}\n";
    let file = std::env::temp_dir().join(format!("nlink-readback-{}.nft", std::process::id()));
    std::fs::write(&file, script).map_err(nlink::Error::from)?;
    let installed = ns.exec("nft", &["-f", file.to_str().unwrap()]);
    let _ = std::fs::remove_file(&file);
    installed?;
    let nft = ns.connection_for::<Nftables>()?;
    let sets = nft.list_sets(Family::Inet).await?;
    let key = |name: &str| {
        let set = sets
            .iter()
            .find(|s| s.table == "x" && s.name == name)
            .unwrap();
        NftSet::from_kernel(set).key_type
    };
    // nft's TYPE_IFNAME is 41, 16 bytes.
    assert_eq!(
        key("names"),
        SetKeyType::Other {
            type_id: 41,
            len: 16
        }
    );
    assert_eq!(
        key("pairs"),
        SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService])
    );
    assert_eq!(
        key("bytes"),
        SetKeyType::Concat(vec![
            SetKeyType::Ipv4Addr,
            SetKeyType::Other {
                type_id: 41,
                len: 16
            }
        ])
    );
    Ok(())
}
