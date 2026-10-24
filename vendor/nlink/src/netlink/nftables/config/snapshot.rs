//! What the declarative diff reads, as a value (#527).
//!
//! [`NftablesConfig::diff`] used to read the kernel as it went. The reads
//! are now a [`RulesetSnapshot`] — taken from the kernel, between two reads
//! of the ruleset generation, or simulated from a config — and
//! [`NftablesConfig::diff_snapshot`] is a pure function of it. So a diff
//! runs without the kernel: [`NftablesConfig::diff_against`] says what
//! going from one config to another would change, without root and without
//! a namespace, and a planner built on it can be unit-tested.

use std::collections::HashMap;

use super::super::object::{ObjectConfig, ObjectInfo, ObjectState};
use super::super::types::{
    ChainInfo, Family, Flowtable, RuleInfo, SetElement, SetFlags, SetInfo, Table,
};
use super::types::{DeclaredSet, NftablesConfig, SetElementMode};
use crate::netlink::error::{Error, Result};
use crate::netlink::{Connection, Nftables};

/// The kernel's nftables state as the declarative diff sees it (#527):
/// every table, chain and flowtable, and the objects, sets, set elements
/// and rules of the tables a config declares.
///
/// Take one from the kernel with [`NftablesConfig::snapshot`], or simulate
/// the state a config would leave with [`from_config`](Self::from_config),
/// and diff a config against it with [`NftablesConfig::diff_snapshot`].
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RulesetSnapshot {
    /// The ruleset generation it was read at; `None` for one simulated
    /// from a config. A diff from it commits only at that generation.
    pub generation: Option<u32>,
    /// Every table.
    pub tables: Vec<Table>,
    /// Every chain.
    pub chains: Vec<ChainInfo>,
    /// Every flowtable.
    pub flowtables: Vec<Flowtable>,
    /// The objects of the tables read.
    pub objects: Vec<ObjectInfo>,
    /// The sets of the tables read, anonymous ones included.
    pub sets: Vec<SetInfo>,
    /// Elements by `(family, table, set)`, interval ranges paired as
    /// [`list_set_elements`](Connection::list_set_elements) pairs them. A
    /// set whose elements were not read is absent.
    pub elements: HashMap<(Family, String, String), Vec<SetElement>>,
    /// The rules of the tables read, in chain order.
    pub rules: Vec<RuleInfo>,
}

impl RulesetSnapshot {
    pub(crate) fn objects_in(&self, table: &str, family: Family) -> Vec<ObjectInfo> {
        self.objects
            .iter()
            .filter(|o| o.table == table && o.family == family)
            .cloned()
            .collect()
    }

    pub(crate) fn sets_in(&self, table: &str, family: Family) -> Vec<SetInfo> {
        self.sets
            .iter()
            .filter(|s| s.table == table && s.family == family)
            .cloned()
            .collect()
    }

    pub(crate) fn rules_in(&self, table: &str, family: Family) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .filter(|r| r.table == table && r.family == family)
            .cloned()
            .collect()
    }

    /// The elements of a set the diff needs; an error when the snapshot
    /// did not read them, rather than a diff that takes the set for empty.
    pub(crate) fn elements_of(&self, family: Family, table: &str, set: &str) -> Result<Vec<SetElement>> {
        self.elements
            .get(&(family, table.to_string(), set.to_string()))
            .cloned()
            .ok_or_else(|| {
                Error::invalid_message(format!(
                    "nftables snapshot: the elements of set {family} {table} {set} were not read"
                ))
            })
    }

    /// The state applying `config` to an empty ruleset leaves, as the
    /// kernel would report it (#527): its tables, chains, flowtables,
    /// objects with zeroed counters, sets with their declared elements
    /// (ranges merged where an interval set merges them), and rules
    /// carrying their keys, in declared order, with handles counted from 1.
    ///
    /// Diffing another config against it is what applying that config
    /// after this one would change: see
    /// [`NftablesConfig::diff_against`].
    pub fn from_config(config: &NftablesConfig) -> Self {
        let mut snapshot = Self::default();
        let mut handle = 0u64;
        let mut next = || {
            handle += 1;
            handle
        };
        for table in &config.tables {
            let (family, name) = (table.family(), table.name().to_string());
            snapshot.tables.push(Table {
                name: name.clone(),
                family,
                flags: table.flags(),
                use_count: 0,
                handle: next(),
                comment: table.comment().map(str::to_string),
            });
            for chain in table.chains() {
                let base = chain.is_base();
                snapshot.chains.push(ChainInfo {
                    table: name.clone(),
                    name: chain.name().to_string(),
                    family,
                    hook: chain.hook().map(|h| h.number(family)),
                    priority: chain.priority().map(|p| p.to_i32()),
                    chain_type: chain.chain_type(),
                    device: chain.device().map(str::to_string),
                    devices: chain.devices().to_vec(),
                    // A base chain without a policy accepts.
                    policy: chain
                        .policy()
                        .map(|p| p.to_u32())
                        .or(base.then(|| super::super::types::Policy::Accept.to_u32())),
                    handle: next(),
                    comment: chain.comment().map(str::to_string),
                    managed: true,
                });
            }
            for flowtable in table.flowtables() {
                snapshot.flowtables.push(Flowtable {
                    family,
                    table: name.clone(),
                    name: flowtable.name().to_string(),
                    devs: flowtable.devs().to_vec(),
                    priority: flowtable.priority(),
                    flags: flowtable.flags(),
                    use_count: 0,
                    handle: next(),
                });
            }
            for object in table.objects() {
                snapshot.objects.push(ObjectInfo {
                    table: name.clone(),
                    name: object.name().to_string(),
                    family,
                    handle: next(),
                    use_count: 0,
                    state: match object.config() {
                        ObjectConfig::Counter => ObjectState::Counter { packets: 0, bytes: 0 },
                        ObjectConfig::Quota(q) => ObjectState::Quota {
                            bytes: q.bytes,
                            consumed: 0,
                            over: q.over,
                            depleted: false,
                        },
                        // The kernel stores a packet limit's burst 0 as 5.
                        ObjectConfig::Limit(l) => {
                            let mut l = l.clone();
                            if l.burst == 0 && l.kind == super::super::types::LimitKind::Packets {
                                l.burst = 5;
                            }
                            ObjectState::Limit(l)
                        }
                        ObjectConfig::CtHelper(h) => ObjectState::CtHelper(h.clone()),
                        ObjectConfig::Secmark(c) => ObjectState::Secmark(c.clone()),
                    },
                    comment: None,
                    managed: true,
                });
            }
            // nft_dynset_init gives a set a dynset writes to, and that
            // has no size, a size of 65535.
            let written: Vec<String> = table
                .rules()
                .iter()
                .filter_map(|rule| rule.body().lowered().ok())
                .flatten()
                .filter_map(|e| match e {
                    super::super::Expr::Dynset(dynset) => Some(dynset.set),
                    _ => None,
                })
                .collect();
            for set in table.sets() {
                let mut info = set_info(set, &name, family, next());
                if info.size.is_none() && written.iter().any(|s| s == set.name()) {
                    info.size = Some(65535);
                }
                snapshot.sets.push(info);
                snapshot
                    .elements
                    .insert((family, name.clone(), set.name().to_string()), set.wire_elements());
            }
            for rule in super::rules::effective_rules(table.rules()) {
                let key = rule.handle_key().map(str::to_string);
                let comment = rule.body().comment_ref().map(str::to_string);
                snapshot.rules.push(RuleInfo {
                    table: name.clone(),
                    chain: rule.chain().to_string(),
                    family,
                    handle: next(),
                    position: None,
                    comment_text: comment.clone(),
                    userdata_raw: super::super::userdata::encode_rule_userdata(key.as_deref(), comment.as_deref())
                        .ok()
                        .flatten(),
                    key,
                    expression_bytes: super::diff::lower_to_expression_bytes(rule.body()),
                });
            }
        }
        snapshot
    }
}

/// A declared set as the kernel reports it.
fn set_info(set: &DeclaredSet, table: &str, family: Family, handle: u64) -> SetInfo {
    use super::super::SetDataType;
    let data_type = set.data_type();
    SetInfo {
        table: table.to_string(),
        name: set.name().to_string(),
        family,
        flags: set.wire_flags(),
        key_type: set.key_type().type_id(),
        key_len: set.key_type().len(),
        handle,
        size: set.size(),
        timeout: set.timeout(),
        gc_interval: set.gc_interval(),
        data_type: data_type.and_then(|d| d.type_id()),
        data_len: data_type.and_then(|d| d.len()),
        object_type: data_type.and_then(|d| match d {
            SetDataType::Object(t) => Some(*t as u32),
            _ => None,
        }),
        comment: set.comment.clone(),
        managed: true,
        policy: set.policy().unwrap_or_default(),
        statements: set.statements().iter().map(|s| s.as_dumped()).collect(),
    }
}

#[nlink_macros::send_futures]
impl NftablesConfig {
    /// Read what [`diff_snapshot`](Self::diff_snapshot) needs from the
    /// kernel (#527): every table, chain and flowtable, and the objects,
    /// sets and rules of the tables this config declares — with the
    /// elements of its declared sets, except where nothing is declared to
    /// add or remove. Taken between two reads of the ruleset generation,
    /// and again if a commit landed in between.
    pub async fn snapshot(&self, conn: &Connection<Nftables>) -> Result<RulesetSnapshot> {
        const ATTEMPTS: usize = 3;
        let mut attempt = 0;
        loop {
            let before = conn.generation().await?;
            let mut snapshot = self.read(conn).await?;
            snapshot.generation = Some(before);
            attempt += 1;
            if attempt == ATTEMPTS || conn.generation().await? == before {
                return Ok(snapshot);
            }
            tracing::debug!(attempt, "nftables snapshot: the ruleset changed under it; again");
        }
    }

    async fn read(&self, conn: &Connection<Nftables>) -> Result<RulesetSnapshot> {
        let mut snapshot = RulesetSnapshot {
            tables: conn.list_tables().await?,
            chains: conn.list_chains().await?,
            flowtables: conn.list_flowtables().await?,
            ..Default::default()
        };
        for declared in &self.tables {
            let (family, name) = (declared.family(), declared.name());
            if !snapshot.tables.iter().any(|t| t.family == family && t.name == name) {
                continue;
            }
            snapshot.objects.extend(conn.list_objects_in(name, family).await?);
            let sets = conn.list_sets_in(name, family).await?;
            for set in declared.sets() {
                let exists = sets
                    .iter()
                    .any(|s| s.name == set.name() && !s.flags.contains(SetFlags::ANONYMOUS));
                // What the packet path put in a set nothing is declared
                // into or removed from is not the diff's to read.
                let object_map = matches!(set.data_type(), Some(super::super::SetDataType::Object(_)));
                let needed = !(set.element_mode() == SetElementMode::Ensure
                    && set.elements().is_empty()
                    && !object_map);
                if exists && needed {
                    let elements = conn.list_set_elements(name, set.name(), family).await?;
                    snapshot
                        .elements
                        .insert((family, name.to_string(), set.name().to_string()), elements);
                }
            }
            snapshot.sets.extend(sets);
            snapshot.rules.extend(conn.list_rules(name, family).await?);
        }
        Ok(snapshot)
    }

    /// What going from `previous` to this config would change (#527),
    /// without the kernel: the diff against
    /// [`RulesetSnapshot::from_config(previous)`](RulesetSnapshot::from_config).
    /// It assumes the kernel holds exactly what `previous` declares — no
    /// foreign tables, no elements the packet path added — and its
    /// [`apply`](super::NftablesDiff::apply) does not check the
    /// generation.
    pub fn diff_against(&self, previous: &NftablesConfig, options: &super::NftDiffOptions) -> Result<super::NftablesDiff> {
        self.diff_snapshot(&RulesetSnapshot::from_config(previous), options)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::netlink::nftables::config::{Change, NftChange, NftDiffOptions};
    use crate::netlink::nftables::expr::{LimitExpr, QuotaExpr};
    use crate::netlink::nftables::types::{
        BaseChain, ChainName, FilterHook, LimitUnit, NatHook, Policy, Priority, SetKeyType, Verdict,
    };

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, last)
    }

    /// A config with one of everything the diff compares.
    fn lab(ssh_port: u16, with_hosts: bool) -> NftablesConfig {
        NftablesConfig::new()
            .table("f", Family::Inet, |t| {
                let t = t
                    .comment("lab")
                    .chain("input", |c| {
                        c.base(
                            BaseChain::filter(FilterHook::Input, Priority::Filter)
                                .policy(Policy::Drop),
                        )
                    })
                    .chain("sub", |c| c)
                    .set("nets", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .interval()
                            .element(SetElement::ipv4_range(ip(1), ip(9)))
                            .element(SetElement::ipv4_range(ip(10), ip(20)))
                    })
                    .set("verdicts", |s| {
                        s.key_type(SetKeyType::InetService)
                            .vmap()
                            .element(SetElement::port(22).verdict(Verdict::Accept))
                    })
                    .object("hits", ObjectConfig::Counter)
                    .object("budget", ObjectConfig::Quota(QuotaExpr::new(1_000_000)))
                    .object("pace", ObjectConfig::Limit(LimitExpr::packets(10, LimitUnit::Second)))
                    .rule_keyed("input", "ssh", move |r| r.match_tcp_dport(ssh_port).accept())
                    .rule("input", |r| r.match_saddr_in_set("nets").counter().accept())
                    .rule_keyed("input", "dns", |r| {
                        r.match_udp_dport(53).jump(ChainName::new("sub").unwrap())
                    });
                if with_hosts {
                    t.set("hosts", |s| s.key_type(SetKeyType::Ipv4Addr).ipv4(ip(30)).ipv4(ip(31)))
                } else {
                    t
                }
            })
            .table("n", Family::Ip, |t| {
                t.chain("post", |c| {
                    c.base(BaseChain::nat(NatHook::Postrouting, Priority::SrcNat))
                })
                .rule_keyed("post", "masq", |r| r.masquerade())
            })
    }

    /// The simulated echo is what the diff reads from the kernel after an
    /// apply: a config diffs empty against its own.
    #[test]
    fn a_config_diffs_empty_against_its_own_echo() {
        let cfg = lab(22, true);
        let diff = cfg
            .diff_snapshot(&RulesetSnapshot::from_config(&cfg), &NftDiffOptions::default())
            .unwrap();
        assert!(diff.is_empty(), "{diff}");
    }

    /// Offline, the diff says what going from one config to the next does.
    #[test]
    fn diff_against_says_what_a_change_would_do() {
        let options = NftDiffOptions::default();
        let diff = lab(2222, false)
            .diff_against(&lab(22, true), &options)
            .unwrap();
        let rules: Vec<_> = diff.rules().collect();
        let [Change::Update { from, to }] = rules[..] else {
            panic!("one rule update: {diff}");
        };
        assert_eq!(to.key.as_deref(), Some("ssh"));
        assert_eq!(from.nft.as_deref(), Some("tcp dport 22 accept"));
        assert_eq!(to.nft.as_deref(), Some("tcp dport 2222 accept"));
        assert!(
            diff.to_string().contains(&format!(
                "~ rule Inet f/input (handle={} key=ssh): tcp dport 22 accept -> tcp dport 2222 accept",
                from.handle.unwrap().0
            )),
            "{diff}"
        );
        let sets: Vec<_> = diff.sets().collect();
        assert!(
            matches!(sets[..], [Change::Remove(s)] if s.table == "f" && s.name == "hosts"),
            "{diff}"
        );
        assert_eq!(diff.change_count(), 2, "{diff}");
        assert_eq!(diff.generation, None, "an offline diff has no generation to hold");

        // And back.
        let back = lab(22, true)
            .diff_against(&lab(2222, false), &options)
            .unwrap();
        assert!(
            matches!(back.sets().collect::<Vec<_>>()[..], [Change::Add(_)]),
            "{back}"
        );
        assert!(
            matches!(
                back.rules().collect::<Vec<_>>()[..],
                [Change::Update { .. }]
            ),
            "{back}"
        );
    }

    /// #527: in a shared table the diff deletes only the undeclared chains,
    /// sets and objects nlink's apply made; an owned table loses all of
    /// them.
    #[test]
    fn a_shared_table_keeps_what_nlink_did_not_make() {
        use crate::netlink::nftables::config::TableMode;
        let options = NftDiffOptions::default();
        let declared = |mode| {
            NftablesConfig::new().table("f", Family::Inet, move |t| t.mode(mode).chain("input", |c| c))
        };
        let held = NftablesConfig::new().table("f", Family::Inet, |t| {
            t.chain("input", |c| c)
                .chain("ours", |c| c)
                .chain("theirs", |c| c)
                .set("our_set", |s| s.key_type(SetKeyType::Ipv4Addr))
                .set("their_set", |s| s.key_type(SetKeyType::Ipv4Addr))
                .object("our_counter", ObjectConfig::Counter)
                .object("their_counter", ObjectConfig::Counter)
        });
        let mut snapshot = RulesetSnapshot::from_config(&held);
        // What another tool added carries no ownership tag.
        for c in snapshot.chains.iter_mut().filter(|c| c.name == "theirs") {
            c.managed = false;
        }
        for s in snapshot.sets.iter_mut().filter(|s| s.name == "their_set") {
            s.managed = false;
        }
        for o in snapshot.objects.iter_mut().filter(|o| o.name == "their_counter") {
            o.managed = false;
        }

        let shared = declared(TableMode::Shared).diff_snapshot(&snapshot, &options).unwrap();
        let names = |d: &crate::netlink::nftables::config::NftablesDiff| {
            let mut n: Vec<String> = d.chains_to_delete.iter().map(|(_, _, c)| c.clone()).collect();
            n.extend(d.sets_to_delete.iter().map(|(_, _, s)| s.clone()));
            n.extend(d.objects_to_delete.iter().map(|(_, _, o, _)| o.clone()));
            n.sort();
            n
        };
        assert_eq!(names(&shared), ["our_counter", "our_set", "ours"], "{shared}");
        let owned = declared(TableMode::Owned).diff_snapshot(&snapshot, &options).unwrap();
        assert_eq!(
            names(&owned),
            ["our_counter", "our_set", "ours", "their_counter", "their_set", "theirs"],
            "{owned}"
        );
    }

    /// #708 — a rule in the diff's JSON is what nft would list, so a
    /// `--check --json` says what changes.
    #[cfg(feature = "serde")]
    #[test]
    fn a_rule_in_the_diff_json_is_its_nft_text() {
        let rules = |json: &serde_json::Value, op: &str| -> Vec<serde_json::Value> {
            json["changes"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|c| c["type"] == "rule" && c["op"] == op)
                .cloned()
                .collect()
        };
        let diff = lab(22, true)
            .diff_against(&NftablesConfig::new(), &NftDiffOptions::default())
            .unwrap();
        let json = serde_json::to_value(&diff).unwrap();
        let added: Vec<_> = rules(&json, "add")
            .iter()
            .map(|add| (add["key"].clone(), add["nft"].clone()))
            .collect();
        assert!(
            added.contains(&("ssh".into(), "tcp dport 22 accept".into())),
            "{added:?}"
        );
        assert!(
            added.contains(&("masq".into(), "masquerade".into())),
            "{added:?}"
        );
        assert!(
            added
                .iter()
                .any(|(_, nft)| nft == "ip saddr @nets counter accept"),
            "a counter is printed as nft -s prints it: {added:?}"
        );

        // A delete and a replace say what the kernel has.
        let was = NftablesConfig::new().table("f", Family::Inet, |t| {
            t.chain("input", |c| c)
                .rule_keyed("input", "dns", |r| r.match_udp_dport(53).counter().accept())
                .rule_keyed("input", "ssh", |r| r.match_tcp_dport(22).accept())
        });
        let now = NftablesConfig::new().table("f", Family::Inet, |t| {
            t.chain("input", |c| c)
                .rule_keyed("input", "ssh", |r| r.match_tcp_dport(2222).accept())
        });
        let diff = now.diff_against(&was, &NftDiffOptions::default()).unwrap();
        let json = serde_json::to_value(&diff).unwrap();
        let delete = &rules(&json, "remove")[0];
        assert_eq!(delete["key"], "dns", "{json:#}");
        assert_eq!(delete["nft"], "udp dport 53 counter accept", "{json:#}");
        let replace = &rules(&json, "update")[0];
        assert_eq!(replace["from"]["nft"], "tcp dport 22 accept", "{json:#}");
        assert_eq!(replace["to"]["nft"], "tcp dport 2222 accept", "{json:#}");
    }

    /// The other ops of `added`'s kind, each recreate taking `cascade`.
    #[cfg(feature = "schemars")]
    fn other_ops(added: &NftChange, cascade: Vec<NftChange>) -> Vec<NftChange> {
        macro_rules! ops {
            ($kind:ident, $x:expr) => {{
                let x = $x;
                vec![
                    NftChange::$kind(Change::Remove(x.clone())),
                    NftChange::$kind(Change::Update {
                        from: x.clone(),
                        to: x.clone(),
                    }),
                    NftChange::$kind(Change::Recreate {
                        from: x.clone(),
                        to: x.clone(),
                        reason: "key Ipv4Addr -> Ipv6Addr".into(),
                        cascade,
                    }),
                ]
            }};
        }
        match added {
            NftChange::Table(Change::Add(x)) => ops!(Table, x),
            NftChange::Chain(Change::Add(x)) => ops!(Chain, x),
            NftChange::Rule(Change::Add(x)) => ops!(Rule, x),
            NftChange::Set(Change::Add(x)) => ops!(Set, x),
            NftChange::Elements(Change::Add(x)) => ops!(Elements, x),
            NftChange::Object(Change::Add(x)) => ops!(Object, x),
            NftChange::Flowtable(Change::Add(x)) => ops!(Flowtable, x),
            other => panic!("not an add: {other:?}"),
        }
    }

    /// #876 — an `NftablesDiff` with every kind of change and every
    /// blocked entry validates against the schema it publishes, and its
    /// JSON names each by the tags pinned here. The adds come from a real
    /// offline diff; the other ops reuse what they add.
    #[cfg(feature = "schemars")]
    #[test]
    fn diff_json_matches_its_schema() {
        use std::collections::BTreeSet;

        use crate::netlink::config::schema_check;
        use crate::netlink::nftables::config::{
            Blocked, NftItem, NftRule, NftablesDiff, RuleHandle, RulePlacement,
        };

        const KINDS: [&str; 7] = [
            "table",
            "chain",
            "rule",
            "set",
            "elements",
            "object",
            "flowtable",
        ];
        let cfg = lab(22, true).table("ft", Family::Inet, |t| {
            t.flowtable("ft", |f| f.device("eth0").hw_offload(true))
        });
        let mut diff = cfg
            .diff_against(&NftablesConfig::new(), &NftDiffOptions::default())
            .unwrap();
        let Some(NftChange::Rule(Change::Add(rule))) =
            diff.changes.iter().find(|c| c.kind() == "rule")
        else {
            panic!("the diff adds no rule: {diff}");
        };
        let mut from = rule.clone();
        from.handle = Some(RuleHandle(6));
        let mut to = rule.clone();
        to.placement = Some(RulePlacement::After(RuleHandle(5)));
        let moved = NftChange::Rule(Change::Update { from, to });
        let mut every = Vec::new();
        for kind in KINDS {
            let added = diff
                .changes
                .iter()
                .find(|c| c.kind() == kind)
                .unwrap_or_else(|| panic!("the diff adds no {kind}: {diff}"));
            every.extend(other_ops(added, vec![moved.clone()]));
        }
        // A recreate in a recreate.
        let chain = every
            .iter()
            .find(|c| c.kind() == "chain" && c.op() == "recreate")
            .cloned()
            .unwrap();
        if let Some(NftChange::Table(Change::Recreate { cascade, .. })) = every
            .iter_mut()
            .find(|c| c.kind() == "table" && c.op() == "recreate")
        {
            cascade.push(chain);
        }
        diff.changes.extend(every);

        let (table, family) = ("f".to_string(), Family::Inet);
        let foreign = NftRule {
            family,
            table: table.clone(),
            chain: "input".into(),
            key: None,
            handle: Some(RuleHandle(9)),
            placement: None,
            spec: crate::netlink::nftables::RuleSpec::new(),
            nft: Some("ip saddr @nets drop".into()),
        };
        let set = NftItem::Set {
            table: table.clone(),
            family,
            name: "nets".into(),
        };
        diff.blocked.extend([
            Blocked::TableFlags {
                family: Family::Ip,
                table: "theirs".into(),
                from: 0,
                to: 2,
            },
            Blocked::TableRecreate {
                family,
                table: table.clone(),
                reason: "comment".into(),
                rules: vec![foreign.clone()],
            },
            Blocked::ChainRecreate {
                family,
                table: table.clone(),
                chain: "input".into(),
                reason: "hook 1 -> 2".into(),
                rules: vec![foreign.clone()],
            },
            Blocked::Bound {
                item: set.clone(),
                rules: vec![foreign.clone()],
            },
            Blocked::InUse {
                item: set,
                rules: vec![foreign],
            },
            Blocked::UnmodelledObject {
                family,
                table,
                name: "syn".into(),
                object_type: 11,
            },
        ]);
        diff.generation = Some(7);

        schema_check::assert_every_root_property_populated(
            &diff,
            NftablesDiff::json_schema_value(),
        );
        schema_check::assert_matches_schema(&diff, NftablesDiff::json_schema_value());

        fn pairs(changes: &serde_json::Value, out: &mut BTreeSet<(String, String)>) {
            for c in changes.as_array().unwrap() {
                out.insert((
                    c["type"].as_str().unwrap().to_string(),
                    c["op"].as_str().unwrap().to_string(),
                ));
                if let Some(cascade) = c.get("cascade") {
                    pairs(cascade, out);
                }
            }
        }
        let json = serde_json::to_value(&diff).unwrap();
        let mut seen = BTreeSet::new();
        pairs(&json["changes"], &mut seen);
        let pinned: BTreeSet<(String, String)> = KINDS
            .iter()
            .flat_map(|kind| {
                ["add", "remove", "update", "recreate"].map(|op| (kind.to_string(), op.to_string()))
            })
            .collect();
        assert_eq!(seen, pinned, "{json:#}");
        let blocked: Vec<&str> = json["blocked"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["kind"].as_str().unwrap())
            .collect();
        assert_eq!(
            blocked,
            [
                "table-flags",
                "table-recreate",
                "chain-recreate",
                "bound",
                "in-use",
                "unmodelled-object"
            ]
        );
        assert_eq!(
            serde_json::to_value(&moved).unwrap()["to"]["placement"],
            serde_json::json!({ "after": 5 })
        );
    }

    /// A snapshot that did not read a set's elements makes the diff fail,
    /// rather than take the set for empty and re-add everything.
    #[test]
    fn unread_elements_are_an_error_not_an_empty_set() {
        let cfg = lab(22, true);
        let mut snapshot = RulesetSnapshot::from_config(&cfg);
        snapshot.elements.clear();
        let err = cfg.diff_snapshot(&snapshot, &NftDiffOptions::default()).unwrap_err();
        assert!(err.to_string().contains("were not read"), "{err}");
    }
}
