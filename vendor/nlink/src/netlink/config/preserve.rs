//! An undeclared TC tree kept across a recreate (#645).
//!
//! Deleting a link to create it again destroys its qdiscs, classes and
//! filters. What a config declares, the apply puts back; what it does not
//! declare refuses the recreate, unless
//! [`PlanOptions::preserve_undeclared_tc`](super::PlanOptions::preserve_undeclared_tc)
//! is set. Then the diff keeps a snapshot of each such object as the kernel
//! dumped it, and the apply replays them once the link is back: qdiscs and
//! classes parent first, then filters, with a mirred action's target looked
//! up again by name, and the attributes a dump adds that a request does not
//! take (an action's statistics, timestamps and padding) left out.
//!
//! What cannot be replayed stays a blocker, so the recreate is still
//! refused for it: a BPF filter or action, whose dump names its program by
//! id, not by the file descriptor a request needs.

use std::collections::{BTreeMap, HashMap};

use crate::netlink::{
    attr::AttrIter,
    builder::MessageBuilder,
    connection::{Connection, create_request, replace_request},
    error::{Error, Result},
    message::NlMsgType,
    messages::TcMessage,
    protocol::Route,
    tc_handle::TcHandle,
    types::tc::{TcMsg, TcaAttr},
};

/// One qdisc, class or filter as the kernel dumped it, to be put back as
/// it was.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TcObject {
    /// Its kind: `htb`, `fq_codel`, `flower`, ….
    pub kind: String,
    /// Its handle (a filter's: the node it is at).
    pub handle: TcHandle,
    /// The qdisc, class or hook it hangs off.
    pub parent: TcHandle,
    /// A filter's `tcm_info`: its priority and protocol.
    pub info: u32,
    /// A filter's chain.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub chain: Option<u32>,
    /// Its `TCA_OPTIONS`, as dumped, in hex: what a class or filter is
    /// put back with.
    #[cfg_attr(feature = "serde", serde(with = "hex"))]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    pub options: Vec<u8>,
    /// A qdisc, read back as a declaration: what it is put back as. A
    /// qdisc's dump is not always a request — HTB reports its version in
    /// a form its init refuses — so qdiscs go back through the typed path.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Option::is_none"))]
    pub spec: Option<crate::netlink::tc_spec::QdiscSpec>,
}

impl TcObject {
    pub(crate) fn from_live(m: &TcMessage) -> Self {
        Self {
            kind: m.kind().unwrap_or_default().to_string(),
            handle: m.handle(),
            parent: m.parent(),
            info: m.header.tcm_info,
            chain: m.chain,
            options: m.raw_options().unwrap_or_default().to_vec(),
            spec: None,
        }
    }

    /// A qdisc, if its kind reads back as a declaration
    /// ([`QdiscSpec::from_live`](crate::netlink::tc_spec::QdiscSpec)); one
    /// that does not cannot be put back, and still refuses the recreate.
    pub(crate) fn qdisc(m: &TcMessage) -> Option<Self> {
        Some(Self {
            spec: Some(crate::netlink::tc_spec::QdiscSpec::from_live(m)?),
            ..Self::from_live(m)
        })
    }
}

/// A device's undeclared TC tree, kept across its recreate (#645).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct PreservedTc {
    /// The device.
    pub dev: String,
    /// Its qdiscs: the root and hook qdiscs, and leaves in classes.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub qdiscs: Vec<TcObject>,
    /// Its classes.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub classes: Vec<TcObject>,
    /// Its filters.
    #[cfg_attr(feature = "serde", serde(default, skip_serializing_if = "Vec::is_empty"))]
    pub filters: Vec<TcObject>,
    /// The devices its mirred actions send to, by the ifindex they had:
    /// each is looked up again by name when the tree is put back. Written
    /// as `[ifindex, name]` pairs.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "BTreeMap::is_empty", with = "pairs")
    )]
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<(u32, String)>"))]
    pub targets: BTreeMap<u32, String>,
}

impl PreservedTc {
    /// How many objects it holds.
    pub fn len(&self) -> usize {
        self.qdiscs.len() + self.classes.len() + self.filters.len()
    }

    /// Whether it holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Display for PreservedTc {
    /// `2 qdiscs, 3 classes and 1 filter on eth0`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = |count: usize, one: &str, many: &str| {
            format!("{count} {}", if count == 1 { one } else { many })
        };
        write!(
            f,
            "{}, {} and {} on {}",
            n(self.qdiscs.len(), "qdisc", "qdiscs"),
            n(self.classes.len(), "class", "classes"),
            n(self.filters.len(), "filter", "filters"),
            self.dev
        )
    }
}

/// What a qdisc that goes has under it (#783): the classes, the qdiscs in
/// them and the filters that its replacement by another kind or handle, or
/// its deletion, destroys with it. An undo puts it back with
/// [`Step::RestoreTc`](super::Step::RestoreTc).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "kebab-case")
)]
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub enum Underneath {
    /// Nothing the kernel does not make with it.
    #[default]
    Nothing,
    /// The qdisc and the tree under it, read back whole: what the inverse
    /// puts back.
    Tree {
        /// The qdisc first, then its classes, qdiscs and filters.
        tree: Box<PreservedTc>,
    },
    /// Something under it that cannot be put back: the step has no
    /// inverse.
    Lost {
        /// What, and why.
        why: Vec<String>,
    },
}

impl Underneath {
    /// Whether it is [`Nothing`](Self::Nothing).
    pub fn is_nothing(&self) -> bool {
        *self == Self::Nothing
    }
}

/// What `root`, a root or hook qdisc on `dev`, has under it (#783): every
/// qdisc in its classes, transitively, the classes users make (a prio's
/// bands, an mq's queues and fq_codel's flows come back with their qdisc),
/// and the filters at any of them. `qdiscs` and `live` are the device's.
pub(crate) fn underneath(
    dev: &str,
    root: &TcMessage,
    qdiscs: &[TcMessage],
    live: &super::tc_tree::TcLive,
    names: &HashMap<u32, &str>,
) -> Underneath {
    let mut majors = vec![root.handle().major()];
    let mut nested: Vec<&TcMessage> = Vec::new();
    loop {
        let more: Vec<&TcMessage> = qdiscs
            .iter()
            .filter(|q| q.handle() != root.handle() && q.handle().major() != 0)
            .filter(|q| majors.contains(&q.parent().major()) && !majors.contains(&q.handle().major()))
            .collect();
        if more.is_empty() {
            break;
        }
        majors.extend(more.iter().map(|q| q.handle().major()));
        nested.extend(more);
    }
    let classes: Vec<&TcMessage> = live
        .classes
        .iter()
        .filter(|c| {
            majors.contains(&c.handle().major())
                && c.handle().minor() != 0
                && matches!(c.kind(), Some("htb" | "hfsc" | "drr" | "qfq" | "cbq"))
        })
        .collect();
    let filters: Vec<&TcMessage> = live
        .filters
        .iter()
        .filter(|f| majors.contains(&f.parent().major()) && !automatic_u32_table(f))
        .collect();
    if nested.is_empty() && classes.is_empty() && filters.is_empty() {
        return Underneath::Nothing;
    }
    let mut why = Vec::new();
    let mut tree = PreservedTc {
        dev: dev.to_string(),
        ..PreservedTc::default()
    };
    for q in std::iter::once(&root).chain(nested.iter()) {
        match TcObject::qdisc(q) {
            Some(o) => tree.qdiscs.push(o),
            None => why.push(format!(
                "qdisc {} {} on {dev}, which does not read back as a declaration",
                q.kind().unwrap_or("?"),
                q.handle()
            )),
        }
    }
    tree.classes = classes.into_iter().map(TcObject::from_live).collect();
    for f in filters {
        if !replayable_filter(f) {
            why.push(format!(
                "filter {} pref {} on {dev}, whose BPF program is named by id",
                f.kind().unwrap_or("?"),
                f.priority().as_u16()
            ));
            continue;
        }
        for target in mirred_targets(f) {
            match names.get(&target) {
                Some(n) => {
                    tree.targets.insert(target, n.to_string());
                }
                None => why.push(format!("a filter on {dev} redirects to ifindex {target}, which is gone")),
            }
        }
        tree.filters.push(TcObject::from_live(f));
    }
    if why.is_empty() {
        Underneath::Tree { tree: Box::new(tree) }
    } else {
        Underneath::Lost { why }
    }
}

/// A map as a list of pairs: a plan's steps are an internally tagged enum,
/// whose buffering does not read a number key back from its string.
#[cfg(feature = "serde")]
mod pairs {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(map: &BTreeMap<u32, String>, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(map.iter())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<u32, String>, D::Error> {
        Ok(Vec::<(u32, String)>::deserialize(d)?.into_iter().collect())
    }
}

#[cfg(feature = "serde")]
mod hex {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        s.serialize_str(&out)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(D::Error::custom("hex bytes come in pairs of digits"));
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(D::Error::custom))
            .collect()
    }
}

/// The attribute that holds a filter kind's actions.
fn act_attr(kind: &str) -> Option<u16> {
    use crate::netlink::types::tc::filter::{
        basic, bpf, cgroup, flow, flower, fw, matchall, route4, u32,
    };
    Some(match kind {
        "flower" => flower::TCA_FLOWER_ACT,
        "matchall" => matchall::TCA_MATCHALL_ACT,
        "fw" => fw::TCA_FW_ACT,
        "u32" => u32::TCA_U32_ACT,
        "basic" => basic::TCA_BASIC_ACT,
        "bpf" => bpf::TCA_BPF_ACT,
        "cgroup" => cgroup::TCA_CGROUP_ACT,
        "flow" => flow::TCA_FLOW_ACT,
        "route" => route4::TCA_ROUTE4_ACT,
        _ => return None,
    })
}

/// The kinds of the actions in a filter's options.
fn action_kinds(kind: &str, options: &[u8]) -> Vec<String> {
    use crate::netlink::types::tc::action::TCA_ACT_KIND;
    let Some(act) = act_attr(kind) else {
        return Vec::new();
    };
    AttrIter::new(options)
        .filter(|(t, _)| t & 0x7FFF == act)
        .flat_map(|(_, list)| AttrIter::new(list))
        .filter_map(|(_, slot)| {
            AttrIter::new(slot)
                .find(|(t, _)| t & 0x7FFF == TCA_ACT_KIND)
                .map(|(_, k)| String::from_utf8_lossy(k).trim_end_matches('\0').to_string())
        })
        .collect()
}

/// Whether a dumped filter can be replayed: not a BPF filter, and no BPF
/// action, whose dumps name their program by id where a request needs a
/// file descriptor.
pub(crate) fn replayable_filter(f: &TcMessage) -> bool {
    let kind = f.kind().unwrap_or_default();
    kind != "bpf"
        && !action_kinds(kind, f.raw_options().unwrap_or_default())
            .iter()
            .any(|k| k == "bpf")
}

/// A u32 hash table the kernel made itself with the filters at a
/// priority (`800:`, `801:`, …): put back with them, not on its own.
pub(crate) fn automatic_u32_table(f: &TcMessage) -> bool {
    let h = f.handle().as_raw();
    f.kind() == Some("u32") && h & 0x000F_FFFF == 0 && h >> 20 >= 0x800
}

/// The ifindexes a filter's mirred actions send to.
pub(crate) fn mirred_targets(f: &TcMessage) -> Vec<u32> {
    let kind = f.kind().unwrap_or_default();
    let mut out = Vec::new();
    for_each_action(kind, f.raw_options().unwrap_or_default(), |kind, options| {
        if kind == "mirred"
            && let Some(m) = mirred_parms(options)
        {
            out.push(m.ifindex);
        }
    });
    out
}

fn mirred_parms(options: &[u8]) -> Option<crate::netlink::types::tc::action::mirred::TcMirred> {
    use crate::netlink::types::tc::action::mirred::{TCA_MIRRED_PARMS, TcMirred};
    use zerocopy::FromBytes;
    let (_, p) = AttrIter::new(options).find(|(t, _)| t & 0x7FFF == TCA_MIRRED_PARMS)?;
    TcMirred::read_from_prefix(p).ok().map(|(m, _)| m)
}

/// Call `f` with each action's kind and options in a filter's options.
fn for_each_action(kind: &str, options: &[u8], mut f: impl FnMut(&str, &[u8])) {
    use crate::netlink::types::tc::action::{TCA_ACT_KIND, TCA_ACT_OPTIONS};
    let Some(act) = act_attr(kind) else {
        return;
    };
    for (_, list) in AttrIter::new(options).filter(|(t, _)| t & 0x7FFF == act) {
        for (_, slot) in AttrIter::new(list) {
            let mut kind = String::new();
            let mut opts: &[u8] = &[];
            for (t, p) in AttrIter::new(slot) {
                match t & 0x7FFF {
                    TCA_ACT_KIND => {
                        kind = String::from_utf8_lossy(p).trim_end_matches('\0').to_string();
                    }
                    TCA_ACT_OPTIONS => opts = p,
                    _ => {}
                }
            }
            f(&kind, opts);
        }
    }
}

/// The attributes of an action's options that a dump adds and a request
/// does not take: its timestamps and padding.
fn dump_only(kind: &str) -> &'static [u16] {
    use crate::netlink::types::tc::action::{
        connmark, csum, ct, ctinfo, gact, gate, ife, mirred, mpls, nat, pedit, police, sample,
        simple_act, skbedit, skbmod, tunnel_key, vlan,
    };
    match kind {
        "gact" => &[gact::TCA_GACT_TM, gact::TCA_GACT_PAD],
        "mirred" => &[mirred::TCA_MIRRED_TM, mirred::TCA_MIRRED_PAD],
        "police" => &[police::TCA_POLICE_TM, police::TCA_POLICE_PAD],
        "vlan" => &[vlan::TCA_VLAN_TM, vlan::TCA_VLAN_PAD],
        "mpls" => &[mpls::TCA_MPLS_TM, mpls::TCA_MPLS_PAD],
        "skbmod" => &[skbmod::TCA_SKBMOD_TM, skbmod::TCA_SKBMOD_PAD],
        "skbedit" => &[skbedit::TCA_SKBEDIT_TM, skbedit::TCA_SKBEDIT_PAD],
        "nat" => &[nat::TCA_NAT_TM, nat::TCA_NAT_PAD],
        "tunnel_key" => &[tunnel_key::TCA_TUNNEL_KEY_TM, tunnel_key::TCA_TUNNEL_KEY_PAD],
        "connmark" => &[connmark::TCA_CONNMARK_TM, connmark::TCA_CONNMARK_PAD],
        "ctinfo" => &[ctinfo::TCA_CTINFO_TM, ctinfo::TCA_CTINFO_PAD],
        "ife" => &[ife::TCA_IFE_TM, ife::TCA_IFE_PAD],
        "gate" => &[gate::TCA_GATE_TM, gate::TCA_GATE_PAD],
        "csum" => &[csum::TCA_CSUM_TM, csum::TCA_CSUM_PAD],
        "sample" => &[sample::TCA_SAMPLE_TM, sample::TCA_SAMPLE_PAD],
        "ct" => &[ct::TCA_CT_TM, ct::TCA_CT_PAD],
        "pedit" => &[pedit::TCA_PEDIT_TM, pedit::TCA_PEDIT_PAD],
        "simple" => &[simple_act::TCA_DEF_TM, simple_act::TCA_DEF_PAD],
        _ => &[],
    }
}

/// A filter kind's flags attribute, which a dump fills with status bits
/// (`not_in_hw`, `in_hw`) that a request refuses, and the attributes only
/// a dump has (its offload count, packet counters).
fn filter_dump_fixups(kind: &str) -> (Option<u16>, &'static [u16]) {
    use crate::netlink::types::tc::filter::{flower, matchall, u32};
    match kind {
        "flower" => (Some(flower::TCA_FLOWER_FLAGS), &[flower::TCA_FLOWER_IN_HW_COUNT]),
        "matchall" => (
            Some(matchall::TCA_MATCHALL_FLAGS),
            &[matchall::TCA_MATCHALL_PCNT, matchall::TCA_MATCHALL_PAD],
        ),
        "u32" => (Some(u32::TCA_U32_FLAGS), &[u32::TCA_U32_PCNT, u32::TCA_U32_PAD]),
        _ => (None, &[]),
    }
}

/// A dumped filter's options as a request: its flags without the status
/// bits a dump adds, none of the attributes only a dump has, each action
/// without what the dump adds (its index, statistics, timestamps), and a
/// mirred action's target through `remap`.
fn request_options(kind: &str, options: &[u8], remap: &HashMap<u32, u32>) -> Vec<u8> {
    use crate::netlink::types::tc::action::{
        TCA_ACT_COOKIE, TCA_ACT_FLAGS, TCA_ACT_HW_STATS, TCA_ACT_KIND, TCA_ACT_OPTIONS,
        mirred::TCA_MIRRED_PARMS,
    };
    use crate::netlink::types::tc::filter::flower::{TCA_CLS_FLAGS_SKIP_HW, TCA_CLS_FLAGS_SKIP_SW};
    let act = act_attr(kind);
    let (flags_attr, dump_only_attrs) = filter_dump_fixups(kind);
    let mut b = MessageBuilder::new(0, 0);
    let start = b.len();
    for (ty, payload) in AttrIter::new(options) {
        let id = ty & 0x7FFF;
        if dump_only_attrs.contains(&id) {
            continue;
        }
        if Some(id) == flags_attr
            && let Some(bytes) = payload.get(..4)
        {
            let flags = u32::from_ne_bytes(bytes.try_into().unwrap());
            b.append_attr_u32(id, flags & (TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_SKIP_SW));
            continue;
        }
        if Some(id) != act {
            b.append_attr(ty, payload);
            continue;
        }
        let list = b.nest_start(ty & 0x7FFF);
        for (slot_ty, slot) in AttrIter::new(payload) {
            let one = b.nest_start(slot_ty & 0x7FFF);
            let action_kind = AttrIter::new(slot)
                .find(|(t, _)| t & 0x7FFF == TCA_ACT_KIND)
                .map(|(_, k)| String::from_utf8_lossy(k).trim_end_matches('\0').to_string())
                .unwrap_or_default();
            for (t, p) in AttrIter::new(slot) {
                match t & 0x7FFF {
                    TCA_ACT_KIND | TCA_ACT_COOKIE | TCA_ACT_FLAGS | TCA_ACT_HW_STATS => {
                        b.append_attr(t & 0x7FFF, p);
                    }
                    TCA_ACT_OPTIONS => {
                        let opts = b.nest_start(TCA_ACT_OPTIONS);
                        let skip = dump_only(&action_kind);
                        for (ot, op) in AttrIter::new(p) {
                            let id = ot & 0x7FFF;
                            if skip.contains(&id) {
                                continue;
                            }
                            if action_kind == "mirred" && id == TCA_MIRRED_PARMS {
                                let mut m = mirred_parms(p).expect("found just now");
                                if let Some(&to) = remap.get(&m.ifindex) {
                                    m.ifindex = to;
                                }
                                let mut bytes = op.to_vec();
                                let parms = m.as_bytes();
                                bytes[..parms.len()].copy_from_slice(parms);
                                b.append_attr(ot, &bytes);
                            } else {
                                b.append_attr(ot, op);
                            }
                        }
                        b.nest_end(opts);
                    }
                    // Its index, statistics and what hardware did with it
                    // are the dump's.
                    _ => {}
                }
            }
            b.nest_end(one);
        }
        b.nest_end(list);
    }
    b.as_bytes()[start..].to_vec()
}

/// Send one object back.
async fn put_back(
    conn: &Connection<Route>,
    msg_type: u16,
    replace: bool,
    ifindex: u32,
    o: &TcObject,
    options: &[u8],
) -> Result<()> {
    let tcmsg = TcMsg::new()
        .with_ifindex(ifindex as i32)
        .with_parent(o.parent.as_raw())
        .with_handle(o.handle.as_raw())
        .with_info(o.info);
    let mut b = if replace {
        replace_request(msg_type)
    } else {
        create_request(msg_type)
    };
    b.append(&tcmsg);
    b.append_attr_str(TcaAttr::Kind as u16, &o.kind);
    if let Some(chain) = o.chain {
        b.append_attr_u32(TcaAttr::Chain as u16, chain);
    }
    if !options.is_empty() {
        let opts = b.nest_start(TcaAttr::Options as u16);
        b.append_bytes(options);
        b.nest_end(opts);
    }
    conn.send_ack(b).await
}

/// Put a preserved tree back on its device, now created again: the root
/// and hook qdiscs, then classes and the qdiscs in them parent first, then
/// filters. The number of objects.
pub(crate) async fn restore(conn: &Connection<Route>, tree: &PreservedTc) -> Result<usize> {
    let ifindex = conn
        .get_link_by_name(&tree.dev)
        .await?
        .ok_or_else(|| conn.interface_not_found(&tree.dev))?
        .ifindex();
    let mut remap = HashMap::new();
    for (old, name) in &tree.targets {
        let now = conn
            .get_link_by_name(name)
            .await?
            .ok_or_else(|| conn.interface_not_found(name).with_context("mirred target"))?
            .ifindex();
        remap.insert(*old, now);
    }
    let context = |what: &str, o: &TcObject| {
        format!("restore {what} {} {} under {} on {}", o.kind, o.handle, o.parent, tree.dev)
    };

    // Qdiscs and classes, each once what it hangs off is there.
    let hooks = |p: TcHandle| p.is_root() || p.is_ingress() || p == TcHandle::CLSACT;
    let mut there: Vec<TcHandle> = Vec::new();
    let mut pending: Vec<(bool, &TcObject)> = tree
        .qdiscs
        .iter()
        .map(|q| (true, q))
        .chain(tree.classes.iter().map(|c| (false, c)))
        .collect();
    let mut count = 0;
    while !pending.is_empty() {
        let (ready, waiting): (Vec<_>, Vec<_>) = pending.into_iter().partition(|(qdisc, o)| {
            if *qdisc {
                hooks(o.parent) || there.contains(&o.parent)
            } else {
                // A class belongs to the qdisc of its own major; HTB reports
                // a top class's parent as the root, which the kernel takes
                // back as that.
                there.contains(&TcHandle::major_only(o.handle.major()))
                    && (o.parent.is_root() || o.parent.minor() == 0 || there.contains(&o.parent))
            }
        });
        if ready.is_empty() {
            let (qdisc, o) = waiting[0];
            return Err(Error::invalid_message(format!(
                "{}: what it hangs off is not there",
                context(if qdisc { "qdisc" } else { "class" }, o)
            )));
        }
        for (qdisc, o) in ready {
            if qdisc {
                let spec = o.spec.clone().ok_or_else(|| {
                    Error::invalid_message(format!(
                        "{}: no declaration to put it back as",
                        context("qdisc", o)
                    ))
                })?;
                // The root and hooks replace what the kernel put there with
                // the link.
                let put = if hooks(o.parent) {
                    conn.replace_qdisc_by_index_full(ifindex, o.parent, Some(o.handle), spec)
                        .await
                } else {
                    conn.add_qdisc_by_index_full(ifindex, o.parent, Some(o.handle), spec)
                        .await
                };
                put.map_err(|e| e.with_context(context("qdisc", o)))?;
            } else {
                put_back(conn, NlMsgType::RTM_NEWTCLASS, false, ifindex, o, &o.options)
                    .await
                    .map_err(|e| e.with_context(context("class", o)))?;
            }
            there.push(o.handle);
            count += 1;
        }
        pending = waiting;
    }
    for f in &tree.filters {
        let options = request_options(&f.kind, &f.options, &remap);
        put_back(conn, NlMsgType::RTM_NEWTFILTER, false, ifindex, f, &options)
            .await
            .map_err(|e| e.with_context(context("filter", f)))?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{
        action::{ActionList, GactAction, MirredAction},
        filter::{FilterConfig, FlowerFilter},
        types::tc::{
            action::{self as act, mirred},
            filter::flower,
        },
    };

    /// A flower filter's options as a dump has them: the flags with
    /// `not_in_hw`, the offload count, and each action with its index,
    /// statistics and timestamps.
    fn dumped_flower(target: u32) -> Vec<u8> {
        let mut f = FlowerFilter::new().ip_proto_tcp().dst_port(22).actions(
            ActionList::new()
                .with(MirredAction::mirror_to_egress(target))
                .with(GactAction::pipe()),
        );
        f.set_protocol(crate::EthProto::IP);
        let mut written = MessageBuilder::new(0, 0);
        let start = written.len();
        f.write_options(&mut written).unwrap();
        let written = written.as_bytes()[start..].to_vec();

        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        b.append_attr_u32(flower::TCA_FLOWER_FLAGS, 0x8 | flower::TCA_CLS_FLAGS_SKIP_HW);
        b.append_attr_u32(flower::TCA_FLOWER_IN_HW_COUNT, 0);
        for (t, p) in AttrIter::new(&written) {
            if t & 0x7FFF != flower::TCA_FLOWER_ACT {
                b.append_attr(t, p);
                continue;
            }
            let list = b.nest_start(flower::TCA_FLOWER_ACT);
            for (slot_t, slot) in AttrIter::new(p) {
                let one = b.nest_start(slot_t & 0x7FFF);
                b.append_attr_u32(act::TCA_ACT_INDEX, 3);
                let stats = b.nest_start(act::TCA_ACT_STATS);
                b.append_attr(1, &[0; 8]);
                b.nest_end(stats);
                for (t, p) in AttrIter::new(slot) {
                    if t & 0x7FFF == act::TCA_ACT_OPTIONS {
                        let opts = b.nest_start(act::TCA_ACT_OPTIONS);
                        b.append_attr(mirred::TCA_MIRRED_TM, &[0; 32]);
                        for (ot, op) in AttrIter::new(p) {
                            b.append_attr(ot, op);
                        }
                        b.nest_end(opts);
                    } else {
                        b.append_attr(t, p);
                    }
                }
                b.nest_end(one);
            }
            b.nest_end(list);
        }
        b.as_bytes()[start..].to_vec()
    }

    #[test]
    fn a_dumped_filter_becomes_a_request() {
        let req = request_options("flower", &dumped_flower(7), &HashMap::from([(7, 9)]));
        let attrs: Vec<(u16, &[u8])> = AttrIter::new(&req).map(|(t, p)| (t & 0x7FFF, p)).collect();
        assert!(!attrs.iter().any(|(t, _)| *t == flower::TCA_FLOWER_IN_HW_COUNT));
        let flags = attrs.iter().find(|(t, _)| *t == flower::TCA_FLOWER_FLAGS).unwrap().1;
        assert_eq!(
            u32::from_ne_bytes(flags.try_into().unwrap()),
            flower::TCA_CLS_FLAGS_SKIP_HW,
            "the status bit is the dump's"
        );
        let actions = attrs.iter().find(|(t, _)| *t == flower::TCA_FLOWER_ACT).unwrap().1;
        let slots: Vec<&[u8]> = AttrIter::new(actions).map(|(_, s)| s).collect();
        assert_eq!(slots.len(), 2);
        for slot in &slots {
            let ids: Vec<u16> = AttrIter::new(slot).map(|(t, _)| t & 0x7FFF).collect();
            assert!(!ids.contains(&act::TCA_ACT_INDEX) && !ids.contains(&act::TCA_ACT_STATS), "{ids:?}");
        }
        let (_, mirred_opts) = AttrIter::new(slots[0])
            .find(|(t, _)| t & 0x7FFF == act::TCA_ACT_OPTIONS)
            .unwrap();
        assert!(!AttrIter::new(mirred_opts).any(|(t, _)| t & 0x7FFF == mirred::TCA_MIRRED_TM));
        assert_eq!(mirred_parms(mirred_opts).unwrap().ifindex, 9, "the target looked up again");
    }

    #[test]
    fn what_is_kept_and_what_still_refuses() {
        let filter = |kind: &str, handle: u32, options: Vec<u8>| {
            let mut m = TcMessage {
                kind: Some(kind.to_string()),
                options: Some(options),
                ..TcMessage::default()
            };
            m.header.tcm_handle = handle;
            m
        };
        let flower = filter("flower", 1, dumped_flower(7));
        assert!(replayable_filter(&flower));
        assert_eq!(mirred_targets(&flower), [7]);
        assert!(!replayable_filter(&filter("bpf", 1, Vec::new())), "a BPF program by id");
        // u32's own tables come back with its filters; one a user made does not.
        assert!(automatic_u32_table(&filter("u32", 0x8000_0000, Vec::new())));
        assert!(!automatic_u32_table(&filter("u32", 0x8000_0800, Vec::new())));
        assert!(!automatic_u32_table(&filter("u32", 0x0020_0000, Vec::new())));

        let tc = PreservedTc {
            dev: "v0".into(),
            qdiscs: vec![TcObject::from_live(&flower)],
            filters: vec![TcObject::from_live(&flower); 2],
            ..PreservedTc::default()
        };
        assert_eq!(tc.to_string(), "1 qdisc, 0 classes and 2 filters on v0");
        assert_eq!(tc.len(), 3);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_kept_tree_reads_back() {
        let mut m = TcMessage {
            kind: Some("netem".to_string()),
            options: Some(vec![0xde, 0xad, 0x01]),
            ..TcMessage::default()
        };
        m.header.tcm_handle = TcHandle::major_only(1).as_raw();
        let tc = PreservedTc {
            dev: "v0".into(),
            qdiscs: vec![TcObject {
                spec: Some(crate::netlink::tc_spec::QdiscSpec::Clsact),
                ..TcObject::from_live(&m)
            }],
            targets: BTreeMap::from([(7, "ifb0".to_string())]),
            ..PreservedTc::default()
        };
        let json = serde_json::to_string(&tc).unwrap();
        assert!(json.contains(r#""options":"dead01""#), "{json}");
        let back: PreservedTc = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tc);
        let plan = super::super::Plan::new(vec![super::super::Step::RestoreTc(tc)]);
        let json = serde_json::to_string(&plan).unwrap();
        let back: super::super::Plan = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        assert!(serde_json::from_str::<PreservedTc>(r#"{"dev":"v0","qdiscs":[{"kind":"x","handle":0,"parent":0,"info":0,"options":"abc"}]}"#).is_err());
    }
}
