//! A declared TC tree in JSON and YAML (#645).
//!
//! Each class, filter and action is its kind and the tokens its
//! `parse_params` reads — the tc(8) words — written by its `to_params`, so a
//! tree reads back as the one written:
//!
//! ```yaml
//! tc:
//!   - dev: eth0
//!     classes:
//!       - { parent: "1:", id: "1:10", kind: htb, params: rate 60mbit ceil 100mbit }
//!     leaves:
//!       - { class: "1:10", handle: "10:", qdisc: { fq_codel: {} } }
//!     filters:
//!       - parent: "1:"
//!         priority: 1
//!         protocol: ip
//!         kind: flower
//!         params: ip_proto tcp dst_port 22 classid 1:10
//!         actions:
//!           - { kind: mirred, params: egress mirror dev ifb0 }
//!       - { parent: "ffff:", priority: 100, protocol: all, redirect-to: ifb0 }
//! ```
//!
//! `params` is one line of words, or a list of them where a word has a
//! space in it. Handles are written as tc(8) writes them (`"1:10"`), and so
//! are protocols (`ip`, `0x88cc`).

use serde::{Deserialize, Serialize, de::Error as _, ser::Error as _};

use super::tc_tree::{
    ClassSpec, DeclaredClass, DeclaredFilter, DeclaredLeaf, DeclaredTc, FilterSpec, TcTreeDiff,
};
use crate::netlink::{
    action::{ActionList, Estimator, action_from_params},
    error::{Error, Result},
    eth_proto::EthProto,
    filter::{FlowerFilter, FwFilter, MatchallFilter, U32Filter},
    tc::{DrrClassConfig, HfscClassConfig, HtbClassConfig, QfqClassConfig},
    tc_handle::{FilterPriority, TcHandle},
    tc_spec::QdiscSpec,
};

/// The words of a class, filter or action: one line, or a list where a
/// word has a space in it.
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(untagged)]
enum Params {
    Line(String),
    Words(Vec<String>),
}

impl Params {
    /// `None` for no words.
    fn from_words(words: Vec<String>) -> Option<Self> {
        if words.is_empty() {
            None
        } else if words.iter().any(|w| w.is_empty() || w.contains(char::is_whitespace)) {
            Some(Self::Words(words))
        } else {
            Some(Self::Line(words.join(" ")))
        }
    }

    fn words(p: Option<&Self>) -> Vec<&str> {
        match p {
            None => Vec::new(),
            Some(Self::Line(l)) => l.split_whitespace().collect(),
            Some(Self::Words(w)) => w.iter().map(String::as_str).collect(),
        }
    }
}

/// A `TcHandle` as tc(8) writes it.
mod handle {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(h: &TcHandle, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(h)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<TcHandle, D::Error> {
        String::deserialize(d)?.parse().map_err(D::Error::custom)
    }
}

/// An `EthProto` as tc(8) writes it.
mod proto {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(p: &EthProto, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(p)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<EthProto, D::Error> {
        String::deserialize(d)?.parse().map_err(D::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(super) struct TcRepr {
    dev: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    classes: Vec<ClassRepr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    leaves: Vec<LeafRepr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    filters: Vec<FilterRepr>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ClassRepr {
    /// The qdisc (`1:`) or class (`1:1`) it hangs under.
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    parent: TcHandle,
    /// Its handle (`1:10`).
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    id: TcHandle,
    /// `htb`, `hfsc`, `drr` or `qfq`.
    kind: String,
    /// tc(8)'s words for its parameters: `rate 60mbit ceil 100mbit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<Params>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct LeafRepr {
    /// The class it sits in.
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    class: TcHandle,
    /// Its handle (`10:`).
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    handle: TcHandle,
    qdisc: QdiscSpec,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct FilterRepr {
    /// The qdisc or hook it hangs off (`1:`, `ffff:`).
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    parent: TcHandle,
    priority: u16,
    /// `ip`, `ipv6`, `all`, `802.1q`, or a number (`0x88cc`).
    #[serde(with = "proto")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    protocol: EthProto,
    /// `flower`, `matchall`, `fw` or `u32`; absent for a `redirect-to`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    /// tc(8)'s words for its keys: `ip_proto tcp dst_port 22 classid 1:10`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<Params>,
    /// A flower's or matchall's actions, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    actions: Vec<ActionRepr>,
    /// The actions' rate estimator, tc(8)'s `<interval> <time constant>`
    /// (`1s 8s`), which a police `avrate` needs (#792).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    estimator: Option<String>,
    /// Everything, redirected out of this device (the IFB redirect).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    redirect_to: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ActionRepr {
    /// `mirred`, `gact`, `police`, …
    kind: String,
    /// tc(8)'s words for it: `egress redirect dev ifb0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    params: Option<Params>,
}

/// A filter's own key, for a removal.
#[derive(Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
struct FilterKeyRepr {
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    parent: TcHandle,
    /// tc(8) `chain`, when not 0 (#793).
    #[serde(skip_serializing_if = "is_zero")]
    chain: u32,
    priority: u16,
    #[serde(with = "proto")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    protocol: EthProto,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// A leaf's own key, for a removal.
#[derive(Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
struct LeafKeyRepr {
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    class: TcHandle,
    #[serde(with = "handle")]
    #[cfg_attr(feature = "schemars", schemars(with = "String"))]
    handle: TcHandle,
}

#[derive(Serialize)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub(super) struct TcTreeDiffRepr {
    dev: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    classes_to_add: Vec<ClassRepr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    classes_to_change: Vec<ClassRepr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schemars", schemars(with = "Vec<String>"))]
    classes_to_remove: Vec<HandleStr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    leaves_to_set: Vec<LeafRepr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    leaves_to_remove: Vec<LeafKeyRepr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    filters_to_set: Vec<FilterRepr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    filters_to_remove: Vec<FilterKeyRepr>,
}

/// A handle serialized as tc(8) writes it.
struct HandleStr(TcHandle);

impl Serialize for HandleStr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        handle::serialize(&self.0, s)
    }
}

fn invalid(what: impl std::fmt::Display) -> Error {
    Error::invalid_message(what.to_string())
}

impl TryFrom<&DeclaredClass> for ClassRepr {
    type Error = Error;
    fn try_from(c: &DeclaredClass) -> Result<Self> {
        let words = match &c.spec {
            ClassSpec::Htb(h) => h.to_params(),
            ClassSpec::Hfsc(h) => h.to_params(),
            ClassSpec::Drr(d) => d.to_params(),
            ClassSpec::Qfq(q) => q.to_params(),
        }
        .map_err(|e| e.with_context(format!("class {}", c.id)))?;
        Ok(Self {
            parent: c.parent,
            id: c.id,
            kind: c.spec.kind().to_string(),
            params: Params::from_words(words),
        })
    }
}

impl TryFrom<ClassRepr> for DeclaredClass {
    type Error = Error;
    fn try_from(r: ClassRepr) -> Result<Self> {
        if r.id.minor() == 0 {
            return Err(invalid(format!("class {}: a class handle has a minor (`1:10`)", r.id)));
        }
        let words = Params::words(r.params.as_ref());
        let spec = match r.kind.as_str() {
            "htb" => ClassSpec::Htb(HtbClassConfig::parse_params(&words)?),
            "hfsc" => ClassSpec::Hfsc(HfscClassConfig::parse_params(&words)?),
            "drr" => ClassSpec::Drr(DrrClassConfig::parse_params(&words)?),
            "qfq" => ClassSpec::Qfq(QfqClassConfig::parse_params(&words)?),
            other => {
                return Err(invalid(format!(
                    "class {}: kind `{other}` (expected htb, hfsc, drr or qfq)",
                    r.id
                )));
            }
        };
        Ok(Self {
            parent: r.parent,
            id: r.id,
            spec,
        })
    }
}

impl From<&DeclaredLeaf> for LeafRepr {
    fn from(l: &DeclaredLeaf) -> Self {
        Self {
            class: l.class,
            handle: l.handle,
            qdisc: l.spec.clone(),
        }
    }
}

impl From<LeafRepr> for DeclaredLeaf {
    fn from(r: LeafRepr) -> Self {
        Self {
            class: r.class,
            handle: r.handle,
            spec: r.qdisc,
        }
    }
}

impl TryFrom<&DeclaredFilter> for FilterRepr {
    type Error = Error;
    fn try_from(f: &DeclaredFilter) -> Result<Self> {
        let at = || {
            format!(
                "filter at {} prio {} {}",
                f.parent, f.priority, f.protocol
            )
        };
        let mut repr = Self {
            parent: f.parent,
            priority: f.priority.as_u16(),
            protocol: f.protocol,
            kind: Some(f.spec.kind().to_string()),
            params: None,
            actions: Vec::new(),
            estimator: None,
            redirect_to: None,
        };
        let (words, actions) = match &f.spec {
            FilterSpec::Flower(x) => (x.to_params(), x.action_list()),
            FilterSpec::Matchall(x) => (x.to_params(), x.action_list()),
            FilterSpec::Fw(x) => (x.to_params(), None),
            FilterSpec::U32(x) => (x.to_params(), None),
            FilterSpec::RedirectTo(dev) => {
                repr.kind = None;
                repr.redirect_to = Some(dev.clone());
                return Ok(repr);
            }
        };
        repr.params = Params::from_words(words.map_err(|e| e.with_context(at()))?);
        if let Some(list) = actions {
            repr.estimator = list.estimator().map(|e| e.to_string());
            repr.actions = list
                .to_params()
                .map_err(|e| e.with_context(at()))?
                .into_iter()
                .map(|(kind, words)| ActionRepr {
                    kind: kind.to_string(),
                    params: Params::from_words(words),
                })
                .collect();
        }
        Ok(repr)
    }
}

impl TryFrom<FilterRepr> for DeclaredFilter {
    type Error = Error;
    fn try_from(r: FilterRepr) -> Result<Self> {
        let at = format!("filter at {} prio {} {}", r.parent, r.priority, r.protocol);
        let words = Params::words(r.params.as_ref());
        let actions = || -> Result<Option<ActionList>> {
            if r.actions.is_empty() {
                return match &r.estimator {
                    Some(_) => Err(invalid(format!(
                        "{at}: an `estimator` is for the filter's actions, and it has none"
                    ))),
                    None => Ok(None),
                };
            }
            let list = match &r.estimator {
                Some(words) => ActionList::new()
                    .with_estimator(Estimator::parse_params(&words.split_whitespace().collect::<Vec<_>>())?),
                None => ActionList::new(),
            };
            r.actions
                .iter()
                .try_fold(list, |list, a| {
                    Ok(list.with_boxed(action_from_params(&a.kind, &Params::words(a.params.as_ref()))?))
                })
                .map(Some)
        };
        let spec = match (r.kind.as_deref(), &r.redirect_to) {
            (None, Some(dev)) if r.params.is_none() && r.actions.is_empty() && r.estimator.is_none() => {
                FilterSpec::RedirectTo(dev.clone())
            }
            (Some(_), Some(_)) | (None, Some(_)) => {
                return Err(invalid(format!(
                    "{at}: `redirect-to` is a filter of its own, without kind, params, actions or estimator"
                )));
            }
            (None, None) => return Err(invalid(format!("{at}: a `kind` or a `redirect-to`"))),
            (Some("flower"), None) => {
                let f = FlowerFilter::parse_params(&words)?;
                FilterSpec::Flower(match actions()? {
                    Some(list) => f.actions(list),
                    None => f,
                })
            }
            (Some("matchall"), None) => {
                let f = MatchallFilter::parse_params(&words)?;
                FilterSpec::Matchall(match actions()? {
                    Some(list) => f.actions(list),
                    None => f,
                })
            }
            (Some(kind @ ("fw" | "u32")), None) => {
                if !r.actions.is_empty() || r.estimator.is_some() {
                    return Err(invalid(format!("{at}: a {kind} filter carries no actions")));
                }
                if kind == "fw" {
                    FilterSpec::Fw(FwFilter::parse_params(&words)?)
                } else {
                    FilterSpec::U32(U32Filter::parse_params(&words)?)
                }
            }
            (Some(other), None) => {
                return Err(invalid(format!(
                    "{at}: kind `{other}` (expected flower, matchall, fw or u32)"
                )));
            }
        };
        Ok(Self {
            parent: r.parent,
            priority: FilterPriority::new(r.priority),
            protocol: r.protocol,
            spec,
        })
    }
}

impl TryFrom<&DeclaredTc> for TcRepr {
    type Error = Error;
    fn try_from(t: &DeclaredTc) -> Result<Self> {
        let dev = |e: Error| e.with_context(format!("tc {}", t.dev));
        Ok(Self {
            dev: t.dev.clone(),
            classes: t.classes.iter().map(ClassRepr::try_from).collect::<Result<_>>().map_err(dev)?,
            leaves: t.leaves.iter().map(LeafRepr::from).collect(),
            filters: t.filters.iter().map(FilterRepr::try_from).collect::<Result<_>>().map_err(dev)?,
        })
    }
}

impl TryFrom<TcRepr> for DeclaredTc {
    type Error = Error;
    fn try_from(r: TcRepr) -> Result<Self> {
        let context = format!("tc {}", r.dev);
        let dev = |e: Error| e.with_context(context.clone());
        Ok(Self {
            classes: r.classes.into_iter().map(DeclaredClass::try_from).collect::<Result<_>>().map_err(dev)?,
            leaves: r.leaves.into_iter().map(DeclaredLeaf::from).collect(),
            filters: r.filters.into_iter().map(DeclaredFilter::try_from).collect::<Result<_>>().map_err(dev)?,
            dev: r.dev,
        })
    }
}

impl Serialize for DeclaredTc {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        TcRepr::try_from(self).map_err(S::Error::custom)?.serialize(s)
    }
}

impl<'de> Deserialize<'de> for DeclaredTc {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        TcRepr::deserialize(d)?.try_into().map_err(D::Error::custom)
    }
}

impl TryFrom<&TcTreeDiff> for TcTreeDiffRepr {
    type Error = Error;
    fn try_from(d: &TcTreeDiff) -> Result<Self> {
        let classes = |cs: &[DeclaredClass]| cs.iter().map(ClassRepr::try_from).collect::<Result<_>>();
        Ok(Self {
            dev: d.dev.clone(),
            classes_to_add: classes(&d.classes_to_add)?,
            classes_to_change: classes(&d.classes_to_change)?,
            classes_to_remove: d.classes_to_remove.iter().copied().map(HandleStr).collect(),
            leaves_to_set: d.leaves_to_set.iter().map(LeafRepr::from).collect(),
            leaves_to_remove: d
                .leaves_to_remove
                .iter()
                .map(|&(class, handle)| LeafKeyRepr { class, handle })
                .collect(),
            filters_to_set: d.filters_to_set.iter().map(FilterRepr::try_from).collect::<Result<_>>()?,
            filters_to_remove: d
                .filters_to_remove
                .iter()
                .map(|k| FilterKeyRepr {
                    parent: k.parent,
                    chain: k.chain,
                    priority: k.priority.as_u16(),
                    protocol: k.protocol,
                })
                .collect(),
        })
    }
}

impl Serialize for TcTreeDiff {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        TcTreeDiffRepr::try_from(self).map_err(S::Error::custom)?.serialize(s)
    }
}

#[cfg(feature = "schemars")]
mod schema {
    use super::*;

    macro_rules! schema_of {
        ($ty:ty => $repr:ty) => {
            impl schemars::JsonSchema for $ty {
                fn schema_name() -> std::borrow::Cow<'static, str> {
                    <$repr>::schema_name()
                }
                fn schema_id() -> std::borrow::Cow<'static, str> {
                    <$repr>::schema_id()
                }
                fn json_schema(g: &mut schemars::SchemaGenerator) -> schemars::Schema {
                    <$repr>::json_schema(g)
                }
                fn inline_schema() -> bool {
                    <$repr>::inline_schema()
                }
            }
        };
    }
    schema_of!(DeclaredTc => TcRepr);
    schema_of!(TcTreeDiff => TcTreeDiffRepr);
}

#[cfg(test)]
mod tests {
    use crate::netlink::{
        action::{ActionList, GactAction, MirredAction},
        config::NetworkConfig,
        filter::{FlowerFilter, FwFilter, MatchallFilter, U32Filter},
        tc::{FqCodelConfig, HfscClassConfig, HtbClassConfig, TcServiceCurve},
    };
    use crate::{EthProto, FilterPriority, Rate, TcHandle};

    fn h(major: u16, minor: u16) -> TcHandle {
        TcHandle::new(major, minor)
    }

    fn tree() -> NetworkConfig {
        NetworkConfig::new()
            .qdisc("d0", |q| q.htb().default_class(0x20))
            .qdisc("d0", |q| q.clsact())
            .tc("d0", |t| {
                t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(100)))
                    .class(h(1, 1), h(1, 0x10), HtbClassConfig::new(Rate::mbit(60)).ceil(Rate::mbit(100)))
                    .leaf(h(1, 0x10), h(0x10, 0), FqCodelConfig::new())
                    .filter(
                        h(1, 0),
                        FilterPriority::new(1),
                        EthProto::IP,
                        FlowerFilter::new().ip_proto_tcp().dst_port(22).classid(h(1, 0x10)).actions(
                            ActionList::new()
                                .with(MirredAction::mirror_to_egress(0).to_dev("ifb0"))
                                .with(GactAction::pass()),
                        ),
                    )
                    .filter(h(1, 0), FilterPriority::new(2), EthProto::ALL, MatchallFilter::new().classid(h(1, 0x10)))
                    .filter(h(1, 0), FilterPriority::new(3), EthProto::IP, FwFilter::new().classid(h(1, 1)).mask(0xff))
                    .filter(
                        h(1, 0),
                        FilterPriority::new(4),
                        EthProto::IP,
                        U32Filter::parse_params(&["match", "ip", "dst", "10.0.0.0/8", "classid", "1:10"]).unwrap(),
                    )
                    .redirect_ingress_to("ifb0")
            })
    }

    /// #645: a tree is written as kinds and tc(8)'s words, and reads back
    /// as the tree written.
    #[test]
    fn a_tree_reads_back_as_written() {
        let cfg = tree();
        let json = cfg.to_json_string().unwrap();
        for want in [
            r#""classes":[{"parent":"1:","id":"1:1","kind":"htb","params":"rate 100mbit"}"#,
            r#""leaves":[{"class":"1:10","handle":"10:","qdisc":{"fq_codel":{}}}]"#,
            r#""kind":"flower","params":"classid 1:10 ip_proto tcp dst_port 22","actions":[{"kind":"mirred","params":"egress mirror dev ifb0"},{"kind":"gact","params":"pass"}]"#,
            r#""parent":"clsact-ingress","priority":100,"protocol":"all","redirect-to":"ifb0""#,
        ] {
            assert!(json.contains(want), "{want}\nmissing from\n{json}");
        }
        let back = NetworkConfig::from_json_str(&json).unwrap();
        assert_eq!(back.tc_trees(), cfg.tc_trees());
        assert_eq!(back.to_json_string().unwrap(), json);
        back.validate().unwrap();

        // Words as a list read the same.
        let listed = json.replace(r#""params":"rate 100mbit""#, r#""params":["rate","100mbit"]"#);
        assert_eq!(NetworkConfig::from_json_str(&listed).unwrap().tc_trees(), cfg.tc_trees());
    }

    /// #792: an action list's rate estimator is written as tc(8)'s words
    /// and reads back, and two filters that differ only in it differ.
    #[test]
    fn an_estimator_reads_back_as_written() {
        use crate::netlink::action::{Estimator, PoliceAction};
        use std::time::Duration;
        let with = |estimator: Option<Estimator>| {
            let police = PoliceAction::new().rate(Rate::mbit(1)).burst(crate::Bytes::kib(32)).avrate(Rate::mbit(1));
            let list = ActionList::new().with(police);
            let list = match estimator {
                Some(e) => list.with_estimator(e),
                None => list,
            };
            NetworkConfig::new().tc("d0", move |t| {
                t.filter(h(1, 0), FilterPriority::new(1), EthProto::ALL, MatchallFilter::new().actions(list))
            })
        };
        let estimator = Estimator::new(Duration::from_secs(1), Duration::from_secs(8)).unwrap();
        let cfg = with(Some(estimator));
        let json = cfg.to_json_string().unwrap();
        assert!(json.contains(r#""estimator":"1s 8s""#), "{json}");
        let back = NetworkConfig::from_json_str(&json).unwrap();
        assert_eq!(back.tc_trees(), cfg.tc_trees());
        assert_eq!(back.to_json_string().unwrap(), json);
        assert_ne!(with(None).tc_trees(), cfg.tc_trees());
    }

    #[test]
    fn hfsc_curves_and_by_name_targets_read_back() {
        let cfg = NetworkConfig::new().qdisc("d0", |q| q.hfsc()).tc("d0", |t| {
            t.class(
                h(1, 0),
                h(1, 1),
                HfscClassConfig::new()
                    .rt_curve(TcServiceCurve::two_slope(2_500_000, 5000, 1_250_000))
                    .ls_rate(Rate::mbit(60)),
            )
        });
        let json = cfg.to_json_string().unwrap();
        assert!(
            json.contains(r#""params":"rt m1 20mbit d 5000us m2 10mbit ls rate 60mbit""#),
            "{json}"
        );
        assert_eq!(NetworkConfig::from_json_str(&json).unwrap().tc_trees(), cfg.tc_trees());
    }

    /// What a document cannot mean is refused as it is read.
    #[test]
    fn a_tree_document_that_cannot_mean_anything_is_refused() {
        let doc = |filter: &str| {
            format!(r#"{{"tc":[{{"dev":"d0","filters":[{{"parent":"1:","priority":1,"protocol":"ip",{filter}}}]}}]}}"#)
        };
        for (doc, says) in [
            (doc(r#""kind":"basic""#), "kind `basic`"),
            (doc(r#""kind":"flower","params":"dst_port""#), "requires a value"),
            (doc(r#""kind":"fw","actions":[{"kind":"gact","params":"drop"}]"#), "carries no actions"),
            (doc(r#""kind":"fw","estimator":"1s 8s""#), "carries no actions"),
            (doc(r#""kind":"matchall","estimator":"1s 8s""#), "it has none"),
            (doc(r#""redirect-to":"ifb0","estimator":"1s 8s""#), "a filter of its own"),
            (doc(r#""kind":"matchall","estimator":"9s 80s","actions":[{"kind":"gact","params":"pass"}]"#), "at most 8s"),
            (doc(r#""redirect-to":"ifb0","params":"x""#), "a filter of its own"),
            (doc(r#""kind":"matchall","actions":[{"kind":"frob"}]"#), "frob"),
            (doc(r#""kind":"matchall","colour":"red""#), "unknown field"),
            (
                r#"{"tc":[{"dev":"d0","filters":[{"parent":"1:","priority":1,"protocol":"ip"}]}]}"#.to_string(),
                "a `kind` or a `redirect-to`",
            ),
            (
                r#"{"tc":[{"dev":"d0","classes":[{"parent":"1:","id":"1:","kind":"htb","params":"rate 1mbit"}]}]}"#.to_string(),
                "a class handle has a minor",
            ),
            (
                r#"{"tc":[{"dev":"d0","classes":[{"parent":"1:","id":"1:1","kind":"htb"}]}]}"#.to_string(),
                "`rate` is required",
            ),
        ] {
            let err = NetworkConfig::from_json_str(&doc).expect_err(&doc).to_string();
            assert!(err.contains(says), "{doc}: {err}");
        }
    }

    /// A tree diff is written in the same words.
    #[test]
    fn a_tree_diff_is_written_in_the_same_words() {
        let cfg = tree();
        let t = &cfg.tc_trees()[0];
        let d = crate::netlink::config::tc_tree::diff_tree(
            t,
            None,
            &[],
            &[],
            &[],
            &std::collections::HashMap::new(),
        );
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.starts_with(r#"{"dev":"d0","classes-to-add":[{"parent":"1:","id":"1:1""#), "{json}");
        assert!(json.contains(r#""filters-to-set":["#), "{json}");
    }
}
