//! Declarative traffic-control trees (#514).
//!
//! [`NetworkConfig::tc`](super::NetworkConfig::tc) declares, per device,
//! what hangs under its qdiscs: HTB, HFSC, DRR or QFQ classes (#645), the
//! leaf qdisc in a class, and filters with their actions — and, through
//! [`TcBuilder::redirect_ingress_to`], the redirect of everything a device
//! receives to an IFB, for shaping inbound traffic. The root and
//! ingress/clsact qdiscs themselves are declared with
//! [`NetworkConfig::qdisc`](super::NetworkConfig::qdisc), as before.
//!
//! A declared tree is owned: the diff adds what is missing, changes or
//! replaces what differs, and removes classes, leaves and filters on the
//! device that it does not declare — filters only at the parents the tree
//! uses. A recreate of the device, which destroys its tree, no longer
//! refuses for the classes and filters declared here: the apply puts them
//! back, with a redirect's target resolved again by name. A class that
//! cannot become its declaration in place — one that moved, or an HFSC
//! class that drops a curve — is deleted and added again, and so are the
//! classes under it, the leaf in it and its qdisc's filters.
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! # let conn = nlink::Connection::<nlink::Route>::new()?;
//! use nlink::{EthProto, FilterPriority, Rate, TcHandle};
//! use nlink::netlink::{config::NetworkConfig, filter::FlowerFilter, tc::{FqCodelConfig, HtbClassConfig}};
//!
//! let config = NetworkConfig::new()
//!     .qdisc("eth0", |q| q.htb().default_class(0x20))
//!     .tc("eth0", |t| {
//!         t.class(TcHandle::major_only(1), TcHandle::new(1, 1), HtbClassConfig::new(Rate::mbit(100)))
//!             .class(TcHandle::new(1, 1), TcHandle::new(1, 0x10), HtbClassConfig::new(Rate::mbit(60)))
//!             .class(TcHandle::new(1, 1), TcHandle::new(1, 0x20), HtbClassConfig::new(Rate::mbit(40)))
//!             .leaf(TcHandle::new(1, 0x10), TcHandle::major_only(0x10), FqCodelConfig::new())
//!             .filter(
//!                 TcHandle::major_only(1),
//!                 FilterPriority::new(1),
//!                 EthProto::IP,
//!                 FlowerFilter::new().ip_proto_tcp().dst_port(22).classid(TcHandle::new(1, 0x10)),
//!             )
//!     });
//! config.apply(&conn).await?;
//! # Ok(())
//! # }
//! ```

use std::collections::{BTreeMap, HashMap};

use crate::netlink::{
    action::{ActionList, Estimator, MirredAction},
    attr::AttrIter,
    builder::MessageBuilder,
    connection::Connection,
    error::{Error, Result},
    eth_proto::EthProto,
    filter::{FilterConfig, FlowerFilter, FwFilter, MatchallFilter, U32Filter},
    messages::{LinkMessage, TcMessage},
    protocol::Route,
    tc::{
        ClassConfig, DrrClassConfig, HfscClassConfig, HtbClassConfig, QfqClassConfig,
        TcServiceCurve,
    },
    tc_handle::{FilterPriority, TcHandle},
    tc_spec::QdiscSpec,
};

/// One device's declared tree.
#[derive(Debug, Clone, PartialEq, Default)]
#[non_exhaustive]
pub struct DeclaredTc {
    pub(crate) dev: String,
    pub(crate) classes: Vec<DeclaredClass>,
    pub(crate) leaves: Vec<DeclaredLeaf>,
    pub(crate) filters: Vec<DeclaredFilter>,
}

impl DeclaredTc {
    /// The device.
    pub fn dev(&self) -> &str {
        &self.dev
    }

    /// Its classes.
    pub fn classes(&self) -> &[DeclaredClass] {
        &self.classes
    }

    /// Its leaf qdiscs.
    pub fn leaves(&self) -> &[DeclaredLeaf] {
        &self.leaves
    }

    /// Its filters.
    pub fn filters(&self) -> &[DeclaredFilter] {
        &self.filters
    }

    /// Whether it declares the class `handle`.
    pub(crate) fn declares_class(&self, handle: TcHandle) -> bool {
        self.classes.iter().any(|c| c.id == handle)
    }

    /// Whether the class `handle` is the tree's: it declares classes under
    /// that qdisc (`1:` for `1:20`), so one it does not declare there goes.
    pub(crate) fn owns_class(&self, handle: TcHandle) -> bool {
        self.classes.iter().any(|c| c.id.major() == handle.major())
    }

    /// Whether the qdisc in class `class` is the tree's.
    pub(crate) fn owns_leaf(&self, class: TcHandle) -> bool {
        self.owns_class(class)
    }

    /// Whether a filter at `parent` is the tree's.
    pub(crate) fn owns_filter(&self, parent: TcHandle) -> bool {
        self.owned_filter_parents().contains(&parent)
    }

    /// Whether it declares a filter at `parent`, `priority`, `protocol`.
    pub(crate) fn declares_filter(
        &self,
        parent: TcHandle,
        priority: FilterPriority,
        protocol: EthProto,
    ) -> bool {
        self.filters
            .iter()
            .any(|f| f.parent == parent && f.priority == priority && f.protocol == protocol)
    }

    /// What is wrong with it, as the validation reports it: a class or
    /// leaf declared twice, a parent class or a leaf's class it does not
    /// declare, a filter named twice, a leaf the kernel would refuse.
    pub(crate) fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for c in &self.classes {
            if !seen.insert(c.id) {
                out.push(format!("class {} is declared twice", c.id));
            }
            if c.parent.minor() != 0 && !self.declares_class(c.parent) {
                out.push(format!(
                    "class {}: its parent class {} is not declared",
                    c.id, c.parent
                ));
            }
            if c.parent.major() != c.id.major() {
                out.push(format!(
                    "class {}: a class belongs to the qdisc of its major, not {}",
                    c.id, c.parent
                ));
            }
            let kind = c.spec.kind();
            if let Some(other) = self
                .classes
                .iter()
                .find(|o| o.id.major() == c.id.major() && o.spec.kind() != kind)
            {
                out.push(format!(
                    "class {} is {kind}, but class {} under the same qdisc is {}",
                    c.id,
                    other.id,
                    other.spec.kind()
                ));
            }
            if let Some(l) = self
                .leaves
                .iter()
                .find(|l| l.handle.major() == c.id.major() && l.spec.kind() != kind)
            {
                out.push(format!(
                    "class {} is {kind}, but its qdisc {} is {}",
                    c.id,
                    l.handle,
                    l.spec.kind()
                ));
            }
            match &c.spec {
                // `hfsc_change_class()` refuses a new class with neither.
                ClassSpec::Hfsc(h)
                    if hfsc_curve(h.curves()[0]).is_none() && hfsc_curve(h.curves()[1]).is_none() =>
                {
                    out.push(format!(
                        "class {}: an hfsc class needs a real-time or a link-sharing curve",
                        c.id
                    ));
                }
                // The kernel takes no parent for these, and reports the
                // qdisc as every class's.
                ClassSpec::Drr(_) | ClassSpec::Qfq(_) if c.parent.minor() != 0 => {
                    out.push(format!(
                        "class {}: {kind} classes are flat; its parent is the qdisc ({}), not {}",
                        c.id,
                        TcHandle::major_only(c.id.major()),
                        c.parent
                    ));
                }
                _ => {}
            }
        }
        let mut seen = std::collections::HashSet::new();
        for l in &self.leaves {
            if !seen.insert(l.class) {
                out.push(format!("class {} has two leaf qdiscs", l.class));
            }
            if !self.declares_class(l.class) {
                out.push(format!("the leaf in class {}: the class is not declared", l.class));
            }
            if let Err(e) = l.spec.validate() {
                out.push(format!("the leaf in class {}: {e}", l.class));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for f in &self.filters {
            if !seen.insert((f.parent, f.priority, f.protocol)) {
                out.push(format!(
                    "two filters at {} prio {} {}: a priority and protocol name one",
                    f.parent, f.priority, f.protocol
                ));
            }
        }
        out
    }

    /// The filter parents it owns: those its filters hang off, and the
    /// qdiscs its classes belong to.
    fn owned_filter_parents(&self) -> Vec<TcHandle> {
        let mut parents: Vec<TcHandle> = self.filters.iter().map(|f| f.parent).collect();
        parents.extend(
            self.classes
                .iter()
                .map(|c| TcHandle::major_only(c.id.major())),
        );
        parents.sort();
        parents.dedup();
        parents
    }
}

/// A declared class: its parent (the qdisc, `1:`, or a class, `1:1`), its
/// handle (`1:10`) and its parameters.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DeclaredClass {
    /// The qdisc or class it hangs under.
    pub parent: TcHandle,
    /// Its handle.
    pub id: TcHandle,
    /// Its parameters.
    pub spec: ClassSpec,
}

/// A class's kind and parameters: the kind of the qdisc it belongs to.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ClassSpec {
    /// An HTB class.
    Htb(HtbClassConfig),
    /// An HFSC class: its real-time, link-sharing and upper-limit curves.
    Hfsc(HfscClassConfig),
    /// A DRR class. DRR classes are flat: each hangs off the qdisc.
    Drr(DrrClassConfig),
    /// A QFQ class. QFQ classes are flat: each hangs off the qdisc.
    Qfq(QfqClassConfig),
}

impl PartialEq for ClassSpec {
    /// Two specs are equal when they encode the same request.
    fn eq(&self, other: &Self) -> bool {
        self.kind() == other.kind() && self.options_bytes() == other.options_bytes()
    }
}

macro_rules! class_from {
    ($($cfg:ident => $v:ident),*) => {$(
        impl From<$cfg> for ClassSpec {
            fn from(c: $cfg) -> Self {
                Self::$v(c)
            }
        }
    )*};
}
class_from!(
    HtbClassConfig => Htb,
    HfscClassConfig => Hfsc,
    DrrClassConfig => Drr,
    QfqClassConfig => Qfq
);

/// An HFSC curve as `(m1, d, m2)`, or `None` for one the kernel treats as
/// not given: `hfsc_change_class()` drops a curve whose slopes are both 0.
fn hfsc_curve(c: Option<TcServiceCurve>) -> Option<(u32, u32, u32)> {
    c.filter(|c| c.m1 != 0 || c.m2 != 0).map(|c| (c.m1, c.d, c.m2))
}

/// A live class's `TCA_OPTIONS` attributes, by type.
fn class_attrs(live: &TcMessage) -> BTreeMap<u16, &[u8]> {
    AttrIter::new(live.raw_options().unwrap_or(&[]))
        .map(|(t, p)| (t & 0x7FFF, p))
        .collect()
}

/// A live HFSC class's curves: real-time, link-sharing, upper-limit. The
/// kernel reports the ones the class has.
fn live_hfsc_curves(live: &TcMessage) -> [Option<(u32, u32, u32)>; 3] {
    use crate::netlink::types::tc::qdisc::hfsc::{TCA_HFSC_FSC, TCA_HFSC_RSC, TCA_HFSC_USC};
    use zerocopy::FromBytes;
    let attrs = class_attrs(live);
    [TCA_HFSC_RSC, TCA_HFSC_FSC, TCA_HFSC_USC].map(|id| {
        let (c, _) = TcServiceCurve::read_from_prefix(attrs.get(&id)?).ok()?;
        Some((c.m1, c.d, c.m2))
    })
}

impl ClassSpec {
    fn config(&self) -> &dyn ClassConfig {
        match self {
            Self::Htb(c) => c,
            Self::Hfsc(c) => c,
            Self::Drr(c) => c,
            Self::Qfq(c) => c,
        }
    }

    /// The kind: that of the qdisc the class belongs to.
    pub fn kind(&self) -> &'static str {
        self.config().kind()
    }

    /// Whether the class has to be deleted and added again to become this
    /// spec: a change keeps an HFSC curve it is not sent, and one cannot
    /// be cleared, so a curve the live class has and the spec drops is
    /// only gone with the class.
    fn needs_recreate(&self, live: &TcMessage) -> bool {
        match self {
            Self::Hfsc(c) if live.kind() == Some("hfsc") => c
                .curves()
                .into_iter()
                .zip(live_hfsc_curves(live))
                .any(|(want, have)| hfsc_curve(want).is_none() && have.is_some()),
            _ => false,
        }
    }

    fn options_bytes(&self) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        if self.config().write_options(&mut b).is_err() {
            return Vec::new();
        }
        b.as_bytes()[start..].to_vec()
    }

    /// Whether `live` is this class, as the kernel keeps it.
    ///
    /// What a spec leaves unset is the kernel's choice and is not
    /// compared, except a QFQ weight, which every change sends as 1 when
    /// it is not given. A DRR quantum and a QFQ `lmax` left unset are the
    /// device's MTU when the class is made.
    fn matches(&self, live: &TcMessage) -> bool {
        use crate::netlink::{
            tc_recipe_internals::{htb_class_matches, htb_class_options},
            types::tc::qdisc::{
                drr::TCA_DRR_QUANTUM,
                qfq::{TCA_QFQ_LMAX, TCA_QFQ_WEIGHT},
            },
        };
        if live.kind() != Some(self.kind()) {
            return false;
        }
        let attrs = class_attrs(live);
        let u32_attr = |id: u16| {
            attrs
                .get(&id)
                .and_then(|p| p.get(..4))
                .map(|b| u32::from_ne_bytes(b.try_into().unwrap()))
        };
        match self {
            Self::Htb(c) => {
                // The quantum, mpu and overhead are dumped back too, and a
                // drift in them used to go unseen (#789).
                let parms = attrs
                    .get(&crate::netlink::types::tc::qdisc::htb::TCA_HTB_PARMS)
                    .and_then(|p| {
                        <crate::netlink::types::tc::qdisc::htb::TcHtbOpt as zerocopy::FromBytes>::read_from_prefix(p)
                            .ok()
                    })
                    .map(|(o, _)| o);
                let (mpu, overhead) = c.mpu_and_overhead();
                htb_class_matches(live, c)
                    && htb_class_options(live).is_some_and(|o| {
                        c.priority().is_none_or(|p| o.priority == p)
                            && c.cburst_as_dumped().is_none_or(|b| o.cburst == b)
                    })
                    && parms.is_some_and(|p| {
                        c.quantum_declared().is_none_or(|q| p.quantum == q)
                            && (p.rate.mpu, p.rate.overhead) == (mpu, overhead)
                            && (p.ceil.mpu, p.ceil.overhead) == (mpu, overhead)
                            && p.rate.linklayer == c.linklayer_wire()
                    })
            }
            // The kernel keeps a curve in its own units, rounding up, and
            // reports it rounding down; the trip is exact for every value
            // (`m2sm()`/`sm2m()`, `d2dx()`/`dx2d()` in sch_hfsc.c).
            Self::Hfsc(c) => c
                .curves()
                .into_iter()
                .zip(live_hfsc_curves(live))
                .all(|(want, have)| hfsc_curve(want) == have),
            Self::Drr(c) => c
                .quantum_bytes()
                .is_none_or(|q| u32_attr(TCA_DRR_QUANTUM) == Some(q.as_u32_saturating())),
            Self::Qfq(c) => {
                let (weight, lmax) = c.weight_lmax();
                u32_attr(TCA_QFQ_WEIGHT) == Some(weight.unwrap_or(1))
                    && lmax.is_none_or(|l| u32_attr(TCA_QFQ_LMAX) == Some(l.as_u32_saturating()))
            }
        }
    }
}

impl ClassConfig for ClassSpec {
    fn kind(&self) -> &'static str {
        ClassSpec::kind(self)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        self.config().write_options(builder)
    }
}

/// A declared leaf: the qdisc in a class.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DeclaredLeaf {
    /// The class it sits in.
    pub class: TcHandle,
    /// Its handle (`10:`).
    pub handle: TcHandle,
    /// The qdisc.
    pub spec: QdiscSpec,
}

/// A declared filter: where it hangs, its priority and protocol — which
/// together name it — and what it is.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct DeclaredFilter {
    /// The qdisc or hook it hangs off (`1:`, a clsact hook).
    pub parent: TcHandle,
    /// Its priority.
    pub priority: FilterPriority,
    /// Its protocol.
    pub protocol: EthProto,
    /// Its kind, keys and actions.
    pub spec: FilterSpec,
}

/// A filter's kind, keys and actions.
#[derive(Debug, Clone)]
#[non_exhaustive]
// A flower's keys make its variant the largest by far (#827); a tree
// declares a handful of filters, so boxing one would buy nothing.
#[allow(clippy::large_enum_variant)]
pub enum FilterSpec {
    /// A flower filter.
    Flower(FlowerFilter),
    /// A matchall filter.
    Matchall(MatchallFilter),
    /// An fw filter.
    Fw(FwFilter),
    /// A u32 filter.
    U32(U32Filter),
    /// Everything, redirected out of the named device — a matchall with a
    /// `mirred egress redirect`, the target resolved by name when the
    /// diff runs and again at the apply. The IFB redirect.
    RedirectTo(String),
}

impl PartialEq for FilterSpec {
    /// Two specs are equal when they encode the same request; a redirect,
    /// and an action that names its target, compare by the target's name.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::RedirectTo(a), Self::RedirectTo(b)) => a == b,
            (Self::RedirectTo(_), _) | (_, Self::RedirectTo(_)) => false,
            (a, b) => {
                // Each name both name stands for the same made-up index,
                // so the bytes differ where the names do.
                let mut names: Vec<&str> = a.device_names();
                names.extend(b.device_names());
                names.sort_unstable();
                names.dedup();
                let stand_in: HashMap<String, u32> = names
                    .iter()
                    .zip(1..)
                    .map(|(n, i)| (n.to_string(), i))
                    .collect();
                a.kind() == b.kind()
                    && a.estimator() == b.estimator()
                    && a.options_bytes(&stand_in) == b.options_bytes(&stand_in)
            }
        }
    }
}

macro_rules! filter_from {
    ($($cfg:ident => $v:ident),*) => {$(
        impl From<$cfg> for FilterSpec {
            fn from(c: $cfg) -> Self {
                Self::$v(c)
            }
        }
    )*};
}
filter_from!(FlowerFilter => Flower, MatchallFilter => Matchall, FwFilter => Fw, U32Filter => U32);

impl FilterSpec {
    /// The kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Flower(_) => "flower",
            Self::Matchall(_) | Self::RedirectTo(_) => "matchall",
            Self::Fw(_) => "fw",
            Self::U32(_) => "u32",
        }
    }

    /// Its chain (tc(8) `chain`), 0 unless set (#793).
    pub(crate) fn chain(&self) -> u32 {
        match self {
            Self::Flower(f) => f.chain(),
            Self::Matchall(f) => f.chain(),
            Self::Fw(f) => f.chain(),
            Self::U32(f) => f.chain(),
            Self::RedirectTo(_) => None,
        }
        .unwrap_or(0)
    }

    /// Its actions' rate estimator (#792), which goes on the request
    /// rather than in `TCA_OPTIONS`. The kernel does not report it, so a
    /// diff cannot compare it.
    pub(crate) fn estimator(&self) -> Option<Estimator> {
        match self {
            Self::Flower(f) => f.estimator(),
            Self::Matchall(f) => f.estimator(),
            Self::Fw(_) | Self::U32(_) | Self::RedirectTo(_) => None,
        }
    }

    /// The devices it names: a redirect's target, the targets of
    /// [`MirredAction::to_dev`] actions.
    pub(crate) fn device_names(&self) -> Vec<&str> {
        match self {
            Self::Flower(f) => f.device_names(),
            Self::Matchall(f) => f.device_names(),
            Self::Fw(f) => f.device_names(),
            Self::U32(f) => f.device_names(),
            Self::RedirectTo(dev) => vec![dev.as_str()],
        }
    }

    /// The config to install, with the devices it names resolved through
    /// `ifindexes`; `None` when one does not exist (yet).
    fn resolve(&self, ifindexes: &HashMap<String, u32>) -> Option<Box<dyn FilterConfigBoxed>> {
        fn resolved<F: FilterConfig + Clone + 'static>(
            f: &F,
            ifindexes: &HashMap<String, u32>,
        ) -> Option<Box<dyn FilterConfigBoxed>> {
            let mut f = f.clone();
            f.resolve_devices(ifindexes).ok()?;
            Some(Box::new(f))
        }
        Some(match self {
            Self::Flower(f) => resolved(f, ifindexes)?,
            Self::Matchall(f) => resolved(f, ifindexes)?,
            Self::Fw(f) => resolved(f, ifindexes)?,
            Self::U32(f) => resolved(f, ifindexes)?,
            Self::RedirectTo(dev) => {
                let target = *ifindexes.get(dev)?;
                Box::new(
                    MatchallFilter::new()
                        .actions(ActionList::new().with(MirredAction::redirect_to_egress(target))),
                )
            }
        })
    }

    /// The `TCA_OPTIONS` payload, under `protocol`.
    fn options_bytes(&self, ifindexes: &HashMap<String, u32>) -> Option<Vec<u8>> {
        let mut cfg = self.resolve(ifindexes)?;
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        cfg.write(&mut b).ok()?;
        let _ = &mut cfg;
        Some(b.as_bytes()[start..].to_vec())
    }
}

/// A filter config behind a box, for one that is resolved at apply.
pub(crate) trait FilterConfigBoxed: Send + Sync {
    fn set_protocol(&mut self, protocol: EthProto);
    fn write(&self, b: &mut MessageBuilder) -> Result<()>;
    fn install<'a>(
        &'a self,
        conn: &'a Connection<Route>,
        ifindex: u32,
        parent: TcHandle,
        protocol: EthProto,
        priority: FilterPriority,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
}

impl<F: FilterConfig + Clone + 'static> FilterConfigBoxed for F {
    fn set_protocol(&mut self, protocol: EthProto) {
        FilterConfig::set_protocol(self, protocol);
    }
    fn write(&self, b: &mut MessageBuilder) -> Result<()> {
        self.write_options(b)
    }
    fn install<'a>(
        &'a self,
        conn: &'a Connection<Route>,
        ifindex: u32,
        parent: TcHandle,
        protocol: EthProto,
        priority: FilterPriority,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(conn.add_filter_by_index_full(
            ifindex,
            parent,
            None,
            protocol,
            priority,
            self.clone(),
        ))
    }
}

/// What an action does, as far as a comparison can tell: read the same way
/// from what nlink sends and from what the kernel reports, so neither side
/// can drift from the other.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ActionSummary {
    Mirred { eaction: i32, ifindex: u32, action: i32 },
    /// Its verdict, and a random or deterministic one with its
    /// probability (`TCA_GACT_PROB`: type, value, verdict), #791.
    Gact { action: i32, prob: Option<(u16, u16, i32)> },
    /// Its rate, burst and mtu, its exceed and conform verdicts, peakrate
    /// and average rate (#791).
    Police { rate: u64, burst: u32, mtu: u32, action: i32, conform: u32, peakrate: u32, avrate: u32 },
    /// A gate's schedule as the kernel keeps it (#813): its verdict,
    /// priority, base time, cycle and extension, flags and clock, and each
    /// entry's state, interval, IPV and octet limit, with the kernel's
    /// defaults for what was not sent.
    Gate {
        action: i32,
        priority: i32,
        base: u64,
        cycle: u64,
        ext: u64,
        flags: u32,
        clockid: i32,
        entries: Vec<(bool, u32, i32, i32)>,
    },
    /// A bpf action's verdict, program and name (#813). A request names
    /// its program by fd and a dump by id, so the fd is read as the id of
    /// the program it holds.
    Bpf { action: i32, prog: Option<u32>, name: Option<String> },
    /// Any other kind (#791): its options' attributes, but for its
    /// timestamps and padding and the bookkeeping at the head of its parms
    /// (index, capabilities, references), which tell two installs of one
    /// action apart. A kind [`action_layout`] does not know is its kind
    /// alone.
    Other { kind: String, attrs: BTreeMap<u16, Vec<u8>> },
}

/// How a kind's options read, for the kinds compared by their attributes
/// (#791): what to leave out, its timestamps, padding and counters
/// (`TCA_<KIND>_TM`, `_PAD`, ctinfo's `_STATS_*`), and its parms, the
/// structs that start with `struct tc_gen`. Not `bpf`, which is sent a
/// program's fd and reports the program's id, nor `gate`, whose echo
/// fills each entry and the cycle in: those have summaries of their own
/// (#813).
fn action_layout(kind: &str) -> Option<(&'static [u16], &'static [u16])> {
    Some(match kind {
        "vlan" => (&[1, 5], &[2]),
        "mpls" => (&[1, 3], &[2]),
        "skbmod" | "skbedit" | "sample" => (&[1, 6], &[2]),
        "tunnel_key" => (&[1, 8], &[2]),
        "nat" | "connmark" | "csum" => (&[2, 3], &[1]),
        "ctinfo" => (&[1, 2, 8, 9, 10], &[3]),
        "ife" => (&[2, 7], &[1]),
        "ct" => (&[2, 15], &[1]),
        // `TCA_PEDIT_PARMS_EX` carries the parms with the extended keys.
        "pedit" => (&[1, 3], &[2, 4]),
        // `TCA_DEF_*`.
        "simple" => (&[1, 4], &[2]),
        _ => return None,
    })
}

/// A gate's schedule as [`ActionSummary::Gate`] compares it (#813), from
/// what is sent or reported: `act_gate`'s defaults stand in for what a
/// request leaves out (`gate_setup_*`: priority, IPV and octet limit -1,
/// the cycle the sum of the intervals, `CLOCK_TAI`). An entry's index is
/// its place in the list, which the kernel numbers itself.
fn gate_summary(opts: &[u8]) -> Option<ActionSummary> {
    use crate::netlink::types::tc::action::gate::*;
    use zerocopy::FromBytes;
    const CLOCK_TAI: i32 = 11;
    let find = |id: u16| AttrIter::new(opts).find(|(t, _)| t & 0x7FFF == id).map(|(_, p)| p);
    let u32_of = |p: &[u8]| p.get(..4).map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
    let u64_of = |p: &[u8]| p.get(..8).map(|b| u64::from_ne_bytes(b.try_into().unwrap()));
    let (parms, _) = TcGate::read_from_prefix(find(TCA_GATE_PARMS)?).ok()?;
    let entries: Vec<(bool, u32, i32, i32)> = find(TCA_GATE_ENTRY_LIST)
        .map(|list| {
            AttrIter::new(list)
                .map(|(_, one)| {
                    let field = |id: u16| AttrIter::new(one).find(|(t, _)| t & 0x7FFF == id).map(|(_, p)| p);
                    (
                        field(TCA_GATE_ENTRY_GATE).is_some(),
                        field(TCA_GATE_ENTRY_INTERVAL).and_then(u32_of).unwrap_or(0),
                        field(TCA_GATE_ENTRY_IPV).and_then(u32_of).map_or(-1, |v| v as i32),
                        field(TCA_GATE_ENTRY_MAX_OCTETS).and_then(u32_of).map_or(-1, |v| v as i32),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let sum: u64 = entries.iter().map(|e| u64::from(e.1)).sum();
    Some(ActionSummary::Gate {
        action: parms.action,
        priority: find(TCA_GATE_PRIORITY).and_then(u32_of).map_or(-1, |v| v as i32),
        base: find(TCA_GATE_BASE_TIME).and_then(u64_of).unwrap_or(0),
        cycle: find(TCA_GATE_CYCLE_TIME).and_then(u64_of).filter(|c| *c != 0).unwrap_or(sum),
        ext: find(TCA_GATE_CYCLE_TIME_EXT).and_then(u64_of).unwrap_or(0),
        flags: find(TCA_GATE_FLAGS).and_then(u32_of).unwrap_or(0),
        clockid: find(TCA_GATE_CLOCKID).and_then(u32_of).map_or(CLOCK_TAI, |v| v as i32),
        entries,
    })
}

/// A bpf action as [`ActionSummary::Bpf`] compares it (#813): the
/// program by the id a dump reports, or by the fd a request sends.
fn bpf_summary(opts: &[u8]) -> Option<ActionSummary> {
    use crate::netlink::types::tc::action::bpf_act::*;
    use zerocopy::FromBytes;
    let find = |id: u16| AttrIter::new(opts).find(|(t, _)| t & 0x7FFF == id).map(|(_, p)| p);
    let u32_of = |p: &[u8]| p.get(..4).map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
    let (parms, _) = crate::netlink::types::tc::action::TcGen::read_from_prefix(find(TCA_ACT_BPF_PARMS)?).ok()?;
    let prog = find(TCA_ACT_BPF_ID).and_then(u32_of).or_else(|| {
        let fd = find(TCA_ACT_BPF_FD).and_then(u32_of)?;
        crate::netlink::bpf_fd::prog_id(fd as std::os::fd::RawFd)
    });
    Some(ActionSummary::Bpf {
        action: parms.action,
        prog,
        name: find(TCA_ACT_BPF_NAME).map(|p| String::from_utf8_lossy(p).trim_end_matches('\0').to_string()),
    })
}

/// An action's attributes, as [`ActionSummary::Other`] compares them.
fn action_attrs(kind: &str, opts: &[u8]) -> BTreeMap<u16, Vec<u8>> {
    let Some((skip, parms)) = action_layout(kind) else {
        return BTreeMap::new();
    };
    AttrIter::new(opts)
        .map(|(t, p)| (t & 0x7FFF, p))
        .filter(|(t, _)| !skip.contains(t))
        .map(|(t, p)| {
            let mut v = unflag_nests(p);
            // `struct tc_gen`: index, capab, action, refcnt, bindcnt.
            if parms.contains(&t) && v.len() >= 20 {
                v[..8].fill(0);
                v[12..20].fill(0);
            }
            (t, v)
        })
        .collect()
}

/// A payload with `NLA_F_NESTED` cleared on every attribute in it that
/// carries the flag, and in theirs: nlink sets it on the nests it sends
/// (a pedit's extended keys), and the kernel does not on the ones it
/// reports. A payload that does not walk as attributes is kept as it is.
fn unflag_nests(payload: &[u8]) -> Vec<u8> {
    const NLA_F_NESTED: u16 = 0x8000;
    let mut out = payload.to_vec();
    let mut at = 0;
    while at + 4 <= out.len() {
        let len = usize::from(u16::from_ne_bytes([out[at], out[at + 1]]));
        let ty = u16::from_ne_bytes([out[at + 2], out[at + 3]]);
        if len < 4 || at + len > out.len() {
            return payload.to_vec();
        }
        if ty & NLA_F_NESTED != 0 {
            out[at + 2..at + 4].copy_from_slice(&(ty & !NLA_F_NESTED).to_ne_bytes());
            let inner = unflag_nests(&out[at + 4..at + len]);
            out[at + 4..at + len].copy_from_slice(&inner);
        }
        at += (len + 3) & !3;
    }
    out
}

/// What the kernel reports for an attribute a request leaves out, by kind
/// (#791): the default it gives one not sent, which is not a difference.
/// Each is what a sweep of every kind, applied twice, read back.
fn kernel_default(kind: &str, id: u16, value: &[u8]) -> bool {
    match (kind, id) {
        // `TCA_VLAN_PUSH_VLAN_PRIORITY`: 0.
        ("vlan", 6) => value == [0],
        // `TCA_MPLS_PROTO` of a push: `ETH_P_MPLS_UC`.
        ("mpls", 4) => value == 0x8847u16.to_be_bytes(),
        // `TCA_CT_ZONE`: 0.
        ("ct", 4) => value == [0, 0],
        // `TCA_IFE_TYPE`: `ETH_P_IFE`.
        ("ife", 5) => value == 0xED3Eu16.to_ne_bytes(),
        _ => false,
    }
}

/// Whether a live action is the declared one (#791). For a kind read as
/// attributes: every attribute the declaration sends, as sent, and any
/// other the kernel reports at the default it gives one not sent.
fn action_matches(want: &ActionSummary, have: &ActionSummary) -> bool {
    match (want, have) {
        (
            ActionSummary::Other { kind: wk, attrs: wa },
            ActionSummary::Other { kind: hk, attrs: ha },
        ) => {
            wk == hk
                && wa.iter().all(|(id, v)| ha.get(id) == Some(v))
                && ha.iter().all(|(id, v)| wa.contains_key(id) || kernel_default(wk, *id, v))
        }
        _ => want == have,
    }
}

/// The attribute that carries a filter kind's actions.
fn act_attr(kind: &str) -> Option<u16> {
    use crate::netlink::types::tc::filter::{flower, fw, matchall, u32};
    Some(match kind {
        "flower" => flower::TCA_FLOWER_ACT,
        "matchall" => matchall::TCA_MATCHALL_ACT,
        "fw" => fw::TCA_FW_ACT,
        "u32" => u32::TCA_U32_ACT,
        _ => return None,
    })
}

/// The filter's own attributes (without its actions) and its actions'
/// summaries, from a `TCA_OPTIONS` payload.
fn split_filter(kind: &str, options: &[u8]) -> (BTreeMap<u16, Vec<u8>>, Vec<ActionSummary>) {
    use crate::netlink::types::tc::action::{TCA_ACT_KIND, TCA_ACT_OPTIONS, gact, mirred, police};
    use zerocopy::FromBytes;

    let act = act_attr(kind);
    let mut attrs = BTreeMap::new();
    let mut actions = Vec::new();
    for (ty, payload) in AttrIter::new(options) {
        let ty = ty & 0x7FFF;
        if Some(ty) != act {
            attrs.insert(ty, payload.to_vec());
            continue;
        }
        for (_, slot) in AttrIter::new(payload) {
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
            let find = |id: u16| {
                AttrIter::new(opts)
                    .find(|(t, _)| t & 0x7FFF == id)
                    .map(|(_, p)| p)
            };
            let summary = match kind.as_str() {
                "gate" => gate_summary(opts),
                "bpf" => bpf_summary(opts),
                "mirred" => find(mirred::TCA_MIRRED_PARMS)
                    .and_then(|p| mirred::TcMirred::read_from_prefix(p).ok())
                    .map(|(m, _)| ActionSummary::Mirred {
                        eaction: m.eaction,
                        ifindex: m.ifindex,
                        action: m.action,
                    }),
                "gact" => find(gact::TCA_GACT_PARMS)
                    .and_then(|p| gact::TcGact::read_from_prefix(p).ok())
                    .map(|(g, _)| ActionSummary::Gact {
                        action: g.action,
                        prob: find(gact::TCA_GACT_PROB)
                            .and_then(|p| gact::TcGactP::read_from_prefix(p).ok())
                            .map(|(p, _)| (p.ptype, p.pval, p.paction))
                            .filter(|p| p.0 != 0),
                    }),
                "police" => find(police::TCA_POLICE_TBF)
                    .and_then(|p| police::TcPolice::read_from_prefix(p).ok())
                    .map(|(p, _)| {
                        let rate64 = find(police::TCA_POLICE_RATE64)
                            .and_then(|b| b.get(..8))
                            .map(|b| u64::from_ne_bytes(b.try_into().unwrap()));
                        let u32_of = |id| find(id).and_then(|b| b.get(..4)).map(|b| u32::from_ne_bytes(b.try_into().unwrap()));
                        ActionSummary::Police {
                            rate: rate64.unwrap_or(u64::from(p.rate.rate)),
                            burst: p.burst,
                            // An mtu of 0 is the kernel's to pick, as tc(8)
                            // leaves it (#800): `255 << cell_log` from the
                            // rate table, no limit without one.
                            mtu: match p.mtu {
                                0 if p.rate.rate > 0 => 255 << p.rate.cell_log,
                                0 => u32::MAX,
                                mtu => mtu,
                            },
                            action: p.action,
                            // Absent is 0: the kernel dumps each only when set.
                            conform: u32_of(police::TCA_POLICE_RESULT).unwrap_or(0),
                            peakrate: p.peakrate.rate,
                            avrate: u32_of(police::TCA_POLICE_AVRATE).unwrap_or(0),
                        }
                    }),
                _ => None,
            };
            actions.push(summary.unwrap_or_else(|| ActionSummary::Other {
                attrs: action_attrs(&kind, opts),
                kind,
            }));
        }
    }
    (attrs, actions)
}

/// The attributes that say what a filter of `kind` matches, or where it
/// sends it: one the live filter has and the declaration does not narrows
/// it. Other attributes a kernel reports (flags, counters) do not.
fn value_keys(kind: &str) -> Vec<u16> {
    use crate::netlink::{
        tc_recipe_internals::RECIPE_FLOWER_VALUE_KEYS,
        types::tc::filter::{flower, fw, matchall, u32},
    };
    match kind {
        "flower" => {
            let mut keys = RECIPE_FLOWER_VALUE_KEYS.to_vec();
            keys.extend([flower::TCA_FLOWER_CLASSID, flower::TCA_FLOWER_INDEV]);
            // The keys #827 added: a live filter with one the declaration
            // does not write matches less than declared.
            keys.extend([
                flower::TCA_FLOWER_KEY_ICMPV4_TYPE,
                flower::TCA_FLOWER_KEY_ICMPV4_CODE,
                flower::TCA_FLOWER_KEY_ICMPV6_TYPE,
                flower::TCA_FLOWER_KEY_ICMPV6_CODE,
                flower::TCA_FLOWER_KEY_FLAGS,
                flower::TCA_FLOWER_KEY_CT_STATE,
                flower::TCA_FLOWER_KEY_CT_ZONE,
                flower::TCA_FLOWER_KEY_CT_MARK,
                flower::TCA_FLOWER_KEY_CT_LABELS,
                flower::TCA_FLOWER_KEY_VLAN_ETH_TYPE,
                flower::TCA_FLOWER_KEY_CVLAN_ID,
                flower::TCA_FLOWER_KEY_CVLAN_PRIO,
                flower::TCA_FLOWER_KEY_CVLAN_ETH_TYPE,
                flower::TCA_FLOWER_KEY_MPLS_LABEL,
                flower::TCA_FLOWER_KEY_MPLS_TC,
                flower::TCA_FLOWER_KEY_MPLS_BOS,
                flower::TCA_FLOWER_KEY_MPLS_TTL,
                flower::TCA_FLOWER_KEY_ARP_OP,
                flower::TCA_FLOWER_KEY_ARP_SIP,
                flower::TCA_FLOWER_KEY_ARP_TIP,
                flower::TCA_FLOWER_KEY_ARP_SHA,
                flower::TCA_FLOWER_KEY_ARP_THA,
                flower::TCA_FLOWER_KEY_ENC_KEY_ID,
                flower::TCA_FLOWER_KEY_ENC_IPV4_SRC,
                flower::TCA_FLOWER_KEY_ENC_IPV4_DST,
                flower::TCA_FLOWER_KEY_ENC_IPV6_SRC,
                flower::TCA_FLOWER_KEY_ENC_IPV6_DST,
                flower::TCA_FLOWER_KEY_ENC_UDP_DST_PORT,
                flower::TCA_FLOWER_KEY_ENC_IP_TOS,
                flower::TCA_FLOWER_KEY_ENC_IP_TTL,
            ]);
            keys
        }
        "matchall" => vec![matchall::TCA_MATCHALL_CLASSID],
        "fw" => vec![fw::TCA_FW_CLASSID, fw::TCA_FW_MASK, fw::TCA_FW_INDEV],
        "u32" => vec![
            u32::TCA_U32_CLASSID,
            u32::TCA_U32_SEL,
            u32::TCA_U32_LINK,
            u32::TCA_U32_INDEV,
            u32::TCA_U32_DIVISOR,
            u32::TCA_U32_MARK,
        ],
        _ => Vec::new(),
    }
}

impl DeclaredFilter {
    /// Whether `live` is this filter: the same kind and protocol, every
    /// attribute the spec writes there byte for byte (a flower's keys, a
    /// classid), no value attribute it does not write, and the same actions
    /// as far as [`ActionSummary`] reads them. A redirect whose target does
    /// not exist matches nothing.
    pub(crate) fn matches(&self, live: &TcMessage, ifindexes: &HashMap<String, u32>) -> bool {
        let kind = self.spec.kind();
        if live.kind() != Some(kind)
            || live.protocol() != self.protocol
            || live.chain().unwrap_or(0) != self.spec.chain()
        {
            return false;
        }
        let Some(mut cfg) = self.spec.resolve(ifindexes) else {
            return false;
        };
        cfg.set_protocol(self.protocol);
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        if cfg.write(&mut b).is_err() {
            return false;
        }
        let (mut want_attrs, want_actions) = split_filter(kind, &b.as_bytes()[start..]);
        let (have_attrs, have_actions) = split_filter(kind, live.raw_options().unwrap_or(&[]));
        if kind == "flower" {
            use crate::netlink::{filter::flower_dumped_eth_type, types::tc::filter::flower::TCA_FLOWER_KEY_ETH_TYPE};
            let echo = flower_dumped_eth_type(|id| want_attrs.get(&id).and_then(|v| v.get(..2)?.try_into().ok()));
            match echo {
                Some(Some(t)) => _ = want_attrs.insert(TCA_FLOWER_KEY_ETH_TYPE, t.to_vec()),
                Some(None) => _ = want_attrs.remove(&TCA_FLOWER_KEY_ETH_TYPE),
                None => {}
            }
        }
        want_attrs
            .iter()
            .all(|(id, want)| have_attrs.get(id) == Some(want))
            && value_keys(kind)
                .iter()
                .all(|id| !have_attrs.contains_key(id) || want_attrs.contains_key(id))
            && want_actions.len() == have_actions.len()
            && want_actions.iter().zip(&have_actions).all(|(w, h)| action_matches(w, h))
    }
}

/// What the apply changes in one device's tree.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TcTreeDiff {
    /// The device.
    pub dev: String,
    /// Classes to add.
    pub classes_to_add: Vec<DeclaredClass>,
    /// Classes to change in place.
    pub classes_to_change: Vec<DeclaredClass>,
    /// Classes on the device the tree does not declare.
    pub classes_to_remove: Vec<TcHandle>,
    /// Leaf qdiscs to put in their class (added, or replacing another).
    pub leaves_to_set: Vec<DeclaredLeaf>,
    /// Leaf qdiscs in a class the tree declares no leaf for:
    /// `(class, handle)`.
    pub leaves_to_remove: Vec<(TcHandle, TcHandle)>,
    /// Filters to add, or replace one of the same name that differs.
    pub filters_to_set: Vec<DeclaredFilter>,
    /// Filters to remove: at a parent the tree owns, ones it does not
    /// declare, and ones of a declared filter's name in another chain.
    pub filters_to_remove: Vec<FilterKey>,
}

/// A live filter's name: where it hangs, its chain, its priority and
/// protocol (#793). A declared filter is named by the three without the
/// chain; one of that name in another chain is a different filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FilterKey {
    /// The qdisc or hook it hangs off.
    pub parent: TcHandle,
    /// tc(8) `chain`; 0 unless set.
    pub chain: u32,
    /// Its priority.
    pub priority: FilterPriority,
    /// Its protocol.
    pub protocol: EthProto,
}

impl FilterKey {
    /// A live filter's.
    fn of(live: &TcMessage) -> Self {
        Self {
            parent: live.parent(),
            chain: live.chain().unwrap_or(0),
            priority: live.priority(),
            protocol: live.protocol(),
        }
    }
}

impl std::fmt::Display for FilterKey {
    /// tc(8)'s words: `1: chain 5 prio 1 ip`, without a chain 0.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.parent)?;
        if self.chain != 0 {
            write!(f, " chain {}", self.chain)?;
        }
        write!(f, " prio {} {}", self.priority, self.protocol)
    }
}

impl TcTreeDiff {
    /// Whether nothing changes.
    pub fn is_empty(&self) -> bool {
        self.classes_to_add.is_empty()
            && self.classes_to_change.is_empty()
            && self.classes_to_remove.is_empty()
            && self.leaves_to_set.is_empty()
            && self.leaves_to_remove.is_empty()
            && self.filters_to_set.is_empty()
            && self.filters_to_remove.is_empty()
    }

    /// How many changes.
    pub fn len(&self) -> usize {
        self.classes_to_add.len()
            + self.classes_to_change.len()
            + self.classes_to_remove.len()
            + self.leaves_to_set.len()
            + self.leaves_to_remove.len()
            + self.filters_to_set.len()
            + self.filters_to_remove.len()
    }
}

impl std::fmt::Display for TcTreeDiff {
    /// One line per change, in the shape of [`ConfigDiff`](super::ConfigDiff)'s.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dev = &self.dev;
        let mut lines = Vec::new();
        for key in &self.filters_to_remove {
            lines.push(format!("- filter at {key} on {dev}"));
        }
        for (class, handle) in &self.leaves_to_remove {
            lines.push(format!("- qdisc {handle} in class {class} on {dev}"));
        }
        for handle in &self.classes_to_remove {
            lines.push(format!("- class {handle} on {dev}"));
        }
        for c in &self.classes_to_add {
            lines.push(format!("+ class {} {} under {} on {dev}", c.spec.kind(), c.id, c.parent));
        }
        for c in &self.classes_to_change {
            lines.push(format!("~ class {} {} on {dev}", c.spec.kind(), c.id));
        }
        for l in &self.leaves_to_set {
            lines.push(format!(
                "+ qdisc {} {} in class {} on {dev}",
                l.spec.kind(),
                l.handle,
                l.class
            ));
        }
        for x in &self.filters_to_set {
            let what = match &x.spec {
                FilterSpec::RedirectTo(target) => format!("redirect to {target}"),
                spec => spec.kind().to_string(),
            };
            lines.push(format!(
                "+ filter {what} at {} prio {} {} on {dev}",
                x.parent, x.priority, x.protocol
            ));
        }
        f.write_str(&lines.join("\n"))
    }
}

/// Each declared tree with the previous config's tree on its device, and a
/// bare tree for each device only the previous config declared one on, so
/// what it owned is removed (#512, #514).
pub(crate) fn with_previous(
    config: &super::NetworkConfig,
    opts: &super::PlanOptions,
) -> Vec<(DeclaredTc, Option<DeclaredTc>)> {
    let previous = opts.previous.as_deref().map(|p| p.tc.as_slice()).unwrap_or(&[]);
    let mut out: Vec<(DeclaredTc, Option<DeclaredTc>)> = config
        .tc
        .iter()
        .map(|t| (t.clone(), previous.iter().find(|p| p.dev == t.dev).cloned()))
        .collect();
    for p in previous {
        if !config.tc.iter().any(|t| t.dev == p.dev) {
            let bare = DeclaredTc {
                dev: p.dev.clone(),
                ..DeclaredTc::default()
            };
            out.push((bare, Some(p.clone())));
        }
    }
    out
}

/// The ifindex of each link by name.
pub(crate) fn ifindexes(links: &[LinkMessage]) -> HashMap<String, u32> {
    links
        .iter()
        .filter_map(|l| Some((l.name()?.to_string(), l.ifindex())))
        .collect()
}

/// Diff one device's declared tree against its live classes, qdiscs and
/// filters. A device that does not exist yet has everything to add.
/// `previous` is the tree the previous config declared on the device
/// ([`PlanOptions::previous`](super::PlanOptions::previous)): what it owned
/// and this one does not declare goes too.
pub(crate) fn diff_tree(
    tree: &DeclaredTc,
    previous: Option<&DeclaredTc>,
    live_classes: &[TcMessage],
    live_qdiscs: &[TcMessage],
    live_filters: &[TcMessage],
    ifindexes: &HashMap<String, u32>,
) -> TcTreeDiff {
    let mut diff = TcTreeDiff {
        dev: tree.dev.clone(),
        ..TcTreeDiff::default()
    };
    // HTB reports a class at the top of the tree with parent `TC_H_ROOT`,
    // not the qdisc's handle it was added under.
    let same_parent =
        |declared: TcHandle, live: TcHandle| declared == live || (live.is_root() && declared.minor() == 0);
    // Classes that are deleted and added again: a class does not move,
    // and a change cannot drop an HFSC curve.
    let mut recreated = Vec::new();
    for c in &tree.classes {
        match live_classes.iter().find(|l| l.handle() == c.id) {
            None => diff.classes_to_add.push(c.clone()),
            Some(l) if !same_parent(c.parent, l.parent()) || c.spec.needs_recreate(l) => {
                recreated.push(c.id);
            }
            Some(l) if !c.spec.matches(l) => diff.classes_to_change.push(c.clone()),
            Some(_) => {}
        }
    }
    // What a recreated class takes with it goes too, and comes back: the
    // classes under it (the kernel refuses to delete a class with
    // children), its leaf, and the filters of its qdisc, which the kernel
    // counts as the class's users while they point at it.
    let mut i = 0;
    while i < recreated.len() {
        let h = recreated[i];
        for c in &tree.classes {
            if c.parent == h
                && !recreated.contains(&c.id)
                && live_classes.iter().any(|l| l.handle() == c.id)
            {
                diff.classes_to_change.retain(|x| x.id != c.id);
                recreated.push(c.id);
            }
        }
        i += 1;
    }
    for h in &recreated {
        diff.classes_to_remove.push(*h);
        diff.classes_to_add
            .extend(tree.classes.iter().filter(|c| c.id == *h).cloned());
    }
    // Under a qdisc the tree declares classes for, a class it does not
    // declare goes. A qdisc's own "classes" (prio bands, mq queues) are
    // not classes anyone made, and neither is HFSC's root class, `1:`.
    for l in live_classes {
        let users = matches!(l.kind(), Some("htb" | "hfsc" | "drr" | "qfq"));
        if users
            && l.handle().minor() != 0
            && (tree.owns_class(l.handle()) || previous.is_some_and(|p| p.owns_class(l.handle())))
            && !tree.declares_class(l.handle())
            && !diff.classes_to_remove.contains(&l.handle())
        {
            diff.classes_to_remove.push(l.handle());
        }
    }
    let is_class = |h: TcHandle| live_classes.iter().any(|c| c.handle() == h);
    for leaf in &tree.leaves {
        let live = live_qdiscs
            .iter()
            .find(|q| q.parent() == leaf.class && q.handle().as_raw() != 0);
        if recreated.contains(&leaf.class)
            || live.is_none_or(|q| q.handle() != leaf.handle || !leaf.spec.matches(q))
        {
            diff.leaves_to_set.push(leaf.clone());
        }
    }
    for q in live_qdiscs {
        let in_class = q.handle().as_raw() != 0 && is_class(q.parent());
        if in_class
            && (tree.owns_leaf(q.parent()) || previous.is_some_and(|p| p.owns_leaf(q.parent())))
            && !tree.leaves.iter().any(|l| l.class == q.parent())
        {
            diff.leaves_to_remove.push((q.parent(), q.handle()));
        }
    }
    // The qdiscs whose filters a recreate takes: the recreated classes'
    // own, and the leaves in them.
    let destroyed: Vec<u16> = recreated
        .iter()
        .map(|h| h.major())
        .chain(
            tree.leaves
                .iter()
                .filter(|l| recreated.contains(&l.class))
                .map(|l| l.handle.major()),
        )
        .collect();
    let recreated_major = |parent: TcHandle| destroyed.contains(&parent.major());
    for f in &tree.filters {
        let chain = f.spec.chain();
        let named = |l: &&TcMessage| {
            l.parent() == f.parent && l.priority() == f.priority && l.protocol() == f.protocol
        };
        // One of its name in another chain is another filter, and goes
        // (#793): the lookup used to take it for this one.
        for l in live_filters.iter().filter(named) {
            if l.chain().unwrap_or(0) != chain {
                diff.filters_to_remove.push(FilterKey::of(l));
            }
        }
        let live = live_filters
            .iter()
            .filter(named)
            .find(|l| l.chain().unwrap_or(0) == chain);
        if let Some(l) = live
            && recreated_major(f.parent)
        {
            diff.filters_to_remove.push(FilterKey::of(l));
            diff.filters_to_set.push(f.clone());
        } else if live.is_none_or(|l| !f.matches(l, ifindexes)) {
            diff.filters_to_set.push(f.clone());
        }
    }
    for l in live_filters {
        let key = FilterKey::of(l);
        if (tree.owns_filter(l.parent()) || previous.is_some_and(|p| p.owns_filter(l.parent())))
            && !tree.declares_filter(key.parent, key.priority, key.protocol)
            && !diff.filters_to_remove.contains(&key)
        {
            diff.filters_to_remove.push(key);
        }
    }
    diff
}

/// A device's live classes, and its filters wherever they hang.
#[derive(Debug, Clone, Default)]
pub(crate) struct TcLive {
    pub(crate) classes: Vec<TcMessage>,
    pub(crate) filters: Vec<TcMessage>,
}

/// Read the classes on the device and its filters: those at the root
/// qdisc and the hooks, and those at every class someone made and every
/// qdisc under one, which a dump without a parent does not reach.
/// `qdiscs` are the device's.
pub(crate) async fn read_live(
    conn: &Connection<Route>,
    ifindex: u32,
    qdiscs: &[TcMessage],
) -> Result<TcLive> {
    let classes = conn.get_classes_by_index(ifindex).await?;
    let mut filters = conn.get_filters_by_index(ifindex).await?;
    let parents = classes
        .iter()
        .filter(|c| matches!(c.kind(), Some("htb" | "hfsc" | "drr" | "qfq")))
        .map(|c| c.handle())
        .chain(
            qdiscs
                .iter()
                .filter(|q| q.handle().as_raw() != 0 && !q.is_root() && !q.parent().is_ingress())
                .map(|q| q.handle()),
        );
    for parent in parents {
        match conn.get_filters_by_parent_index(ifindex, parent).await {
            Ok(more) => filters.extend(more),
            // Gone between the dumps, or a kind with no filter block.
            Err(e) if e.is_not_found() || e.is_invalid_argument() || e.is_not_supported() => {}
            Err(e) => return Err(e),
        }
    }
    filters.sort_by_key(|f| (f.parent(), f.priority(), f.protocol(), f.handle()));
    filters.dedup_by_key(|f| (f.parent(), f.priority(), f.protocol(), f.handle()));
    Ok(TcLive { classes, filters })
}

/// Diff `tree` against the device's live state and apply the difference;
/// the number of changes. Used by the apply, which diffs again here so a
/// root qdisc replaced or a link recreated earlier in the same apply is
/// seen.
pub(crate) async fn apply_declared(
    conn: &Connection<Route>,
    tree: &DeclaredTc,
    previous: Option<&DeclaredTc>,
) -> Result<usize> {
    let Some(link) = conn.get_link_by_name(&tree.dev).await? else {
        // A tree only the previous config declared goes with its device.
        if tree.classes.is_empty() && tree.leaves.is_empty() && tree.filters.is_empty() {
            return Ok(0);
        }
        return Err(conn.interface_not_found(&tree.dev));
    };
    let ifindex = link.ifindex();
    let qdiscs = conn.get_qdiscs_by_index(ifindex).await?;
    let live = read_live(conn, ifindex, &qdiscs).await?;
    let names = ifindexes(&conn.get_links().await?);
    let diff = diff_tree(tree, previous, &live.classes, &qdiscs, &live.filters, &names);
    if diff.is_empty() {
        return Ok(0);
    }
    apply_tree(conn, ifindex, &diff, &names).await
}

/// Apply one device's tree diff: removals children first, then the
/// classes parent first, the leaves, and the filters.
async fn apply_tree(
    conn: &Connection<Route>,
    ifindex: u32,
    diff: &TcTreeDiff,
    names: &HashMap<String, u32>,
) -> Result<usize> {
    let gone_is_ok = |r: Result<()>| match r {
        Err(e) if e.is_not_found() => Ok(()),
        other => other,
    };
    // What each step is done to, for `Error::object` (#718).
    let class = |id: TcHandle| crate::ErrorObject::TcClass {
        dev: diff.dev.clone(),
        classid: id.to_string(),
    };
    let filter = |parent: TcHandle, priority: FilterPriority, protocol: EthProto| {
        crate::ErrorObject::TcFilter {
            dev: diff.dev.clone(),
            parent: parent.to_string(),
            priority: priority.as_u16(),
            protocol: protocol.to_string(),
        }
    };
    let leaf = |at: TcHandle, kind: Option<&str>| crate::ErrorObject::Qdisc {
        dev: diff.dev.clone(),
        parent: Some(at.to_string()),
        kind: kind.map(str::to_string),
    };
    let mut changes = 0;

    for k in &diff.filters_to_remove {
        gone_is_ok(
            conn.del_filter_in_chain_by_index(ifindex, k.parent, k.chain, k.protocol, k.priority)
                .await,
        )
        .map_err(|e| {
            e.with_context(format!("tc {}: remove filter", diff.dev))
                .with_object(filter(k.parent, k.priority, k.protocol))
        })?;
        changes += 1;
    }
    for (class, _) in &diff.leaves_to_remove {
        gone_is_ok(conn.del_qdisc_by_index(ifindex, *class).await)
            .map_err(|e| {
                e.with_context(format!("tc {}: remove leaf in {class}", diff.dev))
                    .with_object(leaf(*class, None))
            })?;
        changes += 1;
    }
    // Children before parents: the deepest minor-numbered order is not a
    // tree order, so retry until nothing more goes (a class with children
    // is EBUSY... refused until they are gone).
    let mut pending: Vec<TcHandle> = diff.classes_to_remove.clone();
    while !pending.is_empty() {
        let before = pending.len();
        let mut next = Vec::new();
        for h in pending {
            match conn.del_class_by_index(ifindex, TcHandle::UNSPEC, h).await {
                Ok(()) => changes += 1,
                Err(e) if e.is_not_found() => {}
                Err(_) => next.push(h),
            }
        }
        if next.len() == before {
            // No progress: the first refusal is the error to report.
            let h = next.remove(0);
            conn.del_class_by_index(ifindex, TcHandle::UNSPEC, h)
                .await
                .map_err(|e| {
                    e.with_context(format!("tc {}: remove class {h}", diff.dev))
                        .with_object(class(h))
                })?;
            changes += 1;
        }
        pending = next;
    }

    // Parents before children.
    let mut to_add: Vec<&DeclaredClass> = diff.classes_to_add.iter().collect();
    while !to_add.is_empty() {
        let (ready, waiting): (Vec<&DeclaredClass>, Vec<&DeclaredClass>) = to_add
            .iter()
            .partition(|c| !to_add.iter().any(|p| p.id == c.parent));
        if ready.is_empty() {
            return Err(Error::invalid_message(format!(
                "tc {}: classes {:?} are each other's parents",
                diff.dev,
                waiting.iter().map(|c| c.id).collect::<Vec<_>>()
            )));
        }
        for c in &ready {
            conn.add_class_by_index(ifindex, c.parent, c.id, c.spec.clone())
                .await
                .map_err(|e| {
                    e.with_context(format!("tc {}: add class {}", diff.dev, c.id))
                        .with_object(class(c.id))
                })?;
            changes += 1;
        }
        to_add = waiting;
    }
    for c in &diff.classes_to_change {
        conn.change_class_by_index(ifindex, c.parent, c.id, c.spec.clone())
            .await
            .map_err(|e| {
                e.with_context(format!("tc {}: change class {}", diff.dev, c.id))
                    .with_object(class(c.id))
            })?;
        changes += 1;
    }
    for l in &diff.leaves_to_set {
        conn.replace_qdisc_by_index_full(ifindex, l.class, Some(l.handle), l.spec.clone())
            .await
            .map_err(|e| {
                e.with_context(format!("tc {}: leaf in {}", diff.dev, l.class))
                    .with_object(leaf(l.class, Some(l.spec.kind())))
            })?;
        changes += 1;
    }

    for f in &diff.filters_to_set {
        let cfg = f.spec.resolve(names).ok_or_else(|| {
            let missing = f.spec.device_names().into_iter().find(|d| !names.contains_key(*d));
            conn.interface_not_found(missing.unwrap_or_default())
        })?;
        // A filter of the same name that differs goes first: the kernel
        // refuses another kind at a priority and protocol, and a replace
        // keeps what it is not sent.
        gone_is_ok(
            conn.del_filter_in_chain_by_index(ifindex, f.parent, f.spec.chain(), f.protocol, f.priority)
                .await,
        )
        .map_err(|e| e.with_object(filter(f.parent, f.priority, f.protocol)))?;
        cfg.install(conn, ifindex, f.parent, f.protocol, f.priority)
            .await
            .map_err(|e| {
                e.with_context(format!(
                    "tc {}: filter at {} prio {} {}",
                    diff.dev, f.parent, f.priority, f.protocol
                ))
                .with_object(filter(f.parent, f.priority, f.protocol))
            })?;
        changes += 1;
    }
    Ok(changes)
}

/// The builder [`NetworkConfig::tc`](super::NetworkConfig::tc) hands its
/// closure.
#[derive(Debug)]
#[must_use = "builders do nothing unless used"]
pub struct TcBuilder {
    tree: DeclaredTc,
    /// The hook the device's declared ingress or clsact qdisc gives, for
    /// `redirect_ingress_to`.
    hook: Option<TcHandle>,
    errors: Vec<String>,
}

impl TcBuilder {
    pub(crate) fn new(dev: &str, hook: Option<TcHandle>) -> Self {
        Self {
            tree: DeclaredTc {
                dev: dev.to_string(),
                ..DeclaredTc::default()
            },
            hook,
            errors: Vec::new(),
        }
    }

    /// A class `id` under `parent` — the qdisc (`1:`) or another class.
    pub fn class(mut self, parent: TcHandle, id: TcHandle, spec: impl Into<ClassSpec>) -> Self {
        if id.minor() == 0 {
            self.errors.push(format!("class {id}: a class handle has a minor (`1:10`)"));
        }
        self.tree.classes.push(DeclaredClass {
            parent,
            id,
            spec: spec.into(),
        });
        self
    }

    /// The leaf qdisc in class `class`, with handle `handle` (`10:`).
    pub fn leaf(mut self, class: TcHandle, handle: TcHandle, spec: impl Into<QdiscSpec>) -> Self {
        if handle.minor() != 0 {
            self.errors.push(format!("leaf {handle}: a qdisc handle has no minor (`10:`)"));
        }
        self.tree.leaves.push(DeclaredLeaf {
            class,
            handle,
            spec: spec.into(),
        });
        self
    }

    /// A filter off `parent` (a qdisc, `1:`, or a clsact hook), named by its
    /// priority and protocol.
    pub fn filter(
        mut self,
        parent: TcHandle,
        priority: FilterPriority,
        protocol: EthProto,
        spec: impl Into<FilterSpec>,
    ) -> Self {
        self.tree.filters.push(DeclaredFilter {
            parent,
            priority,
            protocol,
            spec: spec.into(),
        });
        self
    }

    /// Redirect everything the device receives out of `dev` — an IFB, so
    /// that its root qdisc shapes the device's inbound traffic (#458). A
    /// matchall with a `mirred egress redirect` on the device's ingress
    /// hook, at the first recipe priority; the device needs an `ingress`
    /// or `clsact` qdisc declared before this.
    pub fn redirect_ingress_to(mut self, dev: &str) -> Self {
        let Some(hook) = self.hook else {
            self.errors.push(format!(
                "`.redirect_ingress_to({dev})`: declare the device's ingress or clsact qdisc first"
            ));
            return self;
        };
        self.tree.filters.push(DeclaredFilter {
            parent: hook,
            priority: FilterPriority::recipe(0),
            protocol: EthProto::ALL,
            spec: FilterSpec::RedirectTo(dev.to_string()),
        });
        self
    }

    pub(crate) fn build(self) -> std::result::Result<DeclaredTc, Vec<String>> {
        if self.errors.is_empty() {
            Ok(self.tree)
        } else {
            Err(self.errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::config::NetworkConfig;
    use crate::util::Rate;

    fn h(major: u16, minor: u16) -> TcHandle {
        TcHandle::new(major, minor)
    }

    /// A filter as a dump would show it: the writer's options, under
    /// `parent`, `priority` and `protocol`.
    fn live_filter<F: FilterConfig + Clone>(
        cfg: &F,
        kind: &str,
        parent: TcHandle,
        priority: u16,
        protocol: EthProto,
    ) -> TcMessage {
        let mut cfg = cfg.clone();
        FilterConfig::set_protocol(&mut cfg, protocol);
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        cfg.write_options(&mut b).unwrap();
        let mut msg = TcMessage {
            kind: Some(kind.to_string()),
            options: Some(b.as_bytes()[start..].to_vec()),
            ..TcMessage::default()
        };
        msg.header.tcm_parent = parent.as_raw();
        msg.header.tcm_info = (u32::from(priority) << 16) | u32::from(protocol.as_u16().to_be());
        msg
    }

    fn live_class(kind: &str, parent: TcHandle, handle: TcHandle) -> TcMessage {
        let mut msg = TcMessage {
            kind: Some(kind.to_string()),
            ..TcMessage::default()
        };
        msg.header.tcm_parent = parent.as_raw();
        msg.header.tcm_handle = handle.as_raw();
        msg
    }

    /// A class as a dump shows it: the options `cfg` writes.
    fn live_class_with(cfg: &impl ClassConfig, parent: TcHandle, handle: TcHandle) -> TcMessage {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        cfg.write_options(&mut b).unwrap();
        let mut msg = live_class(cfg.kind(), parent, handle);
        msg.options = Some(b.as_bytes()[start..].to_vec());
        msg
    }

    /// A qdisc as a dump shows it: the options `cfg` writes.
    fn live_qdisc(
        cfg: &impl crate::netlink::tc::QdiscConfig,
        parent: TcHandle,
        handle: TcHandle,
    ) -> TcMessage {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        cfg.write_options(&mut b).unwrap();
        let mut msg = live_class(cfg.kind(), parent, handle);
        msg.options = Some(b.as_bytes()[start..].to_vec());
        msg
    }

    fn ssh() -> FlowerFilter {
        FlowerFilter::new()
            .ip_proto_tcp()
            .dst_port(22)
            .classid(h(1, 0x10))
    }

    fn tree(f: impl FnOnce(TcBuilder) -> TcBuilder) -> DeclaredTc {
        f(TcBuilder::new("d0", Some(TcHandle::INGRESS))).build().unwrap()
    }

    #[test]
    fn a_filter_matches_its_echo_and_nothing_wider_or_narrower() {
        let t = tree(|t| t.filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh()));
        let f = &t.filters[0];
        let names = HashMap::new();
        let echo = live_filter(&ssh(), "flower", h(1, 0), 1, EthProto::IP);
        assert!(f.matches(&echo, &names));
        // Another port, another protocol, another kind: not this filter.
        let other = FlowerFilter::new().ip_proto_tcp().dst_port(80).classid(h(1, 0x10));
        assert!(!f.matches(&live_filter(&other, "flower", h(1, 0), 1, EthProto::IP), &names));
        assert!(!f.matches(&live_filter(&ssh(), "flower", h(1, 0), 1, EthProto::IPV6), &names));
        // A live key the declaration does not have narrows it.
        let narrower = ssh().src_port(1024);
        assert!(!f.matches(&live_filter(&narrower, "flower", h(1, 0), 1, EthProto::IP), &names));
        // So does an action the declaration does not have.
        let acting = ssh().actions(ActionList::new().with(MirredAction::redirect_to_egress(7)));
        assert!(!f.matches(&live_filter(&acting, "flower", h(1, 0), 1, EthProto::IP), &names));
    }

    #[test]
    fn a_redirect_matches_by_the_targets_current_ifindex() {
        let t = tree(|t| t.redirect_ingress_to("ifb0"));
        let f = &t.filters[0];
        assert_eq!((f.parent, f.protocol), (TcHandle::INGRESS, EthProto::ALL));
        let to = |ifindex| {
            MatchallFilter::new()
                .actions(ActionList::new().with(MirredAction::redirect_to_egress(ifindex)))
        };
        let live = live_filter(&to(7), "matchall", TcHandle::INGRESS, f.priority.as_u16(), EthProto::ALL);
        assert!(f.matches(&live, &HashMap::from([("ifb0".to_string(), 7)])));
        // The IFB was recreated: the filter names its old ifindex.
        assert!(!f.matches(&live, &HashMap::from([("ifb0".to_string(), 8)])));
        // No IFB: nothing matches, so the apply reports it missing.
        assert!(!f.matches(&live, &HashMap::new()));
    }

    #[test]
    fn the_tree_removes_only_what_it_owns() {
        let t = tree(|t| {
            t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(10)))
                .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh())
        });
        let classes = [
            // HTB reports a top class's parent as the root, not `1:`.
            live_class("htb", TcHandle::ROOT, h(1, 1)),
            // Under the tree's qdisc and not declared: goes.
            live_class("htb", h(1, 1), h(1, 0x20)),
            // Under another qdisc: not the tree's.
            live_class("htb", TcHandle::ROOT, h(2, 1)),
            // A prio band: the qdisc's own.
            live_class("prio", h(3, 0), h(3, 1)),
        ];
        let filters = [
            live_filter(&ssh(), "flower", h(1, 0), 1, EthProto::IP),
            live_filter(&ssh(), "flower", h(1, 0), 2, EthProto::IP),
            live_filter(&ssh(), "flower", h(2, 0), 1, EthProto::IP),
        ];
        let d = diff_tree(&t, None, &classes, &[], &filters, &HashMap::new());
        assert_eq!(d.classes_to_remove, vec![h(1, 0x20)]);
        assert!(d.classes_to_add.is_empty(), "{d}");
        assert_eq!(
            d.filters_to_remove,
            vec![FilterKey { parent: h(1, 0), chain: 0, priority: FilterPriority::new(2), protocol: EthProto::IP }]
        );
        assert!(d.filters_to_set.is_empty(), "{d}");

        // What the previous config owned and this one dropped goes too.
        let prev = tree(|t| t.class(h(2, 0), h(2, 1), HtbClassConfig::new(Rate::mbit(10))));
        let d = diff_tree(&t, Some(&prev), &classes, &[], &filters, &HashMap::new());
        assert!(d.classes_to_remove.contains(&h(2, 1)), "{d}");
        let key = FilterKey { parent: h(2, 0), chain: 0, priority: FilterPriority::new(1), protocol: EthProto::IP };
        assert!(d.filters_to_remove.contains(&key), "{d}");
    }

    #[test]
    fn validation_names_what_is_wrong_with_a_tree() {
        let cfg = NetworkConfig::new().tc("d0", |t| {
            t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(10)))
                .class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(10)))
                .class(h(1, 5), h(1, 2), HtbClassConfig::new(Rate::mbit(10)))
                .class(h(1, 0), h(2, 3), HtbClassConfig::new(Rate::mbit(10)))
                .leaf(h(1, 9), h(0x10, 0), crate::netlink::tc::FqCodelConfig::new())
                .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh())
                .filter(h(1, 0), FilterPriority::new(1), EthProto::IP, ssh())
        });
        let err = cfg.validate().unwrap_err().to_string();
        for want in [
            "class 1:1 is declared twice",
            "its parent class 1:5 is not declared",
            "a class belongs to the qdisc of its major",
            "the leaf in class 1:9: the class is not declared",
            "two filters at 1: prio 1",
        ] {
            assert!(err.contains(want), "{want:?} missing from {err}");
        }
    }

    #[test]
    fn a_redirect_needs_the_devices_hook_declared_first() {
        let err = NetworkConfig::new()
            .tc("d0", |t| t.redirect_ingress_to("ifb0"))
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("declare the device's ingress or clsact qdisc first"), "{err}");

        let cfg = NetworkConfig::new()
            .qdisc("d0", |q| q.clsact())
            .tc("d0", |t| t.redirect_ingress_to("ifb0"));
        cfg.validate().unwrap();
        assert_eq!(cfg.tc_trees()[0].filters()[0].parent, TcHandle::CLSACT_INGRESS);

        let cfg = NetworkConfig::new()
            .qdisc("d0", |q| q.ingress())
            .tc("d0", |t| t.redirect_ingress_to("ifb0"));
        assert_eq!(cfg.tc_trees()[0].filters()[0].parent, TcHandle::INGRESS);
    }

    /// #645: a filter whose mirred names its target compares by the name,
    /// and matches the kernel's filter through the target's current index.
    #[test]
    fn a_mirred_by_name_compares_by_name_and_matches_by_index() {
        let to = |dev: &str| {
            FilterSpec::from(MatchallFilter::new().actions(
                ActionList::new().with(MirredAction::redirect_to_egress(0).to_dev(dev)),
            ))
        };
        assert_eq!(to("ifb0"), to("ifb0"));
        assert_ne!(to("ifb0"), to("ifb1"));
        assert_eq!(to("ifb0").device_names(), ["ifb0"]);

        let t = tree(|t| t.filter(h(1, 0), FilterPriority::new(1), EthProto::ALL, match to("ifb0") {
            FilterSpec::Matchall(m) => m,
            _ => unreachable!(),
        }));
        let f = &t.filters[0];
        let by_index = MatchallFilter::new()
            .actions(ActionList::new().with(MirredAction::redirect_to_egress(7)));
        let live = live_filter(&by_index, "matchall", h(1, 0), 1, EthProto::ALL);
        assert!(f.matches(&live, &HashMap::from([("ifb0".to_string(), 7)])));
        // Recreated with another index, or gone: not this filter any more.
        assert!(!f.matches(&live, &HashMap::from([("ifb0".to_string(), 8)])));
        assert!(!f.matches(&live, &HashMap::new()));
    }

    #[test]
    fn hfsc_drr_and_qfq_classes_match_their_echo() {
        use crate::util::Bytes;
        let rt = TcServiceCurve::two_slope(2_500_000, 5000, 1_250_000);
        let hfsc = HfscClassConfig::new().rt_curve(rt).ls_rate(Rate::mbit(60));
        let spec = ClassSpec::from(hfsc.clone());
        let echo = live_class_with(&hfsc, h(1, 1), h(1, 0x10));
        assert!(spec.matches(&echo) && !spec.needs_recreate(&echo));
        // Another real-time curve: a change.
        let other = live_class_with(&hfsc.clone().rt_rate(Rate::mbit(5)), h(1, 1), h(1, 0x10));
        assert!(!spec.matches(&other) && !spec.needs_recreate(&other));
        // An upper limit the spec does not have: only gone with the class.
        let capped = live_class_with(&hfsc.clone().ul_rate(Rate::mbit(80)), h(1, 1), h(1, 0x10));
        assert!(!spec.matches(&capped) && spec.needs_recreate(&capped));
        // A curve whose slopes are 0 is no curve, as the kernel reads it.
        assert!(ClassSpec::from(hfsc.clone().ul_curve(TcServiceCurve::rate(0))).matches(&echo));
        // A class of another kind is not this one.
        assert!(!spec.matches(&live_class_with(&DrrClassConfig::new(), h(1, 0), h(1, 0x10))));

        // DRR: a quantum left unset is the kernel's choice.
        let drr = |n| DrrClassConfig::new().quantum(Bytes::new(n));
        let live = live_class_with(&drr(3000), TcHandle::ROOT, h(1, 1));
        assert!(ClassSpec::from(drr(3000)).matches(&live));
        assert!(!ClassSpec::from(drr(6000)).matches(&live));
        assert!(ClassSpec::from(DrrClassConfig::new()).matches(&live));

        // QFQ: a weight left unset is 1, an lmax the kernel's choice.
        let qfq = QfqClassConfig::new().weight(1).lmax(Bytes::new(1514));
        let live = live_class_with(&qfq, TcHandle::ROOT, h(1, 1));
        assert!(ClassSpec::from(QfqClassConfig::new()).matches(&live));
        assert!(!ClassSpec::from(QfqClassConfig::new().weight(2)).matches(&live));
        assert!(!ClassSpec::from(QfqClassConfig::new().lmax(Bytes::new(2048))).matches(&live));
    }

    #[test]
    fn a_dropped_hfsc_curve_recreates_the_class_and_what_it_takes() {
        let ls = |r| HfscClassConfig::new().ls_rate(Rate::mbit(r));
        let sfq = crate::netlink::tc::SfqConfig::new();
        let to_20 = MatchallFilter::new().classid(h(1, 0x20));
        let t = tree(|t| {
            t.class(h(1, 0), h(1, 1), ls(100))
                .class(h(1, 1), h(1, 0x20), ls(40))
                .leaf(h(1, 0x20), h(0x20, 0), sfq.clone())
                .filter(h(1, 0), FilterPriority::new(2), EthProto::IP, to_20.clone())
        });
        let classes = |top: HfscClassConfig| {
            [
                // HFSC's root class: nobody's to remove.
                live_class("hfsc", TcHandle::ROOT, h(1, 0)),
                live_class_with(&top, h(1, 0), h(1, 1)),
                live_class_with(&ls(40), h(1, 1), h(1, 0x20)),
            ]
        };
        let qdiscs = [live_qdisc(&sfq, h(1, 0x20), h(0x20, 0))];
        let filters = [live_filter(&to_20, "matchall", h(1, 0), 2, EthProto::IP)];
        let names = HashMap::new();
        let d = diff_tree(&t, None, &classes(ls(100)), &qdiscs, &filters, &names);
        assert!(d.is_empty(), "{d}");

        // 1:1 has an upper limit the tree drops: it goes, with its child,
        // the leaf in that child, and the filter pointing at it.
        let capped = ls(100).ul_rate(Rate::mbit(100));
        let d = diff_tree(&t, None, &classes(capped), &qdiscs, &filters, &names);
        assert_eq!(d.classes_to_remove, vec![h(1, 1), h(1, 0x20)]);
        let added: Vec<TcHandle> = d.classes_to_add.iter().map(|c| c.id).collect();
        assert_eq!(added, vec![h(1, 1), h(1, 0x20)]);
        assert!(d.classes_to_change.is_empty(), "{d}");
        assert_eq!(d.leaves_to_set.len(), 1, "{d}");
        assert_eq!(
            d.filters_to_remove,
            vec![FilterKey { parent: h(1, 0), chain: 0, priority: FilterPriority::new(2), protocol: EthProto::IP }]
        );
        assert_eq!(d.filters_to_set.len(), 1, "{d}");
        assert!(d.to_string().contains("+ class hfsc 1:1 under 1: on d0"), "{d}");
    }

    #[test]
    fn validation_knows_the_class_kinds() {
        use crate::netlink::tc::QdiscConfig as _;
        let cfg = NetworkConfig::new()
            .qdisc("d0", |q| q.htb())
            .tc("d0", |t| {
                t.class(h(1, 0), h(1, 1), HfscClassConfig::new().ul_rate(Rate::mbit(1)))
                    .class(h(1, 0), h(1, 2), HtbClassConfig::new(Rate::mbit(10)))
            })
            .qdisc("d1", |q| q.drr())
            .tc("d1", |t| {
                t.class(h(1, 0), h(1, 1), DrrClassConfig::new())
                    .class(h(1, 1), h(1, 2), DrrClassConfig::new())
            });
        let err = cfg.validate().unwrap_err().to_string();
        for want in [
            "class 1:1: an hfsc class needs a real-time or a link-sharing curve",
            "class 1:1 is hfsc, but class 1:2 under the same qdisc is htb",
            "class 1:1 is hfsc, but its qdisc 1: is htb",
            "class 1:2: drr classes are flat; its parent is the qdisc (1:), not 1:1",
        ] {
            assert!(err.contains(want), "{want:?} missing from {err}");
        }
        assert!(!err.contains("class 1:2 is htb, but its qdisc"), "{err}");

        // The default class is HTB's and HFSC's, a 16-bit minor for HFSC.
        let cfg = NetworkConfig::new()
            .qdisc("d0", |q| q.drr().default_class(1))
            .qdisc("d1", |q| q.hfsc().default_class(0x1_0000));
        let err = cfg.validate().unwrap_err().to_string();
        for want in [
            "`.default_class()` sets a htb, hfsc parameter, but this qdisc is drr",
            "`.default_class(0x10000)`: a class minor is 16 bits",
        ] {
            assert!(err.contains(want), "{want:?} missing from {err}");
        }

        // The roots are classful, with `1:` by default.
        for q in [
            QdiscSpec::from(crate::netlink::tc::HfscConfig::new()),
            QdiscSpec::from(crate::netlink::tc::DrrConfig::new()),
            QdiscSpec::from(crate::netlink::tc::QfqConfig::new()),
        ] {
            assert_eq!(q.default_handle(), Some(TcHandle::major_only(1)), "{}", q.kind());
        }
    }

    #[test]
    fn a_tree_diff_renders_a_line_per_change() {
        let t = tree(|t| {
            t.class(h(1, 0), h(1, 1), HtbClassConfig::new(Rate::mbit(10)))
                .leaf(h(1, 1), h(0x10, 0), crate::netlink::tc::FqCodelConfig::new())
                .redirect_ingress_to("ifb0")
        });
        let d = diff_tree(&t, None, &[], &[], &[], &HashMap::new());
        assert_eq!(d.len(), 3);
        assert_eq!(
            d.to_string(),
            "+ class htb 1:1 under 1: on d0\n\
             + qdisc fq_codel 10: in class 1:1 on d0\n\
             + filter redirect to ifb0 at ingress prio 100 all on d0"
        );
    }
}
