//! What the kernel holds, one object at a time, as the typed diff says it
//! (#708).
//!
//! Each type is the same on both sides of a change: read back from the
//! kernel with `from_kernel`, or from what a declaration makes the kernel
//! hold (the echo [`RulesetSnapshot::from_config`] simulates). A read-back
//! never fails and never invents a value: what nlink cannot name is kept as
//! the kernel said it ([`SetKeyType::Other`], a rule's raw
//! [`Expr`](crate::netlink::nftables::Expr)s) or named in `unread`.
//!
//! [`RulesetSnapshot::from_config`]: super::RulesetSnapshot::from_config

use std::time::Duration;

use super::super::expr::ElementStatement;
use super::super::object::{ObjectConfig, ObjectInfo, ObjectType};
use super::super::types::{
    ChainInfo, ChainKind, Family, Flowtable, RuleInfo, SetDataType, SetElement, SetFlags, SetInfo,
    SetKeyType, SetPolicy, Table,
};
use super::super::RuleSpec;
use super::diff::{RuleHandle, RulePlacement};

/// A table: its flags and comment. Its contents are changes of their own.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftTable {
    /// Its family.
    pub family: Family,
    /// Its name.
    pub name: String,
    /// `NFT_TABLE_F_*`.
    pub flags: u32,
    /// Its comment.
    pub comment: Option<String>,
}

impl NftTable {
    /// The table as the kernel reports it.
    pub fn from_kernel(table: &Table) -> Self {
        Self {
            family: table.family,
            name: table.name.clone(),
            flags: table.flags,
            comment: table.comment.clone(),
        }
    }
}

/// A chain: regular or base, and its comment.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftChain {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// What it is, with a base chain's devices sorted. `None` for a base
    /// chain of a hook or type nlink has no name for.
    pub kind: Option<ChainKind>,
    /// Its comment.
    pub comment: Option<String>,
}

impl NftChain {
    /// The chain as the kernel reports it.
    pub fn from_kernel(chain: &ChainInfo) -> Self {
        Self {
            family: chain.family,
            table: chain.table.clone(),
            name: chain.name.clone(),
            kind: chain.kind().map(ChainKind::with_sorted_devices),
            comment: chain.comment.clone(),
        }
    }
}

/// A rule: where it is, or where it goes, and its body.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftRule {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its chain.
    pub chain: String,
    /// nlink's key for it, if nlink wrote it.
    pub key: Option<String>,
    /// Its kernel handle: where it is. `None` for a rule not yet added.
    pub handle: Option<RuleHandle>,
    /// Where it goes. `None` for a rule that stays where it is.
    pub placement: Option<RulePlacement>,
    /// Its body. In JSON it is [`nft`](Self::nft).
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "schemars", schemars(skip))]
    pub spec: RuleSpec,
    /// The body as `nft -s list` prints it, or `None` where nlink cannot
    /// print it.
    pub nft: Option<String>,
}

impl NftRule {
    /// The rule as the kernel reports it, lifted to a spec.
    pub fn from_kernel(rule: &RuleInfo) -> Self {
        Self {
            family: rule.family,
            table: rule.table.clone(),
            chain: rule.chain.clone(),
            key: rule.key.clone(),
            handle: Some(RuleHandle(rule.handle)),
            placement: None,
            spec: rule.spec(),
            nft: rule.nft_syntax_stateless(),
        }
    }
}

/// A set or map: its key, data, flags and settings. Its elements are a
/// change of their own, [`NftElements`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftSet {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// Its key.
    pub key_type: SetKeyType,
    /// Its flags, as the kernel keeps them.
    pub flags: SetFlags,
    /// What a map maps to; `None` for a set.
    pub data: Option<SetDataType>,
    /// Its size, if it has one.
    pub size: Option<u32>,
    /// Its elements' default timeout.
    pub timeout: Option<Duration>,
    /// Its garbage collection interval.
    pub gc_interval: Option<Duration>,
    /// What the kernel picks its backend for.
    pub policy: SetPolicy,
    /// The statements each element carries.
    pub statements: Vec<ElementStatement>,
    /// Its comment.
    pub comment: Option<String>,
    /// What nlink could not read: an object type or a statement it has no
    /// name for.
    pub unread: Vec<String>,
}

impl NftSet {
    /// The set as the kernel reports it.
    pub fn from_kernel(set: &SetInfo) -> Self {
        let mut unread = Vec::new();
        let data =
            match SetDataType::from_kernel(set.flags, set.data_type, set.data_len, set.object_type)
            {
                Ok(data) => data,
                Err(why) => {
                    unread.push(why);
                    None
                }
            };
        let mut statements = Vec::new();
        for statement in &set.statements {
            match ElementStatement::from_rule_expr(statement) {
                Some(s) => statements.push(s),
                None => unread.push(format!("statement {statement:?}")),
            }
        }
        Self {
            family: set.family,
            table: set.table.clone(),
            name: set.name.clone(),
            key_type: SetKeyType::from_kernel(set.key_type, set.key_len),
            flags: set.flags,
            data,
            size: set.size,
            timeout: set.timeout,
            gc_interval: set.gc_interval,
            policy: set.policy,
            statements,
            comment: set.comment.clone(),
            unread,
        }
    }
}

/// Elements of a set or map.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftElements {
    /// The set's table's family.
    pub family: Family,
    /// The set's table.
    pub table: String,
    /// The set.
    pub set: String,
    /// The elements.
    pub elements: Vec<SetElement>,
}

/// A named counter, quota, limit, conntrack helper or secmark.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftObject {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// Its configuration, without what the packet path has done to it.
    pub config: ObjectConfig,
}

impl NftObject {
    /// The object as the kernel reports it; `None` for one of a type nlink
    /// does not model.
    pub fn from_kernel(object: &ObjectInfo) -> Option<Self> {
        Some(Self {
            family: object.family,
            table: object.table.clone(),
            name: object.name.clone(),
            config: object.state.config()?,
        })
    }
}

/// A flowtable.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftFlowtable {
    /// Its table's family.
    pub family: Family,
    /// Its table.
    pub table: String,
    /// Its name.
    pub name: String,
    /// Its devices, sorted.
    pub devices: Vec<String>,
    /// Its priority.
    pub priority: i32,
    /// `NFT_FLOWTABLE_*`.
    pub flags: u32,
}

impl NftFlowtable {
    /// The flowtable as the kernel reports it.
    pub fn from_kernel(flowtable: &Flowtable) -> Self {
        let mut devices = flowtable.devs.clone();
        devices.sort();
        Self {
            family: flowtable.family,
            table: flowtable.table.clone(),
            name: flowtable.name.clone(),
            devices,
            priority: flowtable.priority,
            flags: flowtable.flags,
        }
    }
}

/// A chain, set, flowtable or object a [`Blocked`] entry is about (#708).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NftItem {
    /// A chain.
    Chain {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Chain name.
        name: String,
    },
    /// A named set or map.
    Set {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Set name.
        name: String,
    },
    /// A flowtable.
    Flowtable {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Flowtable name.
        name: String,
    },
    /// A named object.
    Object {
        /// Owning table.
        table: String,
        /// Owning family.
        family: Family,
        /// Object name.
        name: String,
        /// Object type.
        object_type: ObjectType,
    },
}

impl std::fmt::Display for NftItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, table, family, name) = match self {
            Self::Chain {
                table,
                family,
                name,
            } => ("chain", table, family, name),
            Self::Set {
                table,
                family,
                name,
            } => ("set", table, family, name),
            Self::Flowtable {
                table,
                family,
                name,
            } => ("flowtable", table, family, name),
            Self::Object {
                table,
                family,
                name,
                object_type,
            } => return write!(f, "object {family:?} {table}/{name} ({object_type:?})"),
        };
        write!(f, "{kind} {family:?} {table}/{name}")
    }
}

/// What the diff cannot do, or leaves alone so as not to break what it
/// does not own (#708). An entry that [`refuses`](Self::refuses) makes
/// [`apply`](super::NftablesDiff::apply) fail before it writes anything; the
/// others are said and skipped.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "kind",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Blocked {
    /// Table flags the kernel does not change on a live table: only
    /// dormant can, and persist or owner needs the table deleted with what
    /// it holds, which the diff will not do (#479). Refuses.
    TableFlags {
        /// The table's family.
        family: Family,
        /// The table.
        table: String,
        /// Its flags.
        from: u32,
        /// The declared flags.
        to: u32,
    },
    /// A table to recreate, holding rules nlink did not write: deleting it
    /// would delete them. Refuses.
    TableRecreate {
        /// The table's family.
        family: Family,
        /// The table.
        table: String,
        /// Why it is recreated.
        reason: String,
        /// The rules it would delete.
        rules: Vec<NftRule>,
    },
    /// A chain to recreate, holding rules nlink did not write, which it
    /// could not put back (#478). Refuses; an
    /// [`exclusive`](super::DeclaredChainBuilder::exclusive) chain deletes
    /// them instead.
    ChainRecreate {
        /// The table's family.
        family: Family,
        /// The table.
        table: String,
        /// The chain.
        chain: String,
        /// Why it is recreated: what cannot change on the live chain.
        reason: String,
        /// The rules it would delete.
        rules: Vec<NftRule>,
    },
    /// A set, object or flowtable to recreate that a rule nlink did not
    /// write uses: the kernel would refuse to delete it (`EBUSY`) and fail
    /// the whole batch. Refuses.
    Bound {
        /// What is recreated.
        item: NftItem,
        /// The rules that use it.
        rules: Vec<NftRule>,
    },
    /// An undeclared chain, set, flowtable or object in a managed table,
    /// left in place because a rule that stays, one nlink does not manage,
    /// uses it (#459). Kept: deleting it would fail every apply.
    InUse {
        /// What is kept.
        item: NftItem,
        /// The rules that use it.
        rules: Vec<NftRule>,
    },
    /// An object of a type nlink does not model, in a managed table: it
    /// cannot say what it is, so it does not delete it. Kept.
    UnmodelledObject {
        /// The table's family.
        family: Family,
        /// The table.
        table: String,
        /// The object.
        name: String,
        /// Its `NFT_OBJECT_*` type.
        object_type: u32,
    },
}

/// The rules a blocked entry is about: each by its handle, or by its text
/// when it has none.
fn rules_named(rules: &[NftRule]) -> String {
    rules
        .iter()
        .map(|r| match (r.handle, &r.nft) {
            (Some(h), _) => format!("rule handle {}", h.0),
            (None, Some(nft)) => format!("rule `{nft}`"),
            (None, None) => format!("a rule in {}", r.chain),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

impl Blocked {
    /// Whether this makes [`apply`](super::NftablesDiff::apply) fail.
    pub fn refuses(&self) -> bool {
        matches!(
            self,
            Self::TableFlags { .. }
                | Self::TableRecreate { .. }
                | Self::ChainRecreate { .. }
                | Self::Bound { .. }
        )
    }

    /// The error a refusing entry makes the apply fail with.
    pub(crate) fn refusal(&self) -> Option<crate::netlink::error::Error> {
        use crate::netlink::error::Error;
        use crate::ErrorObject;
        Some(match self {
            Self::TableFlags {
                family,
                table,
                from,
                to,
            } => Error::not_supported(format!(
                "table {family:?} {table}: flags {from:#x} -> {to:#x}: only dormant can change on a \
                 live table. Delete the table and apply again to recreate it with the new flags."
            ))
            .with_object(ErrorObject::NftTable {
                family: family.to_string(),
                name: table.clone(),
            }),
            Self::TableRecreate {
                family,
                table,
                reason,
                rules,
            } => Error::not_supported(format!(
                "table {family:?} {table}: {reason} needs the table recreated, which would \
                 delete rules nlink did not write: {}. Remove them and apply again.",
                rules_named(rules)
            ))
            .with_object(ErrorObject::NftTable {
                family: family.to_string(),
                name: table.clone(),
            }),
            Self::ChainRecreate {
                family,
                table,
                chain,
                reason,
                rules,
            } => Error::not_supported(format!(
                "chain {table}/{chain}: {reason} cannot be changed on the live chain, and \
                 recreating it would delete rules nlink did not write: {}. Remove them, or \
                 declare the chain exclusive, and apply again.",
                rules_named(rules)
            ))
            .with_object(ErrorObject::NftChain {
                family: family.to_string(),
                table: table.clone(),
                name: chain.clone(),
            }),
            Self::Bound { item, rules } => {
                let error = Error::not_supported(format!(
                    "{item} is recreated, and rules nlink did not write use it, so the kernel \
                     would refuse to delete it: {}. Remove them and apply again.",
                    rules_named(rules)
                ));
                match item {
                    NftItem::Set { table, family, name } => error.with_object(ErrorObject::NftSet {
                        family: family.to_string(),
                        table: table.clone(),
                        name: name.clone(),
                    }),
                    NftItem::Object { table, family, name, .. } => {
                        error.with_object(ErrorObject::NftObject {
                            family: family.to_string(),
                            table: table.clone(),
                            name: name.clone(),
                        })
                    }
                    NftItem::Flowtable { table, family, name } => {
                        error.with_object(ErrorObject::NftFlowtable {
                            family: family.to_string(),
                            table: table.clone(),
                            name: name.clone(),
                        })
                    }
                    NftItem::Chain { table, family, name } => error.with_object(ErrorObject::NftChain {
                        family: family.to_string(),
                        table: table.clone(),
                        name: name.clone(),
                    }),
                }
            }
            Self::InUse { .. } | Self::UnmodelledObject { .. } => return None,
        })
    }
}

impl std::fmt::Display for Blocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TableFlags {
                family,
                table,
                from,
                to,
            } => write!(
                f,
                "table {family:?} {table} (refused: flags {from:#x} -> {to:#x}: only dormant can \
                 change on a live table)"
            ),
            Self::TableRecreate {
                family,
                table,
                reason,
                rules,
            } => write!(
                f,
                "table {family:?} {table} (recreate refused: {reason}; it would delete rules nlink \
                 did not write: {})",
                rules_named(rules)
            ),
            Self::ChainRecreate {
                family,
                table,
                chain,
                reason,
                rules,
            } => write!(
                f,
                "chain {family:?} {table}/{chain} (recreate refused: {reason}; it would delete \
                 rules nlink did not write: {})",
                rules_named(rules)
            ),
            Self::Bound { item, rules } => write!(
                f,
                "{item} (recreate refused: rules nlink did not write use it: {})",
                rules_named(rules)
            ),
            Self::InUse { item, .. } => {
                write!(f, "{item} kept: a rule nlink does not manage uses it")
            }
            Self::UnmodelledObject {
                family,
                table,
                name,
                object_type,
            } => write!(
                f,
                "object {family:?} {table}/{name} kept: nlink does not model its type ({object_type})"
            ),
        }
    }
}

/// One change the diff makes, to a `T` (#708): what the kernel holds
/// (`from`) and what it will hold (`to`).
///
/// A recreate is a delete and an add the kernel cannot make an update: a
/// set's key, a chain's hook. It says why, and carries what it takes with
/// it, the cascade: the rules moved out of the way and put back, the
/// elements the new set gets. What a cascade holds is not listed again at
/// the top.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(
    feature = "serde",
    serde(
        tag = "op",
        rename_all = "kebab-case",
        rename_all_fields = "kebab-case"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change<T> {
    /// Something the kernel does not hold.
    Add(T),
    /// Something the declaration does not hold.
    Remove(T),
    /// Changed in place.
    Update {
        /// What the kernel holds.
        from: T,
        /// What it will hold: `from` with what the update sends. An update
        /// sends what changed, so the rest stays as the kernel has it; a
        /// chain or a rule sends itself whole, so it is the declaration's.
        to: T,
    },
    /// Deleted and created again.
    Recreate {
        /// What the kernel holds.
        from: T,
        /// What it will hold.
        to: T,
        /// Why it cannot change in place.
        reason: String,
        /// What goes with it.
        cascade: Vec<NftChange>,
    },
}

impl<T> Change<T> {
    /// What the kernel holds: `None` for an add.
    pub fn from(&self) -> Option<&T> {
        match self {
            Self::Add(_) => None,
            Self::Remove(t) | Self::Update { from: t, .. } | Self::Recreate { from: t, .. } => {
                Some(t)
            }
        }
    }

    /// What the kernel will hold: `None` for a remove.
    pub fn to(&self) -> Option<&T> {
        match self {
            Self::Remove(_) => None,
            Self::Add(t) | Self::Update { to: t, .. } | Self::Recreate { to: t, .. } => Some(t),
        }
    }

    /// What it is about: what the kernel will hold for an add, what it
    /// holds for the rest.
    fn subject(&self) -> &T {
        match self {
            Self::Add(t)
            | Self::Remove(t)
            | Self::Update { from: t, .. }
            | Self::Recreate { from: t, .. } => t,
        }
    }

    /// What a recreate takes with it.
    pub fn cascade(&self) -> &[NftChange] {
        match self {
            Self::Recreate { cascade, .. } => cascade,
            _ => &[],
        }
    }

    /// What it does, as its JSON `op` says it: `"add"`, `"remove"`,
    /// `"update"` or `"recreate"`.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Add(_) => "add",
            Self::Remove(_) => "remove",
            Self::Update { .. } => "update",
            Self::Recreate { .. } => "recreate",
        }
    }
}

/// A change to one object of the ruleset (#708).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NftChange {
    /// A table: its flags and comment.
    Table(Change<NftTable>),
    /// A chain.
    Chain(Change<NftChain>),
    /// A rule.
    Rule(Change<NftRule>),
    /// A set or map.
    Set(Change<NftSet>),
    /// Elements of a set or map, added or removed.
    Elements(Change<NftElements>),
    /// A named object.
    Object(Change<NftObject>),
    /// A flowtable.
    Flowtable(Change<NftFlowtable>),
}

impl NftChange {
    /// This change, then what its recreate takes with it, depth first.
    pub fn flatten(&self) -> Vec<&NftChange> {
        let mut out = vec![self];
        for c in self.cascade() {
            out.extend(c.flatten());
        }
        out
    }

    /// What a recreate takes with it.
    pub fn cascade(&self) -> &[NftChange] {
        match self {
            Self::Table(c) => c.cascade(),
            Self::Chain(c) => c.cascade(),
            Self::Rule(c) => c.cascade(),
            Self::Set(c) => c.cascade(),
            Self::Elements(c) => c.cascade(),
            Self::Object(c) => c.cascade(),
            Self::Flowtable(c) => c.cascade(),
        }
    }

    /// `add`, `remove`, `update` or `recreate`.
    pub fn op(&self) -> &'static str {
        match self {
            Self::Table(c) => c.op(),
            Self::Chain(c) => c.op(),
            Self::Rule(c) => c.op(),
            Self::Set(c) => c.op(),
            Self::Elements(c) => c.op(),
            Self::Object(c) => c.op(),
            Self::Flowtable(c) => c.op(),
        }
    }

    /// `table`, `chain`, `rule`, `set`, `elements`, `object` or `flowtable`.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Table(_) => "table",
            Self::Chain(_) => "chain",
            Self::Rule(_) => "rule",
            Self::Set(_) => "set",
            Self::Elements(_) => "elements",
            Self::Object(_) => "object",
            Self::Flowtable(_) => "flowtable",
        }
    }
}

/// The lines a change prints as, its cascade's indented under it (#708).
/// `parent` is the recreate a cascade belongs to: it says why a rule in it
/// is moved.
pub(crate) fn lines(
    change: &NftChange,
    parent: Option<&NftChange>,
    indent: usize,
    out: &mut Vec<String>,
) {
    let pad = " ".repeat(indent);
    let elements = |n: usize| format!("{n} element{}", if n == 1 { "" } else { "s" });
    let line = match change {
        NftChange::Table(c) => match c {
            Change::Add(t) => format!("+ table {:?} {}", t.family, t.name),
            Change::Remove(t) => format!("- table {:?} {}", t.family, t.name),
            Change::Update { to, .. } => format!(
                "~ table {:?} {} (flags={:#x})",
                to.family, to.name, to.flags
            ),
            Change::Recreate { to, reason, .. } => {
                format!("-/+ table {:?} {} (recreate: {reason})", to.family, to.name)
            }
        },
        NftChange::Chain(c) => {
            let at = |t: &NftChain| format!("{:?} {}/{}", t.family, t.table, t.name);
            match c {
                Change::Add(t) => format!("+ chain {}", at(t)),
                Change::Remove(t) => format!("- chain {}", at(t)),
                Change::Update { to, .. } => {
                    let base = to.kind.as_ref().and_then(ChainKind::base);
                    format!(
                        "~ chain {} (policy={:?} hook={:?} priority={:?} type={:?} devices={:?})",
                        at(to),
                        base.and_then(|b| b.default_policy()),
                        base.map(|b| b.hook()),
                        base.map(|b| b.priority()),
                        base.map(|b| b.chain_type()),
                        base.map(|b| b.devices().to_vec()).unwrap_or_default(),
                    )
                }
                Change::Recreate { to, reason, .. } => {
                    format!("-/+ chain {} (recreate: {reason})", at(to))
                }
            }
        }
        NftChange::Rule(c) => {
            let at = |t: &NftRule| format!("{:?} {}/{}", t.family, t.table, t.chain);
            let key = |t: &NftRule| t.key.clone().unwrap_or_else(|| "<anonymous>".into());
            let handle = |t: &NftRule| t.handle.map_or(0, |h| h.0);
            let placement = |p: Option<RulePlacement>| match p {
                Some(RulePlacement::Before(h)) => format!(" (before handle={})", h.0),
                Some(RulePlacement::After(h)) => format!(" (after handle={})", h.0),
                Some(RulePlacement::Append) | None => String::new(),
            };
            let body = |from: Option<&str>, to: Option<&str>| match (from, to) {
                (Some(now), Some(to)) if now != to => format!(": {now} -> {to}"),
                (_, Some(to)) => format!(": {to}"),
                (Some(now), None) => format!(" (now: {now})"),
                (None, None) => String::new(),
            };
            match c {
                Change::Add(t) => format!(
                    "+ rule {} [{}]{}{}",
                    at(t),
                    key(t),
                    placement(t.placement),
                    t.nft
                        .as_deref()
                        .map(|b| format!(": {b}"))
                        .unwrap_or_default()
                ),
                Change::Remove(t) => format!(
                    "- rule {}{} (handle={}){}",
                    at(t),
                    t.key
                        .as_deref()
                        .map(|k| format!(" [{k}]"))
                        .unwrap_or_default(),
                    handle(t),
                    t.nft
                        .as_deref()
                        .map(|b| format!(": {b}"))
                        .unwrap_or_default()
                ),
                Change::Update { from, to } | Change::Recreate { from, to, .. }
                    if to.placement.is_none() =>
                {
                    format!(
                        "~ rule {} (handle={} key={}){}",
                        at(to),
                        handle(from),
                        key(to),
                        body(from.nft.as_deref(), to.nft.as_deref())
                    )
                }
                Change::Update { from, to } | Change::Recreate { from, to, .. } => {
                    let why = match parent {
                        Some(NftChange::Chain(_)) => "its chain is recreated",
                        Some(NftChange::Set(_)) => "its set is recreated",
                        Some(NftChange::Object(_)) => "its object is recreated",
                        Some(NftChange::Flowtable(_)) => "its flowtable is recreated",
                        Some(NftChange::Table(_)) => "its table is recreated",
                        // A rule or an element batch carries no cascade.
                        Some(NftChange::Rule(_) | NftChange::Elements(_)) | None => {
                            "out of declared order"
                        }
                    };
                    format!(
                        "~ rule {} (handle={} key={}, re-added: {why}){}{}",
                        at(to),
                        handle(from),
                        key(to),
                        placement(to.placement),
                        body(from.nft.as_deref(), to.nft.as_deref())
                    )
                }
            }
        }
        NftChange::Set(c) => {
            let at = |t: &NftSet| format!("{:?} {}/{}", t.family, t.table, t.name);
            match c {
                Change::Add(t) => format!("+ set {}", at(t)),
                Change::Remove(t) => format!("- set {}", at(t)),
                Change::Update { to, .. } => {
                    let mut what = format!(
                        "size={}",
                        to.size.map_or_else(|| "-".to_string(), |n| n.to_string())
                    );
                    if let Some(t) = to.timeout {
                        what.push_str(&format!(", timeout={t:?}"));
                    }
                    if let Some(gc) = to.gc_interval {
                        what.push_str(&format!(", gc-interval={gc:?}"));
                    }
                    format!("~ set {} ({what})", at(to))
                }
                Change::Recreate { to, reason, .. } => {
                    format!("-/+ set {} (recreate: {reason})", at(to))
                }
            }
        }
        NftChange::Elements(c) => match c {
            Change::Remove(t) => format!(
                "- {} {:?} {}/{}",
                elements(t.elements.len()),
                t.family,
                t.table,
                t.set
            ),
            Change::Add(t) | Change::Update { to: t, .. } | Change::Recreate { to: t, .. } => {
                format!(
                    "+ {} {:?} {}/{}",
                    elements(t.elements.len()),
                    t.family,
                    t.table,
                    t.set
                )
            }
        },
        NftChange::Object(c) => {
            let at = |t: &NftObject| format!("{:?} {}/{}", t.family, t.table, t.name);
            match c {
                Change::Add(t) => format!("+ object {} {:?}", at(t), t.config),
                Change::Remove(t) => format!("- object {} ({:?})", at(t), t.config.object_type()),
                Change::Update { to, .. } => format!("~ object {} {:?}", at(to), to.config),
                Change::Recreate { to, reason, .. } => {
                    format!("-/+ object {} (recreate: {reason})", at(to))
                }
            }
        }
        NftChange::Flowtable(c) => {
            let at = |t: &NftFlowtable| format!("{:?} {}/{}", t.family, t.table, t.name);
            match c {
                Change::Add(t) => format!("+ flowtable {}", at(t)),
                Change::Remove(t) => format!("- flowtable {}", at(t)),
                Change::Update { from, to } => {
                    let mut parts = Vec::new();
                    let added: Vec<&str> = to
                        .devices
                        .iter()
                        .filter(|d| !from.devices.contains(d))
                        .map(String::as_str)
                        .collect();
                    let removed: Vec<&str> = from
                        .devices
                        .iter()
                        .filter(|d| !to.devices.contains(d))
                        .map(String::as_str)
                        .collect();
                    if !added.is_empty() {
                        parts.push(format!("+devices {}", added.join(",")));
                    }
                    if !removed.is_empty() {
                        parts.push(format!("-devices {}", removed.join(",")));
                    }
                    parts.push(format!("flags={:#x}", to.flags));
                    format!("~ flowtable {} ({})", at(to), parts.join(" "))
                }
                Change::Recreate { to, reason, .. } => {
                    format!("-/+ flowtable {} (recreate: {reason})", at(to))
                }
            }
        }
    };
    out.push(format!("{pad}{line}"));
    for c in change.cascade() {
        lines(c, Some(change), indent + 2, out);
    }
}

impl std::fmt::Display for NftChange {
    /// The change's line, and its cascade's indented under it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = Vec::new();
        lines(self, None, 0, &mut out);
        f.write_str(&out.join("\n"))
    }
}

/// The typed changes of `diff`, a pure function of its plan, the snapshot
/// it was taken against and the config it declares (#708). `from` is what
/// the snapshot holds, read back; `to` what the config makes the kernel
/// hold, read back from its echo.
pub(crate) fn build(
    diff: &super::NftablesDiff,
    current: &super::RulesetSnapshot,
    config: &super::NftablesConfig,
) -> Vec<NftChange> {
    let echo = super::RulesetSnapshot::from_config(config);
    let changes = Builder {
        diff,
        current,
        echo: &echo,
    }
    .run();
    // A miss is an nlink bug: every debug build, and so every test, fails
    // on one; a release build says so, and the plan is still what apply
    // sends.
    if let Err(why) = covers_the_plan(diff, &changes) {
        if cfg!(debug_assertions) {
            panic!("the typed changes are not the plan's (#708): {why}\n{changes:#?}");
        }
        tracing::error!(%why, "the typed changes are not the plan's (#708)");
    }
    changes
}

/// Whether `changes`, cascades included, are each of the plan's entries
/// exactly once: what [`build`] is checked against.
fn covers_the_plan(d: &super::NftablesDiff, changes: &[NftChange]) -> Result<(), String> {
    use std::collections::BTreeMap;
    let recreated = |item: &NftItem| d.provenance.recreated.iter().any(|(i, _)| i == item);
    let mut want: BTreeMap<String, usize> = BTreeMap::new();
    let mut add = |key: String, n: usize| *want.entry(key).or_default() += n;
    for t in &d.tables_to_add {
        let op = if d
            .tables_to_recreate
            .iter()
            .any(|(f, n, _)| *f == t.family() && n == t.name())
        {
            "recreate"
        } else {
            "add"
        };
        add(format!("table {op} {} {}", t.family(), t.name()), 1);
    }
    for (f, n, _) in &d.tables_to_modify {
        add(format!("table update {f} {n}"), 1);
    }
    for (f, n) in &d.tables_to_delete {
        if !d
            .tables_to_recreate
            .iter()
            .any(|(rf, rn, _)| rf == f && rn == n)
        {
            add(format!("table remove {f} {n}"), 1);
        }
    }
    for (t, f, c) in &d.chains_to_add {
        add(format!("chain add {f} {t}/{}", c.name()), 1);
    }
    for (t, f, c) in &d.chains_to_modify {
        add(format!("chain update {f} {t}/{}", c.name()), 1);
    }
    for (t, f, n) in &d.chains_to_delete {
        add(format!("chain remove {f} {t}/{n}"), 1);
    }
    for r in &d.chains_to_recreate {
        add(
            format!("chain recreate {} {}/{}", r.family, r.table, r.chain.name()),
            1,
        );
    }
    for r in &d.rules_to_add {
        add(
            format!(
                "rule add {} {}/{} {:?}",
                r.rule.family(),
                r.rule.table(),
                r.rule.chain(),
                r.rule.handle_key()
            ),
            1,
        );
    }
    for r in &d.rules_to_delete {
        add(
            format!(
                "rule remove {} {}/{} {}",
                r.family, r.table, r.chain, r.handle.0
            ),
            1,
        );
    }
    for r in &d.rules_to_replace {
        add(
            format!(
                "rule update {} {}/{} {}",
                r.family, r.table, r.chain, r.handle.0
            ),
            1,
        );
    }
    for r in &d.rules_to_move {
        add(
            format!(
                "rule update {} {}/{} {}",
                r.family, r.table, r.chain, r.from.0
            ),
            1,
        );
    }
    for f in &d.flowtables_to_add {
        let item = NftItem::Flowtable {
            table: f.table().into(),
            family: f.family(),
            name: f.name().into(),
        };
        let op = if recreated(&item) { "recreate" } else { "add" };
        add(
            format!("flowtable {op} {} {}/{}", f.family(), f.table(), f.name()),
            1,
        );
    }
    for (f, t, n) in &d.flowtables_to_delete {
        let item = NftItem::Flowtable {
            table: t.clone(),
            family: *f,
            name: n.clone(),
        };
        if !recreated(&item) {
            add(format!("flowtable remove {f} {t}/{n}"), 1);
        }
    }
    for u in &d.flowtables_to_update {
        let f = &u.flowtable;
        add(
            format!("flowtable update {} {}/{}", f.family(), f.table(), f.name()),
            1,
        );
    }
    for (t, f, s) in &d.sets_to_add {
        let item = NftItem::Set {
            table: t.clone(),
            family: *f,
            name: s.name().into(),
        };
        let op = if recreated(&item) { "recreate" } else { "add" };
        add(format!("set {op} {f} {t}/{}", s.name()), 1);
    }
    for (t, f, n) in &d.sets_to_delete {
        let item = NftItem::Set {
            table: t.clone(),
            family: *f,
            name: n.clone(),
        };
        if !recreated(&item) {
            add(format!("set remove {f} {t}/{n}"), 1);
        }
    }
    for (t, f, s) in &d.sets_to_update {
        add(format!("set update {f} {t}/{}", s.name()), 1);
    }
    for (list, op) in [
        (&d.set_elements_to_add, "add"),
        (&d.set_elements_to_remove, "remove"),
    ] {
        for c in list {
            add(
                format!(
                    "elements {op} {} {}/{}",
                    c.set.family, c.set.table, c.set.name
                ),
                c.elements.len(),
            );
        }
    }
    for (t, f, o) in &d.objects_to_add {
        let item = NftItem::Object {
            table: t.clone(),
            family: *f,
            name: o.name().into(),
            object_type: o.config().object_type(),
        };
        let op = if recreated(&item) { "recreate" } else { "add" };
        add(format!("object {op} {f} {t}/{}", o.name()), 1);
    }
    for (t, f, o) in &d.objects_to_update {
        add(format!("object update {f} {t}/{}", o.name()), 1);
    }
    for (t, f, n, ty) in &d.objects_to_delete {
        let item = NftItem::Object {
            table: t.clone(),
            family: *f,
            name: n.clone(),
            object_type: *ty,
        };
        if !recreated(&item) {
            add(format!("object remove {f} {t}/{n}"), 1);
        }
    }

    let mut have: BTreeMap<String, usize> = BTreeMap::new();
    for change in changes.iter().flat_map(NftChange::flatten) {
        let (key, n) = match change {
            NftChange::Table(c) => {
                let t = c.subject();
                (format!("table {} {} {}", c.op(), t.family, t.name), 1)
            }
            NftChange::Chain(c) => {
                let t = c.subject();
                (
                    format!("chain {} {} {}/{}", c.op(), t.family, t.table, t.name),
                    1,
                )
            }
            NftChange::Rule(c) => match (c.op(), c.from(), c.to()) {
                ("add", _, Some(t)) => (
                    format!(
                        "rule add {} {}/{} {:?}",
                        t.family,
                        t.table,
                        t.chain,
                        t.key.as_deref()
                    ),
                    1,
                ),
                (op, Some(t), _) => (
                    format!(
                        "rule {op} {} {}/{} {}",
                        t.family,
                        t.table,
                        t.chain,
                        t.handle.map_or(0, |h| h.0)
                    ),
                    1,
                ),
                _ => return Err(format!("a rule change without a side: {change:?}")),
            },
            NftChange::Set(c) => {
                let t = c.subject();
                (
                    format!("set {} {} {}/{}", c.op(), t.family, t.table, t.name),
                    1,
                )
            }
            NftChange::Elements(c) => {
                let t = c.subject();
                (
                    format!("elements {} {} {}/{}", c.op(), t.family, t.table, t.set),
                    t.elements.len(),
                )
            }
            NftChange::Object(c) => {
                let t = c.subject();
                (
                    format!("object {} {} {}/{}", c.op(), t.family, t.table, t.name),
                    1,
                )
            }
            NftChange::Flowtable(c) => {
                let t = c.subject();
                (
                    format!("flowtable {} {} {}/{}", c.op(), t.family, t.table, t.name),
                    1,
                )
            }
        };
        *have.entry(key).or_default() += n;
    }
    if want == have {
        return Ok(());
    }
    let keys: std::collections::BTreeSet<&String> = want.keys().chain(have.keys()).collect();
    let wrong: Vec<String> = keys
        .into_iter()
        .filter(|k| want.get(*k) != have.get(*k))
        .map(|k| format!("{k}: plan {:?}, changes {:?}", want.get(k), have.get(k)))
        .collect();
    Err(wrong.join("; "))
}

struct Builder<'a> {
    diff: &'a super::NftablesDiff,
    current: &'a super::RulesetSnapshot,
    echo: &'a super::RulesetSnapshot,
}

type Key<'a> = (Family, &'a str, &'a str);

impl Builder<'_> {
    fn table(&self, s: &super::RulesetSnapshot, family: Family, name: &str) -> Option<NftTable> {
        s.tables
            .iter()
            .find(|t| t.family == family && t.name == name)
            .map(NftTable::from_kernel)
    }

    fn chain(&self, s: &super::RulesetSnapshot, (family, table, name): Key) -> Option<NftChain> {
        s.chains
            .iter()
            .find(|c| c.family == family && c.table == table && c.name == name)
            .map(NftChain::from_kernel)
    }

    fn set(&self, s: &super::RulesetSnapshot, (family, table, name): Key) -> Option<NftSet> {
        s.sets
            .iter()
            .find(|c| c.family == family && c.table == table && c.name == name)
            .map(NftSet::from_kernel)
    }

    fn object(
        &self,
        s: &super::RulesetSnapshot,
        (family, table, name): Key,
        object_type: ObjectType,
    ) -> Option<NftObject> {
        s.objects
            .iter()
            .find(|o| {
                o.family == family
                    && o.table == table
                    && o.name == name
                    && o.object_type() == Some(object_type)
            })
            .and_then(NftObject::from_kernel)
    }

    fn flowtable(
        &self,
        s: &super::RulesetSnapshot,
        (family, table, name): Key,
    ) -> Option<NftFlowtable> {
        s.flowtables
            .iter()
            .find(|f| f.family == family && f.table == table && f.name == name)
            .map(NftFlowtable::from_kernel)
    }

    /// The kernel's rule at `handle`.
    fn kernel_rule(&self, family: Family, table: &str, handle: RuleHandle) -> Option<&RuleInfo> {
        self.current
            .rules
            .iter()
            .find(|r| r.family == family && r.table == table && r.handle == handle.0)
    }

    /// A declared rule as the kernel will hold it, wherever it goes.
    fn declared_rule(
        &self,
        rule: &super::DeclaredRule,
        placement: Option<RulePlacement>,
    ) -> NftRule {
        let echoed = self.echo.rules.iter().find(|r| {
            r.family == rule.family()
                && r.table == rule.table()
                && r.chain == rule.chain()
                && r.key.as_deref() == rule.handle_key()
        });
        let mut out = match echoed {
            Some(r) => NftRule::from_kernel(r),
            None => NftRule {
                family: rule.family(),
                table: rule.table().to_string(),
                chain: rule.chain().to_string(),
                key: rule.handle_key().map(str::to_string),
                handle: None,
                placement: None,
                spec: rule.spec().clone(),
                nft: rule.body().nft_syntax_stateless(),
            },
        };
        out.handle = None;
        out.placement = placement;
        out
    }

    fn run(&self) -> Vec<NftChange> {
        let d = self.diff;
        let mut out = Vec::new();
        let recreated_table = |family: Family, table: &str| {
            d.tables_to_recreate
                .iter()
                .any(|(f, t, _)| *f == family && t == table)
        };
        // What goes in a table's recreate, rather than at the top.
        let mut table_cascades: Vec<(Family, String, Vec<NftChange>)> = d
            .tables_to_recreate
            .iter()
            .map(|(f, t, _)| (*f, t.clone(), Vec::new()))
            .collect();
        let mut push_child =
            |out: &mut Vec<NftChange>, family: Family, table: &str, change: NftChange| {
                match table_cascades
                    .iter_mut()
                    .find(|(f, t, _)| *f == family && t == table)
                {
                    Some((_, _, cascade)) => cascade.push(change),
                    None => out.push(change),
                }
            };

        // Chains.
        let mut chains = Vec::new();
        for (table, family, chain) in &d.chains_to_add {
            let key = (*family, table.as_str(), chain.name());
            if let Some(to) = self.chain(self.echo, key) {
                push_child(
                    &mut chains,
                    *family,
                    table,
                    NftChange::Chain(Change::Add(to)),
                );
            }
        }
        for (table, family, chain) in &d.chains_to_modify {
            let key = (*family, table.as_str(), chain.name());
            if let (Some(from), Some(to)) =
                (self.chain(self.current, key), self.chain(self.echo, key))
            {
                chains.push(NftChange::Chain(Change::Update { from, to }));
            }
        }
        for (table, family, name) in &d.chains_to_delete {
            if let Some(from) = self.chain(self.current, (*family, table, name)) {
                chains.push(NftChange::Chain(Change::Remove(from)));
            }
        }
        // Rules a recreate moves are in its cascade.
        let mut moves: Vec<&super::RuleMove> = d.rules_to_move.iter().collect();
        for recreate in &d.chains_to_recreate {
            let key = (
                recreate.family,
                recreate.table.as_str(),
                recreate.chain.name(),
            );
            let cascade = self.take_moves(&mut moves, |m| {
                m.reason == super::MoveReason::ChainRecreated
                    && m.family == recreate.family
                    && m.table == recreate.table
                    && m.chain == recreate.chain.name()
            });
            if let (Some(from), Some(to)) =
                (self.chain(self.current, key), self.chain(self.echo, key))
            {
                chains.push(NftChange::Chain(Change::Recreate {
                    from,
                    to,
                    reason: recreate.reason.clone(),
                    cascade,
                }));
            }
        }

        // Flowtables.
        let mut flowtables = Vec::new();
        let recreated = |item: &NftItem| {
            d.provenance
                .recreated
                .iter()
                .find(|(i, _)| i == item)
                .map(|(_, why)| why.clone())
        };
        for f in &d.flowtables_to_add {
            let key = (f.family(), f.table(), f.name());
            let item = NftItem::Flowtable {
                table: f.table().to_string(),
                family: f.family(),
                name: f.name().to_string(),
            };
            let Some(to) = self.flowtable(self.echo, key) else { continue };
            match (recreated(&item), self.flowtable(self.current, key)) {
                (Some(reason), Some(from)) => {
                    let cascade = self.take_moves(&mut moves, |m| {
                        m.reason == super::MoveReason::BoundToRecreatedFlowtable
                            && self.moved_references(m, |r| {
                                super::diff::references_flowtable(r, f.name())
                            })
                    });
                    flowtables.push(NftChange::Flowtable(Change::Recreate {
                        from,
                        to,
                        reason,
                        cascade,
                    }));
                }
                _ => push_child(
                    &mut flowtables,
                    f.family(),
                    f.table(),
                    NftChange::Flowtable(Change::Add(to)),
                ),
            }
        }
        for (family, table, name) in &d.flowtables_to_delete {
            let item = NftItem::Flowtable {
                table: table.clone(),
                family: *family,
                name: name.clone(),
            };
            if recreated(&item).is_some() {
                continue;
            }
            if let Some(from) = self.flowtable(self.current, (*family, table, name)) {
                flowtables.push(NftChange::Flowtable(Change::Remove(from)));
            }
        }
        for update in &d.flowtables_to_update {
            let f = &update.flowtable;
            if let Some(from) = self.flowtable(self.current, (f.family(), f.table(), f.name())) {
                let mut to = from.clone();
                to.devices = f.devs().to_vec();
                to.devices.sort();
                to.flags = f.flags();
                flowtables.push(NftChange::Flowtable(Change::Update { from, to }));
            }
        }

        // Objects, and the object-map elements that hold a recreated one.
        let mut objects = Vec::new();
        let mut forced_taken: Vec<&(NftItem, String, SetElement)> = Vec::new();
        for (table, family, object) in &d.objects_to_add {
            let ty = object.config().object_type();
            let key = (*family, table.as_str(), object.name());
            let item = NftItem::Object {
                table: table.clone(),
                family: *family,
                name: object.name().to_string(),
                object_type: ty,
            };
            let Some(to) = self.object(self.echo, key, ty) else { continue };
            match (recreated(&item), self.object(self.current, key, ty)) {
                (Some(reason), Some(from)) => {
                    let mut cascade = self.take_moves(&mut moves, |m| {
                        m.reason == super::MoveReason::BoundToRecreatedObject
                            && self.moved_references(m, |r| {
                                super::diff::references_object(r, object.name(), ty)
                            })
                    });
                    // The elements that hold it, out and back.
                    let held: Vec<&(NftItem, String, SetElement)> = d
                        .provenance
                        .forced
                        .iter()
                        .filter(|(set, name, _)| {
                            name == object.name() && matches!(set, NftItem::Set { table: t, family: f, .. } if t == table && f == family)
                        })
                        .collect();
                    let mut by_set: Vec<(String, Vec<SetElement>)> = Vec::new();
                    for (set, _, element) in &held {
                        let NftItem::Set { name, .. } = set else { continue };
                        match by_set.iter_mut().find(|(n, _)| n == name) {
                            Some((_, elements)) => elements.push(element.clone()),
                            None => by_set.push((name.clone(), vec![element.clone()])),
                        }
                    }
                    for (set, elements) in by_set {
                        let added: Vec<SetElement> = d
                            .set_elements_to_add
                            .iter()
                            .filter(|c| {
                                c.set.family == *family
                                    && c.set.table == *table
                                    && c.set.name == set
                            })
                            .flat_map(|c| c.elements.iter())
                            .filter(|e| elements.iter().any(|h| h.identity() == e.identity()))
                            .cloned()
                            .collect();
                        cascade.push(NftChange::Elements(Change::Remove(NftElements {
                            family: *family,
                            table: table.clone(),
                            set: set.clone(),
                            elements: elements.clone(),
                        })));
                        if !added.is_empty() {
                            cascade.push(NftChange::Elements(Change::Add(NftElements {
                                family: *family,
                                table: table.clone(),
                                set,
                                elements: added,
                            })));
                        }
                    }
                    forced_taken.extend(held);
                    objects.push(NftChange::Object(Change::Recreate {
                        from,
                        to,
                        reason,
                        cascade,
                    }));
                }
                _ => push_child(
                    &mut objects,
                    *family,
                    table,
                    NftChange::Object(Change::Add(to)),
                ),
            }
        }
        for (table, family, object) in &d.objects_to_update {
            let ty = object.config().object_type();
            if let Some(from) = self.object(self.current, (*family, table, object.name()), ty) {
                let mut to = from.clone();
                to.config = object.config().clone();
                objects.push(NftChange::Object(Change::Update { from, to }));
            }
        }
        for (table, family, name, ty) in &d.objects_to_delete {
            let item = NftItem::Object {
                table: table.clone(),
                family: *family,
                name: name.clone(),
                object_type: *ty,
            };
            if recreated(&item).is_some() {
                continue;
            }
            if let Some(from) = self.object(self.current, (*family, table, name), *ty) {
                objects.push(NftChange::Object(Change::Remove(from)));
            }
        }

        // Sets, with what a recreate takes: its elements, its bound rules.
        let mut sets = Vec::new();
        let mut elements_taken: Vec<(Family, String, String)> = Vec::new();
        let elements_of = |family: Family, table: &str, set: &str| -> Vec<SetElement> {
            d.set_elements_to_add
                .iter()
                .filter(|c| c.set.family == family && c.set.table == table && c.set.name == set)
                .flat_map(|c| c.elements.iter().cloned())
                .collect()
        };
        for (table, family, set) in &d.sets_to_add {
            let key = (*family, table.as_str(), set.name());
            let item = NftItem::Set {
                table: table.clone(),
                family: *family,
                name: set.name().to_string(),
            };
            let Some(to) = self.set(self.echo, key) else { continue };
            let added = elements_of(*family, table, set.name());
            let elements = |elements: Vec<SetElement>| {
                NftChange::Elements(Change::Add(NftElements {
                    family: *family,
                    table: table.clone(),
                    set: set.name().to_string(),
                    elements,
                }))
            };
            match (recreated(&item), self.set(self.current, key)) {
                (Some(reason), Some(from)) => {
                    let mut cascade = Vec::new();
                    if !added.is_empty() {
                        cascade.push(elements(added));
                    }
                    cascade.extend(self.take_moves(&mut moves, |m| {
                        m.reason == super::MoveReason::BoundToRecreatedSet
                            && self
                                .moved_references(m, |r| super::diff::references_set(r, set.name()))
                    }));
                    elements_taken.push((*family, table.clone(), set.name().to_string()));
                    sets.push(NftChange::Set(Change::Recreate {
                        from,
                        to,
                        reason,
                        cascade,
                    }));
                }
                _ => {
                    push_child(&mut sets, *family, table, NftChange::Set(Change::Add(to)));
                    if !added.is_empty() {
                        push_child(&mut sets, *family, table, elements(added));
                    }
                    elements_taken.push((*family, table.clone(), set.name().to_string()));
                }
            }
        }
        for (table, family, name) in &d.sets_to_delete {
            let item = NftItem::Set {
                table: table.clone(),
                family: *family,
                name: name.clone(),
            };
            if recreated(&item).is_some() {
                continue;
            }
            if let Some(from) = self.set(self.current, (*family, table, name)) {
                sets.push(NftChange::Set(Change::Remove(from)));
            }
        }
        for (table, family, set) in &d.sets_to_update {
            if let Some(from) = self.set(self.current, (*family, table, set.name())) {
                let mut to = from.clone();
                to.size = set.size().or(from.size);
                to.timeout = set.timeout();
                to.gc_interval = set.gc_interval();
                sets.push(NftChange::Set(Change::Update { from, to }));
            }
        }
        // Element changes no recreate took.
        let mut elements = Vec::new();
        let forced = |c: &super::SetElementsChange, e: &SetElement| {
            forced_taken.iter().any(|(set, _, held)| {
                matches!(set, NftItem::Set { table, family, name } if *table == c.set.table && *family == c.set.family && *name == c.set.name)
                    && held.identity() == e.identity()
            })
        };
        for (list, add) in [
            (&d.set_elements_to_add, true),
            (&d.set_elements_to_remove, false),
        ] {
            for c in list {
                let taken = elements_taken
                    .iter()
                    .any(|(f, t, s)| *f == c.set.family && *t == c.set.table && *s == c.set.name);
                if add && taken {
                    continue;
                }
                let left: Vec<SetElement> = c
                    .elements
                    .iter()
                    .filter(|e| !forced(c, e))
                    .cloned()
                    .collect();
                if left.is_empty() {
                    continue;
                }
                let value = NftElements {
                    family: c.set.family,
                    table: c.set.table.clone(),
                    set: c.set.name.clone(),
                    elements: left,
                };
                elements.push(NftChange::Elements(if add {
                    Change::Add(value)
                } else {
                    Change::Remove(value)
                }));
            }
        }

        // Rules.
        let mut rules = Vec::new();
        for add in &d.rules_to_add {
            let rule = &add.rule;
            push_child(
                &mut rules,
                rule.family(),
                rule.table(),
                NftChange::Rule(Change::Add(self.declared_rule(rule, Some(add.placement)))),
            );
        }
        for delete in &d.rules_to_delete {
            if let Some(from) = self.kernel_rule(delete.family, &delete.table, delete.handle) {
                rules.push(NftChange::Rule(Change::Remove(NftRule::from_kernel(from))));
            }
        }
        for replace in &d.rules_to_replace {
            if let Some(from) = self.kernel_rule(replace.family, &replace.table, replace.handle) {
                let mut to = self.declared_rule(&replace.rule, None);
                to.handle = Some(replace.handle);
                rules.push(NftChange::Rule(Change::Update {
                    from: NftRule::from_kernel(from),
                    to,
                }));
            }
        }
        // The moves no recreate took: a reorder.
        for m in moves {
            rules.extend(self.moved(m));
        }

        // Tables, with a recreated one's contents in its cascade.
        let mut tables = Vec::new();
        for t in &d.tables_to_add {
            let Some(to) = self.table(self.echo, t.family(), t.name()) else { continue };
            match d
                .tables_to_recreate
                .iter()
                .find(|(f, n, _)| *f == t.family() && n == t.name())
            {
                Some((family, name, reason)) => {
                    let Some(from) = self.table(self.current, *family, name) else { continue };
                    let cascade = table_cascades
                        .iter_mut()
                        .find(|(f, n, _)| f == family && n == name)
                        .map(|(_, _, c)| std::mem::take(c))
                        .unwrap_or_default();
                    tables.push(NftChange::Table(Change::Recreate {
                        from,
                        to,
                        reason: reason.clone(),
                        cascade,
                    }));
                }
                None => tables.push(NftChange::Table(Change::Add(to))),
            }
        }
        for (family, name, flags) in &d.tables_to_modify {
            if let Some(from) = self.table(self.current, *family, name) {
                let mut to = from.clone();
                to.flags = *flags;
                tables.push(NftChange::Table(Change::Update { from, to }));
            }
        }
        for (family, name) in &d.tables_to_delete {
            if recreated_table(*family, name) {
                continue;
            }
            if let Some(from) = self.table(self.current, *family, name) {
                tables.push(NftChange::Table(Change::Remove(from)));
            }
        }

        out.extend(tables);
        out.extend(chains);
        out.extend(rules);
        out.extend(flowtables);
        out.extend(sets);
        out.extend(elements);
        out.extend(objects);
        out
    }

    /// Whether the kernel rule a move takes out references what `pred`
    /// looks for.
    fn moved_references(&self, m: &super::RuleMove, pred: impl Fn(&RuleInfo) -> bool) -> bool {
        self.kernel_rule(m.family, &m.table, m.from)
            .is_some_and(pred)
    }

    /// The moves `pred` takes, as rule updates, out of `moves`.
    fn take_moves(
        &self,
        moves: &mut Vec<&super::RuleMove>,
        pred: impl Fn(&super::RuleMove) -> bool,
    ) -> Vec<NftChange> {
        let mut taken = Vec::new();
        moves.retain(|m| {
            if pred(m) {
                taken.extend(self.moved(m));
                false
            } else {
                true
            }
        });
        taken
    }

    /// A move as a rule update: from where it is, to where it goes.
    fn moved(&self, m: &super::RuleMove) -> Option<NftChange> {
        let from = self.kernel_rule(m.family, &m.table, m.from)?;
        Some(NftChange::Rule(Change::Update {
            from: NftRule::from_kernel(from),
            to: self.declared_rule(&m.rule, Some(m.placement)),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refusal names each rule it is about: by handle, or by its text
    /// when it has none.
    #[test]
    fn a_refusal_names_every_rule() {
        let rule = |handle: Option<u64>| NftRule {
            family: Family::Ip,
            table: "t".into(),
            chain: "c".into(),
            key: None,
            handle: handle.map(RuleHandle),
            placement: None,
            spec: RuleSpec::new(),
            nft: Some("ip saddr @s drop".into()),
        };
        let blocked = Blocked::ChainRecreate {
            family: Family::Ip,
            table: "t".into(),
            chain: "c".into(),
            reason: "hook 1 -> 3".into(),
            rules: vec![rule(Some(4)), rule(None)],
        };
        let named = "rule handle 4, rule `ip saddr @s drop`";
        assert!(blocked.to_string().contains(named), "{blocked}");
        let refusal = blocked.refusal().unwrap().to_string();
        assert!(refusal.contains(named), "{refusal}");
    }

    const KEYS: [SetKeyType; 8] = [
        SetKeyType::Ipv4Addr,
        SetKeyType::Ipv6Addr,
        SetKeyType::EtherAddr,
        SetKeyType::InetService,
        SetKeyType::IfIndex,
        SetKeyType::ClassId,
        SetKeyType::Mark,
        SetKeyType::InetProto,
    ];

    /// Every key type nlink names reads back as itself, and so does every
    /// concatenation of two to five of them.
    #[test]
    fn a_key_type_reads_back_as_itself() {
        let back = |k: &SetKeyType| SetKeyType::from_kernel(k.type_id(), k.len());
        for key in &KEYS {
            assert_eq!(back(key), *key);
        }
        let mut concats: Vec<Vec<SetKeyType>> = KEYS.iter().map(|k| vec![k.clone()]).collect();
        let mut checked = 0;
        for _ in 2..=5 {
            concats = concats
                .iter()
                .flat_map(|c| {
                    KEYS.iter().map(move |k| {
                        let mut c = c.clone();
                        c.push(k.clone());
                        c
                    })
                })
                .collect();
            for parts in &concats {
                let key = SetKeyType::Concat(parts.clone());
                assert_eq!(back(&key), key);
                checked += 1;
            }
        }
        assert_eq!(checked, 64 + 512 + 4096 + 32768);
    }

    /// What nlink has no name for is kept as the kernel said it, never
    /// guessed.
    #[test]
    fn an_unknown_key_type_is_kept_as_it_is() {
        // nft's TYPE_IFNAME, 16 bytes.
        let ifname = SetKeyType::from_kernel(41, 16);
        assert_eq!(
            ifname,
            SetKeyType::Other {
                type_id: 41,
                len: 16
            }
        );
        assert_eq!((ifname.type_id(), ifname.len()), (41, 16));
        // A name nlink knows, at a length it is not.
        assert_eq!(
            SetKeyType::from_kernel(7, 16),
            SetKeyType::Other {
                type_id: 7,
                len: 16
            }
        );
        // ifname . ipv4_addr: the unknown part takes what the other leaves.
        assert_eq!(
            SetKeyType::from_kernel((41 << 6) | 7, 20),
            SetKeyType::Concat(vec![
                SetKeyType::Other {
                    type_id: 41,
                    len: 16
                },
                SetKeyType::Ipv4Addr
            ])
        );
        // Two unknown parts, or lengths that do not add up: the whole key.
        assert_eq!(
            SetKeyType::from_kernel((41 << 6) | 42, 20),
            SetKeyType::Other {
                type_id: (41 << 6) | 42,
                len: 20
            }
        );
        assert_eq!(
            SetKeyType::from_kernel((7 << 6) | 13, 12),
            SetKeyType::Other {
                type_id: (7 << 6) | 13,
                len: 12
            }
        );
        // A field of id 0, inside, says nothing of where the fields are.
        let zero = (7 << 12) | 13;
        assert_eq!(
            SetKeyType::from_kernel(zero, 12),
            SetKeyType::Other {
                type_id: zero,
                len: 12
            }
        );
        // The unknown part's room must be whole 4-byte words.
        let odd = (41 << 6) | 7;
        assert_eq!(
            SetKeyType::from_kernel(odd, 22),
            SetKeyType::Other {
                type_id: odd,
                len: 22
            }
        );
    }

    /// A map's data type reads back; an object map of a type nlink does not
    /// model says which.
    #[test]
    fn a_maps_data_type_reads_back() {
        use crate::netlink::nftables::NFT_DATA_VERDICT;
        use crate::netlink::nftables::object::ObjectType;
        let set = SetFlags::empty();
        assert_eq!(SetDataType::from_kernel(set, None, None, None), Ok(None));
        assert_eq!(
            SetDataType::from_kernel(SetFlags::MAP, Some(NFT_DATA_VERDICT), None, None),
            Ok(Some(SetDataType::Verdict))
        );
        assert_eq!(
            SetDataType::from_kernel(SetFlags::MAP, Some(19), Some(4), None),
            Ok(Some(SetDataType::Value(SetKeyType::Mark)))
        );
        assert_eq!(
            SetDataType::from_kernel(
                SetFlags::OBJECT,
                None,
                None,
                Some(ObjectType::Counter as u32)
            ),
            Ok(Some(SetDataType::Object(ObjectType::Counter)))
        );
        assert_eq!(
            SetDataType::from_kernel(SetFlags::OBJECT, None, None, Some(99)),
            Err("object type 99".to_string())
        );
        assert_eq!(
            SetDataType::from_kernel(SetFlags::OBJECT, None, None, None),
            Err("an object map without an object type".to_string())
        );
    }
}

#[cfg(test)]
mod change_tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::netlink::nftables::config::{NftDiffOptions, NftablesConfig};
    use crate::netlink::nftables::types::{
        BaseChain, FilterHook, LimitUnit, PacketField, Priority,
    };
    use crate::netlink::nftables::{LimitExpr, QuotaExpr};

    /// `next` against `previous`, offline.
    fn changes(next: &NftablesConfig, previous: &NftablesConfig) -> Vec<NftChange> {
        next.diff_against(previous, &NftDiffOptions::default())
            .unwrap()
            .changes
    }

    fn table(
        f: impl FnOnce(
            crate::netlink::nftables::config::DeclaredTableBuilder,
        ) -> crate::netlink::nftables::config::DeclaredTableBuilder,
    ) -> NftablesConfig {
        NftablesConfig::new().table("t", Family::Ip, |t| {
            f(t.chain("input", |c| {
                c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
            }))
        })
    }

    /// The only change, and what its recreate takes with it.
    fn recreate(changes: &[NftChange]) -> (&NftChange, Vec<String>) {
        let [only] = changes else {
            panic!("one change: {changes:#?}");
        };
        let cascade = only
            .cascade()
            .iter()
            .map(|c| format!("{} {}", c.op(), c.kind()))
            .collect();
        (only, cascade)
    }

    /// The check every build runs sees a change the builder left out, and
    /// one it made twice.
    #[test]
    fn the_plan_check_sees_a_change_left_out() {
        let before = table(|t| {
            t.set("s", |s| s.key_type(SetKeyType::Ipv4Addr))
                .rule_keyed("input", "a", |r| r.accept())
        });
        let diff = table(|t| t)
            .diff_against(&before, &NftDiffOptions::default())
            .unwrap();
        assert_eq!(diff.changes.len(), 2, "{diff}");
        assert_eq!(covers_the_plan(&diff, &diff.changes), Ok(()));
        let fewer = &diff.changes[1..];
        assert!(covers_the_plan(&diff, fewer).is_err(), "{fewer:?}");
        let twice = [diff.changes.clone(), diff.changes[..1].to_vec()].concat();
        assert!(covers_the_plan(&diff, &twice).is_err(), "{twice:?}");
    }

    #[test]
    fn a_set_recreate_takes_its_elements_and_bound_rules() {
        let with = |key: SetKeyType, element: SetElement, field: PacketField| {
            table(move |t| {
                t.set("s", |s| s.key_type(key).element(element)).rule_keyed(
                    "input",
                    "ours",
                    move |r| r.match_in_set(field, "s").counter(),
                )
            })
        };
        let before = with(
            SetKeyType::Ipv4Addr,
            SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            PacketField::Ip4Saddr,
        );
        let after = with(SetKeyType::Mark, SetElement::mark(1), PacketField::Mark);
        let changes = changes(&after, &before);
        let (only, cascade) = recreate(&changes);
        let NftChange::Set(Change::Recreate {
            from, to, reason, ..
        }) = only
        else {
            panic!("{only:#?}");
        };
        assert_eq!(
            (from.key_type.clone(), to.key_type.clone()),
            (SetKeyType::Ipv4Addr, SetKeyType::Mark)
        );
        assert!(reason.starts_with("key Ipv4Addr -> Mark"), "{reason}");
        assert_eq!(cascade, ["add elements", "update rule"]);
    }

    #[test]
    fn a_chain_recreate_takes_its_rules() {
        let at = |hook| {
            NftablesConfig::new().table("t", Family::Ip, move |t| {
                t.chain("c", |c| c.base(BaseChain::filter(hook, Priority::Filter)))
                    .rule_keyed("c", "a", |r| r.match_tcp_dport(22).accept())
                    .rule_keyed("c", "b", |r| r.counter())
            })
        };
        let changes = changes(&at(FilterHook::Forward), &at(FilterHook::Input));
        let (only, cascade) = recreate(&changes);
        let NftChange::Chain(Change::Recreate { reason, .. }) = only else {
            panic!("{only:#?}");
        };
        assert!(reason.contains("hook"), "{reason}");
        assert_eq!(cascade, ["update rule", "update rule"]);
    }

    #[test]
    fn an_object_recreate_takes_its_rules() {
        let at = |rate| {
            table(move |t| {
                t.object(
                    "l",
                    ObjectConfig::Limit(LimitExpr::packets(rate, LimitUnit::Second)),
                )
                .rule_keyed("input", "limited", |r| r.limit_named("l").accept())
            })
        };
        let changes = changes(&at(20), &at(10));
        let (only, cascade) = recreate(&changes);
        assert!(
            matches!(only, NftChange::Object(Change::Recreate { .. })),
            "{only:#?}"
        );
        assert_eq!(cascade, ["update rule"]);
    }

    #[test]
    fn a_flowtable_recreate_takes_its_rules() {
        let at = |priority| {
            NftablesConfig::new().table("t", Family::Inet, move |t| {
                t.chain("fwd", |c| {
                    c.base(BaseChain::filter(FilterHook::Forward, Priority::Filter))
                })
                .flowtable("ft", |f| f.device("lo").priority(priority))
                .rule_keyed("fwd", "offload", |r| r.flow_offload("ft"))
            })
        };
        let changes = changes(&at(10), &at(0));
        let (only, cascade) = recreate(&changes);
        let NftChange::Flowtable(Change::Recreate { reason, .. }) = only else {
            panic!("{only:#?}");
        };
        assert_eq!(reason, "priority 0 -> 10");
        assert_eq!(cascade, ["update rule"]);
    }

    /// A table recreated for its comment takes everything declared in it,
    /// and none of it is listed again at the top.
    #[test]
    fn a_table_recreate_takes_its_contents() {
        let commented = |comment: &'static str| {
            NftablesConfig::new().table("t", Family::Ip, move |t| {
                t.comment(comment)
                    .chain("input", |c| {
                        c.base(BaseChain::filter(FilterHook::Input, Priority::Filter))
                    })
                    .set("s", |s| {
                        s.key_type(SetKeyType::Ipv4Addr)
                            .element(SetElement::ipv4(Ipv4Addr::LOCALHOST))
                    })
                    .object("c", ObjectConfig::Counter)
                    .rule_keyed("input", "r", |r| {
                        r.match_saddr_in_set("s").counter_named("c")
                    })
            })
        };
        let options = NftDiffOptions::default().recreate_on_comment_change(true);
        let changes = commented("b")
            .diff_against(&commented("a"), &options)
            .unwrap()
            .changes;
        let (only, mut cascade) = recreate(&changes);
        assert!(
            matches!(only, NftChange::Table(Change::Recreate { .. })),
            "{only:#?}"
        );
        cascade.sort();
        assert_eq!(
            cascade,
            [
                "add chain",
                "add elements",
                "add object",
                "add rule",
                "add set"
            ]
        );
    }

    /// An update differs, from to to, in what it changes and nothing else.
    #[test]
    fn an_update_changes_what_it_changes() {
        let at = |quota, size| {
            table(move |t| {
                t.set("s", |s| s.key_type(SetKeyType::Ipv4Addr).size(size))
                    .object("q", ObjectConfig::Quota(QuotaExpr::new(quota)))
            })
        };
        let changes = changes(&at(2_000, 128), &at(1_000, 64));
        assert_eq!(changes.len(), 2, "{changes:#?}");
        for change in &changes {
            match change {
                NftChange::Set(Change::Update { from, to }) => {
                    assert_eq!((from.size, to.size), (Some(64), Some(128)));
                    let mut same = from.clone();
                    same.size = to.size;
                    assert_eq!(same, *to);
                }
                NftChange::Object(Change::Update { from, to }) => {
                    assert_ne!(from.config, to.config);
                    assert_eq!((from.name.as_str(), to.name.as_str()), ("q", "q"));
                }
                other => panic!("{other:#?}"),
            }
        }
    }

    /// A rule's place is part of it: one replaced in place keeps its
    /// handle; one moved says where it goes.
    #[test]
    fn a_rule_says_where_it_is_and_where_it_goes() {
        let rules = |first: &'static str, port: u16| {
            table(move |t| {
                let t = t.rule_keyed("input", first, move |r| r.match_tcp_dport(port).accept());
                let second = if first == "a" { "b" } else { "a" };
                t.rule_keyed("input", second, |r| r.counter())
            })
        };
        let changes = changes(&rules("a", 23), &rules("a", 22));
        let [NftChange::Rule(Change::Update { from, to })] = changes.as_slice() else {
            panic!("{changes:#?}");
        };
        assert_eq!(
            (from.handle.is_some(), to.handle, to.placement),
            (true, from.handle, None)
        );
        assert_eq!(to.nft.as_deref(), Some("tcp dport 23 accept"));

        // The same rules, the other way round: each moves, keeping its
        // body.
        let ordered = |a_first: bool| {
            table(move |t| {
                let a = |t: crate::netlink::nftables::config::DeclaredTableBuilder| {
                    t.rule_keyed("input", "a", |r| r.match_tcp_dport(22).accept())
                };
                let b = |t: crate::netlink::nftables::config::DeclaredTableBuilder| {
                    t.rule_keyed("input", "b", |r| r.counter())
                };
                if a_first { b(a(t)) } else { a(b(t)) }
            })
        };
        let changes = self::changes(&ordered(false), &ordered(true));
        assert!(!changes.is_empty());
        assert!(
            changes
                .iter()
                .all(|c| matches!(c, NftChange::Rule(Change::Update { from, to })
                if to.placement.is_some() && to.handle.is_none() && from.spec == to.spec)),
            "{changes:#?}"
        );
    }
}
