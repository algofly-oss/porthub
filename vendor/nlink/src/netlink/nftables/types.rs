//! nftables data types: Family, Hook, Chain, Rule, Table, etc.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::expr::{Expr, SocketKey};
use super::spec::{Field, Item, Match, Reject, RuleSpec, Stmt, Value};
use crate::netlink::error::{Error, Result};
use crate::netlink::tc_handle::TcHandle;

/// nftables address family.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum Family {
    /// IPv4 only.
    Ip = 2,
    /// IPv6 only.
    Ip6 = 10,
    /// Dual-stack (IPv4 + IPv6).
    Inet = 1,
    /// ARP.
    Arp = 3,
    /// Bridge.
    Bridge = 7,
    /// Netdev (ingress).
    Netdev = 5,
}

impl Family {
    /// The name `nft` gives it: `ip`, `ip6`, `inet`, `arp`, `bridge`,
    /// `netdev` (#523).
    pub fn name(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Ip6 => "ip6",
            Self::Inet => "inet",
            Self::Arp => "arp",
            Self::Bridge => "bridge",
            Self::Netdev => "netdev",
        }
    }

    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            2 => Some(Self::Ip),
            10 => Some(Self::Ip6),
            1 => Some(Self::Inet),
            3 => Some(Self::Arp),
            7 => Some(Self::Bridge),
            5 => Some(Self::Netdev),
            _ => None,
        }
    }
}

/// `nft`'s name for it (#523).
impl std::fmt::Display for Family {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The family `nft` names so (#523).
impl std::str::FromStr for Family {
    type Err = crate::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s {
            "ip" => Self::Ip,
            "ip6" => Self::Ip6,
            "inet" => Self::Inet,
            "arp" => Self::Arp,
            "bridge" => Self::Bridge,
            "netdev" => Self::Netdev,
            _ => return Err(crate::Error::invalid_message(format!("unknown nftables family `{s}`"))),
        })
    }
}

/// Netfilter hook point.
///
/// Its number depends on the family (`NF_INET_*`, `NF_NETDEV_*`,
/// `NF_ARP_*`), so it is sent through [`number`](Self::number).
/// [`Ingress`](Self::Ingress) is `NF_INET_INGRESS = 5` in an inet table and
/// `NF_NETDEV_INGRESS = 0` in a netdev one.
///
/// 0.19 split a family-blind `Ingress`, which always encoded `0` and so put
/// an inet chain on prerouting, into `NetdevIngress` and `InetIngress`
/// (Plan 211 M1). Since `number` takes the family, one `Ingress` is right
/// in both again (#708), and the split variants are deprecated.
///
/// A base chain is built as a [`BaseChain`], whose hooks are
/// [`FilterHook`] and [`NatHook`]; this type names the hook of one.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Hook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    /// Ingress hook for `Family::Netdev`. Encodes `NF_NETDEV_INGRESS = 0`.
    #[deprecated(since = "0.33.0", note = "use `Hook::Ingress`, numbered by the family")]
    NetdevIngress,
    /// Ingress hook for `Family::Inet`. Encodes `NF_INET_INGRESS = 5`.
    #[deprecated(since = "0.33.0", note = "use `Hook::Ingress`, numbered by the family")]
    InetIngress,
    /// Egress hook for `Family::Netdev`. Encodes `NF_NETDEV_EGRESS = 1`.
    #[deprecated(since = "0.33.0", note = "use `Hook::Egress`")]
    NetdevEgress,
    /// The ingress hook: `NF_INET_INGRESS` in an inet table (kernel 5.10+),
    /// `NF_NETDEV_INGRESS` in a netdev one. It takes a device.
    Ingress,
    /// The egress hook of a netdev table (`NF_NETDEV_EGRESS`, kernel
    /// 5.16+). It takes a device.
    Egress,
}

impl Hook {
    /// The kernel's number for this hook in a chain of `family`.
    ///
    /// The numbers are per family: the `arp` family has its own
    /// (`NF_ARP_IN = 0`, `NF_ARP_OUT = 1`, `netfilter_arp.h`), so an `arp`
    /// input chain sent as the inet `NF_INET_LOCAL_IN = 1` filtered
    /// *outgoing* ARP, and an output chain was refused (#484). Ingress is
    /// `NF_NETDEV_INGRESS = 0` in a netdev table and `NF_INET_INGRESS = 5`
    /// elsewhere.
    pub fn number(self, family: Family) -> u32 {
        match (family, self) {
            (Family::Arp, Self::Input) => 0,      // NF_ARP_IN
            (Family::Arp, Self::Output) => 1,     // NF_ARP_OUT
            (Family::Netdev, Self::Ingress) => 0, // NF_NETDEV_INGRESS
            (_, Self::Ingress) => 5,              // NF_INET_INGRESS
            (_, Self::Egress) => 1,               // NF_NETDEV_EGRESS
            #[allow(deprecated)]
            _ => self.to_u32(),
        }
    }

    /// The hook numbered `number` in a chain of `family`: the inverse of
    /// [`number`](Self::number), for a chain read back from the kernel.
    pub fn from_number(family: Family, number: u32) -> Option<Self> {
        Some(match (family, number) {
            (Family::Arp, 0) => Self::Input,
            (Family::Arp, 1) => Self::Output,
            (Family::Arp, _) => return None,
            (Family::Netdev, 0) => Self::Ingress,
            (Family::Netdev, 1) => Self::Egress,
            (Family::Netdev, _) => return None,
            (_, 0) => Self::Prerouting,
            (_, 1) => Self::Input,
            (_, 2) => Self::Forward,
            (_, 3) => Self::Output,
            (_, 4) => Self::Postrouting,
            (_, 5) => Self::Ingress,
            _ => return None,
        })
    }

    /// Returns the kernel hook number for the `inet`, `ip`, `ip6`, `bridge`
    /// and `netdev` families. Verified against
    /// `include/uapi/linux/netfilter.h` (`enum nf_inet_hooks`) and
    /// `include/uapi/linux/netfilter_netdev.h`
    /// (`enum nf_dev_hooks`). Wrong for `arp`, which numbers its hooks
    /// differently, and for an inet `Ingress`: use [`number`](Self::number).
    #[deprecated(
        since = "0.31.0",
        note = "the number depends on the family; use `number(family)`"
    )]
    pub fn to_u32(self) -> u32 {
        #[allow(deprecated)]
        match self {
            Self::Prerouting => 0,    // NF_INET_PRE_ROUTING
            Self::Input => 1,         // NF_INET_LOCAL_IN
            Self::Forward => 2,       // NF_INET_FORWARD
            Self::Output => 3,        // NF_INET_LOCAL_OUT
            Self::Postrouting => 4,   // NF_INET_POST_ROUTING
            Self::InetIngress => 5,   // NF_INET_INGRESS
            Self::NetdevIngress => 0, // NF_NETDEV_INGRESS
            Self::NetdevEgress => 1,  // NF_NETDEV_EGRESS
            Self::Ingress => 0,       // NF_NETDEV_INGRESS
            Self::Egress => 1,        // NF_NETDEV_EGRESS
        }
    }

    /// Returns `true` if a `filter` chain in a `family` table can take this
    /// hook, as the kernel's chain types allow: the five L3 hooks in ip,
    /// ip6, inet and bridge tables, input and output in arp, ingress in
    /// inet and netdev, egress in netdev.
    pub fn is_valid_for_family(self, family: Family) -> bool {
        #[allow(deprecated)]
        match (self, family) {
            (Self::Ingress | Self::NetdevIngress, Family::Netdev) => true,
            (Self::Egress | Self::NetdevEgress, Family::Netdev) => true,
            // The ip and ip6 filter chain types have no ingress hook; only
            // inet's has (`nft_chain_filter_inet`). nft refuses it with
            // "the ip family does not support this hook".
            (Self::Ingress | Self::InetIngress, Family::Inet) => true,
            (
                Self::Prerouting
                | Self::Input
                | Self::Forward
                | Self::Output
                | Self::Postrouting,
                Family::Inet | Family::Ip | Family::Ip6 | Family::Bridge,
            ) => true,
            // ARP has an input and an output hook, and nothing else
            // (`nf_tables_arp`'s filter chain type).
            (Self::Input | Self::Output, Family::Arp) => true,
            _ => false,
        }
    }

    /// The ingress and egress hooks bind to a device.
    fn takes_devices(self) -> bool {
        matches!(self.neutral(), Self::Ingress | Self::Egress)
    }

    /// The hook with the deprecated per-family spellings folded in.
    fn neutral(self) -> Self {
        #[allow(deprecated)]
        match self {
            Self::NetdevIngress | Self::InetIngress => Self::Ingress,
            Self::NetdevEgress => Self::Egress,
            other => other,
        }
    }

    fn name(self) -> &'static str {
        match self.neutral() {
            Self::Prerouting => "prerouting",
            Self::Input => "input",
            Self::Forward => "forward",
            Self::Output => "output",
            Self::Postrouting => "postrouting",
            Self::Ingress => "ingress",
            _ => "egress",
        }
    }
}

impl std::fmt::Display for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Chain type string for the kernel.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChainType {
    Filter,
    Nat,
    Route,
}

impl ChainType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Filter => "filter",
            Self::Nat => "nat",
            Self::Route => "route",
        }
    }

    /// Parse a kernel-side chain-type string (`"filter"`, `"nat"`,
    /// `"route"`) into the typed enum. Returns `None` for any
    /// other string — the kernel can grow new chain types
    /// (`"netdev"` etc.), and an unrecognised value should not
    /// silently collapse to one of the known variants.
    pub fn from_kernel_string(s: &str) -> Option<Self> {
        match s {
            "filter" => Some(Self::Filter),
            "nat" => Some(Self::Nat),
            "route" => Some(Self::Route),
            _ => None,
        }
    }
}

/// Chain priority (determines ordering).
///
/// Two priorities are equal when they are the same number:
/// `Priority::Custom(0) == Priority::Filter`.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Priority {
    Raw,
    Mangle,
    DstNat,
    Filter,
    Security,
    SrcNat,
    Custom(i32),
}

impl Priority {
    pub fn to_i32(self) -> i32 {
        match self {
            Self::Raw => -300,
            Self::Mangle => -150,
            Self::DstNat => -100,
            Self::Filter => 0,
            Self::Security => 50,
            Self::SrcNat => 100,
            Self::Custom(v) => v,
        }
    }

    /// The priority numbered `n`, by its name when it has one: what
    /// [`ChainInfo::kind`] reads back.
    pub fn from_i32(n: i32) -> Self {
        match n {
            -300 => Self::Raw,
            -150 => Self::Mangle,
            -100 => Self::DstNat,
            0 => Self::Filter,
            50 => Self::Security,
            100 => Self::SrcNat,
            n => Self::Custom(n),
        }
    }
}

impl PartialEq for Priority {
    fn eq(&self, other: &Self) -> bool {
        self.to_i32() == other.to_i32()
    }
}

impl Eq for Priority {}

/// Default policy for a base chain.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Policy {
    Accept,
    Drop,
}

impl Policy {
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Accept => 1,
            Self::Drop => 0,
        }
    }

    /// The policy the kernel numbers `n` (`NF_DROP = 0`, `NF_ACCEPT = 1`).
    pub fn from_u32(n: u32) -> Option<Self> {
        match n {
            0 => Some(Self::Drop),
            1 => Some(Self::Accept),
            _ => None,
        }
    }
}

/// What a chain is (#708): one only a `jump` or `goto` enters, or one
/// hooked into the packet path.
///
/// A regular chain has no hook, type, priority or policy, so it cannot be
/// given one. A base chain has them all, in a [`BaseChain`].
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ChainKind {
    /// Entered only by a `jump` or a `goto`.
    #[default]
    Regular,
    /// Hooked into the packet path.
    Base(BaseChain),
}

impl ChainKind {
    /// The kind with a base chain's devices in order: the kernel keeps a
    /// chain's devices as a set (#708).
    pub(crate) fn with_sorted_devices(self) -> Self {
        match self {
            Self::Base(mut base) => {
                base.devices.sort();
                Self::Base(base)
            }
            regular => regular,
        }
    }

    /// The base chain, if this is one.
    pub fn base(&self) -> Option<&BaseChain> {
        match self {
            Self::Base(base) => Some(base),
            Self::Regular => None,
        }
    }

    /// The kind the deprecated setters describe, or why it is none: they
    /// can name a policy without a hook, a nat chain on forward.
    pub(crate) fn from_parts(
        hook: Option<Hook>,
        chain_type: Option<ChainType>,
        priority: Option<Priority>,
        policy: Option<Policy>,
        devices: &[String],
    ) -> std::result::Result<Self, String> {
        let Some(hook) = hook else {
            if policy.is_some() {
                return Err("a policy needs a base chain; a chain without a hook has none".into());
            }
            // The kernel reads a type, a priority and devices only in a
            // hook, so without one they say nothing.
            return Ok(Self::Regular);
        };
        let base = BaseChain::of_parts(
            chain_type.unwrap_or(ChainType::Filter),
            hook,
            priority.unwrap_or(Priority::Filter),
            devices.to_vec(),
        )?;
        Ok(Self::Base(match policy {
            Some(policy) => base.policy(policy),
            None => base,
        }))
    }
}

/// A base chain: its type and hook, its priority, and its default policy
/// (#708).
///
/// It is built from a hook its type has, so a `nat` chain on forward, a
/// `route` chain off output, and an ingress chain without a device cannot
/// be written:
///
/// ```
/// use nlink::netlink::nftables::{BaseChain, FilterHook, NatHook, Policy, Priority};
///
/// let input = BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop);
/// let snat = BaseChain::nat(NatHook::Postrouting, Priority::SrcNat);
/// let reroute = BaseChain::route(Priority::Mangle);
/// let ingress = BaseChain::filter(FilterHook::ingress(["eth0", "eth1"]), Priority::Filter);
/// assert_eq!(ingress.devices(), ["eth0", "eth1"]);
/// ```
///
/// What depends on the table's family is checked when the family is
/// known, before anything is sent ([`check_family`](Self::check_family)):
/// the hooks a family has, `nat` and `route` chains only in ip, ip6 and
/// inet tables, and a `nat` chain's priority above conntrack's.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseChain {
    #[cfg_attr(feature = "serde", serde(rename = "type"))]
    chain_type: ChainType,
    hook: Hook,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Vec::is_empty"))]
    devices: Vec<String>,
    priority: Priority,
    #[cfg_attr(feature = "serde", serde(skip_serializing_if = "Option::is_none"))]
    policy: Option<Policy>,
}

impl BaseChain {
    /// `type filter hook <hook> priority <priority>`.
    pub fn filter(hook: FilterHook, priority: Priority) -> Self {
        let (hook, devices) = match hook {
            FilterHook::Prerouting => (Hook::Prerouting, Vec::new()),
            FilterHook::Input => (Hook::Input, Vec::new()),
            FilterHook::Forward => (Hook::Forward, Vec::new()),
            FilterHook::Output => (Hook::Output, Vec::new()),
            FilterHook::Postrouting => (Hook::Postrouting, Vec::new()),
            FilterHook::Ingress(devices) => (Hook::Ingress, devices.0),
            FilterHook::Egress(devices) => (Hook::Egress, devices.0),
        };
        Self::of(ChainType::Filter, hook, devices, priority)
    }

    /// `type nat hook <hook> priority <priority>`, in an ip, ip6 or inet
    /// table. Its priority must be above conntrack's (-200): NAT needs the
    /// connection tracked first.
    pub fn nat(hook: NatHook, priority: Priority) -> Self {
        let hook = match hook {
            NatHook::Prerouting => Hook::Prerouting,
            NatHook::Input => Hook::Input,
            NatHook::Output => Hook::Output,
            NatHook::Postrouting => Hook::Postrouting,
        };
        Self::of(ChainType::Nat, hook, Vec::new(), priority)
    }

    /// `type route hook output priority <priority>`, in an ip, ip6 or inet
    /// table: a packet a rule changes (its mark, its addresses) is routed
    /// again. Output is the only hook a route chain has.
    pub fn route(priority: Priority) -> Self {
        Self::of(ChainType::Route, Hook::Output, Vec::new(), priority)
    }

    fn of(chain_type: ChainType, hook: Hook, devices: Vec<String>, priority: Priority) -> Self {
        Self {
            chain_type,
            hook,
            devices,
            priority,
            policy: None,
        }
    }

    /// The default policy: what happens to a packet no rule decides. A
    /// chain created without one accepts, and a declared chain without one
    /// keeps whatever the kernel has.
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// A base chain from parts known only at run time, such as a
    /// configuration file or a command line, or an error saying why they
    /// make none: a `nat` chain on forward or ingress, a `route` chain off
    /// output, an ingress or egress hook without a device, a device on any
    /// other hook.
    pub fn try_new<I, S>(
        chain_type: ChainType,
        hook: Hook,
        priority: Priority,
        devices: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let devices = devices.into_iter().map(Into::into).collect();
        Self::of_parts(chain_type, hook, priority, devices).map_err(Error::invalid_message)
    }

    fn of_parts(
        chain_type: ChainType,
        hook: Hook,
        priority: Priority,
        devices: Vec<String>,
    ) -> std::result::Result<Self, String> {
        let hook = hook.neutral();
        let refuse = Err;
        if hook.takes_devices() && devices.is_empty() {
            return refuse(format!("an {hook} chain needs a device"));
        }
        if !hook.takes_devices() && !devices.is_empty() {
            return refuse(format!(
                "a chain on the {hook} hook takes no device; ingress and egress chains do"
            ));
        }
        match (chain_type, hook) {
            (ChainType::Filter, _) => Ok(Self::of(chain_type, hook, devices, priority)),
            (ChainType::Nat, Hook::Prerouting | Hook::Input | Hook::Output | Hook::Postrouting) => {
                Ok(Self::of(chain_type, hook, devices, priority))
            }
            (ChainType::Nat, _) => refuse(format!("a nat chain has no {hook} hook")),
            (ChainType::Route, Hook::Output) => Ok(Self::route(priority)),
            (ChainType::Route, _) => refuse("a route chain hooks output only".into()),
        }
    }

    /// Whether a `family` table can hold this chain, as the kernel's chain
    /// types allow, or an error saying why not:
    /// - a filter chain on a hook the family has (see
    ///   [`Hook::is_valid_for_family`]);
    /// - a nat or route chain in an ip, ip6 or inet table;
    /// - a nat chain above conntrack's priority (`NF_IP_PRI_CONNTRACK`,
    ///   -200).
    pub fn check_family(&self, family: Family) -> Result<()> {
        match self.family_problem(family) {
            Some(why) => Err(Error::invalid_message(why)),
            None => Ok(()),
        }
    }

    pub(crate) fn family_problem(&self, family: Family) -> Option<String> {
        let l3 = matches!(family, Family::Ip | Family::Ip6 | Family::Inet);
        match self.chain_type {
            ChainType::Filter if !self.hook.is_valid_for_family(family) => {
                Some(format!("the {family} family has no {} hook", self.hook))
            }
            ChainType::Nat | ChainType::Route if !l3 => Some(format!(
                "the {family} family has no {} chains",
                self.chain_type.as_str()
            )),
            ChainType::Nat if self.priority.to_i32() <= -200 => {
                Some("a nat chain's priority must be above -200 (conntrack)".into())
            }
            _ => None,
        }
    }

    /// `filter`, `nat` or `route`.
    pub fn chain_type(&self) -> ChainType {
        self.chain_type
    }

    /// The hook.
    pub fn hook(&self) -> Hook {
        self.hook
    }

    /// The devices an ingress or egress chain is bound to; empty for any
    /// other.
    pub fn devices(&self) -> &[String] {
        &self.devices
    }

    /// The priority.
    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// The default policy, if one was given.
    pub fn default_policy(&self) -> Option<Policy> {
        self.policy
    }
}

/// The hook of a `type filter` chain (#708).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterHook {
    Prerouting,
    Input,
    Forward,
    Output,
    Postrouting,
    /// `hook ingress`, on devices: an inet table's (kernel 5.10+) or a
    /// netdev table's.
    Ingress(Devices),
    /// `hook egress`, on devices: a netdev table's (kernel 5.16+).
    Egress(Devices),
}

impl FilterHook {
    /// `hook ingress device eth0`, or `devices = { eth0, eth1 }`.
    pub fn ingress(devices: impl Into<Devices>) -> Self {
        Self::Ingress(devices.into())
    }

    /// `hook egress device eth0`, or `devices = { eth0, eth1 }`.
    pub fn egress(devices: impl Into<Devices>) -> Self {
        Self::Egress(devices.into())
    }
}

/// The hook of a `type nat` chain (#708). There is no forward NAT: a
/// forwarded packet is translated at prerouting and postrouting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NatHook {
    Prerouting,
    Input,
    Output,
    Postrouting,
}

/// The devices an ingress or egress chain is bound to: at least one
/// (#708). One is sent as `NFTA_HOOK_DEV`, several as `NFTA_HOOK_DEVS`.
///
/// ```
/// use nlink::netlink::nftables::Devices;
///
/// assert_eq!(Devices::from("eth0").as_slice(), ["eth0"]);
/// assert_eq!(Devices::new("eth0").and("eth1"), Devices::from(["eth0", "eth1"]));
/// assert!(Devices::try_from(Vec::<String>::new()).is_err());
/// ```
///
/// An empty array does not compile:
///
/// ```compile_fail
/// use nlink::netlink::nftables::Devices;
///
/// let none: [&str; 0] = [];
/// let _ = Devices::from(none);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Devices(Vec<String>);

impl Devices {
    /// One device.
    pub fn new(device: impl Into<String>) -> Self {
        Self(vec![device.into()])
    }

    /// And another.
    pub fn and(mut self, device: impl Into<String>) -> Self {
        self.0.push(device.into());
        self
    }

    /// The devices, in the order given.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}

impl From<&str> for Devices {
    fn from(device: &str) -> Self {
        Self::new(device)
    }
}

impl From<String> for Devices {
    fn from(device: String) -> Self {
        Self::new(device)
    }
}

impl<S: Into<String>, const N: usize> From<[S; N]> for Devices {
    fn from(devices: [S; N]) -> Self {
        const {
            assert!(
                N > 0,
                "an ingress or egress chain needs at least one device"
            )
        };
        Self(devices.into_iter().map(Into::into).collect())
    }
}

impl TryFrom<Vec<String>> for Devices {
    type Error = Error;

    fn try_from(devices: Vec<String>) -> Result<Self> {
        if devices.is_empty() {
            return Err(Error::invalid_message(
                "an ingress or egress chain needs at least one device",
            ));
        }
        Ok(Self(devices))
    }
}

/// A validated nftables chain name.
///
/// Chain identity in nftables is a `(family, table_name, chain_name)`
/// triple, all case-sensitive. The kernel enforces
/// `NFT_NAME_MAXLEN = 256` (per
/// `include/uapi/linux/netfilter/nf_tables.h`) and rejects interior
/// NULs (the attribute is a NUL-terminated C string at the wire layer).
///
/// Construction validates:
/// - Non-empty.
/// - No interior NUL bytes (`\0`).
/// - At most 255 bytes (one byte reserved for the NUL terminator).
///
/// Round-trip note: `ChainName` is `Display` for natural use in
/// log messages and `AsRef<str>` so it slots into existing
/// `&str`-shaped APIs.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainName(String);

impl ChainName {
    /// Maximum chain-name length on the wire, in bytes.
    /// Matches kernel `NFT_NAME_MAXLEN - 1` (the kernel slot is
    /// 256 bytes including the trailing NUL).
    pub const MAX_LEN: usize = 255;

    /// Construct a chain name, validating against the kernel contract.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(Error::invalid_message(
                "ChainName: empty chain names are rejected by nftables",
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(Error::invalid_message(format!(
                "ChainName: {} bytes exceeds NFT_NAME_MAXLEN-1 ({} bytes)",
                s.len(),
                Self::MAX_LEN,
            )));
        }
        if s.contains('\0') {
            return Err(Error::invalid_message(
                "ChainName: interior NUL bytes are rejected — nftables wire format is a \
                 NUL-terminated C string"
                    ,
            ));
        }
        Ok(Self(s))
    }

    /// View as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for ChainName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ChainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unwrap to the owned name. Lossless; the inbound direction stays
/// validating ([`TryFrom<&str>`]/[`ChainName::new`]).
impl From<ChainName> for String {
    #[inline]
    fn from(name: ChainName) -> Self {
        name.0
    }
}

impl TryFrom<&str> for ChainName {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<String> for ChainName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl std::str::FromStr for ChainName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// A validated nftables table name.
///
/// Mirrors [`ChainName`]: the kernel rejects empty / overlong /
/// interior-NUL names, so this newtype enforces the same contract at
/// the API boundary and — crucially — makes the
/// `Chain::new(table, name)` argument order a compile-time concern
/// rather than two interchangeable `&str`s. Construct via
/// [`TableName::new`], `"filter".parse()`, or `TryFrom`; it is
/// `Display` + `AsRef<str>` for natural use in messages and
/// `&str`-shaped APIs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TableName(String);

impl TableName {
    /// Maximum table-name length on the wire, in bytes
    /// (kernel `NFT_NAME_MAXLEN - 1`).
    pub const MAX_LEN: usize = 255;

    /// Construct a table name, validating against the kernel contract.
    pub fn new(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        if s.is_empty() {
            return Err(Error::invalid_message(
                "TableName: empty table names are rejected by nftables",
            ));
        }
        if s.len() > Self::MAX_LEN {
            return Err(Error::invalid_message(format!(
                "TableName: {} bytes exceeds NFT_NAME_MAXLEN-1 ({} bytes)",
                s.len(),
                Self::MAX_LEN,
            )));
        }
        if s.contains('\0') {
            return Err(Error::invalid_message(
                "TableName: interior NUL bytes are rejected — nftables wire format is a \
                 NUL-terminated C string"
                    ,
            ));
        }
        Ok(Self(s))
    }

    /// View as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for TableName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TableName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Unwrap to the owned name. Lossless; the inbound direction stays
/// validating ([`TryFrom<&str>`]/[`TableName::new`]).
impl From<TableName> for String {
    #[inline]
    fn from(name: TableName) -> Self {
        name.0
    }
}

impl TryFrom<&str> for TableName {
    type Error = Error;
    fn try_from(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl TryFrom<String> for TableName {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        Self::new(s)
    }
}

impl std::str::FromStr for TableName {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

/// Rule verdict.
///
/// `#[non_exhaustive]` so new variants can be added additively.
/// [`Verdict::JumpTo`] and [`Verdict::GotoTo`] carry a validated
/// [`ChainName`] — interior NULs / overlong / empty names are
/// rejected at construction rather than at kernel apply time.
///
/// (The 0.20.1 `Verdict::Jump(String)` / `Verdict::Goto(String)`
/// variants were removed in 0.21.)
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Verdict {
    Accept,
    Drop,
    Continue,
    Return,
    /// Jump to a named chain (push-and-continue). Validated against
    /// the kernel chain-name contract at construction.
    JumpTo(ChainName),
    /// Goto a named chain (tail-call). Validated against the kernel
    /// chain-name contract at construction.
    GotoTo(ChainName),
}

#[cfg(test)]
mod chainname_tests {
    use super::*;

    #[test]
    fn chainname_accepts_short_ascii() {
        assert!(ChainName::new("foo").is_ok());
    }

    #[test]
    fn chainname_rejects_empty() {
        assert!(ChainName::new("").is_err());
    }

    #[test]
    fn chainname_rejects_interior_nul() {
        assert!(ChainName::new("foo\0bar").is_err());
    }

    #[test]
    fn chainname_rejects_overlong() {
        let s = "a".repeat(256); // 256 bytes > 255 max
        assert!(ChainName::new(s).is_err());
    }

    #[test]
    fn chainname_accepts_at_max_len() {
        let s = "a".repeat(ChainName::MAX_LEN);
        assert!(ChainName::new(s).is_ok());
    }

    #[test]
    fn chainname_display_matches_str() {
        let c = ChainName::new("filter_input").unwrap();
        assert_eq!(c.to_string(), "filter_input");
        assert_eq!(c.as_str(), "filter_input");
        let s: &str = c.as_ref();
        assert_eq!(s, "filter_input");
    }

    #[test]
    fn chainname_tryfrom_str() {
        let c: ChainName = "input".try_into().unwrap();
        assert_eq!(c.as_str(), "input");
        let r: Result<ChainName> = "".try_into();
        assert!(r.is_err());
    }
}

/// Connection tracking state flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtState(pub u32);

impl CtState {
    pub const INVALID: Self = Self(1);
    pub const ESTABLISHED: Self = Self(2);
    pub const RELATED: Self = Self(4);
    pub const NEW: Self = Self(8);
    pub const UNTRACKED: Self = Self(64);

    /// Create an empty state with no flags set.
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn bits(self) -> u32 {
        self.0
    }
}

impl Default for CtState {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::ops::BitOr for CtState {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for CtState {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// The 16 label bytes with only `bit` set, laid out as the kernel's
/// `unsigned long` bitmap is on this host — which is what `ct label`
/// reads and `ct label set` ORs in. `None` past bit 127.
pub(crate) fn ct_label_mask(bit: u8) -> Option<Vec<u8>> {
    const WORD: usize = usize::BITS as usize;
    let bit = usize::from(bit);
    if bit >= 128 {
        return None;
    }
    let mut words = [0usize; 128 / WORD];
    words[bit / WORD] |= 1 << (bit % WORD);
    Some(words.iter().flat_map(|w| w.to_ne_bytes()).collect())
}

/// A connection's direction — `enum ip_conntrack_dir`: the original
/// tuple, or the reply's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum CtDirection {
    /// `original`: as the connection was opened.
    Original = 0,
    /// `reply`.
    Reply = 1,
}

impl CtDirection {
    /// The direction of an `NFTA_CT_DIRECTION` value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Original),
            1 => Some(Self::Reply),
            _ => None,
        }
    }
}

bitflags::bitflags! {
    /// A connection's status bits (`ct status`), the `IPS_*` of
    /// `linux/netfilter/nf_conntrack_common.h`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct CtStatus: u32 {
        /// `expected`: an expected connection (a helper's).
        const EXPECTED = 1 << 0;
        /// `seen-reply`.
        const SEEN_REPLY = 1 << 1;
        /// `assured`.
        const ASSURED = 1 << 2;
        /// `confirmed`.
        const CONFIRMED = 1 << 3;
        /// `snat`.
        const SRC_NAT = 1 << 4;
        /// `dnat`.
        const DST_NAT = 1 << 5;
        /// `dying`.
        const DYING = 1 << 9;
        /// `fixed-timeout`.
        const FIXED_TIMEOUT = 1 << 10;
        /// `offload`: on a flowtable.
        const OFFLOAD = 1 << 14;
        /// `hw-offload`.
        const HW_OFFLOAD = 1 << 15;
        // The rest read back as they are.
        const _ = !0;
    }
}

/// A packet's type (`meta pkttype`), the `PACKET_*` of
/// `linux/if_packet.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum PktType {
    /// `host`: to this host.
    Host = 0,
    /// `broadcast`.
    Broadcast = 1,
    /// `multicast`.
    Multicast = 2,
    /// `other`: to another host, seen in promiscuous mode.
    OtherHost = 3,
}

/// What a `fib` lookup returns — `enum nft_fib_result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum FibResult {
    /// `oif`: the output interface's index.
    Oif = 1,
    /// `oifname`: its name.
    OifName = 2,
    /// `type`: the address type, an `RTN_*` ([`RouteType`](crate::netlink::types::route::RouteType)).
    AddrType = 3,
}

impl FibResult {
    /// The result of an `NFTA_FIB_RESULT` value.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Oif),
            2 => Some(Self::OifName),
            3 => Some(Self::AddrType),
            _ => None,
        }
    }
}

bitflags::bitflags! {
    /// What a `fib` lookup keys on, and how it answers — the
    /// `NFTA_FIB_F_*` flags: `fib saddr . iif` is `SADDR | IIF`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct FibFlags: u32 {
        /// `saddr`: look up the source address.
        const SADDR = 1 << 0;
        /// `daddr`: look up the destination address.
        const DADDR = 1 << 1;
        /// `mark`: with the packet mark.
        const MARK = 1 << 2;
        /// `iif`: with the input interface.
        const IIF = 1 << 3;
        /// `oif`: with the output interface.
        const OIF = 1 << 4;
        /// Answer whether there is a result (`exists`/`missing`), not the
        /// result.
        const PRESENT = 1 << 5;
        // A newer kernel's flags read back as they are.
        const _ = !0;
    }
}

/// In or out of a range — `enum nft_range_ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum RangeOp {
    /// Within the range.
    Eq = 0,
    /// Outside it.
    Neq = 1,
}

impl RangeOp {
    /// The op of an `NFTA_RANGE_OP` value.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Eq),
            1 => Some(Self::Neq),
            _ => None,
        }
    }
}

/// One end of a range for [`Rule::match_range`] (#528), of the field's
/// kind: a port, an address, a 32-bit mark or interface index, or an
/// 8-bit protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RangeValue {
    /// A port.
    Port(u16),
    /// An IPv4 or IPv6 address.
    Addr(std::net::IpAddr),
    /// A mark or an interface index.
    U32(u32),
    /// A protocol number.
    U8(u8),
}

impl From<u16> for RangeValue {
    fn from(port: u16) -> Self {
        Self::Port(port)
    }
}

impl From<u32> for RangeValue {
    fn from(value: u32) -> Self {
        Self::U32(value)
    }
}

impl From<u8> for RangeValue {
    fn from(value: u8) -> Self {
        Self::U8(value)
    }
}

impl From<std::net::IpAddr> for RangeValue {
    fn from(addr: std::net::IpAddr) -> Self {
        Self::Addr(addr)
    }
}

impl From<Ipv4Addr> for RangeValue {
    fn from(addr: Ipv4Addr) -> Self {
        Self::Addr(addr.into())
    }
}

impl From<Ipv6Addr> for RangeValue {
    fn from(addr: Ipv6Addr) -> Self {
        Self::Addr(addr.into())
    }
}

/// What a [`LimitExpr`](super::expr::LimitExpr) counts (`NFTA_LIMIT_TYPE`).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum LimitKind {
    /// `NFT_LIMIT_PKTS`: packets per unit.
    Packets = 0,
    /// `NFT_LIMIT_PKT_BYTES`: bytes per unit.
    Bytes = 1,
}

impl LimitKind {
    /// The kind of an `NFTA_LIMIT_TYPE` value.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Packets),
            1 => Some(Self::Bytes),
            _ => None,
        }
    }
}

/// The code of a family-independent reject (`reject with icmpx …`),
/// which the kernel turns into the ICMP or ICMPv6 code that means it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum IcmpxCode {
    /// `no-route`.
    NoRoute = 0,
    /// `port-unreachable`, what a plain `reject` sends.
    PortUnreachable = 1,
    /// `host-unreachable`.
    HostUnreachable = 2,
    /// `admin-prohibited`.
    AdminProhibited = 3,
}

impl IcmpxCode {
    /// The code of an `NFTA_REJECT_ICMP_CODE` value, in an ICMPX reject.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NoRoute),
            1 => Some(Self::PortUnreachable),
            2 => Some(Self::HostUnreachable),
            3 => Some(Self::AdminProhibited),
            _ => None,
        }
    }
}

/// Rate limit unit.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LimitUnit {
    Second,
    Minute,
    Hour,
    Day,
}

impl LimitUnit {
    pub fn to_u64(self) -> u64 {
        match self {
            Self::Second => 1,
            Self::Minute => 60,
            Self::Hour => 3600,
            Self::Day => 86400,
        }
    }
}

/// nftables register, encoding the kernel UAPI register IDs from
/// `include/uapi/linux/netfilter/nf_tables.h`.
///
/// The data area is 16 32-bit words. `R0..=R3` (`NFT_REG_1..=NFT_REG_4`)
/// name it in 16-byte steps; `Reg32_00..=Reg32_15` (`NFT_REG32_00..=15`)
/// name each word, which is what a concatenation needs: `ip saddr . tcp
/// dport` loads the address into word 0 and the port into word 1.
///
/// A word that starts a 16-byte register has two names — `Reg32_04` is
/// `R1` — and the kernel dumps the 16-byte one. nlink writes that form too
/// ([`Self::wire`]), so a rule built with either name reads back as it was
/// written and `NftablesConfig::diff` does not see a change that is only a
/// register's spelling (Plan 178).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum Register {
    /// `NFT_REG_VERDICT`. The dedicated verdict register.
    Verdict = 0,
    /// `NFT_REG_1`. First 16-byte data register.
    R0 = 1,
    /// `NFT_REG_2`. Second 16-byte data register.
    R1 = 2,
    /// `NFT_REG_3`. Third 16-byte data register.
    R2 = 3,
    /// `NFT_REG_4`. Fourth 16-byte data register.
    R3 = 4,
    /// `NFT_REG32_00`, word 0 — the first word of `R0`.
    Reg32_00 = 8,
    /// `NFT_REG32_01`, word 1.
    Reg32_01 = 9,
    /// `NFT_REG32_02`, word 2.
    Reg32_02 = 10,
    /// `NFT_REG32_03`, word 3.
    Reg32_03 = 11,
    /// `NFT_REG32_04`, word 4 — the first word of `R1`.
    Reg32_04 = 12,
    /// `NFT_REG32_05`, word 5.
    Reg32_05 = 13,
    /// `NFT_REG32_06`, word 6.
    Reg32_06 = 14,
    /// `NFT_REG32_07`, word 7.
    Reg32_07 = 15,
    /// `NFT_REG32_08`, word 8 — the first word of `R2`.
    Reg32_08 = 16,
    /// `NFT_REG32_09`, word 9.
    Reg32_09 = 17,
    /// `NFT_REG32_10`, word 10.
    Reg32_10 = 18,
    /// `NFT_REG32_11`, word 11.
    Reg32_11 = 19,
    /// `NFT_REG32_12`, word 12 — the first word of `R3`.
    Reg32_12 = 20,
    /// `NFT_REG32_13`, word 13.
    Reg32_13 = 21,
    /// `NFT_REG32_14`, word 14.
    Reg32_14 = 22,
    /// `NFT_REG32_15`, word 15 — the last.
    Reg32_15 = 23,
}

impl Register {
    const WORDS: [Self; 16] = [
        Self::Reg32_00,
        Self::Reg32_01,
        Self::Reg32_02,
        Self::Reg32_03,
        Self::Reg32_04,
        Self::Reg32_05,
        Self::Reg32_06,
        Self::Reg32_07,
        Self::Reg32_08,
        Self::Reg32_09,
        Self::Reg32_10,
        Self::Reg32_11,
        Self::Reg32_12,
        Self::Reg32_13,
        Self::Reg32_14,
        Self::Reg32_15,
    ];

    /// The register starting at 32-bit word `word` of the data area, in
    /// the form the kernel dumps: `R0` for word 0, `Reg32_01` for word 1,
    /// `R1` for word 4. `None` past word 15.
    pub fn word(word: usize) -> Option<Self> {
        Self::WORDS.get(word).map(|r| r.canonical())
    }

    /// The kernel's spelling of this register: a word that starts a
    /// 16-byte register is named by that register.
    pub fn canonical(self) -> Self {
        match self {
            Self::Reg32_00 => Self::R0,
            Self::Reg32_04 => Self::R1,
            Self::Reg32_08 => Self::R2,
            Self::Reg32_12 => Self::R3,
            other => other,
        }
    }

    /// The register number nlink writes: [`Self::canonical`]'s.
    pub fn wire(self) -> u32 {
        self.canonical() as u32
    }

    /// Reverse mapping for the expression decoder (#164). `None` for a
    /// number that is not a register.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Verdict),
            1 => Some(Self::R0),
            2 => Some(Self::R1),
            3 => Some(Self::R2),
            4 => Some(Self::R3),
            8..=23 => Self::WORDS.get((v - 8) as usize).copied(),
            _ => None,
        }
    }
}

/// `meta nfproto` L3-protocol values, used as the guard prepended to
/// the address matchers (see [`Rule::match_saddr_v4`] / `_v6`).
pub(crate) const NFPROTO_IPV4: u8 = 2;
pub(crate) const NFPROTO_IPV6: u8 = 10;

/// `meta l4proto` values, used as the guard prepended by the
/// transport-layer matchers.
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// TCP header flags — the flags byte at offset 13 of the TCP header, for
/// [`Rule::match_tcp_flags`].
///
/// A newtype rather than bare `TCP_FLAG_*` constants: `linux/tcp.h` already
/// defines `TCP_FLAG_SYN` & co., as big-endian masks over the whole fourth
/// header word (`TCP_FLAG_SYN == htonl(0x00020000)`). Same names, different
/// values, different width — and the UAPI audit cannot see the clash, because
/// it cannot evaluate `__constant_cpu_to_be32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: Self = Self(0x01);
    pub const SYN: Self = Self(0x02);
    pub const RST: Self = Self(0x04);
    pub const PSH: Self = Self(0x08);
    pub const ACK: Self = Self(0x10);
    pub const URG: Self = Self(0x20);
    pub const ECE: Self = Self(0x40);
    pub const CWR: Self = Self(0x80);

    /// No flags set.
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn bits(self) -> u8 {
        self.0
    }
}

impl Default for TcpFlags {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::ops::BitOr for TcpFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for TcpFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// TCP option kind of the maximum segment size (`TCPOPT_MAXSEG` in glibc's
/// `<netinet/tcp.h>`; the kernel's private name is `TCPOPT_MSS`).
pub const TCPOPT_MAXSEG: u8 = 2;

/// Comparison operator — `enum nft_cmp_ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum CmpOp {
    Eq = 0,
    Neq = 1,
    Lt = 2,
    Lte = 3,
    Gt = 4,
    Gte = 5,
}

impl CmpOp {
    /// Reverse mapping for the expression decoder (#164).
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Eq),
            1 => Some(Self::Neq),
            2 => Some(Self::Lt),
            3 => Some(Self::Lte),
            4 => Some(Self::Gt),
            5 => Some(Self::Gte),
            _ => None,
        }
    }
}

/// Payload base header — `enum nft_payload_bases`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum PayloadBase {
    LinkLayer = 0,
    Network = 1,
    Transport = 2,
}

/// The checksum a payload write updates (`enum nft_payload_csum_types`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum PayloadCsum {
    /// None.
    None = 0,
    /// The Internet checksum at the expression's checksum offset.
    Inet = 1,
    /// SCTP's CRC32c.
    Sctp = 2,
}

impl PayloadCsum {
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            0 => Self::None,
            1 => Self::Inet,
            2 => Self::Sctp,
            _ => return None,
        })
    }
}

/// What [`Rule::match_socket`] compares (#703).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SocketMatch {
    /// `socket transparent 0|1`.
    Transparent(bool),
    /// `socket wildcard 0|1`.
    Wildcard(bool),
    /// `socket mark <mark>`.
    Mark(u32),
}

/// A value a rule computes into its first register (#703): a `numgen`,
/// a `jhash` of packet fields or a `symhash`. See [`Rule::generate`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Generated {
    /// `numgen inc|random mod <modulus> [offset <offset>]`.
    Numgen {
        /// Counting up, or at random.
        kind: super::expr::NumgenKind,
        /// Modulo this.
        modulus: u32,
        /// Plus this.
        offset: u32,
    },
    /// `jhash <field> [. <field> …] mod <modulus> [seed <seed>] [offset
    /// <offset>]`.
    Jhash {
        /// The fields hashed, behind their guards.
        fields: Vec<PacketField>,
        /// Modulo this.
        modulus: u32,
        /// The seed; `None`, the kernel's.
        seed: Option<u32>,
        /// Plus this.
        offset: u32,
    },
    /// `symhash mod <modulus> [offset <offset>]`.
    Symhash {
        /// Modulo this.
        modulus: u32,
        /// Plus this.
        offset: u32,
    },
}

/// A header field a rule writes, with its value (#703): what nft's
/// `<field> set <value>` statements write, through
/// [`Rule::set_header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderWrite {
    /// `ip dscp set <0..63>`.
    IpDscp(u8),
    /// `ip ttl set <ttl>`.
    IpTtl(u8),
    /// `ip saddr set <addr>`.
    IpSaddr(std::net::Ipv4Addr),
    /// `ip daddr set <addr>`.
    IpDaddr(std::net::Ipv4Addr),
    /// `ip6 dscp set <0..63>`.
    Ip6Dscp(u8),
    /// `ip6 hoplimit set <hops>`.
    Ip6HopLimit(u8),
    /// `ip6 saddr set <addr>`.
    Ip6Saddr(std::net::Ipv6Addr),
    /// `ip6 daddr set <addr>`.
    Ip6Daddr(std::net::Ipv6Addr),
    /// `tcp sport set <port>`.
    TcpSport(u16),
    /// `tcp dport set <port>`.
    TcpDport(u16),
    /// `udp sport set <port>`.
    UdpSport(u16),
    /// `udp dport set <port>`.
    UdpDport(u16),
}

impl PayloadBase {
    /// Reverse mapping for the expression decoder (#164).
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::LinkLayer),
            1 => Some(Self::Network),
            2 => Some(Self::Transport),
            _ => None,
        }
    }
}

/// Which header family an `exthdr` expression addresses — `enum
/// nft_exthdr_op` in the kernel UAPI.
///
/// Only [`TcpOpt`](Self::TcpOpt) can be written
/// ([`Expr::ExthdrSet`]); every op can be
/// loaded, but see [`Dccp`](Self::Dccp).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum ExthdrOp {
    /// IPv6 extension header (`exthdr`).
    Ipv6 = 0,
    /// TCP option (`tcp option`).
    TcpOpt = 1,
    /// IPv4 option (`ip option`), kernel 5.3+. Not valid in an `ip6` table.
    Ipv4 = 2,
    /// SCTP chunk (`sctp chunk`), kernel 5.14+.
    Sctp = 3,
    /// DCCP option (`dccp option`), kernel 6.5+. The kernel only accepts
    /// it as an existence test (`NFT_EXTHDR_F_PRESENT`), which
    /// [`Expr::Exthdr`] does not model, so a
    /// load built from it is rejected. Upstream has scheduled DCCP option
    /// matching for removal in 2027.
    Dccp = 4,
}

impl ExthdrOp {
    /// Reverse mapping for the expression decoder. `None` for ops the
    /// typed enum doesn't model yet.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Ipv6),
            1 => Some(Self::TcpOpt),
            2 => Some(Self::Ipv4),
            3 => Some(Self::Sctp),
            4 => Some(Self::Dccp),
            _ => None,
        }
    }
}

/// Meta key — `enum nft_meta_keys`. Loaded by [`Expr::Meta`]; the keys
/// the kernel lets a rule write (`Mark`, `Priority`) are set with
/// [`Expr::MetaSet`].
///
/// [`Expr::Meta`]: super::expr::Expr::Meta
/// [`Expr::MetaSet`]: super::expr::Expr::MetaSet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum MetaKey {
    Len = 0,
    Protocol = 1,
    /// `skb->priority` — a TC classid (`major:minor`) that HTB and prio
    /// classify on directly; see [`Rule::set_priority`].
    Priority = 2,
    Mark = 3,
    Iif = 4,
    Oif = 5,
    IifName = 6,
    OifName = 7,
    SkUid = 10,
    SkGid = 11,
    NfProto = 15,
    L4Proto = 16,
    CGroup = 23,
    /// `iiftype`: the input interface's ARPHRD type.
    IifType = 8,
    /// `oiftype`.
    OifType = 9,
    /// `nftrace`: set to trace the packet through the ruleset.
    NfTrace = 12,
    /// `rtclassid`: the route's realm.
    RtClassId = 13,
    /// `secmark`.
    Secmark = 14,
    /// `ibrname`: the bridge a frame came in on.
    BriIifName = 17,
    /// `obrname`.
    BriOifName = 18,
    /// `pkttype`: host, broadcast, multicast, other host — see [`PktType`].
    PktType = 19,
    /// `cpu`: the CPU handling the packet.
    Cpu = 20,
    /// `iifgroup`: the input interface's group.
    IifGroup = 21,
    /// `oifgroup`.
    OifGroup = 22,
    /// `random`: a pseudo-random number.
    PRandom = 24,
    /// `ipsec`: whether the packet came through IPsec.
    SecPath = 25,
    /// `iifkind`: the input interface's kind (`veth`, …).
    IifKind = 26,
    /// `oifkind`.
    OifKind = 27,
    /// `ibrpvid`: the bridge port's PVID.
    BriIifPvid = 28,
    /// `ibrvproto`: the bridge's VLAN protocol.
    BriIifVproto = 29,
    /// `time`: nanoseconds since the epoch.
    TimeNs = 30,
    /// `day`: the day of the week.
    TimeDay = 31,
    /// `hour`: seconds since midnight.
    TimeHour = 32,
    /// `sdif`: the L3 master (VRF) slave's index.
    Sdif = 33,
    /// `sdifname`.
    SdifName = 34,
    /// `broute`: route a bridged frame instead.
    BriBroute = 35,
}

impl MetaKey {
    /// Reverse mapping for the expression decoder (#164). `None` for
    /// kernel meta keys the typed enum doesn't model yet — such
    /// expressions decode as `RuleExpr::Unknown`.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Len),
            1 => Some(Self::Protocol),
            2 => Some(Self::Priority),
            3 => Some(Self::Mark),
            4 => Some(Self::Iif),
            5 => Some(Self::Oif),
            6 => Some(Self::IifName),
            7 => Some(Self::OifName),
            10 => Some(Self::SkUid),
            11 => Some(Self::SkGid),
            15 => Some(Self::NfProto),
            16 => Some(Self::L4Proto),
            23 => Some(Self::CGroup),
            8 => Some(Self::IifType),
            9 => Some(Self::OifType),
            12 => Some(Self::NfTrace),
            13 => Some(Self::RtClassId),
            14 => Some(Self::Secmark),
            17 => Some(Self::BriIifName),
            18 => Some(Self::BriOifName),
            19 => Some(Self::PktType),
            20 => Some(Self::Cpu),
            21 => Some(Self::IifGroup),
            22 => Some(Self::OifGroup),
            24 => Some(Self::PRandom),
            25 => Some(Self::SecPath),
            26 => Some(Self::IifKind),
            27 => Some(Self::OifKind),
            28 => Some(Self::BriIifPvid),
            29 => Some(Self::BriIifVproto),
            30 => Some(Self::TimeNs),
            31 => Some(Self::TimeDay),
            32 => Some(Self::TimeHour),
            33 => Some(Self::Sdif),
            34 => Some(Self::SdifName),
            35 => Some(Self::BriBroute),
            _ => None,
        }
    }
}

/// Conntrack key.
/// Conntrack key — matches `enum nft_ct_keys` in the kernel UAPI
/// (`include/uapi/linux/netfilter/nf_tables.h`).
///
/// Plan 221: `Expiration` was hardcoded to `7`, which is
/// `NFT_CT_L3PROTOCOL`. Every rule using `Expr::Ct { key:
/// CtKey::Expiration }` was reading the conntrack L3 protocol byte
/// instead of the expiration time in milliseconds — silent
/// type+value mismatch. Corrected to `5`, and the variants `Secmark`,
/// `Helper`, `L3Protocol` were added so the previously-shadowed
/// kernel values are reachable through the typed enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum CtKey {
    State = 0,
    Direction = 1,
    Status = 2,
    Mark = 3,
    Secmark = 4,
    Expiration = 5,
    Helper = 6,
    L3Protocol = 7,
    /// `ct <dir> saddr`, either family (16 bytes); prefer [`SrcIp`](Self::SrcIp)/[`SrcIp6`](Self::SrcIp6).
    Src = 8,
    /// `ct <dir> daddr`, either family.
    Dst = 9,
    /// `ct protocol`: the layer-4 protocol.
    Protocol = 10,
    /// `ct <dir> proto-src`: the source port.
    ProtoSrc = 11,
    /// `ct <dir> proto-dst`: the destination port.
    ProtoDst = 12,
    /// `ct label`: the 128 label bits.
    Labels = 13,
    /// `ct packets`.
    Pkts = 14,
    /// `ct bytes`.
    Bytes = 15,
    /// `ct avgpkt`: average packet size.
    AvgPkt = 16,
    /// `ct zone`.
    Zone = 17,
    /// `ct event`: which events the connection reports.
    EventMask = 18,
    /// `ct <dir> ip saddr`.
    SrcIp = 19,
    /// `ct <dir> ip daddr`.
    DstIp = 20,
    /// `ct <dir> ip6 saddr`.
    SrcIp6 = 21,
    /// `ct <dir> ip6 daddr`.
    DstIp6 = 22,
    /// `ct id`.
    Id = 23,
}

impl CtKey {
    /// Reverse mapping for the expression decoder. `None` for conntrack
    /// keys the typed enum doesn't model — such expressions decode as
    /// `RuleExpr::Unknown`.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::State),
            1 => Some(Self::Direction),
            2 => Some(Self::Status),
            3 => Some(Self::Mark),
            4 => Some(Self::Secmark),
            5 => Some(Self::Expiration),
            6 => Some(Self::Helper),
            7 => Some(Self::L3Protocol),
            8 => Some(Self::Src),
            9 => Some(Self::Dst),
            10 => Some(Self::Protocol),
            11 => Some(Self::ProtoSrc),
            12 => Some(Self::ProtoDst),
            13 => Some(Self::Labels),
            14 => Some(Self::Pkts),
            15 => Some(Self::Bytes),
            16 => Some(Self::AvgPkt),
            17 => Some(Self::Zone),
            18 => Some(Self::EventMask),
            19 => Some(Self::SrcIp),
            20 => Some(Self::DstIp),
            21 => Some(Self::SrcIp6),
            22 => Some(Self::DstIp6),
            23 => Some(Self::Id),
            _ => None,
        }
    }
}

/// Route key for [`Expr::Rt`] — `enum nft_rt_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum RtKey {
    /// Realm of the packet's route (`skb->dst->tclassid`).
    Classid = 0,
    /// IPv4 next hop.
    Nexthop4 = 1,
    /// IPv6 next hop.
    Nexthop6 = 2,
    /// TCP MSS the path allows: the smaller of the route's and the reverse
    /// route's MTU, less the IP and TCP headers. A **host-order** `u16` —
    /// convert with [`Expr::Byteorder`]
    /// before writing it into a TCP option. Only in the `forward`,
    /// `output` and `postrouting` hooks (`nft_rt_validate`).
    TcpMss = 3,
    /// Whether the route goes through an xfrm (IPsec) transform.
    Xfrm = 4,
}

impl RtKey {
    /// Reverse mapping for the expression decoder.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Classid),
            1 => Some(Self::Nexthop4),
            2 => Some(Self::Nexthop6),
            3 => Some(Self::TcpMss),
            4 => Some(Self::Xfrm),
            _ => None,
        }
    }
}

/// Direction of a [`Expr::Byteorder`]
/// conversion — `enum nft_byteorder_ops`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum ByteorderOp {
    /// Network to host order.
    Ntoh = 0,
    /// Host to network order.
    Hton = 1,
}

impl ByteorderOp {
    /// Reverse mapping for the expression decoder.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Ntoh),
            1 => Some(Self::Hton),
            _ => None,
        }
    }
}

/// NAT type — `enum nft_nat_types`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[non_exhaustive]
pub enum NatType {
    Snat = 0,
    Dnat = 1,
}

/// Whether (and how) a NAT expression's address register (`R0`) is in use.
///
/// The encoder emits `NFTA_NAT_REG_ADDR_MIN` for every variant except
/// [`None`](Self::None). Modeling "register in use" and "the IPv4 address to
/// record" as one enum makes the illegal `(addr recorded, register not in
/// use)` state unrepresentable — a v6 NAT loads its 16-byte address into `R0`
/// but has no `Ipv4Addr` to carry, which [`Reg`](Self::Reg) expresses directly.
///
/// Invariant: any variant other than `None` means an [`Expr::Immediate`]
/// loading the address into `R0` **must** precede this expr in the rule.
/// Constructing this without the matching load makes the encoder reference an
/// empty register (`EINVAL` from the kernel). The `Rule::{snat,dnat,snat_v6,
/// dnat_v6}` builders maintain this for you.
///
/// [`Expr::Immediate`]: super::expr::Expr::Immediate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NatAddr {
    /// No address register; the NAT expr rewrites only the port (or nothing).
    #[default]
    None,
    /// An IPv4 address loaded into `R0`. Recorded for a future dump/decode
    /// path; no decoder currently reads it back.
    V4(Ipv4Addr),
    /// An address (e.g. IPv6) loaded into `R0` with no `Ipv4Addr` to record.
    Reg,
}

impl NatAddr {
    /// Whether `R0` holds an address — i.e. the encoder must emit
    /// `NFTA_NAT_REG_ADDR_MIN`.
    pub fn reg_in_use(&self) -> bool {
        !matches!(self, NatAddr::None)
    }
}

/// NAT expression data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NatExpr {
    pub nat_type: NatType,
    pub family: Family,
    /// The NAT destination address register state. See [`NatAddr`].
    pub addr: NatAddr,
    /// Port to NAT to.
    pub port: Option<u16>,
}

impl NatExpr {
    /// Create a SNAT expression.
    ///
    /// `family` must be [`Family::Ip`] or [`Family::Ip6`] — the kernel rejects
    /// `Family::Inet` with `EAFNOSUPPORT`. Use the concrete family matching
    /// the address type being NAT'd.
    pub fn snat(family: Family) -> Self {
        Self {
            nat_type: NatType::Snat,
            family,
            addr: NatAddr::None,
            port: None,
        }
    }

    /// Create a DNAT expression.
    ///
    /// `family` must be [`Family::Ip`] or [`Family::Ip6`] — the kernel rejects
    /// `Family::Inet` with `EAFNOSUPPORT`. Use the concrete family matching
    /// the address type being NAT'd.
    pub fn dnat(family: Family) -> Self {
        Self {
            nat_type: NatType::Dnat,
            family,
            addr: NatAddr::None,
            port: None,
        }
    }

    /// Set the NAT destination address.
    pub fn addr(mut self, addr: Ipv4Addr) -> Self {
        self.addr = NatAddr::V4(addr);
        self
    }

    /// Set the NAT destination port.
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

/// Which NAT statement a [`NatStatement`] or [`NatRegs`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NatKind {
    /// `snat to …`: rewrite the source.
    Snat,
    /// `dnat to …`: rewrite the destination.
    Dnat,
    /// `masquerade`: source NAT to the outgoing interface's address.
    Masquerade,
    /// `redirect`: destination NAT to the local machine.
    Redirect,
}

/// A NAT statement at register level (#528): which registers hold the
/// address and port ranges. [`Rule::nat`] loads them and builds one; build
/// it yourself only after your own `Immediate` loads.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NatRegs {
    /// The statement.
    pub kind: NatKind,
    /// The family a snat or dnat rewrites, `Ip` or `Ip6`; unused by the
    /// others.
    pub family: Family,
    /// The registers holding the first and last address.
    pub addr: Option<(Register, Register)>,
    /// The registers holding the first and last port.
    pub proto: Option<(Register, Register)>,
    /// Flags beyond the ones the ranges imply.
    pub flags: super::expr::NatFlags,
}

/// A NAT statement, as `nft` writes them (#528) — `snat to 10.0.0.1-10.0.0.9:
/// 40000-40010 fully-random`, `dnat ip to :8080`, `masquerade to :1024-2048
/// random`, `redirect to :3128` — for [`Rule::nat`].
///
/// ```
/// use std::net::Ipv4Addr;
/// use nlink::netlink::nftables::{Family, NatStatement, Rule};
///
/// let snat = Rule::new("nat", "post").nat(
///     NatStatement::snat(Ipv4Addr::new(10, 0, 0, 1))
///         .to(Ipv4Addr::new(10, 0, 0, 9))
///         .ports(40000, 40010)
///         .fully_random(),
/// );
/// let dnat_port = Rule::new("nat", "pre").nat(NatStatement::dnat_to_port(Family::Ip, 8080));
/// let masq = Rule::new("nat", "post").nat(NatStatement::masquerade().ports(1024, 2048).random());
/// ```
///
/// A combination the kernel would refuse — an address on a masquerade, a
/// range whose ends differ in family or run backwards, a family other
/// than `Ip`/`Ip6` — makes adding the rule fail, naming it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NatStatement {
    /// The statement.
    pub kind: NatKind,
    /// The first and last address, for a snat or dnat.
    pub addr: Option<(std::net::IpAddr, std::net::IpAddr)>,
    /// The first and last port.
    pub ports: Option<(u16, u16)>,
    /// The family of a snat or dnat with no address.
    pub family: Option<Family>,
    /// `random`, `fully-random`, `persistent`, `netmap`.
    pub flags: super::expr::NatFlags,
    /// [`to`](Self::to) was called with no first address.
    range_without_start: bool,
}

impl NatStatement {
    fn new(kind: NatKind) -> Self {
        Self {
            kind,
            addr: None,
            ports: None,
            family: None,
            flags: super::expr::NatFlags::empty(),
            range_without_start: false,
        }
    }

    /// `snat to <addr>`.
    pub fn snat(addr: impl Into<std::net::IpAddr>) -> Self {
        let addr = addr.into();
        Self {
            addr: Some((addr, addr)),
            ..Self::new(NatKind::Snat)
        }
    }

    /// `dnat to <addr>`.
    pub fn dnat(addr: impl Into<std::net::IpAddr>) -> Self {
        let addr = addr.into();
        Self {
            addr: Some((addr, addr)),
            ..Self::new(NatKind::Dnat)
        }
    }

    /// `snat <family> to :<port>`: the source port only.
    pub fn snat_to_port(family: Family, port: u16) -> Self {
        Self {
            family: Some(family),
            ports: Some((port, port)),
            ..Self::new(NatKind::Snat)
        }
    }

    /// `dnat <family> to :<port>`: the destination port only.
    pub fn dnat_to_port(family: Family, port: u16) -> Self {
        Self {
            family: Some(family),
            ports: Some((port, port)),
            ..Self::new(NatKind::Dnat)
        }
    }

    /// `masquerade`.
    pub fn masquerade() -> Self {
        Self::new(NatKind::Masquerade)
    }

    /// `redirect`, to the original port unless [`port`](Self::port) says.
    pub fn redirect() -> Self {
        Self::new(NatKind::Redirect)
    }

    /// Make the address a range, from the first one to `last`. On a
    /// statement with no address, adding the rule fails.
    pub fn to(mut self, last: impl Into<std::net::IpAddr>) -> Self {
        let last = last.into();
        match self.addr {
            Some((first, _)) => self.addr = Some((first, last)),
            None => self.range_without_start = true,
        }
        self
    }

    /// To port `port`.
    pub fn port(self, port: u16) -> Self {
        self.ports(port, port)
    }

    /// To a port in `first..=last`.
    pub fn ports(mut self, first: u16, last: u16) -> Self {
        self.ports = Some((first, last));
        self
    }

    /// `random`: pick the port at random.
    pub fn random(mut self) -> Self {
        self.flags |= super::expr::NatFlags::PROTO_RANDOM;
        self
    }

    /// `fully-random`: pick the port fully at random.
    pub fn fully_random(mut self) -> Self {
        self.flags |= super::expr::NatFlags::PROTO_RANDOM_FULLY;
        self
    }

    /// `persistent`: give a client the same address every time.
    pub fn persistent(mut self) -> Self {
        self.flags |= super::expr::NatFlags::PERSISTENT;
        self
    }

    /// `netmap`: map the address range prefix to prefix, keeping the host
    /// part (kernel 5.8+).
    pub fn netmap(mut self) -> Self {
        self.flags |= super::expr::NatFlags::NETMAP;
        self
    }

    /// What the kernel would refuse, and the family a snat or dnat
    /// rewrites.
    pub(crate) fn check(&self) -> std::result::Result<Family, String> {
        let kind = match self.kind {
            NatKind::Snat => "snat",
            NatKind::Dnat => "dnat",
            NatKind::Masquerade => "masquerade",
            NatKind::Redirect => "redirect",
        };
        if let Some((lo, hi)) = self.ports
            && lo > hi
        {
            return Err(format!("nat: {kind} port range {lo}-{hi} runs backwards"));
        }
        if self.range_without_start {
            return Err(format!("nat: {kind} has no address to make a range of"));
        }
        match (self.kind, self.addr) {
            (NatKind::Masquerade | NatKind::Redirect, Some(_)) => {
                Err(format!("nat: {kind} takes no address, only ports"))
            }
            (NatKind::Masquerade | NatKind::Redirect, None) => {
                if self.flags.contains(super::expr::NatFlags::NETMAP) {
                    return Err(format!("nat: {kind} cannot netmap"));
                }
                Ok(Family::Ip)
            }
            (_, Some((lo, hi))) => {
                if lo.is_ipv4() != hi.is_ipv4() {
                    return Err(format!("nat: {kind} range {lo}-{hi} mixes IPv4 and IPv6"));
                }
                if lo > hi {
                    return Err(format!("nat: {kind} range {lo}-{hi} runs backwards"));
                }
                let family = if lo.is_ipv4() { Family::Ip } else { Family::Ip6 };
                match self.family {
                    Some(f) if f != family => {
                        Err(format!("nat: {kind} to {lo} is not a {f} address"))
                    }
                    _ => Ok(family),
                }
            }
            (_, None) => {
                if self.flags.contains(super::expr::NatFlags::NETMAP) {
                    return Err(format!("nat: {kind} netmap needs an address range"));
                }
                match self.family {
                    Some(f @ (Family::Ip | Family::Ip6)) => Ok(f),
                    Some(f) => Err(format!("nat: {kind} family must be ip or ip6, not {f}")),
                    None => Err(format!("nat: {kind} needs an address or a family")),
                }
            }
        }
    }
}

// =============================================================================
// Table (parsed from dump)
// =============================================================================

/// An nftables flowtable.
///
/// Per-table object that caches established conntrack flows, letting
/// the kernel bypass the full nftables rule traversal for matching
/// packets. On capable NICs the flow path can be hardware-offloaded
/// via `NFT_FLOWTABLE_HW_OFFLOAD`.
///
/// Construct via [`Self::new`] + fluent setters; install via
/// `Connection::<Nftables>::add_flowtable`. List via `get_flowtables`.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// # let conn = nlink::Connection::<nlink::netlink::Nftables>::new()?;
/// use nlink::netlink::nftables::{Flowtable, Family};
///
/// let ft = Flowtable::new(Family::Inet, "filter", "ft")
///     .device("eth0")
///     .device("eth1")
///     .priority(0)
///     .hw_offload(true);
/// conn.add_flowtable(&ft).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Flowtable {
    /// Owning table family (typically `Inet`, `Ip`, `Ip6`).
    pub family: Family,
    /// Owning table name.
    pub table: String,
    /// Flowtable name (unique within the table).
    pub name: String,
    /// Device names to attach the ingress hook to. Empty = no
    /// devices (the kernel accepts the add but the flowtable does
    /// nothing until devices are added in a follow-up update).
    pub devs: Vec<String>,
    /// Hook priority. Default 0; `-300` for early ingress.
    pub priority: i32,
    /// Flags bitmap. Combine `NFT_FLOWTABLE_HW_OFFLOAD` and
    /// `NFT_FLOWTABLE_COUNTER` from
    /// [`crate::netlink::nftables`].
    pub flags: u32,
    /// Use-count reported by the kernel (read-only; populated by
    /// `get_flowtables` parse, ignored on add).
    pub use_count: u32,
    /// Kernel-assigned handle (read-only; same as `use_count`).
    pub handle: u64,
}

impl Flowtable {
    /// New builder for a flowtable in the named table.
    pub fn new(
        family: Family,
        table: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            family,
            table: table.into(),
            name: name.into(),
            devs: Vec::new(),
            priority: 0,
            flags: 0,
            use_count: 0,
            handle: 0,
        }
    }

    /// Attach the flowtable's ingress hook to a device. Call
    /// multiple times to attach to several devices (e.g. both ends
    /// of a bridge).
    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.devs.push(dev.into());
        self
    }

    /// Set the ingress hook priority. Default is 0.
    pub fn priority(mut self, p: i32) -> Self {
        self.priority = p;
        self
    }

    /// Request hardware offload (`NFT_FLOWTABLE_HW_OFFLOAD`).
    ///
    /// Requires a NIC with flow-table offload support (mlx5, hns3,
    /// etc.) and a kernel built with `CONFIG_NF_FLOW_TABLE_HW`.
    /// If the NIC doesn't support offload the kernel accepts the
    /// add and silently falls back to software — there's no in-band
    /// signal. Check `ethtool -k <dev> | grep hw-tc-offload` or
    /// inspect per-flow counters to confirm offload engaged.
    pub fn hw_offload(mut self, on: bool) -> Self {
        if on {
            self.flags |= super::NFT_FLOWTABLE_HW_OFFLOAD;
        } else {
            self.flags &= !super::NFT_FLOWTABLE_HW_OFFLOAD;
        }
        self
    }

    /// Request per-flow counter tracking
    /// (`NFT_FLOWTABLE_COUNTER`). Adds overhead.
    pub fn counter(mut self, on: bool) -> Self {
        if on {
            self.flags |= super::NFT_FLOWTABLE_COUNTER;
        } else {
            self.flags &= !super::NFT_FLOWTABLE_COUNTER;
        }
        self
    }
}

/// An nftables table.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Table {
    /// Table name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Flags.
    pub flags: u32,
    /// Number of chains using this table.
    pub use_count: u32,
    /// Kernel handle.
    pub handle: u64,
    /// Its comment, as `nft list` shows it (#528).
    pub comment: Option<String>,
}

// =============================================================================
// Chain builder
// =============================================================================

/// Chain configuration builder.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Chain {
    pub(crate) table: TableName,
    pub(crate) name: ChainName,
    pub(crate) family: Family,
    pub(crate) hook: Option<Hook>,
    pub(crate) priority: Option<Priority>,
    pub(crate) chain_type: Option<ChainType>,
    pub(crate) policy: Option<Policy>,
    pub(crate) devices: Vec<String>,
    pub(crate) comment: Option<String>,
    /// Tag it as the declarative apply's own (#527).
    pub(crate) owned: bool,
}

impl Chain {
    /// Create a new chain builder.
    ///
    /// `table` / `name` accept anything convertible to a validated
    /// [`TableName`] / [`ChainName`] — a `&str` or `String` (validated
    /// here, so an empty / overlong / NUL-bearing name is an early
    /// `Err`) or an already-typed value (infallible). The distinct
    /// types make the `(table, name)` argument order a compile-time
    /// concern rather than two interchangeable strings.
    pub fn new<T, N>(table: T, name: N) -> Result<Self>
    where
        T: TryInto<TableName>,
        T::Error: Into<Error>,
        N: TryInto<ChainName>,
        N::Error: Into<Error>,
    {
        Ok(Self {
            table: table.try_into().map_err(Into::into)?,
            name: name.try_into().map_err(Into::into)?,
            family: Family::Inet,
            hook: None,
            priority: None,
            chain_type: None,
            policy: None,
            devices: Vec::new(),
            comment: None,
            owned: false,
        })
    }

    /// Give the chain a comment, which `nft list` shows (#528). It is
    /// written when the chain is created: changing it later takes
    /// recreating the chain. Adding one longer than 127 bytes fails.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set the address family.
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Make this a base chain (#708): its type and hook, priority and
    /// policy. Without it the chain is a regular one, which only a `jump`
    /// or `goto` enters. A deprecated setter called after it changes that
    /// part of what it set, and the chain is checked as a whole when sent.
    ///
    /// ```
    /// use nlink::netlink::nftables::{BaseChain, Chain, Family, FilterHook, Policy, Priority};
    ///
    /// let input = Chain::new("filter", "input")?
    ///     .family(Family::Inet)
    ///     .base(BaseChain::filter(FilterHook::Input, Priority::Filter).policy(Policy::Drop));
    /// # Ok::<(), nlink::Error>(())
    /// ```
    pub fn base(mut self, base: BaseChain) -> Self {
        self.hook = Some(base.hook);
        self.priority = Some(base.priority);
        self.chain_type = Some(base.chain_type);
        self.policy = base.policy;
        self.devices = base.devices;
        self
    }

    /// Set the hook point (makes this a base chain).
    #[deprecated(
        since = "0.33.0",
        note = "use `base(BaseChain::filter(..))`, `nat` or `route`"
    )]
    pub fn hook(mut self, hook: Hook) -> Self {
        self.hook = Some(hook);
        self
    }

    /// Set the chain priority.
    #[deprecated(since = "0.33.0", note = "a `BaseChain` takes its priority")]
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Set the chain type.
    #[deprecated(
        since = "0.33.0",
        note = "use `base(BaseChain::filter(..))`, `BaseChain::nat` or `BaseChain::route`"
    )]
    pub fn chain_type(mut self, chain_type: ChainType) -> Self {
        self.chain_type = Some(chain_type);
        self
    }

    /// Set the default policy.
    #[deprecated(since = "0.33.0", note = "use `BaseChain::policy`")]
    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Bind a base chain to an interface (`type filter hook ingress device
    /// eth0 priority -150`). Call it again to bind the chain to several
    /// devices (#703).
    #[deprecated(
        since = "0.33.0",
        note = "use `FilterHook::ingress(..)` or `FilterHook::egress(..)`"
    )]
    pub fn device(mut self, dev: impl Into<String>) -> Self {
        self.devices.push(dev.into());
        self
    }

    /// What this chain is, checked against its family, or why it is no
    /// chain the kernel would create.
    pub(crate) fn kind(&self) -> Result<ChainKind> {
        let at = |e: Error| {
            e.with_context(format!(
                "chain {}/{}",
                self.table.as_str(),
                self.name.as_str()
            ))
        };
        let kind = ChainKind::from_parts(
            self.hook,
            self.chain_type,
            self.priority,
            self.policy,
            &self.devices,
        )
        .map_err(|why| at(Error::invalid_message(why)))?;
        if let Some(base) = kind.base() {
            base.check_family(self.family).map_err(at)?;
        }
        Ok(kind)
    }
}

/// Chain info parsed from a dump.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ChainInfo {
    /// Table name.
    pub table: String,
    /// Chain name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Hook point (None for regular chains).
    pub hook: Option<u32>,
    /// Priority (for base chains).
    pub priority: Option<i32>,
    /// Chain type, parsed from the kernel's `NFTA_CHAIN_TYPE`
    /// string. `None` if the chain is regular (no hook) or the
    /// kernel emitted an unrecognised value — Plan 180 picked
    /// the typed form deliberately so callers can pattern-match
    /// without holding a stringly table.
    pub chain_type: Option<ChainType>,
    /// Bound device name for netdev base chains. `None` on
    /// other families or when the chain wasn't dump-included
    /// by the kernel (older kernels omit it for non-netdev). Also
    /// `None` when the chain is bound to more than one device: see
    /// [`devices`](Self::devices).
    pub device: Option<String>,
    /// Every device the chain is bound to (`NFTA_HOOK_DEVS`). A device
    /// change sent as an update adds to this list, so a chain moved from
    /// `eth0` to `eth1` ended up on both, with `device: None`, and drifted
    /// on every apply (#484).
    pub devices: Vec<String>,
    /// Default policy.
    pub policy: Option<u32>,
    /// Kernel handle.
    pub handle: u64,
    /// Its comment (#528).
    pub comment: Option<String>,
    /// Created by nlink's declarative apply: it carries nlink's ownership
    /// tag (#527).
    pub managed: bool,
}

impl ChainInfo {
    /// What the chain is (#708), or `None` for a base chain whose hook or
    /// type nlink does not know.
    ///
    /// A base chain always reads back with a policy, since the kernel
    /// reports the one it uses: `Accept` unless one was set.
    pub fn kind(&self) -> Option<ChainKind> {
        let Some(number) = self.hook else {
            return Some(ChainKind::Regular);
        };
        let devices = if self.devices.is_empty() {
            self.device.iter().cloned().collect()
        } else {
            self.devices.clone()
        };
        Some(ChainKind::Base(BaseChain {
            chain_type: self.chain_type?,
            hook: Hook::from_number(self.family, number)?,
            devices,
            priority: Priority::from_i32(self.priority.unwrap_or(0)),
            policy: self.policy.and_then(Policy::from_u32),
        }))
    }
}

// =============================================================================
// Rule builder
// =============================================================================

/// `addr/prefix` as a match takes it: a prefix as long as the address, or
/// longer, is the address, as the builder always took it.
fn prefixed(addr: std::net::IpAddr, prefix: u8) -> Value {
    let width = if addr.is_ipv4() { 32 } else { 128 };
    if prefix >= width {
        Value::Addr(addr)
    } else {
        Value::Prefix(addr, prefix)
    }
}

/// Rule configuration builder.
///
/// A [`RuleSpec`] with the table, chain and family it goes in (#708). Each
/// match and action method appends an [`Item`] to the spec, and
/// [`then`](Self::then) appends any other; the spec is lowered to the
/// kernel's expressions when the rule is sent, and what cannot be lowered
/// makes adding the rule fail.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use = "builders do nothing unless used"]
pub struct Rule {
    pub(crate) table: String,
    pub(crate) chain: String,
    pub(crate) family: Family,
    pub(crate) spec: RuleSpec,
    pub(crate) position: Option<u64>,
    /// The declarative identity (`nlink:<key>`), set by `NftablesDiff::apply`
    /// from the declared rule's key. Imperative rules have none.
    pub(crate) key: Option<String>,
    /// Why the rule could not be built, from a fallible
    /// [`try_rule`](super::config::DeclaredTableBuilder::try_rule) closure.
    /// Adding the rule fails with it.
    pub(crate) error: Option<String>,
}

impl Rule {
    /// Create a new rule builder.
    pub fn new(table: &str, chain: &str) -> Self {
        Self::from_spec(table, chain, RuleSpec::new())
    }

    /// A rule of `spec` in `chain` of `table` (#708). The family is `Inet`
    /// until [`family`](Self::family) sets it.
    pub fn from_spec(table: &str, chain: &str, spec: RuleSpec) -> Self {
        Self {
            table: table.to_string(),
            chain: chain.to_string(),
            family: Family::Inet,
            spec,
            position: None,
            key: None,
            error: None,
        }
    }

    /// The rule's body.
    pub fn spec(&self) -> &RuleSpec {
        &self.spec
    }

    /// The rule's body, without its table, chain and family.
    pub fn into_spec(self) -> RuleSpec {
        self.spec
    }

    /// Append an item (#708): a [`Match`], a [`Stmt`], a [`Verdict`] or an
    /// [`Expr`]. What the other methods do, for any match the builder has
    /// no method for:
    ///
    /// ```
    /// use nlink::netlink::nftables::{Field, Match, Rule, Value};
    ///
    /// let rule = Rule::new("t", "c")
    ///     .then(Match::ne(Field::TcpDport, Value::range(1000u16, 2000u16)))
    ///     .accept();
    /// assert_eq!(rule.nft_syntax().as_deref(), Some("tcp dport != 1000-2000 accept"));
    /// ```
    pub fn then(mut self, item: impl Into<Item>) -> Self {
        self.spec.push(item);
        self
    }

    /// Why the rule cannot be sent, if anything.
    pub(crate) fn check(&self) -> Result<()> {
        self.lowered().map(drop)
    }

    /// The expressions the rule sends in its family's table, or why it
    /// cannot be sent.
    pub(crate) fn lowered(&self) -> Result<Vec<Expr>> {
        let exprs = match &self.error {
            Some(why) => Err(why.clone()),
            None => self.spec.lower_items(),
        };
        let exprs = exprs.map_err(|why| {
            Error::invalid_message(format!("{}/{}: {why}", self.table, self.chain))
        })?;
        Ok(super::expr::exprs_for_family(&exprs, self.family).into_owned())
    }

    /// The items' expressions as the builder wrote them, before the
    /// family's guards.
    #[cfg(test)]
    pub(crate) fn exprs(&self) -> Vec<Expr> {
        self.spec.lower_items().expect("the rule lowers")
    }

    /// Set the address family.
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Place the rule right **after** the rule with kernel handle `pos`
    /// (nft's `add rule ... position <handle>`).
    ///
    /// `add_rule` always sends `NLM_F_APPEND` — without it the kernel
    /// prepends, and rules land in reverse order (#195) — and with it the
    /// kernel links a positioned rule after the one named. This said
    /// "before" until 0.30, which was true only before #195.
    pub fn position(mut self, pos: u64) -> Self {
        self.position = Some(pos);
        self
    }

    /// Attach a human comment to this rule, shown by `nft list ruleset` as
    /// `comment "..."` (`NFTA_RULE_USERDATA`, libnftnl's TLV). At most 127
    /// bytes.
    ///
    /// Written verbatim. In a declarative `NftablesConfig` the rule's key
    /// goes in front of it — `nlink:<key> <comment>` — and the two share
    /// those 127 bytes; installing a longer one is an error, not a silent
    /// drop.
    pub fn comment(mut self, comment: &str) -> Self {
        self.spec.comment = Some(comment.to_string());
        self
    }

    /// Borrow the rule's comment, if any.
    pub fn comment_ref(&self) -> Option<&str> {
        self.spec.comment_ref()
    }

    /// The rule as `nft list ruleset` will print it once installed, in its
    /// family's table: `Rule::new("t", "c").match_tcp_dport(22).accept()`
    /// is `tcp dport 22 accept` (#708). `None` where
    /// [`RuleInfo::nft_syntax`] would be.
    ///
    /// ```
    /// use nlink::netlink::nftables::Rule;
    ///
    /// let rule = Rule::new("t", "c").match_tcp_dport(22).counter().accept();
    /// assert_eq!(
    ///     rule.nft_syntax().as_deref(),
    ///     Some("tcp dport 22 counter packets 0 bytes 0 accept")
    /// );
    /// ```
    pub fn nft_syntax(&self) -> Option<String> {
        self.spec.nft_syntax(self.family)
    }

    /// [`nft_syntax`](Self::nft_syntax) as `nft -s list ruleset`
    /// (`--stateless`) prints it, which is how [`NftablesDiff`] shows a
    /// rule: a counter without its packets and bytes, a quota without what
    /// it has used.
    ///
    /// [`NftablesDiff`]: super::config::NftablesDiff
    ///
    /// ```
    /// use nlink::netlink::nftables::Rule;
    ///
    /// let rule = Rule::new("t", "c").match_tcp_dport(22).counter().accept();
    /// assert_eq!(
    ///     rule.nft_syntax_stateless().as_deref(),
    ///     Some("tcp dport 22 counter accept")
    /// );
    /// ```
    pub fn nft_syntax_stateless(&self) -> Option<String> {
        self.spec.nft_syntax_stateless(self.family)
    }

    /// Match TCP destination port.
    ///
    /// Generates: meta(L4PROTO) + cmp(==TCP) + payload(dport) + cmp(==port)
    pub fn match_tcp_dport(self, port: u16) -> Self {
        self.then(Match::eq(Field::TcpDport, port))
    }

    /// Match UDP destination port.
    pub fn match_udp_dport(self, port: u16) -> Self {
        self.then(Match::eq(Field::UdpDport, port))
    }

    /// Hand the packet to a local socket (#703): `tproxy [ip|ip6] to
    /// [<addr>][:<port>]`. The socket is the one listening at `addr`
    /// (or the packet's destination) and `port` (or the packet's), and
    /// must have `IP_TRANSPARENT`; the packet keeps its destination.
    /// `family` is the table's address family — `Ip`, `Ip6`, or `Inet` for
    /// either (then without an address); an address must be of it.
    pub fn tproxy(self, family: Family, addr: Option<std::net::IpAddr>, port: Option<u16>) -> Self {
        self.then(Stmt::Tproxy { family, addr, port })
    }

    /// Match the operating system a TCP SYN's fingerprint names (#703):
    /// `osf [ttl loose|skip] [version] name "<name>"` — `Linux`, or with
    /// `version` `Linux:3.11`. Only a SYN matches, and only in a
    /// prerouting, input or forward chain. Without fingerprints loaded
    /// (`nfnl_osf -f pf.os`) every SYN is `unknown`. A name over 15 bytes
    /// is refused.
    pub fn match_osf(self, name: &str, ttl: super::expr::OsfTtl, version: bool) -> Self {
        self.then(Match::eq(Field::Osf { ttl, version }, name))
    }

    /// Match the packet's local socket (#703): `socket transparent 1`,
    /// `socket wildcard 0`, `socket mark 7`. A packet with no local
    /// socket does not match.
    pub fn match_socket(self, m: SocketMatch) -> Self {
        let (key, value) = match m {
            SocketMatch::Transparent(on) => (SocketKey::Transparent, Value::Bool(on)),
            SocketMatch::Wildcard(on) => (SocketKey::Wildcard, Value::Bool(on)),
            SocketMatch::Mark(mark) => (SocketKey::Mark, Value::from(mark)),
        };
        self.then(Match::eq(Field::Socket(key), value))
    }

    /// Compute a value into the first register (#703) — a `numgen`, a
    /// `jhash` of fields, a `symhash` — for the statement after it to
    /// use: [`set_meta_from`](Self::set_meta_from),
    /// [`set_ct_from`](Self::set_ct_from), or a
    /// [`QueueExpr::register`](super::expr::QueueExpr::register).
    ///
    /// ```
    /// use nlink::netlink::nftables::{Generated, MetaKey, NumgenKind, Rule};
    ///
    /// // meta mark set numgen inc mod 2
    /// let r = Rule::new("t", "c")
    ///     .generate(Generated::Numgen { kind: NumgenKind::Incremental, modulus: 2, offset: 0 })
    ///     .set_meta_from(MetaKey::Mark);
    /// # let _ = r;
    /// ```
    pub fn generate(self, generated: Generated) -> Self {
        self.then(Stmt::Generate(generated))
    }

    /// Write the first register into packet metadata: `meta <key> set`
    /// what [`generate`](Self::generate) computed.
    pub fn set_meta_from(self, key: MetaKey) -> Self {
        self.then(Stmt::SetMetaFrom(key))
    }

    /// Write the first register into the conntrack entry: `ct <key> set`
    /// what [`generate`](Self::generate) computed.
    pub fn set_ct_from(self, key: CtKey) -> Self {
        self.then(Stmt::SetCtFrom(key))
    }

    /// Send a copy of the packet (#703): `dup to <addr> [device <dev>]` in
    /// an `ip`/`ip6` chain, routed to `addr` as its gateway, out of the
    /// device with ifindex `dev` when one is given. The copy leaves as it
    /// is; the original goes on.
    pub fn dup_to(self, addr: std::net::IpAddr, dev: Option<u32>) -> Self {
        self.then(Stmt::Dup {
            addr: Some(addr),
            dev,
        })
    }

    /// Send a copy of the packet out of the device with ifindex `dev`
    /// (#703): `dup to <dev>`, in a `netdev` chain.
    pub fn dup_to_device(self, dev: u32) -> Self {
        self.then(Stmt::Dup {
            addr: None,
            dev: Some(dev),
        })
    }

    /// Send the packet out of the device with ifindex `dev` (#703): `fwd
    /// to <dev>`, in a `netdev` chain. The packet is gone from this path.
    pub fn fwd_to(self, dev: u32) -> Self {
        self.then(Stmt::Fwd { dev, addr: None })
    }

    /// Send the packet out of the device with ifindex `dev` to the next hop
    /// `addr`, resolving its link-layer address (#703): `fwd ip to <addr>
    /// device <dev>`, in a `netdev` chain.
    pub fn fwd_ip_to(self, addr: std::net::IpAddr, dev: u32) -> Self {
        self.then(Stmt::Fwd {
            dev,
            addr: Some(addr),
        })
    }

    /// Write a header field (#703): `ip dscp set cs1`, `tcp dport set
    /// 8080`, `ip saddr set 10.0.0.9`, … — as nft writes it, behind the
    /// guard nft puts before it (`meta nfproto`, `meta l4proto`), with the
    /// checksums the field is in updated: the IPv4 header's for its
    /// fields, TCP's for a port, and a transport checksum's pseudo-header
    /// for an address. A field narrower than the 16 bits a checksum update
    /// takes (DSCP, TTL) is read, masked and written back whole.
    pub fn set_header(self, write: HeaderWrite) -> Self {
        self.then(Stmt::SetHeader(write))
    }

    /// Match source IPv4 address with prefix length. Operates on the
    /// IP header (`PayloadBase::Network`), so use only on chains that
    /// see IPv4 traffic (`ip`/`inet`/`netdev` family).
    pub fn match_saddr_v4(self, addr: Ipv4Addr, prefix: u8) -> Self {
        self.then(Match::eq(Field::Ip4Saddr, prefixed(addr.into(), prefix)))
    }

    /// Match source IPv6 address with prefix length. Operates on the
    /// IP header, so use only on chains that see IPv6 traffic
    /// (`ip6`/`inet`/`netdev` family).
    pub fn match_saddr_v6(self, addr: Ipv6Addr, prefix: u8) -> Self {
        self.then(Match::eq(Field::Ip6Saddr, prefixed(addr.into(), prefix)))
    }

    /// Match destination IPv4 address with prefix length. Operates on
    /// the IP header, so use only on chains that see IPv4 traffic.
    pub fn match_daddr_v4(self, addr: Ipv4Addr, prefix: u8) -> Self {
        self.then(Match::eq(Field::Ip4Daddr, prefixed(addr.into(), prefix)))
    }

    /// Match destination IPv6 address with prefix length. Operates on
    /// the IP header, so use only on chains that see IPv6 traffic.
    pub fn match_daddr_v6(self, addr: Ipv6Addr, prefix: u8) -> Self {
        self.then(Match::eq(Field::Ip6Daddr, prefixed(addr.into(), prefix)))
    }

    /// Match input interface by name.
    ///
    /// A name longer than 15 bytes makes adding the rule fail: the kernel's
    /// limit is 15 plus the NUL.
    pub fn match_iif(self, name: &str) -> Self {
        self.then(Match::eq(Field::Iifname, name))
    }

    /// Match packets that did not come in on `name` (`iifname != name`).
    pub fn match_iif_not(self, name: &str) -> Self {
        self.then(Match::ne(Field::Iifname, name))
    }

    /// Match an input interface whose name starts with `prefix`
    /// (`iifname "prefix*"`).
    pub fn match_iif_prefix(self, prefix: &str) -> Self {
        self.then(Match::eq(
            Field::Iifname,
            Value::NamePrefix(prefix.to_string()),
        ))
    }

    /// Match output interface by name. A name longer than 15 bytes makes
    /// adding the rule fail.
    pub fn match_oif(self, name: &str) -> Self {
        self.then(Match::eq(Field::Oifname, name))
    }

    /// Match packets that do not go out on `name` (`oifname != name`).
    pub fn match_oif_not(self, name: &str) -> Self {
        self.then(Match::ne(Field::Oifname, name))
    }

    /// Match an output interface whose name starts with `prefix`
    /// (`oifname "prefix*"`).
    pub fn match_oif_prefix(self, prefix: &str) -> Self {
        self.then(Match::eq(
            Field::Oifname,
            Value::NamePrefix(prefix.to_string()),
        ))
    }

    /// Match connection tracking state.
    pub fn match_ct_state(self, state: CtState) -> Self {
        self.then(Match::eq(Field::CtState, state))
    }

    /// Accept the packet.
    pub fn accept(self) -> Self {
        self.then(Verdict::Accept)
    }

    /// Drop the packet.
    pub fn drop(self) -> Self {
        self.then(Verdict::Drop)
    }

    /// Jump to another chain.
    ///
    /// Pre-validated form — pass a constructed [`ChainName`] when you
    /// already hold one. For the `&str` form that validates the name
    /// at construction, see [`Self::try_jump`].
    pub fn jump(self, chain: ChainName) -> Self {
        self.then(Verdict::JumpTo(chain))
    }

    /// Jump to another chain, validating the name at construction.
    ///
    /// Returns `Err` if the name violates the kernel chain-name
    /// contract (empty, interior NUL, or `len > 255`). The fallible
    /// signature surfaces the validation at the input boundary
    /// instead of as a kernel rejection at apply time.
    ///
    /// (Renamed from the 0.20.1 infallible `jump(&str)` shim in 0.21.
    /// The deprecated `Verdict::Jump(String)` fallback path is gone;
    /// the kernel-name contract is enforced at construction.)
    pub fn try_jump(self, chain: &str) -> Result<Self> {
        Ok(self.jump(ChainName::new(chain)?))
    }

    /// Goto another chain (no return).
    ///
    /// Pre-validated form — pass a constructed [`ChainName`]. For
    /// the `&str` form that validates at construction, see
    /// [`Self::try_goto`].
    pub fn goto(self, chain: ChainName) -> Self {
        self.then(Verdict::GotoTo(chain))
    }

    /// Goto another chain (no return), validating the name at
    /// construction. Returns `Err` if the name violates the kernel
    /// chain-name contract.
    pub fn try_goto(self, chain: &str) -> Result<Self> {
        Ok(self.goto(ChainName::new(chain)?))
    }

    /// Add a packet/byte counter.
    pub fn counter(self) -> Self {
        self.then(Stmt::Counter)
    }

    /// Rate limit: `limit rate <rate>/<unit>` (burst 5). For a burst or
    /// `over`, push a [`LimitExpr`](super::expr::LimitExpr) with
    /// [`expr`](Self::expr).
    pub fn limit(self, rate: u64, unit: LimitUnit) -> Self {
        self.then(Stmt::Limit(super::expr::LimitExpr::packets(rate, unit)))
    }

    /// Byte-rate limit: `limit rate <rate> bytes/<unit>`, no burst (#528).
    /// For a burst or `over`, push a
    /// [`LimitExpr::bytes`](super::expr::LimitExpr::bytes) with
    /// [`expr`](Self::expr).
    pub fn limit_bytes(self, rate: crate::Bytes, unit: LimitUnit) -> Self {
        self.then(Stmt::Limit(super::expr::LimitExpr::bytes(rate, unit)))
    }

    /// Masquerade (source NAT using outgoing interface address).
    pub fn masquerade(self) -> Self {
        self.then(Stmt::Masquerade)
    }

    /// Source NAT to an address (and optional port).
    pub fn snat(self, addr: Ipv4Addr, port: Option<u16>) -> Self {
        self.then(Stmt::NatTo {
            nat_type: NatType::Snat,
            addr: addr.into(),
            port,
        })
    }

    /// Destination NAT to an address (and optional port).
    pub fn dnat(self, addr: Ipv4Addr, port: Option<u16>) -> Self {
        self.then(Stmt::NatTo {
            nat_type: NatType::Dnat,
            addr: addr.into(),
            port,
        })
    }

    /// Source NAT to an IPv6 address (and optional port).
    ///
    /// Use on an `ip6` (or `inet`) NAT chain. The NAT expr's family must match
    /// the address family, so this emits `Family::Ip6` (not the chain's
    /// `Family::Inet`). The 16-byte address is loaded into `R0`; the optional
    /// port into `R1`.
    pub fn snat_v6(self, addr: Ipv6Addr, port: Option<u16>) -> Self {
        self.then(Stmt::NatTo {
            nat_type: NatType::Snat,
            addr: addr.into(),
            port,
        })
    }

    /// Destination NAT to an IPv6 address (and optional port).
    ///
    /// Use on an `ip6` (or `inet`) NAT chain. The NAT expr's family must match
    /// the address family, so this emits `Family::Ip6` (not the chain's
    /// `Family::Inet`). The 16-byte address is loaded into `R0`; the optional
    /// port into `R1`.
    pub fn dnat_v6(self, addr: Ipv6Addr, port: Option<u16>) -> Self {
        self.then(Stmt::NatTo {
            nat_type: NatType::Dnat,
            addr: addr.into(),
            port,
        })
    }

    /// A NAT statement with ranges and flags (#528): see [`NatStatement`].
    /// The address range is loaded into `R0` (and `R1`, for a range), the
    /// port range into the next registers, then the statement names them.
    /// A statement the kernel would refuse makes adding the rule fail.
    pub fn nat(self, nat: NatStatement) -> Self {
        self.then(Stmt::Nat(nat))
    }

    /// Redirect to a local port (DNAT to localhost).
    pub fn redirect(self, port: Option<u16>) -> Self {
        self.then(Stmt::Redirect(port))
    }

    /// Log packet with optional prefix. For an `nflog` group, push a
    /// [`LogExpr`](super::expr::LogExpr) with [`expr`](Self::expr).
    ///
    /// Two things every namespace user meets. To syslog, a `log` in any
    /// namespace but the initial one writes **nothing** unless the host sets
    /// `net.netfilter.nf_log_all_netns=1` (`nf_log_allowed()`); an `nflog`
    /// group has no such limit. And the logger is the `nf_log_syslog` module:
    /// where it cannot be loaded, the rule — and the whole batch with it —
    /// fails with `ENOENT`.
    pub fn log(self, prefix: Option<&str>) -> Self {
        let mut log = super::expr::LogExpr::new();
        if let Some(prefix) = prefix {
            log = log.prefix(prefix);
        }
        self.then(Stmt::Log(log))
    }

    /// Match source IPv4 address against a named set (`ip saddr @set`).
    /// Same as `match_in_set(PacketField::Ip4Saddr, set)`.
    ///
    /// Behind the `meta nfproto ipv4` guard the address matchers carry:
    /// without it, in an `inet` chain an IPv6 packet had bytes 4..8 of its
    /// source address looked up as if they were an IPv4 address.
    pub fn match_saddr_in_set(self, set: &str) -> Self {
        self.match_in_set(PacketField::Ip4Saddr, set)
    }

    /// Match destination IPv4 address against a named set
    /// (`ip daddr @set`). Same as `match_in_set(PacketField::Ip4Daddr, set)`.
    pub fn match_daddr_in_set(self, set: &str) -> Self {
        self.match_in_set(PacketField::Ip4Daddr, set)
    }

    /// Match `field` against a named set: `<field> @<set>` — `ip6 saddr @s`,
    /// `tcp dport @ports`, `meta mark @marks`, … The set's key type must be
    /// `field.key_type()`.
    pub fn match_in_set(self, field: PacketField, set: &str) -> Self {
        self.then(Match::eq(field, Value::set(set)))
    }

    /// Match `field` in an interval set ([`Set::interval`], #703): what
    /// [`match_in_set`](Self::match_in_set) is for a set of ranges. A
    /// host-order field — a mark, an interface index, a class id — is put
    /// in network order first, as nft does, because an interval set stores
    /// those keys that way so their ranges compare as numbers. For any other
    /// field it is `match_in_set`.
    pub fn match_in_interval_set(self, field: PacketField, set: &str) -> Self {
        self.then(Match::eq(field, Value::IntervalSet(set.to_string())))
    }

    /// [`match_in_interval_set`](Self::match_in_interval_set), inverted:
    /// `<field> != @<set>`.
    pub fn match_not_in_interval_set(self, field: PacketField, set: &str) -> Self {
        self.then(Match::ne(field, Value::IntervalSet(set.to_string())))
    }

    /// Match `field` when it is *not* in a named set: `<field> != @<set>` —
    /// iptables `-m set ! --match-set`. Packets that fail the field's
    /// protocol guard (an IPv6 packet, for an IPv4 field) do not match.
    pub fn match_not_in_set(self, field: PacketField, set: &str) -> Self {
        self.then(Match::ne(field, Value::set(set)))
    }

    /// Match a concatenation of fields against a set of concatenated keys:
    /// `ip daddr . udp dport @s` — ipset `hash:ip,port`, and with an
    /// interval set `hash:net,port`. The set's key type must be
    /// `SetKeyType::Concat` of the fields' [`PacketField::key_type`]s, in
    /// the same order.
    ///
    /// Each field's protocol guard comes first, once, then each field is
    /// loaded into the 32-bit word after the previous one, as `nft` lays a
    /// concatenation out. The data area holds 16 words (64 bytes — four
    /// IPv6 addresses); a longer concatenation is refused by the kernel.
    pub fn match_concat_in_set(self, fields: &[PacketField], set: &str) -> Self {
        self.then(Match::eq(Field::Concat(fields.to_vec()), Value::set(set)))
    }

    /// Match a concatenation of fields when it is *not* in a set:
    /// `ip saddr . tcp dport != @s`.
    pub fn match_concat_not_in_set(self, fields: &[PacketField], set: &str) -> Self {
        self.then(Match::ne(Field::Concat(fields.to_vec()), Value::set(set)))
    }

    /// `<field> vmap @<map>`: the verdict the map holds for `field` decides
    /// the packet — accept, drop, or jump to a chain ([`Set::vmap`]). A
    /// packet whose field is not in the map goes on to the next rule.
    pub fn vmap(self, field: PacketField, map: &str) -> Self {
        self.then(Stmt::Vmap {
            key: field.into(),
            map: map.to_string(),
        })
    }

    /// `<field> . <field> vmap @<map>`: [`vmap`](Self::vmap) on a
    /// concatenation, laid out as [`match_concat_in_set`](Self::match_concat_in_set)
    /// does.
    pub fn vmap_concat(self, fields: &[PacketField], map: &str) -> Self {
        self.then(Stmt::Vmap {
            key: Field::Concat(fields.to_vec()),
            map: map.to_string(),
        })
    }

    /// `meta mark set <field> map @<map>`: set the packet mark to the value
    /// the map holds for `field` — a map of [`SetKeyType::Mark`] values. A
    /// packet whose field is not in the map stops at this rule, unmarked.
    pub fn set_mark_from_map(self, field: PacketField, map: &str) -> Self {
        self.then(Stmt::SetMetaFromMap {
            key: MetaKey::Mark,
            field,
            map: map.to_string(),
        })
    }

    /// `meta priority set <field> map @<map>`: the TC class the map holds
    /// for `field` — a map of [`SetKeyType::ClassId`] values
    /// ([`SetElement::classid`]). HTB sends the packet straight to that
    /// class, as with [`set_priority`](Self::set_priority).
    pub fn set_priority_from_map(self, field: PacketField, map: &str) -> Self {
        self.then(Stmt::SetMetaFromMap {
            key: MetaKey::Priority,
            field,
            map: map.to_string(),
        })
    }

    /// Count with, or check against, the named object of `object_type` —
    /// `counter name "web"`, `quota name "q"`, `limit name "l"`. Created
    /// with [`Connection::add_object`](crate::netlink::Connection::add_object)
    /// or declared on the table.
    pub fn objref(self, object_type: super::object::ObjectType, name: &str) -> Self {
        self.then(Stmt::Objref {
            object_type,
            name: name.to_string(),
        })
    }

    /// `counter name "<name>"`: count into a named counter, shared by every
    /// rule that names it.
    pub fn counter_named(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::Counter, name)
    }

    /// `quota name "<name>"`: match against a named quota.
    pub fn quota_named(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::Quota, name)
    }

    /// `limit name "<name>"`: match against a named limit.
    pub fn limit_named(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::Limit, name)
    }

    /// `meta secmark set "<name>"`: give the packet the security mark of the
    /// named secmark object (`ObjectConfig::Secmark`, #703), which the LSM
    /// (SELinux, AppArmor) then mediates.
    pub fn set_secmark(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::Secmark, name)
    }

    /// `ct helper set "<name>"`: assign the named conntrack helper object
    /// ([`CtHelperObject`](super::CtHelperObject)) to the packet's
    /// connection (#703). The kernel attaches it only while the connection
    /// is unconfirmed, on its first packet, so the rule goes in a
    /// prerouting or output chain.
    pub fn set_ct_helper(self, name: &str) -> Self {
        self.objref(super::object::ObjectType::CtHelper, name)
    }

    /// `counter name <field> map @<map>` (and the same for quotas and
    /// limits): use the object the object map holds for `field` — one
    /// counter per address, ipset's per-element `counters`. A packet whose
    /// field is not in the map stops at this rule.
    pub fn objref_from_map(self, field: PacketField, map: &str) -> Self {
        self.then(Stmt::ObjrefFromMap {
            field,
            map: map.to_string(),
        })
    }

    /// `quota until <bytes> bytes`: match until the rule has passed `bytes`
    /// bytes. The quota is the rule's own; share one with
    /// [`quota_named`](Self::quota_named).
    pub fn quota_until(self, bytes: u64) -> Self {
        self.then(Stmt::Quota(super::expr::QuotaExpr::new(bytes)))
    }

    /// `quota over <bytes> bytes`: match once the rule has passed `bytes`.
    pub fn quota_over(self, bytes: u64) -> Self {
        self.then(Stmt::Quota(super::expr::QuotaExpr::new(bytes).over()))
    }

    /// Add `field` to a set from the packet path: `add @<set> { <field>
    /// [timeout T] }` — ipset `SET --add-set`. An element already there is
    /// left alone (its timeout keeps running). `timeout` overrides the
    /// set's default; the set must be [`Set::dynamic`], and have timeouts
    /// for a timeout. See [`DynsetExpr`](super::expr::DynsetExpr).
    pub fn add_to_set(
        self,
        field: PacketField,
        set: &str,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.push_dynset(super::expr::DynsetOp::Add, field, set, timeout)
    }

    /// Add `field` to a set, or restart its timeout if it is there:
    /// `update @<set> { <field> [timeout T] }` — "seen in the last T".
    pub fn update_in_set(
        self,
        field: PacketField,
        set: &str,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        self.push_dynset(super::expr::DynsetOp::Update, field, set, timeout)
    }

    /// Remove `field` from a set: `delete @<set> { <field> }` — ipset
    /// `SET --del-set`. Kernel 5.4+.
    pub fn delete_from_set(self, field: PacketField, set: &str) -> Self {
        self.push_dynset(super::expr::DynsetOp::Delete, field, set, None)
    }

    /// `<op> @<set> { <field> [timeout T] [statements] }`: the general form
    /// of [`add_to_set`](Self::add_to_set), [`update_in_set`](Self::update_in_set)
    /// and [`delete_from_set`](Self::delete_from_set), for a `dynset` with
    /// per-element statements (#703). Loads `field` and sets the dynset's
    /// key register to it.
    ///
    /// ```no_run
    /// # use nlink::netlink::nftables::{DynsetExpr, DynsetOp, LimitExpr};
    /// # use nlink::netlink::nftables::types::{LimitUnit, PacketField, Register, Rule};
    /// // update @flood { ip saddr limit rate over 10/second } drop
    /// let flood = DynsetExpr::new(DynsetOp::Update, "flood", Register::R0)
    ///     .statement(LimitExpr::packets(10, LimitUnit::Second).over());
    /// let rule = Rule::new("filter", "input").dynset(PacketField::Ip4Saddr, flood).drop();
    /// ```
    pub fn dynset(self, field: PacketField, dynset: super::expr::DynsetExpr) -> Self {
        self.then(Stmt::Dynset { field, dynset })
    }

    fn push_dynset(
        self,
        op: super::expr::DynsetOp,
        field: PacketField,
        set: &str,
        timeout: Option<std::time::Duration>,
    ) -> Self {
        let mut dynset = super::expr::DynsetExpr::new(op, set, Register::R0);
        if let Some(timeout) = timeout {
            dynset = dynset.timeout(timeout);
        }
        self.then(Stmt::Dynset { field, dynset })
    }

    /// Match layer-4 protocol (e.g., TCP=6, UDP=17, ICMP=1).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # use nlink::netlink::nftables::Rule;
    /// // Match ICMP traffic
    /// let icmp = Rule::new("filter", "input").match_l4proto(1);
    /// // Match TCP traffic
    /// let tcp = Rule::new("filter", "input").match_l4proto(6);
    /// # Ok(())
    /// # }
    /// ```
    pub fn match_l4proto(self, proto: u8) -> Self {
        self.then(Match::eq(Field::L4Proto, proto))
    }

    /// Match `field` within `first..=last`, both included, as `nft`'s
    /// `tcp dport 1000-2000` or `meta mark 0x10-0x20` (#528). Behind the
    /// field's protocol guard, as [`match_in_set`](Self::match_in_set) is;
    /// a host-order field (a mark, an interface index) is turned to network
    /// order first, as `nft` does, so the range compares numbers. Values of
    /// the wrong kind, or a range that runs backwards, make adding the rule
    /// fail.
    pub fn match_range(
        self,
        field: PacketField,
        first: impl Into<RangeValue>,
        last: impl Into<RangeValue>,
    ) -> Self {
        self.then(Match::eq(field, Value::range(first, last)))
    }

    /// Match `field` outside `first..=last`: `tcp dport != 1000-2000`.
    pub fn match_range_not(
        self,
        field: PacketField,
        first: impl Into<RangeValue>,
        last: impl Into<RangeValue>,
    ) -> Self {
        self.then(Match::ne(field, Value::range(first, last)))
    }

    /// Match the source address in `addr/prefix`, IPv4 or IPv6 (#528).
    pub fn match_saddr(self, addr: std::net::IpAddr, prefix: u8) -> Self {
        match addr {
            std::net::IpAddr::V4(a) => self.match_saddr_v4(a, prefix),
            std::net::IpAddr::V6(a) => self.match_saddr_v6(a, prefix),
        }
    }

    /// Match the source address outside `addr/prefix`, IPv4 or IPv6.
    pub fn match_saddr_not(self, addr: std::net::IpAddr, prefix: u8) -> Self {
        match addr {
            std::net::IpAddr::V4(a) => self.match_saddr_v4_not(a, prefix),
            std::net::IpAddr::V6(a) => self.match_saddr_v6_not(a, prefix),
        }
    }

    /// Match the destination address in `addr/prefix`, IPv4 or IPv6.
    pub fn match_daddr(self, addr: std::net::IpAddr, prefix: u8) -> Self {
        match addr {
            std::net::IpAddr::V4(a) => self.match_daddr_v4(a, prefix),
            std::net::IpAddr::V6(a) => self.match_daddr_v6(a, prefix),
        }
    }

    /// Match the destination address outside `addr/prefix`, IPv4 or IPv6.
    pub fn match_daddr_not(self, addr: std::net::IpAddr, prefix: u8) -> Self {
        match addr {
            std::net::IpAddr::V4(a) => self.match_daddr_v4_not(a, prefix),
            std::net::IpAddr::V6(a) => self.match_daddr_v6_not(a, prefix),
        }
    }

    /// Match a connection with any of `status`'s bits: `ct status dnat`
    /// (#528).
    pub fn match_ct_status(self, status: CtStatus) -> Self {
        self.then(Match::eq(Field::CtStatus, status))
    }

    /// Match the packet's direction in its connection: `ct direction
    /// reply`.
    pub fn match_ct_direction(self, direction: CtDirection) -> Self {
        self.then(Match::eq(Field::CtDirection, direction))
    }

    /// Match the connection's zone: `ct zone <zone>`.
    pub fn match_ct_zone(self, zone: u16) -> Self {
        self.then(Match::eq(Field::CtZone, zone))
    }

    /// Put the packet's connection in `zone`: `ct zone set <zone>`. In a
    /// chain at the `raw` priority, before conntrack sees the packet.
    pub fn set_ct_zone(self, zone: u16) -> Self {
        self.then(Stmt::SetCtZone(zone))
    }

    /// Match an address of the connection's `direction` tuple: `ct
    /// original ip saddr 10.0.0.1` is
    /// `match_ct_addr(CtDirection::Original, true, addr)`; `source: false`
    /// is the destination.
    pub fn match_ct_addr(
        self,
        direction: CtDirection,
        source: bool,
        addr: std::net::IpAddr,
    ) -> Self {
        let field = if source {
            Field::CtSaddr(direction)
        } else {
            Field::CtDaddr(direction)
        };
        self.then(Match::eq(field, addr))
    }

    /// Match a port of the connection's `direction` tuple: `ct reply
    /// proto-src 53` is `match_ct_port(CtDirection::Reply, true, 53)`.
    pub fn match_ct_port(self, direction: CtDirection, source: bool, port: u16) -> Self {
        let field = if source {
            Field::CtSport(direction)
        } else {
            Field::CtDport(direction)
        };
        self.then(Match::eq(field, port))
    }

    /// Match a connection carrying label `bit` (0..=127): `ct label <bit>`.
    pub fn match_ct_label(self, bit: u8) -> Self {
        self.then(Match::eq(Field::CtLabel, bit))
    }

    /// Give the connection label `bit` (0..=127), keeping the others: `ct
    /// label set <bit>`.
    pub fn set_ct_label(self, bit: u8) -> Self {
        self.then(Stmt::SetCtLabel(bit))
    }

    /// Match while the rule has seen at most `count` connections: `ct
    /// count <count>` (needs `nft_connlimit`).
    pub fn match_ct_count(self, count: u32) -> Self {
        self.then(Stmt::CtCount { count, over: false })
    }

    /// Match once the rule has seen more than `count` connections: `ct
    /// count over <count>`.
    pub fn match_ct_count_over(self, count: u32) -> Self {
        self.then(Stmt::CtCount { count, over: true })
    }

    /// Match the packet type: `meta pkttype broadcast` (#528).
    pub fn match_pkttype(self, pkttype: PktType) -> Self {
        self.then(Match::eq(Field::PktType, pkttype))
    }

    /// Match any packet type but `pkttype`: `meta pkttype != broadcast`.
    pub fn match_pkttype_not(self, pkttype: PktType) -> Self {
        self.then(Match::ne(Field::PktType, pkttype))
    }

    /// Match a packet the routing table has no route for, as `flags`
    /// looks it up (#528): `fib saddr . iif oif missing` is
    /// `match_fib_missing(FibFlags::SADDR | FibFlags::IIF)` — the
    /// reverse-path check against spoofed sources.
    pub fn match_fib_missing(self, flags: FibFlags) -> Self {
        self.then(Match::eq(
            Field::Fib {
                flags,
                result: FibResult::Oif,
            },
            false,
        ))
    }

    /// Match a packet whose address, as `flags` looks it up, is of
    /// `addr_type`: `fib daddr type local` is
    /// `match_fib_type(FibFlags::DADDR, RouteType::Local)`.
    pub fn match_fib_type(
        self,
        flags: FibFlags,
        addr_type: crate::netlink::types::route::RouteType,
    ) -> Self {
        self.then(Match::eq(
            Field::Fib {
                flags,
                result: FibResult::AddrType,
            },
            addr_type,
        ))
    }

    /// `notrack` (#528): leave the packet out of connection tracking. In
    /// a chain at the `raw` priority on `prerouting` or `output`, before
    /// conntrack sees it; `ct state untracked` then matches it.
    pub fn notrack(self) -> Self {
        self.then(Stmt::Notrack)
    }

    /// Match a TCP source port other than `port`: `tcp sport != <port>`.
    pub fn match_tcp_sport_not(self, port: u16) -> Self {
        self.then(Match::ne(Field::TcpSport, port))
    }

    /// Match a UDP source port other than `port`: `udp sport != <port>`.
    pub fn match_udp_sport_not(self, port: u16) -> Self {
        self.then(Match::ne(Field::UdpSport, port))
    }

    /// Match a mark other than `mark`: `meta mark != <mark>`.
    pub fn match_mark_not(self, mark: u32) -> Self {
        self.then(Match::ne(Field::Mark, mark))
    }

    /// Match a layer-4 protocol other than `proto`: `meta l4proto != <proto>`.
    pub fn match_l4proto_not(self, proto: u8) -> Self {
        self.then(Match::ne(Field::L4Proto, proto))
    }

    /// Match TCP source port.
    pub fn match_tcp_sport(self, port: u16) -> Self {
        self.then(Match::eq(Field::TcpSport, port))
    }

    /// Match UDP source port.
    pub fn match_udp_sport(self, port: u16) -> Self {
        self.then(Match::eq(Field::UdpSport, port))
    }

    /// Match ICMP type (IPv4).
    ///
    /// Common types: echo-reply=0, echo-request=8, dest-unreachable=3,
    /// time-exceeded=11, redirect=5.
    pub fn match_icmp_type(self, icmp_type: u8) -> Self {
        self.then(Match::eq(Field::IcmpType, icmp_type))
    }

    /// Match ICMPv6 type.
    ///
    /// Common types: echo-request=128, echo-reply=129, neighbor-solicitation=135,
    /// neighbor-advertisement=136, router-solicitation=133, router-advertisement=134.
    pub fn match_icmpv6_type(self, icmp_type: u8) -> Self {
        self.then(Match::eq(Field::Icmp6Type, icmp_type))
    }

    /// Match source IPv4 address not in the given address/prefix.
    /// For prefixes shorter than 32, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_saddr_v4_not(self, addr: Ipv4Addr, prefix: u8) -> Self {
        self.then(Match::ne(Field::Ip4Saddr, prefixed(addr.into(), prefix)))
    }

    /// Match source IPv6 address not in the given address/prefix.
    /// For prefixes shorter than 128, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_saddr_v6_not(self, addr: Ipv6Addr, prefix: u8) -> Self {
        self.then(Match::ne(Field::Ip6Saddr, prefixed(addr.into(), prefix)))
    }

    /// Match destination IPv4 address not in the given address/prefix.
    /// For prefixes shorter than 32, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_daddr_v4_not(self, addr: Ipv4Addr, prefix: u8) -> Self {
        self.then(Match::ne(Field::Ip4Daddr, prefixed(addr.into(), prefix)))
    }

    /// Match destination IPv6 address not in the given address/prefix.
    /// For prefixes shorter than 128, "not equal" means "outside the
    /// subnet" — the load is masked before comparison.
    pub fn match_daddr_v6_not(self, addr: Ipv6Addr, prefix: u8) -> Self {
        self.then(Match::ne(Field::Ip6Daddr, prefixed(addr.into(), prefix)))
    }

    /// Match TCP destination port not equal to the given port.
    pub fn match_tcp_dport_not(self, port: u16) -> Self {
        self.then(Match::ne(Field::TcpDport, port))
    }

    /// Match UDP destination port not equal to the given port.
    pub fn match_udp_dport_not(self, port: u16) -> Self {
        self.then(Match::ne(Field::UdpDport, port))
    }

    /// Match packet mark (nfmark/fwmark).
    pub fn match_mark(self, mark: u32) -> Self {
        self.then(Match::eq(Field::Mark, mark))
    }

    /// Set the packet mark (nfmark/fwmark): `meta mark set <mark>`.
    ///
    /// A statement, not a match: place it after the rule's matches. The
    /// mark is what `tc` `fw` filters and `ip rule fwmark` act on.
    ///
    /// This replaces all 32 bits. On a host where other software uses its
    /// own mark bits (kube-proxy, CNI plugins, VPN policy routing), use
    /// [`set_mark_masked`](Self::set_mark_masked).
    pub fn set_mark(self, mark: u32) -> Self {
        self.then(Stmt::SetMark(mark))
    }

    /// Set only the mark bits under `mask` to `value`, keeping the rest:
    /// `meta mark set mark and ~<mask> or <value>` — iptables
    /// `MARK --set-mark value/mask`.
    ///
    /// Bits of `value` outside `mask` are ignored. Pairs with
    /// [`match_mark_masked`](Self::match_mark_masked) and a `tc` `fw`
    /// filter's mask.
    pub fn set_mark_masked(self, value: u32, mask: u32) -> Self {
        self.then(Stmt::SetMarkMasked { value, mask })
    }

    /// Match the mark bits under `mask`: `meta mark and <mask> == <value>`.
    ///
    /// Bits of `value` outside `mask` are ignored.
    pub fn match_mark_masked(self, value: u32, mask: u32) -> Self {
        self.then(Match::eq(
            Field::Mark,
            Value::Masked {
                value: value.into(),
                mask: mask.into(),
            },
        ))
    }

    /// Set the packet's TC priority to a class: `meta priority set
    /// <major>:<minor>`.
    ///
    /// `skb->priority` is a classid. An HTB qdisc whose handle is `major:`
    /// sends the packet straight to leaf class `major:minor` without
    /// running any filter (`htb_classify`); an inner class runs its own
    /// filters; no such class falls through to the filters and then the
    /// default class. A `prio` qdisc `major:` picks band `minor - 1`. So a
    /// firewall rule can classify into a shaper with no `tc` filter at
    /// all.
    ///
    /// Set it in an `output`, `forward` or `postrouting` chain: for
    /// forwarded IPv4 traffic the kernel overwrites `skb->priority` from
    /// the TOS before the `forward` hook (`net.ipv4.ip_forward_update_priority`,
    /// on by default), so a value set in `prerouting` is lost.
    pub fn set_priority(self, class: TcHandle) -> Self {
        self.then(Stmt::SetPriority(class))
    }

    /// Set the connection's mark: `ct mark set <mark>`.
    ///
    /// The conntrack mark lives with the flow rather than the packet, so
    /// one rule can classify a whole connection: set it once, then copy it
    /// onto every packet with [`restore_mark_from_ct`](Self::restore_mark_from_ct).
    /// Needs the `nft_ct` module.
    pub fn set_ct_mark(self, mark: u32) -> Self {
        self.then(Stmt::SetCtMark(mark))
    }

    /// Match the connection's mark: `ct mark <mark>`.
    pub fn match_ct_mark(self, mark: u32) -> Self {
        self.then(Match::eq(Field::CtMark, mark))
    }

    /// Copy the packet mark to the connection: `ct mark set mark` —
    /// iptables `CONNMARK --save-mark`.
    pub fn save_mark_to_ct(self) -> Self {
        self.then(Stmt::SaveMarkToCt)
    }

    /// Copy the connection mark to the packet: `meta mark set ct mark` —
    /// iptables `CONNMARK --restore-mark`.
    pub fn restore_mark_from_ct(self) -> Self {
        self.then(Stmt::RestoreMarkFromCt)
    }

    /// Match TCP header flags: `tcp flags & <mask> == <flags>`.
    ///
    /// A connection opening (`tcp flags syn / syn,rst`) is
    /// `match_tcp_flags(TcpFlags::SYN, TcpFlags::SYN | TcpFlags::RST)`.
    /// Bits of `flags` outside `mask` are ignored.
    pub fn match_tcp_flags(self, flags: TcpFlags, mask: TcpFlags) -> Self {
        self.then(Match::eq(
            Field::TcpFlags,
            Value::Masked {
                value: flags.bits().into(),
                mask: mask.bits().into(),
            },
        ))
    }

    /// Clamp the TCP MSS option to `mss`: `tcp option maxseg size set <mss>`.
    ///
    /// The MSS is only ever lowered, as with iptables `TCPMSS --set-mss`:
    /// the kernel itself refuses to raise it (`nft_exthdr_tcp_set_eval`,
    /// since 4.14 — "increase can cause connection to stall"), so a SYN
    /// already at or below `mss` passes unchanged. A segment without an
    /// MSS option is also left alone; unlike `TCPMSS`, nftables cannot
    /// insert one.
    ///
    /// A statement, not a match: whatever follows it in the rule still
    /// runs for every TCP packet. Emits what `nft` does — an immediate and
    /// an `exthdr` write — behind the `meta l4proto tcp` guard, because on
    /// a non-TCP packet the write ends rule evaluation. Usually combined
    /// with a SYN match ([`match_tcp_flags`](Self::match_tcp_flags)) in a
    /// `forward` or `postrouting` chain.
    pub fn clamp_tcp_mss(self, mss: u16) -> Self {
        self.then(Stmt::ClampTcpMss(mss))
    }

    /// Clamp the TCP MSS option to what the path allows: `tcp option
    /// maxseg size set rt mtu` — iptables `TCPMSS --clamp-mss-to-pmtu`.
    ///
    /// The route lookup's MSS (the smaller of the route's and the reverse
    /// route's MTU, less the IP and TCP headers) is converted to network
    /// byte order and written, exactly as `nft` linearizes it. As with
    /// [`clamp_tcp_mss`](Self::clamp_tcp_mss) the MSS is only ever lowered,
    /// and a segment without the option is left alone.
    ///
    /// The kernel only allows `rt` in `ip`, `ip6` and `inet` tables, and the
    /// path MSS only in the `forward`, `output` and `postrouting` hooks —
    /// anywhere else the rule is rejected. Usually combined with a SYN
    /// match in `forward`, where a tunnel or PPPoE uplink narrows the path.
    pub fn clamp_tcp_mss_to_pmtu(self) -> Self {
        self.then(Stmt::ClampTcpMssToPmtu)
    }

    /// Reject the packet: send an ICMP port-unreachable, then drop.
    ///
    /// The client fails fast with "connection refused" instead of hanging to
    /// its TCP timeout. For a black hole (no ICMP, no RST), use
    /// [`drop`](Self::drop) instead.
    ///
    /// The type follows the table's family when the rule is sent: `ICMPX`
    /// (family-independent) in `inet`, `bridge` and `netdev`; ICMP port
    /// unreachable in `ip`; ICMPv6 port unreachable in `ip6`. The `ip` and
    /// `ip6` reject expressions do not handle ICMPX, and turned it into a
    /// silent drop (#480). For a TCP RST, or a specific code, use
    /// [`reject_tcp_reset`](Self::reject_tcp_reset),
    /// [`reject_icmp`](Self::reject_icmp) /
    /// [`reject_icmpv6`](Self::reject_icmpv6), or
    /// [`reject_with`](Self::reject_with).
    ///
    /// Until 0.25 this pushed a bare `NF_DROP` verdict — the doc promised
    /// reject semantics and the code delivered a silent drop, so clients hung
    /// until timeout (#205).
    pub fn reject(self) -> Self {
        self.then(Stmt::Reject(Reject::Icmpx(IcmpxCode::PortUnreachable)))
    }

    /// Reject with a TCP reset, behind a `meta l4proto tcp` guard as `nft`
    /// writes it: without one, every non-TCP packet the rule matched would be
    /// dropped silently, since there is nothing to reset (#480).
    pub fn reject_tcp_reset(self) -> Self {
        self.then(Stmt::Reject(Reject::TcpReset))
    }

    /// Reject with an ICMP (IPv4) unreachable of `code` (3 is port
    /// unreachable), behind a `meta nfproto ipv4` guard — `nft`'s `reject
    /// with icmp type …`. Without the guard an `inet` chain would also send
    /// the code to IPv6 packets, as an ICMPv6 code it does not mean (#480).
    /// For `inet`, `ip` and `ip6` tables; in `bridge` and `netdev` the
    /// nfproto is the hook's, and the guard never matches.
    pub fn reject_icmp(self, code: u8) -> Self {
        self.then(Stmt::Reject(Reject::Icmp(code)))
    }

    /// Reject with a family-independent unreachable (#528) — `nft`'s
    /// `reject with icmpx <code>` — which the kernel sends as the ICMP or
    /// ICMPv6 code that means it. [`reject`](Self::reject) is
    /// `reject_icmpx(IcmpxCode::PortUnreachable)`. For `inet`, `bridge` and
    /// `netdev` tables.
    pub fn reject_icmpx(self, code: IcmpxCode) -> Self {
        self.then(Stmt::Reject(Reject::Icmpx(code)))
    }

    /// Reject with an ICMPv6 unreachable of `code` (4 is port
    /// unreachable), behind a `meta nfproto ipv6` guard — `nft`'s `reject
    /// with icmpv6 type …`. See [`reject_icmp`](Self::reject_icmp).
    pub fn reject_icmpv6(self, code: u8) -> Self {
        self.then(Stmt::Reject(Reject::Icmpv6(code)))
    }

    /// Reject the packet with an explicit reject type and ICMP code.
    ///
    /// `reject_type` is one of [`NFT_REJECT_ICMP_UNREACH`],
    /// [`NFT_REJECT_TCP_RST`] or [`NFT_REJECT_ICMPX_UNREACH`]. `icmp_code` is
    /// ignored for a TCP reset.
    ///
    /// [`NFT_REJECT_ICMP_UNREACH`]: super::NFT_REJECT_ICMP_UNREACH
    /// [`NFT_REJECT_TCP_RST`]: super::NFT_REJECT_TCP_RST
    /// [`NFT_REJECT_ICMPX_UNREACH`]: super::NFT_REJECT_ICMPX_UNREACH
    ///
    /// A TCP reset gets a `meta l4proto tcp` guard unless the rule already
    /// has one (#480). `NFT_REJECT_ICMP_UNREACH` gets no guard here: in an
    /// `inet` chain it sends the code to IPv4 and IPv6 packets alike, so
    /// prefer [`reject_icmp`](Self::reject_icmp) /
    /// [`reject_icmpv6`](Self::reject_icmpv6) there.
    pub fn reject_with(self, reject_type: u32, icmp_code: u8) -> Self {
        self.then(Stmt::Reject(Reject::With {
            reject_type,
            code: icmp_code,
        }))
    }

    /// Offload the matched flow to the named flowtable: `flow add @<name>`.
    ///
    /// Follow-on packets of the flow then bypass the ruleset on the
    /// flowtable's fast path. Valid in a `forward` chain only, and the
    /// flowtable must live in the rule's table (see
    /// [`Flowtable`]); usually preceded by
    /// `match_ct_state(CtState::ESTABLISHED)`.
    pub fn flow_offload(self, flowtable: &str) -> Self {
        self.then(Stmt::FlowOffload(flowtable.to_string()))
    }

    /// Append one expression: a payload struct such as
    /// [`LookupExpr`](super::expr::LookupExpr) or
    /// [`LimitExpr`](super::expr::LimitExpr), or any [`Expr`].
    pub fn expr(self, expr: impl Into<Expr>) -> Self {
        self.then(Item::Expr(expr.into()))
    }

    /// Replace the rule's items with raw expressions (advanced): each is
    /// sent as it is, behind the family's guards.
    pub fn expressions(mut self, exprs: Vec<super::expr::Expr>) -> Self {
        self.spec.items = exprs.into_iter().map(Item::Expr).collect();
        self
    }
}

/// Rule info parsed from a dump.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RuleInfo {
    /// Table name.
    pub table: String,
    /// Chain name.
    pub chain: String,
    /// Address family.
    pub family: Family,
    /// Kernel handle.
    pub handle: u64,
    /// Position in chain.
    pub position: Option<u64>,
    /// The declarative identity nlink stored in the rule's comment
    /// (`nlink:<key>`), if this rule was installed by nlink. Drives the
    /// per-rule reconciliation of `NftablesConfig`.
    pub key: Option<String>,
    /// The rule's comment exactly as `nft list ruleset` shows it, whoever
    /// set it (nlink's `nlink:<key>` included).
    pub comment_text: Option<String>,
    /// Raw `NFTA_RULE_USERDATA` payload, preserved verbatim. Lets
    /// callers round-trip foreign comments (set by `iptables-nft`,
    /// `nft -f` users, or other tools) without dropping them, even
    /// though nlink's diff doesn't manage them.
    pub userdata_raw: Option<Vec<u8>>,
    /// Raw `NFTA_RULE_EXPRESSIONS` payload, preserved for the
    /// body-equivalence check in `NftablesDiff::diff` (Plan 157b
    /// v2). Empty when the rule has no expressions (degenerate).
    pub expression_bytes: Vec<u8>,
}

// =============================================================================
// Set types
// =============================================================================

/// Key type for nftables sets.
///
/// Plan 198 §2.1 added `InetProto` (single u8 protocol — e.g.
/// `tcp`, `udp`, `icmp`) and `Concat(Vec<_>)` (composite key
/// used in rules like `ip saddr . tcp dport`).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetKeyType {
    /// IPv4 address (4 bytes).
    Ipv4Addr,
    /// IPv6 address (16 bytes).
    Ipv6Addr,
    /// Ethernet address (6 bytes, padded to 8).
    EtherAddr,
    /// Port number (2 bytes).
    InetService,
    /// Interface index (4 bytes).
    IfIndex,
    /// A TC class id, `major:minor` (4 bytes, host order) — what
    /// `meta priority` holds. A value type for priority maps
    /// ([`Rule::set_priority_from_map`]).
    ClassId,
    /// Mark value (4 bytes).
    Mark,
    /// IP protocol number — a single byte (`tcp` = 6, `udp` = 17,
    /// `icmp` = 1); padded to 4 only as a field of a concatenation.
    /// Plan 198 §2.1.
    InetProto,
    /// Concatenated key — packs multiple component keys
    /// end-to-end with 4-byte alignment between. Common in
    /// rules like `ip saddr . tcp dport`. Plan 198 §2.1.
    /// Build elements with [`SetElement::concat`] and match with
    /// [`Rule::match_concat_in_set`].
    ///
    /// The vector MUST be non-empty (a single-component concat
    /// is degenerate but accepted — the kernel treats it as a
    /// normal key).
    Concat(Vec<SetKeyType>),
    /// A key type nlink has no name for, as the kernel reports it (#708):
    /// nft's datatype id and the key's length. Read back from a set nft
    /// made (`type ifname`); declared, it is sent as it is.
    Other {
        /// The nft datatype id, `NFTA_SET_KEY_TYPE`.
        type_id: u32,
        /// The key's length in bytes, `NFTA_SET_KEY_LEN`.
        len: u32,
    },
}

impl SetKeyType {
    /// Number of bits each component occupies in a `Concat` type word.
    /// nft's `TYPE_BITS`.
    const CONCAT_TYPE_BITS: u32 = 6;

    /// The key type the kernel reports as `type_id` and `len`
    /// (`NFTA_SET_KEY_TYPE`, `NFTA_SET_KEY_LEN`), read back (#708). A
    /// concatenation's id holds a component per 6 bits, the first in the
    /// highest. A type nlink has no name for, or a length that does not
    /// add up, is [`Other`](Self::Other), so the read-back never fails and
    /// never guesses.
    pub fn from_kernel(type_id: u32, len: u32) -> Self {
        let other = Self::Other { type_id, len };
        let single = |id: u32| -> Option<Self> {
            Some(match id {
                7 => Self::Ipv4Addr,
                8 => Self::Ipv6Addr,
                9 => Self::EtherAddr,
                12 => Self::InetProto,
                13 => Self::InetService,
                19 => Self::Mark,
                20 => Self::IfIndex,
                23 => Self::ClassId,
                _ => return None,
            })
        };
        let mask = (1 << Self::CONCAT_TYPE_BITS) - 1;
        if type_id <= mask {
            return match single(type_id) {
                Some(key) if key.len() == len => key,
                _ => other,
            };
        }
        // The components, first to last.
        let mut ids = Vec::new();
        let mut rest = type_id;
        while rest != 0 {
            ids.push(rest & mask);
            rest >>= Self::CONCAT_TYPE_BITS;
        }
        ids.reverse();
        // A field of id 0 is no type; and a leading one could not even be
        // seen, so nothing can be said of the fields.
        if ids.contains(&0) {
            return other;
        }
        let parts: Vec<Option<Self>> = ids.iter().map(|id| single(*id)).collect();
        let known: u32 = parts
            .iter()
            .flatten()
            .map(|p| p.len().next_multiple_of(4))
            .sum();
        let unknown = parts.iter().filter(|p| p.is_none()).count();
        match unknown {
            0 if known == len => Self::Concat(parts.into_iter().flatten().collect()),
            // One component nlink cannot name takes what the others leave,
            // padded to 4 bytes as every field of a concatenation is.
            1 if len > known && (len - known).is_multiple_of(4) => Self::Concat(
                parts
                    .into_iter()
                    .zip(&ids)
                    .map(|(p, id)| {
                        p.unwrap_or(Self::Other {
                            type_id: *id,
                            len: len - known,
                        })
                    })
                    .collect(),
            ),
            _ => other,
        }
    }

    /// The **nftables userspace datatype id** carried in `NFTA_SET_KEY_TYPE`
    /// (nft's `enum datatypes`, `include/datatype.h`).
    ///
    /// The kernel only checks `NFT_DATA_RESERVED_MASK` and stores this value
    /// opaquely, so a wrong id still *creates* the set — it is `nft list
    /// ruleset` that then renders the wrong type, and nft cannot parse or
    /// round-trip the set. Three of these were wrong until 0.25 (#207):
    /// `InetProto` was 14 (which is `icmp_type`), `Mark` was 12 (which is
    /// `inet_protocol`), and `IfIndex` was 15 (which is `tcp_flag`).
    pub fn type_id(&self) -> u32 {
        match self {
            Self::Ipv4Addr => 7,     // TYPE_IPADDR
            Self::Ipv6Addr => 8,     // TYPE_IP6ADDR
            Self::EtherAddr => 9,    // TYPE_ETHERADDR
            Self::InetProto => 12,   // TYPE_INET_PROTOCOL
            Self::InetService => 13, // TYPE_INET_SERVICE
            Self::Mark => 19,        // TYPE_MARK
            Self::IfIndex => 20,     // TYPE_IFINDEX
            Self::ClassId => 23,     // TYPE_CLASSID
            Self::Other { type_id, .. } => *type_id,
            Self::Concat(parts) => {
                // nft's `concat_subtype_add(type, sub) = type << TYPE_BITS | sub`,
                // applied left-to-right across the component list. That puts
                // component 0 in the **high** bits.
                //
                // nlink used to fold the other way (`acc | (id << (i * 6))`),
                // putting component 0 in the *low* bits — the reverse of what
                // nft builds and parses (#207).
                //
                // 6 bits per component in a u32 means at most 5 components fit;
                // beyond that the earliest components shift out the top. The
                // builder caps the list, so this cannot silently truncate.
                parts.iter().fold(0u32, |acc, t| {
                    (acc << Self::CONCAT_TYPE_BITS) | (t.type_id() & 0x3F)
                })
            }
        }
    }

    /// Whether keys of this type are stored in host byte order (a mark, an
    /// ifindex), so their bytes do not compare as numbers. For a
    /// concatenation: whether any of its fields is.
    pub fn is_host_order(&self) -> bool {
        match self {
            Self::Mark | Self::IfIndex | Self::ClassId => true,
            Self::Concat(parts) => parts.iter().any(Self::is_host_order),
            _ => false,
        }
    }

    /// The fields of a concatenation of two or more keys; `None` for any
    /// other key type (a one-field `Concat` is that field).
    pub(crate) fn concat_fields(&self) -> Option<&[SetKeyType]> {
        match self {
            Self::Concat(parts) if parts.len() > 1 => Some(parts),
            _ => None,
        }
    }

    /// Key length in bytes, for `NFTA_SET_KEY_LEN`.
    ///
    /// For `Concat`, the sum of each component's length padded to 4-byte
    /// alignment (the kernel's `nft_set_ext_concat` layout).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u32 {
        match self {
            Self::Ipv4Addr => 4,
            Self::Ipv6Addr => 16,
            // A MAC address is 6 bytes and nft sends klen = 6. It used to say
            // 8 ("padded to 8"), but that padding belongs to the *concat*
            // layout, not to a standalone key — and a klen of 8 makes a 6-byte
            // `sreg` load fail `nft_lookup_init` validation with EINVAL (#207).
            Self::EtherAddr => 6,
            Self::InetService => 2,
            Self::IfIndex => 4,
            Self::ClassId => 4,
            Self::Mark => 4,
            Self::InetProto => 1,
            Self::Other { len, .. } => *len,
            Self::Concat(parts) => {
                // Each component is padded to 4-byte alignment before the next
                // starts. This is where EtherAddr's 6 bytes become 8.
                parts.iter().map(|t| t.len().next_multiple_of(4)).sum()
            }
        }
    }
}

/// A packet field a rule can look up in a set, map or verdict map — with
/// the protocol guard `nft` puts in front of it, and the [`SetKeyType`] a
/// set must have to hold it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PacketField {
    /// `ip saddr` (behind `meta nfproto ipv4`).
    Ip4Saddr,
    /// `ip daddr`.
    Ip4Daddr,
    /// `ip6 saddr` (behind `meta nfproto ipv6`).
    Ip6Saddr,
    /// `ip6 daddr`.
    Ip6Daddr,
    /// `tcp sport` (behind `meta l4proto tcp`).
    TcpSport,
    /// `tcp dport`.
    TcpDport,
    /// `udp sport` (behind `meta l4proto udp`).
    UdpSport,
    /// `udp dport`.
    UdpDport,
    /// `meta mark`.
    Mark,
    /// `meta iif` — an interface index, resolved in the rule's netns.
    Iif,
    /// `meta oif`.
    Oif,
    /// `meta l4proto`.
    L4Proto,
}

impl PacketField {
    /// The `meta` comparison `nft` guards this field with: `meta nfproto`
    /// for an address, `meta l4proto` for a port.
    pub(crate) fn guard(self) -> Option<(MetaKey, u8)> {
        match self {
            Self::Ip4Saddr | Self::Ip4Daddr => Some((MetaKey::NfProto, NFPROTO_IPV4)),
            Self::Ip6Saddr | Self::Ip6Daddr => Some((MetaKey::NfProto, NFPROTO_IPV6)),
            Self::TcpSport | Self::TcpDport => Some((MetaKey::L4Proto, IPPROTO_TCP)),
            Self::UdpSport | Self::UdpDport => Some((MetaKey::L4Proto, IPPROTO_UDP)),
            Self::Mark | Self::Iif | Self::Oif | Self::L4Proto => None,
        }
    }

    /// The expression loading this field into `dreg`.
    pub(crate) fn load(self, dreg: Register) -> Expr {
        let payload = |base, offset, len| Expr::Payload {
            dreg,
            base,
            offset,
            len,
        };
        let meta = |key| Expr::Meta { dreg, key };
        match self {
            Self::Ip4Saddr => payload(PayloadBase::Network, 12, 4),
            Self::Ip4Daddr => payload(PayloadBase::Network, 16, 4),
            Self::Ip6Saddr => payload(PayloadBase::Network, 8, 16),
            Self::Ip6Daddr => payload(PayloadBase::Network, 24, 16),
            Self::TcpSport | Self::UdpSport => payload(PayloadBase::Transport, 0, 2),
            Self::TcpDport | Self::UdpDport => payload(PayloadBase::Transport, 2, 2),
            Self::Mark => meta(MetaKey::Mark),
            Self::Iif => meta(MetaKey::Iif),
            Self::Oif => meta(MetaKey::Oif),
            Self::L4Proto => meta(MetaKey::L4Proto),
        }
    }

    /// `value` as this field holds it in a register, in network byte
    /// order; `None` when it is not of the field's kind.
    pub(crate) fn range_bytes(self, value: RangeValue) -> Option<Vec<u8>> {
        use std::net::IpAddr;
        match (self, value) {
            (Self::Ip4Saddr | Self::Ip4Daddr, RangeValue::Addr(IpAddr::V4(a))) => {
                Some(a.octets().to_vec())
            }
            (Self::Ip6Saddr | Self::Ip6Daddr, RangeValue::Addr(IpAddr::V6(a))) => {
                Some(a.octets().to_vec())
            }
            (
                Self::TcpSport | Self::TcpDport | Self::UdpSport | Self::UdpDport,
                RangeValue::Port(p),
            ) => Some(p.to_be_bytes().to_vec()),
            (Self::Mark | Self::Iif | Self::Oif, RangeValue::U32(v)) => Some(v.to_be_bytes().to_vec()),
            (Self::L4Proto, RangeValue::U8(v)) => Some(vec![v]),
            _ => None,
        }
    }

    /// The key type a set must have to hold this field.
    pub fn key_type(self) -> SetKeyType {
        match self {
            Self::Ip4Saddr | Self::Ip4Daddr => SetKeyType::Ipv4Addr,
            Self::Ip6Saddr | Self::Ip6Daddr => SetKeyType::Ipv6Addr,
            Self::TcpSport | Self::TcpDport | Self::UdpSport | Self::UdpDport => {
                SetKeyType::InetService
            }
            Self::Mark => SetKeyType::Mark,
            Self::Iif | Self::Oif => SetKeyType::IfIndex,
            Self::L4Proto => SetKeyType::InetProto,
        }
    }

    /// Bytes the field occupies in a register.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> u32 {
        self.key_type().len()
    }
}

/// What the kernel picks a set's backend for (`NFTA_SET_POLICY`, #703):
/// lookup speed, the default, or memory.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u32)]
#[non_exhaustive]
pub enum SetPolicy {
    /// `policy performance`, the default; the kernel does not dump it.
    #[default]
    Performance = 0,
    /// `policy memory`.
    Memory = 1,
}

impl SetPolicy {
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::Performance),
            1 => Some(Self::Memory),
            _ => None,
        }
    }
}

/// Set flags — `NFTA_SET_FLAGS`, the `NFT_SET_*` bits, in the shape of
/// [`CtState`] and [`TcpFlags`]. Combine with `|`.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SetFlags(pub u32);

impl SetFlags {
    pub const ANONYMOUS: Self = Self(super::NFT_SET_ANONYMOUS);
    pub const CONSTANT: Self = Self(super::NFT_SET_CONSTANT);
    pub const INTERVAL: Self = Self(super::NFT_SET_INTERVAL);
    pub const MAP: Self = Self(super::NFT_SET_MAP);
    pub const TIMEOUT: Self = Self(super::NFT_SET_TIMEOUT);
    pub const EVAL: Self = Self(super::NFT_SET_EVAL);
    pub const OBJECT: Self = Self(super::NFT_SET_OBJECT);
    pub const CONCAT: Self = Self(super::NFT_SET_CONCAT);
    pub const EXPR: Self = Self(super::NFT_SET_EXPR);

    /// No flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn bits(self) -> u32 {
        self.0
    }

    /// Whether every bit of `other` is set.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for SetFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for SetFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// What a map maps its keys to.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SetDataType {
    /// A verdict: a verdict map (`vmap`), whose lookup decides the packet
    /// or jumps to a chain.
    Verdict,
    /// A value of this type: a mark, a class id, an address, …
    Value(SetKeyType),
    /// A named stateful object of this type: an object map, whose elements
    /// name counters, quotas or limits ([`SetElement::object`]).
    Object(super::object::ObjectType),
}

impl SetDataType {
    /// What a set maps to, as the kernel reports it (#708): `Ok(None)` for
    /// a plain set, the object type's number as the error for an object
    /// map of a type nlink has no name for.
    pub(crate) fn from_kernel(
        flags: SetFlags,
        data_type: Option<u32>,
        data_len: Option<u32>,
        object_type: Option<u32>,
    ) -> std::result::Result<Option<Self>, String> {
        if flags.contains(SetFlags::OBJECT) {
            let Some(id) = object_type else {
                return Err("an object map without an object type".into());
            };
            return super::object::ObjectType::from_u32(id)
                .map(|t| Some(Self::Object(t)))
                .ok_or_else(|| format!("object type {id}"));
        }
        if !flags.contains(SetFlags::MAP) {
            return Ok(None);
        }
        Ok(Some(match data_type {
            Some(super::NFT_DATA_VERDICT) => Self::Verdict,
            Some(id) => Self::Value(SetKeyType::from_kernel(id, data_len.unwrap_or_default())),
            None => return Err("map without a data type".into()),
        }))
    }

    /// `NFTA_SET_DATA_TYPE`: `NFT_DATA_VERDICT` for a verdict map, else the
    /// value type's nft datatype id (the kernel stores it opaquely).
    /// An object map has no data type; it is `NFT_SET_OBJECT` with
    /// `NFTA_SET_OBJ_TYPE` instead.
    pub(crate) fn type_id(&self) -> Option<u32> {
        match self {
            Self::Verdict => Some(super::NFT_DATA_VERDICT),
            Self::Value(value) => Some(value.type_id()),
            Self::Object(_) => None,
        }
    }

    /// `NFTA_SET_DATA_LEN`, for a value map. The kernel sizes a verdict
    /// itself.
    pub(crate) fn len(&self) -> Option<u32> {
        match self {
            Self::Verdict | Self::Object(_) => None,
            Self::Value(value) => Some(value.len()),
        }
    }

    /// The flag that makes a set this kind of map.
    pub(crate) fn flag(&self) -> SetFlags {
        match self {
            Self::Object(_) => SetFlags::OBJECT,
            _ => SetFlags::MAP,
        }
    }
}

/// Set builder.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Set {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) key_type: SetKeyType,
    pub(crate) flags: SetFlags,
    pub(crate) size: Option<u32>,
    pub(crate) timeout: Option<std::time::Duration>,
    pub(crate) gc_interval: Option<std::time::Duration>,
    pub(crate) data_type: Option<SetDataType>,
    pub(crate) comment: Option<String>,
    /// Tag it as the declarative apply's own (#527).
    pub(crate) owned: bool,
    pub(crate) policy: Option<SetPolicy>,
    /// What every element gets (#703).
    pub(crate) statements: Vec<super::expr::ElementStatement>,
}

impl Set {
    /// Create a new named set.
    pub fn new(table: &str, name: &str) -> Self {
        Self {
            table: table.to_string(),
            name: name.to_string(),
            family: Family::Inet,
            key_type: SetKeyType::Ipv4Addr,
            flags: SetFlags::empty(),
            size: None,
            timeout: None,
            gc_interval: None,
            data_type: None,
            comment: None,
            owned: false,
            policy: None,
            statements: Vec::new(),
        }
    }

    /// `policy memory`: let the kernel pick the set's backend for memory
    /// rather than lookup speed (#703). Written when the set is created;
    /// the declarative diff recreates a set whose declared policy changed.
    pub fn policy(mut self, policy: SetPolicy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Give every element a `statement` of its own (#703): `set s { …;
    /// counter; }`, ipset's `counters`. The kernel adds it to each element,
    /// whether a control-plane add or a [`DynsetExpr`](super::DynsetExpr)
    /// puts it there, and a lookup that matches the element updates it:
    /// [`SetElement::counter`] reads what it counted. Written when the set
    /// is created; the declarative diff recreates a set whose statements
    /// changed.
    pub fn statement(mut self, statement: impl Into<super::expr::ElementStatement>) -> Self {
        self.statements.push(statement.into());
        self
    }

    /// A `counter` on every element: [`statement`](Self::statement).
    pub fn counter(self) -> Self {
        self.statement(super::expr::ElementStatement::Counter)
    }

    /// Give the set a comment, which `nft list` shows (#528). Written when
    /// the set is created; changing it later takes recreating the set.
    /// Adding one longer than 127 bytes fails.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Make this a map (`NFT_SET_MAP`, or `NFT_SET_OBJECT` for an object
    /// map): each element maps its key to `data` — [`SetElement::value`],
    /// [`SetElement::verdict`] or [`SetElement::object`]. Read it with
    /// [`Rule::set_mark_from_map`], [`Rule::vmap`],
    /// [`Rule::objref_from_map`] and the like.
    pub fn map(mut self, data: SetDataType) -> Self {
        self.flags |= data.flag();
        self.data_type = Some(data);
        self
    }

    /// A verdict map (`vmap`): `map(SetDataType::Verdict)`.
    pub fn vmap(self) -> Self {
        self.map(SetDataType::Verdict)
    }

    /// Let rules add, refresh and delete elements from the packet path
    /// ([`DynsetExpr`](super::expr::DynsetExpr), `Rule::add_to_set` …):
    /// `NFT_SET_EVAL`, nft's `flags dynamic`. It selects the resizable
    /// hash backend, the one that supports updates — without it a sized
    /// set gets a fixed hash, and a rule updating it fails `EOPNOTSUPP`.
    pub fn dynamic(mut self) -> Self {
        self.flags |= SetFlags::EVAL;
        self
    }

    /// Give elements a default timeout (`timeout 60s`): an element expires
    /// this long after it was added, unless it carries its own. Sets
    /// `NFT_SET_TIMEOUT`. The kernel keeps it in jiffies, so it reads back
    /// rounded down to one; sub-millisecond parts are dropped.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self.timeout = Some(timeout);
        self
    }

    /// Let elements carry their own timeouts, without a default (`flags
    /// timeout`): `NFT_SET_TIMEOUT`.
    pub fn per_element_timeouts(mut self) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self
    }

    /// How often the kernel sweeps expired elements out (`gc-interval`).
    /// Expired elements stop matching and stop being listed at once; this
    /// only bounds the memory they hold. Sets `NFT_SET_TIMEOUT`, which the
    /// kernel requires with it.
    pub fn gc_interval(mut self, interval: std::time::Duration) -> Self {
        self.flags |= SetFlags::TIMEOUT;
        self.gc_interval = Some(interval);
        self
    }

    /// Set the address family.
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Set the key type.
    pub fn key_type(mut self, key_type: SetKeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Mark as constant (immutable after creation).
    pub fn constant(mut self) -> Self {
        self.flags |= SetFlags::CONSTANT;
        self
    }

    /// Make this an interval set (`NFT_SET_INTERVAL`), holding ranges and
    /// prefixes — ipset `hash:net`. Its key type must be one whose bytes
    /// compare as numbers: addresses, ports, protocols. A mark or ifindex
    /// key is host-order (`nft` byte-swaps it first), which nlink does not
    /// model, so their elements are refused.
    ///
    /// With a [`SetKeyType::Concat`] key every field is a range of its own
    /// — `10.0.0.0/24 . 1000-2000`, ipset `hash:net,port` — and the set is
    /// also flagged `NFT_SET_CONCAT` with its field lengths, which is what
    /// selects the kernel's `pipapo` backend.
    pub fn interval(mut self) -> Self {
        self.flags |= SetFlags::INTERVAL;
        self
    }

    /// Maximum number of elements (`nft add set ... { size N; }`).
    ///
    /// Adding an element to a full set fails with `ENFILE`
    /// (`err.errno() == Some(libc::ENFILE)`). Without a size the set is
    /// unbounded. The size also steers the kernel's backend choice: a sized
    /// set without the timeout or interval flags gets the fixed-bucket
    /// `nft_hash` instead of the resizable `nft_rhash`.
    pub fn size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    /// Owning table.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Set name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the flags directly. Overwrites any previously set flags
    /// (including [`Self::constant`]); combine them with `|` if you need
    /// several.
    pub fn flags(mut self, flags: SetFlags) -> Self {
        self.flags = flags;
        self
    }

    /// The flags as written; see [`wire_flags`]. A set with a data type is
    /// a map, whatever its flags say.
    pub(crate) fn wire_flags(&self) -> SetFlags {
        let mut flags = wire_flags(&self.key_type, self.flags);
        if let Some(data) = &self.data_type {
            flags |= data.flag();
        }
        // Several statements are NFTA_SET_EXPRESSIONS, which the kernel
        // takes only with NFT_SET_EXPR, and keeps.
        if self.statements.len() > 1 {
            flags |= SetFlags::EXPR;
        }
        flags
    }

    /// See [`ranges_per_field`].
    pub(crate) fn ranges_per_field(&self) -> bool {
        ranges_per_field(&self.key_type, self.flags)
    }

    /// Whether this interval set stores host-order keys in network order
    /// ([`SetElement::host_to_wire`]), as nft does (#703).
    pub(crate) fn swaps_range_keys(&self) -> bool {
        swaps_range_keys(&self.key_type, self.flags)
    }
}

/// Whether an interval set of `key_type` keeps its keys in network order
/// although the field is in host order: a mark, an ifindex, a class id. A
/// concatenation with such a field is not modelled.
pub(crate) fn swaps_range_keys(key_type: &SetKeyType, flags: SetFlags) -> bool {
    flags.contains(SetFlags::INTERVAL)
        && key_type.concat_fields().is_none()
        && key_type.is_host_order()
}

/// Whether a set holds ranges as a start and an inclusive end in one
/// element (`NFTA_SET_ELEM_KEY_END`) — an interval set of concatenated keys
/// — rather than as a start and an end-plus-one element.
pub(crate) fn ranges_per_field(key_type: &SetKeyType, flags: SetFlags) -> bool {
    flags.contains(SetFlags::INTERVAL) && key_type.concat_fields().is_some()
}

/// A set's flags as written: an interval set of concatenated keys also
/// carries `NFT_SET_CONCAT`, which the kernel requires alongside the field
/// lengths, and reports back.
pub(crate) fn wire_flags(key_type: &SetKeyType, flags: SetFlags) -> SetFlags {
    if ranges_per_field(key_type, flags) {
        flags | SetFlags::CONCAT
    } else {
        flags
    }
}

/// A set element: a key, or a range of keys, with what goes with it.
///
/// The fields are private so an element can grow — a range end, map data,
/// a timeout — without a breaking change; build one with the constructors
/// and read it back with the accessors. How an element is written depends
/// on the set it goes into (an interval set stores a range as two wire
/// elements, for one), which is why the element operations take the
/// [`Set`] rather than its name.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SetElement {
    key: Vec<u8>,
    /// Inclusive end of a range element.
    key_end: Option<Vec<u8>>,
    data: Option<SetElementData>,
    timeout: Option<std::time::Duration>,
    /// Time left before the element expires, as the kernel reports it.
    expiration: Option<std::time::Duration>,
    /// `NFTA_SET_ELEM_FLAGS` as read back (`NFT_SET_ELEM_*`).
    flags: u32,
    /// Its comment (#528).
    comment: Option<String>,
    /// Its counter's packets and bytes, as the kernel reports them (#703).
    counter: Option<(u64, u64)>,
    /// Its quota's bytes used, as the kernel reports them (#703).
    quota_used: Option<u64>,
}

/// What a map element maps its key to.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SetElementData {
    /// A value, in the map's data type (`NFTA_DATA_VALUE`).
    Value(Vec<u8>),
    /// A verdict, in a verdict map (`NFTA_DATA_VERDICT`).
    Verdict(Verdict),
    /// The name of a stateful object, in an object map.
    Object(String),
}

impl SetElement {
    /// Create from raw key bytes, in the set's key layout.
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            key_end: None,
            data: None,
            timeout: None,
            expiration: None,
            flags: 0,
            comment: None,
            counter: None,
            quota_used: None,
        }
    }

    /// With a comment, which `nft list` shows (#528). The declarative diff
    /// matches elements by key, so a comment changed later is not
    /// applied; an interval set that merges ranges drops them. Adding one
    /// longer than 127 bytes fails.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// The element's comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// An IPv4 address element.
    pub fn ipv4(addr: Ipv4Addr) -> Self {
        Self::new(addr.octets().to_vec())
    }

    /// An IPv6 address element.
    pub fn ipv6(addr: std::net::Ipv6Addr) -> Self {
        Self::new(addr.octets().to_vec())
    }

    /// A port element (`inet_service`, network byte order).
    pub fn port(port: u16) -> Self {
        Self::new(port.to_be_bytes().to_vec())
    }

    /// A mark element (host byte order, like `meta mark`).
    pub fn mark(mark: u32) -> Self {
        Self::new(mark.to_ne_bytes().to_vec())
    }

    /// An interface-index element (host byte order, like `meta iif`).
    pub fn ifindex(ifindex: u32) -> Self {
        Self::new(ifindex.to_ne_bytes().to_vec())
    }

    /// An IP protocol element (`inet_proto`, e.g. 6 for TCP).
    pub fn inet_proto(proto: u8) -> Self {
        Self::new(vec![proto])
    }

    /// An Ethernet address element.
    pub fn ether(addr: [u8; 6]) -> Self {
        Self::new(addr.to_vec())
    }

    /// A range `[start, end]`, both inclusive, as raw keys in the set's key
    /// layout. Only an interval set ([`Set::interval`]) takes ranges.
    pub fn range(start: Vec<u8>, end_inclusive: Vec<u8>) -> Self {
        Self {
            key_end: Some(end_inclusive),
            ..Self::new(start)
        }
    }

    /// An IPv4 address range, inclusive.
    pub fn ipv4_range(start: Ipv4Addr, end: Ipv4Addr) -> Self {
        Self::range(start.octets().to_vec(), end.octets().to_vec())
    }

    /// An IPv6 address range, inclusive.
    pub fn ipv6_range(start: std::net::Ipv6Addr, end: std::net::Ipv6Addr) -> Self {
        Self::range(start.octets().to_vec(), end.octets().to_vec())
    }

    /// A port range, inclusive (`1000-2000`).
    pub fn port_range(start: u16, end: u16) -> Self {
        Self::range(start.to_be_bytes().to_vec(), end.to_be_bytes().to_vec())
    }

    /// A range of marks, `start` to `end` inclusive, for an interval set of
    /// marks (#703): written in network order, as nft writes it, and read
    /// back in host order like [`mark`](Self::mark). Match it with
    /// [`Rule::match_in_interval_set`].
    pub fn mark_range(start: u32, end: u32) -> Self {
        Self::range(start.to_ne_bytes().to_vec(), end.to_ne_bytes().to_vec())
    }

    /// An IPv4 prefix (`10.0.0.0/8`) as the range it covers. Host bits in
    /// `addr` are masked off, as `nft` does; a prefix length over 32 is an
    /// error.
    pub fn ipv4_prefix(addr: Ipv4Addr, prefix: u8) -> Result<Self> {
        let (start, end) = prefix_range(&addr.octets(), prefix)?;
        Ok(Self::range(start, end))
    }

    /// An IPv6 prefix (`2001:db8::/32`) as the range it covers. Host bits
    /// are masked off; a prefix length over 128 is an error.
    pub fn ipv6_prefix(addr: std::net::Ipv6Addr, prefix: u8) -> Result<Self> {
        let (start, end) = prefix_range(&addr.octets(), prefix)?;
        Ok(Self::range(start, end))
    }

    /// An element of a set of concatenated keys ([`SetKeyType::Concat`]):
    /// one element per field, in the key's order — `10.0.0.1 . 443` is
    /// `concat([SetElement::ipv4(a), SetElement::port(443)])`. Each field is
    /// padded to 4 bytes, as the kernel lays the fields out in registers.
    ///
    /// In an interval set ([`Set::interval`]) a field can be a range or a
    /// prefix of its own: `concat([SetElement::ipv4_prefix(net, 24)?,
    /// SetElement::port_range(1000, 2000)])` is `10.0.0.0/24 . 1000-2000`.
    /// Only the parts' keys and range ends are used.
    pub fn concat(parts: impl IntoIterator<Item = SetElement>) -> Self {
        let parts: Vec<SetElement> = parts.into_iter().collect();
        let padded = |bytes: &[u8]| {
            let mut field = bytes.to_vec();
            field.resize(bytes.len().next_multiple_of(4), 0);
            field
        };
        let key: Vec<u8> = parts.iter().flat_map(|p| padded(&p.key)).collect();
        let key_end: Vec<u8> = parts
            .iter()
            .flat_map(|p| padded(p.key_end.as_deref().unwrap_or(&p.key)))
            .collect();
        // Ranges that are each one value make a single key.
        Self {
            key_end: (key_end != key).then_some(key_end),
            ..Self::new(key)
        }
    }

    /// The key bytes (the range start, for a range).
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// The inclusive end of a range element.
    pub fn key_end(&self) -> Option<&[u8]> {
        self.key_end.as_deref()
    }

    /// Whether this element is a range.
    pub fn is_range(&self) -> bool {
        self.key_end.is_some()
    }

    /// Map this element's key to a value, in a map of values
    /// ([`Set::map`]): built like a key — `SetElement::ipv4(a)
    /// .value(SetElement::mark(0x10))`. Only the value's key bytes are used.
    pub fn value(mut self, value: SetElement) -> Self {
        self.data = Some(SetElementData::Value(value.key));
        self
    }

    /// Map this element's key to a verdict, in a verdict map
    /// ([`Set::vmap`]): `SetElement::port(22).verdict(Verdict::Accept)`.
    pub fn verdict(mut self, verdict: Verdict) -> Self {
        self.data = Some(SetElementData::Verdict(verdict));
        self
    }

    /// Map this element's key to the stateful object `name`, in an object
    /// map: `SetElement::ipv4(a).object("web")`.
    pub fn object(mut self, name: &str) -> Self {
        self.data = Some(SetElementData::Object(name.to_string()));
        self
    }

    /// A class id element (`meta priority`), as [`Rule::set_priority`]
    /// writes it: host order.
    pub fn classid(class: crate::TcHandle) -> Self {
        Self::new(u32::from(class).to_ne_bytes().to_vec())
    }

    /// Give this element its own timeout. The set needs timeouts
    /// ([`Set::timeout`] or [`Set::per_element_timeouts`]).
    ///
    /// The declarative diff does not compare it: a declared element that is
    /// present is left to run out its time, and added again once it has
    /// expired.
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// The data a map element maps to.
    pub fn data(&self) -> Option<&SetElementData> {
        self.data.as_ref()
    }

    /// The element's own timeout, if it has one. Read back from the kernel,
    /// only a timeout that differs from the set's default is reported.
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.timeout
    }

    /// Time left before the element expires, as read back from the kernel.
    pub fn expiration(&self) -> Option<std::time::Duration> {
        self.expiration
    }

    /// The packets and bytes the element's own counter has counted, as read
    /// back from the kernel (#703): a set with a counter on every element
    /// ([`Set::counter`]), or one a [`DynsetExpr`](super::DynsetExpr) gave
    /// it.
    pub fn counter(&self) -> Option<(u64, u64)> {
        self.counter
    }

    /// The bytes the element's own quota has used, as read back from the
    /// kernel (#703).
    pub fn quota_used(&self) -> Option<u64> {
        self.quota_used
    }

    /// Whether this is a raw interval-end marker (`NFT_SET_ELEM_INTERVAL_END`),
    /// as an element event reports it.
    pub fn is_interval_end(&self) -> bool {
        self.flags & super::NFT_SET_ELEM_INTERVAL_END != 0
    }

    /// Whether this is the catch-all element (`NFT_SET_ELEM_CATCHALL`).
    pub fn is_catchall(&self) -> bool {
        self.flags & super::NFT_SET_ELEM_CATCHALL != 0
    }

    /// What the declarative diff compares: the key, the range end and
    /// catch-all-ness — never live state such as the expiration. A range
    /// `[k, k]` is the key `k`: that is how it is written, and read back.
    pub(crate) fn identity(&self) -> (&[u8], Option<&[u8]>, bool) {
        let end = self.key_end.as_deref().filter(|end| *end != self.key);
        (&self.key, end, self.is_catchall())
    }

    /// Validate this element against the set it is written to. Only what
    /// the writer can encode passes; anything else is an error rather
    /// than something silently dropped.
    /// A `deleting` element is named by its key alone: what it maps to and
    /// its timeout are not checked, and not sent.
    pub(crate) fn check_for(&self, set: &Set, deleting: bool) -> Result<()> {
        let want = set.key_type.len() as usize;
        if self.key.len() != want {
            return Err(Error::invalid_message(format!(
                "set {}: element key is {} bytes, but key type {:?} is {want}",
                set.name,
                self.key.len(),
                set.key_type,
            )));
        }
        if let Some(end) = &self.key_end {
            if !set.flags.contains(SetFlags::INTERVAL) {
                return Err(Error::invalid_message(format!(
                    "set {}: a range element needs an interval set (`Set::interval`)",
                    set.name
                )));
            }
            // A concatenation is a range per field, so each field's end
            // must be at or after its start; the key as a whole proves
            // nothing (`10.0.0.9 . 100` to `10.0.0.10 . 50` sorts fine).
            let widths: Vec<usize> = match set.key_type.concat_fields() {
                Some(fields) => fields.iter().map(|f| f.len().next_multiple_of(4) as usize).collect(),
                None => vec![self.key.len()],
            };
            // A host-order key compares as the number it is (#703).
            let (key, end) = if set.swaps_range_keys() {
                let wire = self.host_to_wire();
                (wire.key, wire.key_end.unwrap_or_default())
            } else {
                (self.key.clone(), end.clone())
            };
            let mut at = 0;
            for width in widths {
                let field = at..at + width;
                at += width;
                if end.len() != key.len() || end[field.clone()] < key[field] {
                    return Err(Error::invalid_message(format!(
                        "set {}: range end {end:02x?} is not at or after its start {key:02x?}",
                        set.name
                    )));
                }
            }
        }
        if deleting {
            return Ok(());
        }
        match (&set.data_type, &self.data) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(Error::invalid_message(format!(
                    "set {}: element data needs a map (`Set::map`)",
                    set.name
                )));
            }
            (Some(_), None) => {
                return Err(Error::invalid_message(format!(
                    "set {}: an element of a map needs data (`SetElement::value` or `::verdict`)",
                    set.name
                )));
            }
            (Some(SetDataType::Verdict), Some(SetElementData::Verdict(_)))
            | (Some(SetDataType::Object(_)), Some(SetElementData::Object(_))) => {}
            (Some(SetDataType::Value(ty)), Some(SetElementData::Value(value)))
                if value.len() == ty.len() as usize => {}
            (Some(want), Some(got)) => {
                return Err(Error::invalid_message(format!(
                    "set {}: element data {got:?} does not fit the map's {want:?}",
                    set.name
                )));
            }
        }
        if self.timeout.is_some() && !set.flags.contains(SetFlags::TIMEOUT) {
            return Err(Error::invalid_message(format!(
                "set {}: an element timeout needs a set with timeouts \
                 (`Set::timeout` or `Set::per_element_timeouts`)",
                set.name
            )));
        }
        Ok(())
    }

    /// An element as read back from the kernel.
    pub(crate) fn from_wire(key: Vec<u8>, flags: u32) -> Self {
        Self {
            flags,
            ..Self::new(key)
        }
    }

    /// This start element as a range ending at `end` (inclusive).
    pub(crate) fn ending_at(mut self, end: Vec<u8>) -> Self {
        self.key_end = Some(end);
        self
    }

    /// With the map data read back.
    pub(crate) fn with_data(mut self, data: Option<SetElementData>) -> Self {
        self.data = data;
        self
    }

    /// With the timeout and time left read back.
    pub(crate) fn with_timers(
        mut self,
        timeout: Option<std::time::Duration>,
        expiration: Option<std::time::Duration>,
    ) -> Self {
        self.timeout = timeout;
        self.expiration = expiration;
        self
    }

    /// With the live state of its statements, as dumped.
    pub(crate) fn with_statements(mut self, statements: &[super::expr::RuleExpr]) -> Self {
        use super::expr::RuleExpr;
        for statement in statements {
            match statement {
                RuleExpr::Counter { packets, bytes } => self.counter = Some((*packets, *bytes)),
                RuleExpr::Quota { consumed, .. } => self.quota_used = Some(*consumed),
                _ => {}
            }
        }
        self
    }

    /// With the range end read back (`NFTA_SET_ELEM_KEY_END`). An end equal
    /// to the key is a single key — what `nft` writes for one — so it reads
    /// back as one.
    pub(crate) fn with_key_end(mut self, key_end: Option<Vec<u8>>) -> Self {
        self.key_end = key_end.filter(|end| *end != self.key);
        self
    }

    /// A host-order key (a mark, an ifindex, a class id) as an interval set
    /// stores it: in network order, so its ranges compare as numbers (#703).
    pub(crate) fn host_to_wire(&self) -> Self {
        self.with_keys(|k| u32::from_ne_bytes(k).to_be_bytes())
    }

    /// The inverse of [`host_to_wire`](Self::host_to_wire).
    pub(crate) fn wire_to_host(&self) -> Self {
        self.with_keys(|k| u32::from_be_bytes(k).to_ne_bytes())
    }

    fn with_keys(&self, swap: impl Fn([u8; 4]) -> [u8; 4]) -> Self {
        let swap = |key: &[u8]| match <[u8; 4]>::try_from(key) {
            Ok(word) => swap(word).to_vec(),
            Err(_) => key.to_vec(),
        };
        let key = swap(&self.key);
        Self {
            // A range of one value is that value, as `with_key_end` has it.
            key_end: self.key_end.as_deref().map(swap).filter(|end| *end != key),
            key,
            ..self.clone()
        }
    }
}

/// Set info parsed from a dump.
///
/// `#[non_exhaustive]` since 0.30: the kernel keeps adding set attributes
/// worth reading back, and each one used to be a breaking change here.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetInfo {
    /// Table name.
    pub table: String,
    /// Set name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Flags.
    pub flags: SetFlags,
    /// Key type ID.
    pub key_type: u32,
    /// Key length.
    pub key_len: u32,
    /// Kernel handle.
    pub handle: u64,
    /// Maximum element count (`NFTA_SET_DESC_SIZE`), if the set has one.
    /// The kernel can report one nobody declared: a set a `dynset`
    /// expression writes to is given 65535.
    pub size: Option<u32>,
    /// Default element timeout (`NFTA_SET_TIMEOUT`), if the set has one —
    /// in whole jiffies, so possibly a little under what was written.
    pub timeout: Option<std::time::Duration>,
    /// Garbage-collection interval (`NFTA_SET_GC_INTERVAL`), if set.
    pub gc_interval: Option<std::time::Duration>,
    /// A map's data type (`NFTA_SET_DATA_TYPE`): `NFT_DATA_VERDICT` for a
    /// verdict map, else an nft datatype id.
    pub data_type: Option<u32>,
    /// A map's data length in bytes (`NFTA_SET_DATA_LEN`).
    pub data_len: Option<u32>,
    /// An object map's object type (`NFTA_SET_OBJ_TYPE`, `NFT_OBJECT_*`).
    pub object_type: Option<u32>,
    /// Its comment (#528).
    pub comment: Option<String>,
    /// Created by nlink's declarative apply: it carries nlink's
    /// ownership tag (#527).
    pub managed: bool,
    /// Its backend policy (#703).
    pub policy: SetPolicy,
    /// The statements every element gets (#703), as their templates dump:
    /// a counter at zero.
    pub statements: Vec<super::expr::RuleExpr>,
}

/// The inclusive range a prefix covers: `addr` with its host bits cleared,
/// and with them set.
fn prefix_range(addr: &[u8], prefix: u8) -> Result<(Vec<u8>, Vec<u8>)> {
    let bits = addr.len() * 8;
    if usize::from(prefix) > bits {
        return Err(Error::invalid_message(format!(
            "prefix length {prefix} is longer than the {bits}-bit address"
        )));
    }
    let mask = prefix_to_mask(addr.len(), prefix);
    let start = addr.iter().zip(&mask).map(|(a, m)| a & m).collect();
    let end = addr.iter().zip(&mask).map(|(a, m)| a | !m).collect();
    Ok((start, end))
}

/// Convert a prefix length to a network mask of `width` bytes.
/// `prefix` is clamped to `width * 8`.
pub(crate) fn prefix_to_mask(width: usize, prefix: u8) -> Vec<u8> {
    let prefix = (prefix as usize).min(width * 8);
    let full_bytes = prefix / 8;
    let remainder = prefix % 8;
    let mut mask = vec![0u8; width];
    for byte in mask.iter_mut().take(full_bytes) {
        *byte = 0xff;
    }
    if remainder != 0 && full_bytes < width {
        mask[full_bytes] = 0xff << (8 - remainder);
    }
    mask
}

#[cfg(test)]
mod tests {

    /// `nft`'s names, both ways (#523).
    #[test]
    fn a_family_shows_and_parses_as_nft_names_it() {
        for f in [Family::Ip, Family::Ip6, Family::Inet, Family::Arp, Family::Bridge, Family::Netdev] {
            assert_eq!(f.to_string().parse::<Family>().unwrap(), f);
        }
        assert_eq!(Family::Inet.to_string(), "inet");
        assert!("ipx".parse::<Family>().is_err());
    }

    use super::*;

    // -------- TableName newtype --------

    #[test]
    fn table_name_validates_like_kernel() {
        assert!(TableName::new("filter").is_ok());
        assert!("filter".parse::<TableName>().is_ok());
        // Empty / interior-NUL / overlong are rejected.
        assert!(TableName::new("").is_err());
        assert!(TableName::new("a\0b").is_err());
        assert!(TableName::new("x".repeat(TableName::MAX_LEN + 1)).is_err());
        // Round-trips through Display / as_str.
        let t = TableName::new("inet-fw").unwrap();
        assert_eq!(t.as_str(), "inet-fw");
        assert_eq!(t.to_string(), "inet-fw");
    }

    #[test]
    fn table_and_chain_name_into_string() {
        let t = TableName::new("filter").unwrap();
        let s: String = t.into();
        assert_eq!(s, "filter");
        let c = ChainName::new("input").unwrap();
        let s: String = c.into();
        assert_eq!(s, "input");
    }

    #[test]
    fn chain_new_accepts_str_and_typed_and_validates() {
        // &str path (validated, fallible).
        let c = Chain::new("filter", "input").unwrap();
        assert_eq!(c.table.as_str(), "filter");
        assert_eq!(c.name.as_str(), "input");
        // Already-typed path (infallible conversion via the
        // Infallible→Error bridge).
        let table = TableName::new("nat").unwrap();
        let name = ChainName::new("postrouting").unwrap();
        let c = Chain::new(table, name).unwrap();
        assert_eq!(c.table.as_str(), "nat");
        // Invalid name surfaces as Err rather than a bad wire frame.
        assert!(Chain::new("", "input").is_err());
        assert!(Chain::new("filter", "a\0b").is_err());
    }

    // -------- Registers and concatenations --------

    #[test]
    fn a_word_that_starts_a_16_byte_register_is_written_as_that_register() {
        assert_eq!(Register::Reg32_00.wire(), 1); // NFT_REG_1
        assert_eq!(Register::Reg32_04.wire(), 2); // NFT_REG_2
        assert_eq!(Register::Reg32_01.wire(), 9); // NFT_REG32_01
        assert_eq!(Register::word(0), Some(Register::R0));
        assert_eq!(Register::word(1), Some(Register::Reg32_01));
        assert_eq!(Register::word(4), Some(Register::R1));
        assert_eq!(Register::word(15), Some(Register::Reg32_15));
        assert_eq!(Register::word(16), None);
        for v in 8..=23 {
            assert_eq!(Register::from_u32(v).map(|r| r as u32), Some(v));
        }
        assert_eq!(Register::from_u32(5), None);
        assert_eq!(Register::from_u32(24), None);
    }

    #[test]
    fn concatenated_elements_pad_each_field_to_a_register_word() {
        let e = SetElement::concat([
            SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::port(443),
        ]);
        assert_eq!(e.key(), [10, 0, 0, 1, 0x01, 0xbb, 0, 0]);
        assert!(!e.is_range());
        // One ranged field makes the element a range; the single field's
        // end is its key.
        let e = SetElement::concat([
            SetElement::ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::port_range(80, 90),
        ]);
        assert_eq!(e.key(), [10, 0, 0, 1, 0, 80, 0, 0]);
        assert_eq!(e.key_end(), Some(&[10, 0, 0, 1, 0, 90, 0, 0][..]));
        // Ranges of one value each are a single key.
        let e = SetElement::concat([
            SetElement::ipv4_range(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 1)),
            SetElement::port_range(80, 80),
        ]);
        assert!(!e.is_range());
        assert_eq!(
            SetElement::range(vec![1], vec![1]).identity(),
            SetElement::new(vec![1]).identity()
        );
        // A MAC is 6 bytes, padded to 8 in a concatenation.
        let e = SetElement::concat([SetElement::ether([1, 2, 3, 4, 5, 6]), SetElement::inet_proto(6)]);
        assert_eq!(e.key(), [1, 2, 3, 4, 5, 6, 0, 0, 6, 0, 0, 0]);
        let key = SetKeyType::Concat(vec![SetKeyType::EtherAddr, SetKeyType::InetProto]);
        assert_eq!(e.key().len(), key.len() as usize);
    }

    #[test]
    fn map_lookups_load_into_the_verdict_or_a_data_register() {
        use super::super::expr::LookupExpr;
        let vmap = Rule::new("t", "c").vmap(PacketField::TcpDport, "vm");
        let last = format!("{:?}", vmap.exprs().last().unwrap());
        let want = LookupExpr::new("vm", Register::R0).dreg(Register::Verdict);
        assert_eq!(last, format!("{:?}", Expr::from(want)));

        let mark = Rule::new("t", "c").set_mark_from_map(PacketField::Ip4Saddr, "m");
        let tail: Vec<String> = mark.exprs()[mark.exprs().len() - 2..]
            .iter()
            .map(|e| format!("{e:?}"))
            .collect();
        let lookup = LookupExpr::new("m", Register::R0).dreg(Register::R0);
        let set = Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: Register::R0,
        };
        assert_eq!(tail, [format!("{:?}", Expr::from(lookup)), format!("{set:?}")]);
    }

    #[test]
    fn a_concat_lookup_guards_first_then_loads_word_by_word() {
        use super::super::expr::{Expr, LookupExpr};
        let rule = Rule::new("t", "c").match_concat_in_set(
            &[PacketField::Ip6Saddr, PacketField::TcpDport, PacketField::TcpSport],
            "s",
        );
        let guard = |key, value| {
            [
                Expr::Meta {
                    dreg: Register::R0,
                    key,
                },
                Expr::Cmp {
                    sreg: Register::R0,
                    op: CmpOp::Eq,
                    data: vec![value],
                },
            ]
        };
        let load = |dreg, base, offset, len| Expr::Payload {
            dreg,
            base,
            offset,
            len,
        };
        let mut want: Vec<Expr> = Vec::new();
        want.extend(guard(MetaKey::NfProto, NFPROTO_IPV6));
        // One l4proto guard for both TCP ports.
        want.extend(guard(MetaKey::L4Proto, IPPROTO_TCP));
        // 16 bytes in words 0-3, then a port in word 4 (`R1`, as the kernel
        // dumps it) and one in word 5.
        want.push(load(Register::R0, PayloadBase::Network, 8, 16));
        want.push(load(Register::R1, PayloadBase::Transport, 2, 2));
        want.push(load(Register::Reg32_05, PayloadBase::Transport, 0, 2));
        want.push(LookupExpr::new("s", Register::R0).into());
        // `Expr` has no `PartialEq`; its `Debug` form names every field.
        assert_eq!(format!("{:?}", rule.exprs()), format!("{want:?}"));
    }

    // -------- SetKeyType wire contract (#207) --------

    /// The scalar datatype ids, against nft's `enum datatypes`
    /// (include/datatype.h). Three of these were wrong, and this test used to
    /// pin one of the wrong ones (`InetProto == 14`, which is actually
    /// `icmp_type`).
    #[test]
    fn set_key_type_scalar_datatype_ids() {
        assert_eq!(SetKeyType::Ipv4Addr.type_id(), 7); // TYPE_IPADDR
        assert_eq!(SetKeyType::Ipv6Addr.type_id(), 8); // TYPE_IP6ADDR
        assert_eq!(SetKeyType::EtherAddr.type_id(), 9); // TYPE_ETHERADDR
        assert_eq!(SetKeyType::InetProto.type_id(), 12); // TYPE_INET_PROTOCOL
        assert_eq!(SetKeyType::InetService.type_id(), 13); // TYPE_INET_SERVICE
        assert_eq!(SetKeyType::Mark.type_id(), 19); // TYPE_MARK
        assert_eq!(SetKeyType::IfIndex.type_id(), 20); // TYPE_IFINDEX

        // The three that were wrong pointed at real-but-different types:
        // 14 = icmp_type, 12 = inet_protocol, 15 = tcp_flag.
        assert_ne!(SetKeyType::InetProto.type_id(), 14);
        assert_ne!(SetKeyType::Mark.type_id(), 12);
        assert_ne!(SetKeyType::IfIndex.type_id(), 15);
    }

    /// A MAC key is 6 bytes on the wire. It used to claim 8 — and a klen of 8
    /// makes a 6-byte `sreg` load fail `nft_lookup_init` with EINVAL. The
    /// padding to 8 belongs to the concat layout, not to a standalone key.
    #[test]
    fn set_key_type_ether_addr_klen_is_six() {
        assert_eq!(SetKeyType::EtherAddr.len(), 6);
        assert_eq!(SetKeyType::InetProto.len(), 1);
        assert_eq!(SetKeyType::InetService.len(), 2);
    }

    #[test]
    fn set_key_type_concat_len_pads_each_component() {
        // ip saddr (4B) . tcp dport (2B → 4B after pad) = 8B.
        let k = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]);
        assert_eq!(k.len(), 8);
    }

    /// nft builds a concat type with
    /// `concat_subtype_add(t, n) = (t << TYPE_BITS) | n`, applied left-to-right
    /// — so component 0 lands in the **high** bits.
    ///
    /// nlink folded the other way, putting component 0 in the *low* bits: the
    /// exact reverse of what nft builds and parses. This test used to pin the
    /// reversed order (#207).
    #[test]
    fn set_key_type_concat_packs_component_zero_in_the_high_bits() {
        // ipv4_addr(7) . inet_service(13)  ->  7 << 6 | 13
        let k = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr, SetKeyType::InetService]);
        assert_eq!(k.type_id(), (7 << 6) | 13);
        assert_ne!(k.type_id(), 7 | (13 << 6), "regression: packing is reversed");
    }

    #[test]
    fn set_key_type_concat_single_component_degenerate() {
        // One-component concat reports the wrapped type's own type_id (no
        // shift). The kernel treats this as a normal key.
        let k = SetKeyType::Concat(vec![SetKeyType::Ipv4Addr]);
        assert_eq!(k.type_id(), 7);
        assert_eq!(k.len(), 4);
    }

    #[test]
    fn set_key_type_concat_three_components_padding_round_trip() {
        // ether_addr (6B → 8B after pad) . ip saddr (4B) . inet_service (2B → 4B) = 16B.
        let k = SetKeyType::Concat(vec![
            SetKeyType::EtherAddr,
            SetKeyType::Ipv4Addr,
            SetKeyType::InetService,
        ]);
        assert_eq!(k.len(), 16);
        // ether_addr(9) . ipv4_addr(7) . inet_service(13), component 0 highest.
        assert_eq!(k.type_id(), (9 << 12) | (7 << 6) | 13);
    }

    // -------- end SetKeyType wire contract --------

    fn find_nat_expr(rule: &Rule) -> Option<NatExpr> {
        rule.exprs().into_iter().find_map(|e| match e {
            super::super::expr::Expr::Nat(n) => Some(n),
            _ => None,
        })
    }

    #[test]
    fn dnat_inet_table_uses_ip_family() {
        let rule = Rule::new("nat", "prerouting")
            .family(Family::Inet)
            .dnat("10.0.0.1".parse().unwrap(), Some(8080));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
        assert_eq!(nat.nat_type, NatType::Dnat);
    }

    #[test]
    fn snat_inet_table_uses_ip_family() {
        let rule = Rule::new("nat", "postrouting")
            .family(Family::Inet)
            .snat("10.0.0.1".parse().unwrap(), None);
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
        assert_eq!(nat.nat_type, NatType::Snat);
    }

    #[test]
    fn dnat_ip_table_uses_ip_family() {
        let rule = Rule::new("nat", "prerouting")
            .family(Family::Ip)
            .dnat("192.168.1.1".parse().unwrap(), Some(80));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
    }

    #[test]
    fn snat_with_port() {
        let rule = Rule::new("nat", "postrouting")
            .family(Family::Inet)
            .snat("192.168.1.1".parse().unwrap(), Some(1024));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.family, Family::Ip);
        assert_eq!(nat.port, Some(1024));
        assert_eq!(nat.addr, NatAddr::V4("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn dnat_v6_loads_address_and_marks_register() {
        let target: Ipv6Addr = "fd30::2".parse().unwrap();
        let rule = Rule::new("t", "c")
            .family(Family::Ip6)
            .match_daddr_v6(Ipv6Addr::LOCALHOST, 128)
            .match_tcp_dport(80)
            .dnat_v6(target, None);

        // The 16-byte target address is loaded into R0 immediately before the
        // NAT expr (after the match exprs).
        let exprs = rule.exprs();
        let imm_r0: Vec<&Vec<u8>> = exprs
            .iter()
            .filter_map(|e| match e {
                super::super::expr::Expr::Immediate {
                    dreg: Register::R0,
                    data,
                } => Some(data),
                _ => None,
            })
            .collect();
        assert!(
            imm_r0.iter().any(|d| d.as_slice() == target.octets()),
            "expected a 16-byte Immediate of the target address into R0"
        );

        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.nat_type, NatType::Dnat);
        assert_eq!(nat.family, Family::Ip6);
        assert_eq!(nat.addr, NatAddr::Reg, "v6 NAT marks the register, carries no Ipv4Addr");
        assert!(nat.addr.reg_in_use(), "address register must be marked in use");
        assert_eq!(nat.port, None);
    }

    #[test]
    fn dnat_v6_with_port_loads_proto_register() {
        let target: Ipv6Addr = "fd30::2".parse().unwrap();
        let rule = Rule::new("t", "c")
            .family(Family::Ip6)
            .dnat_v6(target, Some(8080));
        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.addr, NatAddr::Reg);
        assert_eq!(nat.port, Some(8080));
        // Port loaded into R1.
        let imm_r1 = rule.exprs().iter().any(|e| {
            matches!(
                e,
                super::super::expr::Expr::Immediate {
                    dreg: Register::R1,
                    data,
                } if data.as_slice() == 8080u16.to_be_bytes()
            )
        });
        assert!(imm_r1, "expected port loaded into R1");
    }

    #[test]
    fn snat_v6_loads_address_and_marks_register() {
        let target: Ipv6Addr = "fd30::1".parse().unwrap();
        let rule = Rule::new("t", "c")
            .family(Family::Ip6)
            .snat_v6(target, None);

        let imm_r0 = rule.exprs().iter().any(|e| {
            matches!(
                e,
                super::super::expr::Expr::Immediate {
                    dreg: Register::R0,
                    data,
                } if data.as_slice() == target.octets()
            )
        });
        assert!(imm_r0, "expected a 16-byte Immediate of the target into R0");

        let nat = find_nat_expr(&rule).expect("should have NAT expr");
        assert_eq!(nat.nat_type, NatType::Snat);
        assert_eq!(nat.family, Family::Ip6);
        assert_eq!(nat.addr, NatAddr::Reg, "v6 NAT marks the register, carries no Ipv4Addr");
        assert!(nat.addr.reg_in_use(), "address register must be marked in use");
    }

    // ------------------------------------------------------------
    // IPv6 match helpers
    // ------------------------------------------------------------

    use super::super::expr::Expr;

    fn payload_exprs(rule: &Rule) -> Vec<(PayloadBase, u32, u32)> {
        rule.exprs()
            .iter()
            .filter_map(|e| match e {
                Expr::Payload {
                    base, offset, len, ..
                } => Some((*base, *offset, *len)),
                _ => None,
            })
            .collect()
    }

    /// `Cmp` exprs with the leading nfproto guard stripped by position,
    /// so address-match assertions see only the address comparison.
    fn cmp_exprs(rule: &Rule) -> Vec<(CmpOp, Vec<u8>)> {
        strip_nfproto_guard(&rule.exprs())
            .iter()
            .filter_map(|e| match e {
                Expr::Cmp { op, data, .. } => Some((*op, data.clone())),
                _ => None,
            })
            .collect()
    }

    /// The expression slice with a leading `Meta{NfProto} + Cmp{Eq}`
    /// guard pair removed, if present.
    fn strip_nfproto_guard(exprs: &[Expr]) -> &[Expr] {
        match exprs {
            [
                Expr::Meta { key: MetaKey::NfProto, .. },
                Expr::Cmp { op: CmpOp::Eq, .. },
                rest @ ..,
            ] => rest,
            _ => exprs,
        }
    }

    /// True if `rule` opens with `meta nfproto == <proto>` (Meta at
    /// index 0, its Eq Cmp at index 1).
    fn has_nfproto_guard(rule: &Rule, proto: u8) -> bool {
        matches!(
            rule.exprs().as_slice(),
            [
                Expr::Meta { key: MetaKey::NfProto, .. },
                Expr::Cmp { op: CmpOp::Eq, data, .. },
                ..,
            ] if data.as_slice() == [proto]
        )
    }

    fn bitwise_exprs(rule: &Rule) -> Vec<Vec<u8>> {
        rule.exprs()
            .iter()
            .filter_map(|e| match e {
                Expr::Bitwise { mask, .. } => Some(mask.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn match_saddr_v6_exact() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6(addr, 128);
        let payloads = payload_exprs(&rule);
        let cmps = cmp_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 8, 16)]);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Eq);
        assert_eq!(cmps[0].1, addr.octets().to_vec());
        assert!(bitwise_exprs(&rule).is_empty(), "no mask for /128");
    }

    #[test]
    fn match_saddr_v6_with_prefix() {
        let addr: Ipv6Addr = "2001:db8:cafe::beef".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6(addr, 64);
        let payloads = payload_exprs(&rule);
        let cmps = cmp_exprs(&rule);
        let masks = bitwise_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 8, 16)]);
        assert_eq!(masks.len(), 1);
        assert_eq!(masks[0], prefix_to_mask(16, 64));
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Eq);
        let expected: Vec<u8> = addr
            .octets()
            .iter()
            .zip(prefix_to_mask(16, 64).iter())
            .map(|(a, m)| a & m)
            .collect();
        assert_eq!(cmps[0].1, expected);
    }

    #[test]
    fn match_saddr_v6_overlong_prefix_takes_fast_path() {
        // prefix > 128 is clamped to exact-match: no Bitwise emitted.
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6(addr, 200);
        assert!(bitwise_exprs(&rule).is_empty());
        let cmps = cmp_exprs(&rule);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].1, addr.octets().to_vec());
    }

    #[test]
    fn match_daddr_v6_uses_offset_24() {
        let addr: Ipv6Addr = "fd00::1".parse().unwrap();
        let rule = Rule::new("filter", "output").match_daddr_v6(addr, 128);
        let payloads = payload_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 24, 16)]);
    }

    #[test]
    fn match_saddr_v6_not_flips_op_to_neq() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let rule = Rule::new("filter", "input").match_saddr_v6_not(addr, 128);
        let cmps = cmp_exprs(&rule);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Neq);
    }

    #[test]
    fn match_daddr_v6_not_uses_offset_24_and_neq() {
        let addr: Ipv6Addr = "2001:db8::abcd".parse().unwrap();
        let rule = Rule::new("filter", "output").match_daddr_v6_not(addr, 64);
        let payloads = payload_exprs(&rule);
        let cmps = cmp_exprs(&rule);
        assert_eq!(payloads, vec![(PayloadBase::Network, 24, 16)]);
        assert_eq!(cmps.len(), 1);
        assert_eq!(cmps[0].0, CmpOp::Neq);
    }

    #[test]
    fn addr_matchers_prepend_nfproto_guard() {
        // Every address matcher opens with the two-expr nfproto guard
        // (Meta@0, Eq Cmp@1), with the address Payload immediately after.
        let v4: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let cases = [
            (Rule::new("f", "input").match_saddr_v4(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "output").match_daddr_v4(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "input").match_saddr_v4_not(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "output").match_daddr_v4_not(v4, 24), NFPROTO_IPV4),
            (Rule::new("f", "input").match_saddr_v6(v6, 64), NFPROTO_IPV6),
            (Rule::new("f", "output").match_daddr_v6(v6, 64), NFPROTO_IPV6),
            (Rule::new("f", "input").match_saddr_v6_not(v6, 64), NFPROTO_IPV6),
            (Rule::new("f", "output").match_daddr_v6_not(v6, 64), NFPROTO_IPV6),
        ];
        for (rule, proto) in cases {
            assert!(
                has_nfproto_guard(&rule, proto),
                "matcher must open with meta nfproto == {proto}: {:?}",
                rule.exprs(),
            );
            assert!(
                matches!(rule.exprs().get(2), Some(Expr::Payload { .. })),
                "address payload must immediately follow the 2-expr guard: {:?}",
                rule.exprs(),
            );
        }
    }

    #[test]
    fn icmp_matchers_prepend_nfproto_guard() {
        // ICMP/ICMPv6 are L3-version-specific, so the matchers open with
        // the nfproto guard (Meta@0, Eq Cmp@1) ahead of the l4proto
        // meta+cmp pair — the same `nft`-in-inet behavior as addr matchers.
        let v4 = Rule::new("f", "input").match_icmp_type(8);
        assert!(
            has_nfproto_guard(&v4, NFPROTO_IPV4),
            "match_icmp_type must open with meta nfproto == ipv4: {:?}",
            v4.exprs(),
        );
        let v6 = Rule::new("f", "input").match_icmpv6_type(128);
        assert!(
            has_nfproto_guard(&v6, NFPROTO_IPV6),
            "match_icmpv6_type must open with meta nfproto == ipv6: {:?}",
            v6.exprs(),
        );
    }

    /// What the guards of a rule become in each family (#708): said once,
    /// dropped where the family implies them, an ethertype in bridge and
    /// netdev tables.
    #[test]
    fn guards_are_written_as_the_family_needs_them() {
        use super::super::expr::exprs_for_family;
        let v4: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let rule = Rule::new("f", "c")
            .match_saddr_v4(v4, 32)
            .match_daddr_v4(v4, 32)
            .match_tcp_dport(22)
            .match_tcp_sport(1);
        let guards = |family| -> Vec<(MetaKey, Vec<u8>)> {
            let exprs = exprs_for_family(&rule.exprs(), family).into_owned();
            exprs
                .windows(2)
                .filter_map(|w| match (&w[0], &w[1]) {
                    (Expr::Meta { key, .. }, Expr::Cmp { data, .. })
                        if matches!(key, MetaKey::NfProto | MetaKey::L4Proto | MetaKey::Protocol) =>
                    {
                        Some((*key, data.clone()))
                    }
                    _ => None,
                })
                .collect()
        };
        assert_eq!(
            guards(Family::Inet),
            [(MetaKey::NfProto, vec![NFPROTO_IPV4]), (MetaKey::L4Proto, vec![IPPROTO_TCP])]
        );
        assert_eq!(guards(Family::Ip), [(MetaKey::L4Proto, vec![IPPROTO_TCP])]);
        for family in [Family::Bridge, Family::Netdev] {
            assert_eq!(
                guards(family),
                [(MetaKey::Protocol, vec![0x08, 0x00]), (MetaKey::L4Proto, vec![IPPROTO_TCP])]
            );
        }
        // An ip6 field in an ip table keeps its guard: the rule can never
        // match, and says so.
        let v6 = Rule::new("f", "c").match_saddr_v6("2001:db8::1".parse().unwrap(), 64);
        let lowered = exprs_for_family(&v6.exprs(), Family::Ip).into_owned();
        assert!(matches!(lowered.first(), Some(Expr::Meta { key: MetaKey::NfProto, .. })));
    }

    #[test]
    fn prefix_to_mask_boundaries() {
        // v4 widths
        assert_eq!(prefix_to_mask(4, 0), vec![0u8; 4]);
        assert_eq!(prefix_to_mask(4, 32), vec![0xff; 4]);
        assert_eq!(prefix_to_mask(4, 24), vec![0xff, 0xff, 0xff, 0x00]);
        // v6 widths
        assert_eq!(prefix_to_mask(16, 0), vec![0u8; 16]);
        assert_eq!(prefix_to_mask(16, 128), vec![0xff; 16]);
        let mut sixty_four = vec![0u8; 16];
        for byte in sixty_four.iter_mut().take(8) {
            *byte = 0xff;
        }
        assert_eq!(prefix_to_mask(16, 64), sixty_four);
        // Cross-byte boundary: /68 → 8 bytes 0xff, then 0xf0, then 7 zeros.
        let mut sixty_eight = vec![0u8; 16];
        for byte in sixty_eight.iter_mut().take(8) {
            *byte = 0xff;
        }
        sixty_eight[8] = 0xf0;
        assert_eq!(prefix_to_mask(16, 68), sixty_eight);
        // Clamp: out-of-range prefix saturates to all-ones.
        assert_eq!(prefix_to_mask(16, 200), vec![0xff; 16]);
    }
}

/// #703: each header write is what nft writes for the same statement
/// (`nft --debug=netlink`, nft 1.1.3): the guard, the value or the
/// read-modify-write, and the payload write with its checksums.
#[cfg(test)]
mod header_write_tests {
    use super::*;
    use crate::netlink::nftables::{RuleExpr, expr::Expr};

    fn write(
        base: PayloadBase,
        offset: u32,
        len: u32,
        csum: PayloadCsum,
        csum_offset: u32,
        pseudo: bool,
    ) -> Expr {
        Expr::PayloadSet {
            sreg: Register::R0,
            base,
            offset,
            len,
            csum,
            csum_offset,
            l4_pseudo_header: pseudo,
        }
    }

    fn guard(key: MetaKey, value: u8) -> [Expr; 2] {
        [
            Expr::Meta {
                dreg: Register::R0,
                key,
            },
            Expr::Cmp {
                sreg: Register::R0,
                op: CmpOp::Eq,
                data: vec![value],
            },
        ]
    }

    fn exprs(w: HeaderWrite) -> Vec<Expr> {
        let r = Rule::new("t", "c").set_header(w);
        r.check().unwrap();
        r.exprs()
    }

    #[test]
    fn header_writes_are_what_nft_writes() {
        use PayloadBase::{Network, Transport};
        let imm = |data: &[u8]| Expr::Immediate {
            dreg: Register::R0,
            data: data.to_vec(),
        };
        let rmw = |base, offset, mask: [u8; 2], xor: [u8; 2]| {
            [
                Expr::Payload {
                    dreg: Register::R0,
                    base,
                    offset,
                    len: 2,
                },
                Expr::Bitwise {
                    sreg: Register::R0,
                    dreg: Register::R0,
                    len: 2,
                    mask: mask.to_vec(),
                    xor: xor.to_vec(),
                },
            ]
        };
        let v4 = guard(MetaKey::NfProto, NFPROTO_IPV4);
        let v6 = guard(MetaKey::NfProto, NFPROTO_IPV6);
        let tcp = guard(MetaKey::L4Proto, IPPROTO_TCP);
        let udp = guard(MetaKey::L4Proto, IPPROTO_UDP);
        let cat = |parts: &[&[Expr]]| parts.concat();

        // tcp dport set 8080: immediate 0x1f90, 2b @ th + 2, inet csum at 16.
        assert_eq!(
            exprs(HeaderWrite::TcpDport(8080)),
            cat(&[&tcp, &[imm(&[0x1f, 0x90]), write(Transport, 2, 2, PayloadCsum::Inet, 16, false)]])
        );
        // udp sport set 53: no checksum type, the pseudo-header flag.
        assert_eq!(
            exprs(HeaderWrite::UdpSport(53)),
            cat(&[&udp, &[imm(&[0, 53]), write(Transport, 0, 2, PayloadCsum::None, 0, true)]])
        );
        // ip ttl set 64: 2b @ nh + 8, & 0x00ff ^ 0x4000 (bytes), inet csum at 10.
        assert_eq!(
            exprs(HeaderWrite::IpTtl(64)),
            cat(&[&v4, &rmw(Network, 8, [0x00, 0xff], [64, 0]), &[write(Network, 8, 2, PayloadCsum::Inet, 10, false)]])
        );
        // ip dscp set cs1 (8): 2b @ nh + 0, keep version/ihl and ECN.
        assert_eq!(
            exprs(HeaderWrite::IpDscp(8)),
            cat(&[&v4, &rmw(Network, 0, [0xff, 0x03], [0x00, 0x20]), &[write(Network, 0, 2, PayloadCsum::Inet, 10, false)]])
        );
        // ip saddr set 10.0.0.9: the L4 pseudo-header changes too.
        assert_eq!(
            exprs(HeaderWrite::IpSaddr("10.0.0.9".parse().unwrap())),
            cat(&[&v4, &[imm(&[10, 0, 0, 9]), write(Network, 12, 4, PayloadCsum::Inet, 10, true)]])
        );
        // ip6 dscp set af21 (18): bytes [f0 3f] kept, [04 80] set.
        assert_eq!(
            exprs(HeaderWrite::Ip6Dscp(18)),
            cat(&[&v6, &rmw(Network, 0, [0xf0, 0x3f], [0x04, 0x80]), &[write(Network, 0, 2, PayloadCsum::None, 0, false)]])
        );
        assert_eq!(
            exprs(HeaderWrite::Ip6HopLimit(9)),
            cat(&[&v6, &[imm(&[9]), write(Network, 7, 1, PayloadCsum::None, 0, false)]])
        );
        let a: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            exprs(HeaderWrite::Ip6Daddr(a)),
            cat(&[&v6, &[imm(&a.octets()), write(Network, 24, 16, PayloadCsum::None, 0, true)]])
        );

        let r = Rule::new("t", "c").set_header(HeaderWrite::IpDscp(64));
        assert_eq!(
            r.spec().lower_items().err().as_deref(),
            Some("set_header: DSCP 64 is past 63")
        );
    }

    #[test]
    fn a_payload_write_reads_back() {
        use crate::netlink::{builder::MessageBuilder, nftables::expr};
        let exprs = Rule::new("t", "c")
            .set_header(HeaderWrite::IpSaddr("10.0.0.9".parse().unwrap()))
            .exprs();
        let mut b = MessageBuilder::new(0, 0);
        expr::write_expressions(&mut b, &exprs);
        let back = expr::parse_expressions(&b.as_bytes()[20..]);
        assert!(
            back.iter().any(|e| matches!(
                e,
                RuleExpr::PayloadSet {
                    base: PayloadBase::Network,
                    offset: 12,
                    len: 4,
                    csum: PayloadCsum::Inet,
                    csum_offset: 10,
                    l4_pseudo_header: true,
                    ..
                }
            )),
            "{back:?}"
        );
    }
}
