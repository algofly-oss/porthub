//! TC action builders and configuration.
//!
//! This module provides strongly-typed configuration for TC actions including
//! gact, mirred, police, vlan, skbedit, nat, and tunnel_key actions.
//!
//! # Example
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nlink::netlink::{Connection, Route};
//! use nlink::netlink::action::{GactAction, MirredAction, PoliceAction};
//! use nlink::netlink::filter::MatchallFilter;
//!
//! let conn = Connection::<Route>::new()?;
//!
//! // Drop all traffic
//! let drop = GactAction::drop();
//!
//! // Mirror traffic to another interface by index (namespace-safe):
//! // resolve the name through the connection, not through sysfs.
//! let link = conn
//!     .get_link_by_name("eth1")
//!     .await?
//!     .ok_or("eth1 not found")?;
//! let mirror = MirredAction::mirror_to_egress(link.ifindex());
//!
//! // Rate limit traffic
//! let police = PoliceAction::new()
//!     .rate(nlink::Rate::mbit(8))
//!     .burst(nlink::Bytes::kib(32))
//!     .exceed_drop()
//!     .build();
//! # Ok(())
//! # }
//! ```

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use super::{
    Connection,
    builder::MessageBuilder,
    connection::dump_request,
    error::{Error, Result},
    message::{NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NlMsgType},
    protocol::Route,
    types::tc::{
        TCA_ACT_TAB, TcaMsg,
        action::{
            self, TCA_ACT_INDEX, TCA_ACT_KIND, TCA_ACT_OPTIONS, TcGen, connmark, csum, ct, gact,
            mirred, mpls, nat, pedit, police, sample, skbmod, tunnel_key, vlan,
        },
    },
};

// ============================================================================
// ActionConfig trait
// ============================================================================

/// Trait for action configurations that can be applied.
pub trait ActionConfig: Send + Sync {
    /// Get the action kind (e.g., "gact", "mirred", "police").
    fn kind(&self) -> &'static str;

    /// Write the action options to a message builder.
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;

    /// The devices the action names rather than indexes
    /// ([`MirredAction::to_dev`]), for the connection that installs it to
    /// resolve in its own namespace (#645). None by default.
    fn device_names(&self) -> Vec<&str> {
        Vec::new()
    }

    /// Take the ifindex of each name [`device_names`](Self::device_names)
    /// gave from `ifindexes`; an error for one it does not have.
    fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
        let _ = ifindexes;
        Ok(())
    }

    /// The action as the tokens its `parse_params` reads, its inverse:
    /// parsed back, they install the same action. The document form of a
    /// declared TC tree is written with it (#645). An error for a kind
    /// without one, which is the default, and for a value the grammar
    /// cannot say.
    fn to_params(&self) -> Result<Vec<String>> {
        Err(Error::not_supported(format!(
            "{}: the action has no token form",
            self.kind()
        )))
    }
}

/// The token a verdict is written as: what `parse_params` reads for it
/// (`pass`, `drop`, `pipe`, `reclassify`, `stolen`, `continue`). `None`
/// for one the grammars have no word for (a goto, `queued`, …).
pub(crate) fn verdict_token(action: i32) -> Option<&'static str> {
    Some(match action {
        action::TC_ACT_OK => "pass",
        action::TC_ACT_SHOT => "drop",
        action::TC_ACT_PIPE => "pipe",
        action::TC_ACT_RECLASSIFY => "reclassify",
        action::TC_ACT_STOLEN => "stolen",
        action::TC_ACT_UNSPEC => "continue",
        _ => return None,
    })
}

/// [`verdict_token`], or an error naming `kind`.
fn verdict_param(kind: &str, action: i32) -> Result<String> {
    verdict_token(action).map(str::to_string).ok_or_else(|| {
        Error::not_supported(format!("{kind}: verdict {action:#x} has no token"))
    })
}

/// Whether `tok` is a verdict keyword, as [`parse_gact_verdict`] reads
/// one: the bare verdict most grammars end with, as tc(8)'s `CONTROL`.
fn is_verdict(tok: &str) -> bool {
    matches!(
        tok,
        "pass" | "ok" | "drop" | "shot" | "pipe" | "reclassify" | "stolen" | "continue"
    )
}

/// Push `action`'s bare verdict token onto `out`, unless it is the
/// `default` the grammar gives without one.
fn push_verdict(out: &mut Vec<String>, kind: &str, action: i32, default: i32) -> Result<()> {
    if action != default {
        out.push(verdict_param(kind, action)?);
    }
    Ok(())
}

/// A keyword and its value, as two tokens.
fn kv(key: &str, value: impl std::fmt::Display) -> [String; 2] {
    [key.to_string(), value.to_string()]
}

/// A rate in bytes per second as a `<tc-rate>` token, checked to read
/// back as itself (the parse goes through a float).
fn rate_param(kind: &str, field: &str, bytes_per_sec: u64) -> Result<String> {
    let s = crate::util::Rate::bytes_per_sec(bytes_per_sec).to_string();
    match crate::util::Rate::parse(&s) {
        Ok(r) if r.as_bytes_per_sec() == bytes_per_sec => Ok(s),
        _ => Err(Error::not_supported(format!(
            "{kind}: {field} of {bytes_per_sec} bytes/s has no exact token"
        ))),
    }
}

/// A byte count as a tc-style size token, checked to read back as itself.
fn size_param(kind: &str, field: &str, bytes: u64) -> Result<String> {
    let s = crate::util::Bytes::new(bytes).to_string();
    match crate::util::parse::get_size(&s) {
        Ok(n) if n == bytes => Ok(s),
        _ => Err(Error::not_supported(format!(
            "{kind}: {field} of {bytes} bytes has no exact token"
        ))),
    }
}

// ============================================================================
// GactAction
// ============================================================================

/// Generic action (gact) configuration.
///
/// The gact action performs a simple action on packets: pass, drop, reclassify, etc.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::GactAction;
///
/// // Drop packets
/// let drop = GactAction::drop();
///
/// // Pass packets
/// let pass = GactAction::pass();
///
/// // Pipe to next action
/// let pipe = GactAction::pipe();
///
/// // Random drop with 10% probability
/// let random_drop = GactAction::new(nlink::netlink::types::tc::action::TC_ACT_OK)
///     .random_drop(10)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct GactAction {
    /// The action to take (TC_ACT_OK, TC_ACT_SHOT, etc.).
    action: i32,
    /// Probability type for random actions.
    prob_type: u16,
    /// Probability value (1-10000 for deterministic, 0-65535 for random).
    prob_val: u16,
    /// Action to take on probability match.
    prob_action: i32,
}

impl GactAction {
    /// Create a new gact action with the specified action.
    pub fn new(action: i32) -> Self {
        Self {
            action,
            prob_type: gact::PGACT_NONE,
            prob_val: 0,
            prob_action: action::TC_ACT_OK,
        }
    }

    /// Create a drop action.
    pub fn drop() -> Self {
        Self::new(action::TC_ACT_SHOT)
    }

    /// Create a pass action.
    pub fn pass() -> Self {
        Self::new(action::TC_ACT_OK)
    }

    /// Create a pipe action (continue to next action).
    pub fn pipe() -> Self {
        Self::new(action::TC_ACT_PIPE)
    }

    /// Create a reclassify action.
    pub fn reclassify() -> Self {
        Self::new(action::TC_ACT_RECLASSIFY)
    }

    /// Create a stolen action.
    pub fn stolen() -> Self {
        Self::new(action::TC_ACT_STOLEN)
    }

    /// Create a goto_chain action.
    ///
    /// This transfers packet processing to the specified chain.
    /// Chains provide logical grouping of filters (Linux 4.1+).
    pub fn goto_chain(chain: u32) -> Self {
        use super::types::tc::action::tc_act_goto_chain;
        Self::new(tc_act_goto_chain(chain))
    }

    /// Add random probability for an alternate action.
    ///
    /// The probability is a percentage (0-100).
    pub fn random(mut self, percent: u16, action: i32) -> Self {
        self.prob_type = gact::PGACT_NETRAND;
        // Convert percentage to 0-65535 range
        self.prob_val = ((percent as u32 * 65535) / 100).min(65535) as u16;
        self.prob_action = action;
        self
    }

    /// Add random drop probability.
    pub fn random_drop(self, percent: u16) -> Self {
        self.random(percent, action::TC_ACT_SHOT)
    }

    /// Add deterministic probability (1 in N packets).
    pub fn deterministic(mut self, one_in_n: u16, action: i32) -> Self {
        self.prob_type = gact::PGACT_DETERM;
        self.prob_val = one_in_n;
        self.prob_action = action;
        self
    }

    /// Parse a `tc(8)`-style `gact` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// - One verdict keyword (defaults to `pass` if omitted):
    ///   `pass`/`ok`, `drop`/`shot`, `pipe`, `reclassify`,
    ///   `stolen`, `continue`, or `goto_chain <n>`.
    /// - `random determ <verdict> <one-in-N>` — every Nth matching
    ///   packet takes `<verdict>` instead of the primary verdict.
    /// - `random netrand <verdict> <percent>` — `<percent>` (0-100)
    ///   of matching packets take `<verdict>`.
    ///
    /// Stricter than the legacy `add_gact_options` parser: unknown
    /// tokens, missing values, and unparseable verdicts return
    /// `Error::invalid_message("gact: ...")`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        // Default to TC_ACT_OK (pass).
        let mut act = Self::pass();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "pass" | "ok" => {
                    act = Self::new(action::TC_ACT_OK);
                    i += 1;
                }
                "drop" | "shot" => {
                    act = Self::new(action::TC_ACT_SHOT);
                    i += 1;
                }
                "pipe" => {
                    act = Self::new(action::TC_ACT_PIPE);
                    i += 1;
                }
                "reclassify" => {
                    act = Self::new(action::TC_ACT_RECLASSIFY);
                    i += 1;
                }
                "stolen" => {
                    act = Self::new(action::TC_ACT_STOLEN);
                    i += 1;
                }
                "continue" => {
                    act = Self::new(action::TC_ACT_UNSPEC);
                    i += 1;
                }
                "goto_chain" => {
                    let s = action_need_value(params, i, "gact", key)?;
                    let chain = action_parse_u32("gact", "goto_chain", s)?;
                    act = Self::goto_chain(chain);
                    i += 2;
                }
                "random" => {
                    let kind = action_need_value(params, i, "gact", key)?;
                    let verdict_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "gact: `random <kind>` requires <verdict>".to_string(),
                        )
                    })?;
                    let val_s = params.get(i + 3).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "gact: `random <kind> <verdict>` requires <value>".to_string(),
                        )
                    })?;
                    let verdict = parse_gact_verdict(verdict_s)?;
                    let val: u16 = val_s.parse().map_err(|_| {
                        Error::invalid_message(format!(
                            "gact: invalid random value `{val_s}` (expected u16)"
                        ))
                    })?;
                    act = match kind {
                        "determ" => act.deterministic(val, verdict),
                        "netrand" => act.random(val, verdict),
                        other => {
                            return Err(Error::invalid_message(format!(
                                "gact: unknown random kind `{other}` (expected `determ` or `netrand`)"
                            )));
                        }
                    };
                    i += 4;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "gact: unknown token `{other}` (recognised: pass/drop/pipe/reclassify/stolen/continue, goto_chain <n>, random determ|netrand <verdict> <val>)"
                    )));
                }
            }
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for GactAction {
    fn kind(&self) -> &'static str {
        "gact"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        use super::types::tc::action::{is_goto_chain, tc_act_chain};
        let mut out = if is_goto_chain(self.action) {
            vec!["goto_chain".to_string(), tc_act_chain(self.action).to_string()]
        } else {
            vec![verdict_param("gact", self.action)?]
        };
        let kind = match self.prob_type {
            gact::PGACT_NONE => return Ok(out),
            gact::PGACT_DETERM => "determ",
            gact::PGACT_NETRAND => "netrand",
            other => {
                return Err(Error::not_supported(format!(
                    "gact: random kind {other} has no token"
                )));
            }
        };
        // `random netrand` takes a percentage and stores it scaled to
        // 0..=65535; write the one that scales to this value.
        let value = if self.prob_type == gact::PGACT_NETRAND {
            (0..=100u32)
                .find(|p| (p * 65535 / 100) as u16 == self.prob_val)
                .ok_or_else(|| {
                    Error::not_supported(format!(
                        "gact: random probability {}/65535 is no whole percentage",
                        self.prob_val
                    ))
                })?
        } else {
            u32::from(self.prob_val)
        };
        out.extend([
            "random".to_string(),
            kind.to_string(),
            verdict_param("gact", self.prob_action)?,
            value.to_string(),
        ]);
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = gact::TcGact::new(self.action);
        builder.append_attr(gact::TCA_GACT_PARMS, parms.as_bytes());

        // Add probability if set
        if self.prob_type != gact::PGACT_NONE {
            let prob = gact::TcGactP::new(self.prob_type, self.prob_val, self.prob_action);
            builder.append_attr(gact::TCA_GACT_PROB, prob.as_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// MirredAction
// ============================================================================

/// Mirred action configuration.
///
/// The mirred action redirects or mirrors packets to another interface.
///
/// # Example
///
/// ```no_run
/// # let eth0_ifindex: u32 = 2;
/// # let eth1_ifindex: u32 = 3;
/// # let eth2_ifindex: u32 = 4;
/// use nlink::netlink::action::MirredAction;
///
/// // Redirect to eth1: the packet leaves through it.
/// let redirect = MirredAction::redirect_to_egress(eth1_ifindex);
///
/// // Mirror a copy out of eth2.
/// let mirror = MirredAction::mirror_to_egress(eth2_ifindex);
///
/// // Redirect to eth0's receive path: the packet is *received* by eth0.
/// // To shape inbound traffic through an IFB, use `redirect_to_egress(ifb)`:
/// // the IFB has to transmit the packet for its root qdisc to see it (#458).
/// let ingress_redirect = MirredAction::redirect_to_ingress(eth0_ifindex);
/// ```
#[derive(Debug, Clone)]
pub struct MirredAction {
    /// The mirred action type (redirect, mirror, ingress_redirect, ingress_mirror).
    eaction: i32,
    /// Target interface index.
    ifindex: u32,
    /// The target by name, resolved into `ifindex` by the connection that
    /// installs the action (#645).
    dev: Option<String>,
    /// Action result after mirred.
    action: i32,
}

impl MirredAction {
    /// Create a new mirred action.
    fn new_with_ifindex(eaction: i32, ifindex: u32) -> Self {
        // Default action is TC_ACT_STOLEN for redirect, TC_ACT_PIPE for mirror
        let action = if eaction == mirred::TCA_EGRESS_REDIR || eaction == mirred::TCA_INGRESS_REDIR
        {
            action::TC_ACT_STOLEN
        } else {
            action::TC_ACT_PIPE
        };

        Self {
            eaction,
            ifindex,
            dev: None,
            action,
        }
    }

    /// Send to the device named `dev` instead of the ifindex the
    /// constructor took (#645).
    ///
    /// The name is resolved by the connection that installs the filter —
    /// [`Connection::add_filter`] and its variants, a declared tree's
    /// apply — in that connection's namespace, and again at every install,
    /// so a target that was deleted and created again is found. A filter
    /// whose target does not exist is refused as not found. Writing the
    /// action without a connection ([`ActionConfig::write_options`] on its
    /// own) is an error until it is resolved.
    ///
    /// ```no_run
    /// # async fn example() -> nlink::Result<()> {
    /// # let conn = nlink::Connection::<nlink::Route>::new()?;
    /// use nlink::TcHandle;
    /// use nlink::netlink::{action::{ActionList, MirredAction}, filter::MatchallFilter};
    ///
    /// let to_ifb = MirredAction::redirect_to_egress(0).to_dev("ifb0");
    /// let filter = MatchallFilter::new().actions(ActionList::new().with(to_ifb));
    /// conn.add_filter("eth0", TcHandle::CLSACT_INGRESS, filter).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_dev(mut self, dev: impl Into<String>) -> Self {
        self.dev = Some(dev.into());
        self.ifindex = 0;
        self
    }

    /// The target's name, when [`to_dev`](Self::to_dev) gave one.
    pub fn target_dev(&self) -> Option<&str> {
        self.dev.as_deref()
    }

    /// Redirect to `ifindex`'s **transmit** path: the packet leaves
    /// through that device, past its root qdisc (`mirred egress redirect`).
    ///
    /// This is the redirect for IFB shaping: an IFB shapes what it
    /// transmits, so inbound traffic reaches its root qdisc only this way
    /// (#458).
    pub fn redirect_to_egress(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_EGRESS_REDIR, ifindex)
    }

    /// Redirect to `ifindex`'s **receive** path: the packet arrives on that
    /// device as if it had been received there (`mirred ingress redirect`).
    ///
    /// Not for IFB shaping: a packet redirected this way never passes the
    /// IFB's root qdisc, and the IFB (`IFF_NOARP`) drops ARP, so nothing
    /// gets through. Use [`redirect_to_egress`](Self::redirect_to_egress)
    /// for an IFB (#458).
    pub fn redirect_to_ingress(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_INGRESS_REDIR, ifindex)
    }

    /// Mirror a copy to `ifindex`'s transmit path (`mirred egress
    /// mirror`); the original continues.
    pub fn mirror_to_egress(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_EGRESS_MIRROR, ifindex)
    }

    /// Mirror a copy to `ifindex`'s receive path (`mirred ingress
    /// mirror`); the original continues.
    pub fn mirror_to_ingress(ifindex: u32) -> Self {
        Self::new_with_ifindex(mirred::TCA_INGRESS_MIRROR, ifindex)
    }

    /// An egress redirect.
    #[deprecated(
        since = "0.32.0",
        note = "use `redirect_to_egress`: the name says the direction (#515)"
    )]
    pub fn redirect_by_index(ifindex: u32) -> Self {
        Self::redirect_to_egress(ifindex)
    }

    /// An egress mirror.
    #[deprecated(since = "0.32.0", note = "use `mirror_to_egress` (#515)")]
    pub fn mirror_by_index(ifindex: u32) -> Self {
        Self::mirror_to_egress(ifindex)
    }

    /// An ingress redirect.
    #[deprecated(
        since = "0.32.0",
        note = "use `redirect_to_ingress`, and for an IFB `redirect_to_egress` (#515, #458)"
    )]
    pub fn ingress_redirect_by_index(ifindex: u32) -> Self {
        Self::redirect_to_ingress(ifindex)
    }

    /// An ingress mirror.
    #[deprecated(since = "0.32.0", note = "use `mirror_to_ingress` (#515)")]
    pub fn ingress_mirror_by_index(ifindex: u32) -> Self {
        Self::mirror_to_ingress(ifindex)
    }

    /// Set the action result after mirred.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Continue processing after mirred (use TC_ACT_PIPE).
    pub fn pipe(mut self) -> Self {
        self.action = action::TC_ACT_PIPE;
        self
    }

    /// Parse a `tc(8)`-style `mirred` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// - Direction: `egress` (default) / `ingress`.
    /// - Operation: `redirect` (default) / `mirror`.
    /// - Target interface (one of):
    ///   - `dev <ifname>` — by name, [`to_dev`](Self::to_dev): resolved by
    ///     the connection that installs the filter, in its namespace
    ///     (#645). It used to be looked up through sysfs, in the calling
    ///     process's namespace, as the action was parsed.
    ///   - `ifindex <n>` — a direct ifindex.
    ///
    /// - A verdict for after the action (`pass`, `drop`, `pipe`,
    ///   `reclassify`, `stolen`, `continue`); without one, a redirect
    ///   steals the packet and a mirror pipes it on.
    ///
    /// `dev` and `ifindex` are mutually exclusive; the parser
    /// rejects both being set.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut direction_ingress = false;
        let mut op_mirror = false;
        let mut ifindex: Option<u32> = None;
        let mut dev: Option<&str> = None;
        let mut verdict: Option<i32> = None;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "egress" => {
                    direction_ingress = false;
                    i += 1;
                }
                "ingress" => {
                    direction_ingress = true;
                    i += 1;
                }
                "redirect" => {
                    op_mirror = false;
                    i += 1;
                }
                "mirror" => {
                    op_mirror = true;
                    i += 1;
                }
                "pass" | "ok" | "drop" | "shot" | "pipe" | "reclassify" | "stolen"
                | "continue" => {
                    verdict = Some(parse_gact_verdict(key)?);
                    i += 1;
                }
                "dev" => {
                    let s = action_need_value(params, i, "mirred", key)?;
                    if ifindex.is_some() || dev.is_some() {
                        return Err(Error::invalid_message(
                            "mirred: `dev` and `ifindex` are mutually exclusive".to_string(),
                        ));
                    }
                    dev = Some(s);
                    i += 2;
                }
                "ifindex" => {
                    let s = action_need_value(params, i, "mirred", key)?;
                    if ifindex.is_some() || dev.is_some() {
                        return Err(Error::invalid_message(
                            "mirred: `dev` and `ifindex` are mutually exclusive".to_string(),
                        ));
                    }
                    ifindex = Some(action_parse_u32("mirred", "ifindex", s)?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "mirred: unknown token `{other}` (recognised: egress/ingress, redirect/mirror, dev <ifname>, ifindex <n>, a verdict)"
                    )));
                }
            }
        }

        if ifindex.is_none() && dev.is_none() {
            return Err(Error::invalid_message(
                "mirred: target interface required (use `dev <ifname>` or `ifindex <n>`)"
                    .to_string(),
            ));
        }
        let idx = ifindex.unwrap_or(0);
        let action = match (direction_ingress, op_mirror) {
            (false, false) => Self::redirect_to_egress(idx),
            (false, true) => Self::mirror_to_egress(idx),
            (true, false) => Self::redirect_to_ingress(idx),
            (true, true) => Self::mirror_to_ingress(idx),
        };
        let action = match verdict {
            Some(v) => action.action(v),
            None => action,
        };
        Ok(match dev {
            Some(dev) => action.to_dev(dev),
            None => action,
        })
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for MirredAction {
    fn kind(&self) -> &'static str {
        "mirred"
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if let (Some(dev), 0) = (&self.dev, self.ifindex) {
            return Err(Error::invalid_message(format!(
                "mirred: the target `{dev}` is resolved by the connection that installs the \
                 action; install it through one, or resolve it (`resolve_devices`) first"
            )));
        }
        let parms = mirred::TcMirred::new(self.eaction, self.ifindex, self.action);
        builder.append_attr(mirred::TCA_MIRRED_PARMS, parms.as_bytes());
        Ok(())
    }

    fn device_names(&self) -> Vec<&str> {
        self.dev.as_deref().into_iter().collect()
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let (direction, op) = match self.eaction {
            mirred::TCA_EGRESS_REDIR => ("egress", "redirect"),
            mirred::TCA_EGRESS_MIRROR => ("egress", "mirror"),
            mirred::TCA_INGRESS_REDIR => ("ingress", "redirect"),
            mirred::TCA_INGRESS_MIRROR => ("ingress", "mirror"),
            other => {
                return Err(Error::not_supported(format!(
                    "mirred: eaction {other} has no token"
                )));
            }
        };
        let mut out = vec![direction.to_string(), op.to_string()];
        match &self.dev {
            Some(dev) => out.extend(["dev".to_string(), dev.clone()]),
            None => out.extend(["ifindex".to_string(), self.ifindex.to_string()]),
        }
        // The verdict when it is not the one the constructor gives.
        if self.action != Self::new_with_ifindex(self.eaction, 0).action {
            out.push(verdict_param("mirred", self.action)?);
        }
        Ok(out)
    }

    fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
        if let Some(dev) = &self.dev {
            self.ifindex = *ifindexes
                .get(dev)
                .ok_or_else(|| Error::interface_not_found(dev).with_context("mirred"))?;
        }
        Ok(())
    }
}

// ============================================================================
// PoliceAction
// ============================================================================

/// Police action configuration.
///
/// The police action rate-limits traffic using a token bucket filter.
///
/// # Example
///
/// ```no_run
/// use nlink::{Bytes, Rate};
/// use nlink::netlink::action::PoliceAction;
///
/// // Rate limit to 8 Mbit/s (1 MB/s) with a 32 KiB burst
/// let police = PoliceAction::new()
///     .rate(Rate::mbit(8))
///     .burst(Bytes::kib(32))
///     .exceed_drop()
///     .build();
///
/// // Rate limit with conform/exceed actions
/// let police = PoliceAction::new()
///     .rate(Rate::mbit(80))
///     .burst(Bytes::kib(64))
///     .conform_pass()
///     .exceed_drop()
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct PoliceAction {
    /// Rate in bytes/sec.
    rate: u64,
    /// Peak rate in bytes/sec (optional).
    peakrate: Option<u64>,
    /// Burst size in bytes.
    burst: u32,
    /// MTU.
    mtu: u32,
    /// Action for conforming traffic.
    conform_action: i32,
    /// Action for exceeding traffic.
    exceed_action: i32,
    /// Average rate for exceed action.
    avrate: Option<u32>,
}

impl Default for PoliceAction {
    fn default() -> Self {
        Self::new()
    }
}

impl PoliceAction {
    /// Create a new police action builder.
    pub fn new() -> Self {
        Self {
            rate: 0,
            peakrate: None,
            burst: 0,
            mtu: 2047,
            conform_action: action::TC_ACT_OK,
            exceed_action: action::TC_ACT_SHOT,
            avrate: None,
        }
    }

    /// Set the rate. A typed [`Rate`](crate::Rate) since 0.32: this took
    /// bytes per second as a bare `u64`, beside a `rate_bps` that took bits
    /// (#515).
    pub fn rate(mut self, rate: crate::util::Rate) -> Self {
        self.rate = rate.as_bytes_per_sec();
        self
    }

    /// Set the peak rate.
    pub fn peakrate(mut self, rate: crate::util::Rate) -> Self {
        self.peakrate = Some(rate.as_bytes_per_sec());
        self
    }

    /// Set the burst size.
    pub fn burst(mut self, burst: crate::util::Bytes) -> Self {
        self.burst = burst.as_u32_saturating();
        self
    }

    /// Set the MTU: the largest packet the bucket admits.
    pub fn mtu(mut self, mtu: crate::util::Bytes) -> Self {
        self.mtu = mtu.as_u32_saturating();
        self
    }

    /// Set the action for conforming traffic.
    pub fn conform(mut self, action: i32) -> Self {
        self.conform_action = action;
        self
    }

    /// Pass conforming traffic.
    pub fn conform_pass(mut self) -> Self {
        self.conform_action = action::TC_ACT_OK;
        self
    }

    /// Pipe conforming traffic (continue processing).
    pub fn conform_pipe(mut self) -> Self {
        self.conform_action = action::TC_ACT_PIPE;
        self
    }

    /// Set the action for exceeding traffic.
    pub fn exceed(mut self, action: i32) -> Self {
        self.exceed_action = action;
        self
    }

    /// Drop exceeding traffic.
    pub fn exceed_drop(mut self) -> Self {
        self.exceed_action = action::TC_ACT_SHOT;
        self
    }

    /// Reclassify exceeding traffic.
    pub fn exceed_reclassify(mut self) -> Self {
        self.exceed_action = action::TC_ACT_RECLASSIFY;
        self
    }

    /// Continue processing exceeding traffic.
    pub fn exceed_pipe(mut self) -> Self {
        self.exceed_action = action::TC_ACT_PIPE;
        self
    }

    /// Set the average rate for stateful policing: traffic above it
    /// exceeds, measured by the filter's rate estimator.
    ///
    /// The kernel takes an average rate only with an estimator, and refuses
    /// a filter whose policer has one without with a bare `EINVAL`. Give its
    /// [`ActionList`] one with [`ActionList::with_estimator`] (#792).
    pub fn avrate(mut self, rate: crate::util::Rate) -> Self {
        self.avrate = Some(u32::try_from(rate.as_bytes_per_sec()).unwrap_or(u32::MAX));
        self
    }

    /// Parse a `tc(8)`-style `police` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens (any order)
    ///
    /// - `rate <tc-rate>` (required) — token-bucket fill rate.
    ///   Accepts `100mbit`, `1gbit`, `2.5kbit`, etc.
    /// - `burst <bytes>` (required) — bucket size in `tc(8)` byte
    ///   syntax (`32k`, `1m`, etc.).
    /// - `peakrate <tc-rate>` — optional peak rate.
    /// - `mtu <bytes>` — optional MTU. Without it, 0, as tc(8) sends: the
    ///   kernel takes that as `255 << cell_log` with a rate and as no limit
    ///   without one (#800).
    /// - `avrate <tc-rate>` — optional stateful average rate.
    /// - `conform-exceed <exceed>[/<conform>]` — as tc-police(8) reads
    ///   it, the exceed action first (`drop/pipe` drops what exceeds and
    ///   pipes what conforms; it was read the other way round until
    ///   0.32, #751). Each side accepts the same verdict keywords as
    ///   `gact`. `conform <verdict>` and `exceed <verdict>` set one each.
    ///   Without them, what exceeds is reclassified, as tc(8) does, not
    ///   dropped as [`new`](Self::new)'s default is (#800).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut act = Self::tc_defaults();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "rate" => {
                    let s = action_need_value(params, i, "police", key)?;
                    let r = crate::util::Rate::parse(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "police: invalid rate `{s}` (expected tc-style rate like `1mbit`)"
                        ))
                    })?;
                    act = act.rate(r);
                    i += 2;
                }
                "peakrate" => {
                    let s = action_need_value(params, i, "police", key)?;
                    let r = crate::util::Rate::parse(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "police: invalid peakrate `{s}` (expected tc-style rate)"
                        ))
                    })?;
                    act = act.peakrate(r);
                    i += 2;
                }
                "burst" | "buffer" | "maxburst" => {
                    let s = action_need_value(params, i, "police", key)?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "police: invalid burst `{s}` (expected tc-style size like `32k`)"
                        ))
                    })?;
                    if bytes > u32::MAX as u64 {
                        return Err(Error::invalid_message(format!(
                            "police: burst `{s}` exceeds u32::MAX bytes"
                        )));
                    }
                    act = act.burst(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "mtu" => {
                    let s = action_need_value(params, i, "police", key)?;
                    let bytes = crate::util::parse::get_size(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "police: invalid mtu `{s}` (expected tc-style size)"
                        ))
                    })?;
                    if bytes > u32::MAX as u64 {
                        return Err(Error::invalid_message(format!(
                            "police: mtu `{s}` exceeds u32::MAX bytes"
                        )));
                    }
                    act = act.mtu(crate::util::Bytes::new(bytes));
                    i += 2;
                }
                "avrate" => {
                    let s = action_need_value(params, i, "police", key)?;
                    let r = crate::util::Rate::parse(s).map_err(|_| {
                        Error::invalid_message(format!(
                            "police: invalid avrate `{s}` (expected tc-style rate)"
                        ))
                    })?;
                    let bps = r.as_bytes_per_sec();
                    if bps > u32::MAX as u64 {
                        return Err(Error::invalid_message(format!(
                            "police: avrate `{s}` exceeds u32::MAX bytes/sec"
                        )));
                    }
                    act = act.avrate(r);
                    i += 2;
                }
                "conform-exceed" => {
                    // tc-police(8): `conform-exceed EXCEEDACT[/NOTEXCEEDACT]`,
                    // the exceed action first. It was read conform-first,
                    // so a line from tc(8) policed the wrong traffic (#751).
                    let s = action_need_value(params, i, "police", key)?;
                    let (exceed_s, conform_s) = match s.split_once('/') {
                        Some((e, c)) => (e, Some(c)),
                        None => (s, None),
                    };
                    let verdict = |v: &str| {
                        parse_gact_verdict(v).map_err(|e| {
                            Error::invalid_message(e.to_string().replace("gact:", "police:"))
                        })
                    };
                    act = act.exceed(verdict(exceed_s)?);
                    if let Some(c) = conform_s {
                        act = act.conform(verdict(c)?);
                    }
                    i += 2;
                }
                "conform" => {
                    let s = action_need_value(params, i, "police", key)?;
                    let v = parse_gact_verdict(s).map_err(|e| {
                        Error::invalid_message(e.to_string().replace("gact:", "police:"))
                    })?;
                    act = act.conform(v);
                    i += 2;
                }
                "exceed" => {
                    let s = action_need_value(params, i, "police", key)?;
                    let v = parse_gact_verdict(s).map_err(|e| {
                        Error::invalid_message(e.to_string().replace("gact:", "police:"))
                    })?;
                    act = act.exceed(v);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "police: unknown token `{other}` (recognised: rate, burst/buffer/maxburst, peakrate, mtu, avrate, conform-exceed <exceed>[/<conform>], conform, exceed)"
                    )));
                }
            }
        }
        Ok(act)
    }

    /// What tc(8) sends for the words it is not given (#800): an exceed
    /// verdict of `reclassify`, and an mtu of 0, which the kernel takes as
    /// `255 << cell_log` with a rate table and as no limit without one.
    /// [`parse_params`](Self::parse_params) starts here, and
    /// [`to_params`](ActionConfig::to_params) leaves out what equals it.
    fn tc_defaults() -> Self {
        Self {
            mtu: 0,
            exceed_action: action::TC_ACT_RECLASSIFY,
            ..Self::new()
        }
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for PoliceAction {
    fn kind(&self) -> &'static str {
        "police"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let default = Self::tc_defaults();
        let mut out = Vec::new();
        out.extend(kv("rate", rate_param("police", "rate", self.rate)?));
        out.extend(kv("burst", size_param("police", "burst", self.burst.into())?));
        if let Some(rate) = self.peakrate {
            out.extend(kv("peakrate", rate_param("police", "peakrate", rate)?));
        }
        if self.mtu != default.mtu {
            out.extend(kv("mtu", size_param("police", "mtu", self.mtu.into())?));
        }
        if let Some(rate) = self.avrate {
            out.extend(kv("avrate", rate_param("police", "avrate", rate.into())?));
        }
        // Each on its own: tc(8)'s `conform-exceed` pair is written exceed
        // first, and the two spellings must not be confused.
        if self.conform_action != default.conform_action {
            out.extend(kv("conform", verdict_param("police", self.conform_action)?));
        }
        if self.exceed_action != default.exceed_action {
            out.extend(kv("exceed", verdict_param("police", self.exceed_action)?));
        }
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::{psched, types::tc::qdisc::TcRateSpec};

        // Two defects lived on this message (#194).
        //
        // 1. `tc_police.burst` is psched TICKS — tcf_police_init() does
        //    `police->tcfp_burst = PSCHED_TICKS2NS(parm->burst)`. The raw
        //    byte count made the burst ~15x too small.
        // 2. TCA_POLICE_RATE (the 256-entry rate table) was never emitted at
        //    all. tcf_police_init() calls qdisc_get_rtab() for any non-zero
        //    rate and fails the action when it returns NULL — which it does
        //    both when the attribute is absent *and* when the ratespec's
        //    cell_log is 0. tc_calc_rtable() fixes both by construction.
        let linklayer = psched::LinkLayer::default();

        let mut rate = TcRateSpec {
            rate: self.rate.min(u32::MAX as u64) as u32,
            ..Default::default()
        };
        let rtab = psched::tc_calc_rtable(&mut rate, self.rate, self.mtu, linklayer);

        let mut peakrate = TcRateSpec::default();
        let ptab = self.peakrate.map(|pr| {
            peakrate.rate = pr.min(u32::MAX as u64) as u32;
            psched::tc_calc_rtable(&mut peakrate, pr, self.mtu, linklayer)
        });

        let parms = police::TcPolice {
            rate,
            burst: psched::tc_calc_xmittime(self.rate, self.burst),
            mtu: self.mtu,
            action: self.exceed_action,
            peakrate,
            ..Default::default()
        };

        builder.append_attr(police::TCA_POLICE_TBF, parms.as_bytes());

        // Mandatory whenever a rate is set — see (2) above.
        if self.rate > 0 {
            builder.append_attr(police::TCA_POLICE_RATE, &rtab);
        }
        if let Some(ptab) = &ptab {
            builder.append_attr(police::TCA_POLICE_PEAKRATE, ptab);
        }

        // Add 64-bit rate if needed
        if self.rate > u32::MAX as u64 {
            builder.append_attr(police::TCA_POLICE_RATE64, &self.rate.to_ne_bytes());
        }

        if let Some(pr) = self.peakrate
            && pr > u32::MAX as u64
        {
            builder.append_attr(police::TCA_POLICE_PEAKRATE64, &pr.to_ne_bytes());
        }

        // Add result action
        builder.append_attr_u32(police::TCA_POLICE_RESULT, self.conform_action as u32);

        // Add average rate if set
        if let Some(avrate) = self.avrate {
            builder.append_attr_u32(police::TCA_POLICE_AVRATE, avrate);
        }

        Ok(())
    }
}

// ============================================================================
// VlanAction
// ============================================================================

/// VLAN action configuration.
///
/// The vlan action manipulates VLAN tags on packets.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::VlanAction;
///
/// // Pop VLAN tag
/// let pop = VlanAction::pop();
///
/// // Push VLAN tag with ID 100
/// let push = VlanAction::push(100);
///
/// // Modify VLAN ID to 200
/// let modify = VlanAction::modify(200);
/// ```
#[derive(Debug, Clone)]
pub struct VlanAction {
    /// VLAN action type (pop, push, modify).
    v_action: i32,
    /// VLAN ID (for push/modify).
    vlan_id: Option<u16>,
    /// VLAN priority (for push/modify).
    vlan_prio: Option<u8>,
    /// VLAN protocol (0x8100 for 802.1q, 0x88a8 for 802.1ad).
    vlan_proto: u16,
    /// Action result.
    action: i32,
}

impl VlanAction {
    /// Create a pop VLAN action.
    pub fn pop() -> Self {
        Self {
            v_action: vlan::TCA_VLAN_ACT_POP,
            vlan_id: None,
            vlan_prio: None,
            vlan_proto: vlan::ETH_P_8021Q,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a push VLAN action with the specified VLAN ID.
    pub fn push(vlan_id: u16) -> Self {
        Self {
            v_action: vlan::TCA_VLAN_ACT_PUSH,
            vlan_id: Some(vlan_id),
            vlan_prio: None,
            vlan_proto: vlan::ETH_P_8021Q,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a modify VLAN action with the specified VLAN ID.
    pub fn modify(vlan_id: u16) -> Self {
        Self {
            v_action: vlan::TCA_VLAN_ACT_MODIFY,
            vlan_id: Some(vlan_id),
            vlan_prio: None,
            vlan_proto: vlan::ETH_P_8021Q,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set the VLAN priority.
    pub fn priority(mut self, prio: u8) -> Self {
        self.vlan_prio = Some(prio);
        self
    }

    /// Use 802.1ad (QinQ) protocol.
    pub fn qinq(mut self) -> Self {
        self.vlan_proto = vlan::ETH_P_8021AD;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `vlan` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// Operation (one required):
    /// - `pop` — strip the outer VLAN tag.
    /// - `push id <id>` — push a new tag with VLAN ID `<id>`, as
    ///   tc-vlan(8) spells it; `push <id>` reads too (#817).
    /// - `modify id <id>` — overwrite the existing tag's ID.
    ///
    /// Optional modifiers:
    /// - `priority <p>` — set the VLAN PCP bits (0–7).
    /// - `protocol 802.1ad` — push/modify with QinQ (default
    ///   802.1q).
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let vlan_vid = |s: &str| -> Result<u16> {
            let id = action_parse_u32("vlan", "id", s)?;
            if id > 4095 {
                return Err(Error::invalid_message(format!(
                    "vlan: VLAN ID `{id}` out of range (0–4095)"
                )));
            }
            Ok(id as u16)
        };
        // Parse the operation first (it determines the entry-point
        // constructor that supplies vlan_id), then walk for modifiers.
        let mut op: Option<&str> = None;
        let mut vlan_id: Option<u16> = None;
        let mut priority: Option<u8> = None;
        let mut qinq = false;
        let mut verdict: Option<i32> = None;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    verdict = Some(parse_gact_verdict(v)?);
                    i += 1;
                }
                "pop" => {
                    op = Some("pop");
                    i += 1;
                }
                word @ ("push" | "modify") => {
                    op = Some(word);
                    i += 1;
                    // The id right after the operation, as nlink took it;
                    // tc-vlan(8) spells it `id <vid>`, below (#817).
                    if let Some(s) = params.get(i).filter(|s| s.parse::<u32>().is_ok()) {
                        vlan_id = Some(vlan_vid(s)?);
                        i += 1;
                    }
                }
                "id" => {
                    let s = action_need_value(params, i, "vlan", key)?;
                    vlan_id = Some(vlan_vid(s)?);
                    i += 2;
                }
                "priority" => {
                    let s = action_need_value(params, i, "vlan", key)?;
                    let p = action_parse_u32("vlan", "priority", s)?;
                    if p > 7 {
                        return Err(Error::invalid_message(format!(
                            "vlan: priority `{p}` out of range (0–7)"
                        )));
                    }
                    priority = Some(p as u8);
                    i += 2;
                }
                "protocol" => {
                    let s = action_need_value(params, i, "vlan", key)?;
                    match s {
                        "802.1q" => qinq = false,
                        "802.1ad" => qinq = true,
                        other => {
                            return Err(Error::invalid_message(format!(
                                "vlan: unknown protocol `{other}` (expected `802.1q` or `802.1ad`)"
                            )));
                        }
                    }
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "vlan: unknown token `{other}` (recognised: pop, push <id>, modify <id>, priority <p>, protocol 802.1q|802.1ad, a verdict)"
                    )));
                }
            }
        }

        let mut act = match op {
            Some("pop") => Self::pop(),
            Some("push") => {
                let id = vlan_id.expect("push always sets vlan_id");
                Self::push(id)
            }
            Some("modify") => {
                let id = vlan_id.expect("modify always sets vlan_id");
                Self::modify(id)
            }
            _ => {
                return Err(Error::invalid_message(
                    "vlan: missing operation (pop, push <id>, or modify <id>)".to_string(),
                ));
            }
        };
        if let Some(p) = priority {
            act = act.priority(p);
        }
        if qinq {
            act = act.qinq();
        }
        if let Some(v) = verdict {
            act = act.action(v);
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for VlanAction {
    fn kind(&self) -> &'static str {
        "vlan"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let op = match self.v_action {
            vlan::TCA_VLAN_ACT_POP => "pop",
            vlan::TCA_VLAN_ACT_PUSH => "push",
            vlan::TCA_VLAN_ACT_MODIFY => "modify",
            other => {
                return Err(Error::not_supported(format!(
                    "vlan: operation {other} has no token"
                )));
            }
        };
        let mut out = vec![op.to_string()];
        // A pop has no ID; push and modify take theirs as their value.
        if let Some(id) = self.vlan_id {
            if op == "pop" {
                return Err(Error::not_supported(
                    "vlan: a pop's VLAN ID has no token".to_string(),
                ));
            }
            if id > 4095 {
                return Err(Error::invalid_message(format!(
                    "vlan: VLAN ID `{id}` out of range (0–4095)"
                )));
            }
            out.push(id.to_string());
        }
        if let Some(prio) = self.vlan_prio {
            if prio > 7 {
                return Err(Error::invalid_message(format!(
                    "vlan: priority `{prio}` out of range (0–7)"
                )));
            }
            out.extend(kv("priority", prio));
        }
        match self.vlan_proto {
            vlan::ETH_P_8021Q => {}
            vlan::ETH_P_8021AD => out.extend(kv("protocol", "802.1ad")),
            other => {
                return Err(Error::not_supported(format!(
                    "vlan: protocol {other:#06x} has no token"
                )));
            }
        }
        push_verdict(&mut out, "vlan", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = vlan::TcVlan::new(self.v_action, self.action);
        builder.append_attr(vlan::TCA_VLAN_PARMS, parms.as_bytes());

        if let Some(id) = self.vlan_id {
            builder.append_attr(vlan::TCA_VLAN_PUSH_VLAN_ID, &id.to_ne_bytes());
        }

        if let Some(prio) = self.vlan_prio {
            builder.append_attr(vlan::TCA_VLAN_PUSH_VLAN_PRIORITY, &[prio]);
        }

        // A push's or modify's alone, as tc(8) sends it: a pop has none,
        // and the kernel neither reads nor reports one (#791).
        if matches!(self.v_action, vlan::TCA_VLAN_ACT_PUSH | vlan::TCA_VLAN_ACT_MODIFY) {
            builder.append_attr(
                vlan::TCA_VLAN_PUSH_VLAN_PROTOCOL,
                &self.vlan_proto.to_be_bytes(),
            );
        }

        Ok(())
    }
}

// ============================================================================
// MplsAction
// ============================================================================

/// MPLS action configuration.
///
/// Push, pop, or modify an MPLS shim header, or decrement its TTL.
///
/// ```no_run
/// use nlink::netlink::action::MplsAction;
///
/// // Push label 100 with TTL 64.
/// let a = MplsAction::push(100).ttl(64).build();
/// // Pop, revealing an IPv4 packet.
/// let p = MplsAction::pop(0x0800).build();
/// ```
#[derive(Debug, Clone)]
pub struct MplsAction {
    m_action: i32,
    label: Option<u32>,
    tc: Option<u8>,
    ttl: Option<u8>,
    bos: Option<u8>,
    proto: Option<u16>,
    action: i32,
}

impl MplsAction {
    fn with(m_action: i32) -> Self {
        Self {
            m_action,
            label: None,
            tc: None,
            ttl: None,
            bos: None,
            proto: None,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Pop the outer MPLS header, revealing a packet of `proto`
    /// (ethertype, e.g. `0x0800` for IPv4).
    pub fn pop(proto: u16) -> Self {
        let mut a = Self::with(mpls::TCA_MPLS_ACT_POP);
        a.proto = Some(proto);
        a
    }

    /// Push a new MPLS header with the given label.
    pub fn push(label: u32) -> Self {
        let mut a = Self::with(mpls::TCA_MPLS_ACT_PUSH);
        a.label = Some(label);
        a
    }

    /// Modify the outer MPLS header.
    pub fn modify() -> Self {
        Self::with(mpls::TCA_MPLS_ACT_MODIFY)
    }

    /// Decrement the outer MPLS header's TTL.
    pub fn dec_ttl() -> Self {
        Self::with(mpls::TCA_MPLS_ACT_DEC_TTL)
    }

    /// Set the MPLS label (push/modify).
    pub fn label(mut self, label: u32) -> Self {
        self.label = Some(label);
        self
    }

    /// Set the traffic-class bits (push/modify).
    pub fn tc(mut self, tc: u8) -> Self {
        self.tc = Some(tc);
        self
    }

    /// Set the TTL (push/modify).
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the bottom-of-stack bit (push/modify).
    pub fn bos(mut self, bos: u8) -> Self {
        self.bos = Some(bos);
        self
    }

    /// Set the new header's ethertype (push) or revealed protocol (pop).
    pub fn protocol(mut self, proto: u16) -> Self {
        self.proto = Some(proto);
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a `tc(8)`-style `mpls` token slice into a typed action.
    ///
    /// Operation (one required): `pop`, `push`, `modify`, `dec_ttl`.
    /// Modifiers: `label <n>`, `tc <0-7>`, `ttl <0-255>`, `bos <0|1>`,
    /// `protocol <ethertype>` (decimal, `0x`-hex, or one of `ipv4`,
    /// `ipv6`, `mpls_uc`, `mpls_mc`), and a verdict (`pass`, `drop`,
    /// `pipe`, `reclassify`, `stolen`, `continue`; `pipe` without one).
    /// Strict: unknown tokens, missing values, and unparseable values
    /// all error; `push` requires a `label`.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut op: Option<i32> = None;
        let mut label = None;
        let mut tc = None;
        let mut ttl = None;
        let mut bos = None;
        let mut proto = None;
        let mut verdict = action::TC_ACT_PIPE;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    verdict = parse_gact_verdict(v)?;
                    i += 1;
                }
                "pop" => {
                    op = Some(mpls::TCA_MPLS_ACT_POP);
                    i += 1;
                }
                "push" => {
                    op = Some(mpls::TCA_MPLS_ACT_PUSH);
                    i += 1;
                }
                "modify" => {
                    op = Some(mpls::TCA_MPLS_ACT_MODIFY);
                    i += 1;
                }
                "dec_ttl" => {
                    op = Some(mpls::TCA_MPLS_ACT_DEC_TTL);
                    i += 1;
                }
                "label" => {
                    let s = action_need_value(params, i, "mpls", key)?;
                    let v = action_parse_u32("mpls", "label", s)?;
                    if v > 0xF_FFFF {
                        return Err(Error::invalid_message(format!(
                            "mpls: label `{v}` out of range (0–1048575)"
                        )));
                    }
                    label = Some(v);
                    i += 2;
                }
                "tc" => {
                    let s = action_need_value(params, i, "mpls", key)?;
                    let v = action_parse_u32("mpls", "tc", s)?;
                    if v > 7 {
                        return Err(Error::invalid_message(format!(
                            "mpls: tc `{v}` out of range (0–7)"
                        )));
                    }
                    tc = Some(v as u8);
                    i += 2;
                }
                "ttl" => {
                    let s = action_need_value(params, i, "mpls", key)?;
                    let v = action_parse_u32("mpls", "ttl", s)?;
                    if v > 255 {
                        return Err(Error::invalid_message(format!(
                            "mpls: ttl `{v}` out of range (0–255)"
                        )));
                    }
                    ttl = Some(v as u8);
                    i += 2;
                }
                "bos" => {
                    let s = action_need_value(params, i, "mpls", key)?;
                    let v = action_parse_u32("mpls", "bos", s)?;
                    if v > 1 {
                        return Err(Error::invalid_message(format!(
                            "mpls: bos `{v}` out of range (0–1)"
                        )));
                    }
                    bos = Some(v as u8);
                    i += 2;
                }
                "protocol" => {
                    let s = action_need_value(params, i, "mpls", key)?;
                    proto = Some(parse_ethertype("mpls", s)?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "mpls: unknown token `{other}` (recognised: pop, push, modify, dec_ttl, label <n>, tc <n>, ttl <n>, bos <n>, protocol <ethertype>, a verdict)"
                    )));
                }
            }
        }

        let m_action = op.ok_or_else(|| {
            Error::invalid_message(
                "mpls: missing operation (pop, push, modify, or dec_ttl)".to_string(),
            )
        })?;
        if m_action == mpls::TCA_MPLS_ACT_PUSH && label.is_none() {
            return Err(Error::invalid_message(
                "mpls: push requires a `label`".to_string(),
            ));
        }

        Ok(Self {
            m_action,
            label,
            tc,
            ttl,
            bos,
            proto,
            action: verdict,
        })
    }
}

impl ActionConfig for MplsAction {
    fn kind(&self) -> &'static str {
        "mpls"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let op = match self.m_action {
            mpls::TCA_MPLS_ACT_POP => "pop",
            mpls::TCA_MPLS_ACT_PUSH => "push",
            mpls::TCA_MPLS_ACT_MODIFY => "modify",
            mpls::TCA_MPLS_ACT_DEC_TTL => "dec_ttl",
            other => {
                return Err(Error::not_supported(format!(
                    "mpls: operation {other} has no token"
                )));
            }
        };
        // The ranges `parse_params` reads; the setters take wider types.
        let in_range = |field: &str, value: u32, max: u32| {
            if value > max {
                return Err(Error::invalid_message(format!(
                    "mpls: {field} `{value}` out of range (0–{max})"
                )));
            }
            Ok(kv(field, value))
        };
        let mut out = vec![op.to_string()];
        if let Some(label) = self.label {
            out.extend(in_range("label", label, 0xF_FFFF)?);
        }
        if let Some(tc) = self.tc {
            out.extend(in_range("tc", tc.into(), 7)?);
        }
        if let Some(ttl) = self.ttl {
            out.extend(kv("ttl", ttl));
        }
        if let Some(bos) = self.bos {
            out.extend(in_range("bos", bos.into(), 1)?);
        }
        if let Some(proto) = self.proto {
            out.extend(kv("protocol", crate::EthProto::new(proto)));
        }
        push_verdict(&mut out, "mpls", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = mpls::TcMpls::new(self.m_action, self.action);
        builder.append_attr(mpls::TCA_MPLS_PARMS, parms.as_bytes());

        if let Some(proto) = self.proto {
            builder.append_attr(mpls::TCA_MPLS_PROTO, &proto.to_be_bytes());
        }
        if let Some(label) = self.label {
            builder.append_attr_u32(mpls::TCA_MPLS_LABEL, label);
        }
        if let Some(tc) = self.tc {
            builder.append_attr(mpls::TCA_MPLS_TC, &[tc]);
        }
        if let Some(ttl) = self.ttl {
            builder.append_attr(mpls::TCA_MPLS_TTL, &[ttl]);
        }
        if let Some(bos) = self.bos {
            builder.append_attr(mpls::TCA_MPLS_BOS, &[bos]);
        }
        Ok(())
    }
}

// ============================================================================
// SkbmodAction
// ============================================================================

/// skbmod action configuration.
///
/// Rewrite a packet's L2 source/destination MAC and/or ethertype, or
/// swap source and destination MAC.
///
/// ```no_run
/// use nlink::netlink::action::SkbmodAction;
///
/// let a = SkbmodAction::new()
///     .set_dmac([0x02, 0, 0, 0, 0, 1])
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SkbmodAction {
    dmac: Option<[u8; 6]>,
    smac: Option<[u8; 6]>,
    etype: Option<u16>,
    swap_mac: bool,
    action: i32,
}

impl SkbmodAction {
    /// Create a new skbmod action.
    pub fn new() -> Self {
        Self {
            action: action::TC_ACT_PIPE,
            ..Default::default()
        }
    }

    /// Set the destination MAC.
    pub fn set_dmac(mut self, dmac: [u8; 6]) -> Self {
        self.dmac = Some(dmac);
        self
    }

    /// Set the source MAC.
    pub fn set_smac(mut self, smac: [u8; 6]) -> Self {
        self.smac = Some(smac);
        self
    }

    /// Set the ethertype.
    pub fn set_etype(mut self, etype: u16) -> Self {
        self.etype = Some(etype);
        self
    }

    /// Swap source and destination MAC.
    pub fn swap_mac(mut self) -> Self {
        self.swap_mac = true;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a `tc(8)`-style `skbmod` token slice into a typed action.
    ///
    /// Recognised tokens: `set smac <MAC>`, `set dmac <MAC>`,
    /// `set etype <ethertype>`, `swap mac`, and a verdict (`pass`,
    /// `drop`, `pipe`, `reclassify`, `stolen`, `continue`; `pipe` without
    /// one). At least one operation is required. Strict: unknown tokens,
    /// missing values, and unparseable values all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut a = Self::new();
        let mut any = false;
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    a.action = parse_gact_verdict(v)?;
                    i += 1;
                }
                "set" => {
                    let what = action_need_value(params, i, "skbmod", "set")?;
                    let val = params.get(i + 2).copied().ok_or_else(|| {
                        Error::invalid_message(format!("skbmod: `set {what}` requires a value"))
                    })?;
                    match what {
                        "smac" => {
                            a.smac = Some(crate::util::addr::parse_mac(val).map_err(|_| {
                                Error::invalid_message(format!("skbmod: invalid smac `{val}`"))
                            })?);
                        }
                        "dmac" => {
                            a.dmac = Some(crate::util::addr::parse_mac(val).map_err(|_| {
                                Error::invalid_message(format!("skbmod: invalid dmac `{val}`"))
                            })?);
                        }
                        "etype" => {
                            a.etype = Some(parse_ethertype("skbmod", val)?);
                        }
                        other => {
                            return Err(Error::invalid_message(format!(
                                "skbmod: unknown `set` target `{other}` (expected smac, dmac, etype)"
                            )));
                        }
                    }
                    any = true;
                    i += 3;
                }
                "swap" => {
                    let what = action_need_value(params, i, "skbmod", "swap")?;
                    if what != "mac" {
                        return Err(Error::invalid_message(format!(
                            "skbmod: unknown `swap` target `{what}` (expected mac)"
                        )));
                    }
                    a.swap_mac = true;
                    any = true;
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "skbmod: unknown token `{other}` (recognised: set smac|dmac|etype <v>, swap mac, a verdict)"
                    )));
                }
            }
        }
        if !any {
            return Err(Error::invalid_message(
                "skbmod: at least one operation required (set smac|dmac|etype, swap mac)"
                    .to_string(),
            ));
        }
        Ok(a)
    }
}

impl ActionConfig for SkbmodAction {
    fn kind(&self) -> &'static str {
        "skbmod"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        use crate::util::addr::format_mac;
        let mut out = Vec::new();
        if let Some(mac) = self.dmac {
            out.extend(["set".to_string(), "dmac".to_string(), format_mac(&mac)]);
        }
        if let Some(mac) = self.smac {
            out.extend(["set".to_string(), "smac".to_string(), format_mac(&mac)]);
        }
        if let Some(etype) = self.etype {
            out.extend([
                "set".to_string(),
                "etype".to_string(),
                crate::EthProto::new(etype).to_string(),
            ]);
        }
        if self.swap_mac {
            out.extend(kv("swap", "mac"));
        }
        if out.is_empty() {
            return Err(Error::invalid_message(
                "skbmod: at least one operation required (set smac|dmac|etype, swap mac)"
                    .to_string(),
            ));
        }
        push_verdict(&mut out, "skbmod", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let mut flags = 0u64;
        if self.dmac.is_some() {
            flags |= skbmod::SKBMOD_F_DMAC;
        }
        if self.smac.is_some() {
            flags |= skbmod::SKBMOD_F_SMAC;
        }
        if self.etype.is_some() {
            flags |= skbmod::SKBMOD_F_ETYPE;
        }
        if self.swap_mac {
            flags |= skbmod::SKBMOD_F_SWAPMAC;
        }

        let parms = skbmod::TcSkbmod::new(flags, self.action);
        builder.append_attr(skbmod::TCA_SKBMOD_PARMS, parms.as_bytes());

        if let Some(dmac) = self.dmac {
            builder.append_attr(skbmod::TCA_SKBMOD_DMAC, &dmac);
        }
        if let Some(smac) = self.smac {
            builder.append_attr(skbmod::TCA_SKBMOD_SMAC, &smac);
        }
        // Host order: `tcf_skbmod_init()` reads `nla_get_u16()` and
        // converts it itself (#816).
        if let Some(etype) = self.etype {
            builder.append_attr(skbmod::TCA_SKBMOD_ETYPE, &etype.to_ne_bytes());
        }
        Ok(())
    }
}

// ============================================================================
// SkbeditAction
// ============================================================================

/// Skbedit action configuration.
///
/// The skbedit action modifies SKB (socket buffer) metadata.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::SkbeditAction;
///
/// // Set priority
/// let prio = SkbeditAction::new().priority(7).build();
///
/// // Set mark
/// let mark = SkbeditAction::new().mark(100).build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SkbeditAction {
    /// Queue mapping.
    queue_mapping: Option<u16>,
    /// Priority.
    priority: Option<u32>,
    /// Mark.
    mark: Option<u32>,
    /// Mark mask.
    mark_mask: Option<u32>,
    /// The packet type (`TCA_SKBEDIT_PTYPE`, a `PACKET_*`), #817.
    ptype: Option<u16>,
    /// Take the skb priority from the DS field (`inheritdsfield`), #817.
    inherit_dsfield: bool,
    /// Action result.
    action: i32,
}

/// Skbedit action attributes.
mod skbedit {
    pub const TCA_SKBEDIT_PARMS: u16 = 2;
    pub const TCA_SKBEDIT_PRIORITY: u16 = 3;
    pub const TCA_SKBEDIT_QUEUE_MAPPING: u16 = 4;
    pub const TCA_SKBEDIT_MARK: u16 = 5;
    pub const TCA_SKBEDIT_PTYPE: u16 = 7;
    pub const TCA_SKBEDIT_MASK: u16 = 8;
    pub const TCA_SKBEDIT_FLAGS: u16 = 9;
    pub const SKBEDIT_F_INHERITDSFIELD: u64 = 0x20;
}

/// tc(8)'s names for the packet types skbedit sets (`PACKET_*`), #817.
const SKBEDIT_PTYPES: [(&str, u16); 4] = [("host", 0), ("broadcast", 1), ("multicast", 2), ("otherhost", 3)];

/// A class id as tc(8)'s `get_tc_classid()` reads it (#817): `root`,
/// `none`, a hex major, or `major:minor` in hex. skbedit's `priority`
/// is one.
fn tc_classid(kind: &str, key: &str, s: &str) -> Result<u32> {
    let hex = |v: &str| u32::from_str_radix(v.trim_start_matches("0x"), 16);
    let id = match s {
        "root" => Ok(u32::MAX),
        "none" => Ok(0),
        _ => match s.split_once(':') {
            Some((maj, min)) => (|| {
                let maj = if maj.is_empty() { 0 } else { hex(maj)? };
                let min = if min.is_empty() { 0 } else { hex(min)? };
                Ok::<u32, std::num::ParseIntError>(maj << 16 | (min & 0xFFFF))
            })(),
            None => hex(s),
        },
    };
    id.map_err(|_| {
        Error::invalid_message(format!(
            "{kind}: invalid {key} `{s}` (expected a class id: hex, or major:minor in hex)"
        ))
    })
}

impl SkbeditAction {
    /// Create a new skbedit action builder.
    pub fn new() -> Self {
        Self {
            action: action::TC_ACT_PIPE,
            ..Default::default()
        }
    }

    /// Set the queue mapping.
    pub fn queue_mapping(mut self, queue: u16) -> Self {
        self.queue_mapping = Some(queue);
        self
    }

    /// Set the priority.
    pub fn priority(mut self, prio: u32) -> Self {
        self.priority = Some(prio);
        self
    }

    /// Set the mark.
    pub fn mark(mut self, mark: u32) -> Self {
        self.mark = Some(mark);
        self
    }

    /// Set the mark with mask.
    pub fn mark_with_mask(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some(mark);
        self.mark_mask = Some(mask);
        self
    }

    /// Set the packet type, a `PACKET_*`: 0 host, 1 broadcast, 2 multicast,
    /// 3 other host (#817).
    pub fn ptype(mut self, ptype: u16) -> Self {
        self.ptype = Some(ptype);
        self
    }

    /// Take the skb priority from the packet's DS field (#817).
    pub fn inherit_dsfield(mut self) -> Self {
        self.inherit_dsfield = true;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `skbedit` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens (any order)
    ///
    /// - `priority <classid>` — set the skb priority, a class id as tc(8)
    ///   reads it: hex, or `major:minor` in hex (#817).
    /// - `mark <u32>[/<mask>]` — set the skb mark.
    /// - `mask <u32>` — combine with `mark` for masked update.
    /// - `queue_mapping <u16>` — set the queue mapping index.
    /// - `ptype host|otherhost|broadcast|multicast`, `inheritdsfield`
    ///   (#817).
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut act = Self::new();
        let mut mark: Option<u32> = None;
        let mut mask: Option<u32> = None;
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    act = act.action(parse_gact_verdict(v)?);
                    i += 1;
                }
                "priority" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    act = act.priority(tc_classid("skbedit", "priority", s)?);
                    i += 2;
                }
                "mark" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    let (m, mk) = match s.split_once('/') {
                        Some((m, mk)) => (m, Some(mk)),
                        None => (s, None),
                    };
                    mark = Some(action_parse_u32_any("skbedit", "mark", m)?);
                    if let Some(mk) = mk {
                        mask = Some(action_parse_u32_any("skbedit", "mask", mk)?);
                    }
                    i += 2;
                }
                "ptype" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    let ptype = SKBEDIT_PTYPES.iter().find(|(name, _)| *name == s).map(|(_, v)| *v).ok_or_else(|| {
                        Error::invalid_message(format!(
                            "skbedit: invalid ptype `{s}` (expected host, otherhost, broadcast or multicast)"
                        ))
                    })?;
                    act = act.ptype(ptype);
                    i += 2;
                }
                "inheritdsfield" => {
                    act = act.inherit_dsfield();
                    i += 1;
                }
                "mask" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    mask = Some(action_parse_u32_any("skbedit", "mask", s)?);
                    i += 2;
                }
                "queue_mapping" => {
                    let s = action_need_value(params, i, "skbedit", key)?;
                    let q = action_parse_u32("skbedit", "queue_mapping", s)?;
                    if q > u16::MAX as u32 {
                        return Err(Error::invalid_message(format!(
                            "skbedit: queue_mapping `{q}` out of range (0–65535)"
                        )));
                    }
                    act = act.queue_mapping(q as u16);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "skbedit: unknown token `{other}` (recognised: priority, mark, mask, queue_mapping, ptype, inheritdsfield, a verdict)"
                    )));
                }
            }
        }
        // Apply mark / mask combination at the end so order doesn't
        // matter at the caller.
        match (mark, mask) {
            (Some(m), Some(mk)) => act = act.mark_with_mask(m, mk),
            (Some(m), None) => act = act.mark(m),
            (None, Some(_)) => {
                return Err(Error::invalid_message(
                    "skbedit: `mask` requires a `mark` value".to_string(),
                ));
            }
            (None, None) => {}
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for SkbeditAction {
    fn kind(&self) -> &'static str {
        "skbedit"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        // A class id, as `parse_params` reads it (#817).
        if let Some(prio) = self.priority {
            out.extend(kv("priority", format!("{:x}:{:x}", prio >> 16, prio & 0xFFFF)));
        }
        match (self.mark, self.mark_mask) {
            // tc(8)'s `MARK[/MASK]`: it has no `mask` keyword (#817).
            (Some(mark), None) => out.extend(kv("mark", mark)),
            (Some(mark), Some(mask)) => out.extend(kv("mark", format!("{mark}/{mask:#x}"))),
            (None, None) => {}
            (None, Some(_)) => {
                return Err(Error::not_supported(
                    "skbedit: a mask without a mark has no token".to_string(),
                ));
            }
        }
        if let Some(queue) = self.queue_mapping {
            out.extend(kv("queue_mapping", queue));
        }
        if let Some(ptype) = self.ptype {
            let name = SKBEDIT_PTYPES.iter().find(|(_, v)| *v == ptype).map(|(n, _)| *n).ok_or_else(|| {
                Error::not_supported(format!("skbedit: ptype {ptype} has no token"))
            })?;
            out.extend(kv("ptype", name));
        }
        if self.inherit_dsfield {
            out.push("inheritdsfield".to_string());
        }
        push_verdict(&mut out, "skbedit", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = TcGen::new(self.action);
        builder.append_attr(skbedit::TCA_SKBEDIT_PARMS, parms.as_bytes());

        if let Some(queue) = self.queue_mapping {
            builder.append_attr(skbedit::TCA_SKBEDIT_QUEUE_MAPPING, &queue.to_ne_bytes());
        }

        if let Some(prio) = self.priority {
            builder.append_attr(skbedit::TCA_SKBEDIT_PRIORITY, &prio.to_ne_bytes());
        }

        if let Some(mark) = self.mark {
            builder.append_attr(skbedit::TCA_SKBEDIT_MARK, &mark.to_ne_bytes());
        }

        if let Some(mask) = self.mark_mask {
            builder.append_attr(skbedit::TCA_SKBEDIT_MASK, &mask.to_ne_bytes());
        }

        if let Some(ptype) = self.ptype {
            builder.append_attr(skbedit::TCA_SKBEDIT_PTYPE, &ptype.to_ne_bytes());
        }

        if self.inherit_dsfield {
            builder.append_attr(skbedit::TCA_SKBEDIT_FLAGS, &skbedit::SKBEDIT_F_INHERITDSFIELD.to_ne_bytes());
        }

        Ok(())
    }
}

// ============================================================================
// NatAction
// ============================================================================

/// NAT action configuration.
///
/// The NAT action performs stateless network address translation.
/// It can translate source (egress) or destination (ingress) addresses.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::NatAction;
/// use std::net::Ipv4Addr;
///
/// // Source NAT: translate 10.0.0.0/8 to 192.168.1.1
/// let snat = NatAction::snat(
///     Ipv4Addr::new(10, 0, 0, 0),
///     Ipv4Addr::new(192, 168, 1, 1),
/// ).prefix(8);
///
/// // Destination NAT: translate 192.168.1.1 to 10.0.0.1
/// let dnat = NatAction::dnat(
///     Ipv4Addr::new(192, 168, 1, 1),
///     Ipv4Addr::new(10, 0, 0, 1),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct NatAction {
    /// Original address to match.
    old_addr: Ipv4Addr,
    /// New address to translate to.
    new_addr: Ipv4Addr,
    /// Network prefix length (0-32).
    prefix_len: u8,
    /// True for source NAT (egress), false for destination NAT (ingress).
    egress: bool,
    /// Action result after NAT.
    action: i32,
}

impl NatAction {
    /// Create a source NAT (SNAT) action.
    ///
    /// Source NAT translates the source address of packets on egress.
    pub fn snat(old_addr: Ipv4Addr, new_addr: Ipv4Addr) -> Self {
        Self {
            old_addr,
            new_addr,
            prefix_len: 32,
            egress: true,
            action: action::TC_ACT_OK,
        }
    }

    /// Create a destination NAT (DNAT) action.
    ///
    /// Destination NAT translates the destination address of packets on ingress.
    pub fn dnat(old_addr: Ipv4Addr, new_addr: Ipv4Addr) -> Self {
        Self {
            old_addr,
            new_addr,
            prefix_len: 32,
            egress: false,
            action: action::TC_ACT_OK,
        }
    }

    /// Set the prefix length for network-based NAT.
    ///
    /// This allows translating a range of addresses.
    pub fn prefix(mut self, prefix_len: u8) -> Self {
        self.prefix_len = prefix_len.min(32);
        self
    }

    /// Set the action result after NAT (default: pass).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Pipe to next action after NAT.
    pub fn pipe(mut self) -> Self {
        self.action = action::TC_ACT_PIPE;
        self
    }

    /// Parse a `tc(8)`-style `nat` token slice into a typed action.
    ///
    /// # Recognised tokens (positional, mirrors `tc(8)`)
    ///
    /// `<ingress|egress> <oldaddr[/prefix]> <newaddr> [<verdict>]`
    ///
    /// - `ingress` → DNAT (matches incoming destination, rewrites
    ///   to the new address).
    /// - `egress` → SNAT (matches outgoing source, rewrites to the
    ///   new address).
    /// - Old address may carry a prefix (`10.0.0.0/24`) for
    ///   network-based NAT; bare addresses default to /32.
    /// - An optional verdict (`pass`, `drop`, `pipe`, `reclassify`,
    ///   `stolen`, `continue`); `pass` without one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        if params.len() < 3 {
            return Err(Error::invalid_message(
                "nat: requires `ingress|egress <oldaddr[/prefix]> <newaddr>`".to_string(),
            ));
        }
        let direction = params[0];
        let old_with_prefix = params[1];
        let new_addr_s = params[2];
        let verdict = match params.get(3).copied() {
            Some(v) if is_verdict(v) && params.len() == 4 => Some(parse_gact_verdict(v)?),
            None => None,
            Some(v) => {
                // The token that is not a verdict, or the one after it.
                let extra = if is_verdict(v) { params[4] } else { v };
                return Err(Error::invalid_message(format!(
                    "nat: unexpected token `{extra}` after `{direction} {old_with_prefix} \
                     {new_addr_s}` (only the 3 positional args and a verdict are supported)"
                )));
            }
        };

        let (old_addr_s, prefix) = match old_with_prefix.split_once('/') {
            Some((a, p)) => {
                let pl: u8 = p.parse().map_err(|_| {
                    Error::invalid_message(format!(
                        "nat: invalid old-address prefix `{p}` (expected 0–32)"
                    ))
                })?;
                if pl > 32 {
                    return Err(Error::invalid_message(format!(
                        "nat: prefix `{pl}` out of range (0–32)"
                    )));
                }
                (a, pl)
            }
            None => (old_with_prefix, 32),
        };
        let old_addr: Ipv4Addr = old_addr_s.parse().map_err(|_| {
            Error::invalid_message(format!("nat: invalid old address `{old_addr_s}`"))
        })?;
        let new_addr: Ipv4Addr = new_addr_s.parse().map_err(|_| {
            Error::invalid_message(format!("nat: invalid new address `{new_addr_s}`"))
        })?;

        let mut act = match direction {
            "egress" => Self::snat(old_addr, new_addr),
            "ingress" => Self::dnat(old_addr, new_addr),
            other => {
                return Err(Error::invalid_message(format!(
                    "nat: direction `{other}` (expected `ingress` or `egress`)"
                )));
            }
        };
        if prefix != 32 {
            act = act.prefix(prefix);
        }
        if let Some(v) = verdict {
            act = act.action(v);
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Convert prefix length to network mask.
    fn prefix_to_mask(prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else if prefix_len >= 32 {
            0xFFFFFFFF
        } else {
            !((1u32 << (32 - prefix_len)) - 1)
        }
    }
}

impl ActionConfig for NatAction {
    fn kind(&self) -> &'static str {
        "nat"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let old = match self.prefix_len {
            32 => self.old_addr.to_string(),
            prefix => format!("{}/{prefix}", self.old_addr),
        };
        let direction = if self.egress { "egress" } else { "ingress" };
        let mut out = vec![direction.to_string(), old, self.new_addr.to_string()];
        push_verdict(&mut out, "nat", self.action, action::TC_ACT_OK)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let mask = Self::prefix_to_mask(self.prefix_len);
        let flags = if self.egress {
            nat::TCA_NAT_FLAG_EGRESS
        } else {
            0
        };

        // `struct tc_nat`'s old_addr/new_addr/mask are `__be32`, and the
        // struct is serialized natively — so each field must hold the value
        // whose *memory image* is network order.
        //
        // For the addresses that is `from_ne_bytes(octets())`: octets() is
        // already network order, so reading them natively stores them
        // unchanged. `from_be_bytes` (what this used to do) byte-reverses them
        // on every little-endian host.
        //
        // The mask arrives as a host-order integer from `prefix_to_mask`, so it
        // needs an explicit swap. The old code wrote
        // `u32::from_be_bytes(mask.to_be_bytes())`, which is the identity — a
        // /24 reached the kernel as 0.255.255.255 (#262).
        let parms = nat::TcNat::new(
            u32::from_ne_bytes(self.old_addr.octets()),
            u32::from_ne_bytes(self.new_addr.octets()),
            mask.to_be(),
            flags,
            self.action,
        );

        builder.append_attr(nat::TCA_NAT_PARMS, parms.as_bytes());
        Ok(())
    }
}

// ============================================================================
// TunnelKeyAction
// ============================================================================

/// Tunnel key action configuration.
///
/// The tunnel_key action is used to set or release tunnel metadata
/// for hardware offload of tunnel encapsulation/decapsulation.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::TunnelKeyAction;
/// use std::net::Ipv4Addr;
///
/// // Set tunnel metadata for encapsulation
/// let set = TunnelKeyAction::set()
///     .src(Ipv4Addr::new(192, 168, 1, 1))
///     .dst(Ipv4Addr::new(192, 168, 1, 2))
///     .key_id(100)
///     .dst_port(4789)
///     .build();
///
/// // Release tunnel metadata
/// let release = TunnelKeyAction::release();
/// ```
#[derive(Debug, Clone)]
pub struct TunnelKeyAction {
    /// Action type: set or release.
    t_action: i32,
    /// Source IPv4 address.
    src_ipv4: Option<Ipv4Addr>,
    /// Destination IPv4 address.
    dst_ipv4: Option<Ipv4Addr>,
    /// Source IPv6 address.
    src_ipv6: Option<std::net::Ipv6Addr>,
    /// Destination IPv6 address.
    dst_ipv6: Option<std::net::Ipv6Addr>,
    /// Tunnel key ID (VNI for VXLAN, etc.).
    key_id: Option<u32>,
    /// UDP destination port.
    dst_port: Option<u16>,
    /// TOS/DSCP value.
    tos: Option<u8>,
    /// TTL value.
    ttl: Option<u8>,
    /// Disable checksum.
    no_csum: bool,
    /// Disable fragmentation.
    no_frag: bool,
    /// Action result.
    action: i32,
}

impl TunnelKeyAction {
    /// Create a tunnel key set action.
    ///
    /// This action sets tunnel metadata on packets for encapsulation.
    pub fn set() -> Self {
        Self {
            t_action: tunnel_key::TCA_TUNNEL_KEY_ACT_SET,
            src_ipv4: None,
            dst_ipv4: None,
            src_ipv6: None,
            dst_ipv6: None,
            key_id: None,
            dst_port: None,
            tos: None,
            ttl: None,
            no_csum: false,
            no_frag: false,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a tunnel key release action.
    ///
    /// This action removes tunnel metadata from packets after decapsulation.
    pub fn release() -> Self {
        Self {
            t_action: tunnel_key::TCA_TUNNEL_KEY_ACT_RELEASE,
            src_ipv4: None,
            dst_ipv4: None,
            src_ipv6: None,
            dst_ipv6: None,
            key_id: None,
            dst_port: None,
            tos: None,
            ttl: None,
            no_csum: false,
            no_frag: false,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set source IPv4 address.
    pub fn src(mut self, addr: Ipv4Addr) -> Self {
        self.src_ipv4 = Some(addr);
        self.src_ipv6 = None;
        self
    }

    /// Set destination IPv4 address.
    pub fn dst(mut self, addr: Ipv4Addr) -> Self {
        self.dst_ipv4 = Some(addr);
        self.dst_ipv6 = None;
        self
    }

    /// Set source IPv6 address.
    pub fn src6(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.src_ipv6 = Some(addr);
        self.src_ipv4 = None;
        self
    }

    /// Set destination IPv6 address.
    pub fn dst6(mut self, addr: std::net::Ipv6Addr) -> Self {
        self.dst_ipv6 = Some(addr);
        self.dst_ipv4 = None;
        self
    }

    /// Set tunnel key ID (e.g., VNI for VXLAN).
    pub fn key_id(mut self, id: u32) -> Self {
        self.key_id = Some(id);
        self
    }

    /// Set UDP destination port.
    pub fn dst_port(mut self, port: u16) -> Self {
        self.dst_port = Some(port);
        self
    }

    /// Set TOS/DSCP value.
    pub fn tos(mut self, tos: u8) -> Self {
        self.tos = Some(tos);
        self
    }

    /// Set TTL value.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Disable UDP checksum.
    pub fn no_csum(mut self) -> Self {
        self.no_csum = true;
        self
    }

    /// Disable fragmentation (set DF bit).
    pub fn no_frag(mut self) -> Self {
        self.no_frag = true;
        self
    }

    /// Set action result (default: pipe).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `tunnel_key` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// Operation (required):
    /// - `set` — set tunnel metadata (encap path).
    /// - `release` — strip tunnel metadata (decap path).
    ///
    /// Set-only modifiers (rejected with `release`):
    /// - `src_ip <addr>` / `dst_ip <addr>` — the outer addresses, either
    ///   family, as tc-tunnel_key(8) spells them (#811).
    /// - `src <ipv4>` / `dst <ipv4>` — IPv4 outer addresses.
    /// - `src6 <ipv6>` / `dst6 <ipv6>` — IPv6 outer addresses.
    /// - `id <vni>` — tunnel key (VNI for VXLAN, etc.).
    /// - `dst_port <port>` — UDP destination port.
    /// - `tos <0–255>` / `ttl <0–255>` — outer IP TOS / TTL.
    /// - `no_csum` — disable UDP checksum (flag, no value).
    /// - `no_frag` — disable fragmentation (flag, no value).
    ///
    /// Either operation takes a verdict (`pass`, `drop`, `pipe`,
    /// `reclassify`, `stolen`, `continue`); `pipe` without one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        // Determine operation first (set vs release).
        let mut op: Option<&str> = None;
        for &t in params {
            // tc-tunnel_key(8) says `unset` for `release` (#817).
            if matches!(t, "set" | "release" | "unset") {
                if op.is_some() {
                    return Err(Error::invalid_message(
                        "tunnel_key: only one of `set` / `release` may be specified".to_string(),
                    ));
                }
                op = Some(t);
            }
        }
        let mut act = match op {
            Some("set") => Self::set(),
            Some("release" | "unset") => Self::release(),
            _ => {
                return Err(Error::invalid_message(
                    "tunnel_key: missing operation (`set` or `release`)".to_string(),
                ));
            }
        };
        let is_set = matches!(op, Some("set"));

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "set" | "release" | "unset" => i += 1,
                v if is_verdict(v) => {
                    act = act.action(parse_gact_verdict(v)?);
                    i += 1;
                }
                // tc's default, said: the UDP checksum on (#817).
                "csum" if is_set => i += 1,
                // tc-tunnel_key(8)'s own words, for either family (#811).
                "src_ip" | "dst_ip" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let addr: IpAddr = s.parse().map_err(|_| {
                        Error::invalid_message(format!("tunnel_key: invalid {key} `{s}`"))
                    })?;
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = match (key, addr) {
                        ("src_ip", IpAddr::V4(a)) => act.src(a),
                        ("src_ip", IpAddr::V6(a)) => act.src6(a),
                        (_, IpAddr::V4(a)) => act.dst(a),
                        (_, IpAddr::V6(a)) => act.dst6(a),
                    };
                    i += 2;
                }
                "src" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let addr: Ipv4Addr = s.parse().map_err(|_| {
                        Error::invalid_message(format!("tunnel_key: invalid src `{s}`"))
                    })?;
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.src(addr);
                    i += 2;
                }
                "dst" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let addr: Ipv4Addr = s.parse().map_err(|_| {
                        Error::invalid_message(format!("tunnel_key: invalid dst `{s}`"))
                    })?;
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.dst(addr);
                    i += 2;
                }
                "src6" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let addr: std::net::Ipv6Addr = s.parse().map_err(|_| {
                        Error::invalid_message(format!("tunnel_key: invalid src6 `{s}`"))
                    })?;
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.src6(addr);
                    i += 2;
                }
                "dst6" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let addr: std::net::Ipv6Addr = s.parse().map_err(|_| {
                        Error::invalid_message(format!("tunnel_key: invalid dst6 `{s}`"))
                    })?;
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.dst6(addr);
                    i += 2;
                }
                "id" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let id = action_parse_u32("tunnel_key", "id", s)?;
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.key_id(id);
                    i += 2;
                }
                "dst_port" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let port = action_parse_u32("tunnel_key", "dst_port", s)?;
                    if port > u16::MAX as u32 {
                        return Err(Error::invalid_message(format!(
                            "tunnel_key: dst_port `{port}` out of range (0–65535)"
                        )));
                    }
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.dst_port(port as u16);
                    i += 2;
                }
                "tos" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let v = action_parse_u32("tunnel_key", "tos", s)?;
                    if v > u8::MAX as u32 {
                        return Err(Error::invalid_message(format!(
                            "tunnel_key: tos `{v}` out of range (0–255)"
                        )));
                    }
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.tos(v as u8);
                    i += 2;
                }
                "ttl" => {
                    let s = action_need_value(params, i, "tunnel_key", key)?;
                    let v = action_parse_u32("tunnel_key", "ttl", s)?;
                    if v > u8::MAX as u32 {
                        return Err(Error::invalid_message(format!(
                            "tunnel_key: ttl `{v}` out of range (0–255)"
                        )));
                    }
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: src/dst/id/etc. only valid with `set`".to_string(),
                        ));
                    }
                    act = act.ttl(v as u8);
                    i += 2;
                }
                // `nocsum` and `nofrag` are tc's spelling (#817).
                "no_csum" | "nocsum" => {
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: no_csum only valid with `set`".to_string(),
                        ));
                    }
                    act = act.no_csum();
                    i += 1;
                }
                "no_frag" | "nofrag" => {
                    if !is_set {
                        return Err(Error::invalid_message(
                            "tunnel_key: no_frag only valid with `set`".to_string(),
                        ));
                    }
                    act = act.no_frag();
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "tunnel_key: unknown token `{other}` (recognised: set/release, src/dst[6] <addr>, id <vni>, dst_port <port>, tos/ttl <0-255>, no_csum, no_frag, a verdict)"
                    )));
                }
            }
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for TunnelKeyAction {
    fn kind(&self) -> &'static str {
        "tunnel_key"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let op = match self.t_action {
            tunnel_key::TCA_TUNNEL_KEY_ACT_SET => "set",
            tunnel_key::TCA_TUNNEL_KEY_ACT_RELEASE => "release",
            other => {
                return Err(Error::not_supported(format!(
                    "tunnel_key: operation {other} has no token"
                )));
            }
        };
        let mut fields = Vec::new();
        if let Some(addr) = self.src_ipv4 {
            fields.extend(kv("src", addr));
        }
        if let Some(addr) = self.src_ipv6 {
            fields.extend(kv("src6", addr));
        }
        if let Some(addr) = self.dst_ipv4 {
            fields.extend(kv("dst", addr));
        }
        if let Some(addr) = self.dst_ipv6 {
            fields.extend(kv("dst6", addr));
        }
        if let Some(id) = self.key_id {
            fields.extend(kv("id", id));
        }
        if let Some(port) = self.dst_port {
            fields.extend(kv("dst_port", port));
        }
        if let Some(tos) = self.tos {
            fields.extend(kv("tos", tos));
        }
        if let Some(ttl) = self.ttl {
            fields.extend(kv("ttl", ttl));
        }
        if self.no_csum {
            fields.push("no_csum".to_string());
        }
        if self.no_frag {
            fields.push("no_frag".to_string());
        }
        // A release sends none of them, and its grammar refuses them.
        if let (Some(field), "release") = (fields.first(), op) {
            return Err(Error::invalid_message(format!(
                "tunnel_key: `{field}` is only valid with `set`"
            )));
        }
        let mut out = vec![op.to_string()];
        out.extend(fields);
        push_verdict(&mut out, "tunnel_key", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = tunnel_key::TcTunnelKey::new(self.t_action, self.action);
        builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_PARMS, parms.as_bytes());

        // Only add metadata for "set" action
        if self.t_action == tunnel_key::TCA_TUNNEL_KEY_ACT_SET {
            // IPv4 addresses
            if let Some(addr) = self.src_ipv4 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV4_SRC, &addr.octets());
            }
            if let Some(addr) = self.dst_ipv4 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV4_DST, &addr.octets());
            }

            // IPv6 addresses
            if let Some(addr) = self.src_ipv6 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV6_SRC, &addr.octets());
            }
            if let Some(addr) = self.dst_ipv6 {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_IPV6_DST, &addr.octets());
            }

            // Key ID: a `__be32`. The header's comment says be64, but
            // `tunnel_key_init()` reads it with `nla_get_be32()`, so the 8
            // bytes this used to send installed key id 0 (#811).
            if let Some(id) = self.key_id {
                builder.append_attr(tunnel_key::TCA_TUNNEL_KEY_ENC_KEY_ID, &id.to_be_bytes());
            }

            // Destination port (network byte order)
            if let Some(port) = self.dst_port {
                builder.append_attr_u16_be(tunnel_key::TCA_TUNNEL_KEY_ENC_DST_PORT, port);
            }

            // TOS
            if let Some(tos) = self.tos {
                builder.append_attr_u8(tunnel_key::TCA_TUNNEL_KEY_ENC_TOS, tos);
            }

            // TTL
            if let Some(ttl) = self.ttl {
                builder.append_attr_u8(tunnel_key::TCA_TUNNEL_KEY_ENC_TTL, ttl);
            }

            // No checksum flag (inverted: no_csum=true means checksum disabled)
            builder.append_attr_u8(
                tunnel_key::TCA_TUNNEL_KEY_NO_CSUM,
                if self.no_csum { 1 } else { 0 },
            );

            // No fragmentation flag
            if self.no_frag {
                builder.append_attr_empty(tunnel_key::TCA_TUNNEL_KEY_NO_FRAG);
            }
        }

        Ok(())
    }
}

// ============================================================================
// ConnmarkAction
// ============================================================================

/// Connmark action configuration.
///
/// The connmark action imports the connection tracking mark into the packet's
/// skb mark field, allowing it to be used for classification or other actions.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::ConnmarkAction;
///
/// // Import connmark from default zone
/// let mark = ConnmarkAction::new();
///
/// // Import connmark from specific zone
/// let mark = ConnmarkAction::with_zone(1);
/// ```
#[derive(Debug, Clone)]
pub struct ConnmarkAction {
    /// Conntrack zone (0 = default).
    zone: u16,
    /// Action result (TC_ACT_PIPE by default).
    action: i32,
}

impl ConnmarkAction {
    /// Create a new connmark action for the default zone.
    pub fn new() -> Self {
        Self {
            zone: 0,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a connmark action for a specific zone.
    pub fn with_zone(zone: u16) -> Self {
        Self {
            zone,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set the conntrack zone.
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = zone;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `connmark` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// - `zone <u16>` — conntrack zone (default 0).
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut act = Self::new();
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    act = act.action(parse_gact_verdict(v)?);
                    i += 1;
                }
                "zone" => {
                    let s = action_need_value(params, i, "connmark", key)?;
                    let z = action_parse_u32("connmark", "zone", s)?;
                    if z > u16::MAX as u32 {
                        return Err(Error::invalid_message(format!(
                            "connmark: zone `{z}` out of range (0–65535)"
                        )));
                    }
                    act = act.zone(z as u16);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "connmark: unknown token `{other}` (recognised: zone <0–65535>, a verdict)"
                    )));
                }
            }
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl Default for ConnmarkAction {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionConfig for ConnmarkAction {
    fn kind(&self) -> &'static str {
        "connmark"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        if self.zone != 0 {
            out.extend(kv("zone", self.zone));
        }
        push_verdict(&mut out, "connmark", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = connmark::TcConnmark::new(self.zone, self.action);
        builder.append_attr(connmark::TCA_CONNMARK_PARMS, parms.as_bytes());
        Ok(())
    }
}

// ============================================================================
// CtinfoAction
// ============================================================================

/// ctinfo action configuration.
///
/// `act_ctinfo` copies metadata held in conntrack back into the packet:
/// it can restore a **DSCP** value (under a state mask) into the IP
/// DS field, and/or restore the connection mark (**cpmark**) into
/// `skb->mark`. Typically paired with an earlier `ct` action that stored
/// the values.
///
/// ```no_run
/// use nlink::netlink::action::CtinfoAction;
///
/// // Restore DSCP (top 6 bits) when the conntrack DSCP-set state bit is on,
/// // and restore the connection mark.
/// let a = CtinfoAction::new()
///     .dscp(0xfc, 0x01)
///     .cpmark(0xffffffff)
///     .zone(0)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct CtinfoAction {
    dscp_mask: Option<u32>,
    dscp_statemask: Option<u32>,
    cpmark_mask: Option<u32>,
    zone: Option<u16>,
    action: i32,
}

impl CtinfoAction {
    /// Create a new ctinfo action (default verdict: pipe).
    pub fn new() -> Self {
        Self {
            action: action::TC_ACT_PIPE,
            ..Default::default()
        }
    }

    /// Restore DSCP from conntrack: `mask` selects the DS-field bits and
    /// `statemask` gates the restore on conntrack state bits.
    pub fn dscp(mut self, mask: u32, statemask: u32) -> Self {
        self.dscp_mask = Some(mask);
        self.dscp_statemask = Some(statemask);
        self
    }

    /// Restore the connection mark into `skb->mark` under `mask`.
    pub fn cpmark(mut self, mask: u32) -> Self {
        self.cpmark_mask = Some(mask);
        self
    }

    /// Set the conntrack zone.
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Set the action verdict.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Parse a `tc(8)`-style `ctinfo` token slice into a typed action.
    ///
    /// # Recognised tokens
    ///
    /// - `dscp <mask>[/<statemask>]` — restore DSCP. `mask` and
    ///   `statemask` are hex (`0x..`) or decimal u32; `statemask`
    ///   defaults to 0 when omitted.
    /// - `cpmark [<mask>]` — restore the connection mark. A bare
    ///   `cpmark` uses the full `0xffffffff` mask.
    /// - `zone <0–65535>` — conntrack zone.
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    ///
    /// Strict: unknown tokens, missing values, and unparseable values
    /// all error. At least one of `dscp`/`cpmark` is required.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut a = Self::new();
        let mut any = false;
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    a.action = parse_gact_verdict(v)?;
                    i += 1;
                }
                "dscp" => {
                    let s = action_need_value(params, i, "ctinfo", "dscp")?;
                    // tc-ctinfo(8) gives the statemask as its own word;
                    // `MASK/STATEMASK` reads too (#817).
                    let (mask_s, mut state_s) = match s.split_once('/') {
                        Some((m, st)) => (m, Some(st)),
                        None => (s, None),
                    };
                    let mut used = 2;
                    if state_s.is_none()
                        && let Some(next) = params.get(i + 2).filter(|n| ctinfo_parse_u32("dscp statemask", n).is_ok())
                    {
                        state_s = Some(next);
                        used = 3;
                    }
                    let mask = ctinfo_parse_u32("dscp mask", mask_s)?;
                    let statemask = match state_s {
                        Some(st) => ctinfo_parse_u32("dscp statemask", st)?,
                        None => 0,
                    };
                    a = a.dscp(mask, statemask);
                    any = true;
                    i += used;
                }
                "cpmark" => {
                    // Optional mask: consume the next token only if it
                    // parses as a number; otherwise default to all-ones.
                    let next_is_mask = params
                        .get(i + 1)
                        .is_some_and(|s| ctinfo_parse_u32("cpmark mask", s).is_ok());
                    if next_is_mask {
                        let mask = ctinfo_parse_u32("cpmark mask", params[i + 1])?;
                        a = a.cpmark(mask);
                        i += 2;
                    } else {
                        a = a.cpmark(0xffff_ffff);
                        i += 1;
                    }
                    any = true;
                }
                "zone" => {
                    let s = action_need_value(params, i, "ctinfo", "zone")?;
                    let z = ctinfo_parse_u32("zone", s)?;
                    if z > u16::MAX as u32 {
                        return Err(Error::invalid_message(format!(
                            "ctinfo: zone `{z}` out of range (0–65535)"
                        )));
                    }
                    a = a.zone(z as u16);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "ctinfo: unknown token `{other}` (recognised: dscp <mask>[/<statemask>], cpmark [<mask>], zone <0–65535>, a verdict)"
                    )));
                }
            }
        }
        if !any {
            return Err(Error::invalid_message(
                "ctinfo: at least one of `dscp`/`cpmark` is required".to_string(),
            ));
        }
        Ok(a)
    }
}

impl ActionConfig for CtinfoAction {
    fn kind(&self) -> &'static str {
        "ctinfo"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        match (self.dscp_mask, self.dscp_statemask) {
            (Some(mask), Some(statemask)) => {
                out.extend(kv("dscp", format!("{mask:#x}/{statemask:#x}")));
            }
            (None, None) => {}
            _ => {
                return Err(Error::not_supported(
                    "ctinfo: a DSCP mask without its statemask has no token".to_string(),
                ));
            }
        }
        if let Some(mask) = self.cpmark_mask {
            out.extend(kv("cpmark", format!("{mask:#x}")));
        }
        if out.is_empty() {
            return Err(Error::invalid_message(
                "ctinfo: at least one of `dscp`/`cpmark` is required".to_string(),
            ));
        }
        if let Some(zone) = self.zone {
            out.extend(kv("zone", zone));
        }
        push_verdict(&mut out, "ctinfo", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::action::ctinfo;

        let parms = ctinfo::TcCtinfo::new(self.action);
        builder.append_attr(ctinfo::TCA_CTINFO_ACT, parms.as_bytes());

        if let Some(zone) = self.zone {
            builder.append_attr(ctinfo::TCA_CTINFO_ZONE, &zone.to_ne_bytes());
        }
        if let Some(mask) = self.dscp_mask {
            builder.append_attr_u32(ctinfo::TCA_CTINFO_PARMS_DSCP_MASK, mask);
        }
        if let Some(statemask) = self.dscp_statemask {
            builder.append_attr_u32(ctinfo::TCA_CTINFO_PARMS_DSCP_STATEMASK, statemask);
        }
        if let Some(mask) = self.cpmark_mask {
            builder.append_attr_u32(ctinfo::TCA_CTINFO_PARMS_CPMARK_MASK, mask);
        }
        Ok(())
    }
}

// ============================================================================
// IfeAction
// ============================================================================

/// IFE metadata kind carried by an [`IfeAction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IfeMeta {
    /// skb mark (`IFE_META_SKBMARK`, 4-byte value).
    Mark,
    /// skb priority (`IFE_META_PRIO`, 4-byte value).
    Prio,
    /// tc index (`IFE_META_TCINDEX`, 2-byte value).
    TcIndex,
}

#[derive(Debug, Clone)]
struct IfeMetaEntry {
    kind: IfeMeta,
    /// `None` = `allow` (carry whatever the skb holds); `Some` = `use`
    /// (override with this value).
    value: Option<u32>,
}

/// IFE (Inter-FE) action configuration.
///
/// `act_ife` tunnels selected skb metadata (mark / priority / tcindex)
/// between forwarding elements: in **encode** mode it writes the
/// selected metadata into an IFE Ethernet header (optionally overriding
/// the destination/source MAC and ethertype); in **decode** mode it
/// reads metadata back out of arriving IFE frames.
///
/// Each metadata item is either `allow`ed (carry whatever the skb
/// currently holds) or `use`d with an explicit override value.
///
/// ```no_run
/// use nlink::netlink::action::{IfeAction, IfeMeta};
///
/// // Encode the skb mark and a fixed priority into an IFE header.
/// let a = IfeAction::encode()
///     .allow(IfeMeta::Mark)
///     .use_value(IfeMeta::Prio, 7)
///     .dst([0x02, 0, 0, 0, 0, 1])
///     .etype(0xed3e)
///     .build();
/// ```
///
/// # Override-value byte order
///
/// `use <meta> <value>` overrides are written big-endian (network order)
/// — `u32` for `mark`/`prio`, `u16` for `tcindex`. The `allow` form
/// carries no value and is the common case.
#[derive(Debug, Clone)]
pub struct IfeAction {
    encode: bool,
    dmac: Option<[u8; 6]>,
    smac: Option<[u8; 6]>,
    etype: Option<u16>,
    metadata: Vec<IfeMetaEntry>,
    action: i32,
}

impl IfeAction {
    fn new(encode: bool) -> Self {
        Self {
            encode,
            dmac: None,
            smac: None,
            etype: None,
            metadata: Vec::new(),
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create an IFE action in **encode** mode.
    pub fn encode() -> Self {
        Self::new(true)
    }

    /// Create an IFE action in **decode** mode.
    pub fn decode() -> Self {
        Self::new(false)
    }

    /// Carry whatever value the skb holds for `meta` (`allow`).
    pub fn allow(mut self, meta: IfeMeta) -> Self {
        self.metadata.push(IfeMetaEntry {
            kind: meta,
            value: None,
        });
        self
    }

    /// Override `meta` with an explicit value (`use`).
    pub fn use_value(mut self, meta: IfeMeta, value: u32) -> Self {
        self.metadata.push(IfeMetaEntry {
            kind: meta,
            value: Some(value),
        });
        self
    }

    /// Set the destination MAC written into the IFE header.
    pub fn dst(mut self, mac: [u8; 6]) -> Self {
        self.dmac = Some(mac);
        self
    }

    /// Set the source MAC written into the IFE header.
    pub fn src(mut self, mac: [u8; 6]) -> Self {
        self.smac = Some(mac);
        self
    }

    /// Set the IFE ethertype.
    pub fn etype(mut self, etype: u16) -> Self {
        self.etype = Some(etype);
        self
    }

    /// Set the action verdict.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }

    fn meta_from_str(kind: &str, s: &str) -> Result<IfeMeta> {
        match s {
            "mark" => Ok(IfeMeta::Mark),
            "prio" => Ok(IfeMeta::Prio),
            "tcindex" => Ok(IfeMeta::TcIndex),
            other => Err(Error::invalid_message(format!(
                "{kind}: unknown metadata `{other}` (expected mark, prio, tcindex)"
            ))),
        }
    }

    /// Parse a `tc(8)`-style `ife` token slice into a typed action.
    ///
    /// # Recognised tokens
    ///
    /// - `encode` / `decode` — mode (required, must come first).
    /// - `allow <meta>` — carry the skb's value for `mark`/`prio`/`tcindex`.
    /// - `use <meta> <value>` — override with an explicit value (a `u16`
    ///   for `tcindex`).
    /// - `dst <MAC>` / `src <MAC>` — IFE header MACs.
    /// - `type <ethertype>` — IFE ethertype (name or `0x`-hex/decimal).
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    ///
    /// Strict: unknown tokens, missing values, and unparseable values
    /// all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut a = match params.first() {
            Some(&"encode") => Self::encode(),
            Some(&"decode") => Self::decode(),
            _ => {
                return Err(Error::invalid_message(
                    "ife: first token must be `encode` or `decode`".to_string(),
                ));
            }
        };
        let mut i = 1;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    a.action = parse_gact_verdict(v)?;
                    i += 1;
                }
                "allow" => {
                    let s = action_need_value(params, i, "ife", "allow")?;
                    a = a.allow(Self::meta_from_str("ife", s)?);
                    i += 2;
                }
                "use" => {
                    let what = action_need_value(params, i, "ife", "use")?;
                    let meta = Self::meta_from_str("ife", what)?;
                    let val_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::invalid_message(format!("ife: `use {what}` requires a value"))
                    })?;
                    let val = action_parse_u32("ife", "use value", val_s)?;
                    // tcindex is sent as a u16; a wider value was cut.
                    if meta == IfeMeta::TcIndex && val > u32::from(u16::MAX) {
                        return Err(Error::invalid_message(format!(
                            "ife: tcindex value `{val}` out of range (0–65535)"
                        )));
                    }
                    a = a.use_value(meta, val);
                    i += 3;
                }
                "dst" => {
                    let s = action_need_value(params, i, "ife", "dst")?;
                    a = a.dst(crate::util::addr::parse_mac(s).map_err(|_| {
                        Error::invalid_message(format!("ife: invalid dst MAC `{s}`"))
                    })?);
                    i += 2;
                }
                "src" => {
                    let s = action_need_value(params, i, "ife", "src")?;
                    a = a.src(crate::util::addr::parse_mac(s).map_err(|_| {
                        Error::invalid_message(format!("ife: invalid src MAC `{s}`"))
                    })?);
                    i += 2;
                }
                "type" => {
                    let s = action_need_value(params, i, "ife", "type")?;
                    a = a.etype(parse_ethertype("ife", s)?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "ife: unknown token `{other}` (recognised: encode|decode, allow <meta>, use <meta> <val>, dst/src <MAC>, type <ethertype>, a verdict)"
                    )));
                }
            }
        }
        Ok(a)
    }
}

impl ActionConfig for IfeAction {
    fn kind(&self) -> &'static str {
        "ife"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        use crate::util::addr::format_mac;
        let mode = if self.encode { "encode" } else { "decode" };
        let mut out = vec![mode.to_string()];
        if let Some(mac) = self.dmac {
            out.extend(kv("dst", format_mac(&mac)));
        }
        if let Some(mac) = self.smac {
            out.extend(kv("src", format_mac(&mac)));
        }
        if let Some(etype) = self.etype {
            out.extend(kv("type", crate::EthProto::new(etype)));
        }
        for entry in &self.metadata {
            let meta = match entry.kind {
                IfeMeta::Mark => "mark",
                IfeMeta::Prio => "prio",
                IfeMeta::TcIndex => "tcindex",
            };
            match entry.value {
                None => out.extend(kv("allow", meta)),
                Some(v) if entry.kind == IfeMeta::TcIndex && v > u32::from(u16::MAX) => {
                    return Err(Error::invalid_message(format!(
                        "ife: tcindex value `{v}` out of range (0–65535)"
                    )));
                }
                Some(v) => out.extend(["use".to_string(), meta.to_string(), v.to_string()]),
            }
        }
        push_verdict(&mut out, "ife", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::action::ife;

        let flags = if self.encode { ife::IFE_ENCODE } else { 0 };
        let parms = ife::TcIfe::new(flags, self.action);
        builder.append_attr(ife::TCA_IFE_PARMS, parms.as_bytes());

        if let Some(dmac) = self.dmac {
            builder.append_attr(ife::TCA_IFE_DMAC, &dmac);
        }
        if let Some(smac) = self.smac {
            builder.append_attr(ife::TCA_IFE_SMAC, &smac);
        }
        // Host order, as `tcf_ife_init()` reads it (#816).
        if let Some(etype) = self.etype {
            builder.append_attr(ife::TCA_IFE_TYPE, &etype.to_ne_bytes());
        }

        if !self.metadata.is_empty() {
            let lst = builder.nest_start(ife::TCA_IFE_METALST);
            for entry in &self.metadata {
                let attr = match entry.kind {
                    IfeMeta::Mark => ife::IFE_META_SKBMARK,
                    IfeMeta::Prio => ife::IFE_META_PRIO,
                    IfeMeta::TcIndex => ife::IFE_META_TCINDEX,
                };
                match entry.value {
                    // `allow`: empty payload.
                    None => builder.append_attr(attr, &[]),
                    // `use`: the value, in host order: the metadata ops keep
                    // and report it as a `u32` (tcindex a `u16`), #816.
                    Some(v) => match entry.kind {
                        IfeMeta::TcIndex => builder.append_attr(attr, &(v as u16).to_ne_bytes()),
                        _ => builder.append_attr(attr, &v.to_ne_bytes()),
                    },
                }
            }
            builder.nest_end(lst);
        }

        Ok(())
    }
}

// ============================================================================
// GateAction
// ============================================================================

/// A single schedule entry of a [`GateAction`].
#[derive(Debug, Clone)]
struct GateEntry {
    /// Gate open (admit) during this interval.
    open: bool,
    /// Interval length in nanoseconds. The kernel's field is a `u32`; a
    /// longer one is refused when the action is written (#751), where it
    /// used to wrap.
    interval_ns: u64,
    /// Internal priority value (`-1` = unset).
    ipv: Option<i32>,
    /// Max octets admitted in this interval (`-1` = unset).
    max_octets: Option<i32>,
}

/// gate (IEEE 802.1Qci PSFP) action configuration.
///
/// `act_gate` admits packets only during the open windows of a cyclic
/// time schedule — the per-stream filtering-and-policing gate of TSN.
/// The schedule is a list of `sched-entry` items, each opening or
/// closing the gate for a nanosecond interval, optionally pinning an
/// internal priority value (IPV) and a per-interval octet budget.
///
/// ```no_run
/// use nlink::netlink::action::GateAction;
/// use std::time::Duration;
///
/// let a = GateAction::new()
///     .priority(0)
///     .cycle_time(Duration::from_millis(2))
///     .sched_entry(true, Duration::from_millis(1), None, None)   // open 1ms
///     .sched_entry(false, Duration::from_millis(1), None, None)  // close 1ms
///     .build();
/// ```
///
/// # Time units
///
/// `base_time`/`cycle_time`/`cycle_time_ext` and each entry interval are
/// `Duration`s, sent to the kernel in nanoseconds. The `parse_params`
/// forms accept `tc(8)` time strings (`1ms`, `100us`, …).
#[derive(Debug, Clone, Default)]
pub struct GateAction {
    priority: Option<i32>,
    base_time: Option<u64>,
    cycle_time: Option<u64>,
    cycle_time_ext: Option<u64>,
    clockid: Option<i32>,
    entries: Vec<GateEntry>,
    action: i32,
}

impl GateAction {
    /// Create a new gate action (default verdict: pipe).
    pub fn new() -> Self {
        Self {
            action: action::TC_ACT_PIPE,
            ..Default::default()
        }
    }

    /// Set the gate priority.
    pub fn priority(mut self, prio: i32) -> Self {
        self.priority = Some(prio);
        self
    }

    /// Set the schedule base time.
    pub fn base_time(mut self, t: std::time::Duration) -> Self {
        self.base_time = Some(t.as_nanos() as u64);
        self
    }

    /// Set the schedule cycle time.
    pub fn cycle_time(mut self, t: std::time::Duration) -> Self {
        self.cycle_time = Some(t.as_nanos() as u64);
        self
    }

    /// Set the schedule cycle-time extension.
    pub fn cycle_time_ext(mut self, t: std::time::Duration) -> Self {
        self.cycle_time_ext = Some(t.as_nanos() as u64);
        self
    }

    /// Set the POSIX clock id (e.g. `11` for `CLOCK_TAI`).
    pub fn clockid(mut self, id: i32) -> Self {
        self.clockid = Some(id);
        self
    }

    /// Append a schedule entry: `open` admits packets for `interval`;
    /// `ipv`/`max_octets` are optional per-interval overrides.
    pub fn sched_entry(
        mut self,
        open: bool,
        interval: std::time::Duration,
        ipv: Option<i32>,
        max_octets: Option<i32>,
    ) -> Self {
        self.entries.push(GateEntry {
            open,
            interval_ns: u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX),
            ipv,
            max_octets,
        });
        self
    }

    /// Set the action verdict.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }

    /// Map a `clockid` token (`TAI`, `CLOCK_REALTIME`, …) to its POSIX id.
    fn clockid_from_str(s: &str) -> Result<i32> {
        let bare = s.strip_prefix("CLOCK_").unwrap_or(s);
        Ok(match bare {
            "REALTIME" => 0,
            "MONOTONIC" => 1,
            "BOOTTIME" => 7,
            "TAI" => 11,
            other => other.parse::<i32>().map_err(|_| {
                Error::invalid_message(format!(
                    "gate: unknown clockid `{other}` (expected TAI/REALTIME/MONOTONIC/BOOTTIME or a number)"
                ))
            })?,
        })
    }

    /// The `clockid` token for `id`: tc(8)'s name, or the number.
    fn clockid_token(id: i32) -> String {
        match id {
            0 => "CLOCK_REALTIME".to_string(),
            1 => "CLOCK_MONOTONIC".to_string(),
            7 => "CLOCK_BOOTTIME".to_string(),
            11 => "CLOCK_TAI".to_string(),
            other => other.to_string(),
        }
    }

    fn is_keyword(tok: &str) -> bool {
        matches!(
            tok,
            "priority" | "base-time" | "cycle-time" | "cycle-time-ext" | "clockid" | "sched-entry"
        ) || is_verdict(tok)
    }

    /// A time in nanoseconds as a tc(8) time string. A bare number is
    /// nanoseconds, as tc-gate(8) reads it (#751); it was read as
    /// microseconds, a thousand times too long. A whole number of
    /// nanoseconds (`<n>` or `<n>ns`) is read exactly: the time parser goes
    /// through a float, which holds no more than 2^53 ns (104 days), and an
    /// absolute `base-time` is past that.
    fn time_ns(key: &str, s: &str) -> Result<u64> {
        let invalid = || {
            Error::invalid_message(format!("gate: invalid {key} `{s}` (expected a tc-style time)"))
        };
        let whole = s.strip_suffix("ns").unwrap_or(s);
        if !whole.is_empty() && whole.bytes().all(|b| b.is_ascii_digit()) {
            return whole.parse::<u64>().map_err(|_| invalid());
        }
        if !s.bytes().any(|b| b.is_ascii_alphabetic()) {
            return Err(Error::invalid_message(format!(
                "gate: invalid {key} `{s}` (a bare time is a whole number of nanoseconds)"
            )));
        }
        crate::util::parse::get_time(s)
            .map(|d| d.as_nanos() as u64)
            .map_err(|_| invalid())
    }

    /// `ns` as a time [`time_ns`](Self::time_ns) reads back exactly.
    fn time_token(ns: u64) -> String {
        crate::util::parse::format_time(std::time::Duration::from_nanos(ns))
    }

    /// Parse a `tc(8)`-style `gate` token slice into a typed action.
    ///
    /// # Recognised tokens
    ///
    /// - `priority <int>`
    /// - `base-time <time>` / `cycle-time <time>` / `cycle-time-ext <time>`
    ///   (`tc(8)` time strings, e.g. `1ms`, `200us`; a bare number is
    ///   nanoseconds, as tc-gate(8) reads it, and a whole number of
    ///   nanoseconds is read exactly).
    /// - `clockid <id>` (`TAI`/`REALTIME`/`MONOTONIC`/`BOOTTIME` or a number).
    /// - `sched-entry open|close <interval> [<ipv> [<max-octets>]]` —
    ///   repeatable; the optional `ipv`/`max-octets` are consumed
    ///   greedily up to the next keyword.
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    ///
    /// Strict: unknown tokens, missing values, and unparseable values
    /// all error.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut a = Self::new();
        let mut i = 0;

        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    a.action = parse_gact_verdict(v)?;
                    i += 1;
                }
                "priority" => {
                    let s = action_need_value(params, i, "gate", "priority")?;
                    a.priority = Some(s.parse::<i32>().map_err(|_| {
                        Error::invalid_message(format!("gate: invalid priority `{s}`"))
                    })?);
                    i += 2;
                }
                "base-time" => {
                    let s = action_need_value(params, i, "gate", "base-time")?;
                    a.base_time = Some(Self::time_ns("base-time", s)?);
                    i += 2;
                }
                "cycle-time" => {
                    let s = action_need_value(params, i, "gate", "cycle-time")?;
                    a.cycle_time = Some(Self::time_ns("cycle-time", s)?);
                    i += 2;
                }
                "cycle-time-ext" => {
                    let s = action_need_value(params, i, "gate", "cycle-time-ext")?;
                    a.cycle_time_ext = Some(Self::time_ns("cycle-time-ext", s)?);
                    i += 2;
                }
                "clockid" => {
                    let s = action_need_value(params, i, "gate", "clockid")?;
                    a.clockid = Some(Self::clockid_from_str(s)?);
                    i += 2;
                }
                "sched-entry" => {
                    let state = action_need_value(params, i, "gate", "sched-entry")?;
                    let open = match state {
                        "open" => true,
                        "close" => false,
                        other => {
                            return Err(Error::invalid_message(format!(
                                "gate: sched-entry state `{other}` (expected open or close)"
                            )));
                        }
                    };
                    let interval_s = params.get(i + 2).copied().ok_or_else(|| {
                        Error::invalid_message(
                            "gate: `sched-entry` requires an interval".to_string(),
                        )
                    })?;
                    let interval_ns = Self::time_ns("sched-entry interval", interval_s)?;
                    let interval_ns: u64 = u32::try_from(interval_ns).map(u64::from).map_err(|_| {
                        Error::invalid_message(format!(
                            "gate: sched-entry interval `{interval_s}` exceeds u32 nanoseconds"
                        ))
                    })?;
                    i += 3;

                    // Greedily consume optional ipv then max-octets.
                    let mut ipv = None;
                    let mut max_octets = None;
                    if let Some(tok) = params.get(i)
                        && !Self::is_keyword(tok)
                    {
                        ipv = Some(tok.parse::<i32>().map_err(|_| {
                            Error::invalid_message(format!("gate: invalid sched-entry ipv `{tok}`"))
                        })?);
                        i += 1;
                        if let Some(tok2) = params.get(i)
                            && !Self::is_keyword(tok2)
                        {
                            max_octets = Some(tok2.parse::<i32>().map_err(|_| {
                                Error::invalid_message(format!(
                                    "gate: invalid sched-entry max-octets `{tok2}`"
                                ))
                            })?);
                            i += 1;
                        }
                    }
                    a.entries.push(GateEntry {
                        open,
                        interval_ns,
                        ipv,
                        max_octets,
                    });
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "gate: unknown token `{other}` (recognised: priority, base-time, cycle-time, cycle-time-ext, clockid, sched-entry open|close <interval> [ipv [max-octets]], a verdict)"
                    )));
                }
            }
        }
        Ok(a)
    }
}

impl ActionConfig for GateAction {
    fn kind(&self) -> &'static str {
        "gate"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        if let Some(prio) = self.priority {
            out.extend(kv("priority", prio));
        }
        for (key, t) in [
            ("base-time", self.base_time),
            ("cycle-time", self.cycle_time),
            ("cycle-time-ext", self.cycle_time_ext),
        ] {
            if let Some(t) = t {
                out.extend(kv(key, Self::time_token(t)));
            }
        }
        if let Some(id) = self.clockid {
            out.extend(kv("clockid", Self::clockid_token(id)));
        }
        for e in &self.entries {
            let state = if e.open { "open" } else { "close" };
            out.extend([
                "sched-entry".to_string(),
                state.to_string(),
                Self::time_token(e.interval_ns),
            ]);
            // Positional: a max-octets is the value after an ipv.
            match (e.ipv, e.max_octets) {
                (None, None) => {}
                (Some(ipv), None) => out.push(ipv.to_string()),
                (Some(ipv), Some(octets)) => out.extend([ipv.to_string(), octets.to_string()]),
                (None, Some(_)) => {
                    return Err(Error::not_supported(
                        "gate: a sched-entry's max-octets without an ipv has no token".to_string(),
                    ));
                }
            }
        }
        push_verdict(&mut out, "gate", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::action::gate;

        let parms = gate::TcGate::new(self.action);
        builder.append_attr(gate::TCA_GATE_PARMS, parms.as_bytes());

        if let Some(prio) = self.priority {
            builder.append_attr_u32(gate::TCA_GATE_PRIORITY, prio as u32);
        }
        if let Some(t) = self.base_time {
            builder.append_attr(gate::TCA_GATE_BASE_TIME, &t.to_ne_bytes());
        }
        if let Some(t) = self.cycle_time {
            builder.append_attr(gate::TCA_GATE_CYCLE_TIME, &t.to_ne_bytes());
        }
        if let Some(t) = self.cycle_time_ext {
            builder.append_attr(gate::TCA_GATE_CYCLE_TIME_EXT, &t.to_ne_bytes());
        }
        if let Some(id) = self.clockid {
            builder.append_attr_u32(gate::TCA_GATE_CLOCKID, id as u32);
        }

        if !self.entries.is_empty() {
            let list = builder.nest_start(gate::TCA_GATE_ENTRY_LIST);
            for (idx, e) in self.entries.iter().enumerate() {
                let one = builder.nest_start(gate::TCA_GATE_ONE_ENTRY);
                builder.append_attr_u32(gate::TCA_GATE_ENTRY_INDEX, idx as u32);
                if e.open {
                    // NLA_FLAG: present = gate open, absent = closed.
                    builder.append_attr(gate::TCA_GATE_ENTRY_GATE, &[]);
                }
                let interval = u32::try_from(e.interval_ns).map_err(|_| {
                    Error::invalid_message(format!(
                        "gate: sched-entry {idx}'s interval of {} ns is past the kernel's \
                         u32 nanoseconds (about 4.29 s)",
                        e.interval_ns
                    ))
                })?;
                builder.append_attr_u32(gate::TCA_GATE_ENTRY_INTERVAL, interval);
                if let Some(ipv) = e.ipv {
                    builder.append_attr_u32(gate::TCA_GATE_ENTRY_IPV, ipv as u32);
                }
                if let Some(mo) = e.max_octets {
                    builder.append_attr_u32(gate::TCA_GATE_ENTRY_MAX_OCTETS, mo as u32);
                }
                builder.nest_end(one);
            }
            builder.nest_end(list);
        }

        Ok(())
    }
}

// ============================================================================
// CsumAction
// ============================================================================

/// Checksum recalculation action configuration.
///
/// The csum action recalculates one or more protocol checksums in the packet.
/// This is useful after modifying packet headers with actions like pedit or nat.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::CsumAction;
///
/// // Recalculate IP and TCP checksums
/// let csum = CsumAction::new()
///     .iph()
///     .tcp();
///
/// // Recalculate all common checksums
/// let csum = CsumAction::new()
///     .iph()
///     .tcp()
///     .udp()
///     .icmp();
/// ```
#[derive(Debug, Clone)]
pub struct CsumAction {
    /// Update flags indicating which checksums to recalculate.
    update_flags: u32,
    /// Action result (TC_ACT_OK by default).
    action: i32,
}

impl CsumAction {
    /// Create a new csum action with no checksums selected.
    pub fn new() -> Self {
        Self {
            update_flags: 0,
            action: action::TC_ACT_OK,
        }
    }

    /// Recalculate IPv4 header checksum.
    pub fn iph(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_IPV4HDR;
        self
    }

    /// Recalculate ICMP checksum.
    pub fn icmp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_ICMP;
        self
    }

    /// Recalculate IGMP checksum.
    pub fn igmp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_IGMP;
        self
    }

    /// Recalculate TCP checksum.
    pub fn tcp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_TCP;
        self
    }

    /// Recalculate UDP checksum.
    pub fn udp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_UDP;
        self
    }

    /// Recalculate UDP-Lite checksum.
    pub fn udplite(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_UDPLITE;
        self
    }

    /// Recalculate SCTP checksum.
    pub fn sctp(mut self) -> Self {
        self.update_flags |= csum::TCA_CSUM_UPDATE_FLAG_SCTP;
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `csum` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// One or more checksum-kind keywords, accumulated as flags:
    /// `iph` (IPv4 header), `icmp`, `igmp`, `tcp`, `udp`,
    /// `udplite`, `sctp`. Order is irrelevant; duplicates are a
    /// no-op (bitmask OR). A verdict (`pass`, `drop`, `pipe`,
    /// `reclassify`, `stolen`, `continue`) may be given; `pass` without
    /// one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut act = Self::new();
        for &t in params {
            act = match t {
                // tc separates targets with `and`, and spells `iph`
                // `ip4h` too (#817).
                "and" => act,
                "iph" | "ip4h" => act.iph(),
                "icmp" => act.icmp(),
                "igmp" => act.igmp(),
                "tcp" => act.tcp(),
                "udp" => act.udp(),
                "udplite" => act.udplite(),
                "sctp" => act.sctp(),
                v if is_verdict(v) => act.action(parse_gact_verdict(v)?),
                other => {
                    return Err(Error::invalid_message(format!(
                        "csum: unknown checksum kind `{other}` (recognised: iph/icmp/igmp/tcp/udp/udplite/sctp, a verdict)"
                    )));
                }
            };
        }
        Ok(act)
    }

    /// Each checksum flag and the token `parse_params` reads for it.
    const FLAG_TOKENS: [(u32, &'static str); 7] = [
        (csum::TCA_CSUM_UPDATE_FLAG_IPV4HDR, "iph"),
        (csum::TCA_CSUM_UPDATE_FLAG_ICMP, "icmp"),
        (csum::TCA_CSUM_UPDATE_FLAG_IGMP, "igmp"),
        (csum::TCA_CSUM_UPDATE_FLAG_TCP, "tcp"),
        (csum::TCA_CSUM_UPDATE_FLAG_UDP, "udp"),
        (csum::TCA_CSUM_UPDATE_FLAG_UDPLITE, "udplite"),
        (csum::TCA_CSUM_UPDATE_FLAG_SCTP, "sctp"),
    ];

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl Default for CsumAction {
    fn default() -> Self {
        Self::new()
    }
}

impl ActionConfig for CsumAction {
    fn kind(&self) -> &'static str {
        "csum"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let unknown = Self::FLAG_TOKENS
            .iter()
            .fold(self.update_flags, |flags, (flag, _)| flags & !flag);
        if unknown != 0 {
            return Err(Error::not_supported(format!(
                "csum: update flags {unknown:#x} have no token"
            )));
        }
        let mut out: Vec<String> = Self::FLAG_TOKENS
            .iter()
            .filter(|(flag, _)| self.update_flags & flag != 0)
            .map(|(_, token)| token.to_string())
            .collect();
        push_verdict(&mut out, "csum", self.action, action::TC_ACT_OK)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = csum::TcCsum::new(self.update_flags, self.action);
        builder.append_attr(csum::TCA_CSUM_PARMS, parms.as_bytes());
        Ok(())
    }
}

// ============================================================================
// SampleAction
// ============================================================================

/// Packet sampling action configuration.
///
/// The sample action sends a copy of packets to a psample group for monitoring.
/// This is useful for network analysis, debugging, and traffic monitoring.
///
/// # Example
///
/// ```no_run
/// use nlink::netlink::action::SampleAction;
///
/// // Sample 1 in 100 packets to group 5
/// let sample = SampleAction::new(100, 5);
///
/// // Sample with truncation to 128 bytes
/// let sample = SampleAction::new(100, 5)
///     .trunc(128);
/// ```
#[derive(Debug, Clone)]
pub struct SampleAction {
    /// Sample rate (1 in N packets).
    rate: u32,
    /// Psample group ID.
    group: u32,
    /// Truncation size (optional).
    trunc_size: Option<u32>,
    /// Action result (TC_ACT_PIPE by default).
    action: i32,
}

impl SampleAction {
    /// Create a new sample action.
    ///
    /// - `rate`: Sample 1 in N packets
    /// - `group`: Psample group ID to send samples to
    pub fn new(rate: u32, group: u32) -> Self {
        Self {
            rate,
            group,
            trunc_size: None,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set the truncation size (maximum bytes to sample per packet).
    pub fn trunc(mut self, size: u32) -> Self {
        self.trunc_size = Some(size);
        self
    }

    /// Set the action result.
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `sample` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens (any order)
    ///
    /// Required:
    /// - `rate <N>` — sample 1 in N packets.
    /// - `group <G>` — psample group ID to send samples to.
    ///
    /// Optional:
    /// - `trunc <bytes>` — truncate sampled packets to N bytes.
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut rate: Option<u32> = None;
        let mut group: Option<u32> = None;
        let mut trunc: Option<u32> = None;
        let mut verdict: Option<i32> = None;
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                v if is_verdict(v) => {
                    verdict = Some(parse_gact_verdict(v)?);
                    i += 1;
                }
                "rate" => {
                    let s = action_need_value(params, i, "sample", key)?;
                    rate = Some(action_parse_u32("sample", "rate", s)?);
                    i += 2;
                }
                "group" => {
                    let s = action_need_value(params, i, "sample", key)?;
                    group = Some(action_parse_u32("sample", "group", s)?);
                    i += 2;
                }
                "trunc" => {
                    let s = action_need_value(params, i, "sample", key)?;
                    trunc = Some(action_parse_u32("sample", "trunc", s)?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "sample: unknown token `{other}` (recognised: rate <N>, group <G>, trunc <bytes>, a verdict)"
                    )));
                }
            }
        }
        let rate =
            rate.ok_or_else(|| Error::invalid_message("sample: `rate <N>` required".to_string()))?;
        let group = group
            .ok_or_else(|| Error::invalid_message("sample: `group <G>` required".to_string()))?;
        let mut act = Self::new(rate, group);
        if let Some(t) = trunc {
            act = act.trunc(t);
        }
        if let Some(v) = verdict {
            act = act.action(v);
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for SampleAction {
    fn kind(&self) -> &'static str {
        "sample"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        out.extend(kv("rate", self.rate));
        out.extend(kv("group", self.group));
        if let Some(trunc) = self.trunc_size {
            out.extend(kv("trunc", trunc));
        }
        push_verdict(&mut out, "sample", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = sample::TcSample::new(self.action);
        builder.append_attr(sample::TCA_SAMPLE_PARMS, parms.as_bytes());
        builder.append_attr_u32(sample::TCA_SAMPLE_RATE, self.rate);
        builder.append_attr_u32(sample::TCA_SAMPLE_PSAMPLE_GROUP, self.group);

        if let Some(trunc) = self.trunc_size {
            builder.append_attr_u32(sample::TCA_SAMPLE_TRUNC_SIZE, trunc);
        }

        Ok(())
    }
}

// ============================================================================
// CtAction (Connection Tracking)
// ============================================================================

/// CT (Connection Tracking) action configuration.
///
/// The ct action performs connection tracking on packets. It can commit new
/// connections, restore connection state, perform NAT, and set marks/labels.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::action::CtAction;
///
/// // Simple connection tracking (restore state)
/// let ct = CtAction::new();
///
/// // Commit a new connection
/// let ct = CtAction::commit();
///
/// // Force commit (even if already committed)
/// let ct = CtAction::commit().force();
///
/// // Clear connection tracking state
/// let ct = CtAction::clear();
///
/// // SNAT with IP range and port range
/// let ct = CtAction::commit()
///     .nat_src("10.0.0.1".parse()?, "10.0.0.10".parse()?)
///     .nat_port_range(1024, 65535);
///
/// // DNAT to specific IP
/// let ct = CtAction::commit()
///     .nat_dst_single("192.168.1.1".parse()?);
///
/// // With zone and mark
/// let ct = CtAction::commit()
///     .zone(1)
///     .mark(0x100, 0xffffffff);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct CtAction {
    /// CT action flags.
    ct_action: u16,
    /// Connection tracking zone.
    zone: Option<u16>,
    /// Mark value.
    mark: Option<u32>,
    /// Mark mask.
    mark_mask: Option<u32>,
    /// Labels (up to 128 bits).
    labels: Option<[u8; 16]>,
    /// Labels mask.
    labels_mask: Option<[u8; 16]>,
    /// NAT IPv4 min address.
    nat_ipv4_min: Option<Ipv4Addr>,
    /// NAT IPv4 max address.
    nat_ipv4_max: Option<Ipv4Addr>,
    /// NAT IPv6 min address.
    nat_ipv6_min: Option<std::net::Ipv6Addr>,
    /// NAT IPv6 max address.
    nat_ipv6_max: Option<std::net::Ipv6Addr>,
    /// NAT port min.
    nat_port_min: Option<u16>,
    /// NAT port max.
    nat_port_max: Option<u16>,
    /// Helper name.
    helper_name: Option<String>,
    /// Helper address family.
    helper_family: Option<u8>,
    /// Helper protocol.
    helper_proto: Option<u8>,
    /// Action result.
    action: i32,
}

impl Default for CtAction {
    fn default() -> Self {
        Self::new()
    }
}

impl CtAction {
    /// Create a new CT action (restore connection state).
    pub fn new() -> Self {
        Self {
            ct_action: 0,
            zone: None,
            mark: None,
            mark_mask: None,
            labels: None,
            labels_mask: None,
            nat_ipv4_min: None,
            nat_ipv4_max: None,
            nat_ipv6_min: None,
            nat_ipv6_max: None,
            nat_port_min: None,
            nat_port_max: None,
            helper_name: None,
            helper_family: None,
            helper_proto: None,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Create a CT action that commits the connection.
    pub fn commit() -> Self {
        let mut s = Self::new();
        s.ct_action = ct::TCA_CT_ACT_COMMIT;
        s
    }

    /// Create a CT action that clears connection state.
    pub fn clear() -> Self {
        let mut s = Self::new();
        s.ct_action = ct::TCA_CT_ACT_CLEAR;
        s
    }

    /// Force commit even if already tracked.
    pub fn force(mut self) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_FORCE;
        self
    }

    /// Set connection tracking zone.
    pub fn zone(mut self, zone: u16) -> Self {
        self.zone = Some(zone);
        self
    }

    /// Set mark value and mask.
    pub fn mark(mut self, mark: u32, mask: u32) -> Self {
        self.mark = Some(mark);
        self.mark_mask = Some(mask);
        self
    }

    /// Set labels (128-bit value).
    pub fn labels(mut self, labels: [u8; 16], mask: [u8; 16]) -> Self {
        self.labels = Some(labels);
        self.labels_mask = Some(mask);
        self
    }

    /// NAT the connection as its conntrack entry says, with no range of
    /// its own (tc-ct(8)'s bare `nat`): the reply direction of a NATed
    /// flow.
    pub fn nat(mut self) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT;
        self
    }

    /// Configure SNAT with IPv4 address range.
    pub fn nat_src(mut self, min: Ipv4Addr, max: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_SRC;
        self.nat_ipv4_min = Some(min);
        self.nat_ipv4_max = Some(max);
        self
    }

    /// Configure SNAT with single IPv4 address.
    pub fn nat_src_single(mut self, addr: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_SRC;
        self.nat_ipv4_min = Some(addr);
        self.nat_ipv4_max = Some(addr);
        self
    }

    /// Configure DNAT with IPv4 address range.
    pub fn nat_dst(mut self, min: Ipv4Addr, max: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_DST;
        self.nat_ipv4_min = Some(min);
        self.nat_ipv4_max = Some(max);
        self
    }

    /// Configure DNAT with single IPv4 address.
    pub fn nat_dst_single(mut self, addr: Ipv4Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_DST;
        self.nat_ipv4_min = Some(addr);
        self.nat_ipv4_max = Some(addr);
        self
    }

    /// Configure SNAT with IPv6 address range.
    pub fn nat_src6(mut self, min: std::net::Ipv6Addr, max: std::net::Ipv6Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_SRC;
        self.nat_ipv6_min = Some(min);
        self.nat_ipv6_max = Some(max);
        self
    }

    /// Configure DNAT with IPv6 address range.
    pub fn nat_dst6(mut self, min: std::net::Ipv6Addr, max: std::net::Ipv6Addr) -> Self {
        self.ct_action |= ct::TCA_CT_ACT_NAT | ct::TCA_CT_ACT_NAT_DST;
        self.nat_ipv6_min = Some(min);
        self.nat_ipv6_max = Some(max);
        self
    }

    /// Set NAT port range.
    pub fn nat_port_range(mut self, min: u16, max: u16) -> Self {
        self.nat_port_min = Some(min);
        self.nat_port_max = Some(max);
        self
    }

    /// Set connection tracking helper.
    pub fn helper(mut self, name: &str, family: u8, proto: u8) -> Self {
        self.helper_name = Some(name.to_string());
        self.helper_family = Some(family);
        self.helper_proto = Some(proto);
        self
    }

    /// Set action result (default: pipe).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `ct` token slice into a typed action.
    ///
    /// # Recognised tokens
    ///
    /// Operation (one optional, defaults to "restore state"):
    /// - `commit` — commit the connection.
    /// - `clear` — clear connection state.
    ///
    /// Modifiers:
    /// - `force` (flag, no value) — combined with `commit` to
    ///   re-commit even if already tracked.
    /// - `zone <0–65535>` — connection-tracking zone.
    /// - `mark <m> <mask>` — mark + mask (two values; mask
    ///   defaults to `0xffffffff` if omitted via the typed
    ///   builder, but `parse_params` requires both for clarity).
    /// - `label <hex>[/<hex>]` — the 128-bit conntrack label and its
    ///   mask as tc(8) writes them: up to 32 hex digits each, first byte
    ///   first, the rest zero; the mask is all ones without one.
    /// - `nat src <addr>` / `nat dst <addr>` — single-address
    ///   SNAT / DNAT, IPv4 or IPv6.
    /// - `nat src <min>-<max>` / `nat dst <min>-<max>` — address-range
    ///   NAT, both ends of one family.
    /// - `port <port>[-<port>]` — the NAT port range.
    /// - `helper <family>-<proto>-<name>` — a conntrack helper, as tc(8)
    ///   writes one (`ipv4-tcp-ftp`); the family is `ipv4`, `ipv6` or a
    ///   number, the protocol `tcp`, `udp` or a number.
    /// - A verdict (`pass`, `drop`, `pipe`, `reclassify`, `stolen`,
    ///   `continue`); `pipe` without one.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        // First pass: pick the entry-point constructor (commit /
        // clear / restore-default).
        let op = params.iter().copied().find_map(|t| match t {
            "commit" => Some("commit"),
            "clear" => Some("clear"),
            _ => None,
        });
        let mut act = match op {
            Some("commit") => Self::commit(),
            Some("clear") => Self::clear(),
            _ => Self::new(),
        };

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "commit" | "clear" => i += 1, // already consumed above
                v if is_verdict(v) => {
                    act = act.action(parse_gact_verdict(v)?);
                    i += 1;
                }
                "force" => {
                    act = act.force();
                    i += 1;
                }
                "zone" => {
                    let s = action_need_value(params, i, "ct", key)?;
                    let z = action_parse_u32("ct", "zone", s)?;
                    if z > u16::MAX as u32 {
                        return Err(Error::invalid_message(format!(
                            "ct: zone `{z}` out of range (0–65535)"
                        )));
                    }
                    act = act.zone(z as u16);
                    i += 2;
                }
                "mark" => {
                    let mark_s = action_need_value(params, i, "ct", key)?;
                    // tc-ct(8)'s `MARK[/MASK]`; nlink's `<value> <mask>`
                    // reads too (#817). Without a mask, all of the mark.
                    let (m, mk, used) = match mark_s.split_once('/') {
                        Some((m, mk)) => (
                            action_parse_u32_any("ct", "mark", m)?,
                            action_parse_u32_any("ct", "mark mask", mk)?,
                            2,
                        ),
                        None => match params.get(i + 2).filter(|s| action_parse_u32_any("ct", "mark mask", s).is_ok()) {
                            Some(mk) => (action_parse_u32_any("ct", "mark", mark_s)?, action_parse_u32_any("ct", "mark mask", mk)?, 3),
                            None => (action_parse_u32_any("ct", "mark", mark_s)?, u32::MAX, 2),
                        },
                    };
                    act = act.mark(m, mk);
                    i += used;
                }
                "nat" => {
                    // tc-ct(8): `nat [src|dst addr <addr>[-<addr>]]`. The
                    // `addr` keyword was not read until 0.32 (#751), and a
                    // range without it still is; a bare `nat` NATs as the
                    // conntrack entry says.
                    let src = match params.get(i + 1).copied() {
                        Some("src") => true,
                        Some("dst") => false,
                        _ => {
                            act = act.nat();
                            i += 1;
                            continue;
                        }
                    };
                    let dir = params[i + 1];
                    let mut at = i + 2;
                    if params.get(at) == Some(&"addr") {
                        at += 1;
                    }
                    let range_s = params.get(at).copied().ok_or_else(|| {
                        Error::invalid_message(format!(
                            "ct: `nat {dir} addr` requires an address or `<min>-<max>` range"
                        ))
                    })?;
                    act = match parse_ip_range_or_single(range_s)? {
                        (IpAddr::V4(min), IpAddr::V4(max)) if src => act.nat_src(min, max),
                        (IpAddr::V4(min), IpAddr::V4(max)) => act.nat_dst(min, max),
                        (IpAddr::V6(min), IpAddr::V6(max)) if src => act.nat_src6(min, max),
                        (IpAddr::V6(min), IpAddr::V6(max)) => act.nat_dst6(min, max),
                        _ => {
                            return Err(Error::invalid_message(format!(
                                "ct: NAT range `{range_s}` mixes IPv4 and IPv6"
                            )));
                        }
                    };
                    i = at + 1;
                }
                "port" => {
                    let s = action_need_value(params, i, "ct", key)?;
                    let (min_s, max_s) = s.split_once('-').unwrap_or((s, s));
                    let port = |p: &str| {
                        p.parse::<u16>().map_err(|_| {
                            Error::invalid_message(format!(
                                "ct: invalid NAT port `{p}` (expected 0–65535)"
                            ))
                        })
                    };
                    act = act.nat_port_range(port(min_s)?, port(max_s)?);
                    i += 2;
                }
                "label" => {
                    let s = action_need_value(params, i, "ct", key)?;
                    let (label, mask) = match s.split_once('/') {
                        Some((label, mask)) => {
                            (ct_label("label", label)?, ct_label("label mask", mask)?)
                        }
                        None => (ct_label("label", s)?, [0xff; 16]),
                    };
                    act = act.labels(label, mask);
                    i += 2;
                }
                "helper" => {
                    let s = action_need_value(params, i, "ct", key)?;
                    let invalid = || {
                        Error::invalid_message(format!(
                            "ct: invalid helper `{s}` (expected <family>-<proto>-<name>, such \
                             as ipv4-tcp-ftp)"
                        ))
                    };
                    let mut parts = s.splitn(3, '-');
                    let (Some(family), Some(proto), Some(name)) =
                        (parts.next(), parts.next(), parts.next())
                    else {
                        return Err(invalid());
                    };
                    let family = match family {
                        "ipv4" => libc::AF_INET as u8,
                        "ipv6" => libc::AF_INET6 as u8,
                        n => n.parse::<u8>().map_err(|_| invalid())?,
                    };
                    let proto = match proto {
                        "tcp" => libc::IPPROTO_TCP as u8,
                        "udp" => libc::IPPROTO_UDP as u8,
                        n => n.parse::<u8>().map_err(|_| invalid())?,
                    };
                    if name.is_empty() {
                        return Err(invalid());
                    }
                    act = act.helper(name, family, proto);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "ct: unknown token `{other}` (recognised: commit, clear, force, zone, mark <v> <m>, label <hex>[/<hex>], nat src|dst <addr>|<min>-<max>, port <p>[-<p>], helper <family>-<proto>-<name>, a verdict)"
                    )));
                }
            }
        }
        Ok(act)
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for CtAction {
    fn kind(&self) -> &'static str {
        "ct"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        use ct::{
            TCA_CT_ACT_CLEAR as CLEAR, TCA_CT_ACT_COMMIT as COMMIT, TCA_CT_ACT_FORCE as FORCE,
            TCA_CT_ACT_NAT as NAT, TCA_CT_ACT_NAT_DST as NAT_DST, TCA_CT_ACT_NAT_SRC as NAT_SRC,
        };
        let flags = self.ct_action;
        let no_token = |what: &str| Error::not_supported(format!("ct: {what} has no token"));
        if flags & !(COMMIT | FORCE | CLEAR | NAT | NAT_SRC | NAT_DST) != 0
            || flags & (COMMIT | CLEAR) == COMMIT | CLEAR
        {
            return Err(no_token(&format!("action flags {flags:#x}")));
        }
        let mut out = Vec::new();
        for (flag, token) in [(COMMIT, "commit"), (CLEAR, "clear"), (FORCE, "force")] {
            if flags & flag != 0 {
                out.push(token.to_string());
            }
        }
        if let Some(zone) = self.zone {
            out.extend(kv("zone", zone));
        }
        match (self.mark, self.mark_mask) {
            (Some(mark), Some(mask)) => {
                out.extend(kv("mark", format!("{mark}/{mask:#x}")));
            }
            (None, None) => {}
            _ => return Err(no_token("a mark without its mask")),
        }
        match (&self.labels, &self.labels_mask) {
            (Some(label), Some(mask)) => out.extend(kv(
                "label",
                format!("{}/{}", ct_label_token(label), ct_label_token(mask)),
            )),
            (None, None) => {}
            _ => return Err(no_token("a label without its mask")),
        }

        // NAT: `nat <dir> <range>` for each direction and family set. Each
        // sets its direction's flag and its family's range, so together
        // they give back these flags and ranges.
        fn range<A: std::fmt::Display + PartialEq>(
            min: Option<A>,
            max: Option<A>,
        ) -> Result<Option<String>> {
            match (min, max) {
                (Some(min), Some(max)) if min == max => Ok(Some(min.to_string())),
                (Some(min), Some(max)) => Ok(Some(format!("{min}-{max}"))),
                (None, None) => Ok(None),
                _ => Err(Error::not_supported(
                    "ct: one end of a NAT range has no token".to_string(),
                )),
            }
        }
        let ranges: Vec<String> = [
            range(self.nat_ipv4_min, self.nat_ipv4_max)?,
            range(self.nat_ipv6_min, self.nat_ipv6_max)?,
        ]
        .into_iter()
        .flatten()
        .collect();
        let dirs: Vec<&str> = [(NAT_SRC, "src"), (NAT_DST, "dst")]
            .into_iter()
            .filter(|(flag, _)| flags & flag != 0)
            .map(|(_, dir)| dir)
            .collect();
        if flags & NAT != 0 || !dirs.is_empty() || !ranges.is_empty() {
            if flags & NAT == 0 || dirs.is_empty() != ranges.is_empty() {
                return Err(no_token("NAT without a direction and an address"));
            }
            if dirs.is_empty() {
                out.push("nat".to_string());
            }
            for dir in &dirs {
                for range in &ranges {
                    out.extend([
                        "nat".to_string(),
                        dir.to_string(),
                        "addr".to_string(),
                        range.clone(),
                    ]);
                }
            }
        }
        if let Some(ports) = range(self.nat_port_min, self.nat_port_max)? {
            out.extend(kv("port", ports));
        }

        match (&self.helper_name, self.helper_family, self.helper_proto) {
            (Some(name), Some(family), Some(proto)) => {
                if name.is_empty() {
                    return Err(Error::invalid_message(
                        "ct: a helper needs a name".to_string(),
                    ));
                }
                let family = match family {
                    f if f == libc::AF_INET as u8 => "ipv4".to_string(),
                    f if f == libc::AF_INET6 as u8 => "ipv6".to_string(),
                    f => f.to_string(),
                };
                let proto = match proto {
                    p if p == libc::IPPROTO_TCP as u8 => "tcp".to_string(),
                    p if p == libc::IPPROTO_UDP as u8 => "udp".to_string(),
                    p => p.to_string(),
                };
                out.extend(kv("helper", format!("{family}-{proto}-{name}")));
            }
            (None, None, None) => {}
            _ => return Err(no_token("a partial helper")),
        }
        push_verdict(&mut out, "ct", self.action, action::TC_ACT_PIPE)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        let parms = ct::TcCt::new(self.action);
        builder.append_attr(ct::TCA_CT_PARMS, parms.as_bytes());

        if self.ct_action != 0 {
            builder.append_attr(ct::TCA_CT_ACTION, &self.ct_action.to_ne_bytes());
        }

        if let Some(zone) = self.zone {
            builder.append_attr(ct::TCA_CT_ZONE, &zone.to_ne_bytes());
        }

        if let Some(mark) = self.mark {
            builder.append_attr(ct::TCA_CT_MARK, &mark.to_ne_bytes());
        }

        if let Some(mask) = self.mark_mask {
            builder.append_attr(ct::TCA_CT_MARK_MASK, &mask.to_ne_bytes());
        }

        if let Some(labels) = &self.labels {
            builder.append_attr(ct::TCA_CT_LABELS, labels);
        }

        if let Some(mask) = &self.labels_mask {
            builder.append_attr(ct::TCA_CT_LABELS_MASK, mask);
        }

        if let Some(addr) = self.nat_ipv4_min {
            builder.append_attr(ct::TCA_CT_NAT_IPV4_MIN, &addr.octets());
        }

        if let Some(addr) = self.nat_ipv4_max {
            builder.append_attr(ct::TCA_CT_NAT_IPV4_MAX, &addr.octets());
        }

        if let Some(addr) = self.nat_ipv6_min {
            builder.append_attr(ct::TCA_CT_NAT_IPV6_MIN, &addr.octets());
        }

        if let Some(addr) = self.nat_ipv6_max {
            builder.append_attr(ct::TCA_CT_NAT_IPV6_MAX, &addr.octets());
        }

        if let Some(port) = self.nat_port_min {
            builder.append_attr(ct::TCA_CT_NAT_PORT_MIN, &port.to_be_bytes());
        }

        if let Some(port) = self.nat_port_max {
            builder.append_attr(ct::TCA_CT_NAT_PORT_MAX, &port.to_be_bytes());
        }

        if let Some(name) = &self.helper_name {
            builder.append_attr_str(ct::TCA_CT_HELPER_NAME, name);
        }

        if let Some(family) = self.helper_family {
            builder.append_attr(ct::TCA_CT_HELPER_FAMILY, &[family]);
        }

        if let Some(proto) = self.helper_proto {
            builder.append_attr(ct::TCA_CT_HELPER_PROTO, &[proto]);
        }

        Ok(())
    }
}

// ============================================================================
// PeditAction (Packet Edit)
// ============================================================================

/// Pedit (Packet Edit) action configuration.
///
/// The pedit action allows direct modification of packet header fields.
/// It supports editing Ethernet, IPv4, IPv6, TCP, and UDP headers.
///
/// # Example
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::action::PeditAction;
///
/// // Set IPv4 source address
/// let pedit = PeditAction::new()
///     .set_ipv4_src("10.0.0.1".parse()?)
///     .build();
///
/// // Set IPv4 destination address
/// let pedit = PeditAction::new()
///     .set_ipv4_dst("10.0.0.2".parse()?)
///     .build();
///
/// // Set TCP destination port
/// let pedit = PeditAction::new()
///     .set_tcp_dport(8080)
///     .build();
///
/// // Set Ethernet source MAC
/// let pedit = PeditAction::new()
///     .set_eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
///     .build();
///
/// // Multiple edits
/// let pedit = PeditAction::new()
///     .set_ipv4_src("10.0.0.1".parse()?)
///     .set_ipv4_dst("10.0.0.2".parse()?)
///     .set_tcp_dport(8080)
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct PeditAction {
    /// List of edit operations.
    keys: Vec<PeditKey>,
    /// Action result.
    action: i32,
}

/// A single packet edit key.
#[derive(Debug, Clone, PartialEq)]
struct PeditKey {
    /// Header type.
    htype: u16,
    /// Command (SET or ADD).
    cmd: u16,
    /// Mask of bits to modify.
    mask: u32,
    /// Value to set.
    val: u32,
    /// Offset within the header.
    off: u32,
}

impl Default for PeditAction {
    fn default() -> Self {
        Self::new()
    }
}

impl PeditAction {
    /// Create a new pedit action.
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set IPv4 source address.
    pub fn set_ipv4_src(mut self, addr: Ipv4Addr) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes(addr.octets()),
            off: 12, // Offset of src in IPv4 header
        });
        self
    }

    /// Set IPv4 destination address.
    pub fn set_ipv4_dst(mut self, addr: Ipv4Addr) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes(addr.octets()),
            off: 16, // Offset of dst in IPv4 header
        });
        self
    }

    /// Set IPv4 TOS/DSCP field.
    pub fn set_ipv4_tos(mut self, tos: u8) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            // Wire byte 1 of the word at offset 0 ([ver_ihl, tos, len_hi,
            // len_lo]), i.e. bits 16..23 read big-endian. This used to be
            // `<< 24` with mask 0x00ff_ffff, which addresses byte 0 — the
            // version/IHL nibble — not the TOS (#262).
            mask: 0xff00_ffff,
            val: (tos as u32) << 16,
            off: 0,
        });
        self
    }

    /// Set IPv4 TTL field.
    pub fn set_ipv4_ttl(mut self, ttl: u8) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_IP4,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            // Wire byte 0 of the word at offset 8 ([ttl, proto, csum_hi,
            // csum_lo]), i.e. bits 24..31 read big-endian. This used to be
            // `<< 8` with mask 0xffff_00ff, which addresses byte 2 — the high
            // half of the header checksum (#262).
            mask: 0x00ff_ffff,
            val: (ttl as u32) << 24,
            off: 8,
        });
        self
    }

    /// Set TCP source port.
    pub fn set_tcp_sport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: (port as u32) << 16,
            off: 0, // Source port at offset 0
        });
        self
    }

    /// Set TCP destination port.
    pub fn set_tcp_dport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_TCP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0xffff_0000,
            val: port as u32,
            off: 0, // Dest port at offset 2, but we need aligned access
        });
        self
    }

    /// Set UDP source port.
    pub fn set_udp_sport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: (port as u32) << 16,
            off: 0,
        });
        self
    }

    /// Set UDP destination port.
    pub fn set_udp_dport(mut self, port: u16) -> Self {
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_UDP,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0xffff_0000,
            val: port as u32,
            off: 0,
        });
        self
    }

    /// Set Ethernet source MAC address.
    pub fn set_eth_src(mut self, mac: [u8; 6]) -> Self {
        // First 4 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]),
            off: 6, // Src MAC starts at offset 6
        });
        // Last 2 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: ((mac[4] as u32) << 24) | ((mac[5] as u32) << 16),
            off: 10,
        });
        self
    }

    /// Set Ethernet destination MAC address.
    pub fn set_eth_dst(mut self, mac: [u8; 6]) -> Self {
        // First 4 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0,
            val: u32::from_be_bytes([mac[0], mac[1], mac[2], mac[3]]),
            off: 0, // Dst MAC starts at offset 0
        });
        // Last 2 bytes of MAC
        self.keys.push(PeditKey {
            htype: pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_ETH,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask: 0x0000_ffff,
            val: ((mac[4] as u32) << 24) | ((mac[5] as u32) << 16),
            off: 4,
        });
        self
    }

    /// Add a raw edit at a specific offset.
    pub fn set_raw(mut self, htype: u16, off: u32, val: u32, mask: u32) -> Self {
        self.keys.push(PeditKey {
            htype,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_SET,
            mask,
            val,
            off,
        });
        self
    }

    /// Add a value at a specific offset.
    pub fn add_raw(mut self, htype: u16, off: u32, val: u32, mask: u32) -> Self {
        self.keys.push(PeditKey {
            htype,
            cmd: pedit::TCA_PEDIT_KEY_EX_CMD_ADD,
            mask,
            val,
            off,
        });
        self
    }

    /// Set action result (default: pipe).
    pub fn action(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse the `tc(8)` pedit `munge` DSL.
    ///
    /// Grammar (strict; any unknown token or unmodelled op is an
    /// error, never a silent skip — see `CLAUDE.md ## parse_params
    /// contract`):
    ///
    /// ```text
    /// [ex] munge <LAYERED|RAW> [munge ...] [<CONTROL>]
    ///   LAYERED := (ip (src|dst) set <ipv4>)
    ///            | (ip (ttl|tos|dsfield) set <u8>)
    ///            | ((tcp|udp) (sport|dport) set <u16>)
    ///            | (eth (src|dst) set <mac>)
    ///   RAW     := offset <off> [u8|u16|u32] (set|add) <u32> [retain <mask>]
    ///   CONTROL := pass|ok|drop|shot|pipe|reclassify|stolen|continue
    /// ```
    ///
    /// Values accept decimal or `0x`-prefixed hex. Forms the typed
    /// builder doesn't model (e.g. `ip6`, the `clear`/`invert`/`or`/
    /// `and`/`xor` ops) return a "not modelled" error pointing at
    /// [`PeditAction::set_raw`] / [`add_raw`](PeditAction::add_raw)
    /// rather than being skipped.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut a = Self::new().action(action::TC_ACT_OK);
        let mut any = false;
        let mut i = 0;
        while i < params.len() {
            match params[i] {
                // Extended-mode flag — nlink always emits KEYS_EX, so
                // accept and ignore it.
                "ex" => {
                    i += 1;
                }
                "munge" => {
                    let (next, consumed) = a.parse_one_munge(&params[i + 1..])?;
                    a = next;
                    i += 1 + consumed;
                    any = true;
                }
                // A bare verdict keyword terminates the spec as the
                // control action.
                "pass" | "ok" | "drop" | "shot" | "pipe" | "reclassify" | "stolen" | "continue" => {
                    a.action = parse_gact_verdict(params[i])?;
                    i += 1;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "pedit: unexpected token `{other}` (expected `munge` or a control \
                         verdict like pipe/pass/drop)"
                    )));
                }
            }
        }
        if !any {
            return Err(Error::invalid_message(
                "pedit: requires at least one `munge <field> set <value>` spec".to_string(),
            ));
        }
        Ok(a)
    }

    /// Parse a single `munge` spec from the front of `rest` (the
    /// tokens *after* the `munge` keyword). Returns the updated action
    /// and the number of tokens consumed.
    fn parse_one_munge(self, rest: &[&str]) -> Result<(Self, usize)> {
        let layer = rest.first().copied().ok_or_else(|| {
            Error::invalid_message("pedit: `munge` requires a field spec".to_string())
        })?;

        // Raw form: `offset <off> [u8|u16|u32] (set|add) <u32> [retain <mask>]`
        if layer == "offset" {
            return self.parse_raw_munge(rest);
        }

        // Layered form: `<layer> <field> set <value>` — 4 tokens.
        let field = rest.get(1).copied().ok_or_else(|| {
            Error::invalid_message(format!("pedit: `munge {layer}` requires a field name"))
        })?;
        let op = rest.get(2).copied().ok_or_else(|| {
            Error::invalid_message(format!("pedit: `munge {layer} {field}` requires an op"))
        })?;
        let value = rest.get(3).copied().ok_or_else(|| {
            Error::invalid_message(format!(
                "pedit: `munge {layer} {field} {op}` requires a value"
            ))
        })?;
        if op != "set" {
            return Err(Error::invalid_message(format!(
                "pedit: op `{op}` on `{layer} {field}` is not modelled by the typed builder — \
                 use `munge offset <off> {op} <val>` or PeditAction::set_raw / add_raw"
            )));
        }

        let a = match (layer, field) {
            ("ip", "src") => self.set_ipv4_src(pedit_ipv4(layer, field, value)?),
            ("ip", "dst") => self.set_ipv4_dst(pedit_ipv4(layer, field, value)?),
            ("ip", "ttl") => self.set_ipv4_ttl(pedit_u8(layer, field, value)?),
            ("ip", "tos" | "dsfield") => self.set_ipv4_tos(pedit_u8(layer, field, value)?),
            ("tcp", "sport") => self.set_tcp_sport(pedit_u16(layer, field, value)?),
            ("tcp", "dport") => self.set_tcp_dport(pedit_u16(layer, field, value)?),
            ("udp", "sport") => self.set_udp_sport(pedit_u16(layer, field, value)?),
            ("udp", "dport") => self.set_udp_dport(pedit_u16(layer, field, value)?),
            ("eth", "src") => self.set_eth_src(pedit_mac(layer, field, value)?),
            ("eth", "dst") => self.set_eth_dst(pedit_mac(layer, field, value)?),
            _ => {
                return Err(Error::invalid_message(format!(
                    "pedit: `{layer} {field}` is not modelled by the typed builder \
                     (modelled: ip src|dst|ttl|tos, tcp/udp sport|dport, eth src|dst) — \
                     use `munge offset <off> set <val> [retain <mask>]` for raw edits"
                )));
            }
        };
        Ok((a, 4))
    }

    /// Parse `offset <off> [u8|u16|u32] (set|add) <u32> [retain <mask>]`.
    fn parse_raw_munge(self, rest: &[&str]) -> Result<(Self, usize)> {
        // rest[0] == "offset"
        let off = rest.get(1).copied().ok_or_else(|| {
            Error::invalid_message("pedit: `munge offset` requires an offset".to_string())
        })?;
        let off = pedit_u32("offset", "offset", off)?;

        let mut idx = 2;
        // Optional size keyword.
        if matches!(rest.get(idx).copied(), Some("u8" | "u16" | "u32")) {
            idx += 1;
        }

        let op = rest.get(idx).copied().ok_or_else(|| {
            Error::invalid_message("pedit: `munge offset` requires `set` or `add`".to_string())
        })?;
        let value = rest.get(idx + 1).copied().ok_or_else(|| {
            Error::invalid_message(format!("pedit: `munge offset {off} {op}` requires a value"))
        })?;
        let val = pedit_u32("offset", "value", value)?;
        idx += 2;

        // Optional `retain <mask>` — defaults to 0 (write the whole word).
        let mask = if matches!(rest.get(idx).copied(), Some("retain")) {
            let m = rest.get(idx + 1).copied().ok_or_else(|| {
                Error::invalid_message("pedit: `retain` requires a mask value".to_string())
            })?;
            idx += 2;
            pedit_u32("offset", "retain", m)?
        } else {
            0
        };

        let htype = pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
        let a = match op {
            "set" => self.set_raw(htype, off, val, mask),
            "add" => self.add_raw(htype, off, val, mask),
            other => {
                return Err(Error::invalid_message(format!(
                    "pedit: op `{other}` on `offset` is not modelled (expected set or add)"
                )));
            }
        };
        Ok((a, idx))
    }

    /// The `munge` spec (the tokens after `munge`) for the edit at the
    /// front of `keys`, and how many keys it stands for: a field when its
    /// setter writes exactly these keys, else a raw `offset` edit.
    fn munge_tokens(keys: &[PeditKey]) -> Result<(Vec<String>, usize)> {
        use crate::util::addr::format_mac;
        let key = &keys[0];
        let addr = Ipv4Addr::from(key.val);
        let (hi8, hi16, lo16) = ((key.val >> 24) as u8, (key.val >> 16) as u16, key.val as u16);
        let tos = (key.val >> 16) as u8;
        let mut fields = vec![
            ("ip", "src", addr.to_string(), Self::new().set_ipv4_src(addr)),
            ("ip", "dst", addr.to_string(), Self::new().set_ipv4_dst(addr)),
            ("ip", "ttl", hi8.to_string(), Self::new().set_ipv4_ttl(hi8)),
            ("ip", "tos", tos.to_string(), Self::new().set_ipv4_tos(tos)),
            ("tcp", "sport", hi16.to_string(), Self::new().set_tcp_sport(hi16)),
            ("tcp", "dport", lo16.to_string(), Self::new().set_tcp_dport(lo16)),
            ("udp", "sport", hi16.to_string(), Self::new().set_udp_sport(hi16)),
            ("udp", "dport", lo16.to_string(), Self::new().set_udp_dport(lo16)),
        ];
        // A MAC is two keys: four bytes, then two in the next word's top.
        if let Some(next) = keys.get(1) {
            let (a, b) = (key.val.to_be_bytes(), next.val.to_be_bytes());
            let mac = [a[0], a[1], a[2], a[3], b[0], b[1]];
            fields.push(("eth", "src", format_mac(&mac), Self::new().set_eth_src(mac)));
            fields.push(("eth", "dst", format_mac(&mac), Self::new().set_eth_dst(mac)));
        }
        for (layer, field, value, edit) in fields {
            if keys.starts_with(&edit.keys) {
                let tokens = vec![layer.to_string(), field.to_string(), "set".to_string(), value];
                return Ok((tokens, edit.keys.len()));
            }
        }

        // `munge offset` edits the network header; another header type is
        // a field above or nothing the grammar can say.
        if key.htype != pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK {
            return Err(Error::not_supported(format!(
                "pedit: a raw edit at offset {} of header type {} has no token",
                key.off, key.htype
            )));
        }
        let op = match key.cmd {
            pedit::TCA_PEDIT_KEY_EX_CMD_SET => "set",
            pedit::TCA_PEDIT_KEY_EX_CMD_ADD => "add",
            other => {
                return Err(Error::not_supported(format!(
                    "pedit: edit command {other} has no token"
                )));
            }
        };
        let mut tokens = vec![
            "offset".to_string(),
            key.off.to_string(),
            op.to_string(),
            format!("{:#x}", key.val),
        ];
        if key.mask != 0 {
            tokens.extend(kv("retain", format!("{:#x}", key.mask)));
        }
        Ok((tokens, 1))
    }

    /// Build the action configuration.
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for PeditAction {
    fn kind(&self) -> &'static str {
        "pedit"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        if self.keys.is_empty() {
            return Err(Error::invalid_message(
                "pedit: requires at least one `munge <field> set <value>` spec".to_string(),
            ));
        }
        let mut out = Vec::new();
        let mut keys = &self.keys[..];
        while !keys.is_empty() {
            let (tokens, used) = Self::munge_tokens(keys)?;
            out.push("munge".to_string());
            out.extend(tokens);
            keys = &keys[used..];
        }
        // Against what `parse_params` starts from, tc's `pass` (#817).
        push_verdict(&mut out, "pedit", self.action, action::TC_ACT_OK)?;
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        if self.keys.is_empty() {
            return Err(Error::invalid_message(
                "pedit requires at least one key",
            ));
        }

        // Build the selector header + keys
        let sel = pedit::TcPeditSel::new(self.action, self.keys.len() as u8);

        // We need to write TCA_PEDIT_PARMS_EX which includes sel + keys
        let mut parms_data = Vec::new();
        parms_data.extend_from_slice(sel.as_bytes());

        // Append each key.
        //
        // `val`/`mask` are authored above as big-endian-read integers — the
        // header field laid out as you would read it on the wire — and
        // `struct tc_pedit_key` is serialized natively. So each needs the
        // swap here, exactly as iproute2's `pack_key32()` ends with `htonl()`.
        //
        // Without it every edit landed byte-reversed on little-endian:
        // `set_ipv4_src(10.0.0.1)` rewrote the address to 1.0.0.10 (#262).
        for key in &self.keys {
            let k = pedit::TcPeditKey::new(key.mask.to_be(), key.val.to_be(), key.off);
            parms_data.extend_from_slice(k.as_bytes());
        }

        builder.append_attr(pedit::TCA_PEDIT_PARMS_EX, &parms_data);

        // Write extended key info (header type and command for each key)
        let keys_ex_token = builder.nest_start(pedit::TCA_PEDIT_KEYS_EX);
        for key in &self.keys {
            let key_ex_token = builder.nest_start(pedit::TCA_PEDIT_KEY_EX);
            builder.append_attr(pedit::TCA_PEDIT_KEY_EX_HTYPE, &key.htype.to_ne_bytes());
            builder.append_attr(pedit::TCA_PEDIT_KEY_EX_CMD, &key.cmd.to_ne_bytes());
            builder.nest_end(key_ex_token);
        }
        builder.nest_end(keys_ex_token);

        Ok(())
    }
}

// ============================================================================
// Estimator - the rate estimator a filter gives its actions
// ============================================================================

/// A rate estimator for a filter's actions (tc(8) `estimator <interval>
/// <time constant>`, #792).
///
/// The kernel measures each action's rate with it, and a
/// [`PoliceAction::avrate`] needs one: without it the kernel refuses the
/// filter with a bare `EINVAL`. It travels on the filter request as
/// `TCA_RATE`, and every action the filter creates gets one. Attach it with
/// [`ActionList::with_estimator`].
///
/// ```no_run
/// # async fn example() -> nlink::Result<()> {
/// use std::time::Duration;
///
/// use nlink::netlink::action::{ActionList, Estimator, PoliceAction};
/// use nlink::netlink::filter::MatchallFilter;
/// use nlink::{Bytes, Connection, Rate, Route, TcHandle};
///
/// let conn = Connection::<Route>::new()?;
/// let police = PoliceAction::new()
///     .rate(Rate::mbit(10))
///     .burst(Bytes::kib(64))
///     .avrate(Rate::mbit(8));
/// let actions = ActionList::new()
///     .with_estimator(Estimator::new(Duration::from_secs(1), Duration::from_secs(8))?)
///     .with(police);
/// let filter = MatchallFilter::new().actions(actions);
/// conn.add_filter("eth0", TcHandle::INGRESS, filter).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimator {
    /// log2 of the interval in seconds, -2..=3.
    interval: i8,
    /// log2 of the time constant in intervals, 1..=30.
    ewma_log: u8,
}

impl Estimator {
    /// Sample every `interval` and average over about `time_constant`, as
    /// tc(8) does: the interval is rounded up to a power of two from 250 ms
    /// to 8 s, and the time constant down to the interval times the largest
    /// power of two `2ⁿ` that fits it (`n` from 1 to 30).
    ///
    /// # Errors
    ///
    /// [`ErrorDetail::InvalidMessage`](crate::ErrorDetail::InvalidMessage)
    /// for an interval that is zero or over 8 s, or a time constant under
    /// twice the interval or over 2³⁰ of them.
    pub fn new(interval: std::time::Duration, time_constant: std::time::Duration) -> Result<Self> {
        use crate::util::parse::format_time;
        let a = interval.as_micros();
        let step = (0..=5u32)
            .find(|&i| a > 0 && a <= 250_000u128 << i)
            .ok_or_else(|| {
                Error::invalid_message(format!(
                    "estimator: interval `{}` (expected over 0 and at most 8s)",
                    format_time(interval)
                ))
            })?;
        let constant = time_constant.as_micros();
        // The first n with interval × 2ⁿ over the time constant, less one.
        let ewma_log = (1..32u32).find(|&n| a << n > constant).unwrap_or(32) - 1;
        if !(1..=30).contains(&ewma_log) {
            return Err(Error::invalid_message(format!(
                "estimator: time constant `{}` for interval `{}` (expected 2 to 2^30 intervals)",
                format_time(time_constant),
                format_time(interval)
            )));
        }
        Ok(Self {
            interval: step as i8 - 2,
            ewma_log: ewma_log as u8,
        })
    }

    /// The sampling interval: a power of two from 250 ms to 8 s.
    pub fn interval(&self) -> std::time::Duration {
        std::time::Duration::from_millis(250 << (self.interval + 2))
    }

    /// The averaging time constant: the interval times a power of two.
    pub fn time_constant(&self) -> std::time::Duration {
        self.interval() * (1u32 << self.ewma_log)
    }

    /// Parse tc(8)'s words for one: `<interval> <time constant>`
    /// (`1sec 8sec`).
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let time = |s: &str| {
            crate::util::parse::get_time(s).map_err(|_| {
                Error::invalid_message(format!(
                    "estimator: invalid time `{s}` (expected tc-style time)"
                ))
            })
        };
        match params {
            [interval, constant] => Self::new(time(interval)?, time(constant)?),
            _ => Err(Error::invalid_message(format!(
                "estimator: `{}` (expected `<interval> <time constant>`)",
                params.join(" ")
            ))),
        }
    }

    /// The kernel's `struct tc_estimator`.
    pub(crate) fn parms(&self) -> crate::netlink::types::tc::TcEstimator {
        crate::netlink::types::tc::TcEstimator {
            interval: self.interval,
            ewma_log: self.ewma_log,
        }
    }
}

impl std::fmt::Display for Estimator {
    /// tc(8)'s words, which [`parse_params`](Self::parse_params) reads back.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::util::parse::format_time;
        write!(f, "{} {}", format_time(self.interval()), format_time(self.time_constant()))
    }
}

// ============================================================================
// ActionList - for building action chains
// ============================================================================

/// A list of actions to attach to a filter.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::netlink::action::{ActionList, GactAction, MirredAction};
///
/// // Resolve the interface name to an index through the connection,
/// // which is namespace-safe.
/// let conn = nlink::Connection::<nlink::Route>::new()?;
/// let link = conn
///     .get_link_by_name("eth1")
///     .await?
///     .ok_or("eth1 not found")?;
///
/// let actions = ActionList::new()
///     .with(MirredAction::mirror_to_egress(link.ifindex()))
///     .with(GactAction::pass())
///     .build();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct ActionList {
    actions: Vec<Box<dyn ActionConfigDyn>>,
    estimator: Option<Estimator>,
}

/// Trait for dynamic action dispatch.
pub trait ActionConfigDyn: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> &'static str;
    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()>;
    fn clone_box(&self) -> Box<dyn ActionConfigDyn>;
    /// [`ActionConfig::device_names`].
    fn device_names(&self) -> Vec<&str> {
        Vec::new()
    }
    /// [`ActionConfig::resolve_devices`].
    fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
        let _ = ifindexes;
        Ok(())
    }
    /// [`ActionConfig::to_params`].
    fn to_params(&self) -> Result<Vec<String>> {
        Err(Error::not_supported(format!(
            "{}: the action has no token form",
            self.kind()
        )))
    }
}

impl<T: ActionConfig + Clone + std::fmt::Debug + 'static> ActionConfigDyn for T {
    fn kind(&self) -> &'static str {
        ActionConfig::kind(self)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        ActionConfig::write_options(self, builder)
    }

    fn device_names(&self) -> Vec<&str> {
        ActionConfig::device_names(self)
    }

    fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
        ActionConfig::resolve_devices(self, ifindexes)
    }

    fn to_params(&self) -> Result<Vec<String>> {
        ActionConfig::to_params(self)
    }

    fn clone_box(&self) -> Box<dyn ActionConfigDyn> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn ActionConfigDyn> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl ActionList {
    /// Create a new empty action list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an action to the list.
    pub fn with<T: ActionConfig + Clone + std::fmt::Debug + 'static>(mut self, action: T) -> Self {
        self.actions.push(Box::new(action));
        self
    }

    /// Give the actions a rate estimator, which a
    /// [`PoliceAction::avrate`] needs (#792). It goes on the filter request
    /// as `TCA_RATE`; the kernel does not report it back.
    pub fn with_estimator(mut self, estimator: Estimator) -> Self {
        self.estimator = Some(estimator);
        self
    }

    /// The rate estimator [`with_estimator`](Self::with_estimator) gave.
    pub fn estimator(&self) -> Option<Estimator> {
        self.estimator
    }

    /// Add an action already boxed: one read from a document (#645).
    #[cfg_attr(not(feature = "serde"), allow(dead_code))]
    pub(crate) fn with_boxed(mut self, action: Box<dyn ActionConfigDyn>) -> Self {
        self.actions.push(action);
        self
    }

    /// Check if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Get the number of actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Each action as its kind and [`ActionConfig::to_params`] tokens.
    #[cfg_attr(not(feature = "serde"), allow(dead_code))]
    pub(crate) fn to_params(&self) -> Result<Vec<(&'static str, Vec<String>)>> {
        self.actions
            .iter()
            .map(|a| Ok((a.kind(), a.to_params()?)))
            .collect()
    }

    /// The devices its actions name rather than index (#645).
    pub fn device_names(&self) -> Vec<&str> {
        self.actions.iter().flat_map(|a| a.device_names()).collect()
    }

    /// Resolve the names [`device_names`](Self::device_names) gave, from
    /// `ifindexes`.
    pub fn resolve_devices(&mut self, ifindexes: &HashMap<String, u32>) -> Result<()> {
        self.actions
            .iter_mut()
            .try_for_each(|a| a.resolve_devices(ifindexes))
    }

    /// Write the action list to a message builder.
    ///
    /// This writes nested TCA_ACT_* attributes for each action.
    pub fn write_to(&self, builder: &mut MessageBuilder) -> Result<()> {
        for (i, action) in self.actions.iter().enumerate() {
            // Each action is nested under TCA_ACT_<index> (1-based)
            let act_token = builder.nest_start((i + 1) as u16);

            // Add kind
            builder.append_attr_str(action::TCA_ACT_KIND, action.kind());

            // Add options
            let opt_token = builder.nest_start(action::TCA_ACT_OPTIONS);
            action.write_options(builder)?;
            builder.nest_end(opt_token);

            builder.nest_end(act_token);
        }
        Ok(())
    }

    /// Build the action list.
    pub fn build(self) -> Self {
        self
    }
}

/// The kinds [`action_from_params`] reads: every action with a
/// [`ActionConfig::to_params`] writer.
const PARAMS_KINDS: [&str; 19] = [
    "gact",
    "mirred",
    "police",
    "vlan",
    "mpls",
    "skbmod",
    "skbedit",
    "nat",
    "tunnel_key",
    "connmark",
    "ctinfo",
    "ife",
    "gate",
    "csum",
    "sample",
    "ct",
    "pedit",
    "bpf",
    "simple",
];

/// An action read from its kind and [`ActionConfig::to_params`] tokens:
/// the kinds that have a token form (#645).
#[cfg_attr(not(feature = "serde"), allow(dead_code))]
pub(crate) fn action_from_params(kind: &str, params: &[&str]) -> Result<Box<dyn ActionConfigDyn>> {
    fn boxed<A: ActionConfig + Clone + std::fmt::Debug + 'static>(
        action: A,
    ) -> Box<dyn ActionConfigDyn> {
        Box::new(action)
    }
    Ok(match kind {
        "gact" => boxed(GactAction::parse_params(params)?),
        "mirred" => boxed(MirredAction::parse_params(params)?),
        "police" => boxed(PoliceAction::parse_params(params)?),
        "vlan" => boxed(VlanAction::parse_params(params)?),
        "mpls" => boxed(MplsAction::parse_params(params)?),
        "skbmod" => boxed(SkbmodAction::parse_params(params)?),
        "skbedit" => boxed(SkbeditAction::parse_params(params)?),
        "nat" => boxed(NatAction::parse_params(params)?),
        "tunnel_key" => boxed(TunnelKeyAction::parse_params(params)?),
        "connmark" => boxed(ConnmarkAction::parse_params(params)?),
        "ctinfo" => boxed(CtinfoAction::parse_params(params)?),
        "ife" => boxed(IfeAction::parse_params(params)?),
        "gate" => boxed(GateAction::parse_params(params)?),
        "csum" => boxed(CsumAction::parse_params(params)?),
        "sample" => boxed(SampleAction::parse_params(params)?),
        "ct" => boxed(CtAction::parse_params(params)?),
        "pedit" => boxed(PeditAction::parse_params(params)?),
        "bpf" => boxed(BpfAction::parse_params(params)?),
        "simple" => boxed(SimpleAction::parse_params(params)?),
        other => {
            return Err(Error::invalid_message(format!(
                "action `{other}` has no document form (kinds: {})",
                PARAMS_KINDS.join(", ")
            )));
        }
    })
}

// ============================================================================
// BpfAction
// ============================================================================

/// `act_bpf` action — run a BPF program for side effects.
///
/// Companion to [`super::filter::BpfFilter`]: where the classifier
/// matches packets, this action runs an eBPF program for side effects
/// like marking, redirecting, or dropping. The action's verdict
/// (TC_ACT_OK / TC_ACT_SHOT / etc.) comes from the BPF program's return
/// value when used in direct-action style, or from the [`BpfAction`]'s
/// configured action when not.
///
/// Programs can be referenced either by file descriptor (e.g. one
/// loaded via `aya` or `libbpf-rs`) or by a pinned filesystem path
/// (`bpftool prog pin /sys/fs/bpf/<name>`).
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::TcHandle;
/// use nlink::netlink::action::{ActionList, BpfAction};
/// use nlink::netlink::filter::MatchallFilter;
///
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// // Attach a pinned BPF program as an action on every matched packet.
/// let bpf = BpfAction::from_pinned("/sys/fs/bpf/my_action")?
///     .name("my_action")
///     .pipe()
///     .build();
///
/// let filter = MatchallFilter::new()
///     .actions(ActionList::new().with(bpf))
///     .build();
/// conn.add_filter("eth0", TcHandle::CLSACT_INGRESS, filter).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct BpfAction {
    /// BPF program file descriptor.
    fd: super::bpf_fd::ProgFd,
    /// The pin `fd` was opened from ([`from_pinned`](Self::from_pinned)),
    /// which is how the action is written as tokens (#645).
    pinned: Option<std::path::PathBuf>,
    /// Optional human-readable program name.
    name: Option<String>,
    /// Verdict for this action (TC_ACT_*).
    action: i32,
}

impl BpfAction {
    /// Create a new `act_bpf` action wrapping the given file descriptor.
    ///
    /// The descriptor must reference a BPF program of type `BPF_PROG_TYPE_SCHED_ACT`.
    /// Loading is the caller's responsibility — use `aya` or `libbpf-rs`.
    /// Default verdict is `TC_ACT_PIPE` (continue to next action).
    ///
    /// The fd is duplicated, so the caller's can be closed; the duplicate
    /// is closed with the last clone of the action (#532).
    pub fn from_fd(fd: impl std::os::fd::AsFd) -> Self {
        Self::with_fd(super::bpf_fd::ProgFd::dup(fd))
    }

    #[cfg(test)]
    fn with_raw_fd(fd: i32) -> Self {
        Self::with_fd(super::bpf_fd::ProgFd::Raw(fd))
    }

    fn with_fd(fd: super::bpf_fd::ProgFd) -> Self {
        Self {
            fd,
            pinned: None,
            name: None,
            action: action::TC_ACT_PIPE,
        }
    }

    /// Open a pinned BPF program at `path` and use its file descriptor.
    ///
    /// The program must be pinned via `bpf_obj_pin()` or
    /// `bpftool prog pin id <id> /sys/fs/bpf/<name>`. It is opened with
    /// `bpf(BPF_OBJ_GET)` — bpffs refuses `open(2)` on a pin (#710) — and
    /// the fd is closed with the last clone of the action. The path is
    /// kept: it is what [`ActionConfig::to_params`] writes.
    pub fn from_pinned(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();
        Ok(Self {
            pinned: Some(path.to_path_buf()),
            ..Self::with_fd(super::bpf_fd::ProgFd::open_pinned(path)?)
        })
    }

    /// Set the program's human-readable name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set verdict to `TC_ACT_PIPE` (continue to next action).
    pub fn pipe(mut self) -> Self {
        self.action = action::TC_ACT_PIPE;
        self
    }

    /// Set verdict to `TC_ACT_OK` (let packet proceed).
    pub fn ok(mut self) -> Self {
        self.action = action::TC_ACT_OK;
        self
    }

    /// Set verdict to `TC_ACT_SHOT` (drop packet).
    #[allow(clippy::should_implement_trait)]
    pub fn drop(mut self) -> Self {
        self.action = action::TC_ACT_SHOT;
        self
    }

    /// Set an arbitrary verdict (escape hatch — prefer the named
    /// helpers above).
    pub fn verdict(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `bpf` token slice into a typed action.
    ///
    /// # Recognised tokens (one program source required)
    ///
    /// - `pinned <path>` — open a pinned BPF program (e.g.
    ///   `/sys/fs/bpf/myprog`); equivalent to
    ///   [`BpfAction::from_pinned`].
    /// - `fd <n>` — wrap a raw file descriptor (advanced; the
    ///   caller is responsible for the program's lifetime).
    /// - `name <text>` — optional human-readable label.
    /// - `verdict pass|drop|pipe|reclassify|stolen|continue` —
    ///   override the default `pipe` verdict.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut source: Option<Self> = None;
        let mut name: Option<String> = None;
        let mut verdict: Option<i32> = None;

        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "pinned" => {
                    let s = action_need_value(params, i, "bpf", key)?;
                    if source.is_some() {
                        return Err(Error::invalid_message(
                            "bpf: only one of `pinned` / `fd` may be specified".to_string(),
                        ));
                    }
                    // The errno survives: ENOENT is not found, EPERM denied (#718).
                    source = Some(Self::from_pinned(s).map_err(|e| {
                        e.with_context(format!("bpf: open pinned program `{s}`"))
                    })?);
                    i += 2;
                }
                "fd" => {
                    let s = action_need_value(params, i, "bpf", key)?;
                    if source.is_some() {
                        return Err(Error::invalid_message(
                            "bpf: only one of `pinned` / `fd` may be specified".to_string(),
                        ));
                    }
                    let fd_u = action_parse_u32("bpf", "fd", s)?;
                    // A number the caller holds open, as tc(8) would.
                    source = Some(Self::with_fd(super::bpf_fd::ProgFd::Raw(fd_u as i32)));
                    i += 2;
                }
                "name" => {
                    let s = action_need_value(params, i, "bpf", key)?;
                    name = Some(s.to_string());
                    i += 2;
                }
                "verdict" => {
                    let s = action_need_value(params, i, "bpf", key)?;
                    verdict = Some(parse_gact_verdict(s).map_err(|e| {
                        // Re-prefix gact: → bpf:.
                        Error::invalid_message(e.to_string().replace("gact:", "bpf:"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "bpf: unknown token `{other}` (recognised: pinned <path>, fd <n>, name <text>, verdict <kw>)"
                    )));
                }
            }
        }

        let mut act = source.ok_or_else(|| {
            Error::invalid_message(
                "bpf: program source required (`pinned <path>` or `fd <n>`)".to_string(),
            )
        })?;
        if let Some(n) = name {
            act = act.name(n);
        }
        if let Some(v) = verdict {
            act = act.verdict(v);
        }
        Ok(act)
    }

    /// Build (no-op marker for API consistency).
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for BpfAction {
    fn kind(&self) -> &'static str {
        "bpf"
    }

    /// `pinned <path>`, for a program opened from its pin. A program
    /// given by file descriptor has no token form: a descriptor names
    /// nothing outside the process that holds it.
    fn to_params(&self) -> Result<Vec<String>> {
        let Some(path) = &self.pinned else {
            return Err(Error::not_supported(
                "bpf: a program given by file descriptor has no token (one opened with \
                 `from_pinned` is written as its path)"
                    .to_string(),
            ));
        };
        let path = path.to_str().ok_or_else(|| {
            Error::not_supported(format!(
                "bpf: the pinned path `{}` is not UTF-8",
                path.display()
            ))
        })?;
        let mut out = kv("pinned", path).to_vec();
        if let Some(name) = &self.name {
            out.extend(kv("name", name));
        }
        if self.action != action::TC_ACT_PIPE {
            out.extend(kv("verdict", verdict_param("bpf", self.action)?));
        }
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::action::bpf_act;

        let parms = bpf_act::TcActBpf::new(self.action);
        builder.append_attr(bpf_act::TCA_ACT_BPF_PARMS, parms.as_bytes());
        builder.append_attr_u32(bpf_act::TCA_ACT_BPF_FD, self.fd.raw()? as u32);
        if let Some(ref name) = self.name {
            builder.append_attr_str(bpf_act::TCA_ACT_BPF_NAME, name);
        }
        Ok(())
    }
}

// ============================================================================
// SimpleAction
// ============================================================================

/// `act_simple` action — emit a tagged debug event.
///
/// `act_simple` writes a tagged string (`sdata`) to the kernel log
/// when a packet hits the action. Useful for tracing filter chains
/// during debugging — install at suspect points and watch the log.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use nlink::TcHandle;
/// use nlink::netlink::action::{ActionList, SimpleAction};
/// use nlink::netlink::filter::MatchallFilter;
///
/// # let conn = nlink::Connection::<nlink::Route>::new()?;
/// let trace = SimpleAction::new("matched-port-80").build();
/// let filter = MatchallFilter::new()
///     .actions(ActionList::new().with(trace))
///     .build();
/// conn.add_filter("eth0", TcHandle::CLSACT_INGRESS, filter).await?;
/// // Watch `dmesg` for the tag when traffic hits the filter.
/// # Ok(())
/// # }
/// ```
///
/// The kernel limits `sdata` to a fixed buffer
/// (`SIMP_MAX_DATA = 32` bytes including the trailing NUL); longer
/// strings get truncated by the kernel without error.
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct SimpleAction {
    /// Tag string emitted on every match.
    sdata: String,
    /// Verdict (TC_ACT_*).
    action: i32,
}

impl SimpleAction {
    /// Create a new simple action with the given tag string.
    ///
    /// Default verdict is `TC_ACT_PIPE` so packet processing continues
    /// after the trace fires.
    pub fn new(sdata: impl Into<String>) -> Self {
        Self {
            sdata: sdata.into(),
            action: action::TC_ACT_PIPE,
        }
    }

    /// Set verdict to `TC_ACT_OK` (let packet proceed).
    pub fn ok(mut self) -> Self {
        self.action = action::TC_ACT_OK;
        self
    }

    /// Set verdict to `TC_ACT_SHOT` (drop packet).
    #[allow(clippy::should_implement_trait)]
    pub fn drop(mut self) -> Self {
        self.action = action::TC_ACT_SHOT;
        self
    }

    /// Set an arbitrary verdict.
    pub fn verdict(mut self, action: i32) -> Self {
        self.action = action;
        self
    }

    /// Parse a `tc(8)`-style `simple` token slice into a typed
    /// action.
    ///
    /// # Recognised tokens
    ///
    /// - `sdata <text>` (required) — the tag string emitted on
    ///   every match. Single token (no spaces); the kernel
    ///   truncates strings longer than `SIMP_MAX_DATA = 32` bytes
    ///   (including the trailing NUL).
    /// - `verdict pass|drop|pipe|reclassify|stolen|continue` —
    ///   override the default `pipe` verdict.
    ///
    /// Per Plan 139 §8.4: spaces inside `sdata` aren't supported
    /// since `bins/tc` already pre-tokenises on whitespace.
    /// Callers needing a multi-word tag should construct via
    /// [`SimpleAction::new`] directly.
    pub fn parse_params(params: &[&str]) -> Result<Self> {
        let mut sdata: Option<&str> = None;
        let mut verdict: Option<i32> = None;
        let mut i = 0;
        while i < params.len() {
            let key = params[i];
            match key {
                "sdata" => {
                    let s = action_need_value(params, i, "simple", key)?;
                    sdata = Some(s);
                    i += 2;
                }
                "verdict" => {
                    let s = action_need_value(params, i, "simple", key)?;
                    verdict = Some(parse_gact_verdict(s).map_err(|e| {
                        Error::invalid_message(e.to_string().replace("gact:", "simple:"))
                    })?);
                    i += 2;
                }
                other => {
                    return Err(Error::invalid_message(format!(
                        "simple: unknown token `{other}` (recognised: sdata <text>, verdict <kw>)"
                    )));
                }
            }
        }
        let sdata = sdata
            .ok_or_else(|| Error::invalid_message("simple: `sdata <text>` required".to_string()))?;
        let mut act = Self::new(sdata);
        if let Some(v) = verdict {
            act = act.verdict(v);
        }
        Ok(act)
    }

    /// Build (no-op marker for API consistency).
    pub fn build(self) -> Self {
        self
    }
}

impl ActionConfig for SimpleAction {
    fn kind(&self) -> &'static str {
        "simple"
    }

    fn to_params(&self) -> Result<Vec<String>> {
        let mut out = kv("sdata", &self.sdata).to_vec();
        if self.action != action::TC_ACT_PIPE {
            out.extend(kv("verdict", verdict_param("simple", self.action)?));
        }
        Ok(out)
    }

    fn write_options(&self, builder: &mut MessageBuilder) -> Result<()> {
        use super::types::tc::action::simple_act;

        let parms = simple_act::TcDefact::new(self.action);
        builder.append_attr(simple_act::TCA_DEF_PARMS, parms.as_bytes());

        // sdata is a NUL-terminated string in a fixed-size buffer.
        // Append the bytes plus the trailing NUL; kernel truncates if
        // longer than `SIMP_MAX_DATA`.
        let mut bytes = self.sdata.clone().into_bytes();
        bytes.push(0);
        builder.append_attr(simple_act::TCA_DEF_DATA, &bytes);
        Ok(())
    }
}

// ============================================================================
// Standalone-action CRUD on Connection<Route> (Plan 139 PR A)
// ============================================================================

/// Parsed shared-action dump entry — kind + index + the
/// kind-specific options blob (raw bytes, since per-kind decoders
/// are a separate ~14-parser arc deferred per Plan 139 §3.2).
///
/// Returned from [`Connection::dump_actions`] and
/// [`Connection::get_action`].
#[derive(Debug, Clone)]
pub struct ActionMessage {
    /// Action kind string (`"gact"`, `"mirred"`, etc.).
    pub kind: String,
    /// Kernel-assigned index for this shared action.
    pub index: u32,
    /// Raw bytes of the kind-specific `TCA_ACT_OPTIONS` payload.
    /// Decode via the per-kind parser of your choice or leave as-is
    /// for inspection.
    pub options_raw: Vec<u8>,
}

#[nlink_macros::send_futures]
impl Connection<Route> {
    /// Add a standalone shared action.
    ///
    /// The kernel assigns the action's index; this slice doesn't
    /// capture it (use [`Self::dump_actions`] to enumerate after
    /// add). A future iteration may add `add_action_returning_index`
    /// once the response-payload-capture path is wired up — see
    /// Plan 139 §8.
    ///
    /// Sends `RTM_NEWACTION` with `NLM_F_CREATE`. Wire shape:
    /// `tcamsg + TCA_ACT_TAB { [1] { TCA_ACT_KIND + TCA_ACT_OPTIONS { ... } } }`.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "add_action", kind = %action.kind()))]
    pub async fn add_action<A: ActionConfig>(&self, mut action: A) -> Result<()> {
        let names = self.ifindexes_of(&action.device_names()).await?;
        action.resolve_devices(&names)?;
        let mut b = MessageBuilder::new(
            NlMsgType::RTM_NEWACTION,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        b.append(&TcaMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, action.kind().as_bytes());
        let opts = b.nest_start(TCA_ACT_OPTIONS);
        action.write_options(&mut b)?;
        b.nest_end(opts);
        b.nest_end(act);
        b.nest_end(tab);

        self.send_ack(b).await
    }

    /// Delete a standalone shared action by `(kind, index)`.
    ///
    /// Sends `RTM_DELACTION`. The index goes alongside the kind
    /// (sibling of `TCA_ACT_KIND` inside the action slot) — the
    /// modern lookup path the kernel accepts.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "del_action", kind = %kind, index))]
    pub async fn del_action(&self, kind: &str, index: u32) -> Result<()> {
        let mut b = MessageBuilder::new(NlMsgType::RTM_DELACTION, NLM_F_REQUEST | NLM_F_ACK);
        b.append(&TcaMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, kind.as_bytes());
        b.append_attr_u32(TCA_ACT_INDEX, index);
        b.nest_end(act);
        b.nest_end(tab);

        self.send_ack(b).await
    }

    /// Fetch a single shared action by `(kind, index)`. Returns
    /// `Ok(None)` on ENOENT.
    ///
    /// Sends `RTM_GETACTION` with `NLM_F_REQUEST` only (no DUMP,
    /// no ACK). The kernel responds with a single `RTM_NEWACTION`-
    /// shaped message carrying the action.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "get_action", kind = %kind, index))]
    pub async fn get_action(&self, kind: &str, index: u32) -> Result<Option<ActionMessage>> {
        let mut b = MessageBuilder::new(NlMsgType::RTM_GETACTION, NLM_F_REQUEST);
        b.append(&TcaMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, kind.as_bytes());
        b.append_attr_u32(TCA_ACT_INDEX, index);
        b.nest_end(act);
        b.nest_end(tab);

        match self.send_request(b).await {
            Ok(response) => {
                let msgs = parse_action_messages(&response);
                Ok(msgs.into_iter().next())
            }
            Err(e) if e.is_not_found() => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Dump every shared action of a specific kind. Pass `""` to
    /// dump actions of every kind in one go.
    #[tracing::instrument(level = "debug", skip_all, fields(method = "dump_actions", kind = %kind))]
    pub async fn dump_actions(&self, kind: &str) -> Result<Vec<ActionMessage>> {
        let mut b = dump_request(NlMsgType::RTM_GETACTION);
        b.append(&TcaMsg::default());

        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        if !kind.is_empty() {
            b.append_attr(TCA_ACT_KIND, kind.as_bytes());
        }
        b.nest_end(act);
        b.nest_end(tab);

        let responses = self.send_dump(b).await?;
        let mut actions = Vec::new();
        for response in responses {
            actions.extend(parse_action_messages(&response));
        }
        Ok(actions)
    }
}

/// Skip past the netlink header + tcmsg, returning the slice
/// containing the top-level attributes. Returns `None` if the
/// message is too short.
fn action_attr_slice(msg: &[u8]) -> Option<&[u8]> {
    // nlmsghdr (16) + tcamsg (4). The action API uses `struct tcamsg`,
    // not `struct tcmsg` — this used to skip `size_of::<TcMsg>()` (20),
    // landing 16 bytes into the attribute chain, and the writers sent
    // 20 bytes to match. Both halves were wrong together, so the read
    // path looked self-consistent while the kernel refused every write
    // with "Netlink action attributes missing" (#300).
    const NLMSG_HDRLEN: usize = 16;
    let start = NLMSG_HDRLEN + TcaMsg::SIZE;
    if msg.len() < start {
        return None;
    }
    Some(&msg[start..])
}

/// Walk one netlink netlink-attribute (TLV: 4-byte hdr + payload,
/// padded to 4-byte boundary). Returns `(attr_type, payload, rest)`.
/// `attr_type` is masked through `NLA_TYPE_MASK` so the
/// `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER` flags don't leak into
/// the dispatch.
fn next_nla(input: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    use super::attr::NLA_TYPE_MASK;
    if input.len() < 4 {
        return None;
    }
    // Plan 223 — netlink attribute nla_len / nla_type are kernel
    // native-endian (per `struct nlattr` in include/uapi/linux/netlink.h
    // and nlink's canonical `NlAttr` in `attr.rs` using zerocopy
    // native-endian). Was `from_le_bytes` — silently broken on
    // BE platforms.
    let len = u16::from_ne_bytes([input[0], input[1]]) as usize;
    let attr_type = u16::from_ne_bytes([input[2], input[3]]) & NLA_TYPE_MASK;
    if len < 4 || len > input.len() {
        return None;
    }
    let payload = &input[4..len];
    let aligned = (len + 3) & !3;
    let rest = if aligned <= input.len() {
        &input[aligned..]
    } else {
        &[]
    };
    Some((attr_type, payload, rest))
}

// ============================================================================
// Shared parse_params helpers (Plan 139 PR B sub-slice 1)
// ============================================================================

/// Borrow `params[i + 1]`, returning a kind-prefixed
/// `InvalidMessage` if the value slot is missing. Mirrors
/// `filter::need_value` / `tc::need_value` from the qdisc + filter
/// rollouts.
fn action_need_value<'a>(params: &[&'a str], i: usize, kind: &str, key: &str) -> Result<&'a str> {
    params
        .get(i + 1)
        .copied()
        .ok_or_else(|| Error::invalid_message(format!("{kind}: `{key}` requires a value")))
}

/// Parse a decimal `u32` with kind-prefixed error context.
fn action_parse_u32(kind: &str, key: &str, s: &str) -> Result<u32> {
    s.parse::<u32>().map_err(|_| {
        Error::invalid_message(format!(
            "{kind}: invalid {key} `{s}` (expected unsigned integer)"
        ))
    })
}

/// Parse a `u32` as tc(8)'s `get_u32(.., 0)` does: `strtoul` base 0, so
/// `0x` hex, a leading `0` octal, or decimal (#817). Marks and masks are
/// read this way.
fn action_parse_u32_any(kind: &str, key: &str, s: &str) -> Result<u32> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else if s.len() > 1 && s.starts_with('0') {
        u32::from_str_radix(&s[1..], 8)
    } else {
        s.parse::<u32>()
    };
    parsed.map_err(|_| {
        Error::invalid_message(format!(
            "{kind}: invalid {key} `{s}` (expected unsigned integer: decimal, 0x-hex or 0-octal)"
        ))
    })
}

/// Parse a `0x`-prefixed hex or decimal u32 — used by `ctinfo` mask
/// tokens, which `tc(8)` conventionally writes in hex (`0xfc`).
fn ctinfo_parse_u32(what: &str, s: &str) -> Result<u32> {
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse::<u32>()
    };
    parsed.map_err(|_| {
        Error::invalid_message(format!(
            "ctinfo: invalid {what} `{s}` (expected 0x-hex or decimal u32)"
        ))
    })
}

/// Parse an ethertype as tc(8) reads one: a protocol name, or a number
/// in any base `strtoul` takes (`0x` hex, a leading `0` octal, decimal).
/// `ip6` is kept as an alias of `ipv6`.
fn parse_ethertype(kind: &str, s: &str) -> Result<u16> {
    let s = if s == "ip6" { "ipv6" } else { s };
    s.parse::<crate::EthProto>()
        .map(crate::EthProto::as_u16)
        .map_err(|_| {
            Error::invalid_message(format!(
                "{kind}: invalid protocol `{s}` (expected a protocol name such as ipv4, ipv6, \
                 mpls_uc, or a number)"
            ))
        })
}

/// Parse an IP address or `<min>-<max>` range. Single addresses
/// expand to `(addr, addr)` so callers can always pass a pair to
/// the typed builder. Used by `CtAction::parse_params`.
fn parse_ip_range_or_single(s: &str) -> Result<(IpAddr, IpAddr)> {
    if let Some((min_s, max_s)) = s.split_once('-') {
        let min: IpAddr = min_s.parse().map_err(|_| {
            Error::invalid_message(format!("ct: invalid min address `{min_s}` in range"))
        })?;
        let max: IpAddr = max_s.parse().map_err(|_| {
            Error::invalid_message(format!("ct: invalid max address `{max_s}` in range"))
        })?;
        Ok((min, max))
    } else {
        let addr: IpAddr = s
            .parse()
            .map_err(|_| Error::invalid_message(format!("ct: invalid address `{s}`")))?;
        Ok((addr, addr))
    }
}

/// A ct label or its mask as tc(8) writes one: up to 32 hex digits, an
/// even number of them, first byte first; the bytes it does not give are
/// zero.
fn ct_label(what: &str, s: &str) -> Result<[u8; 16]> {
    let invalid = || {
        Error::invalid_message(format!(
            "ct: invalid {what} `{s}` (expected up to 32 hex digits, an even number)"
        ))
    };
    if s.is_empty()
        || s.len() > 32
        || !s.len().is_multiple_of(2)
        || !s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    let mut out = [0u8; 16];
    for (byte, i) in out.iter_mut().zip((0..s.len()).step_by(2)) {
        *byte = s
            .get(i..i + 2)
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or_else(invalid)?;
    }
    Ok(out)
}

/// A ct label as [`ct_label`] reads it back: all 32 hex digits.
fn ct_label_token(label: &[u8; 16]) -> String {
    label.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a pedit integer value — decimal or `0x`-prefixed hex.
fn pedit_u32(layer: &str, field: &str, s: &str) -> Result<u32> {
    let parsed = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => s.parse::<u32>(),
    };
    parsed.map_err(|_| {
        Error::invalid_message(format!(
            "pedit: invalid {layer} {field} value `{s}` (expected integer or 0x-hex)"
        ))
    })
}

/// Parse a pedit value that must fit in a `u8`.
fn pedit_u8(layer: &str, field: &str, s: &str) -> Result<u8> {
    let v = pedit_u32(layer, field, s)?;
    u8::try_from(v).map_err(|_| {
        Error::invalid_message(format!(
            "pedit: {layer} {field} value `{s}` out of range for u8 (0..=255)"
        ))
    })
}

/// Parse a pedit value that must fit in a `u16`.
fn pedit_u16(layer: &str, field: &str, s: &str) -> Result<u16> {
    let v = pedit_u32(layer, field, s)?;
    u16::try_from(v).map_err(|_| {
        Error::invalid_message(format!(
            "pedit: {layer} {field} value `{s}` out of range for u16 (0..=65535)"
        ))
    })
}

/// Parse a pedit IPv4 address value.
fn pedit_ipv4(layer: &str, field: &str, s: &str) -> Result<Ipv4Addr> {
    s.parse::<Ipv4Addr>().map_err(|_| {
        Error::invalid_message(format!("pedit: invalid {layer} {field} IPv4 address `{s}`"))
    })
}

/// Parse a pedit MAC address value (`aa:bb:cc:dd:ee:ff`).
fn pedit_mac(layer: &str, field: &str, s: &str) -> Result<[u8; 6]> {
    crate::util::addr::parse_mac(s).map_err(|_| {
        Error::invalid_message(format!("pedit: invalid {layer} {field} MAC address `{s}`"))
    })
}

/// Resolve a `gact` verdict keyword (`pass`/`drop`/etc.) to its
/// `TC_ACT_*` integer.
fn parse_gact_verdict(s: &str) -> Result<i32> {
    Ok(match s {
        "pass" | "ok" => action::TC_ACT_OK,
        "drop" | "shot" => action::TC_ACT_SHOT,
        "pipe" => action::TC_ACT_PIPE,
        "reclassify" => action::TC_ACT_RECLASSIFY,
        "stolen" => action::TC_ACT_STOLEN,
        "continue" => action::TC_ACT_UNSPEC,
        other => {
            return Err(Error::invalid_message(format!(
                "gact: unknown verdict `{other}` (expected pass/drop/pipe/reclassify/stolen/continue)"
            )));
        }
    })
}

/// Parse the action-table contents of a single RTM_NEWACTION /
/// RTM_GETACTION response message into a flat list of
/// [`ActionMessage`] entries.
fn parse_action_messages(msg: &[u8]) -> Vec<ActionMessage> {
    let mut out = Vec::new();
    let Some(attrs) = action_attr_slice(msg) else {
        return out;
    };
    let mut input = attrs;
    while let Some((attr_type, payload, rest)) = next_nla(input) {
        input = rest;
        if attr_type != TCA_ACT_TAB {
            continue;
        }
        // Inside TCA_ACT_TAB: each numbered nested attr is one
        // action slot.
        let mut slot_input = payload;
        while let Some((_slot_id, slot_payload, slot_rest)) = next_nla(slot_input) {
            slot_input = slot_rest;
            if let Some(action) = parse_one_action(slot_payload) {
                out.push(action);
            }
        }
    }
    out
}

/// Parse one action slot's attributes into an [`ActionMessage`].
fn parse_one_action(slot: &[u8]) -> Option<ActionMessage> {
    let mut kind: Option<String> = None;
    let mut index: u32 = 0;
    let mut options_raw: Vec<u8> = Vec::new();

    let mut input = slot;
    while let Some((attr_type, payload, rest)) = next_nla(input) {
        input = rest;
        match attr_type {
            TCA_ACT_KIND => {
                let bytes = payload.split(|&b| b == 0).next().unwrap_or(payload);
                kind = Some(String::from_utf8_lossy(bytes).into_owned());
            }
            TCA_ACT_INDEX if payload.len() >= 4 => {
                // Plan 223 — TCA_ACT_INDEX payload is kernel native-endian.
                index = u32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
            }
            TCA_ACT_OPTIONS => {
                options_raw = payload.to_vec();
                // Some kernel versions also embed the index inside the
                // kind-specific PARMS struct. If we didn't see a
                // sibling TCA_ACT_INDEX, try to extract it from the
                // first 4 bytes of the first sub-attr's payload.
                if index == 0
                    && let Some((_kind_attr, parms_payload, _)) = next_nla(payload)
                    && parms_payload.len() >= 4
                {
                    // Plan 223 — kernel-native endian (see comment on
                    // next_nla above).
                    index = u32::from_ne_bytes([
                        parms_payload[0],
                        parms_payload[1],
                        parms_payload[2],
                        parms_payload[3],
                    ]);
                }
            }
            _ => {}
        }
    }

    Some(ActionMessage {
        kind: kind?,
        index,
        options_raw,
    })
}

/// Wire-byte assertions for the NAT encoder (#262).
///
/// `struct tc_nat`'s three address fields are `__be32` in a natively
/// serialized struct, so each must hold the value whose *memory image* is
/// network order.
#[cfg(test)]
mod nat_wire_tests {
    use super::*;
    use crate::netlink::test_support::action_attrs;

    // tc_gen is 5x u32; old_addr, new_addr, mask follow.
    const OLD_ADDR: usize = 20;
    const NEW_ADDR: usize = 24;
    const MASK: usize = 28;

    fn field(cfg: &NatAction, at: usize) -> [u8; 4] {
        let attrs = action_attrs(cfg);
        let parms = &attrs[&nat::TCA_NAT_PARMS];
        assert!(parms.len() >= at + 4, "tc_nat is only {} bytes", parms.len());
        parms[at..at + 4].try_into().unwrap()
    }

    /// Both addresses network order, and the mask a real mask.
    ///
    /// The mask was previously written as
    /// `u32::from_be_bytes(mask.to_be_bytes())` — the identity — so a /24
    /// reached the kernel as `00 FF FF FF`, i.e. 0.255.255.255, matching on
    /// the wrong three octets.
    #[test]
    fn nat_addresses_and_mask_are_network_order() {
        let cfg = NatAction::snat(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(192, 168, 5, 0))
            .prefix(24);

        assert_eq!(field(&cfg, OLD_ADDR), [10, 0, 0, 0]);
        assert_eq!(field(&cfg, NEW_ADDR), [192, 168, 5, 0]);
        assert_eq!(field(&cfg, MASK), [0xFF, 0xFF, 0xFF, 0x00], "/24 mask");
        assert_ne!(
            field(&cfg, MASK),
            [0x00, 0xFF, 0xFF, 0xFF],
            "regression: the mask swap is a no-op again"
        );
    }

    /// A non-palindromic address, so a reversal cannot hide.
    #[test]
    fn nat_address_is_not_byte_reversed() {
        let cfg = NatAction::dnat(Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(10, 20, 30, 40));
        assert_eq!(field(&cfg, OLD_ADDR), [1, 2, 3, 4]);
        assert_ne!(field(&cfg, OLD_ADDR), [4, 3, 2, 1]);
        assert_eq!(field(&cfg, MASK), [0xFF, 0xFF, 0xFF, 0xFF], "/32 mask");
    }
}

/// Wire-byte assertions for the pedit encoder (#262).
///
/// `val` and `mask` are authored as big-endian-read integers and the struct is
/// serialized natively, so the swap at pack time is what puts them on the wire.
/// These assert the *bytes*, never a round-trip: the original bug was
/// symmetric, so anything that went through nlink's own decoder agreed with
/// itself while the kernel edited the wrong bytes.
#[cfg(test)]
mod pedit_wire_tests {
    use super::*;
    use crate::netlink::test_support::action_attrs;

    const SEL_SIZE: usize = 24; // tc_pedit_sel: 5x u32 + u8 + u8 + u16
    const KEY_SIZE: usize = 24; // tc_pedit_key: 6x u32

    /// `(mask, val, off)` of key `n`, as the bytes actually emitted.
    fn key_bytes(cfg: &PeditAction, n: usize) -> ([u8; 4], [u8; 4], u32) {
        let attrs = action_attrs(cfg);
        let parms = &attrs[&pedit::TCA_PEDIT_PARMS_EX];
        let base = SEL_SIZE + n * KEY_SIZE;
        assert!(
            parms.len() >= base + KEY_SIZE,
            "key {n} beyond TCA_PEDIT_PARMS_EX ({} bytes)",
            parms.len()
        );
        let mask = parms[base..base + 4].try_into().unwrap();
        let val = parms[base + 4..base + 8].try_into().unwrap();
        let off = u32::from_ne_bytes(parms[base + 8..base + 12].try_into().unwrap());
        (mask, val, off)
    }

    /// The headline case: a rewritten source address must reach the wire in
    /// network order. Before the fix this emitted `01 00 00 0A`, so
    /// `set_ipv4_src(10.0.0.1)` rewrote packets to 1.0.0.10.
    #[test]
    fn ipv4_src_is_network_order() {
        let cfg = PeditAction::new().set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1));
        let (mask, val, off) = key_bytes(&cfg, 0);

        assert_eq!(val, [10, 0, 0, 1], "address must be network order");
        assert_ne!(val, [1, 0, 0, 10], "regression: byte-reversed again");
        assert_eq!(mask, [0, 0, 0, 0]);
        assert_eq!(off, 12);
    }

    #[test]
    fn ipv4_dst_is_network_order() {
        let cfg = PeditAction::new().set_ipv4_dst(Ipv4Addr::new(192, 168, 1, 254));
        let (_, val, off) = key_bytes(&cfg, 0);
        assert_eq!(val, [192, 168, 1, 254]);
        assert_eq!(off, 16);
    }

    /// TOS is wire byte 1 of the word at offset 0 — `[ver_ihl, tos, len_hi,
    /// len_lo]`. The old encoding put it in byte 3, the low half of the total
    /// length, and cleared byte 0's nibbles instead.
    #[test]
    fn ipv4_tos_targets_byte_one() {
        let cfg = PeditAction::new().set_ipv4_tos(0xB8);
        let (mask, val, off) = key_bytes(&cfg, 0);

        assert_eq!(off, 0);
        assert_eq!(val, [0x00, 0xB8, 0x00, 0x00], "TOS belongs in byte 1");
        assert_eq!(mask, [0xFF, 0x00, 0xFF, 0xFF], "mask must clear only byte 1");
        assert_ne!(val, [0x00, 0x00, 0x00, 0xB8], "regression: total-length byte");
    }

    /// TTL is wire byte 0 of the word at offset 8 — `[ttl, proto, csum_hi,
    /// csum_lo]`. The old encoding targeted byte 2, the checksum's high half.
    #[test]
    fn ipv4_ttl_targets_byte_zero_of_the_ttl_word() {
        let cfg = PeditAction::new().set_ipv4_ttl(64);
        let (mask, val, off) = key_bytes(&cfg, 0);

        assert_eq!(off, 8);
        assert_eq!(val, [64, 0x00, 0x00, 0x00], "TTL belongs in byte 0");
        assert_eq!(mask, [0x00, 0xFF, 0xFF, 0xFF], "mask must clear only byte 0");
        assert_ne!(val, [0x00, 0x00, 64, 0x00], "regression: checksum byte");
    }

    /// Source port is wire bytes 0-1, destination 2-3, of the same word.
    #[test]
    fn l4_ports_land_in_their_own_halves() {
        let (_, val, off) = key_bytes(&PeditAction::new().set_tcp_sport(8080), 0);
        assert_eq!(off, 0);
        assert_eq!(val, [0x1F, 0x90, 0x00, 0x00], "sport is bytes 0-1");

        let (mask, val, _) = key_bytes(&PeditAction::new().set_udp_dport(53), 0);
        assert_eq!(val, [0x00, 0x00, 0x00, 53], "dport is bytes 2-3");
        assert_eq!(mask, [0xFF, 0xFF, 0x00, 0x00]);
    }

    /// A MAC spans two keys: four bytes then two, and both halves have to be
    /// in order for the address to survive.
    #[test]
    fn eth_dst_spans_two_keys_in_order() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let cfg = PeditAction::new().set_eth_dst(mac);

        let (_, val0, off0) = key_bytes(&cfg, 0);
        assert_eq!(off0, 0);
        assert_eq!(val0, [0x02, 0x11, 0x22, 0x33]);

        let (mask1, val1, off1) = key_bytes(&cfg, 1);
        assert_eq!(off1, 4);
        assert_eq!(val1, [0x44, 0x55, 0x00, 0x00]);
        assert_eq!(mask1, [0x00, 0x00, 0xFF, 0xFF]);
    }
}

/// Wire-byte assertions for the police encoder (#194).
///
/// Hand-computed against iproute2's algorithm, never round-tripped through
/// nlink's own decoder.
#[cfg(test)]
mod psched_wire_tests {
    use super::*;
    use crate::netlink::test_support::{action_attrs, u32_at};

    /// police at 10 mbit with a 100 KiB burst.
    ///
    ///   rate  = 10 mbit           = 1_250_000 bytes/sec
    ///   burst = 100 KiB           = 102_400 bytes
    ///   xmit  = 102400/1250000    = 81_920 us
    ///   ticks = 81_920 * 15.625   = 1_280_000
    ///
    /// tcf_police_init(): `police->tcfp_burst = PSCHED_TICKS2NS(parm->burst)`.
    /// The old encoder wrote the raw byte count.
    #[test]
    fn police_burst_is_psched_ticks_not_bytes() {
        let cfg = PoliceAction::new()
            .rate(crate::util::Rate::bytes_per_sec(1_250_000))
            .burst(crate::util::Bytes::new(102_400));
        let attrs = action_attrs(&cfg);

        // struct tc_police: index@0 action@4 limit@8 burst@12 mtu@16 rate@20..
        assert_eq!(
            u32_at(&attrs, police::TCA_POLICE_TBF, 12),
            1_280_000,
            "tc_police.burst must be psched ticks",
        );
        assert_ne!(
            u32_at(&attrs, police::TCA_POLICE_TBF, 12),
            102_400,
            "regression: burst is the raw byte count again",
        );
    }

    /// tcf_police_init() calls qdisc_get_rtab() for any non-zero rate and
    /// fails the action when it returns NULL — which it does both when
    /// TCA_POLICE_RATE is absent *and* when the ratespec's cell_log is 0.
    /// nlink emitted neither, so a policer with a rate could never install.
    #[test]
    fn police_emits_the_mandatory_rate_table() {
        let cfg = PoliceAction::new()
            .rate(crate::util::Rate::bytes_per_sec(1_250_000))
            .burst(crate::util::Bytes::new(102_400));
        let attrs = action_attrs(&cfg);

        let rtab = attrs
            .get(&police::TCA_POLICE_RATE)
            .expect("TCA_POLICE_RATE is mandatory whenever a rate is set");
        assert_eq!(rtab.len(), 1024, "TC_RTAB_SIZE");

        let parms = &attrs[&police::TCA_POLICE_TBF];
        assert_ne!(
            parms[20], 0,
            "rate.cell_log == 0 makes qdisc_get_rtab() return NULL",
        );
    }

    /// A policer with no rate (pure packet-rate / avrate policing) must not
    /// emit a rate table — qdisc_get_rtab() is only consulted for a non-zero
    /// rate.
    #[test]
    fn police_without_a_rate_emits_no_rate_table() {
        let cfg = PoliceAction::new().burst(crate::util::Bytes::new(102_400));
        let attrs = action_attrs(&cfg);
        assert!(!attrs.contains_key(&police::TCA_POLICE_RATE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gact_action() {
        let drop = GactAction::drop();
        assert_eq!(drop.action, action::TC_ACT_SHOT);
        assert_eq!(ActionConfig::kind(&drop), "gact");

        let pass = GactAction::pass();
        assert_eq!(pass.action, action::TC_ACT_OK);

        let random = GactAction::new(action::TC_ACT_OK).random_drop(10).build();
        assert_eq!(random.prob_type, gact::PGACT_NETRAND);
    }

    #[test]
    fn test_police_action() {
        let police = PoliceAction::new()
            .rate(crate::util::Rate::bytes_per_sec(1_000_000))
            .burst(crate::util::Bytes::kib(32))
            .exceed_drop()
            .build();

        assert_eq!(police.rate, 1_000_000);
        assert_eq!(police.burst, 32 * 1024);
        assert_eq!(police.exceed_action, action::TC_ACT_SHOT);
        assert_eq!(ActionConfig::kind(&police), "police");
    }

    #[test]
    fn test_vlan_action() {
        let pop = VlanAction::pop();
        assert_eq!(pop.v_action, vlan::TCA_VLAN_ACT_POP);
        assert_eq!(ActionConfig::kind(&pop), "vlan");

        let push = VlanAction::push(100).priority(3).build();
        assert_eq!(push.v_action, vlan::TCA_VLAN_ACT_PUSH);
        assert_eq!(push.vlan_id, Some(100));
        assert_eq!(push.vlan_prio, Some(3));
    }

    #[test]
    fn test_skbedit_action() {
        let edit = SkbeditAction::new().priority(7).mark(100).build();

        assert_eq!(edit.priority, Some(7));
        assert_eq!(edit.mark, Some(100));
        assert_eq!(ActionConfig::kind(&edit), "skbedit");
    }

    #[test]
    fn test_action_list() {
        let list = ActionList::new().with(GactAction::drop()).build();

        assert_eq!(list.len(), 1);
        assert!(!list.is_empty());
    }

    #[test]
    fn test_nat_action() {
        let snat = NatAction::snat(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(192, 168, 1, 1))
            .prefix(8)
            .build();

        assert_eq!(snat.old_addr, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(snat.new_addr, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(snat.prefix_len, 8);
        assert!(snat.egress);
        assert_eq!(ActionConfig::kind(&snat), "nat");

        let dnat = NatAction::dnat(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1));
        assert!(!dnat.egress);
    }

    #[test]
    fn test_nat_prefix_to_mask() {
        assert_eq!(NatAction::prefix_to_mask(0), 0);
        assert_eq!(NatAction::prefix_to_mask(8), 0xFF000000);
        assert_eq!(NatAction::prefix_to_mask(16), 0xFFFF0000);
        assert_eq!(NatAction::prefix_to_mask(24), 0xFFFFFF00);
        assert_eq!(NatAction::prefix_to_mask(32), 0xFFFFFFFF);
    }

    #[test]
    fn test_tunnel_key_action() {
        let set = TunnelKeyAction::set()
            .src(Ipv4Addr::new(192, 168, 1, 1))
            .dst(Ipv4Addr::new(192, 168, 1, 2))
            .key_id(100)
            .dst_port(4789)
            .ttl(64)
            .no_csum()
            .build();

        assert_eq!(set.t_action, tunnel_key::TCA_TUNNEL_KEY_ACT_SET);
        assert_eq!(set.src_ipv4, Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(set.dst_ipv4, Some(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(set.key_id, Some(100));
        assert_eq!(set.dst_port, Some(4789));
        assert_eq!(set.ttl, Some(64));
        assert!(set.no_csum);
        assert_eq!(ActionConfig::kind(&set), "tunnel_key");

        let release = TunnelKeyAction::release();
        assert_eq!(release.t_action, tunnel_key::TCA_TUNNEL_KEY_ACT_RELEASE);
    }

    #[test]
    fn test_connmark_action() {
        let mark = ConnmarkAction::new();
        assert_eq!(mark.zone, 0);
        assert_eq!(ActionConfig::kind(&mark), "connmark");

        let mark_zone = ConnmarkAction::with_zone(5);
        assert_eq!(mark_zone.zone, 5);

        let mark_custom = ConnmarkAction::new()
            .zone(10)
            .action(action::TC_ACT_OK)
            .build();
        assert_eq!(mark_custom.zone, 10);
        assert_eq!(mark_custom.action, action::TC_ACT_OK);
    }

    #[test]
    fn test_csum_action() {
        let csum_action = CsumAction::new().iph().tcp().udp().build();

        assert_eq!(
            csum_action.update_flags,
            csum::TCA_CSUM_UPDATE_FLAG_IPV4HDR
                | csum::TCA_CSUM_UPDATE_FLAG_TCP
                | csum::TCA_CSUM_UPDATE_FLAG_UDP
        );
        assert_eq!(ActionConfig::kind(&csum_action), "csum");

        // Test all flags
        let all = CsumAction::new()
            .iph()
            .icmp()
            .igmp()
            .tcp()
            .udp()
            .udplite()
            .sctp()
            .build();

        assert_eq!(all.update_flags, 0x7F); // All 7 flags set
    }

    #[test]
    fn test_sample_action() {
        let sample = SampleAction::new(100, 5);
        assert_eq!(sample.rate, 100);
        assert_eq!(sample.group, 5);
        assert_eq!(sample.trunc_size, None);
        assert_eq!(ActionConfig::kind(&sample), "sample");

        let sample_trunc = SampleAction::new(50, 10).trunc(128).build();
        assert_eq!(sample_trunc.rate, 50);
        assert_eq!(sample_trunc.group, 10);
        assert_eq!(sample_trunc.trunc_size, Some(128));
    }

    #[test]
    fn test_ct_action() {
        let ct = CtAction::new();
        assert_eq!(ct.ct_action, 0);
        assert_eq!(ActionConfig::kind(&ct), "ct");

        let commit = CtAction::commit();
        assert_eq!(commit.ct_action, ct::TCA_CT_ACT_COMMIT);

        let force = CtAction::commit().force();
        assert_eq!(
            force.ct_action,
            ct::TCA_CT_ACT_COMMIT | ct::TCA_CT_ACT_FORCE
        );

        let clear = CtAction::clear();
        assert_eq!(clear.ct_action, ct::TCA_CT_ACT_CLEAR);

        let snat = CtAction::commit()
            .nat_src_single(Ipv4Addr::new(10, 0, 0, 1))
            .zone(1)
            .mark(0x100, 0xffffffff)
            .build();

        assert!(snat.ct_action & ct::TCA_CT_ACT_NAT != 0);
        assert!(snat.ct_action & ct::TCA_CT_ACT_NAT_SRC != 0);
        assert_eq!(snat.zone, Some(1));
        assert_eq!(snat.mark, Some(0x100));
        assert_eq!(snat.nat_ipv4_min, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_pedit_action() {
        let pedit = PeditAction::new()
            .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
            .build();

        assert_eq!(pedit.keys.len(), 1);
        assert_eq!(ActionConfig::kind(&pedit), "pedit");

        let pedit_multi = PeditAction::new()
            .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
            .set_ipv4_dst(Ipv4Addr::new(10, 0, 0, 2))
            .set_tcp_dport(8080)
            .build();

        assert_eq!(pedit_multi.keys.len(), 3);

        let pedit_eth = PeditAction::new()
            .set_eth_src([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])
            .build();

        // MAC address requires 2 keys (4 bytes + 2 bytes)
        assert_eq!(pedit_eth.keys.len(), 2);
    }

    #[test]
    fn test_bpf_action_default_pipe() {
        let bpf = BpfAction::with_raw_fd(42);
        assert_eq!(bpf.action, action::TC_ACT_PIPE);
        assert_eq!(bpf.fd.raw().unwrap(), 42);
        assert!(bpf.name.is_none());
        assert_eq!(ActionConfig::kind(&bpf), "bpf");
    }

    #[test]
    fn test_bpf_action_verdict_helpers() {
        assert_eq!(BpfAction::with_raw_fd(1).ok().action, action::TC_ACT_OK);
        assert_eq!(BpfAction::with_raw_fd(1).drop().action, action::TC_ACT_SHOT);
        assert_eq!(BpfAction::with_raw_fd(1).pipe().action, action::TC_ACT_PIPE);
        assert_eq!(BpfAction::with_raw_fd(1).verdict(7).action, 7);
    }

    #[test]
    fn test_bpf_action_with_name() {
        let bpf = BpfAction::with_raw_fd(10).name("my_bpf").build();
        assert_eq!(bpf.name.as_deref(), Some("my_bpf"));
    }

    #[test]
    fn test_bpf_action_from_pinned_missing_path() {
        // Should error rather than panic when the pin doesn't exist.
        let result = BpfAction::from_pinned("/nonexistent/path/that/should/not/exist");
        assert!(result.is_err());
    }

    #[test]
    fn test_bpf_action_writes_attrs() {
        let bpf = BpfAction::with_raw_fd(42).name("trace").build();
        let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = builder.len();
        ActionConfig::write_options(&bpf, &mut builder).unwrap();
        let end = builder.len();
        // PARMS (20 bytes + 4 hdr + 0 pad) + FD (4 bytes + 4 hdr) +
        // NAME (5 bytes "trace\0" + 4 hdr + 3 pad to align). The fd
        // and name attrs should add up to a non-zero count.
        assert!(end > start);
    }

    #[test]
    fn test_simple_action_default_pipe() {
        let s = SimpleAction::new("trace");
        assert_eq!(s.action, action::TC_ACT_PIPE);
        assert_eq!(s.sdata, "trace");
        assert_eq!(ActionConfig::kind(&s), "simple");
    }

    #[test]
    fn test_simple_action_verdicts() {
        assert_eq!(SimpleAction::new("x").ok().action, action::TC_ACT_OK);
        assert_eq!(SimpleAction::new("x").drop().action, action::TC_ACT_SHOT);
        assert_eq!(SimpleAction::new("x").verdict(99).action, 99);
    }

    #[test]
    fn test_simple_action_writes_sdata_with_nul() {
        let s = SimpleAction::new("hi").build();
        let mut builder = crate::netlink::builder::MessageBuilder::new(0, 0);
        let start = builder.len();
        ActionConfig::write_options(&s, &mut builder).unwrap();
        let bytes = &builder.as_bytes()[start..];
        // sdata blob "hi\0" appears somewhere in the written attrs.
        assert!(bytes.windows(3).any(|w| w == b"hi\0"));
    }

    // ==========================================================
    // Plan 139 PR A — wire-format tests for ActionMessage parser
    // and the new Connection<Route> standalone-action methods.
    // We don't need a live Connection<Route>; we construct the
    // request bytes via MessageBuilder and run them back through
    // parse_action_messages, mirroring the SA round-trip pattern.
    // ==========================================================

    /// Build the bytes that `add_action(action)` would emit.
    fn build_add_action_frame<A: ActionConfig>(action: A) -> Vec<u8> {
        let mut b = MessageBuilder::new(
            NlMsgType::RTM_NEWACTION,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE,
        );
        b.append(&TcaMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, action.kind().as_bytes());
        let opts = b.nest_start(TCA_ACT_OPTIONS);
        action.write_options(&mut b).unwrap();
        b.nest_end(opts);
        b.nest_end(act);
        b.nest_end(tab);
        b.finish()
    }

    #[test]
    fn add_action_gact_drop_roundtrips_through_parser() {
        let frame = build_add_action_frame(GactAction::drop());
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1, "exactly one action slot");
        assert_eq!(parsed[0].kind, "gact");
        assert!(!parsed[0].options_raw.is_empty());
    }

    #[test]
    fn add_action_mirred_roundtrips() {
        let action = MirredAction::redirect_to_egress(7);
        let frame = build_add_action_frame(action);
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "mirred");
    }

    #[test]
    fn add_action_police_roundtrips() {
        let action = PoliceAction::new()
            .rate(crate::util::Rate::bytes_per_sec(1_000_000))
            .burst(crate::util::Bytes::kib(32))
            .exceed_drop()
            .build();
        let frame = build_add_action_frame(action);
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "police");
    }

    #[test]
    fn add_action_vlan_pop_roundtrips() {
        let frame = build_add_action_frame(VlanAction::pop());
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "vlan");
    }

    #[test]
    fn add_action_skbedit_roundtrips() {
        let frame = build_add_action_frame(SkbeditAction::new().mark(0x42).build());
        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "skbedit");
    }

    #[test]
    fn del_action_emits_kind_plus_index_at_slot_level() {
        let mut b = MessageBuilder::new(NlMsgType::RTM_DELACTION, NLM_F_REQUEST | NLM_F_ACK);
        b.append(&TcaMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, b"gact");
        b.append_attr_u32(TCA_ACT_INDEX, 42);
        b.nest_end(act);
        b.nest_end(tab);
        let frame = b.finish();

        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].kind, "gact");
        assert_eq!(parsed[0].index, 42);
        assert!(parsed[0].options_raw.is_empty(), "del has no options");

        // nlmsg_type at offset 4..6 must be RTM_DELACTION.
        // Plan 223 — kernel-native endian.
        let nlmsg_type = u16::from_ne_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, NlMsgType::RTM_DELACTION);
    }

    #[test]
    fn get_action_request_uses_request_only_flags() {
        let mut b = MessageBuilder::new(NlMsgType::RTM_GETACTION, NLM_F_REQUEST);
        b.append(&TcaMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);
        let act = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, b"mirred");
        b.append_attr_u32(TCA_ACT_INDEX, 7);
        b.nest_end(act);
        b.nest_end(tab);
        let frame = b.finish();

        // Plan 223 — kernel-native endian.
        let nlmsg_type = u16::from_ne_bytes([frame[4], frame[5]]);
        assert_eq!(nlmsg_type, NlMsgType::RTM_GETACTION);
        let flags = u16::from_ne_bytes([frame[6], frame[7]]);
        // Single-result GET: REQUEST only, no DUMP, no ACK.
        const NLM_F_DUMP: u16 = 0x300;
        assert_eq!(flags & NLM_F_DUMP, 0);
        assert_eq!(flags & NLM_F_ACK, 0);
        assert!(flags & NLM_F_REQUEST != 0);
    }

    #[test]
    fn parse_action_messages_handles_two_slots() {
        // Build an action table with two slots: gact + mirred.
        let mut b = MessageBuilder::new(NlMsgType::RTM_NEWACTION, 0);
        b.append(&TcaMsg::default());
        let tab = b.nest_start(TCA_ACT_TAB);

        let act1 = b.nest_start(1);
        b.append_attr(TCA_ACT_KIND, b"gact");
        b.append_attr_u32(TCA_ACT_INDEX, 1);
        b.nest_end(act1);

        let act2 = b.nest_start(2);
        b.append_attr(TCA_ACT_KIND, b"mirred");
        b.append_attr_u32(TCA_ACT_INDEX, 2);
        b.nest_end(act2);

        b.nest_end(tab);
        let frame = b.finish();

        let parsed = parse_action_messages(&frame);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].kind, "gact");
        assert_eq!(parsed[0].index, 1);
        assert_eq!(parsed[1].kind, "mirred");
        assert_eq!(parsed[1].index, 2);
    }

    #[test]
    fn parse_action_messages_skips_truncated_input() {
        // Truncated frame (just the nlmsghdr) should yield zero
        // actions, not panic.
        let parsed = parse_action_messages(&[0u8; 8]);
        assert!(parsed.is_empty());
    }

    // ==========================================================
    // Plan 139 PR B sub-slice 1 — parse_params for 5 simple
    // action kinds. Each parser follows the same shape as the
    // qdisc/filter parsers from slices 1-15.
    // ==========================================================

    fn write_options_bytes<A: ActionConfig>(a: &A) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        a.write_options(&mut b).unwrap();
        b.as_bytes()[start..].to_vec()
    }

    // ---- GactAction ----

    #[test]
    fn gact_parse_params_default_yields_pass() {
        let a = GactAction::parse_params(&[]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&GactAction::pass())
        );
    }

    #[test]
    fn gact_parse_params_drop_alias_shot() {
        let a = GactAction::parse_params(&["drop"]).unwrap();
        let b = GactAction::parse_params(&["shot"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&GactAction::drop())
        );
    }

    #[test]
    fn gact_parse_params_pass_alias_ok() {
        assert_eq!(
            write_options_bytes(&GactAction::parse_params(&["pass"]).unwrap()),
            write_options_bytes(&GactAction::parse_params(&["ok"]).unwrap()),
        );
    }

    #[test]
    fn gact_parse_params_goto_chain() {
        let a = GactAction::parse_params(&["goto_chain", "5"]).unwrap();
        let b = GactAction::goto_chain(5);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn gact_parse_params_random_determ() {
        let a = GactAction::parse_params(&["pass", "random", "determ", "drop", "10"]).unwrap();
        let b = GactAction::pass().deterministic(10, action::TC_ACT_SHOT);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn gact_parse_params_random_netrand_percent() {
        let a = GactAction::parse_params(&["pass", "random", "netrand", "drop", "25"]).unwrap();
        let b = GactAction::pass().random(25, action::TC_ACT_SHOT);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn gact_parse_params_unknown_token_errors() {
        let err = GactAction::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("gact: unknown token"));
    }

    #[test]
    fn gact_parse_params_random_unknown_kind_errors() {
        let err = GactAction::parse_params(&["pass", "random", "wat", "drop", "10"]).unwrap_err();
        assert!(err.to_string().contains("unknown random kind"));
    }

    // ---- MirredAction ----

    #[test]
    fn mirred_parse_params_egress_redirect_by_ifindex() {
        let a = MirredAction::parse_params(&["egress", "redirect", "ifindex", "7"]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&MirredAction::redirect_to_egress(7)),
        );
    }

    #[test]
    fn mirred_parse_params_ingress_mirror_by_ifindex() {
        let a = MirredAction::parse_params(&["ingress", "mirror", "ifindex", "11"]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&MirredAction::mirror_to_ingress(11)),
        );
    }

    #[test]
    fn mirred_parse_params_token_order_independent() {
        let a = MirredAction::parse_params(&["ifindex", "3", "ingress", "redirect"]).unwrap();
        let b = MirredAction::parse_params(&["ingress", "redirect", "ifindex", "3"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn mirred_parse_params_dev_and_ifindex_mutually_exclusive() {
        // We can't easily test `dev <name>` (sysfs lookup), but we
        // can verify the mutex error fires when both are set.
        let err = MirredAction::parse_params(&["ifindex", "1", "ifindex", "2"]).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn mirred_parse_params_missing_ifindex_errors() {
        let err = MirredAction::parse_params(&["egress", "redirect"]).unwrap_err();
        assert!(err.to_string().contains("target interface required"));
    }

    // ---- VlanAction ----

    #[test]
    fn vlan_parse_params_pop() {
        let a = VlanAction::parse_params(&["pop"]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&VlanAction::pop())
        );
    }

    #[test]
    fn vlan_parse_params_push_with_priority() {
        let a = VlanAction::parse_params(&["push", "100", "priority", "3"]).unwrap();
        let b = VlanAction::push(100).priority(3);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn vlan_parse_params_modify_qinq() {
        let a = VlanAction::parse_params(&["modify", "200", "protocol", "802.1ad"]).unwrap();
        let b = VlanAction::modify(200).qinq();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn vlan_parse_params_id_out_of_range_errors() {
        let err = VlanAction::parse_params(&["push", "5000"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn vlan_parse_params_missing_op_errors() {
        let err = VlanAction::parse_params(&["priority", "3"]).unwrap_err();
        assert!(err.to_string().contains("missing operation"));
    }

    #[test]
    fn vlan_parse_params_unknown_protocol_errors() {
        let err = VlanAction::parse_params(&["pop", "protocol", "wat"]).unwrap_err();
        assert!(err.to_string().contains("unknown protocol"));
    }

    // ---- MplsAction ----

    #[test]
    fn mpls_parse_params_push() {
        let a =
            MplsAction::parse_params(&["push", "label", "100", "ttl", "64", "tc", "3"]).unwrap();
        let b = MplsAction::push(100).ttl(64).tc(3).build();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn mpls_parse_params_pop_protocol_names() {
        let a = MplsAction::parse_params(&["pop", "protocol", "ipv4"]).unwrap();
        assert_eq!(a.proto, Some(0x0800));
        let b = MplsAction::parse_params(&["pop", "protocol", "0x8847"]).unwrap();
        assert_eq!(b.proto, Some(0x8847));
    }

    #[test]
    fn mpls_parse_params_strict() {
        // push requires a label
        assert!(MplsAction::parse_params(&["push"]).is_err());
        // missing op
        assert!(MplsAction::parse_params(&["label", "5"]).is_err());
        // out-of-range label / tc, unknown token, bad protocol
        assert!(MplsAction::parse_params(&["push", "label", "2000000"]).is_err());
        assert!(MplsAction::parse_params(&["modify", "tc", "9"]).is_err());
        assert!(MplsAction::parse_params(&["pop", "protocol", "nope"]).is_err());
        assert!(MplsAction::parse_params(&["bogus"]).is_err());
    }

    // ---- SkbmodAction ----

    #[test]
    fn skbmod_parse_params_set_and_swap() {
        let a = SkbmodAction::parse_params(&["set", "dmac", "02:00:00:00:00:01", "swap", "mac"])
            .unwrap();
        let b = SkbmodAction::new()
            .set_dmac([0x02, 0, 0, 0, 0, 1])
            .swap_mac()
            .build();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn skbmod_parse_params_strict() {
        // at least one op required
        assert!(SkbmodAction::parse_params(&[]).is_err());
        // bad MAC, unknown set target, unknown token, swap non-mac
        assert!(SkbmodAction::parse_params(&["set", "smac", "zz"]).is_err());
        assert!(SkbmodAction::parse_params(&["set", "bogus", "1"]).is_err());
        assert!(SkbmodAction::parse_params(&["swap", "ip"]).is_err());
        assert!(SkbmodAction::parse_params(&["nope"]).is_err());
    }

    // ---- SkbeditAction ----

    #[test]
    fn skbedit_parse_params_priority() {
        let a = SkbeditAction::parse_params(&["priority", "7"]).unwrap();
        let b = SkbeditAction::new().priority(7).build();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn skbedit_parse_params_mark() {
        let a = SkbeditAction::parse_params(&["mark", "42"]).unwrap();
        let b = SkbeditAction::new().mark(42).build();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn skbedit_parse_params_mark_with_mask_any_order() {
        // tc(8) reads marks in any base and writes the mask after a
        // slash (#817); nlink's `mask` keyword reads too.
        let a = SkbeditAction::parse_params(&["mark", "1/0xff"]).unwrap();
        let b = SkbeditAction::parse_params(&["mark", "1", "mask", "0xff"]).unwrap();
        let c = SkbeditAction::parse_params(&["mask", "255", "mark", "1"]).unwrap();
        let d = SkbeditAction::parse_params(&["mark", "01/0377"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
        assert_eq!(write_options_bytes(&b), write_options_bytes(&c));
        assert_eq!(write_options_bytes(&c), write_options_bytes(&d));
        assert!(SkbeditAction::parse_params(&["mark", "1/0xfg"]).is_err());
    }

    #[test]
    fn skbedit_priority_is_a_class_id() {
        // tc(8)'s get_tc_classid(): hex, or major:minor in hex (#817).
        for (word, prio) in [("10", 0x10), ("1:10", 0x1_0010), (":7", 7), ("ff:", 0xff_0000), ("none", 0)] {
            let a = SkbeditAction::parse_params(&["priority", word]).unwrap();
            let b = SkbeditAction::new().priority(prio);
            assert_eq!(write_options_bytes(&a), write_options_bytes(&b), "{word}");
        }
        assert!(SkbeditAction::parse_params(&["priority", "1:2:3"]).is_err());
        assert!(SkbeditAction::parse_params(&["priority", "x"]).is_err());
    }

    #[test]
    fn skbedit_parse_params_mask_without_mark_errors() {
        let err = SkbeditAction::parse_params(&["mask", "255"]).unwrap_err();
        assert!(err.to_string().contains("`mask` requires a `mark`"));
    }

    #[test]
    fn skbedit_parse_params_queue_mapping_out_of_range() {
        let err = SkbeditAction::parse_params(&["queue_mapping", "100000"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    // ---- ConnmarkAction ----

    #[test]
    fn connmark_parse_params_default_zone_zero() {
        let a = ConnmarkAction::parse_params(&[]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&ConnmarkAction::new()),
        );
    }

    #[test]
    fn connmark_parse_params_with_zone() {
        let a = ConnmarkAction::parse_params(&["zone", "5"]).unwrap();
        let b = ConnmarkAction::with_zone(5);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn connmark_parse_params_zone_out_of_range_errors() {
        let err = ConnmarkAction::parse_params(&["zone", "100000"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn connmark_parse_params_unknown_token_errors() {
        let err = ConnmarkAction::parse_params(&["nonsense"]).unwrap_err();
        assert!(err.to_string().contains("connmark: unknown token"));
    }

    // ---- CtinfoAction ----

    #[test]
    fn ctinfo_parse_params_dscp_with_statemask() {
        let a = CtinfoAction::parse_params(&["dscp", "0xfc/0x01", "zone", "5"]).unwrap();
        assert_eq!(ActionConfig::kind(&a), "ctinfo");
        assert_eq!(a.dscp_mask, Some(0xfc));
        assert_eq!(a.dscp_statemask, Some(0x01));
        assert_eq!(a.zone, Some(5));
        // statemask defaults to 0 when omitted
        let a2 = CtinfoAction::parse_params(&["dscp", "0xfc"]).unwrap();
        assert_eq!(a2.dscp_mask, Some(0xfc));
        assert_eq!(a2.dscp_statemask, Some(0));
    }

    #[test]
    fn ctinfo_parse_params_cpmark_optional_mask() {
        // bare cpmark -> default all-ones mask, and must NOT swallow the
        // following keyword.
        let a = CtinfoAction::parse_params(&["cpmark", "zone", "1"]).unwrap();
        assert_eq!(a.cpmark_mask, Some(0xffff_ffff));
        assert_eq!(a.zone, Some(1));
        // explicit mask consumed
        let a2 = CtinfoAction::parse_params(&["cpmark", "0x00ff"]).unwrap();
        assert_eq!(a2.cpmark_mask, Some(0x00ff));
    }

    #[test]
    fn ctinfo_parse_params_requires_dscp_or_cpmark() {
        let err = CtinfoAction::parse_params(&["zone", "1"]).unwrap_err();
        assert!(
            err.to_string().contains("at least one of `dscp`/`cpmark`"),
            "got: {err}"
        );
    }

    #[test]
    fn ctinfo_parse_params_strict_errors() {
        assert!(
            CtinfoAction::parse_params(&["nonsense"])
                .unwrap_err()
                .to_string()
                .contains("ctinfo: unknown token")
        );
        assert!(
            CtinfoAction::parse_params(&["dscp", "nothex"])
                .unwrap_err()
                .to_string()
                .contains("invalid dscp mask")
        );
        assert!(
            CtinfoAction::parse_params(&["zone", "70000"])
                .unwrap_err()
                .to_string()
                .contains("out of range")
        );
    }

    // ---- IfeAction ----

    #[test]
    fn ife_parse_params_encode_allow_and_use() {
        let a = IfeAction::parse_params(&[
            "encode",
            "allow",
            "mark",
            "use",
            "prio",
            "7",
            "dst",
            "02:00:00:00:00:01",
            "type",
            "0xed3e",
        ])
        .unwrap();
        assert_eq!(ActionConfig::kind(&a), "ife");
        assert_eq!(a.metadata.len(), 2);
        assert_eq!(a.metadata[0].kind, IfeMeta::Mark);
        assert_eq!(a.metadata[0].value, None); // allow
        assert_eq!(a.metadata[1].kind, IfeMeta::Prio);
        assert_eq!(a.metadata[1].value, Some(7)); // use
        assert_eq!(a.etype, Some(0xed3e));
        assert!(a.dmac.is_some());
        assert!(a.encode);
    }

    #[test]
    fn ife_parse_params_decode_mode() {
        let a = IfeAction::parse_params(&["decode", "allow", "tcindex"]).unwrap();
        assert!(!a.encode);
        assert_eq!(a.metadata[0].kind, IfeMeta::TcIndex);
    }

    #[test]
    fn ife_parse_params_mode_required_first() {
        let err = IfeAction::parse_params(&["allow", "mark"]).unwrap_err();
        assert!(
            err.to_string()
                .contains("first token must be `encode` or `decode`")
        );
    }

    #[test]
    fn ife_parse_params_strict_errors() {
        assert!(
            IfeAction::parse_params(&["encode", "allow", "bogusmeta"])
                .unwrap_err()
                .to_string()
                .contains("unknown metadata")
        );
        assert!(
            IfeAction::parse_params(&["encode", "use", "mark"])
                .unwrap_err()
                .to_string()
                .contains("requires a value")
        );
        assert!(
            IfeAction::parse_params(&["encode", "nonsense"])
                .unwrap_err()
                .to_string()
                .contains("ife: unknown token")
        );
    }

    // ---- GateAction ----

    #[test]
    fn gate_parse_params_schedule() {
        let a = GateAction::parse_params(&[
            "priority",
            "0",
            "cycle-time",
            "2ms",
            "clockid",
            "TAI",
            "sched-entry",
            "open",
            "1ms",
            "sched-entry",
            "close",
            "1ms",
        ])
        .unwrap();
        assert_eq!(ActionConfig::kind(&a), "gate");
        assert_eq!(a.priority, Some(0));
        assert_eq!(a.cycle_time, Some(2_000_000));
        assert_eq!(a.clockid, Some(11)); // CLOCK_TAI
        assert_eq!(a.entries.len(), 2);
        assert!(a.entries[0].open);
        assert_eq!(a.entries[0].interval_ns, 1_000_000);
        assert!(!a.entries[1].open);
    }

    #[test]
    fn gate_parse_params_entry_optional_ipv_max_octets() {
        // ipv + max-octets consumed greedily, then a following keyword
        // (sched-entry) is NOT swallowed.
        let a = GateAction::parse_params(&[
            "sched-entry",
            "open",
            "300us",
            "2",
            "1500",
            "sched-entry",
            "close",
            "300us",
        ])
        .unwrap();
        assert_eq!(a.entries.len(), 2);
        assert_eq!(a.entries[0].ipv, Some(2));
        assert_eq!(a.entries[0].max_octets, Some(1500));
        assert_eq!(a.entries[1].ipv, None);
    }

    #[test]
    fn gate_parse_params_clockid_names() {
        assert_eq!(
            GateAction::parse_params(&["clockid", "CLOCK_REALTIME"])
                .unwrap()
                .clockid,
            Some(0)
        );
        assert_eq!(
            GateAction::parse_params(&["clockid", "MONOTONIC"])
                .unwrap()
                .clockid,
            Some(1)
        );
    }

    #[test]
    fn gate_parse_params_strict_errors() {
        assert!(
            GateAction::parse_params(&["nonsense"])
                .unwrap_err()
                .to_string()
                .contains("gate: unknown token")
        );
        assert!(
            GateAction::parse_params(&["sched-entry", "halfopen", "1ms"])
                .unwrap_err()
                .to_string()
                .contains("expected open or close")
        );
        assert!(
            GateAction::parse_params(&["cycle-time", "notatime"])
                .unwrap_err()
                .to_string()
                .contains("invalid cycle-time")
        );
    }

    // ==========================================================
    // Plan 139 PR B sub-slice 2 — 6 more action parsers.
    // ==========================================================

    // ---- CsumAction ----

    #[test]
    fn csum_parse_params_iph_only() {
        let a = CsumAction::parse_params(&["iph"]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&CsumAction::new().iph())
        );
    }

    #[test]
    fn csum_parse_params_combo_any_order_idempotent() {
        let a = CsumAction::parse_params(&["iph", "tcp", "udp"]).unwrap();
        let b = CsumAction::parse_params(&["udp", "iph", "tcp"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
        // Duplicate is a no-op (bitmask OR).
        let c = CsumAction::parse_params(&["iph", "iph", "tcp", "tcp", "udp"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&c));
    }

    #[test]
    fn csum_parse_params_all_kinds() {
        let a = CsumAction::parse_params(&["iph", "icmp", "igmp", "tcp", "udp", "udplite", "sctp"])
            .unwrap();
        let b = CsumAction::new()
            .iph()
            .icmp()
            .igmp()
            .tcp()
            .udp()
            .udplite()
            .sctp();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn csum_parse_params_unknown_kind_errors() {
        let err = CsumAction::parse_params(&["iph", "wat"]).unwrap_err();
        assert!(err.to_string().contains("unknown checksum kind"));
    }

    // ---- SampleAction ----

    #[test]
    fn sample_parse_params_required_rate_and_group() {
        let a = SampleAction::parse_params(&["rate", "100", "group", "5"]).unwrap();
        assert_eq!(
            write_options_bytes(&a),
            write_options_bytes(&SampleAction::new(100, 5))
        );
    }

    #[test]
    fn sample_parse_params_with_trunc_any_order() {
        let a = SampleAction::parse_params(&["trunc", "128", "rate", "100", "group", "5"]).unwrap();
        let b = SampleAction::new(100, 5).trunc(128);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn sample_parse_params_missing_rate_errors() {
        let err = SampleAction::parse_params(&["group", "5"]).unwrap_err();
        assert!(err.to_string().contains("`rate <N>` required"));
    }

    #[test]
    fn sample_parse_params_missing_group_errors() {
        let err = SampleAction::parse_params(&["rate", "100"]).unwrap_err();
        assert!(err.to_string().contains("`group <G>` required"));
    }

    // ---- TunnelKeyAction ----

    #[test]
    fn tunnel_key_parse_params_set_full_v4() {
        let a = TunnelKeyAction::parse_params(&[
            "set", "src", "10.0.0.1", "dst", "10.0.0.2", "id", "100", "dst_port", "4789",
        ])
        .unwrap();
        let b = TunnelKeyAction::set()
            .src("10.0.0.1".parse().unwrap())
            .dst("10.0.0.2".parse().unwrap())
            .key_id(100)
            .dst_port(4789);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn tunnel_key_parse_params_release_emits_no_metadata() {
        let a = TunnelKeyAction::parse_params(&["release"]).unwrap();
        let b = TunnelKeyAction::release();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn tunnel_key_parse_params_set_with_no_csum_no_frag() {
        let a = TunnelKeyAction::parse_params(&[
            "set", "dst", "10.0.0.2", "id", "1", "no_csum", "no_frag",
        ])
        .unwrap();
        let b = TunnelKeyAction::set()
            .dst("10.0.0.2".parse().unwrap())
            .key_id(1)
            .no_csum()
            .no_frag();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn tunnel_key_parse_params_release_rejects_set_modifiers() {
        let err = TunnelKeyAction::parse_params(&["release", "src", "10.0.0.1"]).unwrap_err();
        assert!(err.to_string().contains("only valid with `set`"));
    }

    #[test]
    fn tunnel_key_parse_params_missing_op_errors() {
        let err = TunnelKeyAction::parse_params(&["src", "10.0.0.1"]).unwrap_err();
        assert!(err.to_string().contains("missing operation"));
    }

    #[test]
    fn tunnel_key_parse_params_invalid_dst_port_errors() {
        let err = TunnelKeyAction::parse_params(&["set", "dst_port", "70000"]).unwrap_err();
        assert!(err.to_string().contains("dst_port"));
    }

    // ---- NatAction ----

    #[test]
    fn nat_parse_params_egress_snat_full_addr() {
        let a = NatAction::parse_params(&["egress", "10.0.0.1", "192.168.0.1"]).unwrap();
        let b = NatAction::snat("10.0.0.1".parse().unwrap(), "192.168.0.1".parse().unwrap());
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn nat_parse_params_ingress_dnat_with_prefix() {
        let a = NatAction::parse_params(&["ingress", "10.0.0.0/24", "192.168.0.0"]).unwrap();
        let b =
            NatAction::dnat("10.0.0.0".parse().unwrap(), "192.168.0.0".parse().unwrap()).prefix(24);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn nat_parse_params_short_input_errors() {
        let err = NatAction::parse_params(&["egress", "10.0.0.1"]).unwrap_err();
        assert!(err.to_string().contains("requires"));
    }

    #[test]
    fn nat_parse_params_unknown_direction_errors() {
        let err = NatAction::parse_params(&["wat", "10.0.0.1", "192.168.0.1"]).unwrap_err();
        assert!(err.to_string().contains("direction"));
    }

    #[test]
    fn nat_parse_params_invalid_prefix_errors() {
        let err = NatAction::parse_params(&["egress", "10.0.0.0/40", "192.168.0.0"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    // ---- SimpleAction ----

    #[test]
    fn simple_parse_params_sdata_required() {
        let err = SimpleAction::parse_params(&[]).unwrap_err();
        assert!(err.to_string().contains("`sdata <text>` required"));
    }

    #[test]
    fn simple_parse_params_sdata_only() {
        let a = SimpleAction::parse_params(&["sdata", "matched-port-80"]).unwrap();
        let b = SimpleAction::new("matched-port-80");
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn simple_parse_params_with_verdict() {
        let a = SimpleAction::parse_params(&["sdata", "trace", "verdict", "drop"]).unwrap();
        let b = SimpleAction::new("trace").drop();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn simple_parse_params_unknown_verdict_rebrands_error_prefix() {
        let err = SimpleAction::parse_params(&["sdata", "x", "verdict", "wat"]).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("simple:"),
            "must rebrand gact: → simple: ({msg})"
        );
        assert!(!msg.contains("gact:"));
    }

    // ---- BpfAction ----

    #[test]
    fn bpf_parse_params_fd_basic() {
        let a = BpfAction::parse_params(&["fd", "42"]).unwrap();
        let b = BpfAction::with_raw_fd(42);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn bpf_parse_params_fd_with_name() {
        let a = BpfAction::parse_params(&["fd", "7", "name", "trace"]).unwrap();
        let b = BpfAction::with_raw_fd(7).name("trace");
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn bpf_parse_params_fd_with_verdict() {
        let a = BpfAction::parse_params(&["fd", "1", "verdict", "drop"]).unwrap();
        let b = BpfAction::with_raw_fd(1).verdict(action::TC_ACT_SHOT);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn bpf_parse_params_pinned_missing_path_errors() {
        let err = BpfAction::parse_params(&["pinned", "/nonexistent/xyzzy"]).unwrap_err();
        assert!(err.to_string().contains("bpf: open pinned program"), "{err}");
        // The kernel's errno survives, not a message (#718).
        assert!(err.errno().is_some(), "{err:?}");
    }

    /// #645: a mirred `dev` is kept by name, for the connection that
    /// installs the action to resolve in its namespace, not looked up in
    /// the caller's. Unresolved, it does not write; resolved, it writes the
    /// ifindex; a name the namespace does not have is not found (#718).
    #[test]
    fn mirred_dev_is_resolved_by_the_installer() {
        let mut m = MirredAction::parse_params(&["egress", "redirect", "dev", "ifb0"]).unwrap();
        assert_eq!(m.target_dev(), Some("ifb0"));
        assert_eq!(ActionConfig::device_names(&m), ["ifb0"]);
        let mut b = MessageBuilder::new(0, 0);
        let err = ActionConfig::write_options(&m, &mut b).unwrap_err();
        assert!(err.to_string().contains("resolved by the connection"), "{err}");

        let err = ActionConfig::resolve_devices(&mut m, &HashMap::new()).unwrap_err();
        assert!(err.is_not_found(), "{err:?}");
        assert_eq!(err.context(), ["mirred"], "{err:?}");

        ActionConfig::resolve_devices(&mut m, &HashMap::from([("ifb0".to_string(), 7)])).unwrap();
        let want = MirredAction::redirect_to_egress(7);
        let bytes = |a: &MirredAction| {
            let mut b = MessageBuilder::new(0, 0);
            let start = b.len();
            ActionConfig::write_options(a, &mut b).unwrap();
            b.as_bytes()[start..].to_vec()
        };
        assert_eq!(bytes(&m), bytes(&want));

        // In a list, and through a filter.
        let list = ActionList::new()
            .with(GactAction::drop())
            .with(MirredAction::mirror_to_ingress(0).to_dev("veth1"));
        assert_eq!(list.device_names(), ["veth1"]);
        let mut filter = crate::netlink::filter::MatchallFilter::new().actions(list);
        assert_eq!(crate::netlink::filter::FilterConfig::device_names(&filter), ["veth1"]);
        crate::netlink::filter::FilterConfig::resolve_devices(
            &mut filter,
            &HashMap::from([("veth1".to_string(), 9)]),
        )
        .unwrap();
        let mut b = MessageBuilder::new(0, 0);
        crate::netlink::filter::FilterConfig::write_options(&filter, &mut b).unwrap();
    }

    #[test]
    fn bpf_parse_params_no_source_errors() {
        let err = BpfAction::parse_params(&["name", "x"]).unwrap_err();
        assert!(err.to_string().contains("program source required"));
    }

    #[test]
    fn bpf_parse_params_pinned_and_fd_mutually_exclusive() {
        let err = BpfAction::parse_params(&["fd", "1", "fd", "2"]).unwrap_err();
        assert!(err.to_string().contains("only one of"));
    }

    // ==========================================================
    // Plan 139 PR B sub-slice 3 — police / ct / pedit (closes
    // PR B at 14 of 14 action kinds typed-first; pedit is a
    // not-yet-typed-modelled stub per Plan 139 §10).
    // ==========================================================

    // ---- PoliceAction ----

    /// #800: what a line leaves out is what tc(8) leaves out: an mtu of 0,
    /// for the kernel to pick, and `reclassify` for what exceeds.
    #[test]
    fn police_parse_params_rate_and_burst() {
        let a = PoliceAction::parse_params(&["rate", "1mbit", "burst", "32k"]).unwrap();
        let b = PoliceAction::new()
            .rate(crate::util::Rate::mbit(1))
            .burst(crate::util::Bytes::kib(32))
            .mtu(crate::util::Bytes::new(0))
            .exceed_reclassify();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    /// #751: a bare gate time is nanoseconds, as tc-gate(8) reads it, and a
    /// bare decimal means nothing; an interval past the kernel's u32
    /// nanoseconds is refused when written, where it used to wrap.
    #[test]
    fn gate_times_are_nanoseconds_and_intervals_do_not_wrap() {
        use std::time::Duration;
        let parsed = GateAction::parse_params(&["base-time", "1000", "sched-entry", "open", "2000"])
            .unwrap();
        let want = GateAction::new()
            .base_time(Duration::from_nanos(1000))
            .sched_entry(true, Duration::from_nanos(2000), None, None);
        assert_eq!(write_options_bytes(&parsed), write_options_bytes(&want));
        let err = GateAction::parse_params(&["base-time", "1.5"]).unwrap_err();
        assert!(err.to_string().contains("whole number of nanoseconds"), "{err}");

        let long = GateAction::new().sched_entry(true, Duration::from_secs(5), None, None);
        let mut b = MessageBuilder::new(0, 0);
        let err = ActionConfig::write_options(&long, &mut b).unwrap_err();
        assert!(err.to_string().contains("past the kernel's u32 nanoseconds"), "{err}");
    }

    /// #751: `conform-exceed` is exceed first, as tc-police(8) reads it:
    /// `drop/pipe` drops what exceeds and pipes what conforms. The conform
    /// half is optional.
    #[test]
    fn police_parse_params_conform_exceed_is_exceed_first() {
        let police = |pair: &str| {
            PoliceAction::parse_params(&["rate", "1mbit", "burst", "32k", "conform-exceed", pair])
                .unwrap()
        };
        let base = || {
            PoliceAction::new()
                .rate(crate::util::Rate::mbit(1))
                .burst(crate::util::Bytes::kib(32))
                .mtu(crate::util::Bytes::new(0))
        };
        assert_eq!(
            write_options_bytes(&police("drop/pipe")),
            write_options_bytes(&base().exceed(action::TC_ACT_SHOT).conform(action::TC_ACT_PIPE))
        );
        assert_eq!(
            write_options_bytes(&police("reclassify")),
            write_options_bytes(&base().exceed(action::TC_ACT_RECLASSIFY))
        );
    }

    #[test]
    fn police_parse_params_individual_conform_exceed() {
        let a = PoliceAction::parse_params(&[
            "rate",
            "1mbit",
            "burst",
            "32k",
            "conform",
            "pipe",
            "exceed",
            "reclassify",
        ])
        .unwrap();
        let b = PoliceAction::new()
            .rate(crate::util::Rate::mbit(1))
            .burst(crate::util::Bytes::kib(32))
            .mtu(crate::util::Bytes::new(0))
            .conform(action::TC_ACT_PIPE)
            .exceed(action::TC_ACT_RECLASSIFY);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn police_parse_params_invalid_rate_errors() {
        let err = PoliceAction::parse_params(&["rate", "wat", "burst", "32k"]).unwrap_err();
        assert!(err.to_string().contains("invalid rate"));
    }

    /// The conform half is optional (#751); what is there must be a verdict.
    #[test]
    fn police_parse_params_conform_exceed_bad_verdict_errors() {
        let err = PoliceAction::parse_params(&["conform-exceed", "passdrop"]).unwrap_err();
        assert!(err.to_string().contains("police: unknown verdict `passdrop`"), "{err}");
    }

    #[test]
    fn police_parse_params_conform_exceed_unknown_verdict_rebrands() {
        let err = PoliceAction::parse_params(&["conform-exceed", "wat/drop"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("police:"), "rebranded prefix expected: {msg}");
        assert!(!msg.contains("gact:"));
    }

    // ---- CtAction ----

    #[test]
    fn ct_parse_params_commit_with_zone_and_mark() {
        let a = CtAction::parse_params(&["commit", "zone", "5", "mark", "0", "0"]).unwrap();
        // Build the equivalent via the typed builder. mark expects
        // decimal u32 (no hex in this parser today — locked in by
        // sub-slice 1's skbedit test).
        let b = CtAction::commit().zone(5).mark(0, 0);
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn ct_parse_params_clear_with_force() {
        // `force` is meaningful when combined with commit per
        // kernel docs, but the parser accepts it regardless and
        // lets the kernel reject if invalid.
        let a = CtAction::parse_params(&["clear", "force"]).unwrap();
        let b = CtAction::clear().force();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn ct_parse_params_nat_src_single_addr() {
        let a = CtAction::parse_params(&["commit", "nat", "src", "10.0.0.1"]).unwrap();
        let b = CtAction::commit().nat_src_single("10.0.0.1".parse().unwrap());
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn ct_parse_params_nat_dst_address_range() {
        let a = CtAction::parse_params(&["commit", "nat", "dst", "10.0.0.10-10.0.0.20"]).unwrap();
        let b =
            CtAction::commit().nat_dst("10.0.0.10".parse().unwrap(), "10.0.0.20".parse().unwrap());
        assert_eq!(write_options_bytes(&a), write_options_bytes(&b));
    }

    #[test]
    fn ct_parse_params_zone_out_of_range_errors() {
        let err = CtAction::parse_params(&["zone", "100000"]).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn ct_parse_params_mark_reads_tcs_forms() {
        // tc-ct(8)'s `mark MARK[/MASK]`; without a mask, all of the mark
        // (#817). nlink's `<value> <mask>` still reads.
        let all = CtAction::new().mark(1, u32::MAX);
        for words in [&["mark", "1"][..], &["mark", "1/0xffffffff"], &["mark", "1", "4294967295"]] {
            let a = CtAction::parse_params(words).unwrap();
            assert_eq!(write_options_bytes(&a), write_options_bytes(&all), "{words:?}");
        }
        let a = CtAction::parse_params(&["mark", "7/0xff"]).unwrap();
        assert_eq!(write_options_bytes(&a), write_options_bytes(&CtAction::new().mark(7, 0xff)));
    }

    /// #751: `nat` reads as tc-ct(8) writes it — `nat src addr <range>`,
    /// the old form without `addr` too, and a bare `nat` — and what follows
    /// a bare `nat` is a token of its own.
    #[test]
    fn ct_parse_params_nat_reads_tc_spelling() {
        let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let want = write_options_bytes(&CtAction::new().nat_src(v4("10.0.0.1"), v4("10.0.0.9")));
        for form in [
            &["nat", "src", "addr", "10.0.0.1-10.0.0.9"][..],
            &["nat", "src", "10.0.0.1-10.0.0.9"],
        ] {
            assert_eq!(write_options_bytes(&CtAction::parse_params(form).unwrap()), want, "{form:?}");
        }
        assert_eq!(
            write_options_bytes(&CtAction::parse_params(&["nat"]).unwrap()),
            write_options_bytes(&CtAction::new().nat())
        );
        let err = CtAction::parse_params(&["nat", "wat", "10.0.0.1"]).unwrap_err();
        assert!(err.to_string().contains("`wat`"), "{err}");
        let err = CtAction::parse_params(&["nat", "dst", "addr"]).unwrap_err();
        assert!(err.to_string().contains("requires an address"), "{err}");
    }

    // ---- PeditAction (munge DSL parser) ----

    #[test]
    fn pedit_parse_ip_src_matches_builder() {
        // A pedit line's verdict is tc(8)'s `pass` (#817).
        let parsed = PeditAction::parse_params(&["munge", "ip", "src", "set", "10.0.0.1"]).unwrap();
        let built = PeditAction::new().set_ipv4_src("10.0.0.1".parse().unwrap()).action(action::TC_ACT_OK);
        assert_eq!(write_options_bytes(&parsed), write_options_bytes(&built));
    }

    #[test]
    fn pedit_parse_multi_munge_and_control_action() {
        // ip dst + tcp dport + trailing `pipe` control verdict.
        let parsed = PeditAction::parse_params(&[
            "munge",
            "ip",
            "dst",
            "set",
            "192.168.1.2",
            "munge",
            "tcp",
            "dport",
            "set",
            "8080",
            "pipe",
        ])
        .unwrap();
        let built = PeditAction::new()
            .set_ipv4_dst("192.168.1.2".parse().unwrap())
            .set_tcp_dport(8080)
            .action(action::TC_ACT_PIPE);
        assert_eq!(write_options_bytes(&parsed), write_options_bytes(&built));
    }

    #[test]
    fn pedit_parse_eth_and_ttl_and_drop() {
        let parsed = PeditAction::parse_params(&[
            "munge",
            "eth",
            "dst",
            "set",
            "aa:bb:cc:dd:ee:ff",
            "munge",
            "ip",
            "ttl",
            "set",
            "64",
            "drop",
        ])
        .unwrap();
        let built = PeditAction::new()
            .set_eth_dst([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
            .set_ipv4_ttl(64)
            .action(action::TC_ACT_SHOT);
        assert_eq!(write_options_bytes(&parsed), write_options_bytes(&built));
    }

    #[test]
    fn pedit_parse_raw_offset_with_size_and_retain() {
        // `munge offset 12 u32 set 0x0a000001 retain 0xffffffff`
        let parsed = PeditAction::parse_params(&[
            "munge",
            "offset",
            "12",
            "u32",
            "set",
            "0x0a000001",
            "retain",
            "0xffffffff",
        ])
        .unwrap();
        let built = PeditAction::new()
            .set_raw(pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK, 12, 0x0a00_0001, 0xffff_ffff)
            .action(action::TC_ACT_OK);
        assert_eq!(write_options_bytes(&parsed), write_options_bytes(&built));
    }

    #[test]
    fn pedit_parse_raw_offset_add_defaults_mask_zero() {
        let parsed = PeditAction::parse_params(&["munge", "offset", "8", "add", "1"]).unwrap();
        let built = PeditAction::new()
            .add_raw(pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK, 8, 1, 0)
            .action(action::TC_ACT_OK);
        assert_eq!(write_options_bytes(&parsed), write_options_bytes(&built));
    }

    #[test]
    fn pedit_parse_rejects_empty() {
        let err = PeditAction::parse_params(&[]).unwrap_err();
        assert!(err.to_string().contains("pedit:"), "{err}");
        assert!(err.to_string().contains("at least one"), "{err}");
    }

    #[test]
    fn pedit_parse_rejects_unmodelled_layer_field() {
        // ip6 has no typed builder — must error, not silently skip.
        let err = PeditAction::parse_params(&["munge", "ip6", "src", "set", "::1"]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("not modelled"), "{msg}");
        assert!(
            msg.contains("offset"),
            "points at the raw escape hatch: {msg}"
        );
    }

    #[test]
    fn pedit_parse_rejects_unmodelled_layered_op() {
        let err = PeditAction::parse_params(&["munge", "ip", "ttl", "add", "1"]).unwrap_err();
        assert!(err.to_string().contains("not modelled"), "{err}");
    }

    #[test]
    fn pedit_parse_rejects_garbage_value() {
        let err =
            PeditAction::parse_params(&["munge", "tcp", "dport", "set", "notaport"]).unwrap_err();
        assert!(err.to_string().contains("pedit:"), "{err}");
        let err2 = PeditAction::parse_params(&["munge", "ip", "ttl", "set", "999"]).unwrap_err();
        assert!(err2.to_string().contains("out of range"), "{err2}");
    }

    #[test]
    fn pedit_parse_rejects_unknown_leading_token() {
        let err = PeditAction::parse_params(&["frobnicate"]).unwrap_err();
        assert!(err.to_string().contains("unexpected token"), "{err}");
    }
}

/// `to_params` is `parse_params`' inverse (#645): the tokens an action
/// writes parse back to one that writes the same request, and the same
/// tokens.
#[cfg(test)]
mod params_tests {
    use super::*;
    use crate::netlink::parse_params::ParseParams;

    fn bytes(a: &dyn ActionConfigDyn) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        a.write_options(&mut b).unwrap_or_else(|e| panic!("{a:?}: {e}"));
        b.as_bytes()[start..].to_vec()
    }

    /// The tokens `a` writes; that they read back as `a` is asserted.
    fn round_trips<A>(a: A) -> Vec<String>
    where
        A: ActionConfig + ParseParams + Clone + std::fmt::Debug + 'static,
    {
        let tokens = ActionConfig::to_params(&a).unwrap_or_else(|e| panic!("{a:?}: {e}"));
        let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
        let back = A::parse_params(&refs).unwrap_or_else(|e| panic!("{tokens:?}: {e}"));
        assert_eq!(ActionConfig::to_params(&back).unwrap(), tokens, "{a:?}");
        // A name stands for the same index on both sides.
        let names: HashMap<String, u32> = ActionConfig::device_names(&a)
            .into_iter()
            .zip(1..)
            .map(|(n, i)| (n.to_string(), i))
            .collect();
        let (mut a, mut back) = (a, back);
        ActionConfig::resolve_devices(&mut a, &names).unwrap();
        ActionConfig::resolve_devices(&mut back, &names).unwrap();
        assert_eq!(bytes(&back), bytes(&a), "{tokens:?}");
        tokens
    }

    #[test]
    fn gact_round_trips() {
        assert_eq!(round_trips(GactAction::drop()), ["drop"]);
        for a in [
            GactAction::pass(),
            GactAction::pipe(),
            GactAction::reclassify(),
            GactAction::stolen(),
            GactAction::new(action::TC_ACT_UNSPEC),
            GactAction::goto_chain(7),
            GactAction::pass().random_drop(25),
            GactAction::pass().random(100, action::TC_ACT_PIPE),
            GactAction::drop().deterministic(10, action::TC_ACT_OK),
        ] {
            round_trips(a);
        }
        assert_eq!(
            round_trips(GactAction::pass().random_drop(25)),
            ["pass", "random", "netrand", "drop", "25"]
        );
        // A probability no percentage scales to has no token.
        let mut odd = GactAction::pass().random_drop(25);
        odd.prob_val += 1;
        assert!(ActionConfig::to_params(&odd).is_err());
        assert!(ActionConfig::to_params(&GactAction::new(action::TC_ACT_TRAP)).is_err());
    }

    /// A goto is its opcode, not one bit of it: `continue` (-1) has every
    /// bit, and was read as a goto to chain 16777215. Chains take 28 bits.
    #[test]
    fn a_goto_is_its_opcode() {
        use crate::netlink::types::tc::action::{is_goto_chain, tc_act_chain, tc_act_goto_chain};
        assert!(!is_goto_chain(action::TC_ACT_UNSPEC));
        assert!(!is_goto_chain(action::TC_ACT_JUMP | 1));
        assert!(is_goto_chain(tc_act_goto_chain(7)));
        assert_eq!(tc_act_chain(tc_act_goto_chain(1 << 24)), 1 << 24);
    }

    #[test]
    fn mirred_round_trips() {
        assert_eq!(
            round_trips(MirredAction::redirect_to_egress(0).to_dev("ifb0")),
            ["egress", "redirect", "dev", "ifb0"]
        );
        assert_eq!(
            round_trips(MirredAction::mirror_to_ingress(7)),
            ["ingress", "mirror", "ifindex", "7"]
        );
        round_trips(MirredAction::redirect_to_ingress(3).to_dev("veth1"));
        // A verdict other than the constructor's is written.
        assert_eq!(
            round_trips(MirredAction::mirror_to_egress(0).to_dev("d0").action(action::TC_ACT_SHOT)),
            ["egress", "mirror", "dev", "d0", "drop"]
        );
        round_trips(MirredAction::redirect_to_egress(5).pipe());
    }

    /// An action kind without a token form says so.
    #[test]
    fn a_kind_without_tokens_says_so() {
        #[derive(Debug, Clone)]
        struct Opaque;
        impl ActionConfig for Opaque {
            fn kind(&self) -> &'static str {
                "opaque"
            }
            fn write_options(&self, _: &mut MessageBuilder) -> Result<()> {
                Ok(())
            }
        }
        let err = ActionList::new().with(Opaque).to_params().unwrap_err();
        assert!(err.to_string().contains("opaque: the action has no token form"), "{err}");
    }

    #[test]
    fn police_round_trips() {
        use crate::util::{Bytes, Rate};
        let p = || PoliceAction::new().rate(Rate::mbit(8)).burst(Bytes::kib(32));
        // What differs from tc(8)'s defaults is written (#800): the
        // builder's mtu and exceed verdict are not tc's.
        assert_eq!(round_trips(p()), ["rate", "8mbit", "burst", "32kib", "mtu", "2047b", "exceed", "drop"]);
        let words = ["rate", "8mbit", "burst", "32kib"];
        assert_eq!(round_trips(PoliceAction::parse_params(&words).unwrap()), words);
        for a in [
            PoliceAction::new(),
            p().peakrate(Rate::mbit(16)).mtu(Bytes::new(9000)),
            p().avrate(Rate::kbit(500)),
            // Past u32 bytes/s: the 64-bit rate attributes.
            p().rate(Rate::gbit(100)).peakrate(Rate::gbit(400)),
            p().rate(Rate::bytes_per_sec(12_345)).burst(Bytes::new(1500)),
            p().conform(action::TC_ACT_UNSPEC).exceed(action::TC_ACT_STOLEN),
        ] {
            round_trips(a);
        }
        // `conform` and `exceed` each by name, never as tc(8)'s
        // exceed-first `conform-exceed` pair.
        assert_eq!(
            round_trips(p().conform_pipe()),
            ["rate", "8mbit", "burst", "32kib", "mtu", "2047b", "conform", "pipe", "exceed", "drop"]
        );
        assert!(ActionConfig::to_params(&p().exceed(action::tc_act_goto_chain(1))).is_err());
    }

    #[test]
    fn vlan_round_trips() {
        assert_eq!(
            round_trips(VlanAction::push(100).priority(3).qinq()),
            ["push", "100", "priority", "3", "protocol", "802.1ad"]
        );
        for a in [
            VlanAction::pop(),
            VlanAction::pop().qinq(),
            VlanAction::modify(4095),
            VlanAction::push(0).action(action::TC_ACT_OK),
            VlanAction::modify(7).priority(0).action(action::TC_ACT_UNSPEC),
        ] {
            round_trips(a);
        }
        assert_eq!(round_trips(VlanAction::pop().action(action::TC_ACT_SHOT)), ["pop", "drop"]);
        // What `parse_params` refuses, the writer does too.
        assert!(ActionConfig::to_params(&VlanAction::push(5000)).is_err());
        assert!(ActionConfig::to_params(&VlanAction::pop().priority(8)).is_err());
        let goto = VlanAction::pop().action(action::tc_act_goto_chain(2));
        assert!(ActionConfig::to_params(&goto).is_err());
    }

    #[test]
    fn mpls_round_trips() {
        assert_eq!(
            round_trips(MplsAction::push(100).tc(3).ttl(64).bos(1).protocol(0x8847)),
            ["push", "label", "100", "tc", "3", "ttl", "64", "bos", "1", "protocol", "mpls_uc"]
        );
        for a in [
            MplsAction::pop(0x0800),
            MplsAction::pop(0x1234),
            MplsAction::modify().label(0xF_FFFF),
            MplsAction::dec_ttl(),
            MplsAction::dec_ttl().action(action::TC_ACT_SHOT),
        ] {
            round_trips(a);
        }
        assert!(ActionConfig::to_params(&MplsAction::push(0x10_0000)).is_err());
        assert!(ActionConfig::to_params(&MplsAction::modify().tc(8)).is_err());
        assert!(ActionConfig::to_params(&MplsAction::modify().bos(2)).is_err());
    }

    #[test]
    fn skbmod_round_trips() {
        let mac = [0x02, 0, 0, 0, 0, 0x01];
        assert_eq!(
            round_trips(SkbmodAction::new().set_dmac(mac)),
            ["set", "dmac", "02:00:00:00:00:01"]
        );
        for a in [
            SkbmodAction::new().set_smac(mac).set_etype(0x88b5),
            SkbmodAction::new().set_etype(0x0800).swap_mac(),
            SkbmodAction::new().swap_mac().action(action::TC_ACT_OK),
        ] {
            round_trips(a);
        }
        // Nothing to do is not an action the grammar can say.
        assert!(ActionConfig::to_params(&SkbmodAction::new()).is_err());
    }

    #[test]
    fn skbedit_round_trips() {
        assert_eq!(round_trips(SkbeditAction::new().priority(7)), ["priority", "0:7"]);
        assert_eq!(round_trips(SkbeditAction::new().priority(0x1_0010)), ["priority", "1:10"]);
        assert_eq!(round_trips(SkbeditAction::new().mark_with_mask(1, 0xff)), ["mark", "1/0xff"]);
        round_trips(SkbeditAction::new().ptype(3).inherit_dsfield());
        for a in [
            SkbeditAction::new(),
            SkbeditAction::new().mark(100),
            SkbeditAction::new().mark_with_mask(0x10, 0xff).queue_mapping(3),
            SkbeditAction::new().priority(0x1_0010).action(action::TC_ACT_OK),
        ] {
            round_trips(a);
        }
        assert_eq!(
            round_trips(SkbeditAction::new().mark_with_mask(1, 255).action(action::TC_ACT_SHOT)),
            ["mark", "1/0xff", "drop"]
        );
    }

    #[test]
    fn nat_round_trips() {
        let (net, to) = (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(
            round_trips(NatAction::snat(net, to).prefix(8)),
            ["egress", "10.0.0.0/8", "192.168.1.1"]
        );
        for a in [
            NatAction::dnat(to, net),
            NatAction::snat(net, to).prefix(0),
            NatAction::dnat(to, net).action(action::TC_ACT_UNSPEC),
        ] {
            round_trips(a);
        }
        assert_eq!(
            round_trips(NatAction::dnat(to, net).pipe()),
            ["ingress", "192.168.1.1", "10.0.0.0", "pipe"]
        );
        // A verdict, and nothing else, may follow the addresses.
        let tokens = ["egress", "10.0.0.1", "10.0.0.2", "pipe", "drop"];
        assert!(NatAction::parse_params(&tokens).is_err());
        assert!(NatAction::parse_params(&tokens[..4]).is_ok());
        assert!(NatAction::parse_params(&["egress", "10.0.0.1", "10.0.0.2", "wat"]).is_err());
    }

    #[test]
    fn tunnel_key_round_trips() {
        let v6: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            round_trips(
                TunnelKeyAction::set()
                    .src(Ipv4Addr::new(192, 168, 1, 1))
                    .dst(Ipv4Addr::new(192, 168, 1, 2))
                    .key_id(100)
                    .dst_port(4789)
            ),
            ["set", "src", "192.168.1.1", "dst", "192.168.1.2", "id", "100", "dst_port", "4789"]
        );
        for a in [
            TunnelKeyAction::release(),
            TunnelKeyAction::set(),
            TunnelKeyAction::set().src6(v6).dst6(v6).tos(4).ttl(64).no_csum().no_frag(),
            TunnelKeyAction::release().action(action::TC_ACT_SHOT),
        ] {
            round_trips(a);
        }
        // A release sends no metadata, and its grammar takes none.
        assert!(ActionConfig::to_params(&TunnelKeyAction::release().key_id(1)).is_err());
    }

    #[test]
    fn connmark_round_trips() {
        assert_eq!(round_trips(ConnmarkAction::with_zone(1)), ["zone", "1"]);
        assert!(round_trips(ConnmarkAction::new()).is_empty());
        assert_eq!(round_trips(ConnmarkAction::new().action(action::TC_ACT_OK)), ["pass"]);
    }

    #[test]
    fn ctinfo_round_trips() {
        assert_eq!(
            round_trips(CtinfoAction::new().dscp(0xfc, 0x1).cpmark(0xffff_ffff).zone(2)),
            ["dscp", "0xfc/0x1", "cpmark", "0xffffffff", "zone", "2"]
        );
        for a in [
            CtinfoAction::new().cpmark(0xff),
            CtinfoAction::new().dscp(0xfc, 0),
            CtinfoAction::new().cpmark(1).action(action::TC_ACT_SHOT),
        ] {
            round_trips(a);
        }
        // Neither restore is not an action the grammar can say.
        assert!(ActionConfig::to_params(&CtinfoAction::new().zone(1)).is_err());
    }

    #[test]
    fn ife_round_trips() {
        let mac = [0x02, 0, 0, 0, 0, 0x01];
        assert_eq!(
            round_trips(
                IfeAction::encode()
                    .allow(IfeMeta::Mark)
                    .use_value(IfeMeta::Prio, 7)
                    .dst(mac)
                    .etype(0xed3e)
            ),
            [
                "encode",
                "dst",
                "02:00:00:00:00:01",
                "type",
                "0xed3e",
                "allow",
                "mark",
                "use",
                "prio",
                "7"
            ]
        );
        for a in [
            IfeAction::decode(),
            IfeAction::encode()
                .src(mac)
                .use_value(IfeMeta::TcIndex, 65535)
                .allow(IfeMeta::TcIndex),
            IfeAction::decode().action(action::TC_ACT_SHOT),
        ] {
            round_trips(a);
        }
        // tcindex is a u16 on the wire: a wider value used to be cut to it.
        let wide = IfeAction::encode().use_value(IfeMeta::TcIndex, 70_000);
        assert!(ActionConfig::to_params(&wide).is_err());
        assert!(IfeAction::parse_params(&["encode", "use", "tcindex", "70000"]).is_err());
    }

    #[test]
    fn gate_round_trips() {
        use std::time::Duration;
        let ms = Duration::from_millis;
        assert_eq!(
            round_trips(
                GateAction::new()
                    .priority(0)
                    .cycle_time(ms(2))
                    .sched_entry(true, ms(1), None, None)
                    .sched_entry(false, ms(1), None, None)
            ),
            [
                "priority",
                "0",
                "cycle-time",
                "2ms",
                "sched-entry",
                "open",
                "1ms",
                "sched-entry",
                "close",
                "1ms"
            ]
        );
        // An absolute base time is past the nanoseconds a float holds.
        let base = Duration::from_nanos(1_528_743_495_910_289_987);
        assert_eq!(
            round_trips(GateAction::new().base_time(base).clockid(11)),
            ["base-time", "1528743495910289987ns", "clockid", "CLOCK_TAI"]
        );
        for a in [
            GateAction::new(),
            GateAction::new().cycle_time_ext(Duration::from_nanos(1500)).clockid(5).priority(-1),
            GateAction::new()
                .sched_entry(false, Duration::from_micros(300), Some(-1), Some(1500))
                .sched_entry(true, Duration::from_micros(200), Some(3), None)
                .action(action::TC_ACT_STOLEN),
        ] {
            round_trips(a);
        }
        // Positional: a max-octets is the value after an ipv.
        let entry = GateAction::new().sched_entry(true, ms(1), None, Some(10));
        assert!(ActionConfig::to_params(&entry).is_err());
    }

    #[test]
    fn csum_round_trips() {
        assert_eq!(round_trips(CsumAction::new().iph().tcp()), ["iph", "tcp"]);
        for a in [
            CsumAction::new(),
            CsumAction::new().iph().icmp().igmp().tcp().udp().udplite().sctp(),
            CsumAction::new().udp().action(action::TC_ACT_PIPE),
        ] {
            round_trips(a);
        }
        let mut odd = CsumAction::new().tcp();
        odd.update_flags |= 0x80;
        assert!(ActionConfig::to_params(&odd).is_err());
    }

    #[test]
    fn sample_round_trips() {
        assert_eq!(round_trips(SampleAction::new(100, 5)), ["rate", "100", "group", "5"]);
        round_trips(SampleAction::new(100, 5).trunc(128));
        assert_eq!(
            round_trips(SampleAction::new(1, 2).action(action::TC_ACT_SHOT)),
            ["rate", "1", "group", "2", "drop"]
        );
    }

    #[test]
    fn ct_round_trips() {
        let v4 = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let v6 = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap();
        let (inet, inet6) = (libc::AF_INET as u8, libc::AF_INET6 as u8);
        let (tcp, udp) = (libc::IPPROTO_TCP as u8, libc::IPPROTO_UDP as u8);
        assert_eq!(
            round_trips(CtAction::commit().zone(1).mark(0x100, 0xffff_ffff)),
            ["commit", "zone", "1", "mark", "256/0xffffffff"]
        );
        assert_eq!(
            round_trips(
                CtAction::commit()
                    .nat_src(v4("10.0.0.1"), v4("10.0.0.10"))
                    .nat_port_range(1024, 65535)
            ),
            ["commit", "nat", "src", "addr", "10.0.0.1-10.0.0.10", "port", "1024-65535"]
        );
        let mut label = [0u8; 16];
        (label[0], label[15]) = (0x12, 0x01);
        assert_eq!(
            round_trips(CtAction::commit().labels(label, [0xff; 16]).helper("ftp", inet, tcp)),
            [
                "commit",
                "label",
                "12000000000000000000000000000001/ffffffffffffffffffffffffffffffff",
                "helper",
                "ipv4-tcp-ftp"
            ]
        );
        for a in [
            CtAction::new(),
            CtAction::clear(),
            CtAction::new().force(),
            CtAction::commit().force().zone(3),
            CtAction::commit().nat_dst_single(v4("192.168.1.1")),
            CtAction::commit().nat_src6(v6("2001:db8::1"), v6("2001:db8::10")),
            CtAction::commit()
                .nat_dst6(v6("2001:db8::1"), v6("2001:db8::1"))
                .nat_port_range(80, 80),
            // Two families, or two directions: each clause sets its own.
            CtAction::commit()
                .nat_src_single(v4("10.0.0.1"))
                .nat_src6(v6("::1"), v6("::2")),
            CtAction::commit()
                .nat_src_single(v4("10.0.0.1"))
                .nat_dst_single(v4("10.0.0.2")),
            CtAction::new().nat_port_range(1, 2),
            CtAction::commit().labels(label, [0x0f; 16]),
            CtAction::commit().helper("sip-x", inet6, udp),
            CtAction::commit().helper("x", 3, 132),
            CtAction::new().action(action::TC_ACT_SHOT),
        ] {
            round_trips(a);
        }
        // tc(8)'s short label: the bytes it gives, then zeros; a full mask.
        let short = CtAction::parse_params(&["label", "12"]).unwrap();
        let mut want = [0u8; 16];
        want[0] = 0x12;
        assert_eq!(bytes(&short), bytes(&CtAction::new().labels(want, [0xff; 16])));
        let bad: [&[&str]; 8] = [
            &["label", "1"],
            &["label", "+1"],
            &["label", "12/0x"],
            &["helper", "ipv4-tcp-"],
            &["helper", "ipv4-ftp"],
            &["helper", "inet-tcp-ftp"],
            &["port", "1-x"],
            &["nat", "src", "10.0.0.1-::1"],
        ];
        for bad in bad {
            assert!(CtAction::parse_params(bad).is_err(), "{bad:?}");
        }
        assert!(ActionConfig::to_params(&CtAction::commit().helper("", inet, tcp)).is_err());
        assert_eq!(round_trips(CtAction::new().nat()), ["nat"]);
    }

    #[test]
    fn pedit_round_trips() {
        let network = pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_NETWORK;
        assert_eq!(
            round_trips(
                PeditAction::new()
                    .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
                    .set_tcp_dport(8080)
            ),
            ["munge", "ip", "src", "set", "10.0.0.1", "munge", "tcp", "dport", "set", "8080", "pipe"]
        );
        assert_eq!(
            round_trips(PeditAction::new().add_raw(network, 8, 0xff00_0000, 0x00ff_ffff)),
            ["munge", "offset", "8", "add", "0xff000000", "retain", "0xffffff", "pipe"]
        );
        for a in [
            PeditAction::new()
                .set_ipv4_dst(Ipv4Addr::new(10, 0, 0, 2))
                .set_ipv4_ttl(63)
                .set_ipv4_tos(0x10),
            PeditAction::new().set_tcp_sport(1).set_udp_sport(2).set_udp_dport(3),
            PeditAction::new()
                .set_eth_src([2, 0, 0, 0, 0, 1])
                .set_eth_dst([2, 0, 0, 0, 0, 2]),
            PeditAction::new().set_raw(network, 12, 0x0a00_0001, 0),
            PeditAction::new()
                .set_ipv4_src(Ipv4Addr::new(10, 0, 0, 1))
                .action(action::TC_ACT_SHOT),
        ] {
            round_trips(a);
        }
        assert!(ActionConfig::to_params(&PeditAction::new()).is_err());
        // `munge offset` edits the network header; a raw edit of another
        // that no field's setter writes has no token.
        let tcp = pedit::TCA_PEDIT_KEY_EX_HDR_TYPE_TCP;
        assert!(ActionConfig::to_params(&PeditAction::new().set_raw(tcp, 4, 1, 0)).is_err());
    }

    #[test]
    fn simple_round_trips() {
        assert_eq!(round_trips(SimpleAction::new("matched-port-80")), ["sdata", "matched-port-80"]);
        for a in [
            SimpleAction::new("two words"),
            SimpleAction::new("x").ok(),
            SimpleAction::new("").verdict(action::TC_ACT_UNSPEC),
        ] {
            round_trips(a);
        }
        assert_eq!(
            round_trips(SimpleAction::new("y").drop()),
            ["sdata", "y", "verdict", "drop"]
        );
    }

    /// A program opened from its pin is written as the path; one given by
    /// descriptor has no token.
    #[test]
    fn bpf_pinned_is_written_as_its_path() {
        let mut a = BpfAction::with_raw_fd(7).name("trace").drop();
        a.pinned = Some("/sys/fs/bpf/nlink-test-absent".into());
        let tokens = ActionConfig::to_params(&a).unwrap();
        assert_eq!(
            tokens,
            ["pinned", "/sys/fs/bpf/nlink-test-absent", "name", "trace", "verdict", "drop"]
        );
        // Read back, the pin is opened again, and this one does not exist.
        let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
        let err = BpfAction::parse_params(&refs).unwrap_err();
        assert!(err.errno().is_some(), "{err:?}");
        // With the descriptor in its place, the rest reads back to the
        // same request.
        let mut refs = refs;
        (refs[0], refs[1]) = ("fd", "7");
        assert_eq!(bytes(&BpfAction::parse_params(&refs).unwrap()), bytes(&a));

        assert!(ActionConfig::to_params(&BpfAction::with_raw_fd(7)).is_err());
        assert!(ActionConfig::to_params(&BpfAction::from_fd(std::io::stdin())).is_err());
    }

    /// Every kind with a writer reads back through `action_from_params`,
    /// from its kind and tokens, to the same request.
    #[test]
    fn an_action_reads_back_from_its_kind_and_tokens() {
        use crate::util::{Bytes, Rate};
        let mac = [0x02, 0, 0, 0, 0, 0x01];
        let net = Ipv4Addr::new(10, 0, 0, 0);
        let actions: Vec<Box<dyn ActionConfigDyn>> = vec![
            Box::new(GactAction::pass().random_drop(25)),
            Box::new(MirredAction::mirror_to_ingress(7).action(action::TC_ACT_SHOT)),
            Box::new(PoliceAction::new().rate(Rate::mbit(8)).burst(Bytes::kib(32))),
            Box::new(VlanAction::push(100).qinq()),
            Box::new(MplsAction::pop(0x0800)),
            Box::new(SkbmodAction::new().swap_mac()),
            Box::new(SkbeditAction::new().mark_with_mask(1, 0xff)),
            Box::new(NatAction::snat(net, Ipv4Addr::new(192, 0, 2, 1)).prefix(24)),
            Box::new(TunnelKeyAction::set().key_id(42)),
            Box::new(ConnmarkAction::with_zone(4)),
            Box::new(CtinfoAction::new().cpmark(0xff)),
            Box::new(IfeAction::encode().allow(IfeMeta::Mark).dst(mac)),
            Box::new(GateAction::new().sched_entry(
                true,
                std::time::Duration::from_millis(1),
                None,
                None,
            )),
            Box::new(CsumAction::new().iph().udp()),
            Box::new(SampleAction::new(10, 1)),
            Box::new(CtAction::commit().zone(2)),
            Box::new(PeditAction::new().set_tcp_dport(80)),
            Box::new(SimpleAction::new("hit")),
        ];
        // bpf opens its pin as it is read, and the test has none: below.
        let mut kinds: Vec<&str> = actions.iter().map(|a| a.kind()).chain(["bpf"]).collect();
        kinds.sort_unstable();
        let mut all = PARAMS_KINDS.to_vec();
        all.sort_unstable();
        assert_eq!(kinds, all, "one of each kind with a writer");

        for a in &actions {
            let tokens = a.to_params().unwrap_or_else(|e| panic!("{a:?}: {e}"));
            let refs: Vec<&str> = tokens.iter().map(String::as_str).collect();
            let back = action_from_params(a.kind(), &refs)
                .unwrap_or_else(|e| panic!("{}: {tokens:?}: {e}", a.kind()));
            assert_eq!(back.kind(), a.kind());
            assert_eq!(bytes(&*back), bytes(&**a), "{tokens:?}");
        }
        let err = action_from_params("bpf", &["pinned", "/sys/fs/bpf/nlink-test-absent"])
            .unwrap_err();
        assert!(err.to_string().contains("bpf: open pinned program"), "{err}");
        let err = action_from_params("connmark2", &[]).unwrap_err();
        assert!(
            err.to_string()
                .contains("action `connmark2` has no document form (kinds: gact, mirred, police"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod estimator_tests {
    use std::time::Duration;

    use super::Estimator;

    /// #792: an estimator is what tc(8) makes of the same words
    /// (`tc_setup_estimator`): the interval rounded up to a power of two
    /// from 250 ms, and the weight the first power of two that takes the
    /// interval past the time constant, less one. It prints as the times
    /// those stand for, which read back as the same estimator.
    #[test]
    fn an_estimator_is_what_tc_makes_of_its_words() {
        for (words, interval, ewma_log, shown) in [
            ("1sec 8sec", 0, 3, "1s 8s"),
            ("250ms 2s", -2, 3, "250ms 2s"),
            ("200ms 1s", -2, 2, "250ms 1s"),
            ("3s 30s", 2, 3, "4s 32s"),
            ("8s 16s", 3, 1, "8s 16s"),
        ] {
            let e = Estimator::parse_params(&words.split_whitespace().collect::<Vec<_>>()).unwrap();
            let parms = e.parms();
            assert_eq!((parms.interval, parms.ewma_log), (interval, ewma_log), "{words}");
            assert_eq!(e.to_string(), shown, "{words}");
            let back = Estimator::parse_params(&shown.split_whitespace().collect::<Vec<_>>()).unwrap();
            assert_eq!(back, e, "{words}");
        }
        assert_eq!(
            Estimator::new(Duration::from_secs(1), Duration::from_secs(8)).unwrap().time_constant(),
            Duration::from_secs(8)
        );
    }

    /// What tc(8) refuses is refused, saying why.
    #[test]
    fn an_estimator_out_of_range_is_refused() {
        for (words, says) in [
            ("9s 80s", "at most 8s"),
            ("0 1s", "over 0"),
            ("1s 1s", "2 to 2^30 intervals"),
            ("1s 3000000000s", "2 to 2^30 intervals"),
            ("1s", "expected `<interval> <time constant>`"),
            ("1s 8x", "invalid time `8x`"),
        ] {
            let err = Estimator::parse_params(&words.split_whitespace().collect::<Vec<_>>())
                .expect_err(words)
                .to_string();
            assert!(err.contains(says) && err.contains("estimator"), "{words}: {err}");
        }
    }
}
