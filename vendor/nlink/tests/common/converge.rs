//! Convergence and transition checks for the declarative configs.
//!
//! The declarative diffs compare a declaration against the kernel's dump
//! of what the last apply installed. Wherever the kernel stores something
//! other than what it was sent, or an apply step undoes an earlier one,
//! the next diff is not empty and every apply after it rewrites the same
//! thing forever — invisible applying once to an empty namespace.
//!
//! So every step here is applied, diffed, applied again and diffed again,
//! and all four must say "nothing to do". A case with several steps
//! applies them in order to one namespace: that is how a change from one
//! declared value to another gets exercised at all. And because a diff
//! that does not compare a field agrees with anything, a case can end in
//! a check that reads the kernel through something else.

use nlink::netlink::config::{ApplyOptions, PlanOptions, NetworkConfig};
use nlink::netlink::genl::wireguard::WireguardConfig;
use nlink::netlink::nftables::config::{NftDiffOptions, NftablesConfig};
use nlink::netlink::{Connection, Nftables, Route, Wireguard};

use super::{STEP_TIMEOUT, TestNamespace};

/// A declarative config the harness can apply and diff.
pub(crate) trait Declarative {
    type Conn;

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn>;

    /// Apply, returning how many changes were made; an apply that reports
    /// errors is an `Err`.
    async fn apply(&self, conn: &Self::Conn, purge: bool) -> Result<usize, String>;

    /// The diff against the kernel, rendered, or `None` when it is empty.
    async fn pending(&self, conn: &Self::Conn, purge: bool) -> Result<Option<String>, String>;
}

impl Declarative for NetworkConfig {
    type Conn = Connection<Route>;

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn> {
        ns.connection()
    }

    async fn apply(&self, conn: &Self::Conn, purge: bool) -> Result<usize, String> {
        let applied = self
            .apply_with_options(conn, ApplyOptions::default().with_purge(purge))
            .await
            .map_err(|e| e.to_string())?;
        if !applied.is_success() {
            return Err(format!("reported errors: {:?}", applied.errors));
        }
        Ok(applied.changes_made)
    }

    async fn pending(&self, conn: &Self::Conn, purge: bool) -> Result<Option<String>, String> {
        let diff = self
            .diff_with_options(conn, PlanOptions::default().purge(purge))
            .await
            .map_err(|e| e.to_string())?;
        Ok((!diff.is_empty()).then(|| diff.to_string()))
    }
}

impl Declarative for NftablesConfig {
    type Conn = Connection<Nftables>;

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn> {
        ns.connection_for()
    }

    async fn apply(&self, conn: &Self::Conn, purge: bool) -> Result<usize, String> {
        let options = NftDiffOptions::default().purge_tables(purge);
        let diff = self
            .diff_with_options(conn, &options)
            .await
            .map_err(|e| format!("diff: {e}"))?;
        let applied = diff.apply(conn).await.map_err(|e| e.to_string())?;
        // #708: what each change said the kernel would hold, it holds.
        let after = self
            .snapshot(conn)
            .await
            .map_err(|e| format!("snapshot: {e}"))?;
        changes_hold(&diff, &after)?;
        Ok(applied)
    }

    async fn pending(&self, conn: &Self::Conn, purge: bool) -> Result<Option<String>, String> {
        let options = NftDiffOptions::default().purge_tables(purge);
        let diff = self
            .diff_with_options(conn, &options)
            .await
            .map_err(|e| e.to_string())?;
        Ok((!diff.is_empty()).then(|| diff.to_string()))
    }
}

/// Whether every change of `diff` holds in `after`, the ruleset its apply
/// left: each `to` is what the kernel reads back, each removed item is
/// gone (#708). Handles are where the kernel put them, a placement where
/// the rule went; a timeout is compared in 20 ms steps.
fn changes_hold(
    diff: &nlink::netlink::nftables::config::NftablesDiff,
    after: &nlink::netlink::nftables::config::RulesetSnapshot,
) -> Result<(), String> {
    use nlink::netlink::nftables::config::{
        Change, NftChain, NftChange, NftFlowtable, NftObject, NftRule, NftSet, NftTable,
    };
    let step = |d: Option<std::time::Duration>| d.map(|d| d.as_millis() - d.as_millis() % 20);
    let set_view = |mut s: NftSet| {
        let timers = (step(s.timeout), step(s.gc_interval));
        s.timeout = None;
        s.gc_interval = None;
        (s, timers)
    };
    let rule_view = |mut r: NftRule| {
        r.handle = None;
        r.placement = None;
        r
    };
    let mut wrong = Vec::new();
    for change in diff.changes.iter().flat_map(NftChange::flatten) {
        let (held, gone) = match change {
            NftChange::Table(c) => {
                let read = |t: &NftTable| {
                    after
                        .tables
                        .iter()
                        .find(|k| k.family == t.family && k.name == t.name)
                        .map(NftTable::from_kernel)
                };
                (
                    c.to().map(|t| read(t).as_ref() == Some(t)),
                    matches!(c, Change::Remove(t) if read(t).is_some()),
                )
            }
            NftChange::Chain(c) => {
                let read = |t: &NftChain| {
                    after
                        .chains
                        .iter()
                        .find(|k| k.family == t.family && k.table == t.table && k.name == t.name)
                        .map(NftChain::from_kernel)
                };
                (
                    c.to().map(|t| read(t).as_ref() == Some(t)),
                    matches!(c, Change::Remove(t) if read(t).is_some()),
                )
            }
            NftChange::Rule(c) => {
                let read = |t: &NftRule| {
                    after
                        .rules
                        .iter()
                        .find(|k| {
                            k.family == t.family
                                && k.table == t.table
                                && k.chain == t.chain
                                && k.key == t.key
                                && (t.key.is_some() || Some(k.handle) == t.handle.map(|h| h.0))
                        })
                        .map(|k| rule_view(NftRule::from_kernel(k)))
                };
                (
                    c.to().map(|t| read(t) == Some(rule_view(t.clone()))),
                    matches!(c, Change::Remove(t) if t.key.is_some() && read(t).is_some()),
                )
            }
            NftChange::Set(c) => {
                let read = |t: &NftSet| {
                    after
                        .sets
                        .iter()
                        .find(|k| k.family == t.family && k.table == t.table && k.name == t.name)
                        .map(|k| set_view(NftSet::from_kernel(k)))
                };
                (
                    c.to().map(|t| read(t) == Some(set_view(t.clone()))),
                    matches!(c, Change::Remove(t) if read(t).is_some()),
                )
            }
            NftChange::Elements(c) => {
                let present = |t: &nlink::netlink::nftables::config::NftElements, e: &nlink::netlink::nftables::SetElement| {
                    after
                        .elements
                        .get(&(t.family, t.table.clone(), t.set.clone()))
                        .is_some_and(|all| {
                            all.iter().any(|k| {
                                k.key() == e.key()
                                    && k.key_end().filter(|end| *end != k.key())
                                        == e.key_end().filter(|end| *end != e.key())
                                    && k.data() == e.data()
                            })
                        })
                };
                match c {
                    Change::Add(t) => (Some(t.elements.iter().all(|e| present(t, e))), false),
                    // A removed element can be added back by the same diff.
                    _ => (None, false),
                }
            }
            NftChange::Object(c) => {
                let read = |t: &NftObject| {
                    after
                        .objects
                        .iter()
                        .find(|k| k.family == t.family && k.table == t.table && k.name == t.name)
                        .and_then(NftObject::from_kernel)
                };
                (
                    c.to().map(|t| read(t).as_ref() == Some(t)),
                    matches!(c, Change::Remove(t) if read(t).is_some()),
                )
            }
            NftChange::Flowtable(c) => {
                let read = |t: &NftFlowtable| {
                    after
                        .flowtables
                        .iter()
                        .find(|k| k.family == t.family && k.table == t.table && k.name == t.name)
                        .map(NftFlowtable::from_kernel)
                };
                (
                    c.to().map(|t| read(t).as_ref() == Some(t)),
                    matches!(c, Change::Remove(t) if read(t).is_some()),
                )
            }
            other => {
                wrong.push(format!("a change the check does not know: {other:?}"));
                continue;
            }
        };
        if held == Some(false) {
            wrong.push(format!(
                "not what the kernel holds after the apply: {change:#?}"
            ));
        }
        if gone {
            wrong.push(format!("still there after the apply: {change:#?}"));
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong.join("\n"))
    }
}

/// WireGuard has no purge: a step that asks for one is a test bug.
impl Declarative for WireguardConfig {
    type Conn = (Connection<Route>, Connection<Wireguard>);

    async fn connect(ns: &TestNamespace) -> nlink::Result<Self::Conn> {
        Ok((ns.connection()?, ns.connection_for_async().await?))
    }

    async fn apply(&self, (route, wg): &Self::Conn, purge: bool) -> Result<usize, String> {
        assert!(!purge, "WireguardConfig has no purge");
        self.ensure_devices(route)
            .await
            .map_err(|e| format!("ensure_devices: {e}"))?;
        let applied = self.apply(wg).await.map_err(|e| e.to_string())?;
        Ok(applied.total_writes())
    }

    async fn pending(&self, (_, wg): &Self::Conn, purge: bool) -> Result<Option<String>, String> {
        assert!(!purge, "WireguardConfig has no purge");
        let diff = self.diff(wg).await.map_err(|e| e.to_string())?;
        Ok((!diff.is_empty()).then(|| diff.to_string()))
    }
}

/// Apply `cfg` and check that it converged: the diff after the apply is
/// empty, a second apply changes nothing, and the diff after that is
/// empty too.
pub async fn converges<D: Declarative>(conn: &D::Conn, cfg: &D, purge: bool) -> Result<(), String> {
    cfg.apply(conn, purge)
        .await
        .map_err(|e| format!("first apply failed: {e}"))?;
    if let Some(diff) = cfg
        .pending(conn, purge)
        .await
        .map_err(|e| format!("diff after apply failed: {e}"))?
    {
        return Err(format!("diff after apply is not empty:\n{diff}"));
    }
    let changes = cfg
        .apply(conn, purge)
        .await
        .map_err(|e| format!("second apply failed: {e}"))?;
    if changes != 0 {
        return Err(format!("second apply made {changes} change(s)"));
    }
    if let Some(diff) = cfg
        .pending(conn, purge)
        .await
        .map_err(|e| format!("diff after second apply failed: {e}"))?
    {
        return Err(format!("diff after second apply is not empty:\n{diff}"));
    }
    Ok(())
}

/// What the kernel must hold after a case's last step.
type Check = Box<dyn Fn(&TestNamespace) -> Result<(), String>>;

/// One declaration, or a sequence applied in order to one namespace.
pub struct Case<D> {
    name: String,
    steps: Vec<D>,
    purge: bool,
    check: Option<Check>,
}

pub fn case<D>(name: impl Into<String>, steps: Vec<D>) -> Case<D> {
    Case {
        name: name.into(),
        steps,
        purge: false,
        check: None,
    }
}

impl<D> Case<D> {
    /// Apply and diff every step with purge on.
    pub fn purging(mut self) -> Self {
        self.purge = true;
        self
    }

    /// After the last step converged, `check` must pass too. Read the
    /// kernel with something other than nlink (`ip_json`) where you can.
    pub fn check(mut self, check: impl Fn(&TestNamespace) -> Result<(), String> + 'static) -> Self {
        self.check = Some(Box::new(check));
        self
    }
}

async fn run_case<D: Declarative>(ns: &TestNamespace, case: &Case<D>) -> Result<(), String> {
    let conn = D::connect(ns).await.map_err(|e| format!("connect: {e}"))?;
    for (i, step) in case.steps.iter().enumerate() {
        let outcome =
            match tokio::time::timeout(STEP_TIMEOUT, converges(&conn, step, case.purge)).await {
                Ok(outcome) => outcome,
                Err(_elapsed) => Err("timed out".to_string()),
            };
        outcome.map_err(|why| format!("step {}: {why}", i + 1))?;
    }
    if let Some(check) = &case.check {
        check(ns).map_err(|why| format!("check after the last step: {why}"))?;
    }
    Ok(())
}

/// Run every case in its own namespace, then fail once, listing every
/// case that did not converge — so a run reports every red shape at once
/// instead of stopping at the first.
pub async fn assert_converges<D: Declarative>(
    prefix: &str,
    cases: Vec<Case<D>>,
) -> nlink::Result<()> {
    let mut failures = Vec::new();
    for case in cases {
        let ns = TestNamespace::new(prefix)?;
        if let Err(why) = run_case(&ns, &case).await {
            failures.push(format!("[{}] {why}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "{} case(s) did not converge:\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
    Ok(())
}

/// Apply `steps` in order to `ns`, each of which must converge, and run
/// `check(i, conn)` after step `i` (0-based). Stops at the first failure.
pub async fn assert_transition<D: Declarative>(
    ns: &TestNamespace,
    steps: &[D],
    purge: bool,
    mut check: impl AsyncFnMut(usize, &D::Conn) -> Result<(), String>,
) -> nlink::Result<()> {
    let conn = D::connect(ns).await?;
    for (i, step) in steps.iter().enumerate() {
        let outcome = match tokio::time::timeout(STEP_TIMEOUT, converges(&conn, step, purge)).await
        {
            Ok(outcome) => outcome,
            Err(_elapsed) => Err("timed out".to_string()),
        };
        if let Err(why) = outcome {
            panic!("step {} did not converge: {why}", i + 1);
        }
        if let Err(why) = check(i, &conn).await {
            panic!("check after step {} failed: {why}", i + 1);
        }
    }
    Ok(())
}

/// [`assert_transition`] for a `NetworkConfig` whose steps are each
/// applied and diffed with the step before as the previous config (#512):
/// what a step drops is removed, as a caller that keeps its last config
/// sees it. Every step applies, diffs empty, applies with no changes and
/// diffs empty, then `check` reads the kernel.
pub async fn assert_transition_with_previous(
    ns: &TestNamespace,
    steps: &[NetworkConfig],
    mut check: impl AsyncFnMut(usize, &Connection<Route>) -> Result<(), String>,
) -> nlink::Result<()> {
    let conn = ns.connection()?;
    for (i, step) in steps.iter().enumerate() {
        let previous = i.checked_sub(1).map(|p| std::sync::Arc::new(steps[p].clone()));
        let plan = || {
            let opts = PlanOptions::default();
            match &previous {
                Some(p) => opts.previous(p.clone()),
                None => opts,
            }
        };
        let apply = || {
            let opts = ApplyOptions::default();
            match &previous {
                Some(p) => opts.with_previous(p.clone()),
                None => opts,
            }
        };
        let outcome = async {
            let applied = step.apply_with_options(&conn, apply()).await.map_err(|e| format!("first apply failed: {e}"))?;
            if !applied.is_success() {
                return Err(format!("first apply reported errors: {:?}", applied.errors));
            }
            let diff = step.diff_with_options(&conn, plan()).await.map_err(|e| e.to_string())?;
            if !diff.is_empty() {
                return Err(format!("diff after apply is not empty:\n{diff}"));
            }
            let again = step.apply_with_options(&conn, apply()).await.map_err(|e| format!("second apply failed: {e}"))?;
            if again.changes_made != 0 {
                return Err(format!("second apply made {} changes: {:?}", again.changes_made, again.summary));
            }
            let diff = step.diff_with_options(&conn, plan()).await.map_err(|e| e.to_string())?;
            if !diff.is_empty() {
                return Err(format!("diff after the second apply is not empty:\n{diff}"));
            }
            Ok(())
        };
        let outcome = match tokio::time::timeout(STEP_TIMEOUT, outcome).await {
            Ok(outcome) => outcome,
            Err(_elapsed) => Err("timed out".to_string()),
        };
        if let Err(why) = outcome {
            panic!("step {} did not converge: {why}", i + 1);
        }
        if let Err(why) = check(i, &conn).await {
            panic!("check after step {} failed: {why}", i + 1);
        }
    }
    Ok(())
}

/// `ip -j <args>` inside `ns`, parsed.
///
/// An independent reader: a diff converging only shows that the diff and
/// the kernel agree, and a diff that does not compare a field agrees
/// with anything.
pub fn ip_json(ns: &TestNamespace, args: &[&str]) -> Result<serde_json::Value, String> {
    let mut full = vec!["-j"];
    full.extend_from_slice(args);
    let out = ns
        .exec("ip", &full)
        .map_err(|e| format!("ip {}: {e}", args.join(" ")))?;
    serde_json::from_str(&out).map_err(|e| format!("ip {}: {e}: {out}", args.join(" ")))
}
