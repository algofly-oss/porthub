//! Compile [`FilterExpr`] predicates to `INET_DIAG_REQ_BYTECODE`.
//!
//! `NETLINK_SOCK_DIAG` lets a dump carry a bytecode program that the
//! kernel runs per socket, so only matching sockets cross into
//! userspace. The program is a stream of `struct inet_diag_bc_op`
//! (`{ u8 code; u8 yes; u16 no }`) the kernel walks: on a matching op
//! it advances by `yes`, on a non-match it advances by `no`. A socket
//! is **accepted** iff execution falls off the end with the remaining
//! length at exactly zero — so a failing branch that should reject
//! overshoots the end (`no = remaining + 4`), leaving the length
//! negative.
//!
//! # Supported surface (#163)
//!
//! [`compile_filter`] lowers the full [`FilterExpr`] grammar:
//!
//! - **Port comparisons** (`sport`/`dport` with `=`/`!=`/`<`/`<=`/
//!   `>`/`>=`) → `S_GE`/`S_LE`/`D_GE`/`D_LE` op pairs.
//! - **Address conditions** (`src`/`dst` with optional prefix) →
//!   `S_COND`/`D_COND` + `inet_diag_hostcond`.
//! - **`and` / `or` / `not`** → jump structure (De Morgan push-down;
//!   the kernel has no NOT opcode, so negation lowers to comparison
//!   flips at port leaves and a 2-op skip/jump inversion at host
//!   leaves).
//! - **`state`** → NOT bytecode: there is no state opcode. Pure-state
//!   conjuncts of the top-level `and` spine hoist into the request
//!   header's `idiag_states` bitmask ([`CompiledFilter::states`]);
//!   state predicates in any other position stay client-side.
//!
//! Anything not expressible kernel-side is simply left out of the
//! program — the kernel then passes a **superset** and the caller's
//! client-side evaluation ([`FilterExpr::matches`]) stays the
//! correctness backstop ([`CompiledFilter::exact`] says whether it may
//! be skipped). The compiler never emits a program that could
//! under-approximate.
//!
//! The kernel **audits** every program (`inet_diag_bc_audit`) and
//! rejects malformed ones with `EINVAL`, so a structurally-invalid
//! program fails loudly rather than mis-filtering silently. The
//! emission discipline here makes audit-validity structural: every
//! instruction's `yes` is its own size (success always falls through),
//! so the yes-chain covers every instruction and any forward `no`
//! landing on an instruction boundary passes the kernel's `valid_cc`
//! reachability check. `INET_DIAG_BC_S_EQ`/`D_EQ` (kernel 4.16+) and
//! `MARK_COND` (CAP_NET_ADMIN) are deliberately not emitted — an
//! `EINVAL` on an old kernel would fail the whole dump instead of
//! falling back.

use std::net::IpAddr;

use super::{
    expr::{Comparison, FilterExpr},
    types::{SocketState, TcpState},
};

// `struct inet_diag_bc_op` codes (uapi/linux/inet_diag.h).
const INET_DIAG_BC_JMP: u8 = 1;
const INET_DIAG_BC_S_GE: u8 = 2;
const INET_DIAG_BC_S_LE: u8 = 3;
const INET_DIAG_BC_D_GE: u8 = 4;
const INET_DIAG_BC_D_LE: u8 = 5;
const INET_DIAG_BC_S_COND: u8 = 7;
const INET_DIAG_BC_D_COND: u8 = 8;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// `INET_DIAG_REQ_BYTECODE` request attribute type.
pub const INET_DIAG_REQ_BYTECODE: u16 = 1;

/// Result of [`compile_filter`]: the kernel-side lowering of a
/// [`FilterExpr`], split into the two mechanisms the kernel offers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CompiledFilter {
    /// Bitmask to AND into the request header's `idiag_states`
    /// (`None` = no state constraint was hoisted).
    pub states: Option<u32>,
    /// `INET_DIAG_REQ_BYTECODE` payload (`None` = nothing to run
    /// kernel-side beyond the states mask).
    pub bytecode: Option<Vec<u8>>,
    /// `true` when the kernel-side filtering is exact — every socket
    /// the kernel passes matches the expression, so the client-side
    /// backstop may be skipped. `false` whenever anything was
    /// over-approximated (dropped conjuncts, host conditions — an
    /// AF_INET cond also matches v4-mapped v6 sockets kernel-side).
    pub exact: bool,
}

// ============================================================================
// NNF lowering
// ============================================================================

/// Address payload of a host condition.
#[derive(Debug, Clone, Copy)]
enum HostAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl HostAddr {
    fn len(&self) -> usize {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 16,
        }
    }
}

/// A kernel-expressible primitive.
#[derive(Debug, Clone, Copy)]
enum Prim {
    /// Port bound: 8 bytes (comparison op + data op carrying the port).
    Port { code: u8, port: u16 },
    /// Host condition: 4-byte op + 8-byte `inet_diag_hostcond` + addr.
    Host {
        code: u8,
        family: u8,
        prefix_len: u8,
        addr: HostAddr,
    },
    /// Unconditional forward jump (4 bytes; always takes `no`).
    Jmp,
}

impl Prim {
    fn size(&self) -> usize {
        match self {
            Self::Port { .. } => 8,
            Self::Host { addr, .. } => 4 + 8 + addr.len(),
            Self::Jmp => 4,
        }
    }
}

/// Negation-normal form of the kernel-expressible fragment.
#[derive(Debug)]
enum Nnf {
    And(Vec<Nnf>),
    Or(Vec<Nnf>),
    Leaf(Prim),
}

fn flip(cmp: Comparison) -> Comparison {
    match cmp {
        Comparison::Eq => Comparison::Ne,
        Comparison::Ne => Comparison::Eq,
        Comparison::Lt => Comparison::Ge,
        Comparison::Ge => Comparison::Lt,
        Comparison::Le => Comparison::Gt,
        Comparison::Gt => Comparison::Le,
    }
}

/// Lower a port comparison into NNF. `None` for bounds that cannot be
/// expressed (`> 65535`, `< 0` — constant-false after normalization).
fn lower_port_cmp(is_source: bool, cmp: Comparison, port: u16) -> Option<Nnf> {
    let (ge, le) = if is_source {
        (INET_DIAG_BC_S_GE, INET_DIAG_BC_S_LE)
    } else {
        (INET_DIAG_BC_D_GE, INET_DIAG_BC_D_LE)
    };
    let leaf = |code, port| Nnf::Leaf(Prim::Port { code, port });
    Some(match cmp {
        // p == x  ⇒  p >= x AND p <= x
        Comparison::Eq => Nnf::And(vec![leaf(ge, port), leaf(le, port)]),
        Comparison::Ge => leaf(ge, port),
        Comparison::Le => leaf(le, port),
        // p > x  ⇒  p >= x+1  (x == 65535 can never be exceeded)
        Comparison::Gt => leaf(ge, port.checked_add(1)?),
        // p < x  ⇒  p <= x-1  (x == 0 can never be undercut)
        Comparison::Lt => leaf(le, port.checked_sub(1)?),
        // p != x  ⇒  p <= x-1 OR p >= x+1 (edges collapse to one arm).
        Comparison::Ne => match (port.checked_sub(1), port.checked_add(1)) {
            (Some(lo), Some(hi)) => Nnf::Or(vec![leaf(le, lo), leaf(ge, hi)]),
            (None, Some(hi)) => leaf(ge, hi),
            (Some(lo), None) => leaf(le, lo),
            (None, None) => unreachable!("u16 has more than one value"),
        },
    })
}

fn lower_host(is_source: bool, addr: &IpAddr, prefix_len: u8) -> Prim {
    let code = if is_source {
        INET_DIAG_BC_S_COND
    } else {
        INET_DIAG_BC_D_COND
    };
    // Clamp like the client-side `ip_matches`: >= max means exact.
    match addr {
        IpAddr::V4(v4) => Prim::Host {
            code,
            family: AF_INET,
            prefix_len: prefix_len.min(32),
            addr: HostAddr::V4(v4.octets()),
        },
        IpAddr::V6(v6) => Prim::Host {
            code,
            family: AF_INET6,
            prefix_len: prefix_len.min(128),
            addr: HostAddr::V6(v6.octets()),
        },
    }
}

/// NNF push-down: negation is pushed to the leaves via De Morgan, where a
/// port leaf absorbs it by flipping its comparison.
///
/// `None` means "not expressible kernel-side" — the caller drops the conjunct
/// and falls back to the client-side backstop. Three things produce it:
///
/// - a `State` leaf ([`compile_filter`] hoists those into `idiag_states`;
///   there is no state opcode),
/// - a bound the wire format cannot represent,
/// - **a negated host condition** (#198).
///
/// That last one is the subtle one, and it is why there is no `NotHost` node.
/// The kernel's hostcond is a strict *superset* of nlink's client-side
/// `ip_matches`: `inet_diag_bc_run` deliberately matches an AF_INET cond
/// against an AF_INET6 entry whose address is v4-mapped, which `ip_matches`
/// reports as a cross-family non-match. Complementing a superset yields a
/// **subset**, so a kernel-side `not src 10.0.0.0/8` *rejects* the dual-stack
/// listener's `::ffff:10.1.2.3` socket that the expression should keep — and
/// once the kernel has dropped it, no client-side pass can bring it back.
/// Only *positive* host conds are safe to lower.
fn lower(expr: &FilterExpr, negated: bool) -> Option<Nnf> {
    match expr {
        FilterExpr::And(a, b) => {
            let (a, b) = (lower(a, negated)?, lower(b, negated)?);
            Some(if negated {
                Nnf::Or(vec![a, b]) // ¬(a ∧ b) = ¬a ∨ ¬b
            } else {
                Nnf::And(vec![a, b])
            })
        }
        FilterExpr::Or(a, b) => {
            let (a, b) = (lower(a, negated)?, lower(b, negated)?);
            Some(if negated {
                Nnf::And(vec![a, b]) // ¬(a ∨ b) = ¬a ∧ ¬b
            } else {
                Nnf::Or(vec![a, b])
            })
        }
        FilterExpr::Not(inner) => lower(inner, !negated),
        FilterExpr::Sport(cmp, port) => {
            let cmp = if negated { flip(*cmp) } else { *cmp };
            lower_port_cmp(true, cmp, *port)
        }
        FilterExpr::Dport(cmp, port) => {
            let cmp = if negated { flip(*cmp) } else { *cmp };
            lower_port_cmp(false, cmp, *port)
        }
        // A negated host cond is never lowered — see the note above.
        FilterExpr::Src(_, _) | FilterExpr::Dst(_, _) if negated => None,
        FilterExpr::Src(addr, plen) => Some(Nnf::Leaf(lower_host(true, addr, *plen))),
        FilterExpr::Dst(addr, plen) => Some(Nnf::Leaf(lower_host(false, addr, *plen))),
        // No state opcode exists; `compile_filter` hoists top-level
        // pure-state conjuncts into idiag_states instead.
        FilterExpr::State(_) => None,
    }
}

// ============================================================================
// Codegen: continuation-passing with forward labels
// ============================================================================

type LabelId = usize;

#[derive(Debug, Clone, Copy)]
enum Target {
    /// Overshoot the end by 4 → reject.
    Reject,
    /// Forward label, bound later. A label bound at (or past) the
    /// program end means accept — falling off the end with exactly
    /// zero remaining.
    Label(LabelId),
}

struct Program {
    instrs: Vec<(Prim, Target)>,
    /// label → instruction index it binds to (usize::MAX = end).
    labels: Vec<usize>,
}

impl Program {
    fn new() -> Self {
        Self {
            instrs: Vec::new(),
            labels: Vec::new(),
        }
    }

    fn new_label(&mut self) -> LabelId {
        self.labels.push(usize::MAX);
        self.labels.len() - 1
    }

    fn bind(&mut self, label: LabelId) {
        self.labels[label] = self.instrs.len();
    }

    /// Emit `nnf` such that success falls through and failure
    /// transfers to `fail`. All control flow is forward-only.
    fn emit_nnf(&mut self, nnf: &Nnf, fail: Target) {
        match nnf {
            Nnf::And(parts) => {
                for p in parts {
                    self.emit_nnf(p, fail);
                }
            }
            Nnf::Or(parts) => {
                let done = self.new_label();
                for (i, alt) in parts.iter().enumerate() {
                    if i + 1 == parts.len() {
                        // Last alternative: its failure is the Or's.
                        self.emit_nnf(alt, fail);
                    } else {
                        let next_alt = self.new_label();
                        self.emit_nnf(alt, Target::Label(next_alt));
                        // Alternative matched → skip the rest.
                        self.instrs.push((Prim::Jmp, Target::Label(done)));
                        self.bind(next_alt);
                    }
                }
                self.bind(done);
            }
            Nnf::Leaf(p) => self.instrs.push((*p, fail)),
        }
    }

    /// Resolve labels to byte offsets and serialize. `None` if any
    /// `no` offset exceeds the u16 the wire format allows.
    fn resolve(&self) -> Option<Vec<u8>> {
        let n = self.instrs.len();
        // Byte offset of each instruction (+ total at the end).
        let mut offsets = Vec::with_capacity(n + 1);
        let mut off = 0usize;
        for (prim, _) in &self.instrs {
            offsets.push(off);
            off += prim.size();
        }
        offsets.push(off);
        let total = off;

        // The program rides in one netlink attribute whose nla_len is
        // a u16 including the 4-byte header; reject offsets must also
        // reach total+4. Anything bigger cannot be expressed.
        if total > u16::MAX as usize - 8 {
            return None;
        }

        let mut bc = Vec::with_capacity(total);
        for (i, (prim, target)) in self.instrs.iter().enumerate() {
            let here = offsets[i];
            let no = match target {
                Target::Reject => total - here + 4,
                Target::Label(l) => {
                    let idx = self.labels[*l];
                    let dest = if idx == usize::MAX || idx >= n {
                        total
                    } else {
                        offsets[idx]
                    };
                    dest - here
                }
            };
            let no = u16::try_from(no).ok()?;
            let yes = u8::try_from(prim.size()).ok()?;

            match prim {
                Prim::Port { code, port } => {
                    // Comparison op {code, yes=8, no} + data op
                    // {0, 0, port} the kernel reads as op[1].no.
                    bc.push(*code);
                    bc.push(yes);
                    bc.extend_from_slice(&no.to_ne_bytes());
                    bc.push(0);
                    bc.push(0);
                    bc.extend_from_slice(&port.to_ne_bytes());
                }
                Prim::Host {
                    code,
                    family,
                    prefix_len,
                    addr,
                } => {
                    // Op, then `struct inet_diag_hostcond { u8 family;
                    // u8 prefix_len; int port; __be32 addr[]; }`.
                    // port == -1 is the wildcard (ports are matched via
                    // the dedicated port ops instead).
                    bc.push(*code);
                    bc.push(yes);
                    bc.extend_from_slice(&no.to_ne_bytes());
                    bc.push(*family);
                    bc.push(*prefix_len);
                    bc.extend_from_slice(&[0, 0]); // struct padding
                    bc.extend_from_slice(&(-1i32).to_ne_bytes());
                    match addr {
                        HostAddr::V4(o) => bc.extend_from_slice(o),
                        HostAddr::V6(o) => bc.extend_from_slice(o),
                    }
                }
                Prim::Jmp => {
                    bc.push(INET_DIAG_BC_JMP);
                    bc.push(yes);
                    bc.extend_from_slice(&no.to_ne_bytes());
                }
            }
        }
        Some(bc)
    }
}

/// Whether the lowered program filters exactly what the expression
/// says. Host conditions are inexact kernel-side: an AF_INET cond
/// also matches v4-mapped addresses on AF_INET6 sockets, which the
/// client-side `ip_matches` (deliberately) does not.
fn nnf_is_exact(nnf: &Nnf) -> bool {
    match nnf {
        Nnf::And(parts) | Nnf::Or(parts) => parts.iter().all(nnf_is_exact),
        Nnf::Leaf(Prim::Port { .. }) => true,
        // A positive host cond is a kernel-side *superset* of `ip_matches`
        // (v4-mapped v6), so it over-approximates: safe, but the client-side
        // backstop must still run.
        Nnf::Leaf(_) => false,
    }
}

// ============================================================================
// State hoisting + public entry points
// ============================================================================

fn state_mask(state: &SocketState) -> u32 {
    match state {
        SocketState::Tcp(s) => s.mask(),
        SocketState::Close => TcpState::Close.mask(),
        SocketState::Established => TcpState::Established.mask(),
        SocketState::Listen => TcpState::Listen.mask(),
    }
}

/// Evaluate a **pure-state** subexpression (only `State` leaves under
/// And/Or/Not) to an `idiag_states` mask. `None` if any non-state
/// leaf appears.
fn eval_state_mask(expr: &FilterExpr) -> Option<u32> {
    match expr {
        FilterExpr::State(s) => Some(state_mask(s)),
        FilterExpr::And(a, b) => Some(eval_state_mask(a)? & eval_state_mask(b)?),
        FilterExpr::Or(a, b) => Some(eval_state_mask(a)? | eval_state_mask(b)?),
        FilterExpr::Not(inner) => Some(!eval_state_mask(inner)? & TcpState::all_mask()),
        _ => None,
    }
}

fn contains_state(expr: &FilterExpr) -> bool {
    match expr {
        FilterExpr::State(_) => true,
        FilterExpr::And(a, b) | FilterExpr::Or(a, b) => contains_state(a) || contains_state(b),
        FilterExpr::Not(inner) => contains_state(inner),
        _ => false,
    }
}

/// Flatten the top-level `and` spine into conjuncts.
fn conjuncts(expr: &FilterExpr) -> Vec<&FilterExpr> {
    match expr {
        FilterExpr::And(a, b) => {
            let mut out = conjuncts(a);
            out.extend(conjuncts(b));
            out
        }
        other => vec![other],
    }
}

/// Compile a filter expression into its kernel-side lowering (#163).
///
/// Splits the top-level `and` spine three ways:
///
/// 1. **Pure-state conjuncts** fold into
///    [`CompiledFilter::states`] (the request header's
///    `idiag_states` — there is no state opcode).
/// 2. **State-free conjuncts** compile to bytecode.
/// 3. **Mixed conjuncts** (state under `or`/`not` alongside other
///    predicates) can't go kernel-side; they're dropped from the
///    kernel program — a safe over-approximation — and
///    [`CompiledFilter::exact`] turns `false` so the caller keeps
///    the client-side backstop.
///
/// Never under-approximates: every socket matching the expression is
/// passed by whatever the kernel runs.
pub fn compile_filter(expr: &FilterExpr) -> CompiledFilter {
    let mut states: Option<u32> = None;
    let mut bc_parts: Vec<&FilterExpr> = Vec::new();
    let mut exact = true;

    for c in conjuncts(expr) {
        if let Some(mask) = eval_state_mask(c) {
            states = Some(states.unwrap_or(u32::MAX) & mask);
        } else if !contains_state(c) {
            bc_parts.push(c);
        } else {
            // Mixed state/non-state below an or/not: client-side only.
            exact = false;
        }
    }

    // Lower each top-level conjunct independently. A conjunct that will not
    // lower is *dropped*, not fatal: the parts are ANDed, so a missing one can
    // only widen the kernel-side result set, and `exact = false` puts the
    // client-side backstop back in charge of narrowing it. (Dropping a piece
    // of an `Or` would instead *narrow* it — which is why `lower` itself is
    // all-or-nothing within a conjunct and returns `None` for the whole thing.)
    let mut lowered: Vec<Nnf> = Vec::with_capacity(bc_parts.len());
    for c in &bc_parts {
        match lower(c, false) {
            Some(nnf) => lowered.push(nnf),
            None => exact = false,
        }
    }

    let bytecode = if lowered.is_empty() {
        None
    } else {
        let nnf = Nnf::And(lowered);
        if !nnf_is_exact(&nnf) {
            exact = false;
        }
        let mut prog = Program::new();
        prog.emit_nnf(&nnf, Target::Reject);
        let bytes = prog.resolve();
        if bytes.is_none() {
            // Overflow → nothing kernel-side for these parts.
            exact = false;
        }
        bytes
    };

    CompiledFilter {
        states,
        bytecode,
        exact,
    }
}

/// Compile a filter expression to a bare `INET_DIAG_REQ_BYTECODE`
/// payload.
///
/// Returns `None` when any part of the expression has no bytecode
/// form (`state` anywhere, inexpressible bounds, offset overflow) —
/// the caller then dumps unfiltered and relies on client-side
/// evaluation. Prefer [`compile_filter`], which also hoists state
/// predicates into the header mask instead of giving up.
pub fn compile(expr: &FilterExpr) -> Option<Vec<u8>> {
    let nnf = lower(expr, false)?;
    let mut prog = Program::new();
    prog.emit_nnf(&nnf, Target::Reject);
    prog.resolve()
}

/// Build a bytecode program that pins an exact source and/or
/// destination port (`sport == s AND dport == d`), or `None` if
/// neither is given.
///
/// This is what the inet dump path uses to lower the filter's
/// `local_port`/`remote_port` into a kernel-side pre-filter.
pub fn for_ports(sport: Option<u16>, dport: Option<u16>) -> Option<Vec<u8>> {
    let mut parts = Vec::new();
    if let Some(s) = sport {
        parts.push(lower_port_cmp(true, Comparison::Eq, s)?);
    }
    if let Some(d) = dport {
        parts.push(lower_port_cmp(false, Comparison::Eq, d)?);
    }
    if parts.is_empty() {
        return None;
    }
    let mut prog = Program::new();
    prog.emit_nnf(&Nnf::And(parts), Target::Reject);
    prog.resolve()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(bytes: &[u8], i: usize) -> (u8, u8, u16) {
        let b = &bytes[i * 4..i * 4 + 4];
        (b[0], b[1], u16::from_ne_bytes([b[2], b[3]]))
    }

    /// Decode the op at BYTE offset `at` (for mixed-size programs).
    fn op_at(bytes: &[u8], at: usize) -> (u8, u8, u16) {
        (
            bytes[at],
            bytes[at + 1],
            u16::from_ne_bytes([bytes[at + 2], bytes[at + 3]]),
        )
    }

    // ------------------------------------------------------------------
    // Kernel-audit oracle: a faithful ~40-line reimplementation of
    // inet_diag_bc_audit + valid_cc. Every program the compiler emits
    // must pass it — this is the same check that would EINVAL a live
    // dump.
    // ------------------------------------------------------------------
    fn audit(prog: &[u8]) -> Result<(), String> {
        let min_len = |code: u8, remaining: usize, at: usize| -> Result<usize, String> {
            Ok(match code {
                1 => 4,     // JMP
                2..=5 => 8, // port ops (op + data op)
                7 | 8 => {
                    // hostcond: op(4) + family/prefix/port(8) + addr
                    if remaining < 12 {
                        return Err(format!("truncated hostcond at {at}"));
                    }
                    let family = prog[at + 4];
                    let addr_len: usize = match family {
                        0 => 0,
                        2 => 4,
                        10 => 16,
                        f => return Err(format!("bad family {f} at {at}")),
                    };
                    let prefix = prog[at + 5];
                    if prefix as usize > 8 * addr_len {
                        return Err(format!("prefix {prefix} too long at {at}"));
                    }
                    4 + 8 + addr_len
                }
                c => return Err(format!("unknown code {c} at {at}")),
            })
        };

        // Collect the yes-chain (offsets reachable by success).
        let len = prog.len();
        let mut yes_chain = Vec::new();
        let mut at = 0usize;
        while at < len {
            yes_chain.push(at);
            if len - at < 4 {
                return Err(format!("trailing garbage at {at}"));
            }
            let (code, yes, no) = (
                prog[at],
                prog[at + 1] as usize,
                u16::from_ne_bytes([prog[at + 2], prog[at + 3]]) as usize,
            );
            let ml = min_len(code, len - at, at)?;
            if yes < ml || yes > len - at || yes % 4 != 0 {
                return Err(format!("bad yes {yes} at {at} (min {ml})"));
            }
            if no < ml || no > len - at + 4 || no % 4 != 0 {
                return Err(format!("bad no {no} at {at} (min {ml})"));
            }
            // valid_cc: a non-overshooting `no` must land on the
            // yes-chain (checked after the walk).
            at += yes;
        }
        // Second pass: every intra-program `no` target must be on the
        // yes-chain or exactly at/next-past the end.
        for &start in &yes_chain {
            let no = u16::from_ne_bytes([prog[start + 2], prog[start + 3]]) as usize;
            let dest = start + no;
            if dest < len && !yes_chain.contains(&dest) {
                return Err(format!("no-target {dest} from {start} not on yes-chain"));
            }
            if dest > len + 4 {
                return Err(format!("no-target {dest} overshoots past len+4"));
            }
        }
        Ok(())
    }

    fn assert_audited(expr: &str) -> Vec<u8> {
        let bc = compile(&FilterExpr::parse(expr).unwrap())
            .unwrap_or_else(|| panic!("`{expr}` must compile"));
        audit(&bc).unwrap_or_else(|e| panic!("`{expr}` fails kernel audit: {e}\n{bc:02x?}"));
        bc
    }

    // ------------------------------------------------------------------
    // Pinned legacy layouts (unchanged from the port-only compiler).
    // ------------------------------------------------------------------

    #[test]
    fn sport_eq_compiles_to_ge_le_range() {
        let bc = assert_audited("sport = :22");
        // 2 primitives × 8 bytes.
        assert_eq!(bc.len(), 16);
        // op0: S_GE, yes=8, no=remaining(16)+4=20
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_S_GE, 8, 20));
        // op1: data, port 22
        assert_eq!(op(&bc, 1), (0, 0, 22));
        // op2: S_LE, yes=8, no=remaining(8)+4=12
        assert_eq!(op(&bc, 2), (INET_DIAG_BC_S_LE, 8, 12));
        // op3: data, port 22
        assert_eq!(op(&bc, 3), (0, 0, 22));
    }

    #[test]
    fn dport_gt_uses_ge_plus_one() {
        let bc = assert_audited("dport > :1024");
        assert_eq!(bc.len(), 8);
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_D_GE, 8, 12));
        assert_eq!(op(&bc, 1), (0, 0, 1025));
    }

    #[test]
    fn sport_lt_uses_le_minus_one() {
        let bc = assert_audited("sport < :1024");
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_S_LE, 8, 12));
        assert_eq!(op(&bc, 1), (0, 0, 1023));
    }

    #[test]
    fn and_chain_offsets_decrease() {
        // sport = :22 and dport >= :80  → 3 primitives (GE 22, LE 22, D_GE 80)
        let bc = assert_audited("sport = :22 and dport >= :80");
        assert_eq!(bc.len(), 24);
        // remaining at each instruction: 24, 16, 8 → no = 28, 20, 12
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_S_GE, 8, 28));
        assert_eq!(op(&bc, 2), (INET_DIAG_BC_S_LE, 8, 20));
        assert_eq!(op(&bc, 4), (INET_DIAG_BC_D_GE, 8, 12));
        for i in [0usize, 2, 4] {
            assert_eq!(op(&bc, i).2 % 4, 0);
        }
    }

    #[test]
    fn for_ports_builds_exact_match_program() {
        let bc = for_ports(Some(22), None).unwrap();
        audit(&bc).unwrap();
        assert_eq!(bc.len(), 16);
        assert_eq!(op(&bc, 0), (INET_DIAG_BC_S_GE, 8, 20));
        assert_eq!(op(&bc, 2), (INET_DIAG_BC_S_LE, 8, 12));
        let bc = for_ports(Some(22), Some(443)).unwrap();
        audit(&bc).unwrap();
        assert_eq!(bc.len(), 32);
        assert_eq!(op(&bc, 0).0, INET_DIAG_BC_S_GE);
        assert_eq!(op(&bc, 4).0, INET_DIAG_BC_D_GE);
        assert_eq!(op(&bc, 6), (INET_DIAG_BC_D_LE, 8, 12));
        assert!(for_ports(None, None).is_none());
    }

    #[test]
    fn boundary_ports_that_cannot_match_return_none() {
        assert!(compile(&FilterExpr::parse("dport > :65535").unwrap()).is_none());
        assert!(compile(&FilterExpr::parse("sport < :0").unwrap()).is_none());
    }

    // ------------------------------------------------------------------
    // #163 — host conditions.
    // ------------------------------------------------------------------

    #[test]
    fn src_v4_prefix_emits_hostcond() {
        let bc = assert_audited("src 10.0.0.0/8");
        assert_eq!(bc.len(), 16);
        assert_eq!(op_at(&bc, 0), (INET_DIAG_BC_S_COND, 16, 20));
        assert_eq!(bc[4], AF_INET);
        assert_eq!(bc[5], 8); // prefix_len
        assert_eq!(&bc[6..8], &[0, 0]); // struct padding
        assert_eq!(i32::from_ne_bytes(bc[8..12].try_into().unwrap()), -1);
        assert_eq!(&bc[12..16], &[10, 0, 0, 0]);
    }

    #[test]
    fn dst_v6_emits_28_byte_hostcond() {
        let bc = assert_audited("dst ::1");
        assert_eq!(bc.len(), 28);
        assert_eq!(op_at(&bc, 0), (INET_DIAG_BC_D_COND, 28, 32));
        assert_eq!(bc[4], AF_INET6);
        assert_eq!(bc[5], 128);
        let mut want = [0u8; 16];
        want[15] = 1;
        assert_eq!(&bc[12..28], &want);
    }

    #[test]
    fn prefix_len_clamps_to_family_max() {
        let a = compile(&FilterExpr::parse("src 10.0.0.1/40").unwrap()).unwrap();
        let b = compile(&FilterExpr::parse("src 10.0.0.1/32").unwrap()).unwrap();
        assert_eq!(a, b);
    }

    // ------------------------------------------------------------------
    // #163 — or / not lowering.
    // ------------------------------------------------------------------

    #[test]
    fn or_of_two_sports_lowers_with_jump() {
        // GE22 LE22 JMP GE80 LE80 — first alt failure jumps into the
        // second alt; first alt success jumps over it.
        let bc = assert_audited("sport = :22 or sport = :80");
        assert_eq!(bc.len(), 36);
        // Alt 1: GE22 fails → next alt at byte 20.
        assert_eq!(op_at(&bc, 0), (INET_DIAG_BC_S_GE, 8, 20));
        // LE22 fails → next alt at byte 20 (12 from here).
        assert_eq!(op_at(&bc, 8), (INET_DIAG_BC_S_LE, 8, 12));
        // Alt 1 matched → JMP to end (done label at byte 36 → no=20).
        assert_eq!(op_at(&bc, 16), (INET_DIAG_BC_JMP, 4, 20));
        // Alt 2: failure = reject (overshoot).
        assert_eq!(op_at(&bc, 20), (INET_DIAG_BC_S_GE, 8, 20));
        assert_eq!(op_at(&bc, 28), (INET_DIAG_BC_S_LE, 8, 12));
        assert_eq!(op_at(&bc, 28).2 as usize + 28, bc.len() + 4);
    }

    #[test]
    fn sport_ne_lowers_to_le_or_ge() {
        // != 22 → LE21 or GE23: LE21(no → alt2) JMP(end) GE23(reject)
        let bc = assert_audited("sport != :22");
        assert_eq!(bc.len(), 20);
        assert_eq!(op_at(&bc, 0), (INET_DIAG_BC_S_LE, 8, 12));
        assert_eq!(op_at(&bc, 4).2, 21);
        assert_eq!(op_at(&bc, 8), (INET_DIAG_BC_JMP, 4, 12));
        assert_eq!(op_at(&bc, 12), (INET_DIAG_BC_S_GE, 8, 12));
        assert_eq!(op_at(&bc, 16).2, 23);
    }

    #[test]
    fn not_sport_eq_equals_ne() {
        let a = compile(&FilterExpr::parse("not sport = :22").unwrap()).unwrap();
        let b = compile(&FilterExpr::parse("sport != :22").unwrap()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn ne_edge_ports_collapse_to_single_bound() {
        let bc = assert_audited("sport != :0");
        assert_eq!(bc.len(), 8);
        assert_eq!(op_at(&bc, 0).0, INET_DIAG_BC_S_GE);
        assert_eq!(op_at(&bc, 4).2, 1);

        let bc = assert_audited("sport != :65535");
        assert_eq!(bc.len(), 8);
        assert_eq!(op_at(&bc, 0).0, INET_DIAG_BC_S_LE);
        assert_eq!(op_at(&bc, 4).2, 65534);
    }

    /// **#198.** A negated host cond must never reach the kernel.
    ///
    /// The kernel's hostcond matches an AF_INET cond against a v4-mapped
    /// AF_INET6 entry; `ip_matches` calls that a cross-family non-match. The
    /// kernel cond is therefore a *superset*, and complementing a superset
    /// gives a subset — a kernel-side `not dst 10/8` would reject the
    /// dual-stack socket at `::ffff:10.1.2.3` that the filter must keep, with
    /// no way for the client-side pass to get it back.
    #[test]
    fn a_negated_host_cond_is_never_lowered_kernel_side() {
        let c = compile_filter(&FilterExpr::parse("not dst 10.0.0.0/8").unwrap());
        assert!(
            c.bytecode.is_none(),
            "a negated host cond was compiled kernel-side; it under-approximates (#198)"
        );
        assert!(
            !c.exact,
            "dropping the conjunct must mark the filter inexact so the \
             client-side backstop still runs"
        );
    }

    /// The negated host conjunct is dropped; the *rest* still compiles.
    ///
    /// Dropping one conjunct of an AND only widens the kernel-side result set,
    /// and the backstop narrows it again — so the port conjunct is still worth
    /// pushing down.
    #[test]
    fn a_negated_host_does_not_take_the_whole_program_with_it() {
        let c = compile_filter(&FilterExpr::parse("sport = :22 and not dst 10.0.0.0/8").unwrap());
        let bc = c
            .bytecode
            .expect("the sport conjunct must still be lowered kernel-side");
        audit(&bc).unwrap();
        assert_eq!(bc.len(), 16, "expected exactly the two sport primitives");
        assert!(!c.exact);
    }

    /// De Morgan still pushes `not` through `and` for the port leaves it can
    /// absorb — but a host leaf underneath sinks the whole conjunct, because
    /// dropping one arm of the resulting `Or` would *narrow* the set.
    #[test]
    fn de_morgan_pushes_not_through_and() {
        let a = compile(&FilterExpr::parse("not ( sport = :22 and dport = :80 )").unwrap())
            .unwrap();
        let b = compile(&FilterExpr::parse("sport != :22 or dport != :80").unwrap()).unwrap();
        assert_eq!(a, b);
        audit(&a).unwrap();

        // With a host leaf under the negation, there is no sound lowering.
        assert!(
            compile(&FilterExpr::parse("not ( sport = :22 and dst 10.0.0.0/8 )").unwrap())
                .is_none()
        );
    }

    #[test]
    fn nested_or_and_chains_pass_audit() {
        for expr in [
            "( sport = :22 or sport = :80 ) and dst 10.0.0.0/8",
            "src 127.0.0.1 or src ::1",
            "not ( sport = :22 or dport = :443 )",
            "( src 10.0.0.0/8 or src 192.168.0.0/16 ) and not dport = :53",
            "sport >= :1024 and sport <= :2048 and dst 10.1.2.3",
        ] {
            assert_audited(expr);
        }
    }

    #[test]
    fn huge_or_chain_overflows_to_none() {
        // Each `or` alternative costs ~20 bytes; build one that blows
        // past u16 no-offsets (~65 KB). The parser builds a 5000-deep
        // Or tree, so run on a thread with room for the recursion
        // (parse + lower + the FilterExpr Drop are all recursive).
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let mut s = String::from("sport = :1");
                for p in 2..5000u32 {
                    s.push_str(&format!(" or sport = :{p}"));
                }
                assert!(compile(&FilterExpr::parse(&s).unwrap()).is_none());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // ------------------------------------------------------------------
    // #163 — compile_filter state hoisting.
    // ------------------------------------------------------------------

    #[test]
    fn pure_state_hoists_to_mask_only() {
        let c = compile_filter(&FilterExpr::parse("state established").unwrap());
        assert_eq!(c.states, Some(TcpState::Established.mask()));
        assert!(c.bytecode.is_none());
        assert!(c.exact);
    }

    #[test]
    fn state_or_state_unions_masks() {
        let c = compile_filter(&FilterExpr::parse("state established or state time-wait").unwrap());
        assert_eq!(
            c.states,
            Some(TcpState::Established.mask() | TcpState::TimeWait.mask())
        );
        assert!(c.bytecode.is_none());
        assert!(c.exact);
    }

    #[test]
    fn not_state_complements_within_all_mask() {
        let c = compile_filter(&FilterExpr::parse("not state listen").unwrap());
        assert_eq!(
            c.states,
            Some(TcpState::all_mask() & !TcpState::Listen.mask())
        );
        assert!(c.exact);
    }

    #[test]
    fn state_and_port_split_between_mask_and_bytecode() {
        let c = compile_filter(&FilterExpr::parse("state established and sport = :22").unwrap());
        assert_eq!(c.states, Some(TcpState::Established.mask()));
        let bc = c.bytecode.expect("port half compiles");
        audit(&bc).unwrap();
        assert!(c.exact);
    }

    #[test]
    fn state_under_or_with_port_is_client_side_only() {
        // Can't hoist (or is not a conjunct boundary) and can't
        // bytecode (no state opcode): safe over-approximation.
        let c = compile_filter(&FilterExpr::parse("sport = :22 or state established").unwrap());
        assert_eq!(c.states, None);
        assert!(c.bytecode.is_none());
        assert!(!c.exact);
    }

    #[test]
    fn mixed_or_conjunct_drops_but_other_conjuncts_compile() {
        let c = compile_filter(
            &FilterExpr::parse("( sport = :22 or state listen ) and dport = :443").unwrap(),
        );
        assert_eq!(c.states, None);
        let bc = c.bytecode.expect("dport conjunct still compiles");
        audit(&bc).unwrap();
        // Only the dport program: GE443 LE443.
        assert_eq!(bc.len(), 16);
        assert_eq!(op_at(&bc, 0).0, INET_DIAG_BC_D_GE);
        assert!(!c.exact);
    }

    #[test]
    fn host_conditions_are_inexact() {
        // v4 hostconds also match v4-mapped v6 sockets kernel-side —
        // the client backstop must keep final say.
        let c = compile_filter(&FilterExpr::parse("src 10.0.0.0/8").unwrap());
        assert!(c.bytecode.is_some());
        assert!(!c.exact);

        let c = compile_filter(&FilterExpr::parse("sport = :22").unwrap());
        assert!(c.bytecode.is_some());
        assert!(c.exact, "pure port programs are exact");
    }

    #[test]
    fn compile_filter_of_port_expr_matches_compile() {
        let expr = FilterExpr::parse("sport = :22 and dport >= :80").unwrap();
        let c = compile_filter(&expr);
        assert_eq!(c.bytecode, compile(&expr));
        assert_eq!(c.states, None);
    }

    #[test]
    fn audit_oracle_rejects_malformed_programs() {
        // Sanity that the oracle itself catches breakage.
        assert!(audit(&[9, 8, 0, 0]).is_err()); // unknown code
        assert!(audit(&[2, 8, 3, 0, 0, 0, 22, 0]).is_err()); // unaligned no
        let mut bad = compile(&FilterExpr::parse("sport = :22").unwrap()).unwrap();
        bad[1] = 4; // yes below min_len for a port op
        assert!(audit(&bad).is_err());
    }
}
