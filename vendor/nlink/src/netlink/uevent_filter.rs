//! Kernel-side prefiltering for `NETLINK_KOBJECT_UEVENT` subscribers
//! (#251).
//!
//! A uevent monitor that cares about one subsystem is, by default,
//! woken for every USB, block, input, power-supply and thermal event
//! on the box. Each wake-up copies the whole environment block into
//! userspace and parses it into a [`HashMap`](std::collections::HashMap)
//! that is then thrown away. On a busy host that is the dominant cost
//! of running a monitor.
//!
//! [`UeventFilter`] describes what the caller wants and
//! [`UeventFilter::compile`] lowers as much of it as possible into a
//! classic-BPF program for `SO_ATTACH_FILTER`, so the kernel drops the
//! rest before it is ever queued. This mirrors
//! [`crate::sockdiag::bytecode`], which lowers a `FilterExpr` into
//! `INET_DIAG_REQ_BYTECODE` and keeps a client-side backstop for the
//! parts it cannot express — same split, same discipline.
//!
//! # The kernel-uevent wire format, and why the libudev trick doesn't apply
//!
//! `libudev` filters uevents by hashing the subsystem and devtype and
//! comparing against hashes the *udev daemon* stores in a
//! `struct udev_monitor_netlink_header`. That header exists only on
//! udevd's rebroadcast (`NETLINK_KOBJECT_UEVENT` group 2). nlink
//! subscribes to group 1 — the **kernel's** uevents — which carry no
//! such header and no hashes. So the hash trick is unavailable here,
//! and a naive substring search is not expressible in classic BPF,
//! which has no loops.
//!
//! What makes exact filtering possible anyway is the kernel's fixed
//! layout. `kobject_uevent_env()` emits `ACTION`, `DEVPATH` and
//! `SUBSYSTEM` as the first three variables, in that order, before any
//! caller- or kset-supplied key; `alloc_uevent_skb()` prefixes the
//! whole block with `"<action>@<devpath>\0"`. So a frame is always:
//!
//! ```text
//! <action>@<devpath>\0ACTION=<action>\0DEVPATH=<devpath>\0SUBSYSTEM=<sub>\0…
//! ^0                 ^H
//! ```
//!
//! Two consequences the compiler leans on:
//!
//! * **`action` is a fixed-offset prefix match.** `"add@"`,
//!   `"remove@"`, … compare at offset 0. No scan at all.
//! * **`SUBSYSTEM=` sits at a computable offset.** With
//!   `H = len(action) + 1 + len(devpath)` (the first NUL) the
//!   `SUBSYSTEM` key begins at exactly
//!   `H + 1 + (7 + a + 1) + (8 + d + 1) = 2H + 17`. One unrolled scan
//!   for the first NUL yields `H`; everything after is arithmetic.
//!
//! Anything else — `DEVTYPE`, arbitrary `KEY=VALUE` — lands after the
//! three defaults in an order the kernel does not fix, so it cannot be
//! reached without a search. Those stay in userspace.
//!
//! # The program is a prefilter; [`UeventFilter::matches`] is the authority
//!
//! The compiled program is deliberately **over-approximate**. Where it
//! cannot decide — a devpath longer than the unrolled scan, a
//! criterion classic BPF can't reach — it accepts and leaves the call
//! to userspace. It can pass a frame the caller didn't ask for; it
//! does not drop one they did. Always confirm with
//! [`UeventFilter::matches`] — [`Connection::<KobjectUevent>::recv_matching`]
//! does exactly that.
//!
//! "Accept when unsure" is not applied blindly, though. Inside a gate,
//! an alternative whose literal doesn't fit the frame fails *closed*
//! and moves to the next one, because bailing out to "accept" there
//! would make a filter for a long value match every frame too short to
//! hold it — which is every frame carrying a shorter value.
//!
//! [`Connection::<KobjectUevent>::recv_matching`]: crate::netlink::Connection::recv_matching

use super::uevent::Uevent;

/// Longest devpath the NUL scan is unrolled for.
///
/// Classic BPF has no loops, so finding the header's NUL terminator
/// costs one unrolled block per candidate offset. Real sysfs devpaths
/// run to ~60 bytes and rarely pass 150; 320 leaves generous margin
/// while keeping the program (6 instructions per step) well inside the
/// kernel's 4096-instruction `BPF_MAXINSNS` ceiling. A frame whose
/// header is longer simply falls through to "accept" and is settled by
/// [`UeventFilter::matches`].
const SCAN_LIMIT: u32 = 320;

/// Instructions the unrolled NUL scan spends per candidate offset.
const SCAN_STEP_INSNS: usize = 6;

/// Offset of the `SUBSYSTEM=` key relative to `2 * H`, where `H` is
/// the offset of the header's NUL terminator. Derived in the module
/// docs; asserted against real frames in the tests.
const SUBSYSTEM_KEY_BIAS: u32 = 17;

/// `sock_filter` is 4 fields packed into 8 bytes.
const SOCK_FILTER_SIZE: usize = 8;

// Classic-BPF opcode fragments (linux/bpf_common.h). Plain constants
// rather than a `#[repr(u16)]` enum: these are bit fields that get
// OR-ed together, so an enum would be a lie about the value space
// (and would need classifying by the UAPI audit gate as something it
// is not).
const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ST: u16 = 0x02;
const BPF_ALU: u16 = 0x04;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_MISC: u16 = 0x07;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_IMM: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MEM: u16 = 0x60;
const BPF_LEN: u16 = 0x80;

const BPF_ADD: u16 = 0x00;
const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;

const BPF_K: u16 = 0x00;
const BPF_X: u16 = 0x08;

const BPF_TAX: u16 = 0x00;
const BPF_TXA: u16 = 0x80;

/// Scratch-memory slot holding the computed `SUBSYSTEM=` offset.
const M_SUBSYS_BASE: u32 = 0;

/// Filter return value meaning "take the whole frame". A smaller
/// non-zero return would *truncate* the frame, which is never what we
/// want — a half-read uevent is worse than a dropped one.
const ACCEPT: u32 = u32::MAX;
/// Filter return value meaning "drop the frame".
const DROP: u32 = 0;

/// One classic-BPF instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl Insn {
    const fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    /// Native-endian `struct sock_filter`, which is what the kernel
    /// copies in — not a wire format, so no byte-order conversion.
    fn to_bytes(self) -> [u8; SOCK_FILTER_SIZE] {
        let mut out = [0u8; SOCK_FILTER_SIZE];
        out[0..2].copy_from_slice(&self.code.to_ne_bytes());
        out[2] = self.jt;
        out[3] = self.jf;
        out[4..8].copy_from_slice(&self.k.to_ne_bytes());
        out
    }
}

/// A compiled uevent prefilter: the classic-BPF program plus whether
/// the kernel evaluates the caller's request in full.
#[derive(Debug, Clone)]
pub struct CompiledUeventFilter {
    program: Vec<u8>,
    exact: bool,
}

impl CompiledUeventFilter {
    /// The program, in flat `struct sock_filter` layout, ready for
    /// [`crate::netlink::socket::NetlinkSocket::attach_filter`].
    pub fn program(&self) -> &[u8] {
        &self.program
    }

    /// Number of instructions.
    pub fn len(&self) -> usize {
        self.program.len() / SOCK_FILTER_SIZE
    }

    /// Whether the program is empty (an unconstrained filter compiles
    /// to nothing — attaching it would only cost cycles).
    pub fn is_empty(&self) -> bool {
        self.program.is_empty()
    }

    /// `true` when every criterion was lowered into the kernel.
    ///
    /// Even then the program stays over-approximate on frames it
    /// cannot evaluate safely, so
    /// [`UeventFilter::matches`] remains the authority. What `exact`
    /// tells you is whether the kernel is doing the *bulk* of the
    /// work, or merely the cheap part of it — the same signal
    /// [`crate::sockdiag::bytecode::compile_filter`] reports for
    /// sockdiag bytecode.
    pub fn is_exact(&self) -> bool {
        self.exact
    }
}

/// What a uevent subscriber wants to see.
///
/// Fluent setters consume `self` and return `Self`, per the crate's
/// typed-config convention; repeating a setter widens that criterion
/// (`action("add").action("remove")` matches either). Distinct
/// criteria are AND-ed: `action("add").subsystem("net")` matches only
/// added net devices.
///
/// ```no_run
/// use nlink::netlink::uevent_filter::UeventFilter;
///
/// let filter = UeventFilter::new()
///     .subsystem("net")
///     .action("add")
///     .action("remove")
///     .build();
///
/// let compiled = filter.compile();
/// assert!(compiled.is_exact());
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UeventFilter {
    actions: Vec<String>,
    subsystems: Vec<String>,
    devtypes: Vec<String>,
    env: Vec<(String, String)>,
}

impl UeventFilter {
    /// An unconstrained filter: matches everything, compiles to an
    /// empty program.
    pub fn new() -> Self {
        Self::default()
    }

    /// Match this `ACTION` (`add`, `remove`, `change`, `move`,
    /// `online`, `offline`, `bind`, `unbind`). Lowered into the kernel
    /// as a fixed-offset prefix match.
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.actions.push(action.into());
        self
    }

    /// Match this `SUBSYSTEM` (`net`, `block`, `usb`, …). Lowered into
    /// the kernel via the computed `2H + 17` offset.
    pub fn subsystem(mut self, subsystem: impl Into<String>) -> Self {
        self.subsystems.push(subsystem.into());
        self
    }

    /// Match this `DEVTYPE`.
    ///
    /// **Userspace-only.** `DEVTYPE` is added by the kset's `uevent`
    /// callback, after the three fixed keys and in no guaranteed
    /// position, so classic BPF cannot reach it. Setting this makes
    /// [`CompiledUeventFilter::is_exact`] false.
    pub fn devtype(mut self, devtype: impl Into<String>) -> Self {
        self.devtypes.push(devtype.into());
        self
    }

    /// Match an arbitrary `KEY=VALUE` from the event environment.
    ///
    /// **Userspace-only**, for the same reason as
    /// [`Self::devtype`]. Repeating with different keys AND-s them.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    /// Terminal no-op, for symmetry with the crate's other typed
    /// configs.
    pub fn build(self) -> Self {
        self
    }

    /// Whether this filter constrains anything at all.
    pub fn is_unconstrained(&self) -> bool {
        self.actions.is_empty()
            && self.subsystems.is_empty()
            && self.devtypes.is_empty()
            && self.env.is_empty()
    }

    /// The authoritative, userspace-side match.
    ///
    /// Always apply this to what comes off the socket: the compiled
    /// program is an over-approximation by construction.
    pub fn matches(&self, event: &Uevent) -> bool {
        if !self.actions.is_empty() && !self.actions.contains(&event.action) {
            return false;
        }
        if !self.subsystems.is_empty() && !self.subsystems.contains(&event.subsystem) {
            return false;
        }
        if !self.devtypes.is_empty() {
            let Some(devtype) = event.devtype() else {
                return false;
            };
            if !self.devtypes.iter().any(|d| d == devtype) {
                return false;
            }
        }
        for (key, want) in &self.env {
            if event.env.get(key).map(String::as_str) != Some(want.as_str()) {
                return false;
            }
        }
        true
    }

    /// Lower what can be lowered into a classic-BPF program.
    ///
    /// An unconstrained filter, or one whose criteria are all
    /// userspace-side, compiles to an empty program — attach nothing
    /// rather than pay for a program that accepts everything.
    pub fn compile(&self) -> CompiledUeventFilter {
        // "<action>@" — the trailing `@` is what stops `bind` from
        // matching `unbind`'s frame, and `add` from matching nothing.
        let action_literals: Vec<Vec<u8>> = self
            .actions
            .iter()
            .map(|a| {
                let mut l = a.clone().into_bytes();
                l.push(b'@');
                l
            })
            .collect();
        // "SUBSYSTEM=<value>\0" — the trailing NUL is what stops
        // `net` from matching `net_bogus`.
        let subsystem_literals: Vec<Vec<u8>> = self
            .subsystems
            .iter()
            .map(|s| {
                let mut l = b"SUBSYSTEM=".to_vec();
                l.extend_from_slice(s.as_bytes());
                l.push(0);
                l
            })
            .collect();

        // A criterion whose literal won't encode is left to
        // `matches`; lowering it half-way would be worse than not
        // lowering it. Every alternative of a gate has to be
        // encodable, since a gate drops what none of its
        // alternatives match.
        let lower_actions = !action_literals.is_empty()
            && action_literals
                .iter()
                .all(|l| literal_is_encodable(l, false));
        let lower_subsystems = !subsystem_literals.is_empty()
            && subsystem_literals
                .iter()
                .all(|l| literal_is_encodable(l, true));

        let user_side = !self.devtypes.is_empty()
            || !self.env.is_empty()
            || (!action_literals.is_empty() && !lower_actions)
            || (!subsystem_literals.is_empty() && !lower_subsystems);

        if !lower_actions && !lower_subsystems {
            return CompiledUeventFilter {
                program: Vec::new(),
                exact: !user_side,
            };
        }

        let mut prog: Vec<Insn> = Vec::new();
        if lower_actions {
            emit_action_gate(&mut prog, &action_literals);
        }
        if lower_subsystems {
            emit_subsystem_gate(&mut prog, &subsystem_literals);
        }
        prog.push(ret(ACCEPT));

        let mut program = Vec::with_capacity(prog.len() * SOCK_FILTER_SIZE);
        for insn in &prog {
            program.extend_from_slice(&insn.to_bytes());
        }

        CompiledUeventFilter {
            program,
            exact: !user_side,
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction constructors
// ---------------------------------------------------------------------------

/// `ret #k`
const fn ret(k: u32) -> Insn {
    Insn::new(BPF_RET | BPF_K, 0, 0, k)
}

/// `ja +k` — unconditional forward jump with a 32-bit displacement,
/// the escape hatch for the 8-bit `jt`/`jf` fields.
const fn ja(k: u32) -> Insn {
    Insn::new(BPF_JMP | BPF_JA, 0, 0, k)
}

/// `ld #len` — A = frame length.
const fn ld_len() -> Insn {
    Insn::new(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0)
}

/// `ldx #k`
const fn ldx_imm(k: u32) -> Insn {
    Insn::new(BPF_LDX | BPF_W | BPF_IMM, 0, 0, k)
}

/// `ld M[slot]` — A = scratch slot.
const fn ld_mem(slot: u32) -> Insn {
    Insn::new(BPF_LD | BPF_W | BPF_MEM, 0, 0, slot)
}

/// `ldx M[slot]`
const fn ldx_mem(slot: u32) -> Insn {
    Insn::new(BPF_LDX | BPF_W | BPF_MEM, 0, 0, slot)
}

/// `st M[slot]`
const fn st_mem(slot: u32) -> Insn {
    Insn::new(BPF_ST, 0, 0, slot)
}

/// `tax` — X = A.
const fn tax() -> Insn {
    Insn::new(BPF_MISC | BPF_TAX, 0, 0, 0)
}

/// `txa` — A = X.
const fn txa() -> Insn {
    Insn::new(BPF_MISC | BPF_TXA, 0, 0, 0)
}

/// `add #k`
const fn add_imm(k: u32) -> Insn {
    Insn::new(BPF_ALU | BPF_ADD | BPF_K, 0, 0, k)
}

/// `add x` — A += X.
const fn add_x() -> Insn {
    Insn::new(BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0)
}

/// `jge #k, jt, jf` — taken when A >= k.
const fn jge_imm(k: u32, jt: u8, jf: u8) -> Insn {
    Insn::new(BPF_JMP | BPF_JGE | BPF_K, jt, jf, k)
}

/// `jge x, jt, jf` — taken when A >= X.
const fn jge_x(jt: u8, jf: u8) -> Insn {
    Insn::new(BPF_JMP | BPF_JGE | BPF_X, jt, jf, 0)
}

/// `jeq #k, jt, jf`
const fn jeq_imm(k: u32, jt: u8, jf: u8) -> Insn {
    Insn::new(BPF_JMP | BPF_JEQ | BPF_K, jt, jf, k)
}

/// Absolute load of `width` bytes at `offset`.
const fn ld_abs(width: u16, offset: u32) -> Insn {
    Insn::new(BPF_LD | width | BPF_ABS, 0, 0, offset)
}

/// X-relative load of `width` bytes at `X + offset`.
const fn ld_ind(width: u16, offset: u32) -> Insn {
    Insn::new(BPF_LD | width | BPF_IND, 0, 0, offset)
}

// ---------------------------------------------------------------------------
// Literal comparison
// ---------------------------------------------------------------------------

/// Where a literal comparison starts, and how the frame-length guard
/// in front of it is expressed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Addressing {
    /// `[k]` — a compile-time-known offset from the start of the frame.
    Absolute(u32),
    /// `[x + k]`, with the base offset stashed in scratch slot
    /// `M[slot]` because computing the guard clobbers X.
    Indirect { slot: u32 },
}

/// Longest literal the compiler will lower.
///
/// Each alternative's mismatch path is an 8-bit `jf` displacement over
/// its own comparison block, which runs about one instruction per two
/// literal bytes. 100 bytes leaves a wide margin (a subsystem name is
/// a handful of characters); anything longer is left to
/// [`UeventFilter::matches`] rather than encoded unsafely.
const MAX_LITERAL: usize = 100;

/// Split `literal` into the (width, offset, big-endian value) chunks a
/// comparison walks.
///
/// Chunks never read past the literal's own length: 4-byte words while
/// at least 4 bytes remain, then a 2-byte half, then single bytes. A
/// 3-byte tail becomes half + byte. That is what lets the guard bound
/// the frame-length check at exactly `literal.len()`.
///
/// cBPF's multi-byte loads are big-endian (`get_unaligned_be32`), so
/// each immediate is the literal's bytes read most-significant-first.
fn chunks(literal: &[u8]) -> Vec<(u16, u32, u32)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < literal.len() {
        let remaining = literal.len() - i;
        if remaining >= 4 {
            let v = u32::from_be_bytes([literal[i], literal[i + 1], literal[i + 2], literal[i + 3]]);
            out.push((BPF_W, i as u32, v));
            i += 4;
        } else if remaining >= 2 {
            let v = u16::from_be_bytes([literal[i], literal[i + 1]]) as u32;
            out.push((BPF_H, i as u32, v));
            i += 2;
        } else {
            out.push((BPF_B, i as u32, literal[i] as u32));
            i += 1;
        }
    }
    out
}

/// Emit one alternative of a gate: "if the frame holds `literal` at
/// the addressing's base, jump to the gate's exit; otherwise fall
/// through to whatever comes next".
///
/// The alternative opens with a frame-length guard, and a frame too
/// short to hold this literal **fails closed** — it moves on to the
/// next alternative rather than accepting. It has to: an alternative
/// that bailed out to "accept" would make a filter for a long value
/// (`SUBSYSTEM=power_supply`) match every frame merely shorter than
/// it, which is every frame for a different, shorter subsystem.
///
/// The guard is also what keeps the comparison in bounds. cBPF answers
/// an out-of-bounds packet read by dropping the frame outright — not
/// by failing that one comparison — so an unguarded compare in an
/// early alternative would swallow frames a later alternative would
/// have matched.
///
/// Success jumps are placeholders; the caller patches them once the
/// gate's exit is known.
fn emit_literal_alternative(
    prog: &mut Vec<Insn>,
    literal: &[u8],
    addressing: Addressing,
    pending_success: &mut Vec<usize>,
) {
    let chunks = chunks(literal);
    // First compare through the trailing `ja`.
    let block_len = chunks.len() * 2 + 1;

    match addressing {
        Addressing::Absolute(base) => {
            // Base is constant, so the guard folds to one comparison.
            prog.push(ld_len());
            prog.push(jge_imm(base + literal.len() as u32, 0, block_len as u8));
        }
        Addressing::Indirect { slot } => {
            // X = base + len(literal), compared against the frame
            // length; then X is restored from the scratch slot.
            prog.push(ld_mem(slot));
            prog.push(add_imm(literal.len() as u32));
            prog.push(tax());
            prog.push(ld_len());
            prog.push(jge_x(0, (block_len + 1) as u8));
            prog.push(ldx_mem(slot));
        }
    }

    let base_off = match addressing {
        Addressing::Absolute(base) => base,
        Addressing::Indirect { .. } => 0,
    };
    for (i, (width, offset, value)) in chunks.iter().copied().enumerate() {
        prog.push(match addressing {
            Addressing::Absolute(_) => ld_abs(width, base_off + offset),
            Addressing::Indirect { .. } => ld_ind(width, offset),
        });
        // Instructions still to come in this alternative *after* the
        // jeq: the remaining (load, jeq) pairs plus the `ja`.
        let remaining_after = block_len - (i * 2 + 2);
        prog.push(jeq_imm(value, 0, remaining_after as u8));
    }
    // Every chunk matched. Placeholder — patched to the gate's exit.
    pending_success.push(prog.len());
    prog.push(ja(0));
}

/// Whether `literal` fits the 8-bit displacements an alternative uses.
fn literal_is_encodable(literal: &[u8], indirect: bool) -> bool {
    if literal.is_empty() || literal.len() > MAX_LITERAL {
        return false;
    }
    let block_len = chunks(literal).len() * 2 + 1;
    let widest = if indirect { block_len + 1 } else { block_len };
    widest <= u8::MAX as usize
}

/// Patch every recorded `ja` placeholder to land on `target`.
fn patch_success_jumps(prog: &mut [Insn], pending: &[usize], target: usize) {
    for &idx in pending {
        // cBPF displacements count instructions *after* the jump.
        prog[idx].k = (target - idx - 1) as u32;
    }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

/// `<action>@` at offset 0, for any of `literals`; drop otherwise.
fn emit_action_gate(prog: &mut Vec<Insn>, literals: &[Vec<u8>]) {
    let mut pending = Vec::new();
    for literal in literals {
        emit_literal_alternative(prog, literal, Addressing::Absolute(0), &mut pending);
    }
    // Fell past every alternative: no action matched.
    prog.push(ret(DROP));
    let exit = prog.len();
    patch_success_jumps(prog, &pending, exit);
}

/// `SUBSYSTEM=<sub>\0` at the computed offset, for any of `literals`;
/// drop otherwise.
fn emit_subsystem_gate(prog: &mut Vec<Insn>, literals: &[Vec<u8>]) {
    // --- scan for the header's NUL terminator -> X = H ---
    //
    // Six instructions per candidate offset. The `ja` trampoline is
    // what makes the exit reachable at all: `jeq`'s jt/jf are 8-bit
    // and the scan runs far longer than 255 instructions.
    //
    // A frame with no NUL inside the scan window is read out of
    // bounds and so dropped by the kernel. That is the right answer:
    // `Uevent::parse` needs the header's NUL too, so such a frame
    // could never have matched.
    prog.push(ldx_imm(0));
    let scan_start = prog.len();
    for _ in 0..SCAN_LIMIT {
        prog.push(ld_ind(BPF_B, 0)); // A = frame[X]
        prog.push(jeq_imm(0, 0, 1)); // NUL? -> next insn : skip the ja
        prog.push(ja(0)); // patched to `found`
        prog.push(txa());
        prog.push(add_imm(1));
        prog.push(tax());
    }
    // Ran off the end of the unrolled scan: a devpath longer than
    // SCAN_LIMIT. The base offset is unknowable here, so this is the
    // one place the gate has to fail open.
    prog.push(ret(ACCEPT));

    let found = prog.len();
    for step in 0..SCAN_LIMIT as usize {
        let ja_idx = scan_start + step * SCAN_STEP_INSNS + 2;
        prog[ja_idx].k = (found - ja_idx - 1) as u32;
    }

    // --- X = 2H + 17, stashed for the per-alternative guards ---
    prog.push(txa()); // A = H
    prog.push(add_x()); // A = 2H
    prog.push(add_imm(SUBSYSTEM_KEY_BIAS)); // A = base
    prog.push(st_mem(M_SUBSYS_BASE)); // M[0] = base
    prog.push(tax()); // X = base

    let mut pending = Vec::new();
    for literal in literals {
        emit_literal_alternative(
            prog,
            literal,
            Addressing::Indirect {
                slot: M_SUBSYS_BASE,
            },
            &mut pending,
        );
    }
    prog.push(ret(DROP));
    let exit = prog.len();
    patch_success_jumps(prog, &pending, exit);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a kernel-shaped uevent frame the way `alloc_uevent_skb`
    /// does: `"<action>@<devpath>\0"` then the environment block with
    /// ACTION/DEVPATH/SUBSYSTEM first.
    fn frame(action: &str, devpath: &str, subsystem: &str, extra: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(format!("{action}@{devpath}").as_bytes());
        out.push(0);
        for kv in [
            format!("ACTION={action}"),
            format!("DEVPATH={devpath}"),
            format!("SUBSYSTEM={subsystem}"),
        ]
        .iter()
        .chain(extra.iter().map(|s| s.to_string()).collect::<Vec<_>>().iter())
        {
            out.extend_from_slice(kv.as_bytes());
            out.push(0);
        }
        out
    }

    /// The whole subsystem gate rests on this identity. Check it
    /// against real frame shapes rather than trusting the algebra.
    #[test]
    fn subsystem_key_sits_at_twice_the_header_nul_plus_17() {
        for (action, devpath, subsystem) in [
            ("add", "/devices/pci0000:00/0000:00:14.0/usb1/1-1", "usb"),
            ("remove", "/devices/virtual/block/loop0", "block"),
            ("bind", "/devices/virtual/net/veth0", "net"),
            ("change", "/d", "x"),
        ] {
            let f = frame(action, devpath, subsystem, &[]);
            let h = f.iter().position(|&b| b == 0).unwrap() as u32;
            let base = (2 * h + SUBSYSTEM_KEY_BIAS) as usize;
            assert_eq!(
                &f[base..base + 10],
                b"SUBSYSTEM=",
                "action={action} devpath={devpath}"
            );
        }
    }

    /// A tiny classic-BPF interpreter — enough of the instruction set
    /// for the programs this module emits. Returns the filter's
    /// verdict; an out-of-bounds load drops, as the kernel's does.
    fn run(program: &[u8], frame: &[u8]) -> u32 {
        let insns: Vec<Insn> = program
            .as_chunks::<SOCK_FILTER_SIZE>()
            .0
            .iter()
            .map(|c| Insn {
                code: u16::from_ne_bytes([c[0], c[1]]),
                jt: c[2],
                jf: c[3],
                k: u32::from_ne_bytes([c[4], c[5], c[6], c[7]]),
            })
            .collect();

        let load = |off: u32, width: u16| -> Option<u32> {
            let off = off as usize;
            let n = match width {
                BPF_W => 4,
                BPF_H => 2,
                _ => 1,
            };
            if off.checked_add(n)? > frame.len() {
                return None;
            }
            Some(match n {
                4 => u32::from_be_bytes([
                    frame[off],
                    frame[off + 1],
                    frame[off + 2],
                    frame[off + 3],
                ]),
                2 => u16::from_be_bytes([frame[off], frame[off + 1]]) as u32,
                _ => frame[off] as u32,
            })
        };

        let (mut a, mut x) = (0u32, 0u32);
        let mut mem = [0u32; 16];
        let mut pc = 0usize;
        let mut steps = 0usize;
        loop {
            steps += 1;
            assert!(steps < 1_000_000, "interpreter did not terminate");
            let i = insns[pc];
            pc += 1;
            let class = i.code & 0x07;
            match class {
                BPF_RET => return i.k,
                BPF_LD => {
                    let mode = i.code & 0xe0;
                    let width = i.code & 0x18;
                    let v = match mode {
                        BPF_LEN => Some(frame.len() as u32),
                        BPF_IMM => Some(i.k),
                        BPF_MEM => Some(mem[i.k as usize]),
                        BPF_ABS => load(i.k, width),
                        BPF_IND => load(x.wrapping_add(i.k), width),
                        _ => unreachable!("unsupported ld mode {mode:#x}"),
                    };
                    match v {
                        Some(v) => a = v,
                        // The kernel aborts the program on an
                        // out-of-bounds packet read.
                        None => return DROP,
                    }
                }
                BPF_LDX => {
                    x = match i.code & 0xe0 {
                        BPF_IMM => i.k,
                        BPF_MEM => mem[i.k as usize],
                        mode => unreachable!("unsupported ldx mode {mode:#x}"),
                    }
                }
                BPF_ST => mem[i.k as usize] = a,
                BPF_ALU => {
                    let operand = if i.code & BPF_X != 0 { x } else { i.k };
                    match i.code & 0xf0 {
                        BPF_ADD => a = a.wrapping_add(operand),
                        op => unreachable!("unsupported alu op {op:#x}"),
                    }
                }
                BPF_JMP => {
                    let op = i.code & 0xf0;
                    if op == BPF_JA {
                        pc += i.k as usize;
                        continue;
                    }
                    let operand = if i.code & BPF_X != 0 { x } else { i.k };
                    let taken = match op {
                        BPF_JEQ => a == operand,
                        BPF_JGE => a >= operand,
                        _ => unreachable!("unsupported jmp op {op:#x}"),
                    };
                    pc += if taken { i.jt as usize } else { i.jf as usize };
                }
                BPF_MISC => {
                    if i.code & 0xf8 == BPF_TXA {
                        a = x;
                    } else {
                        x = a;
                    }
                }
                _ => unreachable!("unsupported class {class:#x}"),
            }
        }
    }

    fn accepts(filter: &UeventFilter, f: &[u8]) -> bool {
        run(filter.compile().program(), f) != DROP
    }

    /// The interpreter above decodes `struct sock_filter` with the
    /// same field layout `Insn::to_bytes` encodes, so the two are
    /// mirror images: swap `jt`/`jf`, or emit `k` before them, and
    /// every semantic test still passes while the kernel rejects the
    /// program (or worse, accepts a different one).
    ///
    /// So pin the bytes by hand. This is the smallest program the
    /// compiler emits — one action, one chunk — laid out instruction
    /// by instruction.
    ///
    /// `sock_filter` is native-endian (the kernel copies the struct in
    /// rather than parsing a wire format), so the literal bytes below
    /// are little-endian and the assertion is gated accordingly.
    #[test]
    #[cfg(target_endian = "little")]
    fn program_bytes_match_the_sock_filter_layout() {
        let program = UeventFilter::new().action("add").build().compile();

        #[rustfmt::skip]
        let expected: [u8; 7 * SOCK_FILTER_SIZE] = [
            // ld #len                     BPF_LD|BPF_W|BPF_LEN = 0x80
            0x80, 0x00,  0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
            // jge #4, 0, 3                BPF_JMP|BPF_JGE|BPF_K = 0x35
            // Frame shorter than "add@" cannot match: jf skips the
            // 3-instruction comparison block to the gate's `ret #0`.
            0x35, 0x00,  0x00, 0x03,  0x04, 0x00, 0x00, 0x00,
            // ld [0]                      BPF_LD|BPF_W|BPF_ABS = 0x20
            0x20, 0x00,  0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
            // jeq #0x61646440, 0, 1       BPF_JMP|BPF_JEQ|BPF_K = 0x15
            // "add@" read big-endian, as cBPF's word loads are.
            0x15, 0x00,  0x00, 0x01,  0x40, 0x64, 0x64, 0x61,
            // ja +1                       BPF_JMP|BPF_JA = 0x05
            0x05, 0x00,  0x00, 0x00,  0x01, 0x00, 0x00, 0x00,
            // ret #0                      BPF_RET|BPF_K = 0x06
            0x06, 0x00,  0x00, 0x00,  0x00, 0x00, 0x00, 0x00,
            // ret #0xffffffff             accept the whole frame
            0x06, 0x00,  0x00, 0x00,  0xff, 0xff, 0xff, 0xff,
        ];

        assert_eq!(program.len(), 7);
        assert_eq!(program.program(), &expected[..]);
    }

    /// The chunker decides both what the comparison reads and where
    /// the length guard is set, so pin its output directly rather than
    /// only through the interpreter.
    #[test]
    fn chunking_covers_every_remainder_without_overreading() {
        // 4 bytes: one word.
        assert_eq!(chunks(b"add@"), vec![(BPF_W, 0, 0x6164_6440)]);
        // 1, 2 and 3-byte tails: byte, half, half+byte.
        assert_eq!(chunks(b"a"), vec![(BPF_B, 0, 0x61)]);
        assert_eq!(chunks(b"ab"), vec![(BPF_H, 0, 0x6162)]);
        assert_eq!(chunks(b"abc"), vec![(BPF_H, 0, 0x6162), (BPF_B, 2, 0x63)]);
        assert_eq!(
            chunks(b"abcdef"),
            vec![(BPF_W, 0, 0x6162_6364), (BPF_H, 4, 0x6566)]
        );

        // The guard bounds the frame-length check at exactly the
        // literal's length, which only holds if no chunk reads past
        // it.
        for len in 1..40usize {
            let literal = vec![b'x'; len];
            let last = *chunks(&literal).last().unwrap();
            let width = match last.0 {
                BPF_W => 4,
                BPF_H => 2,
                _ => 1,
            };
            assert_eq!(last.1 as usize + width, len, "literal of {len} bytes");
        }
    }

    #[test]
    fn is_unconstrained_tracks_every_criterion() {
        assert!(UeventFilter::new().is_unconstrained());
        assert!(!UeventFilter::new().action("add").is_unconstrained());
        assert!(!UeventFilter::new().subsystem("net").is_unconstrained());
        assert!(!UeventFilter::new().devtype("disk").is_unconstrained());
        assert!(!UeventFilter::new().env("IFINDEX", "3").is_unconstrained());
    }

    /// An unconstrained filter matches everything — otherwise
    /// `recv_matching` on a filter with only kernel-side criteria
    /// would silently drop what the kernel let through.
    #[test]
    fn an_unconstrained_filter_matches_every_event() {
        let filter = UeventFilter::new().build();
        for action in ["add", "remove", "bind"] {
            for subsystem in ["net", "usb"] {
                let event =
                    Uevent::parse(&frame(action, "/devices/x", subsystem, &[])).unwrap();
                assert!(filter.matches(&event));
            }
        }
    }

    #[test]
    fn unconstrained_filter_compiles_to_nothing() {
        let compiled = UeventFilter::new().build().compile();
        assert!(compiled.is_empty());
        assert!(compiled.is_exact());
    }

    #[test]
    fn userspace_only_filter_compiles_to_nothing_and_is_inexact() {
        let compiled = UeventFilter::new().devtype("disk").build().compile();
        assert!(compiled.is_empty());
        assert!(!compiled.is_exact());
    }

    #[test]
    fn program_is_a_whole_number_of_instructions() {
        let compiled = UeventFilter::new().subsystem("net").action("add").compile();
        assert_eq!(compiled.program().len() % SOCK_FILTER_SIZE, 0);
        assert_eq!(compiled.len(), compiled.program().len() / SOCK_FILTER_SIZE);
    }

    #[test]
    fn instruction_count_stays_under_bpf_maxinsns() {
        // The kernel rejects anything past BPF_MAXINSNS outright, and
        // the unrolled scan is the only thing here that scales.
        const BPF_MAXINSNS: usize = 4096;
        let compiled = UeventFilter::new()
            .subsystem("net")
            .subsystem("block")
            .subsystem("power_supply")
            .action("add")
            .action("remove")
            .action("change")
            .compile();
        assert!(
            compiled.len() < BPF_MAXINSNS,
            "{} instructions",
            compiled.len()
        );
    }

    #[test]
    fn action_gate_accepts_only_named_actions() {
        let filter = UeventFilter::new().action("add").action("remove").build();
        assert!(accepts(&filter, &frame("add", "/devices/virtual/net/veth0", "net", &[])));
        assert!(accepts(&filter, &frame("remove", "/devices/virtual/net/veth0", "net", &[])));
        assert!(!accepts(&filter, &frame("change", "/devices/virtual/net/veth0", "net", &[])));
        assert!(!accepts(&filter, &frame("bind", "/devices/virtual/net/veth0", "net", &[])));
    }

    /// `add` is a prefix of nothing, but `bind`/`unbind` share a tail
    /// and `remove` shares a prefix with nothing — the trailing `@` is
    /// what keeps these from aliasing.
    #[test]
    fn action_gate_does_not_alias_on_prefixes() {
        let filter = UeventFilter::new().action("bind").build();
        assert!(accepts(&filter, &frame("bind", "/devices/x", "net", &[])));
        assert!(!accepts(&filter, &frame("unbind", "/devices/x", "net", &[])));
    }

    #[test]
    fn subsystem_gate_accepts_only_named_subsystems() {
        let filter = UeventFilter::new().subsystem("net").build();
        assert!(accepts(&filter, &frame("add", "/devices/virtual/net/veth0", "net", &[])));
        assert!(!accepts(&filter, &frame("add", "/devices/virtual/block/loop0", "block", &[])));
        assert!(!accepts(
            &filter,
            &frame("add", "/devices/pci0000:00/0000:00:14.0/usb1/1-1", "usb", &[])
        ));
    }

    /// `net` must not match `netlink`-style longer names: the literal
    /// carries the value's NUL terminator for exactly this reason.
    #[test]
    fn subsystem_gate_requires_the_whole_value() {
        let filter = UeventFilter::new().subsystem("net").build();
        assert!(!accepts(&filter, &frame("add", "/devices/x", "net_bogus", &[])));

        let filter = UeventFilter::new().subsystem("net_bogus").build();
        assert!(!accepts(&filter, &frame("add", "/devices/x", "net", &[])));
        assert!(accepts(&filter, &frame("add", "/devices/x", "net_bogus", &[])));
    }

    #[test]
    fn subsystem_gate_handles_every_literal_tail_length() {
        // "SUBSYSTEM=" + value + NUL, exercised across all four
        // remainders mod 4 so the word/half/byte chunking is covered.
        for value in ["a", "ab", "abc", "abcd", "abcde", "abcdef"] {
            let filter = UeventFilter::new().subsystem(value).build();
            assert!(
                accepts(&filter, &frame("add", "/devices/x", value, &[])),
                "value={value}"
            );
            assert!(
                !accepts(&filter, &frame("add", "/devices/x", "other", &[])),
                "value={value}"
            );
        }
    }

    #[test]
    fn combined_gates_are_anded() {
        let filter = UeventFilter::new().action("add").subsystem("net").build();
        assert!(accepts(&filter, &frame("add", "/devices/x", "net", &[])));
        assert!(!accepts(&filter, &frame("remove", "/devices/x", "net", &[])));
        assert!(!accepts(&filter, &frame("add", "/devices/x", "block", &[])));
    }

    /// The devpath scan is bounded; past the bound the program must
    /// fail *open*, never dropping something the caller asked for.
    #[test]
    fn overlong_devpath_falls_through_to_accept() {
        let long = format!("/devices/{}", "x".repeat(SCAN_LIMIT as usize + 64));
        let filter = UeventFilter::new().subsystem("net").build();
        // Wrong subsystem, but unresolvable within the scan bound —
        // so it is passed up for `matches` to reject.
        assert!(accepts(&filter, &frame("add", &long, "block", &[])));
    }

    /// The contract on a truncated frame is not "always accept" — it
    /// is "never drop something `matches` would have kept". A
    /// truncation that no longer parses, or that parses into an event
    /// the filter rejects anyway, may be dropped in the kernel.
    ///
    /// Truncations are taken at NUL boundaries: that is the only
    /// shape a short frame can have coming off the socket, since the
    /// kernel terminates every variable it writes. The one
    /// mid-variable case that behaves differently is pinned by
    /// [`unterminated_subsystem_value_is_dropped`].
    #[test]
    fn truncation_never_drops_a_frame_that_matches() {
        let filter = UeventFilter::new()
            .action("remove")
            .action("add")
            .subsystem("net")
            .build();
        let full = frame("remove", "/devices/virtual/net/veth0", "net", &["SEQNUM=9"]);

        let boundaries = (0..=full.len())
            .filter(|&n| n == 0 || n == full.len() || full[n - 1] == 0);
        for len in boundaries {
            let truncated = &full[..len];
            let Some(event) = Uevent::parse(truncated) else {
                continue;
            };
            if filter.matches(&event) {
                assert!(
                    accepts(&filter, truncated),
                    "dropped a matching {len}-byte truncation"
                );
            }
        }
    }

    /// The one place the kernel program and the backstop disagree.
    ///
    /// `Uevent::parse` treats end-of-data as a variable terminator, so
    /// a frame cut off mid-`SUBSYSTEM` still parses with a complete
    /// subsystem value. The compiled program compares the literal
    /// *including* its NUL — which it must, or `net` would match
    /// `net_bogus` — so it fails the length guard and drops.
    ///
    /// The kernel never emits such a frame: `add_uevent_var` NUL-
    /// terminates every variable, and `SEQNUM` always follows
    /// `SUBSYSTEM`. And nlink would not deliver one anyway — `recv_msg`
    /// reads every datagram whole (#505), and drops one past its 1 MiB
    /// cap as `Error::FrameTruncated` rather than parsing a prefix.
    /// Pinned here so the divergence is a known one rather than a
    /// surprise.
    #[test]
    fn unterminated_subsystem_value_is_dropped() {
        let filter = UeventFilter::new().subsystem("net").build();
        let full = frame("remove", "/devices/virtual/net/veth0", "net", &[]);
        let cut = &full[..full.len() - 1];

        let event = Uevent::parse(cut).unwrap();
        assert_eq!(event.subsystem, "net");
        assert!(filter.matches(&event));
        assert!(!accepts(&filter, cut));
    }

    /// A subsystem name too long to encode safely is left entirely to
    /// `matches` rather than lowered half-way.
    #[test]
    fn unencodable_literal_falls_back_to_userspace() {
        let huge = "s".repeat(MAX_LITERAL + 1);
        let compiled = UeventFilter::new().subsystem(&huge).build().compile();
        assert!(compiled.is_empty());
        assert!(!compiled.is_exact());

        // Mixing it with an encodable action still lowers the action.
        let compiled = UeventFilter::new()
            .action("add")
            .subsystem(&huge)
            .build()
            .compile();
        assert!(!compiled.is_empty());
        assert!(!compiled.is_exact());
    }

    /// A gate drops what none of its alternatives match, so a long
    /// alternative must not swallow the frames a short one would take.
    /// This is why an under-length alternative fails closed.
    #[test]
    fn a_long_alternative_does_not_shadow_a_short_one() {
        let filter = UeventFilter::new()
            .subsystem("power_supply")
            .subsystem("net")
            .build();
        assert!(accepts(&filter, &frame("add", "/d", "net", &[])));
        assert!(accepts(&filter, &frame("add", "/d", "power_supply", &[])));
        assert!(!accepts(&filter, &frame("add", "/d", "block", &[])));

        // Same set, opposite declaration order — the verdict must not
        // depend on it.
        let filter = UeventFilter::new()
            .subsystem("net")
            .subsystem("power_supply")
            .build();
        assert!(accepts(&filter, &frame("add", "/d", "net", &[])));
        assert!(accepts(&filter, &frame("add", "/d", "power_supply", &[])));
        assert!(!accepts(&filter, &frame("add", "/d", "block", &[])));
    }

    #[test]
    fn matches_is_the_authority_for_userspace_criteria() {
        let filter = UeventFilter::new()
            .subsystem("block")
            .devtype("partition")
            .build();

        let disk = Uevent::parse(&frame(
            "add",
            "/devices/virtual/block/loop0",
            "block",
            &["DEVTYPE=disk"],
        ))
        .unwrap();
        let part = Uevent::parse(&frame(
            "add",
            "/devices/virtual/block/loop0p1",
            "block",
            &["DEVTYPE=partition"],
        ))
        .unwrap();

        // The kernel program cannot tell these apart...
        assert!(accepts(&filter, &frame("add", "/devices/virtual/block/loop0", "block", &["DEVTYPE=disk"])));
        // ...but the backstop can.
        assert!(!filter.matches(&disk));
        assert!(filter.matches(&part));
    }

    #[test]
    fn matches_ands_distinct_criteria_and_ors_repeats() {
        let filter = UeventFilter::new()
            .action("add")
            .action("change")
            .subsystem("net")
            .env("IFINDEX", "3")
            .build();

        let ev = |action: &str, sub: &str, ifindex: &str| {
            Uevent::parse(&frame(
                action,
                "/devices/virtual/net/veth0",
                sub,
                &[&format!("IFINDEX={ifindex}")],
            ))
            .unwrap()
        };

        assert!(filter.matches(&ev("add", "net", "3")));
        assert!(filter.matches(&ev("change", "net", "3")));
        assert!(!filter.matches(&ev("remove", "net", "3")));
        assert!(!filter.matches(&ev("add", "block", "3")));
        assert!(!filter.matches(&ev("add", "net", "4")));
    }

    #[test]
    fn every_kernel_accepted_frame_that_matches_is_accepted() {
        // The contract in one property: the program may over-accept,
        // but must never drop something `matches` would keep.
        let filter = UeventFilter::new()
            .action("add")
            .action("remove")
            .subsystem("net")
            .build();

        for action in ["add", "remove", "change", "bind", "unbind"] {
            for subsystem in ["net", "block", "usb", "n", "network"] {
                for devpath in ["/d", "/devices/virtual/net/veth0", "/devices/pci0000:00/x/y/z"] {
                    let f = frame(action, devpath, subsystem, &["SEQNUM=1"]);
                    let event = Uevent::parse(&f).unwrap();
                    if filter.matches(&event) {
                        assert!(
                            accepts(&filter, &f),
                            "dropped a matching frame: {action}@{devpath} {subsystem}"
                        );
                    }
                }
            }
        }
    }

}
