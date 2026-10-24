//! A dumped rule as a [`RuleSpec`]'s items (#708): the inverse of
//! lowering.
//!
//! The lift reads a rule's expressions left to right. At each one it tries
//! the items that could have written it: the match a load and its comparison
//! make, or the statement an anchor and the immediates feeding it make. An
//! item is taken only if lowering it after what came before gives exactly
//! the expressions it stands for, compared as the diff compares them. What
//! no item gives stays an [`Item::Expr`]. So lowering a lift gives the
//! kernel's rule back, whatever the rule is. A last check over the whole
//! rule falls back to raw expressions should an item ever disagree with its
//! context.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::config::expression_bytes;
use super::expr::{
    Expr, HashKind, LookupExpr, NatFlags, ObjrefExpr, RuleExpr, SocketKey, exprs_for_family,
    guard_at, guard_implied,
};
use super::spec::{Field, Item, Match, MatchOp, Reject, RuleSpec, Stmt, Value};
use super::types::{
    ByteorderOp, CmpOp, CtDirection, CtKey, CtState, CtStatus, ExthdrOp, Family, FibFlags,
    FibResult, Generated, HeaderWrite, IcmpxCode, MetaKey, NatKind, NatRegs, NatStatement, NatType,
    PacketField, PayloadBase, PktType, RangeOp, RangeValue, Register, RtKey, TCPOPT_MAXSEG,
    TcpFlags, ct_label_mask,
};
use super::{NFT_REJECT_ICMP_UNREACH, NFT_REJECT_TCP_RST};
use crate::netlink::tc_handle::TcHandle;
use crate::netlink::types::route::RouteType;

/// The items `exprs` lift to in a `family` table. `bytes` are the kernel's
/// own `NFTA_RULE_EXPRESSIONS`, when there are any, which the lift is
/// checked against; otherwise it is checked against `exprs` sent again.
pub(crate) fn lift(exprs: &[RuleExpr], bytes: Option<&[u8]>, family: Family) -> Vec<Item> {
    let kernel: Vec<Expr> = exprs.iter().map(RuleExpr::to_expr).collect();
    // Each item is checked against the rule so far, so the work grows with
    // the square of the rule's length. nft's rules are a handful of
    // expressions; one past this is read back as it is.
    if kernel.len() > MAX_LIFTED {
        return kernel.into_iter().map(Item::Expr).collect();
    }
    let own;
    let bytes = match bytes {
        Some(bytes) => bytes,
        None => {
            own = expression_bytes(&kernel);
            &own
        }
    };
    // The kernel's expressions as the diff compares them, one by one, where
    // they line up with what was decoded.
    let canonical = match super::config::canonical_elements(bytes) {
        elements if elements.len() == kernel.len() => elements,
        _ => kernel.iter().map(canonical).collect(),
    };
    // A guard said twice, or one the family implies, is a guard nft and
    // nlink no longer write; the diff ignores it, and so does the lift.
    let keep = kept(&kernel, family);
    let kernel: Vec<Expr> = kernel
        .into_iter()
        .zip(&keep)
        .filter_map(|(e, k)| k.then_some(e))
        .collect();
    let canonical: Vec<Vec<u8>> = canonical
        .into_iter()
        .zip(&keep)
        .filter_map(|(e, k)| k.then_some(e))
        .collect();
    let mut lifter = Lifter {
        family,
        kernel: &kernel,
        canonical: &canonical,
        raw: Vec::new(),
        sent: 0,
        items: Vec::new(),
    };
    let mut i = 0;
    while i < kernel.len() {
        let typed = lifter
            .candidates(i)
            .into_iter()
            .find_map(|item| lifter.fits(i, &item).map(|n| (item, n)));
        match typed {
            Some((item, n)) => {
                lifter.take(item);
                i += n;
            }
            None => {
                lifter.take(Item::Expr(kernel[i].clone()));
                i += 1;
            }
        }
    }
    let items = lifter.items;
    if same_body(&items, bytes, family) {
        items
    } else {
        exprs.iter().map(|e| Item::Expr(e.to_expr())).collect()
    }
}

/// The longest rule the lift types.
const MAX_LIFTED: usize = 256;

/// The most choices of fields a concatenation is tried as: two ports of
/// either protocol in each of five fields is 32.
const MAX_CHOICES: usize = 64;

/// Whether `items` lower in a `family` table to the rule `bytes` are, as
/// the diff compares them.
fn same_body(items: &[Item], bytes: &[u8], family: Family) -> bool {
    let spec: RuleSpec = items.iter().cloned().collect();
    let Ok(lowered) = spec.lower(family) else {
        return false;
    };
    super::config::canonical_body(&expression_bytes(&lowered), family)
        == super::config::canonical_body(bytes, family)
}

/// One expression as the diff compares it.
fn canonical(expr: &Expr) -> Vec<u8> {
    super::config::canonical_elements(&expression_bytes(std::slice::from_ref(expr)))
        .pop()
        .unwrap_or_default()
}

/// Which expressions are not a repeated or implied guard.
fn kept(exprs: &[Expr], family: Family) -> Vec<bool> {
    let mut keep = vec![true; exprs.len()];
    let mut seen: Vec<(MetaKey, u8)> = Vec::new();
    let mut i = 0;
    while i < exprs.len() {
        if let Some((_, key, value)) = guard_at(exprs, i) {
            if seen.contains(&(key, value)) || guard_implied(family, key, value) {
                keep[i] = false;
                keep[i + 1] = false;
            }
            seen.push((key, value));
            i += 2;
            continue;
        }
        i += 1;
    }
    keep
}

struct Lifter<'a> {
    family: Family,
    kernel: &'a [Expr],
    canonical: &'a [Vec<u8>],
    /// What the items taken so far lower to, before the family's guards.
    raw: Vec<Expr>,
    /// How many expressions `raw` sends.
    sent: usize,
    items: Vec<Item>,
}

impl Lifter<'_> {
    /// The expressions `item` stands for at `i`, after the items taken so
    /// far, if the kernel has exactly them there.
    fn fits(&self, i: usize, item: &Item) -> Option<usize> {
        let lowered = RuleSpec::new().then(item.clone()).lower_items().ok()?;
        let mut all = self.raw.clone();
        all.extend(lowered);
        let sent = exprs_for_family(&all, self.family);
        let new = sent.get(self.sent..)?;
        let there = self.canonical.get(i..i + new.len())?;
        (!new.is_empty() && new.iter().zip(there).all(|(e, k)| canonical(e) == *k))
            .then_some(new.len())
    }

    fn take(&mut self, item: Item) {
        if let Ok(lowered) = RuleSpec::new().then(item.clone()).lower_items() {
            self.raw.extend(lowered);
        }
        self.sent = exprs_for_family(&self.raw, self.family).len();
        self.items.push(item);
    }

    /// The items that could have written the expressions at `i`: past the
    /// guards in front of them first (a field's own, which it writes), then
    /// a guard as a match of its own.
    fn candidates(&self, i: usize) -> Vec<Item> {
        let rest = &self.kernel[i..];
        let guards = self.guard_run(rest);
        let mut out = self.at(&rest[guards..]);
        if guards > 0 {
            out.extend(self.at(rest));
        }
        out
    }

    /// How many expressions at the start of `exprs` are protocol guards: a
    /// `meta nfproto` or `meta l4proto` equality, or in a bridge or netdev
    /// table the `meta protocol` one nlink writes for `meta nfproto`.
    fn guard_run(&self, exprs: &[Expr]) -> usize {
        let mut n = 0;
        while let (
            Some(Expr::Meta { dreg, key }),
            Some(Expr::Cmp {
                sreg,
                op: CmpOp::Eq,
                data,
            }),
        ) = (exprs.get(n), exprs.get(n + 1))
        {
            let guard = match key {
                MetaKey::NfProto | MetaKey::L4Proto => data.len() == 1,
                MetaKey::Protocol => {
                    matches!(self.family, Family::Bridge | Family::Netdev) && data.len() == 2
                }
                _ => false,
            };
            if !guard || dreg != sreg {
                break;
            }
            n += 2;
        }
        n
    }

    /// The items whose expressions, past their guards, start at `exprs[0]`.
    fn at(&self, exprs: &[Expr]) -> Vec<Item> {
        let mut out = Vec::new();
        let Some(first) = exprs.first() else {
            return out;
        };
        for field in fields_of(first) {
            out.extend(matches_of(&field, &exprs[1..]));
            if let Some(pf) = field.packet_field() {
                out.extend(keyed_statements(pf, &exprs[1..]));
            }
        }
        for (fields, n) in concat_of(exprs) {
            out.extend(concat_items(fields, &exprs[n..]));
        }
        out.extend(statements_of(exprs, self.family));
        out
    }
}

/// Every packet field a set can hold.
const PACKET_FIELDS: [PacketField; 12] = [
    PacketField::Ip4Saddr,
    PacketField::Ip4Daddr,
    PacketField::Ip6Saddr,
    PacketField::Ip6Daddr,
    PacketField::TcpSport,
    PacketField::TcpDport,
    PacketField::UdpSport,
    PacketField::UdpDport,
    PacketField::Mark,
    PacketField::Iif,
    PacketField::Oif,
    PacketField::L4Proto,
];

/// The fields whose load into `R0` is `expr`.
fn fields_of(expr: &Expr) -> Vec<Field> {
    let r0 = Register::R0;
    let mut out: Vec<Field> = PACKET_FIELDS
        .iter()
        .filter(|f| f.load(r0) == *expr)
        .map(|f| Field::from(*f))
        .collect();
    let payload = |base, offset, len| Expr::Payload {
        dreg: r0,
        base,
        offset,
        len,
    };
    match expr {
        e if *e == payload(PayloadBase::Transport, 13, 1) => out.push(Field::TcpFlags),
        e if *e == payload(PayloadBase::Transport, 0, 1) => {
            out.extend([Field::IcmpType, Field::Icmp6Type])
        }
        Expr::Meta { dreg, key } if *dreg == r0 => out.extend(match key {
            MetaKey::IifName => Some(Field::Iifname),
            MetaKey::OifName => Some(Field::Oifname),
            MetaKey::PktType => Some(Field::PktType),
            MetaKey::NfProto => Some(Field::NfProto),
            MetaKey::Protocol => Some(Field::Protocol),
            _ => None,
        }),
        Expr::Ct { dreg, key } if *dreg == r0 => out.extend(match key {
            CtKey::State => Some(Field::CtState),
            CtKey::Status => Some(Field::CtStatus),
            CtKey::Direction => Some(Field::CtDirection),
            CtKey::Zone => Some(Field::CtZone),
            CtKey::Mark => Some(Field::CtMark),
            CtKey::Labels => Some(Field::CtLabel),
            _ => None,
        }),
        Expr::CtDirectional {
            dreg,
            key,
            direction,
        } if *dreg == r0 => out.extend(match key {
            CtKey::SrcIp | CtKey::SrcIp6 => Some(Field::CtSaddr(*direction)),
            CtKey::DstIp | CtKey::DstIp6 => Some(Field::CtDaddr(*direction)),
            CtKey::ProtoSrc => Some(Field::CtSport(*direction)),
            CtKey::ProtoDst => Some(Field::CtDport(*direction)),
            _ => None,
        }),
        Expr::Fib {
            dreg,
            result,
            flags,
        } if *dreg == r0 => out.push(Field::Fib {
            flags: *flags - FibFlags::PRESENT,
            result: *result,
        }),
        Expr::Osf { dreg, ttl, version } if *dreg == r0 => out.push(Field::Osf {
            ttl: *ttl,
            version: *version,
        }),
        Expr::Socket { dreg, key } if *dreg == r0 => out.push(Field::Socket(*key)),
        _ => {}
    }
    out
}

fn match_op(op: CmpOp) -> MatchOp {
    match op {
        CmpOp::Eq => MatchOp::Eq,
        CmpOp::Neq => MatchOp::Ne,
        CmpOp::Lt => MatchOp::Lt,
        CmpOp::Lte => MatchOp::Le,
        CmpOp::Gt => MatchOp::Gt,
        CmpOp::Gte => MatchOp::Ge,
    }
}

fn addr(data: &[u8]) -> Option<IpAddr> {
    match data.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
        _ => None,
    }
}

/// A prefix mask's length, if `mask` is one.
fn prefix_len(mask: &[u8]) -> Option<u8> {
    let ones: u32 = mask.iter().map(|b| b.count_ones()).sum();
    let len = u8::try_from(ones).ok()?;
    (super::types::prefix_to_mask(mask.len(), len) == mask).then_some(len)
}

/// A range of `field`, from its ends in network order.
fn push_range(
    push: &mut impl FnMut(MatchOp, Value),
    field: &Field,
    op: RangeOp,
    from: &[u8],
    to: &[u8],
) {
    if let (Some(first), Some(last)) = (range_value(field, from), range_value(field, to)) {
        let op = match op {
            RangeOp::Eq => MatchOp::Eq,
            RangeOp::Neq => MatchOp::Ne,
        };
        push(op, Value::Range(first, last));
    }
}

/// A label mask's bit, if it has one bit.
fn label_bit(mask: &[u8]) -> Option<u8> {
    (0..128u8).find(|bit| ct_label_mask(*bit).as_deref() == Some(mask))
}

fn ne_u32(data: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(data.try_into().ok()?))
}

fn be_u16(data: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(data.try_into().ok()?))
}

fn be_int(data: &[u8]) -> Option<u64> {
    (data.len() <= 8).then(|| data.iter().fold(0u64, |n, b| n << 8 | u64::from(*b)))
}

fn pkttype(n: u8) -> Option<PktType> {
    Some(match n {
        0 => PktType::Host,
        1 => PktType::Broadcast,
        2 => PktType::Multicast,
        3 => PktType::OtherHost,
        _ => return None,
    })
}

/// A flag field's bits as its typed value.
fn flags_value(field: &Field, bits: &[u8]) -> Option<Value> {
    Some(match field {
        Field::CtState => Value::CtState(CtState(ne_u32(bits)?)),
        Field::CtStatus => Value::CtStatus(CtStatus::from_bits_retain(ne_u32(bits)?)),
        Field::TcpFlags => Value::TcpFlags(TcpFlags(*bits.first().filter(|_| bits.len() == 1)?)),
        Field::CtLabel => Value::Int(label_bit(bits)?.into()),
        _ => return None,
    })
}

/// What a field's comparison with `data` could be, typed values first.
fn values(field: &Field, op: CmpOp, data: &[u8]) -> Vec<Value> {
    let mut out = Vec::new();
    if op == CmpOp::Neq {
        out.extend(flags_value(field, data));
    }
    match field {
        Field::Iifname | Field::Oifname => {
            if data.len() == 16 && data.last() == Some(&0) {
                let name = data.split(|b| *b == 0).next().unwrap_or_default();
                out.extend(std::str::from_utf8(name).ok().map(Value::from));
            }
            out.extend(
                std::str::from_utf8(data)
                    .ok()
                    .map(|p| Value::NamePrefix(p.to_string())),
            );
        }
        Field::Osf { .. } => {
            let name = data.split(|b| *b == 0).next().unwrap_or_default();
            out.extend(std::str::from_utf8(name).ok().map(Value::from));
        }
        Field::CtDirection => out.extend(
            data.first()
                .and_then(|d| CtDirection::from_u8(*d))
                .map(Value::CtDirection),
        ),
        Field::PktType => out.extend(data.first().and_then(|d| pkttype(*d)).map(Value::PktType)),
        Field::Fib {
            result: FibResult::Oif,
            ..
        } => out.extend(ne_u32(data).map(|n| Value::Bool(n != 0))),
        Field::Fib {
            result: FibResult::AddrType,
            ..
        } => out.extend(
            ne_u32(data)
                .and_then(|n| u8::try_from(n).ok())
                .map(|n| Value::RouteType(RouteType::from(n))),
        ),
        Field::Socket(SocketKey::Transparent | SocketKey::Wildcard) => {
            out.extend(data.first().map(|b| Value::Bool(*b != 0)))
        }
        _ => {}
    }
    out.extend(addr(data).map(Value::Addr));
    out.extend(field.int_value(data).map(Value::Int));
    out
}

/// A range's end as the field holds it, in network order.
fn range_value(field: &Field, data: &[u8]) -> Option<RangeValue> {
    match field.packet_field() {
        Some(
            PacketField::TcpSport
            | PacketField::TcpDport
            | PacketField::UdpSport
            | PacketField::UdpDport,
        ) => be_u16(data).map(RangeValue::Port),
        Some(PacketField::L4Proto) => {
            Some(RangeValue::U8(*data.first().filter(|_| data.len() == 1)?))
        }
        Some(PacketField::Mark | PacketField::Iif | PacketField::Oif) => {
            Some(RangeValue::U32(u32::from_be_bytes(data.try_into().ok()?)))
        }
        Some(_) => addr(data).map(RangeValue::Addr),
        None => match field {
            Field::CtMark => Some(RangeValue::U32(u32::from_be_bytes(data.try_into().ok()?))),
            Field::CtSport(_) | Field::CtDport(_) => be_u16(data).map(RangeValue::Port),
            _ => None,
        },
    }
}

/// The matches on `field` whose comparison is `rest`, after the field's
/// load.
fn matches_of(field: &Field, rest: &[Expr]) -> Vec<Item> {
    let r0 = Register::R0;
    let mut out = Vec::new();
    let mut push = |op: MatchOp, value: Value| {
        out.push(Item::Match(Match {
            field: field.clone(),
            op,
            value,
        }))
    };
    let hton = |e: &Expr| matches!(e, Expr::Byteorder { sreg, dreg, op: ByteorderOp::Hton, .. } if *sreg == r0 && *dreg == r0);
    let set = |lookup: &LookupExpr| lookup.sreg == r0 && lookup.dreg.is_none();
    match rest {
        [Expr::Cmp { sreg, op, data }, ..] if *sreg == r0 => {
            for value in values(field, *op, data) {
                push(match_op(*op), value);
            }
        }
        [
            Expr::Bitwise {
                sreg,
                dreg,
                mask,
                xor,
                ..
            },
            Expr::Cmp {
                sreg: cmp,
                op,
                data,
            },
            ..,
        ] if *sreg == r0 && *dreg == r0 && *cmp == r0 && xor.iter().all(|b| *b == 0) => {
            let zero = data.iter().all(|b| *b == 0);
            if *op == CmpOp::Neq
                && zero
                && let Some(value) = flags_value(field, mask)
            {
                push(MatchOp::Eq, value);
            }
            if let (Some(a), Some(len)) = (addr(data), prefix_len(mask)) {
                push(match_op(*op), Value::Prefix(a, len));
            }
            if let (Some(value), Some(mask)) = (field.int_value(data), field.int_value(mask)) {
                push(match_op(*op), Value::Masked { value, mask });
            }
        }
        [b, Expr::Cmp { sreg, op, data }, ..] if hton(b) && *sreg == r0 => {
            out.extend(be_int(data).map(|n| {
                Item::Match(Match {
                    field: field.clone(),
                    op: match_op(*op),
                    value: Value::Int(n),
                })
            }));
        }
        [Expr::Range { sreg, op, from, to }, ..] if *sreg == r0 => {
            push_range(&mut push, field, *op, from, to)
        }
        [b, Expr::Range { sreg, op, from, to }, ..] if hton(b) && *sreg == r0 => {
            push_range(&mut push, field, *op, from, to)
        }
        [b, Expr::Lookup(lookup), ..] if hton(b) && set(lookup) => {
            let op = if lookup.invert {
                MatchOp::Ne
            } else {
                MatchOp::Eq
            };
            push(op, Value::IntervalSet(lookup.set.clone()));
        }
        [Expr::Lookup(lookup), ..] if set(lookup) => {
            let op = if lookup.invert {
                MatchOp::Ne
            } else {
                MatchOp::Eq
            };
            push(op, Value::Set(lookup.set.clone()));
            push(op, Value::IntervalSet(lookup.set.clone()));
        }
        _ => {}
    }
    out
}

/// The statements keyed on the packet field `field`, whose expressions
/// after its load are `rest`: a verdict map, a value map, an object map,
/// a dynset.
fn keyed_statements(field: PacketField, rest: &[Expr]) -> Vec<Item> {
    let r0 = Register::R0;
    let mut out = Vec::new();
    match rest {
        [Expr::Lookup(lookup), ..]
            if lookup.sreg == r0 && lookup.dreg == Some(Register::Verdict) =>
        {
            out.push(Item::Stmt(Stmt::Vmap {
                key: field.into(),
                map: lookup.set.clone(),
            }))
        }
        [Expr::Lookup(lookup), Expr::MetaSet { key, sreg }, ..]
            if lookup.sreg == r0 && lookup.dreg == Some(r0) && *sreg == r0 =>
        {
            out.push(Item::Stmt(Stmt::SetMetaFromMap {
                key: *key,
                field,
                map: lookup.set.clone(),
            }))
        }
        [Expr::Objref(ObjrefExpr::Map { sreg, map }), ..] if *sreg == r0 => {
            out.push(Item::Stmt(Stmt::ObjrefFromMap {
                field,
                map: map.clone(),
            }))
        }
        [Expr::Dynset(dynset), ..] if dynset.sreg_key == r0 => out.push(Item::Stmt(Stmt::Dynset {
            field,
            dynset: dynset.clone(),
        })),
        _ => {}
    }
    out
}

/// Packet fields loaded into consecutive words from `R0`, as a
/// concatenation is: each choice of fields the loads could be (a TCP and a
/// UDP port load alike; the guards tell them apart), and how many loads.
fn concat_of(exprs: &[Expr]) -> Vec<(Vec<PacketField>, usize)> {
    let mut choices: Vec<Vec<PacketField>> = vec![Vec::new()];
    let mut word = 0;
    // A data area holds 16 words, so 16 loads at most.
    for expr in exprs.iter().take(16) {
        // Past the last word the encoder asks for the last one.
        let dreg = Register::word(word).unwrap_or(Register::Reg32_15);
        let fields: Vec<PacketField> = PACKET_FIELDS
            .iter()
            .copied()
            .filter(|f| f.load(dreg) == *expr)
            .collect();
        let Some(first) = fields.first() else {
            break;
        };
        word += first.len().div_ceil(4) as usize;
        if choices.len() * fields.len() > MAX_CHOICES {
            break;
        }
        choices = choices
            .into_iter()
            .flat_map(|choice| {
                fields.iter().map(move |f| {
                    let mut choice = choice.clone();
                    choice.push(*f);
                    choice
                })
            })
            .collect();
    }
    let n = choices[0].len();
    if n == 0 {
        return Vec::new();
    }
    choices.into_iter().map(|fields| (fields, n)).collect()
}

/// What a concatenation of `fields` feeds, after its loads: a set lookup, a
/// verdict map, a hash.
fn concat_items(fields: Vec<PacketField>, rest: &[Expr]) -> Vec<Item> {
    let r0 = Register::R0;
    let mut out = Vec::new();
    match rest.first() {
        Some(Expr::Lookup(lookup)) if lookup.sreg == r0 && lookup.dreg.is_none() => {
            out.push(Item::Match(Match {
                field: Field::Concat(fields),
                op: if lookup.invert {
                    MatchOp::Ne
                } else {
                    MatchOp::Eq
                },
                value: Value::Set(lookup.set.clone()),
            }))
        }
        Some(Expr::Lookup(lookup))
            if lookup.sreg == r0 && lookup.dreg == Some(Register::Verdict) =>
        {
            out.push(Item::Stmt(Stmt::Vmap {
                key: Field::Concat(fields),
                map: lookup.set.clone(),
            }))
        }
        Some(Expr::Hash {
            dreg,
            kind: HashKind::Jenkins,
            sreg: Some(sreg),
            modulus,
            seed,
            offset,
            ..
        }) if *dreg == r0 && *sreg == r0 => {
            out.push(Item::Stmt(Stmt::Generate(Generated::Jhash {
                fields,
                modulus: *modulus,
                seed: *seed,
                offset: *offset,
            })))
        }
        _ => {}
    }
    out
}

/// The statements and verdicts whose expressions start at `exprs[0]`.
fn statements_of(exprs: &[Expr], family: Family) -> Vec<Item> {
    let r0 = Register::R0;
    let stmt = |s: Stmt| Item::Stmt(s);
    let mut out = Vec::new();
    let Some(first) = exprs.first() else {
        return out;
    };
    match first {
        Expr::Verdict(v) => out.push(Item::Verdict(v.clone())),
        Expr::Counter => out.push(stmt(Stmt::Counter)),
        Expr::Limit(limit) => out.push(stmt(Stmt::Limit(limit.clone()))),
        Expr::Quota(quota) => out.push(stmt(Stmt::Quota(quota.clone()))),
        Expr::Log(log) => out.push(stmt(Stmt::Log(log.clone()))),
        Expr::Objref(ObjrefExpr::Named { object_type, name }) => out.push(stmt(Stmt::Objref {
            object_type: *object_type,
            name: name.clone(),
        })),
        Expr::Connlimit { count, over } => out.push(stmt(Stmt::CtCount {
            count: *count,
            over: *over,
        })),
        Expr::Notrack => out.push(stmt(Stmt::Notrack)),
        Expr::FlowOffload { flowtable } => out.push(stmt(Stmt::FlowOffload(flowtable.clone()))),
        Expr::Queue(queue) => out.push(stmt(Stmt::Queue(queue.clone()))),
        Expr::Synproxy(synproxy) => out.push(stmt(Stmt::Synproxy(synproxy.clone()))),
        Expr::Reject {
            reject_type,
            icmp_code,
        } => {
            let (reject_type, code) = (*reject_type, *icmp_code);
            if reject_type == NFT_REJECT_TCP_RST && code == 0 {
                out.push(stmt(Stmt::Reject(Reject::TcpReset)));
            }
            for icmpx in [
                IcmpxCode::PortUnreachable,
                IcmpxCode::NoRoute,
                IcmpxCode::HostUnreachable,
                IcmpxCode::AdminProhibited,
            ] {
                out.push(stmt(Stmt::Reject(Reject::Icmpx(icmpx))));
            }
            if reject_type == NFT_REJECT_ICMP_UNREACH {
                out.push(stmt(Stmt::Reject(Reject::Icmp(code))));
                out.push(stmt(Stmt::Reject(Reject::Icmpv6(code))));
            }
            out.push(stmt(Stmt::Reject(Reject::With { reject_type, code })));
        }
        Expr::Numgen {
            dreg,
            kind,
            modulus,
            offset,
        } if *dreg == r0 => out.push(stmt(Stmt::Generate(Generated::Numgen {
            kind: *kind,
            modulus: *modulus,
            offset: *offset,
        }))),
        Expr::Hash {
            dreg,
            kind: HashKind::Sym,
            modulus,
            offset,
            ..
        } if *dreg == r0 => out.push(stmt(Stmt::Generate(Generated::Symhash {
            modulus: *modulus,
            offset: *offset,
        }))),
        Expr::MetaSet { key, sreg } if *sreg == r0 => out.push(stmt(Stmt::SetMetaFrom(*key))),
        Expr::CtSet { key, sreg } if *sreg == r0 => out.push(stmt(Stmt::SetCtFrom(*key))),
        _ => {}
    }
    // Two- and three-expression statements.
    match exprs {
        [
            Expr::Meta {
                dreg,
                key: MetaKey::Mark,
            },
            Expr::Bitwise { mask, xor, .. },
            Expr::MetaSet {
                key: MetaKey::Mark,
                sreg,
            },
            ..,
        ] if *dreg == r0 && *sreg == r0 => {
            if let (Some(mask), Some(value)) = (ne_u32(mask), ne_u32(xor)) {
                out.push(stmt(Stmt::SetMarkMasked { value, mask: !mask }));
            }
        }
        [
            Expr::Meta {
                dreg,
                key: MetaKey::Mark,
            },
            Expr::CtSet {
                key: CtKey::Mark,
                sreg,
            },
            ..,
        ] if *dreg == r0 && *sreg == r0 => out.push(stmt(Stmt::SaveMarkToCt)),
        [
            Expr::Ct {
                dreg,
                key: CtKey::Mark,
            },
            Expr::MetaSet {
                key: MetaKey::Mark,
                sreg,
            },
            ..,
        ] if *dreg == r0 && *sreg == r0 => out.push(stmt(Stmt::RestoreMarkFromCt)),
        [
            Expr::Rt {
                dreg,
                key: RtKey::TcpMss,
            },
            Expr::Byteorder { .. },
            Expr::ExthdrSet { .. },
            ..,
        ] if *dreg == r0 => out.push(stmt(Stmt::ClampTcpMssToPmtu)),
        [
            Expr::Payload {
                dreg,
                base: PayloadBase::Network,
                offset,
                len: 2,
            },
            Expr::Bitwise { mask, xor, .. },
            Expr::PayloadSet { .. },
            ..,
        ] if *dreg == r0 && mask.len() == 2 && xor.len() == 2 => {
            let write = match (offset, mask.as_slice()) {
                (0, [0xff, 0x03]) => Some(HeaderWrite::IpDscp(xor[1] >> 2)),
                (0, [0xf0, 0x3f]) => Some(HeaderWrite::Ip6Dscp((xor[0] << 2) | (xor[1] >> 6))),
                (8, [0x00, 0xff]) => Some(HeaderWrite::IpTtl(xor[0])),
                _ => None,
            };
            out.extend(write.map(|w| stmt(Stmt::SetHeader(w))));
        }
        _ => {}
    }
    // What a run of immediates feeds.
    let imms = exprs
        .iter()
        .take_while(|e| matches!(e, Expr::Immediate { .. }))
        .count();
    let regs: Vec<(Register, &Vec<u8>)> = exprs[..imms]
        .iter()
        .filter_map(|e| match e {
            Expr::Immediate { dreg, data } => Some((*dreg, data)),
            _ => None,
        })
        .collect();
    let reg = |r: Register| {
        regs.iter()
            .find(|(d, _)| *d == r)
            .map(|(_, data)| data.as_slice())
    };
    let Some(anchor) = exprs.get(imms) else {
        return out;
    };
    match anchor {
        Expr::MetaSet { key, sreg } if *sreg == r0 && imms == 1 => {
            let value = reg(r0).and_then(ne_u32);
            match key {
                MetaKey::Mark => out.extend(value.map(|m| stmt(Stmt::SetMark(m)))),
                MetaKey::Priority => {
                    out.extend(value.map(|c| stmt(Stmt::SetPriority(TcHandle::from(c)))))
                }
                _ => {}
            }
        }
        Expr::CtSet { key, sreg } if *sreg == r0 && imms == 1 => {
            let data = reg(r0).unwrap_or_default();
            match key {
                CtKey::Mark => out.extend(ne_u32(data).map(|m| stmt(Stmt::SetCtMark(m)))),
                CtKey::Zone => out.extend(
                    <[u8; 2]>::try_from(data)
                        .ok()
                        .map(|z| stmt(Stmt::SetCtZone(u16::from_ne_bytes(z)))),
                ),
                CtKey::Labels => out.extend(label_bit(data).map(|b| stmt(Stmt::SetCtLabel(b)))),
                _ => {}
            }
        }
        Expr::ExthdrSet {
            sreg,
            op: ExthdrOp::TcpOpt,
            exthdr_type: TCPOPT_MAXSEG,
            ..
        } if *sreg == r0 && imms == 1 => out.extend(
            reg(r0)
                .and_then(be_u16)
                .map(|mss| stmt(Stmt::ClampTcpMss(mss))),
        ),
        Expr::PayloadSet {
            sreg,
            base,
            offset,
            len,
            ..
        } if *sreg == r0 && imms == 1 => {
            let data = reg(r0).unwrap_or_default();
            let v4 = || <[u8; 4]>::try_from(data).ok().map(Ipv4Addr::from);
            let v6 = || <[u8; 16]>::try_from(data).ok().map(Ipv6Addr::from);
            let port = be_u16(data);
            let writes: Vec<HeaderWrite> = match (base, offset, len) {
                (PayloadBase::Network, 12, 4) => v4().map(HeaderWrite::IpSaddr).into_iter().collect(),
                (PayloadBase::Network, 16, 4) => v4().map(HeaderWrite::IpDaddr).into_iter().collect(),
                (PayloadBase::Network, 8, 16) => v6().map(HeaderWrite::Ip6Saddr).into_iter().collect(),
                (PayloadBase::Network, 24, 16) => v6().map(HeaderWrite::Ip6Daddr).into_iter().collect(),
                (PayloadBase::Network, 7, 1) => {
                    data.first().map(|h| HeaderWrite::Ip6HopLimit(*h)).into_iter().collect()
                }
                (PayloadBase::Transport, 0, 2) => port
                    .map(|p| vec![HeaderWrite::TcpSport(p), HeaderWrite::UdpSport(p)])
                    .unwrap_or_default(),
                (PayloadBase::Transport, 2, 2) => port
                    .map(|p| vec![HeaderWrite::TcpDport(p), HeaderWrite::UdpDport(p)])
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            out.extend(writes.into_iter().map(|w| stmt(Stmt::SetHeader(w))));
        }
        Expr::NatRegs(nat) => out.extend(nat_statements(nat, &reg).into_iter().map(stmt)),
        Expr::Tproxy {
            sreg_addr,
            sreg_port,
            ..
        } => {
            let addr_of = sreg_addr.map(|r| reg(r).and_then(addr));
            let port_of = sreg_port.map(|r| reg(r).and_then(be_u16));
            if let (Some(None), _) | (_, Some(None)) = (addr_of, port_of) {
                return out;
            }
            let (addr, port) = (addr_of.flatten(), port_of.flatten());
            let mut families = vec![family, Family::Inet, Family::Ip, Family::Ip6];
            families.dedup();
            for family in families {
                out.push(stmt(Stmt::Tproxy { family, addr, port }));
            }
        }
        Expr::Dup {
            sreg_addr,
            sreg_dev,
        } => {
            let addr = sreg_addr.map(|r| reg(r).and_then(addr));
            let dev = sreg_dev.map(|r| reg(r).and_then(ne_u32));
            if !matches!(addr, Some(None)) && !matches!(dev, Some(None)) {
                out.push(stmt(Stmt::Dup {
                    addr: addr.flatten(),
                    dev: dev.flatten(),
                }));
            }
        }
        Expr::Fwd {
            sreg_dev,
            sreg_addr,
        } => {
            let addr = sreg_addr.map(|(r, _)| reg(r).and_then(addr));
            if let (Some(dev), false) =
                (reg(*sreg_dev).and_then(ne_u32), matches!(addr, Some(None)))
            {
                out.push(stmt(Stmt::Fwd {
                    dev,
                    addr: addr.flatten(),
                }));
            }
        }
        _ => {}
    }
    out
}

/// The NAT statements that write `nat`, with its registers loaded as `reg`
/// says.
fn nat_statements<'a>(nat: &NatRegs, reg: &impl Fn(Register) -> Option<&'a [u8]>) -> Vec<Stmt> {
    let mut out = Vec::new();
    let pair = |regs: Option<(Register, Register)>, read: &dyn Fn(&[u8]) -> Option<u64>| match regs
    {
        None => Some(None),
        Some((lo, hi)) => Some(Some((read(reg(lo)?)?, read(reg(hi)?)?))),
    };
    let Some(ports) = pair(nat.proto, &|d| be_u16(d).map(u64::from)) else {
        return out;
    };
    let ports = ports.map(|(lo, hi)| (lo as u16, hi as u16));
    let addrs = match nat.addr {
        None => None,
        Some((lo, hi)) => match (reg(lo).and_then(addr), reg(hi).and_then(addr)) {
            (Some(lo), Some(hi)) => Some((lo, hi)),
            _ => return out,
        },
    };
    let flags = nat.flags - NatFlags::MAP_IPS - NatFlags::PROTO_SPECIFIED;
    let with_flags = |mut s: NatStatement| {
        if let Some((lo, hi)) = ports {
            s = s.ports(lo, hi);
        }
        s.flags = flags;
        s
    };
    match nat.kind {
        NatKind::Snat | NatKind::Dnat => {
            let nat_type = if nat.kind == NatKind::Snat {
                NatType::Snat
            } else {
                NatType::Dnat
            };
            if let (Some((lo, hi)), true) = (addrs, flags.is_empty()) {
                let one_port = match ports {
                    None => Some(None),
                    Some((lo, hi)) if lo == hi => Some(Some(lo)),
                    Some(_) => None,
                };
                if let (true, Some(port)) = (lo == hi, one_port) {
                    out.push(Stmt::NatTo {
                        nat_type,
                        addr: lo,
                        port,
                    });
                }
            }
            let base = match (addrs, nat.kind) {
                (Some((lo, hi)), NatKind::Snat) if lo == hi => NatStatement::snat(lo),
                (Some((lo, hi)), NatKind::Snat) => NatStatement::snat(lo).to(hi),
                (Some((lo, hi)), _) if lo == hi => NatStatement::dnat(lo),
                (Some((lo, hi)), _) => NatStatement::dnat(lo).to(hi),
                (None, kind) => {
                    let Some((port, _)) = ports else {
                        return out;
                    };
                    if kind == NatKind::Snat {
                        NatStatement::snat_to_port(nat.family, port)
                    } else {
                        NatStatement::dnat_to_port(nat.family, port)
                    }
                }
            };
            out.push(Stmt::Nat(with_flags(base)));
        }
        NatKind::Masquerade => {
            if ports.is_none() && flags.is_empty() {
                out.push(Stmt::Masquerade);
            }
            out.push(Stmt::Nat(with_flags(NatStatement::masquerade())));
        }
        NatKind::Redirect => {
            match ports {
                None if flags.is_empty() => out.push(Stmt::Redirect(None)),
                Some((lo, hi)) if lo == hi && flags.is_empty() => {
                    out.push(Stmt::Redirect(Some(lo)))
                }
                _ => {}
            }
            out.push(Stmt::Nat(with_flags(NatStatement::redirect())));
        }
    }
    out
}
