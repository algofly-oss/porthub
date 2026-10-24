//! Interval sets: ranges of big-endian keys, and how they go on the wire.
//!
//! An interval set (`NFT_SET_INTERVAL`, the rbtree backend) stores a range
//! `[a, b]` as two elements: `a`, and `b + 1` flagged
//! `NFT_SET_ELEM_INTERVAL_END`. A range that runs to the key's maximum
//! value has no end element — a start without an end runs to the top. Keys
//! are compared as big-endian numbers, which is what addresses and ports
//! are on the wire.
//!
//! This is what an interval start without its end element means, too —
//! which is why nlink refused to write interval-set elements as plain keys
//! until this module: `10.0.0.1` alone would have matched everything from
//! `10.0.0.1` up.

use super::NFT_SET_ELEM_INTERVAL_END;
use super::types::SetElement;

/// One element as it goes on the wire: a key and its element flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireElement {
    pub(crate) key: Vec<u8>,
    /// Inclusive range end, in one element (`NFTA_SET_ELEM_KEY_END`): how
    /// an interval set of concatenated keys stores a range.
    pub(crate) key_end: Option<Vec<u8>>,
    pub(crate) flags: u32,
    /// The element's own timeout (on a range's start only).
    pub(crate) timeout: Option<std::time::Duration>,
    /// Map data (on a range's start only).
    pub(crate) data: Option<super::types::SetElementData>,
    /// The element's comment (on a range's start only).
    pub(crate) comment: Option<String>,
}

/// `key + 1`, big-endian; `None` when `key` is the maximum value.
pub(crate) fn increment(key: &[u8]) -> Option<Vec<u8>> {
    let mut out = key.to_vec();
    for byte in out.iter_mut().rev() {
        if *byte == 0xff {
            *byte = 0;
        } else {
            *byte += 1;
            return Some(out);
        }
    }
    None
}

/// `key - 1`, big-endian; `None` when `key` is zero.
pub(crate) fn decrement(key: &[u8]) -> Option<Vec<u8>> {
    let mut out = key.to_vec();
    for byte in out.iter_mut().rev() {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            return Some(out);
        }
    }
    None
}

/// An inclusive range `[start, end]` of big-endian keys.
pub(crate) type Range = (Vec<u8>, Vec<u8>);

/// The inclusive range an element covers: `[key, key_end]`, or `[key, key]`
/// for a single key.
pub(crate) fn range_of(element: &SetElement) -> Range {
    let start = element.key().to_vec();
    let end = element.key_end().map_or_else(|| start.clone(), <[u8]>::to_vec);
    (start, end)
}

/// The wire elements of a range: its start, and its end `+ 1` flagged
/// `INTERVAL_END` unless the range runs to the maximum value.
pub(crate) fn lower(range: &Range) -> Vec<WireElement> {
    let mut out = vec![WireElement {
        key: range.0.clone(),
        key_end: None,
        flags: 0,
        timeout: None,
        data: None,
        comment: None,
    }];
    if let Some(end) = increment(&range.1) {
        out.push(WireElement {
            key: end,
            key_end: None,
            flags: NFT_SET_ELEM_INTERVAL_END,
            timeout: None,
            data: None,
            comment: None,
        });
    }
    out
}

/// Pair an interval set's wire elements, as a dump returns them — in any
/// order — back into inclusive ranges.
///
/// Sorted by key, with an end before a start of the same key (adjacent
/// ranges share that key): an end closes the open start; a start with no
/// end runs to the maximum value. An end with no open start is dropped:
/// that is the all-zero "null" element `nft` adds in front of a set's first
/// range, or an orphan.
#[cfg(test)]
pub(crate) fn pair(elements: &[SetElement]) -> Vec<Range> {
    pair_elements(elements).iter().map(range_of).collect()
}

/// [`pair`], keeping what each range's start element carries — map data,
/// a timeout, the time left — on the range element.
pub(crate) fn pair_elements(elements: &[SetElement]) -> Vec<SetElement> {
    let mut sorted: Vec<&SetElement> = elements.iter().collect();
    sorted.sort_by(|a, b| {
        a.key()
            .cmp(b.key())
            .then(b.is_interval_end().cmp(&a.is_interval_end()))
    });
    let to_top = |start: &SetElement| start.clone().ending_at(vec![0xff; start.key().len()]);
    let mut ranges = Vec::new();
    let mut open: Option<&SetElement> = None;
    for element in sorted {
        if element.is_interval_end() {
            if let Some(start) = open.take()
                && let Some(end) = decrement(element.key())
            {
                ranges.push(start.clone().ending_at(end));
            }
        } else {
            if let Some(start) = open.take() {
                // Two starts in a row: the first can only run to the top.
                ranges.push(to_top(start));
            }
            open = Some(element);
        }
    }
    if let Some(start) = open {
        ranges.push(to_top(start));
    }
    ranges
}

/// Sort ranges and merge the ones that overlap or touch, the way the
/// kernel's lookups see them: `[1, 5]` and `[6, 9]` are `[1, 9]`.
pub(crate) fn canonicalize(mut ranges: Vec<Range>) -> Vec<Range> {
    ranges.sort();
    let mut out: Vec<Range> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = out.last_mut() {
            let touches = increment(&last.1).is_none_or(|next| start <= next);
            if touches {
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

/// The element for a range.
pub(crate) fn element_of(range: &Range) -> SetElement {
    SetElement::range(range.0.clone(), range.1.clone())
}

/// [`canonicalize`], for elements: sort them, and merge ranges that overlap
/// or touch when their timeouts agree. Each keeps its own timeout, which
/// rebuilding the elements from bare ranges dropped, so a range declared
/// with a timeout never timed out (#483). Ranges with different timeouts
/// stay apart: touching, that is two elements; overlapping, the kernel
/// refuses it, as it should.
pub(crate) fn canonicalize_elements(elements: &[SetElement]) -> Vec<SetElement> {
    let mut ranges: Vec<(Range, Option<std::time::Duration>)> = elements
        .iter()
        .map(|e| (range_of(e), e.timeout()))
        .collect();
    ranges.sort();
    let mut out: Vec<(Range, Option<std::time::Duration>)> = Vec::with_capacity(ranges.len());
    for ((start, end), timeout) in ranges {
        if let Some(((_, last_end), last_timeout)) = out.last_mut()
            && *last_timeout == timeout
            && increment(last_end).is_none_or(|next| start <= next)
        {
            if end > *last_end {
                *last_end = end;
            }
            continue;
        }
        out.push(((start, end), timeout));
    }
    out.into_iter()
        .map(|(range, timeout)| {
            let element = element_of(&range);
            match timeout {
                Some(t) => element.with_timeout(t),
                None => element,
            }
        })
        .collect()
}

/// The parts of `range` that no range in `held` covers. `held` must be
/// [`canonicalize`]d: sorted, and not overlapping.
pub(crate) fn subtract(range: &Range, held: &[Range]) -> Vec<Range> {
    let mut out = Vec::new();
    let mut from = Some(range.0.clone());
    for (start, end) in held {
        let Some(at) = from.clone() else { break };
        if *end < at || *start > range.1 {
            continue;
        }
        if *start > at
            && let Some(before) = decrement(start)
        {
            out.push((at, before));
        }
        from = increment(end);
    }
    if let Some(at) = from
        && at <= range.1
    {
        out.push((at, range.1.clone()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn el(key: &[u8], end: bool) -> SetElement {
        SetElement::from_wire(key.to_vec(), if end { NFT_SET_ELEM_INTERVAL_END } else { 0 })
    }

    #[test]
    fn subtract_leaves_the_uncovered_parts() {
        let r = |a: u8, b: u8| (vec![a], vec![b]);
        assert_eq!(subtract(&r(10, 50), &[r(20, 30)]), [r(10, 19), r(31, 50)]);
        assert_eq!(subtract(&r(10, 50), &[r(0, 15), r(40, 60)]), [r(16, 39)]);
        assert!(subtract(&r(10, 50), &[r(0, 255)]).is_empty());
        assert_eq!(subtract(&r(10, 50), &[r(60, 70)]), [r(10, 50)]);
        assert_eq!(subtract(&r(250, 255), &[r(240, 252)]), [r(253, 255)]);
    }

    #[test]
    fn canonicalizing_elements_keeps_their_timeouts() {
        use std::time::Duration;
        let el = |a: u8, b: u8, t: Option<u64>| {
            let e = SetElement::range(vec![a], vec![b]);
            match t {
                Some(t) => e.with_timeout(Duration::from_secs(t)),
                None => e,
            }
        };
        let out =
            canonicalize_elements(&[el(10, 20, Some(60)), el(21, 30, Some(60)), el(31, 40, None)]);
        assert_eq!(out.len(), 2);
        assert_eq!(
            (range_of(&out[0]), out[0].timeout()),
            ((vec![10], vec![30]), Some(Duration::from_secs(60)))
        );
        assert_eq!(
            (range_of(&out[1]), out[1].timeout()),
            ((vec![31], vec![40]), None)
        );
    }

    #[test]
    fn increment_and_decrement_carry_across_bytes() {
        assert_eq!(increment(&[0x00, 0xff]), Some(vec![0x01, 0x00]));
        assert_eq!(increment(&[0xff, 0xff]), None);
        assert_eq!(decrement(&[0x01, 0x00]), Some(vec![0x00, 0xff]));
        assert_eq!(decrement(&[0x00, 0x00]), None);
    }

    #[test]
    fn a_range_lowers_to_start_and_end_plus_one() {
        // udp dport 1000-2000
        let range = (1000u16.to_be_bytes().to_vec(), 2000u16.to_be_bytes().to_vec());
        assert_eq!(
            lower(&range),
            [
                WireElement {
                    key: 1000u16.to_be_bytes().to_vec(),
                    key_end: None,
                    flags: 0,
                    timeout: None,
                    data: None,
                    comment: None,
                },
                WireElement {
                    key: 2001u16.to_be_bytes().to_vec(),
                    key_end: None,
                    flags: NFT_SET_ELEM_INTERVAL_END,
                    timeout: None,
                    data: None,
                    comment: None,
                },
            ]
        );
    }

    #[test]
    fn a_range_to_the_maximum_has_no_end_element() {
        // 255.255.255.0/24 runs to 255.255.255.255.
        let range = (vec![255, 255, 255, 0], vec![255, 255, 255, 255]);
        assert_eq!(lower(&range).len(), 1);
    }

    #[test]
    fn pairing_accepts_any_dump_order_and_skips_the_null_element() {
        // [10, 20], [21, 30] (adjacent: 21 is both an end and a start),
        // and [40, max], dumped backwards with nft's null element.
        let dump = [
            el(&[40], false),
            el(&[31], true),
            el(&[21], false),
            el(&[21], true),
            el(&[10], false),
            el(&[0], true),
        ];
        assert_eq!(
            pair(&dump),
            [
                (vec![10], vec![20]),
                (vec![21], vec![30]),
                (vec![40], vec![255]),
            ]
        );
    }

    #[test]
    fn canonical_ranges_merge_overlapping_and_adjacent() {
        let ranges = vec![
            (vec![21], vec![30]),
            (vec![10], vec![20]),
            (vec![25], vec![35]),
            (vec![50], vec![60]),
            (vec![200], vec![255]),
            (vec![240], vec![250]),
        ];
        assert_eq!(
            canonicalize(ranges),
            [(vec![10], vec![35]), (vec![50], vec![60]), (vec![200], vec![255])]
        );
    }
}
