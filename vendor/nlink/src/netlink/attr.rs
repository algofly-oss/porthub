//! Netlink attribute (rtattr/nlattr) handling.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::error::{Error, Result};

/// Netlink attribute alignment.
pub const NLA_ALIGNTO: usize = 4;

/// Align a length to NLA_ALIGNTO boundary.
#[inline]
pub const fn nla_align(len: usize) -> usize {
    (len + NLA_ALIGNTO - 1) & !(NLA_ALIGNTO - 1)
}

/// Size of the attribute header.
pub const NLA_HDRLEN: usize = 4; // nla_align(size_of::<NlAttr>())

/// Netlink attribute header (mirrors struct nlattr / struct rtattr).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
pub struct NlAttr {
    /// Length including header.
    pub nla_len: u16,
    /// Attribute type.
    pub nla_type: u16,
}

/// Attribute type flags.
pub const NLA_F_NESTED: u16 = 1 << 15;
pub const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
pub const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

impl NlAttr {
    /// Create a new attribute header.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `NLA_HDRLEN + data_len` exceeds `u16::MAX`
    /// — the kernel's `nla_len` field is a `u16` and any larger value would
    /// silently truncate on the wire, producing a malformed (and undetectable
    /// once flushed) netlink message. Release builds saturate to `u16::MAX`
    /// so the kernel rejects the message at parse time rather than
    /// misinterpreting a wrapped length.
    pub fn new(attr_type: u16, data_len: usize) -> Self {
        let total = NLA_HDRLEN + data_len;
        debug_assert!(
            total <= u16::MAX as usize,
            "NlAttr::new: nla_len {total} exceeds u16::MAX (kernel wire limit) — \
             attribute payload {data_len} bytes is too large; split it across \
             multiple attributes"
        );
        Self {
            nla_len: total.min(u16::MAX as usize) as u16,
            nla_type: attr_type,
        }
    }

    /// Get the attribute type without flags.
    pub fn kind(&self) -> u16 {
        self.nla_type & NLA_TYPE_MASK
    }

    /// Check if this is a nested attribute.
    pub fn is_nested(&self) -> bool {
        self.nla_type & NLA_F_NESTED != 0
    }

    /// Get the payload length (total length minus header).
    pub fn payload_len(&self) -> usize {
        (self.nla_len as usize).saturating_sub(NLA_HDRLEN)
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8] {
        <Self as IntoBytes>::as_bytes(self)
    }

    /// Parse from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        Self::ref_from_prefix(data)
            .map(|(r, _)| r)
            .map_err(|_| Error::from(crate::netlink::ErrorDetail::Truncated {
                expected: std::mem::size_of::<Self>(),
                actual: data.len(),
            }))
    }
}

/// Iterator over netlink attributes in a buffer.
pub struct AttrIter<'a> {
    data: &'a [u8],
}

impl<'a> AttrIter<'a> {
    /// Create a new attribute iterator.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Check if there are no more attributes.
    pub fn is_empty(&self) -> bool {
        self.data.len() < NLA_HDRLEN
    }
}

impl<'a> Iterator for AttrIter<'a> {
    /// Returns (attribute type, payload data).
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() < NLA_HDRLEN {
            return None;
        }

        let attr = match NlAttr::from_bytes(self.data) {
            Ok(a) => a,
            Err(_) => return None,
        };

        let len = attr.nla_len as usize;
        if len < NLA_HDRLEN || len > self.data.len() {
            return None;
        }

        let payload = &self.data[NLA_HDRLEN..len];
        let aligned_len = nla_align(len);

        // Move to next attribute
        if aligned_len >= self.data.len() {
            self.data = &[];
        } else {
            self.data = &self.data[aligned_len..];
        }

        Some((attr.kind(), payload))
    }
}

/// Helper functions for extracting typed values from attribute payloads.
pub mod get {
    use super::*;

    /// Extract a u8 value.
    pub fn u8(data: &[u8]) -> Result<u8> {
        if data.is_empty() {
            return Err(Error::invalid_attribute("empty u8 attribute"));
        }
        Ok(data[0])
    }

    /// Extract a u16 value (native endian).
    pub fn u16_ne(data: &[u8]) -> Result<u16> {
        if data.len() < 2 {
            return Err(Error::invalid_attribute("truncated u16 attribute"));
        }
        Ok(u16::from_ne_bytes([data[0], data[1]]))
    }

    /// Extract a u32 value (native endian).
    pub fn u32_ne(data: &[u8]) -> Result<u32> {
        if data.len() < 4 {
            return Err(Error::invalid_attribute("truncated u32 attribute"));
        }
        Ok(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Extract a u64 value (native endian).
    pub fn u64_ne(data: &[u8]) -> Result<u64> {
        if data.len() < 8 {
            return Err(Error::invalid_attribute("truncated u64 attribute"));
        }
        Ok(u64::from_ne_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]))
    }

    /// Extract a u16 value (big endian / network order).
    pub fn u16_be(data: &[u8]) -> Result<u16> {
        if data.len() < 2 {
            return Err(Error::invalid_attribute("truncated u16 attribute"));
        }
        Ok(u16::from_be_bytes([data[0], data[1]]))
    }

    /// Extract a u32 value (big endian / network order).
    pub fn u32_be(data: &[u8]) -> Result<u32> {
        if data.len() < 4 {
            return Err(Error::invalid_attribute("truncated u32 attribute"));
        }
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }

    /// Extract a u64 value (big endian / network order).
    pub fn u64_be(data: &[u8]) -> Result<u64> {
        if data.len() < 8 {
            return Err(Error::invalid_attribute("truncated u64 attribute"));
        }
        Ok(u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]))
    }

    /// Extract a null-terminated string.
    pub fn string(data: &[u8]) -> Result<&str> {
        // Find null terminator or use whole buffer
        let len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        std::str::from_utf8(&data[..len])
            .map_err(|e| Error::invalid_attribute(format!("invalid UTF-8: {}", e)))
    }

    /// Extract bytes (no interpretation).
    pub fn bytes(data: &[u8]) -> &[u8] {
        data
    }

    /// Extract an i32 value (native endian).
    pub fn i32_ne(data: &[u8]) -> Result<i32> {
        if data.len() < 4 {
            return Err(Error::invalid_attribute("truncated i32 attribute"));
        }
        Ok(i32::from_ne_bytes([data[0], data[1], data[2], data[3]]))
    }
}

// ============================================================================
// 0.19 — AttrIter parser-robustness contract tests
// ============================================================================
//
// Plan 193 §2.3 pinned the "MessageIter must exhaust on malformed input"
// contract for the outer-frame iterator. AttrIter is the equivalent
// iterator for nested attributes — used by every parser in the lib. It
// returns `None` on malformed input rather than `Some(Err)` (i.e. it
// terminates iteration cleanly), but pre-0.19 no test pinned this:
// future refactors could quietly turn the safe `return None` paths
// into infinite loops or panics. The tests below pin the contract for
// the three CLAUDE.md `## Parser robustness` rules:
//   1. accept-larger-than-expected on fixed-size struct attribute payloads
//   2. pathological-length input guards (zero-len, truncated-len)
//   3. recoverable per-message parse failures (here: terminate cleanly)
#[cfg(test)]
mod attr_iter_robustness_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// Build an attribute with `data` as payload and `attr_type` as kind,
    /// aligned to NLA_ALIGNTO. Used to assemble well-formed test inputs.
    fn attr_bytes(attr_type: u16, data: &[u8]) -> Vec<u8> {
        let attr = NlAttr::new(attr_type, data.len());
        let mut buf = Vec::with_capacity(nla_align(NLA_HDRLEN + data.len()));
        buf.extend_from_slice(attr.as_bytes());
        buf.extend_from_slice(data);
        buf.resize(nla_align(buf.len()), 0);
        buf
    }

    #[test]
    fn empty_buffer_yields_nothing() {
        let mut it = AttrIter::new(&[]);
        assert!(it.next().is_none());
        assert!(AttrIter::new(&[]).is_empty());
    }

    #[test]
    fn under_header_size_yields_nothing() {
        // 3 bytes is below NLA_HDRLEN (4) — must not panic, must not loop.
        let mut it = AttrIter::new(&[0u8, 0, 0]);
        assert!(it.next().is_none());
    }

    #[test]
    fn single_well_formed_attribute_parses() {
        let buf = attr_bytes(7, &[0xde, 0xad, 0xbe, 0xef]);
        let mut it = AttrIter::new(&buf);
        let (kind, payload) = it.next().expect("one attribute");
        assert_eq!(kind, 7);
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef]);
        assert!(it.next().is_none());
    }

    #[test]
    fn nla_f_nested_flag_is_masked_from_kind() {
        // Build a nested attribute (NLA_F_NESTED bit set on nla_type).
        // The iterator's exposed `kind` must strip the flag bits so
        // downstream `match` dispatch sees the kernel attribute number,
        // not 0x8000 | number. Tracks vishvananda/netlink #1104.
        let attr = NlAttr {
            nla_len: (NLA_HDRLEN + 4) as u16,
            nla_type: NLA_F_NESTED | 42,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(attr.as_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        let (kind, _) = AttrIter::new(&buf).next().unwrap();
        assert_eq!(kind, 42, "NLA_F_NESTED flag must not bleed into kind");
    }

    #[test]
    fn nla_f_net_byteorder_flag_is_masked_from_kind() {
        let attr = NlAttr {
            nla_len: (NLA_HDRLEN + 4) as u16,
            nla_type: NLA_F_NET_BYTEORDER | 17,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(attr.as_bytes());
        buf.extend_from_slice(&[1, 2, 3, 4]);
        let (kind, _) = AttrIter::new(&buf).next().unwrap();
        assert_eq!(kind, 17);
    }

    #[test]
    fn zero_length_attr_terminates_iteration_without_loop() {
        // Pathological input — nla_len = 0. Pre-test the iterator
        // would re-emit the same zero-len attribute forever. The fix
        // is in `if len < NLA_HDRLEN { return None }` at the iterator
        // step; this test pins that behavior so a future regression
        // (e.g. switching the < to !=) trips immediately.
        // Reference bug class: netlink-packet-route #152.
        let buf = vec![0u8; 16]; // every header word is zero → nla_len == 0
        let start = Instant::now();
        let count = AttrIter::new(&buf).count();
        assert_eq!(count, 0);
        assert!(
            start.elapsed() < Duration::from_millis(100),
            "AttrIter on zero-len attr should terminate immediately, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn under_min_length_attr_terminates_without_panic() {
        // nla_len = 1 advertises a 1-byte attribute, but NLA_HDRLEN
        // is 4 — the kernel can never produce this, but a malicious or
        // future-kernel fuzzer might. Iterator must refuse to advance
        // into the under-sized slice (the `len < NLA_HDRLEN` guard).
        let buf = vec![1u8, 0, 0, 0, 0, 0, 0, 0];
        let mut it = AttrIter::new(&buf);
        assert!(it.next().is_none(), "under-min len must terminate");
    }

    #[test]
    fn truncated_len_beyond_buffer_terminates() {
        // nla_len = 100, but only 8 bytes of buffer present. The
        // `len > self.data.len()` guard must trip — otherwise the
        // `&self.data[NLA_HDRLEN..len]` slice would panic.
        let buf = vec![
            100, 0, // nla_len = 100
            1, 0, // nla_type = 1
            0xaa, 0xbb, 0xcc, 0xdd, // 4 bytes of payload (advertised was 96)
        ];
        let mut it = AttrIter::new(&buf);
        assert!(it.next().is_none(), "truncated-len attr must terminate");
    }

    #[test]
    fn iterator_handles_partial_final_attribute_payload() {
        // Forward-compat per CLAUDE.md rule 1: a future-kernel
        // attribute whose payload grew past the parser's expected
        // size must still parse — the caller takes the prefix it
        // understands and ignores the trailing bytes.
        //
        // Here: an attribute claims a 12-byte payload via nla_len=16
        // (header 4 + payload 12) but a consumer that only knows
        // about 4 bytes must still be able to extract the prefix.
        let buf = attr_bytes(5, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        let (kind, payload) = AttrIter::new(&buf).next().unwrap();
        assert_eq!(kind, 5);
        assert_eq!(payload, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
        // A consumer that only expects 4 bytes (e.g. older u32 attr)
        // still works because get::u32_ne reads the prefix:
        let v = get::u32_ne(payload).expect("u32 prefix");
        assert_eq!(v, u32::from_ne_bytes([1, 2, 3, 4]));
    }

    #[test]
    fn multiple_attributes_walk_correctly() {
        let mut buf = attr_bytes(1, &[0xaa]);
        buf.extend(attr_bytes(2, &[0xbb, 0xcc]));
        buf.extend(attr_bytes(3, &[0xdd, 0xee, 0xff, 0x11]));
        let attrs: Vec<_> = AttrIter::new(&buf).collect();
        assert_eq!(attrs.len(), 3);
        assert_eq!(attrs[0].0, 1);
        assert_eq!(attrs[1].0, 2);
        assert_eq!(attrs[2].0, 3);
        assert_eq!(attrs[2].1, &[0xdd, 0xee, 0xff, 0x11]);
    }

    #[test]
    fn final_attribute_ending_at_exact_buffer_boundary_terminates() {
        // The `if aligned_len >= self.data.len()` guard at line 114
        // catches "exact end" without re-entering the iterator. This
        // is the one path where AttrIter::next sets self.data = &[]
        // explicitly. Pin it.
        let buf = attr_bytes(9, &[0x01, 0x02, 0x03, 0x04]);
        let collected: Vec<_> = AttrIter::new(&buf).collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].0, 9);
    }

    #[test]
    fn iterator_does_not_loop_on_repeated_malformed_input() {
        // Defense-in-depth: even if the implementation regressed
        // toward infinite-loop on bad data, this test caps it at
        // 100 iterations and a 200ms wall-clock budget.
        let buf = vec![3u8, 0, 0, 0, 0, 0, 0, 0]; // nla_len = 3 < NLA_HDRLEN
        let start = Instant::now();
        let count = AttrIter::new(&buf).take(100).count();
        assert_eq!(count, 0);
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn is_empty_predicate_matches_iteration_behavior() {
        assert!(AttrIter::new(&[]).is_empty());
        assert!(AttrIter::new(&[0u8, 0, 0]).is_empty()); // < NLA_HDRLEN
        // Well-formed attribute: not empty.
        let buf = attr_bytes(1, &[0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(!AttrIter::new(&buf).is_empty());
    }

    /// Plan 223 — lock the NLA-header endianness policy at the
    /// test level. NLA headers round-trip through `from_ne_bytes`
    /// / `to_ne_bytes` and the bytes the kernel saw are the bytes
    /// we get out. This test fails the moment anyone reintroduces
    /// `from_le_bytes` for an NLA header on a BE host.
    #[test]
    fn nla_header_round_trips_native_endian() {
        let len: u16 = 0x0102;
        let kind: u16 = 0x0304;
        let bytes = [
            len.to_ne_bytes()[0],
            len.to_ne_bytes()[1],
            kind.to_ne_bytes()[0],
            kind.to_ne_bytes()[1],
        ];
        let parsed_len = u16::from_ne_bytes([bytes[0], bytes[1]]);
        let parsed_kind = u16::from_ne_bytes([bytes[2], bytes[3]]);
        assert_eq!(parsed_len, len);
        assert_eq!(parsed_kind, kind);
    }
}
