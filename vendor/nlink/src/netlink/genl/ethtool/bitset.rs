//! Ethtool bitset parsing and building.
//!
//! Ethtool uses a special bitset format for feature flags and link modes.
//! There are two formats:
//!
//! 1. **Compact format**: Two bitmaps (values + mask)
//! 2. **Bit-by-bit format**: Nested list of (index, name, value) tuples
//!
//! This module handles both formats transparently.

use std::collections::HashMap;

use super::{EthtoolBitsetAttr, EthtoolBitsetBitAttr};
use crate::netlink::{
    attr::{AttrIter, NLA_F_NESTED},
    builder::MessageBuilder,
    error::Result,
};

/// An ethtool bitset.
///
/// Represents a set of named bits, each with an index, name, and value.
#[derive(Debug, Clone, Default)]
pub struct EthtoolBitset {
    /// Number of bits in the set.
    size: u32,
    /// Bit values by index.
    values: HashMap<u32, bool>,
    /// Bit names by index.
    names: HashMap<u32, String>,
    /// Index lookup by name.
    name_to_index: HashMap<String, u32>,
}

impl EthtoolBitset {
    /// Create an empty bitset.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a bitset from netlink attributes.
    ///
    /// Handles both compact and bit-by-bit formats.
    pub fn parse(data: &[u8]) -> Result<Self> {
        let mut bitset = Self::new();
        let mut compact_value: Option<&[u8]> = None;
        let mut compact_mask: Option<&[u8]> = None;
        let mut is_nomask = false;
        let mut bits: Option<&[u8]> = None;

        for (attr_type, payload) in AttrIter::new(data) {
            match attr_type {
                t if t == EthtoolBitsetAttr::Nomask as u16 => {
                    is_nomask = true;
                }
                t if t == EthtoolBitsetAttr::Size as u16 && payload.len() >= 4 => {
                    bitset.size = u32::from_ne_bytes(payload[..4].try_into().unwrap());
                }
                t if t == EthtoolBitsetAttr::Value as u16 => {
                    compact_value = Some(payload);
                }
                t if t == EthtoolBitsetAttr::Mask as u16 => {
                    compact_mask = Some(payload);
                }
                t if t == EthtoolBitsetAttr::Bits as u16 => {
                    // Bit-by-bit format
                    bits = Some(payload);
                }
                _ => {}
            }
        }

        // After the loop, so NOMASK is known whatever the attribute order.
        if let Some(bits) = bits {
            bitset.parse_bits(bits, is_nomask)?;
        }

        // Handle compact format
        if let Some(value) = compact_value {
            bitset.parse_compact(value, compact_mask, is_nomask)?;
        }

        Ok(bitset)
    }

    /// Parse bit-by-bit format.
    ///
    /// Each list entry carries an optional `Index` (u32), an optional
    /// `Name` (string), and an optional `Value` flag. Real-world
    /// payload shapes:
    /// - **Kernel GET responses** include both `Index` and `Name`.
    /// - **Userspace SET requests** typically include only `Name`
    ///   (the kernel resolves names to indices itself). The
    ///   roundtrip test in this module verifies that `write_to` →
    ///   `parse` works for the name-only shape; if `Index` is
    ///   absent we synthesize one from the entry's position so the
    ///   bit still gets recorded.
    ///
    /// A NOMASK bitset is a list: every bit in it is set, and none carries
    /// ETHTOOL_A_BITSET_BIT_VALUE. The wanted, active and nochange feature
    /// sets come as lists, and read as all clear while the flag was
    /// required (#754).
    fn parse_bits(&mut self, data: &[u8], is_nomask: bool) -> Result<()> {
        for (_idx, bit_data) in AttrIter::new(data) {
            let mut index: Option<u32> = None;
            let mut name: Option<String> = None;
            let mut value = is_nomask;

            for (attr_type, payload) in AttrIter::new(bit_data) {
                match attr_type {
                    t if t == EthtoolBitsetBitAttr::Index as u16 && payload.len() >= 4 => {
                        index = Some(u32::from_ne_bytes(payload[..4].try_into().unwrap()));
                    }
                    t if t == EthtoolBitsetBitAttr::Name as u16 => {
                        name = Some(
                            std::str::from_utf8(payload)
                                .unwrap_or("")
                                .trim_end_matches('\0')
                                .to_string(),
                        );
                    }
                    t if t == EthtoolBitsetBitAttr::Value as u16 => {
                        // Flag attribute - presence means true
                        value = true;
                    }
                    _ => {}
                }
            }

            // For kernel GET responses both Index and Name are
            // present; for our own write_to (SET requests) only Name
            // is present. In the latter case, fall back to using the
            // position in the names table so the bit is still
            // tracked. Drop entries with neither.
            let idx = index.unwrap_or(self.names.len() as u32);
            if name.is_some() || index.is_some() {
                self.values.insert(idx, value);
                if let Some(n) = name {
                    self.name_to_index.insert(n.clone(), idx);
                    self.names.insert(idx, n);
                }
            }
        }

        Ok(())
    }

    /// Parse compact bitmap format.
    ///
    /// **Name limitation:** the compact format carries no per-bit
    /// names — only value/mask bitmaps indexed by position. So after
    /// parsing a compact bitset, [`is_set_by_index`](Self::is_set_by_index)
    /// works but the name-based accessors ([`is_set`](Self::is_set),
    /// [`active_names`](Self::active_names)) return nothing, because the
    /// kernel→string mapping (`link_mode_names[]` in
    /// `net/ethtool/common.c`) is not on the wire. nlink's ethtool GETs
    /// never request `ETHTOOL_FLAG_COMPACT_BITSET`, so the kernel
    /// answers with the verbose (named) format and link-mode names are
    /// populated; this path only triggers if a peer/kernel sends compact
    /// anyway. The fix (a static index→name table) is deliberately not
    /// done here — see #137.
    fn parse_compact(&mut self, value: &[u8], mask: Option<&[u8]>, is_nomask: bool) -> Result<()> {
        let bits_count = self.size.min((value.len() * 8) as u32);

        for bit_idx in 0..bits_count {
            let byte_idx = (bit_idx / 8) as usize;
            let bit_pos = bit_idx % 8;

            if byte_idx >= value.len() {
                break;
            }

            let bit_value = (value[byte_idx] >> bit_pos) & 1 != 0;

            // Check if this bit is in the mask (relevant)
            let in_mask = if is_nomask {
                true
            } else if let Some(m) = mask {
                if byte_idx < m.len() {
                    (m[byte_idx] >> bit_pos) & 1 != 0
                } else {
                    false
                }
            } else {
                true
            };

            if in_mask {
                self.values.insert(bit_idx, bit_value);
            }
        }

        Ok(())
    }

    /// Check if a bit is set by name.
    pub fn is_set(&self, name: &str) -> bool {
        if let Some(&idx) = self.name_to_index.get(name) {
            self.values.get(&idx).copied().unwrap_or(false)
        } else {
            false
        }
    }

    /// Check if a bit is set by index.
    pub fn is_set_by_index(&self, index: u32) -> bool {
        self.values.get(&index).copied().unwrap_or(false)
    }

    /// Get the name of a bit by index.
    pub fn name(&self, index: u32) -> Option<&str> {
        self.names.get(&index).map(|s| s.as_str())
    }

    /// Get the index of a bit by name.
    pub fn index(&self, name: &str) -> Option<u32> {
        self.name_to_index.get(name).copied()
    }

    /// Get all active (set) bit names.
    pub fn active_names(&self) -> Vec<&str> {
        self.values
            .iter()
            .filter(|&(_, v)| *v)
            .filter_map(|(idx, _)| self.names.get(idx).map(|s| s.as_str()))
            .collect()
    }

    /// Get all bit names (set or not).
    pub fn all_names(&self) -> Vec<&str> {
        self.names.values().map(|s| s.as_str()).collect()
    }

    /// A copy of this bitset with every **present** bit set to `true`.
    ///
    /// A mask-carrying bitset says two things at once: which bits are *in the
    /// set at all* (the mask), and which of those are *on* (the value). The
    /// kernel leans on this for `ETHTOOL_A_LINKMODES_OURS`, where it packs the
    /// supported modes into the mask and the advertised ones into the value —
    /// one attribute, two answers. This turns the mask half back into a bitset
    /// of its own, so "supported" reads like any other set.
    pub fn all_bits_set(&self) -> Self {
        Self {
            size: self.size,
            values: self.values.keys().map(|&idx| (idx, true)).collect(),
            names: self.names.clone(),
            name_to_index: self.name_to_index.clone(),
        }
    }

    /// Iterate over all bits with their values.
    pub fn iter(&self) -> impl Iterator<Item = (&str, bool)> {
        self.names.iter().map(|(idx, name)| {
            let value = self.values.get(idx).copied().unwrap_or(false);
            (name.as_str(), value)
        })
    }

    /// Get the number of bits.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Check if the bitset is empty.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Set a bit by name.
    pub fn set(&mut self, name: &str, value: bool) {
        if let Some(&idx) = self.name_to_index.get(name) {
            self.values.insert(idx, value);
        } else {
            // Add new bit with auto-assigned index
            let idx = self.names.len() as u32;
            self.names.insert(idx, name.to_string());
            self.name_to_index.insert(name.to_string(), idx);
            self.values.insert(idx, value);
        }
    }

    /// Add a named bit.
    pub fn add(&mut self, index: u32, name: &str, value: bool) {
        self.names.insert(index, name.to_string());
        self.name_to_index.insert(name.to_string(), index);
        self.values.insert(index, value);
        if index >= self.size {
            self.size = index + 1;
        }
    }

    /// Encode this bitset as a nested netlink attribute using the
    /// **bit-by-bit format** (the format ethtool SET requests use to
    /// convey, for example, `ETHTOOL_A_FEATURES_WANTED`).
    ///
    /// The outer attribute is `attr_type` (with `NLA_F_NESTED`); the
    /// inner structure is one `EthtoolBitsetBitAttr::Name` (+
    /// optional `EthtoolBitsetBitAttr::Value` flag) per set/cleared
    /// bit. List entries use sequential 1-based attr-type indices,
    /// matching what `parse_bits` reads back.
    ///
    /// Kernel semantics for SET requests:
    /// - Bits **present** in the list = "I'm changing this bit".
    /// - Bits with the `Value` flag = set to **true**.
    /// - Bits without the `Value` flag = set to **false**.
    /// - Bits **absent** from the list = untouched.
    ///
    /// So `enable("rx-gro")` on an empty bitset writes `(name=rx-gro,
    /// VALUE flag set)`, and `disable("rx-gro")` writes `(name=rx-gro,
    /// no VALUE flag)`.
    ///
    /// `pub(crate)` rather than `pub`: only the ethtool connection
    /// helpers need to encode bitsets; downstream users hit it
    /// through `set_features` / `set_link_modes` etc. Promoting to
    /// `pub` is a semver-minor change and so out of scope for a
    /// patch release; the right venue for that is 0.16.
    pub(crate) fn write_to(&self, builder: &mut MessageBuilder, attr_type: u16) {
        let outer = builder.nest_start(attr_type | NLA_F_NESTED);
        let bits = builder.nest_start(EthtoolBitsetAttr::Bits as u16 | NLA_F_NESTED);
        // Walk in deterministic name order so encoded bytes are
        // reproducible (HashMap iteration order is otherwise
        // randomized per run, which would break test fixtures).
        let mut entries: Vec<(&u32, &String)> = self.names.iter().collect();
        // `sort_unstable_by_key` with a borrowed-`&str` key — avoids one
        // clone per name on every `set_features` call. Ordering across
        // equal keys doesn't matter for bitset encoding (names are
        // unique within a bitset by construction); the unstable variant
        // is the right choice.
        entries.sort_unstable_by_key(|(_, name)| name.as_str());
        for (i, (idx, name)) in entries.iter().enumerate() {
            let entry_id = (i as u16) + 1;
            let entry = builder.nest_start(entry_id | NLA_F_NESTED);
            builder.append_attr_str(EthtoolBitsetBitAttr::Name as u16, name);
            if self.values.get(*idx).copied().unwrap_or(false) {
                builder.append_attr(EthtoolBitsetBitAttr::Value as u16, &[]);
            }
            builder.nest_end(entry);
        }
        builder.nest_end(bits);
        builder.nest_end(outer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitset_set_get() {
        let mut bs = EthtoolBitset::new();
        bs.add(0, "tx-checksum", true);
        bs.add(1, "rx-checksum", false);
        bs.add(2, "tso", true);

        assert!(bs.is_set("tx-checksum"));
        assert!(!bs.is_set("rx-checksum"));
        assert!(bs.is_set("tso"));
        assert!(!bs.is_set("nonexistent"));

        assert_eq!(bs.index("tx-checksum"), Some(0));
        assert_eq!(bs.name(0), Some("tx-checksum"));
    }

    #[test]
    fn test_active_names() {
        let mut bs = EthtoolBitset::new();
        bs.add(0, "a", true);
        bs.add(1, "b", false);
        bs.add(2, "c", true);

        let active: Vec<_> = bs.active_names();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&"a"));
        assert!(active.contains(&"c"));
    }

    /// `write_to` must emit bytes that `parse` reads back faithfully.
    /// This is the pure-format-correctness gate; live-kernel
    /// validation of `set_features` happens in integration tests
    /// (skip-if-no-ethtool-hw).
    #[test]
    fn write_to_roundtrips_through_parse() {
        use crate::netlink::builder::MessageBuilder;

        let mut bs = EthtoolBitset::new();
        bs.set("rx-gro", true);
        bs.set("tx-tcp-segmentation", true);
        bs.set("rx-checksum", false);

        // Write into a netlink message under attr type 99 (arbitrary).
        let mut builder = MessageBuilder::new(0, 0);
        bs.write_to(&mut builder, 99);
        let bytes = builder.finish();

        // Locate our attr 99 in the produced message and feed its
        // payload into the parser.
        let payload_start =
            find_attr_payload(&bytes, 99).expect("attr 99 should exist in the encoded message");
        let payload = &bytes[payload_start.0..payload_start.1];

        // The bitset payload starts with the inner ETHTOOL_A_BITSET_BITS
        // nest. parse() handles both compact and bit-by-bit; we encode
        // bit-by-bit, so it should reconstruct the same names/values.
        let parsed = EthtoolBitset::parse(payload).expect("parse should succeed");

        // Verify every input bit roundtripped (both true and false).
        assert!(parsed.is_set("rx-gro"), "rx-gro should be true");
        assert!(
            parsed.is_set("tx-tcp-segmentation"),
            "tx-tcp-segmentation should be true"
        );
        assert!(!parsed.is_set("rx-checksum"), "rx-checksum should be false");
        // Sanity: a name we never touched stays absent from the index.
        assert_eq!(parsed.index("nonexistent"), None);
    }

    /// The Wake-on-LAN modes bitset (the full `WOL_MODE_NAMES` space
    /// with selected bits active) must round-trip so a `get_wol` parse
    /// recovers `supported` (all names) and `active` (set names).
    #[test]
    fn wol_modes_bitset_roundtrips() {
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::genl::ethtool::WOL_MODE_NAMES;

        let mut bs = EthtoolBitset::new();
        for (idx, name) in WOL_MODE_NAMES.iter().enumerate() {
            // Enable only magic + phy, like `ethtool -W eth0 wol gp`.
            let on = *name == "magic" || *name == "phy";
            bs.add(idx as u32, name, on);
        }

        let mut builder = MessageBuilder::new(0, 0);
        bs.write_to(&mut builder, 2);
        let bytes = builder.finish();
        let (s, e) = find_attr_payload(&bytes, 2).expect("attr 2 present");
        let parsed = EthtoolBitset::parse(&bytes[s..e]).expect("parse");

        let mut supported = parsed
            .all_names()
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        supported.sort();
        assert_eq!(supported.len(), WOL_MODE_NAMES.len());

        let mut active = parsed
            .active_names()
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        active.sort();
        assert_eq!(active, vec!["magic".to_string(), "phy".to_string()]);
    }

    /// Emit a netlink attribute (TLV, 4-byte aligned) into `buf`.
    fn push_attr(buf: &mut Vec<u8>, atype: u16, payload: &[u8]) {
        let len = 4 + payload.len();
        buf.extend_from_slice(&(len as u16).to_ne_bytes());
        buf.extend_from_slice(&atype.to_ne_bytes());
        buf.extend_from_slice(payload);
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    /// Link-mode bitsets in the **verbose** (kernel-default) format
    /// carry names, so the name-based `LinkModes` accessors work. Pin
    /// that the linkmodes-shaped names round-trip through write/parse.
    #[test]
    fn link_mode_named_bitset_roundtrips() {
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::genl::ethtool::EthtoolLinkmodesAttr;
        let mut bs = EthtoolBitset::new();
        bs.add(1, "10baseT/Full", false);
        bs.add(5, "1000baseT/Full", true);
        bs.add(6, "Autoneg", true);
        bs.add(7, "TP", false);

        let mut builder = MessageBuilder::new(0, 0);
        bs.write_to(&mut builder, EthtoolLinkmodesAttr::Ours as u16);
        let bytes = builder.finish();
        let (s, e) =
            find_attr_payload(&bytes, EthtoolLinkmodesAttr::Ours as u16).expect("attr present");
        let parsed = EthtoolBitset::parse(&bytes[s..e]).expect("parse");

        assert!(parsed.is_set("1000baseT/Full"));
        assert!(parsed.is_set("Autoneg"));
        assert!(!parsed.is_set("10baseT/Full"));
        assert!(!parsed.is_set("TP"));
        let mut active = parsed.active_names();
        active.sort_unstable();
        assert_eq!(active, vec!["1000baseT/Full", "Autoneg"]);
    }

    /// The **compact** format (value + mask bitmaps, no names) had no
    /// test coverage. Pin the value&mask decode by index, the
    /// out-of-mask exclusion, and the documented name limitation
    /// (`active_names()` empty because compact carries no names).
    #[test]
    fn compact_bitset_decodes_by_index_with_mask() {
        let mut payload = Vec::new();
        push_attr(&mut payload, EthtoolBitsetAttr::Size as u16, &8u32.to_ne_bytes());
        // bits 1 and 3 set in value
        push_attr(&mut payload, EthtoolBitsetAttr::Value as u16, &[0b0000_1010]);
        // bits 1,2,3 relevant in mask (bit 0 not relevant)
        push_attr(&mut payload, EthtoolBitsetAttr::Mask as u16, &[0b0000_1110]);

        let bs = EthtoolBitset::parse(&payload).expect("parse compact");
        assert!(bs.is_set_by_index(1), "bit 1 set + in mask");
        assert!(!bs.is_set_by_index(2), "bit 2 clear + in mask");
        assert!(bs.is_set_by_index(3), "bit 3 set + in mask");
        // bit 0 is set in value's complement but not in mask → not recorded.
        assert!(!bs.is_set_by_index(0));
        // Compact carries no names: name-based views are empty.
        assert!(bs.active_names().is_empty());
        assert!(bs.all_names().is_empty());
    }

    /// Compact `nomask` form (every bit relevant) decodes all bits up to
    /// `size` without a mask attribute.
    #[test]
    fn compact_bitset_nomask_decodes_all_bits() {
        let mut payload = Vec::new();
        push_attr(&mut payload, EthtoolBitsetAttr::Nomask as u16, &[]);
        push_attr(&mut payload, EthtoolBitsetAttr::Size as u16, &4u32.to_ne_bytes());
        push_attr(&mut payload, EthtoolBitsetAttr::Value as u16, &[0b0000_0101]);

        let bs = EthtoolBitset::parse(&payload).expect("parse nomask compact");
        assert!(bs.is_set_by_index(0));
        assert!(!bs.is_set_by_index(1));
        assert!(bs.is_set_by_index(2));
        assert!(!bs.is_set_by_index(3));
    }

    #[test]
    fn bitset_parse_arbitrary_bytes_never_panics() {
        for len in 0..48usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let _ = EthtoolBitset::parse(&data);
        }
    }

    /// Helper: walk netlink message bytes, find the (start, end)
    /// payload range for a given outer attr type, ignoring the
    /// netlink message header. Used only by the roundtrip test.
    fn find_attr_payload(bytes: &[u8], target_type: u16) -> Option<(usize, usize)> {
        use crate::netlink::attr::{NLA_F_NESTED, NLA_TYPE_MASK};
        // Skip the 16-byte nlmsghdr.
        let mut cursor = 16;
        while cursor + 4 <= bytes.len() {
            let nla_len = u16::from_ne_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            let nla_type = u16::from_ne_bytes([bytes[cursor + 2], bytes[cursor + 3]])
                & !NLA_F_NESTED
                & NLA_TYPE_MASK;
            if nla_len < 4 || cursor + nla_len > bytes.len() {
                return None;
            }
            if nla_type == target_type {
                let payload_start = cursor + 4;
                let payload_end = cursor + nla_len;
                return Some((payload_start, payload_end));
            }
            // 4-byte align next attr
            cursor += (nla_len + 3) & !3;
        }
        None
    }
}
