//! Byte-level assertions on encoder output.
//!
//! Before this module existed there was **no test anywhere in the crate
//! that asserted a single byte** of a TC qdisc/class/filter/action
//! payload. The `write_options` "tests" built a [`MessageBuilder`],
//! called the encoder, and threw the buffer away — so a field written in
//! the wrong unit, or an attribute never emitted at all, was invisible.
//! That is how the psched-tick bugs (#191–#194) and the dropped `r2q`
//! (#213) survived.
//!
//! [`qdisc_attrs`] and friends run an encoder and hand back the emitted
//! attribute stream as a `type -> payload` map, so a test can pin an
//! exact wire value *and* assert that an attribute is present at all.
//!
//! Deliberately **not** a round-trip through nlink's own decoder: a
//! symmetrically-wrong writer and reader agree with each other. Assert
//! against hand-computed values or a capture from real `tc`/`nft`.

use std::collections::BTreeMap;

use super::{
    action::ActionConfig,
    builder::MessageBuilder,
    message::NLMSG_HDRLEN,
    tc::{ClassConfig, QdiscConfig},
};

/// Attribute type (with the nested/byteorder flags masked off) to its
/// payload, with the alignment padding stripped.
pub(crate) type AttrMap = BTreeMap<u16, Vec<u8>>;

/// Split a bare netlink attribute stream into `type -> payload`.
///
/// A nested attribute's payload is its inner stream; call this again on
/// it to descend.
pub(crate) fn parse_attrs(mut input: &[u8]) -> AttrMap {
    let mut out = AttrMap::new();
    while input.len() >= 4 {
        let len = u16::from_ne_bytes(input[0..2].try_into().unwrap()) as usize;
        let ty = u16::from_ne_bytes(input[2..4].try_into().unwrap()) & 0x3FFF;
        assert!(
            (4..=input.len()).contains(&len),
            "attr {ty}: bogus nla_len {len} with {} bytes left",
            input.len(),
        );
        out.insert(ty, input[4..len].to_vec());
        input = &input[len.next_multiple_of(4).min(input.len())..];
    }
    out
}

/// Peel the `nlmsghdr` [`MessageBuilder`] prepends and parse the
/// top-level attribute stream.
///
/// `MessageBuilder::new` seeds the buffer with `NLMSG_HDRLEN` bytes of
/// header and appends attributes after it, so everything past the header
/// *is* the attribute stream. (The length field is only stamped by
/// `finish()`, which is irrelevant here.)
pub(crate) fn builder_attrs(builder: &MessageBuilder) -> AttrMap {
    parse_attrs(&builder.as_bytes()[NLMSG_HDRLEN..])
}

pub(crate) fn encode(f: impl FnOnce(&mut MessageBuilder) -> crate::Result<()>) -> AttrMap {
    let mut builder = MessageBuilder::new(0, 0);
    f(&mut builder).expect("write_options failed");
    builder_attrs(&builder)
}

/// The attributes a qdisc config emits.
pub(crate) fn qdisc_attrs(cfg: &impl QdiscConfig) -> AttrMap {
    encode(|b| cfg.write_options(b))
}

/// The attributes a class config emits.
pub(crate) fn class_attrs(cfg: &impl ClassConfig) -> AttrMap {
    encode(|b| cfg.write_options(b))
}

/// The attributes an action config emits.
pub(crate) fn action_attrs(cfg: &impl ActionConfig) -> AttrMap {
    encode(|b| cfg.write_options(b))
}

/// The native-endian `u32` at `off` in the payload of `attr_type`.
///
/// Panics with the attribute type and payload length rather than a bare
/// slice-index panic, so a failing wire assertion says what it was
/// looking at.
pub(crate) fn u32_at(attrs: &AttrMap, attr_type: u16, off: usize) -> u32 {
    let payload = attrs
        .get(&attr_type)
        .unwrap_or_else(|| panic!("attribute {attr_type} not emitted; got {:?}", attrs.keys()));
    let end = off + 4;
    assert!(
        end <= payload.len(),
        "attribute {attr_type}: want u32 at {off}..{end}, payload is only {} bytes",
        payload.len(),
    );
    u32::from_ne_bytes(payload[off..end].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_attrs_splits_a_padded_stream() {
        let mut b = MessageBuilder::new(0, 0);
        b.append_attr(1, &[0xaa]); // 1 byte -> padded to 4
        b.append_attr(2, &7u32.to_ne_bytes());

        let attrs = builder_attrs(&b);
        assert_eq!(attrs.len(), 2);
        // Padding is stripped: the payload is the declared length, not the
        // aligned one.
        assert_eq!(attrs[&1], vec![0xaa]);
        assert_eq!(u32_at(&attrs, 2, 0), 7);
    }

    #[test]
    fn parse_attrs_masks_the_nested_flag() {
        let mut b = MessageBuilder::new(0, 0);
        let nest = b.nest_start(3);
        b.append_attr(1, &1u32.to_ne_bytes());
        b.nest_end(nest);

        let attrs = builder_attrs(&b);
        // Keyed by 3, not 3 | NLA_F_NESTED.
        let inner = parse_attrs(&attrs[&3]);
        assert_eq!(u32_at(&inner, 1, 0), 1);
    }
}
