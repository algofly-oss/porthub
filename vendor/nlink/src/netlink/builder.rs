//! Message builder for constructing netlink messages.

use zerocopy::{Immutable, IntoBytes};

use super::{
    attr::{NLA_F_NESTED, NlAttr, nla_align},
    message::{NLMSG_HDRLEN, NlMsgHdr, nlmsg_align},
};

/// Token returned when starting a nested attribute.
/// Used to finalize the nested attribute length.
#[derive(Debug, Clone, Copy)]
pub struct NestToken {
    /// Offset of the nested attribute header in the buffer.
    offset: usize,
}

/// Builder for constructing netlink messages.
#[derive(Debug, Clone)]
pub struct MessageBuilder {
    buf: Vec<u8>,
    /// The largest nested attribute that did not fit `nla_len`, if any;
    /// see [`oversized_nest`](Self::oversized_nest).
    oversized: Option<usize>,
}

impl MessageBuilder {
    /// Create a new message builder with the given type and flags.
    pub fn new(msg_type: u16, flags: u16) -> Self {
        let header = NlMsgHdr::new(msg_type, flags);
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[..std::mem::size_of::<NlMsgHdr>()].copy_from_slice(header.as_bytes());
        Self {
            buf,
            oversized: None,
        }
    }

    /// Create a builder from an existing header.
    pub fn with_header(header: NlMsgHdr) -> Self {
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[..std::mem::size_of::<NlMsgHdr>()].copy_from_slice(header.as_bytes());
        Self {
            buf,
            oversized: None,
        }
    }

    /// The length of the largest nested attribute that exceeded the
    /// 65535-byte `nla_len`, if one did (#500). Its header is clamped, which
    /// the kernel would misparse; nlink's send paths refuse such a message.
    pub fn oversized_nest(&self) -> Option<usize> {
        self.oversized
    }

    /// An error for a message with an [oversized nest](Self::oversized_nest).
    pub(crate) fn check_size(&self) -> crate::Result<()> {
        match self.oversized {
            None => Ok(()),
            Some(len) => Err(crate::Error::invalid_message(format!(
                "netlink: a nested attribute of {len} bytes exceeds the 65535 an nla_len can say"
            ))),
        }
    }

    /// Get the current message length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Check if the message is empty (header only).
    pub fn is_empty(&self) -> bool {
        self.buf.len() == NLMSG_HDRLEN
    }

    /// Append raw bytes to the message (with alignment padding).
    pub fn append_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        // Pad to alignment
        let aligned = nlmsg_align(self.buf.len());
        self.buf.resize(aligned, 0);
    }

    /// Append a fixed-size struct to the message.
    ///
    /// The type T must implement `IntoBytes` and `Immutable` (from zerocopy),
    /// which guarantees safe byte conversion without undefined behavior.
    pub fn append<T: IntoBytes + Immutable>(&mut self, data: &T) {
        self.append_bytes(data.as_bytes());
    }

    /// Append an attribute with the given type and data.
    pub fn append_attr(&mut self, attr_type: u16, data: &[u8]) {
        let attr = NlAttr::new(attr_type, data.len());
        self.buf.extend_from_slice(attr.as_bytes());
        self.buf.extend_from_slice(data);
        // Pad to alignment
        let aligned = nla_align(self.buf.len());
        self.buf.resize(aligned, 0);
    }

    /// Append a u8 attribute.
    pub fn append_attr_u8(&mut self, attr_type: u16, value: u8) {
        self.append_attr(attr_type, &[value]);
    }

    /// Append an empty (flag) attribute with no payload.
    pub fn append_attr_empty(&mut self, attr_type: u16) {
        self.append_attr(attr_type, &[]);
    }

    /// Append a u16 attribute (native endian).
    pub fn append_attr_u16(&mut self, attr_type: u16, value: u16) {
        self.append_attr(attr_type, &value.to_ne_bytes());
    }

    /// Append a u32 attribute (native endian).
    pub fn append_attr_u32(&mut self, attr_type: u16, value: u32) {
        self.append_attr(attr_type, &value.to_ne_bytes());
    }

    /// Append a u64 attribute (native endian).
    pub fn append_attr_u64(&mut self, attr_type: u16, value: u64) {
        self.append_attr(attr_type, &value.to_ne_bytes());
    }

    /// Append a u64 attribute (big endian / network order).
    pub fn append_attr_u64_be(&mut self, attr_type: u16, value: u64) {
        self.append_attr(attr_type, &value.to_be_bytes());
    }

    /// Append a u16 attribute (big endian / network order).
    pub fn append_attr_u16_be(&mut self, attr_type: u16, value: u16) {
        self.append_attr(attr_type, &value.to_be_bytes());
    }

    /// Append a u32 attribute (big endian / network order).
    pub fn append_attr_u32_be(&mut self, attr_type: u16, value: u32) {
        self.append_attr(attr_type, &value.to_be_bytes());
    }

    /// Append a null-terminated string attribute.
    pub fn append_attr_str(&mut self, attr_type: u16, value: &str) {
        let mut data = value.as_bytes().to_vec();
        data.push(0); // null terminator
        self.append_attr(attr_type, &data);
    }

    /// Append a string attribute without null terminator.
    pub fn append_attr_string(&mut self, attr_type: u16, value: &str) {
        self.append_attr(attr_type, value.as_bytes());
    }

    /// Start a nested attribute. Returns a token to finalize it.
    pub fn nest_start(&mut self, attr_type: u16) -> NestToken {
        let offset = self.buf.len();
        // Write placeholder header with nested flag
        let attr = NlAttr::new(attr_type | NLA_F_NESTED, 0);
        self.buf.extend_from_slice(attr.as_bytes());
        NestToken { offset }
    }

    /// End a nested attribute started with `nest_start`.
    ///
    /// # Panics
    ///
    /// A nested attribute longer than `u16::MAX` (the `nla_len` wire limit)
    /// is recorded in [`oversized_nest`](Self::oversized_nest), and its
    /// header clamped. It used to be a debug-only panic and a silently
    /// clamped header in release (#500); `Connection`'s send paths now
    /// refuse the message, in every build.
    pub fn nest_end(&mut self, token: NestToken) {
        let len = self.buf.len() - token.offset;
        if len > u16::MAX as usize {
            self.oversized = Some(self.oversized.map_or(len, |seen| seen.max(len)));
        }
        // Update the length in the nested attribute header
        let len_bytes = (len.min(u16::MAX as usize) as u16).to_ne_bytes();
        self.buf[token.offset] = len_bytes[0];
        self.buf[token.offset + 1] = len_bytes[1];
        // Ensure alignment
        let aligned = nla_align(self.buf.len());
        self.buf.resize(aligned, 0);
    }

    /// Set the sequence number.
    pub fn set_seq(&mut self, seq: u32) {
        let bytes = seq.to_ne_bytes();
        self.buf[8..12].copy_from_slice(&bytes);
    }

    /// Set the port ID.
    pub fn set_pid(&mut self, pid: u32) {
        let bytes = pid.to_ne_bytes();
        self.buf[12..16].copy_from_slice(&bytes);
    }

    /// Finalize and return the message bytes.
    pub fn finish(mut self) -> Vec<u8> {
        // Update message length in header
        let len = self.buf.len() as u32;
        let len_bytes = len.to_ne_bytes();
        self.buf[0..4].copy_from_slice(&len_bytes);
        self.buf
    }

    /// Get the current buffer for inspection.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{attr::NLA_HDRLEN, message::NLM_F_REQUEST};

    #[test]
    fn test_simple_message() {
        let msg = MessageBuilder::new(16, NLM_F_REQUEST).finish();
        assert_eq!(msg.len(), NLMSG_HDRLEN);

        let header = NlMsgHdr::from_bytes(&msg).unwrap();
        assert_eq!(header.nlmsg_len as usize, NLMSG_HDRLEN);
        assert_eq!(header.nlmsg_type, 16);
        assert_eq!(header.nlmsg_flags, NLM_F_REQUEST);
    }

    #[test]
    fn test_attribute() {
        let mut builder = MessageBuilder::new(16, NLM_F_REQUEST);
        builder.append_attr_u32(1, 0x12345678);
        let msg = builder.finish();

        // Header + attr header + u32 value
        assert!(msg.len() >= NLMSG_HDRLEN + NLA_HDRLEN + 4);
    }

    #[test]
    fn test_nested_attribute() {
        let mut builder = MessageBuilder::new(16, NLM_F_REQUEST);
        let nest = builder.nest_start(1);
        builder.append_attr_u32(2, 100);
        builder.nest_end(nest);
        let msg = builder.finish();

        assert!(msg.len() > NLMSG_HDRLEN);
    }

    // ----- 0.19 regression: u16 nla_len overflow class -----
    //
    // Pre-0.19 the silent `(len as u16)` cast in `nest_end` and the
    // matching cast in `NlAttr::new` would silently produce a corrupt
    // nla_len when a payload crossed the 65535-byte wire limit. The
    // kernel would either reject the message (best case) or interpret
    // the wrapped length as a tiny attribute and skip past the real
    // payload bytes (worst case). The debug_assert kills the bug class
    // at test time; the saturating cast keeps release builds
    // kernel-rejectable rather than silently miswritten.

    #[test]
    fn nest_end_just_under_u16_max_boundary_succeeds() {
        // u16::MAX == 65_535. nla_len is u16, and alignment rounds up to
        // 4-byte boundaries — so the largest representable aligned
        // nested region is 65_532. Build exactly that.
        // Layout: nest_start hdr (4) + inner attr hdr (4) + payload (P)
        //         + alignment padding. We pick P so the inner is
        //         already 4-aligned (no padding) and the nest total is
        //         65_532.
        let mut builder = MessageBuilder::new(16, NLM_F_REQUEST);
        let nest = builder.nest_start(1);
        // 4 (nest hdr) + 4 (inner hdr) + 65_524 (payload) = 65_532
        let payload = vec![0xabu8; 65_524];
        builder.append_attr(2, &payload);
        builder.nest_end(nest); // must NOT panic — nested len = 65_532 ≤ u16::MAX
        let msg = builder.finish();
        assert!(msg.len() > NLMSG_HDRLEN + 65_000);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "exceeds u16::MAX")]
    fn nest_end_over_u16_max_panics_in_debug() {
        let mut builder = MessageBuilder::new(16, NLM_F_REQUEST);
        let nest = builder.nest_start(1);
        // Force the nested region to exceed u16::MAX.
        let payload = vec![0u8; (u16::MAX as usize) + 8];
        builder.append_attr(2, &payload);
        builder.nest_end(nest);
    }
}
