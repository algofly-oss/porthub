//! Libnftnl-compatible TLV encoding for `NFTA_RULE_USERDATA`.
//!
//! `NFTA_RULE_USERDATA` is the kernel's opaque-bytes attribute on
//! rules — preserved verbatim across reads / writes, max 256
//! bytes. By convention (set by libnftnl + adopted by Google's
//! `nftables` Go library + the `nft` CLI) the payload is a TLV
//! sequence where each entry is `[type: u8][length: u8][data: N
//! bytes]`. Type `NFTNL_UDATA_RULE_COMMENT = 0` is the standard
//! human-readable comment that `nft list ruleset` renders as
//! inline `comment "..."`.
//!
//! nlink uses this for **per-rule reconciliation identity** —
//! the [`DeclaredRule::handle_key`] is encoded as
//! `"nlink:<key>"`, so the kernel round-trips it across dumps
//! and the diff layer can match declared rules to kernel rules
//! by key (Plan 157b v2 — analogous to `LinkConfig::name` /
//! `RouteConfig::destination` in the existing `NetworkConfig`).
//!
//! Foreign comments — anything that doesn't start with
//! `"nlink:"` — are preserved as opaque bytes
//! ([`RuleInfo::userdata_raw`]) so re-applying a config doesn't
//! strip comments set by other tools.
//!
//! [`DeclaredRule::handle_key`]:
//!     crate::netlink::nftables::config::DeclaredRule
//! [`RuleInfo::userdata_raw`]: super::types::RuleInfo

/// `NFTNL_UDATA_RULE_COMMENT = 0` — the libnftnl-defined TLV
/// type for user-visible rule comments.
pub(crate) const NFTNL_UDATA_RULE_COMMENT: u8 = 0;

/// `NFTNL_UDATA_COMMENT_MAXLEN = 128` — libnftnl-enforced max
/// length for the comment string (including trailing NUL).
pub(crate) const NFTNL_UDATA_COMMENT_MAXLEN: usize = 128;

/// Prefix attached to the user-supplied `handle_key` so the diff
/// layer can distinguish rules nlink created from rules added
/// externally (`iptables-nft`, hand-edited via `nft -f`, etc.).
const NLINK_PREFIX: &str = "nlink:";

/// The TLV type nlink keeps a rule's key in (#527), apart from its comment.
/// libnftnl defines 0 (comment) and 1 (eBPF) for rules, and `nft` skips
/// the types it does not know, so the key stays out of `nft list`.
pub(crate) const NLINK_UDATA_RULE_KEY: u8 = 0xF0;


/// Encode a rule's key and comment as a libnftnl-compatible TLV `userdata`
/// payload, suitable for `NFTA_RULE_USERDATA`. `Ok(None)` when the rule has
/// neither.
///
/// A comment longer than `NFTNL_UDATA_COMMENT_MAXLEN` (127 bytes and the
/// NUL) is an error. It used to be dropped silently, installing a keyed
/// rule with no identity — which the declarative diff then re-added on
/// every apply.
pub(crate) fn encode_rule_userdata(
    key: Option<&str>,
    comment: Option<&str>,
) -> crate::netlink::error::Result<Option<Vec<u8>>> {
    // The comment as `nft list` shows it, then the key in its own TLV
    // (#527): the comment used to be `nlink:<key> <comment>`, and the two
    // shared its 127 bytes.
    let mut out = Vec::new();
    if let Some(comment) = comment {
        out.extend(rule_tlv(NFTNL_UDATA_RULE_COMMENT, "rule comment", comment)?);
    }
    if let Some(key) = key {
        out.extend(rule_tlv(NLINK_UDATA_RULE_KEY, "rule key", key)?);
    }
    Ok((!out.is_empty()).then_some(out))
}

/// One NUL-terminated rule TLV, refused past libnftnl's 127 bytes.
fn rule_tlv(kind: u8, what: &str, text: &str) -> crate::netlink::error::Result<Vec<u8>> {
    if text.contains('\0') {
        return Err(crate::netlink::error::Error::invalid_message(format!(
            "{what} contains a NUL byte"
        )));
    }
    let len = text.len() + 1;
    if len > NFTNL_UDATA_COMMENT_MAXLEN {
        return Err(crate::netlink::error::Error::invalid_message(format!(
            "{what} `{text}` is {} bytes; the kernel keeps at most {}",
            text.len(),
            NFTNL_UDATA_COMMENT_MAXLEN - 1,
        )));
    }
    let mut tlv = vec![kind, len as u8];
    tlv.extend_from_slice(text.as_bytes());
    tlv.push(0);
    Ok(tlv)
}

/// Encode a bare key, as `nlink:<key>`. Test convenience.
#[cfg(test)]
pub(crate) fn encode_nlink_comment(key: &str) -> Option<Vec<u8>> {
    encode_rule_userdata(Some(key), None).ok().flatten()
}

/// Walk a libnftnl-formatted TLV `userdata` payload and extract
/// an `nlink:`-prefixed comment, if any.
///
/// Returns `None` when:
/// - The payload is empty or malformed (truncated TLV).
/// - No `NFTNL_UDATA_RULE_COMMENT` entry is present.
/// - The comment exists but doesn't carry the `nlink:` prefix
///   (i.e., it's a foreign comment — preserved in
///   [`RuleInfo::userdata_raw`] but not managed by our diff).
///
/// The TLV walk is lenient: unknown TLV types are skipped (forward-
/// compat with future libnftnl additions like
/// `NFTNL_UDATA_RULE_EBPF`).
///
/// [`RuleInfo::userdata_raw`]: super::types::RuleInfo
pub(crate) fn parse_nlink_comment(userdata: &[u8]) -> Option<String> {
    if let Some(key) = comment_of(userdata, NLINK_UDATA_RULE_KEY) {
        return Some(key);
    }
    // A rule written before #527: `nlink:<key>[ <comment>]` in the comment.
    let text = parse_comment(userdata)?;
    let rest = text.strip_prefix(NLINK_PREFIX)?;
    // The key runs to the first space; what follows is a human comment.
    Some(rest.split_once(' ').map_or(rest, |(key, _)| key).to_string())
}

/// A rule's comment without nlink's key: the comment TLV as it is when the
/// key has its own TLV, else what follows `nlink:<key> ` in a comment
/// written before #527, else the whole comment of a rule nlink did not
/// write.
pub(crate) fn human_comment_of(userdata: &[u8]) -> Option<String> {
    let text = parse_comment(userdata)?;
    if comment_of(userdata, NLINK_UDATA_RULE_KEY).is_some() {
        return Some(text);
    }
    match text.strip_prefix(NLINK_PREFIX) {
        Some(rest) => rest.split_once(' ').map(|(_, human)| human.to_string()),
        None => Some(text),
    }
}

/// The rule comment exactly as `nft list ruleset` shows it — the
/// `NFTNL_UDATA_RULE_COMMENT` string with its NUL removed — whoever set
/// it. `None` when there is no comment or the TLVs are malformed.
pub(crate) fn parse_comment(userdata: &[u8]) -> Option<String> {
    let mut cursor = userdata;
    while cursor.len() >= 2 {
        let ty = cursor[0];
        let len = cursor[1] as usize;
        if cursor.len() < 2 + len {
            // Truncated TLV; bail. Foreign tools shouldn't ship
            // these but defensive code costs nothing.
            return None;
        }
        let payload = &cursor[2..2 + len];
        if ty == NFTNL_UDATA_RULE_COMMENT {
            let s = std::str::from_utf8(payload)
                .ok()?
                .trim_end_matches('\0');
            return Some(s.to_string());
        }
        cursor = &cursor[2 + len..];
    }
    None
}

/// The TLV type of nlink's ownership tag on a chain, set or object (#527):
/// present on what the declarative apply created, so a
/// [`TableMode::Shared`](super::config::TableMode::Shared) table's diff
/// deletes only what nlink made. nft skips the types it does not know.
pub(crate) const NLINK_UDATA_OWNED: u8 = 0xF0;

/// The userdata of a chain, set or object: its comment TLV of type
/// `comment_kind`, then nlink's ownership tag if `owned`.
pub(crate) fn encode_object_userdata(
    comment_kind: u8,
    comment: Option<&str>,
    owned: bool,
) -> crate::netlink::error::Result<Option<Vec<u8>>> {
    let mut out = match comment {
        Some(comment) => encode_comment(comment_kind, comment)?,
        None => Vec::new(),
    };
    if owned {
        out.extend_from_slice(&[NLINK_UDATA_OWNED, 6]);
        out.extend_from_slice(b"nlink\0");
    }
    Ok((!out.is_empty()).then_some(out))
}

/// Whether userdata carries nlink's ownership tag.
pub(crate) fn is_owned(userdata: &[u8]) -> bool {
    comment_of(userdata, NLINK_UDATA_OWNED).is_some()
}

/// libnftnl's comment TLV type on a table, chain, object or set element
/// (`NFTNL_UDATA_{TABLE,CHAIN,OBJ,SET_ELEM}_COMMENT`).
pub(crate) const NFTNL_UDATA_COMMENT: u8 = 0;
/// `NFTNL_UDATA_SET_COMMENT`: a set's comment comes after six other set
/// TLV types (key/data byte order, merge, typeof ×2, expr, interval).
pub(crate) const NFTNL_UDATA_SET_COMMENT: u8 = 7;

/// A comment as the libnftnl TLV of type `kind` — `[kind][len][text\0]` —
/// that `nft list` shows as `comment "..."` (#528). An error for one with
/// a NUL in it or longer than 127 bytes, which libnftnl would refuse.
pub(crate) fn encode_comment(kind: u8, comment: &str) -> crate::netlink::error::Result<Vec<u8>> {
    if comment.as_bytes().contains(&0) {
        return Err(crate::netlink::error::Error::invalid_message(format!(
            "nftables comment {comment:?} has a NUL in it"
        )));
    }
    let len = comment.len() + 1;
    if len > NFTNL_UDATA_COMMENT_MAXLEN {
        return Err(crate::netlink::error::Error::invalid_message(format!(
            "nftables comment is {} bytes; at most {} fit",
            comment.len(),
            NFTNL_UDATA_COMMENT_MAXLEN - 1
        )));
    }
    let mut out = vec![kind, len as u8];
    out.extend_from_slice(comment.as_bytes());
    out.push(0);
    Ok(out)
}

/// The comment TLV of type `kind` in `userdata`, its NUL removed.
pub(crate) fn comment_of(userdata: &[u8], kind: u8) -> Option<String> {
    let mut cursor = userdata;
    while cursor.len() >= 2 {
        let (ty, len) = (cursor[0], cursor[1] as usize);
        let payload = cursor.get(2..2 + len)?;
        if ty == kind {
            return std::str::from_utf8(payload)
                .ok()
                .map(|s| s.trim_end_matches('\0').to_string());
        }
        cursor = &cursor[2 + len..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_comments_round_trip_and_refuse_what_libnftnl_would() {
        let tlv = encode_comment(NFTNL_UDATA_SET_COMMENT, "blocked hosts").unwrap();
        assert_eq!(&tlv[..2], [7, 14]);
        assert_eq!(comment_of(&tlv, NFTNL_UDATA_SET_COMMENT).as_deref(), Some("blocked hosts"));
        assert_eq!(comment_of(&tlv, NFTNL_UDATA_COMMENT), None, "another type");
        // Behind another TLV, as a set's key byte order would be.
        let mut both = vec![0, 4, 1, 0, 0, 0];
        both.extend(&tlv);
        assert_eq!(comment_of(&both, NFTNL_UDATA_SET_COMMENT).as_deref(), Some("blocked hosts"));
        assert!(encode_comment(0, &"x".repeat(127)).is_ok());
        assert!(encode_comment(0, &"x".repeat(128)).is_err());
        assert!(encode_comment(0, "a\0b").is_err());
    }

    #[test]
    fn encode_then_parse_round_trips() {
        let key = "input/ssh-accept";
        let encoded = encode_nlink_comment(key).expect("encode");
        // The key alone: its own TLV, no comment for nft to show.
        assert_eq!(encoded[0], NLINK_UDATA_RULE_KEY);
        assert_eq!(encoded[1] as usize, key.len() + 1);
        assert_eq!(parse_nlink_comment(&encoded).as_deref(), Some(key));
        assert_eq!(parse_comment(&encoded), None);
        assert_eq!(human_comment_of(&encoded), None);
    }

    /// #527: the key and the comment each have libnftnl's 127 bytes.
    #[test]
    fn the_key_and_the_comment_each_have_127_bytes() {
        let key = "k".repeat(127);
        let comment = "c".repeat(127);
        let encoded = encode_rule_userdata(Some(&key), Some(&comment)).unwrap().unwrap();
        assert_eq!(parse_nlink_comment(&encoded).as_deref(), Some(key.as_str()));
        assert_eq!(parse_comment(&encoded).as_deref(), Some(comment.as_str()));
        assert_eq!(human_comment_of(&encoded).as_deref(), Some(comment.as_str()));
        assert!(encode_rule_userdata(Some(&"k".repeat(128)), None).is_err());
        assert!(encode_rule_userdata(None, Some(&"c".repeat(128))).is_err());
    }

    /// A rule written before #527 still has its key, and its comment.
    #[test]
    fn a_key_in_the_comment_still_reads() {
        let body = b"nlink:ssh allow admins\0";
        let mut tlv = vec![NFTNL_UDATA_RULE_COMMENT, body.len() as u8];
        tlv.extend_from_slice(body);
        assert_eq!(parse_nlink_comment(&tlv).as_deref(), Some("ssh"));
        assert_eq!(human_comment_of(&tlv).as_deref(), Some("allow admins"));
        let bare = b"nlink:ssh\0";
        let mut tlv = vec![NFTNL_UDATA_RULE_COMMENT, bare.len() as u8];
        tlv.extend_from_slice(bare);
        assert_eq!(human_comment_of(&tlv), None);
    }

    /// With the key in its own TLV, a comment that starts `nlink:` is the
    /// user's, whole.
    #[test]
    fn a_comment_beside_a_key_is_taken_whole() {
        let encoded = encode_rule_userdata(Some("k"), Some("nlink:looks like a key")).unwrap().unwrap();
        assert_eq!(parse_nlink_comment(&encoded).as_deref(), Some("k"));
        assert_eq!(human_comment_of(&encoded).as_deref(), Some("nlink:looks like a key"));
    }

    #[test]
    fn parse_ignores_foreign_comment_prefix() {
        // Comment without our prefix — foreign tool's tag.
        let body = b"cilium:abc123\0";
        let mut tlv = vec![NFTNL_UDATA_RULE_COMMENT, body.len() as u8];
        tlv.extend_from_slice(body);
        assert_eq!(parse_nlink_comment(&tlv), None);
    }

    #[test]
    fn parse_skips_unknown_tlv_types() {
        // Unknown TLV first, then our comment — should still find
        // the comment by walking past the unknown entry.
        let mut tlv = Vec::new();
        // Unknown type 99, 4 bytes of junk.
        tlv.extend_from_slice(&[99, 4, 0xde, 0xad, 0xbe, 0xef]);
        // Our comment.
        let body = b"nlink:my-key\0";
        tlv.extend_from_slice(&[NFTNL_UDATA_RULE_COMMENT, body.len() as u8]);
        tlv.extend_from_slice(body);

        assert_eq!(parse_nlink_comment(&tlv), Some("my-key".to_string()));
    }

    #[test]
    fn parse_handles_empty_userdata() {
        assert_eq!(parse_nlink_comment(&[]), None);
    }

    #[test]
    fn parse_handles_truncated_tlv() {
        // type=0, length=10 but only 2 bytes follow → truncated.
        let tlv = [NFTNL_UDATA_RULE_COMMENT, 10, 0x6e, 0x6c];
        assert_eq!(parse_nlink_comment(&tlv), None);
    }

    #[test]
    fn parse_handles_invalid_utf8() {
        // Type-0 TLV with non-UTF-8 bytes.
        let tlv = [NFTNL_UDATA_RULE_COMMENT, 2, 0xff, 0xfe];
        assert_eq!(parse_nlink_comment(&tlv), None);
    }
}

#[cfg(test)]
mod comment_tests {
    use super::*;

    fn tlv(comment: &str) -> Vec<u8> {
        let body = format!("{comment}\0");
        let mut tlv = vec![NFTNL_UDATA_RULE_COMMENT, body.len() as u8];
        tlv.extend_from_slice(body.as_bytes());
        tlv
    }

    #[test]
    fn a_foreign_comment_has_text_but_no_key() {
        let foreign = tlv("allow ssh from the office");
        assert_eq!(parse_nlink_comment(&foreign), None);
        assert_eq!(
            parse_comment(&foreign).as_deref(),
            Some("allow ssh from the office")
        );
    }

    #[test]
    fn an_nlink_rule_has_its_key_and_its_comment_apart() {
        let ours = encode_rule_userdata(Some("k"), Some("hello")).unwrap().unwrap();
        assert_eq!(parse_nlink_comment(&ours).as_deref(), Some("k"));
        assert_eq!(parse_comment(&ours).as_deref(), Some("hello"));
    }
}
