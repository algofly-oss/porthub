//! What a refused nftables batch says about each operation it refused.
//!
//! `nfnetlink` does not stop at the first failing message of a batch: it
//! processes every one, reports each failure with that message's sequence
//! number, and then rolls the whole batch back. The error's
//! `NLMSGERR_ATTR_OFFS` is an offset into the failing message, whose bytes
//! nlink still holds — so it can say which operation failed and which of
//! its attributes the kernel blamed, instead of "errno 16 at offset 36"
//! (#481).

use super::{
    NFT_MSG_DELCHAIN, NFT_MSG_DELFLOWTABLE, NFT_MSG_DELOBJ, NFT_MSG_DELRULE, NFT_MSG_DELSET,
    NFT_MSG_DELSETELEM, NFT_MSG_DELTABLE, NFT_MSG_NEWCHAIN, NFT_MSG_NEWFLOWTABLE, NFT_MSG_NEWOBJ,
    NFT_MSG_NEWRULE, NFT_MSG_NEWSET, NFT_MSG_NEWSETELEM, NFT_MSG_NEWTABLE, NFTA_EXPR_NAME,
    NFTA_LIST_ELEM, NFTA_RULE_EXPRESSIONS, NFTA_RULE_USERDATA,
};
use crate::netlink::attr::{AttrIter, get};
use crate::netlink::error::{ErrorObject, strerror};
use crate::netlink::message::{NLM_F_CREATE, NLM_F_EXCL, NLM_F_REPLACE, ParsedExtAck};

/// `nlmsghdr` (16) + `nfgenmsg` (4): where an nftables message's
/// attributes start.
const ATTRS_START: usize = 20;

/// One operation of an nftables batch that the kernel refused.
///
/// Carried by [`ErrorDetail::NftBatch`](crate::ErrorDetail::NftBatch), one per refused
/// operation, in batch order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NftBatchFailure {
    /// The operation's position in the transaction, from 0. `None` for a
    /// failure of the batch as a whole: a failed commit (`operation` is
    /// `commit`), or the kernel refusing the batch before reading an
    /// operation (`batch begin`).
    pub index: Option<usize>,
    /// What the operation was: `add rule ip t/input [ssh]`,
    /// `delete set inet fw/blocked`.
    pub operation: String,
    /// The errno, positive.
    pub errno: i32,
    /// What the kernel's extended ack said, if anything.
    pub ext_ack: Option<String>,
    /// `NLMSGERR_ATTR_OFFS`: the offset, within the failing message, of
    /// the attribute the kernel blamed.
    pub offset: Option<u32>,
    /// That attribute, resolved against the message nlink sent:
    /// `expression #4 (log)`, `attribute 3`.
    pub attribute: Option<String>,
    /// What the operation was done to, read from the message (#718):
    /// the table, chain, rule, set, object or flowtable. `None` for a
    /// failure of the batch as a whole. An
    /// [`Error`](crate::Error)'s [`object`](crate::Error::object) is the
    /// first refused operation's.
    pub object: Option<ErrorObject>,
}

impl std::fmt::Display for NftBatchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.index {
            Some(i) => write!(f, "op #{i} {}: ", self.operation)?,
            None => write!(f, "{}: ", self.operation)?,
        }
        write!(f, "{} (errno {})", strerror(self.errno), self.errno)?;
        if let Some(msg) = &self.ext_ack {
            write!(f, ": {msg}")?;
        }
        match (&self.attribute, self.offset) {
            (Some(attr), _) => write!(f, " (at {attr})")?,
            (None, Some(off)) => write!(f, " (at message offset {off})")?,
            (None, None) => {}
        }
        if let Some(hint) = self.hint() {
            write!(f, " — {hint}")?;
        }
        Ok(())
    }
}

impl NftBatchFailure {
    /// A failure of the operation at `index`, whose wire bytes are
    /// `message`.
    pub(crate) fn of_message(index: usize, message: &[u8], errno: i32, ext: ParsedExtAck) -> Self {
        let attribute = ext
            .offset
            .and_then(|off| resolve_offset(message, off as usize));
        Self {
            index: Some(index),
            operation: describe_operation(message),
            errno: errno.abs(),
            ext_ack: ext.describe(),
            offset: ext.offset,
            attribute,
            object: object_of(message),
        }
    }

    /// This failure, read again as a failed commit's. The kernel reports
    /// one at the first operation's seq, so it first reads as that
    /// operation's refusal (#868).
    pub(crate) fn read_as_commit(&mut self) {
        self.index = None;
        self.operation = "commit".to_string();
        self.attribute = None;
        self.object = None;
    }

    /// A failure of the batch as a whole: the begin or end marker, or the
    /// commit.
    pub(crate) fn of_batch(what: &str, errno: i32, ext: ParsedExtAck) -> Self {
        Self {
            index: None,
            operation: what.to_string(),
            errno: errno.abs(),
            ext_ack: ext.describe(),
            offset: ext.offset,
            attribute: None,
            object: None,
        }
    }

    /// The likely cause of a failure nlink can recognise.
    fn hint(&self) -> Option<&'static str> {
        let on_expression = self
            .attribute
            .as_deref()
            .is_some_and(|a| a.starts_with("expression"));
        match self.errno {
            libc::ENOENT if on_expression => Some(
                "the kernel does not know this expression: is its module (nft_*, or \
                 nf_log_syslog for `log`) available?",
            ),
            libc::EBUSY if self.operation.starts_with("delete") => {
                Some("something still uses it (a rule, a map element, a jump)")
            }
            libc::EINVAL if self.operation == "commit" => Some(
                "every operation was accepted, the ruleset as a whole was not: an \
                 anonymous set or chain no rule uses, for one",
            ),
            _ => None,
        }
    }
}

/// What one batch message is done to (#718).
fn object_of(message: &[u8]) -> Option<ErrorObject> {
    let header = message.get(..ATTRS_START)?;
    let msg_type = u16::from_ne_bytes([header[4], header[5]]);
    let family = family_name(header[16]).to_string();
    let attrs = message.get(ATTRS_START..).unwrap_or(&[]);
    let string = |ty: u16| {
        AttrIter::new(attrs)
            .find(|(t, _)| t & 0x7FFF == ty)
            .and_then(|(_, p)| get::string(p).ok().map(str::to_string))
            .unwrap_or_default()
    };
    // Every message names its table first (`NFTA_*_TABLE` is 1), then
    // what it is about: a chain's name is 3, a set's, object's and
    // flowtable's 2, and a rule's chain 2.
    let table = string(1);
    let in_table = |name_attr: u16| (family.clone(), table.clone(), string(name_attr));
    Some(match (msg_type & 0xFF) as u8 {
        NFT_MSG_NEWTABLE | NFT_MSG_DELTABLE => ErrorObject::NftTable {
            family: family.clone(),
            name: table.clone(),
        },
        NFT_MSG_NEWCHAIN | NFT_MSG_DELCHAIN => {
            let (family, table, name) = in_table(3);
            ErrorObject::NftChain { family, table, name }
        }
        NFT_MSG_NEWRULE | NFT_MSG_DELRULE => ErrorObject::NftRule {
            family: family.clone(),
            table: table.clone(),
            chain: string(2),
            key: AttrIter::new(attrs)
                .find(|(t, _)| t & 0x7FFF == NFTA_RULE_USERDATA)
                .and_then(|(_, p)| super::userdata::parse_nlink_comment(p)),
        },
        NFT_MSG_NEWSET | NFT_MSG_DELSET | NFT_MSG_NEWSETELEM | NFT_MSG_DELSETELEM => {
            let (family, table, name) = in_table(2);
            ErrorObject::NftSet { family, table, name }
        }
        NFT_MSG_NEWOBJ | NFT_MSG_DELOBJ => {
            let (family, table, name) = in_table(2);
            ErrorObject::NftObject { family, table, name }
        }
        NFT_MSG_NEWFLOWTABLE | NFT_MSG_DELFLOWTABLE => {
            let (family, table, name) = in_table(2);
            ErrorObject::NftFlowtable { family, table, name }
        }
        _ => return None,
    })
}

/// The name of an `nfgenmsg` family, as nft spells it.
fn family_name(family: u8) -> &'static str {
    match family {
        1 => "inet",
        2 => "ip",
        3 => "arp",
        5 => "netdev",
        7 => "bridge",
        10 => "ip6",
        _ => "unspec",
    }
}

/// Render one batch message as the operation it asks for.
fn describe_operation(message: &[u8]) -> String {
    let Some(header) = message.get(..ATTRS_START) else {
        return "malformed message".to_string();
    };
    let msg_type = u16::from_ne_bytes([header[4], header[5]]);
    let flags = u16::from_ne_bytes([header[6], header[7]]);
    let family = family_name(header[16]);
    let attrs = message.get(ATTRS_START..).unwrap_or(&[]);
    let string = |ty: u16| {
        AttrIter::new(attrs)
            .find(|(t, _)| t & 0x7FFF == ty)
            .and_then(|(_, p)| get::string(p).ok().map(str::to_string))
    };
    let table = string(1).unwrap_or_default();
    let named = |what: &str, verb: &str, name_attr: u16| {
        let name = string(name_attr).unwrap_or_default();
        format!("{verb} {what} {family} {table}/{name}")
    };
    // A NEW* without NLM_F_EXCL updates what exists (a chain's policy, a
    // table's flags); with it, it only creates.
    let verb = |new: &str| {
        if flags & NLM_F_CREATE != 0 && flags & NLM_F_EXCL == 0 {
            "add or update".to_string()
        } else {
            new.to_string()
        }
    };
    match (msg_type & 0xFF) as u8 {
        NFT_MSG_NEWTABLE => format!("{} table {family} {table}", verb("add")),
        NFT_MSG_DELTABLE => format!("delete table {family} {table}"),
        NFT_MSG_NEWCHAIN => named("chain", &verb("add"), 3),
        NFT_MSG_DELCHAIN => named("chain", "delete", 3),
        NFT_MSG_NEWRULE | NFT_MSG_DELRULE => {
            let verb = if msg_type & 0xFF == u16::from(NFT_MSG_DELRULE) {
                "delete"
            } else if flags & NLM_F_REPLACE != 0 {
                "replace"
            } else {
                "add"
            };
            let chain = string(2).unwrap_or_default();
            let key = AttrIter::new(attrs)
                .find(|(t, _)| t & 0x7FFF == NFTA_RULE_USERDATA)
                .and_then(|(_, p)| super::userdata::parse_nlink_comment(p));
            match key {
                Some(key) => format!("{verb} rule {family} {table}/{chain} [{key}]"),
                None => format!("{verb} rule {family} {table}/{chain}"),
            }
        }
        NFT_MSG_NEWSET => named("set", &verb("add"), 2),
        NFT_MSG_DELSET => named("set", "delete", 2),
        NFT_MSG_NEWSETELEM => named("set elements in", "add", 2),
        NFT_MSG_DELSETELEM => named("set elements in", "delete", 2),
        NFT_MSG_NEWOBJ => named("object", &verb("add"), 2),
        NFT_MSG_DELOBJ => named("object", "delete", 2),
        NFT_MSG_NEWFLOWTABLE => named("flowtable", &verb("add"), 2),
        NFT_MSG_DELFLOWTABLE => named("flowtable", "delete", 2),
        other => format!("message type {other} {family} {table}"),
    }
}

/// The attribute at `offset` in `message`: the expression it falls in for
/// a rule's expression list, else the top-level attribute's type.
fn resolve_offset(message: &[u8], offset: usize) -> Option<String> {
    let mut pos = ATTRS_START;
    for (ty, payload) in AttrIter::new(message.get(ATTRS_START..)?) {
        let len = 4 + payload.len();
        let (start, end) = (pos, pos + len);
        pos += (len + 3) & !3;
        if !(start..end).contains(&offset) {
            continue;
        }
        let ty = ty & 0x7FFF;
        let is_rule = message
            .get(4..6)
            .is_some_and(|t| u16::from_ne_bytes([t[0], t[1]]) & 0xFF == u16::from(NFT_MSG_NEWRULE));
        if is_rule && ty == NFTA_RULE_EXPRESSIONS {
            return Some(resolve_expression(payload, start + 4, offset));
        }
        return Some(format!("attribute {ty}"));
    }
    None
}

/// Which element of a rule's expression list `offset` falls in, and the
/// expression's name.
fn resolve_expression(list: &[u8], list_start: usize, offset: usize) -> String {
    let mut pos = list_start;
    for (i, (ty, elem)) in AttrIter::new(list).enumerate() {
        let len = 4 + elem.len();
        let (start, end) = (pos, pos + len);
        pos += (len + 3) & !3;
        if ty & 0x7FFF != NFTA_LIST_ELEM || !(start..end).contains(&offset) {
            continue;
        }
        let name = AttrIter::new(elem)
            .find(|(t, _)| t & 0x7FFF == NFTA_EXPR_NAME)
            .and_then(|(_, p)| get::string(p).ok().map(str::to_string));
        return match name {
            Some(name) => format!("expression #{} ({name})", i + 1),
            None => format!("expression #{}", i + 1),
        };
    }
    "the expression list".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::nftables::Rule;
    use crate::netlink::nftables::connection::Transaction;

    /// A one-rule transaction's message bytes.
    fn rule_message(rule: Rule) -> Vec<u8> {
        let tx = Transaction::new_for_test().add_rule(rule);
        tx.messages_for_test().remove(0)
    }

    /// Where element `n` (1-based) of the rule's expression list starts.
    fn expression_offset(message: &[u8], n: usize) -> usize {
        let mut pos = ATTRS_START;
        for (ty, payload) in AttrIter::new(&message[ATTRS_START..]) {
            if ty & 0x7FFF == NFTA_RULE_EXPRESSIONS {
                let mut inner = pos + 4;
                for (i, (_, elem)) in AttrIter::new(payload).enumerate() {
                    if i + 1 == n {
                        return inner;
                    }
                    inner += (4 + elem.len() + 3) & !3;
                }
            }
            pos += (4 + payload.len() + 3) & !3;
        }
        panic!("no expression #{n}");
    }

    /// #718: each message names what it is done to.
    #[test]
    fn a_message_names_its_object() {
        use crate::netlink::nftables::{Chain, Family, Set, SetKeyType};
        let mut rule = Rule::new("fw", "input").match_tcp_dport(22).accept();
        rule.key = Some("ssh".into());
        assert_eq!(
            object_of(&rule_message(rule)),
            Some(ErrorObject::NftRule {
                family: "inet".into(),
                table: "fw".into(),
                chain: "input".into(),
                key: Some("ssh".into()),
            })
        );
        let tx = Transaction::new_for_test()
            .add_table("fw", Family::Ip6)
            .add_chain(Chain::new("fw", "fwd").unwrap().family(Family::Ip6))
            .add_set(Set::new("fw", "blocked").family(Family::Ip6).key_type(SetKeyType::Ipv6Addr));
        let objects: Vec<_> = tx.messages_for_test().iter().map(|m| object_of(m)).collect();
        let in_fw = |name: &str| ("ip6".to_string(), "fw".to_string(), name.to_string());
        let (family, table, name) = in_fw("fwd");
        let chain = ErrorObject::NftChain { family, table, name };
        let (family, table, name) = in_fw("blocked");
        let set = ErrorObject::NftSet { family, table, name };
        assert_eq!(
            objects,
            [
                Some(ErrorObject::NftTable {
                    family: "ip6".into(),
                    name: "fw".into()
                }),
                Some(chain),
                Some(set),
            ]
        );
        assert_eq!(set_display(), "nftables set ip6 fw/blocked");
    }

    fn set_display() -> String {
        ErrorObject::NftSet {
            family: "ip6".into(),
            table: "fw".into(),
            name: "blocked".into(),
        }
        .to_string()
    }

    #[test]
    fn a_rule_is_described_by_table_chain_and_key() {
        let mut rule = Rule::new("fw", "input").match_tcp_dport(22).accept();
        rule.key = Some("ssh".into());
        let msg = rule_message(rule);
        assert_eq!(describe_operation(&msg), "add rule inet fw/input [ssh]");
    }

    #[test]
    fn an_offset_inside_an_expression_names_it() {
        let rule = Rule::new("fw", "input")
            .match_tcp_dport(22)
            .counter()
            .log(None);
        let msg = rule_message(rule);
        let exprs: Vec<String> = AttrIter::new(&msg[ATTRS_START..])
            .filter(|(t, _)| t & 0x7FFF == NFTA_RULE_EXPRESSIONS)
            .flat_map(|(_, p)| {
                AttrIter::new(p)
                    .map(|(_, e)| e.to_vec())
                    .collect::<Vec<_>>()
            })
            .map(|e| {
                AttrIter::new(&e)
                    .find(|(t, _)| t & 0x7FFF == NFTA_EXPR_NAME)
                    .and_then(|(_, p)| get::string(p).ok().map(str::to_string))
                    .unwrap()
            })
            .collect();
        let log = exprs
            .iter()
            .position(|e| e == "log")
            .expect("a log expression")
            + 1;
        let off = expression_offset(&msg, log);
        assert_eq!(
            resolve_offset(&msg, off).as_deref(),
            Some(format!("expression #{log} (log)").as_str())
        );
    }

    #[test]
    fn a_failure_reads_as_operation_errno_message_and_attribute() {
        let rule = Rule::new("fw", "input").log(None);
        let msg = rule_message(rule);
        let ext = ParsedExtAck {
            offset: Some(expression_offset(&msg, 1) as u32),
            ..Default::default()
        };
        let failure = NftBatchFailure::of_message(3, &msg, -libc::ENOENT, ext);
        let shown = failure.to_string();
        assert!(
            shown.starts_with(
                "op #3 add rule inet fw/input: No such file or directory (errno 2) \
                 (at expression #1 (log)) — the kernel does not know this expression"
            ),
            "{shown}"
        );
    }

    #[test]
    fn strerror_drops_the_os_error_suffix() {
        assert_eq!(strerror(libc::EBUSY), "Device or resource busy");
        let e = crate::Error::from_errno(libc::EBUSY).to_string();
        assert_eq!(e, "kernel error: Device or resource busy (errno 16)");
    }
}
