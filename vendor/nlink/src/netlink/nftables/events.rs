//! Nftables multicast event types + parser.
//!
//! The kernel emits `NFT_MSG_NEW*` / `NFT_MSG_DEL*` notifications
//! on `NFNLGRP_NFTABLES` (group 7) whenever a table, chain, rule, set,
//! set element, object or flowtable is created or destroyed — by **any**
//! writer in the namespace, not just the current process — and an
//! `NFT_MSG_NEWGEN` closing each committed batch. Subscribers see the full
//! ruleset mutation history in real time. Use cases include
//! reconcile-on-drift in declarative managers (Plan 157), audit
//! pipelines, and live introspection in `nft monitor`-style tools.
//!
//! Subscribe via [`Connection::<Nftables>::subscribe`] + consume the
//! [`Stream`](tokio_stream::Stream) returned by
//! [`Connection::events`](crate::netlink::Connection::events).
//!
//! See the parent module's `add_table` / `add_chain` etc. for the
//! mutating side that produces these events.
//!
//! [`Connection::<Nftables>::subscribe`]: crate::netlink::Connection

use super::connection::{
    parse_chain, parse_flowtable, parse_rule, parse_set, parse_set_elements, parse_table,
};
use super::types::{ChainInfo, Family, Flowtable, RuleInfo, SetElement, SetInfo, Table};
use super::{
    NFGENMSG_HDRLEN, NFNL_SUBSYS_NFTABLES, NFT_MSG_DELCHAIN, NFT_MSG_DELFLOWTABLE,
    NFT_MSG_DELRULE, NFT_MSG_DELSET, NFT_MSG_DELSETELEM, NFT_MSG_DELTABLE, NFT_MSG_NEWCHAIN,
    NFT_MSG_NEWFLOWTABLE, NFT_MSG_NEWGEN, NFT_MSG_NEWRULE, NFT_MSG_NEWSET, NFT_MSG_NEWSETELEM,
    NFT_MSG_NEWTABLE, NFT_MSG_NEWOBJ, NFT_MSG_DELOBJ, NFTA_GEN_ID, NFTA_GEN_PROC_NAME, NFTA_GEN_PROC_PID,
    NFTA_SET_ELEM_LIST_SET, NFTA_SET_ELEM_LIST_TABLE,
};
use crate::netlink::attr::{AttrIter, get};

/// `NFNLGRP_NFTABLES` (7) — the single multicast group on which
/// the kernel announces ruleset mutations and new generations.
///
/// All nftables events flow through this one group; the per-event
/// "kind" (new vs del, table vs chain vs rule vs set vs element vs
/// object vs flowtable, or a generation) is encoded in the `nlmsg_type`
/// byte. Compare with conntrack which
/// uses one group per event kind.
pub const NFNLGRP_NFTABLES: u32 = 7;

/// Multicast group to subscribe to via
/// [`Connection::<Nftables>::subscribe`][subscribe].
///
/// At present nftables only ships a single multicast group
/// (`NFNLGRP_NFTABLES = 7`); this enum exists for forward symmetry
/// with [`ConntrackGroup`](crate::netlink::netfilter::ConntrackGroup)
/// and to leave room for the kernel adding finer-grained groups
/// later.
///
/// [subscribe]: crate::netlink::Connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NftablesGroup {
    /// `NFNLGRP_NFTABLES` — every ruleset mutation, and the
    /// `NFT_MSG_NEWGEN` that closes each committed batch. A drift view
    /// that wants only the ruleset filters [`NftablesEvent::NewGen`] out.
    All,
}

impl NftablesGroup {
    /// Map to the kernel multicast group ID.
    pub fn to_kernel_group(self) -> u32 {
        match self {
            Self::All => NFNLGRP_NFTABLES,
        }
    }
}

/// An event delivered on the nftables multicast stream.
///
/// One variant per ruleset-mutating wire message the kernel emits, plus
/// the generation announcement (`NFT_MSG_NEWGEN`) that closes each
/// committed batch. A message nlink cannot parse — or one in an address
/// family it does not know — is dropped with a `tracing` debug record.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum NftablesEvent {
    /// `NFT_MSG_NEWTABLE` — a table was created or updated. The
    /// kernel uses the same wire shape for both, so a stream
    /// subscribed to `All` sees both as `NewTable`.
    NewTable(Table),
    /// `NFT_MSG_DELTABLE` — a table was destroyed.
    DelTable(Table),
    /// `NFT_MSG_NEWCHAIN` — a chain was created or updated.
    NewChain(ChainInfo),
    /// `NFT_MSG_DELCHAIN` — a chain was destroyed.
    DelChain(ChainInfo),
    /// `NFT_MSG_NEWRULE` — a rule was added to a chain.
    NewRule(RuleInfo),
    /// `NFT_MSG_DELRULE` — a rule was removed from a chain.
    DelRule(RuleInfo),
    /// `NFT_MSG_NEWFLOWTABLE` — a flowtable was created or updated.
    NewFlowtable(Flowtable),
    /// `NFT_MSG_DELFLOWTABLE` — a flowtable was destroyed.
    DelFlowtable(Flowtable),
    /// `NFT_MSG_NEWSET` — a set was created or updated. Sets
    /// model named collections (anonymous-set elements, verdict
    /// maps, interval ranges) referenced by rule expressions.
    NewSet(SetInfo),
    /// `NFT_MSG_DELSET` — a set was destroyed.
    DelSet(SetInfo),
    /// `NFT_MSG_NEWSETELEM` — elements were added to a set.
    NewSetElements(SetElementsEvent),
    /// `NFT_MSG_DELSETELEM` — elements were removed from a set.
    DelSetElements(SetElementsEvent),
    /// `NFT_MSG_NEWGEN` — a batch was committed; the ruleset generation
    /// moved on.
    NewGen(GenInfo),
    /// `NFT_MSG_NEWOBJ` — a stateful object was created or updated.
    NewObject(super::object::ObjectInfo),
    /// `NFT_MSG_DELOBJ` — a stateful object was destroyed.
    DelObject(super::object::ObjectInfo),
}

impl NftablesEvent {
    /// The object this event is about, for
    /// [`with_gap_deltas`](crate::netlink::resync_ext::ResyncStreamExt::with_gap_deltas)
    /// (#523): a table, chain, set, flowtable or object by family, table
    /// and name, a rule by its handle. `None` for set elements and
    /// generations, which nothing here tracks.
    pub fn object_key(&self) -> Option<crate::netlink::resync_ext::ObjectKey> {
        use crate::netlink::resync_ext::ObjectKey;
        let key = match self {
            Self::NewTable(t) | Self::DelTable(t) => {
                ObjectKey::new("table", format!("{} {}", t.family, t.name))
            }
            Self::NewChain(c) | Self::DelChain(c) => {
                ObjectKey::new("chain", format!("{} {} {}", c.family, c.table, c.name))
            }
            Self::NewRule(r) | Self::DelRule(r) => ObjectKey::new(
                "rule",
                format!("{} {} {} {}", r.family, r.table, r.chain, r.handle),
            ),
            Self::NewSet(s) | Self::DelSet(s) => {
                ObjectKey::new("set", format!("{} {} {}", s.family, s.table, s.name))
            }
            Self::NewFlowtable(f) | Self::DelFlowtable(f) => {
                ObjectKey::new("flowtable", format!("{} {} {}", f.family, f.table, f.name))
            }
            Self::NewObject(o) | Self::DelObject(o) => ObjectKey::new(
                "object",
                format!("{} {} {} {:?}", o.family, o.table, o.name, o.object_type()),
            ),
            _ => return None,
        };
        Some(key)
    }
}

impl crate::netlink::resync_ext::GapDelta for NftablesEvent {
    fn is_removal(&self) -> bool {
        matches!(
            self,
            Self::DelTable(_)
                | Self::DelChain(_)
                | Self::DelRule(_)
                | Self::DelFlowtable(_)
                | Self::DelSet(_)
                | Self::DelSetElements(_)
                | Self::DelObject(_)
        )
    }

    fn removal(&self) -> Option<Self> {
        let removal = match self {
            Self::NewTable(t) => Self::DelTable(t.clone()),
            Self::NewChain(c) => Self::DelChain(c.clone()),
            Self::NewRule(r) => Self::DelRule(r.clone()),
            Self::NewFlowtable(f) => Self::DelFlowtable(f.clone()),
            Self::NewSet(s) => Self::DelSet(s.clone()),
            Self::NewSetElements(e) => Self::DelSetElements(e.clone()),
            Self::NewObject(o) => Self::DelObject(o.clone()),
            _ => return None,
        };
        Some(removal)
    }
}

/// Elements added to or removed from a set, as one notification carries
/// them. They are the raw wire elements: an event does not say what kind
/// of set it is, so an interval set's range shows as its start element and
/// its end marker ([`SetElement::is_interval_end`]). Elements a rule adds
/// from the packet path (`add @set`) are not notified by the kernel.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SetElementsEvent {
    /// Address family.
    pub family: Family,
    /// Owning table.
    pub table: String,
    /// Set name.
    pub set: String,
    /// The elements.
    pub elements: Vec<SetElement>,
}

/// A committed batch: the new ruleset generation, and who committed it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GenInfo {
    /// Generation ID, incremented by every commit.
    pub id: u32,
    /// PID of the committing process, if the kernel reports it.
    pub pid: Option<u32>,
    /// Name of the committing process, if the kernel reports it.
    pub proc_name: Option<String>,
}

fn parse_set_elements_event(attrs: &[u8], family: Family) -> Option<SetElementsEvent> {
    let mut table = None;
    let mut set = None;
    for (attr, payload) in AttrIter::new(attrs) {
        match attr {
            NFTA_SET_ELEM_LIST_TABLE => table = get::string(payload).ok().map(str::to_string),
            NFTA_SET_ELEM_LIST_SET => set = get::string(payload).ok().map(str::to_string),
            _ => {}
        }
    }
    let mut elements = Vec::new();
    parse_set_elements(attrs, &mut elements);
    Some(SetElementsEvent {
        family,
        table: table?,
        set: set?,
        elements,
    })
}

pub(crate) fn parse_gen(attrs: &[u8]) -> Option<GenInfo> {
    let mut id = None;
    let mut pid = None;
    let mut proc_name = None;
    for (attr, payload) in AttrIter::new(attrs) {
        match attr {
            NFTA_GEN_ID => id = get::u32_be(payload).ok(),
            NFTA_GEN_PROC_PID => pid = get::u32_be(payload).ok(),
            NFTA_GEN_PROC_NAME => proc_name = get::string(payload).ok().map(str::to_string),
            _ => {}
        }
    }
    Some(GenInfo {
        id: id?,
        pid,
        proc_name,
    })
}

/// Build an [`NftablesEvent`] from the netlink message type byte +
/// the body (post-nlmsghdr). Returns `None` for messages we don't
/// recognise (error frames, other subsystems) or cannot parse.
///
/// The body is `nfgenmsg (4 bytes) || attribute payload`. The
/// nfgenmsg's first byte is the address family, which we feed into
/// the per-type parser so the resulting typed value carries the
/// family the kernel reported.
pub(crate) fn parse_nftables_event(msg_type: u16, body: &[u8]) -> Option<NftablesEvent> {
    if (msg_type >> 8) != NFNL_SUBSYS_NFTABLES {
        return None;
    }
    if body.len() < NFGENMSG_HDRLEN {
        return None;
    }
    let attrs = &body[NFGENMSG_HDRLEN..];
    // A generation message is the ruleset's, family AF_UNSPEC. Anything
    // else in a family nlink does not know is dropped with a trace; it was
    // reported as `inet`, which it is not (#505).
    let family = match Family::from_u8(body[0]) {
        Some(family) => family,
        None if (msg_type & 0xFF) as u8 == NFT_MSG_NEWGEN => Family::Inet,
        None => {
            tracing::debug!(
                family = body[0],
                "nftables event in an unknown family; dropped"
            );
            return None;
        }
    };

    match (msg_type & 0xFF) as u8 {
        NFT_MSG_NEWTABLE => parse_table(attrs, family).map(NftablesEvent::NewTable),
        NFT_MSG_DELTABLE => parse_table(attrs, family).map(NftablesEvent::DelTable),
        NFT_MSG_NEWCHAIN => parse_chain(attrs, family).map(NftablesEvent::NewChain),
        NFT_MSG_DELCHAIN => parse_chain(attrs, family).map(NftablesEvent::DelChain),
        NFT_MSG_NEWRULE => parse_rule(attrs, family).map(NftablesEvent::NewRule),
        NFT_MSG_DELRULE => parse_rule(attrs, family).map(NftablesEvent::DelRule),
        NFT_MSG_NEWFLOWTABLE => parse_flowtable(attrs, family).map(NftablesEvent::NewFlowtable),
        NFT_MSG_DELFLOWTABLE => parse_flowtable(attrs, family).map(NftablesEvent::DelFlowtable),
        NFT_MSG_NEWSET => parse_set(attrs, family).map(NftablesEvent::NewSet),
        NFT_MSG_DELSET => parse_set(attrs, family).map(NftablesEvent::DelSet),
        NFT_MSG_NEWSETELEM => {
            parse_set_elements_event(attrs, family).map(NftablesEvent::NewSetElements)
        }
        NFT_MSG_DELSETELEM => {
            parse_set_elements_event(attrs, family).map(NftablesEvent::DelSetElements)
        }
        NFT_MSG_NEWGEN => parse_gen(attrs).map(NftablesEvent::NewGen),
        NFT_MSG_NEWOBJ => {
            super::object::parse_object(attrs, family).map(NftablesEvent::NewObject)
        }
        NFT_MSG_DELOBJ => {
            super::object::parse_object(attrs, family).map(NftablesEvent::DelObject)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_maps_to_kernel_id() {
        assert_eq!(NftablesGroup::All.to_kernel_group(), 7);
    }

    #[test]
    fn parse_rejects_wrong_subsystem() {
        // Subsystem byte != NFNL_SUBSYS_NFTABLES (10) — e.g. conntrack (1).
        let msg_type = (1u16 << 8) | NFT_MSG_NEWTABLE as u16;
        let body = vec![0u8; NFGENMSG_HDRLEN];
        assert!(parse_nftables_event(msg_type, &body).is_none());
    }

    #[test]
    fn parse_rejects_truncated_body() {
        let msg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE as u16;
        let body: Vec<u8> = vec![0; 2]; // shorter than NFGENMSG_HDRLEN (4)
        assert!(parse_nftables_event(msg_type, &body).is_none());
    }

    #[test]
    fn parse_unknown_msg_type_returns_none() {
        // Valid nftables subsystem byte, but a message type this module
        // does not parse (NFT_MSG_TRACE).
        let msg_type = (NFNL_SUBSYS_NFTABLES << 8) | 17u16;
        let body = vec![0u8; NFGENMSG_HDRLEN];
        assert!(parse_nftables_event(msg_type, &body).is_none());
    }

    /// #505: a message in a family nlink does not know was reported as
    /// `inet`, which it is not. It is dropped now; a known family is not.
    #[test]
    fn unknown_family_is_dropped_not_reported_as_inet() {
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::nftables::NFTA_TABLE_NAME;
        let table = |family: u8| {
            let mut b = MessageBuilder::new(0, 0);
            b.append_bytes(&[family, 0, 0, 0]);
            b.append_attr_str(NFTA_TABLE_NAME, "t");
            b.as_bytes()[16..].to_vec()
        };
        let msg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE as u16;
        assert!(parse_nftables_event(msg_type, &table(99)).is_none());
        match parse_nftables_event(msg_type, &table(2)) {
            Some(NftablesEvent::NewTable(t)) => assert_eq!(t.family, Family::Ip),
            other => panic!("expected an ip NewTable, got {other:?}"),
        }
    }

    #[test]
    fn set_element_and_gen_events_decode() {
        use crate::netlink::builder::MessageBuilder;
        use crate::netlink::nftables::{
            NFTA_DATA_VALUE, NFTA_LIST_ELEM, NFTA_SET_ELEM_KEY, NFTA_SET_ELEM_LIST_ELEMENTS,
        };
        let mut b = MessageBuilder::new(0, 0);
        b.append_bytes(&[2, 0, 0, 0]); // nfgenmsg: AF_INET
        b.append_attr_str(NFTA_SET_ELEM_LIST_TABLE, "t");
        b.append_attr_str(NFTA_SET_ELEM_LIST_SET, "s");
        let elems = b.nest_start(NFTA_SET_ELEM_LIST_ELEMENTS | 0x8000);
        let elem = b.nest_start(NFTA_LIST_ELEM | 0x8000);
        let key = b.nest_start(NFTA_SET_ELEM_KEY | 0x8000);
        b.append_attr(NFTA_DATA_VALUE, &[10, 0, 0, 1]);
        b.nest_end(key);
        b.nest_end(elem);
        b.nest_end(elems);
        let body = b.as_bytes()[16..].to_vec();
        let msg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM as u16;
        match parse_nftables_event(msg_type, &body) {
            Some(NftablesEvent::NewSetElements(e)) => {
                assert_eq!((e.table.as_str(), e.set.as_str()), ("t", "s"));
                assert_eq!(e.elements.len(), 1);
                assert_eq!(e.elements[0].key(), [10, 0, 0, 1]);
            }
            other => panic!("expected NewSetElements, got {other:?}"),
        }

        let mut b = MessageBuilder::new(0, 0);
        b.append_bytes(&[0, 0, 0, 0]);
        b.append_attr_u32_be(NFTA_GEN_ID, 42);
        b.append_attr_u32_be(NFTA_GEN_PROC_PID, 7);
        b.append_attr_str(NFTA_GEN_PROC_NAME, "nlink");
        let body = b.as_bytes()[16..].to_vec();
        let msg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWGEN as u16;
        match parse_nftables_event(msg_type, &body) {
            Some(NftablesEvent::NewGen(g)) => {
                assert_eq!(g.id, 42);
                assert_eq!(g.pid, Some(7));
                assert_eq!(g.proc_name.as_deref(), Some("nlink"));
            }
            other => panic!("expected NewGen, got {other:?}"),
        }
    }
}
