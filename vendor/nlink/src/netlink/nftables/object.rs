//! Named stateful objects — counters, quotas, limits and conntrack helpers a
//! table holds by name and rules share (`counter name "web"`, `quota name
//! "q"`, `ct helper set "ftp-std"`), and that object maps pick per packet.
//! ipset's per-element `counters` become a map of counter objects.

use super::expr::{LimitExpr, QuotaExpr};
use super::types::Family;
use super::*;
use crate::netlink::attr::{AttrIter, get};
use crate::netlink::builder::MessageBuilder;

/// The kind of a stateful object: `NFT_OBJECT_*`. Only the kinds nlink can
/// build are named; [`ObjectState::Other`] carries the rest as read back.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
#[non_exhaustive]
pub enum ObjectType {
    /// `NFT_OBJECT_COUNTER`.
    Counter = 1,
    /// `NFT_OBJECT_QUOTA`.
    Quota = 2,
    /// `NFT_OBJECT_CT_HELPER`.
    CtHelper = 3,
    /// `NFT_OBJECT_LIMIT`.
    Limit = 4,
    /// `NFT_OBJECT_SECMARK`.
    Secmark = 8,
}

impl ObjectType {
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Counter),
            2 => Some(Self::Quota),
            3 => Some(Self::CtHelper),
            4 => Some(Self::Limit),
            8 => Some(Self::Secmark),
            _ => None,
        }
    }
}

/// What an object is configured to do.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectConfig {
    /// A counter: packets and bytes.
    Counter,
    /// A byte quota — see [`QuotaExpr`].
    Quota(QuotaExpr),
    /// A packet-rate limit — see [`LimitExpr`].
    Limit(LimitExpr),
    /// A conntrack helper — see [`CtHelperObject`] (#703).
    CtHelper(CtHelperObject),
    /// A security mark, by its LSM security context (#703): `secmark
    /// <name> { "system_u:object_r:ssh_server_packet_t:s0" }` under
    /// SELinux, a label such as `"unconfined"` under AppArmor. Given with
    /// [`Rule::set_secmark`](super::Rule::set_secmark); the kernel refuses
    /// a context its LSM does not know.
    Secmark(String),
}

impl ObjectConfig {
    /// The object type this configures.
    pub fn object_type(&self) -> ObjectType {
        match self {
            Self::Counter => ObjectType::Counter,
            Self::Quota(_) => ObjectType::Quota,
            Self::Limit(_) => ObjectType::Limit,
            Self::CtHelper(_) => ObjectType::CtHelper,
            Self::Secmark(_) => ObjectType::Secmark,
        }
    }
}

/// A conntrack helper object (#703): `ct helper <name> { type "<helper>"
/// protocol <proto>; [l3proto ip|ip6;] }`, which a rule assigns with
/// [`Rule::set_ct_helper`](super::Rule::set_ct_helper). The helper module
/// (`nf_conntrack_ftp`, …) must be loadable.
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CtHelperObject {
    /// The helper: `ftp`, `tftp`, `sip`, ….
    pub helper: String,
    /// Its layer-4 protocol: 6 (TCP) or 17 (UDP).
    pub protocol: u8,
    /// Its layer-3 family, `NFPROTO_IPV4` or `NFPROTO_IPV6`; `None`, the
    /// table's (both, in an inet table).
    pub family: Option<u8>,
}

impl CtHelperObject {
    /// The helper `helper` for `protocol`.
    pub fn new(helper: impl Into<String>, protocol: u8) -> Self {
        Self {
            helper: helper.into(),
            protocol,
            family: None,
        }
    }

    /// For one layer-3 family only (`l3proto ip`).
    pub fn family(mut self, nfproto: u8) -> Self {
        self.family = Some(nfproto);
        self
    }
}

/// The `NFPROTO_*` a helper object in a `family` table defaults to, and
/// echoes: the table's own, `NFPROTO_INET` in an inet table, where it serves
/// both.
fn table_nfproto(family: Family) -> u8 {
    family as u8
}

/// A named stateful object, to create with
/// [`Connection::add_object`](crate::netlink::Connection::add_object).
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[derive(Debug, Clone)]
#[must_use = "builders do nothing unless used"]
pub struct Object {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) family: Family,
    pub(crate) config: ObjectConfig,
    pub(crate) comment: Option<String>,
    /// Tag it as the declarative apply's own (#527).
    pub(crate) owned: bool,
}

impl Object {
    /// An object named `name` in `table`, configured by `config`.
    pub fn new(table: &str, name: &str, config: ObjectConfig) -> Self {
        Self {
            table: table.to_string(),
            name: name.to_string(),
            family: Family::Inet,
            config,
            comment: None,
            owned: false,
        }
    }

    /// Give the object a comment, which `nft list` shows (#528). Written
    /// when the object is created. Adding one longer than 127 bytes fails.
    pub fn comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// A named counter (`counter name`).
    pub fn counter(table: &str, name: &str) -> Self {
        Self::new(table, name, ObjectConfig::Counter)
    }

    /// A named quota (`quota name`).
    pub fn quota(table: &str, name: &str, quota: QuotaExpr) -> Self {
        Self::new(table, name, ObjectConfig::Quota(quota))
    }

    /// A named limit (`limit name`).
    pub fn limit(table: &str, name: &str, limit: LimitExpr) -> Self {
        Self::new(table, name, ObjectConfig::Limit(limit))
    }

    /// A named conntrack helper (`ct helper`).
    pub fn ct_helper(table: &str, name: &str, helper: CtHelperObject) -> Self {
        Self::new(table, name, ObjectConfig::CtHelper(helper))
    }

    /// Set the address family (default `inet`).
    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    /// Owning table.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Object name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its configuration.
    pub fn config(&self) -> &ObjectConfig {
        &self.config
    }
}

/// A stateful object as read back from the kernel.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ObjectInfo {
    /// Owning table.
    pub table: String,
    /// Object name.
    pub name: String,
    /// Address family.
    pub family: Family,
    /// Kernel handle.
    pub handle: u64,
    /// How many rules and set elements reference it.
    pub use_count: u32,
    /// Its configuration and live state.
    pub state: ObjectState,
    /// Its comment (#528).
    pub comment: Option<String>,
    /// Created by nlink's declarative apply: it carries nlink's ownership
    /// tag (#527).
    pub managed: bool,
}

impl ObjectInfo {
    /// The object type, if nlink models it.
    pub fn object_type(&self) -> Option<ObjectType> {
        match &self.state {
            ObjectState::Counter { .. } => Some(ObjectType::Counter),
            ObjectState::Quota { .. } => Some(ObjectType::Quota),
            ObjectState::Limit(_) => Some(ObjectType::Limit),
            ObjectState::CtHelper(_) => Some(ObjectType::CtHelper),
            ObjectState::Secmark(_) => Some(ObjectType::Secmark),
            ObjectState::Other { .. } => None,
        }
    }
}

/// An object's configuration and live state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ObjectState {
    /// A counter's totals.
    #[non_exhaustive]
    Counter {
        /// Packets counted.
        packets: u64,
        /// Bytes counted.
        bytes: u64,
    },
    /// A quota.
    #[non_exhaustive]
    Quota {
        /// The quota, in bytes.
        bytes: u64,
        /// Bytes used, capped at the quota.
        consumed: u64,
        /// `quota over`: matches once used up.
        over: bool,
        /// Used up (`NFT_QUOTA_F_DEPLETED`).
        depleted: bool,
    },
    /// A packet-rate limit.
    Limit(LimitExpr),
    /// A conntrack helper.
    CtHelper(CtHelperObject),
    /// A security mark's context.
    Secmark(String),
    /// A kind nlink does not model (or a byte-rate limit): its
    /// `NFT_OBJECT_*` type and raw `NFTA_OBJ_DATA`.
    #[non_exhaustive]
    Other {
        /// `NFT_OBJECT_*`.
        object_type: u32,
        /// The raw `NFTA_OBJ_DATA` payload.
        data: Vec<u8>,
    },
}

impl ObjectState {
    /// The configuration part of this state, for the declarative diff; live
    /// counts and consumption are not configuration.
    pub(crate) fn config(&self) -> Option<ObjectConfig> {
        match self {
            Self::Counter { .. } => Some(ObjectConfig::Counter),
            Self::Quota { bytes, over, .. } => {
                let mut quota = QuotaExpr::new(*bytes);
                quota.over = *over;
                Some(ObjectConfig::Quota(quota))
            }
            Self::Limit(limit) => Some(ObjectConfig::Limit(limit.clone())),
            Self::CtHelper(h) => Some(ObjectConfig::CtHelper(h.clone())),
            Self::Secmark(context) => Some(ObjectConfig::Secmark(context.clone())),
            Self::Other { .. } => None,
        }
    }
}

/// Append `NFTA_OBJ_DATA` for `config` in a `family` table: what
/// `nft_obj_init` reads, in the shape the matching expression has. A
/// helper's family goes as the kernel echoes it, the table's when none is
/// declared.
pub(crate) fn append_object_data(builder: &mut MessageBuilder, config: &ObjectConfig, family: Family) {
    let data = builder.nest_start(NFTA_OBJ_DATA | 0x8000);
    match config {
        ObjectConfig::Counter => {}
        ObjectConfig::Quota(quota) => super::expr::write_quota_attrs(builder, quota, false),
        ObjectConfig::Limit(limit) => super::expr::write_limit_attrs(builder, limit),
        ObjectConfig::CtHelper(h) => {
            builder.append_attr_str(NFTA_CT_HELPER_NAME, &h.helper);
            let nfproto = h.family.unwrap_or_else(|| table_nfproto(family));
            builder.append_attr_u16_be(NFTA_CT_HELPER_L3PROTO, u16::from(nfproto));
            builder.append_attr(NFTA_CT_HELPER_L4PROTO, &[h.protocol]);
        }
        ObjectConfig::Secmark(context) => builder.append_attr_str(NFTA_SECMARK_CTX, context),
    }
    builder.nest_end(data);
}

/// Parse one `NFT_MSG_NEWOBJ` dump payload (after the nfgenmsg).
pub(crate) fn parse_object(data: &[u8], family: Family) -> Option<ObjectInfo> {
    let mut table = None;
    let mut name = None;
    let mut object_type = None;
    let mut payload: &[u8] = &[];
    let mut handle = 0;
    let mut use_count = 0;
    let mut comment = None;
    let mut managed = false;
    for (attr, value) in AttrIter::new(data) {
        match attr & 0x7FFF {
            NFTA_OBJ_USERDATA => {
                comment = super::userdata::comment_of(value, super::userdata::NFTNL_UDATA_COMMENT);
                managed = super::userdata::is_owned(value);
            }
            NFTA_OBJ_TABLE => table = get::string(value).ok().map(str::to_string),
            NFTA_OBJ_NAME => name = get::string(value).ok().map(str::to_string),
            NFTA_OBJ_TYPE => object_type = get::u32_be(value).ok(),
            NFTA_OBJ_DATA => payload = value,
            NFTA_OBJ_HANDLE => handle = get::u64_be(value).unwrap_or(0),
            NFTA_OBJ_USE => use_count = get::u32_be(value).unwrap_or(0),
            _ => {}
        }
    }
    let object_type = object_type?;
    let state = parse_state(object_type, payload, family).unwrap_or_else(|| ObjectState::Other {
        object_type,
        data: payload.to_vec(),
    });
    Some(ObjectInfo {
        table: table?,
        name: name?,
        family,
        handle,
        use_count,
        state,
        comment,
        managed,
    })
}

fn parse_state(object_type: u32, data: &[u8], family: Family) -> Option<ObjectState> {
    let attrs: Vec<(u16, &[u8])> = AttrIter::new(data).map(|(a, v)| (a & 0x7FFF, v)).collect();
    let u64_of = |id| {
        attrs
            .iter()
            .find(|(a, _)| *a == id)
            .and_then(|(_, v)| get::u64_be(v).ok())
    };
    let u32_of = |id| {
        attrs
            .iter()
            .find(|(a, _)| *a == id)
            .and_then(|(_, v)| get::u32_be(v).ok())
    };
    match ObjectType::from_u32(object_type)? {
        ObjectType::Counter => Some(ObjectState::Counter {
            packets: u64_of(NFTA_COUNTER_PACKETS)?,
            bytes: u64_of(NFTA_COUNTER_BYTES)?,
        }),
        ObjectType::Quota => {
            let flags = u32_of(NFTA_QUOTA_FLAGS).unwrap_or(0);
            Some(ObjectState::Quota {
                bytes: u64_of(NFTA_QUOTA_BYTES)?,
                consumed: u64_of(NFTA_QUOTA_CONSUMED).unwrap_or(0),
                over: flags & NFT_QUOTA_F_INV != 0,
                depleted: flags & NFT_QUOTA_F_DEPLETED != 0,
            })
        }
        ObjectType::Limit => super::expr::parse_limit_attrs(data).map(ObjectState::Limit),
        ObjectType::CtHelper => {
            let attr = |id| attrs.iter().find(|(a, _)| *a == id).map(|(_, v)| *v);
            let l3 = attr(NFTA_CT_HELPER_L3PROTO).and_then(|v| get::u16_be(v).ok())?;
            let l3 = u8::try_from(l3).ok()?;
            Some(ObjectState::CtHelper(CtHelperObject {
                helper: get::string(attr(NFTA_CT_HELPER_NAME)?).ok()?.to_string(),
                protocol: *attr(NFTA_CT_HELPER_L4PROTO)?.first()?,
                // The table's own reads as none, as it is declared.
                family: (l3 != table_nfproto(family)).then_some(l3),
            }))
        }
        ObjectType::Secmark => {
            let context = attrs.iter().find(|(a, _)| *a == NFTA_SECMARK_CTX)?.1;
            Some(ObjectState::Secmark(get::string(context).ok()?.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::nftables::types::LimitUnit;

    fn data_of(config: &ObjectConfig) -> Vec<u8> {
        data_in(config, Family::Inet)
    }

    fn data_in(config: &ObjectConfig, family: Family) -> Vec<u8> {
        let mut b = MessageBuilder::new(0, 0);
        append_object_data(&mut b, config, family);
        // Header (16) + the NFTA_OBJ_DATA nest header (4).
        b.as_bytes()[20..].to_vec()
    }

    #[test]
    fn object_data_reads_back_as_its_configuration() {
        let quota = ObjectConfig::Quota(QuotaExpr::new(1_000_000).over());
        let state = parse_state(ObjectType::Quota as u32, &data_of(&quota), Family::Inet).unwrap();
        assert_eq!(state.config(), Some(quota));

        let limit = ObjectConfig::Limit(LimitExpr::packets(10, LimitUnit::Minute).burst(3));
        let state = parse_state(ObjectType::Limit as u32, &data_of(&limit), Family::Inet).unwrap();
        assert_eq!(state.config(), Some(limit));

        // A counter's request carries no data; the dump has its totals.
        assert!(data_of(&ObjectConfig::Counter).is_empty());
    }

    #[test]
    fn a_request_never_carries_a_quota_consumption_or_depletion() {
        // nft_quota_do_init starts the quota at CONSUMED if it is sent, and
        // refuses NFT_QUOTA_F_DEPLETED (EOPNOTSUPP).
        let data = data_of(&ObjectConfig::Quota(QuotaExpr::new(500)));
        let attrs: Vec<u16> = AttrIter::new(&data).map(|(a, _)| a & 0x7FFF).collect();
        assert_eq!(attrs, [NFTA_QUOTA_BYTES, NFTA_QUOTA_FLAGS]);
    }

    /// A byte limit is a limit (#528); an unknown type or kind is not a
    /// guess.
    #[test]
    fn a_byte_limit_decodes_and_an_unknown_kind_is_other() {
        let limit = |kind: u32| {
            let mut b = MessageBuilder::new(0, 0);
            b.append_attr_u64_be(NFTA_LIMIT_RATE, 1000);
            b.append_attr_u64_be(NFTA_LIMIT_UNIT, 1);
            b.append_attr_u32_be(NFTA_LIMIT_BURST, 1500);
            b.append_attr_u32_be(NFTA_LIMIT_TYPE, kind);
            parse_state(ObjectType::Limit as u32, &b.as_bytes()[16..], Family::Inet)
        };
        assert_eq!(
            limit(1), // NFT_LIMIT_PKT_BYTES
            Some(ObjectState::Limit(
                LimitExpr::bytes(crate::Bytes::new(1000), LimitUnit::Second).burst(1500)
            ))
        );
        assert_eq!(limit(7), None);
        assert_eq!(parse_state(7, &[], Family::Inet), None); // ct timeout
    }

    /// A secmark's context reads back as written (#703).
    #[test]
    fn a_secmark_reads_back_its_context() {
        let config = ObjectConfig::Secmark("system_u:object_r:ssh_server_packet_t:s0".into());
        let state = parse_state(ObjectType::Secmark as u32, &data_of(&config), Family::Inet).unwrap();
        assert_eq!(state.config(), Some(config));
    }

    /// A helper always sends its family, as the kernel echoes it, and reads
    /// the table's back as none, as it is declared (#703).
    #[test]
    fn a_ct_helper_reads_back_as_declared() {
        for (family, helper, l3) in [
            (Family::Ip, CtHelperObject::new("ftp", 6), 2),
            (Family::Inet, CtHelperObject::new("tftp", 17), 1),
            (Family::Inet, CtHelperObject::new("ftp", 6).family(10), 10),
        ] {
            let config = ObjectConfig::CtHelper(helper);
            let data = data_in(&config, family);
            let attrs: Vec<(u16, &[u8])> = AttrIter::new(&data).collect();
            assert_eq!(attrs[1], (NFTA_CT_HELPER_L3PROTO, &[0, l3][..]), "{config:?}");
            let state = parse_state(ObjectType::CtHelper as u32, &data, family).unwrap();
            assert_eq!(state.config(), Some(config));
        }
    }
}
