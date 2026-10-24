//! Per-device IP settings over netlink (#516): the IPv4 devconf
//! (`/proc/sys/net/ipv4/conf/<dev>/…`), which a link dump reports and
//! `RTM_SETLINK` writes, and the IPv6 address generation mode and token.
//!
//! Both live in a link's `IFLA_AF_SPEC`, nested by family:
//!
//! ```text
//! IFLA_AF_SPEC
//!   AF_INET   { IFLA_INET_CONF: u32[IPV4_DEVCONF_MAX] }   (dump: an array; set: nested by id)
//!   AF_INET6  { IFLA_INET6_CONF: s32[DEVCONF_MAX], IFLA_INET6_TOKEN, IFLA_INET6_ADDR_GEN_MODE: u8 }
//! ```
//!
//! The rest of the IPv6 devconf (`accept_dad`, `disable_ipv6`, …) the kernel
//! reports here but only takes through `/proc/sys`.

use std::net::Ipv6Addr;

use super::attr::AttrIter;

/// An IPv4 per-device setting (`IPV4_DEVCONF_*`): the file of that name in
/// `/proc/sys/net/ipv4/conf/<dev>/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
#[non_exhaustive]
pub enum Ipv4Devconf {
    Forwarding = 1,
    McForwarding = 2,
    ProxyArp = 3,
    AcceptRedirects = 4,
    SecureRedirects = 5,
    SendRedirects = 6,
    SharedMedia = 7,
    RpFilter = 8,
    AcceptSourceRoute = 9,
    BootpRelay = 10,
    LogMartians = 11,
    Tag = 12,
    ArpFilter = 13,
    MediumId = 14,
    NoXfrm = 15,
    NoPolicy = 16,
    ForceIgmpVersion = 17,
    ArpAnnounce = 18,
    ArpIgnore = 19,
    PromoteSecondaries = 20,
    ArpAccept = 21,
    ArpNotify = 22,
    AcceptLocal = 23,
    SrcVmark = 24,
    ProxyArpPvlan = 25,
    RouteLocalnet = 26,
    Igmpv2UnsolicitedReportInterval = 27,
    Igmpv3UnsolicitedReportInterval = 28,
    IgnoreRoutesWithLinkdown = 29,
    DropUnicastInL2Multicast = 30,
    DropGratuitousArp = 31,
    BcForwarding = 32,
    ArpEvictNocarrier = 33,
}

impl Ipv4Devconf {
    /// Every setting, in id order.
    pub const ALL: [Self; 33] = [
        Self::Forwarding,
        Self::McForwarding,
        Self::ProxyArp,
        Self::AcceptRedirects,
        Self::SecureRedirects,
        Self::SendRedirects,
        Self::SharedMedia,
        Self::RpFilter,
        Self::AcceptSourceRoute,
        Self::BootpRelay,
        Self::LogMartians,
        Self::Tag,
        Self::ArpFilter,
        Self::MediumId,
        Self::NoXfrm,
        Self::NoPolicy,
        Self::ForceIgmpVersion,
        Self::ArpAnnounce,
        Self::ArpIgnore,
        Self::PromoteSecondaries,
        Self::ArpAccept,
        Self::ArpNotify,
        Self::AcceptLocal,
        Self::SrcVmark,
        Self::ProxyArpPvlan,
        Self::RouteLocalnet,
        Self::Igmpv2UnsolicitedReportInterval,
        Self::Igmpv3UnsolicitedReportInterval,
        Self::IgnoreRoutesWithLinkdown,
        Self::DropUnicastInL2Multicast,
        Self::DropGratuitousArp,
        Self::BcForwarding,
        Self::ArpEvictNocarrier,
    ];

    /// The sysctl's name: `rp_filter` for [`Self::RpFilter`].
    pub fn name(self) -> &'static str {
        match self {
            Self::Forwarding => "forwarding",
            Self::McForwarding => "mc_forwarding",
            Self::ProxyArp => "proxy_arp",
            Self::AcceptRedirects => "accept_redirects",
            Self::SecureRedirects => "secure_redirects",
            Self::SendRedirects => "send_redirects",
            Self::SharedMedia => "shared_media",
            Self::RpFilter => "rp_filter",
            Self::AcceptSourceRoute => "accept_source_route",
            Self::BootpRelay => "bootp_relay",
            Self::LogMartians => "log_martians",
            Self::Tag => "tag",
            Self::ArpFilter => "arp_filter",
            Self::MediumId => "medium_id",
            Self::NoXfrm => "disable_xfrm",
            Self::NoPolicy => "disable_policy",
            Self::ForceIgmpVersion => "force_igmp_version",
            Self::ArpAnnounce => "arp_announce",
            Self::ArpIgnore => "arp_ignore",
            Self::PromoteSecondaries => "promote_secondaries",
            Self::ArpAccept => "arp_accept",
            Self::ArpNotify => "arp_notify",
            Self::AcceptLocal => "accept_local",
            Self::SrcVmark => "src_valid_mark",
            Self::ProxyArpPvlan => "proxy_arp_pvlan",
            Self::RouteLocalnet => "route_localnet",
            Self::Igmpv2UnsolicitedReportInterval => "igmpv2_unsolicited_report_interval",
            Self::Igmpv3UnsolicitedReportInterval => "igmpv3_unsolicited_report_interval",
            Self::IgnoreRoutesWithLinkdown => "ignore_routes_with_linkdown",
            Self::DropUnicastInL2Multicast => "drop_unicast_in_l2_multicast",
            Self::DropGratuitousArp => "drop_gratuitous_arp",
            Self::BcForwarding => "bc_forwarding",
            Self::ArpEvictNocarrier => "arp_evict_nocarrier",
        }
    }

    /// The setting with sysctl name `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == name)
    }

    /// The kernel's id (`IPV4_DEVCONF_*`).
    pub fn id(self) -> u16 {
        self as u16
    }
}

impl std::fmt::Display for Ipv4Devconf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// An IPv6 per-device setting (`DEVCONF_*`): the file of that name in
/// `/proc/sys/net/ipv6/conf/<dev>/` (#516). The link dump reports each; the
/// kernel takes them only through `/proc/sys`, so an apply writes them from
/// inside the link's namespace.
///
/// Integer settings only: the ones that are intervals are left out, since
/// the dump gives them in milliseconds and `/proc` in seconds, and so are
/// `stable_secret` (an address), the read-only `mc_forwarding`, and
/// `addr_gen_mode`, which [`AddrGenMode`] sets over netlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u16)]
#[non_exhaustive]
pub enum Ipv6Devconf {
    Forwarding = 0,
    Hoplimit = 1,
    Mtu6 = 2,
    AcceptRa = 3,
    AcceptRedirects = 4,
    Autoconf = 5,
    DadTransmits = 6,
    RtrSolicits = 7,
    UseTempaddr = 10,
    TempValidLft = 11,
    TempPreferedLft = 12,
    MaxAddresses = 15,
    ForceMldVersion = 16,
    AcceptRaDefrtr = 17,
    AcceptRaPinfo = 18,
    AcceptRaRtrPref = 19,
    AcceptRaRtInfoMaxPlen = 21,
    ProxyNdp = 22,
    OptimisticDad = 23,
    AcceptSourceRoute = 24,
    DisableIpv6 = 26,
    AcceptDad = 27,
    ForceTllao = 28,
    NdiscNotify = 29,
    SuppressFragNdisc = 32,
    AcceptRaFromLocal = 33,
    UseOptimistic = 34,
    AcceptRaMtu = 35,
    UseOifAddrsOnly = 37,
    AcceptRaMinHopLimit = 38,
    IgnoreRoutesWithLinkdown = 39,
    DropUnicastInL2Multicast = 40,
    DropUnsolicitedNa = 41,
    KeepAddrOnDown = 42,
    Seg6Enabled = 44,
    Seg6RequireHmac = 45,
    EnhancedDad = 46,
    DisablePolicy = 48,
    AcceptRaRtInfoMinPlen = 49,
    NdiscTclass = 50,
    RplSegEnabled = 51,
    RaDefrtrMetric = 52,
    Ioam6Enabled = 53,
    Ioam6Id = 54,
    Ioam6IdWide = 55,
    NdiscEvictNocarrier = 56,
    AcceptUntrackedNa = 57,
}

impl Ipv6Devconf {
    /// Every setting this type has, in id order.
    pub const ALL: [Self; 47] = [
        Self::Forwarding,
        Self::Hoplimit,
        Self::Mtu6,
        Self::AcceptRa,
        Self::AcceptRedirects,
        Self::Autoconf,
        Self::DadTransmits,
        Self::RtrSolicits,
        Self::UseTempaddr,
        Self::TempValidLft,
        Self::TempPreferedLft,
        Self::MaxAddresses,
        Self::ForceMldVersion,
        Self::AcceptRaDefrtr,
        Self::AcceptRaPinfo,
        Self::AcceptRaRtrPref,
        Self::AcceptRaRtInfoMaxPlen,
        Self::ProxyNdp,
        Self::OptimisticDad,
        Self::AcceptSourceRoute,
        Self::DisableIpv6,
        Self::AcceptDad,
        Self::ForceTllao,
        Self::NdiscNotify,
        Self::SuppressFragNdisc,
        Self::AcceptRaFromLocal,
        Self::UseOptimistic,
        Self::AcceptRaMtu,
        Self::UseOifAddrsOnly,
        Self::AcceptRaMinHopLimit,
        Self::IgnoreRoutesWithLinkdown,
        Self::DropUnicastInL2Multicast,
        Self::DropUnsolicitedNa,
        Self::KeepAddrOnDown,
        Self::Seg6Enabled,
        Self::Seg6RequireHmac,
        Self::EnhancedDad,
        Self::DisablePolicy,
        Self::AcceptRaRtInfoMinPlen,
        Self::NdiscTclass,
        Self::RplSegEnabled,
        Self::RaDefrtrMetric,
        Self::Ioam6Enabled,
        Self::Ioam6Id,
        Self::Ioam6IdWide,
        Self::NdiscEvictNocarrier,
        Self::AcceptUntrackedNa,
    ];

    /// The sysctl's name: `accept_dad` for [`Self::AcceptDad`].
    pub fn name(self) -> &'static str {
        match self {
            Self::Forwarding => "forwarding",
            Self::Hoplimit => "hop_limit",
            Self::Mtu6 => "mtu",
            Self::AcceptRa => "accept_ra",
            Self::AcceptRedirects => "accept_redirects",
            Self::Autoconf => "autoconf",
            Self::DadTransmits => "dad_transmits",
            Self::RtrSolicits => "router_solicitations",
            Self::UseTempaddr => "use_tempaddr",
            Self::TempValidLft => "temp_valid_lft",
            Self::TempPreferedLft => "temp_prefered_lft",
            Self::MaxAddresses => "max_addresses",
            Self::ForceMldVersion => "force_mld_version",
            Self::AcceptRaDefrtr => "accept_ra_defrtr",
            Self::AcceptRaPinfo => "accept_ra_pinfo",
            Self::AcceptRaRtrPref => "accept_ra_rtr_pref",
            Self::AcceptRaRtInfoMaxPlen => "accept_ra_rt_info_max_plen",
            Self::ProxyNdp => "proxy_ndp",
            Self::OptimisticDad => "optimistic_dad",
            Self::AcceptSourceRoute => "accept_source_route",
            Self::DisableIpv6 => "disable_ipv6",
            Self::AcceptDad => "accept_dad",
            Self::ForceTllao => "force_tllao",
            Self::NdiscNotify => "ndisc_notify",
            Self::SuppressFragNdisc => "suppress_frag_ndisc",
            Self::AcceptRaFromLocal => "accept_ra_from_local",
            Self::UseOptimistic => "use_optimistic",
            Self::AcceptRaMtu => "accept_ra_mtu",
            Self::UseOifAddrsOnly => "use_oif_addrs_only",
            Self::AcceptRaMinHopLimit => "accept_ra_min_hop_limit",
            Self::IgnoreRoutesWithLinkdown => "ignore_routes_with_linkdown",
            Self::DropUnicastInL2Multicast => "drop_unicast_in_l2_multicast",
            Self::DropUnsolicitedNa => "drop_unsolicited_na",
            Self::KeepAddrOnDown => "keep_addr_on_down",
            Self::Seg6Enabled => "seg6_enabled",
            Self::Seg6RequireHmac => "seg6_require_hmac",
            Self::EnhancedDad => "enhanced_dad",
            Self::DisablePolicy => "disable_policy",
            Self::AcceptRaRtInfoMinPlen => "accept_ra_rt_info_min_plen",
            Self::NdiscTclass => "ndisc_tclass",
            Self::RplSegEnabled => "rpl_seg_enabled",
            Self::RaDefrtrMetric => "ra_defrtr_metric",
            Self::Ioam6Enabled => "ioam6_enabled",
            Self::Ioam6Id => "ioam6_id",
            Self::Ioam6IdWide => "ioam6_id_wide",
            Self::NdiscEvictNocarrier => "ndisc_evict_nocarrier",
            Self::AcceptUntrackedNa => "accept_untracked_na",
        }
    }

    /// The setting with sysctl name `name`.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|d| d.name() == name)
    }

    /// The kernel's id (`DEVCONF_*`): its index in `IFLA_INET6_CONF`.
    pub fn id(self) -> u16 {
        self as u16
    }
}

impl std::fmt::Display for Ipv6Devconf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How the kernel makes a link's IPv6 link-local address (`IN6_ADDR_GEN_MODE_*`,
/// `ip link set … addrgenmode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum AddrGenMode {
    /// From the MAC address (the default).
    Eui64 = 0,
    /// None: the link gets no link-local address.
    None = 1,
    /// RFC 7217, from `stable_secret`.
    StablePrivacy = 2,
    /// Random.
    Random = 3,
}

impl AddrGenMode {
    /// The mode `ip link` names `name` (`eui64`, `none`,
    /// `stable_secret`, `random`).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "eui64" => Self::Eui64,
            "none" => Self::None,
            "stable_secret" | "stable-privacy" => Self::StablePrivacy,
            "random" => Self::Random,
            _ => return None,
        })
    }

    /// The name `ip link` gives it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Eui64 => "eui64",
            Self::None => "none",
            Self::StablePrivacy => "stable_secret",
            Self::Random => "random",
        }
    }

    pub(crate) fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Eui64,
            1 => Self::None,
            2 => Self::StablePrivacy,
            3 => Self::Random,
            _ => return None,
        })
    }
}

/// `IFLA_INET_*` and `IFLA_INET6_*` (`linux/if_link.h`).
pub(crate) mod af {
    pub const IFLA_INET_CONF: u16 = 1;
    pub const IFLA_INET6_CONF: u16 = 2;
    pub const IFLA_INET6_TOKEN: u16 = 7;
    pub const IFLA_INET6_ADDR_GEN_MODE: u16 = 8;
}

/// What a link's `IFLA_AF_SPEC` says of IPv4 and IPv6.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InetAfSpec {
    /// `IFLA_INET_CONF`: entry `i` is `IPV4_DEVCONF` id `i + 1`.
    pub(crate) ipv4_conf: Option<Vec<u32>>,
    /// `IFLA_INET6_CONF`: entry `i` is `DEVCONF` id `i`.
    pub(crate) ipv6_conf: Option<Vec<i32>>,
    pub(crate) ipv6_token: Option<Ipv6Addr>,
    pub(crate) addr_gen_mode: Option<u8>,
}

impl InetAfSpec {
    /// Read the `AF_INET` and `AF_INET6` nests of an `IFLA_AF_SPEC`
    /// payload; the other families are not this one's.
    pub(crate) fn parse(af_spec: &[u8]) -> Self {
        let words = |p: &[u8]| -> Vec<[u8; 4]> { p.as_chunks::<4>().0.to_vec() };
        let mut out = Self::default();
        for (family, nest) in AttrIter::new(af_spec) {
            match i32::from(family & 0x3FFF) {
                libc::AF_INET => {
                    for (t, p) in AttrIter::new(nest) {
                        if t & 0x3FFF == af::IFLA_INET_CONF {
                            out.ipv4_conf =
                                Some(words(p).into_iter().map(u32::from_ne_bytes).collect());
                        }
                    }
                }
                libc::AF_INET6 => {
                    for (t, p) in AttrIter::new(nest) {
                        match t & 0x3FFF {
                            af::IFLA_INET6_CONF => {
                                out.ipv6_conf =
                                    Some(words(p).into_iter().map(i32::from_ne_bytes).collect());
                            }
                            af::IFLA_INET6_TOKEN => {
                                if let Ok(b) = <[u8; 16]>::try_from(p.get(..16).unwrap_or(&[])) {
                                    out.ipv6_token = Some(Ipv6Addr::from(b));
                                }
                            }
                            af::IFLA_INET6_ADDR_GEN_MODE => out.addr_gen_mode = p.first().copied(),
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    /// An IPv6 setting's value.
    pub(crate) fn ipv6(&self, d: Ipv6Devconf) -> Option<i32> {
        self.ipv6_conf.as_ref()?.get(usize::from(d.id())).copied()
    }

    /// An IPv4 setting's value.
    pub(crate) fn ipv4(&self, d: Ipv4Devconf) -> Option<u32> {
        self.ipv4_conf
            .as_ref()?
            .get(usize::from(d.id()) - 1)
            .copied()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AddrGenMode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AddrGenMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = String::deserialize(d)?;
        Self::from_name(&name).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown addrgenmode {name:?} (eui64, none, stable_secret, random)"
            ))
        })
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for AddrGenMode {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AddrGenMode".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({ "enum": ["eui64", "none", "stable_secret", "random"] })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ipv4Devconf {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Ipv6Devconf {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ipv4Devconf {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        Self::from_name(&name)
            .ok_or_else(|| serde::de::Error::custom(format!("not an IPv4 devconf setting: {name}")))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Ipv6Devconf {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let name = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        Self::from_name(&name)
            .ok_or_else(|| serde::de::Error::custom(format!("not an IPv6 devconf setting: {name}")))
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for Ipv6Devconf {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Ipv6Devconf".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let names: Vec<&str> = Self::ALL.iter().map(|d| d.name()).collect();
        schemars::json_schema!({ "enum": names })
    }
}

#[cfg(feature = "schemars")]
impl schemars::JsonSchema for Ipv4Devconf {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Ipv4Devconf".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let names: Vec<&str> = Self::ALL.iter().map(|d| d.name()).collect();
        schemars::json_schema!({ "enum": names })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::builder::MessageBuilder;

    #[test]
    fn names_round_trip_and_ids_are_dense() {
        for (i, d) in Ipv4Devconf::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(d.id()), i + 1);
            assert_eq!(Ipv4Devconf::from_name(d.name()), Some(d));
        }
        for d in Ipv6Devconf::ALL {
            assert_eq!(Ipv6Devconf::from_name(d.name()), Some(d));
        }
        for m in [AddrGenMode::Eui64, AddrGenMode::None, AddrGenMode::StablePrivacy, AddrGenMode::Random] {
            assert_eq!(AddrGenMode::from_name(m.name()), Some(m));
            assert_eq!(AddrGenMode::from_u8(m as u8), Some(m));
        }
    }

    #[test]
    fn an_af_spec_is_read_by_family() {
        let mut b = MessageBuilder::new(0, 0);
        let start = b.len();
        let inet = b.nest_start(libc::AF_INET as u16);
        let conf: Vec<u8> = (1u32..=33).flat_map(|v| v.to_ne_bytes()).collect();
        b.append_attr(af::IFLA_INET_CONF, &conf);
        b.nest_end(inet);
        let inet6 = b.nest_start(libc::AF_INET6 as u16);
        b.append_attr_u8(af::IFLA_INET6_ADDR_GEN_MODE, 1);
        b.append_attr(af::IFLA_INET6_TOKEN, &"::1:2".parse::<Ipv6Addr>().unwrap().octets());
        b.nest_end(inet6);
        let spec = InetAfSpec::parse(&b.as_bytes()[start..]);
        assert_eq!(spec.ipv4(Ipv4Devconf::Forwarding), Some(1));
        assert_eq!(spec.ipv4(Ipv4Devconf::RpFilter), Some(8));
        assert_eq!(spec.ipv4(Ipv4Devconf::ArpEvictNocarrier), Some(33));
        assert_eq!(spec.addr_gen_mode, Some(1));
        assert_eq!(spec.ipv6_token, Some("::1:2".parse().unwrap()));
    }
}
