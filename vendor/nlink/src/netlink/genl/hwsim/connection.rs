//! `Connection<Hwsim>`: create, list and delete simulated radios (#530).

use super::*;
use crate::{
    macros::__rt::resolve_genl_family,
    netlink::{
        attr::{AttrIter, get},
        builder::MessageBuilder,
        connection::Connection,
        error::{Error, Result},
        genl::{GENL_HDRLEN, GenlMsgHdr},
        message::{MessageIter, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_HDRLEN},
        protocol::{AsyncProtocolInit, Hwsim},
        socket::NetlinkSocket,
    },
};

/// The family's genl version.
const HWSIM_GENL_VERSION: u8 = 1;

impl AsyncProtocolInit for Hwsim {
    async fn resolve_async(socket: &NetlinkSocket) -> Result<Self> {
        let family_id = resolve_genl_family(socket, HWSIM_GENL_NAME).await?;
        Ok(Self { family_id })
    }
}

/// A radio to create (#530). The kernel's defaults are one channel, a
/// default interface, and a generated name and address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NewRadio {
    /// The radio's name (`HWSIM_ATTR_RADIO_NAME`).
    pub name: Option<String>,
    /// Concurrent channels (`HWSIM_ATTR_CHANNELS`).
    pub channels: Option<u32>,
    /// A regulatory hint, two letters (`HWSIM_ATTR_REG_HINT_ALPHA2`).
    pub reg_alpha2: Option<[u8; 2]>,
    /// The permanent MAC address (`HWSIM_ATTR_PERM_ADDR`).
    pub perm_addr: Option<[u8; 6]>,
    /// No default interface (`HWSIM_ATTR_NO_VIF`).
    pub no_vif: bool,
    /// Channel contexts (`HWSIM_ATTR_USE_CHANCTX`).
    pub use_chanctx: bool,
    /// A P2P device (`HWSIM_ATTR_SUPPORT_P2P_DEVICE`).
    pub p2p_device: bool,
    /// Delete the radio when the creating socket closes
    /// (`HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE`).
    pub destroy_on_close: bool,
}

impl NewRadio {
    /// A radio with the kernel's defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Name it.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Its number of concurrent channels.
    pub fn channels(mut self, channels: u32) -> Self {
        self.channels = Some(channels);
        self
    }

    /// Its regulatory hint, `"DE"`.
    pub fn reg_alpha2(mut self, alpha2: [u8; 2]) -> Self {
        self.reg_alpha2 = Some(alpha2);
        self
    }

    /// Its permanent MAC address.
    pub fn perm_addr(mut self, addr: [u8; 6]) -> Self {
        self.perm_addr = Some(addr);
        self
    }

    /// No default interface: create them with `new_interface`.
    pub fn no_vif(mut self) -> Self {
        self.no_vif = true;
        self
    }

    /// Use channel contexts.
    pub fn use_chanctx(mut self) -> Self {
        self.use_chanctx = true;
        self
    }

    /// Delete the radio when this connection closes.
    pub fn destroy_on_close(mut self) -> Self {
        self.destroy_on_close = true;
        self
    }

    fn append(&self, builder: &mut MessageBuilder) {
        if let Some(channels) = self.channels {
            builder.append_attr_u32(HWSIM_ATTR_CHANNELS, channels);
        }
        if let Some(alpha2) = self.reg_alpha2 {
            builder.append_attr(HWSIM_ATTR_REG_HINT_ALPHA2, &alpha2);
        }
        for (on, attr) in [
            (self.p2p_device, HWSIM_ATTR_SUPPORT_P2P_DEVICE),
            (self.use_chanctx, HWSIM_ATTR_USE_CHANCTX),
            (self.destroy_on_close, HWSIM_ATTR_DESTROY_RADIO_ON_CLOSE),
            (self.no_vif, HWSIM_ATTR_NO_VIF),
        ] {
            if on {
                builder.append_attr(attr, &[]);
            }
        }
        if let Some(name) = &self.name {
            builder.append_attr(HWSIM_ATTR_RADIO_NAME, name.as_bytes());
        }
        if let Some(addr) = self.perm_addr {
            builder.append_attr(HWSIM_ATTR_PERM_ADDR, &addr);
        }
    }
}

/// A radio, as `HWSIM_CMD_GET_RADIO` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HwsimRadio {
    /// Its id.
    pub id: u32,
    /// Its name, which is its wiphy's: find the wiphy with
    /// [`Connection::<Nl80211>::get_phy_by_name`](crate::netlink::Connection::get_phy_by_name).
    pub name: Option<String>,
    /// Its concurrent channels.
    pub channels: Option<u32>,
}

impl HwsimRadio {
    fn parse(attrs: &[u8]) -> Option<Self> {
        let mut radio = Self {
            id: u32::MAX,
            name: None,
            channels: None,
        };
        for (attr, value) in AttrIter::new(attrs) {
            match attr & 0x7FFF {
                HWSIM_ATTR_RADIO_ID => radio.id = get::u32_ne(value).ok()?,
                // The name is not NUL-terminated (nla_put, not nla_put_string).
                HWSIM_ATTR_RADIO_NAME => {
                    radio.name = Some(String::from_utf8_lossy(value).trim_end_matches('\0').to_string());
                }
                HWSIM_ATTR_CHANNELS => radio.channels = get::u32_ne(value).ok(),
                _ => {}
            }
        }
        (radio.id != u32::MAX).then_some(radio)
    }
}

#[nlink_macros::send_futures]
impl Connection<Hwsim> {
    /// The resolved family id.
    pub fn family_id(&self) -> u16 {
        self.state().family_id
    }

    /// Create a radio (#530) in this connection's namespace, returning
    /// its id — which the kernel puts in the ACK's error field, where an
    /// ACK has 0. Needs `CAP_NET_ADMIN`. Unverified on a live kernel.
    pub async fn new_radio(&self, radio: NewRadio) -> Result<u32> {
        let mut builder = self.request(HWSIM_CMD_NEW_RADIO, NLM_F_REQUEST | NLM_F_ACK);
        radio.append(&mut builder);
        let id = self.send_ack_value(builder).await?;
        u32::try_from(id).map_err(|_| Error::invalid_message(format!("hwsim: radio id {id}")))
    }

    /// Delete radio `id`.
    pub async fn del_radio(&self, id: u32) -> Result<()> {
        let mut builder = self.request(HWSIM_CMD_DEL_RADIO, NLM_F_REQUEST | NLM_F_ACK);
        builder.append_attr_u32(HWSIM_ATTR_RADIO_ID, id);
        self.send_ack_value(builder).await.map(drop)
    }

    /// Delete the radio named `name`.
    pub async fn del_radio_by_name(&self, name: &str) -> Result<()> {
        let mut builder = self.request(HWSIM_CMD_DEL_RADIO, NLM_F_REQUEST | NLM_F_ACK);
        builder.append_attr(HWSIM_ATTR_RADIO_NAME, name.as_bytes());
        self.send_ack_value(builder).await.map(drop)
    }

    /// Radio `id`, if this namespace sees it.
    pub async fn get_radio(&self, id: u32) -> Result<Option<HwsimRadio>> {
        let mut builder = self.request(HWSIM_CMD_GET_RADIO, NLM_F_REQUEST);
        builder.append_attr_u32(HWSIM_ATTR_RADIO_ID, id);
        let response = match self.send_request(builder).await {
            Ok(response) => response,
            // The driver's answer for an id it does not have here.
            Err(e) if e.is_no_device() => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(MessageIter::new(&response)
            .flatten()
            .filter(|(header, _)| !header.is_error())
            .find_map(|(_, payload)| HwsimRadio::parse(payload.get(GENL_HDRLEN..)?)))
    }

    /// Every radio this namespace sees.
    pub async fn get_radios(&self) -> Result<Vec<HwsimRadio>> {
        let builder = self.request(HWSIM_CMD_GET_RADIO, NLM_F_REQUEST | NLM_F_DUMP);
        let responses = self.send_dump(builder).await?;
        Ok(responses
            .iter()
            .filter_map(|r| r.get(NLMSG_HDRLEN + GENL_HDRLEN..))
            .filter_map(HwsimRadio::parse)
            .collect())
    }

    fn request(&self, cmd: u8, flags: u16) -> MessageBuilder {
        new_request(self.state().family_id, cmd, flags)
    }
}

fn new_request(family_id: u16, cmd: u8, flags: u16) -> MessageBuilder {
    let mut builder = MessageBuilder::new(family_id, flags);
    builder.append(&GenlMsgHdr::new(cmd, HWSIM_GENL_VERSION));
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The numbers of the driver-private header, which the UAPI audit
    /// cannot see (`mac80211_hwsim.h`).
    #[test]
    fn the_hwsim_numbers_are_the_drivers() {
        assert_eq!((HWSIM_CMD_NEW_RADIO, HWSIM_CMD_DEL_RADIO, HWSIM_CMD_GET_RADIO), (4, 5, 6));
        assert_eq!((HWSIM_ATTR_CHANNELS, HWSIM_ATTR_RADIO_ID, HWSIM_ATTR_RADIO_NAME), (9, 10, 17));
        assert_eq!((HWSIM_ATTR_NO_VIF, HWSIM_ATTR_PERM_ADDR), (18, 22));
    }

    #[test]
    fn a_new_radio_carries_what_it_was_given() {
        let msg = {
            let mut b = new_request(0x22, HWSIM_CMD_NEW_RADIO, NLM_F_REQUEST | NLM_F_ACK);
            NewRadio::new().name("r1").channels(2).no_vif().append(&mut b);
            b.finish()
        };
        assert_eq!(msg[16], HWSIM_CMD_NEW_RADIO);
        let attrs: Vec<(u16, Vec<u8>)> = AttrIter::new(&msg[20..]).map(|(a, v)| (a, v.to_vec())).collect();
        assert_eq!(
            attrs,
            [
                (HWSIM_ATTR_CHANNELS, 2u32.to_ne_bytes().to_vec()),
                (HWSIM_ATTR_NO_VIF, vec![]),
                (HWSIM_ATTR_RADIO_NAME, b"r1".to_vec()),
            ]
        );
    }

    #[test]
    fn a_radio_reads_back() {
        let mut b = MessageBuilder::new(0, 0);
        b.append_attr_u32(HWSIM_ATTR_RADIO_ID, 3);
        b.append_attr(HWSIM_ATTR_RADIO_NAME, b"phy3");
        b.append_attr_u32(HWSIM_ATTR_CHANNELS, 1);
        let msg = b.finish();
        let radio = HwsimRadio::parse(&msg[16..]).unwrap();
        assert_eq!((radio.id, radio.name.as_deref(), radio.channels), (3, Some("phy3"), Some(1)));
        assert_eq!(HwsimRadio::parse(&[]), None, "no id, no radio");
    }
}
