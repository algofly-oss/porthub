//! NFLOG: reading the packets `log group N` sends (#528).
//!
//! An nftables `log group N` (or iptables `-j NFLOG --nflog-group N`)
//! hands each matched packet to `nfnetlink_log`, which sends it to the
//! netlink socket bound to group `N` in that namespace. A syslog `log`
//! writes nothing in any namespace but the initial one unless the host
//! sets `net.netfilter.nf_log_all_netns=1`; an NFLOG group has no such
//! limit, which makes it how a lab sees what its firewall logged.
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::netlink::{Connection, Nflog};
//! use tokio_stream::StreamExt;
//!
//! let nflog = Connection::<Nflog>::new()?;
//! nflog.bind_group(5, 0xffff).await?;
//! let mut packets = nflog.events().await;
//! while let Some(packet) = packets.next().await {
//!     let packet = packet?;
//!     println!("{:?}: {} bytes on {:?}", packet.prefix, packet.payload.len(), packet.indev);
//! }
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use super::attr::{AttrIter, get};
use super::builder::MessageBuilder;
use super::connection::Connection;
use super::error::Result;
use super::message::{NLM_F_ACK, NLM_F_REQUEST};
use super::protocol::Nflog;

/// `NFNL_SUBSYS_ULOG` — `nfnetlink_log`'s subsystem.
pub const NFNL_SUBSYS_ULOG: u16 = 4;
/// `NFULNL_MSG_PACKET` — a logged packet, kernel to user.
pub const NFULNL_MSG_PACKET: u16 = 0;
/// `NFULNL_MSG_CONFIG` — bind, unbind, set the copy mode.
pub const NFULNL_MSG_CONFIG: u16 = 1;

/// `NFULA_CFG_CMD` — an `nfulnl_msg_config_cmd`.
pub const NFULA_CFG_CMD: u16 = 1;
/// `NFULA_CFG_MODE` — an `nfulnl_msg_config_mode`.
pub const NFULA_CFG_MODE: u16 = 2;
/// `NFULNL_CFG_CMD_BIND` — receive a group's packets.
pub const NFULNL_CFG_CMD_BIND: u8 = 1;
/// `NFULNL_CFG_CMD_UNBIND`.
pub const NFULNL_CFG_CMD_UNBIND: u8 = 2;
/// `NFULNL_COPY_PACKET` — copy the packet, up to the copy range.
pub const NFULNL_COPY_PACKET: u8 = 0x02;

/// `NFULA_PACKET_HDR` — an `nfulnl_msg_packet_hdr`.
pub const NFULA_PACKET_HDR: u16 = 1;
/// `NFULA_MARK` — the packet mark.
pub const NFULA_MARK: u16 = 2;
/// `NFULA_TIMESTAMP` — an `nfulnl_msg_packet_timestamp`.
pub const NFULA_TIMESTAMP: u16 = 3;
/// `NFULA_IFINDEX_INDEV`.
pub const NFULA_IFINDEX_INDEV: u16 = 4;
/// `NFULA_IFINDEX_OUTDEV`.
pub const NFULA_IFINDEX_OUTDEV: u16 = 5;
/// `NFULA_IFINDEX_PHYSINDEV` — the bridge port it came in on.
pub const NFULA_IFINDEX_PHYSINDEV: u16 = 6;
/// `NFULA_IFINDEX_PHYSOUTDEV`.
pub const NFULA_IFINDEX_PHYSOUTDEV: u16 = 7;
/// `NFULA_HWADDR` — an `nfulnl_msg_packet_hw`.
pub const NFULA_HWADDR: u16 = 8;
/// `NFULA_PAYLOAD` — the packet, from the network header.
pub const NFULA_PAYLOAD: u16 = 9;
/// `NFULA_PREFIX` — the rule's log prefix.
pub const NFULA_PREFIX: u16 = 10;
/// `NFULA_UID` — the sending socket's user.
pub const NFULA_UID: u16 = 11;
/// `NFULA_SEQ` — the group's sequence number (`NFULNL_CFG_F_SEQ`).
pub const NFULA_SEQ: u16 = 12;
/// `NFULA_GID` — the sending socket's group.
pub const NFULA_GID: u16 = 14;

/// One packet a `log group` rule sent (#528).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NflogPacket {
    /// The protocol family, `NFPROTO_*`: 2 for IPv4, 10 for IPv6, 7 for
    /// bridge.
    pub family: u8,
    /// The group it was logged to.
    pub group: u16,
    /// The link-layer protocol (ethertype), 0x0800 for IPv4.
    pub hw_protocol: u16,
    /// The netfilter hook it was logged in (`NF_INET_*`).
    pub hook: u8,
    /// The rule's log prefix.
    pub prefix: Option<String>,
    /// The packet mark.
    pub mark: Option<u32>,
    /// When it was logged, since the epoch, if the kernel timestamped it.
    pub timestamp: Option<Duration>,
    /// The input interface's index.
    pub indev: Option<u32>,
    /// The output interface's index.
    pub outdev: Option<u32>,
    /// The bridge port it came in on.
    pub physindev: Option<u32>,
    /// The bridge port it goes out on.
    pub physoutdev: Option<u32>,
    /// The source link-layer address.
    pub hwaddr: Option<Vec<u8>>,
    /// The sending socket's user and group, for a local packet.
    pub uid: Option<u32>,
    /// See [`uid`](Self::uid).
    pub gid: Option<u32>,
    /// The packet, from its network header, up to the copy range.
    pub payload: Vec<u8>,
}

impl NflogPacket {
    /// Decode one `NFULNL_MSG_PACKET` payload: the nfgenmsg, then the
    /// attributes. `None` for one too short to hold the nfgenmsg.
    pub(crate) fn parse(payload: &[u8]) -> Option<Self> {
        let (head, attrs) = (payload.get(..4)?, &payload[4..]);
        let mut packet = Self {
            family: head[0],
            group: u16::from_be_bytes([head[2], head[3]]),
            hw_protocol: 0,
            hook: 0,
            prefix: None,
            mark: None,
            timestamp: None,
            indev: None,
            outdev: None,
            physindev: None,
            physoutdev: None,
            hwaddr: None,
            uid: None,
            gid: None,
            payload: Vec::new(),
        };
        for (attr, value) in AttrIter::new(attrs) {
            match attr & 0x7FFF {
                NFULA_PACKET_HDR if value.len() >= 3 => {
                    packet.hw_protocol = u16::from_be_bytes([value[0], value[1]]);
                    packet.hook = value[2];
                }
                NFULA_MARK => packet.mark = get::u32_be(value).ok(),
                NFULA_TIMESTAMP if value.len() >= 16 => {
                    let sec = u64::from_be_bytes(value[..8].try_into().ok()?);
                    let usec = u64::from_be_bytes(value[8..16].try_into().ok()?);
                    packet.timestamp = Some(Duration::from_secs(sec) + Duration::from_micros(usec));
                }
                NFULA_IFINDEX_INDEV => packet.indev = get::u32_be(value).ok(),
                NFULA_IFINDEX_OUTDEV => packet.outdev = get::u32_be(value).ok(),
                NFULA_IFINDEX_PHYSINDEV => packet.physindev = get::u32_be(value).ok(),
                NFULA_IFINDEX_PHYSOUTDEV => packet.physoutdev = get::u32_be(value).ok(),
                // `hw_addrlen` (be16), two bytes of padding, then the address.
                NFULA_HWADDR if value.len() >= 4 => {
                    let len = usize::from(u16::from_be_bytes([value[0], value[1]]));
                    packet.hwaddr = value.get(4..4 + len).map(<[u8]>::to_vec);
                }
                NFULA_PAYLOAD => packet.payload = value.to_vec(),
                NFULA_PREFIX => {
                    packet.prefix = get::string(value).ok().map(str::to_string);
                }
                NFULA_UID => packet.uid = get::u32_be(value).ok(),
                NFULA_GID => packet.gid = get::u32_be(value).ok(),
                _ => {}
            }
        }
        Some(packet)
    }
}

/// The netlink message type of an `nfnetlink_log` message.
const fn msg_type(msg: u16) -> u16 {
    (NFNL_SUBSYS_ULOG << 8) | msg
}

#[nlink_macros::send_futures]
impl Connection<Nflog> {
    /// Receive group `group`'s packets on this connection (#528), each
    /// copied up to `copy_range` bytes (at most 0xffff). Read them with
    /// [`events`](Connection::events); a group has one listener at a time
    /// per namespace (`EBUSY` for a second).
    pub async fn bind_group(&self, group: u16, copy_range: u32) -> Result<()> {
        self.send_ack(config(group, NFULNL_CFG_CMD_BIND)).await?;
        let mut builder = config_message(group);
        let mut mode = copy_range.min(0xffff).to_be_bytes().to_vec();
        mode.extend_from_slice(&[NFULNL_COPY_PACKET, 0]);
        builder.append_attr(NFULA_CFG_MODE, &mode);
        self.send_ack(builder).await
    }

    /// Stop receiving group `group`'s packets.
    pub async fn unbind_group(&self, group: u16) -> Result<()> {
        self.send_ack(config(group, NFULNL_CFG_CMD_UNBIND)).await
    }
}

/// A config message for `group`, with no attributes yet.
fn config_message(group: u16) -> MessageBuilder {
    let mut builder = MessageBuilder::new(msg_type(NFULNL_MSG_CONFIG), NLM_F_REQUEST | NLM_F_ACK);
    // nfgenmsg: AF_UNSPEC, NFNETLINK_V0, the group as res_id (big-endian).
    let [hi, lo] = group.to_be_bytes();
    builder.append_bytes(&[0, 0, hi, lo]);
    builder
}

/// A config message for `group` carrying `command`.
fn config(group: u16, command: u8) -> MessageBuilder {
    let mut builder = config_message(group);
    builder.append_attr(NFULA_CFG_CMD, &[command]);
    builder
}

/// Whether a netlink message type is a logged packet.
pub(crate) fn is_packet(nlmsg_type: u16) -> bool {
    nlmsg_type == msg_type(NFULNL_MSG_PACKET)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A packet as `__build_packet_message` lays it out.
    #[test]
    fn a_logged_packet_decodes() {
        let mut b = MessageBuilder::new(0, 0);
        b.append_bytes(&[2, 0, 0, 5]); // NFPROTO_IPV4, group 5
        b.append_attr(NFULA_PACKET_HDR, &[0x08, 0x00, 1, 0]);
        b.append_attr(NFULA_MARK, &7u32.to_be_bytes());
        let mut ts = 1_700_000_000u64.to_be_bytes().to_vec();
        ts.extend(250_000u64.to_be_bytes());
        b.append_attr(NFULA_TIMESTAMP, &ts);
        b.append_attr(NFULA_IFINDEX_INDEV, &3u32.to_be_bytes());
        b.append_attr(NFULA_HWADDR, &[0, 6, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0]);
        b.append_attr(NFULA_PREFIX, b"lab: \0");
        b.append_attr(NFULA_PAYLOAD, &[0x45, 0, 0, 33]);
        let bytes = b.finish();
        let packet = NflogPacket::parse(&bytes[16..]).unwrap();
        assert_eq!((packet.family, packet.group, packet.hw_protocol, packet.hook), (2, 5, 0x0800, 1));
        assert_eq!(packet.mark, Some(7));
        assert_eq!(packet.timestamp, Some(Duration::from_secs(1_700_000_000) + Duration::from_millis(250)));
        assert_eq!(packet.indev, Some(3));
        assert_eq!(packet.hwaddr.as_deref(), Some(&[2, 0, 0, 0, 0, 1][..]));
        assert_eq!(packet.prefix.as_deref(), Some("lab: "));
        assert_eq!(packet.payload, [0x45, 0, 0, 33]);
        assert!(is_packet(0x0400));
        assert!(!is_packet(0x0401));
    }

    #[test]
    fn a_bind_names_the_group_in_res_id() {
        let bytes = config(0x0105, NFULNL_CFG_CMD_BIND).finish();
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]), 0x0401);
        assert_eq!(&bytes[16..20], [0, 0, 0x01, 0x05]);
        assert_eq!(&bytes[20..25], [5, 0, 1, 0, 1]);
    }
}
