//! Browser-compatible transport engine. Signaling must already be authorized by
//! the terminal gateway; this engine never grants a role or opens a shell.
//! Kept behind `direct` until signaling and relay handover are integrated.
pub mod replay;

use anyhow::{ensure, Context, Result};
use bytes::BytesMut;
use rtc::{
    data_channel::RTCDataChannelId,
    peer_connection::{
        configuration::setting_engine::SettingEngineBuilder,
        event::{RTCDataChannelEvent, RTCPeerConnectionEvent},
        message::{RTCMessage, TaggedRTCMessage},
        sdp::{RTCSdpType, RTCSessionDescription},
        state::RTCPeerConnectionState,
        transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate},
        RTCPeerConnection, RTCPeerConnectionBuilder,
    },
    sansio::Protocol,
    shared::{TaggedBytesMut, TransportContext, TransportProtocol},
};
use std::{net::SocketAddr, time::Instant};

pub const LABEL: &str = "porthub-terminal/1";
pub const MAX_FRAME: usize = 32 * 1024;
pub const MAX_OUTSTANDING: usize = 64 * 1024;
const MAX_SDP: usize = 64 * 1024;

pub enum Event {
    Ready,
    Closed,
}
/// One guest, one reliable ordered channel. It owns no sockets, timers or tasks.
pub struct Peer {
    connection: RTCPeerConnection,
    channel: Option<RTCDataChannelId>,
}
impl Peer {
    /// Accept an authenticated offer using candidates gathered by the caller.
    pub fn answer(now: Instant, offer: &str, candidates: &[SocketAddr]) -> Result<(Self, String)> {
        ensure!(offer.len() <= MAX_SDP, "terminal offer exceeds limit");
        ensure!(
            !candidates.is_empty() && candidates.len() <= 64,
            "invalid terminal candidates"
        );
        let offer: RTCSessionDescription =
            serde_json::from_str(offer).context("invalid terminal offer")?;
        ensure!(
            offer.sdp_type == RTCSdpType::Offer,
            "terminal signaling requires an offer"
        );
        let media: Vec<_> = offer
            .sdp
            .lines()
            .filter(|line| line.starts_with("m="))
            .collect();
        ensure!(
            media.len() == 1 && media[0].starts_with("m=application "),
            "terminal transport accepts one data channel media section only"
        );
        let settings = SettingEngineBuilder::new()
            .with_sctp_max_receive_buffer_size(MAX_OUTSTANDING as u32)
            .build();
        let mut connection = RTCPeerConnectionBuilder::new()
            .with_setting_engine(settings)
            .build(now)?;
        connection.set_remote_description(now, offer)?;
        for address in candidates {
            ensure!(
                address.port() != 0
                    && !address.ip().is_unspecified()
                    && !address.ip().is_multicast(),
                "invalid terminal candidate address"
            );
            let candidate = CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".into(),
                    address: address.ip().to_string(),
                    port: address.port(),
                    component: 1,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host()?;
            connection.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;
        }
        let answer = connection.create_answer(None)?;
        connection.set_local_description(now, answer)?;
        let answer = serde_json::to_string(
            &connection
                .local_description()
                .context("terminal answer unavailable")?,
        )?;
        ensure!(answer.len() <= MAX_SDP, "terminal answer exceeds limit");
        Ok((
            Self {
                connection,
                channel: None,
            },
            answer,
        ))
    }
    pub fn receive(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        bytes: &[u8],
    ) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 65535,
            "invalid terminal datagram"
        );
        self.connection.handle_read(TaggedBytesMut {
            now,
            transport: TransportContext {
                local_addr: local,
                peer_addr: remote,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: BytesMut::from(bytes),
        })?;
        Ok(())
    }
    pub fn datagram(&mut self) -> Option<(SocketAddr, BytesMut)> {
        self.connection
            .poll_write()
            .map(|packet| (packet.transport.peer_addr, packet.message))
    }
    pub fn deadline(&mut self) -> Option<Instant> {
        self.connection.poll_timeout()
    }
    pub fn timeout(&mut self, now: Instant) -> Result<()> {
        self.connection.handle_timeout(now)?;
        Ok(())
    }
    pub fn event(&mut self) -> Result<Option<Event>> {
        while let Some(event) = self.connection.poll_event() {
            match event {
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnOpen(id)) => {
                    ensure!(
                        self.channel.is_none(),
                        "multiple terminal channels are not allowed"
                    );
                    let channel = self
                        .connection
                        .data_channel(id)
                        .context("terminal channel unavailable")?;
                    ensure!(
                        channel.label() == LABEL
                            && channel.ordered()
                            && channel.max_retransmits().is_none()
                            && channel.max_packet_life_time().is_none(),
                        "invalid terminal channel"
                    );
                    self.channel = Some(id);
                    return Ok(Some(Event::Ready));
                }
                RTCPeerConnectionEvent::OnDataChannel(RTCDataChannelEvent::OnClose(_))
                | RTCPeerConnectionEvent::OnConnectionStateChangeEvent(
                    RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed,
                ) => return Ok(Some(Event::Closed)),
                _ => {}
            }
        }
        Ok(None)
    }
    pub fn read(&mut self) -> Result<Option<Vec<u8>>> {
        while let Some(TaggedRTCMessage { message, .. }) = self.connection.poll_read() {
            match message {
                RTCMessage::DataChannelMessage(id, message) => {
                    ensure!(Some(id) == self.channel, "terminal channel is not ready");
                    ensure!(
                        message.data.len() <= MAX_FRAME,
                        "terminal frame exceeds limit"
                    );
                    return Ok(Some(message.data.to_vec()));
                }
                _ => anyhow::bail!("terminal transport does not accept media"),
            }
        }
        Ok(None)
    }
    pub fn send(&mut self, now: Instant, bytes: &[u8]) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_FRAME,
            "invalid terminal frame size"
        );
        let id = self.channel.context("terminal channel is not ready")?;
        let mut channel = self
            .connection
            .data_channel(id)
            .context("terminal channel unavailable")?;
        ensure!(
            channel.outstanding_bytes() + bytes.len() <= MAX_OUTSTANDING,
            "terminal channel is backpressured"
        );
        channel.send(now, BytesMut::from(bytes))?;
        Ok(())
    }
    pub fn close(&mut self) -> Result<()> {
        self.connection.close()?;
        self.channel = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn offer() -> Result<String> {
        let mut connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
        connection.create_data_channel(LABEL, None)?;
        Ok(serde_json::to_string(&connection.create_offer(None)?)?)
    }
    #[test]
    fn direct_offer_and_candidate_limits_are_enforced_before_channel_use() -> Result<()> {
        let local = "127.0.0.1:12345".parse()?;
        let offer = offer()?;
        assert!(Peer::answer(Instant::now(), &"x".repeat(MAX_SDP + 1), &[local]).is_err());
        assert!(Peer::answer(Instant::now(), &offer, &[]).is_err());
        assert!(Peer::answer(Instant::now(), &offer, &vec![local; 65]).is_err());
        for address in ["0.0.0.0:12345", "224.0.0.1:12345", "127.0.0.1:0"] {
            assert!(Peer::answer(Instant::now(), &offer, &[address.parse()?]).is_err());
        }
        let mut wrong: serde_json::Value = serde_json::from_str(&offer)?;
        wrong["type"] = "answer".into();
        assert!(Peer::answer(Instant::now(), &wrong.to_string(), &[local]).is_err());
        wrong = serde_json::from_str(&offer)?;
        wrong["sdp"] = wrong["sdp"]
            .as_str()
            .unwrap()
            .replace("m=application ", "m=audio ")
            .into();
        assert!(Peer::answer(Instant::now(), &wrong.to_string(), &[local]).is_err());
        let (mut peer, _) = Peer::answer(Instant::now(), &offer, &[local])?;
        assert!(peer.send(Instant::now(), b"premature input").is_err());
        assert!(peer.send(Instant::now(), &vec![0; MAX_FRAME + 1]).is_err());
        assert!(peer.receive(Instant::now(), local, local, &[]).is_err());
        peer.close()?;
        Ok(())
    }
}
