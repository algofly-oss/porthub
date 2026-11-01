//! Browser-compatible transport engine. Signaling must already be authorized by
//! the terminal gateway; this engine never grants a role or opens a shell.
//! Kept behind `direct` while native joins and release gates are completed.
pub use crate::delivery as replay;
#[cfg(unix)]
pub mod host;

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
        transport::{
            CandidateConfig, CandidateHostConfig, CandidateServerReflexiveConfig, RTCIceCandidate,
        },
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
        Self::answer_reflexive(now, offer, candidates, &[])
    }
    pub fn answer_reflexive(
        now: Instant,
        offer: &str,
        candidates: &[SocketAddr],
        reflexive: &[(SocketAddr, SocketAddr)],
    ) -> Result<(Self, String)> {
        let offer = description(offer, RTCSdpType::Offer)?;
        ensure!(
            !candidates.is_empty() && candidates.len() + reflexive.len() <= 64,
            "invalid terminal candidates"
        );
        let mut connection = new_connection(now)?;
        connection.set_remote_description(now, offer)?;
        add_candidates(&mut connection, candidates, reflexive)?;
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
    /// Begin an authenticated native guest's one-channel negotiation. The
    /// caller owns sockets and signaling, just as for the host answerer.
    pub fn offer(
        now: Instant,
        candidates: &[SocketAddr],
        reflexive: &[(SocketAddr, SocketAddr)],
    ) -> Result<(Self, String)> {
        ensure!(
            !candidates.is_empty() && candidates.len() + reflexive.len() <= 64,
            "invalid terminal candidates"
        );
        let mut connection = new_connection(now)?;
        connection.create_data_channel(LABEL, None)?;
        add_candidates(&mut connection, candidates, reflexive)?;
        let offer = connection.create_offer(None)?;
        connection.set_local_description(now, offer)?;
        let offer = serde_json::to_string(
            &connection
                .local_description()
                .context("terminal offer unavailable")?,
        )?;
        ensure!(offer.len() <= MAX_SDP, "terminal offer exceeds limit");
        Ok((
            Self {
                connection,
                channel: None,
            },
            offer,
        ))
    }
    pub fn accept_answer(&mut self, now: Instant, answer: &str) -> Result<()> {
        self.connection
            .set_remote_description(now, description(answer, RTCSdpType::Answer)?)?;
        Ok(())
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
        self.datagram_from()
            .map(|(_, remote, bytes)| (remote, bytes))
    }
    pub fn datagram_from(&mut self) -> Option<(SocketAddr, SocketAddr, BytesMut)> {
        self.connection.poll_write().map(|packet| {
            (
                packet.transport.local_addr,
                packet.transport.peer_addr,
                packet.message,
            )
        })
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

fn new_connection(now: Instant) -> Result<RTCPeerConnection> {
    let settings = SettingEngineBuilder::new()
        .with_sctp_max_receive_buffer_size(MAX_OUTSTANDING as u32)
        .build();
    Ok(RTCPeerConnectionBuilder::new()
        .with_setting_engine(settings)
        .build(now)?)
}
fn description(text: &str, kind: RTCSdpType) -> Result<RTCSessionDescription> {
    ensure!(text.len() <= MAX_SDP, "terminal description exceeds limit");
    let description: RTCSessionDescription =
        serde_json::from_str(text).map_err(|_| anyhow::anyhow!("invalid terminal description"))?;
    ensure!(
        description.sdp_type == kind,
        "unexpected terminal description type"
    );
    let media: Vec<_> = description
        .sdp
        .lines()
        .filter(|line| line.starts_with("m="))
        .collect();
    ensure!(
        media.len() == 1 && media[0].starts_with("m=application "),
        "terminal transport accepts one data channel media section only"
    );
    Ok(description)
}
fn add_candidates(
    connection: &mut RTCPeerConnection,
    candidates: &[SocketAddr],
    reflexive: &[(SocketAddr, SocketAddr)],
) -> Result<()> {
    ensure!(
        !candidates.is_empty() && candidates.len() + reflexive.len() <= 64,
        "invalid terminal candidates"
    );
    for address in candidates {
        ensure!(
            address.port() != 0 && !address.ip().is_unspecified() && !address.ip().is_multicast(),
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
    ensure!(
        candidates.len() + reflexive.len() <= 64,
        "too many terminal candidates"
    );
    for (mapped, base) in reflexive {
        ensure!(
            mapped.port() != 0
                && !mapped.ip().is_unspecified()
                && !mapped.ip().is_multicast()
                && candidates.contains(base),
            "invalid reflexive terminal candidate"
        );
        let candidate = CandidateServerReflexiveConfig {
            base_config: CandidateConfig {
                network: "udp".into(),
                address: mapped.ip().to_string(),
                port: mapped.port(),
                component: 1,
                ..Default::default()
            },
            rel_addr: base.ip().to_string(),
            rel_port: base.port(),
            ..Default::default()
        }
        .new_candidate_server_reflexive()?;
        connection.add_local_candidate(RTCIceCandidate::from(&candidate).to_json()?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_offer_and_host_answer_exchange_binary_data_without_external_io() -> Result<()> {
        use crate::delivery::{Frame, Message};
        let mut now = Instant::now();
        let viewer_address: SocketAddr = "127.0.0.1:31001".parse()?;
        let host_address: SocketAddr = "127.0.0.1:31002".parse()?;
        let (mut viewer, offer) = Peer::offer(now, &[viewer_address], &[])?;
        let (mut host, answer) = Peer::answer(now, &offer, &[host_address])?;
        viewer.accept_answer(now, &answer)?;
        let input = Message::Data(Frame::new(&"a".repeat(32), 1, b"native\0\xff")?).encode()?;
        let output =
            Message::Data(Frame::new(&"b".repeat(32), 1, b"shell output\r\n")?).encode()?;
        let (mut viewer_ready, mut host_ready, mut sent) = (false, false, false);
        let (mut received_input, mut received_output) = (Vec::new(), Vec::new());
        // Pump the actual ICE/DTLS/SCTP engines in memory. These synthetic
        // endpoints never bind a socket or send a packet outside the test.
        for _ in 0..5000 {
            now += std::time::Duration::from_millis(1);
            while let Some((source, destination, bytes)) = viewer.datagram_from() {
                assert_eq!(destination, host_address);
                host.receive(now, host_address, source, &bytes)?;
            }
            while let Some((source, destination, bytes)) = host.datagram_from() {
                assert_eq!(destination, viewer_address);
                viewer.receive(now, viewer_address, source, &bytes)?;
            }
            for (peer, ready) in [
                (&mut viewer, &mut viewer_ready),
                (&mut host, &mut host_ready),
            ] {
                if peer.deadline().is_some_and(|at| at <= now) {
                    peer.timeout(now)?;
                }
                while let Some(event) = peer.event()? {
                    match event {
                        Event::Ready => *ready = true,
                        Event::Closed => anyhow::bail!("native peer closed before delivery"),
                    }
                }
            }
            if viewer_ready && host_ready && !sent {
                viewer.send(now, &input)?;
                host.send(now, &output)?;
                sent = true;
            }
            while let Some(bytes) = viewer.read()? {
                received_output.push(bytes);
            }
            while let Some(bytes) = host.read()? {
                received_input.push(bytes);
            }
            if !received_input.is_empty() && !received_output.is_empty() {
                break;
            }
        }
        assert!(
            viewer_ready && host_ready && sent,
            "native negotiation did not open both ordered channels"
        );
        assert_eq!(received_input, vec![input]);
        assert_eq!(received_output, vec![output]);
        viewer.close()?;
        host.close()?;
        Ok(())
    }

    #[test]
    fn native_guest_rejects_invalid_candidates_and_answer_media_before_use() -> Result<()> {
        let now = Instant::now();
        let local = "127.0.0.1:31001".parse()?;
        assert!(Peer::offer(now, &[], &[]).is_err());
        assert!(Peer::offer(now, &["0.0.0.0:31001".parse()?], &[]).is_err());
        assert!(Peer::offer(now, &vec![local; 65], &[]).is_err());
        let (mut peer, offer) = Peer::offer(now, &[local], &[])?;
        assert!(peer.accept_answer(now, &offer).is_err());
        assert!(peer.accept_answer(now, &"x".repeat(MAX_SDP + 1)).is_err());
        let (_, answer) = Peer::answer(now, &offer, &["127.0.0.1:31002".parse()?])?;
        let mut wrong: serde_json::Value = serde_json::from_str(&answer)?;
        wrong["sdp"] = wrong["sdp"]
            .as_str()
            .unwrap()
            .replace("m=application ", "m=audio ")
            .into();
        assert!(peer.accept_answer(now, &wrong.to_string()).is_err());
        assert!(peer.send(now, b"not open").is_err());
        peer.accept_answer(now, &answer)?;
        assert!(
            peer.accept_answer(now, &answer).is_err(),
            "stale answers cannot renegotiate a stable peer"
        );
        peer.close()?;
        Ok(())
    }
    fn offer() -> Result<String> {
        let mut connection = RTCPeerConnectionBuilder::new().build(Instant::now())?;
        connection.create_data_channel(LABEL, None)?;
        Ok(serde_json::to_string(&connection.create_offer(None)?)?)
    }
    #[test]
    fn reflexive_candidates_keep_their_bound_socket_and_appear_in_the_answer() -> Result<()> {
        let base = "127.0.0.1:12345".parse()?;
        let mapped = "203.0.113.9:23456".parse()?;
        let offer = offer()?;
        let (mut peer, answer) =
            Peer::answer_reflexive(Instant::now(), &offer, &[base], &[(mapped, base)])?;
        assert!(answer.contains("typ srflx") && answer.contains("203.0.113.9"));
        assert!(Peer::answer_reflexive(
            Instant::now(),
            &offer,
            &[base],
            &[(mapped, "127.0.0.2:12345".parse()?)]
        )
        .is_err());
        peer.close()?;
        Ok(())
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
