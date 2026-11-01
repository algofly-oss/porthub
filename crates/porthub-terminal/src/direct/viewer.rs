//! Native guest transport. The caller must supply a policy-approved bound UDP
//! socket; no interface discovery, implicit STUN service or exit bypass occurs
//! here. Authorization/signaling continue through the authenticated gateway.
use super::{Event, Peer};
use crate::{
    delivery::{Frame, Message},
    protocol::*,
    viewer::{Incoming, Outbound, Viewer},
};
use anyhow::{ensure, Result};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;

#[derive(Debug)]
pub enum Stalled {
    Negotiation,
    Input,
}
impl std::fmt::Display for Stalled {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Negotiation => "native terminal negotiation timed out",
            Self::Input => "native terminal input acknowledgements stalled",
        })
    }
}
impl std::error::Error for Stalled {}

#[derive(Default, Clone, Copy, Debug)]
pub struct Traffic {
    /// Actual UDP bytes, including ICE/DTLS/SCTP overhead and retransmissions.
    pub udp_sent: u64,
    pub udp_received: u64,
}
struct Network {
    socket: UdpSocket,
    local: SocketAddr,
    peer: Box<Peer>,
    ready: bool,
    started: Instant,
    receive: Box<[u8]>,
}
pub struct Transport {
    viewer: Viewer,
    network: Option<Network>,
    offer_deadline: Option<Instant>,
    last_progress: Option<Instant>,
    output_ack_pending: bool,
    traffic: Traffic,
    direct_cursor: u64,
}
impl Transport {
    pub fn offer(socket: UdpSocket, read_only: bool) -> Result<(Self, ViewerInput)> {
        let local = socket.local_addr()?;
        ensure!(
            !local.ip().is_unspecified() && !local.ip().is_multicast() && local.port() != 0,
            "native terminal requires an approved concrete UDP address"
        );
        let now = Instant::now();
        let (peer, description) = Peer::offer(now, &[local], &[])?;
        let mut viewer = Viewer::new(read_only);
        let offer = viewer.begin_offer(1, DirectDescription(description))?;
        Ok((
            Self {
                viewer,
                network: Some(Network {
                    socket,
                    local,
                    peer: Box::new(peer),
                    ready: false,
                    started: now,
                    receive: vec![0; 65536].into_boxed_slice(),
                }),
                offer_deadline: Some(now + Duration::from_secs(15)),
                last_progress: None,
                output_ack_pending: false,
                traffic: Traffic::default(),
                direct_cursor: 0,
            },
            offer,
        ))
    }
    pub fn direct(&self) -> bool {
        self.network.as_ref().is_some_and(|network| network.ready)
    }
    pub fn traffic(&self) -> Traffic {
        self.traffic
    }
    pub fn input_capacity(&self) -> usize {
        self.viewer.input_capacity()
    }
    pub fn pending_input_bytes(&self) -> usize {
        self.viewer.pending_input_bytes()
    }
    pub fn legacy_output(&self, data: &str) -> Result<Vec<u8>> {
        self.viewer.legacy_output(data)
    }
    pub fn answer(&mut self, answer: &DirectAnswer) -> Result<Vec<ViewerInput>> {
        let queued = self.viewer.accept_answer(answer)?;
        self.offer_deadline = None;
        if let Some(network) = &mut self.network {
            if network
                .peer
                .accept_answer(Instant::now(), &answer.description.0)
                .is_err()
            {
                self.network = None;
            }
        }
        self.route(queued)
    }
    pub fn unavailable(&mut self, request: u32) -> Result<Vec<ViewerInput>> {
        let queued = self.viewer.unavailable(request)?;
        self.offer_deadline = None;
        self.network = None;
        self.route(queued)
    }
    pub fn input(&mut self, bytes: &[u8]) -> Result<Vec<ViewerInput>> {
        let packets = self.viewer.input(bytes)?;
        self.route(packets)
    }
    fn route(&mut self, packets: Vec<Outbound>) -> Result<Vec<ViewerInput>> {
        let mut relay = Vec::new();
        for packet in packets {
            match packet {
                Outbound::Gateway(input) => relay.push(input),
                Outbound::Packet(message) => {
                    if self.direct() {
                        let sequence = match &message {
                            Message::Data(frame) => Some(frame.sequence()),
                            _ => None,
                        };
                        if sequence.is_some_and(|sequence| sequence <= self.direct_cursor) {
                            continue;
                        }
                        let network = self.network.as_mut().unwrap();
                        let bytes = message.encode()?;
                        match network.peer.can_send(bytes.len()) {
                            Ok(false) if sequence.is_some() => {
                                // Healthy SCTP backpressure retains the unsent
                                // journal tail; it must not force a path switch.
                                self.watch_input();
                                return Ok(relay);
                            }
                            Ok(false) => {
                                // Output ACKs can use relay while input fills
                                // the direct sender, avoiding a circular stall.
                                relay.push(ViewerInput::Delivery {
                                    packet: DeliveryPacket::encode(&message)?,
                                });
                                continue;
                            }
                            Ok(true) if network.peer.send(Instant::now(), &bytes).is_ok() => {
                                if let Some(sequence) = sequence {
                                    self.direct_cursor = sequence;
                                }
                                continue;
                            }
                            _ => {}
                        }
                        relay.extend(self.fallback()?);
                        if sequence.is_none() {
                            relay.push(ViewerInput::Delivery {
                                packet: DeliveryPacket::encode(&message)?,
                            });
                        }
                        self.watch_input();
                        return Ok(relay);
                    }
                    relay.push(ViewerInput::Delivery {
                        packet: DeliveryPacket::encode(&message)?,
                    });
                }
            }
        }
        self.watch_input();
        Ok(relay)
    }
    fn watch_input(&mut self) {
        if self.offer_deadline.is_some() || self.viewer.pending_input_bytes() == 0 {
            self.last_progress = None;
        } else {
            self.last_progress.get_or_insert_with(Instant::now);
        }
    }
    pub fn receipt(&mut self, message: Message) -> Result<()> {
        let before = self.viewer.pending_input_bytes();
        match self.viewer.receive(message)? {
            Incoming::InputAcknowledged => {
                if self.viewer.pending_input_bytes() < before {
                    self.last_progress = Some(Instant::now());
                }
                self.watch_input();
            }
            Incoming::Output => self.output_ack_pending = true,
        }
        Ok(())
    }
    pub fn next_output(&self) -> Option<&Frame> {
        self.viewer.next_output()
    }
    pub fn commit_output(&mut self, sequence: u64) -> Result<()> {
        self.viewer.commit_output(sequence)
    }
    /// Call after the terminal accepts all currently contiguous output. Even a
    /// duplicate needs the existing cursor ACK; receipt alone never advances it.
    pub fn acknowledge_output(&mut self) -> Result<Vec<ViewerInput>> {
        if !self.output_ack_pending {
            return Ok(Vec::new());
        }
        let ack = self.viewer.output_acknowledgement()?;
        let routed = self.route(vec![Outbound::Packet(ack)])?;
        self.output_ack_pending = false;
        Ok(routed)
    }
    /// Force relay without resetting epochs or replaying acknowledged commands.
    /// The socket is closed, so failed ICE cannot keep an idle polling loop alive.
    pub fn fallback(&mut self) -> Result<Vec<ViewerInput>> {
        self.network = None;
        self.viewer
            .replay_input()
            .into_iter()
            .map(|packet| match packet {
                Outbound::Packet(message) => Ok(ViewerInput::Delivery {
                    packet: DeliveryPacket::encode(&message)?,
                }),
                _ => anyhow::bail!("invalid native terminal replay"),
            })
            .collect()
    }
    async fn flush(&mut self) -> Result<Vec<ViewerInput>> {
        if let Some(network) = &mut self.network {
            for _ in 0..256 {
                let Some((remote, bytes)) = network.peer.datagram() else {
                    return Ok(Vec::new());
                };
                match tokio::time::timeout(
                    Duration::from_millis(100),
                    network.socket.send_to(&bytes, remote),
                )
                .await
                {
                    Ok(Ok(count)) if count == bytes.len() => {
                        self.traffic.udp_sent = self.traffic.udp_sent.saturating_add(count as u64)
                    }
                    _ => return self.fallback(),
                }
            }
            anyhow::bail!("native terminal UDP output burst exceeds limit");
        }
        Ok(Vec::new())
    }
    /// Cancellation is safe: delivery/ACK deadlines live in this object, not in
    /// a particular read future. UDP itself may lose packets; journals and RTC
    /// retransmission handle that without inventing another shell command.
    pub async fn network(&mut self) -> Result<Vec<ViewerInput>> {
        let mut relay = if self.direct() {
            self.route(self.viewer.replay_input())?
        } else {
            Vec::new()
        };
        relay.extend(self.flush().await?);
        if !relay.is_empty() {
            return Ok(relay);
        }
        let mut deadline = self.offer_deadline;
        if let Some(network) = &mut self.network {
            if let Some(at) = network.peer.deadline() {
                deadline = Some(deadline.map_or(at, |old| old.min(at)));
            }
            if self.offer_deadline.is_none() && !network.ready {
                let at = network.started + Duration::from_secs(10);
                deadline = Some(deadline.map_or(at, |old| old.min(at)));
            }
        }
        if let Some(progress) = self.last_progress {
            let at = if self.direct() {
                progress.max(self.network.as_ref().unwrap().started) + Duration::from_secs(1)
            } else {
                progress + Duration::from_secs(15)
            };
            deadline = Some(deadline.map_or(at, |old| old.min(at)));
        }
        tokio::select! {
            packet=async {match &mut self.network {Some(network)=>network.socket.recv_from(&mut network.receive).await,None=>std::future::pending().await}}=>{
                let (count,remote)=match packet {Ok(packet)=>packet,Err(_)=>return self.fallback()};
                self.traffic.udp_received=self.traffic.udp_received.saturating_add(count as u64);
                if let Some(network)=&mut self.network {
                    // Unauthenticated garbage UDP must not kill the guest.
                    let _=network.peer.receive(Instant::now(),network.local,remote,&network.receive[..count]);
                }
            },
            _=async {match deadline {Some(at)=>tokio::time::sleep_until(at.into()).await,None=>std::future::pending().await}}=>{
                let now=Instant::now();
                ensure!(!self.offer_deadline.is_some_and(|at|now>=at),Stalled::Negotiation);
                if let Some(at)=self.last_progress {
                    ensure!(at.elapsed()<Duration::from_secs(15),Stalled::Input);
                    if self.direct() && at.max(self.network.as_ref().unwrap().started).elapsed()>=Duration::from_secs(1) {return self.fallback();}
                }
                if let Some(network)=&mut self.network {
                    if self.offer_deadline.is_none() && !network.ready && network.started.elapsed()>=Duration::from_secs(10) {
                        return self.fallback();
                    }
                    if network.peer.timeout(now).is_err() {return self.fallback();}
                }
            },
        }
        if let Some(network) = &mut self.network {
            while let Some(event) = network.peer.event()? {
                match event {
                    Event::Ready => {
                        network.ready = true;
                        network.started = Instant::now();
                        self.direct_cursor = 0;
                    }
                    Event::Closed => return self.fallback(),
                }
            }
        }
        let mut relay = Vec::new();
        loop {
            let bytes = match &mut self.network {
                Some(network) => network.peer.read()?,
                None => None,
            };
            let Some(bytes) = bytes else {
                break;
            };
            self.receipt(Message::parse(&bytes)?)?;
        }
        if self.direct() {
            relay.extend(self.route(self.viewer.replay_input())?);
        }
        relay.extend(self.flush().await?);
        Ok(relay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::Receiver;
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    };
    use tokio::sync::mpsc;
    use tokio_util::task::AbortOnDropHandle;
    enum Command {
        Send(Message),
        Relay(Message),
    }
    fn relay(input: ViewerInput) -> Result<Message> {
        match input {
            ViewerInput::Delivery { packet } => packet.decode(),
            _ => anyhow::bail!("sequenced delivery expected"),
        }
    }
    #[tokio::test]
    async fn real_udp_delivers_both_directions_then_ack_stall_replays_once_over_relay() -> Result<()>
    {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let (mut native, offer) = Transport::offer(socket, false)?;
        let ViewerInput::DirectOffer {
            request,
            description,
        } = offer
        else {
            unreachable!()
        };
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let local = socket.local_addr()?;
        let (mut host, description) = Peer::answer(Instant::now(), &description.0, &[local])?;
        let input_epoch = "a".repeat(32);
        let output_epoch = "b".repeat(32);
        assert!(native
            .answer(&DirectAnswer {
                request,
                description: DirectDescription(description),
                input_epoch: input_epoch.clone(),
                output_epoch: output_epoch.clone()
            })?
            .is_empty());
        let applied = Arc::new(Mutex::new(Vec::new()));
        let copy = applied.clone();
        let suppress_ack = Arc::new(AtomicBool::new(false));
        let suppress = suppress_ack.clone();
        let acknowledged = Arc::new(AtomicU64::new(0));
        let ack = acknowledged.clone();
        let (commands, mut command) = mpsc::channel(32);
        let (gateway, mut relayed) = mpsc::channel(32);
        let host_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut receive = Receiver::new(&input_epoch)?;
            let mut bytes = [0; 65536];
            let mut ready = false;
            loop {
                while let Some(event) = host.event()? {
                    match event {
                        Event::Ready => ready = true,
                        Event::Closed => return Ok::<_, anyhow::Error>(()),
                    }
                }
                while let Some((remote, bytes)) = host.datagram() {
                    socket.send_to(&bytes, remote).await?;
                }
                let deadline = host
                    .deadline()
                    .unwrap_or(Instant::now() + Duration::from_secs(60));
                let incoming = tokio::select! {
                    command=command.recv()=>match command {
                        Some(Command::Send(message))=>{ensure!(ready,"host not ready");host.send(Instant::now(),&message.encode()?)?;continue;},
                        Some(Command::Relay(message))=>Some((message,true)),
                        None=>return Ok(()),
                    },
                    packet=socket.recv_from(&mut bytes)=>{
                        let (count,remote)=packet?;let _=host.receive(Instant::now(),local,remote,&bytes[..count]);None
                    },
                    _=tokio::time::sleep_until(deadline.into())=>{host.timeout(Instant::now())?;None},
                };
                let mut messages = Vec::new();
                if let Some(message) = incoming {
                    messages.push(message);
                }
                while let Some(bytes) = host.read()? {
                    messages.push((Message::parse(&bytes)?, false));
                }
                for (message, is_relay) in messages {
                    match message {
                        Message::Data(frame) => {
                            receive.stage(frame)?;
                            while let Some(frame) = receive.next() {
                                copy.lock().unwrap().extend_from_slice(frame.payload());
                                receive.commit(frame.sequence())?;
                            }
                            if !suppress.load(Ordering::SeqCst) {
                                let message = Message::Ack {
                                    epoch: input_epoch.clone(),
                                    sequence: receive.acknowledged(),
                                };
                                if is_relay {
                                    gateway.send(message).await?;
                                } else {
                                    host.send(Instant::now(), &message.encode()?)?;
                                }
                            }
                        }
                        Message::Ack { epoch, sequence } => {
                            ensure!(epoch == output_epoch, "wrong output ACK");
                            ack.fetch_max(sequence, Ordering::SeqCst);
                        }
                    }
                }
            }
        }));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !native.direct() {
                assert!(native.network().await?.is_empty());
            }
            let mut first = vec![0xff; crate::delivery::MAX_BYTES];
            first[0] = 0;
            assert!(native.input(&first)?.is_empty());
            while native.pending_input_bytes() != 0 {
                assert!(native.network().await?.is_empty());
            }
            assert!(
                native.direct(),
                "a full input window must not cause fallback from healthy SCTP backpressure"
            );
            commands
                .send(Command::Send(Message::Data(Frame::new(
                    &"b".repeat(32),
                    2,
                    b"tail",
                )?)))
                .await?;
            commands
                .send(Command::Send(Message::Data(Frame::new(
                    &"b".repeat(32),
                    1,
                    b"head",
                )?)))
                .await?;
            while native.next_output().is_none() {
                assert!(native.network().await?.is_empty());
            }
            assert_eq!(
                acknowledged.load(Ordering::SeqCst),
                0,
                "receipt must not ACK terminal acceptance"
            );
            let mut output = Vec::new();
            while let Some(frame) = native.next_output() {
                let sequence = frame.sequence();
                output.extend_from_slice(frame.payload());
                native.commit_output(sequence)?;
            }
            // The second UDP message can arrive in a later readiness turn.
            while output.len() < 8 {
                assert!(native.network().await?.is_empty());
                while let Some(frame) = native.next_output() {
                    let sequence = frame.sequence();
                    output.extend_from_slice(frame.payload());
                    native.commit_output(sequence)?;
                }
            }
            assert_eq!(output, b"headtail");
            assert!(native.acknowledge_output()?.is_empty());
            // Flush without requiring any application output from the host.
            let _ = tokio::time::timeout(Duration::from_millis(30), native.network()).await;
            assert_eq!(acknowledged.load(Ordering::SeqCst), 2);
            suppress_ack.store(true, Ordering::SeqCst);
            assert!(native.input(b"second\r")?.is_empty());
            let replay = loop {
                let relay = native.network().await?;
                if !relay.is_empty() {
                    break relay;
                }
            };
            assert!(!native.direct());
            assert_eq!(replay.len(), 1);
            suppress_ack.store(false, Ordering::SeqCst);
            commands
                .send(Command::Relay(relay(replay.into_iter().next().unwrap())?))
                .await?;
            native.receipt(relayed.recv().await.unwrap())?;
            assert_eq!(native.pending_input_bytes(), 0);
            let mut expected = first;
            expected.extend_from_slice(b"second\r");
            ensure!(
                *applied.lock().unwrap() == expected,
                "relay replay executed input twice or a full paste lost its unsent suffix"
            );
            let frame = Frame::new(&"b".repeat(32), 3, b"after fallback")?;
            native.receipt(Message::Data(frame.clone()))?;
            native.receipt(Message::Data(frame))?;
            assert_eq!(native.next_output().unwrap().payload(), b"after fallback");
            native.commit_output(3)?;
            assert!(native.next_output().is_none());
            let ack = native.acknowledge_output()?;
            assert!(matches!(
                relay(ack.into_iter().next().unwrap())?,
                Message::Ack { sequence: 3, .. }
            ));
            assert!(native.traffic().udp_sent > 0 && native.traffic().udp_received > 0);
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        drop(host_task);
        Ok(())
    }
    #[tokio::test]
    async fn unavailable_is_legacy_and_idle_and_approved_addresses_and_roles_are_required(
    ) -> Result<()> {
        assert!(Transport::offer(UdpSocket::bind("0.0.0.0:0").await?, false).is_err());
        let (mut native, _) = Transport::offer(UdpSocket::bind("127.0.0.1:0").await?, false)?;
        assert!(native.input(b"queued\r")?.is_empty());
        let queued = native.unavailable(1)?;
        assert!(
            matches!(&queued[..],[ViewerInput::Input {data}] if decode_data(data).unwrap()==b"queued\r")
        );
        assert_eq!(native.pending_input_bytes(), 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), native.network())
                .await
                .is_err(),
            "idle relay must not poll"
        );
        assert_eq!(native.legacy_output(&encode_data(b"legacy"))?, b"legacy");
        let (mut reader, _) = Transport::offer(UdpSocket::bind("127.0.0.1:0").await?, true)?;
        assert_eq!(reader.input_capacity(), 0);
        assert!(reader.input(b"forbidden").is_err());
        assert!(reader.unavailable(2).is_err());
        assert!(reader.unavailable(1)?.is_empty());
        assert!(reader.input(b"still forbidden").is_err());
        Ok(())
    }
    #[tokio::test]
    async fn lost_answers_and_stalled_input_are_bounded_and_failed_ice_becomes_idle_relay(
    ) -> Result<()> {
        let (mut pending, _) = Transport::offer(UdpSocket::bind("127.0.0.1:0").await?, false)?;
        pending.input(b"uncertain")?;
        pending.offer_deadline = Some(Instant::now() - Duration::from_secs(1));
        let error = pending.network().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Stalled>(),
            Some(Stalled::Negotiation)
        ));
        assert_eq!(
            pending.pending_input_bytes(),
            9,
            "lost answer cannot flush uncertain bytes as legacy input"
        );
        let (mut native, offer) = Transport::offer(UdpSocket::bind("127.0.0.1:0").await?, false)?;
        let ViewerInput::DirectOffer {
            request,
            description,
        } = offer
        else {
            unreachable!()
        };
        let host_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let (_host, answer) =
            Peer::answer(Instant::now(), &description.0, &[host_socket.local_addr()?])?;
        native.answer(&DirectAnswer {
            request,
            description: DirectDescription(answer),
            input_epoch: "a".repeat(32),
            output_epoch: "b".repeat(32),
        })?;
        native.network.as_mut().unwrap().started = Instant::now() - Duration::from_secs(11);
        assert!(native.network().await?.is_empty());
        assert!(
            native.network.is_none(),
            "failed ICE must release its socket and polling timers"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), native.network())
                .await
                .is_err()
        );
        assert!(
            native.legacy_output(&encode_data(b"legacy")).is_err(),
            "negotiated relay retains sequenced framing"
        );
        assert_eq!(native.input(b"waiting")?.len(), 1);
        native.last_progress = Some(Instant::now() - Duration::from_secs(16));
        let error = native.network().await.unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Stalled>(),
            Some(Stalled::Input)
        ));
        Ok(())
    }
}
