use anyhow::{ensure, Result};
use bytes::{Bytes, BytesMut};
use rtc_crypto::RTCCryptoProvider;
use rtc_dtls::{
    cipher_suite::CipherSuiteId,
    config::{ClientAuthType, ConfigBuilder, ExtendedMasterSecretType, HandshakeConfig},
    crypto::Certificate,
    endpoint::{Endpoint, EndpointEvent},
};
use rtc_ice::{
    agent::{agent_config::AgentConfig, Event},
    candidate::{
        candidate_host::CandidateHostConfig, candidate_relay::CandidateRelayConfig,
        candidate_server_reflexive::CandidateServerReflexiveConfig, unmarshal_candidate,
        CandidateConfig,
    },
    mdns::MulticastDnsMode,
    state::ConnectionState,
    Agent,
};
use rtc_shared::{TransportContext, TransportMessage, TransportProtocol};
use sansio::Protocol;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fmt,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

const LABEL: &str = "a=porthub-transport:dtls1";
const MAX_CANDIDATES: usize = 64;
const VIRTUAL_REMOTE: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 1);
fn safe<T, E>(result: std::result::Result<T, E>, message: &'static str) -> Result<T> {
    result.map_err(|_| anyhow::anyhow!(message))
}
fn fingerprint(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn pin(value: &str) -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    let parts: Vec<_> = value.split(':').collect();
    ensure!(
        parts.len() == 32,
        "invalid enrolled certificate fingerprint"
    );
    for (byte, part) in bytes.iter_mut().zip(parts) {
        ensure!(part.len() == 2, "invalid enrolled certificate fingerprint");
        *byte = safe(
            u8::from_str_radix(part, 16),
            "invalid enrolled certificate fingerprint",
        )?;
    }
    Ok(bytes)
}
fn id(value: &str) -> bool {
    (1..=60).contains(&value.len())
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_:".contains(&c))
}

#[derive(Clone)]
pub struct Identity {
    certificate: Certificate,
    provider: Arc<dyn RTCCryptoProvider>,
    fingerprint: String,
}
impl Identity {
    pub fn new() -> Result<Self> {
        let provider = safe(
            rtc_crypto::default_provider(),
            "private crypto provider unavailable",
        )?;
        let certificate = safe(
            Certificate::generate_self_signed(
                vec!["private.porthub.invalid".into()],
                provider.crypto(),
            ),
            "private certificate generation failed",
        )?;
        let fingerprint = fingerprint(certificate.certificate[0].as_ref());
        Ok(Self {
            certificate,
            provider,
            fingerprint,
        })
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Offer,
    Answer,
    Candidate,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Description {
    pub r#type: Kind,
    pub sdp: String,
}
impl fmt::Debug for Description {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Description")
            .field("type", &self.r#type)
            .finish_non_exhaustive()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Waiting,
    Connecting,
    Ready,
    Failed,
    Closed,
}
pub struct Datagram {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub bytes: BytesMut,
}
impl fmt::Debug for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Datagram")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

pub struct Peer {
    local_id: String,
    remote_id: String,
    identity: Identity,
    pin: [u8; 32],
    local: SocketAddr,
    ice: Agent,
    dtls: Endpoint,
    config: Arc<HandshakeConfig>,
    verified: Arc<AtomicBool>,
    controlling: bool,
    started: bool,
    remote_credentials: Option<(String, String)>,
    state: State,
    deadline: Option<Instant>,
    ice_tick: Option<Instant>,
    packets: VecDeque<Bytes>,
    last_pair: Option<(SocketAddr, SocketAddr)>,
}
impl Peer {
    pub fn new(
        now: Instant,
        local: SocketAddr,
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        expected_fingerprint: &str,
    ) -> Result<Self> {
        Self::new_transport(
            now,
            local,
            local_id,
            remote_id,
            identity,
            expected_fingerprint,
            false,
        )
    }
    pub fn new_relay(
        now: Instant,
        local: SocketAddr,
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        expected_fingerprint: &str,
    ) -> Result<Self> {
        Self::new_transport(
            now,
            local,
            local_id,
            remote_id,
            identity,
            expected_fingerprint,
            true,
        )
    }
    fn new_transport(
        now: Instant,
        local: SocketAddr,
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        expected_fingerprint: &str,
        relay: bool,
    ) -> Result<Self> {
        ensure!(
            id(local_id) && id(remote_id) && local_id != remote_id,
            "invalid private peer identities"
        );
        ensure!(
            !local.ip().is_unspecified() && local.port() != 0,
            "private candidate needs a bound interface address"
        );
        let pin = pin(expected_fingerprint)?;
        let controlling = local_id < remote_id;
        let verified = Arc::new(AtomicBool::new(false));
        let verified_clone = verified.clone();
        let config = ConfigBuilder::default()
            .with_crypto_provider(identity.provider.clone())
            .with_certificates(vec![identity.certificate.clone()])
            .with_cipher_suites(vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256])
            .with_client_auth(ClientAuthType::RequireAnyClientCert)
            .with_extended_master_secret(ExtendedMasterSecretType::Require)
            .with_insecure_skip_verify(true)
            .with_mtu(1450)
            .with_verify_peer_certificate(Some(Arc::new(move |raw, _| {
                let Some(leaf) = raw.first() else {
                    return Err(rtc_shared::error::Error::Other(
                        "missing enrolled certificate".into(),
                    ));
                };
                let actual: [u8; 32] = Sha256::digest(leaf).into();
                if actual != pin {
                    return Err(rtc_shared::error::Error::Other(
                        "enrolled certificate mismatch".into(),
                    ));
                }
                verified_clone.store(true, Ordering::Release);
                Ok(())
            })))
            .build(controlling, Some(VIRTUAL_REMOTE));
        let config = Arc::new(safe(config, "private DTLS configuration rejected")?);
        let mut ice = safe(
            Agent::new(
                now,
                Arc::new(AgentConfig {
                    multicast_dns_mode: MulticastDnsMode::Disabled,
                    disconnected_timeout: Some(Duration::from_secs(5)),
                    failed_timeout: Some(Duration::from_secs(12)),
                    keepalive_interval: Some(Duration::from_secs(2)),
                    ..Default::default()
                }),
                identity.provider.clone(),
            ),
            "private ICE configuration rejected",
        )?;
        let base_config = CandidateConfig {
            network: "udp".into(),
            address: local.ip().to_string(),
            port: local.port(),
            component: 1,
            priority: (if relay { 0u32 } else { 126u32 } << 24) + (65535u32 << 8) + 255,
            ..Default::default()
        };
        let candidate = if relay {
            safe(
                CandidateRelayConfig {
                    base_config,
                    rel_addr: "0.0.0.0".into(),
                    rel_port: 0,
                    ..Default::default()
                }
                .new_candidate_relay(),
                "private relay candidate rejected",
            )?
        } else {
            safe(
                CandidateHostConfig {
                    base_config,
                    ..Default::default()
                }
                .new_candidate_host(),
                "private host candidate rejected",
            )?
        };
        safe(
            ice.add_local_candidate(candidate),
            "private candidate rejected",
        )?;
        let dtls = Endpoint::new(
            local,
            TransportProtocol::UDP,
            if controlling {
                None
            } else {
                Some(config.clone())
            },
        );
        Ok(Self {
            local_id: local_id.into(),
            remote_id: remote_id.into(),
            identity,
            pin,
            local,
            ice,
            dtls,
            config,
            verified,
            controlling,
            started: false,
            remote_credentials: None,
            state: State::Waiting,
            deadline: None,
            ice_tick: None,
            packets: VecDeque::new(),
            last_pair: None,
        })
    }
    pub fn add_interface(&mut self, local: SocketAddr) -> Result<()> {
        ensure!(
            !self.started && self.ice.get_local_candidates().len() < 16,
            "private interface limit exceeded"
        );
        ensure!(
            local.is_ipv4() && !local.ip().is_unspecified() && local.port() != 0,
            "invalid private interface"
        );
        let candidate = safe(
            CandidateHostConfig {
                base_config: CandidateConfig {
                    network: "udp".into(),
                    address: local.ip().to_string(),
                    port: local.port(),
                    component: 1,
                    priority: (126u32 << 24)
                        + ((65535u32 - self.ice.get_local_candidates().len() as u32) << 8)
                        + 255,
                    ..Default::default()
                },
                ..Default::default()
            }
            .new_candidate_host(),
            "private host candidate rejected",
        )?;
        safe(
            self.ice.add_local_candidate(candidate),
            "private host candidate rejected",
        )?;
        Ok(())
    }
    pub fn add_reflexive(&mut self, base: SocketAddr, mapped: SocketAddr) -> Result<()> {
        ensure!(
            !self.started && self.ice.get_local_candidates().len() < MAX_CANDIDATES,
            "private candidate limit exceeded"
        );
        ensure!(
            mapped.is_ipv4()
                && !mapped.ip().is_unspecified()
                && !mapped.ip().is_multicast()
                && mapped.port() != 0
                && self
                    .ice
                    .get_local_candidates()
                    .iter()
                    .any(|candidate| candidate.addr() == base),
            "invalid private reflexive candidate"
        );
        if self
            .ice
            .get_local_candidates()
            .iter()
            .any(|candidate| candidate.addr() == mapped)
        {
            return Ok(());
        }
        let candidate = safe(
            CandidateServerReflexiveConfig {
                base_config: CandidateConfig {
                    network: "udp".into(),
                    address: mapped.ip().to_string(),
                    port: mapped.port(),
                    component: 1,
                    priority: (100u32 << 24) + (65535u32 << 8) + 255,
                    ..Default::default()
                },
                rel_addr: base.ip().to_string(),
                rel_port: base.port(),
                ..Default::default()
            }
            .new_candidate_server_reflexive(),
            "private reflexive candidate rejected",
        )?;
        safe(
            self.ice.add_local_candidate(candidate),
            "private reflexive candidate rejected",
        )?;
        Ok(())
    }
    pub fn add_relay(&mut self, local: SocketAddr) -> Result<()> {
        ensure!(
            !self.started && self.ice.get_local_candidates().len() < MAX_CANDIDATES,
            "private candidate limit exceeded"
        );
        ensure!(
            local.is_ipv4() && !local.ip().is_unspecified() && local.port() != 0,
            "invalid private relay address"
        );
        let candidate = safe(
            CandidateRelayConfig {
                base_config: CandidateConfig {
                    network: "udp".into(),
                    address: local.ip().to_string(),
                    port: local.port(),
                    component: 1,
                    priority: (65535u32 << 8) + 255,
                    ..Default::default()
                },
                rel_addr: "0.0.0.0".into(),
                rel_port: 0,
                ..Default::default()
            }
            .new_candidate_relay(),
            "private relay candidate rejected",
        )?;
        safe(
            self.ice.add_local_candidate(candidate),
            "private relay candidate rejected",
        )?;
        Ok(())
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn description(&self) -> Description {
        let credentials = self.ice.get_local_credentials();
        let mut sdp=format!("v=0\r\no=- 0 0 IN IP4 0.0.0.0\r\ns=porthub\r\nt=0 0\r\n{LABEL}\r\na=porthub-peer-id:{}\r\na=ice-ufrag:{}\r\na=ice-pwd:{}\r\na=fingerprint:sha-256 {}\r\n",self.local_id,credentials.ufrag,credentials.pwd,self.identity.fingerprint);
        for candidate in self.ice.get_local_candidates() {
            sdp.push_str(&format!("a=candidate:{}\r\n", candidate.marshal()));
        }
        Description {
            r#type: if self.controlling {
                Kind::Offer
            } else {
                Kind::Answer
            },
            sdp,
        }
    }
    /// Validate the complete authenticated description before changing ICE.
    pub fn remote(&mut self, now: Instant, actor: &str, description: &Description) -> Result<()> {
        ensure!(
            actor == self.remote_id,
            "signaling actor does not match enrolled peer"
        );
        ensure!(
            description.sdp.len()
                <= if description.r#type == Kind::Candidate {
                    4096
                } else {
                    65536
                },
            "private description exceeds size limit"
        );
        let mut found = false;
        let mut label = false;
        let mut ufrag = None;
        let mut pwd = None;
        let mut candidates = Vec::new();
        for line in description.sdp.lines().map(str::trim) {
            if line == LABEL {
                label = true;
            } else if let Some(value) = line.strip_prefix("a=porthub-peer-id:") {
                ensure!(value == self.remote_id, "description identity mismatch");
            } else if let Some(value) = line.strip_prefix("a=fingerprint:") {
                let Some(value) = value.strip_prefix("sha-256 ") else {
                    anyhow::bail!("unsupported certificate fingerprint");
                };
                ensure!(pin(value)? == self.pin, "description certificate mismatch");
                found = true;
            } else if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
                ensure!(
                    ufrag.replace(value.to_owned()).is_none(),
                    "duplicate ICE credentials"
                );
            } else if let Some(value) = line.strip_prefix("a=ice-pwd:") {
                ensure!(
                    pwd.replace(value.to_owned()).is_none(),
                    "duplicate ICE credentials"
                );
            } else if let Some(value) = line.strip_prefix("a=candidate:") {
                ensure!(
                    candidates.len() < MAX_CANDIDATES,
                    "too many private candidates"
                );
                candidates.push(safe(
                    unmarshal_candidate(value),
                    "invalid private candidate",
                )?);
            }
        }
        ensure!(found, "missing enrolled certificate fingerprint");
        if description.r#type == Kind::Candidate {
            ensure!(candidates.len() == 1, "one trickle candidate required");
        }
        candidates.retain(|candidate| {
            !self
                .ice
                .get_remote_candidates()
                .iter()
                .any(|existing| existing.marshal() == candidate.marshal())
        });
        ensure!(
            self.ice.get_remote_candidates().len() + candidates.len() <= MAX_CANDIDATES,
            "too many private candidates"
        );
        if description.r#type != Kind::Candidate {
            ensure!(
                description.r#type
                    == if self.controlling {
                        Kind::Answer
                    } else {
                        Kind::Offer
                    },
                "invalid private negotiation direction"
            );
            ensure!(label, "unsupported private transport");
            let (ufrag, pwd) = (
                ufrag.ok_or_else(|| anyhow::anyhow!("missing ICE credentials"))?,
                pwd.ok_or_else(|| anyhow::anyhow!("missing ICE credentials"))?,
            );
            ensure!(
                [&ufrag, &pwd].iter().all(|v| !v.is_empty()
                    && v.len() <= 256
                    && v.bytes().all(|c| c.is_ascii_graphic())),
                "invalid ICE credentials"
            );
            if let Some(current) = &self.remote_credentials {
                ensure!(
                    current == &(ufrag.clone(), pwd.clone()),
                    "ICE restart requires a new session"
                );
            } else {
                safe(
                    self.ice.start_connectivity_checks(
                        now,
                        self.controlling,
                        ufrag.clone(),
                        pwd.clone(),
                    ),
                    "private connectivity checks failed",
                )?;
                self.remote_credentials = Some((ufrag, pwd));
                self.state = State::Connecting;
                self.deadline = Some(now + Duration::from_secs(40));
            }
        }
        for candidate in candidates {
            safe(
                self.ice.add_remote_candidate(candidate),
                "private candidate rejected",
            )?;
        }
        self.events(now)
    }
    fn events(&mut self, now: Instant) -> Result<()> {
        while let Some(event) = self.ice.poll_event() {
            if let Event::ConnectionStateChange(ConnectionState::Failed | ConnectionState::Closed) =
                event.event
            {
                self.state = State::Failed;
            }
        }
        if !self.started && self.controlling && self.ice.get_selected_candidate_pair().is_some() {
            safe(
                self.dtls
                    .connect(now, VIRTUAL_REMOTE, self.config.clone(), None),
                "private DTLS handshake failed",
            )?;
            self.started = true;
        }
        Ok(())
    }
    pub fn timeout(&mut self, now: Instant) -> Result<()> {
        if self.deadline.is_some_and(|deadline| now >= deadline) && self.state != State::Ready {
            self.state = State::Failed;
            anyhow::bail!("private handshake timed out");
        }
        safe(
            self.ice.handle_timeout(now),
            "private connectivity timer failed",
        )?;
        self.ice_tick = Some(now + Duration::from_secs(2));
        if self
            .dtls
            .poll_timeout(&VIRTUAL_REMOTE)
            .is_some_and(|deadline| deadline <= now)
        {
            safe(
                self.dtls.handle_timeout(VIRTUAL_REMOTE, now),
                "private handshake timer failed",
            )?;
        }
        self.events(now)
    }
    pub fn next_timeout(&mut self) -> Option<Instant> {
        if matches!(self.state, State::Closed | State::Failed) {
            return None;
        }
        let ice = if self.state == State::Ready && self.ice.state() == ConnectionState::Connected {
            self.ice_tick.or_else(|| self.ice.poll_timeout())
        } else {
            self.ice.poll_timeout()
        };
        [
            ice,
            self.dtls.poll_timeout(&VIRTUAL_REMOTE),
            if self.state == State::Ready {
                None
            } else {
                self.deadline
            },
        ]
        .into_iter()
        .flatten()
        .min()
    }
    pub fn receive(&mut self, now: Instant, remote: SocketAddr, bytes: BytesMut) -> Result<()> {
        self.receive_on(now, self.local, remote, bytes)
    }
    pub fn receive_on(
        &mut self,
        now: Instant,
        local: SocketAddr,
        remote: SocketAddr,
        bytes: BytesMut,
    ) -> Result<()> {
        if bytes.len() > 8192 || matches!(self.state, State::Closed | State::Failed) {
            return Ok(());
        }
        let transport = TransportContext {
            local_addr: local,
            peer_addr: remote,
            transport_protocol: TransportProtocol::UDP,
            ecn: None,
        };
        // STUN has the RFC 5389 magic cookie. Everything else still needs ICE
        // tuple validation followed by DTLS record authentication.
        if bytes.len() >= 20 && bytes[0] & 0xc0 == 0 && bytes[4..8] == [0x21, 0x12, 0xa4, 0x42] {
            let _ = self.ice.handle_read(TransportMessage {
                now,
                transport,
                message: bytes,
            });
            self.events(now)?;
        } else if self.ice.is_valid_non_stun_traffic(now, transport) {
            let events = match self.dtls.read(now, VIRTUAL_REMOTE, None, bytes) {
                Ok(events) => events,
                Err(_) => {
                    if self.state != State::Ready {
                        self.state = State::Failed;
                        anyhow::bail!("private certificate handshake rejected");
                    }
                    return Ok(());
                }
            };
            for event in events {
                match event {
                    EndpointEvent::HandshakeComplete => {
                        ensure!(
                            self.verified.load(Ordering::Acquire),
                            "private certificate proof missing"
                        );
                        self.state = State::Ready;
                        self.ice_tick = Some(now + Duration::from_secs(2));
                    }
                    EndpointEvent::ApplicationData(data)
                        if self.state == State::Ready
                            && (20..=crate::MAX_PACKET).contains(&data.len()) =>
                    {
                        if self.packets.len() < 2048 {
                            self.packets.push_back(data.freeze());
                        }
                    }
                    EndpointEvent::PeerClosed => self.state = State::Closed,
                    _ => {}
                }
            }
        }
        Ok(())
    }
    pub fn send(&mut self, now: Instant, packet: &[u8]) -> Result<()> {
        ensure!(self.state == State::Ready, "private peer is not ready");
        ensure!(
            (20..=crate::MAX_PACKET).contains(&packet.len()),
            "invalid private packet size"
        );
        safe(
            self.dtls.write(now, VIRTUAL_REMOTE, packet),
            "private packet write failed",
        )
    }
    pub fn packet(&mut self) -> Option<Bytes> {
        self.packets.pop_front()
    }
    pub fn is_relay(&self) -> bool {
        self.ice
            .get_selected_candidate_pair()
            .is_some_and(|(a, b)| {
                a.candidate_type() == rtc_ice::candidate::CandidateType::Relay
                    || b.candidate_type() == rtc_ice::candidate::CandidateType::Relay
            })
    }
    pub fn transmit(&mut self) -> Option<Datagram> {
        if let Some(packet) = self.ice.poll_write() {
            return Some(Datagram {
                local: packet.transport.local_addr,
                remote: packet.transport.peer_addr,
                bytes: packet.message,
            });
        }
        let pair = self
            .ice
            .get_selected_candidate_pair()
            .map(|(a, b)| (a.base_addr(), b.addr()))
            .or(self.last_pair)?;
        self.last_pair = Some(pair);
        let (local, remote) = pair;
        self.dtls.poll_transmit().map(|p| Datagram {
            local,
            remote,
            bytes: p.message,
        })
    }
    pub fn close(&mut self, now: Instant) {
        self.last_pair = self
            .ice
            .get_selected_candidate_pair()
            .map(|(a, b)| (a.base_addr(), b.addr()))
            .or(self.last_pair);
        let _ = self.dtls.close(now);
        let _ = self.ice.close();
        self.state = State::Closed;
        self.packets.clear();
    }
}
