use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub const MAX_DATA: usize = 16 * 1024;
pub const MAX_VIEWERS: usize = 32;
pub const DEFAULT_HISTORY: u32 = 100_000;
/// Positive identities fit both MongoDB signed integers and JavaScript numbers.
pub fn participant_id() -> u64 {
    use rand::Rng;
    rand::rngs::OsRng.gen_range(1..(1u64 << 52))
}

pub fn random_token(bytes: usize) -> String {
    use rand::RngCore;
    let mut data = vec![0; bytes];
    rand::rngs::OsRng.fill_bytes(&mut data);
    data.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn token(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
pub fn digest(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub name: String,
    /// Invitation expiry only; zero keeps invitations valid until session end.
    pub expires_at: i64,
    #[serde(default)]
    pub session_expires_at: Option<i64>,
    pub idle_timeout: u32,
    pub reconnect_timeout: u32,
    pub history_limit: u32,
    pub mouse: bool,
    pub read_only: bool,
    pub size_policy: SizePolicy,
    #[serde(default)]
    pub access: Access,
    #[serde(default = "default_max_viewers")]
    pub max_viewers: u8,
}
fn default_max_viewers() -> u8 {
    16
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Ssh,
    Web,
    #[default]
    Both,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SizePolicy {
    Smallest,
    Largest,
    Latest,
}
impl Options {
    pub fn validate(&self, now: i64) -> Result<()> {
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 64
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b)),
            "session name must be 1–64 letters, numbers, spaces, dots, underscores or hyphens"
        );
        ensure!(
            self.expires_at == 0 || self.expires_at > 0 && self.expires_at <= now + 604_800,
            "invitation expiry must be zero or within seven days"
        );
        ensure!(
            self.session_expires_at
                .is_none_or(|at| at > 0 && at <= now + 604_800),
            "session timeout must be within seven days"
        );
        ensure!(
            (10..=300).contains(&self.reconnect_timeout),
            "reconnect timeout must be 10–300 seconds"
        );
        ensure!(
            self.idle_timeout == 0 || (60..=86_400).contains(&self.idle_timeout),
            "idle timeout must be zero or 60–86400 seconds"
        );
        ensure!(
            (1000..=200_000).contains(&self.history_limit),
            "history limit must be 1000–200000 lines"
        );
        ensure!(
            (1..=32).contains(&self.max_viewers),
            "participant limit must be 1–32"
        );
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostHello {
    #[serde(default, skip_serializing_if = "is_false")]
    pub direct_transport: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub history_snapshots: bool,
    pub id: String,
    pub secret: String,
    pub write_token: String,
    pub read_token: String,
    pub options: Options,
}
impl HostHello {
    pub fn validate(&self, now: i64) -> Result<()> {
        ensure!(
            token(&self.id, 32)
                && token(&self.secret, 64)
                && token(&self.write_token, 64)
                && token(&self.read_token, 64),
            "invalid terminal session identity"
        );
        ensure!(
            self.secret != self.write_token
                && self.secret != self.read_token
                && self.write_token != self.read_token,
            "terminal capabilities must be distinct"
        );
        self.options.validate(now)
    }
}
/// Gateway-assigned identity, scoped to one shared session. No IP addresses or
/// invitation capabilities are exposed to participants.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub id: u64,
    pub read_only: bool,
    pub joined_at: i64,
    pub last_active_at: i64,
}

/// Hash-only invitation state loaded from the gateway's authoritative database.
#[derive(Clone, Debug)]
pub struct PersistedInvitations {
    pub revision: u64,
    pub write_hash: String,
    pub read_hash: String,
    pub expires_at: i64,
    pub revoked: bool,
}
impl PersistedInvitations {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.revision <= i64::MAX as u64
                && token(&self.write_hash, 64)
                && token(&self.read_hash, 64)
                && self.write_hash != self.read_hash
                && self.expires_at >= 0,
            "invalid persisted invitation state"
        );
        Ok(())
    }
}

/// Replacement invitation capabilities, authorized and persisted by the gateway
/// before installation. Revision makes retries idempotent and fences old updates.
/// Deliberately does not implement Debug: capabilities must not enter logs.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationUpdate {
    pub revision: u64,
    pub write_token: String,
    pub read_token: String,
    pub expires_at: i64,
}
impl std::fmt::Debug for InvitationUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationUpdate")
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}
impl InvitationUpdate {
    pub fn validate(&self, at: i64) -> Result<()> {
        ensure!(
            self.revision > 0 && self.revision <= i64::MAX as u64,
            "invalid invitation revision"
        );
        ensure!(
            token(&self.write_token, 64)
                && token(&self.read_token, 64)
                && self.write_token != self.read_token,
            "invalid replacement invitation capabilities"
        );
        ensure!(
            self.expires_at >= 0 && self.expires_at <= at + 604800,
            "replacement invitation expiry must be within seven days"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryChunk {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    pub request: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane: Option<String>,
    pub data: String,
    pub done: bool,
    pub total: u32,
    pub before: u32,
    pub lines: u16,
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
pub fn history_request(pane: &str, before: u32, lines: u16) -> Result<()> {
    ensure!(
        pane.is_empty()
            || pane.len() <= 20
                && pane.starts_with('%')
                && pane.len() > 1
                && pane[1..].bytes().all(|b| b.is_ascii_digit()),
        "invalid history pane"
    );
    ensure!(
        before <= 200_000 && (1..=512).contains(&lines),
        "history slice exceeds limits"
    );
    Ok(())
}
impl HistoryChunk {
    pub fn validate(&self) -> Result<()> {
        if let Some(snapshot) = &self.snapshot {
            ensure!(token(snapshot, 32) && self.pane.is_some(), "invalid anchored history response");
        }
        if let Some(pane) = &self.pane {
            ensure!(!pane.is_empty(), "invalid resolved history pane");
            history_request(pane, self.before, self.lines.max(1))?;
        }
        ensure!(
            self.total <= 200_000
                && self.before <= 200_000
                && self.lines <= 512
                && self.error.as_ref().is_none_or(|error| error.len() <= 256),
            "invalid history response"
        );
        decode_data(&self.data)?;
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostEvent {
    Delivery { client: u64, packet: DeliveryPacket },
    DirectOffer { client: u64, request: u32, description: DirectDescription },
    InvitationsRotated {
        revision: u64,
        expires_at: i64,
        invitations_revoked: bool,
    },
    Redraw {
        client: u64,
    },
    InvitationsRevoked,
    History {
        #[serde(default, skip_serializing_if = "is_false")]
        freeze: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snapshot: Option<String>,
        client: u64,
        request: u32,
        pane: String,
        before: u32,
        lines: u16,
    },
    Ready {
        #[serde(default, skip_serializing_if = "is_false")]
        direct_transport: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        history_snapshots: bool,
        #[serde(default)]
        invitations_revoked: bool,
        ssh_host: String,
        ssh_port: u16,
        public_base: String,
    },
    Attach {
        client: u64,
        read_only: bool,
        cols: u16,
        rows: u16,
        term: String,
    },
    Input {
        client: u64,
        data: String,
    },
    Resize {
        client: u64,
        cols: u16,
        rows: u16,
    },
    Detach {
        client: u64,
    },
    Stop {
        reason: String,
    },
    Reconnect {
        reason: String,
    },
    Presence {
        members: Vec<Participant>,
    },
    Ping,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostOutput {
    Delivery { client: u64, packet: DeliveryPacket },
    DirectAnswer { client: u64, answer: DirectAnswer },
    DirectUnavailable { client: u64, request: u32 },
    RotateInvitations { update: InvitationUpdate },
    RevokeInvitations,
    History { client: u64, page: HistoryChunk },
    Kick { client: u64 },
    Output { client: u64, data: String },
    Closed { client: u64 },
    End,
    Pong,
    Activity,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ViewerEvent {
    Delivery { packet: DeliveryPacket },
    DirectAnswer { answer: DirectAnswer },
    DirectUnavailable { request: u32 },
    History {
        page: HistoryChunk,
    },
    Recovery {
        session: String,
        token: String,
        participant: u64,
        reconnect_timeout: u32,
    },
    Welcome {
        #[serde(default, skip_serializing_if = "is_false")]
        direct_transport: bool,
        #[serde(default, skip_serializing_if = "is_false")]
        history_snapshots: bool,
        name: String,
        read_only: bool,
        expires_at: i64,
        participants: usize,
    },
    Output {
        data: String,
    },
    Presence {
        participants: usize,
        members: Vec<Participant>,
    },
    Closed {
        reason: String,
        #[serde(default)]
        retryable: bool,
    },
    Ping,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ViewerInput {
    Delivery { packet: DeliveryPacket },
    DirectOffer { request: u32, description: DirectDescription },
    Redraw,
    History {
        #[serde(default, skip_serializing_if = "is_false")]
        freeze: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        snapshot: Option<String>,
        request: u32,
        pane: String,
        before: u32,
        lines: u16,
    },
    Input {
        data: String,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Pong,
}
pub fn dimensions(cols: u16, rows: u16) -> Result<()> {
    ensure!(
        (20..=500).contains(&cols) && (5..=200).contains(&rows),
        "terminal size must be 20–500 columns and 5–200 rows"
    );
    Ok(())
}
pub fn decode_data(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    ensure!(
        data.len() <= MAX_DATA * 4 / 3 + 4,
        "terminal frame exceeds size limit"
    );
    let bytes = base64::engine::general_purpose::STANDARD.decode(data)?;
    ensure!(bytes.len() <= MAX_DATA, "terminal frame exceeds size limit");
    Ok(bytes)
}
pub fn encode_data(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod history_tests {
    use super::*;
    #[test]
    fn frozen_history_requires_an_opaque_anchor_and_resolved_pane() {
        let legacy = serde_json::json!({"request":1,"data":"","done":true,"total":0,"before":0,"lines":0,"truncated":false});
        let mut page: HistoryChunk = serde_json::from_value(legacy.clone()).unwrap();
        assert!(serde_json::to_value(&page).unwrap().get("snapshot").is_none());
        page.snapshot = Some("a".repeat(32));
        assert!(page.validate().is_err());
        page.pane = Some("%42".into());
        page.validate().unwrap();
        for invalid in ["", "%42", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "../another-session"] {
            page.snapshot = Some(invalid.into());
            assert!(page.validate().is_err());
        }
    }

    #[test]
    fn resolved_pane_is_optional_for_older_hosts_and_strict_when_present() {
        let legacy = serde_json::json!({"request":1,"data":"","done":true,"total":0,"before":0,"lines":0,"truncated":false});
        let mut page: HistoryChunk = serde_json::from_value(legacy).unwrap();
        page.validate().unwrap();
        assert!(page.pane.is_none());
        for invalid in [
            "",
            "workspace:",
            "%",
            "%1;kill-server",
            "%12345678901234567890",
        ] {
            page.pane = Some(invalid.into());
            assert!(page.validate().is_err());
        }
        page.pane = Some("%42".into());
        page.validate().unwrap();
    }
}

fn is_false(value: &bool) -> bool { !*value }

/// SDP contains ICE credentials and addresses; diagnostics must never print it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DirectDescription(pub String);
impl std::fmt::Debug for DirectDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("DirectDescription([redacted])") }
}
impl DirectDescription {
    pub fn validate(&self, kind: &str) -> anyhow::Result<()> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Description { r#type:String, sdp:String }
        ensure!(self.0.len()<=16384,"terminal direct description exceeds limit");
        let value:Description=serde_json::from_str(&self.0).map_err(|_|anyhow::anyhow!("invalid terminal direct description"))?;
        ensure!(value.r#type==kind,"unexpected terminal direct description type");
        ensure!(value.sdp.is_ascii() && !value.sdp.contains('\0'),"invalid terminal direct SDP");
        let lines:Vec<_>=value.sdp.lines().collect();
        ensure!(lines.len()<=256 && lines.iter().filter(|line|line.starts_with("a=candidate:")).count()<=64,"terminal direct SDP exceeds limits");
        let media:Vec<_>=lines.iter().filter(|line|line.starts_with("m=")).collect();
        ensure!(media.len()==1 && media[0].starts_with("m=application "),"terminal direct SDP must contain one application section");
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectAnswer {
    pub request: u32,
    pub description: DirectDescription,
    pub input_epoch: String,
    pub output_epoch: String,
}
impl DirectAnswer {
    pub fn validate(&self) -> anyhow::Result<()> {
        self.description.validate("answer")?;
        ensure!(token(&self.input_epoch,32) && token(&self.output_epoch,32) && self.input_epoch!=self.output_epoch,"invalid terminal direct epochs");
        Ok(())
    }
}

#[cfg(test)]
mod direct_signal_tests {
    use super::*;
    #[test]
    fn descriptions_are_bounded_typed_and_redacted() -> anyhow::Result<()> {
        let description=DirectDescription(serde_json::json!({"type":"offer","sdp":"v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-pwd:never-log-this\r\n"}).to_string());
        description.validate("offer")?;
        assert!(!format!("{:?}",ViewerInput::DirectOffer {request:1,description:description.clone()}).contains("never-log-this"));
        assert!(description.validate("answer").is_err());
        assert!(DirectDescription("x".repeat(16385)).validate("offer").is_err());
        assert!(DirectDescription(serde_json::json!({"type":"offer","sdp":"m=audio 9 RTP/AVP 0","client":123}).to_string()).validate("offer").is_err());
        assert!(serde_json::from_value::<ViewerInput>(serde_json::json!({"type":"direct_offer","request":1,"description":description.0,"read_only":false})).is_err());
        Ok(())
    }
}

/// A bounded relay carrier for the same binary frame used by WebRTC. Payloads
/// remain redacted in protocol diagnostics and never supply an authorization role.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeliveryPacket(pub String);
impl std::fmt::Debug for DeliveryPacket {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {f.write_str("DeliveryPacket([redacted])")}
}
impl DeliveryPacket {
    pub fn encode(message:&crate::delivery::Message)->anyhow::Result<Self> {
        use base64::Engine;
        Ok(Self(base64::engine::general_purpose::STANDARD.encode(message.encode()?)))
    }
    pub fn decode(&self)->anyhow::Result<crate::delivery::Message> {
        use base64::Engine;
        ensure!(self.0.len()<=crate::delivery::MAX_WIRE.div_ceil(3)*4,"terminal delivery envelope exceeds limit");
        let bytes=base64::engine::general_purpose::STANDARD.decode(&self.0).map_err(|_|anyhow::anyhow!("invalid terminal delivery encoding"))?;
        crate::delivery::Message::parse(&bytes)
    }
}
