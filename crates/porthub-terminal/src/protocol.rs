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
            self.expires_at == 0 || self.expires_at > at && self.expires_at <= at + 604800,
            "replacement invitation expiry must be within seven days"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryChunk {
    pub request: u32,
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
    Redraw {
        client: u64,
    },
    InvitationsRevoked,
    History {
        client: u64,
        request: u32,
        pane: String,
        before: u32,
        lines: u16,
    },
    Ready {
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
    Redraw,
    History {
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
