//! Media endpoints are selectable OS inputs, not physical USB attachments.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Microphone,
    Camera,
    Speaker,
}
/// Readonly enumeration never grants microphone permission. A supported source
/// can be requested explicitly while permission is unknown; the OS decides on use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureState {
    #[default]
    Unsupported,
    PermissionUnknown,
    Ready,
    Denied,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub backend: String,
    /// Native identity is machine-local; labels are never used as identity.
    pub native_id: String,
    pub capture_available: bool,
    #[serde(default)]
    pub capture_state: CaptureState,
    pub unavailable_reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receiver {
    pub kind: Kind,
    pub backend: String,
    /// True only after the compatible publisher is installed and preflight succeeds.
    pub publication_available: bool,
    pub unavailable_reason: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub devices: Vec<Device>,
    pub receivers: Vec<Receiver>,
    pub enumeration_available: bool,
    pub unavailable_reason: Option<String>,
    /// Capability defaults never imply active capture.
    pub microphone_share_enabled: bool,
    pub camera_share_enabled: bool,
    pub media_receive_enabled: bool,
    pub capture_active: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalSource {
    pub device: Device,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camera_identity: Option<serde_json::Value>,
}
impl LocalSource {
    pub fn valid(&self) -> bool {
        self.device.valid()
            && match self.device.kind {
                Kind::Microphone | Kind::Speaker => self.camera_identity.is_none(),
                Kind::Camera => self.camera_identity.as_ref().is_some_and(|v| {
                    v.is_object() && serde_json::to_vec(v).is_ok_and(|b| b.len() <= 6144)
                }),
            }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalInventory {
    pub sources: Vec<LocalSource>,
    pub microphone_unavailable_reason: Option<String>,
    pub camera_unavailable_reason: Option<String>,
    #[serde(default)]
    pub speaker_unavailable_reason: Option<String>,
}
impl LocalInventory {
    pub fn valid(&self) -> bool {
        self.sources.len() <= 64
            && self.sources.iter().all(LocalSource::valid)
            && [
                &self.microphone_unavailable_reason,
                &self.camera_unavailable_reason,
                &self.speaker_unavailable_reason,
            ]
            .iter()
            .all(|v| {
                v.as_ref()
                    .is_none_or(|s| s.len() <= 512 && !s.chars().any(char::is_control))
            })
    }
}

/// Private inherited-pipe request. No enrollment credentials cross into media adapters.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub operation: Operation,
    pub session: String,
    pub name: String,
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video_format: Option<VideoFormat>,
    /// Machine-local inventory proof, never forwarded to the API or receiver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camera_identity: Option<serde_json::Value>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    CaptureMicrophone,
    PublishMicrophone,
    CaptureCamera,
    CapturePlayback,
    RenderPlayback,
}
pub const PCM_RATE: u32 = 48_000;
pub const PCM_CHANNELS: u32 = 1;
pub const MAX_PCM_FRAME: usize = 3840; // 20ms mono F32LE.
impl SessionRequest {
    pub fn valid(&self) -> bool {
        self.session.len() == 32
            && self.session.bytes().all(|b| b.is_ascii_hexdigit())
            && !self.name.is_empty()
            && self.name.len() <= 256
            && !self.name.chars().any(char::is_control)
            && match self.operation {
                Operation::CaptureMicrophone | Operation::CapturePlayback => {
                    self.video_format.is_none()
                        && self.camera_identity.is_none()
                        && self.source_id.as_ref().is_some_and(|s| {
                            !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control)
                        })
                }
                Operation::PublishMicrophone | Operation::RenderPlayback => {
                    self.source_id.is_none()
                        && self.video_format.is_none()
                        && self.camera_identity.is_none()
                }
                Operation::CaptureCamera => {
                    self.source_id.as_ref().is_some_and(|s| {
                        s.len() == 70
                            && s.starts_with("media:")
                            && s[6..].bytes().all(|b| b.is_ascii_hexdigit())
                    }) && self
                        .video_format
                        .is_some_and(|f| f == VideoFormat::baseline_mjpeg())
                        && self.camera_identity.as_ref().is_some_and(|v| {
                            v.is_object() && serde_json::to_vec(v).is_ok_and(|b| b.len() <= 6144)
                        })
                }
            }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn camera_requests_cannot_be_misread_as_legacy_microphone_sessions() {
        let mut request = SessionRequest {
            operation: Operation::CaptureMicrophone,
            session: "a".repeat(32),
            name: "Mic".into(),
            source_id: Some("native-id".into()),
            video_format: None,
            camera_identity: None,
        };
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("video_format").is_none() && json.get("camera_identity").is_none());
        request.operation = Operation::CaptureCamera;
        assert!(!request.valid());
        request.source_id = Some(stable_source_id(Kind::Camera, "v4l2", "exact"));
        request.video_format = Some(VideoFormat::baseline_mjpeg());
        request.camera_identity = Some(serde_json::json!({"retained":"proof"}));
        assert!(request.valid());
        request.operation = Operation::CaptureMicrophone;
        assert!(!request.valid());
    }
    #[test]
    fn sessions_require_explicit_source_and_bounded_identity() {
        let mut r = SessionRequest {
            operation: Operation::PublishMicrophone,
            session: "a".repeat(32),
            name: "Mic".into(),
            source_id: None,
            video_format: None,
            camera_identity: None,
        };
        assert!(r.valid());
        r.operation = Operation::CaptureMicrophone;
        assert!(!r.valid());
        r.source_id = Some("alsa_input.verified".into());
        assert!(r.valid());
        r.name = "Mic\ncommand".into();
        assert!(!r.valid());
    }
}

/// Authenticated carrier payload v1: fixed 48kHz mono F32LE, not opaque USB URBs.
/// Timestamp is source-agent delivery time, not a hardware capture timestamp.
#[derive(Clone, Debug, PartialEq)]
pub struct PcmFrame {
    pub sequence: u64,
    pub sample_offset: u64,
    pub source_monotonic_micros: u64,
    pub pcm: Vec<u8>,
}
pub const MAX_NETWORK_FRAME: usize = 32 + MAX_PCM_FRAME;
impl PcmFrame {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !valid_pcm(&self.pcm) {
            return None;
        }
        let mut out = Vec::with_capacity(32 + self.pcm.len());
        out.extend(b"PHM1");
        out.extend(self.sequence.to_be_bytes());
        out.extend(self.sample_offset.to_be_bytes());
        out.extend(self.source_monotonic_micros.to_be_bytes());
        out.extend((self.pcm.len() as u32).to_be_bytes());
        out.extend(&self.pcm);
        Some(out)
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 || bytes.len() > MAX_NETWORK_FRAME || &bytes[..4] != b"PHM1" {
            return None;
        }
        let length = u32::from_be_bytes(bytes[28..32].try_into().ok()?) as usize;
        if length != bytes.len() - 32 || !valid_pcm(&bytes[32..]) {
            return None;
        }
        Some(Self {
            sequence: u64::from_be_bytes(bytes[4..12].try_into().ok()?),
            sample_offset: u64::from_be_bytes(bytes[12..20].try_into().ok()?),
            source_monotonic_micros: u64::from_be_bytes(bytes[20..28].try_into().ok()?),
            pcm: bytes[32..].to_vec(),
        })
    }
}
fn valid_pcm(pcm: &[u8]) -> bool {
    !pcm.is_empty()
        && pcm.len() <= MAX_PCM_FRAME
        && pcm.len() % 4 == 0
        && pcm
            .chunks_exact(4)
            .all(|v| f32::from_le_bytes(v.try_into().unwrap()).is_finite())
}
/// Ordered transports may lose frames on reconnect, but never replay an old sample interval.
#[derive(Default)]
pub struct PcmContinuity {
    last: Option<(u64, u64, u64)>,
}
impl PcmContinuity {
    pub fn accept(&mut self, frame: &PcmFrame) -> bool {
        if !valid_pcm(&frame.pcm) {
            return false;
        }
        let Some(end) = frame
            .sample_offset
            .checked_add((frame.pcm.len() / 4) as u64)
        else {
            return false;
        };
        if let Some((sequence, offset, time)) = self.last {
            if frame.sequence <= sequence
                || frame.sample_offset < offset
                || frame.source_monotonic_micros < time
            {
                return false;
            }
        }
        self.last = Some((frame.sequence, end, frame.source_monotonic_micros));
        true
    }
}
#[cfg(test)]
mod frame_tests {
    use super::*;
    #[test]
    fn carrier_frames_reject_wrong_purpose_truncation_nonfinite_and_replay() {
        let frame = PcmFrame {
            sequence: 1,
            sample_offset: 0,
            source_monotonic_micros: 10,
            pcm: vec![0; 8],
        };
        let encoded = frame.encode().unwrap();
        assert_eq!(PcmFrame::decode(&encoded), Some(frame.clone()));
        assert!(PcmFrame::decode(&encoded[..encoded.len() - 1]).is_none());
        let mut corrupt = encoded.clone();
        corrupt[0] = 0;
        assert!(PcmFrame::decode(&corrupt).is_none());
        corrupt = encoded;
        corrupt[32..36].copy_from_slice(&f32::NAN.to_le_bytes());
        assert!(PcmFrame::decode(&corrupt).is_none());
        let mut clock = PcmContinuity::default();
        assert!(clock.accept(&frame));
        assert!(!clock.accept(&frame));
        let mut next = frame.clone();
        next.sequence = 3;
        next.sample_offset = 4;
        next.source_monotonic_micros = 11;
        assert!(clock.accept(&next));
        next.sequence = 4;
        next.sample_offset = 3;
        assert!(!clock.accept(&next));
    }
}

/// Physical/native endpoint identity, independent of a transient PipeWire node name.
pub fn stable_source_id(kind: Kind, hardware: &str, endpoint: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(match kind {
        Kind::Microphone => b"microphone" as &[u8],
        Kind::Camera => b"camera",
        Kind::Speaker => b"speaker",
    });
    for value in [hardware, endpoint] {
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value.as_bytes());
    }
    format!("media:{:x}", hash.finalize())
}
impl Device {
    pub fn can_request_capture(&self) -> bool {
        matches!(
            self.capture_state,
            CaptureState::PermissionUnknown | CaptureState::Ready
        )
    }
    pub fn valid(&self) -> bool {
        [&self.id, &self.native_id]
            .iter()
            .all(|s| !s.is_empty() && s.len() <= 512 && !s.chars().any(char::is_control))
            && self.name.len() <= 256
            && !self.name.chars().any(char::is_control)
            && !self.backend.is_empty()
            && self.backend.len() <= 64
            && self
                .unavailable_reason
                .as_ref()
                .is_none_or(|s| s.len() <= 512 && !s.chars().any(char::is_control))
    }
}

pub use crate::media_video::{
    jpeg_dimensions, VideoEncoding, VideoFormat, VideoFrame, MAX_VIDEO_FRAME,
    MAX_VIDEO_NETWORK_FRAME,
};
