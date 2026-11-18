//! Separate native-media contracts. Legacy USB descriptors/plans are unchanged.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UsbIdentity {
    pub vendor: u16,
    pub product: u16,
}
impl UsbIdentity {
    pub fn valid(&self) -> bool {
        self.vendor != 0 && self.vendor != u16::MAX && self.product != 0
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub uid: u32,
    pub desktop_session: Option<String>,
    pub device: crate::media::Device,
}
impl Source {
    pub fn valid(&self) -> bool {
        valid_desktop(self.uid, self.desktop_session.as_deref()) && self.device.valid()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub id: String,
    pub source: String,
    pub destination: String,
    pub desktop_uid: u32,
    pub desktop_session: Option<String>,
    pub source_id: String,
    pub name: String,
    pub identity: UsbIdentity,
    pub persistent: bool,
    /// An immutable transport mode; raw USB URBs must never enter this carrier.
    pub mode: String,
}
impl Plan {
    pub fn kind(&self) -> Option<crate::media::Kind> {
        match self.mode.as_str() {
            "phs1-speaker-v1" => Some(crate::media::Kind::Speaker),
            "phm1-microphone-v1" => Some(crate::media::Kind::Microphone),
            "phv1-camera-mjpeg-v1" => Some(crate::media::Kind::Camera),
            _ => None,
        }
    }
    pub fn format(&self) -> Option<crate::media::VideoFormat> {
        if self.kind() == Some(crate::media::Kind::Camera) {
            Some(crate::media::VideoFormat::baseline_mjpeg())
        } else {
            None
        }
    }
    pub fn valid(&self) -> bool {
        self.kind().is_some()
            && self.id.len() == 32
            && self.id.bytes().all(|b| b.is_ascii_hexdigit())
            && self.source.len() == 24
            && self.source.bytes().all(|b| b.is_ascii_hexdigit())
            && self.destination.len() == 24
            && self.destination.bytes().all(|b| b.is_ascii_hexdigit())
            && self.source != self.destination
            && valid_desktop(self.desktop_uid, self.desktop_session.as_deref())
            && self.source_id.starts_with("media:")
            && self.source_id.len() == 70
            && self.source_id[6..].bytes().all(|b| b.is_ascii_hexdigit())
            && self.name.len() <= 256
            && !self.name.chars().any(char::is_control)
            && self.identity.valid()
    }
}

pub fn valid_desktop(uid: u32, session: Option<&str>) -> bool {
    match session {
        None => uid > 0,
        Some(value) => {
            uid == 0
                && value.strip_prefix("windows:").is_some_and(|hash| {
                    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
                })
        }
    }
}
