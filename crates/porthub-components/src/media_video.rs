//! Bounded encoded camera frames. This module does not activate a camera or
//! decode pixels; native source and virtual receiver must agree on exact mode.
use serde::{Deserialize, Serialize};
pub const MAX_VIDEO_FRAME: usize = 2 * 1024 * 1024;
pub const MAX_VIDEO_NETWORK_FRAME: usize = 40 + MAX_VIDEO_FRAME;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VideoEncoding {
    Mjpeg,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoFormat {
    pub encoding: VideoEncoding,
    pub width: u32,
    pub height: u32,
    pub fps_num: u32,
    pub fps_den: u32,
}
impl VideoFormat {
    pub fn baseline_mjpeg() -> Self {
        Self {
            encoding: VideoEncoding::Mjpeg,
            width: 640,
            height: 480,
            fps_num: 15,
            fps_den: 1,
        }
    }
    pub fn valid(&self) -> bool {
        self.width > 0
            && self.width <= 1920
            && self.height > 0
            && self.height <= 1080
            && self.fps_den > 0
            && self.fps_den <= 1_000_000
            && self.fps_num >= self.fps_den
            && self.fps_num as u64 <= 60 * self.fps_den as u64
    }
}
/// Timestamp describes source-agent delivery, not a claimed hardware clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VideoFrame {
    pub sequence: u64,
    pub source_monotonic_micros: u64,
    pub format: VideoFormat,
    pub jpeg: Vec<u8>,
}
pub fn jpeg_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    if !(4..=MAX_VIDEO_FRAME).contains(&bytes.len())
        || bytes[..2] != [0xff, 0xd8]
        || bytes[bytes.len() - 2..] != [0xff, 0xd9]
    {
        return None;
    }
    let mut at = 2;
    while at + 4 <= bytes.len() - 2 {
        if bytes[at] != 0xff {
            return None;
        }
        while at < bytes.len() - 2 && bytes[at] == 0xff {
            at += 1;
        }
        let marker = *bytes.get(at)?;
        at += 1;
        if matches!(marker, 0x00 | 0xd8 | 0xd9 | 0xda) {
            return None;
        }
        if marker == 0x01 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        let length = u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?) as usize;
        let end = at.checked_add(length)?;
        if length < 2 || end > bytes.len() - 2 {
            return None;
        }
        if matches!(marker, 0xc0 | 0xc1 | 0xc2) {
            if length < 8 || bytes[at + 2] != 8 {
                return None;
            }
            let components = bytes[at + 7] as usize;
            if ![1, 3].contains(&components) || length != 8 + 3 * components {
                return None;
            }
            let height = u16::from_be_bytes(bytes[at + 3..at + 5].try_into().ok()?) as u32;
            let width = u16::from_be_bytes(bytes[at + 5..at + 7].try_into().ok()?) as u32;
            return Some((width, height));
        }
        at = end;
    }
    None
}
impl VideoFrame {
    pub fn valid(&self) -> bool {
        self.format.valid()
            && jpeg_dimensions(&self.jpeg) == Some((self.format.width, self.format.height))
    }
    pub fn encode(&self) -> Option<Vec<u8>> {
        if !self.valid() {
            return None;
        }
        let mut out = Vec::with_capacity(40 + self.jpeg.len());
        out.extend(b"PHV1");
        out.extend(self.sequence.to_be_bytes());
        out.extend(self.source_monotonic_micros.to_be_bytes());
        for value in [
            self.format.width,
            self.format.height,
            self.format.fps_num,
            self.format.fps_den,
            self.jpeg.len() as u32,
        ] {
            out.extend(value.to_be_bytes());
        }
        out.extend(&self.jpeg);
        Some(out)
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if !(44..=MAX_VIDEO_NETWORK_FRAME).contains(&bytes.len()) || bytes[..4] != *b"PHV1" {
            return None;
        }
        let u32at = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
        if u32at(36) as usize != bytes.len() - 40 {
            return None;
        }
        let format = VideoFormat {
            encoding: VideoEncoding::Mjpeg,
            width: u32at(20),
            height: u32at(24),
            fps_num: u32at(28),
            fps_den: u32at(32),
        };
        if !format.valid() || jpeg_dimensions(&bytes[40..]) != Some((format.width, format.height)) {
            return None;
        }
        Some(Self {
            sequence: u64::from_be_bytes(bytes[4..12].try_into().ok()?),
            source_monotonic_micros: u64::from_be_bytes(bytes[12..20].try_into().ok()?),
            format,
            jpeg: bytes[40..].to_vec(),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> VideoFrame {
        // Header validation fixture, not a decoded image or hardware capture proof.
        let jpeg = vec![
            0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 1, 224, 2, 128, 1, 1, 0x11, 0, 0xff, 0xd9,
        ];
        VideoFrame {
            sequence: 7,
            source_monotonic_micros: 12,
            format: VideoFormat {
                encoding: VideoEncoding::Mjpeg,
                width: 640,
                height: 480,
                fps_num: 15,
                fps_den: 1,
            },
            jpeg,
        }
    }
    #[test]
    fn encoded_frames_bind_exact_mode_and_bounded_jpeg_headers() {
        let frame = fixture();
        assert!(frame.valid());
        let wire = frame.encode().unwrap();
        assert_eq!(VideoFrame::decode(&wire), Some(frame.clone()));
        let mut invalid = wire.clone();
        invalid[23] = 1;
        assert!(VideoFrame::decode(&invalid).is_none());
        let mut wrong = frame.clone();
        wrong.format.width = 1920;
        assert!(!wrong.valid());
        let mut truncated = frame.jpeg.clone();
        truncated.pop();
        assert!(jpeg_dimensions(&truncated).is_none());
        let mut huge = frame.clone();
        huge.jpeg.resize(MAX_VIDEO_FRAME + 1, 0);
        assert!(!huge.valid());
    }
    #[test]
    fn geometry_and_rates_reject_unbounded_or_silent_mode_changes() {
        let mut mode = fixture().format;
        mode.fps_den = 0;
        assert!(!mode.valid());
        mode.fps_den = 1;
        mode.fps_num = 61;
        assert!(!mode.valid());
        mode.fps_num = 15;
        mode.width = 1921;
        assert!(!mode.valid());
    }
}
