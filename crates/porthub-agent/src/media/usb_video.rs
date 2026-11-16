//! Receiver-local UVC1.1 MJPEG function. No camera access, USB/IP executor or
//! private VID allocation lives here. Caller serializes endpoint requests.
//!
//! Contracts: USB-IF Video Class v1.1 document set (VC/VS descriptors and
//! Probe/Commit), Linux include/uapi/linux/usb/video.h, and Linux uvcvideo's
//! bulk decoder (payload ends on a short transfer or dwMaxPayloadTransferSize).
use anyhow::{Result, ensure};
use porthub_components::media::{MAX_VIDEO_FRAME, VideoEncoding, VideoFormat, VideoFrame};

pub const WIDTH: u32 = 640;
pub const HEIGHT: u32 = 480;
pub const FPS: u32 = 15;
pub const INTERVAL_100NS: u32 = 666_666;
pub const BULK_ENDPOINT: u8 = 0x81;
pub const STATUS_ENDPOINT: u8 = 0x82;
pub const MAX_PACKET: usize = 512;
pub const MAX_PAYLOAD: usize = 16 * 1024;
pub const MAX_BULK_REQUEST: usize = 1024 * 1024;
const CONTROL_SIZE: usize = 34;
const CLOCK: u32 = 48_000_000;
const EPIPE: i32 = -32;
const EINVAL: i32 = -22;
const FID: u8 = 1;
const EOF: u8 = 2;
const ERR: u8 = 0x40;
const EOH: u8 = 0x80;
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub vendor: u16,
    pub product: u16,
}
#[derive(Default, Clone, Copy, Debug)]
pub struct Counters {
    pub completed_frames: u64,
    pub discarded_frames: u64,
    pub stale_frames: u64,
}
struct Bytes(Vec<u8>);
impl Drop for Bytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
struct Frame {
    jpeg: Bytes,
    offset: usize,
    started: bool,
}
struct Payload {
    bytes: Bytes,
    offset: usize,
    last: bool,
}
/// One active frame, at most one newer waiting frame, and one16KiB payload.
/// Epoch switches discard all unsent image data and explicitly invalidate any
/// partially transmitted frame before new-epoch payloads can follow.
pub struct Camera {
    identity: Identity,
    serial: String,
    name: String,
    configured: bool,
    committed: bool,
    halted: [bool; 2],
    probe: [u8; CONTROL_SIZE],
    commit: [u8; CONTROL_SIZE],
    error: u8,
    epoch: Option<String>,
    retired_epoch: Option<String>,
    last_sequence: Option<u64>,
    last_time: Option<u64>,
    latest: Option<Bytes>,
    active: Option<Frame>,
    payload: Option<Payload>,
    fid: u8,
    zlp: bool,
    abort: Option<u8>,
    pub counters: Counters,
}
impl Camera {
    pub fn new(identity: Identity, serial: String) -> Result<Self> {
        ensure!(
            identity.vendor != 0 && identity.vendor != u16::MAX && identity.product != 0,
            "Explicit allocated camera USB identity required"
        );
        ensure!(
            !serial.is_empty()
                && serial.len() <= 64
                && serial.bytes().all(|b| b.is_ascii_alphanumeric()),
            "Invalid camera serial"
        );
        let control = Self::default_control();
        Ok(Self {
            identity,
            serial,
            name: "PortHub Forwarded Camera".into(),
            configured: false,
            committed: false,
            halted: [false; 2],
            probe: control,
            commit: control,
            error: 0,
            epoch: None,
            retired_epoch: None,
            last_sequence: None,
            last_time: None,
            latest: None,
            active: None,
            payload: None,
            fid: 0,
            zlp: false,
            abort: None,
            counters: Default::default(),
        })
    }
    pub fn format() -> VideoFormat {
        VideoFormat {
            encoding: VideoEncoding::Mjpeg,
            width: WIDTH,
            height: HEIGHT,
            fps_num: FPS,
            fps_den: 1,
        }
    }
    pub fn set_name(&mut self, name: &str) -> Result<()> {
        ensure!(
            !name.is_empty() && !name.chars().any(char::is_control),
            "Invalid camera name"
        );
        let mut name = format!("PortHub · {name}");
        while name.encode_utf16().count() > 126 {
            name.pop();
        }
        self.name = name;
        Ok(())
    }
    pub fn device_descriptor(&self) -> Vec<u8> {
        let mut d = vec![18, 1, 0, 2, 0xef, 2, 1, 64, 0, 0, 0, 0, 0, 1, 1, 2, 3, 1];
        d[8..10].copy_from_slice(&self.identity.vendor.to_le_bytes());
        d[10..12].copy_from_slice(&self.identity.product.to_le_bytes());
        d
    }
    pub fn configuration_descriptor() -> Vec<u8> {
        Self::configuration(false)
    }
    fn configuration(other_speed: bool) -> Vec<u8> {
        let mut d = vec![
            9,
            if other_speed { 7 } else { 2 },
            0,
            0,
            2,
            1,
            0,
            0x80,
            1,
            8,
            11,
            0,
            2,
            0x0e,
            3,
            0,
            0, // IAD: one Video Interface Collection.
            9,
            4,
            0,
            0,
            1,
            0x0e,
            1,
            0,
            0, // VC interface0, one status endpoint.
            13,
            0x24,
            1,
            0x10,
            1,
            40,
            0,
            0,
            0x6c,
            0xdc,
            2,
            1,
            1, // UVC1.1,48MHz, VS interface1.
            18,
            0x24,
            2,
            1,
            1,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            3,
            0,
            0,
            0, // Camera IT1; no optional controls.
            9,
            0x24,
            3,
            2,
            1,
            1,
            0,
            1,
            0, // Streaming OT2, sourceIT1.
            7,
            5,
            STATUS_ENDPOINT,
            3,
            16,
            0,
            8, // Interrupt status; no unsolicited messages.
            5,
            0x25,
            3,
            16,
            0,
            9,
            4,
            1,
            0,
            1,
            0x0e,
            2,
            0,
            0, // Bulk streaming has only alternate0.
            14,
            0x24,
            1,
            1,
            61,
            0,
            BULK_ENDPOINT,
            0,
            2,
            0,
            0,
            0,
            1,
            0,
            11,
            0x24,
            6,
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0, // MJPEG format1, variable-size samples.
            30,
            0x24,
            7,
            1,
            0,
            0x80,
            2,
            0xe0,
            1, // Frame1,640x480.
        ];
        // Variable JPEG size, fixed nominal15fps; payload buffers are bounded.
        d.extend(1u32.to_le_bytes());
        let max_rate = ((MAX_VIDEO_FRAME as u64) * 8 * 10_000_000 / INTERVAL_100NS as u64) as u32;
        d.extend(max_rate.to_le_bytes());
        d.extend((MAX_VIDEO_FRAME as u32).to_le_bytes());
        d.extend(INTERVAL_100NS.to_le_bytes());
        d.push(1);
        d.extend(INTERVAL_100NS.to_le_bytes());
        d.extend([6, 0x24, 13, 0, 0, 0]); // Source colorimetry is unspecified.
        let packet = if other_speed {
            64u16
        } else {
            MAX_PACKET as u16
        };
        d.extend([7, 5, BULK_ENDPOINT, 2, packet as u8, (packet >> 8) as u8, 0]);
        let total = d.len() as u16;
        d[2..4].copy_from_slice(&total.to_le_bytes());
        d
    }
    fn default_control() -> [u8; CONTROL_SIZE] {
        let mut v = [0; CONTROL_SIZE];
        v[0] = 1;
        v[2] = 1;
        v[3] = 1;
        v[4..8].copy_from_slice(&INTERVAL_100NS.to_le_bytes());
        v[18..22].copy_from_slice(&(MAX_VIDEO_FRAME as u32).to_le_bytes());
        v[22..26].copy_from_slice(&(MAX_PAYLOAD as u32).to_le_bytes());
        v[26..30].copy_from_slice(&CLOCK.to_le_bytes());
        v[30] = 3;
        v[31] = 1;
        v[32] = 1;
        v[33] = 1;
        v
    }
    fn string(&self, index: u8, language: u16) -> Option<Vec<u8>> {
        if index == 0 {
            return (language == 0).then(|| vec![4, 3, 9, 4]);
        }
        if language != 0 && language != 0x0409 {
            return None;
        }
        let text = match index {
            1 => "PortHub",
            2 => &self.name,
            3 => &self.serial,
            _ => return None,
        };
        let mut v = vec![0, 3];
        for ch in text.encode_utf16() {
            v.extend(ch.to_le_bytes());
        }
        v[0] = v.len() as u8;
        Some(v)
    }
    pub fn streaming(&self) -> bool {
        self.configured && self.committed
    }
    fn clear_transport(&mut self) {
        if let Some(epoch) = self.epoch.take() {
            self.retired_epoch = Some(epoch);
        }
        self.last_sequence = None;
        self.last_time = None;
        self.latest = None;
        self.active = None;
        self.payload = None;
        self.zlp = false;
        self.abort = None;
    }
    pub fn stop(&mut self) {
        self.configured = false;
        self.committed = false;
        self.clear_transport();
    }
    /// Stop an active source without changing USB configuration. Any partial
    /// payload is terminated before a future source can supply a new image.
    pub fn end_epoch(&mut self) {
        let Some(epoch) = self.epoch.take() else {
            return;
        };
        self.retired_epoch = Some(epoch);
        self.last_sequence = None;
        self.last_time = None;
        if self.payload.as_ref().is_some_and(|p| p.offset > 0) {
            self.zlp = true;
        }
        if self.active.as_ref().is_some_and(|f| f.started) {
            self.abort = Some(self.fid);
        }
        self.counters.discarded_frames = self
            .counters
            .discarded_frames
            .saturating_add(u64::from(self.latest.is_some()) + u64::from(self.active.is_some()));
        self.latest = None;
        self.active = None;
        self.payload = None;
    }
    /// Caller rotates this32hex session epoch when the source changes/restarts.
    pub fn begin_epoch(&mut self, epoch: &str) -> Result<()> {
        ensure!(
            epoch.len() == 32 && epoch.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid camera epoch"
        );
        ensure!(
            self.retired_epoch.as_deref() != Some(epoch),
            "Camera epoch was retired by stream reset"
        );
        if self.epoch.as_deref() == Some(epoch) {
            return Ok(());
        }
        if self.payload.as_ref().is_some_and(|p| p.offset > 0) {
            self.zlp = true;
        }
        if self.active.as_ref().is_some_and(|frame| frame.started) {
            self.abort = Some(self.fid);
        }
        self.counters.discarded_frames = self
            .counters
            .discarded_frames
            .saturating_add(u64::from(self.latest.is_some()) + u64::from(self.active.is_some()));
        self.latest = None;
        self.active = None;
        self.payload = None;
        self.epoch = Some(epoch.into());
        self.last_sequence = None;
        self.last_time = None;
        Ok(())
    }
    /// Structural validation is not pixel decoding. Only baseline MJPEG at the
    /// advertised mode is accepted; unknown epochs/sequences never enter a queue.
    pub fn push(&mut self, epoch: &str, mut frame: VideoFrame) -> Result<bool> {
        if self.epoch.as_deref() != Some(epoch)
            || self.last_sequence.is_some_and(|s| frame.sequence <= s)
            || self
                .last_time
                .is_some_and(|t| frame.source_monotonic_micros < t)
        {
            frame.jpeg.fill(0);
            self.counters.stale_frames = self.counters.stale_frames.saturating_add(1);
            return Ok(false);
        }
        let valid = frame.valid() && baseline(&frame.jpeg);
        let mut jpeg = Bytes(std::mem::take(&mut frame.jpeg));
        ensure!(self.streaming(), "Camera is not committed");
        ensure!(
            valid
                && frame.format.encoding == VideoEncoding::Mjpeg
                && frame.format.width == WIDTH
                && frame.format.height == HEIGHT
                && frame.format.fps_num as u64 == FPS as u64 * frame.format.fps_den as u64,
            "Camera frame does not match advertised baseline MJPEG mode"
        );
        normalize_short_apps(&mut jpeg.0)?;
        ensure!(baseline(&jpeg.0), "Normalized camera header is not baseline MJPEG");
        self.last_sequence = Some(frame.sequence);
        self.last_time = Some(frame.source_monotonic_micros);
        if self.latest.replace(jpeg).is_some() {
            self.counters.discarded_frames = self.counters.discarded_frames.saturating_add(1);
        }
        Ok(true)
    }
    /// `None` means NAK/wait, never fabricate an empty image. Serialize calls in
    /// endpoint order. A returned empty Vec is a deliberate short/ZLP boundary.
    pub fn bulk_in(&mut self, requested: usize) -> std::result::Result<Option<Vec<u8>>, i32> {
        if !self.streaming() || self.halted[0] {
            return Err(EPIPE);
        }
        if requested == 0 {
            return Ok(Some(vec![]));
        }
        if !(2..=MAX_BULK_REQUEST).contains(&requested) {
            return Err(EINVAL);
        }
        if self.zlp {
            self.zlp = false;
            return Ok(Some(vec![]));
        }
        if self.payload.is_none() {
            if let Some(fid) = self.abort.take() {
                self.payload = Some(Payload {
                    bytes: Bytes(vec![2, EOH | ERR | EOF | fid]),
                    offset: 0,
                    last: false,
                });
            } else {
                if self.active.is_none() {
                    let Some(jpeg) = self.latest.take() else {
                        return Ok(None);
                    };
                    self.fid ^= FID;
                    self.active = Some(Frame {
                        jpeg,
                        offset: 0,
                        started: false,
                    });
                }
                let frame = self.active.as_mut().unwrap();
                let count = (MAX_PAYLOAD - 2).min(frame.jpeg.0.len() - frame.offset);
                let last = frame.offset + count == frame.jpeg.0.len();
                let mut bytes = Vec::with_capacity(count + 2);
                bytes.extend([2, EOH | self.fid | if last { EOF } else { 0 }]);
                bytes.extend_from_slice(&frame.jpeg.0[frame.offset..frame.offset + count]);
                frame.offset += count;
                frame.started = true;
                self.payload = Some(Payload {
                    bytes: Bytes(bytes),
                    offset: 0,
                    last,
                });
            }
        }
        let payload = self.payload.as_mut().unwrap();
        let count = requested.min(payload.bytes.0.len() - payload.offset);
        let bytes = payload.bytes.0[payload.offset..payload.offset + count].to_vec();
        payload.offset += count;
        if payload.offset == payload.bytes.0.len() {
            let payload = self.payload.take().unwrap();
            self.zlp = payload.bytes.0.len() < MAX_PAYLOAD && count == requested;
            if payload.last {
                self.active = None;
                self.counters.completed_frames = self.counters.completed_frames.saturating_add(1);
            }
        }
        Ok(Some(bytes))
    }
    /// No status notifications are advertised as ready: the outer executor must
    /// wait/cancel a status interrupt request, not return an invented event.
    pub fn interrupt_status(&self) -> std::result::Result<Option<Vec<u8>>, i32> {
        if !self.configured || self.halted[1] {
            return Err(EPIPE);
        }
        Ok(None)
    }
    pub fn control(&mut self, setup: [u8; 8], data: &[u8]) -> std::result::Result<Vec<u8>, i32> {
        let result = self.control_inner(setup, data);
        if result.is_err() {
            self.error = 7;
        }
        result
    }
    fn control_inner(&mut self, s: [u8; 8], data: &[u8]) -> std::result::Result<Vec<u8>, i32> {
        let value = u16::from_le_bytes([s[2], s[3]]);
        let index = u16::from_le_bytes([s[4], s[5]]);
        let length = u16::from_le_bytes([s[6], s[7]]) as usize;
        if length > 4096
            || (s[0] & 0x80 == 0 && data.len() != length)
            || (s[0] & 0x80 != 0 && !data.is_empty())
        {
            return Err(EPIPE);
        }
        let mut out = match (s[0], s[1]) {
            (0x80, 6) => match (value >> 8, value as u8) {
                (1, 0) if index == 0 => self.device_descriptor(),
                (2, 0) if index == 0 => Self::configuration(false),
                (3, n) => self.string(n, index).ok_or(EPIPE)?,
                (6, 0) if index == 0 => vec![10, 6, 0, 2, 0xef, 2, 1, 64, 1, 0],
                (7, 0) if index == 0 => Self::configuration(true),
                _ => return Err(EPIPE),
            },
            (0, 5) if value <= 127 && index == 0 && length == 0 => vec![],
            (0, 9) if value <= 1 && index == 0 && length == 0 => {
                self.configured = value == 1;
                self.halted = [false; 2];
                self.committed = false;
                self.probe = Self::default_control();
                self.commit = self.probe;
                self.clear_transport();
                vec![]
            }
            (0x80, 8) if value == 0 && index == 0 => vec![u8::from(self.configured)],
            (0x80, 0) if value == 0 && index == 0 => vec![0, 0],
            (0x81, 0) if value == 0 && index <= 1 && self.configured => vec![0, 0],
            (0x82, 0) if value == 0 && index == 0 => vec![0, 0],
            (0x82, 0)
                if value == 0
                    && self.configured
                    && [BULK_ENDPOINT as u16, STATUS_ENDPOINT as u16].contains(&index) =>
            {
                vec![
                    u8::from(self.halted[usize::from(index == STATUS_ENDPOINT as u16)]),
                    0,
                ]
            }
            (2, request @ (1 | 3))
                if value == 0
                    && length == 0
                    && self.configured
                    && [BULK_ENDPOINT as u16, STATUS_ENDPOINT as u16].contains(&index) =>
            {
                self.halted[usize::from(index == STATUS_ENDPOINT as u16)] = request == 3;
                vec![]
            }
            (0x81, 10) if value == 0 && index <= 1 && self.configured => vec![0],
            (1, 11) if value == 0 && index <= 1 && length == 0 && self.configured => {
                if index == 1 {
                    // Bulk VS exposes only alt0: Windows selects it AFTER COMMIT.
                    // Reset transfer ownership/epoch, retain negotiated Probe/Commit.
                    // Primary driver contract: https://docs.tinyusb.org/en/latest/reference/class/video.html#frame-flow
                    self.halted[0] = false;
                    self.clear_transport();
                }
                vec![]
            }
            (0xa1, 0x81) if index == 0 && value == 0x0200 && self.configured => {
                let error = self.error;
                self.error = 0;
                vec![error]
            }
            (0xa1, 0x86) if index == 0 && value == 0x0200 && self.configured => vec![1],
            (0x21, 1)
                if index == 1
                    && [0x0100, 0x0200].contains(&value)
                    && length == CONTROL_SIZE
                    && self.configured =>
            {
                if data[2] > 1 || data[3] > 1 || u16::from_le_bytes([data[0], data[1]]) & !0x1f != 0
                {
                    return Err(EPIPE);
                }
                let interval = u32::from_le_bytes(data[4..8].try_into().unwrap());
                if value == 0x0200 && (data[2] != 1 || data[3] != 1 || interval != INTERVAL_100NS) {
                    return Err(EPIPE);
                }
                if value == 0x0100 {
                    self.probe = Self::default_control();
                } else {
                    self.commit = self.probe;
                    self.committed = true;
                    self.clear_transport();
                }
                vec![]
            }
            (0xa1, request)
                if index == 1 && [0x0100, 0x0200].contains(&value) && self.configured =>
            {
                match request {
                    0x85 => (CONTROL_SIZE as u16).to_le_bytes().to_vec(),
                    0x86 => vec![3],
                    0x81 => {
                        if value == 0x0100 {
                            self.probe.to_vec()
                        } else {
                            self.commit.to_vec()
                        }
                    }
                    0x82 | 0x83 | 0x87 => Self::default_control().to_vec(),
                    0x84 => vec![0; CONTROL_SIZE],
                    _ => return Err(EPIPE),
                }
            }
            _ => return Err(EPIPE),
        };
        out.truncate(length);
        Ok(out)
    }
}
/// Remove only identifier-less optional APP segments rejected by common MJPEG
/// decoders. Valid metadata and the complete encoded scan remain byte-exact.
/// The caller retains the epoch, mode and baseline guards and owns zeroization.
fn normalize_short_apps(bytes:&mut Vec<u8>)->Result<usize>{
    ensure!(bytes.len()<=MAX_VIDEO_FRAME&&bytes.starts_with(&[255,216])&&bytes.ends_with(&[255,217]),"Bounded complete JPEG required");
    // No APP marker means no interoperability work; preserve the existing
    // structural-only fixtures and leave pixel validation to the consumer.
    if !bytes.windows(2).any(|v|v[0]==255&&(224..=239).contains(&v[1])){return Ok(0);}
    let mut at=2;let mut count=0;let mut remove=Vec::new();let mut scan=false;
    while at+4<=bytes.len(){
        ensure!(count<256&&bytes[at]==255,"Invalid bounded JPEG marker");let begin=at;
        while bytes.get(at)==Some(&255){at+=1;}
        let marker=*bytes.get(at).ok_or_else(||anyhow::anyhow!("Truncated JPEG marker"))?;at+=1;
        ensure!(!matches!(marker,0|1|216|217|208..=215),"Unexpected JPEG header marker");
        let length=bytes.get(at..at+2).ok_or_else(||anyhow::anyhow!("Truncated JPEG length"))?;let length=u16::from_be_bytes(length.try_into().unwrap())as usize;
        ensure!(length>=2&&at+length<=bytes.len(),"Invalid JPEG segment length");let end=at+length;
        if marker==218{scan=true;break;}
        if (224..=239).contains(&marker)&&length<6{ensure!(remove.len()<32,"Short APP segment limit");remove.push((begin,end));}
        at=end;count+=1;
    }
    ensure!(scan,"JPEG scan header unavailable");
    if remove.is_empty(){return Ok(0);}
    let original=bytes.len();let mut read=0;let mut write=0;
    for &(start,end)in &remove{bytes.copy_within(read..start,write);write+=start-read;read=end;}
    bytes.copy_within(read..original,write);let length=write+original-read;
    bytes[length..].fill(0);bytes.truncate(length);Ok(remove.len())
}

fn baseline(bytes: &[u8]) -> bool {
    let mut at = 2;
    while at + 4 <= bytes.len().saturating_sub(2) {
        if bytes[at] != 0xff {
            return false;
        }
        while at < bytes.len() - 2 && bytes[at] == 0xff {
            at += 1;
        }
        let Some(&marker) = bytes.get(at) else {
            return false;
        };
        at += 1;
        if [0xc0, 0xc1, 0xc2].contains(&marker) {
            return marker == 0xc0;
        }
        if marker == 1 || (0xd0..=0xd7).contains(&marker) {
            continue;
        }
        if [0, 0xd8, 0xd9, 0xda].contains(&marker) || at + 2 > bytes.len() {
            return false;
        }
        let length = u16::from_be_bytes([bytes[at], bytes[at + 1]]) as usize;
        if length < 2 {
            return false;
        }
        let Some(next) = at.checked_add(length) else {
            return false;
        };
        if next > bytes.len() - 2 {
            return false;
        }
        at = next;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    const E: &str = "11111111111111111111111111111111";
    fn setup(t: u8, r: u8, v: u16, i: u16, n: u16) -> [u8; 8] {
        let mut s = [t, r, 0, 0, 0, 0, 0, 0];
        s[2..4].copy_from_slice(&v.to_le_bytes());
        s[4..6].copy_from_slice(&i.to_le_bytes());
        s[6..].copy_from_slice(&n.to_le_bytes());
        s
    }
    fn camera() -> Camera {
        let mut c = Camera::new(
            Identity {
                vendor: 0x1209,
                product: 1,
            },
            "Fixture01".into(),
        )
        .unwrap();
        c.control(setup(0, 9, 1, 0, 0), &[]).unwrap();
        let p = Camera::default_control();
        c.control(setup(0x21, 1, 0x200, 1, 34), &p).unwrap();
        c.begin_epoch(E).unwrap();
        c
    }
    // Structural JPEG fixture only: this deliberately does not claim pixel decoding.
    fn frame(seq: u64, size: usize) -> VideoFrame {
        let mut j = vec![
            0xff, 0xd8, 0xff, 0xc0, 0, 17, 8, 1, 0xe0, 2, 0x80, 3, 1, 0x11, 0, 2, 0x11, 0, 3, 0x11,
            0,
        ];
        j.resize(size.max(23) - 2, 0);
        j.extend([0xff, 0xd9]);
        VideoFrame {
            sequence: seq,
            source_monotonic_micros: seq,
            format: VideoFormat {
                encoding: VideoEncoding::Mjpeg,
                width: WIDTH,
                height: HEIGHT,
                fps_num: FPS,
                fps_den: 1,
            },
            jpeg: j,
        }
    }
    #[test]
    fn short_app_interop_keeps_valid_metadata_and_scan_byte_exact()->Result<()> {
        let golden=include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg").to_vec();let mut unchanged=golden.clone();assert_eq!(normalize_short_apps(&mut unchanged)?,0);assert_eq!(unchanged,golden);
        let mut source=golden[..2].to_vec();source.extend([255,224,0,33]);source.extend(b"AVI1");source.extend([0;27]);source.extend([255,225,0,4,0,0]);source.extend(&golden[2..]);
        let mut expected=golden[..2].to_vec();expected.extend([255,224,0,33]);expected.extend(b"AVI1");expected.extend([0;27]);expected.extend(&golden[2..]);assert_eq!(normalize_short_apps(&mut source)?,1);assert_eq!(source,expected);assert!(baseline(&source));Ok(())
    }
    #[test]
    fn short_app_malformed_and_limits_fail_without_partial_compaction(){
        let golden=include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg");
        for segment in [vec![255,225,0,1],vec![255,225,255,255]]{let mut data=golden[..2].to_vec();data.extend(segment);data.extend(&golden[2..]);let before=data.clone();assert!(normalize_short_apps(&mut data).is_err());assert_eq!(data,before);}
        let mut data=golden[..2].to_vec();for _ in 0..33{data.extend([255,225,0,2]);}data.extend(&golden[2..]);assert!(normalize_short_apps(&mut data).is_err());let mut oversized=vec![0;MAX_VIDEO_FRAME+1];assert!(normalize_short_apps(&mut oversized).is_err());
    }
    #[test]
    fn camera_push_normalizes_only_current_epoch_after_mode_guards()->Result<()> {
        let golden=include_bytes!("../../tests/data/private_uvc_colorbars_640x480.jpg").to_vec();let mut jpeg=golden[..2].to_vec();jpeg.extend([255,225,0,4,0,0]);jpeg.extend(&golden[2..]);let make=||VideoFrame{sequence:1,source_monotonic_micros:1,format:Camera::format(),jpeg:jpeg.clone()};let mut c=camera();assert!(!c.push("retired",make())?);assert!(c.latest.is_none());assert!(c.push(E,make())?);assert_eq!(c.latest.as_ref().unwrap().0,golden);Ok(())
    }
    #[test]
    fn descriptor_lengths_and_bulk_contract() {
        let d = Camera::configuration(false);
        assert_eq!(d.len(), 155);
        assert_eq!(u16::from_le_bytes([d[2], d[3]]) as usize, d.len());
        let mut at = 0;
        let mut bulk = false;
        let mut mjpeg = false;
        while at < d.len() {
            let n = d[at] as usize;
            assert!(n >= 2 && at + n <= d.len());
            let v = &d[at..at + n];
            if v[1] == 5 && v[2] == BULK_ENDPOINT {
                assert_eq!(&v[3..6], &[2, 0, 2]);
                bulk = true;
            }
            if n == 11 && v[1] == 0x24 && v[2] == 6 {
                assert_eq!(v[5], 0);
                mjpeg = true;
            }
            at += n;
        }
        assert!(bulk && mjpeg);
    }
    #[test]
    fn strict_probe_commit_and_halt() {
        let mut c = camera();
        assert_eq!(
            c.control(setup(0xa1, 0x85, 0x100, 1, 2), &[]).unwrap(),
            [34, 0]
        );
        let mut p = Camera::default_control();
        p[4..8].fill(0);
        assert!(c.control(setup(0x21, 1, 0x200, 1, 34), &p).is_err());
        c.control(setup(0x21, 1, 0x100, 1, 34), &p).unwrap();
        assert_eq!(c.probe, Camera::default_control());
        c.control(setup(2, 3, 0, 0x81, 0), &[]).unwrap();
        assert_eq!(c.bulk_in(512), Err(EPIPE));
        assert_eq!(c.control(setup(0x82, 0, 0, 0x81, 2), &[]).unwrap(), [1, 0]);
        c.control(setup(2, 1, 0, 0x81, 0), &[]).unwrap();
        assert_eq!(c.bulk_in(512).unwrap(), None);
        c.control(setup(0, 9, 0, 0, 0), &[]).unwrap();
        assert!(c.control(setup(0xa1, 0x81, 0x100, 1, 34), &[]).is_err());
    }
    #[test]
    fn bulk_alt_zero_preserves_commit_but_retires_old_epoch_and_payload(){
        let mut c=camera();let probe=c.probe;let commit=c.commit;
        assert!(c.push(E,frame(1,100)).unwrap());assert!(c.bulk_in(16).unwrap().is_some());
        c.control(setup(2,3,0,0x81,0),&[]).unwrap();
        c.control(setup(1,11,0,1,0),&[]).unwrap();
        assert!(c.streaming(),"bulk alt0 after COMMIT must preserve negotiated stream");assert_eq!(c.probe,probe);assert_eq!(c.commit,commit);assert!(!c.halted[0]);
        assert!(c.payload.is_none()&&c.active.is_none()&&c.latest.is_none());assert!(c.begin_epoch(E).is_err());assert!(!c.push(E,frame(2,100)).unwrap());assert_eq!(c.bulk_in(512).unwrap(),None);
        let fresh="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";c.begin_epoch(fresh).unwrap();assert!(c.push(fresh,frame(1,40)).unwrap());assert_eq!(c.bulk_in(512).unwrap().unwrap().len(),42);
        assert!(c.control(setup(1,11,1,1,0),&[]).is_err());assert!(c.streaming(),"invalid alternate setting must stall without resetting valid commit");
        c.control(setup(0,9,0,0,0),&[]).unwrap();assert!(!c.streaming());assert!(!c.committed);assert_eq!(c.bulk_in(512),Err(EPIPE));
    }
    #[test]
    fn bounded_latest_queue_and_stale_frames() {
        let mut c = camera();
        assert!(c.push(E, frame(1, 30)).unwrap());
        assert!(c.push(E, frame(2, 40)).unwrap());
        assert_eq!(c.counters.discarded_frames, 1);
        assert!(!c.push(E, frame(1, 30)).unwrap());
        let mut bad = frame(3, 30);
        bad.jpeg[3] = 0xc2;
        assert!(c.push(E, bad).is_err());
        assert!(c.push(E, frame(3, MAX_VIDEO_FRAME + 1)).is_err());
        assert_eq!(c.latest.as_ref().unwrap().0.len(), 40);
    }
    #[test]
    fn payload_boundaries_and_frame_id() {
        let mut c = camera();
        c.push(E, frame(1, MAX_PAYLOAD + 20)).unwrap();
        let a = c.bulk_in(MAX_PAYLOAD).unwrap().unwrap();
        assert_eq!(a.len(), MAX_PAYLOAD);
        assert_eq!(a[0], 2);
        assert_eq!(a[1] & EOF, 0);
        let b = c.bulk_in(MAX_PAYLOAD).unwrap().unwrap();
        assert_eq!(b[1] & EOF, EOF);
        assert_eq!(a[1] & FID, b[1] & FID);
        assert_eq!(c.counters.completed_frames, 1);
        assert_eq!(c.bulk_in(MAX_PAYLOAD).unwrap(), None);
        c.push(E, frame(2, 30)).unwrap();
        let b = c.bulk_in(32).unwrap().unwrap();
        assert_ne!(a[1] & FID, b[1] & FID);
        assert_eq!(c.bulk_in(32).unwrap(), Some(vec![]));
    }
    #[test]
    fn epoch_cut_discards_old_payload_and_terminates_frame() {
        let mut c = camera();
        c.push(E, frame(1, 2000)).unwrap();
        let a = c.bulk_in(512).unwrap().unwrap();
        let new = "22222222222222222222222222222222";
        c.begin_epoch(new).unwrap();
        assert_eq!(c.bulk_in(512).unwrap(), Some(vec![]));
        let end = c.bulk_in(512).unwrap().unwrap();
        assert_eq!(end, [2, EOH | ERR | EOF | (a[1] & FID)]);
        assert!(!c.push(E, frame(2, 30)).unwrap());
        c.push(new, frame(1, 30)).unwrap();
        let b = c.bulk_in(512).unwrap().unwrap();
        assert_ne!(a[1] & FID, b[1] & FID);
        assert_eq!(b.len(), 32);
    }
    #[test]
    fn control_reset_retires_source_epoch_atomically() {
        let mut c = camera();
        c.push(E, frame(1, 30)).unwrap();
        let p = Camera::default_control();
        c.control(setup(0x21, 1, 0x200, 1, 34), &p).unwrap();
        assert!(!c.push(E, frame(2, 30)).unwrap());
        assert!(c.begin_epoch(E).is_err());
        let next = "33333333333333333333333333333333";
        c.begin_epoch(next).unwrap();
        assert!(c.push(next, frame(1, 30)).unwrap());
    }
}
