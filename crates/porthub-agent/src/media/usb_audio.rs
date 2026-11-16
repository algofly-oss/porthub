//! Experimental USB Audio Class 1.0 microphone function, separate from physical USB adapters.
//! USB/IP authentication, import framing and native capture lifetime belong to its caller.
use anyhow::{ensure, Result};
use std::collections::VecDeque;
pub const RATE: u32 = 48_000;
pub const PACKET_BYTES: usize = 96; // Full-speed 1ms mono S16LE.
const QUEUED_SAMPLES: usize = 4800;
#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub vendor: u16,
    pub product: u16,
}
/// VID/PID are supplied explicitly by the integrator; this module claims no vendor allocation.
pub struct Microphone {
    identity: Identity,
    serial: String,
    name: String,
    configured: bool,
    alternate: u8,
    generation: u64,
    pcm: VecDeque<i16>,
    pub underrun_samples: u64,
    pub discarded_samples: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct IsoPacket {
    pub offset: u32,
    pub length: u32,
}
pub struct IsoReply {
    pub packed: Vec<u8>,
    pub actual_lengths: Vec<u32>,
}
impl Microphone {
    pub fn new(identity: Identity, serial: String) -> Result<Self> {
        ensure!(
            !serial.is_empty()
                && serial.len() <= 64
                && serial.bytes().all(|v| v.is_ascii_alphanumeric()),
            "Invalid virtual microphone identity"
        );
        Ok(Self {
            identity,
            serial,
            name: "PortHub Forwarded Microphone".into(),
            configured: false,
            alternate: 0,
            generation: 0,
            pcm: VecDeque::new(),
            underrun_samples: 0,
            discarded_samples: 0,
        })
    }
    pub fn set_name(&mut self, name: &str) -> Result<()> {
        ensure!(
            !name.is_empty() && !name.chars().any(char::is_control),
            "Invalid virtual microphone display name"
        );
        let mut name = format!("PortHub · {name}");
        while name.encode_utf16().count() > 126 {
            name.pop();
        }
        self.name = name;
        Ok(())
    }
    pub fn stop(&mut self) {
        self.configured = false;
        self.alternate = 0;
        self.clear();
    }
    pub fn streaming(&self) -> bool {
        self.configured && self.alternate == 1
    }
    pub fn device_descriptor(&self) -> Vec<u8> {
        let mut d = vec![18, 1, 0x10, 0x01, 0, 0, 0, 64, 0, 0, 0, 0, 0, 1, 1, 2, 3, 1];
        d[8..10].copy_from_slice(&self.identity.vendor.to_le_bytes());
        d[10..12].copy_from_slice(&self.identity.product.to_le_bytes());
        d
    }
    pub fn configuration_descriptor() -> Vec<u8> {
        vec![
            9, 2, 100, 0, 2, 1, 0, 0x80, 1, // Configuration, two interfaces.
            9, 4, 0, 0, 0, 1, 1, 0, 0, // AudioControl.
            9, 0x24, 1, 0, 1, 30, 0, 1, 1, // UAC1 header, AC total30, AS interface1.
            12, 0x24, 2, 1, 1, 2, 0, 1, 0, 0, 0, 0, // Microphone input terminal1.
            9, 0x24, 3, 2, 1, 1, 0, 1, 0, // USB streaming output terminal2, linked to1.
            9, 4, 1, 0, 0, 1, 2, 0, 0, // AS zero-bandwidth alternate0.
            9, 4, 1, 1, 1, 1, 2, 0, 0, // AS alternate1, one input endpoint.
            7, 0x24, 1, 2, 1, 1, 0, // AS terminal2, PCM format.
            11, 0x24, 2, 1, 1, 2, 16, 1, 0x80, 0xbb, 0, // TypeI mono16bit48k fixed.
            9, 5, 0x81, 0x0d, 96, 0, 1, 0, 0, // Synchronous isochronous IN, 1ms96bytes.
            7, 0x25, 1, 0, 0, 0, 0, // No variable sample-rate endpoint control.
        ]
    }
    fn string_descriptor(&self, index: u8) -> Option<Vec<u8>> {
        if index == 0 {
            return Some(vec![4, 3, 9, 4]);
        }
        let text = match index {
            1 => "PortHub",
            2 => &self.name,
            3 => &self.serial,
            _ => return None,
        };
        let mut bytes = vec![0, 3];
        for v in text.encode_utf16() {
            bytes.extend(v.to_le_bytes());
        }
        bytes[0] = bytes.len() as u8;
        Some(bytes)
    }
    /// Unknown or malformed requests STALL (-EPIPE). No guessed successful controls.
    pub fn control(&mut self, setup: [u8; 8], data: &[u8]) -> std::result::Result<Vec<u8>, i32> {
        let value = u16::from_le_bytes([setup[2], setup[3]]);
        let index = u16::from_le_bytes([setup[4], setup[5]]);
        let length = u16::from_le_bytes([setup[6], setup[7]]) as usize;
        if length > 4096 || setup[0] & 0x80 == 0 && data.len() != length {
            return Err(-32);
        }
        let mut response = match (setup[0], setup[1]) {
            (0x80, 6) => match (value >> 8, value as u8) {
                (1, 0) if index == 0 => self.device_descriptor(),
                (2, 0) if index == 0 => Self::configuration_descriptor(),
                (3, n) => self.string_descriptor(n).ok_or(-32)?,
                _ => return Err(-32),
            },
            (0x80, 8) if value == 0 && index == 0 => vec![u8::from(self.configured)],
            (0, 5) if value <= 127 && index == 0 && length == 0 => vec![],
            (0, 9) if value <= 1 && index == 0 && length == 0 => {
                self.configured = value == 1;
                self.alternate = 0;
                self.clear();
                vec![]
            }
            (0x81, 10) if value == 0 && index <= 1 && self.configured => {
                vec![if index == 1 { self.alternate } else { 0 }]
            }
            (1, 11)
                if index <= 1
                    && value <= 1
                    && self.configured
                    && length == 0
                    && (index == 1 || value == 0) =>
            {
                if index == 1 {
                    self.alternate = value as u8;
                    self.clear();
                }
                vec![]
            }
            (0x80, 0) if value == 0 && index == 0 => vec![0, 0],
            (0x81, 0) if value == 0 && index <= 1 => vec![0, 0],
            (0x82, 0) if value == 0 && (index == 0 || index == 0x81) => vec![0, 0],
            // Some class drivers probe the fixed sampling frequency regardless of advertised control support.
            (0xa2, 0x81) if index == 0x81 && value == 0x0100 => vec![0x80, 0xbb, 0],
            (0x22, 1)
                if index == 0x81 && value == 0x0100 && length == 3 && data == [0x80, 0xbb, 0] =>
            {
                vec![]
            }
            _ => return Err(-32),
        };
        response.truncate(length);
        Ok(response)
    }
    pub fn stream_generation(&self) -> u64 {
        self.generation
    }
    /// Retire queued source audio on consumer idle without changing USB controls.
    pub fn retire_pcm_epoch(&mut self) {
        self.clear();
    }
    fn clear(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        for v in &mut self.pcm {
            *v = 0;
        }
        self.pcm.clear();
    }
    pub fn push_f32le(&mut self, frame: &[u8]) -> Result<()> {
        ensure!(
            self.streaming(),
            "Virtual microphone is not in its active streaming alternate"
        );
        ensure!(
            !frame.is_empty()
                && frame.len() % 4 == 0
                && frame.len() <= porthub_components::media::MAX_PCM_FRAME,
            "Invalid native PCM frame"
        );
        for sample in frame.chunks_exact(4) {
            let value = f32::from_le_bytes(sample.try_into().unwrap());
            ensure!(value.is_finite(), "Invalid native PCM sample");
        }
        for sample in frame.chunks_exact(4) {
            let value = f32::from_le_bytes(sample.try_into().unwrap());
            let value = (value.clamp(-1., 1.) * 32768.)
                .round()
                .clamp(-32768., 32767.) as i16;
            if self.pcm.len() == QUEUED_SAMPLES {
                self.pcm.pop_front();
                self.discarded_samples = self.discarded_samples.saturating_add(1);
            }
            self.pcm.push_back(value);
        }
        Ok(())
    }
    /// Payload is packed in descriptor order as required by USB/IP ISO returns.
    pub fn isochronous(&mut self, buffer_length: usize, packets: &[IsoPacket]) -> Result<IsoReply> {
        ensure!(self.streaming(), "Virtual microphone stream is inactive");
        ensure!(
            !packets.is_empty() && packets.len() <= 1024 && buffer_length <= 1024 * PACKET_BYTES,
            "ISO transfer exceeds bound"
        );
        let mut last = 0;
        for p in packets {
            let offset = p.offset as usize;
            let length = p.length as usize;
            ensure!(
                length <= PACKET_BYTES && length % 2 == 0 && offset >= last,
                "Invalid ISO packet range"
            );
            last = offset
                .checked_add(length)
                .ok_or_else(|| anyhow::anyhow!("ISO range overflow"))?;
            ensure!(last <= buffer_length, "ISO packet outside transfer buffer");
        }
        let mut packed = Vec::with_capacity(packets.len() * PACKET_BYTES);
        let mut actual_lengths = Vec::with_capacity(packets.len());
        for p in packets {
            for _ in 0..p.length / 2 {
                let sample = match self.pcm.pop_front() {
                    Some(v) => v,
                    None => {
                        self.underrun_samples = self.underrun_samples.saturating_add(1);
                        0
                    }
                };
                packed.extend(sample.to_le_bytes());
            }
            actual_lengths.push(p.length);
        }
        Ok(IsoReply {
            packed,
            actual_lengths,
        })
    }
}
impl Drop for Microphone {
    fn drop(&mut self) {
        self.clear();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn mic() -> Microphone {
        Microphone::new(
            Identity {
                vendor: 0,
                product: 1,
            },
            "PrototypeOnly01".into(),
        )
        .unwrap()
    }
    fn active() -> Microphone {
        let mut m = mic();
        m.control([0, 9, 1, 0, 0, 0, 0, 0], &[]).unwrap();
        m.control([1, 11, 1, 0, 1, 0, 0, 0], &[]).unwrap();
        m
    }
    #[test]
    fn consumer_idle_retires_pcm_without_disabling_the_usb_alternate() {
        let mut m=active();let generation=m.stream_generation();
        m.push_f32le(&0.5f32.to_le_bytes()).unwrap();assert!(!m.pcm.is_empty());
        m.retire_pcm_epoch();assert!(m.streaming());assert!(m.pcm.is_empty());
        assert_ne!(m.stream_generation(),generation,"Frames parsed before idle must fail the receiver generation check");
    }
    #[test]
    fn external_device_label_is_distinct_bounded_and_utf16_safe() -> Result<()> {
        let mut mic = Microphone::new(
            Identity {
                vendor: 0x1209,
                product: 1,
            },
            "PrivateOnly".into(),
        )?;
        mic.set_name(&format!("Source host · {}", "🎤".repeat(160)))?;
        let bytes = mic.control([0x80, 6, 2, 3, 9, 4, 255, 0], &[]).unwrap();
        assert_eq!(bytes[0] as usize, bytes.len());
        assert!(bytes.len() <= 254);
        let decoded = String::from_utf16(
            &bytes[2..]
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes(v.try_into().unwrap()))
                .collect::<Vec<_>>(),
        )?;
        assert!(decoded.starts_with("PortHub · Source host"));
        assert!(mic.set_name("Source\nunsafe").is_err());
        Ok(())
    }
    #[test]
    fn descriptor_lengths_terminal_links_and_format_are_consistent() {
        let c = Microphone::configuration_descriptor();
        assert_eq!(c.len(), 100);
        let mut n = 0;
        while n < c.len() {
            let size = c[n] as usize;
            assert!(size >= 3);
            n += size;
        }
        assert_eq!(n, c.len());
        let mut m = mic();
        assert_eq!(
            m.control([0x80, 6, 0, 1, 0, 0, 8, 0], &[]).unwrap().len(),
            8
        );
        assert_eq!(m.control([0x80, 6, 0, 6, 0, 0, 10, 0], &[]), Err(-32));
    }
    #[test]
    fn only_explicit_configured_alternate_streams_and_disable_clears_private_pcm() {
        let mut m = mic();
        assert!(!m.streaming());
        assert!(m.push_f32le(&0.2f32.to_le_bytes()).is_err());
        assert!(m.control([1, 11, 1, 0, 1, 0, 0, 0], &[]).is_err());
        m = active();
        m.push_f32le(&1f32.to_le_bytes()).unwrap();
        m.control([1, 11, 0, 0, 1, 0, 0, 0], &[]).unwrap();
        assert!(m.pcm.is_empty() && !m.streaming());
    }
    #[test]
    fn iso_ranges_are_checked_before_consumption_and_pcm_is_bounded() {
        let mut m = active();
        m.push_f32le(&1f32.to_le_bytes()).unwrap();
        assert!(m
            .isochronous(
                96,
                &[IsoPacket {
                    offset: 95,
                    length: 2
                }]
            )
            .is_err());
        assert_eq!(m.pcm.len(), 1);
        let out = m
            .isochronous(
                96,
                &[IsoPacket {
                    offset: 0,
                    length: 96,
                }],
            )
            .unwrap();
        assert_eq!(&out.packed[..2], &32767i16.to_le_bytes());
        assert_eq!(out.packed.len(), 96);
        assert_eq!(m.underrun_samples, 47);
        assert!(m
            .control([0x22, 1, 0, 1, 0x81, 0, 3, 0], &[0, 0, 0])
            .is_err());
    }
}
