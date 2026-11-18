//! Fixed PCM framing and at most100ms playback/capture backlog.
use anyhow::{ensure, Result};
use porthub_components::media::{MAX_PCM_FRAME, PCM_RATE};
use std::{collections::VecDeque, io::Read};
pub(crate) const QUEUE_BYTES: usize = PCM_RATE as usize * 4 / 10; // 100ms maximum, oldest samples discarded.
#[derive(Default)]
pub(crate) struct Queue(pub(crate) VecDeque<u8>);
impl Queue {
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        if bytes.len() % 4 != 0 {
            return;
        }
        for bytes in bytes.chunks(4) {
            while self.0.len() + 4 > QUEUE_BYTES {
                for _ in 0..4 {
                    self.0.pop_front();
                }
            }
            self.0.extend(bytes);
        }
    }
    pub(crate) fn clear(&mut self) {
        for byte in &mut self.0 {
            *byte = 0;
        }
        self.0.clear();
    }
}
pub(crate) fn valid_samples(bytes: &[u8]) -> bool {
    bytes.len() % 4 == 0
        && bytes
            .chunks_exact(4)
            .all(|v| f32::from_le_bytes(v.try_into().unwrap()).is_finite())
}
pub(crate) fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut size = [0u8; 4];
    match reader.read(&mut size[..1])? {
        0 => return Ok(None),
        _ => reader.read_exact(&mut size[1..])?,
    }
    let size = u32::from_le_bytes(size) as usize;
    ensure!(
        size > 0 && size <= MAX_PCM_FRAME && size % 4 == 0,
        "Invalid PCM frame size"
    );
    let mut data = vec![0; size];
    reader.read_exact(&mut data)?;
    ensure!(valid_samples(&data), "Invalid PCM sample");
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pcm_stream_validates_each_frame_before_render() {
        for samples in [
            vec![],
            vec![0],
            vec![0; MAX_PCM_FRAME + 4],
            f32::NAN.to_le_bytes().to_vec(),
        ] {
            let bytes = [
                (samples.len() as u32).to_le_bytes().as_slice(),
                samples.as_slice(),
            ]
            .concat();
            assert!(read_frame(&mut bytes.as_slice()).is_err());
        }
        let payload = [0.25f32.to_le_bytes(), (-0.5f32).to_le_bytes()].concat();
        let bytes = [8u32.to_le_bytes().as_slice(), payload.as_slice()].concat();
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(payload));
        assert!(read_frame(&mut &[4, 0, 0, 0, 0][..]).is_err());
    }
    #[test]
    fn bounded_playback_discards_whole_old_samples_and_cancel_clears() {
        let mut queue = Queue::default();
        queue.push(&vec![0; QUEUE_BYTES]);
        queue.push(&0.5f32.to_le_bytes());
        assert_eq!(queue.0.len(), QUEUE_BYTES);
        assert_eq!(
            queue.0.iter().rev().take(4).copied().collect::<Vec<_>>(),
            0.5f32.to_le_bytes().into_iter().rev().collect::<Vec<_>>()
        );
        queue.clear();
        assert!(queue.0.is_empty());
    }
}
