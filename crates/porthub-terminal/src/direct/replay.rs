//! One attachment epoch's bounded data journal, shared by direct and relay paths.
//! Commit receive progress only after the terminal/PTY accepts the bytes. A new
//! process/attachment epoch must not automatically replay old uncertain input.
use anyhow::{ensure, Result};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};

pub const MAX_PAYLOAD: usize = 16 * 1024;
pub const MAX_BYTES: usize = 64 * 1024;
pub const MAX_FRAMES: usize = 256;
pub const MAX_SEQUENCE: u64 = (1u64 << 53) - 1;

#[derive(Clone)]
pub struct Frame {
    epoch: String,
    sequence: u64,
    payload: Arc<[u8]>,
}
impl Frame {
    /// Parse transport metadata only after verifying its attachment and role.
    pub fn new(epoch: &str, sequence: u64, payload: &[u8]) -> Result<Self> {
        valid_epoch(epoch)?;
        ensure!(
            (1..=MAX_SEQUENCE).contains(&sequence),
            "invalid terminal sequence"
        );
        ensure!(
            !payload.is_empty() && payload.len() <= MAX_PAYLOAD,
            "invalid terminal payload"
        );
        Ok(Self {
            epoch: epoch.into(),
            sequence,
            payload: payload.into(),
        })
    }
    pub fn epoch(&self) -> &str {
        &self.epoch
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}
fn valid_epoch(epoch: &str) -> Result<()> {
    ensure!(
        crate::protocol::token(epoch, 32),
        "invalid terminal attachment epoch"
    );
    Ok(())
}

pub struct Sender {
    epoch: String,
    last: u64,
    acknowledged: u64,
    pending: VecDeque<Frame>,
    bytes: usize,
}
impl Sender {
    pub fn new(epoch: &str) -> Result<Self> {
        valid_epoch(epoch)?;
        Ok(Self {
            epoch: epoch.into(),
            last: 0,
            acknowledged: 0,
            pending: VecDeque::new(),
            bytes: 0,
        })
    }
    /// Backpressure is explicit: callers retain unsent bytes rather than drop
    /// keystrokes or allocate an unbounded queue during a stalled connection.
    pub fn enqueue(&mut self, payload: &[u8]) -> Result<Frame> {
        ensure!(
            self.pending.len() < MAX_FRAMES && self.bytes + payload.len() <= MAX_BYTES,
            "terminal replay journal is full"
        );
        let sequence = self
            .last
            .checked_add(1)
            .filter(|v| *v <= MAX_SEQUENCE)
            .ok_or_else(|| anyhow::anyhow!("terminal sequence exhausted"))?;
        let frame = Frame::new(&self.epoch, sequence, payload)?;
        self.bytes += payload.len();
        self.last = sequence;
        self.pending.push_back(frame.clone());
        Ok(frame)
    }
    pub fn acknowledge(&mut self, epoch: &str, sequence: u64) -> Result<()> {
        ensure!(
            epoch == self.epoch,
            "terminal acknowledgement epoch mismatch"
        );
        ensure!(
            sequence <= self.last,
            "terminal acknowledgement exceeds sent data"
        );
        if sequence <= self.acknowledged {
            return Ok(());
        }
        while self
            .pending
            .front()
            .is_some_and(|frame| frame.sequence <= sequence)
        {
            self.bytes -= self.pending.pop_front().unwrap().payload.len();
        }
        self.acknowledged = sequence;
        Ok(())
    }
    /// Replays retain original sequence numbers when the carrier changes.
    pub fn replay(&self) -> impl Iterator<Item = &Frame> {
        self.pending.iter()
    }
    pub fn retained_bytes(&self) -> usize {
        self.bytes
    }
}

pub struct Receiver {
    epoch: String,
    committed: u64,
    pending: BTreeMap<u64, Frame>,
    bytes: usize,
}
impl Receiver {
    pub fn new(epoch: &str) -> Result<Self> {
        valid_epoch(epoch)?;
        Ok(Self {
            epoch: epoch.into(),
            committed: 0,
            pending: BTreeMap::new(),
            bytes: 0,
        })
    }
    /// True inserts new bytes; false is a duplicate on either carrier. Gaps are
    /// retained within a small bounded window so delayed direct data can arrive
    /// after relay retransmissions without reordering terminal input/output.
    pub fn stage(&mut self, frame: Frame) -> Result<bool> {
        ensure!(frame.epoch == self.epoch, "terminal data epoch mismatch");
        if frame.sequence <= self.committed {
            return Ok(false);
        }
        ensure!(
            frame.sequence - self.committed <= MAX_FRAMES as u64,
            "terminal receive sequence exceeds window"
        );
        if let Some(previous) = self.pending.get(&frame.sequence) {
            ensure!(
                previous.payload == frame.payload,
                "conflicting terminal replay"
            );
            return Ok(false);
        }
        ensure!(
            self.pending.len() < MAX_FRAMES && self.bytes + frame.payload.len() <= MAX_BYTES,
            "terminal receive journal is full"
        );
        self.bytes += frame.payload.len();
        self.pending.insert(frame.sequence, frame);
        Ok(true)
    }
    pub fn next(&self) -> Option<&Frame> {
        self.pending.get(&self.committed.saturating_add(1))
    }
    /// Call only after applying `next()` successfully. Failed/backpressured PTY
    /// writes leave both the bytes and acknowledgement cursor unchanged.
    pub fn commit(&mut self, sequence: u64) -> Result<()> {
        ensure!(
            sequence == self.committed + 1 && self.pending.contains_key(&sequence),
            "terminal commit is not the next queued frame"
        );
        self.bytes -= self.pending.remove(&sequence).unwrap().payload.len();
        self.committed = sequence;
        Ok(())
    }
    pub fn acknowledged(&self) -> u64 {
        self.committed
    }
    pub fn retained_bytes(&self) -> usize {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const EPOCH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    #[test]
    fn relay_replay_and_delayed_direct_frames_apply_keystrokes_once_in_order() -> Result<()> {
        let mut sender = Sender::new(EPOCH)?;
        let mut receiver = Receiver::new(EPOCH)?;
        let first = sender.enqueue(b"echo ")?;
        let second = sender.enqueue(b"hello\r")?;
        receiver.stage(second.clone())?;
        assert!(receiver.next().is_none());
        receiver.stage(first.clone())?;
        let mut applied = Vec::new();
        while let Some(frame) = receiver.next() {
            let sequence = frame.sequence();
            applied.extend_from_slice(frame.payload());
            receiver.commit(sequence)?;
        }
        assert_eq!(applied, b"echo hello\r");
        for frame in sender.replay() {
            assert!(!receiver.stage(frame.clone())?);
        }
        assert!(!receiver.stage(first)?);
        assert!(!receiver.stage(second)?);
        assert!(receiver.next().is_none());
        assert_eq!(receiver.acknowledged(), 2);
        sender.acknowledge(EPOCH, 2)?;
        assert_eq!(sender.retained_bytes(), 0);
        Ok(())
    }
    #[test]
    fn failed_application_and_invalid_acks_cannot_discard_input() -> Result<()> {
        let mut sender = Sender::new(EPOCH)?;
        let mut receiver = Receiver::new(EPOCH)?;
        let frame = sender.enqueue(b"important command\r")?;
        receiver.stage(frame.clone())?;
        assert_eq!(receiver.acknowledged(), 0);
        assert!(receiver.next().is_some());
        assert!(receiver.commit(2).is_err());
        assert_eq!(receiver.acknowledged(), 0);
        assert!(sender.acknowledge(EPOCH, 2).is_err());
        assert!(sender
            .acknowledge("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1)
            .is_err());
        assert_eq!(sender.replay().count(), 1);
        assert!(receiver
            .stage(Frame::new(EPOCH, 1, b"different command")?)
            .is_err());
        assert_eq!(receiver.next().unwrap().payload(), frame.payload());
        receiver.commit(1)?;
        sender.acknowledge(EPOCH, 1)?;
        sender.acknowledge(EPOCH, 0)?;
        assert_eq!(sender.replay().count(), 0);
        Ok(())
    }
    #[test]
    fn disconnected_paths_remain_bounded_and_epochs_do_not_mix() -> Result<()> {
        let mut sender = Sender::new(EPOCH)?;
        let mut receiver = Receiver::new(EPOCH)?;
        for _ in 0..4 {
            receiver.stage(sender.enqueue(&vec![0; MAX_PAYLOAD])?)?;
        }
        assert!(sender.enqueue(b"extra").is_err());
        assert_eq!(sender.retained_bytes(), MAX_BYTES);
        assert!(receiver.stage(Frame::new(EPOCH, 5, b"extra")?).is_err());
        assert_eq!(receiver.retained_bytes(), MAX_BYTES);
        assert!(receiver
            .stage(Frame::new(EPOCH, MAX_FRAMES as u64 + 1, b"gap")?)
            .is_err());
        assert!(receiver
            .stage(Frame::new(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                1,
                b"old input"
            )?)
            .is_err());
        assert!(Frame::new(EPOCH, MAX_SEQUENCE + 1, b"overflow").is_err());
        assert!(Frame::new(EPOCH, 1, &vec![0; MAX_PAYLOAD + 1]).is_err());
        let mut tiny = Sender::new(EPOCH)?;
        for _ in 0..MAX_FRAMES {
            tiny.enqueue(b"x")?;
        }
        assert!(tiny.enqueue(b"x").is_err());
        Ok(())
    }
}

/// The transport control envelope contains no user-supplied participant or role.
/// Its authenticated connection determines which attachment owns this journal.
pub enum Message {
    Data(Frame),
    Ack { epoch: String, sequence: u64 },
}
// The channel label versions the format. Fixed 25-byte control headers avoid
// JSON/base64 expansion for every interactive keystroke on a direct carrier.
const HEADER: usize = 25;
impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let (kind, epoch, sequence, payload) = match self {
            Self::Data(frame) => (1, frame.epoch.as_str(), frame.sequence, frame.payload()),
            Self::Ack { epoch, sequence } => (2, epoch.as_str(), *sequence, &[][..]),
        };
        valid_epoch(epoch)?;
        ensure!(sequence <= MAX_SEQUENCE, "invalid terminal acknowledgement");
        let mut bytes = Vec::with_capacity(HEADER + payload.len());
        bytes.push(kind);
        for index in (0..32).step_by(2) {
            bytes.push(u8::from_str_radix(&epoch[index..index + 2], 16)?);
        }
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(payload);
        Ok(bytes)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (HEADER..=HEADER + MAX_PAYLOAD).contains(&bytes.len()),
            "invalid terminal envelope size"
        );
        let epoch: String = bytes[1..17]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let sequence = u64::from_be_bytes(bytes[17..25].try_into().unwrap());
        ensure!(sequence <= MAX_SEQUENCE, "invalid terminal sequence");
        Ok(match bytes[0] {
            1 => Self::Data(Frame::new(&epoch, sequence, &bytes[HEADER..])?),
            2 => {
                ensure!(
                    bytes.len() == HEADER,
                    "terminal acknowledgement contains unexpected data"
                );
                Self::Ack { epoch, sequence }
            }
            _ => anyhow::bail!("unknown terminal transport envelope"),
        })
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    #[test]
    fn wire_is_bounded_binary_safe_and_cannot_smuggle_a_role_or_guest() -> Result<()> {
        let epoch = "a".repeat(32);
        let frame = Frame::new(&epoch, 1, &vec![0xff; MAX_PAYLOAD])?;
        let encoded = Message::Data(frame).encode()?;
        assert!(encoded.len() < super::super::MAX_FRAME);
        let Message::Data(decoded) = Message::parse(&encoded)? else {
            panic!("data expected")
        };
        assert_eq!(decoded.payload(), vec![0xff; MAX_PAYLOAD]);
        assert_eq!(
            encoded.len(),
            HEADER + MAX_PAYLOAD,
            "direct data must not expand binary payloads"
        );
        assert!(Message::parse(br#"{\"client\":123,\"read_only\":false}"#).is_err());
        let ack = Message::Ack {
            epoch: epoch.clone(),
            sequence: MAX_SEQUENCE,
        }
        .encode()?;
        assert!(matches!(
            Message::parse(&ack)?,
            Message::Ack {
                sequence: MAX_SEQUENCE,
                ..
            }
        ));
        assert_eq!(ack.len(), HEADER);
        for length in 0..HEADER {
            assert!(Message::parse(&ack[..length]).is_err());
        }
        let mut empty_data = ack.clone();
        empty_data[0] = 1;
        assert!(Message::parse(&empty_data).is_err());
        let mut overflow = ack.clone();
        overflow[17..25].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(Message::parse(&overflow).is_err());
        let mut smuggled = ack.clone();
        smuggled.extend_from_slice(b"admin");
        assert!(Message::parse(&smuggled).is_err());
        let mut unknown = ack.clone();
        unknown[0] = 255;
        assert!(Message::parse(&unknown).is_err());
        assert!(Message::Ack {
            epoch,
            sequence: MAX_SEQUENCE + 1
        }
        .encode()
        .is_err());
        assert!(Message::parse(&vec![0; HEADER + MAX_PAYLOAD + 1]).is_err());
        Ok(())
    }
}
