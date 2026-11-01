//! One authenticated guest attachment's carrier-independent delivery state.
//! Role comes from Welcome. Recovery creates a fresh instance: never replay
//! uncertain old shell input automatically into a new attachment epoch.
use crate::{
    delivery::{self, Message, Receiver, Sender},
    protocol::*,
};
use anyhow::{ensure, Context, Result};

pub enum Outbound {
    Gateway(ViewerInput),
    Packet(Message),
}

pub enum Incoming {
    InputAcknowledged,
    Output,
}
struct Journals {
    input: Sender,
    output: Receiver,
    input_epoch: String,
    output_epoch: String,
}

pub struct Viewer {
    read_only: bool,
    pending: Option<u32>,
    last_request: u32,
    queued: Vec<u8>,
    journals: Option<Journals>,
}
impl Viewer {
    pub fn new(read_only: bool) -> Self {
        Self {
            read_only,
            pending: None,
            last_request: 0,
            queued: Vec::new(),
            journals: None,
        }
    }
    pub fn begin_offer(
        &mut self,
        request: u32,
        description: DirectDescription,
    ) -> Result<ViewerInput> {
        ensure!(
            self.pending.is_none() && request > self.last_request,
            "terminal negotiation is pending or stale"
        );
        description.validate("offer")?;
        self.pending = Some(request);
        self.last_request = request;
        Ok(ViewerInput::DirectOffer {
            request,
            description,
        })
    }
    pub fn input(&mut self, bytes: &[u8]) -> Result<Vec<Outbound>> {
        ensure!(!self.read_only, "terminal participant is read-only");
        ensure!(
            !bytes.is_empty() && bytes.len() <= delivery::MAX_BYTES,
            "terminal input exceeds limit"
        );
        if let Some(journals) = &mut self.journals {
            let pieces = bytes.chunks(delivery::MAX_PAYLOAD);
            ensure!(
                journals.input.can_enqueue_batch(bytes.len(), pieces.len()),
                "terminal input is awaiting acknowledgement"
            );
            pieces
                .map(|piece| {
                    Ok(Outbound::Packet(Message::Data(
                        journals.input.enqueue(piece)?,
                    )))
                })
                .collect()
        } else if self.pending.is_some() {
            ensure!(
                self.queued.len() + bytes.len() <= delivery::MAX_BYTES,
                "terminal negotiation input is full"
            );
            self.queued.extend_from_slice(bytes);
            Ok(Vec::new())
        } else {
            Ok(bytes
                .chunks(delivery::MAX_PAYLOAD)
                .map(|piece| {
                    Outbound::Gateway(ViewerInput::Input {
                        data: encode_data(piece),
                    })
                })
                .collect())
        }
    }
    pub fn accept_answer(&mut self, answer: &DirectAnswer) -> Result<Vec<Outbound>> {
        ensure!(
            self.pending == Some(answer.request),
            "unexpected terminal answer"
        );
        answer.validate()?;
        if let Some(journals) = &self.journals {
            ensure!(
                journals.input_epoch == answer.input_epoch
                    && journals.output_epoch == answer.output_epoch,
                "terminal attachment epochs changed; reconnect without replaying old input"
            );
        } else {
            self.journals = Some(Journals {
                input: Sender::new(&answer.input_epoch)?,
                output: Receiver::new(&answer.output_epoch)?,
                input_epoch: answer.input_epoch.clone(),
                output_epoch: answer.output_epoch.clone(),
            });
        }
        self.pending = None;
        self.flush_queued()
    }
    pub fn unavailable(&mut self, request: u32) -> Result<Vec<Outbound>> {
        ensure!(
            self.pending == Some(request),
            "unexpected terminal negotiation response"
        );
        self.pending = None;
        if self.journals.is_some() {
            Ok(self.replay_input())
        } else {
            self.flush_queued()
        }
    }
    fn flush_queued(&mut self) -> Result<Vec<Outbound>> {
        if self.queued.is_empty() {
            return Ok(Vec::new());
        }
        let bytes = std::mem::take(&mut self.queued);
        self.input(&bytes)
    }
    /// Replays keep their original epochs and sequence numbers on either
    /// carrier. An empty journal produces no repeat of acknowledged commands.
    pub fn replay_input(&self) -> Vec<Outbound> {
        self.journals.as_ref().map_or_else(Vec::new, |journals| {
            journals
                .input
                .replay()
                .map(|frame| Outbound::Packet(Message::Data(frame.clone())))
                .collect()
        })
    }
    pub fn pending_input_bytes(&self) -> usize {
        self.queued.len()
            + self
                .journals
                .as_ref()
                .map_or(0, |journals| journals.input.retained_bytes())
    }
    pub fn legacy_output(&self, data: &str) -> Result<Vec<u8>> {
        ensure!(
            self.journals.is_none(),
            "unsequenced terminal output after negotiation"
        );
        decode_data(data)
    }
    pub fn receive(&mut self, message: Message) -> Result<Incoming> {
        let journals = self
            .journals
            .as_mut()
            .context("terminal data arrived before negotiation")?;
        match message {
            Message::Ack { epoch, sequence } => {
                journals.input.acknowledge(&epoch, sequence)?;
                Ok(Incoming::InputAcknowledged)
            }
            Message::Data(frame) => {
                journals.output.stage(frame)?;
                Ok(Incoming::Output)
            }
        }
    }
    pub fn next_output(&self) -> Option<&delivery::Frame> {
        self.journals.as_ref()?.output.next()
    }
    /// Call only after stdout/renderer acceptance. Receipt alone must not
    /// release the host's retained output or advance the application cursor.
    pub fn commit_output(&mut self, sequence: u64) -> Result<()> {
        self.journals
            .as_mut()
            .context("terminal output is not negotiated")?
            .output
            .commit(sequence)
    }
    pub fn output_acknowledgement(&self) -> Result<Message> {
        let journals = self
            .journals
            .as_ref()
            .context("terminal output is not negotiated")?;
        Ok(Message::Ack {
            epoch: journals.output_epoch.clone(),
            sequence: journals.output.acknowledged(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn description(kind: &str) -> DirectDescription {
        DirectDescription(serde_json::json!({"type":kind,"sdp":"v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n"}).to_string())
    }
    fn answer(request: u32) -> DirectAnswer {
        DirectAnswer {
            request,
            description: description("answer"),
            input_epoch: "a".repeat(32),
            output_epoch: "b".repeat(32),
        }
    }
    fn packet(outbound: Outbound) -> Result<Message> {
        match outbound {
            Outbound::Packet(message) => Ok(message),
            _ => anyhow::bail!("sequenced packet required"),
        }
    }
    fn data(message: Message) -> Result<delivery::Frame> {
        match message {
            Message::Data(frame) => Ok(frame),
            _ => anyhow::bail!("data frame required"),
        }
    }
    #[test]
    fn negotiation_buffers_input_then_fallback_replays_only_unacknowledged_frames() -> Result<()> {
        let mut viewer = Viewer::new(false);
        assert!(matches!(
            viewer.input(b"old path\r")?.pop(),
            Some(Outbound::Gateway(ViewerInput::Input { .. }))
        ));
        viewer.begin_offer(1, description("offer"))?;
        assert!(viewer.input(b"new command\r")?.is_empty());
        assert_eq!(viewer.pending_input_bytes(), 12);
        let first = data(packet(viewer.accept_answer(&answer(1))?.pop().unwrap())?)?;
        assert_eq!(first.payload(), b"new command\r");
        assert_eq!(first.sequence(), 1);
        assert_eq!(
            data(packet(viewer.replay_input().pop().unwrap())?)?.sequence(),
            1
        );
        assert!(viewer
            .receive(Message::Ack {
                epoch: "c".repeat(32),
                sequence: 1
            })
            .is_err());
        assert!(viewer
            .receive(Message::Ack {
                epoch: "a".repeat(32),
                sequence: 2
            })
            .is_err());
        viewer.receive(Message::Ack {
            epoch: "a".repeat(32),
            sequence: 1,
        })?;
        assert!(viewer.replay_input().is_empty());
        viewer.begin_offer(2, description("offer"))?;
        let second = data(packet(viewer.input(b"next\r")?.pop().unwrap())?)?;
        assert_eq!(
            second.sequence(),
            2,
            "a reoffer must retain the current attachment journal"
        );
        assert!(viewer.accept_answer(&answer(2))?.is_empty());
        viewer.begin_offer(3, description("offer"))?;
        let mut changed = answer(3);
        changed.input_epoch = "c".repeat(32);
        assert!(viewer.accept_answer(&changed).is_err());
        assert_eq!(
            data(packet(viewer.replay_input().pop().unwrap())?)?.sequence(),
            2
        );
        assert_eq!(viewer.pending_input_bytes(), 5);
        Ok(())
    }
    #[test]
    fn output_commits_after_acceptance_and_ignores_replayed_copies_on_either_carrier() -> Result<()>
    {
        let mut viewer = Viewer::new(true);
        viewer.begin_offer(1, description("offer"))?;
        viewer.accept_answer(&answer(1))?;
        let frame = |sequence, bytes: &[u8]| delivery::Frame::new(&"b".repeat(32), sequence, bytes);
        viewer.receive(Message::Data(frame(2, b"world")?))?;
        assert!(viewer.next_output().is_none());
        viewer.receive(Message::Data(frame(1, b"hello ")?))?;
        assert_eq!(viewer.next_output().unwrap().payload(), b"hello ");
        assert!(matches!(
            viewer.output_acknowledgement()?,
            Message::Ack { sequence: 0, .. }
        ));
        assert!(viewer.commit_output(2).is_err());
        assert!(viewer
            .receive(Message::Data(frame(1, b"conflict")?))
            .is_err());
        viewer.commit_output(1)?;
        assert_eq!(viewer.next_output().unwrap().payload(), b"world");
        viewer.commit_output(2)?;
        viewer.receive(Message::Data(frame(1, b"hello ")?))?;
        assert!(viewer.next_output().is_none());
        assert!(matches!(
            viewer.output_acknowledgement()?,
            Message::Ack { sequence: 2, .. }
        ));
        assert!(viewer.input(b"forbidden\r").is_err());
        assert!(viewer.legacy_output(&encode_data(b"unsequenced")).is_err());
        Ok(())
    }
    #[test]
    fn queues_and_pastes_are_bounded_and_read_only_cannot_type_during_negotiation() -> Result<()> {
        let mut viewer = Viewer::new(false);
        viewer.begin_offer(1, description("offer"))?;
        assert!(viewer.begin_offer(2, description("offer")).is_err());
        viewer.input(&vec![0; delivery::MAX_BYTES])?;
        assert!(viewer.input(b"extra").is_err());
        assert_eq!(viewer.pending_input_bytes(), delivery::MAX_BYTES);
        let legacy = viewer.unavailable(1)?;
        assert_eq!(legacy.len(), 4);
        assert_eq!(viewer.pending_input_bytes(), 0);
        assert!(viewer.begin_offer(1, description("offer")).is_err());
        viewer.begin_offer(2, description("offer"))?;
        viewer.accept_answer(&answer(2))?;
        for _ in 0..delivery::MAX_FRAMES {
            viewer.input(b"x")?;
        }
        assert!(viewer.input(b"whole paste").is_err());
        assert_eq!(viewer.pending_input_bytes(), delivery::MAX_FRAMES);
        let mut reader = Viewer::new(true);
        assert!(reader.input(b"no").is_err());
        reader.begin_offer(1, description("offer"))?;
        assert!(reader.input(b"still no").is_err());
        assert_eq!(reader.pending_input_bytes(), 0);
        assert!(reader.accept_answer(&answer(2)).is_err());
        reader.accept_answer(&answer(1))?;
        assert!(reader.input(b"never").is_err());
        Ok(())
    }
}
