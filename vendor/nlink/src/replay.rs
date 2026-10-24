//! Record a connection's netlink traffic, and replay it without a kernel
//! (#168, feature `replay`).
//!
//! A [`Recorder`] hands out a connection whose socket keeps every datagram
//! it sends and receives. Its [`Fixture`] — saved as a text file, one hex
//! frame per line — hands out a connection whose socket answers from the
//! recording instead: code that drives nlink can then be tested without
//! root, a namespace or a kernel that has the feature.
//!
//! ```no_run
//! # async fn example() -> nlink::Result<()> {
//! use nlink::netlink::Route;
//! use nlink::replay::{Fixture, Recorder};
//!
//! // Once, as root, against a real kernel:
//! let recorder = Recorder::new();
//! let conn = recorder.connection::<Route>()?;
//! let links = conn.get_links().await?;
//! recorder.fixture().save("tests/fixtures/links.nlreplay")?;
//!
//! // Then anywhere, as anyone:
//! let conn = Fixture::load("tests/fixtures/links.nlreplay")?.connection::<Route>()?;
//! assert_eq!(conn.get_links().await?.len(), links.len());
//! # Ok(())
//! # }
//! ```
//!
//! **How a replay answers.** Each datagram the code sends must be the next
//! one recorded, its sequence numbers and port id aside; the datagrams
//! recorded after it are then received, with the live sequence numbers
//! written in (an acknowledgement's copy of the request included).
//! Multicast datagrams come back as they were. A send that differs from the
//! recording is an error; so is a receive once the recording has ended,
//! rather than a wait that never ends. A receive while the recording's next
//! frame is a send waits for that send, so a dispatcher's receive task can
//! run ahead of its requests.
//!
//! **What it does not do.** One recorder or fixture is one connection's
//! traffic, in order: requests that go out concurrently replay only in the
//! order they were recorded. File descriptors passed with a message are
//! not recorded, and a socket option set on a replayed connection goes to a
//! real, idle socket.

use std::{
    collections::{HashMap, VecDeque},
    os::fd::AsFd,
    path::Path,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use crate::{
    Error, Result,
    netlink::{
        AsyncProtocolInit, Connection, ProtocolState,
        construction::{AsyncConstructible, SyncConstructible},
        NetlinkSocket,
    },
};

/// The first line of a fixture.
const HEADER: &str = "nlink-replay v1";

/// One datagram of a recording.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Frame {
    /// What the code sent (`tx`).
    Sent(Vec<u8>),
    /// What the kernel answered it (`rx`).
    Received(Vec<u8>),
    /// A multicast datagram (`mc`).
    Multicast(Vec<u8>),
}

/// A recording: the frames of one connection, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fixture {
    frames: Vec<Frame>,
}

#[nlink_macros::send_futures]
impl Fixture {
    /// A fixture of `frames`.
    pub fn new(frames: Vec<Frame>) -> Self {
        Self { frames }
    }

    /// Its frames.
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }

    /// Read a fixture's text: a `nlink-replay v1` line, then one frame per
    /// line, `tx`, `rx` or `mc` and the datagram in hex. Blank lines and
    /// lines starting with `#` are skipped.
    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'));
        if lines.next() != Some(HEADER) {
            return Err(Error::invalid_message(format!("replay: a fixture starts with `{HEADER}`")));
        }
        let frames = lines
            .map(|line| {
                // An empty datagram is its kind alone.
                let (kind, hex) = line.split_once(' ').unwrap_or((line, ""));
                let bytes = from_hex(hex.trim())?;
                match kind {
                    "tx" => Ok(Frame::Sent(bytes)),
                    "rx" => Ok(Frame::Received(bytes)),
                    "mc" => Ok(Frame::Multicast(bytes)),
                    other => Err(Error::invalid_message(format!("replay: unknown frame kind `{other}`"))),
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { frames })
    }

    /// Read the fixture at `path`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::from(e).with_context(format!("replay: read {}", path.display())))?;
        Self::parse(&text)
    }

    /// The fixture's text, as [`parse`](Self::parse) reads it.
    pub fn to_text(&self) -> String {
        let mut out = format!("{HEADER}\n");
        for frame in &self.frames {
            let (kind, bytes) = match frame {
                Frame::Sent(b) => ("tx", b),
                Frame::Received(b) => ("rx", b),
                Frame::Multicast(b) => ("mc", b),
            };
            out.push_str(kind);
            if !bytes.is_empty() {
                out.push(' ');
            }
            for byte in bytes {
                out.push_str(&format!("{byte:02x}"));
            }
            out.push('\n');
        }
        out
    }

    /// Write the fixture to `path`.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        std::fs::write(path, self.to_text())
            .map_err(|e| Error::from(e).with_context(format!("replay: write {}", path.display())))
    }

    /// A connection that answers from this recording. For a protocol a
    /// connection is made for at once (`Route`, `SockDiag`, …).
    pub fn connection<P>(&self) -> Result<Connection<P>>
    where
        P: ProtocolState + Default + SyncConstructible,
    {
        let socket = NetlinkSocket::new(P::PROTOCOL)?.with_hook(Hook::replay(self));
        Ok(Connection::from_parts(socket, P::default()))
    }

    /// [`connection`](Self::connection) for a Generic Netlink family: the
    /// family's id is resolved from the recording too.
    pub async fn connection_async<P>(&self) -> Result<Connection<P>>
    where
        P: AsyncProtocolInit + AsyncConstructible,
    {
        let socket = NetlinkSocket::new(P::PROTOCOL)?.with_hook(Hook::replay(self));
        let state = P::resolve_async(&socket).await?;
        Ok(Connection::from_parts(socket, state))
    }
}

/// Records one connection's traffic. Cheap to clone; the clones share the
/// recording.
#[derive(Debug, Clone, Default)]
pub struct Recorder {
    frames: Arc<Mutex<Vec<Frame>>>,
}

#[nlink_macros::send_futures]
impl Recorder {
    /// An empty recording.
    pub fn new() -> Self {
        Self::default()
    }

    /// A connection in this process's namespace whose traffic is recorded.
    pub fn connection<P>(&self) -> Result<Connection<P>>
    where
        P: ProtocolState + Default + SyncConstructible,
    {
        let socket = NetlinkSocket::new(P::PROTOCOL)?.with_hook(Hook::Record(self.clone()));
        Ok(Connection::from_parts(socket, P::default()))
    }

    /// [`connection`](Self::connection) in the namespace `ns` (an open
    /// nsfs fd, a [`Netns`](crate::netlink::namespace::Netns)).
    pub fn connection_in<P>(&self, ns: impl AsFd) -> Result<Connection<P>>
    where
        P: ProtocolState + Default + SyncConstructible,
    {
        let socket = NetlinkSocket::new_in_namespace(P::PROTOCOL, ns)?
            .with_hook(Hook::Record(self.clone()));
        Ok(Connection::from_parts(socket, P::default()))
    }

    /// [`connection`](Self::connection) for a Generic Netlink family, its
    /// id resolution recorded too.
    pub async fn connection_async<P>(&self) -> Result<Connection<P>>
    where
        P: AsyncProtocolInit + AsyncConstructible,
    {
        let socket = NetlinkSocket::new(P::PROTOCOL)?.with_hook(Hook::Record(self.clone()));
        let state = P::resolve_async(&socket).await?;
        Ok(Connection::from_parts(socket, state))
    }

    /// [`connection_async`](Self::connection_async) in the namespace `ns`.
    pub async fn connection_async_in<P>(&self, ns: impl AsFd) -> Result<Connection<P>>
    where
        P: AsyncProtocolInit + AsyncConstructible,
    {
        let socket = NetlinkSocket::new_in_namespace(P::PROTOCOL, ns)?
            .with_hook(Hook::Record(self.clone()));
        let state = P::resolve_async(&socket).await?;
        Ok(Connection::from_parts(socket, state))
    }

    /// What has been recorded so far.
    pub fn fixture(&self) -> Fixture {
        Fixture {
            frames: self.frames.lock().expect("recorder lock").clone(),
        }
    }

    fn push(&self, frame: Frame) {
        self.frames.lock().expect("recorder lock").push(frame);
    }
}

/// What a socket does with its traffic besides sending it.
#[derive(Debug)]
pub(crate) enum Hook {
    Record(Recorder),
    Replay(Replay),
}

impl Hook {
    fn replay(fixture: &Fixture) -> Self {
        Self::Replay(Replay {
            state: Mutex::new(ReplayState {
                frames: fixture.frames.iter().cloned().collect(),
                seqs: HashMap::new(),
                pid: None,
                wakers: Vec::new(),
            }),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Before a datagram goes out: a replay takes it instead, and says so
    /// with `Some`.
    pub(crate) fn before_send(&self, msg: &[u8]) -> Option<Result<()>> {
        match self {
            Self::Record(_) => None,
            Self::Replay(replay) => Some(replay.send(msg)),
        }
    }

    /// After a datagram went out.
    pub(crate) fn after_send(&self, msg: &[u8]) {
        if let Self::Record(recorder) = self {
            recorder.push(Frame::Sent(msg.to_vec()));
        }
    }

    /// After a datagram came in.
    pub(crate) fn after_recv(&self, data: &[u8], multicast: bool) {
        if let Self::Record(recorder) = self {
            recorder.push(if multicast {
                Frame::Multicast(data.to_vec())
            } else {
                Frame::Received(data.to_vec())
            });
        }
    }

    pub(crate) fn as_replay(&self) -> Option<&Replay> {
        match self {
            Self::Replay(replay) => Some(replay),
            Self::Record(_) => None,
        }
    }
}

/// A socket answering from a recording.
#[derive(Debug)]
pub(crate) struct Replay {
    state: Mutex<ReplayState>,
    /// Signalled when a send lets the next received frames through.
    notify: tokio::sync::Notify,
}

#[derive(Debug)]
struct ReplayState {
    frames: VecDeque<Frame>,
    /// Recorded sequence number → the live one the code used.
    seqs: HashMap<u32, u32>,
    /// The port id the code's messages carry, written into what it
    /// receives.
    pid: Option<u32>,
    wakers: Vec<Waker>,
}

/// What a receive finds.
enum Next {
    Frame(Vec<u8>, bool),
    /// The recording's next frame is a send.
    Waiting,
    Ended,
}

impl Replay {
    fn send(&self, msg: &[u8]) -> Result<()> {
        let mut state = self.state.lock().expect("replay lock");
        let recorded = match state.frames.front() {
            Some(Frame::Sent(recorded)) => recorded.clone(),
            Some(_) => {
                return Err(Error::invalid_message(
                    "replay: the code sent a message where the recording receives one",
                ));
            }
            None => {
                return Err(Error::invalid_message(
                    "replay: the code sent a message after the recording ended",
                ));
            }
        };
        let live = headers(msg);
        let then = headers(&recorded);
        if live.len() != then.len() || masked(msg) != masked(&recorded) {
            return Err(Error::invalid_message(format!(
                "replay: the code sent {} bytes that differ from the {} recorded",
                msg.len(),
                recorded.len()
            )));
        }
        for ((_, then_seq, _), (_, live_seq, live_pid)) in then.iter().zip(&live) {
            state.seqs.insert(*then_seq, *live_seq);
            if *live_pid != 0 {
                state.pid = Some(*live_pid);
            }
        }
        state.frames.pop_front();
        for waker in state.wakers.drain(..) {
            waker.wake();
        }
        drop(state);
        self.notify.notify_waiters();
        Ok(())
    }

    fn next(&self) -> Next {
        let mut state = self.state.lock().expect("replay lock");
        let (data, multicast) = match state.frames.front() {
            Some(Frame::Received(data)) => (data.clone(), false),
            Some(Frame::Multicast(data)) => (data.clone(), true),
            Some(Frame::Sent(_)) => return Next::Waiting,
            None => return Next::Ended,
        };
        state.frames.pop_front();
        let data = if multicast { data } else { rewrite(data, &state.seqs, state.pid) };
        Next::Frame(data, multicast)
    }

    /// The next received datagram, waiting while the recording's next frame
    /// is a send; an error once it has ended.
    pub(crate) async fn recv(&self) -> Result<(Vec<u8>, bool)> {
        loop {
            let notified = self.notify.notified();
            match self.next() {
                Next::Frame(data, multicast) => return Ok((data, multicast)),
                Next::Ended => return Err(ended()),
                Next::Waiting => notified.await,
            }
        }
    }

    /// The next received datagram if one is due now.
    pub(crate) fn try_recv(&self) -> Option<(Vec<u8>, bool)> {
        match self.next() {
            Next::Frame(data, multicast) => Some((data, multicast)),
            Next::Waiting | Next::Ended => None,
        }
    }

    /// [`recv`](Self::recv), polled.
    pub(crate) fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<(Vec<u8>, bool)>> {
        match self.next() {
            Next::Frame(data, multicast) => Poll::Ready(Ok((data, multicast))),
            Next::Ended => Poll::Ready(Err(ended())),
            Next::Waiting => {
                let mut state = self.state.lock().expect("replay lock");
                // A send may have come between the look and the lock.
                if !matches!(state.frames.front(), Some(Frame::Sent(_))) {
                    cx.waker().wake_by_ref();
                } else {
                    state.wakers.push(cx.waker().clone());
                }
                Poll::Pending
            }
        }
    }
}

fn ended() -> Error {
    Error::invalid_message("replay: the recording has ended; nothing more is received")
}

/// The `(offset, seq, pid)` of each netlink header in a datagram.
fn headers(data: &[u8]) -> Vec<(usize, u32, u32)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 16 <= data.len() {
        let len = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap()) as usize;
        let seq = u32::from_ne_bytes(data[at + 8..at + 12].try_into().unwrap());
        let pid = u32::from_ne_bytes(data[at + 12..at + 16].try_into().unwrap());
        out.push((at, seq, pid));
        if len < 16 {
            break;
        }
        at += len.next_multiple_of(4);
    }
    out
}

/// A datagram with every header's seq and pid zeroed: what a send is
/// compared by.
fn masked(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    for (at, _, _) in headers(data) {
        out[at + 8..at + 16].fill(0);
    }
    out
}

/// A received datagram with the live seqs (and port id) written in: in each
/// header, and in the copy of the request an `NLMSG_ERROR` carries.
fn rewrite(mut data: Vec<u8>, seqs: &HashMap<u32, u32>, pid: Option<u32>) -> Vec<u8> {
    const NLMSG_ERROR: u16 = 2;
    for (at, seq, _) in headers(&data) {
        let mut fix = |at: usize, seq: u32| {
            if let Some(live) = seqs.get(&seq) {
                data[at + 8..at + 12].copy_from_slice(&live.to_ne_bytes());
            }
            if let Some(pid) = pid {
                data[at + 12..at + 16].copy_from_slice(&pid.to_ne_bytes());
            }
        };
        fix(at, seq);
        let kind = u16::from_ne_bytes(data[at + 4..at + 6].try_into().unwrap());
        // nlmsgerr: the errno, then the request's header.
        let inner = at + 16 + 4;
        if kind == NLMSG_ERROR && inner + 16 <= data.len() {
            let inner_seq = u32::from_ne_bytes(data[inner + 8..inner + 12].try_into().unwrap());
            let mut fix = |at: usize, seq: u32| {
                if let Some(live) = seqs.get(&seq) {
                    data[at + 8..at + 12].copy_from_slice(&live.to_ne_bytes());
                }
                if let Some(pid) = pid {
                    data[at + 12..at + 16].copy_from_slice(&pid.to_ne_bytes());
                }
            };
            fix(inner, inner_seq);
        }
    }
    data
}

fn from_hex(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(Error::invalid_message("replay: an odd number of hex digits"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| Error::invalid_message(format!("replay: `{}` is not hex", &hex[i..i + 2])))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(kind: u16, seq: u32, pid: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&0u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&pid.to_ne_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_fixture_reads_back_as_written() {
        let fixture = Fixture::new(vec![
            Frame::Sent(vec![1, 2, 255]),
            Frame::Received(vec![0]),
            Frame::Multicast(vec![]),
        ]);
        let text = fixture.to_text();
        assert!(text.starts_with("nlink-replay v1\ntx 0102ff\nrx 00\n"));
        assert_eq!(Fixture::parse(&text).unwrap(), fixture);
        assert!(Fixture::parse("tx 00").is_err(), "no header");
        assert!(Fixture::parse("nlink-replay v1\nzz 00").is_err());
        assert!(Fixture::parse("nlink-replay v1\ntx 0").is_err());
    }

    /// A send matches the recording whatever its seq and pid; what comes
    /// back carries the live seq, in the ack's copy of the request too;
    /// then the recording has ended.
    #[tokio::test]
    async fn a_replay_answers_with_the_live_seq() {
        let request = msg(18, 7, 100, &[1, 2, 3, 4]);
        let mut errno = 0i32.to_ne_bytes().to_vec();
        errno.extend_from_slice(&request);
        let ack = msg(2, 7, 100, &errno);
        let Hook::Replay(replay) = Hook::replay(&Fixture::new(vec![
            Frame::Sent(request),
            Frame::Received(ack),
        ])) else {
            unreachable!()
        };
        assert!(replay.try_recv().is_none(), "nothing before the send");
        replay.send(&msg(18, 42, 9, &[1, 2, 3, 4])).unwrap();
        let (got, multicast) = replay.recv().await.unwrap();
        assert!(!multicast);
        let heads = headers(&got);
        assert_eq!((heads[0].1, heads[0].2), (42, 9));
        assert_eq!(&got[20 + 8..20 + 16], [42u32.to_ne_bytes(), 9u32.to_ne_bytes()].concat());
        assert!(replay.recv().await.is_err(), "the recording has ended");
    }

    /// The committed recording (`scripts/regen-replay-fixtures.sh`) of
    /// listing a namespace's links, adding a dummy and listing them again,
    /// replayed with no kernel and no root: the second listing has the
    /// dummy the first did not.
    #[tokio::test]
    async fn a_committed_recording_replays_without_a_kernel() {
        use crate::netlink::Route;
        use crate::netlink::link::DummyLink;
        let fixture = Fixture::parse(include_str!("../tests/fixtures/route-links.nlreplay")).unwrap();
        let conn = fixture.connection::<Route>().unwrap();
        let names = |links: Vec<crate::netlink::messages::LinkMessage>| -> Vec<String> {
            let mut names: Vec<String> =
                links.iter().filter_map(|l| l.name().map(str::to_string)).collect();
            names.sort();
            names
        };
        // Whatever the recording namespace had — `lo`, and the fallback
        // tunnels of the modules loaded — and then `rp0` as well.
        let mut before = names(conn.get_links().await.unwrap());
        assert!(before.contains(&"lo".to_string()), "{before:?}");
        conn.add_link(DummyLink::new("rp0")).await.unwrap();
        before.push("rp0".to_string());
        before.sort();
        assert_eq!(names(conn.get_links().await.unwrap()), before);
    }

    #[test]
    fn a_send_the_recording_does_not_have_is_an_error() {
        let Hook::Replay(replay) =
            Hook::replay(&Fixture::new(vec![Frame::Sent(msg(18, 1, 0, &[1]))]))
        else {
            unreachable!()
        };
        assert!(replay.send(&msg(18, 1, 0, &[2])).is_err());
        assert!(replay.send(&msg(18, 1, 0, &[1])).is_ok());
        assert!(replay.send(&msg(18, 1, 0, &[1])).is_err(), "after the end");
    }
}
