//! Experimental tagged native TCP DATA/ACK and RX origin adapter. No
//! DuplexStream can bypass origin tags. Runtime/optimized-stream negotiation
//! is not enabled; whole-path chunk protocol/receipt integration remains separate.
use super::{Flow, MAX_FLOWS, MTU};
use anyhow::{ensure, Result};
use bytes::Bytes;
use porthub_mesh::udp::SendPermit;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as StackInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, TcpPacket},
};
use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::{CancellationToken, PollSender};
mod rx;
const QUEUE: usize = 256;
const CHUNK: usize = 8192;
const MAX_BYTES: usize = 8 * 1024 * 1024;
/// Combined native TCP flight window on a datagram carrier.
pub const DIRECT_FORWARD_WINDOW: usize = 1024 * 1024;
/// Largest contiguous LAN read carrying one immutable admission.
pub const FORWARD_WINDOW: usize = 8 * 1024 * 1024;
const FORWARD_SOCKET_BUFFER: usize = 1024 * 1024;
// Limit the aggregate memory added by wide socket windows across all virtual
// hosts in one agent. Other flows retain the ordinary socket capacities.
static WIDE_FORWARD_SOCKETS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Busy,
    Invalid,
    Retired,
}
impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Busy => "native origin budget busy",
            Self::Invalid => "invalid native chunk",
            Self::Retired => "native origin retired",
        })
    }
}
impl std::error::Error for AdmissionError {}
#[derive(Clone)]
pub struct Packet {
    stack_scope: Arc<()>,
    owner: u64,
    flow: Flow,
    alive: Arc<AtomicBool>,
    bytes: Bytes,
    permit: SendPermit,
}
impl Packet {
    pub fn admission(&self) -> SendPermit { self.permit.clone() }
    pub fn remaining(&self) -> Option<Duration> {
        self.permit.remaining()
    }
    /// Add an independent authority; never replace or reset the first origin.
    pub fn intersect(&self, additional: SendPermit) -> Self {
        let mut packet = self.clone();
        packet.permit = SendPermit::combine(vec![self.permit.clone(), additional]);
        packet
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn valid(&self) -> bool {
        self.permit.valid()
    }
    pub async fn deliver<T, F: std::future::Future<Output = Result<T>>>(
        &self,
        delivery: impl FnOnce(Bytes) -> F,
    ) -> Result<T> {
        // Callback construction may itself perform synchronous native work.
        // Validate before exposing bytes, then again before every future poll.
        ensure!(
            self.permit.valid(),
            "native packet admission retired before delivery callback"
        );
        self.permit.during(delivery(self.bytes.clone())).await?
    }
}
#[derive(Clone)]
struct Binding {
    id: u64,
    alive: Arc<AtomicBool>,
}
type Bindings = Arc<RwLock<HashMap<Flow, Binding>>>;
struct Budget {
    used: Mutex<usize>,
    released: tokio::sync::Notify,
    capacity: usize,
}
impl Default for Budget {
    fn default() -> Self {
        Self::new(MAX_BYTES)
    }
}
struct Credit {
    budget: Arc<Budget>,
    bytes: usize,
}
impl Drop for Credit {
    fn drop(&mut self) {
        *self.budget.used.lock().unwrap_or_else(|p| p.into_inner()) -= self.bytes;
        self.budget.released.notify_waiters();
    }
}
impl Budget {
    fn new(capacity: usize) -> Self {
        Self {
            used: Mutex::new(0),
            released: tokio::sync::Notify::new(),
            capacity,
        }
    }

    fn forwarding() -> &'static Arc<Self> {
        static SHARED: std::sync::OnceLock<Arc<Budget>> = std::sync::OnceLock::new();
        SHARED.get_or_init(|| Arc::new(Budget::new(32 * 1024 * 1024)))
    }

    fn reserve(self: &Arc<Self>, bytes: usize, limit: usize) -> Result<Credit> {
        if !(1..=limit).contains(&bytes) {
            return Err(AdmissionError::Invalid.into());
        }
        let mut used = self.used.lock().unwrap_or_else(|p| p.into_inner());
        if *used + bytes > self.capacity {
            return Err(AdmissionError::Busy.into());
        }
        *used += bytes;
        Ok(Credit {
            budget: self.clone(),
            bytes,
        })
    }
}
/// Native received bytes/EOF retain first-admission spans until downstream
/// delivery; abandonment retires the owner rather than silently losing bytes.
pub struct NativeRead {
    stack_scope: Arc<()>,
    owner: u64,
    flow: Flow,
    bytes: Bytes,
    eof: bool,
    permit: SendPermit,
    _credit: Option<Credit>,
    alive: Arc<AtomicBool>,
    delivered: bool,
}
impl NativeRead {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub fn eof(&self) -> bool {
        self.eof
    }
    pub fn valid(&self) -> bool {
        self.permit.valid()
    }
    /// Carry this immutable origin into any downstream chunk/queue admission.
    pub fn admission(&self) -> SendPermit {
        self.permit.clone()
    }
    pub async fn deliver<T, F: std::future::Future<Output = Result<T>>>(
        mut self,
        delivery: impl FnOnce(Bytes, bool) -> F,
    ) -> Result<T> {
        ensure!(
            self.permit.valid(),
            "native RX admission retired before delivery callback"
        );
        let result = self
            .permit
            .during(delivery(self.bytes.clone(), self.eof))
            .await?;
        if result.is_ok() {
            self.delivered = true;
        }
        result
    }
}
impl Drop for NativeRead {
    fn drop(&mut self) {
        if !self.delivered {
            self.alive.store(false, Ordering::SeqCst);
        }
    }
}
/// Issued only after the actual native TCP send queue acknowledges the chunk.
/// The original permit remains attached for subsequent receipt publication.
pub struct NativeAck {
    permit: SendPermit,
    terminal_owner: Option<(Arc<AtomicBool>, Arc<AtomicBool>)>,
    stack_scope: Arc<()>,
    owner: u64,
    flow: Flow,
    id: [u8; 16],
    offset: u64,
    length: usize,
}

impl Drop for NativeAck {
    fn drop(&mut self) {
        if let Some((complete, owner)) = &self.terminal_owner {
            if !complete.load(Ordering::SeqCst) {
                owner.store(false, Ordering::SeqCst);
            }
        }
    }
}
struct Terminal {
    origin: SendPermit,
    complete: Arc<AtomicBool>,
}
struct FinWrite {
    id: [u8; 16],
    offset: u64,
    permit: SendPermit,
    reply: oneshot::Sender<Result<NativeAck>>,
    sent: bool,
}

struct Write {
    id: [u8; 16],
    offset: u64,
    bytes: Bytes,
    copied: usize,
    permit: SendPermit,
    reply: oneshot::Sender<Result<NativeAck>>,
    _credit: Credit,
}
enum Command {
    Connect {
        flow: Flow,
        permit: SendPermit,
        reply: oneshot::Sender<Result<u64>>,
        alive: Arc<AtomicBool>,
        syn: Option<Bytes>,
        direct_carrier: bool,
    },
    Input {
        id: u64,
        bytes: Bytes,
        permit: SendPermit,
    },
    Write {
        id: u64,
        flow: Flow,
        write: Write,
    },
    Finish {
        id: u64,
        flow: Flow,
        fin: FinWrite,
    },
    Read {
        id: u64,
        flow: Flow,
        reply: oneshot::Sender<Result<NativeRead>>,
    },
    Renew {
        id: u64,
        flow: Flow,
        permit: SendPermit,
    },
    Close {
        id: u64,
        flow: Flow,
    },
}
#[derive(Clone)]
pub struct Handle {
    stack_scope: Arc<()>,
    commands: mpsc::Sender<Command>,
    bindings: Bindings,
    budget: Arc<Budget>,
}
pub struct Connection {
    alive: Arc<AtomicBool>,
    handle: Handle,
    flow: Flow,
    id: u64,
}
/// A pinned ingress capability exists before the handshake finishes. Its
/// stack, tuple and owner Arc are immutable; it cannot adopt a replacement.
#[derive(Clone)]
pub struct Ingress {
    handle: Handle,
    flow: Flow,
    alive: Arc<AtomicBool>,
    opening: Option<SendPermit>,
}
impl Ingress {
    pub fn flow(&self) -> Flow {
        self.flow
    }
    pub fn valid(&self) -> bool {
        self.alive.load(Ordering::SeqCst) && self.opening.as_ref().is_none_or(SendPermit::valid)
    }
    pub fn owns_packet(&self, packet: &Packet) -> bool {
        self.valid()
            && packet.valid()
            && self.flow == packet.flow
            && Arc::ptr_eq(&self.handle.stack_scope, &packet.stack_scope)
            && Arc::ptr_eq(&self.alive, &packet.alive)
    }
    pub fn input(&self, bytes: Bytes, original: SendPermit) -> Result<()> {
        ensure!(
            self.valid() && original.valid(),
            "native ingress owner/origin retired"
        );
        Handle::validate_input(&bytes)?;
        let incoming = Flow::from_packet(&bytes).ok_or(AdmissionError::Invalid)?;
        ensure!(
            bytes.len() <= MTU && incoming == self.flow.reverse(),
            "native ingress tuple mismatch"
        );
        let binding = self
            .handle
            .bindings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&incoming)
            .cloned()
            .ok_or(AdmissionError::Retired)?;
        ensure!(
            Arc::ptr_eq(&binding.alive, &self.alive) && binding.alive.load(Ordering::SeqCst),
            "native ingress generation replaced"
        );
        let permit = match &self.opening {
            Some(opening) => SendPermit::combine(vec![opening.clone(), original]),
            None => original,
        };
        ensure!(
            permit.valid(),
            "native opening/original expired before enqueue"
        );
        self.handle
            .commands
            .try_send(Command::Input {
                id: binding.id,
                bytes,
                permit,
            })
            .map_err(|_| AdmissionError::Busy.into())
    }
}
/// Creation is queued, but no caller needs to await TCP establishment before
/// routing its SYNACK/ACK into the exact admitted generation.
pub struct PendingConnection {
    ingress: Ingress,
    waiting: Option<oneshot::Receiver<Result<u64>>>,
    complete: bool,
}
impl PendingConnection {
    pub fn ingress(&self) -> Ingress {
        self.ingress.clone()
    }
    pub async fn established(mut self) -> Result<Connection> {
        let original = self
            .ingress
            .opening
            .as_ref()
            .ok_or(AdmissionError::Invalid)?
            .clone();
        let waiting = self.waiting.take().ok_or(AdmissionError::Invalid)?;
        let id = original
            .during(waiting)
            .await?
            .map_err(|_| anyhow::anyhow!("native runner stopped"))??;
        ensure!(self.ingress.valid(), "native opening owner retired");
        self.complete = true;
        Ok(Connection {
            alive: self.ingress.alive.clone(),
            handle: self.ingress.handle.clone(),
            flow: self.ingress.flow,
            id,
        })
    }
}
impl Drop for PendingConnection {
    fn drop(&mut self) {
        if !self.complete {
            self.ingress.alive.store(false, Ordering::SeqCst);
        }
    }
}
struct RetireOnDrop {
    alive: Arc<AtomicBool>,
    armed: bool,
}
impl Drop for RetireOnDrop {
    fn drop(&mut self) {
        if self.armed {
            self.alive.store(false, Ordering::SeqCst);
        }
    }
}
/// Validate the exact initial SYN before asynchronous flow-open admission.
/// No packet origin is created here; the caller must retain its sealed policy
/// admission when transferring this immutable packet into a native owner.
pub fn validate_syn(syn: &[u8]) -> Result<Flow> {
    Handle::validate_input(syn)?;
    let incoming = Flow::from_packet(syn).ok_or(AdmissionError::Invalid)?;
    let ip = Ipv4Packet::new_checked(syn)?;
    let tcp = TcpPacket::new_checked(ip.payload())?;
    ensure!(
        syn.len() <= MTU
            && tcp.syn()
            && !tcp.ack()
            && !tcp.rst()
            && !tcp.fin()
            && tcp.payload().is_empty(),
        "invalid native SYN"
    );
    incoming.validate()?;
    Ok(incoming)
}
impl Handle {
    pub async fn connect(&self, flow: Flow, permit: SendPermit) -> Result<Connection> {
        self.prepare_connect(flow, permit)
            .await?
            .established()
            .await
    }
    pub async fn accept_syn(&self, syn: Bytes, permit: SendPermit) -> Result<Connection> {
        self.prepare_syn(syn, permit).await?.established().await
    }
    pub async fn prepare_connect(
        &self,
        flow: Flow,
        permit: SendPermit,
    ) -> Result<PendingConnection> {
        self.prepare(flow, permit, None, false).await
    }
    pub async fn prepare_syn(&self, syn: Bytes, permit: SendPermit) -> Result<PendingConnection> {
        self.prepare_forward_syn(syn, permit, false).await
    }
    pub async fn prepare_forward_syn(
        &self,
        syn: Bytes,
        permit: SendPermit,
        direct_carrier: bool,
    ) -> Result<PendingConnection> {
        let incoming = validate_syn(&syn)?;
        self.prepare(incoming.reverse(), permit, Some(syn), direct_carrier)
            .await
    }
    async fn prepare(
        &self,
        flow: Flow,
        permit: SendPermit,
        syn: Option<Bytes>,
        direct_carrier: bool,
    ) -> Result<PendingConnection> {
        flow.validate()?;
        ensure!(permit.valid(), "native flow admission retired");
        let (reply, waiting) = oneshot::channel();
        let alive = Arc::new(AtomicBool::new(true));
        let mut abandoned = RetireOnDrop {
            alive: alive.clone(),
            armed: true,
        };
        permit
            .during(self.commands.send(Command::Connect {
                alive: alive.clone(),
                syn,
                direct_carrier,
                flow,
                permit: permit.clone(),
                reply,
            }))
            .await?
            .map_err(|_| anyhow::anyhow!("native runner stopped"))?;
        abandoned.armed = false;
        Ok(PendingConnection {
            ingress: Ingress {
                handle: self.clone(),
                flow,
                alive,
                opening: Some(permit),
            },
            waiting: Some(waiting),
            complete: false,
        })
    }
    fn validate_input(bytes: &[u8]) -> Result<()> {
        let ip = Ipv4Packet::new_checked(bytes).map_err(|_| AdmissionError::Invalid)?;
        if ip.next_header() != IpProtocol::Tcp
            || !ip.verify_checksum()
            || ip.more_frags()
            || ip.frag_offset() != 0
        {
            return Err(AdmissionError::Invalid.into());
        }
        let tcp = TcpPacket::new_checked(ip.payload()).map_err(|_| AdmissionError::Invalid)?;
        if !tcp.verify_checksum(
            &IpAddress::Ipv4(ip.src_addr()),
            &IpAddress::Ipv4(ip.dst_addr()),
        ) {
            return Err(AdmissionError::Invalid.into());
        }
        Ok(())
    }
    pub fn incoming(&self, bytes: Bytes, permit: SendPermit) -> Result<()> {
        ensure!(
            bytes.len() <= MTU && permit.valid(),
            "native input admission retired"
        );
        let flow = Flow::from_packet(&bytes)
            .ok_or_else(|| anyhow::anyhow!("invalid native TCP packet"))?;
        Self::validate_input(&bytes)?;
        let binding = self
            .bindings
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&flow)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("native input is not owned"))?;
        ensure!(binding.alive.load(Ordering::SeqCst), "native flow retired");
        self.commands
            .try_send(Command::Input {
                id: binding.id,
                bytes,
                permit,
            })
            .map_err(|_| anyhow::anyhow!("native input queue unavailable"))
    }
}
impl Connection {
    pub fn owns_packet(&self, packet: &Packet) -> bool {
        self.id == packet.owner && self.ingress().owns_packet(packet)
    }
    pub fn ingress(&self) -> Ingress {
        Ingress {
            handle: self.handle.clone(),
            flow: self.flow,
            alive: self.alive.clone(),
            opening: None,
        }
    }
    pub fn flow(&self) -> Flow {
        self.flow
    }
    pub fn owns_read(&self, read: &NativeRead) -> bool {
        self.alive.load(Ordering::SeqCst)
            && read.valid()
            && Arc::ptr_eq(&self.handle.stack_scope, &read.stack_scope)
            && self.id == read.owner
            && self.flow == read.flow
    }
    pub fn acknowledges(&self, ack: &NativeAck, id: [u8; 16], offset: u64, length: usize) -> bool {
        self.alive.load(Ordering::SeqCst)
            && ack.permit.valid()
            && Arc::ptr_eq(&self.handle.stack_scope, &ack.stack_scope)
            && ack.owner == self.id
            && ack.flow == self.flow
            && ack.id == id
            && ack.offset == offset
            && ack.length == length
    }
    /// Publish a protocol receipt only under the exact native ACK's original
    /// admission. Dropping/cancelling a terminal receipt retires the flow.
    pub async fn publish_receipt<T, F: std::future::Future<Output = Result<T>>>(
        &self,
        ack: NativeAck,
        id: [u8; 16],
        offset: u64,
        length: usize,
        delivery: impl FnOnce() -> F,
    ) -> Result<T> {
        ensure!(
            self.acknowledges(&ack, id, offset, length),
            "native receipt binding invalid or retired"
        );
        let mut abandoned = RetireOnDrop {
            alive: self.alive.clone(),
            armed: true,
        };
        let result = ack.permit.during(delivery()).await?;
        if result.is_ok() {
            abandoned.armed = false;
            if let Some((complete, _)) = &ack.terminal_owner {
                complete.store(true, Ordering::SeqCst);
            }
        }
        result
    }
    pub fn retire(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }
    pub async fn renew_control(&self, permit: SendPermit) -> Result<()> {
        ensure!(self.alive.load(Ordering::SeqCst), "native flow retired");
        ensure!(permit.valid(), "native control admission retired");
        self.handle
            .commands
            .send(Command::Renew {
                id: self.id,
                flow: self.flow,
                permit,
            })
            .await
            .map_err(|_| anyhow::anyhow!("native runner stopped"))
    }
    pub async fn write_chunk(
        &self,
        id: [u8; 16],
        offset: u64,
        bytes: Bytes,
        permit: SendPermit,
    ) -> Result<NativeAck> {
        self.validate_write(id, &permit)?;
        let credit = self.handle.budget.reserve(bytes.len(), CHUNK)?;
        self.write_admitted(id, offset, bytes, permit, credit).await
    }

    /// Forward one LAN read across a native TCP window. The original admission
    /// covers every fragment, retransmission and final ACK while it is in flight.
    pub async fn write_window(
        &self,
        id: [u8; 16],
        offset: u64,
        bytes: Bytes,
        permit: SendPermit,
    ) -> Result<NativeAck> {
        let budget = Budget::forwarding();
        let credit = loop {
            self.validate_write(id, &permit)?;
            let available = budget.released.notified();
            tokio::pin!(available);
            available.as_mut().enable();
            match budget.reserve(bytes.len(), FORWARD_WINDOW) {
                Ok(credit) => break credit,
                Err(error)
                    if error.downcast_ref::<AdmissionError>() == Some(&AdmissionError::Busy) =>
                {
                    permit.during(available).await?;
                }
                Err(error) => return Err(error),
            }
        };
        self.write_admitted(id, offset, bytes, permit, credit).await
    }

    fn validate_write(&self, id: [u8; 16], permit: &SendPermit) -> Result<()> {
        ensure!(
            self.alive.load(Ordering::SeqCst) && id != [0; 16] && permit.valid(),
            "native chunk admission invalid"
        );
        Ok(())
    }

    async fn write_admitted(
        &self,
        id: [u8; 16],
        offset: u64,
        bytes: Bytes,
        permit: SendPermit,
        credit: Credit,
    ) -> Result<NativeAck> {
        let (reply, waiting) = oneshot::channel();
        let write = Write {
            id,
            offset,
            bytes,
            copied: 0,
            permit: permit.clone(),
            reply,
            _credit: credit,
        };
        permit
            .during(self.handle.commands.send(Command::Write {
                id: self.id,
                flow: self.flow,
                write,
            }))
            .await?
            .map_err(|_| anyhow::anyhow!("native runner stopped"))?;
        let mut abandoned = RetireOnDrop {
            alive: self.alive.clone(),
            armed: true,
        };
        let result = waiting
            .await
            .map_err(|_| anyhow::anyhow!("native chunk retired"))?;
        abandoned.armed = false;
        result
    }
    /// Return only after native TCP acknowledges FIN. An abandoned terminal
    /// receipt retires this generation; successful publication preserves peer
    /// half-close reads. No control renewal prolongs an unpublished FIN grant.
    pub async fn finish(&self, id: [u8; 16], offset: u64, permit: SendPermit) -> Result<NativeAck> {
        ensure!(
            id != [0; 16] && permit.valid() && self.alive.load(Ordering::SeqCst),
            "native FIN admission invalid"
        );
        let (reply, waiting) = oneshot::channel();
        permit
            .during(self.handle.commands.send(Command::Finish {
                id: self.id,
                flow: self.flow,
                fin: FinWrite {
                    id,
                    offset,
                    permit: permit.clone(),
                    reply,
                    sent: false,
                },
            }))
            .await?
            .map_err(|_| anyhow::anyhow!("native runner stopped"))?;
        let mut abandoned = RetireOnDrop {
            alive: self.alive.clone(),
            armed: true,
        };
        let result = waiting
            .await
            .map_err(|_| anyhow::anyhow!("native FIN retired"))?;
        abandoned.armed = false;
        result
    }
    pub async fn read_chunk(&self) -> Result<NativeRead> {
        ensure!(self.alive.load(Ordering::SeqCst), "native RX owner retired");
        let (reply, waiting) = oneshot::channel();
        self.handle
            .commands
            .send(Command::Read {
                id: self.id,
                flow: self.flow,
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("native runner stopped"))?;
        let mut abandoned = RetireOnDrop {
            alive: self.alive.clone(),
            armed: true,
        };
        let result = waiting
            .await
            .map_err(|_| anyhow::anyhow!("native RX retired"))?;
        abandoned.armed = false;
        result
    }
    pub async fn close(&self) -> Result<()> {
        self.retire();
        self.handle
            .commands
            .send(Command::Close {
                id: self.id,
                flow: self.flow,
            })
            .await
            .map_err(|_| anyhow::anyhow!("native runner stopped"))
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.retire();
    }
}
// Reply origins are separate from renewable connection control. An incoming
// segment can schedule a later socket-dispatch ACK rather than use its paired
// TxToken. Keep first origins until a cumulative ACK covers their sequence end.
#[derive(Default)]
struct Replies(Vec<(u32, u32, SendPermit)>);
impl Replies {
    fn observe(&mut self, tcp: &TcpPacket<&[u8]>, permit: SendPermit) -> Result<()> {
        let len = tcp.payload().len() + usize::from(tcp.syn()) + usize::from(tcp.fin());
        if len == 0 {
            return Ok(());
        }
        let start = tcp.seq_number().0 as u32;
        let end = start.wrapping_add(len as u32);
        if self
            .0
            .iter()
            .any(|(old_start, old_end, _)| *old_start == start && *old_end == end)
        {
            return Ok(());
        }
        ensure!(self.0.len() < QUEUE, "native reply origin metadata full");
        self.0.push((start, end, permit));
        Ok(())
    }
    fn acknowledge(&mut self, ack: u32) -> Vec<SendPermit> {
        let origins = self.0.iter().map(|(_, _, permit)| permit.clone()).collect();
        self.0
            .retain(|(_, end, _)| (ack.wrapping_sub(*end) as i32) < 0);
        origins
    }
}
#[derive(Clone)]
struct Context {
    stack_scope: Arc<()>,
    owner: u64,
    alive: Arc<AtomicBool>,
    control: SendPermit,
    replies: Arc<Mutex<Replies>>,
    data: Option<SendPermit>,
    fin: Option<SendPermit>,
}
#[derive(Default)]
struct Packets {
    input: VecDeque<Input>,
    output: VecDeque<Packet>,
    contexts: HashMap<Flow, Context>,
}
struct Input {
    bytes: Bytes,
    permit: SendPermit,
    alive: Arc<AtomicBool>,
    rx: Option<Arc<Mutex<rx::Origins>>>,
    reset: Option<Arc<AtomicBool>>,
    replies: Arc<Mutex<Replies>>,
}
struct Receive(Input);
struct Trigger {
    flow: Flow,
    alive: Arc<AtomicBool>,
    permit: SendPermit,
}
struct Transmit<'a> {
    trigger: Option<Trigger>,
    output: &'a mut VecDeque<Packet>,
    contexts: &'a HashMap<Flow, Context>,
}
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        if self.0.alive.load(Ordering::SeqCst) && self.0.permit.valid() {
            if let Some(rx) = &self.0.rx {
                let observed = (|| -> Result<()> {
                    let ip = Ipv4Packet::new_checked(self.0.bytes.as_ref())
                        .map_err(|_| AdmissionError::Invalid)?;
                    let tcp = TcpPacket::new_checked(ip.payload())
                        .map_err(|_| AdmissionError::Invalid)?;
                    self.0
                        .replies
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .observe(&tcp, self.0.permit.clone())?;
                    if tcp.rst() {
                        if let Some(reset) = &self.0.reset {
                            reset.store(true, Ordering::SeqCst);
                        }
                    }
                    rx.lock().unwrap_or_else(|p| p.into_inner()).observe(
                        tcp.seq_number().0 as u32,
                        tcp.syn(),
                        tcp.payload().len(),
                        tcp.fin(),
                        self.0.permit.clone(),
                    )
                })();
                if observed.is_err() {
                    self.0.alive.store(false, Ordering::SeqCst);
                    return f(&[]);
                }
            }
            f(&self.0.bytes)
        } else {
            f(&[])
        }
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, length: usize, f: F) -> R {
        let mut bytes = vec![0; length];
        let result = f(&mut bytes);
        if let Some(flow) = Flow::from_packet(&bytes) {
            if let Some(context) = self.contexts.get(&flow) {
                if self.trigger.as_ref().is_some_and(|trigger| {
                    trigger.flow != flow || !Arc::ptr_eq(&trigger.alive, &context.alive)
                }) {
                    return result; // A paired RX response cannot borrow another tuple/generation.
                }
                let ip = Ipv4Packet::new_checked(&bytes).ok();
                let has_data = ip
                    .as_ref()
                    .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok())
                    .is_some_and(|tcp| !tcp.payload().is_empty());
                if has_data && context.data.is_none() {
                    context.alive.store(false, Ordering::SeqCst);
                    return result;
                }
                let has_fin = ip
                    .as_ref()
                    .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok())
                    .is_some_and(|tcp| tcp.fin());
                if has_fin && context.fin.is_none() {
                    context.alive.store(false, Ordering::SeqCst);
                    return result;
                }
                let mut context = context.clone();
                if !has_data {
                    context.data = None;
                }
                if !has_fin {
                    context.fin = None;
                }
                let mut origins = vec![context.control.clone()];
                // The receive companion can immediately ACK an old input. Keep
                // that exact input's origin on the queued reply, not as the
                // established connection's renewable control authority.
                origins.extend(self.trigger.as_ref().map(|trigger| trigger.permit.clone()));
                if let Some(tcp) = ip
                    .as_ref()
                    .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok())
                {
                    if tcp.ack() {
                        origins.extend(
                            context
                                .replies
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                .acknowledge(tcp.ack_number().0 as u32),
                        );
                    }
                }
                origins.extend(context.data.iter().cloned());
                origins.extend(context.fin.iter().cloned());
                let stack_scope = context.stack_scope.clone();
                let owner = context.owner;
                let alive = context.alive.clone();
                let permit = SendPermit::combine(origins).constrain(move || {
                    let valid = context.alive.load(Ordering::SeqCst)
                        && context.control.valid()
                        && context.data.as_ref().is_none_or(|p| p.valid())
                        && context.fin.as_ref().is_none_or(|p| p.valid());
                    if !valid {
                        context.alive.store(false, Ordering::SeqCst);
                    }
                    valid
                });
                if permit.valid() {
                    self.output.push_back(Packet {
                        stack_scope,
                        owner,
                        flow,
                        alive,
                        bytes: bytes.into(),
                        permit,
                    });
                }
            }
        }
        result
    }
}
impl Device for Packets {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(Receive, Transmit<'_>)> {
        if self.output.len() >= QUEUE {
            return None;
        }
        while self
            .input
            .front()
            .is_some_and(|input| !input.alive.load(Ordering::SeqCst) || !input.permit.valid())
        {
            self.input.pop_front();
        }
        let input = self.input.pop_front()?;
        let trigger = Trigger {
            flow: Flow::from_packet(&input.bytes)?.reverse(),
            alive: input.alive.clone(),
            permit: input.permit.clone(),
        };
        Some((
            Receive(input),
            Transmit {
                trigger: Some(trigger),
                output: &mut self.output,
                contexts: &self.contexts,
            },
        ))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<Transmit<'_>> {
        (self.output.len() < QUEUE).then_some(Transmit {
            trigger: None,
            output: &mut self.output,
            contexts: &self.contexts,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}
struct Active {
    _wide_window: Option<tokio::sync::SemaphorePermit<'static>>,
    id: u64,
    socket: SocketHandle,
    incoming: Flow,
    alive: Arc<AtomicBool>,
    control: SendPermit,
    connected: Option<oneshot::Sender<Result<u64>>>,
    deadline: Instant,
    next_offset: u64,
    writes: VecDeque<Write>,
    rx: Arc<Mutex<rx::Origins>>,
    replies: Arc<Mutex<Replies>>,
    read: Option<oneshot::Sender<Result<NativeRead>>>,
    fin: Option<FinWrite>,
    terminal: Option<Terminal>,
    local_fin_done: bool,
    prior_state: tcp::State,
    reset: Arc<AtomicBool>,
}
pub struct Runner {
    wide_forwarding: bool,
    stack_scope: Arc<()>,
    commands: mpsc::Receiver<Command>,
    output: PollSender<Packet>,
    bindings: Bindings,
    interface: Interface,
    sockets: SocketSet<'static>,
    packets: Packets,
    flows: HashMap<Flow, Active>,
    origin: Instant,
    next_id: u64,
    budget: Arc<Budget>,
}
pub fn stack() -> Result<(Handle, mpsc::Receiver<Packet>, Runner)> {
    build_stack(false)
}
/// Use a wider TCP window for socket forwarding across long-delay links.
pub fn forwarding_stack() -> Result<(Handle, mpsc::Receiver<Packet>, Runner)> {
    build_stack(true)
}
fn build_stack(wide_forwarding: bool) -> Result<(Handle, mpsc::Receiver<Packet>, Runner)> {
    let (commands, input) = mpsc::channel(QUEUE);
    let (output, packets) = mpsc::channel(QUEUE);
    let bindings: Bindings = Default::default();
    let stack_scope = Arc::new(());
    let budget = Arc::new(Budget::default());
    let mut device = Packets::default();
    let mut config = Config::new(HardwareAddress::Ip);
    let mut seed = [0; 8];
    getrandom::fill(&mut seed).map_err(|_| anyhow::anyhow!("native TCP randomness unavailable"))?;
    config.random_seed = u64::from_ne_bytes(seed);
    let mut interface = Interface::new(config, &mut device, StackInstant::from_millis(0));
    let router = std::net::Ipv4Addr::new(10, 255, 255, 254);
    interface.update_ip_addrs(|ips| ips.push(IpCidr::new(IpAddress::Ipv4(router), 32)).unwrap());
    interface.routes_mut().add_default_ipv4_route(router)?;
    interface.set_any_ip(true);
    Ok((
        Handle {
            stack_scope: stack_scope.clone(),
            commands,
            bindings: bindings.clone(),
            budget: budget.clone(),
        },
        packets,
        Runner {
            wide_forwarding,
            stack_scope,
            commands: input,
            output: PollSender::new(output),
            bindings,
            interface,
            sockets: SocketSet::new(Vec::new()),
            packets: device,
            flows: HashMap::new(),
            origin: Instant::now(),
            next_id: 1,
            budget,
        },
    ))
}
impl Runner {
    fn now(&self) -> StackInstant {
        StackInstant::from_millis(self.origin.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }
    fn create(
        &mut self,
        flow: Flow,
        permit: SendPermit,
        reply: oneshot::Sender<Result<u64>>,
        alive: Arc<AtomicBool>,
        syn: Option<Bytes>,
        direct_carrier: bool,
    ) {
        if self.packets.input.len() >= QUEUE
            || !alive.load(Ordering::SeqCst)
            || !permit.valid()
            || self.flows.len() >= MAX_FLOWS
            || self.flows.contains_key(&flow)
            || self.next_id == u64::MAX
        {
            let _ = reply.send(Err(anyhow::anyhow!("native flow unavailable")));
            return;
        }
        let accepting = syn.is_some();
        if accepting && (!self.packets.input.is_empty() || self.packets.output.len() >= QUEUE) {
            let _ = reply.send(Err(AdmissionError::Busy.into()));
            return;
        }
        let wide_window = self
            .wide_forwarding
            .then(|| WIDE_FORWARD_SOCKETS.try_acquire().ok())
            .flatten();
        let (receive_size, send_size) = if wide_window.is_some() {
            let send_size = if direct_carrier {
                DIRECT_FORWARD_WINDOW
            } else {
                2 * FORWARD_SOCKET_BUFFER
            };
            (FORWARD_SOCKET_BUFFER, send_size)
        } else {
            (16 * 1024, super::TCP_SEND_BUFFER)
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; receive_size]),
            tcp::SocketBuffer::new(vec![0; send_size]),
        );
        socket.set_timeout(None);
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        let endpoint =
            |address: std::net::SocketAddrV4| (IpAddress::Ipv4(*address.ip()), address.port());
        let configured = if syn.is_some() {
            socket.listen(endpoint(flow.source)).map_err(|_| ())
        } else {
            socket
                .connect(
                    self.interface.context(),
                    endpoint(flow.destination),
                    endpoint(flow.source),
                )
                .map_err(|_| ())
        };
        if configured.is_err() {
            let _ = reply.send(Err(anyhow::anyhow!("native flow unavailable")));
            return;
        }
        let id = self.next_id;
        self.next_id += 1;
        let incoming = flow.reverse();
        self.bindings
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                incoming,
                Binding {
                    id,
                    alive: alive.clone(),
                },
            );
        let rx = Arc::new(Mutex::new(rx::Origins::with_window(receive_size)));
        let replies = Arc::new(Mutex::new(Replies::default()));
        let reset = Arc::new(AtomicBool::new(false));
        if let Some(bytes) = syn {
            self.packets.input.push_back(Input {
                bytes,
                permit: permit.clone(),
                alive: alive.clone(),
                rx: Some(rx.clone()),
                reset: Some(reset.clone()),
                replies: replies.clone(),
            });
        }
        self.flows.insert(
            flow,
            Active {
                _wide_window: wide_window,
                id,
                socket: self.sockets.add(socket),
                incoming,
                alive,
                control: permit,
                connected: Some(reply),
                deadline: Instant::now() + Duration::from_secs(10),
                next_offset: 0,
                writes: VecDeque::new(),
                rx,
                replies,
                read: None,
                fin: None,
                terminal: None,
                local_fin_done: false,
                prior_state: tcp::State::Closed,
                reset,
            },
        );
        if accepting {
            // Bind the admitted remote before another listener for this service
            // can exist; never let generic listen choose a different owner.
            let active = self.flows.get(&flow).unwrap();
            self.packets.contexts.insert(
                flow,
                Context {
                    stack_scope: self.stack_scope.clone(),
                    owner: active.id,
                    alive: active.alive.clone(),
                    control: active.control.clone(),
                    replies: active.replies.clone(),
                    data: None,
                    fin: None,
                },
            );
            self.interface
                .poll(self.now(), &mut self.packets, &mut self.sockets);
            let active = self.flows.get(&flow).unwrap();
            let bound = self
                .sockets
                .get::<tcp::Socket>(active.socket)
                .remote_endpoint()
                .is_some_and(|r| {
                    r.addr == endpoint(flow.destination).0 && r.port == flow.destination.port()
                });
            if !bound {
                let active = self.flows.remove(&flow).unwrap();
                active.alive.store(false, Ordering::SeqCst);
                self.packets
                    .input
                    .retain(|input| !Arc::ptr_eq(&input.alive, &active.alive));
                self.bindings
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&active.incoming);
                self.packets.contexts.remove(&flow);
                self.sockets.remove(active.socket);
                if let Some(reply) = active.connected {
                    let _ = reply.send(Err(anyhow::anyhow!("native SYN rejected or blocked")));
                }
            }
        }
    }
    fn valid_input(bytes: &[u8]) -> bool {
        Handle::validate_input(bytes).is_ok()
    }
    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<bool>> {
        use std::task::Poll;
        let mut progress = false;
        for _ in 0..64 {
            match self.commands.poll_recv(cx) {
                Poll::Ready(Some(command)) => {
                    progress = true;
                    match command {
                        Command::Connect {
                            flow,
                            permit,
                            reply,
                            alive,
                            syn,
                            direct_carrier,
                        } => self.create(flow, permit, reply, alive, syn, direct_carrier),
                        Command::Input { id, bytes, permit } => {
                            if permit.valid() && Self::valid_input(&bytes) {
                                if let Some(incoming) = Flow::from_packet(&bytes) {
                                    if let Some(active) = self.flows.values_mut().find(|a| {
                                        a.incoming == incoming
                                            && a.id == id
                                            && a.alive.load(Ordering::SeqCst)
                                    }) {
                                        // Packet origins remain in Input/RX spans. Only
                                        // explicit Renew replaces established control:
                                        // an old packet must not roll its deadline back.
                                        if self.packets.input.len() < QUEUE {
                                            self.packets.input.push_back(Input {
                                                bytes,
                                                permit,
                                                alive: active.alive.clone(),
                                                rx: Some(active.rx.clone()),
                                                reset: Some(active.reset.clone()),
                                                replies: active.replies.clone(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        Command::Write { id, flow, write } => {
                            let error = if let Some(active) = self
                                .flows
                                .get_mut(&flow)
                                .filter(|a| a.id == id && a.alive.load(Ordering::SeqCst))
                            {
                                if active.fin.is_some() || active.local_fin_done {
                                    AdmissionError::Invalid
                                } else if !write.permit.valid() {
                                    AdmissionError::Retired
                                } else if active.writes.len() >= 2 {
                                    AdmissionError::Busy
                                } else if write.offset != active.next_offset {
                                    AdmissionError::Invalid
                                } else if let Some(next) =
                                    active.next_offset.checked_add(write.bytes.len() as u64)
                                {
                                    active.next_offset = next;
                                    active.writes.push_back(write);
                                    continue;
                                } else {
                                    AdmissionError::Invalid
                                }
                            } else {
                                AdmissionError::Retired
                            };
                            let _ = write.reply.send(Err(error.into()));
                        }
                        Command::Finish { id, flow, fin } => {
                            let error = if let Some(active) = self
                                .flows
                                .get_mut(&flow)
                                .filter(|a| a.id == id && a.alive.load(Ordering::SeqCst))
                            {
                                if !fin.permit.valid() {
                                    AdmissionError::Retired
                                } else if active.fin.is_some()
                                    || active.terminal.is_some()
                                    || fin.offset != active.next_offset
                                {
                                    AdmissionError::Invalid
                                } else {
                                    active.fin = Some(fin);
                                    continue;
                                }
                            } else {
                                AdmissionError::Retired
                            };
                            let _ = fin.reply.send(Err(error.into()));
                        }
                        Command::Read { id, flow, reply } => {
                            if let Some(active) = self
                                .flows
                                .get_mut(&flow)
                                .filter(|a| a.id == id && a.alive.load(Ordering::SeqCst))
                            {
                                if active.read.is_some() {
                                    let _ = reply.send(Err(AdmissionError::Busy.into()));
                                } else {
                                    active.read = Some(reply);
                                }
                            } else {
                                let _ = reply.send(Err(AdmissionError::Retired.into()));
                            }
                        }
                        Command::Renew { id, flow, permit } => {
                            if let Some(active) = self
                                .flows
                                .get_mut(&flow)
                                .filter(|a| a.id == id && permit.valid())
                            {
                                active.control = permit;
                            }
                        }
                        Command::Close { id, flow } => {
                            if let Some(active) = self.flows.get(&flow).filter(|a| a.id == id) {
                                active.alive.store(false, Ordering::SeqCst);
                            }
                        }
                    }
                }
                Poll::Ready(None) => return Poll::Ready(Ok(false)),
                Poll::Pending => break,
            }
        }
        self.packets.contexts.clear();
        for (flow, active) in &self.flows {
            if !active.rx.lock().unwrap_or_else(|p| p.into_inner()).valid()
                || active.read.as_ref().is_some_and(|r| r.is_closed())
                || !active.control.valid()
                || active
                    .fin
                    .as_ref()
                    .is_some_and(|f| !f.permit.valid() || f.reply.is_closed())
                || active
                    .terminal
                    .as_ref()
                    .is_some_and(|t| !t.complete.load(Ordering::SeqCst) && !t.origin.valid())
                || active
                    .writes
                    .iter()
                    .any(|w| !w.permit.valid() || w.reply.is_closed())
            {
                active.alive.store(false, Ordering::SeqCst);
            }
            self.packets.contexts.insert(
                *flow,
                Context {
                    stack_scope: self.stack_scope.clone(),
                    owner: active.id,
                    alive: active.alive.clone(),
                    control: active.control.clone(),
                    replies: active.replies.clone(),
                    data: active.writes.front().map(|w| w.permit.clone()),
                    fin: active.fin.as_ref().map(|f| f.permit.clone()),
                },
            );
            if !active.alive.load(Ordering::SeqCst) {
                self.sockets.get_mut::<tcp::Socket>(active.socket).abort();
            }
        }
        for active in self.flows.values_mut() {
            active.prior_state = self.sockets.get::<tcp::Socket>(active.socket).state();
        }
        let now = self.now();
        progress |= self
            .interface
            .poll(now, &mut self.packets, &mut self.sockets)
            != smoltcp::iface::PollResult::None;
        let mut removed = Vec::new();
        for (flow, active) in &mut self.flows {
            let socket = self.sockets.get_mut::<tcp::Socket>(active.socket);
            let reset = active.reset.swap(false, Ordering::SeqCst);
            let fin_acked = !reset
                && active
                    .fin
                    .as_ref()
                    .is_some_and(|f| f.sent && f.permit.valid() && !f.reply.is_closed())
                && (matches!(socket.state(), tcp::State::FinWait2 | tcp::State::TimeWait)
                    || socket.state() == tcp::State::Closed
                        && active.prior_state == tcp::State::LastAck)
                && active.alive.load(Ordering::SeqCst);
            if fin_acked {
                let fin = active.fin.take().unwrap();
                let origin = fin.permit.clone();
                let alive = active.alive.clone();
                let complete = Arc::new(AtomicBool::new(false));
                active.local_fin_done = true;
                active.terminal = Some(Terminal {
                    origin: fin.permit,
                    complete: complete.clone(),
                });
                let ack = NativeAck {
                    permit: origin.constrain(move || alive.load(Ordering::SeqCst)),
                    terminal_owner: Some((complete, active.alive.clone())),
                    stack_scope: self.stack_scope.clone(),
                    owner: active.id,
                    flow: *flow,
                    id: fin.id,
                    offset: fin.offset,
                    length: 0,
                };
                if fin.reply.send(Ok(ack)).is_err() {
                    active.alive.store(false, Ordering::SeqCst);
                }
                progress = true;
            }
            if !active.alive.load(Ordering::SeqCst)
                || !active.control.valid()
                || socket.state() == tcp::State::Closed && active.terminal.is_none()
                || active.connected.as_ref().is_some_and(|r| r.is_closed())
                || active.connected.is_some() && Instant::now() >= active.deadline
            {
                active.alive.store(false, Ordering::SeqCst);
                socket.abort();
                removed.push(*flow);
                continue;
            }
            let eof_ready = active.connected.is_none()
                && !socket.may_recv()
                && active
                    .rx
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .eof_pending();
            if active.read.is_some() && (socket.recv_queue() > 0 || eof_ready) {
                let len = socket.recv_queue().min(CHUNK);
                let eof = len == 0 && eof_ready;
                let result = (|| -> Result<NativeRead> {
                    let credit = if len > 0 {
                        Some(self.budget.reserve(len, CHUNK)?)
                    } else {
                        None
                    };
                    let origins = active
                        .rx
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .take(len, eof)?;
                    let alive = active.alive.clone();
                    let combined = SendPermit::combine(origins);
                    let checked = combined.clone();
                    let permit = combined.constrain(move || {
                        let valid = alive.load(Ordering::SeqCst) && checked.valid();
                        if !valid {
                            alive.store(false, Ordering::SeqCst);
                        }
                        valid
                    });
                    ensure!(permit.valid(), "native RX origin retired");
                    let mut bytes = vec![0; len];
                    if len > 0 {
                        ensure!(
                            socket.recv_slice(&mut bytes)? == len,
                            "native RX length changed"
                        );
                    }
                    Ok(NativeRead {
                        stack_scope: self.stack_scope.clone(),
                        owner: active.id,
                        flow: *flow,
                        bytes: bytes.into(),
                        eof,
                        permit,
                        _credit: credit,
                        alive: active.alive.clone(),
                        delivered: false,
                    })
                })();
                if result.as_ref().err().is_some_and(|e| {
                    e.downcast_ref::<AdmissionError>() != Some(&AdmissionError::Busy)
                }) {
                    active.alive.store(false, Ordering::SeqCst);
                }
                if let Some(reply) = active.read.take() {
                    if reply.send(result).is_err() {
                        active.alive.store(false, Ordering::SeqCst);
                    }
                }
                progress = true;
            }
            if matches!(
                socket.state(),
                tcp::State::Established | tcp::State::CloseWait
            ) {
                if let Some(reply) = active.connected.take() {
                    if reply.send(Ok(active.id)).is_err() {
                        active.alive.store(false, Ordering::SeqCst);
                    }
                    progress = true;
                }
                if let Some(write) = active.writes.front_mut() {
                    if !write.permit.valid() || write.reply.is_closed() {
                        active.alive.store(false, Ordering::SeqCst);
                        socket.abort();
                        removed.push(*flow);
                        continue;
                    }
                    if write.copied == write.bytes.len() && socket.send_queue() == 0 {
                        let write = active.writes.pop_front().unwrap();
                        let origin = write.permit.clone();
                        let alive = active.alive.clone();
                        let _ = write.reply.send(Ok(NativeAck {
                            terminal_owner: None,
                            permit: origin.constrain(move || alive.load(Ordering::SeqCst)),
                            stack_scope: self.stack_scope.clone(),
                            owner: active.id,
                            flow: *flow,
                            id: write.id,
                            offset: write.offset,
                            length: write.bytes.len(),
                        }));
                        progress = true;
                    } else if write.copied < write.bytes.len() && socket.can_send() {
                        if let Ok(count) = socket.send_slice(&write.bytes[write.copied..]) {
                            write.copied += count;
                            progress |= count > 0;
                        }
                    }
                }
                if active.writes.is_empty() {
                    if let Some(fin) = &mut active.fin {
                        if !fin.sent {
                            socket.close();
                            fin.sent = true;
                            progress = true;
                        }
                    }
                }
            }
        }
        for flow in removed {
            if let Some(active) = self.flows.remove(&flow) {
                active.alive.store(false, Ordering::SeqCst);
                self.bindings
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&active.incoming);
                self.sockets.remove(active.socket);
            }
        }
        while let Some(packet) = self.packets.output.front() {
            if !packet.valid() {
                self.packets.output.pop_front();
                progress = true;
                continue;
            }
            match self.output.poll_reserve(cx) {
                Poll::Ready(Ok(())) => {
                    self.output
                        .send_item(packet.clone())
                        .map_err(|_| anyhow::anyhow!("native consumer stopped"))?;
                    self.packets.output.pop_front();
                    progress = true;
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(anyhow::anyhow!("native consumer stopped")))
                }
                Poll::Pending => break,
            }
        }
        if progress {
            Poll::Ready(Ok(true))
        } else {
            Poll::Pending
        }
    }
    pub async fn run(mut self, cancel: CancellationToken) -> Result<()> {
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let active = !self.flows.is_empty();
            tokio::select! {_=cancel.cancelled()=>return Ok(()),_=tick.tick(),if active=>{},result=poll_fn(|cx|self.poll(cx))=>if !result?{return Ok(());}}
            tokio::task::yield_now().await;
        }
    }
}
impl Drop for Runner {
    fn drop(&mut self) {
        for active in self.flows.values() {
            active.alive.store(false, Ordering::SeqCst);
        }
        self.bindings
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Rig {
        connection: Arc<Connection>,
        app: tokio::io::DuplexStream,
        handle: Handle,
        native: super::super::Handle,
        stop: CancellationToken,
        tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
        release: tokio::sync::watch::Sender<bool>,
        held_acks: Arc<AtomicUsize>,
        held_packets: mpsc::Receiver<Packet>,
        held_input: mpsc::Receiver<Bytes>,
        delivered: Arc<AtomicUsize>,
    }
    async fn rig(hold_data: bool) -> Result<Rig> {
        rig_rx(hold_data, false).await
    }
    async fn rig_rx(hold_data: bool, hold_rx: bool) -> Result<Rig> {
        rig_rx_control(hold_data, hold_rx, false).await
    }
    async fn rig_rx_control(hold_data: bool, hold_rx: bool, hold_control: bool) -> Result<Rig> {
        let (handle, mut outgoing, runner) = stack()?;
        let (native, mut incoming, native_runner) = super::super::stack()?;
        let stop = CancellationToken::new();
        let a = stop.clone();
        let b = stop.clone();
        let first = tokio::spawn(async move { runner.run(a).await });
        let second = tokio::spawn(async move { native_runner.run(b).await });
        let flow = Flow {
            source: "10.234.250.1:4000".parse()?,
            destination: "10.234.250.2:443".parse()?,
        };
        let h = handle.clone();
        let connecting =
            tokio::spawn(async move { h.connect(flow, SendPermit::new(|| true)).await });
        let syn = tokio::time::timeout(Duration::from_secs(1), outgoing.recv())
            .await?
            .unwrap();
        let target = native.clone();
        let accepting = tokio::spawn(async move {
            syn.deliver(move |bytes| async move { target.accept_syn(bytes).await })
                .await
        });
        let synack = tokio::time::timeout(Duration::from_secs(1), incoming.recv())
            .await?
            .unwrap();
        handle.incoming(synack, SendPermit::new(|| true))?;
        let ack = tokio::time::timeout(Duration::from_secs(1), outgoing.recv())
            .await?
            .unwrap();
        let target = native.clone();
        ack.deliver(move |bytes| async move { target.packet(bytes) })
            .await?;
        let connection = Arc::new(connecting.await??);
        let (_, app) = accepting.await??;
        let (release, mut released) = tokio::sync::watch::channel(false);
        let held_acks = Arc::new(AtomicUsize::new(0));
        let held_count = held_acks.clone();
        let (delivery, held_packets) = mpsc::channel(1);
        let (rx_delivery, held_input) = mpsc::channel(32);
        let delivered = Arc::new(AtomicUsize::new(0));
        let count = delivered.clone();
        let target = native.clone();
        let h = handle.clone();
        let cancel = stop.clone();
        let pump = tokio::spawn(async move {
            let mut held = Vec::new();
            let mut open = false;
            loop {
                tokio::select! {biased;
                 _=cancel.cancelled()=>return Ok(()),
                 changed=released.changed()=>{if changed.is_err(){return Ok(());}open=*released.borrow_and_update();if open{for bytes in held.drain(..){let _=h.incoming(bytes,SendPermit::new(||true));}}},
                 packet=outgoing.recv()=>{let Some(packet)=packet else{return Ok(());};
                  let payload=Ipv4Packet::new_checked(packet.bytes()).ok().and_then(|ip|TcpPacket::new_checked(ip.payload()).ok().map(|tcp|tcp.payload().len())).unwrap_or(0);
                  if hold_data&&payload>0 || hold_control&&payload==0 {let _=delivery.try_send(packet);continue;}
                  let target=target.clone();let count=count.clone();let _=packet.deliver(move|bytes|async move{target.packet(bytes)?;count.fetch_add(payload,Ordering::SeqCst);Ok(())}).await;
                 },
                 packet=incoming.recv()=>{let Some(packet)=packet else{return Ok(());};let ip=Ipv4Packet::new_checked(packet.as_ref())?;let tcp=TcpPacket::new_checked(ip.payload())?;if hold_rx&&(!tcp.payload().is_empty()||tcp.fin()||tcp.rst()){let _=rx_delivery.try_send(packet);continue;}if open{let _=h.incoming(packet,SendPermit::new(||true));}else{ensure!(held.len()<32,"fixture ACK holding bound exceeded");held.push(packet);held_count.store(held.len(),Ordering::SeqCst);}}
                }
            }
        });
        Ok(Rig {
            connection,
            app,
            handle,
            native,
            stop,
            tasks: vec![first, second, pump],
            release,
            held_acks,
            held_packets,
            held_input,
            delivered,
        })
    }
    async fn cleanup(rig: Rig) -> Result<()> {
        rig.stop.cancel();
        for task in rig.tasks {
            task.await??;
        }
        ensure!(
            *rig.handle.budget.used.lock().unwrap() == 0,
            "native chunk credits leaked"
        );
        ensure!(
            rig.handle.bindings.read().unwrap().is_empty(),
            "native tuple ownership leaked"
        );
        Ok(())
    }
    #[test]
    fn deferred_reply_origins_cover_cumulative_ack_wrap_and_first_admission() -> Result<()> {
        fn segment(sequence: u32, payload: usize) -> Vec<u8> {
            let mut bytes = vec![0; 20 + payload];
            let mut tcp = TcpPacket::new_unchecked(&mut bytes[..]);
            tcp.set_header_len(20);
            tcp.set_seq_number(smoltcp::wire::TcpSeqNumber(sequence as i32));
            bytes
        }
        let mut replies = Replies::default();
        let first = Arc::new(AtomicBool::new(true));
        let flag = first.clone();
        let bytes = segment(u32::MAX - 3, 8);
        replies.observe(
            &TcpPacket::new_checked(&bytes[..])?,
            SendPermit::new(move || flag.load(Ordering::SeqCst)),
        )?;
        // An exact retransmission cannot replace the immutable first origin.
        replies.observe(
            &TcpPacket::new_checked(&bytes[..])?,
            SendPermit::new(|| true),
        )?;
        ensure!(replies.0.len() == 1, "duplicate consumed reply metadata");
        let out_of_order = segment(10, 5);
        replies.observe(
            &TcpPacket::new_checked(&out_of_order[..])?,
            SendPermit::new(|| true),
        )?;
        let partial = replies.acknowledge(3);
        ensure!(
            partial.len() == 2 && replies.0.len() == 2,
            "partial ACK released uncovered wrapped segment"
        );
        first.store(false, Ordering::SeqCst);
        ensure!(!partial[0].valid(), "duplicate replaced first admission");
        let cumulative = replies.acknowledge(4);
        ensure!(
            !cumulative[0].valid() && replies.0.len() == 1,
            "wrapped ACK failed exact coverage"
        );
        replies.acknowledge(15);
        ensure!(
            replies.0.is_empty(),
            "cumulative ACK retained covered metadata"
        );
        // Pure ACKs cannot pin later idle control to a historical packet.
        let ack = segment(20, 0);
        replies.observe(
            &TcpPacket::new_checked(&ack[..])?,
            SendPermit::new(|| false),
        )?;
        ensure!(replies.0.is_empty(), "pure ACK retained idle authority");
        for sequence in 0..QUEUE {
            let bytes = segment(sequence as u32, 1);
            replies.observe(
                &TcpPacket::new_checked(&bytes[..])?,
                SendPermit::new(|| true),
            )?;
        }
        let overflow = segment(QUEUE as u32, 1);
        ensure!(
            replies
                .observe(
                    &TcpPacket::new_checked(&overflow[..])?,
                    SendPermit::new(|| true)
                )
                .is_err(),
            "reply metadata exceeded bound"
        );
        Ok(())
    }
    #[tokio::test]
    async fn consumed_native_input_cannot_roll_back_fresh_control_to_old_packet_deadline(
    ) -> Result<()> {
        let mut rig = rig_rx_control(false, true, true).await?;
        rig.release.send(true)?;
        let result = async {
            rig.app.write_all(b"old-native-byte").await?;
            let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_input.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("old native DATA absent"))?;
            let fresh_deadline = Instant::now() + Duration::from_secs(5);
            let current = Arc::new(AtomicBool::new(true));
            let observed = current.clone();
            let fresh = SendPermit::bounded(
                move || observed.load(Ordering::SeqCst) && Instant::now() < fresh_deadline,
                move || fresh_deadline.checked_duration_since(Instant::now()),
            );
            rig.connection.renew_control(fresh.clone()).await?;
            let old_deadline = Instant::now() + Duration::from_secs(1);
            let old = SendPermit::bounded(
                move || Instant::now() < old_deadline,
                move || old_deadline.checked_duration_since(Instant::now()),
            );
            rig.handle.incoming(packet, old.clone())?;
            let read =
                tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
            read.deliver(|bytes, eof| async move {
                ensure!(
                    !eof && bytes.as_ref() == b"old-native-byte",
                    "old native DATA changed"
                );
                Ok(())
            })
            .await?;
            let ack = tokio::time::timeout(Duration::from_secs(1), rig.held_packets.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("old native ACK absent"))?;
            ensure!(ack.valid(), "old native ACK was not originally authorized");
            // Deliver one authorized copy now; retain the same packet's queued
            // copy to prove its immutable admission still expires independently.
            let target = rig.native.clone();
            ack.clone()
                .deliver(move |bytes| async move { target.packet(bytes) })
                .await?;
            // The old byte has crossed its actual native read/delivery boundary.
            // Its deadline cannot become the current flow-control deadline.
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                old_deadline + Duration::from_millis(100),
            ))
            .await;
            ensure!(
                !old.valid() && fresh.valid(),
                "fixture did not separate original and current deadlines"
            );
            ensure!(
                rig.connection.alive.load(Ordering::SeqCst),
                "consumed old packet retired freshly authorized native control"
            );
            let called = Arc::new(AtomicBool::new(false));
            let callback = called.clone();
            ensure!(
                ack.deliver(|_| async move {
                    callback.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
                .is_err()
                    && !called.load(Ordering::SeqCst),
                "queued native ACK lost the triggering input origin"
            );
            rig.app.write_all(b"fresh-native-byte").await?;
            let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_input.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("fresh native DATA absent"))?;
            rig.handle.incoming(packet, fresh.clone())?;
            let read =
                tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
            read.deliver(|bytes, eof| async move {
                ensure!(
                    !eof && bytes.as_ref() == b"fresh-native-byte",
                    "fresh native DATA changed"
                );
                Ok(())
            })
            .await?;
            current.store(false, Ordering::SeqCst);
            tokio::time::timeout(Duration::from_secs(1), async {
                while rig.connection.alive.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        let cleaned = cleanup(rig).await;
        result?;
        cleaned
    }
    fn portion(packet: &Bytes, start: usize, length: usize) -> Result<Bytes> {
        let ip = Ipv4Packet::new_checked(packet.as_ref())?;
        let tcp = TcpPacket::new_checked(ip.payload())?;
        let ih = ip.header_len() as usize;
        let th = tcp.header_len() as usize;
        let mut bytes = Vec::from(&packet[..ih + th]);
        bytes.extend_from_slice(&tcp.payload()[start..start + length]);
        let n = bytes.len() as u16;
        let mut ip = Ipv4Packet::new_unchecked(bytes.as_mut_slice());
        ip.set_total_len(n);
        ip.fill_checksum();
        let source = IpAddress::Ipv4(ip.src_addr());
        let destination = IpAddress::Ipv4(ip.dst_addr());
        let mut part = TcpPacket::new_unchecked(ip.payload_mut());
        part.set_seq_number(tcp.seq_number() + start);
        part.set_fin(false);
        part.fill_checksum(&source, &destination);
        Ok(bytes.into())
    }
    #[tokio::test]
    async fn real_tcp_reassembly_out_of_order_overlap_and_blocked_read_keep_first_origin(
    ) -> Result<()> {
        let mut rig = rig_rx(false, true).await?;
        rig.release.send(true)?;
        rig.app.write_all(&[9; 1024]).await?;
        let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_input.recv())
            .await?
            .unwrap();
        let ip = Ipv4Packet::new_checked(packet.as_ref())?;
        let tcp = TcpPacket::new_checked(ip.payload())?;
        ensure!(tcp.payload().len() == 1024, "fixture segmentation changed");
        let old = Arc::new(AtomicBool::new(true));
        let p = old.clone();
        let left = Arc::new(std::sync::atomic::AtomicU64::new(500));
        let left_read = left.clone();
        rig.handle.incoming(
            portion(&packet, 512, 512)?,
            SendPermit::bounded(
                move || p.load(Ordering::SeqCst),
                move || Some(Duration::from_millis(left_read.load(Ordering::SeqCst))),
            ),
        )?;
        // Fresh overlap cannot replace the original admission of the tail.
        rig.handle.incoming(
            packet.clone(),
            SendPermit::bounded(|| true, || Some(Duration::from_millis(900))),
        )?;
        let read =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        ensure!(
            rig.connection.owns_read(&read),
            "own native read lost origin binding"
        );
        let other = rig_rx(false, true).await?;
        ensure!(
            !other.connection.owns_read(&read),
            "same tuple on another stack adopted read"
        );
        cleanup(other).await?;
        ensure!(
            read.len() == 1024 && !read.eof(),
            "actual reassembly length mismatch"
        );
        let origin = read.admission();
        ensure!(
            origin.remaining() == Some(Duration::from_millis(500)),
            "native RX lost earliest original bound"
        );
        left.store(35, Ordering::SeqCst);
        ensure!(
            origin.remaining() == Some(Duration::from_millis(35)),
            "native RX reset original bound"
        );
        let (entered, waiting) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let delivered = Arc::new(AtomicBool::new(false));
        let copied = delivered.clone();
        let task = tokio::spawn(async move {
            read.deliver(move |bytes, _| async move {
                let _ = entered.send(());
                let _ = resume.await;
                ensure!(
                    bytes.as_ref() == [9; 1024],
                    "native reassembly data mismatch"
                );
                copied.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
        });
        waiting.await?;
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        old.store(false, Ordering::SeqCst);
        let _ = release.send(());
        ensure!(
            task.await?.is_err(),
            "fresh control relabeled buffered receive bytes"
        );
        ensure!(
            !delivered.load(Ordering::SeqCst),
            "retired native bytes delivered"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn real_tcp_payload_and_fin_have_original_delivery_and_owner() -> Result<()> {
        let mut rig = rig_rx(false, true).await?;
        rig.release.send(true)?;
        rig.app.write_all(&[4; 1024]).await?;
        let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_input.recv())
            .await?
            .unwrap();
        rig.handle.incoming(packet, SendPermit::new(|| true))?;
        let read =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        read.deliver(|bytes, eof| async move {
            ensure!(!eof && bytes.as_ref() == [4; 1024], "native bytes changed");
            Ok(())
        })
        .await?;
        rig.app.shutdown().await?;
        let fin = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let p = rig.held_input.recv().await.unwrap();
                let ip = Ipv4Packet::new_checked(p.as_ref()).unwrap();
                let t = TcpPacket::new_checked(ip.payload()).unwrap();
                if t.fin() {
                    break p;
                }
            }
        })
        .await?;
        let valid = Arc::new(AtomicBool::new(true));
        let p = valid.clone();
        rig.handle
            .incoming(fin, SendPermit::new(move || p.load(Ordering::SeqCst)))?;
        let eof =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        ensure!(eof.eof() && eof.is_empty(), "FIN was not ordered EOF");
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        valid.store(false, Ordering::SeqCst);
        ensure!(
            eof.deliver::<(), _>(|_, _| async { anyhow::bail!("expired FIN delivered") })
                .await
                .is_err(),
            "expired FIN admitted"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn accepting_two_native_syns_pins_each_remote_before_next_listener() -> Result<()> {
        let (_, _, mut runner) = stack()?;
        let (native, mut packets, native_runner) = super::super::stack()?;
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(async move { native_runner.run(stop).await });
        let mut clients = Vec::new();
        let mut waiters = Vec::new();
        for port in [5101, 5102] {
            let flow = Flow {
                source: format!("10.234.248.1:{port}").parse()?,
                destination: "10.234.248.2:443".parse()?,
            };
            let native = native.clone();
            clients.push(tokio::spawn(async move { native.connect(flow).await }));
            let syn = tokio::time::timeout(Duration::from_secs(1), packets.recv())
                .await?
                .unwrap();
            let (reply, wait) = oneshot::channel();
            waiters.push(wait);
            runner.create(
                flow.reverse(),
                SendPermit::new(|| true),
                reply,
                Arc::new(AtomicBool::new(true)),
                Some(syn),
                false,
            );
            let active = runner
                .flows
                .get(&flow.reverse())
                .ok_or_else(|| anyhow::anyhow!("native listener rejected owned SYN"))?;
            let remote = runner
                .sockets
                .get::<tcp::Socket>(active.socket)
                .remote_endpoint()
                .unwrap();
            ensure!(
                remote.addr == IpAddress::Ipv4(*flow.source.ip()) && remote.port == port,
                "native listener borrowed another admitted remote"
            );
        }
        ensure!(
            runner.flows.len() == 2,
            "listener alias replaced owned flow"
        );
        drop(runner);
        for c in clients {
            c.abort();
            let _ = c.await;
        }
        cancel.cancel();
        task.await??;
        Ok(())
    }
    #[tokio::test]
    async fn real_native_accept_source_reads_and_return_chunk_waits_for_tcp_ack() -> Result<()> {
        let (tagged, mut output, runner) = stack()?;
        let (native, mut input, native_runner) = super::super::stack()?;
        let cancel = CancellationToken::new();
        let a = cancel.clone();
        let b = cancel.clone();
        let first = tokio::spawn(async move { runner.run(a).await });
        let second = tokio::spawn(async move { native_runner.run(b).await });
        let flow = Flow {
            source: "10.234.249.1:5100".parse()?,
            destination: "10.234.249.2:443".parse()?,
        };
        let n = native.clone();
        let connecting = tokio::spawn(async move { n.connect(flow).await });
        let syn = tokio::time::timeout(Duration::from_secs(1), input.recv())
            .await?
            .unwrap();
        let h = tagged.clone();
        let accepting =
            tokio::spawn(async move { h.accept_syn(syn, SendPermit::new(|| true)).await });
        let synack = tokio::time::timeout(Duration::from_secs(1), output.recv())
            .await?
            .unwrap();
        let n = native.clone();
        synack.deliver(move |b| async move { n.packet(b) }).await?;
        let ack = tokio::time::timeout(Duration::from_secs(1), input.recv())
            .await?
            .unwrap();
        tagged.incoming(ack, SendPermit::new(|| true))?;
        let connection = Arc::new(accepting.await??);
        let mut app = connecting.await??;
        ensure!(
            connection.flow() == flow.reverse(),
            "native accepted tuple reversed incorrectly"
        );
        let h = tagged.clone();
        let n = native.clone();
        let stop = cancel.clone();
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _=stop.cancelled()=>return Ok::<_,anyhow::Error>(()),
                    packet=input.recv()=>{let Some(packet)=packet else{return Ok(())};h.incoming(packet,SendPermit::new(||true))?;},
                    packet=output.recv()=>{let Some(packet)=packet else{return Ok(())};let n=n.clone();packet.deliver(move|b|async move{n.packet(b)}).await?;}
                }
            }
        });
        app.write_all(&[5; 1024]).await?;
        let source =
            tokio::time::timeout(Duration::from_secs(1), connection.read_chunk()).await??;
        source
            .deliver(|b, eof| async move {
                ensure!(
                    !eof && b.as_ref() == [5; 1024],
                    "accepted native RX origin changed"
                );
                Ok(())
            })
            .await?;
        app.shutdown().await?;
        let eof = tokio::time::timeout(Duration::from_secs(1), connection.read_chunk()).await??;
        ensure!(eof.eof() && eof.is_empty(), "accepted native FIN lost");
        eof.deliver(|_, _| async { Ok(()) }).await?;
        let writer = connection.clone();
        let write = tokio::spawn(async move {
            writer
                .write_chunk(
                    [8; 16],
                    0,
                    Bytes::from(vec![6; 1024]),
                    SendPermit::new(|| true),
                )
                .await
        });
        let mut returned = [0; 1024];
        tokio::time::timeout(Duration::from_secs(1), app.read_exact(&mut returned)).await??;
        ensure!(returned == [6; 1024], "native return chunk changed");
        let ack = tokio::time::timeout(Duration::from_secs(1), write).await???;
        ensure!(
            connection.acknowledges(&ack, [8; 16], 0, 1024),
            "native source ACK binding lost"
        );
        cancel.cancel();
        first.await??;
        second.await??;
        pump.await??;
        ensure!(
            tagged.bindings.read().unwrap().is_empty(),
            "accepted tuple leaked"
        );
        ensure!(
            *tagged.budget.used.lock().unwrap() == 0,
            "accepted native credits leaked"
        );
        Ok(())
    }
    async fn native_eof(app: &mut tokio::io::DuplexStream) -> Result<()> {
        let mut byte = [0; 1];
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), app.read(&mut byte)).await?? == 0,
            "native FIN did not reach peer"
        );
        Ok(())
    }
    #[tokio::test]
    async fn native_fin_ack_waits_for_real_tcp_ack_and_preserves_response_half_close() -> Result<()>
    {
        let mut rig = rig(false).await?;
        let valid = Arc::new(AtomicBool::new(true));
        let original = valid.clone();
        let c = rig.connection.clone();
        let finishing = tokio::spawn(async move {
            c.finish(
                [11; 16],
                0,
                SendPermit::new(move || original.load(Ordering::SeqCst)),
            )
            .await
        });
        native_eof(&mut rig.app).await?;
        ensure!(
            !finishing.is_finished(),
            "FIN copy falsely proved native ACK"
        );
        rig.release.send(true)?;
        let ack = tokio::time::timeout(Duration::from_secs(1), finishing).await???;
        ensure!(
            rig.connection.acknowledges(&ack, [11; 16], 0, 0),
            "native FIN ACK not exact"
        );
        rig.connection
            .publish_receipt(ack, [11; 16], 0, 0, || async { Ok(()) })
            .await?;
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        valid.store(false, Ordering::SeqCst);
        rig.app.write_all(&[8; 64]).await?;
        let read =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        read.deliver(|b, eof| async move {
            ensure!(
                b.as_ref() == [8; 64] && !eof,
                "half-close lost response data"
            );
            Ok(())
        })
        .await?;
        rig.app.shutdown().await?;
        let eof =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        ensure!(eof.eof(), "local FIN prevented peer EOF");
        eof.deliver(|_, _| async { Ok(()) }).await?;
        cleanup(rig).await
    }
    #[tokio::test]
    async fn native_last_ack_closed_keeps_only_original_terminal_receipt_scope() -> Result<()> {
        let mut rig = rig_rx(false, true).await?;
        rig.app.shutdown().await?;
        let fin = tokio::time::timeout(Duration::from_secs(1), rig.held_input.recv())
            .await?
            .unwrap();
        rig.handle.incoming(fin, SendPermit::new(|| true))?;
        let eof =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        ensure!(eof.eof(), "peer half-close missing");
        eof.deliver(|_, _| async { Ok(()) }).await?;
        let valid = Arc::new(AtomicBool::new(true));
        let p = valid.clone();
        let c = rig.connection.clone();
        let finishing = tokio::spawn(async move {
            c.finish(
                [12; 16],
                0,
                SendPermit::new(move || p.load(Ordering::SeqCst)),
            )
            .await
        });
        native_eof(&mut rig.app).await?;
        ensure!(
            !finishing.is_finished(),
            "LastAck falsely completed before native ACK"
        );
        rig.release.send(true)?;
        let ack = tokio::time::timeout(Duration::from_secs(1), finishing).await???;
        ensure!(
            rig.connection.acknowledges(&ack, [12; 16], 0, 0),
            "clean Closed lost terminal ACK binding"
        );
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        let (entered, waiting) = oneshot::channel();
        let (release, resume) = oneshot::channel();
        let c = rig.connection.clone();
        let delivered = Arc::new(AtomicBool::new(false));
        let out = delivered.clone();
        let publishing = tokio::spawn(async move {
            c.publish_receipt(ack, [12; 16], 0, 0, || async move {
                let _ = entered.send(());
                let _ = resume.await;
                out.store(true, Ordering::SeqCst);
                Ok(())
            })
            .await
        });
        waiting.await?;
        valid.store(false, Ordering::SeqCst);
        let _ = release.send(());
        ensure!(
            publishing.await?.is_err() && !delivered.load(Ordering::SeqCst),
            "delayed terminal receipt borrowed new control"
        );
        ensure!(
            !rig.connection.alive.load(Ordering::SeqCst),
            "abandoned terminal scope stayed live"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn native_pending_fin_original_expiry_is_not_renewed_by_control_or_late_ack() -> Result<()>
    {
        let mut rig = rig(false).await?;
        let valid = Arc::new(AtomicBool::new(true));
        let p = valid.clone();
        let c = rig.connection.clone();
        let finishing = tokio::spawn(async move {
            c.finish(
                [14; 16],
                0,
                SendPermit::new(move || p.load(Ordering::SeqCst)),
            )
            .await
        });
        native_eof(&mut rig.app).await?;
        ensure!(!finishing.is_finished(), "native FIN lacked withheld ACK");
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        valid.store(false, Ordering::SeqCst);
        rig.release.send(true)?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), finishing)
                .await??
                .is_err(),
            "expired FIN accepted late ACK under fresh control"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn actual_native_rst_is_not_a_fin_ack() -> Result<()> {
        let mut rig = rig_rx(false, true).await?;
        let c = rig.connection.clone();
        let finishing =
            tokio::spawn(async move { c.finish([13; 16], 0, SendPermit::new(|| true)).await });
        native_eof(&mut rig.app).await?;
        rig.native.close(rig.connection.flow()).await?;
        let rst = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let p = rig
                    .held_input
                    .recv()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("native RST stream ended"))?;
                let ip = Ipv4Packet::new_checked(p.as_ref())?;
                let tcp = TcpPacket::new_checked(ip.payload())?;
                if tcp.rst() {
                    return Ok::<_, anyhow::Error>(p);
                }
            }
        })
        .await??;
        rig.handle.incoming(rst, SendPermit::new(|| true))?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), finishing)
                .await??
                .is_err(),
            "native RST fabricated FIN ACK"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn abandoning_actual_data_ack_receipt_retires_its_native_owner() -> Result<()> {
        let mut rig = rig(false).await?;
        rig.release.send(true)?;
        let c = rig.connection.clone();
        let writing = tokio::spawn(async move {
            c.write_chunk(
                [15; 16],
                0,
                Bytes::from(vec![2; 1024]),
                SendPermit::new(|| true),
            )
            .await
        });
        let mut bytes = [0; 1024];
        tokio::time::timeout(Duration::from_secs(1), rig.app.read_exact(&mut bytes)).await??;
        let ack = tokio::time::timeout(Duration::from_secs(1), writing).await???;
        let c = rig.connection.clone();
        let (entered, waiting) = oneshot::channel();
        let publishing = tokio::spawn(async move {
            c.publish_receipt(ack, [15; 16], 0, 1024, || async move {
                let _ = entered.send(());
                std::future::pending::<Result<()>>().await
            })
            .await
        });
        waiting.await?;
        publishing.abort();
        let _ = publishing.await;
        ensure!(
            !rig.connection.alive.load(Ordering::SeqCst),
            "cancelled DATA receipt left native owner live"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn completed_native_ack_cannot_authorize_delayed_receipt_after_original_expiry(
    ) -> Result<()> {
        let mut rig = rig(false).await?;
        rig.release.send(true)?;
        let valid = Arc::new(AtomicBool::new(true));
        let origin = valid.clone();
        let c = rig.connection.clone();
        let writing = tokio::spawn(async move {
            c.write_chunk(
                [9; 16],
                0,
                Bytes::from(vec![2; 1024]),
                SendPermit::new(move || origin.load(Ordering::SeqCst)),
            )
            .await
        });
        let mut bytes = [0; 1024];
        tokio::time::timeout(Duration::from_secs(1), rig.app.read_exact(&mut bytes)).await??;
        let ack = tokio::time::timeout(Duration::from_secs(1), writing).await???;
        ensure!(
            rig.connection.acknowledges(&ack, [9; 16], 0, 1024),
            "fresh actual native ACK not recognized"
        );
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        valid.store(false, Ordering::SeqCst);
        ensure!(
            !rig.connection.acknowledges(&ack, [9; 16], 0, 1024),
            "late ACK receipt borrowed fresh grant"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn retired_actual_native_read_never_invokes_byte_callback() -> Result<()> {
        let mut rig = rig_rx(false, true).await?;
        rig.release.send(true)?;
        rig.app.write_all(&[3; 1024]).await?;
        let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_input.recv())
            .await?
            .unwrap();
        rig.handle.incoming(packet, SendPermit::new(|| true))?;
        let read =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        ensure!(read.len() == 1024, "fixture RX length changed");
        let original = read.admission();
        ensure!(
            original.remaining().is_none(),
            "unknown native origin silently gained lifetime"
        );
        rig.connection.retire();
        let invoked = Arc::new(AtomicBool::new(false));
        let observed = invoked.clone();
        ensure!(
            read.deliver(move |_, _| {
                observed.store(true, Ordering::SeqCst);
                async { Ok(()) }
            })
            .await
            .is_err()
                && !invoked.load(Ordering::SeqCst),
            "retired RX bytes reached synchronous callback constructor"
        );
        ensure!(
            !rig.connection.alive.load(Ordering::SeqCst) && !original.valid(),
            "abandoned RX lost owner fence"
        );
        ensure!(
            *rig.handle.budget.used.lock().unwrap() == 0,
            "abandoned read leaked payload credit"
        );
        ensure!(
            rig.connection.read_chunk().await.is_err(),
            "retired source read again"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn dropping_actual_native_read_still_retires_without_callback() -> Result<()> {
        let mut rig = rig_rx(false, true).await?;
        rig.release.send(true)?;
        rig.app.write_all(&[3; 1024]).await?;
        let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_input.recv())
            .await?
            .unwrap();
        rig.handle.incoming(packet, SendPermit::new(|| true))?;
        let read =
            tokio::time::timeout(Duration::from_secs(1), rig.connection.read_chunk()).await??;
        drop(read);
        ensure!(
            !rig.connection.alive.load(Ordering::SeqCst),
            "abandoned read did not retire original native owner"
        );
        cleanup(rig).await
    }
    #[test]
    fn queued_native_input_keeps_original_admission_and_owner_after_control_changes() {
        let mut packets = Packets::default();
        let valid = Arc::new(AtomicBool::new(true));
        let old = valid.clone();
        packets.input.push_back(Input {
            bytes: Bytes::from(vec![0; 40]),
            permit: SendPermit::new(move || old.load(Ordering::SeqCst)),
            alive: Arc::new(AtomicBool::new(true)),
            rx: None,
            reset: None,
            replies: Default::default(),
        });
        valid.store(false, Ordering::SeqCst);
        assert!(packets.receive(StackInstant::from_millis(0)).is_none());
        assert!(packets.input.is_empty());
        let old_owner = Arc::new(AtomicBool::new(true));
        packets.input.push_back(Input {
            bytes: Bytes::from(vec![0; 40]),
            permit: SendPermit::new(|| true),
            alive: old_owner.clone(),
            rx: None,
            reset: None,
            replies: Default::default(),
        });
        old_owner.store(false, Ordering::SeqCst);
        let replacement = Arc::new(AtomicBool::new(true));
        assert!(replacement.load(Ordering::SeqCst));
        assert!(packets.receive(StackInstant::from_millis(0)).is_none());
        assert!(packets.input.is_empty());
    }
    #[tokio::test]
    async fn real_tcp_ack_not_just_copy_into_socket_completes_chunk() -> Result<()> {
        let mut rig = rig(false).await?;
        let connection = rig.connection.clone();
        let writing = tokio::spawn(async move {
            connection
                .write_chunk(
                    [1; 16],
                    0,
                    Bytes::from(vec![3; 1024]),
                    SendPermit::new(|| true),
                )
                .await
        });
        let mut bytes = vec![0; 1024];
        tokio::time::timeout(Duration::from_secs(1), rig.app.read_exact(&mut bytes)).await??;
        ensure!(bytes.iter().all(|b| *b == 3), "native payload changed");
        tokio::time::timeout(Duration::from_secs(1), async {
            while rig.held_acks.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        ensure!(
            !writing.is_finished(),
            "copy to native peer falsely counted as ACK"
        );
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        rig.release.send(true)?;
        let ack = tokio::time::timeout(Duration::from_secs(1), writing).await???;
        ensure!(
            rig.connection.acknowledges(&ack, [1; 16], 0, 1024),
            "ACK identity mismatch"
        );
        let other = self::rig(false).await?;
        ensure!(
            !other.connection.acknowledges(&ack, [1; 16], 0, 1024),
            "foreign stack/registration adopted native receipt"
        );
        rig.connection.retire();
        ensure!(
            !rig.connection.acknowledges(&ack, [1; 16], 0, 1024),
            "retired native owner reused past receipt"
        );
        cleanup(other).await?;
        cleanup(rig).await
    }
    #[tokio::test]
    async fn delayed_real_native_ack_with_fresh_control_cannot_extend_old_chunk() -> Result<()> {
        let mut rig = rig(false).await?;
        let valid = Arc::new(AtomicBool::new(true));
        let origin = valid.clone();
        let connection = rig.connection.clone();
        let writing = tokio::spawn(async move {
            connection
                .write_chunk(
                    [2; 16],
                    0,
                    Bytes::from(vec![3; 1024]),
                    SendPermit::new(move || origin.load(Ordering::SeqCst)),
                )
                .await
        });
        let mut bytes = vec![0; 1024];
        tokio::time::timeout(Duration::from_secs(1), rig.app.read_exact(&mut bytes)).await??;
        tokio::time::timeout(Duration::from_secs(1), async {
            while rig.held_acks.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        ensure!(!writing.is_finished(), "withheld ACK falsely completed");
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        valid.store(false, Ordering::SeqCst);
        rig.release.send(true)?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), writing)
                .await??
                .is_err(),
            "late ACK borrowed fresh control grant"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn bounded_native_queue_busy_is_not_revocation_or_false_ack() -> Result<()> {
        let mut rig = rig(false).await?;
        let first = rig.connection.clone();
        let first = tokio::spawn(async move {
            first
                .write_chunk(
                    [5; 16],
                    0,
                    Bytes::from(vec![3; 1024]),
                    SendPermit::new(|| true),
                )
                .await
        });
        let mut bytes = [0; 1024];
        tokio::time::timeout(Duration::from_secs(1), rig.app.read_exact(&mut bytes)).await??;
        let second = rig.connection.clone();
        let second = tokio::spawn(async move {
            second
                .write_chunk(
                    [6; 16],
                    1024,
                    Bytes::from(vec![3; 1024]),
                    SendPermit::new(|| true),
                )
                .await
        });
        tokio::task::yield_now().await;
        let busy = tokio::time::timeout(
            Duration::from_secs(1),
            rig.connection.write_chunk(
                [7; 16],
                2048,
                Bytes::from(vec![3; 1024]),
                SendPermit::new(|| true),
            ),
        )
        .await?;
        match busy {
            Err(error) => ensure!(
                error.downcast_ref::<AdmissionError>() == Some(&AdmissionError::Busy),
                "quota error misclassified"
            ),
            Ok(_) => anyhow::bail!("excess chunk falsely acknowledged"),
        }
        ensure!(
            rig.connection.alive.load(Ordering::SeqCst) && !first.is_finished(),
            "busy admission revoked prior work"
        );
        rig.release.send(true)?;
        let a = tokio::time::timeout(Duration::from_secs(1), first).await???;
        let b = tokio::time::timeout(Duration::from_secs(1), second).await???;
        ensure!(
            rig.connection.acknowledges(&a, [5; 16], 0, 1024)
                && rig.connection.acknowledges(&b, [6; 16], 1024, 1024),
            "queued receipt identity changed"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn actual_tcp_retransmission_keeps_old_origin_after_fresh_control() -> Result<()> {
        let mut rig = rig(true).await?;
        let valid = Arc::new(AtomicBool::new(true));
        let old = valid.clone();
        let connection = rig.connection.clone();
        let writing = tokio::spawn(async move {
            connection
                .write_chunk(
                    [8; 16],
                    0,
                    Bytes::from(vec![3; 1024]),
                    SendPermit::new(move || old.load(Ordering::SeqCst)),
                )
                .await
        });
        let first = tokio::time::timeout(Duration::from_secs(1), rig.held_packets.recv())
            .await?
            .unwrap();
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        // Pinned smoltcp0.14 RFC6298 minimum/initial RTO is 1000ms.
        let retry = tokio::time::timeout(Duration::from_secs(3), rig.held_packets.recv())
            .await?
            .unwrap();
        let first_ip = Ipv4Packet::new_checked(first.bytes())?;
        let first_tcp = TcpPacket::new_checked(first_ip.payload())?;
        let retry_ip = Ipv4Packet::new_checked(retry.bytes())?;
        let retry_tcp = TcpPacket::new_checked(retry_ip.payload())?;
        ensure!(
            first_tcp.seq_number() == retry_tcp.seq_number()
                && first_tcp.payload() == retry_tcp.payload(),
            "expected actual TCP retransmission"
        );
        valid.store(false, Ordering::SeqCst);
        let native = rig.native.clone();
        ensure!(
            retry
                .deliver(move |bytes| async move { native.packet(bytes) })
                .await
                .is_err(),
            "TCP retry borrowed fresh control origin"
        );
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), writing)
                .await??
                .is_err(),
            "retired retransmission falsely acknowledged"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn abandoned_native_chunk_synchronously_retires_queued_delivery() -> Result<()> {
        let mut rig = rig(true).await?;
        let connection = rig.connection.clone();
        let writing = tokio::spawn(async move {
            connection
                .write_chunk(
                    [4; 16],
                    0,
                    Bytes::from(vec![3; CHUNK]),
                    SendPermit::new(|| true),
                )
                .await
        });
        let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_packets.recv())
            .await?
            .unwrap();
        writing.abort();
        let _ = writing.await;
        ensure!(
            !rig.connection.alive.load(Ordering::SeqCst),
            "abandoned native writer remained active"
        );
        let native = rig.native.clone();
        ensure!(
            packet
                .deliver(move |bytes| async move { native.packet(bytes) })
                .await
                .is_err(),
            "abandoned bytes reached native peer"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn queued_native_payload_keeps_origin_through_backpressure_and_control_renewal(
    ) -> Result<()> {
        let mut rig = rig(true).await?;
        let valid = Arc::new(AtomicBool::new(true));
        let original = valid.clone();
        let connection = rig.connection.clone();
        let writing = tokio::spawn(async move {
            connection
                .write_chunk(
                    [3; 16],
                    0,
                    Bytes::from(vec![3; CHUNK]),
                    SendPermit::new(move || original.load(Ordering::SeqCst)),
                )
                .await
        });
        let packet = tokio::time::timeout(Duration::from_secs(1), rig.held_packets.recv())
            .await?
            .unwrap();
        let (entered, wait) = oneshot::channel();
        let (release, blocked) = oneshot::channel();
        let native = rig.native.clone();
        let delivered = rig.delivered.clone();
        let delivery = tokio::spawn(async move {
            packet
                .deliver(move |bytes| async move {
                    let _ = entered.send(());
                    let _ = blocked.await;
                    native.packet(bytes)?;
                    delivered.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
        });
        wait.await?;
        rig.connection
            .renew_control(SendPermit::new(|| true))
            .await?;
        valid.store(false, Ordering::SeqCst);
        let _ = release.send(());
        ensure!(
            delivery.await?.is_err(),
            "blocked native delivery used fresh control permit"
        );
        ensure!(
            rig.delivered.load(Ordering::SeqCst) == 0,
            "retired bytes reached native peer"
        );
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), writing)
                .await??
                .is_err(),
            "unacknowledged bytes got receipt"
        );
        cleanup(rig).await
    }
    #[tokio::test]
    async fn actual_pending_handshake_ingress_and_delayed_establishment_cannot_renew_or_adopt_replacement(
    ) -> Result<()> {
        use std::sync::atomic::AtomicU64;
        let (handle, mut output, runner) = stack()?;
        let (peer, mut input, peer_runner) = super::super::stack()?;
        let stop = CancellationToken::new();
        let a = tokio::spawn(runner.run(stop.clone()));
        let b = tokio::spawn(peer_runner.run(stop.clone()));
        let clock = Arc::new(AtomicU64::new(0));
        let expiry = clock.clone();
        let original = SendPermit::bounded(
            || true,
            move || {
                Duration::from_secs(15)
                    .checked_sub(Duration::from_millis(expiry.load(Ordering::SeqCst)))
                    .filter(|n| !n.is_zero())
            },
        );
        let fresh = || SendPermit::bounded(|| true, || Some(Duration::from_secs(15)));
        let flow = Flow {
            source: "10.234.244.1:42000".parse()?,
            destination: "10.234.244.2:443".parse()?,
        };
        let pending = handle.prepare_connect(flow, original).await?;
        let old = pending.ingress();
        let syn = tokio::time::timeout(Duration::from_secs(1), output.recv())
            .await?
            .unwrap();
        let origin_packet = syn.clone();
        let other = peer.clone();
        let accepting = tokio::spawn(async move {
            syn.deliver(|bytes| async move { other.accept_syn(bytes).await })
                .await
        });
        let synack = tokio::time::timeout(Duration::from_secs(1), input.recv())
            .await?
            .unwrap();
        old.input(synack.clone(), fresh())?;
        let ack = tokio::time::timeout(Duration::from_secs(1), output.recv())
            .await?
            .unwrap();
        let other = peer.clone();
        ack.deliver(|bytes| async move { other.packet(bytes) })
            .await?;
        let _app = accepting.await??;
        // Receiving the actual final ACK proves the TCP handshake progressed;
        // publication is intentionally delayed until the original bound expires.
        let short_clock = clock.clone();
        let shortened = origin_packet.intersect(SendPermit::bounded(
            || true,
            move || {
                Duration::from_secs(5)
                    .checked_sub(Duration::from_millis(short_clock.load(Ordering::SeqCst)))
                    .filter(|n| !n.is_zero())
            },
        ));
        clock.store(5000, Ordering::SeqCst);
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = called.clone();
        ensure!(
            shortened
                .deliver(|_| {
                    seen.store(true, Ordering::SeqCst);
                    async { Ok::<_, anyhow::Error>(()) }
                })
                .await
                .is_err()
                && !called.load(Ordering::SeqCst),
            "queued output ignored independent current-at-issue deadline"
        );
        ensure!(
            origin_packet.valid(),
            "retiring a narrowed queued control record destroyed still-valid original owner"
        );
        clock.store(15000, Ordering::SeqCst);
        ensure!(
            pending.established().await.is_err(),
            "queued established result acquired a fresh publication lifetime"
        );
        ensure!(
            !old.valid() && old.input(synack.clone(), fresh()).is_err(),
            "retired opening ingress borrowed fresh caller authority"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !handle
                    .bindings
                    .read()
                    .unwrap()
                    .contains_key(&flow.reverse())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let replacement = handle.prepare_connect(flow, fresh()).await?;
        let new = replacement.ingress();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if handle
                    .bindings
                    .read()
                    .unwrap()
                    .get(&flow.reverse())
                    .is_some_and(|binding| Arc::ptr_eq(&binding.alive, &new.alive))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        ensure!(
            new.valid() && old.flow() == new.flow() && !Arc::ptr_eq(&old.alive, &new.alive),
            "replacement did not receive distinct immutable generation"
        );
        ensure!(
            old.input(synack, fresh()).is_err(),
            "same-tuple replacement adopted stale ingress callback"
        );
        drop(replacement);
        ensure!(!new.valid(), "abandoned pending native owner remained live");
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(1), a).await???;
        tokio::time::timeout(Duration::from_secs(1), b).await???;
        Ok(())
    }
}
