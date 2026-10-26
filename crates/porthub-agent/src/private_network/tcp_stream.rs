//! Portable TCP termination beside the local kernel. The caller owns peer
//! authentication, port grants and transport selection; this module owns only
//! explicitly admitted TCP tuples and never opens a host network socket.
use anyhow::{ensure, Result};
use bytes::Bytes;
use smoltcp::{
    iface::{Config, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp,
    time::Instant as StackInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, TcpPacket},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::{poll_fn, Future},
    net::{Ipv4Addr, SocketAddrV4},
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{mpsc, oneshot},
    time::Sleep,
};
use tokio_util::{sync::CancellationToken, sync::PollSender};

const MTU: usize = 1380;
const MAX_FLOWS: usize = 512;
const PACKET_QUEUE: usize = 256;
// Each virtual TCP leg feeds a QUIC stream whose RTT may be tens of
// milliseconds, while the local TUN peer sees a sub-millisecond RTT. Keep a
// larger receive window so that the synthetic TCP ACKs do not throttle the
// WAN stream to a small per-flow buffer. The send side stays modest because
// the bounded duplex pipe and QUIC stream already provide backpressure.
const TCP_RECEIVE_BUFFER: usize = 524288;
const TCP_SEND_BUFFER: usize = 131072;
const PIPE_BUFFER: usize = 16384;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Flow {
    pub source: SocketAddrV4,
    pub destination: SocketAddrV4,
}
impl Flow {
    pub fn from_packet(bytes: &[u8]) -> Option<Self> {
        let ip = Ipv4Packet::new_checked(bytes).ok()?;
        if ip.next_header() != IpProtocol::Tcp || ip.total_len() as usize != bytes.len() {
            return None;
        }
        let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
        Some(Self {
            source: SocketAddrV4::new(ip.src_addr(), tcp.src_port()),
            destination: SocketAddrV4::new(ip.dst_addr(), tcp.dst_port()),
        })
    }
    pub fn reverse(self) -> Self {
        Self {
            source: self.destination,
            destination: self.source,
        }
    }
    fn validate(self) -> Result<()> {
        ensure!(
            self.source.ip().is_private()
                && self.destination.ip().is_private()
                && self.source.ip() != self.destination.ip()
                && self.source.port() != 0
                && self.destination.port() != 0,
            "invalid private TCP tuple"
        );
        Ok(())
    }
}

type Connected = oneshot::Sender<Result<DuplexStream>>;
enum Command {
    Accept {
        flow: Flow,
        syn: Bytes,
        connected: Connected,
    },
    Connect {
        flow: Flow,
        connected: Connected,
    },
    Packet(Bytes),
    Close(Flow),
}
#[derive(Clone)]
pub struct Handle {
    commands: mpsc::Sender<Command>,
    active: Arc<RwLock<HashSet<Flow>>>,
}
impl Handle {
    pub fn owns(&self, flow: Flow) -> bool {
        self.active
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&flow)
    }
    pub async fn accept_syn(&self, syn: Bytes) -> Result<(Flow, DuplexStream)> {
        let flow =
            Flow::from_packet(&syn).ok_or_else(|| anyhow::anyhow!("invalid private TCP SYN"))?;
        flow.validate()?;
        let ip = Ipv4Packet::new_checked(syn.as_ref())?;
        let tcp = TcpPacket::new_checked(ip.payload())?;
        ensure!(
            syn.len() <= MTU && tcp.syn() && !tcp.ack() && !tcp.rst(),
            "invalid private TCP SYN"
        );
        let (connected, waiting) = oneshot::channel();
        self.commands
            .send(Command::Accept {
                flow,
                syn,
                connected,
            })
            .await
            .map_err(|_| anyhow::anyhow!("private TCP adapter stopped"))?;
        Ok((
            flow,
            waiting
                .await
                .map_err(|_| anyhow::anyhow!("private TCP adapter stopped"))??,
        ))
    }
    pub async fn connect(&self, flow: Flow) -> Result<DuplexStream> {
        flow.validate()?;
        let (connected, waiting) = oneshot::channel();
        self.commands
            .send(Command::Connect { flow, connected })
            .await
            .map_err(|_| anyhow::anyhow!("private TCP adapter stopped"))?;
        waiting
            .await
            .map_err(|_| anyhow::anyhow!("private TCP adapter stopped"))?
    }
    pub fn packet(&self, packet: Bytes) -> Result<()> {
        ensure!(packet.len() <= MTU, "private TCP packet exceeds MTU");
        self.commands
            .try_send(Command::Packet(packet))
            .map_err(|_| anyhow::anyhow!("private TCP packet queue unavailable"))
    }
    pub async fn close(&self, flow: Flow) -> Result<()> {
        self.commands
            .send(Command::Close(flow))
            .await
            .map_err(|_| anyhow::anyhow!("private TCP adapter stopped"))
    }
}

pub fn reject_syn(syn: &[u8]) -> Result<Bytes> {
    let flow = Flow::from_packet(syn).ok_or_else(|| anyhow::anyhow!("invalid private TCP SYN"))?;
    flow.validate()?;
    let original = Ipv4Packet::new_checked(syn)?;
    let tcp = TcpPacket::new_checked(original.payload())?;
    ensure!(
        original.verify_checksum()
            && tcp.syn()
            && !tcp.ack()
            && !tcp.rst()
            && tcp.verify_checksum(
                &IpAddress::Ipv4(*flow.source.ip()),
                &IpAddress::Ipv4(*flow.destination.ip())
            ),
        "invalid private TCP SYN"
    );
    let acknowledgement = tcp.seq_number() + tcp.segment_len();
    let mut bytes = vec![0; 40];
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..20]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(*flow.destination.ip());
        ip.set_dst_addr(*flow.source.ip());
        ip.fill_checksum();
    }
    {
        let mut tcp = TcpPacket::new_unchecked(&mut bytes[20..]);
        tcp.set_src_port(flow.destination.port());
        tcp.set_dst_port(flow.source.port());
        tcp.set_header_len(20);
        tcp.set_rst(true);
        tcp.set_ack(true);
        tcp.set_ack_number(acknowledgement);
        tcp.fill_checksum(
            &IpAddress::Ipv4(*flow.destination.ip()),
            &IpAddress::Ipv4(*flow.source.ip()),
        );
    }
    Ok(bytes.into())
}

#[derive(Default)]
struct PacketDevice {
    input: VecDeque<Bytes>,
    output: VecDeque<Bytes>,
}
struct Receive(Bytes);
struct Transmit<'a>(&'a mut VecDeque<Bytes>);
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet.into());
        result
    }
}
impl Device for PacketDevice {
    type RxToken<'a> = Receive;
    type TxToken<'a> = Transmit<'a>;
    fn receive(&mut self, _: StackInstant) -> Option<(Receive, Transmit<'_>)> {
        if self.output.len() >= PACKET_QUEUE {
            return None;
        }
        Some((Receive(self.input.pop_front()?), Transmit(&mut self.output)))
    }
    fn transmit(&mut self, _: StackInstant) -> Option<Transmit<'_>> {
        (self.output.len() < PACKET_QUEUE).then_some(Transmit(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = MTU;
        caps
    }
}

struct Active {
    handle: SocketHandle,
    incoming: Flow,
    pipe: DuplexStream,
    application: Option<DuplexStream>,
    connected: Option<Connected>,
    deadline: Instant,
    eof: bool,
    read_closed: bool,
}
pub struct Runner {
    commands: mpsc::Receiver<Command>,
    output: PollSender<Bytes>,
    device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<Flow, Active>,
    incoming: HashMap<Flow, Flow>,
    origin: Instant,
    active: Arc<RwLock<HashSet<Flow>>>,
}
pub fn stack() -> Result<(Handle, mpsc::Receiver<Bytes>, Runner)> {
    let (commands, input) = mpsc::channel(PACKET_QUEUE);
    let (output, packets) = mpsc::channel(PACKET_QUEUE);
    let active = Arc::new(RwLock::new(HashSet::new()));
    let mut device = PacketDevice::default();
    let mut config = Config::new(HardwareAddress::Ip);
    let mut seed = [0; 8];
    getrandom::fill(&mut seed)
        .map_err(|_| anyhow::anyhow!("private TCP randomness unavailable"))?;
    config.random_seed = u64::from_ne_bytes(seed);
    let mut interface = Interface::new(config, &mut device, StackInstant::from_millis(0));
    let virtual_router = Ipv4Addr::new(10, 255, 255, 254);
    interface.update_ip_addrs(|addresses| {
        addresses
            .push(IpCidr::new(IpAddress::Ipv4(virtual_router), 32))
            .unwrap();
    });
    interface
        .routes_mut()
        .add_default_ipv4_route(virtual_router)?;
    interface.set_any_ip(true);
    Ok((
        Handle {
            commands,
            active: active.clone(),
        },
        packets,
        Runner {
            commands: input,
            output: PollSender::new(output),
            device,
            interface,
            sockets: SocketSet::new(Vec::new()),
            flows: HashMap::new(),
            incoming: HashMap::new(),
            origin: Instant::now(),
            active,
        },
    ))
}
impl Runner {
    fn now(&self) -> StackInstant {
        StackInstant::from_millis(self.origin.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }
    fn create(&mut self, flow: Flow, syn: Option<Bytes>, connected: Connected) {
        if self.flows.len() >= MAX_FLOWS || self.flows.contains_key(&flow) {
            let _ = connected.send(Err(anyhow::anyhow!("private TCP flow unavailable")));
            return;
        }
        let incoming = if syn.is_some() { flow } else { flow.reverse() };
        if self.incoming.contains_key(&incoming) {
            let _ = connected.send(Err(anyhow::anyhow!("private TCP tuple already owned")));
            return;
        }
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RECEIVE_BUFFER]),
            tcp::SocketBuffer::new(vec![0; TCP_SEND_BUFFER]),
        );
        // This TCP leg stays on the local TUN. Match a stream proxy's
        // TCP_NODELAY behavior; delayed local ACKs must not pace WAN data.
        socket.set_nagle_enabled(false);
        socket.set_ack_delay(None);
        let endpoint = |address: SocketAddrV4| (IpAddress::Ipv4(*address.ip()), address.port());
        let configured = if syn.is_some() {
            socket.listen(endpoint(flow.destination)).map_err(|_| ())
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
            let _ = connected.send(Err(anyhow::anyhow!("private TCP endpoint unavailable")));
            return;
        }
        let handle = self.sockets.add(socket);
        if let Some(syn) = syn {
            // Bind this listener to its admitted remote tuple before another
            // listener for the same service can be created.
            self.device.input.push_back(syn);
            self.interface
                .poll(self.now(), &mut self.device, &mut self.sockets);
            let socket = self.sockets.get::<tcp::Socket>(handle);
            if socket.remote_endpoint().is_none_or(|remote| {
                remote.addr != endpoint(flow.source).0 || remote.port != flow.source.port()
            }) {
                self.sockets.remove(handle);
                let _ = connected.send(Err(anyhow::anyhow!("private TCP SYN was rejected")));
                return;
            }
        }
        let (pipe, application) = tokio::io::duplex(PIPE_BUFFER);
        self.incoming.insert(incoming, flow);
        self.active
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .insert(flow);
        self.flows.insert(
            flow,
            Active {
                handle,
                incoming,
                pipe,
                application: Some(application),
                connected: Some(connected),
                deadline: Instant::now() + CONNECT_TIMEOUT,
                eof: false,
                read_closed: false,
            },
        );
    }
    fn poll(&mut self, cx: &mut Context<'_>, timer: &mut Pin<Box<Sleep>>) -> Poll<Result<bool>> {
        let mut progress = false;
        for _ in 0..64 {
            match self.commands.poll_recv(cx) {
                Poll::Ready(Some(command)) => {
                    progress = true;
                    match command {
                        Command::Accept {
                            flow,
                            syn,
                            connected,
                        } => self.create(flow, Some(syn), connected),
                        Command::Connect { flow, connected } => self.create(flow, None, connected),
                        Command::Packet(packet) => {
                            if Flow::from_packet(&packet)
                                .is_some_and(|tuple| self.incoming.contains_key(&tuple))
                            {
                                self.device.input.push_back(packet);
                            }
                        }
                        Command::Close(flow) => {
                            if let Some(active) = self.flows.get(&flow) {
                                self.sockets.get_mut::<tcp::Socket>(active.handle).abort();
                            }
                        }
                    }
                }
                Poll::Ready(None) => return Poll::Ready(Ok(false)),
                Poll::Pending => break,
            }
        }
        let now = self.now();
        progress |= self
            .interface
            .poll(now, &mut self.device, &mut self.sockets)
            != PollResult::None;
        let mut closed = Vec::new();
        for (flow, active) in &mut self.flows {
            let socket = self.sockets.get_mut::<tcp::Socket>(active.handle);
            if active.connected.is_some()
                && (Instant::now() >= active.deadline
                    || active.connected.as_ref().is_some_and(Connected::is_closed))
            {
                socket.abort();
            }
            if socket.state() == tcp::State::Established {
                if let Some(connected) = active.connected.take() {
                    if connected
                        .send(Ok(active.application.take().unwrap()))
                        .is_err()
                    {
                        socket.abort();
                    }
                    progress = true;
                }
            }
            if socket.state() == tcp::State::Closed {
                closed.push(*flow);
                continue;
            }
            if socket.can_recv() {
                let result =
                    socket.recv(
                        |bytes| match Pin::new(&mut active.pipe).poll_write(cx, bytes) {
                            Poll::Ready(Ok(count)) => (count, Some(count)),
                            Poll::Ready(Err(_)) => (0, Some(0)),
                            Poll::Pending => (0, None),
                        },
                    );
                match result {
                    Ok(Some(0)) => socket.abort(),
                    Ok(Some(_)) => progress = true,
                    _ => {}
                }
            }
            if active.connected.is_none()
                && !socket.may_recv()
                && socket.recv_queue() == 0
                && !active.read_closed
                && Pin::new(&mut active.pipe).poll_shutdown(cx).is_ready()
            {
                active.read_closed = true;
                progress = true;
            }
            if socket.can_send() && !active.eof {
                let mut bytes = [0; 8192];
                let limit = bytes
                    .len()
                    .min(socket.send_capacity().saturating_sub(socket.send_queue()));
                let mut buffer = ReadBuf::new(&mut bytes[..limit]);
                match Pin::new(&mut active.pipe).poll_read(cx, &mut buffer) {
                    Poll::Ready(Ok(())) if buffer.filled().is_empty() => {
                        active.eof = true;
                        socket.close();
                        progress = true;
                    }
                    Poll::Ready(Ok(())) => {
                        let _ = socket.send_slice(buffer.filled());
                        progress = true;
                    }
                    Poll::Ready(Err(_)) => {
                        socket.abort();
                        progress = true;
                    }
                    Poll::Pending => {}
                }
            }
        }
        for flow in closed {
            if let Some(active) = self.flows.remove(&flow) {
                if let Some(connected) = active.connected {
                    let _ = connected.send(Err(anyhow::anyhow!("private TCP connection closed")));
                }
                self.incoming.remove(&active.incoming);
                self.active
                    .write()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(&flow);
                self.sockets.remove(active.handle);
                progress = true;
            }
        }
        while !self.device.output.is_empty() {
            match self.output.poll_reserve(cx) {
                Poll::Ready(Ok(())) => {
                    self.output
                        .send_item(self.device.output.pop_front().unwrap())
                        .map_err(|_| anyhow::anyhow!("private TCP packet consumer stopped"))?;
                    progress = true;
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(Err(anyhow::anyhow!("private TCP packet consumer stopped")))
                }
                Poll::Pending => break,
            }
        }
        if progress {
            return Poll::Ready(Ok(true));
        }
        let transport = self
            .interface
            .poll_at(now, &self.sockets)
            .map(|at| self.origin + Duration::from_millis(at.total_millis().max(0) as u64));
        let handshake = self
            .flows
            .values()
            .filter(|flow| flow.connected.is_some())
            .map(|flow| flow.deadline)
            .min();
        if let Some(deadline) = transport.into_iter().chain(handshake).min() {
            timer.as_mut().reset(tokio::time::Instant::from_std(
                deadline.max(Instant::now() + Duration::from_millis(1)),
            ));
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(true));
            }
        }
        Poll::Pending
    }
    pub async fn run(mut self, cancel: CancellationToken) -> Result<()> {
        let mut timer = Box::pin(tokio::time::sleep(Duration::from_secs(86400)));
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = poll_fn(|cx| self.poll(cx, &mut timer)) => if !result? { return Ok(()); },
            }
            tokio::task::yield_now().await;
        }
    }
}
impl Drop for Runner {
    fn drop(&mut self) {
        self.active
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }
}
