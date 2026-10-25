//! Tokio UDP ownership and bounded queues for the private protocol core.
use crate::relay::{Allocation, Socket};
use crate::{Description, Identity, Peer, State, MAX_PACKET};
use anyhow::{ensure, Result};
use bytes::{Bytes, BytesMut};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Default, Debug)]
pub struct Statistics {
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub dropped_outgoing: u64,
    pub dropped_incoming: u64,
    pub write_errors: u64,
    pub read_errors: u64,
}

enum Datagram {
    Packet(SocketAddr, SocketAddr, BytesMut),
    ReadError(SocketAddr, bool),
}
fn truncated_datagram(error: &turn_util::Error) -> bool {
    if matches!(error, turn_util::Error::ErrPacketTooBig) {
        return true;
    }
    // Winsock discards the excess of a UDP datagram and returns WSAEMSGSIZE
    // (10040), rather than a truncated successful receive as on Linux. This
    // consumes one bad packet; it does not mean that the socket has closed.
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
    #[cfg(windows)]
    if matches!(error, turn_util::Error::Io(error) if error.0.raw_os_error() == Some(10040)) {
        return true;
    }
    false
}
fn retry_read(error: &turn_util::Error) -> bool {
    use std::io::ErrorKind;
    match error {
        turn_util::Error::ErrTimeout | turn_util::Error::ErrPacketTooBig => true,
        turn_util::Error::Io(error) => matches!(
            error.0.kind(),
            ErrorKind::Interrupted
                | ErrorKind::WouldBlock
                | ErrorKind::TimedOut
                | ErrorKind::ConnectionRefused
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::NetworkDown
                | ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
                | ErrorKind::AddrNotAvailable
        ),
        _ => false,
    }
}
fn closed(error: &turn_util::Error) -> bool {
    matches!(
        error,
        turn_util::Error::ErrUseClosedNetworkConn
            | turn_util::Error::ErrBufferClosed
            | turn_util::Error::ErrAlreadyClosed
            | turn_util::Error::ErrClosedListener
            | turn_util::Error::ErrNoSuchUdpConn
    )
}
enum Command {
    Remote {
        actor: String,
        description: Description,
        reply: oneshot::Sender<Result<()>>,
    },
    Statistics(oneshot::Sender<Statistics>),
}
struct Lifetime {
    cancel: CancellationToken,
    task: Mutex<Option<JoinHandle<()>>>,
    _allocation: Option<Allocation>,
}
impl Drop for Lifetime {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.get_mut().expect("task mutex poisoned").take() {
            task.abort();
        }
    }
}
#[derive(Clone)]
pub struct Session {
    commands: mpsc::Sender<Command>,
    packets: mpsc::Sender<Bytes>,
    state: watch::Receiver<(State, bool)>,
    description: Description,
    lifetime: Arc<Lifetime>,
}
impl Session {
    /// The supplied address is an explicit underlay interface. Interface/STUN/
    /// TURN gathering and private control sync are owned by the higher layer.
    pub async fn bind(
        local: SocketAddr,
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        pin: &str,
    ) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        Self::bind_interfaces(&[local], local_id, remote_id, identity, pin).await
    }
    pub async fn bind_interfaces(
        locals: &[SocketAddr],
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        pin: &str,
    ) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        Self::bind_interfaces_with_relay(locals, local_id, remote_id, identity, pin, None).await
    }
    pub async fn bind_interfaces_with_relay(
        locals: &[SocketAddr],
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        pin: &str,
        allocation: Option<Allocation>,
    ) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        Self::gather(locals, local_id, remote_id, identity, pin, allocation, &[]).await
    }
    /// Host and STUN candidates share the same bound UDP sockets. Gathering is
    /// a bounded setup operation and finishes before any receive owner starts.
    pub async fn gather(
        locals: &[SocketAddr],
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        pin: &str,
        allocation: Option<Allocation>,
        stun_servers: &[String],
    ) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        ensure!(
            !locals.is_empty() && locals.len() <= 16,
            "invalid private interfaces"
        );
        let mut sockets = HashMap::new();
        let mut bound = Vec::new();
        let mut gathering = JoinSet::new();
        for local in locals {
            let socket = UdpSocket::bind(local)
                .await
                .map_err(|_| anyhow::anyhow!("private UDP bind failed"))?;
            let address = socket
                .local_addr()
                .map_err(|_| anyhow::anyhow!("private UDP address unavailable"))?;
            bound.push(address);
            let socket = Arc::new(socket);
            if !stun_servers.is_empty() {
                let socket = socket.clone();
                let servers = stun_servers.to_vec();
                gathering
                    .spawn(async move { (address, crate::stun::mapped(&socket, &servers).await) });
            }
            sockets.insert(address, socket as Socket);
        }
        let mut peer = Peer::new(Instant::now(), bound[0], local_id, remote_id, identity, pin)?;
        for address in &bound[1..] {
            peer.add_interface(*address)?;
        }
        while let Some(result) = gathering.join_next().await {
            if let Ok((base, Some(mapped))) = result {
                peer.add_reflexive(base, mapped)?;
            }
        }
        if let Some(allocation) = &allocation {
            let socket = allocation.socket();
            let address = socket
                .local_addr()
                .map_err(|_| anyhow::anyhow!("private relay address unavailable"))?;
            ensure!(
                !sockets.contains_key(&address),
                "private relay address conflicts with an interface"
            );
            peer.add_relay(address)?;
            sockets.insert(address, socket);
        }
        Self::start(sockets, peer, allocation)
    }
    /// Forces the encrypted peer protocol through one pre-authenticated TURN
    /// allocation. No UDP listener or plaintext gateway packet path is used.
    pub fn bind_relay(
        allocation: Allocation,
        local_id: &str,
        remote_id: &str,
        identity: Identity,
        pin: &str,
    ) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        let socket = allocation.socket();
        let address = socket
            .local_addr()
            .map_err(|_| anyhow::anyhow!("private relay address unavailable"))?;
        let peer = Peer::new_relay(Instant::now(), address, local_id, remote_id, identity, pin)?;
        Self::start(HashMap::from([(address, socket)]), peer, Some(allocation))
    }
    fn start(
        sockets: HashMap<SocketAddr, Socket>,
        peer: Peer,
        allocation: Option<Allocation>,
    ) -> Result<(Self, mpsc::Receiver<Bytes>)> {
        let description = peer.description();
        let (commands, command_rx) = mpsc::channel(64);
        let (packets, packet_rx) = mpsc::channel(2048);
        let (received, received_rx) = mpsc::channel(2048);
        let (state_tx, state) = watch::channel((State::Waiting, false));
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let mut peer = peer;
            let result = drive(
                &sockets,
                &mut peer,
                command_rx,
                packet_rx,
                received,
                &state_tx,
                &task_cancel,
            )
            .await;
            // Reader cancellation can close its channel before the driver's
            // select observes cancellation. Explicit shutdown still ends Closed.
            let failed = result.is_err() && !task_cancel.is_cancelled();
            peer.close(Instant::now());
            // Best-effort close_notify never holds up shutdown on a full socket.
            while let Some(packet) = peer.transmit() {
                if let Some(socket) = sockets.get(&packet.local) {
                    let _ = tokio::time::timeout(
                        Duration::from_millis(5),
                        socket.send_to(&packet.bytes, packet.remote),
                    )
                    .await;
                }
            }
            state_tx.send_replace((if failed { State::Failed } else { State::Closed }, false));
        });
        Ok((
            Self {
                commands,
                packets,
                state,
                description,
                lifetime: Arc::new(Lifetime {
                    cancel,
                    task: Mutex::new(Some(task)),
                    _allocation: allocation,
                }),
            },
            received_rx,
        ))
    }
    pub fn description(&self) -> Description {
        self.description.clone()
    }
    pub fn state(&self) -> State {
        self.state.borrow().0
    }
    pub fn is_relay(&self) -> bool {
        self.state.borrow().1
    }
    pub async fn remote(&self, actor: &str, description: Description) -> Result<()> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Remote {
                actor: actor.into(),
                description,
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("private peer closed"))?;
        result
            .await
            .map_err(|_| anyhow::anyhow!("private peer closed"))?
    }
    pub async fn ready(&self) -> Result<()> {
        let mut state = self.state.clone();
        loop {
            match state.borrow_and_update().0 {
                State::Ready => return Ok(()),
                State::Closed | State::Failed => anyhow::bail!("private peer handshake failed"),
                _ => {}
            }
            state
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("private peer closed"))?;
        }
    }
    /// Queueing never waits for this or another peer's transport. The inner IP
    /// flow supplies reliability/congestion control when packets are dropped.
    pub fn send(&self, packet: Bytes) -> Result<()> {
        ensure!(self.state() == State::Ready, "private peer is not ready");
        ensure!(
            (20..=MAX_PACKET).contains(&packet.len()),
            "invalid private packet size"
        );
        self.packets
            .try_send(packet)
            .map_err(|_| anyhow::anyhow!("private peer send queue unavailable"))
    }
    /// Reliable stream carriers propagate bounded queue pressure in their own
    /// worker, without blocking the TUN packet owner or control-plane work.
    #[cfg(feature = "streams")]
    pub async fn send_stream(&self, packet: Bytes) -> Result<()> {
        ensure!(self.state() == State::Ready, "private peer is not ready");
        ensure!(
            (20..=MAX_PACKET).contains(&packet.len()),
            "invalid private packet size"
        );
        self.packets
            .send(packet)
            .await
            .map_err(|_| anyhow::anyhow!("private peer closed"))
    }
    pub async fn statistics(&self) -> Result<Statistics> {
        let (reply, result) = oneshot::channel();
        self.commands
            .send(Command::Statistics(reply))
            .await
            .map_err(|_| anyhow::anyhow!("private peer closed"))?;
        result
            .await
            .map_err(|_| anyhow::anyhow!("private peer closed"))
    }
    pub async fn close(&self) {
        self.lifetime.cancel.cancel();
        let task = self
            .lifetime
            .task
            .lock()
            .expect("task mutex poisoned")
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
        if let Some(allocation) = &self.lifetime._allocation {
            allocation.close().await;
        }
    }
}
async fn read_datagrams(
    local: SocketAddr,
    socket: Socket,
    datagrams: mpsc::Sender<Datagram>,
    cancel: CancellationToken,
) {
    // One extra byte distinguishes oversized input even if the OS truncates it.
    let mut buffer = [0u8; 8193];
    let mut backoff = Duration::from_millis(100);
    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => return,
            result = socket.recv_from(&mut buffer) => result,
        };
        let (packet, retry) = match result {
            Ok((size, remote)) if size <= 8192 => {
                backoff = Duration::from_millis(100);
                (
                    Datagram::Packet(local, remote, BytesMut::from(&buffer[..size])),
                    None,
                )
            }
            Ok(_) => (Datagram::ReadError(local, false), None),
            Err(error) if truncated_datagram(&error) => (Datagram::ReadError(local, false), None),
            Err(error) => {
                let retry = retry_read(&error);
                (Datagram::ReadError(local, !retry), Some(retry))
            }
        };
        tokio::select! {
            _ = cancel.cancelled() => return,
            result = datagrams.send(packet) => if result.is_err() { return; },
        }
        if let Some(retry) = retry {
            if !retry {
                return;
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(1));
        }
    }
}
async fn drive(
    sockets: &HashMap<SocketAddr, Socket>,
    peer: &mut Peer,
    mut commands: mpsc::Receiver<Command>,
    mut outgoing: mpsc::Receiver<Bytes>,
    incoming: mpsc::Sender<Bytes>,
    state: &watch::Sender<(State, bool)>,
    cancel: &CancellationToken,
) -> Result<()> {
    let mut statistics = Statistics::default();
    let (datagrams, mut datagram_rx) = mpsc::channel(256);
    let mut readers = JoinSet::new();
    for (local, socket) in sockets {
        let local = *local;
        let socket = socket.clone();
        let datagrams = datagrams.clone();
        let cancel = cancel.clone();
        readers.spawn(read_datagrams(local, socket, datagrams, cancel));
    }
    drop(datagrams);
    let mut disabled = HashSet::new();
    loop {
        while let Some(packet) = peer.transmit() {
            if disabled.contains(&packet.local) {
                continue;
            }
            let socket = sockets
                .get(&packet.local)
                .ok_or_else(|| anyhow::anyhow!("private interface unavailable"))?;
            tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),result=socket.send_to(&packet.bytes,packet.remote)=>{
                if let Err(error)=result {
                    statistics.write_errors=statistics.write_errors.saturating_add(1);
                    if closed(&error) {disabled.insert(packet.local);}
                    // A failed ICE destination or datagram must not tear down
                    // an authenticated connection over another viable path.
                }
            }}
        }
        ensure!(
            disabled.len() < sockets.len(),
            "all private interfaces are closed"
        );
        while let Some(packet) = peer.packet() {
            statistics.received_bytes = statistics
                .received_bytes
                .saturating_add(packet.len() as u64);
            if incoming.try_send(packet).is_err() {
                statistics.dropped_incoming = statistics.dropped_incoming.saturating_add(1);
            }
        }
        let current = (peer.state(), peer.is_relay());
        if *state.borrow() != current {
            state.send_replace(current);
        }
        if peer.state() == State::Failed {
            anyhow::bail!("private peer failed");
        }
        if peer.state() == State::Closed {
            return Ok(());
        }
        let deadline = peer.next_timeout();
        tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            received=datagram_rx.recv()=>{
                match received.ok_or_else(||anyhow::anyhow!("private UDP read failed"))? {
                    Datagram::Packet(local,remote,bytes)=>peer.receive_on(Instant::now(),local,remote,bytes)?,
                    Datagram::ReadError(local,closed)=>{
                        statistics.read_errors=statistics.read_errors.saturating_add(1);
                        if closed {disabled.insert(local);}
                    },
                }
            },
            command=commands.recv()=>match command {
                Some(Command::Remote{actor,description,reply})=>{let _=reply.send(peer.remote(Instant::now(),&actor,&description));},
                Some(Command::Statistics(reply))=>{let _=reply.send(statistics);},None=>return Ok(()),
            },
            packet=outgoing.recv()=>match packet {
                Some(packet)=>{
                    if peer.send(Instant::now(),&packet).is_ok() {statistics.sent_bytes=statistics.sent_bytes.saturating_add(packet.len() as u64);}
                    else {statistics.dropped_outgoing=statistics.dropped_outgoing.saturating_add(1);}
                },None=>return Ok(()),
            },
            _=async {match deadline {Some(deadline)=>tokio::time::sleep_until(tokio::time::Instant::from_std(deadline.max(Instant::now()+Duration::from_millis(1)))).await,None=>std::future::pending().await}}=>{peer.timeout(Instant::now())?;},
        }
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use turn_util::{Conn, Error as IoError, Result as IoResult};

    struct FaultSocket {
        socket: Arc<UdpSocket>,
        target: SocketAddr,
        reset: AtomicBool,
        oversized: AtomicBool,
        closed: bool,
        rejected: AtomicUsize,
    }
    #[async_trait]
    impl Conn for FaultSocket {
        async fn connect(&self, remote: SocketAddr) -> IoResult<()> {
            Ok(self.socket.connect(remote).await?)
        }
        async fn recv(&self, buffer: &mut [u8]) -> IoResult<usize> {
            Ok(self.recv_from(buffer).await?.0)
        }
        async fn recv_from(&self, buffer: &mut [u8]) -> IoResult<(usize, SocketAddr)> {
            if self.closed {
                return Err(IoError::ErrUseClosedNetworkConn);
            }
            if self.reset.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into());
            }
            if self.oversized.swap(false, Ordering::SeqCst) {
                return Err(IoError::ErrPacketTooBig);
            }
            Ok(self.socket.recv_from(buffer).await?)
        }
        async fn send(&self, buffer: &[u8]) -> IoResult<usize> {
            self.send_to(buffer, self.target).await
        }
        async fn send_to(&self, buffer: &[u8], remote: SocketAddr) -> IoResult<usize> {
            if self.closed {
                return Err(IoError::ErrUseClosedNetworkConn);
            }
            if remote != self.target {
                self.rejected.fetch_add(1, Ordering::SeqCst);
                return Err(std::io::Error::from(std::io::ErrorKind::NetworkUnreachable).into());
            }
            Ok(self.socket.send_to(buffer, remote).await?)
        }
        fn local_addr(&self) -> IoResult<SocketAddr> {
            Ok(self.socket.local_addr()?)
        }
        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
        async fn close(&self) -> IoResult<()> {
            Ok(())
        }
        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    }
    async fn exchange(left: &Session, right: &mut mpsc::Receiver<Bytes>) -> Result<()> {
        let packet = Bytes::from(vec![0x45; MAX_PACKET]);
        left.send(packet.clone())?;
        ensure!(tokio::time::timeout(Duration::from_secs(2), right.recv()).await? == Some(packet));
        Ok(())
    }
    async fn exercise(dead_interface: bool) -> Result<()> {
        let a = Identity::new()?;
        let b = Identity::new()?;
        let left_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let right_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let la = left_socket.local_addr()?;
        let ra = right_socket.local_addr()?;
        let wrapped = Arc::new(FaultSocket {
            socket: left_socket,
            target: ra,
            reset: AtomicBool::new(true),
            oversized: AtomicBool::new(true),
            closed: false,
            rejected: AtomicUsize::new(0),
        });
        let mut left = Peer::new(
            Instant::now(),
            la,
            "peer-a",
            "peer-b",
            a.clone(),
            b.fingerprint(),
        )?;
        let right = Peer::new(Instant::now(), ra, "peer-b", "peer-a", b, a.fingerprint())?;
        let mut sockets = HashMap::from([(la, wrapped.clone() as Socket)]);
        if dead_interface {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            let address = socket.local_addr()?;
            left.add_interface(address)?;
            sockets.insert(
                address,
                Arc::new(FaultSocket {
                    socket,
                    target: ra,
                    reset: AtomicBool::new(false),
                    oversized: AtomicBool::new(false),
                    closed: true,
                    rejected: AtomicUsize::new(0),
                }) as Socket,
            );
        }
        let (left, mut left_rx) = Session::start(sockets, left, None)?;
        let (right, mut right_rx) =
            Session::start(HashMap::from([(ra, right_socket as Socket)]), right, None)?;
        let result = async {
            let mut description = right.description();
            if !dead_interface {
                description.sdp.push_str(
                    "a=candidate:unreachable 1 udp 4294967295 192.0.2.5 59999 typ host\r\n",
                );
            }
            left.remote("peer-b", description).await?;
            right.remote("peer-a", left.description()).await?;
            tokio::time::timeout(Duration::from_secs(6), async {
                left.ready().await?;
                right.ready().await
            })
            .await??;
            exchange(&left, &mut right_rx).await?;
            exchange(&right, &mut left_rx).await?;
            // Oversized unauthenticated datagrams cannot close a proven peer.
            let outsider = UdpSocket::bind("127.0.0.1:0").await?;
            outsider.send_to(&vec![0; 9000], la).await?;
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if left.statistics().await?.read_errors >= 3 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                anyhow::Ok(())
            })
            .await??;
            exchange(&left, &mut right_rx).await?;
            exchange(&right, &mut left_rx).await?;
            if !dead_interface {
                ensure!(
                    wrapped.rejected.load(Ordering::SeqCst) > 0
                        && left.statistics().await?.write_errors > 0
                );
            }
            anyhow::Ok(())
        }
        .await;
        left.close().await;
        right.close().await;
        result
    }
    #[tokio::test]
    async fn unreachable_candidate_receive_reset_and_oversized_datagrams_preserve_the_valid_peer(
    ) -> Result<()> {
        exercise(false).await
    }
    #[tokio::test]
    async fn closed_interface_does_not_close_a_peer_using_another_interface() -> Result<()> {
        exercise(true).await
    }
    #[tokio::test]
    async fn all_closed_interfaces_fail_promptly_for_route_fallback() -> Result<()> {
        let identity = Identity::new()?;
        let remote_identity = Identity::new()?;
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let address = socket.local_addr()?;
        let peer = Peer::new(
            Instant::now(),
            address,
            "peer-a",
            "peer-b",
            identity,
            remote_identity.fingerprint(),
        )?;
        let closed = Arc::new(FaultSocket {
            socket,
            target: address,
            reset: AtomicBool::new(false),
            oversized: AtomicBool::new(false),
            closed: true,
            rejected: AtomicUsize::new(0),
        });
        let (session, _packets) =
            Session::start(HashMap::from([(address, closed as Socket)]), peer, None)?;
        let result = tokio::time::timeout(Duration::from_secs(1), session.ready()).await;
        let state = session.state();
        session.close().await;
        ensure!(result.is_ok_and(|ready| ready.is_err()));
        ensure!(state == State::Failed);
        Ok(())
    }
}
