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

/// Immutable upper-layer admission witness. The mesh owns no ACL policy: it
/// retains this observation-only check through its bounded packet/native queue.
#[derive(Clone)]
pub struct SendPermit {
    observe: Arc<dyn Fn() -> Option<PermitBound> + Send + Sync>,
}
#[derive(Clone, Copy)]
enum PermitBound {
    Unknown,
    Control,
    Known(Duration),
}
impl SendPermit {
    /// Legacy authority without a known temporal bound.
    pub fn new(check: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self { observe: Arc::new(move || check().then_some(PermitBound::Unknown)) }
    }
    /// A local non-authorizing veto, never an independent byte origin.
    pub fn control(check: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        Self { observe: Arc::new(move || check().then_some(PermitBound::Control)) }
    }
    /// Both callbacks observe the EXISTING immutable admission, never renew it.
    pub fn bounded(
        check: impl Fn() -> bool + Send + Sync + 'static,
        remaining: impl Fn() -> Option<Duration> + Send + Sync + 'static,
    ) -> Self {
        Self { observe: Arc::new(move || {
            if !check() { return None; }
            remaining().filter(|n| !n.is_zero()).map(PermitBound::Known)
        }) }
    }
    pub fn valid(&self) -> bool { (self.observe)().is_some() }
    pub fn remaining(&self) -> Option<Duration> {
        match (self.observe)()? {
            PermitBound::Known(left) => Some(left),
            PermitBound::Unknown | PermitBound::Control => None,
        }
    }
    /// Add a live local veto while preserving every original bound.
    pub fn constrain(&self, control: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        let original = self.clone();
        Self { observe: Arc::new(move || {
            if !control() { return None; }
            (original.observe)()
        }) }
    }
    /// Retire a flow once any original native byte or control authority expires.
    /// Return the bound from the same observation that validated it.
    pub fn retire_owner_on_expiry(self, alive: Arc<std::sync::atomic::AtomicBool>) -> Self {
        use std::sync::atomic::Ordering;
        Self {
            observe: Arc::new(move || {
                if !alive.load(Ordering::SeqCst) {
                    return None;
                }
                let bound = (self.observe)();
                if bound.is_none() {
                    alive.store(false, Ordering::SeqCst);
                }
                bound
            }),
        }
    }
    /// Evaluate each independent origin once per observation. No observation
    /// is cached across polls or emissions: revocation and clocks stay live.
    /// Unknown bounds remain unknown; control vetoes never provide a lease.
    pub fn combine(origins: Vec<Self>) -> Self {
        Self { observe: Arc::new(move || {
            if origins.is_empty() { return None; }
            let mut unknown = false;
            let mut left: Option<Duration> = None;
            for origin in &origins {
                match (origin.observe)()? {
                    PermitBound::Unknown => unknown = true,
                    PermitBound::Control => {},
                    PermitBound::Known(n) => left = Some(left.map_or(n, |old| old.min(n))),
                }
            }
            Some(if unknown { PermitBound::Unknown }
                 else if let Some(n) = left { PermitBound::Known(n) }
                 else { PermitBound::Control })
        }) }
    }
    pub async fn during<F:std::future::Future>(&self,operation:F)->Result<F::Output>{
        tokio::pin!(operation);let mut tick=tokio::time::interval(Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let guarded=std::future::poll_fn(|cx|{
                if !self.valid(){return std::task::Poll::Ready(Err(anyhow::anyhow!("private packet admission retired")));}
                operation.as_mut().poll(cx).map(Ok)
            });
            tokio::select!{result=guarded=>return result,_=tick.tick()=>ensure!(self.valid(),"private packet admission retired")}
        }
    }
}
#[cfg(test)]
mod permit_observation_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[test]
    fn nested_origins_are_checked_once_and_revocation_is_immediate() {
        let calls = Arc::new(AtomicUsize::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let (count, live) = (calls.clone(), alive.clone());
        let mut permit = SendPermit::bounded(move || {
            count.fetch_add(1, Ordering::Relaxed);
            live.load(Ordering::SeqCst)
        }, || Some(Duration::from_secs(1)));
        for _ in 0..16 {
            permit = SendPermit::combine(vec![permit]).constrain(|| true);
        }
        assert!(permit.valid());
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(permit.remaining(), Some(Duration::from_secs(1)));
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        alive.store(false, Ordering::SeqCst);
        assert!(!permit.valid());
        assert_eq!(permit.remaining(), None);
    }

    #[test]
    fn native_owner_retires_on_the_first_invalid_observation() {
        let checks = Arc::new(AtomicUsize::new(0));
        let witness = checks.clone();
        let owner = Arc::new(AtomicBool::new(true));
        let permit = SendPermit::bounded(
            move || witness.fetch_add(1, Ordering::SeqCst) != 1,
            || Some(Duration::from_secs(1)),
        )
        .retire_owner_on_expiry(owner.clone());
        assert_eq!(permit.remaining(), Some(Duration::from_secs(1)));
        assert!(!permit.valid());
        assert!(!owner.load(Ordering::SeqCst));
        assert!(!permit.valid());
        assert_eq!(checks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn composition_preserves_unknown_bounds_and_control_vetoes() {
        let known = || SendPermit::bounded(|| true, || Some(Duration::from_secs(3)));
        let unknown = SendPermit::combine(vec![known(), SendPermit::new(|| true)]);
        assert!(unknown.valid());
        assert_eq!(unknown.remaining(), None);
        let control = SendPermit::combine(vec![SendPermit::control(|| true)]);
        assert!(control.valid());
        assert_eq!(control.remaining(), None);
        assert_eq!(SendPermit::combine(vec![known(), control]).remaining(), Some(Duration::from_secs(3)));
        assert!(!SendPermit::combine(vec![known(), SendPermit::control(|| false)]).valid());
        assert!(!SendPermit::combine(Vec::new()).valid());
    }

    #[test]
    fn every_original_clock_is_observed_without_extension() {
        let expired = Arc::new(AtomicBool::new(false));
        let flag = expired.clone();
        let first = SendPermit::bounded(|| true, move || {
            Some(if flag.load(Ordering::SeqCst) { Duration::ZERO } else { Duration::from_secs(2) })
        });
        let second = SendPermit::bounded(|| true, || Some(Duration::from_secs(9)));
        let combined = SendPermit::combine(vec![first, second]).constrain(|| true);
        assert_eq!(combined.remaining(), Some(Duration::from_secs(2)));
        expired.store(true, Ordering::SeqCst);
        assert!(!combined.valid());
        assert_eq!(combined.remaining(), None);
        assert!(!SendPermit::bounded(|| true, || None).valid());
    }
}

/// Immutable socket-generation factory. It may snapshot original pending
/// origins, but the factory itself is never replaced on an existing socket.
#[derive(Clone)]
pub struct SendFactory(Arc<dyn Fn()->Option<SendPermit>+Send+Sync>);
impl SendFactory {
    pub fn new(factory:impl Fn()->Option<SendPermit>+Send+Sync+'static)->Self{Self(Arc::new(factory))}
    pub fn snapshot(&self)->Option<SendPermit>{(self.0)()}
    pub fn same_generation(&self,other:&Self)->bool{Arc::ptr_eq(&self.0,&other.0)}
}

struct Outbound {bytes:Bytes,permit:Option<SendPermit>}

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
    packets: mpsc::Sender<Outbound>,
    guarded:Arc<std::sync::atomic::AtomicBool>,
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
            // Native snapshots race address removal and some hosts disable one
            // IP family. Keep the other usable interfaces instead of losing
            // every direct path because a single optional bind failed.
            let Ok(socket) = UdpSocket::bind(local).await else { continue; };
            #[cfg(target_os = "macos")]
            if crate::underlay::bind_interface(&socket2::SockRef::from(&socket), local.ip()).is_err() {
                continue;
            }
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
        ensure!(!bound.is_empty(), "private UDP bind failed on every interface");
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
        let guarded=Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task_guarded=guarded.clone();
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
            while let Some(packet) = peer.transmit().filter(|_|!task_guarded.load(std::sync::atomic::Ordering::SeqCst)) {
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
                guarded,
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
    pub fn send(&self, packet: Bytes) -> Result<()> {self.send_guarded(packet,None)}
    pub fn send_guarded(&self,packet:Bytes,permit:Option<SendPermit>)->Result<()> {
        ensure!(self.state() == State::Ready, "private peer is not ready");
        ensure!(
            (20..=MAX_PACKET).contains(&packet.len()),
            "invalid private packet size"
        );
        self.packets
            .try_send({if let Some(permit)=&permit {ensure!(permit.valid(),"private packet admission retired");self.guarded.store(true,std::sync::atomic::Ordering::SeqCst);}Outbound{bytes:packet,permit}})
            .map_err(|_| anyhow::anyhow!("private peer send queue unavailable"))
    }
    /// Reliable stream carriers propagate bounded queue pressure in their own
    /// worker, without blocking the TUN packet owner or control-plane work.
    #[cfg(feature = "streams")]
    pub async fn send_stream(&self, packet: Bytes) -> Result<()> {self.send_stream_guarded(packet,None).await}
    #[cfg(feature="streams")]
    pub async fn send_stream_guarded(&self,packet:Bytes,permit:Option<SendPermit>)->Result<()> {
        ensure!(self.state() == State::Ready, "private peer is not ready");
        ensure!(
            (20..=MAX_PACKET).contains(&packet.len()),
            "invalid private packet size"
        );
        self.packets
            .send({if let Some(permit)=&permit {ensure!(permit.valid(),"private packet admission retired");self.guarded.store(true,std::sync::atomic::Ordering::SeqCst);}Outbound{bytes:packet,permit}})
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
    mut outgoing: mpsc::Receiver<Outbound>,
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
    let mut pending_permit:Option<SendPermit>=None;
    let mut earliest_timer = Instant::now();
    loop {
        while let Some(packet) = peer.transmit() {
            if disabled.contains(&packet.local) {
                continue;
            }
            let socket = sockets
                .get(&packet.local)
                .ok_or_else(|| anyhow::anyhow!("private interface unavailable"))?;
            tokio::select! {biased;_=cancel.cancelled()=>return Ok(()),result=async {if let Some(permit)=&pending_permit {permit.during(socket.send_to(&packet.bytes,packet.remote)).await}else{Ok(socket.send_to(&packet.bytes,packet.remote).await)}}=>{
                let result=result?;
                if let Err(error)=result {
                    statistics.write_errors=statistics.write_errors.saturating_add(1);
                    if closed(&error) {disabled.insert(packet.local);}
                    // A failed ICE destination or datagram must not tear down
                    // an authenticated connection over another viable path.
                }
            }}
        }
        pending_permit=None;
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
        // Keep the timer floor anchored to the last service, even when data or
        // control messages keep winning the select. An overdue connectivity
        // check must run before processing another packet.
        let deadline = peer.next_timeout().map(|at| at.max(earliest_timer));
        let now = Instant::now();
        if deadline.is_some_and(|at| at <= now) {
            peer.timeout(now)?;
            earliest_timer = now + Duration::from_millis(1);
            continue;
        }
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
                    if packet.permit.as_ref().is_some_and(|permit|!permit.valid()) {statistics.dropped_outgoing=statistics.dropped_outgoing.saturating_add(1);continue;}
                    pending_permit=packet.permit;
                    if peer.send(Instant::now(),&packet.bytes).is_ok() {statistics.sent_bytes=statistics.sent_bytes.saturating_add(packet.bytes.len() as u64);}
                    else {statistics.dropped_outgoing=statistics.dropped_outgoing.saturating_add(1);}
                },None=>return Ok(()),
            },
            _=async {match deadline {Some(deadline)=>tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await,None=>std::future::pending().await}}=>{},
        }
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use turn_util::{Conn, Error as IoError, Result as IoResult};

    #[derive(Default)]
    struct Gate {isolated:AtomicBool,blocked:AtomicBool,entered:tokio::sync::Notify,release:tokio::sync::Notify,sends:AtomicUsize}
    struct FaultSocket {
        gate:Option<Arc<Gate>>,
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
            loop {
                let packet = self.socket.recv_from(buffer).await?;
                if !self.gate.as_ref().is_some_and(|gate| gate.isolated.load(Ordering::SeqCst)) {
                    return Ok(packet);
                }
            }
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
            if let Some(gate)=&self.gate {
                if gate.isolated.load(Ordering::SeqCst) { return Ok(buffer.len()); }
                if gate.blocked.load(Ordering::SeqCst){gate.entered.notify_one();gate.release.notified().await;}
                gate.sends.fetch_add(1,Ordering::SeqCst);
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
    #[derive(Clone, Copy, PartialEq)]
    enum Fault { Unreachable, ClosedInterface, RetiredPermit, SilentLoss }
    async fn exercise(fault: Fault) -> Result<()> {
        let dead_interface = fault == Fault::ClosedInterface;
        let gate=Arc::new(Gate::default());
        let a = Identity::new()?;
        let b = Identity::new()?;
        let left_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let right_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let la = left_socket.local_addr()?;
        let ra = right_socket.local_addr()?;
        let wrapped = Arc::new(FaultSocket {
            gate:Some(gate.clone()),
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
                    gate:None,
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
            if fault == Fault::SilentLoss {
                gate.isolated.store(true, Ordering::SeqCst);
                // Keep an otherwise healthy control queue busy while the established
                // UDP path silently drops every datagram in both directions.
                tokio::time::timeout(Duration::from_secs(30), async {
                    while left.state() == State::Ready {
                        let _ = left.statistics().await;
                        tokio::task::yield_now().await;
                    }
                }).await?;
                ensure!(left.state() == State::Failed);
            }
            if fault == Fault::RetiredPermit {
                let valid=Arc::new(AtomicBool::new(true));let check=valid.clone();
                gate.blocked.store(true,Ordering::SeqCst);let sent=gate.sends.load(Ordering::SeqCst);
                left.send_guarded(Bytes::from(vec![7;20]),Some(SendPermit::new(move||check.load(Ordering::SeqCst))))?;
                tokio::time::timeout(Duration::from_secs(1),gate.entered.notified()).await?;
                valid.store(false,Ordering::SeqCst);gate.release.notify_one();
                tokio::time::timeout(Duration::from_secs(1),async {while left.state()!=State::Failed {tokio::time::sleep(Duration::from_millis(1)).await;}}).await?;
                ensure!(gate.sends.load(Ordering::SeqCst)==sent,"retired native operation or close flush transmitted data");
                ensure!(tokio::time::timeout(Duration::from_millis(50),right_rx.recv()).await.is_err(),"retired payload reached remote application");
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
        exercise(Fault::Unreachable).await
    }
    #[tokio::test]
    async fn closed_interface_does_not_close_a_peer_using_another_interface() -> Result<()> {
        exercise(Fault::ClosedInterface).await
    }
    #[tokio::test]
    async fn actual_native_udp_pending_send_cannot_resume_after_admission_retirement()->Result<()> {exercise(Fault::RetiredPermit).await}
    #[tokio::test]
    async fn busy_session_detects_silent_loss_of_established_path() -> Result<()> {
        exercise(Fault::SilentLoss).await
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
            gate:None,
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

#[cfg(test)]
mod permit_bound_contract_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64,AtomicBool,Ordering};
    #[test]
    fn every_known_origin_contributes_immutable_min_and_unknown_never_upgrades(){
        let old=Arc::new(AtomicU64::new(400));let read=old.clone();let first=SendPermit::bounded(||true,move||Some(Duration::from_millis(read.load(Ordering::SeqCst))));
        let second=SendPermit::bounded(||true,||Some(Duration::from_millis(900)));
        let both=SendPermit::combine(vec![first.clone(),second]);assert_eq!(both.remaining(),Some(Duration::from_millis(400)));
        old.store(30,Ordering::SeqCst);assert_eq!(both.remaining(),Some(Duration::from_millis(30)));assert_eq!(both.clone().remaining(),both.remaining());
        let unknown=SendPermit::combine(vec![both.clone(),SendPermit::new(||true)]);assert!(unknown.valid());assert_eq!(unknown.remaining(),None);
        old.store(0,Ordering::SeqCst);assert!(!both.valid()&&!unknown.valid());
    }
    #[test]
    fn owner_control_can_veto_but_cannot_mint_or_reset_authority(){
        let owner=Arc::new(AtomicBool::new(true));let read=owner.clone();let control=SendPermit::control(move||read.load(Ordering::SeqCst));assert!(control.valid());assert!(control.remaining().is_none());
        let authority=SendPermit::bounded(||true,||Some(Duration::from_millis(10)));let combined=SendPermit::combine(vec![authority.clone(),control.clone()]);assert_eq!(combined.remaining(),authority.remaining());
        let constrained=authority.constrain(||true);assert_eq!(constrained.remaining(),authority.remaining());
        owner.store(false,Ordering::SeqCst);assert!(!combined.valid());assert!(combined.remaining().is_none());
        assert!(SendPermit::combine(vec![SendPermit::control(||true)]).remaining().is_none());
    }
}
