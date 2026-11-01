//! Per-attachment transport actor. Output backpressure stops only this PTY's
//! reader, while input, acknowledgements and the other participants keep moving.
use super::{Event, Peer};
use crate::{
    delivery::{self, Message, Receiver, Sender},
    protocol::*,
    pty::InputSink,
};
use anyhow::{ensure, Context, Result};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

#[derive(Clone)]
pub struct Config {
    pub addresses: Vec<IpAddr>,
    pub stun_servers: Vec<String>,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.addresses.is_empty() && self.addresses.len() <= 16,
            "invalid terminal interfaces"
        );
        ensure!(
            self.addresses
                .iter()
                .all(|ip| !ip.is_unspecified() && !ip.is_multicast()),
            "invalid terminal interface address"
        );
        ensure!(
            self.stun_servers.len() <= 2 && self.stun_servers.iter().all(|s| porthub_mesh::stun::normalize_server(s).is_some()),
            "invalid terminal STUN configuration"
        );
        Ok(())
    }
}
enum Command {
    Offer {
        request: u32,
        description: DirectDescription,
    },
    Relay {
        message: Message,
        _bytes: Option<OwnedSemaphorePermit>,
    },
}
pub struct Handle {
    commands: mpsc::Sender<Command>,
    input_bytes: Arc<Semaphore>,
    cancel: CancellationToken,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}
impl Handle {
    fn channel() -> (Self, mpsc::Receiver<Command>) {
        // One input window, output acknowledgements and a fallback replay can
        // arrive before this actor is scheduled. Count payload bytes separately
        // so small keystrokes do not exhaust an arbitrary 32-message limit.
        let (commands, receive) = mpsc::channel(delivery::MAX_FRAMES * 4);
        (
            Self {
                commands,
                input_bytes: Arc::new(Semaphore::new(delivery::MAX_BYTES * 2)),
                cancel: CancellationToken::new(),
            },
            receive,
        )
    }
    pub fn offer(&self, request: u32, description: DirectDescription) -> Result<()> {
        self.commands
            .try_send(Command::Offer {
                request,
                description,
            })
            .map_err(|_| anyhow::anyhow!("terminal transport control is backpressured"))
    }
    pub fn relay(&self, packet: DeliveryPacket) -> Result<()> {
        let message = packet.decode()?;
        let bytes = match &message {
            Message::Data(frame) => Some(
                self.input_bytes
                    .clone()
                    .try_acquire_many_owned(frame.payload().len() as u32)
                    .map_err(|_| {
                        anyhow::anyhow!("terminal input control bytes are backpressured")
                    })?,
            ),
            Message::Ack { .. } => None,
        };
        self.commands
            .try_send(Command::Relay {
                message,
                _bytes: bytes,
            })
            .map_err(|_| anyhow::anyhow!("terminal transport control is backpressured"))
    }
}
struct Network {
    peer: Peer,
    sockets: Vec<Arc<UdpSocket>>,
    reflexive: Vec<(SocketAddr, SocketAddr)>,
    incoming: mpsc::Receiver<(SocketAddr, SocketAddr, Vec<u8>)>,
    readers: JoinSet<()>,
    ready: bool,
    traffic: crate::traffic::Counters,
}
impl Drop for Network {
    fn drop(&mut self) {
        self.readers.abort_all();
    }
}
impl Network {
    async fn prepare(config: Config, description: DirectDescription,traffic: crate::traffic::Counters) -> Result<(Self, String)> {
        description.validate("offer")?;
        config.validate()?;
        let mut gathering = JoinSet::new();
        for ip in config.addresses {
            let servers = config.stun_servers.clone();
            gathering.spawn(async move {
                let socket = Arc::new(UdpSocket::bind(SocketAddr::new(ip, 0)).await?);
                #[cfg(target_os = "macos")]
                porthub_mesh::underlay::bind_interface(
                    &socket2::SockRef::from(socket.as_ref()),
                    ip,
                )?;
                let mapped = if servers.is_empty() {
                    None
                } else {
                    porthub_mesh::stun::mapped(&socket, &servers).await
                };
                Ok::<_, anyhow::Error>((socket, mapped))
            });
        }
        let mut sockets = Vec::new();
        let mut reflexive = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(result) = gathering.join_next().await {
                if let Ok(Ok((socket, mapped))) = result {
                    if let Some(mapped) = mapped {
                        reflexive.push((mapped, socket.local_addr()?));
                    }
                    sockets.push(socket);
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("terminal candidate gathering timed out")??;
        let addresses = sockets
            .iter()
            .map(|socket| socket.local_addr())
            .collect::<std::io::Result<Vec<_>>>()?;
        let (peer, answer) =
            Peer::answer_reflexive(Instant::now(), &description.0, &addresses, &reflexive)?;
        let (send, incoming) = mpsc::channel(32);
        let mut readers = JoinSet::new();
        for socket in &sockets {
            let socket = socket.clone();
            let send = send.clone();
            let traffic = traffic.clone();
            readers.spawn(async move {
                let Ok(local) = socket.local_addr() else {
                    return;
                };
                let mut buffer = [0; 2048];
                while let Ok((count, remote)) = socket.recv_from(&mut buffer).await {
                    traffic.received(count);
                    if send
                        .send((local, remote, buffer[..count].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        Ok((
            Self {
                peer,
                sockets,
                reflexive,
                incoming,
                readers,
                ready: false,
                traffic,
            },
            answer,
        ))
    }
    async fn flush(&mut self) -> Result<()> {
        while let Some((local, remote, bytes)) = self.peer.datagram_from() {
            let base = self
                .reflexive
                .iter()
                .find_map(|(mapped, base)| (*mapped == local).then_some(*base))
                .unwrap_or(local);
            let socket = self
                .sockets
                .iter()
                .find(|socket| socket.local_addr().ok() == Some(base))
                .or_else(|| {
                    self.sockets.iter().find(|socket| {
                        socket
                            .local_addr()
                            .is_ok_and(|addr| addr.is_ipv4() == remote.is_ipv4())
                    })
                })
                .context("terminal UDP interface unavailable")?;
            let count = socket.send_to(&bytes, remote).await?;
            self.traffic.sent(count);
        }
        Ok(())
    }
}
struct Delivery {
    input_epoch: String,
    output_epoch: String,
    send: Sender,
    receive: Receiver,
    direct_cursor: u64,
    relay_cursor: u64,
    prefer_direct: bool,
    last_progress: Instant,
    direct_since: Instant,
}
impl Delivery {
    fn new() -> Result<Self> {
        let input_epoch = random_token(16);
        let output_epoch = random_token(16);
        ensure!(
            input_epoch != output_epoch,
            "terminal direction epochs must differ"
        );
        Ok(Self {
            send: Sender::new(&output_epoch)?,
            receive: Receiver::new(&input_epoch)?,
            input_epoch,
            output_epoch,
            direct_cursor: 0,
            relay_cursor: 0,
            prefer_direct: false,
            last_progress: Instant::now(),
            direct_since: Instant::now(),
        })
    }
}
async fn emit(
    send: &mpsc::Sender<HostOutput>,
    cancel: &CancellationToken,
    event: HostOutput,
) -> Result<()> {
    tokio::select! {_ = cancel.cancelled()=>anyhow::bail!("terminal transport cancelled"),result=tokio::time::timeout(Duration::from_secs(5),send.send(event))=>{result??;Ok(())}}
}
fn network_events(network: &mut Option<Network>, delivery: &mut Option<Delivery>) -> Result<()> {
    let mut closed = false;
    if let Some(net) = network {
        while let Some(event) = net.peer.event()? {
            match event {
                Event::Ready => {
                    net.ready = true;
                    if let Some(state) = delivery {
                        state.prefer_direct = true;
                        state.direct_cursor = 0;
                        state.direct_since = Instant::now();
                    }
                }
                Event::Closed => closed = true,
            }
        }
    }
    if closed {
        *network = None;
        if let Some(state) = delivery {
            state.prefer_direct = false;
            state.relay_cursor = 0;
        }
    }
    Ok(())
}
async fn flush_network(network: &mut Option<Network>, delivery: &mut Option<Delivery>) {
    if let Some(net) = network {
        if !matches!(
            tokio::time::timeout(Duration::from_millis(100), net.flush()).await,
            Ok(Ok(()))
        ) {
            *network = None;
            if let Some(state) = delivery {
                state.prefer_direct = false;
                state.relay_cursor = 0;
            }
        }
    }
}
async fn receipt(
    delivery: &mut Delivery,
    message: Message,
    direct: bool,
    network: &mut Option<Network>,
    sink: &InputSink,
    client: u64,
    send: &mpsc::Sender<HostOutput>,
    cancel: &CancellationToken,
) -> Result<()> {
    match message {
        Message::Ack { epoch, sequence } => {
            let before = delivery.send.retained_bytes();
            delivery.send.acknowledge(&epoch, sequence)?;
            if delivery.send.retained_bytes() < before {
                delivery.last_progress = Instant::now();
            }
        }
        Message::Data(frame) => {
            delivery.receive.stage(frame)?;
            while let Some(frame) = delivery.receive.next() {
                let sequence = frame.sequence();
                sink.write(frame.payload())?;
                delivery.receive.commit(sequence)?;
            }
            let ack = Message::Ack {
                epoch: delivery.input_epoch.clone(),
                sequence: delivery.receive.acknowledged(),
            };
            if direct {
                if let Some(net) = network {
                    if net.ready && net.peer.send(Instant::now(), &ack.encode()?).is_ok() {
                        return Ok(());
                    }
                }
            }
            emit(
                send,
                cancel,
                HostOutput::Delivery {
                    client,
                    packet: DeliveryPacket::encode(&ack)?,
                },
            )
            .await?;
        }
    }
    Ok(())
}
/// The private PTY output queue is created before attachment, so a large burst
/// cannot bypass per-guest flow control after transport negotiation.
pub fn spawn(
    client: u64,
    sink: InputSink,
    output: mpsc::Receiver<HostOutput>,
    send: mpsc::Sender<HostOutput>,
    config: Config,
) -> Handle {
    spawn_measured(client, sink, output, send, config, Default::default())
}
pub(crate) fn spawn_measured(
    client: u64,
    sink: InputSink,
    output: mpsc::Receiver<HostOutput>,
    send: mpsc::Sender<HostOutput>,
    config: Config,
    traffic: crate::traffic::Counters,
) -> Handle {
    let (handle, receive) = Handle::channel();
    let actor_cancel = handle.cancel.clone();
    tokio::spawn(async move {
        let _ = run(
            client,
            sink,
            output,
            receive,
            send.clone(),
            config,
            actor_cancel,
            traffic,
        )
        .await;
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            send.send(HostOutput::Closed { client }),
        )
        .await;
    });
    handle
}
async fn run(
    client: u64,
    sink: InputSink,
    mut output: mpsc::Receiver<HostOutput>,
    mut commands: mpsc::Receiver<Command>,
    send: mpsc::Sender<HostOutput>,
    config: Config,
    cancel: CancellationToken,
    traffic: crate::traffic::Counters,
) -> Result<()> {
    let mut delivery: Option<Delivery> = None;
    let mut network: Option<Network> = None;
    let mut pending: Option<(u32, AbortOnDropHandle<Result<(Network, String)>>)> = None;
    let mut last_activity = Instant::now();
    let mut output_closed = false;
    let mut drain_started: Option<Instant> = None;
    loop {
        if output_closed
            && (delivery
                .as_ref()
                .is_none_or(|state| state.send.retained_bytes() == 0)
                || drain_started.is_some_and(|at| at.elapsed() > Duration::from_secs(2)))
        {
            return Ok(());
        }
        network_events(&mut network, &mut delivery)?;
        flush_network(&mut network, &mut delivery).await;
        if let Some(state) = &mut delivery {
            if state.prefer_direct
                && state.send.retained_bytes() > 0
                && state.last_progress.max(state.direct_since).elapsed() > Duration::from_secs(1)
            {
                state.prefer_direct = false;
                state.relay_cursor = 0;
            }
            for frame in state.send.replay() {
                if state.prefer_direct {
                    if frame.sequence() > state.direct_cursor {
                        let net = network
                            .as_mut()
                            .context("direct terminal path unavailable")?;
                        if net
                            .peer
                            .send(Instant::now(), &Message::Data(frame.clone()).encode()?)
                            .is_err()
                        {
                            break;
                        }
                        state.direct_cursor = frame.sequence();
                    }
                } else if frame.sequence() > state.relay_cursor {
                    emit(
                        &send,
                        &cancel,
                        HostOutput::Delivery {
                            client,
                            packet: DeliveryPacket::encode(&Message::Data(frame.clone()))?,
                        },
                    )
                    .await?;
                    state.relay_cursor = frame.sequence();
                }
            }
            if state.send.retained_bytes() > 0
                && state.last_progress.elapsed() > Duration::from_secs(15)
            {
                anyhow::bail!("terminal output acknowledgements stalled");
            }
        }
        flush_network(&mut network, &mut delivery).await;
        // Idle legacy attachments need no polling. Active peers use the RTC
        // engine's deadline; application ACK/drain deadlines remain independent.
        let mut deadline = Instant::now() + Duration::from_secs(86400);
        if let Some(net) = &mut network {
            if let Some(at) = net.peer.deadline() {
                deadline = deadline.min(at);
            }
        }
        if let Some(state) = &delivery {
            if state.send.retained_bytes() > 0 {
                deadline = deadline.min(state.last_progress + Duration::from_secs(15));
                if state.prefer_direct {
                    deadline = deadline
                        .min(state.last_progress.max(state.direct_since) + Duration::from_secs(1));
                }
            }
        }
        if let Some(at) = drain_started {
            deadline = deadline.min(at + Duration::from_secs(2));
        }
        let timed = network.is_some()
            || delivery
                .as_ref()
                .is_some_and(|state| state.send.retained_bytes() > 0)
            || output_closed;
        tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            ready=async {match &mut pending {Some((request,task))=>Some((*request,task.await)),None=>std::future::pending().await}}=>{
                pending=None;let (request,result)=ready.unwrap();
                if let Ok(Ok((net,description)))=result {
                    if delivery.is_none(){delivery=Some(Delivery::new()?);}
                    let state=delivery.as_ref().unwrap();
                    emit(&send,&cancel,HostOutput::DirectAnswer {client,answer:DirectAnswer {request,description:DirectDescription(description),input_epoch:state.input_epoch.clone(),output_epoch:state.output_epoch.clone()}}).await?;
                    if let Some(state)=&mut delivery {state.prefer_direct=false;state.relay_cursor=0;}
                    network=Some(net);
                }else{emit(&send,&cancel,HostOutput::DirectUnavailable {client,request}).await?;}
            },
            command=commands.recv()=>match command {
                Some(Command::Offer {request,description})=>{
                    ensure!(pending.is_none(),"terminal negotiation is already pending");let config=config.clone();
                    pending=Some((request,AbortOnDropHandle::new(tokio::spawn(Network::prepare(config,description,traffic.clone())))));
                },
                Some(Command::Relay {message,_bytes})=>{
                    receipt(delivery.as_mut().context("terminal delivery is not negotiated")?,message,false,&mut network,&sink,client,&send,&cancel).await?;
                },
                None=>return Ok(()),
            },
            event=output.recv(),if !output_closed && delivery.as_ref().is_none_or(|state|state.send.can_enqueue(delivery::MAX_PAYLOAD))=>match event {
                Some(HostOutput::Output {client:id,data})=>{
                    ensure!(id==client,"terminal output routing mismatch");
                    if let Some(state)=&mut delivery {let bytes=decode_data(&data)?;if state.send.retained_bytes()==0 {state.last_progress=Instant::now();}state.send.enqueue(&bytes)?;}
                    else {emit(&send,&cancel,HostOutput::Output {client,data}).await?;}
                },
                Some(HostOutput::Closed {..})|None=>{output_closed=true;drain_started=Some(Instant::now());},_=>anyhow::bail!("invalid private terminal output"),
            },
            packet=async {match &mut network {Some(net)=>net.incoming.recv().await,None=>std::future::pending().await}}=>{
                if packet.is_none(){network=None;if let Some(state)=&mut delivery{state.prefer_direct=false;state.relay_cursor=0;}continue;}
                if let Some((local,remote,bytes))=packet {
                    let net=network.as_mut().unwrap();let _=net.peer.receive(Instant::now(),local,remote,&bytes);
                    network_events(&mut network,&mut delivery)?;
                    if network.is_some() {
                        while let Some(bytes)=network.as_mut().unwrap().peer.read()? {
                            let message=Message::parse(&bytes)?;
                            receipt(delivery.as_mut().context("terminal delivery is not negotiated")?,message,true,&mut network,&sink,client,&send,&cancel).await?;
                            if last_activity.elapsed()>Duration::from_secs(5){emit(&send,&cancel,HostOutput::Activity).await?;last_activity=Instant::now();}
                        }
                    }
                }
            },
            _=tokio::time::sleep_until(deadline.into()),if timed=>{if let Some(net)=&mut network {let _=net.peer.timeout(Instant::now());}},
        }
    }
}

#[cfg(test)]
mod control_tests {
    use super::*;
    const EPOCH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn data(sequence: u64, bytes: usize) -> Result<DeliveryPacket> {
        DeliveryPacket::encode(&Message::Data(delivery::Frame::new(
            EPOCH,
            sequence,
            &vec![0; bytes],
        )?))
    }
    fn ack() -> Result<DeliveryPacket> {
        DeliveryPacket::encode(&Message::Ack {
            epoch: EPOCH.into(),
            sequence: 0,
        })
    }
    #[test]
    fn fast_keystrokes_output_acks_and_one_replay_fit_before_actor_scheduling() -> Result<()> {
        let (handle, _receive) = Handle::channel();
        for sequence in 1..=delivery::MAX_FRAMES as u64 {
            handle.relay(data(sequence, 1)?)?;
            handle.relay(ack()?)?;
            handle.relay(data(sequence, 1)?)?;
        }
        assert_eq!(
            handle.input_bytes.available_permits(),
            delivery::MAX_BYTES * 2 - delivery::MAX_FRAMES * 2
        );
        Ok(())
    }
    #[test]
    fn payload_bytes_are_bounded_independently_and_do_not_block_acknowledgements() -> Result<()> {
        let (handle, mut receive) = Handle::channel();
        for sequence in 1..=8 {
            handle.relay(data(sequence, delivery::MAX_PAYLOAD)?)?;
        }
        assert_eq!(handle.input_bytes.available_permits(), 0);
        assert!(handle.relay(data(9, 1)?).is_err());
        handle.relay(ack()?)?;
        let queued = receive.try_recv()?;
        assert_eq!(
            handle.input_bytes.available_permits(),
            0,
            "in-flight input keeps its reservation"
        );
        drop(queued);
        assert_eq!(
            handle.input_bytes.available_permits(),
            delivery::MAX_PAYLOAD
        );
        handle.relay(data(9, 1)?)?;
        drop(receive);
        assert_eq!(
            handle.input_bytes.available_permits(),
            delivery::MAX_BYTES * 2
        );
        assert!(handle.relay(ack()?).is_err());
        assert_eq!(
            handle.input_bytes.available_permits(),
            delivery::MAX_BYTES * 2
        );
        Ok(())
    }
    #[test]
    fn ack_only_flood_is_still_bounded() -> Result<()> {
        let (handle, _receive) = Handle::channel();
        for _ in 0..delivery::MAX_FRAMES * 4 {
            handle.relay(ack()?)?;
        }
        assert!(handle.relay(ack()?).is_err());
        assert_eq!(
            handle.input_bytes.available_permits(),
            delivery::MAX_BYTES * 2
        );
        Ok(())
    }
}
