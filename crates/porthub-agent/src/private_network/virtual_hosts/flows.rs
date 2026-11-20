use super::{Admission, Flow, Lan};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use porthub_mesh::{MAX_PACKET, udp::SendPermit};
use porthub_network::tcp_stream::tagged;
use smoltcp::wire::{IpProtocol, Ipv4Packet, UdpPacket};
use std::{collections::HashMap, net::SocketAddrV4, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc, watch},
    task::{AbortHandle, JoinSet},
};

const FLOW_LIMIT: usize = 64;
type Datagram = (Bytes, SendPermit);
type Reply = (String, Bytes, SendPermit);

struct Active<T> {
    route: T,
    grant: Admission,
    task: AbortHandle,
}
impl<T> Active<T> {
    fn usable(&self) -> bool {
        !self.task.is_finished() && self.grant.current().is_some()
    }
}
impl<T> Drop for Active<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) struct Flows {
    stack: tagged::Handle,
    direct_writers: std::sync::Arc<tokio::sync::Semaphore>,
    tcp: HashMap<Flow, Active<watch::Receiver<Option<tagged::Ingress>>>>,
    udp: HashMap<Flow, Active<mpsc::Sender<Datagram>>>,
    tasks: JoinSet<()>,
    replies: mpsc::Sender<Reply>,
}
impl Flows {
    pub(super) fn new(stack: tagged::Handle, replies: mpsc::Sender<Reply>) -> Self {
        Self {
            stack,
            direct_writers: std::sync::Arc::new(tokio::sync::Semaphore::new(FLOW_LIMIT)),
            replies,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            tasks: JoinSet::new(),
        }
    }
    pub(super) fn prune(&mut self) {
        self.tcp
            .retain(|_, flow| flow.usable() && flow.grant.pairs.touch_peer(&flow.grant.peer));
        self.udp
            .retain(|_, flow| flow.usable() && flow.grant.pairs.touch_peer(&flow.grant.peer));
        while self.tasks.try_join_next().is_some() {}
    }
    pub(super) async fn receive(
        &mut self,
        bytes: Bytes,
        grant: Admission,
        permit: SendPermit,
        lan: &Lan,
        direct_carrier: bool,
    ) {
        let full = self.tcp.len() + self.udp.len() >= FLOW_LIMIT;
        if bytes[9] == 6 {
            let Some(key) = Flow::from_packet(&bytes) else {
                return;
            };
            if let Some(flow) = self.tcp.get(&key) {
                if flow.grant.peer == grant.peer && flow.usable() {
                    if let Some(ingress) = flow.route.borrow().as_ref() {
                        let _ = ingress.input(bytes, permit);
                    }
                }
                return;
            }
            if full || tagged::validate_syn(&bytes).is_err() {
                return;
            }
            let (publish, route) = watch::channel(None);
            let lan = lan.clone();
            let stack = self.stack.clone();
            let direct_writers = direct_carrier.then(|| self.direct_writers.clone());
            let replies = self.replies.clone();
            let admitted = grant.clone();
            let task = self.tasks.spawn(async move {
                let _ = async {
                    let tcp = match permit.during(lan.tcp(key.destination.port())).await? {
                        Ok(tcp) => tcp,
                        Err(error) => {
                            if error
                                .downcast_ref::<std::io::Error>()
                                .is_some_and(|reason| {
                                    reason.kind() == std::io::ErrorKind::ConnectionRefused
                                })
                            {
                                let reset = porthub_network::tcp_stream::reject_syn(&bytes)?;
                                let _ = replies.try_send((admitted.peer.clone(), reset, permit));
                            }
                            return Err(error);
                        }
                    };
                    let pending = stack
                        .prepare_forward_syn(bytes, permit, direct_carrier)
                        .await?;
                    publish.send_replace(Some(pending.ingress()));
                    let conn = pending.established().await?;
                    publish.send_replace(Some(conn.ingress()));
                    tcp_bridge(conn, tcp, admitted, direct_writers.as_deref()).await
                }
                .await;
            });
            self.tcp.insert(key, Active { route, grant, task });
        } else {
            let Some((key, body)) = udp_payload(&bytes) else {
                return;
            };
            if let Some(flow) = self.udp.get(&key) {
                if flow.grant.peer == grant.peer && flow.usable() {
                    let _ = flow.route.try_send((body, permit));
                }
                return;
            }
            if full {
                return;
            }
            let (route, recv) = mpsc::channel(16);
            let _ = route.try_send((body, permit.clone()));
            let lan = lan.clone();
            let replies = self.replies.clone();
            let admitted = grant.clone();
            let task = self.tasks.spawn(async move {
                let _ = udp_bridge(lan, key, admitted, permit, recv, replies).await;
            });
            self.udp.insert(key, Active { route, grant, task });
        }
    }
    pub(super) fn tcp_egress(&self, pkt: &tagged::Packet) -> Option<(String, SendPermit)> {
        let key = Flow::from_packet(pkt.bytes())?.reverse();
        let flow = self.tcp.get(&key)?;
        if !flow.route.borrow().as_ref()?.owns_packet(pkt) {
            return None;
        }
        Some((flow.grant.peer.clone(), flow.grant.current()?))
    }
}
async fn tcp_bridge(
    conn: tagged::Connection,
    tcp: tokio::net::TcpStream,
    grant: Admission,
    direct_writers: Option<&tokio::sync::Semaphore>,
) -> Result<()> {
    tcp.set_nodelay(true)?;
    let (read, mut write) = tcp.into_split();
    let to_lan = async {
        loop {
            let chunk = conn.read_chunk().await?;
            ensure!(conn.owns_read(&chunk), "virtual host TCP ingress changed");
            let eof = chunk.eof();
            let permit = grant.current().context("virtual host access ended")?;
            let writer = &mut write;
            chunk
                .deliver(|data, finish| async move {
                    permit
                        .during(async {
                            writer.write_all(&data).await?;
                            if finish {
                                writer.shutdown().await?;
                            }
                            anyhow::Ok(())
                        })
                        .await?
                })
                .await?;
            if eof {
                return anyhow::Ok(());
            }
        }
    };
    let to_mesh = forward_reads(&conn, &read, &grant, direct_writers);
    let renew = async {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            conn.renew_control(grant.current().context("virtual host access ended")?)
                .await?;
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    tokio::select! {
        result=async{tokio::try_join!(to_lan,to_mesh)}=>{result?;}
        result=renew=>result?,
    }
    conn.close().await
}
/// Bytes read while the preceding TCP window awaits acknowledgement retain
/// their own original authority. At most one window can wait behind the writer.
// Growing readers share a process-wide allowance. An idle connection starts
// with an 8KiB read and the extra capacity stays charged until its bytes retire.
static READ_CAPACITY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8192);
struct ReadStorage {
    data: Vec<u8>,
    _credit: Option<tokio::sync::SemaphorePermit<'static>>,
}
impl AsRef<[u8]> for ReadStorage {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}
struct LanRead {
    storage: ReadStorage,
    used: usize,
    eof: bool,
    permit: Option<SendPermit>,
}

impl LanRead {
    fn new(desired: usize) -> Self {
        let mut size = desired;
        let credit = loop {
            if size <= 8192 {
                break None;
            }
            if let Ok(credit) = READ_CAPACITY.try_acquire_many((size / 8192 - 1) as u32) {
                break Some(credit);
            }
            size /= 2;
        };
        Self {
            storage: ReadStorage {
                data: vec![0; size],
                _credit: credit,
            },
            used: 0,
            eof: false,
            permit: None,
        }
    }

    fn read_ready(
        &mut self,
        socket: &tokio::net::tcp::OwnedReadHalf,
        grant: &Admission,
    ) -> Result<()> {
        let permit = self
            .permit
            .clone()
            .or_else(|| grant.current())
            .context("virtual host access ended")?;
        ensure!(permit.valid(), "virtual host LAN read expired");
        match socket.try_read(&mut self.storage.data[self.used..]) {
            Ok(n) => {
                self.eof = n == 0;
                self.used += n;
                self.permit = Some(permit);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

async fn forward_reads(
    conn: &tagged::Connection,
    socket: &tokio::net::tcp::OwnedReadHalf,
    grant: &Admission,
    direct_writers: Option<&tokio::sync::Semaphore>,
) -> Result<()> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut offset = 0;
    let initial_capacity = if direct_writers.is_some() {
        8192
    } else {
        64 * 1024
    };
    let mut batch = LanRead::new(initial_capacity);
    let mut prior_ack = Duration::ZERO;
    loop {
        while batch.permit.is_none() {
            socket.readable().await?;
            batch.read_ready(socket, grant)?;
        }
        let permit = batch.permit.take().context("missing LAN admission")?;
        let n = batch.used;
        let capacity = batch.storage.data.len();
        if n == 0 {
            let ack = conn.finish(id, offset, permit).await?;
            conn.publish_receipt(ack, id, offset, 0, || async { Ok(()) })
                .await?;
            return Ok(());
        }
        // Share the datagram flight window between currently sending flows.
        // Idle TCP connections consume neither window nor writer slot.
        let _writer = direct_writers
            .map(|slots| slots.try_acquire())
            .transpose()?;
        let read_limit = direct_writers.map_or(tagged::FORWARD_WINDOW, |slots| {
            tagged::DIRECT_FORWARD_WINDOW
                / (FLOW_LIMIT - slots.available_permits()).next_power_of_two()
        });
        let next_size = if n == capacity && prior_ack < Duration::from_secs(1) {
            capacity * 2
        } else if prior_ack > Duration::from_secs(2) {
            (capacity / 2).max(8192)
        } else {
            capacity
        }
        .min(read_limit);
        batch.storage.data.truncate(n);
        let mut next = LanRead::new(next_size);
        // EOF observed while filling a partial window follows its bytes under
        // the same immutable admission.
        if batch.eof {
            next.eof = true;
            next.permit = Some(permit.clone());
        }
        let bytes = Bytes::from_owner(batch.storage);
        let started = std::time::Instant::now();
        let send = async move {
            let ack = conn.write_window(id, offset, bytes, permit).await?;
            conn.publish_receipt(ack, id, offset, n, || async { Ok(()) })
                .await
        };
        tokio::pin!(send);
        loop {
            tokio::select! {
                biased;
                result=&mut send=>{result?;break;}
                result=socket.readable(), if !next.eof && next.used<next.storage.data.len()=>{
                    result?;
                    next.read_ready(socket,grant)?;
                }
            }
        }
        prior_ack = started.elapsed();
        offset += n as u64;
        batch = next;
    }
}
fn udp_payload(bytes: &Bytes) -> Option<(Flow, Bytes)> {
    let ip = Ipv4Packet::new_checked(bytes.as_ref()).ok()?;
    if ip.next_header() != IpProtocol::Udp
        || ip.total_len() as usize != bytes.len()
        || !ip.verify_checksum()
        || ip.more_frags()
        || ip.frag_offset() != 0
    {
        return None;
    }
    let udp = UdpPacket::new_checked(ip.payload()).ok()?;
    let src = ip.src_addr();
    let dst = ip.dst_addr();
    if usize::from(udp.len()) != ip.payload().len()
        || udp.src_port() == 0
        || udp.dst_port() == 0
        || (udp.checksum() != 0 && !udp.verify_checksum(&src.into(), &dst.into()))
    {
        return None;
    }
    Some((
        Flow {
            source: SocketAddrV4::new(src, udp.src_port()),
            destination: SocketAddrV4::new(dst, udp.dst_port()),
        },
        bytes.slice(usize::from(ip.header_len()) + 8..),
    ))
}
fn udp_frame(flow: Flow, body: &[u8]) -> Bytes {
    let len = 28 + body.len();
    let mut bytes = vec![0; len];
    let mut ip = Ipv4Packet::new_unchecked(&mut bytes[..]);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(len as u16);
    ip.set_hop_limit(64);
    ip.set_next_header(IpProtocol::Udp);
    let src = *flow.source.ip();
    let dst = *flow.destination.ip();
    ip.set_src_addr(src);
    ip.set_dst_addr(dst);
    ip.fill_checksum();
    let mut udp = UdpPacket::new_unchecked(ip.payload_mut());
    udp.set_len((8 + body.len()) as u16);
    udp.set_src_port(flow.source.port());
    udp.set_dst_port(flow.destination.port());
    udp.payload_mut().copy_from_slice(body);
    udp.fill_checksum(&src.into(), &dst.into());
    bytes.into()
}
async fn udp_bridge(
    lan: Lan,
    key: Flow,
    grant: Admission,
    opening: SendPermit,
    mut input: mpsc::Receiver<Datagram>,
    output: mpsc::Sender<Reply>,
) -> Result<()> {
    let socket = opening.during(lan.udp(key.destination.port())).await??;
    let mut buffer = [0; MAX_PACKET - 28 + 1];
    loop {
        tokio::select! {
            _=tokio::time::sleep(Duration::from_secs(30))=>return Ok(()),
            message=input.recv()=>{
                let Some((body,original))=message else{return Ok(())};
                let permit=SendPermit::combine(vec![original,grant.current().context("virtual host access ended")?]);
                permit.during(socket.send(&body)).await??;
            }
            result=socket.readable()=>{
                result?;
                let permit=grant.current().context("virtual host access ended")?;
                match socket.try_recv(&mut buffer){
                    Ok(n) if n<buffer.len()=>{let _=output.try_send((grant.peer.clone(),udp_frame(key.reverse(),&buffer[..n]),permit));}
                    Err(e) if e.kind()!=std::io::ErrorKind::WouldBlock=>return Err(e.into()),
                    _=>{}
                }
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_reply_preserves_virtual_endpoints_and_detects_corruption() {
        let flow = Flow {
            source: "10.203.1.6:53".parse().unwrap(),
            destination: "10.203.1.8:40401".parse().unwrap(),
        };
        let packet = udp_frame(flow, b"answer");
        let (parsed, body) = udp_payload(&packet).unwrap();
        assert_eq!(parsed, flow);
        assert_eq!(&body[..], b"answer");
        let mut changed = packet.to_vec();
        *changed.last_mut().unwrap() ^= 1;
        assert!(udp_payload(&changed.into()).is_none());
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "flow_tests.rs"]
mod flow_tests;
