//! Transparent TCP to an authorized SSH profile. The only dial is the
//! profile-scoped authenticated gateway endpoint; the caller supplies a port.
use super::{Names, Scope};
use crate::private_network::{controller::Event, device::Tun};
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use porthub_mesh::udp::SendPermit;
use porthub_network::tcp_stream::{self, tagged, Flow};
use std::{collections::HashMap, future::poll_fn, net::Ipv4Addr, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    sync::{mpsc, watch},
    task::{AbortHandle, JoinSet},
};
use tokio_util::sync::CancellationToken;
const MAX_FLOWS: usize = 64;
pub(crate) enum Reply {
    Packet(tagged::Packet),
    Reset(Bytes, SendPermit),
}
struct Active {
    scope: Scope,
    ingress: watch::Receiver<Option<tagged::Ingress>>,
    task: AbortHandle,
}
impl Drop for Active {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(in crate::private_network) struct Native {
    names: Names,
    stack: tagged::Handle,
    events: mpsc::Sender<Event>,
    flows: HashMap<Flow, Active>,
    tasks: JoinSet<()>,
}
impl Native {
    pub(in crate::private_network) fn new(
        names: Names,
        events: mpsc::Sender<Event>,
        stop: CancellationToken,
    ) -> Result<Self> {
        // The stack's timer only runs when it owns an active TCP tuple.
        let (stack, mut output, runner) = tagged::forwarding_stack()?;
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let _ = runner.run(stop).await;
        });
        let sender = events.clone();
        tasks.spawn(async move {
            while let Some(packet) = output.recv().await {
                if sender
                    .send(Event::ForwardLocal(Reply::Packet(packet)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Self {
            names,
            stack,
            events,
            flows: HashMap::new(),
            tasks,
        })
    }
    pub(in crate::private_network) fn packet(
        &mut self,
        own: Option<Ipv4Addr>,
        destination: Ipv4Addr,
        bytes: &[u8],
    ) -> bool {
        let Some(scope) = self.names.target(destination) else {
            return false;
        };
        let Some(flow) = Flow::from_packet(bytes) else {
            return true;
        };
        if Some(*flow.source.ip()) != own {
            return true;
        }
        let Some(permit) = scope.current() else {
            return true;
        };
        if !scope.allows(flow.destination.port()) {
            if let Ok(reply) = tcp_stream::reject_syn(bytes) {
                let _ = self
                    .events
                    .try_send(Event::ForwardLocal(Reply::Reset(reply, permit)));
            }
            return true;
        }
        self.flows.retain(|_, f| {
            !f.task.is_finished()
                && !f.scope.entry.stop.is_cancelled()
                && !f.scope.capture.is_cancelled()
                && !f.scope.g.stop.is_cancelled()
        });
        while self.tasks.try_join_next().is_some() {}
        if let Some(active) = self.flows.get(&flow) {
            if let Some(ingress) = active.ingress.borrow().as_ref() {
                let _ = ingress.input(Bytes::copy_from_slice(bytes), permit);
            }
            return true;
        }
        if self.flows.len() >= MAX_FLOWS || tagged::validate_syn(bytes).is_err() {
            return true;
        }
        let stack = self.stack.clone();
        let events = self.events.clone();
        let syn = Bytes::copy_from_slice(bytes);
        let admitted = scope.clone();
        let (publish, ingress) = watch::channel(None);
        let task = self.tasks.spawn(async move {
            let run = async {
                let identity = &admitted.entry.identity;
                let open = admitted.g.client.open(
                    &identity.entry_id, flow.destination.port(), identity.ports.is_empty()
                );
                let remote = match permit.during(open).await? {
                    Ok(remote) => remote,
                    Err(error) => {
                        if let Ok(reset) = tcp_stream::reject_syn(&syn) {
                            let _ = events.try_send(Event::ForwardLocal(Reply::Reset(reset, permit)));
                        }
                        return Err(error);
                    }
                };
                let pending = stack.prepare_syn(syn, permit).await?;
                publish.send_replace(Some(pending.ingress()));
                let conn = pending.established().await?;
                publish.send_replace(Some(conn.ingress()));
                bridge(conn, remote, &admitted).await
            };
            tokio::select! {
                biased;
                _ = admitted.g.stop.cancelled() => {},
                _ = admitted.entry.stop.cancelled() => {},
                _ = admitted.capture.cancelled() => {},
                result = run => { if let Err(error) = result {
                    tracing::debug!(port=flow.destination.port(), %error, "private SSH host flow closed");
                } }
            }
        });
        self.flows.insert(
            flow,
            Active {
                scope,
                ingress,
                task,
            },
        );
        true
    }
    pub(in crate::private_network) async fn deliver(
        &self,
        reply: Reply,
        tun: &Tun,
        own: Ipv4Addr,
    ) -> Result<()> {
        self.deliver_with(reply, own, |bytes| async move { tun.write(&bytes).await })
            .await
    }
    pub(super) async fn deliver_with<F: std::future::Future<Output = Result<()>>>(
        &self,
        reply: Reply,
        own: Ipv4Addr,
        write: impl FnOnce(Bytes) -> F,
    ) -> Result<()> {
        match reply {
            Reply::Packet(packet) => {
                if !packet.valid() {
                    return Ok(());
                }
                let Some(flow) = Flow::from_packet(packet.bytes())
                    .map(Flow::reverse)
                    .filter(|f| *f.source.ip() == own)
                else {
                    return Ok(());
                };
                if !self.flows.get(&flow).is_some_and(|active| {
                    active
                        .ingress
                        .borrow()
                        .as_ref()
                        .is_some_and(|r| r.owns_packet(&packet))
                }) {
                    return Ok(());
                }
                let result = packet.deliver(write).await;
                if packet.valid() {
                    result?;
                }
            }
            Reply::Reset(bytes, permit) => {
                if permit.valid()
                    && Flow::from_packet(&bytes).is_some_and(|flow| *flow.destination.ip() == own)
                {
                    let result = permit.during(write(bytes)).await;
                    if permit.valid() {
                        result??;
                    }
                }
            }
        }
        Ok(())
    }
}
async fn bridge(
    conn: tagged::Connection,
    remote: porthub_egress::BoxStream,
    scope: &Scope,
) -> Result<()> {
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
    let to_remote = async {
        loop {
            let chunk = conn.read_chunk().await?;
            ensure!(conn.owns_read(&chunk), "SSH host flow changed");
            let finish = chunk.eof();
            let writer = &mut remote_write;
            chunk
                .deliver(|bytes, eof| async move {
                    writer.write_all(&bytes).await?;
                    if eof {
                        writer.shutdown().await?;
                    }
                    Ok(())
                })
                .await?;
            if finish {
                return anyhow::Ok(());
            }
        }
    };
    let to_native = async {
        let id = *uuid::Uuid::new_v4().as_bytes();
        let mut offset = 0u64;
        let mut buffer = vec![0u8; 65536];
        loop {
            // Capture authority at the actual read, including after a wake from
            // backpressure. A later control refresh cannot extend these bytes.
            let (n, permit) = poll_fn(|cx| {
                let permit = scope.current().context("SSH host access ended")?;
                let mut read = ReadBuf::new(&mut buffer);
                std::task::ready!(Pin::new(&mut remote_read).poll_read(cx, &mut read))?;
                std::task::Poll::Ready(anyhow::Ok((read.filled().len(), permit)))
            })
            .await?;
            let ack = if n == 0 {
                conn.finish(id, offset, permit).await?
            } else {
                conn.write_window(id, offset, Bytes::copy_from_slice(&buffer[..n]), permit)
                    .await?
            };
            conn.publish_receipt(ack, id, offset, n, || async { Ok(()) })
                .await?;
            if n == 0 {
                return anyhow::Ok(());
            }
            offset = offset
                .checked_add(n as u64)
                .context("SSH stream length overflow")?;
        }
    };
    let renew = async {
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            conn.renew_control(scope.current().context("SSH host access ended")?)
                .await?;
        }
        #[allow(unreachable_code)]
        anyhow::Ok(())
    };
    tokio::select! {result=async{tokio::try_join!(to_remote,to_native)}=>{result?;},result=renew=>result?,}
    conn.close().await
}
