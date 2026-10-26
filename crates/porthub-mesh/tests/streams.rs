#![cfg(feature = "streams")]
use anyhow::{ensure, Context, Result};
use porthub_mesh::{
    streams::{Datagram, Endpoint, PacketIo, Peer},
    Identity,
};
use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_util::sync::CancellationToken;

const STRIPE_BURST: u64 = 64;

struct Frame {
    from_a: bool,
    datagram: Datagram,
}
struct Wire {
    active: Arc<AtomicUsize>,
    drop_next: Arc<AtomicUsize>,
    counts: [Arc<AtomicUsize>; 2],
    tasks: JoinSet<()>,
    cancel: CancellationToken,
}
impl Wire {
    fn new(a: PacketIo, b: PacketIo, a_ip: Ipv4Addr, b_ip: Ipv4Addr) -> Self {
        Self::with_striping(a, b, a_ip, b_ip, false)
    }
    fn with_striping(
        mut a: PacketIo,
        mut b: PacketIo,
        a_ip: Ipv4Addr,
        b_ip: Ipv4Addr,
        striped: bool,
    ) -> Self {
        let active = Arc::new(AtomicUsize::new(0));
        let drop_next = Arc::new(AtomicUsize::new(0));
        let counts = [Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0))];
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let a_in = a.ingress();
        let b_in = b.ingress();
        let mut paths = Vec::new();
        for index in 0..2 {
            let (send, mut receive) = mpsc::channel::<Frame>(32768);
            paths.push(send);
            let active = active.clone();
            let drop_next = drop_next.clone();
            let count = counts[index].clone();
            let a_in = a_in.clone();
            let b_in = b_in.clone();
            let stop = cancel.clone();
            tasks.spawn(async move { let mut sequence = 0u64; loop {tokio::select! {
                _=stop.cancelled()=>return,
                frame=receive.recv()=>{
                    let Some(frame)=frame else {return;};
                    count.fetch_add(1,Ordering::Relaxed);
                    if striped {
                        if index == 1 && sequence % STRIPE_BURST == 0 {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                        sequence += 1;
                    } else if active.load(Ordering::Acquire)!=index {continue;}
                    if drop_next.try_update(Ordering::AcqRel,Ordering::Acquire,|left|left.checked_sub(1)).is_ok() {continue;}
                    if frame.from_a {
                        assert_eq!(frame.datagram.address,b_ip);let _=b_in.send(a_ip,frame.datagram.payload);
                    } else {
                        assert_eq!(frame.datagram.address,a_ip);let _=a_in.send(b_ip,frame.datagram.payload);
                    }
                }
            }} });
        }
        let route = active.clone();
        let stop = cancel.clone();
        tasks.spawn(async move {let mut a_sequence=0u64;loop {tokio::select! {
            _=stop.cancelled()=>return,
            datagram=a.outgoing()=>{let Some(datagram)=datagram else{return;};let _=paths[if striped {let lane=(a_sequence/STRIPE_BURST%2) as usize;a_sequence+=1;lane} else {route.load(Ordering::Acquire)}].try_send(Frame {from_a:true,datagram});},
            datagram=b.outgoing()=>{let Some(datagram)=datagram else{return;};let _=paths[if striped {0} else {route.load(Ordering::Acquire)}].try_send(Frame {from_a:false,datagram});},
        }} });
        Self {
            active,
            drop_next,
            counts,
            tasks,
            cancel,
        }
    }
    async fn stop(mut self) {
        self.cancel.cancel();
        while let Some(task) = self.tasks.join_next().await {
            task.unwrap();
        }
    }
}
fn peer(id: &str, ip: Ipv4Addr, identity: &Identity) -> Peer {
    Peer {
        id: id.into(),
        ip,
        fingerprint: identity.fingerprint().into(),
        instance: format!("{id}-instance"),
    }
}

#[tokio::test]
async fn reliable_stream_survives_carrier_change_and_packet_loss_without_reconnecting() -> Result<()>
{
    transfer_with_wire(false).await
}

#[tokio::test]
async fn reliable_stream_survives_bursts_on_independently_delayed_carriers() -> Result<()> {
    transfer_with_wire(true).await
}

#[tokio::test]
async fn active_peer_scales_to_eight_bounded_congestion_lanes() -> Result<()> {
    let a_ip = Ipv4Addr::new(10, 234, 250, 1);
    let b_ip = Ipv4Addr::new(10, 234, 250, 2);
    let a_identity = Identity::new()?;
    let b_identity = Identity::new()?;
    let (a, a_io) = Endpoint::new(a_identity.clone(), a_ip)?;
    let (b, b_io) = Endpoint::new(b_identity.clone(), b_ip)?;
    let b_peer = peer("b", b_ip, &b_identity);
    let a_peer = peer("a", a_ip, &a_identity);
    a.update_peers(vec![b_peer.clone()])?;
    b.update_peers(vec![a_peer.clone()])?;
    let wire = Wire::new(a_io, b_io, a_ip, b_ip);
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let (_source, accepted) = tokio::try_join!(a.connect(&b_peer), b.accept())?;
        let (remote, first) = accepted;
        ensure!(remote.id == "a");
        let mut target_lanes = vec![first];
        for _ in 1..8 {
            let (source, accepted) = tokio::try_join!(a.connect_additional(&b_peer), b.accept())?;
            let (remote, target) = accepted;
            ensure!(remote.id == "a");
            ensure!(source.stable_id() != 0);
            target_lanes.push(target);
        }
        ensure!(a.connection_count(&b_peer) == 8);
        ensure!(b.connection_count(&a_peer) == 8);

        let source_lanes: Vec<_> = (0..8)
            .map(|_| a.prepared(&b_peer).expect("prepared lane"))
            .collect();
        let selected: Vec<_> = source_lanes.iter().map(|lane| lane.stable_id()).collect();
        ensure!(selected.iter().copied().collect::<HashSet<_>>().len() == 8);
        ensure!(
            a.connect_additional(&b_peer).await.is_err(),
            "per-peer connection bound was not enforced"
        );

        let mut readers = JoinSet::new();
        for target in target_lanes {
            readers.spawn(async move {
                let (mut send, mut receive) = target.accept_bi().await?;
                let body = receive.read_to_end(64).await?;
                send.write_all(&body).await?;
                send.finish()?;
                Ok::<_, anyhow::Error>(body)
            });
        }
        for (index, connection) in source_lanes.iter().enumerate() {
            let body = format!("lane-{index}").into_bytes();
            let (mut send, mut receive) = connection.open_bi().await?;
            send.write_all(&body).await?;
            send.finish()?;
            ensure!(receive.read_to_end(64).await? == body);
        }
        for _ in 0..8 {
            let received = readers
                .join_next()
                .await
                .context("lane reader stopped")???;
            ensure!(received.starts_with(b"lane-"));
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("bounded private lane test timed out")?;
    a.close();
    b.close();
    wire.stop().await;
    result
}

async fn transfer_with_wire(striped: bool) -> Result<()> {
    let a_ip = Ipv4Addr::new(10, 234, 251, 1);
    let b_ip = Ipv4Addr::new(10, 234, 251, 2);
    let a_identity = Identity::new()?;
    let b_identity = Identity::new()?;
    let (a, a_io) = Endpoint::new(a_identity.clone(), a_ip)?;
    let (b, b_io) = Endpoint::new(b_identity.clone(), b_ip)?;
    let b_peer = peer("b", b_ip, &b_identity);
    a.update_peers(vec![b_peer.clone()])?;
    b.update_peers(vec![peer("a", a_ip, &a_identity)])?;
    let wire = Wire::with_striping(a_io, b_io, a_ip, b_ip, striped);
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        let (source, destination) = tokio::try_join!(a.connect(&b_peer), b.accept())?;
        let (remote, destination) = destination;
        ensure!(remote.id == "a");
        let original = (source.stable_id(), destination.stable_id());
        let payload: Vec<_> = (0..if striped {
            16 * 1024 * 1024
        } else {
            4 * 1024 * 1024
        })
            .map(|i| (i % 251) as u8)
            .collect();
        let (mut send, mut receive) = source.open_bi().await?;
        let sending = async {
            send.write_all(&payload).await?;
            send.finish()?;
            let reply = receive.read_to_end(16).await?;
            ensure!(reply == b"received");
            Ok::<_, anyhow::Error>(())
        };
        let receiving = async {
            let (mut send, mut receive) = destination.accept_bi().await?;
            let mut offset = 0;
            let mut switched = false;
            while let Some(chunk) = receive.read_chunk(65536, true).await? {
                ensure!(offset + chunk.bytes.len() <= payload.len());
                ensure!(chunk.bytes.as_ref() == &payload[offset..offset + chunk.bytes.len()]);
                offset += chunk.bytes.len();
                if offset >= 65536 && !switched && !striped {
                    wire.drop_next.store(5, Ordering::Release);
                    wire.active.store(1, Ordering::Release);
                    switched = true;
                }
            }
            ensure!(offset == payload.len());
            send.write_all(b"received").await?;
            send.finish()?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(sending, receiving)?;
        ensure!((source.stable_id(), destination.stable_id()) == original);
        ensure!(wire
            .counts
            .iter()
            .all(|count| count.load(Ordering::Relaxed) > 0));
        a.update_peers(Vec::new())?;
        ensure!(source.close_reason().is_some());
        let _ = destination.closed().await;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("private stream path-change test timed out")?;
    a.close();
    b.close();
    wire.stop().await;
    result
}

#[tokio::test]
async fn same_virtual_address_with_a_different_certificate_cannot_impersonate_peer() -> Result<()> {
    let a_ip = Ipv4Addr::new(10, 234, 252, 1);
    let b_ip = Ipv4Addr::new(10, 234, 252, 2);
    let a_identity = Identity::new()?;
    let b_identity = Identity::new()?;
    let impostor = Identity::new()?;
    let (a, a_io) = Endpoint::new(a_identity.clone(), a_ip)?;
    let (b, b_io) = Endpoint::new(b_identity.clone(), b_ip)?;
    let wrong_peer = peer("b", b_ip, &impostor);
    let b_peer = peer("b", b_ip, &b_identity);
    a.update_peers(vec![wrong_peer.clone()])?;
    b.update_peers(vec![peer("a", a_ip, &a_identity)])?;
    let wire = Wire::new(a_io, b_io, a_ip, b_ip);
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let (dial, accept) = tokio::join!(a.connect(&wrong_peer), b.accept());
        ensure!(
            dial.is_err() && accept.is_err(),
            "certificate identity was not enforced"
        );
        a.update_peers(vec![b_peer.clone()])?;
        ensure!(
            a.connect(&wrong_peer).await.is_err(),
            "stale fingerprint was admitted by address"
        );
        let (source, destination) = tokio::try_join!(a.connect(&b_peer), b.accept())?;
        let (_, destination) = destination;
        let mut replacement = peer("b", b_ip, &b_identity);
        replacement.instance = "replacement-instance".into();
        a.update_peers(vec![replacement])?;
        ensure!(
            source.close_reason().is_some(),
            "old peer instance retained an active stream"
        );
        let _ = destination.closed().await;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("private stream identity test timed out")?;
    a.close();
    b.close();
    wire.stop().await;
    result
}
