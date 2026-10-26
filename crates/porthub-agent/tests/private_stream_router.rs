#![cfg(feature = "private-stream")]
use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use porthub_agent::private_network::{
    controller::Event,
    policy::{Engine, Packet, Snapshot},
    stream_router::{self, Router},
    tcp_stream::{self, Flow},
};
use porthub_mesh::{control_packet, Identity};
use serde_json::json;
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddrV4},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    sync::mpsc,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
type Policy = Arc<Mutex<Engine>>;
struct Delivery {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    payload: Bytes,
}
struct Kernel {
    handle: tcp_stream::Handle,
    accepted: mpsc::Receiver<(Flow, DuplexStream)>,
}
struct Node {
    router: Router,
    events: mpsc::Receiver<Event>,
    datagrams: mpsc::Receiver<porthub_mesh::streams::Datagram>,
    kernel: tcp_stream::Handle,
    packets: mpsc::Receiver<Bytes>,
    policy: Policy,
    own: Ipv4Addr,
    other: String,
    services: HashSet<u16>,
}
fn node(
    node: Node,
    carrier: mpsc::Sender<Delivery>,
    cancel: CancellationToken,
    tasks: &mut JoinSet<Result<()>>,
) -> Kernel {
    let Node {
        router,
        mut events,
        mut datagrams,
        kernel,
        mut packets,
        policy,
        own,
        other,
        services,
    } = node;
    let handle = kernel.clone();
    let (accepted, accepting) = mpsc::channel(16);
    tasks.spawn(async move {
        let mut opening=HashSet::new();let mut children=JoinSet::new();
        loop {tokio::select! {
            _=cancel.cancelled()=>return Ok(()),
            packet=datagrams.recv()=>{
                let Some(packet)=packet else {ensure!(cancel.is_cancelled(),"stream carrier stopped");return Ok(());};
                if carrier.send(Delivery {source:own,destination:packet.address,payload:packet.payload}).await.is_err() {
                    ensure!(cancel.is_cancelled(), "test carrier stopped before cancellation");
                    return Ok(());
                }
            },
            packet=packets.recv()=>{
                let Some(packet)=packet else {ensure!(cancel.is_cancelled(),"kernel simulator stopped");return Ok(());};
                let admitted=policy.lock().unwrap().check(&packet,&other,false);
                if admitted {ensure!(router.kernel_packet(&other,packet,true),"prepared private stream unexpectedly fell back to packets");}
            },
            event=events.recv()=>match event {
                Some(Event::StreamDatagram {destination,payload})=>{
                    let envelope=control_packet::encode(control_packet::STREAM,own,destination,&payload)?;
                    let envelope=control_packet::decode(control_packet::STREAM,envelope).context("stream carrier envelope rejected")?;
                    if carrier.send(Delivery {source:envelope.source,destination:envelope.destination,payload:envelope.payload}).await.is_err() {
                        ensure!(cancel.is_cancelled(), "test carrier stopped before cancellation");
                        return Ok(());
                    }
                },
                Some(Event::StreamLocal {peer,bytes})=>{
                    ensure!(peer==other,"private peer identity changed");
                    let parsed=Packet::parse(&bytes).context("invalid local TCP packet")?;
                    ensure!(parsed.destination()==own);
                    let admitted=policy.lock().unwrap().check(&bytes,&other,true) || parsed.is_reset();
                    if !admitted {continue;}
                    let flow=Flow::from_packet(&bytes).context("invalid local TCP tuple")?;
                    let tcp=smoltcp::wire::Ipv4Packet::new_checked(bytes.as_ref()).unwrap();
                    let tcp=smoltcp::wire::TcpPacket::new_checked(tcp.payload()).unwrap();
                    if tcp.syn() && !tcp.ack() && opening.insert(flow) {
                        ensure!(services.contains(&flow.destination.port()),"unauthorized backend TCP socket was opened");
                        let kernel=kernel.clone();
                        children.spawn(async move {kernel.accept_syn(bytes).await});
                    } else {kernel.packet(bytes)?;}
                },
                None if cancel.is_cancelled()=>return Ok(()),
                _=>anyhow::bail!("unexpected private stream event"),
            },
            result=children.join_next(),if !children.is_empty()=>{
                if let Some(Ok(Ok(connection)))=result {let _=accepted.send(connection).await;}
            },
        }}
    });
    Kernel {
        handle,
        accepted: accepting,
    }
}
fn snapshot(own: &str, a: &Identity, b: &Identity) -> Snapshot {
    serde_json::from_value(json!({"workspace":"workspace","self":own,"revision":1,
        "expires_at":chrono::Utc::now()+chrono::Duration::seconds(30),
        "peers":[
            {"id":"a","ip":"10.234.253.1","fingerprint":a.fingerprint(),"instance":"instance-aaaaaaaa","hostname":"a.phub","stream_transport":"quic1"},
            {"id":"b","ip":"10.234.253.2","fingerprint":b.fingerprint(),"instance":"instance-bbbbbbbb","hostname":"b.phub","stream_transport":"quic1"}],
        "grants":[{"source":"a","destination":"b","protocol":"tcp","ports":[{"start":41000,"end":if own=="a" {41001}else{41000}}]},
                  {"source":"b","destination":"a","protocol":"tcp","ports":[{"start":41002,"end":41002}]}]})).unwrap()
}

#[tokio::test]
async fn private_router_uses_prepared_streams_enforces_ports_and_revokes_active_flows() -> Result<()>
{
    let a_ip = Ipv4Addr::new(10, 234, 253, 1);
    let b_ip = Ipv4Addr::new(10, 234, 253, 2);
    let a_identity = Identity::new()?;
    let b_identity = Identity::new()?;
    let mut a_snapshot = snapshot("a", &a_identity, &b_identity);
    let mut b_snapshot = snapshot("b", &a_identity, &b_identity);
    let a_policy: Policy = Default::default();
    let b_policy: Policy = Default::default();
    a_policy.lock().unwrap().apply(a_snapshot.clone())?;
    b_policy.lock().unwrap().apply(b_snapshot.clone())?;
    let cancel = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let (a_events, a_input) = mpsc::channel(4096);
    let (b_events, b_input) = mpsc::channel(4096);
    let (a, a_owner) =
        stream_router::new("a".into(), a_ip, a_identity, a_events, cancel.child_token())?;
    let (b, b_owner) =
        stream_router::new("b".into(), b_ip, b_identity, b_events, cancel.child_token())?;
    a.update(&a_snapshot)?;
    b.update(&b_snapshot)?;
    let (a_datagrams, a_wire) = mpsc::channel(1);
    let (b_datagrams, b_wire) = mpsc::channel(1);
    tasks.spawn(a_owner.with_carrier(a_datagrams).run());
    tasks.spawn(b_owner.with_carrier(b_datagrams).run());
    let (a_kernel, a_packets, a_runner) = tcp_stream::stack()?;
    let (b_kernel, b_packets, b_runner) = tcp_stream::stack()?;
    tasks.spawn(a_runner.run(cancel.clone()));
    tasks.spawn(b_runner.run(cancel.clone()));
    let (carrier, mut deliveries) = mpsc::channel::<Delivery>(4096);
    let mut a_node = node(
        Node {
            router: a.clone(),
            events: a_input,
            datagrams: a_wire,
            kernel: a_kernel,
            packets: a_packets,
            policy: a_policy.clone(),
            own: a_ip,
            other: "b".into(),
            services: HashSet::from([41002]),
        },
        carrier.clone(),
        cancel.clone(),
        &mut tasks,
    );
    let mut b_node = node(
        Node {
            router: b.clone(),
            events: b_input,
            datagrams: b_wire,
            kernel: b_kernel,
            packets: b_packets,
            policy: b_policy.clone(),
            own: b_ip,
            other: "a".into(),
            services: HashSet::from([41000]),
        },
        carrier,
        cancel.clone(),
        &mut tasks,
    );
    let dropped = Arc::new(AtomicUsize::new(0));
    let drop_packets = dropped.clone();
    let stop = cancel.clone();
    let a_in = a.clone();
    let b_in = b.clone();
    tasks.spawn(async move {loop {tokio::select! {
        _=stop.cancelled()=>return Ok(()),
        delivery=deliveries.recv()=>{
            let Some(delivery)=delivery else {return Ok(());};
            if drop_packets.try_update(Ordering::AcqRel,Ordering::Acquire,|left|left.checked_sub(1)).is_ok(){continue;}
            if delivery.destination==a_ip {a_in.receive(delivery.source,delivery.payload).await;} else {ensure!(delivery.destination==b_ip);b_in.receive(delivery.source,delivery.payload).await;}
        }
    }}});
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        while !a.prepared("b") || !b.prepared("a") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let flow = Flow {
            source: SocketAddrV4::new(a_ip, 35001),
            destination: SocketAddrV4::new(b_ip, 41000),
        };
        let mut source = a_node.handle.connect(flow).await?;
        let (accepted, mut target) = b_node
            .accepted
            .recv()
            .await
            .context("target backend was not opened")?;
        ensure!(accepted == flow);
        let mib = std::env::var("PORTHUB_TEST_PAYLOAD_MIB")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 128);
        let payload: Vec<_> = (0..mib * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let started = std::time::Instant::now();
        let sending = async {
            source.write_all(&payload).await?;
            let mut reply = [0; 2];
            source.read_exact(&mut reply).await?;
            ensure!(&reply == b"ok");
            Ok::<_, anyhow::Error>(())
        };
        let receiving = async {
            let mut received = vec![0; payload.len()];
            target.read_exact(&mut received[..65536]).await?;
            dropped.store(5, Ordering::Release);
            target.read_exact(&mut received[65536..]).await?;
            ensure!(received == payload);
            target.write_all(b"ok").await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(sending, receiving)?;
        if mib > 1 {
            eprintln!(
                "Local stream diagnostic: {:.2} MB/s",
                payload.len() as f64 / started.elapsed().as_secs_f64() / 1_000_000.0
            );
        }

        let refused = Flow {
            source: SocketAddrV4::new(a_ip, 35002),
            destination: SocketAddrV4::new(b_ip, 41001),
        };
        if let Ok(mut denied) = a_node.handle.connect(refused).await {
            let mut byte = [0];
            ensure!(
                denied.read(&mut byte).await? == 0,
                "target's stricter port policy was bypassed"
            );
        }
        let reverse = Flow {
            source: SocketAddrV4::new(b_ip, 35003),
            destination: SocketAddrV4::new(a_ip, 41002),
        };
        let mut reverse_source = b_node.handle.connect(reverse).await?;
        let (accepted, mut reverse_target) = a_node
            .accepted
            .recv()
            .await
            .context("reverse target backend was not opened")?;
        ensure!(accepted == reverse);
        reverse_source.write_all(b"reverse").await?;
        let mut response = [0; 7];
        reverse_target.read_exact(&mut response).await?;
        ensure!(&response == b"reverse");

        a_snapshot.revision += 1;
        a_snapshot.grants.clear();
        b_snapshot.revision += 1;
        b_snapshot.grants.clear();
        a_policy.lock().unwrap().apply(a_snapshot.clone())?;
        b_policy.lock().unwrap().apply(b_snapshot.clone())?;
        a.update(&a_snapshot)?;
        b.update(&b_snapshot)?;
        let mut eof = [0; 1];
        ensure!(source.read(&mut eof).await? == 0);
        ensure!(target.read(&mut eof).await? == 0);
        ensure!(reverse_source.read(&mut eof).await? == 0);
        ensure!(reverse_target.read(&mut eof).await? == 0);
        ensure!(!a.prepared("b") && !b.prepared("a"));
        Ok::<_, anyhow::Error>(())
    })
    .await;
    cancel.cancel();
    let mut failure = None;
    while let Some(task) = tasks.join_next().await {
        if let Err(error) = task? {
            failure = Some(error);
        }
    }
    if let Some(error) = failure {
        return Err(error);
    }
    result.context("private stream integration timed out")?
}
