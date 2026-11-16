use super::super::{
    flow_authority::{LocalAuthority, Side},
    flow_open, source,
};
use super::*;
use porthub_mesh::{
    streams::{BoundedSourceConnection, CreditedReceiverConnection, Endpoint},
    Identity,
};
use porthub_network::tcp_stream;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{timeout, Duration},
};

struct Link {
    client: BoundedSourceConnection,
    server: Option<CreditedReceiverConnection>,
    source: Arc<Endpoint>,
    destination: Arc<Endpoint>,
    stop: CancellationToken,
    pump: JoinHandle<Result<()>>,
}
impl Drop for Link {
    fn drop(&mut self) {
        self.stop.cancel();
        self.source.close();
        self.destination.close();
    }
}
async fn forward_carrier(
    datagram: porthub_mesh::streams::Datagram,
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    key: carrier::Key,
    ingress: &porthub_mesh::streams::Ingress,
) -> Result<()> {
    let frame = carrier::Frame::new(key, datagram.payload)?.encode();
    let wire = porthub_mesh::control_packet::encode(
        porthub_mesh::control_packet::STREAM,
        source,
        destination,
        &frame,
    )?;
    ensure!(
        wire.len() <= porthub_mesh::MAX_PACKET,
        "origin carrier exceeded existing native packet bound"
    );
    let envelope = porthub_mesh::control_packet::decode(porthub_mesh::control_packet::STREAM, wire)
        .ok_or_else(|| anyhow::anyhow!("carrier envelope rejected"))?;
    ensure!(
        envelope.source == source && envelope.destination == destination,
        "carrier authenticated source/target changed"
    );
    let frame = carrier::Frame::decode(envelope.payload)?;
    ensure!(
        frame.key() == key,
        "carrier endpoint nonce/direction/role changed"
    );
    ingress
        .send_reliable_guarded(source, frame.payload(), datagram.permit)
        .await
}
async fn link(
    a: Identity,
    b: Identity,
    ap: &Peer,
    bp: &Peer,
    ga: &Gate,
    gb: &Gate,
    key: carrier::Key,
) -> Result<Link> {
    let (source, mut ai) = Endpoint::new_fenced_source(a, ap.ip, ga.factory())?;
    let (destination, mut bi) = Endpoint::new_fenced_credited(b, bp.ip, gb.factory())?;
    source.update_peers(vec![bp.clone()])?;
    destination.update_peers(vec![ap.clone()])?;
    let ia = ai.ingress();
    let ib = bi.ingress();
    let aip = ap.ip;
    let bip = bp.ip;
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let pump = tokio::spawn(async move {
        loop {
            tokio::select! {_=cancel.cancelled()=>break,p=ai.outgoing()=>match p{Some(p)=>{forward_carrier(p,aip,bip,key.reverse(),&ib).await?;},None=>break},p=bi.outgoing()=>match p{Some(p)=>{forward_carrier(p,bip,aip,key,&ia).await?;},None=>break}}
        }
        Ok::<_, anyhow::Error>(())
    });
    let (source, destination) = (Arc::new(source), Arc::new(destination));
    let (c, s) = timeout(Duration::from_secs(2), async {
        tokio::join!(source.connect_source(bp), destination.accept_credited())
    })
    .await?;
    Ok(Link {
        client: c?,
        server: Some(s?),
        source,
        destination,
        stop,
        pump,
    })
}
async fn forward_native(
    ingress: &flow_open::NativeIngress,
    packet: &tagged::Packet,
    target: &tcp_stream::Handle,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel(1);
    ingress.publish(packet.clone(), &tx).await?;
    let event = rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("native event queue closed"))?;
    let crate::private_network::controller::Event::GuardedStreamLocal { peer, packet } = event
    else {
        anyhow::bail!("native output lost sealed event type")
    };
    ensure!(
        !peer.is_empty() && packet.remaining().is_some(),
        "native event lost peer/original bound"
    );
    let target = target.clone();
    packet
        .deliver(|bytes| async move { target.packet(bytes) })
        .await
}
struct Native {
    owner: flow_open::NativeOwner,
    connection: Arc<tagged::Connection>,
    app: tokio::io::DuplexStream,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<Result<()>>>,
    hold_ack: Arc<AtomicBool>,
}
impl Drop for Native {
    fn drop(&mut self) {
        self.stop.cancel();
        self.connection.retire();
    }
}
async fn native_destination(
    opened: &flow_open::Opened,
    current: source::Current,
) -> Result<Native> {
    let (handle, mut output, runner) = tagged::stack()?;
    let (peer, mut input, peer_runner) = tcp_stream::stack()?;
    let stop = CancellationToken::new();
    let a = tokio::spawn(runner.run(stop.clone()));
    let b = tokio::spawn(peer_runner.run(stop.clone()));
    let opening = opened.prepare_destination(&handle).await?;
    let ingress = opening.ingress(current.clone())?;
    let syn = timeout(Duration::from_secs(1), output.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("destination SYN missing"))?;
    let (tx, mut rx) = mpsc::channel(1);
    ingress.publish(syn, &tx).await?;
    let crate::private_network::controller::Event::GuardedStreamLocal { packet: syn, .. } =
        rx.recv().await.unwrap()
    else {
        anyhow::bail!("SYN lost origin event")
    };
    let other = peer.clone();
    let accepting = tokio::spawn(async move {
        syn.deliver(|bytes| async move { other.accept_syn(bytes).await })
            .await
    });
    ingress.input(
        timeout(Duration::from_secs(1), input.recv())
            .await?
            .unwrap(),
    )?;
    let ack = timeout(Duration::from_secs(1), output.recv())
        .await?
        .unwrap();
    forward_native(&ingress, &ack, &peer).await?;
    let owner = timeout(Duration::from_secs(1), opening.established()).await??;
    let (_, _, connection) = owner.parts();
    let ingress = owner.ingress(current)?;
    let (_, app) = accepting.await??;
    let cancel = stop.clone();
    let hold_ack = Arc::new(AtomicBool::new(false));
    let hold = hold_ack.clone();
    let pump = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            tokio::select! {
                _=cancel.cancelled()=>break,
                p=output.recv()=>match p{Some(p)=>{let result=forward_native(&ingress,&p,&peer).await;if p.valid(){result?;}},None=>break},
                p=input.recv()=>match p{Some(p)=>{if hold.load(Ordering::SeqCst){ensure!(held.len()<32,"held native ACK fixture bound");held.push(p);}else{ingress.input(p)?;}},None=>break}
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    Ok(Native {
        owner,
        connection,
        app,
        stop,
        tasks: vec![a, b, pump],
        hold_ack,
    })
}

struct PendingSource {
    syn: flow_authority::PendingSyn,
    handle: tagged::Handle,
    user: tcp_stream::Handle,
    output: tokio::sync::mpsc::Receiver<tagged::Packet>,
    input: tokio::sync::mpsc::Receiver<Bytes>,
    stop: CancellationToken,
    tasks: Vec<JoinHandle<Result<()>>>,
    connecting: JoinHandle<Result<tokio::io::DuplexStream>>,
}
async fn prepare_source(local: &LocalAuthority, flow: tcp_stream::Flow) -> Result<PendingSource> {
    let (handle, output, runner) = tagged::stack()?;
    let (user, mut input, user_runner) = tcp_stream::stack()?;
    let stop = CancellationToken::new();
    let a = tokio::spawn(runner.run(stop.clone()));
    let b = tokio::spawn(user_runner.run(stop.clone()));
    let source = user.clone();
    let connecting = tokio::spawn(async move { source.connect(flow).await });
    let bytes = timeout(Duration::from_secs(1), input.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("source SYN missing"))?;
    let syn = local.admit_syn(bytes)?;
    Ok(PendingSource {
        syn,
        handle,
        user,
        output,
        input,
        stop,
        tasks: vec![a, b],
        connecting,
    })
}
async fn accept_source(
    prepared: PendingSource,
    opened: &flow_open::Opened,
    current: source::Current,
) -> Result<Native> {
    let PendingSource {
        syn,
        handle,
        user,
        mut output,
        mut input,
        stop,
        mut tasks,
        connecting,
    } = prepared;
    let opening = opened.prepare_source(&handle, syn).await?;
    let ingress = opening.ingress(current.clone())?;
    let synack = timeout(Duration::from_secs(1), output.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("source SYNACK missing"))?;
    forward_native(&ingress, &synack, &user).await?;
    ingress.input(
        timeout(Duration::from_secs(1), input.recv())
            .await?
            .unwrap(),
    )?;
    let owner = timeout(Duration::from_secs(1), opening.established()).await??;
    let (_, _, connection) = owner.parts();
    let ingress = owner.ingress(current)?;
    let app = timeout(Duration::from_secs(1), connecting).await???;
    let cancel = stop.clone();
    let pump = tokio::spawn(async move {
        loop {
            tokio::select! {
                _=cancel.cancelled()=>break,
                p=output.recv()=>match p{Some(p)=>{let result=forward_native(&ingress,&p,&user).await;if p.valid(){result?;}},None=>break},
                p=input.recv()=>match p{Some(bytes)=>{ingress.input(bytes)?;},None=>break}
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    tasks.push(pump);
    Ok(Native {
        owner,
        connection,
        app,
        stop,
        tasks,
        hold_ack: Arc::new(AtomicBool::new(false)),
    })
}

fn source_current(local: Arc<LocalAuthority>) -> source::Current {
    Arc::new(move || Some(local.clone()))
}
fn receiver_current(
    context: flow_authority::Context,
    local: Arc<LocalAuthority>,
    side: Side,
) -> receiver::Current {
    Arc::new(move || context.receiver_access(&local, side).ok())
}
async fn exercise(revoke: bool) -> Result<()> {
    let a = Identity::new()?;
    let b = Identity::new()?;
    let ap = Peer {
        id: "a".into(),
        ip: "10.234.250.1".parse()?,
        fingerprint: a.fingerprint().into(),
        instance: "a-instance".into(),
    };
    let bp = Peer {
        id: "b".into(),
        ip: "10.234.250.2".parse()?,
        fingerprint: b.fingerprint().into(),
        instance: "b-instance".into(),
    };
    let gas = Gate::new(SendPermit::control(|| true));
    let gar = Gate::new(SendPermit::control(|| true));
    let gbs = Gate::new(SendPermit::control(|| true));
    let gbr = Gate::new(SendPermit::control(|| true));
    let (_ha, la) = flow_open::tests::local(&ap, &bp, "a")?;
    let (_hb, lb) = flow_open::tests::local(&bp, &ap, "b")?;
    let (la, lb) = (Arc::new(la), Arc::new(lb));
    let prepared = prepare_source(
        &la,
        tcp_stream::Flow {
            source: std::net::SocketAddrV4::new(ap.ip, 42000),
            destination: std::net::SocketAddrV4::new(bp.ip, 443),
        },
    )
    .await?;
    let nonce = prepared.syn.parameters().0;
    let mut ab = link(
        a.clone(),
        b.clone(),
        &ap,
        &bp,
        &gas,
        &gbr,
        carrier::Key::new(nonce, 0, carrier::Role::Source)?,
    )
    .await?;
    let mut ba = link(
        b,
        a,
        &bp,
        &ap,
        &gbs,
        &gar,
        carrier::Key::new(nonce, 1, carrier::Role::Source)?,
    )
    .await?;
    let (open_a, open_b) = tokio::try_join!(
        flow_open::initiate_native(&ab.client, &gas, &la, &prepared.syn),
        flow_open::accept_request(
            ab.server.as_mut().unwrap(),
            &gbr,
            &lb,
            carrier::Key::new(prepared.syn.parameters().0, 0, carrier::Role::Receiver)?
        )
    )?;
    let (reply_b, reply_a) = tokio::try_join!(
        flow_open::initiate_response(&ba.client, &gbs, &lb, &open_b),
        flow_open::accept_response(
            ba.server.as_mut().unwrap(),
            &gar,
            &la,
            &open_a,
            open_a.receiver_key()
        )
    )?;
    ensure!(
        open_a.context().digest() == reply_a.context().digest()
            && open_b.context().digest() == reply_b.context().digest(),
        "response bridge changed flow identity"
    );
    let context = open_a.context();
    let mut na = accept_source(prepared, &open_a, source_current(la.clone())).await?;
    let mut nb = native_destination(&open_b, source_current(lb.clone())).await?;
    nb.hold_ack.store(revoke, Ordering::SeqCst);
    // Same tuple and valid policy are insufficient: this real packet comes
    // from an independently created native stack/generation.
    let (foreign, mut foreign_output, foreign_runner) = tagged::stack()?;
    let foreign_stop = CancellationToken::new();
    let foreign_task = tokio::spawn(foreign_runner.run(foreign_stop.clone()));
    let foreign_pending = foreign
        .prepare_connect(context.source_native_tuple(Side::Initiator), la.original())
        .await?;
    let foreign_packet = timeout(Duration::from_secs(1), foreign_output.recv())
        .await?
        .unwrap();
    let own_ingress = na.owner.ingress(source_current(la.clone()))?;
    let (tx, mut rx) = mpsc::channel(1);
    ensure!(
        own_ingress.publish(foreign_packet, &tx).await.is_err() && rx.try_recv().is_err(),
        "same-tuple foreign native stack published through current owner"
    );
    drop(foreign_pending);
    foreign_stop.cancel();
    timeout(Duration::from_secs(1), foreign_task).await???;
    let budgets = [Budget::default(), Budget::default()];
    // A sealed native owner from the other endpoint cannot be relabeled.
    ensure!(
        Source::from_native(
            nb.owner.clone(),
            ab.client.clone(),
            gas.clone(),
            budgets[0].clone(),
            source_current(la.clone())
        )
        .is_err(),
        "source adopted foreign native owner"
    );
    let sa = Source::from_native(
        na.owner.clone(),
        ab.client.clone(),
        gas,
        budgets[0].clone(),
        source_current(la.clone()),
    )?;
    let sb = Source::from_native(
        nb.owner.clone(),
        ba.client.clone(),
        gbs,
        budgets[1].clone(),
        source_current(lb.clone()),
    )?;
    let ca = receiver_current(context.clone(), la.clone(), Side::Initiator);
    let cb = receiver_current(context.clone(), lb.clone(), Side::Acceptor);
    let ra = Receiver::from_native(
        na.owner.clone(),
        ba.server.take().unwrap(),
        gar,
        budgets[0].clone(),
        ca.clone(),
    )?;
    let rb = Receiver::from_native(
        nb.owner.clone(),
        ab.server.take().unwrap(),
        gbr,
        budgets[1].clone(),
        cb.clone(),
    )?;
    let mut da = Duplex::new(sa, ra, ca)?;
    let mut db = Duplex::new(sb, rb, cb)?;
    let ta = tokio::spawn(async move {
        let r = da.run().await;
        (da, r)
    });
    let tb = tokio::spawn(async move {
        let r = db.run().await;
        (db, r)
    });
    let result = timeout(Duration::from_secs(4), async {
        if revoke {
            na.app.write_all(b"native-request-body").await?;
            let mut body = [0; 19];
            nb.app.read_exact(&mut body).await?;
            ensure!(
                &body == b"native-request-body" && !ta.is_finished(),
                "native copy falsely completed source before ACK"
            );
            _ha.revoke_all();
            let (mut da, result) = timeout(Duration::from_secs(1), ta).await??;
            ensure!(
                result.is_err(),
                "revoked source published blocked native ACK receipt"
            );
            da.shutdown().await?;
            tb.abort();
            let _ = tb.await;
            return Ok::<_, anyhow::Error>(());
        }
        eprintln!("app-a write request");
        let request_body = vec![3; 2 * CHUNK + 193];
        na.app.write_all(&request_body).await?;
        na.app.shutdown().await?;
        let mut request = Vec::new();
        eprintln!("app-b wait request EOF");
        nb.app.read_to_end(&mut request).await?;
        eprintln!("app-b request EOF");
        ensure!(request == request_body, "native request differs");
        let response_body = vec![7; 2 * CHUNK + 77];
        nb.app.write_all(&response_body).await?;
        nb.app.shutdown().await?;
        let mut response = Vec::new();
        eprintln!("app-a wait response EOF");
        na.app.read_to_end(&mut response).await?;
        eprintln!("app-a response EOF");
        ensure!(response == response_body, "native response differs");
        let (mut da, ra) = ta.await?;
        ra?;
        let (mut db, rb) = tb.await?;
        rb?;
        ensure!(
            da.drain_authority()?.remaining().is_some()
                && db.drain_authority()?.remaining().is_some(),
            "completed flow lost original retirement bound"
        );
        da.shutdown().await?;
        db.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await?;
    // Independent test-owned shutdown; no OS adapter, route, or host packet used.
    na.stop.cancel();
    nb.stop.cancel();
    ab.stop.cancel();
    ba.stop.cancel();
    ab.source.close();
    ab.destination.close();
    ba.source.close();
    ba.destination.close();
    timeout(Duration::from_secs(1), &mut ab.pump).await???;
    timeout(Duration::from_secs(1), &mut ba.pump).await???;
    for task in na.tasks.drain(..).chain(nb.tasks.drain(..)) {
        timeout(Duration::from_secs(1), task).await???;
    }
    timeout(Duration::from_secs(1), async {
        loop {
            let empty = budgets.iter().all(|b| {
                let s = b.0.lock().unwrap();
                s.total.bytes == 0 && s.total.chunks == 0 && s.total.connections == 0
            });
            if empty {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await?;
    result
}

#[tokio::test]
async fn actual_two_pinned_tls_native_source_data_fin_duplex_preserves_response_and_releases_credits(
) -> Result<()> {
    exercise(false).await
}
#[tokio::test]
async fn actual_native_source_revoke_while_remote_native_ack_blocked_cannot_publish_receipt(
) -> Result<()> {
    exercise(true).await
}
