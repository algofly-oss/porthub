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
fn lease() -> SendPermit {
    let start = std::time::Instant::now();
    SendPermit::bounded(
        || true,
        move || Duration::from_secs(15).checked_sub(start.elapsed()),
    )
}
struct Link {
    client: BoundedSourceConnection,
    server: Option<CreditedReceiverConnection>,
    source: Arc<Endpoint>,
    destination: Arc<Endpoint>,
    stop: CancellationToken,
    pump: JoinHandle<()>,
}
impl Drop for Link {
    fn drop(&mut self) {
        self.stop.cancel();
        self.source.close();
        self.destination.close();
    }
}
async fn link(
    a: Identity,
    b: Identity,
    ap: &Peer,
    bp: &Peer,
    ga: &Gate,
    gb: &Gate,
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
            tokio::select! {_=cancel.cancelled()=>break,p=ai.outgoing()=>match p{Some(p)=>{let _=ib.send_reliable_guarded(aip,p.payload,p.permit).await;},None=>break},p=bi.outgoing()=>match p{Some(p)=>{let _=ia.send_reliable_guarded(bip,p.payload,p.permit).await;},None=>break}}
        }
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
struct Native {
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
async fn native(flow: tcp_stream::Flow) -> Result<Native> {
    let (handle, mut output, runner) = tagged::stack()?;
    let (peer, mut input, peer_runner) = tcp_stream::stack()?;
    let stop = CancellationToken::new();
    let a = tokio::spawn(runner.run(stop.clone()));
    let b = tokio::spawn(peer_runner.run(stop.clone()));
    let h = handle.clone();
    let connecting = tokio::spawn(async move { h.connect(flow, lease()).await });
    let syn = timeout(Duration::from_secs(1), output.recv())
        .await?
        .unwrap();
    let other = peer.clone();
    let accepting = tokio::spawn(async move {
        syn.deliver(|bytes| async move { other.accept_syn(bytes).await })
            .await
    });
    handle.incoming(
        timeout(Duration::from_secs(1), input.recv())
            .await?
            .unwrap(),
        lease(),
    )?;
    let ack = timeout(Duration::from_secs(1), output.recv())
        .await?
        .unwrap();
    let other = peer.clone();
    ack.deliver(|bytes| async move { other.packet(bytes) })
        .await?;
    let connection = Arc::new(connecting.await??);
    let (_, app) = accepting.await??;
    let cancel = stop.clone();
    let hold_ack = Arc::new(AtomicBool::new(false));
    let hold = hold_ack.clone();
    let pump = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            tokio::select! {_=cancel.cancelled()=>break,p=output.recv()=>match p{Some(p)=>{let other=peer.clone();p.deliver(|bytes|async move{other.packet(bytes)}).await?;},None=>break},p=input.recv()=>match p{Some(p)=>{if hold.load(Ordering::SeqCst){ensure!(held.len()<32,"held native ACK fixture bound");held.push(p);}else{handle.incoming(p,lease())?;}},None=>break}}
        }
        Ok::<_, anyhow::Error>(())
    });
    Ok(Native {
        connection,
        app,
        stop,
        tasks: vec![a, b, pump],
        hold_ack,
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
    let mut ab = link(a.clone(), b.clone(), &ap, &bp, &gas, &gbr).await?;
    let mut ba = link(b, a, &bp, &ap, &gbs, &gar).await?;
    let (_ha, la) = flow_open::tests::local(&ap, &bp, "a")?;
    let (_hb, lb) = flow_open::tests::local(&bp, &ap, "b")?;
    let (la, lb) = (Arc::new(la), Arc::new(lb));
    let (open_a, open_b) = tokio::try_join!(
        flow_open::initiate(&ab.client, &gas, &la, [8; 16], 42000, 443),
        flow_open::accept(ab.server.as_mut().unwrap(), &gbr, &lb)
    )?;
    let (reply_b, reply_a) = tokio::try_join!(
        flow_open::initiate_response(&ba.client, &gbs, &lb, &open_b),
        flow_open::accept_response(ba.server.as_mut().unwrap(), &gar, &la, &open_a)
    )?;
    ensure!(
        open_a.context().digest() == reply_a.context().digest()
            && open_b.context().digest() == reply_b.context().digest(),
        "response bridge changed flow identity"
    );
    let context = open_a.context();
    let mut na = native(context.source_native_tuple(Side::Initiator)).await?;
    let mut nb = native(context.source_native_tuple(Side::Acceptor)).await?;
    nb.hold_ack.store(revoke, Ordering::SeqCst);
    let budgets = [Budget::default(), Budget::default()];
    // Constructor rejects a real other native generation/tuple before actor creation.
    ensure!(
        Source::new(
            context.clone(),
            Side::Initiator,
            ab.client.clone(),
            gas.clone(),
            budgets[0].clone(),
            nb.connection.clone(),
            source_current(la.clone())
        )
        .is_err(),
        "source adopted another native leg"
    );
    let sa = Source::new(
        context.clone(),
        Side::Initiator,
        ab.client.clone(),
        gas,
        budgets[0].clone(),
        na.connection.clone(),
        source_current(la.clone()),
    )?;
    let sb = Source::new(
        context.clone(),
        Side::Acceptor,
        ba.client.clone(),
        gbs,
        budgets[1].clone(),
        nb.connection.clone(),
        source_current(lb.clone()),
    )?;
    let ca = receiver_current(context.clone(), la.clone(), Side::Initiator);
    let cb = receiver_current(context.clone(), lb.clone(), Side::Acceptor);
    let ra = Receiver::new(
        ba.server.take().unwrap(),
        gar,
        budgets[0].clone(),
        context.data_flow(Side::Acceptor),
        na.connection.clone(),
        ca.clone(),
    )?;
    let rb = Receiver::new(
        ab.server.take().unwrap(),
        gbr,
        budgets[1].clone(),
        context.data_flow(Side::Initiator),
        nb.connection.clone(),
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
        na.app.write_all(b"native-request-body").await?;
        na.app.shutdown().await?;
        let mut request = Vec::new();
        eprintln!("app-b wait request EOF");
        nb.app.read_to_end(&mut request).await?;
        eprintln!("app-b request EOF");
        ensure!(request == b"native-request-body", "native request differs");
        nb.app.write_all(b"response-after-request-fin").await?;
        nb.app.shutdown().await?;
        let mut response = Vec::new();
        eprintln!("app-a wait response EOF");
        na.app.read_to_end(&mut response).await?;
        eprintln!("app-a response EOF");
        ensure!(
            response == b"response-after-request-fin",
            "native response differs"
        );
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
