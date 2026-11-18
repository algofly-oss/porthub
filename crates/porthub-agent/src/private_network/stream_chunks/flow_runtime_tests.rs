use super::*;
use anyhow::Context;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

async fn bridge(
    mut events: mpsc::Receiver<Event>,
    own: Runtime,
    other: Runtime,
    kernel: tcp_stream::Handle,
    own_peer: Peer,
    remote: Peer,
    accepted: mpsc::Sender<tokio::io::DuplexStream>,
    stop: CancellationToken,
    allow_new: Arc<AtomicBool>,
) -> Result<()> {
    let mut acceptors = tokio::task::JoinSet::new();
    let mut services_started = std::collections::HashSet::new();
    let result = async { loop { tokio::select! {
        biased;
        _=stop.cancelled()=>break,
        event=events.recv()=>{let Some(event)=event else {break}; match event {
            Event::StreamDatagram{destination,payload,permit}=>{
                ensure!(destination==remote.ip,"carrier destination escaped exact peer");
                let wire=porthub_mesh::control_packet::encode(porthub_mesh::control_packet::STREAM,own_peer.ip,destination,&payload)?;
                let envelope=porthub_mesh::control_packet::decode(porthub_mesh::control_packet::STREAM,wire).ok_or_else(||anyhow::anyhow!("carrier invalid"))?;
                let permit=permit.ok_or_else(||anyhow::anyhow!("carrier lost origin"))?;
                // Match the production carrier boundary: an expired original
                // is discarded, never delivered or promoted to a profile error.
                // A live peer receiver error remains fatal and is not swallowed.
                if !permit.valid(){continue;}
                let admitted=tokio::select! {
                    biased;
                    _=stop.cancelled()=>break,
                    result=permit.during(async{other.receive_offered(&own_peer.id,own_peer.ip,envelope.payload,allow_new.load(Ordering::SeqCst))})=>result,
                };
                match admitted {
                    Ok(received)=>{received?;},
                    Err(_) if !permit.valid()=>continue,
                    Err(error)=>return Err(error.context("fixture carrier admission")),
                }
            },
            Event::GuardedStreamLocal{peer,packet}=>{
                ensure!(peer==remote.id,"native delivery changed authenticated peer");
                ensure!(!own.raw_ingress(packet.bytes()),"an active optimized tuple also admitted raw native delivery");
                let is_syn=packet.bytes().get(33).is_some_and(|flags|flags&0x12==2);
                if is_syn&&services_started.insert(tcp_stream::Flow::from_packet(packet.bytes()).ok_or_else(||anyhow::anyhow!("native SYN tuple absent"))?) { let k=kernel.clone();let ready=accepted.clone();
                    acceptors.spawn(async move{let (_,app)=packet.deliver(|bytes|async move{k.accept_syn(bytes).await}).await.context("fixture native SYN delivery")?;ready.send(app).await.map_err(|_|anyhow::anyhow!("test service receiver gone"))});
                } else {let k=kernel.clone();tokio::select! {
                    biased;
                    _=stop.cancelled()=>break,
                    result=packet.deliver(|bytes|async move{k.packet(bytes)})=>result.context("fixture native packet delivery")?,
                };}
            },
            _=>anyhow::bail!("unexpected runtime event")
        }},
        task=acceptors.join_next(),if !acceptors.is_empty()=>{task.unwrap()??;}
    }} Ok::<_,anyhow::Error>(()) }.await;
    acceptors.abort_all();
    while acceptors.join_next().await.is_some() {}
    let _ = own;
    result
}

async fn exercise(revoke: bool, parallel: usize, withdraw: bool) -> Result<()> {
    timeout(Duration::from_secs(12),async {
        let a=Identity::new()?;let b=Identity::new()?;
        let ap=Peer{id:"a".into(),ip:"10.234.250.1".parse()?,fingerprint:a.fingerprint().into(),instance:"a-instance".into()};
        let bp=Peer{id:"b".into(),ip:"10.235.1.2".parse()?,fingerprint:b.fingerprint().into(),instance:"b-instance".into()};
        let (ha,_)=flow_open::tests::local(&ap,&bp,"a")?;let (hb,_)=flow_open::tests::local(&bp,&ap,"b")?;
        let ca=ha.clone();let cb=hb.clone();
        let (ea,ra)=mpsc::channel(64);let (eb,rb)=mpsc::channel(64);let stop=CancellationToken::new();
        let (a,ar)=Runtime::new(a,Arc::new(move|id|LocalAuthority::capture(&ca,"w","a",id).ok().map(Arc::new)),Arc::new(|_|{}),ea,stop.child_token())?;
        let (b,br)=Runtime::new(b,Arc::new(move|id|LocalAuthority::capture(&cb,"w","b",id).ok().map(Arc::new)),Arc::new(|_|{}),eb,stop.child_token())?;
        let (ka,mut pa,kar)=tcp_stream::stack()?;let (kb,mut pb,kbr)=tcp_stream::stack()?;
        let mut tasks=tokio::task::JoinSet::new();tasks.spawn(ar.run());tasks.spawn(br.run());tasks.spawn(kar.run(stop.child_token()));tasks.spawn(kbr.run(stop.child_token()));
        let (accepted,mut apps)=mpsc::channel(2);let allow_new=Arc::new(AtomicBool::new(true));
        tasks.spawn(bridge(ra,a.clone(),b.clone(),ka.clone(),ap.clone(),bp.clone(),accepted.clone(),stop.child_token(),allow_new.clone()));
        tasks.spawn(bridge(rb,b.clone(),a.clone(),kb.clone(),bp.clone(),ap.clone(),accepted,stop.child_token(),allow_new.clone()));
        let aa=a.clone();let bb=b.clone();let ca=stop.child_token();let cb=stop.child_token();
        tasks.spawn(async move{loop{tokio::select!{_=ca.cancelled()=>{while pa.recv().await.is_some(){}break;},p=pa.recv()=>{let Some(p)=p else{break};ensure!(aa.kernel_packet("b",p,true),"source native packet lost flow owner");}}}Ok(())});
        tasks.spawn(async move{loop{tokio::select!{_=cb.cancelled()=>{while pb.recv().await.is_some(){}break;},p=pb.recv()=>{let Some(p)=p else{break};ensure!(bb.kernel_packet("a",p,false),"target native packet lost flow owner");}}}Ok(())});
        let mut clients=Vec::new();
        for i in 0..parallel {
            let kernel=ka.clone();
            let flow=tcp_stream::Flow{source:std::net::SocketAddrV4::new(ap.ip,42000+i as u16),destination:std::net::SocketAddrV4::new(bp.ip,443)};
            clients.push(tokio::spawn(async move{kernel.connect(flow).await}));
        }
        let result=async {
            let mut servers=Vec::new();for _ in 0..parallel {servers.push(apps.recv().await.ok_or_else(||anyhow::anyhow!("service never accepted"))?);}
            let mut connected=Vec::new();for client in clients {connected.push(client.await??);}
            if withdraw {
                allow_new.store(false,Ordering::SeqCst);
                let before=(a.counts(),b.counts());
                let cold=Frame::new(Key::new([77;16],0,Role::Receiver)?,Bytes::from_static(b"unoffered-cold-initial"))?.encode();
                ensure!(a.receive_offered("b",bp.ip,cold.clone(),false)?==Outcome::Missing&&b.receive_offered("a",ap.ip,cold,false)?==Outcome::Missing,"withdrawn capability allocated a cold flow");
                ensure!((a.counts(),b.counts())==before,"withdrawal changed existing owner registrations");
            }
            if revoke {
                let mut client=connected.remove(0);let mut server=servers.remove(0);
                client.write_all(b"native-request-body").await?;let mut body=[0;19];server.read_exact(&mut body).await?;
                ensure!(&body==b"native-request-body","flow never reached actual native consumer");
                ha.revoke_all();hb.revoke_all();
                timeout(Duration::from_secs(1),async {while a.counts()!=(0,0)||b.counts()!=(0,0){tokio::time::sleep(Duration::from_millis(5)).await;}}).await?;
                ensure!(a.0.state.lock().unwrap().decisions.values().all(|d|matches!(d,Decision::Stream(_))),"retired flow silently changed to raw transport");
                return Ok(());
            }
            let mut applications=tokio::task::JoinSet::new();
            for mut server in servers {
                applications.spawn(async move {
                    let mut bytes=Vec::new();server.read_to_end(&mut bytes).await?;
                    ensure!(bytes.len()==CHUNK*2+193 && bytes.first().is_some_and(|first|bytes.iter().all(|byte|byte==first)),"request DATA/FIN mismatch or cross-flow delivery");
                    server.write_all(&vec![bytes[0]+0x44;CHUNK*2+77]).await?;server.shutdown().await?;Ok::<_,anyhow::Error>(())
                });
            }
            for (i,mut client) in connected.into_iter().enumerate() {
                applications.spawn(async move {
                    let value=0x35+i as u8;
                    client.write_all(&vec![value;CHUNK*2+193]).await?;client.shutdown().await?;
                    let mut bytes=Vec::new();client.read_to_end(&mut bytes).await?;
                    ensure!(bytes==vec![value+0x44;CHUNK*2+77],"response DATA/FIN mismatch or crossed native flow");Ok(())
                });
            }
            while let Some(application)=applications.join_next().await{application??;}
            ensure!(a.counts()==(parallel,parallel*2)&&b.counts()==(parallel,parallel*2),"autonomous flows escaped shared registry budget");
            Ok::<_,anyhow::Error>(())
        }.await;
        eprintln!("FOUR_FLOW_PHASE parallel={parallel} withdraw={withdraw} application_completed={}",result.is_ok());
        stop.cancel();
        let mut cleanup=Ok(());
        while let Some(task)=tasks.join_next().await {
            let joined=match task {Ok(result)=>result,Err(error)=>Err(error.into())};
            if cleanup.is_ok(){cleanup=joined.context("fixture joined owner after cancellation");}
        }
        if let Err(primary)=result {
            if let Err(error)=cleanup {eprintln!("FOUR_FLOW_SECONDARY_CLEANUP {error:#}");}
            return Err(primary.context("fixture application stage"));
        }
        cleanup?;
        ensure!(a.counts()==(0,0)&&b.counts()==(0,0),"autonomous runtime retained flow/endpoint ownership");
        Ok(())
    }).await?
}

#[tokio::test]
async fn autonomous_cross_pool_native_syn_dispatches_authenticated_duplex_without_manual_flow_open(
) -> Result<()> {
    exercise(false, 1, false).await
}
#[tokio::test]
async fn autonomous_active_native_flow_api_pair_retirement_reaps_dispatch_and_prevents_raw_fallthrough(
) -> Result<()> {
    exercise(true, 1, false).await
}

#[tokio::test]
async fn cold_missing_pair_requests_lookup_without_allocating_transport_or_native_owner(
) -> Result<()> {
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = requests.clone();
    let (events, _) = mpsc::channel(1);
    let (runtime, _background) = Runtime::new(
        Identity::new()?,
        Arc::new(|_| None),
        Arc::new(move |peer| {
            assert_eq!(peer, "cold");
            count.fetch_add(1, Ordering::SeqCst);
        }),
        events,
        CancellationToken::new(),
    )?;
    let frame = Frame::new(
        Key::new([7; 16], 0, Role::Receiver)?,
        Bytes::from_static(b"untrusted-initial"),
    )?
    .encode();
    assert!(runtime.receive("cold", "10.235.1.2".parse()?, frame)? == Outcome::Busy);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(runtime.counts(), (0, 0));
    Ok(())
}

async fn native_syn(flow: tcp_stream::Flow) -> Result<Bytes> {
    let (kernel, mut output, runner) = tcp_stream::stack()?;
    let stop = CancellationToken::new();
    let task = tokio::spawn(runner.run(stop.clone()));
    let connecting = tokio::spawn(async move { kernel.connect(flow).await });
    let syn = timeout(Duration::from_secs(1), output.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("test native SYN absent"))?;
    stop.cancel();
    task.await??;
    connecting.abort();
    let _ = connecting.await;
    Ok(syn)
}
#[tokio::test]
async fn real_raw_syn_cannot_be_adopted_after_preference_changes_or_new_carrier_arrives(
) -> Result<()> {
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
        ip: "10.235.1.2".parse()?,
        fingerprint: b.fingerprint().into(),
        instance: "b-instance".into(),
    };
    let (handle, _) = flow_open::tests::local(&ap, &bp, "a")?;
    let (flow_events, _) = mpsc::channel(1);
    let (runtime, _) = Runtime::new(
        a,
        Arc::new(move |peer| {
            LocalAuthority::capture(&handle, "w", "a", peer)
                .ok()
                .map(Arc::new)
        }),
        Arc::new(|_| {}),
        flow_events,
        CancellationToken::new(),
    )?;
    let flow = tcp_stream::Flow {
        source: std::net::SocketAddrV4::new(ap.ip, 42000),
        destination: std::net::SocketAddrV4::new(bp.ip, 443),
    };
    let syn = native_syn(flow).await?;
    assert!(!runtime.kernel_packet("b", syn.clone(), false));
    assert!(!runtime.kernel_packet("b", syn, true));
    assert_eq!(runtime.counts(), (0, 0));
    let (record, _) = runtime.reserve("b", [9; 16], None)?;
    assert!(
        runtime.bind_kernel(&record, flow).is_err(),
        "a cold authenticated carrier adopted an existing raw tuple"
    );
    runtime.remove(&record);
    assert_eq!(runtime.counts(), (0, 0));
    Ok(())
}
#[tokio::test]
async fn shared_runtime_records_are_bounded_across_peers_and_raw_budget_pressure_declines_optimization(
) -> Result<()> {
    let (events, _) = mpsc::channel(1);
    let (runtime, _) = Runtime::new(
        Identity::new()?,
        Arc::new(|_| None),
        Arc::new(|_| {}),
        events,
        CancellationToken::new(),
    )?;
    let mut records = Vec::new();
    for peer in 0..64 {
        for flow in 0..4 {
            let mut nonce = [1; 16];
            nonce[0] = flow;
            let (record, _) = runtime.reserve(&format!("peer-{peer}"), nonce, None)?;
            records.push(record);
        }
    }
    assert!(runtime.reserve("overflow", [8; 16], None).is_err());
    assert!(runtime.reserve("peer-0", [8; 16], None).is_err());
    assert_eq!(runtime.counts(), (256, 0));
    for record in records {
        runtime.remove(&record);
    }
    assert_eq!(runtime.counts(), (0, 0));
    {
        let mut state = runtime.0.state.lock().unwrap();
        state.decisions_full = true;
    }
    let flow = tcp_stream::Flow {
        source: "10.234.250.1:42000".parse()?,
        destination: "10.235.1.2:443".parse()?,
    };
    assert!(!runtime.kernel_packet("b", native_syn(flow).await?, true));
    assert_eq!(runtime.counts(), (0, 0));
    Ok(())
}

#[tokio::test]
async fn autonomous_four_flows_survive_capability_withdrawal_while_new_cold_flows_are_declined(
) -> Result<()> {
    exercise(false, 4, true).await
}

#[tokio::test]
async fn retired_queued_carrier_is_not_dispatched_and_live_carrier_errors_remain_fatal() -> Result<()> {
    let ap=Peer{id:"a".into(),ip:"10.234.250.1".parse()?,fingerprint:Identity::new()?.fingerprint().into(),instance:"a-instance".into()};
    let bp=Peer{id:"b".into(),ip:"10.235.1.2".parse()?,fingerprint:Identity::new()?.fingerprint().into(),instance:"b-instance".into()};
    let (unused_a,_)=mpsc::channel(1);let (unused_b,_)=mpsc::channel(1);
    let stop=CancellationToken::new();
    let (own,_)=Runtime::new(Identity::new()?,Arc::new(|_|None),Arc::new(|_|{}),unused_a,stop.child_token())?;
    let requests=Arc::new(std::sync::atomic::AtomicUsize::new(0));let observed=requests.clone();
    let (other,_)=Runtime::new(Identity::new()?,Arc::new(|_|None),Arc::new(move |_|{observed.fetch_add(1,Ordering::SeqCst);}),unused_b,stop.child_token())?;
    let (kernel,_,_)=tcp_stream::stack()?;let (accepted,_)=mpsc::channel(1);
    let (events,input)=mpsc::channel(2);
    // A legitimate queued frame whose original owner retired before dequeue.
    // Dispatching it would invoke the cold-authority lookup callback.
    let cold=Frame::new(Key::new([79;16],0,Role::Receiver)?,Bytes::from_static(b"retired-initial"))?.encode();
    events.send(Event::StreamDatagram{destination:bp.ip,payload:cold,permit:Some(SendPermit::bounded(||false,||None))}).await?;
    // Still-live malformed payload must not be swallowed by stale-frame handling.
    events.send(Event::StreamDatagram{destination:bp.ip,payload:Bytes::from_static(b"invalid-live-carrier"),permit:Some(SendPermit::bounded(||true,||Some(Duration::from_secs(60))))}).await?;
    drop(events);
    let error=bridge(input,own,other.clone(),kernel,ap,bp,accepted,stop,Arc::new(AtomicBool::new(true))).await.unwrap_err();
    ensure!(format!("{error:#}").contains("foreign/oversized guarded carrier"),"live payload error was replaced: {error:#}");
    ensure!(requests.load(Ordering::SeqCst)==0,"retired queued frame reached peer lookup");
    ensure!(other.counts()==(0,0),"retired frame allocated ownership");
    Ok(())
}

#[tokio::test]
async fn real_failed_flow_completion_reports_bounded_metadata_without_restarting_owner() -> Result<()> {
    let mut tasks=tokio::task::JoinSet::new();
    tasks.spawn(async{Err::<(),_>(anyhow::anyhow!("untrusted-private-token-and-payload").context("source-open"))});
    let mut reporter=FlowFailureReporter::default();
    let summary=reporter.completed(tasks.join_next().await.unwrap(),std::time::Instant::now())?.unwrap();
    assert_eq!(summary.stage,"source-open");assert_eq!(summary.reason,"other");assert_eq!(summary.fingerprint.len(),64);
    assert!(!format!("{summary:?}").contains("untrusted-private-token-and-payload"));
    tasks.spawn(async{Ok::<_,anyhow::Error>(())});
    assert!(reporter.completed(tasks.join_next().await.unwrap(),std::time::Instant::now())?.is_none());
    Ok(())
}
#[test]
fn flow_failure_reports_rate_limit_and_account_for_suppressed_errors() -> Result<()> {
    let now=std::time::Instant::now();let mut reporter=FlowFailureReporter::default();
    let fail=||Ok(Err(anyhow::anyhow!("source flow authority unavailable")));
    assert_eq!(reporter.completed(fail(),now)?.unwrap().reason,"authority");
    for _ in 0..100 {assert!(reporter.completed(fail(),now+Duration::from_secs(1))?.is_none());}
    let next=reporter.completed(fail(),now+Duration::from_secs(30))?.unwrap();assert_eq!(next.suppressed,100);
    assert_eq!(reporter.completed(fail(),now+Duration::from_secs(60))?.unwrap().suppressed,0);Ok(())
}
