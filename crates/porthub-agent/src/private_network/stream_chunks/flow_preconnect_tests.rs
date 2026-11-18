//! Exact native SYN ownership across opportunistic QUIC pre-connect failure.
use super::*;
use std::sync::atomic::{AtomicUsize,Ordering};

fn roles(a:&Identity,b:&Identity)->(Peer,Peer) {
    (Peer{id:"a".into(),ip:"10.234.250.1".parse().unwrap(),fingerprint:a.fingerprint().into(),instance:"a-instance".into()},
     Peer{id:"b".into(),ip:"10.235.1.2".parse().unwrap(),fingerprint:b.fingerprint().into(),instance:"b-instance".into()})
}
fn flow(port:u16)->tcp_stream::Flow {
    tcp_stream::Flow{source:format!("10.234.250.1:{port}").parse().unwrap(),destination:"10.235.1.2:443".parse().unwrap()}
}
async fn pending_handoff()->Result<(Runtime,RawSyn,crate::private_network::sparse::Handle,mpsc::Receiver<Event>)> {
    let ai=Identity::new()?;let bi=Identity::new()?;let(ap,bp)=roles(&ai,&bi);
    let(h,_)=flow_open::tests::local(&ap,&bp,"a")?;let captured=h.clone();let(tx,rx)=mpsc::channel(64);
    let(r,background)=Runtime::new_requested(ai,Arc::new(move|peer|LocalAuthority::capture(&captured,"w","a",peer).ok().map(Arc::new)),Arc::new(|_|{}),tx,CancellationToken::new())?;
    drop(background);
    let bytes=native_syn(flow(49100)).await?;
    let syn=(r.0.current)("b").unwrap().admit_syn(bytes)?;
    let(record,_)=r.reserve("b",syn.parameters().0,Some(flow(49100)))?;
    record.cancel.cancel();record.phase.send_replace(Phase::RawPending);
    let handoff=RawSyn{runtime:Arc::downgrade(&r.0),record,syn:Some(syn)};
    Ok((r,handoff,h,rx))
}
#[tokio::test]
async fn queued_preopen_syn_rejects_pair_revocation_and_runtime_owner_drop()->Result<()> {
    let(r,handoff,h,_)=pending_handoff().await?;
    h.revoke_all();assert!(handoff.release().is_err());assert_eq!(r.counts(),(0,0));
    let(r,handoff,_h,mut receiver)=pending_handoff().await?;
    let weak=Arc::downgrade(&r.0);
    r.0.events.send(Event::GuardedRawSyn{handoff}).await.map_err(|_|anyhow::anyhow!("event closed"))?;
    drop(r);
    assert!(weak.upgrade().is_none(),"queued handoff formed an Arc cycle with its event sender");
    let Event::GuardedRawSyn{handoff}=receiver.recv().await.unwrap() else{panic!("wrong event")};
    assert!(handoff.release().is_err());Ok(())
}
#[tokio::test]
async fn raw_preopen_final_permit_retires_with_original_or_profile_owner()->Result<()> {
    let(r,handoff,h,_)=pending_handoff().await?;
    let(_,permit)=handoff.release()?;assert!(permit.valid());h.revoke_all();assert!(!permit.valid());
    assert_eq!(r.counts(),(0,0));
    let(r,handoff,_h,_)=pending_handoff().await?;
    let(_,permit)=handoff.release()?;assert!(permit.valid());r.0.cancel.cancel();assert!(!permit.valid());Ok(())
}
#[tokio::test]
async fn preopen_handoff_cannot_release_after_native_phase_or_replaced_record()->Result<()> {
    let(r,handoff,_h,_)=pending_handoff().await?;
    handoff.record.phase.send_replace(Phase::Running);
    assert!(handoff.release().is_err());assert_eq!(r.counts(),(0,0));
    let(r,handoff,_h,_)=pending_handoff().await?;
    r.remove(&handoff.record);
    assert!(handoff.release().is_err());assert_eq!(r.counts(),(0,0));Ok(())
}

struct Observation {
    raw_handoffs: AtomicUsize,
    raw_native_syns: AtomicUsize,
    optimized_native_syns: AtomicUsize,
    retired_carrier_frames: AtomicUsize,
}
impl Observation {fn new()->Arc<Self>{Arc::new(Self{raw_handoffs:AtomicUsize::new(0),raw_native_syns:AtomicUsize::new(0),optimized_native_syns:AtomicUsize::new(0),retired_carrier_frames:AtomicUsize::new(0)})}}

type Applications=mpsc::Sender<tokio::io::DuplexStream>;
async fn native_delivery(
    runtime:&Runtime,kernel:&tcp_stream::Handle,bytes:Bytes,raw:bool,
    started:&mut std::collections::HashMap<tcp_stream::Flow,(bool,Option<u32>)>,acceptors:&mut tokio::task::JoinSet<Result<()>>,
    applications:&Applications,observation:&Observation,
)->Result<()> {
    let is_syn=syn_sequence(&bytes).is_some();
    if raw{ensure!(runtime.raw_ingress(&bytes),"raw SYN/data also had an optimized native owner");}
    else{ensure!(!runtime.raw_ingress(&bytes),"optimized packet also admitted raw ownership");}
    if is_syn {
        let flow=tcp_stream::Flow::from_packet(&bytes).unwrap();
        if let Some((first_raw,first_sequence))=started.get(&flow){
            ensure!(*first_raw==raw&&*first_sequence==syn_sequence(&bytes),"native tuple crossed transport or SYN generation");
            // Ordinary kernel retransmission is not a second connection/open.
            kernel.packet(bytes)?;return Ok(());
        }
        started.insert(flow,(raw,syn_sequence(&bytes)));
        if raw{observation.raw_native_syns.fetch_add(1,Ordering::SeqCst);}else{observation.optimized_native_syns.fetch_add(1,Ordering::SeqCst);}
        let kernel=kernel.clone();let applications=applications.clone();
        acceptors.spawn(async move{let(_,app)=kernel.accept_syn(bytes).await?;applications.send(app).await.map_err(|_|anyhow::anyhow!("application owner closed"))});
    }else{kernel.packet(bytes)?;}
    Ok(())
}

async fn carrier_preconnect_case(delayed_healthy:bool,hold_native_after_open:bool,deplete_setup:bool)->Result<()> {
    timeout(Duration::from_secs(7),async {
        let ai=Identity::new()?;let bi=Identity::new()?;let(ap,bp)=roles(&ai,&bi);
        struct SetupClock(std::sync::atomic::AtomicU64);
        impl crate::private_network::authority_clock::SuspendClock for SetupClock {
            fn elapsed_since_boot(&self)->Result<Duration>{Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))}
        }
        let setup_clock=Arc::new(SetupClock(std::sync::atomic::AtomicU64::new(0)));
        let(ha,_)=flow_open::tests::local_with_clock(&ap,&bp,"a",setup_clock.clone())?;let(hb,_)=flow_open::tests::local(&bp,&ap,"b")?;
        let aa=ha.clone();let bb=hb.clone();let(ea,mut ra)=mpsc::channel(256);let(eb,mut rb)=mpsc::channel(256);
        let stop=CancellationToken::new();
        let(a,ar)=Runtime::new_requested(ai,Arc::new(move|peer|LocalAuthority::capture(&aa,"w","a",peer).ok().map(Arc::new)),Arc::new(|_|{}),ea,stop.child_token())?;
        let(b,br)=Runtime::new_requested(bi,Arc::new(move|peer|LocalAuthority::capture(&bb,"w","b",peer).ok().map(Arc::new)),Arc::new(|_|{}),eb,stop.child_token())?;
        let(ka,mut pa,kar)=tcp_stream::stack()?;let(kb,mut pb,kbr)=tcp_stream::stack()?;
        let observed=Observation::new();let observations=observed.clone();
        let release=Arc::new(AtomicBool::new(false));let release_carrier=release.clone();
        let mut tasks=tokio::task::JoinSet::new();tasks.spawn(ar.run());tasks.spawn(br.run());tasks.spawn(kar.run(stop.child_token()));tasks.spawn(kbr.run(stop.child_token()));
        let(applications,mut accepted)=mpsc::channel(8);
        let ca=a.clone();let cb=b.clone();let ka_io=ka.clone();let kb_io=kb.clone();let cs=stop.clone();
        tasks.spawn(async move{
            let mut acceptors=tokio::task::JoinSet::new();let mut started_a=std::collections::HashMap::new();let mut started_b=std::collections::HashMap::new();
            let mut held=Vec::new();let mut held_native=Vec::new();let began=std::time::Instant::now();let mut tick=tokio::time::interval(Duration::from_millis(5));
            let result=async{loop{tokio::select!{
                _=cs.cancelled()=>break,
                packet=pa.recv()=>{let Some(packet)=packet else{break};if !ca.kernel_packet("b",packet.clone(),true){native_delivery(&cb,&kb_io,packet,true,&mut started_b,&mut acceptors,&applications,&observations).await?;}},
                packet=pb.recv()=>{let Some(packet)=packet else{break};if !cb.kernel_packet("a",packet.clone(),false){native_delivery(&ca,&ka_io,packet,true,&mut started_a,&mut acceptors,&applications,&observations).await?;}},
                event=ra.recv()=>{let Some(event)=event else{break};match event{
                    Event::StreamDatagram{payload,permit,..}=>{
                        if deplete_setup {setup_clock.0.store(12000,Ordering::SeqCst);}
                        held.push((true,payload,permit.ok_or_else(||anyhow::anyhow!("source carrier lost permit"))?));
                    },
                    Event::GuardedRawSyn{handoff}=>{
                        observations.raw_handoffs.fetch_add(1,Ordering::SeqCst);
                        let(bytes,permit)=handoff.release()?;
                        permit.during(async{native_delivery(&cb,&kb_io,bytes,true,&mut started_b,&mut acceptors,&applications,&observations).await}).await??;
                    },
                    Event::GuardedStreamLocal{packet,..}=>{packet.deliver(|bytes|async{native_delivery(&ca,&ka_io,bytes,false,&mut started_a,&mut acceptors,&applications,&observations).await}).await?;},
                    _=>anyhow::bail!("unexpected source event"),
                }},
                event=rb.recv()=>{let Some(event)=event else{break};match event{
                    Event::StreamDatagram{payload,permit,..}=>{held.push((false,payload,permit.ok_or_else(||anyhow::anyhow!("target carrier lost permit"))?));},
                    Event::GuardedStreamLocal{packet,..}=>{
                        if hold_native_after_open&&syn_sequence(packet.bytes()).is_some(){observations.optimized_native_syns.fetch_add(1,Ordering::SeqCst);held_native.push(packet);}
                        else{packet.deliver(|bytes|async{native_delivery(&cb,&kb_io,bytes,false,&mut started_b,&mut acceptors,&applications,&observations).await}).await?;}
                    },
                    Event::GuardedRawSyn{..}=>anyhow::bail!("target unexpectedly started a cold optimized flow"),
                    _=>anyhow::bail!("unexpected target event"),
                }},
                _=tick.tick()=>{
                    if hold_native_after_open||(delayed_healthy&&began.elapsed()>=Duration::from_millis(500))||release_carrier.load(Ordering::SeqCst){
                        for(from_a,payload,permit) in std::mem::take(&mut held){
                            if !permit.valid(){observations.retired_carrier_frames.fetch_add(1,Ordering::SeqCst);continue;}
                            let received=permit.during(async{if from_a{cb.receive_offered("a",ap.ip,payload,true)}else{ca.receive_offered("b",bp.ip,payload,true)}}).await?;received?;
                        }
                    }
                },
                result=acceptors.join_next(),if !acceptors.is_empty()=>{result.unwrap()??;},
            }}Ok::<_,anyhow::Error>(())}.await;
            acceptors.abort_all();while acceptors.join_next().await.is_some(){}result
        });
        let count=if delayed_healthy||hold_native_after_open||deplete_setup{1}else{5};
        let mut clients=tokio::task::JoinSet::new();
        for index in 0..count {
            if index==4 {
                timeout(Duration::from_millis(500),async{while a.counts().0!=4{tokio::task::yield_now().await;}}).await?;
            }
            let ka=ka.clone();clients.spawn(async move{
                let began=std::time::Instant::now();let mut app=ka.connect(flow(49200+index)).await?;
                let mut banner=[0;8];app.read_exact(&mut banner).await?;ensure!(&banner==b"SSH-test","first SYN did not reach real target application");
                if index==4{ensure!(began.elapsed()<Duration::from_millis(700),"fifth raw flow blocked on four stalled optimizations");}
                app.write_all(&[index as u8;31]).await?;app.shutdown().await?;let mut echoed=Vec::new();app.read_to_end(&mut echoed).await?;ensure!(echoed==vec![index as u8;31],"raw/optimized payload crossed native flow");Ok::<_,anyhow::Error>(())
            });
        }
        let mut services=tokio::task::JoinSet::new();
        let result=async{
            if hold_native_after_open {
                timeout(Duration::from_secs(2),async{while observed.optimized_native_syns.load(Ordering::SeqCst)==0{tokio::task::yield_now().await;}}).await?;
                tokio::time::sleep(PRECONNECT_BUDGET+Duration::from_millis(100)).await;
                ensure!(observed.raw_handoffs.load(Ordering::SeqCst)==0&&observed.raw_native_syns.load(Ordering::SeqCst)==0,"flow-open/native offer was migrated to raw");
                return Ok(());
            }
            for _ in 0..count{
                let mut app=accepted.recv().await.ok_or_else(||anyhow::anyhow!("target did not accept original SYN"))?;
                services.spawn(async move{app.write_all(b"SSH-test").await?;let mut request=Vec::new();app.read_to_end(&mut request).await?;ensure!(request.len()==31,"request FIN/body missing");app.write_all(&request).await?;app.shutdown().await?;Ok::<_,anyhow::Error>(())});
            }
            while let Some(client)=clients.join_next().await{client??;}while let Some(server)=services.join_next().await{server??;}
            if deplete_setup {
                ensure!(a.0.connected_sources.load(Ordering::SeqCst)==1,"test must exercise successful QUIC preconnect before raw handoff");
                ensure!(observed.raw_handoffs.load(Ordering::SeqCst)==1&&observed.raw_native_syns.load(Ordering::SeqCst)==1&&observed.optimized_native_syns.load(Ordering::SeqCst)==0,"postconnect depleted original did not return exactly one raw SYN");
            }else if delayed_healthy {
                ensure!(observed.raw_handoffs.load(Ordering::SeqCst)==0&&observed.optimized_native_syns.load(Ordering::SeqCst)>0,"delayed healthy setup lost useful optimization");
            }else{
                ensure!(observed.raw_handoffs.load(Ordering::SeqCst)==4&&observed.raw_native_syns.load(Ordering::SeqCst)==5&&observed.optimized_native_syns.load(Ordering::SeqCst)==0,"stalled preconnect did not hand off each original exactly once");
                release.store(true,Ordering::SeqCst);tokio::time::sleep(Duration::from_millis(50)).await;
                ensure!(observed.retired_carrier_frames.load(Ordering::SeqCst)>0&&observed.optimized_native_syns.load(Ordering::SeqCst)==0,"late carrier revived an old native SYN");
            }
            Ok::<_,anyhow::Error>(())
        }.await;
        stop.cancel();clients.abort_all();services.abort_all();
        while clients.join_next().await.is_some(){}while services.join_next().await.is_some(){}
        let mut cleanup=Ok(());while let Some(task)=tasks.join_next().await{let task=task.map_err(anyhow::Error::from).and_then(|r|r);if cleanup.is_ok(){cleanup=task;}}
        result?;cleanup?;ensure!(a.counts()==(0,0)&&b.counts()==(0,0),"preconnect fixture leaked native owners");Ok(())
    }).await?
}
#[tokio::test]
async fn four_stalled_preconnects_deliver_original_syn_once_and_fifth_raw_is_responsive()->Result<()>{carrier_preconnect_case(false,false,false).await}
#[tokio::test]
async fn delayed_healthy_preconnect_preserves_optimized_native_duplex()->Result<()>{carrier_preconnect_case(true,false,false).await}

#[tokio::test]
async fn already_offered_native_syn_never_falls_back_when_native_ack_stalls()->Result<()>{carrier_preconnect_case(false,true,false).await}

// Exercise the actual synchronous ownership decision with a suspend-aware
// authority clock, without sleeping until a live lease is nearly expired.
#[tokio::test]
async fn late_original_syn_declines_stream_before_reserving_native_owner() -> Result<()> {
    use crate::private_network::{
        authority_clock::{RequestWindow, SuspendClock},
        authority_event::Authority,
    };
    use std::sync::atomic::AtomicU64;
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    let ai = Identity::new()?;
    let bi = Identity::new()?;
    let (ap, bp) = roles(&ai, &bi);
    let info = |p: &Peer| serde_json::json!({"id":p.id,"ip":p.ip,"fingerprint":p.fingerprint,"instance":p.instance,"hostname":format!("{}.phub",p.id)});
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(15);
    let epoch = "a".repeat(64);
    let base = serde_json::from_value(
        serde_json::json!({"workspace":"w","self":"a","revision":1,"expires_at":expiry,"sparse":{"protocol":1,"epoch":epoch},"peers":[info(&ap)],"grants":[]}),
    )?;
    let pair = serde_json::from_value(
        serde_json::json!({"workspace":"w","self":"a","epoch":epoch,"revision":1,"expires_at":expiry,"local":info(&ap),"peer":info(&bp),"grants":[{"source":"a","destination":"b","protocol":"tcp","ports":[{"start":443,"end":443}]}]}),
    )?;
    let clock = Arc::new(Clock(AtomicU64::new(0)));
    let authority = || {
        Authority::new(
            (),
            Some(RequestWindow::start(clock.clone()).unwrap()),
            expiry,
        )
    };
    let (h, _) = crate::private_network::sparse::channel();
    h.update_base_authority(&base, authority());
    h.installed_authority(
        &porthub_network::policy::Lookup {
            kind: "peer".into(),
            value: "b".into(),
        },
        pair,
        authority(),
    );
    let captured = h.clone();
    let (tx, _) = mpsc::channel(64);
    let (runtime, background) = Runtime::new_requested(
        ai,
        Arc::new(move |id| {
            LocalAuthority::capture(&captured, "w", "a", id)
                .ok()
                .map(Arc::new)
        }),
        Arc::new(|_| {}),
        tx,
        CancellationToken::new(),
    )?;
    let syn = native_syn(flow(49300)).await?;
    clock.0.store(12000, Ordering::SeqCst);
    assert!(
        h.bound_pair_authority("b").unwrap().permit().valid(),
        "late lease remains authorized for raw transport"
    );
    assert!(
        !runtime.kernel_packet("b", syn.clone(), true),
        "late original must not commit to an optimized native owner"
    );
    assert_eq!(runtime.counts(), (0, 0));
    assert!(matches!(
        runtime.0.state.lock().unwrap().decisions.get(&flow(49300)),
        Some(Decision::Raw)
    ));
    assert!(
        !runtime.kernel_packet("b", syn, true),
        "same SYN retains its first raw decision"
    );
    drop(background);
    Ok(())
}

#[test]
fn setup_runway_consumption_and_original_retirement_never_renew_admission() {
    use std::sync::atomic::AtomicU64;
    let left = Arc::new(AtomicU64::new(6000));
    let original = left.clone();
    let permit = SendPermit::bounded(
        || true,
        move || Some(Duration::from_millis(original.load(Ordering::SeqCst))),
    );
    assert!(setup_ready(&permit, SETUP_RUNWAY));
    left.store(4999, Ordering::SeqCst);
    assert!(permit.valid());
    assert!(
        !setup_ready(&permit, SETUP_RUNWAY),
        "preconnect must not enter flow-open with depleted original runway"
    );
    assert!(
        setup_ready(&permit, flow_open::OPEN_BUDGET.saturating_mul(2)),
        "connected QUIC no longer needs its preconnect budget"
    );
    left.store(0, Ordering::SeqCst);
    assert!(!permit.valid());
    assert!(!setup_ready(&permit, SETUP_RUNWAY));
    let veto = Arc::new(AtomicBool::new(true));
    let check = veto.clone();
    let permit = SendPermit::bounded(
        move || check.load(Ordering::SeqCst),
        || Some(Duration::from_secs(10)),
    );
    assert!(setup_ready(&permit, SETUP_RUNWAY));
    veto.store(false, Ordering::SeqCst);
    assert!(!setup_ready(&permit, SETUP_RUNWAY));
}

#[tokio::test]
async fn connected_quic_with_depleted_original_returns_syn_before_native_open() -> Result<()> {
    carrier_preconnect_case(true, false, true).await
}
