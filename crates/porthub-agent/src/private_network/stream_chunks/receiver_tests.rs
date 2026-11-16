use super::*;
use porthub_mesh::{streams::Endpoint, Identity};
use porthub_network::tcp_stream;
use tokio::{
    io::AsyncReadExt,
    sync::watch,
    time::{timeout, Duration},
};
fn lease(check: impl Fn() -> bool + Send + Sync + 'static) -> SendPermit {
    let start = std::time::Instant::now();
    SendPermit::bounded(check, move || {
        Duration::from_secs(15)
            .checked_sub(start.elapsed())
            .filter(|n| !n.is_zero())
    })
}
fn mask(allow: bool) -> Result<CompiledPortMask> {
    use base64::Engine as _;
    let tcp = if allow {
        let mut bits = vec![0; 8192];
        bits[443 / 8] |= 1 << (443 % 8);
        serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(bits))
    } else {
        serde_json::Value::Bool(false)
    };
    let acl: porthub_network::policy::pair_acl::PairAcl = serde_json::from_value(
        serde_json::json!({"version":1,"forward":{"tcp":tcp,"udp":!allow,"icmp":false},"reverse":{"tcp":false,"udp":false,"icmp":false}}),
    )?;
    Ok(acl.compile()?.tcp(false))
}

struct Rig {
    receiver: Option<Receiver>,
    sender: Sender,
    owner: Option<Owner>,
    client: Connection,
    flow: Flow,
    peer: Peer,
    current: Arc<AtomicBool>,
    profile: Arc<AtomicBool>,
    original: Arc<AtomicBool>,
    source: Arc<Endpoint>,
    destination: Arc<Endpoint>,
    source_budget: Budget,
    receiver_budget: Budget,
    native_app: tokio::io::DuplexStream,
    release: watch::Sender<bool>,
    native_bytes: Arc<std::sync::atomic::AtomicUsize>,
    hold_native: Arc<AtomicBool>,
    held_native: tokio::sync::mpsc::Receiver<tagged::Packet>,
    native_target: tcp_stream::Handle,
    stop: CancellationToken,
    pump: JoinHandle<()>,
    native_tasks: Vec<JoinHandle<Result<()>>>,
}
impl Drop for Rig {
    fn drop(&mut self) {
        self.stop.cancel();
        self.source.close();
        self.destination.close();
    }
}
impl Rig {
    fn access(&self) -> Result<Access> {
        let original = self.original.clone();
        Ok(Access {
            peer: self.peer.clone(),
            epoch: self.flow.epoch,
            ports: mask(true)?,
            permit: lease(move || original.load(Ordering::SeqCst)),
        })
    }
    async fn cleanup(mut self) -> Result<()> {
        drop(self.receiver.take());
        if let Some(owner) = self.owner.take() {
            owner.shutdown().await?;
        }
        self.stop.cancel();
        self.source.close();
        self.destination.close();
        timeout(Duration::from_secs(1), &mut self.pump).await??;
        for task in self.native_tasks.drain(..) {
            timeout(Duration::from_secs(1), task).await???;
        }
        for budget in [&self.source_budget, &self.receiver_budget] {
            let b = budget.0.lock().unwrap();
            ensure!(
                b.total.bytes == 0
                    && b.total.chunks == 0
                    && b.total.connections == 0
                    && b.peers.is_empty()
                    && b.flows.is_empty(),
                "RX fixture credit leak"
            );
        }
        Ok(())
    }
}
async fn rig() -> Result<Rig> {
    let a = Identity::new()?;
    let b = Identity::new()?;
    let a_ip = "10.234.247.1".parse()?;
    let b_ip = "10.234.247.2".parse()?;
    let a_peer = Peer {
        id: "rx-source".into(),
        ip: a_ip,
        fingerprint: a.fingerprint().into(),
        instance: "one".into(),
    };
    let b_peer = Peer {
        id: "rx-target".into(),
        ip: b_ip,
        fingerprint: b.fingerprint().into(),
        instance: "two".into(),
    };
    let gate_a = Gate::new(SendPermit::control(|| true));
    let profile = Arc::new(AtomicBool::new(true));
    let parent = profile.clone();
    let gate_b = Gate::new(SendPermit::control(move || parent.load(Ordering::SeqCst)));
    let (source, mut a_io) = Endpoint::new_fenced(a, a_ip, gate_a.factory())?;
    let (destination, mut b_io) = Endpoint::new_fenced_credited(b, b_ip, gate_b.factory())?;
    source.update_peers(vec![b_peer.clone()])?;
    destination.update_peers(vec![a_peer.clone()])?;
    let a_in = a_io.ingress();
    let b_in = b_io.ingress();
    let stop = CancellationToken::new();
    let cancel = stop.clone();
    let pump = tokio::spawn(async move {
        loop {
            tokio::select! {
                _=cancel.cancelled()=>break,
                packet=a_io.outgoing()=>match packet{Some(p)=>{let _=b_in.send_reliable_guarded(a_ip,p.payload,p.permit).await;},None=>break},
                packet=b_io.outgoing()=>match packet{Some(p)=>{let _=a_in.send_reliable_guarded(b_ip,p.payload,p.permit).await;},None=>break}
            }
        }
    });
    let (source, destination) = (Arc::new(source), Arc::new(destination));
    let (client, accepted) = timeout(Duration::from_secs(3), async {
        tokio::join!(
            source.connect_fenced(&b_peer),
            destination.accept_credited()
        )
    })
    .await?;
    let client = client?;
    let remote = accepted?;
    let raw = client.connection().clone();
    let (handle, mut output, runner) = tagged::stack()?;
    let (native, mut input, native_runner) = tcp_stream::stack()?;
    let x = stop.clone();
    let y = stop.clone();
    let one = tokio::spawn(async move { runner.run(x).await });
    let two = tokio::spawn(async move { native_runner.run(y).await });
    let tuple = tcp_stream::Flow {
        source: std::net::SocketAddrV4::new(a_ip, 4000),
        destination: std::net::SocketAddrV4::new(b_ip, 443),
    };
    let h = handle.clone();
    let connecting = tokio::spawn(async move { h.connect(tuple, lease(|| true)).await });
    let syn = timeout(Duration::from_secs(1), output.recv())
        .await?
        .unwrap();
    let n = native.clone();
    let accepting = tokio::spawn(async move {
        syn.deliver(move |b| async move { n.accept_syn(b).await })
            .await
    });
    handle.incoming(
        timeout(Duration::from_secs(1), input.recv())
            .await?
            .unwrap(),
        lease(|| true),
    )?;
    let ack = timeout(Duration::from_secs(1), output.recv())
        .await?
        .unwrap();
    let n = native.clone();
    ack.deliver(move |b| async move { n.packet(b) }).await?;
    let connection = Arc::new(connecting.await??);
    let (_, native_app) = accepting.await??;
    let (release, mut released) = watch::channel(false);
    let native_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = native_bytes.clone();
    let hold_native = Arc::new(AtomicBool::new(false));
    let hold = hold_native.clone();
    let (native_sender, held_native) = tokio::sync::mpsc::channel(1);
    let native_target = native.clone();
    let cancel = stop.clone();
    let native_pump = tokio::spawn(async move {
        let mut held = Vec::new();
        let mut open = false;
        loop {
            tokio::select! {biased;
                _=cancel.cancelled()=>return Ok::<_,anyhow::Error>(()),
                changed=released.changed()=>{if changed.is_err(){return Ok(());}open=*released.borrow_and_update();if open{for b in held.drain(..){let _=handle.incoming(b,lease(||true));}}},
                p=output.recv()=>{let Some(p)=p else{return Ok(())};let bytes=p.bytes();let ih=usize::from(bytes[0]&15)*4;let th=usize::from(bytes[ih+12]>>4)*4;let payload=bytes.len()-ih-th;if payload>0&&hold.load(Ordering::SeqCst){let _=native_sender.try_send(p);continue;}let n=native.clone();let count=count.clone();p.deliver(move|b|async move{n.packet(b)?;count.fetch_add(payload,Ordering::SeqCst);Ok(())}).await?;},
                p=input.recv()=>{let Some(p)=p else{return Ok(())};if open{let _=handle.incoming(p,lease(||true));}else{ensure!(held.len()<32,"native ACK hold bound");held.push(p);}}
            }
        }
    });
    let flow = Flow {
        nonce: [3; 16],
        direction: 0,
        local_port: 4000,
        remote_port: 443,
        epoch: [4; 32],
    };
    let source_budget = Budget::default();
    let receiver_budget = Budget::default();
    let (sender, owner) = start(b_peer, client, gate_a, source_budget.clone(), flow.clone())?;
    let current_flag = Arc::new(AtomicBool::new(true));
    let flag = current_flag.clone();
    let peer = a_peer.clone();
    let epoch = flow.epoch;
    let allow = mask(true)?;
    let deny = mask(false)?;
    let current_origin = lease(|| true);
    let current: Current = Arc::new(move || {
        Some(Access {
            peer: peer.clone(),
            epoch,
            ports: if flag.load(Ordering::SeqCst) {
                allow.clone()
            } else {
                deny.clone()
            },
            permit: current_origin.clone(),
        })
    });
    let receiver = Receiver::new(
        remote,
        gate_b,
        receiver_budget.clone(),
        flow.clone(),
        connection,
        current,
    )?;
    Ok(Rig {
        receiver: Some(receiver),
        sender,
        owner: Some(owner),
        client: raw,
        flow,
        peer: a_peer,
        current: current_flag,
        profile,
        original: Arc::new(AtomicBool::new(true)),
        source,
        destination,
        source_budget,
        receiver_budget,
        native_app,
        release,
        native_bytes,
        hold_native,
        held_native,
        native_target,
        stop,
        pump,
        native_tasks: vec![one, two, native_pump],
    })
}
#[tokio::test]
async fn no_stream_before_credit_and_native_ack_is_required_for_phc2_receipt() -> Result<()> {
    let mut r = rig().await?;
    let result = async {
        let sender = r.sender.clone();
        let sending = tokio::spawn(async move {
            sender
                .send(Bytes::from(vec![3; 1024]), lease(|| true))
                .await
        });
        tokio::task::yield_now().await;
        ensure!(
            !sending.is_finished() && r.native_bytes.load(Ordering::SeqCst) == 0,
            "uncredited data admitted"
        );
        let access = r.access()?;
        let receiver = r.receiver.take().unwrap();
        let receiving = tokio::spawn(async move {
            let mut receiver = receiver;
            let result = receiver.receive(access).await;
            (receiver, result)
        });
        let mut bytes = [0; 1024];
        timeout(Duration::from_secs(2), r.native_app.read_exact(&mut bytes)).await??;
        ensure!(bytes == [3; 1024], "native payload mismatch");
        ensure!(
            !sending.is_finished() && !receiving.is_finished(),
            "copied native bytes produced PHC2 receipt before ACK"
        );
        r.release.send(true)?;
        let (receiver, received) = timeout(Duration::from_secs(2), receiving).await??;
        r.receiver = Some(receiver);
        let received = received?;
        let sent = timeout(Duration::from_secs(2), sending).await???;
        ensure!(
            sent == received,
            "native ACK receipt did not bind exact header"
        );
        // Completion does not automatically advertise another grant.
        let blocked = timeout(Duration::from_millis(50), r.client.open_bi()).await;
        ensure!(blocked.is_err(), "QUIC auto-replenished unissued credit");
        // Completed original credit can expire without relabeling next work.
        r.original.store(false, Ordering::SeqCst);
        let mut fresh = r.access()?;
        fresh.permit = lease(|| true);
        let sender = r.sender.clone();
        let sending =
            tokio::spawn(
                async move { sender.send(Bytes::from(vec![4; 64]), lease(|| true)).await },
            );
        let receiver = r.receiver.take().unwrap();
        let receiving = tokio::spawn(async move {
            let mut receiver = receiver;
            let result = receiver.receive(fresh).await;
            (receiver, result)
        });
        let mut next = [0; 64];
        timeout(Duration::from_secs(2), r.native_app.read_exact(&mut next)).await??;
        ensure!(next == [4; 64], "new credit lost continuing native flow");
        let (receiver, result) = timeout(Duration::from_secs(2), receiving).await??;
        r.receiver = Some(receiver);
        let result = result?;
        let sent = timeout(Duration::from_secs(2), sending).await???;
        ensure!(
            sent == result
                && u64::from_be_bytes(result[21..29].try_into()?) == 1
                && u64::from_be_bytes(result[29..37].try_into()?) == 1024,
            "second credit changed sequence/offset"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    r.cleanup().await?;
    result
}
#[tokio::test]
async fn prebuffered_quinn_body_cannot_borrow_new_receiver_grant() -> Result<()> {
    let mut r = rig().await?;
    let result = async {
        let access = r.access()?;
        let receiver = r.receiver.as_mut().unwrap();
        let mut receiving = Box::pin(receiver.receive(access));
        ensure!(
            futures_util::poll!(receiving.as_mut()).is_pending(),
            "RX did not await credited stream"
        );
        let (mut send, mut receipt) = timeout(Duration::from_secs(1), r.client.open_bi()).await??;
        let header = wire_header(r.flow.header(0, 0, 1024, [6; 16])?, [6; 16], 10_000)?;
        send.write_all(&header).await?;
        send.write_all(&[3; 1024]).await?;
        send.finish()?;
        ensure!(
            timeout(Duration::from_secs(1), send.stopped())
                .await??
                .is_none(),
            "Quinn did not ACK prebuffered body"
        );
        r.original.store(false, Ordering::SeqCst);
        r.current.store(true, Ordering::SeqCst);
        ensure!(
            timeout(Duration::from_secs(1), receiving.as_mut())
                .await?
                .is_err(),
            "prebuffered bytes borrowed fresh receiver grant"
        );
        drop(receiving);
        ensure!(
            r.native_bytes.load(Ordering::SeqCst) == 0,
            "expired prebuffer reached native TCP"
        );
        let mut byte = [0];
        ensure!(
            !matches!(
                timeout(Duration::from_millis(50), receipt.read(&mut byte)).await,
                Ok(Ok(Some(_)))
            ),
            "expired chunk produced receipt"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    r.cleanup().await?;
    result
}
#[tokio::test]
async fn original_acl_and_current_acl_are_both_required() -> Result<()> {
    let mut r = rig().await?;
    let result = async {
        let mut old = r.access()?;
        old.ports = mask(false)?;
        ensure!(
            r.receiver.as_mut().unwrap().receive(old).await.is_err(),
            "fresh broader ACL widened original credit"
        );
        let old = r.access()?;
        r.current.store(false, Ordering::SeqCst);
        ensure!(
            r.receiver.as_mut().unwrap().receive(old).await.is_err(),
            "original allow bypassed current denial"
        );
        ensure!(
            r.native_bytes.load(Ordering::SeqCst) == 0,
            "denied credit reached native TCP"
        );
        ensure!(
            timeout(Duration::from_millis(50), r.client.open_bi())
                .await
                .is_err(),
            "denied credit advertised stream"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    r.cleanup().await?;
    result
}

#[tokio::test]
async fn current_acl_or_profile_retirement_while_native_ack_blocked_cannot_publish_receipt(
) -> Result<()> {
    for profile in [false, true] {
        let mut r = rig().await?;
        let result = async {
            let sender = r.sender.clone();
            let mut sending = tokio::spawn(async move {
                sender
                    .send(Bytes::from(vec![3; 1024]), lease(|| true))
                    .await
            });
            let original = r.access()?;
            let receiver = r.receiver.take().unwrap();
            let receiving = tokio::spawn(async move {
                let mut receiver = receiver;
                let result = receiver.receive(original).await;
                (receiver, result)
            });
            let mut bytes = [0; 1024];
            timeout(Duration::from_secs(2), r.native_app.read_exact(&mut bytes)).await??;
            ensure!(
                bytes == [3; 1024] && !receiving.is_finished() && !sending.is_finished(),
                "native ACK was not held at revocation boundary"
            );
            if profile {
                r.profile.store(false, Ordering::SeqCst);
            } else {
                r.current.store(false, Ordering::SeqCst);
            }
            r.release.send(true)?;
            let (receiver, result) = timeout(Duration::from_secs(1), receiving).await??;
            r.receiver = Some(receiver);
            ensure!(
                result.is_err(),
                "revoked current ACL produced native receipt"
            );
            ensure!(
                timeout(Duration::from_millis(50), &mut sending)
                    .await
                    .is_err(),
                "source received revoked native ACK receipt"
            );
            sending.abort();
            let _ = sending.await;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        r.cleanup().await?;
        result?;
    }
    Ok(())
}
#[tokio::test]
async fn actual_quinn_foreign_header_is_rejected_before_native_write() -> Result<()> {
    let mut r = rig().await?;
    let result = async {
        let original = r.access()?;
        let mut receiving = Box::pin(r.receiver.as_mut().unwrap().receive(original));
        ensure!(
            futures_util::poll!(receiving.as_mut()).is_pending(),
            "receiver did not await original credit"
        );
        let (mut body, mut reply) = timeout(Duration::from_secs(1), r.client.open_bi()).await??;
        let mut header = wire_header(r.flow.header(0, 0, 1024, [6; 16])?, [6; 16], 10_000)?;
        header[93] = 1;
        body.write_all(&header).await?;
        body.write_all(&[3; 1024]).await?;
        body.finish()?;
        ensure!(
            timeout(Duration::from_secs(1), receiving.as_mut())
                .await?
                .is_err(),
            "noncanonical header accepted"
        );
        drop(receiving);
        ensure!(
            r.native_bytes.load(Ordering::SeqCst) == 0,
            "foreign header wrote native bytes"
        );
        let mut byte = [0];
        ensure!(
            !matches!(
                timeout(Duration::from_millis(50), reply.read(&mut byte)).await,
                Ok(Ok(Some(_)))
            ),
            "foreign header produced receipt"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    r.cleanup().await?;
    result
}

#[tokio::test]
async fn abandoning_issued_receive_credit_retires_native_and_quinn_generation() -> Result<()> {
    let mut r = rig().await?;
    let result = async {
        let original = r.access()?;
        let receiver = r.receiver.as_mut().unwrap();
        let mut receiving = Box::pin(receiver.receive(original));
        ensure!(
            futures_util::poll!(receiving.as_mut()).is_pending(),
            "receiver did not hold issued credit"
        );
        drop(receiving);
        let receiver = r.receiver.as_mut().unwrap();
        ensure!(
            !receiver.gate.state.alive.load(Ordering::SeqCst),
            "abandoned credit generation stayed live"
        );
        ensure!(
            receiver.native.read_chunk().await.is_err(),
            "abandoned credit kept native owner"
        );
        let fresh = Access {
            peer: r.peer.clone(),
            epoch: r.flow.epoch,
            ports: mask(true)?,
            permit: lease(|| true),
        };
        ensure!(
            receiver.receive(fresh).await.is_err(),
            "fresh grant revived abandoned receive credit"
        );
        let b = r.receiver_budget.0.lock().unwrap();
        ensure!(
            b.total.bytes == 0 && b.total.chunks == 0,
            "abandoned credit leaked body reservation"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    r.cleanup().await?;
    result
}
#[tokio::test]
async fn header_binding_rejects_each_foreign_field_and_size() -> Result<()> {
    let r = rig().await?;
    let result = (|| {
        let receiver = r.receiver.as_ref().unwrap();
        let valid = wire_header(r.flow.header(0, 0, 1024, [6; 16])?, [6; 16], 10_000)?;
        ensure!(
            receiver.header(&valid)?.0 == 1024,
            "valid bound header rejected"
        );
        for index in [0, 4, 20, 21, 29, 41, 43, 45, 93] {
            let mut bad = valid;
            bad[index] ^= 1;
            ensure!(
                receiver.header(&bad).is_err(),
                "foreign header byte {index} accepted"
            );
        }
        for len in [0u32, 8193] {
            let mut bad = valid;
            bad[37..41].copy_from_slice(&len.to_be_bytes());
            ensure!(
                receiver.header(&bad).is_err(),
                "invalid chunk size accepted"
            );
        }
        let mut zero_ttl = valid;
        zero_ttl[93..96].fill(0);
        ensure!(receiver.header(&zero_ttl).is_err(), "zero TTL accepted");
        let mut old_version = valid;
        old_version[..4].copy_from_slice(b"PHC1");
        ensure!(
            receiver.header(&old_version).is_err(),
            "old unbounded protocol accepted"
        );
        let maximum = wire_header(r.flow.header(0, 0, 1024, [6; 16])?, [6; 16], 15_000)?;
        ensure!(
            receiver.header(&maximum)?.2 == Duration::from_millis(15_000),
            "canonical maximum TTL rejected"
        );
        let mut too_long = valid;
        too_long[93..96].copy_from_slice(&15_001u32.to_be_bytes()[1..]);
        ensure!(
            receiver.header(&too_long).is_err(),
            "oversized TTL accepted"
        );
        let mut zero = valid;
        zero[77..93].fill(0);
        ensure!(receiver.header(&zero).is_err(), "empty chunk ID accepted");
        Ok::<_, anyhow::Error>(())
    })();
    r.cleanup().await?;
    result
}

#[tokio::test]
async fn source_original_expiry_must_revoke_already_queued_receiver_native_payload() -> Result<()> {
    let mut r = rig().await?;
    let result =
        async {
            r.hold_native.store(true, Ordering::SeqCst);
            use crate::private_network::authority_clock::{RequestWindow, SuspendClock};
            struct AgedClock {
                start: std::time::Instant,
                offset: std::sync::atomic::AtomicU64,
            }
            impl SuspendClock for AgedClock {
                fn elapsed_since_boot(&self) -> Result<Duration> {
                    Ok(self.start.elapsed()
                        + Duration::from_millis(self.offset.load(Ordering::SeqCst)))
                }
            }
            let clock = Arc::new(AgedClock {
                start: std::time::Instant::now(),
                offset: std::sync::atomic::AtomicU64::new(0),
            });
            let window = RequestWindow::start(clock.clone())?;
            // It is 14.3s old before waiting for credit. Delaying credit by
            // 200ms makes any pre-open TTL sample observably unsafe; its final
            // ~500ms must be sampled only AFTER the stream credit resolves.
            clock.offset.store(14_300, Ordering::SeqCst);
            let server_expiry = std::time::SystemTime::now() + Duration::from_secs(60);
            let remaining_window = window.clone();
            let sender = r.sender.clone();
            let sending = tokio::spawn(async move {
                sender
                    .send(
                        Bytes::from(vec![3; 1024]),
                        SendPermit::bounded(
                            move || window.check(server_expiry).is_ok(),
                            move || remaining_window.remaining(server_expiry).ok(),
                        ),
                    )
                    .await
            });
            tokio::time::sleep(Duration::from_millis(200)).await;
            let original = r.access()?;
            let receiver = r.receiver.take().unwrap();
            let receiving = tokio::spawn(async move {
                let mut receiver = receiver;
                let result = receiver.receive(original).await;
                (receiver, result)
            });
            let queued = timeout(Duration::from_secs(2), r.held_native.recv())
                .await?
                .ok_or_else(|| anyhow::anyhow!("native payload not queued"))?;
            ensure!(
                r.native_bytes.load(Ordering::SeqCst) == 0,
                "native delivery was not held"
            );
            ensure!(
                timeout(Duration::from_secs(1), sending).await??.is_err(),
                "source original did not actually retire"
            );
            ensure!(
                r.original.load(Ordering::SeqCst) && r.current.load(Ordering::SeqCst),
                "receiver grant unexpectedly expired too"
            );
            let native = r.native_target.clone();
            // The API permits synchronous native work while constructing the
            // future; validation must precede callback invocation too.
            let delivery = queued
                .deliver(move |bytes| {
                    let result = native.packet(bytes);
                    async move { result }
                })
                .await;
            let mut bytes = [0; 1024];
            let read = timeout(
                Duration::from_millis(100),
                r.native_app.read_exact(&mut bytes),
            )
            .await;
            receiving.abort();
            let _ = receiving.await;
            ensure!(
            delivery.is_err() && !matches!(read, Ok(Ok(_))),
            "EXPIRED SOURCE ORIGIN delivered queued native payload under newer receiver authority"
        );
            Ok::<_, anyhow::Error>(())
        }
        .await;
    let cleanup = r.cleanup().await;
    result.and(cleanup)
}

#[tokio::test]
async fn credited_endpoint_never_exposes_raw_cached_or_new_quinn_connection() -> Result<()> {
    let r = rig().await?;
    let result = async {
        ensure!(
            r.destination.connection_count(&r.peer) == 1,
            "typed connected fixture missing"
        );
        ensure!(
            r.destination.prepared(&r.peer).is_none(),
            "credited cached connection escaped raw accessor"
        );
        ensure!(
            matches!(
                timeout(Duration::from_millis(50), r.destination.accept()).await,
                Ok(Err(_))
            ),
            "raw accept consumed or waited for credited connection"
        );
        ensure!(
            matches!(
                timeout(Duration::from_millis(50), r.destination.accept_fenced()).await,
                Ok(Err(_))
            ),
            "legacy fenced accept bypassed credited owner"
        );
        ensure!(
            r.destination.connect(&r.peer).await.is_err()
                && r.destination.connect_additional(&r.peer).await.is_err(),
            "raw connect bypassed credited cached connection"
        );
        ensure!(
            !r.destination.connection_stats(&r.peer).is_empty(),
            "credited read-only stats unexpectedly hidden"
        );
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = r.cleanup().await;
    result.and(cleanup)
}
