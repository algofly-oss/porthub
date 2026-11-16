//! Bounded pinned-TLS flow-open. A remote epoch is context, never authority.
use super::flow_authority::{Context, LocalAuthority, Side};
use super::*;
use crate::private_network::authority_clock::{NativeClock, RequestWindow};
use porthub_mesh::streams::CreditedReceiverConnection;
use std::time::Duration;
fn remaining(permit: &SendPermit) -> Result<u32> {
    let n = permit
        .remaining()
        .ok_or_else(|| anyhow::anyhow!("flow-open original deadline unknown"))?
        .as_millis();
    ensure!(
        (1..=15000).contains(&n),
        "flow-open original deadline outside wire bounds"
    );
    Ok(n as u32)
}
fn received(start: RequestWindow, bytes: &[u8]) -> Result<SendPermit> {
    let ms = u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]);
    ensure!((1..=15000).contains(&ms), "flow-open remote bound invalid");
    let limit = Duration::from_millis(u64::from(ms));
    let a = start.clone();
    let p = SendPermit::bounded(
        move || a.remaining_within(limit).is_ok(),
        move || start.remaining_within(limit).ok(),
    );
    ensure!(p.valid(), "flow-open remote original expired");
    Ok(p)
}
// The same immutable opening witness also fences Quinn's prepared encrypted
// transmissions/retransmissions. Checking only read/write futures is insufficient.
struct Flight {
    gate: Gate,
    key: [u8; HEADER],
    close: Box<dyn Fn() + Send + Sync>,
    complete: bool,
}
impl Flight {
    fn new(
        gate: &Gate,
        permit: SendPermit,
        close: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self> {
        ensure!(
            gate.state.alive.load(Ordering::SeqCst) && permit.remaining().is_some(),
            "flow-open generation/original retired"
        );
        let mut key = [0; HEADER];
        key[..4].copy_from_slice(b"OPEN");
        getrandom::fill(&mut key[4..20])
            .map_err(|_| anyhow::anyhow!("flow-open nonce unavailable"))?;
        let mut pending = gate.state.pending.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            pending.is_empty(),
            "flow-open generation already has pending work"
        );
        pending.insert(key, permit);
        Ok(Self {
            gate: gate.clone(),
            key,
            close: Box::new(close),
            complete: false,
        })
    }
    fn narrow(&mut self, permit: SendPermit) -> Result<()> {
        let mut pending = self
            .gate
            .state
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let old = pending
            .get(&self.key)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("opening fence disappeared"))?;
        let both = SendPermit::combine(vec![old, permit]);
        ensure!(both.valid(), "opening source retired before fence update");
        pending.insert(self.key, both);
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        let mut pending = self
            .gate
            .state
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        ensure!(
            pending.get(&self.key).is_some_and(SendPermit::valid),
            "flow-open original expired before publication"
        );
        pending.remove(&self.key);
        self.complete = true;
        Ok(())
    }
}
impl Drop for Flight {
    fn drop(&mut self) {
        if !self.complete {
            self.gate.retire();
            (self.close)();
            self.gate
                .state
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&self.key);
        }
    }
}
/// Authority applies only to creating this exact native leg, not future bytes.
/// Future DATA/FIN must obtain sealed NativeRead first-origin admissions.
pub(crate) struct Opened {
    context: Context,
    opening: SendPermit,
    side: Side,
}
impl Opened {
    pub(crate) fn context(&self) -> Context {
        self.context.clone()
    }
    pub(crate) async fn connect_destination(
        &self,
        handle: &porthub_network::tcp_stream::tagged::Handle,
    ) -> Result<porthub_network::tcp_stream::tagged::Connection> {
        ensure!(
            self.side == Side::Acceptor,
            "initiator cannot create destination native leg"
        );
        // Destination initiates the OS application leg only AFTER reciprocal
        // flow-open. The native connection's outgoing tuple is initiator→service.
        let tuple = self.context.source_native_tuple(Side::Acceptor);
        self.opening
            .during(handle.connect(tuple, self.opening.clone()))
            .await?
    }
}
async fn initiate_inner(
    connection: &BoundedSourceConnection,
    gate: &Gate,
    local: &LocalAuthority,
    nonce: [u8; 16],
    source: u16,
    destination: u16,
    side: Side,
    expected: Option<&Context>,
) -> Result<Opened> {
    local.bind_transport(
        connection.peer(),
        connection.local_ip(),
        connection.belongs_to(&gate.factory),
    )?;
    let original = SendPermit::combine(vec![local.original(), gate.state.parent.clone()]);
    ensure!(original.remaining().is_some(), "flow-open unknown original");
    // This start precedes the remote response witness sampling. Never start a
    // remote deadline when its delayed response arrives.
    let start = RequestWindow::start(Arc::new(NativeClock))?;
    let closing = connection.clone();
    let mut flight = Flight::new(gate, original.clone(), move || closing.close())?;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        original.during(async {
            let (mut output, mut input) = connection.open_chunk(&original).await?;
            let mut request = [0; HEADER];
            request[..4].copy_from_slice(if side == Side::Initiator {
                b"PHO2"
            } else {
                b"PHR2"
            });
            request[4..36].copy_from_slice(&local.local_epoch());
            request[36..52].copy_from_slice(&nonce);
            request[52..54].copy_from_slice(&source.to_be_bytes());
            request[54..56].copy_from_slice(&destination.to_be_bytes());
            request[56..59].copy_from_slice(&remaining(&original)?.to_be_bytes()[1..]);
            output.write_all(&request).await?;
            output.finish()?;
            let mut response = [0; HEADER];
            input.read_exact(&mut response).await?;
            let mut extra = [0];
            ensure!(
                input.read(&mut extra).await?.is_none(),
                "flow-open response exceeds exact window"
            );
            ensure!(
                &response[..4] == b"PHA2"
                    && response[68..84] == nonce
                    && response[84..88] == request[52..56]
                    && response[91..].iter().all(|b| *b == 0),
                "foreign/noncanonical flow-open response"
            );
            let context = Context::from_local(
                local,
                side,
                response[4..36].try_into()?,
                nonce,
                source,
                destination,
            )?;
            ensure!(
                response[36..68] == context.digest(),
                "flow-open reciprocal identity/epoch mismatch"
            );
            ensure!(
                expected.is_none_or(|old| old.digest() == context.digest()),
                "response flow cannot replace original context"
            );
            let opening =
                SendPermit::combine(vec![original.clone(), received(start, &response[88..91])?]);
            flight.narrow(opening.clone())?;
            ensure!(
                output.stopped().await?.is_none() && opening.valid(),
                "flow-open request not acknowledged under original"
            );
            Ok(Opened {
                context,
                opening,
                side,
            })
        }),
    )
    .await???;
    flight.finish()?;
    Ok(result)
}
async fn accept_inner(
    connection: &mut CreditedReceiverConnection,
    gate: &Gate,
    local: &LocalAuthority,
    side: Side,
    expected: Option<&Context>,
) -> Result<Opened> {
    local.bind_transport(
        connection.peer(),
        connection.local_ip(),
        connection.belongs_to(&gate.factory),
    )?;
    let original = SendPermit::combine(vec![local.original(), gate.state.parent.clone()]);
    ensure!(
        original.remaining().is_some(),
        "flow-open unknown local original"
    );
    let start = RequestWindow::start(Arc::new(NativeClock))?;
    let closing = connection.closer();
    let mut flight = Flight::new(gate, original.clone(), move || closing.close())?;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        original.during(async {
            let (mut output, mut input) = connection.accept_one(&original).await?;
            let mut request = [0; HEADER];
            input.read_exact(&mut request).await?;
            let mut extra = [0];
            ensure!(
                input.read(&mut extra).await?.is_none(),
                "flow-open request exceeds exact window"
            );
            ensure!(
                &request[..4]
                    == (if side == Side::Acceptor {
                        b"PHO2"
                    } else {
                        b"PHR2"
                    })
                    && request[59..].iter().all(|b| *b == 0),
                "foreign/noncanonical flow-open request"
            );
            let nonce = request[36..52].try_into()?;
            let source = u16::from_be_bytes(request[52..54].try_into()?);
            let destination = u16::from_be_bytes(request[54..56].try_into()?);
            let context = Context::from_local(
                local,
                side,
                request[4..36].try_into()?,
                nonce,
                source,
                destination,
            )?;
            ensure!(
                expected.is_none_or(|old| old.digest() == context.digest()),
                "reverse source cannot replace original flow context"
            );
            let opening =
                SendPermit::combine(vec![original.clone(), received(start, &request[56..59])?]);
            flight.narrow(opening.clone())?;
            opening
                .during(async {
                    let mut response = [0; HEADER];
                    response[..4].copy_from_slice(b"PHA2");
                    response[4..36].copy_from_slice(&local.local_epoch());
                    response[36..68].copy_from_slice(&context.digest());
                    response[68..84].copy_from_slice(&nonce);
                    response[84..88].copy_from_slice(&request[52..56]);
                    response[88..91].copy_from_slice(&remaining(&opening)?.to_be_bytes()[1..]);
                    output.write_all(&response).await?;
                    output.finish()?;
                    ensure!(
                        output.stopped().await?.is_none(),
                        "flow-open response reset"
                    );
                    Ok::<_, anyhow::Error>(())
                })
                .await??;
            Ok(Opened {
                context,
                opening,
                side,
            })
        }),
    )
    .await???;
    flight.finish()?;
    Ok(result)
}

pub(crate) async fn initiate(
    connection: &BoundedSourceConnection,
    gate: &Gate,
    local: &LocalAuthority,
    nonce: [u8; 16],
    source: u16,
    destination: u16,
) -> Result<Opened> {
    initiate_inner(
        connection,
        gate,
        local,
        nonce,
        source,
        destination,
        Side::Initiator,
        None,
    )
    .await
}
pub(crate) async fn accept(
    connection: &mut CreditedReceiverConnection,
    gate: &Gate,
    local: &LocalAuthority,
) -> Result<Opened> {
    accept_inner(connection, gate, local, Side::Acceptor, None).await
}
pub(crate) async fn initiate_response(
    connection: &BoundedSourceConnection,
    gate: &Gate,
    local: &LocalAuthority,
    opened: &Opened,
) -> Result<Opened> {
    ensure!(
        opened.side == Side::Acceptor,
        "only accepted flow can initiate response binding"
    );
    let (nonce, source, destination) = opened.context.parameters();
    initiate_inner(
        connection,
        gate,
        local,
        nonce,
        source,
        destination,
        Side::Acceptor,
        Some(&opened.context),
    )
    .await
}
pub(crate) async fn accept_response(
    connection: &mut CreditedReceiverConnection,
    gate: &Gate,
    local: &LocalAuthority,
    opened: &Opened,
) -> Result<Opened> {
    ensure!(
        opened.side == Side::Initiator,
        "only initiating flow can accept response binding"
    );
    accept_inner(
        connection,
        gate,
        local,
        Side::Initiator,
        Some(&opened.context),
    )
    .await
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::private_network::{authority_event::Authority, sparse};
    use porthub_mesh::{streams::Endpoint, Identity};
    use tokio::time::{timeout, Duration};
    pub(crate) fn local(
        own: &Peer,
        remote: &Peer,
        label: &str,
    ) -> Result<(sparse::Handle, LocalAuthority)> {
        let info = |p: &Peer| serde_json::json!({"id":p.id,"ip":p.ip,"fingerprint":p.fingerprint,"instance":p.instance,"hostname":format!("{}.phub",p.id)});
        let expiry = chrono::Utc::now() + chrono::Duration::seconds(60);
        let epoch = label.repeat(64);
        let base = serde_json::from_value(
            serde_json::json!({"workspace":"w","self":own.id,"revision":1,"expires_at":expiry,"sparse":{"protocol":1,"epoch":epoch},"peers":[info(own)],"grants":[]}),
        )?;
        let pair = serde_json::from_value(
            serde_json::json!({"workspace":"w","self":own.id,"epoch":epoch,"revision":1,"expires_at":expiry,"local":info(own),"peer":info(remote),"grants":[{"source":"a","destination":"b","protocol":"tcp","ports":[{"start":443,"end":443}]}]}),
        )?;
        let authority = || {
            Authority::new(
                (),
                Some(RequestWindow::start(Arc::new(NativeClock)).unwrap()),
                expiry,
            )
        };
        let (h, _) = sparse::channel();
        h.update_base_authority(&base, authority());
        h.installed_authority(
            &porthub_network::policy::Lookup {
                kind: "peer".into(),
                value: remote.id.clone(),
            },
            pair,
            authority(),
        );
        let view = LocalAuthority::capture(&h, "w", &own.id, &remote.id)?;
        Ok((h, view))
    }
    async fn exercise(port: u16) -> Result<()> {
        let a = Identity::new()?;
        let b = Identity::new()?;
        let ap = Peer {
            id: "a".into(),
            ip: "10.234.248.1".parse()?,
            fingerprint: a.fingerprint().into(),
            instance: "a-instance".into(),
        };
        let bp = Peer {
            id: "b".into(),
            ip: "10.234.248.2".parse()?,
            fingerprint: b.fingerprint().into(),
            instance: "b-instance".into(),
        };
        let ga = Gate::new(SendPermit::control(|| true));
        let gb = Gate::new(SendPermit::control(|| true));
        let (ea, mut ioa) = Endpoint::new_fenced_source(a, ap.ip, ga.factory())?;
        let (eb, mut iob) = Endpoint::new_fenced_credited(b, bp.ip, gb.factory())?;
        ea.update_peers(vec![bp.clone()])?;
        eb.update_peers(vec![ap.clone()])?;
        let ia = ioa.ingress();
        let ib = iob.ingress();
        let stop = CancellationToken::new();
        let cancel = stop.clone();
        let pump = tokio::spawn(async move {
            loop {
                tokio::select! {_=cancel.cancelled()=>break,p=ioa.outgoing()=>match p{Some(p)=>{let _=ib.send_reliable_guarded(ap.ip,p.payload,p.permit).await;},None=>break},p=iob.outgoing()=>match p{Some(p)=>{let _=ia.send_reliable_guarded(bp.ip,p.payload,p.permit).await;},None=>break}}
            }
        });
        let result = async {
            let (client, server) = timeout(Duration::from_secs(2), async {
                tokio::join!(ea.connect_source(&bp), eb.accept_credited())
            })
            .await?;
            let client = client?;
            let mut server = server?;
            let (_ha, a) = local(&ap, &bp, "a")?;
            let (_hb, b) = local(&bp, &ap, "b")?;
            let (left, right) = timeout(Duration::from_secs(3), async {
                tokio::join!(
                    initiate(&client, &ga, &a, [9; 16], 42000, port),
                    accept(&mut server, &gb, &b)
                )
            })
            .await?;
            if port == 443 {
                let l = left?;
                let r = right?;
                ensure!(
                    l.context.digest() == r.context.digest(),
                    "pinned endpoints disagree on reciprocal flow"
                );
                ensure!(
                    l.opening.remaining().is_some() && r.opening.remaining().is_some(),
                    "opening lost original bound"
                );
                ensure!(
                    ga.state.pending.lock().unwrap().is_empty()
                        && gb.state.pending.lock().unwrap().is_empty(),
                    "ACKed opening left fences"
                );
            } else {
                ensure!(
                    left.is_err() && right.is_err(),
                    "denied service opened native authority"
                );
                ensure!(
                    !gb.state.alive.load(Ordering::SeqCst),
                    "denied receiver did not retire prepared transmission generation"
                );
            }
            Ok::<_, anyhow::Error>(())
        }
        .await;
        stop.cancel();
        ea.close();
        eb.close();
        timeout(Duration::from_secs(1), pump).await??;
        result
    }
    #[tokio::test]
    async fn actual_pinned_tls_reciprocal_open_binds_distinct_local_epochs_and_original_deadlines(
    ) -> Result<()> {
        exercise(443).await
    }
    #[tokio::test]
    async fn actual_pinned_tls_denied_service_never_publishes_opening_authority() -> Result<()> {
        exercise(80).await
    }
}

#[cfg(test)]
mod original_deadline_tests {
    use super::*;
    use crate::private_network::authority_clock::SuspendClock;
    use std::sync::atomic::AtomicU64;
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            Ok(Duration::from_millis(self.0.load(Ordering::SeqCst)))
        }
    }
    #[test]
    fn delayed_open_header_and_prepared_quinn_packet_keep_precredit_start_and_minimum() -> Result<()>
    {
        let clock = Arc::new(Clock(AtomicU64::new(0)));
        let start = RequestWindow::start(clock.clone())?;
        let gate = Gate::new(SendPermit::control(|| true));
        let closed = Arc::new(AtomicBool::new(false));
        let observed = closed.clone();
        let local = SendPermit::bounded(|| true, || Some(Duration::from_secs(15)));
        let mut flight = Flight::new(&gate, local, move || observed.store(true, Ordering::SeqCst))?;
        clock.0.store(800, Ordering::SeqCst);
        let remote = received(start.clone(), &[0, 3, 232])?;
        ensure!(
            remote.remaining() == Some(Duration::from_millis(200)),
            "header arrival reset remote expiry"
        );
        flight.narrow(remote)?;
        let prepared = gate.factory.snapshot().unwrap();
        clock.0.store(1000, Ordering::SeqCst);
        ensure!(
            !prepared.valid() && gate.factory.snapshot().is_none(),
            "prepared opening response borrowed a fresh local permit"
        );
        ensure!(flight.finish().is_err(), "expired opening was published");
        drop(flight);
        ensure!(
            closed.load(Ordering::SeqCst),
            "failed opening did not close exact generation"
        );
        ensure!(
            received(start.clone(), &[0, 0, 0]).is_err() && received(start, &[0, 58, 153]).is_err(),
            "unknown/oversized lifetime accepted"
        );
        Ok(())
    }
}
