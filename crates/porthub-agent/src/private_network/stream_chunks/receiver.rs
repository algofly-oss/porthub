//! Experimental one-credit native-ACK receiver. Not negotiated by production.
//! The native leg must already belong to separately authenticated flow-open
//! admission. This validates chunks; it does not authorize opening a TCP leg.
use super::*;
use crate::private_network::authority_clock::{NativeClock, RequestWindow};
use porthub_mesh::streams::{CreditedReceiverConnection, ReceiverCloser};
use porthub_network::{policy::pair_acl::CompiledPortMask, tcp_stream::tagged};
#[derive(Clone)]
pub(crate) struct Access {
    pub peer: Peer,
    pub epoch: [u8; 32],
    /// The initiating connection's service-port mask, including its response
    /// direction. Never substitute a reverse-initiation grant for this mask.
    pub ports: CompiledPortMask,
    pub permit: SendPermit,
}
/// Bounded installed-policy lookup only: no IO, awaits, or re-entry into the
/// transport gate/factory. Returned mask/permit must share the exact peer epoch.
pub(crate) type Current = Arc<dyn Fn() -> Option<Access> + Send + Sync>;
pub(crate) struct Receiver {
    connection: CreditedReceiverConnection,
    gate: Gate,
    budget: Budget,
    flow: Flow,
    native: Arc<tagged::Connection>,
    current: Current,
    sequence: u64,
    offset: u64,
    finished: bool,
    terminal: Option<SendPermit>,
    _connection_credit: Credit,
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.gate.retire();
        if !self.finished {
            self.native.retire();
        }
        self.connection.closer().close();
    }
}
struct Receiving {
    gate: Gate,
    native: Arc<tagged::Connection>,
    connection: ReceiverCloser,
    armed: bool,
}
impl Drop for Receiving {
    fn drop(&mut self) {
        if self.armed {
            self.gate.retire();
            self.native.retire();
            self.connection.close();
        }
    }
}
impl Receiver {
    pub(crate) fn from_native(
        owner: super::flow_open::NativeOwner,
        connection: CreditedReceiverConnection,
        gate: Gate,
        budget: Budget,
        current: Current,
    ) -> Result<Self> {
        let (context, side, native) = owner.parts();
        let other = match side {
            super::flow_authority::Side::Initiator => super::flow_authority::Side::Acceptor,
            super::flow_authority::Side::Acceptor => super::flow_authority::Side::Initiator,
        };
        Self::new(
            connection,
            gate,
            budget,
            context.data_flow(other),
            native,
            current,
        )
    }
    fn new(
        connection: CreditedReceiverConnection,
        gate: Gate,
        budget: Budget,
        flow: Flow,
        native: Arc<tagged::Connection>,
        current: Current,
    ) -> Result<Self> {
        ensure!(
            connection.belongs_to(&gate.factory),
            "RX endpoint has no pre-issued-credit profile/fence"
        );
        // Identity/fingerprint/instance are sealed by Endpoint::register in accept_credited.
        flow.header(0, 0, 1, [1; 16])?;
        let tuple = native.flow();
        ensure!(
            *tuple.source.ip() == connection.peer().ip
                && *tuple.destination.ip() == connection.local_ip()
                && tuple.source.port() == flow.local_port
                && tuple.destination.port() == flow.remote_port,
            "RX native tuple/identity mismatch"
        );
        ensure!(
            gate.state
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "RX generation already admitted work"
        );
        let credit = budget.receiver_connection(&connection.peer().id, flow.nonce)?;
        Ok(Self {
            connection,
            gate,
            budget,
            flow,
            native,
            current,
            sequence: 0,
            offset: 0,
            finished: false,
            terminal: None,
            _connection_credit: credit,
        })
    }
    pub(super) fn retire(&self) {
        self.gate.retire();
        self.connection.closer().close();
        self.native.retire();
    }
    pub(super) fn terminal(&self) -> Option<SendPermit> {
        self.terminal.clone()
    }
    pub(super) fn agrees(&self, native: &Arc<tagged::Connection>, flow: &Flow) -> bool {
        Arc::ptr_eq(native, &self.native)
            && self.flow.nonce == flow.nonce
            && self.flow.direction == flow.direction
            && self.flow.local_port == flow.local_port
            && self.flow.remote_port == flow.remote_port
            && self.flow.epoch == flow.epoch
    }
    fn service(&self) -> u16 {
        if self.flow.direction == 0 {
            self.flow.remote_port
        } else {
            self.flow.local_port
        }
    }
    fn valid_access(access: &Access, peer: &Peer, epoch: &[u8; 32], port: u16) -> bool {
        access.peer == *peer
            && access.epoch == *epoch
            && access.ports.contains(port)
            && access.permit.valid()
            && access.permit.remaining().is_some()
    }
    fn header(&self, h: &[u8; HEADER]) -> Result<(usize, [u8; 16], std::time::Duration)> {
        ensure!(
            (&h[..4] == b"PHC2" || &h[..4] == b"PHF2")
                && h[4..20] == self.flow.nonce
                && h[20] == self.flow.direction
                && h[45..77] == self.flow.epoch,
            "foreign/noncanonical RX header"
        );
        ensure!(
            u64::from_be_bytes(h[21..29].try_into()?) == self.sequence
                && u64::from_be_bytes(h[29..37].try_into()?) == self.offset,
            "RX sequence/offset mismatch"
        );
        ensure!(
            u16::from_be_bytes(h[41..43].try_into()?) == self.flow.local_port
                && u16::from_be_bytes(h[43..45].try_into()?) == self.flow.remote_port,
            "RX ports mismatch"
        );
        let length = u32::from_be_bytes(h[37..41].try_into()?) as usize;
        let id: [u8; 16] = h[77..93].try_into()?;
        ensure!(
            ((&h[..4] == b"PHC2" && (1..=CHUNK).contains(&length))
                || (&h[..4] == b"PHF2" && length == 0))
                && id != [0; 16],
            "RX size/nonce invalid"
        );
        let millis = u32::from_be_bytes([0, h[93], h[94], h[95]]);
        ensure!(
            (1..=15_000).contains(&millis),
            "RX source remaining lifetime invalid"
        );
        Ok((
            length,
            id,
            std::time::Duration::from_millis(u64::from(millis)),
        ))
    }
    pub(crate) async fn receive(&mut self, original: Access) -> Result<[u8; HEADER]> {
        ensure!(!self.finished, "RX DATA/FIN after terminal event");
        let peer = self.connection.peer().clone();
        let epoch = self.flow.epoch;
        let port = self.service();
        ensure!(
            Self::valid_access(&original, &peer, &epoch, port),
            "original RX ACL denied"
        );
        let current = self.current.clone();
        let current_at_issue =
            current().ok_or_else(|| anyhow::anyhow!("current RX authority unavailable"))?;
        ensure!(
            Self::valid_access(&current_at_issue, &peer, &epoch, port),
            "current RX authority denied"
        );
        let combined = SendPermit::combine(vec![
            original.permit.clone(),
            current_at_issue.permit.clone(),
            self.gate.state.parent.clone(),
        ]);
        ensure!(combined.remaining().is_some(), "RX original bound unknown");
        let old = original.clone();
        let owner = self.gate.state.clone();
        let permit = combined.constrain(move || {
            let valid = owner.alive.load(Ordering::SeqCst)
                && owner.parent.valid()
                && Self::valid_access(&old, &peer, &epoch, port)
                && current().is_some_and(|now| Self::valid_access(&now, &peer, &epoch, port));
            if !valid {
                owner.retire();
            }
            valid
        });
        ensure!(permit.valid(), "current RX ACL denied");
        // Reserve the full advertised per-stream capacity before granting QUIC
        // any stream credit. Header/body may arrive before accept_bi is polled.
        let _credit =
            self.budget
                .charge(&self.connection.peer().id, self.flow.nonce, Some(CHUNK))?;
        // Captured BEFORE advertising credit. Source remaining is sampled
        // only after the sender's open_bi resolves, so shortening this start
        // is conservative; never start the received TTL at header arrival.
        let credit_start = RequestWindow::start(Arc::new(NativeClock))?;
        let mut key = self
            .flow
            .header(self.sequence, self.offset, CHUNK, [2; 16])?;
        key[..4].copy_from_slice(b"RXCR");
        {
            let mut pending = self
                .gate
                .state
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            ensure!(pending.is_empty(), "RX original credit already outstanding");
            pending.insert(key, permit.clone());
        }
        let mut receiving = Receiving {
            gate: self.gate.clone(),
            native: self.native.clone(),
            connection: self.connection.closer(),
            armed: true,
        };
        let (result, delivery) = permit
            .during(async {
                let (mut reply, mut input) = self.connection.accept_one(&permit).await?;
                let mut header = [0; HEADER];
                input.read_exact(&mut header).await?;
                let (length, id, limit) = self.header(&header)?;
                ensure!(permit.valid(), "RX ACL changed at header");
                let deadline = credit_start.clone();
                let remaining = credit_start.clone();
                let source = SendPermit::bounded(
                    move || deadline.remaining_within(limit).is_ok(),
                    move || remaining.remaining_within(limit).ok(),
                );
                let delivery = SendPermit::combine(vec![permit.clone(), source]);
                ensure!(delivery.valid(), "RX source deadline expired at header");
                self.gate
                    .state
                    .pending
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert(key, delivery.clone());
                delivery
                    .during(async {
                        let mut payload = vec![0; length];
                        input.read_exact(&mut payload).await?;
                        let mut extra = [0];
                        ensure!(
                            input.read(&mut extra).await?.is_none(),
                            "RX chunk exceeds finite declared body"
                        );
                        let ack = if &header[..4] == b"PHF2" {
                            self.native
                                .finish(id, self.offset, delivery.clone())
                                .await?
                        } else {
                            self.native
                                .write_chunk(id, self.offset, payload.into(), delivery.clone())
                                .await?
                        };
                        self.native
                            .publish_receipt(ack, id, self.offset, length, || async {
                                reply.write_all(&header).await?;
                                reply.finish()?;
                                ensure!(reply.stopped().await?.is_none(), "RX receipt reset");
                                Ok(())
                            })
                            .await?;
                        Ok::<_, anyhow::Error>(())
                    })
                    .await??;
                Ok::<_, anyhow::Error>((header, delivery))
            })
            .await??;
        ensure!(
            permit.valid() && delivery.valid(),
            "RX original/source credit expired after receipt"
        );
        let length = u32::from_be_bytes(result[37..41].try_into()?) as u64;
        self.offset = self
            .offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("RX offset overflow"))?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("RX sequence overflow"))?;
        self.gate
            .state
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&key);
        self.finished = &result[..4] == b"PHF2";
        if self.finished {
            self.terminal = Some(delivery.clone());
        }
        receiving.armed = false;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod tests;
