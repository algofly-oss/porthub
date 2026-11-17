//! Bounded authenticated-peer/nonce/direction/role routing. Registration never
//! opens a native connection. Its flow actor owns endpoint/native teardown.
use super::*;
use super::{
    carrier::{Frame, Key},
    flow_authority::ChannelIdentity,
    source::Current,
};
use porthub_mesh::streams::{Datagram, Ingress};
use std::{
    net::Ipv4Addr,
    sync::{OnceLock, Weak},
};
const MAX_SLOTS: usize = 512;
const MAX_PEERS: usize = 64;
const PER_PEER: usize = 8;
type SlotKey = (Ipv4Addr, Key);
struct Slot {
    identity: ChannelIdentity,
    current: Current,
    ingress: OnceLock<Ingress>,
    live: Arc<AtomicBool>,
    key: Key,
    owner: OnceLock<CancellationToken>,
    gate: OnceLock<Weak<GateState>>,
}
impl Slot {
    fn authority(&self) -> Result<SendPermit> {
        ensure!(
            self.live.load(Ordering::SeqCst)
                && self.owner.get().is_none_or(|owner| !owner.is_cancelled())
                && self.gate.get().is_none_or(|gate| gate
                    .upgrade()
                    .is_some_and(|gate| gate.alive.load(Ordering::SeqCst))),
            "carrier slot/endpoint owner retired"
        );
        let current = (self.current)()
            .ok_or_else(|| anyhow::anyhow!("carrier current authority unavailable"))?;
        self.identity.admit(&current, self.key.local_side())
    }
    fn valid(&self) -> bool {
        self.authority().is_ok()
    }
    fn permit(self: &Arc<Self>) -> Result<SendPermit> {
        let original = self.authority()?;
        let slot = self.clone();
        Ok(original.constrain(move || slot.valid()))
    }
}
#[derive(Default)]
struct Table {
    slots: HashMap<SlotKey, Arc<Slot>>,
}
impl Drop for Table {
    fn drop(&mut self) {
        for slot in self.slots.values() {
            slot.live.store(false, Ordering::SeqCst);
        }
    }
}
#[derive(Clone, Default)]
pub(crate) struct Dispatcher(Arc<Mutex<Table>>);
pub(crate) struct Registration {
    table: Weak<Mutex<Table>>,
    key: SlotKey,
    slot: Arc<Slot>,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Outcome {
    Delivered,
    Busy,
    Missing,
    Denied,
}
impl Dispatcher {
    #[cfg(test)]
    pub(crate) fn register(
        &self,
        key: Key,
        current: Current,
        ingress: Ingress,
    ) -> Result<Registration> {
        let reservation = self.reserve(key, current)?;
        reservation.attach(ingress)?;
        Ok(reservation)
    }
    fn reserve(&self, key: Key, current: Current) -> Result<Registration> {
        let local = current()
            .ok_or_else(|| anyhow::anyhow!("carrier registration authority unavailable"))?;
        let identity = local.channel_identity();
        identity.admit(&local, key.local_side())?;
        let address = identity.peer().ip;
        let id = identity.peer().id.clone();
        let mut table = self.0.lock().unwrap_or_else(|p| p.into_inner());
        ensure!(
            !table.slots.contains_key(&(address, key)),
            "carrier slot already owned"
        );
        ensure!(
            table.slots.len() < MAX_SLOTS,
            "carrier global slot budget busy"
        );
        ensure!(
            table
                .slots
                .values()
                .filter(|slot| slot.identity.peer().id == id)
                .count()
                < PER_PEER,
            "carrier peer slot budget busy"
        );
        let peers = table
            .slots
            .values()
            .map(|slot| slot.identity.peer().id.as_str())
            .collect::<std::collections::HashSet<_>>();
        ensure!(
            peers.contains(id.as_str()) || peers.len() < MAX_PEERS,
            "carrier active peer budget busy"
        );
        ensure!(
            !table
                .slots
                .values()
                .any(|slot| slot.identity.peer().ip == address && slot.identity.peer().id != id),
            "carrier address still belongs to another identity"
        );
        let slot = Arc::new(Slot {
            identity,
            current,
            ingress: OnceLock::new(),
            live: Arc::new(AtomicBool::new(true)),
            key,
            owner: OnceLock::new(),
            gate: OnceLock::new(),
        });
        table.slots.insert((address, key), slot.clone());
        Ok(Registration {
            table: Arc::downgrade(&self.0),
            key: (address, key),
            slot,
        })
    }
    pub(crate) fn receive(&self, peer: &str, address: Ipv4Addr, bytes: Bytes) -> Result<Outcome> {
        let frame = Frame::decode(bytes)?;
        let key = (address, frame.key());
        let slot = {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .slots
                .get(&key)
                .cloned()
        };
        let Some(slot) = slot else {
            return Ok(Outcome::Missing);
        };
        if slot.identity.peer().id != peer {
            return Ok(Outcome::Denied);
        }
        let permit = match slot.permit() {
            Ok(permit) => permit,
            Err(_) => {
                self.retire_matching(key, &slot);
                return Ok(Outcome::Denied);
            }
        };
        let Some(ingress) = slot.ingress.get() else {
            return Ok(Outcome::Busy);
        };
        match ingress.try_send_guarded(address, frame.payload(), permit) {
            Ok(true) => Ok(Outcome::Delivered),
            Ok(false) => Ok(Outcome::Busy),
            Err(error) => {
                if !slot.valid() {
                    self.retire_matching(key, &slot);
                    Ok(Outcome::Denied)
                } else {
                    Err(error)
                }
            }
        }
    }
    fn retire_matching(&self, key: SlotKey, slot: &Arc<Slot>) {
        slot.live.store(false, Ordering::SeqCst);
        let mut table = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if table
            .slots
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, slot))
        {
            table.slots.remove(&key);
        }
    }
    pub(crate) fn reconcile(&self) {
        // Never call a prepared-current callback under the registry mutex.
        let snapshot = {
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .slots
                .iter()
                .map(|(key, slot)| (*key, slot.clone()))
                .collect::<Vec<_>>()
        };
        for (key, slot) in snapshot {
            if !slot.valid() {
                self.retire_matching(key, &slot);
            }
        }
    }
    pub(crate) fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).slots.len()
    }
}
impl Registration {
    fn attach(&self, ingress: Ingress) -> Result<()> {
        ensure!(
            self.slot.valid(),
            "carrier reservation retired before endpoint attachment"
        );
        self.slot
            .ingress
            .set(ingress)
            .map_err(|_| anyhow::anyhow!("carrier endpoint already attached"))
    }
    pub(crate) fn parent_scope(&self) -> SendPermit {
        let slot = self.slot.clone();
        SendPermit::control(move || slot.valid())
    }
    pub(crate) fn outgoing(
        &self,
        datagram: Datagram,
    ) -> Result<Option<(Ipv4Addr, Bytes, SendPermit)>> {
        ensure!(
            datagram.address == self.slot.identity.peer().ip,
            "carrier target identity mismatch"
        );
        let current = self.slot.permit()?;
        let original = datagram
            .permit
            .ok_or_else(|| anyhow::anyhow!("unfenced ciphertext cannot enter origin carrier"))?;
        if !original.valid() {
            return Ok(None);
        }
        let permit = SendPermit::combine(vec![original, current]);
        ensure!(
            permit.remaining().is_some(),
            "carrier ciphertext original authority unknown/expired"
        );
        let frame = Frame::new(self.slot.key.reverse(), datagram.payload)?;
        Ok(Some((self.slot.identity.peer().ip, frame.encode(), permit)))
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        self.slot.live.store(false, Ordering::SeqCst);
        if let Some(table) = self.table.upgrade() {
            let mut table = table.lock().unwrap_or_else(|p| p.into_inner());
            if table
                .slots
                .get(&self.key)
                .is_some_and(|slot| Arc::ptr_eq(slot, &self.slot))
            {
                table.slots.remove(&self.key);
            }
        }
    }
}

/// Reserve quota BEFORE constructing a QUIC endpoint. Queue capacity is fixed
/// by the origin profile; dropping this owner closes only its exact endpoint.
pub(crate) struct EndpointSlot {
    endpoint: Arc<porthub_mesh::streams::Endpoint>,
    packets: Option<porthub_mesh::streams::PacketIo>,
    registration: Registration,
    gate: Gate,
}
impl EndpointSlot {
    pub(crate) fn new(
        dispatcher: &Dispatcher,
        key: Key,
        current: Current,
        identity: porthub_mesh::Identity,
        owner: CancellationToken,
    ) -> Result<Self> {
        Self::new_protocol(dispatcher, key, current, identity, owner, false)
    }
    pub(crate) fn new_protocol(
        dispatcher: &Dispatcher,
        key: Key,
        current: Current,
        identity: porthub_mesh::Identity,
        owner: CancellationToken,
        requested: bool,
    ) -> Result<Self> {
        let registration = dispatcher.reserve(key, current)?;
        registration.slot.identity.bind_identity(&identity)?;
        registration
            .slot
            .owner
            .set(owner.clone())
            .map_err(|_| anyhow::anyhow!("carrier owner already attached"))?;
        let slot = registration.slot.clone();
        let gate = Gate::new(SendPermit::control(move || {
            !owner.is_cancelled() && slot.valid()
        }));
        registration
            .slot
            .gate
            .set(Arc::downgrade(&gate.state))
            .map_err(|_| anyhow::anyhow!("carrier gate already attached"))?;
        let local = registration.slot.identity.local_ip();
        let (endpoint, packets) = if requested {
            match key.role() {
                super::carrier::Role::Source => {
                    porthub_mesh::streams::Endpoint::new_requested_source(
                        identity,
                        local,
                        gate.factory(),
                    )?
                }
                super::carrier::Role::Receiver => {
                    porthub_mesh::streams::Endpoint::new_requested_receiver(
                        identity,
                        local,
                        gate.factory(),
                    )?
                }
            }
        } else {
            match key.role() {
                super::carrier::Role::Source => porthub_mesh::streams::Endpoint::new_fenced_source(
                    identity,
                    local,
                    gate.factory(),
                )?,
                super::carrier::Role::Receiver => {
                    porthub_mesh::streams::Endpoint::new_fenced_credited(
                        identity,
                        local,
                        gate.factory(),
                    )?
                }
            }
        };
        endpoint.update_peers(vec![registration.slot.identity.peer().clone()])?;
        registration.attach(packets.ingress())?;
        Ok(Self {
            endpoint: Arc::new(endpoint),
            packets: Some(packets),
            registration,
            gate,
        })
    }
    pub(crate) fn active(&self) -> bool {
        self.registration.slot.valid() && self.gate.state.alive.load(Ordering::SeqCst)
    }
    pub(crate) fn endpoint(&self) -> Arc<porthub_mesh::streams::Endpoint> {
        self.endpoint.clone()
    }
    pub(crate) fn gate(&self) -> Gate {
        self.gate.clone()
    }
    pub(crate) fn take_packets(&mut self) -> Result<porthub_mesh::streams::PacketIo> {
        self.packets
            .take()
            .ok_or_else(|| anyhow::anyhow!("carrier packet owner already taken"))
    }
    pub(crate) fn outgoing(
        &self,
        datagram: Datagram,
    ) -> Result<Option<(Ipv4Addr, Bytes, SendPermit)>> {
        self.registration.outgoing(datagram)
    }
}
impl Drop for EndpointSlot {
    fn drop(&mut self) {
        self.registration.slot.live.store(false, Ordering::SeqCst);
        self.gate.retire();
        self.endpoint.close();
    }
}
