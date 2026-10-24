//! Pin an active inner flow to its pre-established transport. A newly ready
//! direct route is used by new flows; queue pressure never moves active flows.
use super::policy::{FlowId, Packet};
use std::{collections::HashMap, time::Instant};
#[derive(Default)]
pub struct Pinned {
    flows: HashMap<FlowId, (bool, Instant)>,
}
impl Pinned {
    pub fn observe(&mut self, packet: Packet, direct: bool) {
        let key = packet.flow_id();
        let now = Instant::now();
        self.expire_at_capacity(now);
        if self.flows.len() < 65536 || self.flows.contains_key(&key) {
            let entry = self.flows.entry(key).or_insert((direct, now));
            // Receiving through fallback is evidence that the other side had
            // to fail over. Retain it for this flow even if ICE later recovers.
            if !direct {
                entry.0 = false;
            }
            entry.1 = now + packet.flow_ttl();
        }
    }
    pub fn choose(&mut self, packet: Packet, direct: bool, relay: bool) -> Option<bool> {
        self.choose_preferred(packet, direct, relay, true)
    }
    /// The preference applies only to a new flow. Existing replies and active
    /// application sockets retain their established transport.
    pub fn choose_preferred(
        &mut self,
        packet: Packet,
        direct: bool,
        relay: bool,
        prefer_direct: bool,
    ) -> Option<bool> {
        let key = packet.flow_id();
        let now = Instant::now();
        if let Some((route, expires)) = self
            .flows
            .get_mut(&key)
            .filter(|(_, expires)| *expires > now)
        {
            if *route && !direct {
                if relay {
                    *route = false;
                } else {
                    return None;
                }
            }
            if !*route && !relay {
                return None;
            }
            *expires = now + packet.flow_ttl();
            return Some(*route);
        }
        let route = if direct && (prefer_direct || !relay) {
            true
        } else if relay {
            false
        } else {
            return None;
        };
        self.expire_at_capacity(now);
        if self.flows.len() >= 65536 && !self.flows.contains_key(&key) {
            return None;
        }
        self.flows.insert(key, (route, now + packet.flow_ttl()));
        Some(route)
    }
    fn expire_at_capacity(&mut self, now: Instant) {
        if self.flows.len() >= 65536 {
            self.flows.retain(|_, (_, expires)| *expires > now);
        }
    }
}
