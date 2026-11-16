//! Origin2 carrier dispatch metadata. This is NOT native/peer authorization.
use super::flow_authority::Side;
use super::*;
use porthub_mesh::streams::{MAX_ORIGIN_DATAGRAM, ORIGIN_CARRIER_OVERHEAD};
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Role {
    Source,
    Receiver,
}
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Key {
    nonce: [u8; 16],
    direction: u8,
    receiver: bool,
}
impl Key {
    pub(crate) fn new(nonce: [u8; 16], direction: u8, role: Role) -> Result<Self> {
        ensure!(
            nonce != [0; 16] && direction < 2,
            "invalid guarded carrier identity"
        );
        Ok(Self {
            nonce,
            direction,
            receiver: role == Role::Receiver,
        })
    }
    pub(crate) fn nonce(&self) -> [u8; 16] {
        self.nonce
    }
    pub(crate) fn direction(&self) -> u8 {
        self.direction
    }
    pub(crate) fn role(&self) -> Role {
        if self.receiver {
            Role::Receiver
        } else {
            Role::Source
        }
    }
    pub(crate) fn local_side(&self) -> Side {
        if (self.direction == 0) == self.receiver {
            Side::Acceptor
        } else {
            Side::Initiator
        }
    }
    pub(crate) fn reverse(&self) -> Self {
        Self {
            receiver: !self.receiver,
            ..*self
        }
    }
}
pub(crate) struct Frame {
    key: Key,
    payload: Bytes,
}
impl Frame {
    pub(crate) fn new(key: Key, payload: Bytes) -> Result<Self> {
        ensure!(
            !payload.is_empty() && payload.len() <= MAX_ORIGIN_DATAGRAM,
            "origin carrier payload outside MTU bound"
        );
        Ok(Self { key, payload })
    }
    pub(crate) fn key(&self) -> Key {
        self.key
    }
    pub(crate) fn payload(&self) -> Bytes {
        self.payload.clone()
    }
    pub(crate) fn encode(&self) -> Bytes {
        let mut bytes = Vec::with_capacity(ORIGIN_CARRIER_OVERHEAD + self.payload.len());
        bytes.extend_from_slice(b"PHG2");
        bytes.extend_from_slice(&self.key.nonce);
        bytes.push(self.key.direction);
        bytes.push(u8::from(self.key.receiver));
        bytes.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes.into()
    }
    pub(crate) fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(
            bytes.len() > ORIGIN_CARRIER_OVERHEAD
                && bytes.len() <= porthub_mesh::streams::MAX_DATAGRAM
                && &bytes[..4] == b"PHG2",
            "foreign/oversized guarded carrier"
        );
        ensure!(bytes[21] < 2, "unknown guarded carrier role");
        let key = Key::new(
            bytes[4..20].try_into()?,
            bytes[20],
            if bytes[21] == 0 {
                Role::Source
            } else {
                Role::Receiver
            },
        )?;
        let length = usize::from(u16::from_be_bytes(bytes[22..24].try_into()?));
        ensure!(
            length == bytes.len() - ORIGIN_CARRIER_OVERHEAD,
            "guarded carrier trailing/truncated data"
        );
        Self::new(key, bytes.slice(ORIGIN_CARRIER_OVERHEAD..))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_nonce_direction_role_and_mtu_envelope_round_trip() -> Result<()> {
        for direction in 0..2 {
            for role in [Role::Source, Role::Receiver] {
                let key = Key::new([9; 16], direction, role)?;
                let f = Frame::new(key, Bytes::from(vec![3; MAX_ORIGIN_DATAGRAM]))?;
                let encoded = f.encode();
                ensure!(
                    encoded.len() + 20 == porthub_mesh::MAX_PACKET,
                    "origin overhead changed native carrier MTU"
                );
                let parsed = Frame::decode(encoded)?;
                ensure!(
                    parsed.key() == key && parsed.payload() == f.payload(),
                    "carrier dispatch identity/payload changed"
                );
                ensure!(
                    key.reverse().reverse() == key
                        && key.reverse().local_side() != key.local_side(),
                    "carrier role reversal changed direction"
                );
            }
        }
        ensure!(
            MAX_ORIGIN_DATAGRAM >= 1200,
            "QUIC minimum Initial MTU unsupported"
        );
        Ok(())
    }
    #[test]
    fn unknown_flags_nonce_lengths_and_legacy_payloads_fail_closed() -> Result<()> {
        let frame = Frame::new(
            Key::new([1; 16], 0, Role::Receiver)?,
            Bytes::from_static(b"quic"),
        )?
        .encode();
        for (index, value) in [(0, b'X'), (20, 2), (21, 2), (22, 255), (23, 0)] {
            let mut bad = frame.to_vec();
            bad[index] = value;
            ensure!(
                Frame::decode(bad.into()).is_err(),
                "noncanonical carrier accepted"
            );
        }
        let mut zero = frame.to_vec();
        zero[4..20].fill(0);
        ensure!(
            Frame::decode(zero.into()).is_err(),
            "zero flow nonce accepted"
        );
        let mut extra = frame.to_vec();
        extra.push(0);
        ensure!(
            Frame::decode(extra.into()).is_err(),
            "trailing carrier bytes accepted"
        );
        ensure!(
            Frame::new(
                Key::new([1; 16], 0, Role::Source)?,
                Bytes::from(vec![0; MAX_ORIGIN_DATAGRAM + 1])
            )
            .is_err(),
            "origin MTU bound bypassed"
        );
        Ok(())
    }
}
