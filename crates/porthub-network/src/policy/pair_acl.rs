//! Fixed-size exact pair permissions. Wire size and packet lookup cost do not grow
//! with the number of rule books/ranges that authorize the same two identities.
use super::Grant;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
const BYTES: usize = 8192;
const ENCODED: usize = 10924;
// Bound compilation by the existing complete grant/range representation budget,
// not by registered machine count. No legacy wire/peer limit is increased.
const MAX_SOURCE_RANGES: usize = 65536 * 64;
#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum Mask {
    Flag(bool),
    Bitmap(String),
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Direction {
    tcp: Mask,
    udp: Mask,
    icmp: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairAcl {
    version: u8,
    forward: Direction,
    reverse: Direction,
}
#[derive(Clone)]
pub struct CompiledPortMask {
    all: bool,
    bits: Option<Arc<[u8]>>,
}
impl CompiledPortMask {
    pub fn contains(&self, port: u16) -> bool {
        self.all
            || self
                .bits
                .as_ref()
                .is_some_and(|b| b[usize::from(port) / 8] & (1 << (port % 8)) != 0)
    }
    pub fn any(&self) -> bool {
        self.all
            || self
                .bits
                .as_ref()
                .is_some_and(|b| b.iter().any(|v| *v != 0))
    }
}
struct CompiledDirection {
    tcp: CompiledPortMask,
    udp: CompiledPortMask,
    icmp: bool,
}
pub struct CompiledPairAcl {
    forward: CompiledDirection,
    reverse: CompiledDirection,
}
impl CompiledPairAcl {
    pub fn tcp(&self, reverse: bool) -> CompiledPortMask {
        if reverse {
            self.reverse.tcp.clone()
        } else {
            self.forward.tcp.clone()
        }
    }
    pub fn allows(&self, reverse: bool, protocol: u8, port: u16) -> bool {
        let d = if reverse {
            &self.reverse
        } else {
            &self.forward
        };
        match protocol {
            6 => d.tcp.contains(port),
            17 => d.udp.contains(port),
            1 => d.icmp,
            _ => false,
        }
    }
}
impl Mask {
    fn compile(&self) -> Result<CompiledPortMask> {
        match self {
            Self::Flag(all) => Ok(CompiledPortMask {
                all: *all,
                bits: None,
            }),
            Self::Bitmap(value) => {
                ensure!(value.len() == ENCODED, "invalid pair port bitmap size");
                let bytes = STANDARD.decode(value)?;
                ensure!(
                    bytes.len() == BYTES && STANDARD.encode(&bytes) == *value,
                    "invalid or noncanonical pair port bitmap"
                );
                Ok(CompiledPortMask {
                    all: false,
                    bits: Some(Arc::from(bytes)),
                })
            }
        }
    }
}
impl Direction {
    fn compile(&self) -> Result<CompiledDirection> {
        Ok(CompiledDirection {
            tcp: self.tcp.compile()?,
            udp: self.udp.compile()?,
            icmp: self.icmp,
        })
    }
}
#[derive(Default)]
struct Builder {
    all: bool,
    ranges: Vec<(u16, u16)>,
}
impl Builder {
    fn all(&mut self) {
        self.all = true;
        self.ranges.clear();
    }
    fn range(&mut self, start: u16, end: u16) {
        if !self.all {
            self.ranges.push((start, end));
        }
    }
    fn fill(b: &mut [u8], start: u16, end: u16) {
        let first = usize::from(start) / 8;
        let last = usize::from(end) / 8;
        if first == last {
            for bit in start % 8..=end % 8 {
                b[first] |= 1 << bit;
            }
            return;
        }
        b[first] |= u8::MAX << (start % 8);
        b[last] |= u8::MAX >> (7 - end % 8);
        if last > first + 1 {
            b[first + 1..last].fill(u8::MAX);
        }
    }
    fn finish(mut self) -> Mask {
        if self.all {
            return Mask::Flag(true);
        }
        if self.ranges.is_empty() {
            return Mask::Flag(false);
        }
        // Merge before painting: even a million repeated broad ranges touch each
        // bitmap byte once, rather than performing gigabytes of duplicate writes.
        self.ranges.sort_unstable();
        let mut bits = vec![0; BYTES];
        let mut current: Option<(u16, u16)> = None;
        for (start, end) in self.ranges {
            if let Some((a, b)) = current {
                if start <= b.saturating_add(1) {
                    current = Some((a, b.max(end)));
                } else {
                    Self::fill(&mut bits, a, b);
                    current = Some((start, end));
                }
            } else {
                current = Some((start, end));
            }
        }
        if let Some((a, b)) = current {
            Self::fill(&mut bits, a, b);
        }
        Mask::Bitmap(STANDARD.encode(bits))
    }
}
#[derive(Default)]
struct DirectionBuilder {
    tcp: Builder,
    udp: Builder,
    icmp: bool,
}
impl DirectionBuilder {
    fn finish(self) -> Direction {
        Direction {
            tcp: self.tcp.finish(),
            udp: self.udp.finish(),
            icmp: self.icmp,
        }
    }
}
impl PairAcl {
    pub fn from_grants(local: &str, peer: &str, grants: &[Grant]) -> Result<Self> {
        Self::from_iter(local, peer, grants.iter().cloned())
    }
    pub fn from_iter(
        local: &str,
        peer: &str,
        grants: impl IntoIterator<Item = Grant>,
    ) -> Result<Self> {
        ensure!(
            !local.is_empty() && !peer.is_empty() && local != peer,
            "invalid pair ACL identities"
        );
        let mut forward = DirectionBuilder::default();
        let mut reverse = DirectionBuilder::default();
        let mut ranges = 0usize;
        let mut count = 0usize;
        for g in grants {
            count += 1;
            ensure!(count <= 65536, "pair ACL input exceeds grant budget");
            let d = if g.source == local && g.destination == peer {
                &mut forward
            } else if g.source == peer && g.destination == local {
                &mut reverse
            } else {
                anyhow::bail!("pair ACL includes another identity")
            };
            ensure!(
                ["any", "tcp", "udp", "icmp"].contains(&g.protocol.as_str()),
                "invalid pair ACL protocol"
            );
            ensure!(
                g.ports.is_empty() || ["tcp", "udp"].contains(&g.protocol.as_str()),
                "invalid pair ACL port restriction"
            );
            ranges = ranges
                .checked_add(g.ports.len())
                .ok_or_else(|| anyhow::anyhow!("pair range budget overflow"))?;
            ensure!(
                ranges <= MAX_SOURCE_RANGES,
                "pair ACL source ranges exceed compilation budget"
            );
            match g.protocol.as_str() {
                "any" => {
                    d.tcp.all();
                    d.udp.all();
                    d.icmp = true;
                }
                "icmp" => d.icmp = true,
                protocol => {
                    let mask = if protocol == "tcp" {
                        &mut d.tcp
                    } else {
                        &mut d.udp
                    };
                    if g.ports.is_empty() {
                        mask.all();
                    }
                    for p in &g.ports {
                        ensure!(p.start > 0 && p.end >= p.start, "invalid pair ACL range");
                        mask.range(p.start, p.end);
                    }
                }
            }
        }
        ensure!(count > 0, "empty pair ACL is not authority");
        let acl = Self {
            version: 1,
            forward: forward.finish(),
            reverse: reverse.finish(),
        };
        acl.compile()?;
        Ok(acl)
    }
    pub fn compile(&self) -> Result<CompiledPairAcl> {
        ensure!(self.version == 1, "unsupported pair ACL encoding");
        let forward = self.forward.compile()?;
        let reverse = self.reverse.compile()?;
        ensure!(
            forward.tcp.any()
                || forward.udp.any()
                || forward.icmp
                || reverse.tcp.any()
                || reverse.udp.any()
                || reverse.icmp,
            "empty pair ACL is not authority"
        );
        Ok(CompiledPairAcl { forward, reverse })
    }
}
#[cfg(test)]
mod tests {
    use super::super::Port;
    use super::*;
    fn grant(source: &str, destination: &str, protocol: &str, ports: Vec<Port>) -> Grant {
        Grant {
            source: source.into(),
            destination: destination.into(),
            protocol: protocol.into(),
            ports,
        }
    }
    #[test]
    fn exact_exhaustive_port_parity_for_mixed_overlapping_and_disjoint_rules() {
        let ports: Vec<_> = (1..=u16::MAX)
            .step_by(2)
            .map(|p| Port { start: p, end: p })
            .collect();
        let grants = vec![
            grant("a", "b", "tcp", ports),
            grant(
                "a",
                "b",
                "udp",
                vec![
                    Port {
                        start: 20,
                        end: 300,
                    },
                    Port {
                        start: 200,
                        end: 400,
                    },
                ],
            ),
            grant("b", "a", "icmp", vec![]),
        ];
        let wire = PairAcl::from_grants("a", "b", &grants).unwrap();
        let compiled = wire.compile().unwrap();
        for reverse in [false, true] {
            for protocol in [1, 6, 17, 99] {
                for port in 0..=u16::MAX {
                    let expected = if !reverse && protocol == 6 {
                        port % 2 == 1
                    } else {
                        grants.iter().any(|g| {
                            g.source == if reverse { "b" } else { "a" }
                                && (g.protocol == "any"
                                    || g.protocol
                                        == match protocol {
                                            1 => "icmp",
                                            6 => "tcp",
                                            17 => "udp",
                                            _ => "unknown",
                                        })
                                && (g.ports.is_empty()
                                    || g.ports.iter().any(|p| p.start <= port && port <= p.end))
                        })
                    };
                    // The alternating-port oracle is independent of the bitmap implementation.
                    assert_eq!(
                        compiled.allows(reverse, protocol, port),
                        expected,
                        "direction={reverse}, protocol={protocol}, port={port}"
                    );
                }
            }
        }
        assert!(serde_json::to_vec(&wire).unwrap().len() < 45000);
    }
    #[test]
    fn worst_case_four_masks_have_fixed_wire_size_and_overlapping_rules_canonicalize() {
        let odd: Vec<_> = (1..=u16::MAX)
            .step_by(2)
            .map(|p| super::super::Port { start: p, end: p })
            .collect();
        let mut grants = Vec::new();
        for (a, b) in [("a", "b"), ("b", "a")] {
            for protocol in ["tcp", "udp"] {
                grants.push(grant(a, b, protocol, odd.clone()));
            }
        }
        let worst = PairAcl::from_grants("a", "b", &grants).unwrap();
        assert!(serde_json::to_vec(&worst).unwrap().len() < 45000);
        let many = (0..1000)
            .map(|_| {
                grant(
                    "a",
                    "b",
                    "tcp",
                    vec![
                        super::super::Port {
                            start: 1,
                            end: 65535
                        };
                        16
                    ],
                )
            })
            .collect::<Vec<_>>();
        let single = grant(
            "a",
            "b",
            "tcp",
            vec![super::super::Port {
                start: 1,
                end: 65535,
            }],
        );
        assert_eq!(
            serde_json::to_value(PairAcl::from_grants("a", "b", &many).unwrap()).unwrap(),
            serde_json::to_value(PairAcl::from_grants("a", "b", &[single]).unwrap()).unwrap()
        );
    }
    #[test]
    fn malformed_bits_mixed_identity_and_unbounded_input_never_authorize() {
        assert!(PairAcl::from_grants("a", "b", &[grant("a", "c", "any", vec![])]).is_err());
        let wire = PairAcl::from_grants("a", "b", &[grant("a", "b", "any", vec![])]).unwrap();
        let mut bad = serde_json::to_value(wire).unwrap();
        bad["forward"]["tcp"] = serde_json::json!("A".repeat(ENCODED + 1));
        assert!(serde_json::from_value::<PairAcl>(bad)
            .unwrap()
            .compile()
            .is_err());
        let wire = PairAcl::from_grants(
            "a",
            "b",
            &[grant(
                "a",
                "b",
                "tcp",
                vec![Port {
                    start: 1,
                    end: 65535,
                }],
            )],
        )
        .unwrap()
        .compile()
        .unwrap();
        assert!(!wire.allows(false, 6, 0));
        assert!(wire.allows(false, 6, 65535));
        assert!(!wire.allows(true, 6, 65535));
    }
}
