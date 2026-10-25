//! Low-rate private-path measurements over the transports that are already up.
//! Probe frames are authenticated by the peer DTLS session or gateway relay and
//! never enter the host TUN or an application flow.
use bytes::Bytes;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

const MAGIC: &[u8; 8] = b"PHUBQOS1";
const FRAME_SIZE: usize = 1200;
pub const PROBE_PACKETS: u8 = 32;
const PROBE_BYTES: u64 = (FRAME_SIZE as u64) * (PROBE_PACKETS as u64);
const SCORE_TTL: Duration = Duration::from_secs(600);
const PROBE_INTERVAL: Duration = Duration::from_secs(120);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_PEERS: usize = 4096;
const ALL_SEEN: u64 = (1u64 << PROBE_PACKETS) - 1;

#[derive(Clone, Hash, PartialEq, Eq)]
struct Key {
    peer: String,
    direct: bool,
    nonce: u64,
}

#[derive(Clone, Copy)]
struct Frame {
    pong: bool,
    direct: bool,
    nonce: u64,
    sequence: u8,
    count: u8,
    elapsed_ns: u32,
}

impl Frame {
    fn encode(self) -> Bytes {
        let mut bytes = vec![0u8; FRAME_SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8] = u8::from(self.pong);
        bytes[9] = u8::from(self.direct);
        bytes[10] = self.sequence;
        bytes[11] = self.count;
        bytes[12..20].copy_from_slice(&self.nonce.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.elapsed_ns.to_be_bytes());
        bytes.into()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FRAME_SIZE || &bytes[..8] != MAGIC || bytes[8] > 1 || bytes[9] > 1 {
            return None;
        }
        let count = bytes[11];
        let sequence = bytes[10];
        let elapsed_ns = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        if count != PROBE_PACKETS
            || sequence >= count
            || (bytes[8] == 0 && elapsed_ns != 0)
            || (bytes[8] == 1 && elapsed_ns == 0)
        {
            return None;
        }
        Some(Self {
            pong: bytes[8] == 1,
            direct: bytes[9] == 1,
            sequence,
            count,
            nonce: u64::from_be_bytes(bytes[12..20].try_into().ok()?),
            elapsed_ns,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Score {
    bits_per_second: u64,
    rtt: Duration,
    measured_at: Instant,
}

struct Pending {
    started: Instant,
    first_reply: Option<Instant>,
    last_reply: Option<Instant>,
    seen: u64,
    remote_elapsed_ns: Option<u32>,
}

struct ReplyBatch {
    first_packet: Instant,
    last_packet: Instant,
    seen: u64,
}

/// `handle` returns `None` for application packets. `Some` means the frame was
/// consumed; it may contain responses to send over the same transport.
#[derive(Default)]
pub struct Quality {
    pending: HashMap<Key, Pending>,
    replies: HashMap<Key, ReplyBatch>,
    scores: HashMap<String, [Option<Score>; 2]>,
    next_allowed: HashMap<(String, bool), Instant>,
}

impl Quality {
    pub fn start(&mut self, peer: &str, direct: bool, nonce: u64, now: Instant) -> Vec<Bytes> {
        let route = (peer.to_owned(), direct);
        if self.next_allowed.get(&route).is_some_and(|due| now < *due) {
            return Vec::new();
        }
        let key = Key {
            peer: peer.to_owned(),
            direct,
            nonce,
        };
        if self.pending.contains_key(&key) || self.pending.len() >= MAX_PEERS {
            return Vec::new();
        }
        self.next_allowed.insert(route, now + PROBE_INTERVAL);
        self.pending.insert(
            key,
            Pending {
                started: now,
                first_reply: None,
                last_reply: None,
                seen: 0,
                remote_elapsed_ns: None,
            },
        );
        (0..PROBE_PACKETS)
            .map(|sequence| {
                Frame {
                    pong: false,
                    direct,
                    nonce,
                    sequence,
                    count: PROBE_PACKETS,
                    elapsed_ns: 0,
                }
                .encode()
            })
            .collect()
    }

    pub fn cancel(&mut self, peer: &str, direct: bool, nonce: u64, now: Instant) {
        self.pending.remove(&Key {
            peer: peer.to_owned(),
            direct,
            nonce,
        });
        self.next_allowed
            .insert((peer.to_owned(), direct), now + Duration::from_secs(15));
    }

    pub fn handle(
        &mut self,
        peer: &str,
        actual_direct: bool,
        bytes: &[u8],
        now: Instant,
    ) -> Option<Vec<Bytes>> {
        let frame = Frame::decode(bytes)?;
        // A frame cannot use one transport while claiming to measure the other.
        if frame.direct != actual_direct {
            return Some(Vec::new());
        }
        let key = Key {
            peer: peer.to_owned(),
            direct: actual_direct,
            nonce: frame.nonce,
        };
        if !frame.pong {
            if !self.replies.contains_key(&key) && self.replies.len() >= MAX_PEERS * 2 {
                return Some(Vec::new());
            }
            let batch = self.replies.entry(key.clone()).or_insert(ReplyBatch {
                first_packet: now,
                last_packet: now,
                seen: 0,
            });
            let bit = 1u64 << frame.sequence;
            if batch.seen & bit == 0 {
                batch.seen |= bit;
                batch.last_packet = now;
            }
            let complete = batch.seen == ALL_SEEN;
            if !complete {
                return Some(Vec::new());
            }
            let batch = self.replies.remove(&key).expect("completed probe batch");
            let elapsed_ns = batch
                .last_packet
                .saturating_duration_since(batch.first_packet)
                .as_nanos()
                .clamp(1, u128::from(u32::MAX)) as u32;
            return Some(
                (0..PROBE_PACKETS)
                    .map(|sequence| {
                        Frame {
                            pong: true,
                            direct: actual_direct,
                            nonce: frame.nonce,
                            sequence,
                            count: PROBE_PACKETS,
                            elapsed_ns,
                        }
                        .encode()
                    })
                    .collect(),
            );
        }

        let Some(pending) = self.pending.get_mut(&key) else {
            return Some(Vec::new());
        };
        if pending
            .remote_elapsed_ns
            .is_some_and(|elapsed| elapsed != frame.elapsed_ns)
        {
            self.pending.remove(&key);
            return Some(Vec::new());
        }
        pending.remote_elapsed_ns = Some(frame.elapsed_ns);
        let bit = 1u64 << frame.sequence;
        if pending.seen & bit == 0 {
            pending.seen |= bit;
            pending.first_reply.get_or_insert(now);
            pending.last_reply = Some(now);
        }
        if pending.seen != ALL_SEEN {
            return Some(Vec::new());
        }
        let pending = self
            .pending
            .remove(&key)
            .expect("completed probe measurement");
        let Some(remote_ns) = pending.remote_elapsed_ns else {
            return Some(Vec::new());
        };
        let response_ns = pending
            .last_reply
            .unwrap_or(now)
            .saturating_duration_since(pending.first_reply.unwrap_or(now))
            .as_nanos()
            .clamp(1, u128::from(u32::MAX)) as u32;
        let bits_per_second =
            throughput(PROBE_BYTES, remote_ns).min(throughput(PROBE_BYTES, response_ns));
        // Remove the measured serialization time in each direction from the
        // first-response delay. Keep a 1 ms floor for clock and queue jitter.
        let elapsed = now.saturating_duration_since(pending.started);
        let transfer =
            Duration::from_nanos(u64::from(remote_ns).saturating_add(u64::from(response_ns)));
        let rtt = elapsed
            .saturating_sub(transfer)
            .max(Duration::from_millis(1));
        self.observe(
            peer,
            actual_direct,
            Score {
                bits_per_second,
                rtt,
                measured_at: now,
            },
        );
        Some(Vec::new())
    }

    pub fn prefer_peer(&self, peer: &str, default: bool, now: Instant) -> bool {
        let Some(scores) = self.scores.get(peer) else {
            return default;
        };
        let fresh = |score: Option<Score>| {
            score.filter(|score| now.saturating_duration_since(score.measured_at) <= SCORE_TTL)
        };
        let (Some(peer), Some(gateway)) = (fresh(scores[1]), fresh(scores[0])) else {
            return default;
        };
        if peer.bits_per_second >= gateway.bits_per_second.saturating_mul(6) / 5 {
            return true;
        }
        if gateway.bits_per_second >= peer.bits_per_second.saturating_mul(6) / 5 {
            return false;
        }
        if peer.rtt.saturating_add(Duration::from_millis(10)) < gateway.rtt {
            true
        } else if gateway.rtt.saturating_add(Duration::from_millis(10)) < peer.rtt {
            false
        } else {
            default
        }
    }

    fn observe(&mut self, peer: &str, direct: bool, next: Score) {
        let scores = self.scores.entry(peer.to_owned()).or_insert([None, None]);
        let score = scores[direct as usize].get_or_insert(next);
        // Smooth brief queue spikes without making a real sustained change
        // take many minutes to influence new flows.
        score.bits_per_second =
            score.bits_per_second.saturating_mul(3) / 4 + next.bits_per_second / 4;
        score.rtt = score.rtt.mul_f64(0.75) + next.rtt.mul_f64(0.25);
        score.measured_at = next.measured_at;
        if self.scores.len() > MAX_PEERS {
            self.scores.retain(|_, values| {
                for value in values.iter_mut() {
                    if value.as_ref().is_some_and(|score| {
                        next.measured_at
                            .saturating_duration_since(score.measured_at)
                            > SCORE_TTL
                    }) {
                        *value = None;
                    }
                }
                values.iter().any(Option::is_some)
            });
        }
    }

    fn expire(&mut self, now: Instant) {
        let failed: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, value)| now.saturating_duration_since(value.started) > PROBE_TIMEOUT)
            .map(|(key, _)| key.clone())
            .collect();
        for key in failed {
            self.pending.remove(&key);
            self.observe(
                &key.peer,
                key.direct,
                Score {
                    bits_per_second: 0,
                    rtt: PROBE_TIMEOUT,
                    measured_at: now,
                },
            );
            // Retry failed paths after a short cooldown instead of leaving a
            // dead candidate unmeasured for the full two-minute interval.
            self.next_allowed
                .insert((key.peer, key.direct), now + Duration::from_secs(15));
        }
        self.next_allowed.retain(|_, due| now < *due);
        self.replies
            .retain(|_, value| now.saturating_duration_since(value.last_packet) <= PROBE_TIMEOUT);
        self.scores.retain(|_, values| {
            for value in values.iter_mut() {
                if value.as_ref().is_some_and(|score| {
                    now.saturating_duration_since(score.measured_at) > SCORE_TTL
                }) {
                    *value = None;
                }
            }
            values.iter().any(Option::is_some)
        });
    }

    pub fn prune(&mut self, now: Instant) {
        self.expire(now);
    }
}

fn throughput(bytes: u64, nanos: u32) -> u64 {
    (u128::from(bytes) * 8 * 1_000_000_000 / u128::from(nanos.max(1))).min(u128::from(u64::MAX))
        as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_burst_measures_both_transport_directions_and_prefers_capacity() {
        let start = Instant::now();
        let mut source = Quality::default();
        let mut target = Quality::default();
        for (direct, nonce, spacing) in [
            (true, 1, Duration::from_millis(2)),
            (false, 2, Duration::from_micros(50)),
        ] {
            let sent = source.start("target", direct, nonce, start);
            let mut replies = Vec::new();
            for (index, request) in sent.into_iter().enumerate() {
                replies.extend(
                    target
                        .handle(
                            "source",
                            direct,
                            &request,
                            start + spacing.mul_f64(index as f64),
                        )
                        .unwrap(),
                );
            }
            for (index, reply) in replies.into_iter().enumerate() {
                let _ = source.handle(
                    "target",
                    direct,
                    &reply,
                    start + Duration::from_millis(100) + spacing.mul_f64(index as f64),
                );
            }
        }
        // A faster gateway path must override Auto's usual peer-first default.
        assert!(!source.prefer_peer("target", true, start + Duration::from_secs(1)));
        // Scores are keyed by the authenticated remote identity, not the IP
        // address shared by unrelated machines.
        assert!(source.prefer_peer("another-peer", true, start + Duration::from_secs(1)));
    }

    #[test]
    fn mismatched_transport_and_stale_measurements_do_not_change_auto() {
        let mut quality = Quality::default();
        let now = Instant::now();
        let sent = quality.start("peer", true, 1, now);
        assert_eq!(
            quality.handle("peer", false, &sent[0], now),
            Some(Vec::new())
        );
        quality.cancel("peer", true, 1, now);
        assert!(quality.prefer_peer("peer", true, now));
        quality.observe(
            "peer",
            true,
            Score {
                bits_per_second: 10_000_000,
                rtt: Duration::from_millis(80),
                measured_at: now,
            },
        );
        quality.observe(
            "peer",
            false,
            Score {
                bits_per_second: 20_000_000,
                rtt: Duration::from_millis(40),
                measured_at: now,
            },
        );
        assert!(!quality.prefer_peer("peer", true, now));
        assert!(quality.prefer_peer("peer", true, now + SCORE_TTL + Duration::from_secs(1)));
        quality.prune(now + SCORE_TTL + Duration::from_secs(1));
        assert!(quality.scores.is_empty());
        assert!(Frame::decode(b"not a path probe").is_none());
    }

    #[test]
    fn timed_out_peer_path_is_disfavored_and_retried_after_cooldown() {
        let mut quality = Quality::default();
        let now = Instant::now();
        assert_eq!(
            quality.start("peer", true, 1, now).len(),
            usize::from(PROBE_PACKETS)
        );
        quality.prune(now + PROBE_TIMEOUT + Duration::from_secs(1));
        quality.observe(
            "peer",
            false,
            Score {
                bits_per_second: 1_000_000,
                rtt: Duration::from_millis(30),
                measured_at: now + PROBE_TIMEOUT + Duration::from_secs(1),
            },
        );
        assert!(!quality.prefer_peer("peer", true, now + Duration::from_secs(7)));
        assert!(quality
            .start("peer", true, 2, now + Duration::from_secs(7))
            .is_empty());
        assert_eq!(
            quality
                .start("peer", true, 3, now + Duration::from_secs(22))
                .len(),
            usize::from(PROBE_PACKETS)
        );
    }
}
