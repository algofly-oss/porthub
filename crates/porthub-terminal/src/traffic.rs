//! Content-free host measurements. PTY payload and direct UDP observations are
//! separate scopes; adding them together would double-count application data.
use serde::{Deserialize, Serialize};
#[cfg(any(test, feature = "hosting", feature = "direct"))]
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Bytes successfully written into guest attachment PTYs.
    pub input_bytes: u64,
    /// Bytes read from guest attachment PTYs, including redraws per participant.
    pub output_bytes: u64,
    /// Successful RTC UDP sends; excludes external candidate-discovery probes.
    pub direct_udp_sent_bytes: u64,
    /// RTC socket bytes consumed, including protocol overhead and invalid input.
    pub direct_udp_received_bytes: u64,
}
#[cfg(any(test, feature = "hosting", feature = "direct"))]
#[derive(Default)]
struct Storage {
    input: AtomicU64,
    output: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
}
#[cfg(any(test, feature = "hosting", feature = "direct"))]
#[derive(Clone, Default)]
pub struct Counters {
    own: Arc<Storage>,
    parent: Option<Arc<Storage>>,
}
#[cfg(any(test, feature = "hosting", feature = "direct"))]
impl Counters {
    /// A host owns the root; each attachment gets one child. Producers retain
    /// both arcs, so a write finishing after detach still updates host totals.
    pub(crate) fn child(&self) -> Self {
        Self {
            own: Arc::default(),
            parent: Some(self.own.clone()),
        }
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            input_bytes: self.own.input.load(Ordering::Relaxed),
            output_bytes: self.own.output.load(Ordering::Relaxed),
            direct_udp_sent_bytes: self.own.sent.load(Ordering::Relaxed),
            direct_udp_received_bytes: self.own.received.load(Ordering::Relaxed),
        }
    }
    fn add(&self, field: fn(&Storage) -> &AtomicU64, bytes: usize) {
        let increment = |storage: &Storage| {
            let _ = field(storage).try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(bytes as u64))
            });
        };
        increment(&self.own);
        if let Some(parent) = &self.parent {
            increment(parent);
        }
    }
    pub(crate) fn input(&self, bytes: usize) {
        self.add(|value| &value.input, bytes);
    }
    pub(crate) fn output(&self, bytes: usize) {
        self.add(|value| &value.output, bytes);
    }
    #[cfg(any(test, feature = "direct"))]
    pub(crate) fn sent(&self, bytes: usize) {
        self.add(|value| &value.sent, bytes);
    }
    #[cfg(any(test, feature = "direct"))]
    pub(crate) fn received(&self, bytes: usize) {
        self.add(|value| &value.received, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_producers_and_detached_attachments_keep_separate_host_totals() {
        let host = Counters::default();
        let first = host.child();
        let second = host.child();
        let producer = first.clone();
        drop(first);
        let threads = (0..4)
            .map(|_| {
                let producer = producer.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        producer.input(3);
                        producer.sent(5);
                    }
                })
            })
            .collect::<Vec<_>>();
        second.output(11);
        second.received(13);
        for task in threads {
            task.join().unwrap();
        }
        assert_eq!(producer.snapshot().input_bytes, 12000);
        assert_eq!(producer.snapshot().output_bytes, 0);
        assert_eq!(second.snapshot().input_bytes, 0);
        assert_eq!(
            host.snapshot(),
            Snapshot {
                input_bytes: 12000,
                output_bytes: 11,
                direct_udp_sent_bytes: 20000,
                direct_udp_received_bytes: 13
            }
        );
        let row = serde_json::to_value(host.snapshot()).unwrap();
        assert_eq!(
            row.as_object().unwrap().len(),
            4,
            "telemetry must contain no terminal content or identity"
        );
    }
    #[test]
    fn byte_counters_saturate_instead_of_wrapping() {
        let counters = Counters::default();
        counters.own.input.store(u64::MAX - 1, Ordering::Relaxed);
        counters.input(7);
        assert_eq!(counters.snapshot().input_bytes, u64::MAX);
    }
}
