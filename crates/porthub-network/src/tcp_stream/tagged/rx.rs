//! First-admission TCP sequence spans. Metadata never authorizes a packet; the
//! native TCP parser still validates it. Ambiguity/overflow retires the flow.
use super::{AdmissionError, SendPermit};
use anyhow::{Result, ensure};
const DEFAULT_WINDOW: usize = 16 * 1024;
const SPANS: usize = 256;
#[derive(Clone)]
struct Span {
    start: u64,
    end: u64,
    permit: SendPermit,
}
pub(super) struct Origins {
    window: u64,
    max_spans: usize,
    base: Option<u32>,
    consumed: u64,
    spans: Vec<Span>,
    fin: Option<(u64, SendPermit)>,
    eof: bool,
}
impl Default for Origins {
    fn default() -> Self {
        Self::with_window(DEFAULT_WINDOW)
    }
}
impl Origins {
    pub fn with_window(window: usize) -> Self {
        Self {
            window: window as u64,
            max_spans: SPANS.max(window.div_ceil(512)),
            base: None,
            consumed: 0,
            spans: Vec::new(),
            fin: None,
            eof: false,
        }
    }
    pub fn eof_pending(&self) -> bool {
        !self.eof
            && self
                .fin
                .as_ref()
                .is_some_and(|(at, _)| *at == self.consumed)
    }
    pub fn valid(&self) -> bool {
        self.spans.iter().all(|s| s.permit.valid())
            && self.fin.as_ref().is_none_or(|(_, p)| p.valid())
    }
    pub fn observe(
        &mut self,
        sequence: u32,
        syn: bool,
        len: usize,
        fin: bool,
        permit: SendPermit,
    ) -> Result<()> {
        ensure!(permit.valid(), "native input origin expired");
        if syn {
            let base = sequence.wrapping_add(1);
            ensure!(
                self.base.is_none_or(|old| old == base),
                "native RX sequence owner changed"
            );
            self.base = Some(base);
        }
        if len == 0 && !fin {
            return Ok(());
        }
        let base = self.base.ok_or(AdmissionError::Invalid)?;
        let wire_consumed = base.wrapping_add(self.consumed as u32);
        let start = self.consumed as i128
            + sequence
                .wrapping_add(u32::from(syn))
                .wrapping_sub(wire_consumed) as i32 as i128;
        let end = start + len as i128;
        let low = start.max(self.consumed as i128);
        let high = end.min((self.consumed + self.window) as i128);
        if high > low {
            let (mut cursor, high) = (low as u64, high as u64);
            let mut additions = Vec::new();
            for old in &self.spans {
                if old.end <= cursor {
                    continue;
                }
                if old.start >= high {
                    break;
                }
                if cursor < old.start {
                    additions.push(Span {
                        start: cursor,
                        end: old.start.min(high),
                        permit: permit.clone(),
                    });
                }
                cursor = cursor.max(old.end);
            }
            if cursor < high {
                additions.push(Span {
                    start: cursor,
                    end: high,
                    permit: permit.clone(),
                });
            }
            ensure!(
                self.spans.len() + additions.len() <= self.max_spans,
                "native RX origin metadata full"
            );
            self.spans.extend(additions);
            self.spans.sort_by_key(|s| s.start);
        }
        if fin && end >= self.consumed as i128 && end <= (self.consumed + self.window) as i128 {
            let at = end as u64;
            if let Some((old, _)) = &self.fin {
                ensure!(*old == at, "native FIN sequence changed");
            } else {
                self.fin = Some((at, permit));
            }
        }
        ensure!(self.valid(), "native buffered original admission retired");
        Ok(())
    }
    pub fn take(&mut self, len: usize, eof: bool) -> Result<Vec<SendPermit>> {
        ensure!(
            self.valid() && !self.eof,
            "native RX original admission retired"
        );
        let end = self
            .consumed
            .checked_add(len as u64)
            .ok_or(AdmissionError::Invalid)?;
        let mut cursor = self.consumed;
        let mut permits = Vec::new();
        for span in &self.spans {
            if span.end <= cursor {
                continue;
            }
            if cursor >= end {
                break;
            }
            ensure!(
                span.start <= cursor,
                "native TCP bytes have no original admission"
            );
            permits.push(span.permit.clone());
            cursor = span.end.min(end);
        }
        ensure!(cursor == end, "native TCP bytes have no original admission");
        if eof {
            let (at, permit) = self.fin.as_ref().ok_or(AdmissionError::Invalid)?;
            ensure!(*at == end, "native EOF has no original FIN admission");
            permits.push(permit.clone());
            self.fin = None;
            self.eof = true;
        }
        self.consumed = end;
        self.spans.retain(|s| s.end > end);
        for s in &mut self.spans {
            s.start = s.start.max(end);
        }
        Ok(permits)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    #[test]
    fn forwarding_receive_window_retains_the_first_origin_beyond_the_legacy_window() -> Result<()> {
        let mut origins = Origins::with_window(super::super::FORWARD_WINDOW);
        let active = Arc::new(AtomicBool::new(true));
        let first = active.clone();
        origins.observe(0, true, 0, false, SendPermit::new(|| true))?;
        let offset = 24 * 1024;
        origins.observe(
            1 + offset,
            false,
            1024,
            false,
            SendPermit::new(move || first.load(Ordering::SeqCst)),
        )?;
        for start in (0..=offset).step_by(1024) {
            origins.observe(1 + start, false, 1024, false, SendPermit::new(|| true))?;
        }
        origins.take(offset as usize, false)?;
        let originals = origins.take(1024, false)?;
        active.store(false, Ordering::SeqCst);
        assert!(originals.iter().any(|p| !p.valid()));
        Ok(())
    }
    #[test]
    fn wrapping_out_of_order_spans_keep_first_origin_on_overlap() -> Result<()> {
        let mut o = Origins::default();
        let old = Arc::new(AtomicBool::new(true));
        let p = old.clone();
        o.observe(u32::MAX - 3, true, 0, false, SendPermit::new(|| true))?;
        o.observe(
            1,
            false,
            4,
            false,
            SendPermit::new(move || p.load(Ordering::SeqCst)),
        )?;
        o.observe(u32::MAX - 2, false, 6, false, SendPermit::new(|| true))?;
        let permits = o.take(8, false)?;
        assert_eq!(o.consumed, 8);
        assert_eq!(permits.len(), 2);
        old.store(false, Ordering::SeqCst);
        assert!(!permits.iter().all(|p| p.valid()));
        Ok(())
    }
    #[test]
    fn duplicate_consumed_bytes_do_not_retire_new_data_but_fin_keeps_origin() -> Result<()> {
        let mut o = Origins::default();
        o.observe(10, true, 0, false, SendPermit::new(|| true))?;
        o.observe(11, false, 4, false, SendPermit::new(|| true))?;
        o.take(4, false)?;
        let expired = Arc::new(AtomicBool::new(true));
        let p = expired.clone();
        o.observe(
            11,
            false,
            4,
            false,
            SendPermit::new(move || p.load(Ordering::SeqCst)),
        )?;
        expired.store(false, Ordering::SeqCst);
        assert!(o.valid());
        let live = Arc::new(AtomicBool::new(true));
        let p = live.clone();
        o.observe(
            15,
            false,
            0,
            true,
            SendPermit::new(move || p.load(Ordering::SeqCst)),
        )?;
        let eof = o.take(0, true)?;
        live.store(false, Ordering::SeqCst);
        assert!(!eof[0].valid());
        assert!(o.valid(), "delivered EOF left a pending old origin fence");
        assert!(o.take(0, true).is_err());
        Ok(())
    }
    #[test]
    fn missing_gap_and_metadata_overflow_fail_closed() -> Result<()> {
        let mut o = Origins::default();
        o.observe(100, true, 0, false, SendPermit::new(|| true))?;
        o.observe(102, false, 1, false, SendPermit::new(|| true))?;
        assert!(o.take(2, false).is_err());
        for n in 0..255 {
            o.observe(104 + n * 2, false, 1, false, SendPermit::new(|| true))?;
        }
        assert!(
            o.observe(1000, false, 1, false, SendPermit::new(|| true))
                .is_err()
        );
        Ok(())
    }
}
