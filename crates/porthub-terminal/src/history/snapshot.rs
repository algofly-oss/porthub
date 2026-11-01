//! Immutable host-side scrollback. Paging never re-reads a moving tmux buffer.
use super::{capture, CapturedPage, MAX_CAPTURE};
use crate::{multiplexer::Workspace, protocol::*};
use anyhow::{ensure, Result};
use std::sync::Arc;

const MAX_SNAPSHOT: usize = 64 * 1024 * 1024;
const MAX_HEADER: usize = 128;

#[derive(Clone)]
pub struct Snapshot {
    id: String,
    pane: String,
    bytes: Arc<[u8]>,
    offsets: Arc<[usize]>,
}

impl Snapshot {
    pub(super) fn new(pane: String, bytes: Vec<u8>) -> Result<Self> {
        history_request(&pane, 0, 1)?;
        ensure!(!pane.is_empty(), "snapshot requires a resolved pane");
        ensure!(
            bytes.len() <= MAX_SNAPSHOT,
            "history snapshot exceeds host storage limit"
        );
        let mut offsets = vec![0];
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'\n' {
                offsets.push(index + 1);
            }
        }
        if offsets.last().copied() != Some(bytes.len()) {
            offsets.push(bytes.len());
        }
        ensure!(
            offsets.len() <= 200_001,
            "history snapshot exceeds line limit"
        );
        Ok(Self {
            id: random_token(16),
            pane,
            bytes: bytes.into(),
            offsets: offsets.into(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn pane(&self) -> &str {
        &self.pane
    }
    pub fn total(&self) -> u32 {
        (self.offsets.len() - 1) as u32
    }
    /// Include the index in host cache accounting, not just terminal bytes.
    pub fn storage_bytes(&self) -> usize {
        self.bytes.len() + self.offsets.len() * std::mem::size_of::<usize>()
    }

    /// The membership guard, metadata and capture run in one synchronous tmux
    /// command queue. No external shell or guest-supplied command is executed.
    pub async fn capture(workspace: &Workspace, pane: &str) -> Result<Self> {
        history_request(pane, 0, 1)?;
        let target = if pane.is_empty() { "=workspace:" } else { pane };
        let body = format!(
            "display-message -p -t {target} 'PORTHUB-SNAPSHOT|#{{pane_id}}|#{{history_size}}'; \
             if-shell -F -t {target} '#{{history_size}}' 'capture-pane -p -t {target} -S - -E -1'"
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (mut bytes, truncated) = capture(
                workspace,
                &[
                    "if-shell".into(),
                    "-F".into(),
                    "-t".into(),
                    target.into(),
                    "#{==:#{session_name},workspace}".into(),
                    body,
                    "display-message -p 'PORTHUB-SNAPSHOT-REJECTED'".into(),
                ],
                MAX_SNAPSHOT + MAX_HEADER,
            )
            .await?;
            ensure!(!truncated, "history snapshot exceeds host storage limit");
            let end = bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .filter(|end| *end < MAX_HEADER)
                .ok_or_else(|| anyhow::anyhow!("history snapshot metadata missing"))?;
            let header = std::str::from_utf8(&bytes[..end])?;
            let mut fields = header.split('|');
            ensure!(
                fields.next() == Some("PORTHUB-SNAPSHOT"),
                "pane is outside the shared workspace"
            );
            let pane = fields
                .next()
                .ok_or_else(|| anyhow::anyhow!("snapshot pane missing"))?
                .to_owned();
            let total: u32 = fields
                .next()
                .ok_or_else(|| anyhow::anyhow!("snapshot size missing"))?
                .parse()?;
            ensure!(
                fields.next().is_none() && total <= 200_000,
                "invalid snapshot metadata"
            );
            bytes.drain(..=end);
            let snapshot = Self::new(pane, bytes)?;
            ensure!(
                snapshot.total() == total,
                "history changed during capture; refresh to try again"
            );
            Ok(snapshot)
        })
        .await?
    }

    pub fn page(&self, before: u32, lines: u16) -> Result<CapturedPage> {
        history_request(&self.pane, before, lines)?;
        let end = self.total().saturating_sub(before) as usize;
        let count = end.min(usize::from(lines));
        let start = self.offsets[end - count];
        let finish = self.offsets[end];
        let limit = finish.min(start.saturating_add(MAX_CAPTURE));
        Ok(CapturedPage {
            bytes: self.bytes[start..limit].to_vec(),
            total: self.total(),
            lines: count as u16,
            truncated: limit < finish,
            pane: self.pane.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_pages_have_no_gaps_and_share_identity_across_clones() -> Result<()> {
        let bytes = "first 🦀\nsecond e\u{301}\nthird\nlast\n"
            .as_bytes()
            .to_vec();
        let snapshot = Snapshot::new("%42".into(), bytes.clone())?;
        let copy = snapshot.clone();
        assert_eq!(snapshot.total(), 4);
        assert_eq!(snapshot.id(), copy.id());
        assert!(token(snapshot.id(), 32));
        let mut joined = snapshot.page(2, 2)?.bytes;
        joined.extend(copy.page(0, 2)?.bytes);
        assert_eq!(joined, bytes);
        assert_eq!(snapshot.page(200_000, 2)?.bytes, b"");
        assert_eq!(snapshot.pane(), "%42");
        assert!(snapshot.storage_bytes() >= bytes.len());
        Ok(())
    }

    #[test]
    fn empty_blank_and_unterminated_lines_have_exact_boundaries() -> Result<()> {
        for (bytes, count) in [(b"".as_slice(), 0), (b"\n", 1), (b"x", 1), (b"x\n\n", 2)] {
            let snapshot = Snapshot::new("%0".into(), bytes.into())?;
            assert_eq!(snapshot.total(), count);
            assert_eq!(snapshot.page(0, 5)?.bytes, bytes);
        }
        Ok(())
    }

    #[test]
    fn responses_remain_bounded_and_unsafe_selectors_are_rejected() -> Result<()> {
        let snapshot = Snapshot::new("%0".into(), vec![b'x'; MAX_CAPTURE + 1])?;
        let page = snapshot.page(0, 1)?;
        assert!(page.truncated);
        assert_eq!(page.bytes.len(), MAX_CAPTURE);
        assert!(snapshot.page(0, 0).is_err());
        assert!(Snapshot::new("%0; unsafe".into(), vec![]).is_err());
        assert!(Snapshot::new(String::new(), vec![]).is_err());
        assert!(Snapshot::new("%0".into(), vec![b'x'; MAX_SNAPSHOT + 1]).is_err());
        Ok(())
    }
}
