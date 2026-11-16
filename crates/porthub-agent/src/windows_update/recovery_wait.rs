//! Startup reconciliation waits only while the protected journal's known file
//! endpoints remain authoritative; unrelated/corrupt files never become trust.
use anyhow::Result;
use std::time::Duration;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Snapshot {
    Known,
    Transient,
    Foreign,
}
pub(super) async fn wait<K, I>(mut known: K, mut installed: I, limit: Duration) -> Result<()>
where
    K: FnMut() -> Result<Snapshot>,
    I: FnMut() -> Result<bool>,
{
    tokio::time::timeout(limit, async {
        loop {
            match known()? {
                Snapshot::Foreign => anyhow::bail!(
                    "Operator registration edits preserved; recovery authority refused"
                ),
                Snapshot::Known => {
                    // The unit and manifest may be individually atomic but not
                    // mutually consistent until the worker finishes both writes.
                    if installed().unwrap_or(false) {
                        return Ok(());
                    }
                }
                Snapshot::Transient => {}
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("Windows recovery metadata is still pending"))?
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test(start_paused = true)]
    async fn transient_installed_mismatch_then_repair_allows_controller_start() {
        let checks = AtomicUsize::new(0);
        wait(
            || Ok(Snapshot::Known),
            || match checks.fetch_add(1, Ordering::SeqCst) {
                0 => anyhow::bail!("known unit/manifest temporarily disagree"),
                1 => Ok(false),
                _ => Ok(true),
            },
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        // This is the real prerequisite for constructing the SCM Controller:
        // initial inspect failure is not mistaken for a permanent absence.
        assert_eq!(checks.load(Ordering::SeqCst), 3);
    }
    #[tokio::test(start_paused = true)]
    async fn missing_transient_metadata_is_bounded() {
        let result = wait(
            || Ok(Snapshot::Transient),
            || panic!("cannot authorize unreadable state"),
            Duration::from_secs(10),
        )
        .await;
        assert!(result.is_err());
    }
    #[tokio::test]
    async fn foreign_state_never_reaches_controller_inspection() {
        assert!(wait(
            || Ok(Snapshot::Foreign),
            || panic!("foreign metadata authorized"),
            Duration::from_secs(10)
        )
        .await
        .is_err());
    }
}
