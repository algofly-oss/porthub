//! Platform-independent transaction/recovery rules used by the Windows worker.
use anyhow::{ensure, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum Phase {
    Prepared,
    Applying,
    Verifying,
    Committed,
    RollingBack,
    RolledBack,
    Cancelled,
    RecoveryRequired,
}
impl Phase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Committed | Self::RolledBack | Self::Cancelled)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Installed {
    Previous,
    Candidate,
    Foreign,
}
#[async_trait]
pub(super) trait Backend: Send + Sync {
    async fn installed(&self) -> Result<Installed>;
    fn permitted(&self) -> bool;
    async fn install_candidate(&self) -> Result<()>;
    async fn ready_candidate(&self) -> Result<()>;
    async fn restore_previous(&self) -> Result<()>;
    async fn ready_previous(&self) -> Result<()>;
}
pub(super) trait Journal {
    fn phase(&self) -> Phase;
    fn persist(&mut self, phase: Phase) -> Result<()>;
}
/// Used for both manifest and unit recovery. A similarly shaped or partly
/// modified file is not one of the two authorized transaction snapshots.
pub(super) fn known_snapshot(current: &[u8], previous: &[u8], candidate: &[u8]) -> bool {
    current == previous || current == candidate
}
pub(super) struct CommitIdentity<'a> {
    pub request: &'a crate::update::Request,
    pub version: &'a str,
    pub source: &'a str,
}
pub(super) fn can_ack(
    phase: Phase,
    receipt: CommitIdentity<'_>,
    running: CommitIdentity<'_>,
) -> bool {
    phase == Phase::Committed
        && receipt.request == running.request
        && receipt.request.target_version == receipt.version
        && running.request.target_version == running.version
        && receipt.version == running.version
        && receipt.source.len() == 40
        && receipt.source == running.source
}
pub(super) fn retry_seconds(attempt: u8) -> u64 {
    30u64
        .saturating_mul(1u64.checked_shl(u32::from(attempt)).unwrap_or(u64::MAX))
        .min(900)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RequestState {
    Newer,
    EqualUnproven,
    Superseded,
    Committed,
    Unsupported,
}
pub(super) fn request_state(current: &str, target: &str, committed: bool) -> RequestState {
    match porthub_components::release_version::compare(target, current) {
        Some(std::cmp::Ordering::Greater) => RequestState::Newer,
        Some(std::cmp::Ordering::Less) => RequestState::Superseded,
        Some(std::cmp::Ordering::Equal) if committed => RequestState::Committed,
        Some(std::cmp::Ordering::Equal) => RequestState::EqualUnproven,
        None => RequestState::Unsupported,
    }
}
pub(super) fn target_allowed(current: &str, target: &str) -> bool {
    request_state(current, target, false) == RequestState::Newer
}
pub(super) fn parse_provenance(text: &str, version: &str, target: &str) -> Result<String> {
    let lines = text.lines().collect::<Vec<_>>();
    ensure!(
        lines.len() == 3
            && lines[0] == format!("porthub {version}")
            && lines[2] == format!("target {target}"),
        "Published core target/version mismatch"
    );
    let revision = lines[1]
        .strip_prefix("build ")
        .ok_or_else(|| anyhow::anyhow!("Source revision missing"))?;
    ensure!(
        revision.len() == 40 && revision.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid core source revision"
    );
    Ok(revision.to_owned())
}
async fn rollback<B: Backend, J: Journal>(backend: &B, journal: &mut J) -> Result<()> {
    journal.persist(Phase::RollingBack)?;
    let result = async {
        match backend.installed().await? {
            Installed::Candidate => backend.restore_previous().await?,
            Installed::Previous => {}
            Installed::Foreign => {
                anyhow::bail!("Operator state changed; automatic rollback refused")
            }
        }
        backend.ready_previous().await?;
        journal.persist(Phase::RolledBack)
    }
    .await;
    if result.is_err() {
        let _ = journal.persist(Phase::RecoveryRequired);
    }
    result
}
/// Resume is idempotent. Never cancel an in-flight service transaction: after it
/// settles, revoked permission requires rollback instead of a success receipt.
pub(super) async fn execute<B: Backend, J: Journal>(backend: &B, journal: &mut J) -> Result<()> {
    let installed = backend.installed().await?;
    if installed == Installed::Foreign {
        journal.persist(Phase::RecoveryRequired)?;
        anyhow::bail!("Installed registration differs from both verified update endpoints");
    }
    match journal.phase() {
        Phase::Committed => {
            ensure!(installed == Installed::Candidate, "Committed image changed");
            return backend.ready_candidate().await;
        }
        Phase::Cancelled | Phase::RolledBack => {
            ensure!(
                installed == Installed::Previous,
                "Terminal rollback image changed"
            );
            return Ok(());
        }
        Phase::RollingBack | Phase::RecoveryRequired => return rollback(backend, journal).await,
        _ => {}
    }
    if installed == Installed::Previous {
        if !backend.permitted() {
            journal.persist(Phase::Cancelled)?;
            return Ok(());
        }
        journal.persist(Phase::Applying)?;
        if backend.install_candidate().await.is_err() {
            return rollback(backend, journal).await;
        }
    }
    if !backend.permitted() {
        return rollback(backend, journal).await;
    }
    journal.persist(Phase::Verifying)?;
    if backend.ready_candidate().await.is_err() || !backend.permitted() {
        return rollback(backend, journal).await;
    }
    // A matching runtime report alone cannot acknowledge a changed registration.
    if backend.installed().await? != Installed::Candidate {
        journal.persist(Phase::RecoveryRequired)?;
        anyhow::bail!("Candidate registration changed before commit");
    }
    journal.persist(Phase::Committed)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    struct Fake {
        image: Mutex<Installed>,
        allowed: AtomicBool,
        calls: Mutex<Vec<&'static str>>,
        fail_install: bool,
        fail_ready: bool,
        fail_restore: bool,
        revoke_after_install: bool,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                image: Mutex::new(Installed::Previous),
                allowed: AtomicBool::new(true),
                calls: Mutex::new(vec![]),
                fail_install: false,
                fail_ready: false,
                fail_restore: false,
                revoke_after_install: false,
            }
        }
    }
    #[async_trait]
    impl Backend for Fake {
        async fn installed(&self) -> Result<Installed> {
            Ok(*self.image.lock().unwrap())
        }
        fn permitted(&self) -> bool {
            self.allowed.load(Ordering::SeqCst)
        }
        async fn install_candidate(&self) -> Result<()> {
            self.calls.lock().unwrap().push("install");
            *self.image.lock().unwrap() = Installed::Candidate;
            if self.revoke_after_install {
                self.allowed.store(false, Ordering::SeqCst);
            }
            ensure!(!self.fail_install, "install failed");
            Ok(())
        }
        async fn ready_candidate(&self) -> Result<()> {
            self.calls.lock().unwrap().push("ready-new");
            ensure!(!self.fail_ready, "not ready");
            Ok(())
        }
        async fn restore_previous(&self) -> Result<()> {
            self.calls.lock().unwrap().push("rollback");
            ensure!(!self.fail_restore, "rollback failed");
            *self.image.lock().unwrap() = Installed::Previous;
            Ok(())
        }
        async fn ready_previous(&self) -> Result<()> {
            self.calls.lock().unwrap().push("ready-old");
            Ok(())
        }
    }
    struct Memory {
        phase: Phase,
        writes: Vec<Phase>,
        fail_commit: bool,
    }
    impl Memory {
        fn new(phase: Phase) -> Self {
            Self {
                phase,
                writes: vec![],
                fail_commit: false,
            }
        }
    }
    impl Journal for Memory {
        fn phase(&self) -> Phase {
            self.phase
        }
        fn persist(&mut self, p: Phase) -> Result<()> {
            ensure!(!(self.fail_commit && p == Phase::Committed), "disk failure");
            self.phase = p;
            self.writes.push(p);
            Ok(())
        }
    }
    #[tokio::test]
    async fn commit_requires_installed_and_ready_then_durable_journal() {
        let b = Fake::default();
        let mut j = Memory::new(Phase::Prepared);
        execute(&b, &mut j).await.unwrap();
        assert_eq!(j.phase, Phase::Committed);
        assert_eq!(
            j.writes,
            vec![Phase::Applying, Phase::Verifying, Phase::Committed]
        );
        assert_eq!(*b.calls.lock().unwrap(), vec!["install", "ready-new"]);
    }
    #[tokio::test]
    async fn revoked_before_start_never_mutates() {
        let b = Fake::default();
        b.allowed.store(false, Ordering::SeqCst);
        let mut j = Memory::new(Phase::Prepared);
        execute(&b, &mut j).await.unwrap();
        assert_eq!(j.phase, Phase::Cancelled);
        assert!(b.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn revoked_during_install_settles_then_rolls_back() {
        let b = Fake {
            revoke_after_install: true,
            ..Default::default()
        };
        let mut j = Memory::new(Phase::Prepared);
        execute(&b, &mut j).await.unwrap();
        assert_eq!(j.phase, Phase::RolledBack);
        assert_eq!(*b.image.lock().unwrap(), Installed::Previous);
    }
    #[tokio::test]
    async fn failed_readiness_and_partial_install_both_restore() {
        for install in [false, true] {
            let b = Fake {
                fail_ready: !install,
                fail_install: install,
                ..Default::default()
            };
            let mut j = Memory::new(Phase::Prepared);
            execute(&b, &mut j).await.unwrap();
            assert_eq!(j.phase, Phase::RolledBack);
        }
    }
    #[tokio::test]
    async fn failed_rollback_retains_recovery_requirement() {
        let b = Fake {
            fail_ready: true,
            fail_restore: true,
            ..Default::default()
        };
        let mut j = Memory::new(Phase::Prepared);
        assert!(execute(&b, &mut j).await.is_err());
        assert_eq!(j.phase, Phase::RecoveryRequired);
    }
    #[tokio::test]
    async fn interrupted_install_recovers_verified_candidate_without_reinstall() {
        let b = Fake::default();
        *b.image.lock().unwrap() = Installed::Candidate;
        let mut j = Memory::new(Phase::Applying);
        execute(&b, &mut j).await.unwrap();
        assert_eq!(j.phase, Phase::Committed);
        assert_eq!(*b.calls.lock().unwrap(), vec!["ready-new"]);
    }
    #[tokio::test]
    async fn foreign_operator_state_is_never_overwritten() {
        let b = Fake::default();
        *b.image.lock().unwrap() = Installed::Foreign;
        let mut j = Memory::new(Phase::Applying);
        assert!(execute(&b, &mut j).await.is_err());
        assert_eq!(j.phase, Phase::RecoveryRequired);
        assert!(b.calls.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn failed_commit_is_unacknowledged_and_retry_recovers() {
        let b = Fake::default();
        let mut j = Memory::new(Phase::Prepared);
        j.fail_commit = true;
        assert!(execute(&b, &mut j).await.is_err());
        assert_eq!(j.phase, Phase::Verifying);
        j.fail_commit = false;
        execute(&b, &mut j).await.unwrap();
        assert_eq!(j.phase, Phase::Committed);
        assert_eq!(
            b.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|&&c| c == "install")
                .count(),
            1
        );
    }
    #[test]
    fn recovery_accepts_only_exact_endpoint_snapshots() {
        assert!(known_snapshot(b"old", b"old", b"new"));
        assert!(known_snapshot(b"new", b"old", b"new"));
        for bad in [b"neW".as_slice(), b"new\n", b"old\0", b"", b"operator"] {
            assert!(!known_snapshot(bad, b"old", b"new"));
        }
    }
    #[test]
    fn provenance_and_monotonic_version_are_strict() {
        let text = format!(
            "porthub 1.11.35\nbuild {}\ntarget x86_64-pc-windows-msvc\n",
            "a".repeat(40)
        );
        assert_eq!(
            parse_provenance(&text, "1.11.35", "x86_64-pc-windows-msvc").unwrap(),
            "a".repeat(40)
        );
        assert!(parse_provenance(&text, "1.11.34", "x86_64-pc-windows-msvc").is_err());
        assert!(parse_provenance(&text, "1.11.35", "aarch64-pc-windows-msvc").is_err());
        assert!(parse_provenance(
            &text.replace(&"a".repeat(40), "unknown"),
            "1.11.35",
            "x86_64-pc-windows-msvc"
        )
        .is_err());
        assert!(parse_provenance(
            &(text.clone() + "unexpected"),
            "1.11.35",
            "x86_64-pc-windows-msvc"
        )
        .is_err());
        assert!(target_allowed("1.11.9", "1.11.10"));
        for target in ["1.11.9", "1.11.8", "unknown"] {
            assert!(!target_allowed("1.11.9", target));
        }
    }

    #[test]
    fn retry_delay_is_bounded_and_persistable() {
        assert_eq!(
            (0..8).map(retry_seconds).collect::<Vec<_>>(),
            vec![30, 60, 120, 240, 480, 900, 900, 900]
        );
        assert_eq!(retry_seconds(255), 900);
    }
    #[test]
    fn legacy_observed_requests_do_not_fabricate_ack_or_block_newer_updates() {
        // Installing the first supported updater over32/34 legitimately
        // supersedes older requested targets; only the server owns that record.
        assert_eq!(
            request_state("1.11.35", "1.11.34", false),
            RequestState::Superseded
        );
        // Equal-version manual install has no durable OTA receipt, so no ack.
        assert_eq!(
            request_state("1.11.35", "1.11.35", false),
            RequestState::EqualUnproven
        );
        assert!(!target_allowed("1.11.35", "1.11.35"));
        // There is no terminal latch for that stale ID: a later request runs.
        assert_eq!(
            request_state("1.11.35", "1.11.36", false),
            RequestState::Newer
        );
        assert!(target_allowed("1.11.35", "1.11.36"));
        assert_eq!(
            request_state("1.11.36", "1.11.36", true),
            RequestState::Committed
        );
        assert_eq!(
            request_state("1.11.36", "1.11.36", false),
            RequestState::EqualUnproven
        );
        assert_ne!(
            request_state("1.11.36", "1.11.35", true),
            RequestState::Committed
        );
    }
    #[test]
    fn acknowledgement_requires_matching_durable_transaction_and_running_identity() {
        use crate::update::Request;
        let request = Request {
            id: "real-request".into(),
            target_version: "1.11.36".into(),
        };
        let other = Request {
            id: "another-request".into(),
            target_version: "1.11.36".into(),
        };
        let source = "a".repeat(40);
        let receipt = || CommitIdentity {
            request: &request,
            version: "1.11.36",
            source: &source,
        };
        let running = || CommitIdentity {
            request: &request,
            version: "1.11.36",
            source: &source,
        };
        assert!(can_ack(Phase::Committed, receipt(), running()));
        for phase in [
            Phase::Prepared,
            Phase::Applying,
            Phase::Verifying,
            Phase::RollingBack,
            Phase::RolledBack,
            Phase::Cancelled,
            Phase::RecoveryRequired,
        ] {
            assert!(!can_ack(phase, receipt(), running()));
        }
        assert!(!can_ack(
            Phase::Committed,
            receipt(),
            CommitIdentity {
                request: &other,
                ..running()
            }
        ));
        assert!(!can_ack(
            Phase::Committed,
            receipt(),
            CommitIdentity {
                version: "1.11.35",
                ..running()
            }
        ));
        assert!(!can_ack(
            Phase::Committed,
            receipt(),
            CommitIdentity {
                source: &"b".repeat(40),
                ..running()
            }
        ));
    }
}
