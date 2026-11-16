//! Version/identity decisions for process-wide CLI/desktop artifacts. A tenant's
//! core version is not necessarily the version of the shared CLI or GUI worker.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Image {
    pub executable: PathBuf,
    pub sha256: String,
    pub version: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cli {
    pub path: PathBuf,
    pub image: Image,
}
pub(super) fn higher<'a>(left: &'a Image, right: &'a Image) -> Result<&'a Image> {
    match porthub_components::release_version::compare(&left.version, &right.version) {
        Some(std::cmp::Ordering::Greater) => Ok(left),
        Some(std::cmp::Ordering::Less) => Ok(right),
        Some(std::cmp::Ordering::Equal) => {
            ensure!(
                left.sha256 == right.sha256,
                "Equal-version shared images have different bytes; preserve operator choice"
            );
            Ok(left)
        }
        None => anyhow::bail!("Shared image version is not comparable"),
    }
}
pub(super) fn publish_candidate(
    owns_cli: bool,
    previous: Option<&Image>,
    candidate: &Image,
) -> Result<bool> {
    if !owns_cli {
        return Ok(false);
    }
    let previous =
        previous.ok_or_else(|| anyhow::anyhow!("Owned CLI disappeared before maintenance"))?;
    Ok(higher(previous, candidate)?.sha256 == candidate.sha256
        && previous.sha256 != candidate.sha256)
}
pub(super) fn reconcile_candidate(
    phase: super::transaction::Phase,
    installed_candidate: bool,
    publishes: bool,
) -> bool {
    installed_candidate
        && publishes
        && !matches!(
            phase,
            super::transaction::Phase::RollingBack
                | super::transaction::Phase::RecoveryRequired
                | super::transaction::Phase::RolledBack
                | super::transaction::Phase::Cancelled
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn image(version: &str) -> Image {
        Image {
            executable: version.into(),
            sha256: version.repeat(4),
            version: version.into(),
        }
    }
    #[test]
    fn interrupted_rollback_never_republishes_candidate_cli() {
        use super::super::transaction::Phase;
        assert!(reconcile_candidate(Phase::Applying, true, true));
        assert!(reconcile_candidate(Phase::Committed, true, true));
        for phase in [
            Phase::RollingBack,
            Phase::RecoveryRequired,
            Phase::RolledBack,
            Phase::Cancelled,
        ] {
            assert!(!reconcile_candidate(phase, true, true));
        }
        assert!(!reconcile_candidate(Phase::Verifying, true, false));
        assert!(!reconcile_candidate(Phase::Verifying, false, true));
    }
    #[test]
    fn higher_shared_cli_survives_older_tenant_success_and_rollback() {
        let service = image("1.11.33");
        let candidate = image("1.11.34");
        let shared = image("1.11.35");
        assert!(!publish_candidate(true, Some(&shared), &candidate).unwrap());
        assert_eq!(higher(&shared, &candidate).unwrap(), &shared);
        assert_eq!(higher(&shared, &service).unwrap(), &shared);
    }
    #[test]
    fn forward_publication_is_owned_and_does_not_infer_service_equals_cli() {
        let service = image("1.11.33");
        let cli = image("1.11.35");
        let candidate = image("1.11.36");
        assert!(publish_candidate(true, Some(&cli), &candidate).unwrap());
        assert!(!publish_candidate(false, Some(&cli), &candidate).unwrap());
        assert_ne!(cli.sha256, service.sha256);
        assert_eq!(higher(&cli, &service).unwrap(), &cli);
    }
    #[test]
    fn equal_version_fork_and_unversioned_cli_are_not_overwritten() {
        let a = image("1.11.35");
        let mut fork = a.clone();
        fork.sha256 = "other".into();
        assert!(higher(&a, &fork).is_err());
        assert!(higher(&a, &image("unknown")).is_err());
        assert!(!publish_candidate(true, Some(&a), &a).unwrap());
    }
}
