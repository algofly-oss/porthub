//! Local evidence for a stopped private worker. A single enrolled worker owns the
//! profile lease while recording. Recovery and successful renewals never write here.
use crate::{profile, runtime::PrivateWorkerFailure};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const LIMIT: usize = 8;
pub(crate) const SUFFIX: &str = ".private-failures.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FailureRecord {
    pub first_unix_seconds: u64,
    pub last_unix_seconds: u64,
    pub occurrences: u32,
    pub stage: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_error: Option<i32>,
}

impl FailureRecord {
    pub(crate) fn from_error(error: &anyhow::Error) -> Self {
        let os_error = error
            .chain()
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
            .find_map(std::io::Error::raw_os_error);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            first_unix_seconds: now,
            last_unix_seconds: now,
            occurrences: 1,
            stage: crate::unified::private_failure_stage(error).to_owned(),
            reason: crate::unified::private_failure_reason(error).to_owned(),
            os_error,
        }
    }

    pub(crate) fn status(&self) -> PrivateWorkerFailure {
        let reason = match self.os_error {
            Some(code) => format!("{} (OS error {code})", self.reason),
            None => self.reason.clone(),
        };
        PrivateWorkerFailure {
            stage: self.stage.clone(),
            reason,
        }
    }
}

pub(crate) fn recent(private_profile: &Path) -> Result<Vec<FailureRecord>> {
    let path = profile::sibling(private_profile, SUFFIX);
    if !path.try_exists()? {
        return Ok(Vec::new());
    }
    let bytes = profile::read_private(&path)?;
    // The journal is diagnostic. A damaged previous copy must not prevent
    // recording a future incident. Propagate filesystem/ownership errors above.
    if bytes.len() <= 8192 {
        if let Ok(records) = serde_json::from_slice::<Vec<FailureRecord>>(&bytes) {
            if records.len() <= LIMIT {
                return Ok(records);
            }
        }
    }
    tracing::debug!("discarding invalid local private failure history");
    Ok(Vec::new())
}

pub(crate) fn record(private_profile: &Path, event: FailureRecord) -> Result<()> {
    let mut records = recent(private_profile)?;
    // Preserve the initiating failure even if a long outage produces many
    // identical native-owner retries. Insertion order also survives wall-clock jumps.
    if let Some(previous) = records.last_mut().filter(|last| {
        last.stage == event.stage && last.reason == event.reason && last.os_error == event.os_error
    }) {
        previous.last_unix_seconds = event.last_unix_seconds;
        previous.occurrences = previous.occurrences.saturating_add(1);
    } else {
        if records.len() == LIMIT {
            records.remove(0);
        }
        records.push(event);
    }
    profile::write_private(
        &profile::sibling(private_profile, SUFFIX),
        &serde_json::to_vec(&records)?,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified::PrivateStage;

    #[test]
    fn private_worker_diagnostics_persist_only_bounded_safe_causes() -> Result<()> {
        let root = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let profile = root.path().join("profile.json");
        let lock_owner = profile::Lease::acquire(&profile)?;
        let collision = profile::Lease::acquire(&profile)
            .err()
            .expect("lease must be exclusive");
        let event = FailureRecord::from_error(&collision.context(PrivateStage::NativeOwner));
        assert_eq!(event.reason, "private worker lock is held by another owner");
        assert_eq!(event.os_error, fs2::lock_contended_error().raw_os_error());
        drop(lock_owner);
        let fake =
            anyhow::anyhow!("macOS utun read failed: http://private.invalid/token (OS error 55)");
        let unclassified = FailureRecord::from_error(&fake);
        assert_eq!(unclassified.os_error, None);
        assert!(!unclassified.reason.contains("packet read"));
        assert!(!unclassified.reason.contains("private.invalid"));
        assert!(recent(&profile)?.is_empty());
        profile::write_private(&profile::sibling(&profile, SUFFIX), b"incomplete", true)?;
        for code in 1..=11 {
            let error = anyhow::Error::from(std::io::Error::from_raw_os_error(code))
                .context("http://private.invalid/secret-token")
                .context("macOS utun read failed")
                .context(PrivateStage::NativeOwner);
            let event = FailureRecord::from_error(&error);
            assert_eq!(event.os_error, Some(code));
            assert_eq!(event.stage, "native-owner");
            assert_eq!(event.reason, "macOS private tunnel packet read failed");
            assert!(event.status().reason.contains(&format!("OS error {code}")));
            record(&profile, event)?;
        }
        let records = recent(&profile)?;
        assert_eq!(
            records
                .iter()
                .filter_map(|e| e.os_error)
                .collect::<Vec<_>>(),
            (4..=11).collect::<Vec<_>>()
        );
        let mut repeated = records.last().unwrap().clone();
        repeated.last_unix_seconds = 1;
        record(&profile, repeated)?;
        let coalesced = recent(&profile)?;
        assert_eq!(coalesced.len(), LIMIT);
        assert_eq!(coalesced.last().unwrap().occurrences, 2);
        assert_eq!(coalesced.last().unwrap().last_unix_seconds, 1);
        let file = profile::sibling(&profile, SUFFIX);
        assert!(!std::fs::read_to_string(&file)?.contains("secret-token"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(file)?.permissions().mode() & 0o077, 0);
        }
        Ok(())
    }
}
