//! Journal validation is independent of native handles, and always precedes
//! restoration. A journal is an identity-bound capability, never a path list.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct DiskIdentity {
    pub instance: String,
    pub serial: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Volume {
    pub path: String,
    pub ranges: Vec<(i64, i64)>,
    pub changed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal {
    pub version: u32,
    pub busid: String,
    pub disk: DiskIdentity,
    pub volumes: Vec<Volume>,
}
pub(super) fn valid_volume_path(path: &str) -> bool {
    path.strip_prefix("\\\\?\\Volume{")
        .and_then(|s| s.strip_suffix('}'))
        .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
}
pub(super) fn validate(j: &Journal) -> Result<()> {
    ensure!(
        j.version == 1,
        "Unsupported USB preparation journal version"
    );
    ensure!(
        j.disk.instance.starts_with("USB\\")
            && j.disk.instance.len() <= 1024
            && !j.disk.instance.contains('\0')
            && !j.disk.serial.is_empty()
            && j.disk.serial.len() <= 1024
            && j.disk.bytes > 0
            && j.disk.bytes <= i64::MAX as u64,
        "Invalid prepared USB disk identity"
    );
    ensure!(
        !j.volumes.is_empty() && j.volumes.len() <= 256,
        "Invalid prepared volume count"
    );
    let mut paths = std::collections::HashSet::new();
    let mut ranges = Vec::new();
    for v in &j.volumes {
        ensure!(
            valid_volume_path(&v.path) && paths.insert(v.path.to_ascii_lowercase()),
            "Invalid or duplicate prepared volume identity"
        );
        ensure!(
            !v.ranges.is_empty() && v.ranges.len() <= 256,
            "Invalid prepared volume extents"
        );
        for &(start, length) in &v.ranges {
            ensure!(start >= 0 && length > 0, "Invalid prepared extent range");
            let end = start
                .checked_add(length)
                .filter(|end| *end as u64 <= j.disk.bytes)
                .ok_or_else(|| anyhow::anyhow!("Prepared extent exceeds USB disk"))?;
            ranges.push((start, end));
        }
    }
    ranges.sort_unstable();
    ensure!(
        ranges.windows(2).all(|p| p[0].1 <= p[1].0),
        "Prepared volume extents overlap"
    );
    Ok(())
}
/// Acquire all locks as a single prerequisite. If any lock fails, release
/// every previously acquired lock; callers retain handles until this returns.
pub(super) fn lock_all(
    count: usize,
    mut operation: impl FnMut(usize, bool) -> Result<()>,
) -> Result<()> {
    for index in 0..count {
        if let Err(error) = operation(index, true) {
            for previous in 0..index {
                let _ = operation(previous, false);
            }
            return Err(error.context(
                "Cannot lock all USB volumes; close applications using the drive and retry",
            ));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn journal() -> Journal {
        Journal {
            version: 1,
            busid: "1-14".into(),
            disk: DiskIdentity {
                instance: "USB\\VID_0781&PID_55A9\\serial".into(),
                serial: "serial".into(),
                bytes: 10000,
            },
            volumes: vec![Volume {
                path: "\\\\?\\Volume{5261fe12-e0cc-11f1-8916-7c5079dd840b}".into(),
                ranges: vec![(100, 900)],
                changed: true,
            }],
        }
    }
    #[test]
    fn valid_identity_roundtrips_without_extra_capabilities() {
        let j = journal();
        validate(&j).unwrap();
        let bytes = serde_json::to_vec(&j).unwrap();
        validate(&serde_json::from_slice::<Journal>(&bytes).unwrap()).unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        json["force"] = true.into();
        assert!(serde_json::from_value::<Journal>(json).is_err());
    }
    #[test]
    fn rejects_arbitrary_device_paths_duplicate_volumes_and_ranges() {
        let mut j = journal();
        j.volumes[0].path = "\\\\.\\PhysicalDrive0".into();
        assert!(validate(&j).is_err());
        let mut j = journal();
        j.volumes.push(j.volumes[0].clone());
        assert!(validate(&j).is_err());
        let mut j = journal();
        j.volumes[0].ranges.push((500, 10));
        assert!(validate(&j).is_err());
    }
    #[test]
    fn rejects_overflow_out_of_disk_and_unstable_identity() {
        for range in [(-1, 10), (0, 0), (9999, 2), (i64::MAX, 1)] {
            let mut j = journal();
            j.volumes[0].ranges = vec![range];
            assert!(validate(&j).is_err());
        }
        let mut j = journal();
        j.disk.serial.clear();
        assert!(validate(&j).is_err());
        j = journal();
        j.disk.instance = "ROOT\\internal".into();
        assert!(validate(&j).is_err());
    }
    #[test]
    fn permits_disjoint_partitions_and_preserves_changed_flags() {
        let mut j = journal();
        let mut second = j.volumes[0].clone();
        second.path = "\\\\?\\Volume{6261fe12-e0cc-11f1-8916-7c5079dd840b}".into();
        second.ranges = vec![(1000, 200)];
        second.changed = false;
        j.volumes.push(second);
        validate(&j).unwrap();
        assert!(j.volumes[0].changed);
        assert!(!j.volumes[1].changed);
    }
    #[test]
    fn lock_failure_releases_every_prior_lock_without_proceeding() {
        let mut calls = Vec::new();
        let result = lock_all(4, |index, acquire| {
            calls.push((index, acquire));
            if index == 2 && acquire {
                anyhow::bail!("busy volume");
            }
            // Even an unlock failure must not skip releasing the other locks.
            if index == 0 && !acquire {
                anyhow::bail!("removed volume");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            calls,
            [(0, true), (1, true), (2, true), (0, false), (1, false)]
        );
    }
    #[test]
    fn successful_lock_prerequisite_acquires_every_volume() {
        let mut calls = Vec::new();
        lock_all(3, |index, acquire| {
            calls.push((index, acquire));
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, [(0, true), (1, true), (2, true)]);
    }
}
