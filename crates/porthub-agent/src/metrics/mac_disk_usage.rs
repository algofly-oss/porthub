//! Physical macOS storage allocation. APFS container capacity comes from the OS,
//! never from adding quota-scoped volumes or snapshots sharing the same pool.
use porthub_components::metrics::{Disk, Memory};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
#[cfg(target_os = "macos")]
mod native;
#[derive(Clone, Debug)]
struct Partition {
    bsd: String,
    size: u64,
    apfs: bool,
}
#[derive(Clone, Debug)]
struct Physical {
    id: String,
    name: String,
    size: u64,
    partitions: Vec<Partition>,
}
#[derive(Clone, Debug)]
struct Container {
    id: String,
    bsd: String,
    stores: Vec<String>,
    total: u64,
    free: u64,
}
#[derive(Clone, Debug, Default)]
struct Snapshot {
    physical: Vec<Physical>,
    containers: Option<Vec<Container>>,
}
#[derive(Clone, Debug)]
struct Mount {
    bsd: String,
    used: u64,
    total: u64,
}
fn bsd(value: &str) -> bool {
    let Some(value) = value.strip_prefix("disk") else {
        return false;
    };
    let mut sections = value.split('s');
    sections.all(|part| !part.is_empty() && part.bytes().all(|v| v.is_ascii_digit()))
        && value.len() <= 60
}
fn bounded_size(value: &Value) -> Option<u64> {
    value.as_u64().filter(|v| *v > 0 && *v <= i64::MAX as u64)
}
fn parse(
    physical: &Value,
    apfs: Option<&Value>,
    mut identify: impl FnMut(&str, &[String]) -> (String, String),
) -> Option<Snapshot> {
    let rows = physical["AllDisksAndPartitions"].as_array()?;
    if rows.len() > 64 {
        return None;
    }
    let mut disks = Vec::new();
    let mut seen = HashSet::new();
    for row in rows {
        let name = row["DeviceIdentifier"].as_str().filter(|v| bsd(v))?;
        if !seen.insert(name.to_owned()) {
            return None;
        }
        let size = bounded_size(&row["Size"])?;
        let mut partitions = Vec::new();
        let mut uuids = Vec::new();
        if let Some(parts) = row["Partitions"].as_array() {
            if parts.len() > 128 {
                return None;
            }
            for part in parts {
                let key = part["DeviceIdentifier"].as_str().filter(|v| bsd(v))?;
                let content = part["Content"].as_str().unwrap_or_default();
                partitions.push(Partition {
                    bsd: key.into(),
                    size: bounded_size(&part["Size"])?,
                    apfs: content.starts_with("Apple_APFS"),
                });
                if let Some(uuid) = part["DiskUUID"]
                    .as_str()
                    .filter(|v| !v.is_empty() && v.len() <= 128)
                {
                    uuids.push(uuid.to_owned());
                }
            }
        } else if !row["Content"]
            .as_str()
            .unwrap_or_default()
            .ends_with("partition_scheme")
        {
            partitions.push(Partition {
                bsd: name.into(),
                size,
                apfs: row["Content"]
                    .as_str()
                    .unwrap_or_default()
                    .starts_with("Apple_APFS"),
            });
        }
        uuids.sort();
        let (id, display) = identify(name, &uuids);
        if id.is_empty() || id.len() > 256 || id.chars().any(char::is_control) {
            return None;
        }
        disks.push(Physical {
            id,
            name: super::integrated_gpu::label(&format!("{display} · {name}"), 120),
            size,
            partitions,
        });
    }
    let containers = apfs.and_then(|value| {
        let rows = value["Containers"].as_array()?;
        if rows.len() > 128 {
            return None;
        }
        rows.iter()
            .map(|row| {
                let stores = row["PhysicalStores"].as_array()?;
                if stores.is_empty() || stores.len() > 64 {
                    return None;
                }
                let stores = stores
                    .iter()
                    .map(|store| {
                        store["DeviceIdentifier"]
                            .as_str()
                            .filter(|v| bsd(v))
                            .map(str::to_owned)
                    })
                    .collect::<Option<Vec<_>>>()?;
                Some(Container {
                    id: row["APFSContainerUUID"]
                        .as_str()
                        .filter(|v| !v.is_empty() && v.len() <= 128)?
                        .to_owned(),
                    bsd: row["ContainerReference"]
                        .as_str()
                        .filter(|v| bsd(v))?
                        .into(),
                    stores,
                    total: bounded_size(&row["CapacityCeiling"])?,
                    free: row["CapacityFree"].as_u64()?,
                })
            })
            .collect::<Option<Vec<_>>>()
    });
    Some(Snapshot {
        physical: disks,
        containers,
    })
}
fn mounted_container(mount: &Mount, container: &str) -> bool {
    mount.bsd == container
        || mount
            .bsd
            .strip_prefix(container)
            .is_some_and(|rest| rest.starts_with('s') && bsd(&mount.bsd))
}
fn collect(snapshot: &Snapshot, mounts: Option<&[Mount]>) -> Vec<Disk> {
    let mut owner = HashMap::new();
    let mut duplicate_partition = HashSet::new();
    for (index, drive) in snapshot.physical.iter().enumerate() {
        for part in &drive.partitions {
            if let Some(previous) = owner.insert(part.bsd.as_str(), (index, part.size)) {
                duplicate_partition.insert(previous.0);
                duplicate_partition.insert(index);
            }
        }
    }
    let mut pools = BTreeMap::<String, &Container>::new();
    let mut inconsistent = false;
    if let Some(containers) = &snapshot.containers {
        for container in containers {
            if let Some(previous) = pools.insert(container.id.clone(), container) {
                if previous.bsd != container.bsd
                    || previous.stores != container.stores
                    || previous.total != container.total
                    || previous.free != container.free
                {
                    inconsistent = true;
                }
            }
        }
    }
    snapshot
        .physical
        .iter()
        .enumerate()
        .map(|(index, drive)| {
            let mut used = 0u64;
            let mut total = 0u64;
            let mut mounted = false;
            let mut uncertain = mounts.is_none()
                || drive.partitions.is_empty()
                || duplicate_partition.contains(&index)
                || inconsistent;
            let mut covered = HashSet::new();
            for container in pools.values() {
                let stores = container
                    .stores
                    .iter()
                    .map(|store| owner.get(store.as_str()).copied())
                    .collect::<Vec<_>>();
                if !stores.iter().flatten().any(|(owner, _)| *owner == index) {
                    continue;
                } // Disk-image pools are not physical allocations.
                if stores
                    .iter()
                    .any(|store| store.is_none_or(|(owner, _)| owner != index))
                {
                    uncertain = true;
                    continue;
                }
                let ceiling = stores
                    .iter()
                    .flatten()
                    .try_fold(0u64, |sum, (_, size)| sum.checked_add(*size));
                if container.free > container.total
                    || ceiling.is_none_or(|ceiling| container.total > ceiling)
                {
                    uncertain = true;
                    continue;
                }
                for store in &container.stores {
                    if !covered.insert(store.clone()) {
                        uncertain = true;
                    }
                }
                mounted |= mounts.is_some_and(|mounts| {
                    mounts
                        .iter()
                        .any(|mount| mounted_container(mount, &container.bsd))
                });
                used = used.saturating_add(container.total - container.free);
                total = total.saturating_add(container.total);
            }
            for part in &drive.partitions {
                if covered.contains(&part.bsd) {
                    continue;
                }
                if part.apfs {
                    uncertain = true;
                    continue;
                }
                let candidates = mounts
                    .into_iter()
                    .flatten()
                    .filter(|mount| mount.bsd == part.bsd)
                    .collect::<Vec<_>>();
                let Some(first) = candidates.first() else {
                    uncertain = true;
                    continue;
                };
                mounted = true;
                if first.total == 0
                    || first.used > first.total
                    || first.total > part.size
                    || candidates
                        .iter()
                        .any(|mount| mount.used != first.used || mount.total != first.total)
                {
                    uncertain = true;
                    continue;
                }
                used = used.saturating_add(first.used);
                total = total.saturating_add(first.total);
            }
            if !mounted || uncertain || total > drive.size || used > total {
                used = 0;
                total = 0;
            }
            Disk {
                id: drive.id.clone(),
                name: drive.name.clone(),
                used,
                total,
            }
        })
        .collect()
}
pub(super) fn aggregate(disks: &[Disk]) -> Memory {
    if disks.iter().any(|disk| disk.total == 0) {
        return Memory { used: 0, total: 0 };
    }
    let used = disks
        .iter()
        .try_fold(0u64, |sum, disk| sum.checked_add(disk.used));
    let total = disks
        .iter()
        .try_fold(0u64, |sum, disk| sum.checked_add(disk.total));
    match used
        .zip(total)
        .filter(|(u, t)| u <= t && *t <= i64::MAX as u64)
    {
        Some((used, total)) => Memory { used, total },
        None => Memory { used: 0, total: 0 },
    }
}
#[cfg(target_os = "macos")]
pub(super) struct Worker {
    receiver: tokio::sync::watch::Receiver<Option<(std::time::Instant, Snapshot)>>,
    task: tokio::task::JoinHandle<()>,
}
#[cfg(target_os = "macos")]
impl Drop for Worker {
    fn drop(&mut self) {
        self.task.abort();
    }
}
#[cfg(target_os = "macos")]
impl Worker {
    pub fn start(path: std::path::PathBuf, cancel: tokio_util::sync::CancellationToken) -> Self {
        let (sender, receiver) = tokio::sync::watch::channel(None);
        let task = tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut policy = crate::features::subscribe(&path);
            loop {
                let refresh = tokio::select! { _=cancel.cancelled()=>break, _=tick.tick()=>true, changed=policy.changed()=>{if changed.is_err(){break;}false} };
                if !crate::features::enabled(&path, crate::features::Feature::Metrics) {
                    let _ = sender.send(None);
                    continue;
                }
                if !refresh {
                    continue;
                }
                if let Ok(Some(snapshot)) = tokio::task::spawn_blocking(native::snapshot).await {
                    let _ = sender.send(Some((std::time::Instant::now(), snapshot)));
                }
            }
        });
        Self { receiver, task }
    }
    pub fn sample(&self) -> Vec<Disk> {
        let value = self.receiver.borrow();
        let Some((at, snapshot)) = value.as_ref() else {
            return Vec::new();
        };
        let mounts = (at.elapsed() <= std::time::Duration::from_secs(90))
            .then(native::mounts)
            .flatten();
        collect(snapshot, mounts.as_deref())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, Value) {
        (
            json!({"AllDisksAndPartitions":[{"DeviceIdentifier":"disk0","Size":1200,"Content":"GUID_partition_scheme","Partitions":[
            {"DeviceIdentifier":"disk0s1","DiskUUID":"partition-a","Size":1000,"Content":"Apple_APFS"},
            {"DeviceIdentifier":"disk0s2","DiskUUID":"partition-b","Size":100,"Content":"Apple_APFS_Recovery"}]}]}),
            json!({"Containers":[{"APFSContainerUUID":"pool-a","ContainerReference":"disk3","CapacityCeiling":1000,"CapacityFree":400,
            "PhysicalStores":[{"DeviceIdentifier":"disk0s1"}],"Volumes":[{"Name":"Data","CapacityQuota":30,"CapacityReserve":10,"CapacityInUse":20},{"Name":"Data","CapacityInUse":900}]},
            {"APFSContainerUUID":"pool-b","ContainerReference":"disk4","CapacityCeiling":100,"CapacityFree":90,"PhysicalStores":[{"DeviceIdentifier":"disk0s2"}]}]}),
        )
    }
    fn snapshot(physical: &Value, apfs: Option<&Value>) -> Snapshot {
        parse(physical, apfs, |_, ids| {
            (
                format!("native:{}", ids.join(":")),
                "Identical label".into(),
            )
        })
        .unwrap()
    }
    #[test]
    fn apfs_quotas_snapshots_and_multiple_volumes_do_not_duplicate_container_capacity() {
        let (physical, apfs) = fixture();
        let data = snapshot(&physical, Some(&apfs));
        let mounts = [
            Mount {
                bsd: "disk3s1s1".into(),
                used: 1,
                total: 30,
            },
            Mount {
                bsd: "disk3s5".into(),
                used: 20,
                total: 1000,
            },
        ];
        let disks = collect(&data, Some(&mounts));
        assert_eq!(disks.len(), 1);
        assert_eq!((disks[0].used, disks[0].total), (610, 1100));
        assert_eq!(aggregate(&disks).total, 1100);
        assert!(mounted_container(&mounts[0], "disk3"));
        assert!(!mounted_container(
            &Mount {
                bsd: "disk30s1".into(),
                used: 0,
                total: 1
            },
            "disk3"
        ));
    }
    #[test]
    fn equal_named_distinct_physical_drives_survive_and_mount_aliases_deduplicate() {
        let physical = json!({"AllDisksAndPartitions":[
            {"DeviceIdentifier":"disk1","Size":100,"Partitions":[{"DeviceIdentifier":"disk1s1","Size":100,"DiskUUID":"uuid-one","Content":"Windows_NTFS"}]},
            {"DeviceIdentifier":"disk2","Size":100,"Partitions":[{"DeviceIdentifier":"disk2s1","Size":100,"DiskUUID":"uuid-two","Content":"Windows_NTFS"}]}]});
        let data = snapshot(&physical, None);
        let mounts = [
            Mount {
                bsd: "disk1s1".into(),
                used: 20,
                total: 100,
            },
            Mount {
                bsd: "disk1s1".into(),
                used: 20,
                total: 100,
            },
            Mount {
                bsd: "disk2s1".into(),
                used: 40,
                total: 100,
            },
        ];
        let disks = collect(&data, Some(&mounts));
        assert_eq!(disks.len(), 2);
        assert_ne!(disks[0].id, disks[1].id);
        assert_ne!(disks[0].name, disks[1].name);
        assert_eq!((aggregate(&disks).used, aggregate(&disks).total), (60, 200));
    }
    #[test]
    fn missing_unknown_unmounted_removed_and_invalid_metadata_are_not_zero_usage() {
        let (physical, mut apfs) = fixture();
        let data = snapshot(&physical, Some(&apfs));
        let unmounted = collect(&data, Some(&[]));
        assert_eq!(unmounted[0].total, 0);
        assert_eq!(aggregate(&unmounted).total, 0);
        assert_eq!(collect(&data, None)[0].total, 0);
        let mounts = [Mount {
            bsd: "disk3s5".into(),
            used: 20,
            total: 1000,
        }];
        assert_eq!(
            collect(&snapshot(&physical, None), Some(&mounts))[0].total,
            0
        );
        apfs["Containers"][0]["CapacityFree"] = json!(1001);
        assert_eq!(
            collect(&snapshot(&physical, Some(&apfs)), Some(&mounts))[0].total,
            0
        );
        assert!(
            collect(&Snapshot::default(), Some(&mounts)).is_empty(),
            "A removed drive does not retain live usage"
        );
        let sample:porthub_components::metrics::Sample=serde_json::from_value(json!({"cpu":12,"cores":8,"ram":{"used":4,"total":8},"disk":{"used":0,"total":0},"disks":unmounted,"gpus":[]})).unwrap();
        assert!(
            sample.valid(),
            "Unavailable optional storage preserves CPU/RAM reporting"
        );
    }
    #[test]
    fn fusion_or_unmapped_physical_stores_never_guess_per_drive_usage() {
        let (mut physical, mut apfs) = fixture();
        physical["AllDisksAndPartitions"].as_array_mut().unwrap().push(json!({"DeviceIdentifier":"disk1","Size":1000,"Partitions":[{"DeviceIdentifier":"disk1s1","DiskUUID":"partition-c","Size":1000,"Content":"Apple_APFS"}]}));
        apfs["Containers"][0]["PhysicalStores"]
            .as_array_mut()
            .unwrap()
            .push(json!({"DeviceIdentifier":"disk1s1"}));
        let mounts = [Mount {
            bsd: "disk3s1".into(),
            used: 500,
            total: 1000,
        }];
        assert!(collect(&snapshot(&physical, Some(&apfs)), Some(&mounts))
            .iter()
            .all(|disk| disk.total == 0));
    }
    #[test]
    fn duplicate_pool_rows_do_not_double_count_and_unknown_partitions_stay_unavailable() {
        let (mut physical, mut apfs) = fixture();
        let duplicate = apfs["Containers"][0].clone();
        apfs["Containers"].as_array_mut().unwrap().push(duplicate);
        let mounts = [Mount {
            bsd: "disk3s5".into(),
            used: 500,
            total: 1000,
        }];
        assert_eq!(
            collect(&snapshot(&physical, Some(&apfs)), Some(&mounts))[0].total,
            1100
        );
        physical["AllDisksAndPartitions"][0]["Partitions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"DeviceIdentifier":"disk0s3","Size":10,"Content":"EFI"}));
        assert_eq!(
            collect(&snapshot(&physical, Some(&apfs)), Some(&mounts))[0].total,
            0
        );
    }
}
