//! Windows disk names are volume labels, which may be blank or duplicated.
//! Report/deduplicate volumes by native GUID, with a nonempty mount-path fallback.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub key: std::ffi::OsString,
    pub id: String,
    pub name: String,
}
#[cfg(any(windows, test))]
fn windows_identity(label: &str, mount: &str, guid: Option<&str>) -> Option<Identity> {
    let mount = mount.trim().replace('/', "\\");
    if mount.is_empty() || mount.chars().any(char::is_control) {
        return None;
    }
    let guid = guid.filter(|value| !value.is_empty() && !value.chars().any(char::is_control));
    let id = if let Some(guid) = guid {
        format!("windows-volume:{}", guid.to_lowercase())
    } else {
        format!("windows-mount:{}", mount.to_lowercase())
    };
    // Never truncate an identity: different long mount paths must not collide.
    if id.len() > 256 {
        return None;
    }
    let label = label.trim();
    let name = if label.is_empty() {
        mount
    } else {
        format!("{mount} · {label}")
    };
    Some(Identity {
        key: std::ffi::OsString::from(&id),
        id,
        name: super::integrated_gpu::label(&name, 120),
    })
}
#[cfg(windows)]
pub(super) fn collect(disk: &sysinfo::Disk) -> Option<Identity> {
    use std::os::windows::ffi::OsStrExt;
    let mount = disk.mount_point();
    let mut path = mount.as_os_str().encode_wide().collect::<Vec<_>>();
    if path.last() != Some(&(b'\\' as u16)) {
        path.push(b'\\' as u16);
    }
    path.push(0);
    let mut guid = [0u16; 128];
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW(
            path.as_ptr(),
            guid.as_mut_ptr(),
            guid.len() as u32,
        )
    };
    let guid = if ok != 0 {
        guid.iter()
            .position(|v| *v == 0)
            .and_then(|len| String::from_utf16(&guid[..len]).ok())
    } else {
        None
    };
    windows_identity(
        &disk.name().to_string_lossy(),
        &mount.to_string_lossy(),
        guid.as_deref(),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_windows_volume_label_preserves_identity_and_mount_display() {
        let disk = windows_identity("", "C:\\", Some("\\\\?\\Volume{abc}\\")).unwrap();
        assert!(!disk.id.is_empty());
        assert_eq!(disk.name, "C:\\");
        assert_eq!(disk.id, "windows-volume:\\\\?\\volume{abc}\\");
        let sample: porthub_components::metrics::Sample =
            serde_json::from_value(serde_json::json!({
                "cpu": 12, "cores": 8, "ram": {"used": 4, "total": 16},
                "disk": {"used": 40, "total": 100}, "gpus": [],
                "disks": [{"id": disk.id, "name": disk.name, "used": 40, "total": 100}],
            }))
            .unwrap();
        assert!(
            sample.valid(),
            "An empty C: volume label must not suppress the whole metrics report"
        );
    }
    #[test]
    fn equal_labels_are_distinct_but_multiple_mounts_of_one_volume_deduplicate() {
        let first = windows_identity("Data", "C:\\", Some("volume-a")).unwrap();
        let second = windows_identity("Data", "D:\\", Some("volume-b")).unwrap();
        let alias = windows_identity("Data", "C:\\mount\\", Some("VOLUME-A")).unwrap();
        assert_ne!(first.key, second.key);
        assert_ne!(first.name, second.name);
        assert_eq!(first.key, alias.key);
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(first.key));
        assert!(seen.insert(second.key));
        assert!(!seen.insert(alias.key));
    }
    #[test]
    fn guid_failure_uses_normalized_mount_and_invalid_optional_identity_is_skipped() {
        let mount = windows_identity("", "C:/", None).unwrap();
        assert_eq!(mount.key, windows_identity("", "c:\\", None).unwrap().key);
        assert_ne!(mount.key, windows_identity("", "D:\\", None).unwrap().key);
        assert!(windows_identity("Label", "", None).is_none());
        assert!(windows_identity("Label", "C:\\bad\npath", None).is_none());
        assert!(windows_identity("Label", &"a".repeat(300), None).is_none());
    }
}
