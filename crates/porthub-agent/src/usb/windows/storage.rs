//! Explicit local preparation of removable USB storage. No server request can
//! reach these operations. Every volume is locked before any is dismounted.
use super::*;
use std::io;
const LOCK: u32 = 0x90018;
const UNLOCK: u32 = 0x9001c;
const DISMOUNT: u32 = 0x90020;
const OFFLINE: u32 = 0x56c00c;
const ONLINE: u32 = 0x56c008;
const IS_OFFLINE: u32 = 0x560010;
#[path = "storage/state.rs"]
mod state;
use state::{DiskIdentity, Journal, Volume};
fn control(file: &File, code: u32) -> Result<()> {
    ensure!(
        query_metadata(file, code, &mut []).is_some(),
        "Native volume operation {code:#x} failed: {}",
        io::Error::last_os_error()
    );
    Ok(())
}
fn open_access(path: &str, access: u32, share: u32) -> Result<File> {
    let p: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            access,
            share,
            std::ptr::null(),
            3,
            0,
            std::ptr::null_mut(),
        )
    };
    ensure!(
        h != INVALID_HANDLE_VALUE,
        "Cannot exclusively prepare volume; close applications using it: {}",
        io::Error::last_os_error()
    );
    Ok(unsafe { File::from_raw_handle(h) })
}
fn open_rw(path: &str) -> Result<File> {
    open_access(path, 0xc0000000, 3)
}
fn ioctl_input(file: &File, code: u32, input: &[u8], out: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            out.as_mut_ptr().cast(),
            out.len() as u32,
            &mut n,
            std::ptr::null_mut(),
        )
    };
    ensure!(
        ok != 0 && n as usize <= out.len(),
        "Cannot verify storage identity: {}",
        io::Error::last_os_error()
    );
    Ok(n as usize)
}
fn disk_identity(instance: &str, number: u32) -> Result<DiskIdentity> {
    let f = open_access(&format!("\\\\.\\PhysicalDrive{number}"), 0x80000000, 7)?;
    let mut data = vec![0u8; 65536];
    let n = ioctl_input(&f, 0x2d1400, &[0; 12], &mut data)?;
    ensure!(
        n >= 36 && u32::from_le_bytes(data[28..32].try_into()?) == 7,
        "Only directly attached USB disks can be prepared"
    );
    let off = u32::from_le_bytes(data[24..28].try_into()?) as usize;
    ensure!(
        off >= 36 && off < n,
        "USB disk has no stable native serial identity"
    );
    let end = data[off..n]
        .iter()
        .position(|b| *b == 0)
        .context("Invalid disk serial")?
        + off;
    let serial = std::str::from_utf8(&data[off..end])?.trim().to_owned();
    ensure!(!serial.is_empty(), "USB disk has no stable serial");
    let mut size = [0; 8];
    let n = query_metadata(&f, 0x7405c, &mut size).context("Cannot verify disk size")?;
    ensure!(n == 8, "Incomplete disk size");
    let bytes = u64::from_le_bytes(size);
    ensure!(bytes > 0 && bytes <= i64::MAX as u64, "Invalid disk size");
    Ok(DiskIdentity {
        instance: instance.into(),
        serial,
        bytes,
    })
}
fn selected(busid: &str) -> Result<(DiskIdentity, u32)> {
    let state = host_state()?;
    let rows = state["Devices"]
        .as_array()
        .context("USB inventory unavailable")?;
    let row = rows
        .iter()
        .find(|r| r["BusId"] == busid)
        .context("USB device not present; refresh porthub usb devices")?;
    ensure!(
        row["ClientIPAddress"].is_null(),
        "Stop the active USB forward before preparing or restoring storage"
    );
    let instance = row["InstanceId"]
        .as_str()
        .context("USB instance unavailable")?;
    let disks = disk_ancestry().context("Cannot verify complete physical disk ancestry")?;
    let selected: Vec<_> = disks
        .iter()
        .filter(|d| d.ancestors.iter().any(|s| s.eq_ignore_ascii_case(instance)))
        .collect();
    ensure!(
        selected.len() == 1,
        "Preparation requires exactly one physical USB disk; multi-LUN devices are not supported"
    );
    let d = selected[0];
    ensure!(!d.indirect&&!d.offline,"Disk must be directly attached and online; already offline disks need no volume preparation");
    let number = d.number.context("USB disk number unknown")?;
    Ok((disk_identity(instance, number)?, number))
}
fn ranges(file: &File, number: u32) -> Result<Option<Vec<(i64, i64)>>> {
    let mut buf = vec![0; 8 + 256 * 24];
    let n = query_metadata(file, 0x560000, &mut buf)
        .context("Cannot verify complete volume extent map")?;
    let numbers = extent_numbers(&buf[..n]).context("Invalid volume extent map")?;
    if !numbers.contains(&number) {
        return Ok(None);
    }
    ensure!(
        numbers == [number],
        "Spanned/shared disk volumes cannot be prepared"
    );
    let count = u32::from_le_bytes(buf[..4].try_into()?) as usize;
    Ok(Some(
        (0..count)
            .map(|i| {
                let o = 8 + i * 24;
                (
                    i64::from_le_bytes(buf[o + 8..o + 16].try_into().unwrap()),
                    i64::from_le_bytes(buf[o + 16..o + 24].try_into().unwrap()),
                )
            })
            .collect(),
    ))
}
fn volumes(number: u32) -> Result<Vec<Volume>> {
    unsafe {
        let mut name = [0u16; 1024];
        let h = FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32);
        ensure!(h != INVALID_HANDLE_VALUE, "Cannot enumerate all volumes");
        struct Guard(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for Guard {
            fn drop(&mut self) {
                unsafe {
                    FindVolumeClose(self.0);
                }
            }
        }
        let _guard = Guard(h);
        let mut result = Vec::new();
        for _ in 0..256 {
            let n = name
                .iter()
                .position(|v| *v == 0)
                .context("Invalid native volume name")?;
            let path = String::from_utf16(&name[..n])?
                .trim_end_matches('\\')
                .to_owned();
            if !matches!(GetDriveTypeW(name.as_ptr()), 4 | 5 | 6) {
                let f = metadata_volume(&path)?;
                if let Some(ranges) = ranges(&f, number)? {
                    ensure!(
                        query_metadata(&f, IS_OFFLINE, &mut []).is_none(),
                        "Volume is already offline; its existing state will not be claimed"
                    );
                    result.push(Volume {
                        path,
                        ranges,
                        changed: false,
                    });
                }
            }
            name.fill(0);
            if FindNextVolumeW(h, name.as_mut_ptr(), name.len() as u32) == 0 {
                ensure!(
                    io::Error::last_os_error().raw_os_error() == Some(18),
                    "Volume enumeration incomplete"
                );
                ensure!(!result.is_empty(), "No eligible USB storage volumes found");
                return Ok(result);
            }
        }
        anyhow::bail!("Too many volumes to verify safely")
    }
}
fn journal_path(busid: &str) -> Result<PathBuf> {
    let root =
        PathBuf::from(std::env::var_os("ProgramData").context("Shared Windows state unavailable")?)
            .join("PortHub/usb-prepared");
    crate::service::directory(&root, true)?;
    Ok(root.join(format!("{busid}.json")))
}
fn save(path: &Path, journal: &Journal, replace: bool) -> Result<()> {
    crate::profile::write_private(path, &serde_json::to_vec(journal)?, replace)
}
fn restore_journal(path: &Path, j: &Journal, identity: &DiskIdentity, number: u32) -> Result<()> {
    state::validate(j)?;
    ensure!(
        j.version == 1 && j.disk == *identity && !j.volumes.is_empty() && j.volumes.len() <= 256,
        "Prepared USB identity changed; refusing restoration"
    );
    // Validate every identity and extent before bringing any volume online.
    let mut handles = Vec::new();
    for v in &j.volumes {
        ensure!(
            state::valid_volume_path(&v.path),
            "Invalid prepared volume identity"
        );
        let f = open_rw(&v.path)?;
        ensure!(
            ranges(&f, number)?.as_ref() == Some(&v.ranges),
            "Prepared volume extents changed; refusing restoration"
        );
        handles.push(f);
    }
    for (v, f) in j.volumes.iter().zip(&handles) {
        if v.changed {
            control(f, ONLINE)?;
        }
    }
    drop(handles);
    std::fs::remove_file(path)?;
    Ok(())
}
/// Explicit local-only operation. Acquires the same device lease as capture.
pub(crate) fn run(busid: &str, restore: bool) -> Result<()> {
    crate::service::require_administrator()?;
    ensure!(
        porthub_components::usb::valid_busid(busid),
        "Use a valid USB bus ID from porthub usb devices"
    );
    let _lease = source_lease(busid)?;
    let path = journal_path(busid)?;
    let (identity, number) = selected(busid)?;
    if restore {
        let bytes = crate::profile::read_private(&path)
            .context("No PortHub preparation journal for this device")?;
        let j: Journal = serde_json::from_slice(&bytes)?;
        ensure!(j.busid == busid, "Prepared bus identity mismatch");
        restore_journal(&path, &j, &identity, number)?;
        println!("Restored USB {busid}; its volumes are online.");
        return Ok(());
    }
    ensure!(
        !path.try_exists()?,
        "Storage preparation already exists; run porthub usb restore {busid} first"
    );
    let mut j = Journal {
        version: 1,
        busid: busid.into(),
        disk: identity,
        volumes: volumes(number)?,
    };
    state::validate(&j)?;
    let mut handles = Vec::new();
    for v in &j.volumes {
        handles.push(open_rw(&v.path)?);
    }
    // Filesystem FSCTLs require a filesystem-capable handle. Access-zero
    // metadata handles can prove native extents/offline state but do not reach
    // the mounted filesystem on Windows.
    for file in &handles {
        control(file, 0x90028)
            .context("Cannot positively verify the original mounted volume state")?;
    }
    // No dismount/offline operation occurs unless every lock succeeds. Native lock
    // refuses system/pagefile volumes and open files, and flushes cached writes.
    state::lock_all(handles.len(), |index, acquire| {
        control(&handles[index], if acquire { LOCK } else { UNLOCK })
    })?;
    let mut journal_owned = false;
    let result = (|| -> Result<()> {
        save(&path, &j, false)?;
        journal_owned = true;
        // Recheck physical identity after locks and before changing mount state.
        ensure!(
            disk_identity(&j.disk.instance, number)? == j.disk,
            "USB disk identity changed during preparation"
        );
        // Volume GUIDs and disk numbers are locators, not identities. Recheck
        // the complete set after obtaining all locks, then each held handle.
        let fresh = volumes(number)?;
        ensure!(
            fresh.len() == j.volumes.len()
                && fresh.iter().all(|v| {
                    j.volumes
                        .iter()
                        .any(|old| old.path.eq_ignore_ascii_case(&v.path) && old.ranges == v.ranges)
                }),
            "USB volume topology changed while obtaining locks"
        );
        for (v, f) in j.volumes.iter().zip(&handles) {
            ensure!(
                ranges(f, number)?.as_ref() == Some(&v.ranges),
                "Locked USB volume extents changed; refusing preparation"
            );
        }
        for (i, f) in handles.iter().enumerate() {
            control(f, DISMOUNT)?;
            // Persist intent while holding the lock, so a crash before/after OFFLINE can
            // be recovered without touching any volume that was originally offline.
            j.volumes[i].changed = true;
            save(&path, &j, true)?;
            control(f, OFFLINE)?;
            control(f, IS_OFFLINE)?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut failures = Vec::new();
        for (v, f) in j.volumes.iter().zip(&handles) {
            if v.changed {
                if let Err(e) = control(f, ONLINE) {
                    failures.push(e.to_string())
                }
            }
        }
        for f in &handles {
            let _ = control(f, UNLOCK);
        }
        drop(handles);
        if failures.is_empty() {
            if journal_owned && path.try_exists()? {
                std::fs::remove_file(&path)?;
            }
            return Err(error);
        }
        anyhow::bail!("{error}; rollback incomplete: {}; preserve journal and run porthub usb restore {busid}",failures.join("; "))
    }
    for f in &handles {
        control(f, UNLOCK)?;
    }
    drop(handles);
    println!("Prepared USB {busid}. Volumes are safely offline; forwarding is now allowed. After stopping forwarding, run: porthub usb restore {busid}");
    Ok(())
}
