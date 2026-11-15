//! Windows kernel adapters. PortHub owns authorization, transport and lifecycle;
//! the signed USB/IP host/UDE drivers provide the OS device handoff.
use anyhow::{ensure, Context, Result};
use porthub_components::usb::Device;
use serde_json::Value;
use std::{
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use windows_sys::{
    core::GUID,
    Win32::{
        Devices::DeviceAndDriverInstallation::{
            CM_Get_Device_IDW, CM_Get_Parent, CM_Locate_DevNodeW, SetupDiDestroyDeviceInfoList,
            SetupDiEnumDeviceInterfaces, SetupDiGetClassDevsW, SetupDiGetDeviceInterfaceDetailW,
            DIGCF_DEVICEINTERFACE, DIGCF_PRESENT, HDEVINFO, SP_DEVICE_INTERFACE_DATA,
            SP_DEVINFO_DATA,
        },
        Foundation::INVALID_HANDLE_VALUE,
        Storage::FileSystem::{
            CreateFileW, FindFirstVolumeW, FindNextVolumeW, FindVolumeClose, GetDriveTypeW,
        },
        System::IO::DeviceIoControl,
    },
};
const INTERFACE: GUID = GUID::from_u128(0xb4030c06_dc5f_4fcc_87eb_e5515a0935c0);
fn host() -> Result<PathBuf> {
    let root = std::env::var_os("ProgramFiles").context("Windows ProgramFiles unavailable")?;
    Ok(PathBuf::from(root).join("usbipd-win/usbipd.exe"))
}
fn host_output(args: &[&str]) -> Result<std::process::Output> {
    use std::{io::Read, process::Stdio};
    let mut child = std::process::Command::new(host()?)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .context("USB helper output unavailable")?;
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout
            .by_ref()
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes);
        let _ = tx.send((result, bytes));
    });
    let until = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Windows USB helper timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let (result, stdout) = rx
        .recv_timeout(Duration::from_secs(1))
        .context("USB helper output timed out")?;
    result?;
    ensure!(
        stdout.len() <= 1024 * 1024,
        "USB helper output exceeds limit"
    );
    Ok(std::process::Output {
        status,
        stdout,
        stderr: Vec::new(),
    })
}
fn host_state() -> Result<Value> {
    let out = host_output(&["state"])?;
    ensure!(
        out.status.success(),
        "Windows USB driver inventory unavailable"
    );
    Ok(serde_json::from_slice(&out.stdout)?)
}
async fn host_command(args: &[&str]) -> Result<()> {
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(host()?)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "Windows USB driver operation failed: {}",
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(512)
            .collect::<String>()
    );
    Ok(())
}
fn metadata_volume(path: &str) -> Result<File> {
    let path: Vec<u16> = std::ffi::OsStr::new(path)
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        // IOCTL_STORAGE_QUERY_PROPERTY is FILE_ANY_ACCESS. Do not request data
        // read access to locked/recovery volumes just to inspect their bus type.
        let handle = CreateFileW(
            path.as_ptr(),
            0,
            7,
            std::ptr::null(),
            3,
            0,
            std::ptr::null_mut(),
        );
        ensure!(
            handle != INVALID_HANDLE_VALUE,
            "Cannot open volume metadata: {}",
            std::io::Error::last_os_error()
        );
        Ok(File::from_raw_handle(handle))
    }
}
fn online_usb_storage() -> Option<bool> {
    // Enumerate every volume, including volumes mounted in directories without
    // drive letters. Native query failures never grant storage capture.
    unsafe {
        let mut name = [0u16; 1024];
        let handle = FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32);
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        struct Volumes(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for Volumes {
            fn drop(&mut self) {
                unsafe {
                    FindVolumeClose(self.0);
                }
            }
        }
        let _guard = Volumes(handle);
        let mut uncertain = false;
        for _ in 0..256 {
            match GetDriveTypeW(name.as_ptr()) {
                2 | 3 => {
                    let length = name.iter().position(|c| *c == 0).unwrap_or(name.len());
                    let path = String::from_utf16_lossy(&name[..length])
                        .trim_end_matches('\\')
                        .to_owned();
                    match metadata_volume(&path) {
                        Ok(volume) => {
                            let mut query = [0u32; 3];
                            let mut result = [0u8; 1024];
                            let mut returned = 0;
                            let ok = DeviceIoControl(
                                volume.as_raw_handle(),
                                0x002d1400,
                                query.as_mut_ptr().cast(),
                                12,
                                result.as_mut_ptr().cast(),
                                result.len() as u32,
                                &mut returned,
                                std::ptr::null_mut(),
                            );
                            if ok == 0 || returned < 36 {
                                uncertain = true;
                            } else {
                                let bus = u32::from_le_bytes(result[28..32].try_into().unwrap());
                                if bus == 7 {
                                    return Some(true);
                                }
                                if bus == 0 || bus == 16 {
                                    uncertain = true;
                                }
                            }
                        }
                        Err(_) => uncertain = true,
                    }
                }
                0 => uncertain = true,
                _ => {}
            }
            name.fill(0);
            if FindNextVolumeW(handle, name.as_mut_ptr(), name.len() as u32) == 0 {
                return if std::io::Error::last_os_error().raw_os_error() == Some(18) && !uncertain {
                    Some(false)
                } else {
                    None
                };
            }
        }
        None
    }
}

#[derive(Clone, Debug)]
struct DiskNode {
    ancestors: Vec<String>,
    number: Option<u32>,
    offline: bool,
    indirect: bool,
}
#[derive(Clone, Debug)]
struct VolumeState {
    disks: Option<Vec<u32>>,
    offline: bool,
    // A false FSCTL result may mean another application's lock or an error.
    // Only true is positive mount evidence; false never grants capture.
    mounted: bool,
}
fn query_metadata(file: &File, code: u32, output: &mut [u8]) -> Option<usize> {
    let mut returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            std::ptr::null(),
            0,
            if output.is_empty() {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            },
            output.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    (ok != 0 && returned as usize <= output.len()).then_some(returned as usize)
}
fn disk_metadata(path: &str) -> (Option<u32>, bool, bool) {
    let Ok(file) = metadata_volume(path) else {
        return (None, false, true);
    };
    let mut number = [0u8; 12];
    let number = query_metadata(&file, 0x002d1080, &mut number)
        .filter(|n| *n >= 12)
        .filter(|_| u32::from_le_bytes(number[..4].try_into().unwrap()) == 7)
        .map(|_| u32::from_le_bytes(number[4..8].try_into().unwrap()));
    let mut attributes = [0u8; 16];
    attributes[..4].copy_from_slice(&16u32.to_le_bytes());
    let offline = query_metadata(&file, 0x000700f0, &mut attributes).is_some_and(|n| {
        n >= 16
            && u32::from_le_bytes(attributes[..4].try_into().unwrap()) == 16
            && u64::from_le_bytes(attributes[8..16].try_into().unwrap()) & 1 != 0
    });
    let query = [0u32; 3];
    let mut descriptor = [0u8; 1024];
    let mut returned = 0;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x002d1400,
            query.as_ptr().cast(),
            12,
            descriptor.as_mut_ptr().cast(),
            descriptor.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let bus = (ok != 0 && returned >= 36 && returned as usize <= descriptor.len())
        .then(|| u32::from_le_bytes(descriptor[28..32].try_into().unwrap()));
    (number, offline, indirect_storage_bus(bus))
}
fn indirect_storage_bus(bus: Option<u32>) -> bool {
    // SCSI/RAID can also represent virtual storage. With Spaces, VHDs or an
    // unknown bus, physical extents alone cannot exclude an indirect backing
    // file/pool relationship. Affirmative disk OFFLINE still proves safety.
    !matches!(bus, Some(2 | 3 | 4 | 7 | 10 | 11 | 12 | 13 | 17 | 18 | 19))
}
#[repr(C)]
struct DiskExtent {
    number: u32,
    offset: i64,
    length: i64,
}
#[repr(C)]
struct DiskExtents {
    count: u32,
    extents: [DiskExtent; 1],
}
fn extent_numbers(bytes: &[u8]) -> Option<Vec<u32>> {
    let count = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    if !(1..=256).contains(&count) {
        return None;
    }
    let start = std::mem::offset_of!(DiskExtents, extents);
    let stride = std::mem::size_of::<DiskExtent>();
    if bytes.len() < start.checked_add(count.checked_mul(stride)?)? {
        return None;
    }
    let mut numbers = Vec::new();
    for index in 0..count {
        let offset = start + index * stride;
        let number = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?);
        let start = i64::from_le_bytes(bytes[offset + 8..offset + 16].try_into().ok()?);
        let length = i64::from_le_bytes(bytes[offset + 16..offset + 24].try_into().ok()?);
        if number == u32::MAX || start < 0 || length <= 0 {
            return None;
        }
        if !numbers.contains(&number) {
            numbers.push(number);
        }
    }
    Some(numbers)
}
fn volume_states() -> Option<Vec<VolumeState>> {
    unsafe {
        let mut name = [0u16; 1024];
        let handle = FindFirstVolumeW(name.as_mut_ptr(), name.len() as u32);
        if handle == INVALID_HANDLE_VALUE {
            return None;
        }
        struct Volumes(windows_sys::Win32::Foundation::HANDLE);
        impl Drop for Volumes {
            fn drop(&mut self) {
                unsafe {
                    FindVolumeClose(self.0);
                }
            }
        }
        let _guard = Volumes(handle);
        let mut rows = Vec::new();
        for _ in 0..256 {
            let length = name.iter().position(|c| *c == 0)?;
            let path = String::from_utf16(&name[..length])
                .ok()?
                .trim_end_matches('\\')
                .to_owned();
            // Volume GUIDs can include optical/network filesystems that cannot
            // be USB disk descendants. Unknown/local volume types remain gated.
            if !matches!(GetDriveTypeW(name.as_ptr()), 4 | 5 | 6) {
                let state = match metadata_volume(&path) {
                    Ok(file) => {
                        let mut extents = vec![
                            0u8;
                            std::mem::offset_of!(DiskExtents, extents)
                                + 256 * std::mem::size_of::<DiskExtent>()
                        ];
                        let disks = query_metadata(&file, 0x00560000, &mut extents)
                            .and_then(|n| extent_numbers(&extents[..n]));
                        let offline = query_metadata(&file, 0x00560010, &mut []).is_some();
                        let mounted = query_metadata(&file, 0x00090028, &mut []).is_some();
                        VolumeState {
                            disks,
                            offline,
                            mounted,
                        }
                    }
                    Err(_) => VolumeState {
                        disks: None,
                        offline: false,
                        mounted: false,
                    },
                };
                rows.push(state);
            }
            name.fill(0);
            if FindNextVolumeW(handle, name.as_mut_ptr(), name.len() as u32) == 0 {
                return (std::io::Error::last_os_error().raw_os_error() == Some(18))
                    .then_some(rows);
            }
        }
        None
    }
}
fn selected_storage_online(
    instance: &str,
    disks: Option<&[DiskNode]>,
    volumes: Option<&[VolumeState]>,
) -> Option<bool> {
    if instance.is_empty() {
        return None;
    }
    let disks = disks?;
    let selected = disks
        .iter()
        .filter(|disk| {
            disk.ancestors
                .iter()
                .any(|node| node.eq_ignore_ascii_case(instance))
        })
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Some(false);
    }
    // Disk-level OFFLINE is affirmative OS evidence, even when its inaccessible
    // offline volumes cannot be opened. No operation here changes disk state.
    if selected.iter().all(|disk| disk.offline) {
        return Some(false);
    }
    let numbers = selected
        .iter()
        .filter(|disk| !disk.offline)
        .map(|disk| disk.number)
        .collect::<Option<Vec<_>>>()?;
    let mut uncertain = disks.iter().any(|disk| disk.indirect);
    for volume in volumes? {
        let Some(extents) = &volume.disks else {
            uncertain = true;
            continue;
        };
        if extents.is_empty() {
            uncertain = true;
            continue;
        }
        if !extents.iter().any(|number| numbers.contains(number)) {
            continue;
        }
        if volume.mounted {
            return Some(true);
        }
        if !volume.offline {
            uncertain = true;
        }
    }
    // A complete extent map with no matching volume also proves there is no
    // mounted Windows filesystem on an unformatted/foreign-filesystem disk.
    (!uncertain).then_some(false)
}

// Complete native disk ancestry proves that a vendor/composite USB device is
// unrelated to every present disk, even when its function driver is missing.
// Any uncertain enumeration falls back to the existing mounted-storage guard.
fn disk_ancestry() -> Option<Vec<DiskNode>> {
    const DISK: GUID = GUID::from_u128(0x53f56307_b6bf_11d0_94f2_00a0c91efb8b);
    unsafe {
        let mut root = 0;
        if CM_Locate_DevNodeW(&mut root, std::ptr::null(), 0) != 0 {
            return None;
        }
        let set = SetupDiGetClassDevsW(
            &DISK,
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        if set as isize == -1 {
            return None;
        }
        struct List(HDEVINFO);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe {
                    SetupDiDestroyDeviceInfoList(self.0);
                }
            }
        }
        let list = List(set);
        let mut rows = Vec::new();
        for index in 0..256 {
            let mut interface: SP_DEVICE_INTERFACE_DATA = std::mem::zeroed();
            interface.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
            if SetupDiEnumDeviceInterfaces(list.0, std::ptr::null(), &DISK, index, &mut interface)
                == 0
            {
                return (std::io::Error::last_os_error().raw_os_error() == Some(259))
                    .then_some(rows);
            }
            let mut required = 0;
            SetupDiGetDeviceInterfaceDetailW(
                list.0,
                &interface,
                std::ptr::null_mut(),
                0,
                &mut required,
                std::ptr::null_mut(),
            );
            if !(8..=32768).contains(&required) {
                return None;
            }
            let mut buffer = vec![0u64; (required as usize + 7) / 8];
            // SP_DEVICE_INTERFACE_DETAIL_DATA_W has a pointer-aligned size on
            // x64/ARM64, and a packed six-byte header on 32-bit Windows.
            *(buffer.as_mut_ptr() as *mut u32) = if cfg!(target_pointer_width = "64") {
                8
            } else {
                6
            };
            let mut device: SP_DEVINFO_DATA = std::mem::zeroed();
            device.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
            if SetupDiGetDeviceInterfaceDetailW(
                list.0,
                &interface,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
                &mut device,
            ) == 0
            {
                return None;
            }
            let mut node = device.DevInst;
            let mut chain = Vec::new();
            let mut complete = false;
            for _ in 0..64 {
                if node == root {
                    complete = true;
                    break;
                }
                let mut id = [0u16; 512];
                if CM_Get_Device_IDW(node, id.as_mut_ptr(), id.len() as u32, 0) != 0 {
                    return None;
                }
                let length = id.iter().position(|v| *v == 0)?;
                let id = String::from_utf16(&id[..length]).ok()?;
                if id.is_empty() || chain.iter().any(|previous| previous == &id) {
                    return None;
                }
                chain.push(id);
                let mut parent = 0;
                if CM_Get_Parent(&mut parent, node, 0) != 0 || parent == node {
                    return None;
                }
                node = parent;
            }
            if !complete {
                return None;
            }
            if required as usize > buffer.len() * 8 {
                return None;
            }
            let raw = std::slice::from_raw_parts(
                (buffer.as_ptr() as *const u8).add(4).cast::<u16>(),
                (required as usize - 4) / 2,
            );
            let path_len = raw.iter().position(|v| *v == 0)?;
            let path = String::from_utf16(&raw[..path_len]).ok()?;
            let (number, offline, indirect) = disk_metadata(&path);
            rows.push(DiskNode {
                ancestors: chain,
                number,
                offline,
                indirect,
            });
        }
        None
    }
}
fn has_disk_descendant(instance: &str, ancestry: Option<&[DiskNode]>) -> Option<bool> {
    if instance.is_empty() {
        return None;
    }
    ancestry.map(|rows| {
        rows.iter()
            .flat_map(|disk| &disk.ancestors)
            .any(|node| node.eq_ignore_ascii_case(instance))
    })
}
fn storage_guard_required(known_nonstorage: bool, disk_descendant: Option<bool>) -> bool {
    // Positive disk ancestry always wins over a stale registry function class.
    disk_descendant == Some(true) || (!known_nonstorage && disk_descendant != Some(false))
}

fn proven_serial(service: &str, class: &str) -> bool {
    let service = service.to_ascii_lowercase();
    // CDC class 02/0a can also describe a network adapter. Require the
    // installed native serial driver and Ports class, never its friendly name.
    service == "ftdibus"
        || (class.eq_ignore_ascii_case("{4d36e978-e325-11ce-bfc1-08002be10318}")
            && matches!(
                service.as_str(),
                "usbser" | "silabser" | "ftser2k" | "ch341ser" | "ch341ser_a64"
            ))
}
fn safe_nonstorage(instance: &str) -> bool {
    // Registry class identifiers are supplied by PnP, not editable device names.
    // Composite/vendor classes remain conservative because child interfaces may be storage.
    let Ok(key) = windows_registry::LOCAL_MACHINE
        .open(format!("SYSTEM\\CurrentControlSet\\Enum\\{instance}"))
    else {
        return false;
    };
    let service = key.get_string("Service").unwrap_or_default();
    let class = key.get_string("ClassGUID").unwrap_or_default();
    if proven_serial(&service, &class) {
        return true;
    }
    let ids = key.get_multi_string("CompatibleIDs").unwrap_or_default();
    !ids.is_empty()
        && ids.iter().any(|id| {
            let id = id.to_ascii_uppercase();
            id.starts_with("USB\\CLASS_03") || id.starts_with("USB\\CLASS_01")
        })
}
fn parse_device(
    row: &Value,
    storage_online: Option<bool>,
    disk_descendant: Option<bool>,
) -> Option<Device> {
    let busid = row["BusId"].as_str()?;
    if !porthub_components::usb::valid_busid(busid) {
        return None;
    }
    let instance = row["InstanceId"].as_str()?;
    let upper = instance.to_ascii_uppercase();
    let id = |prefix: &str| -> Option<String> {
        let start = upper.find(prefix)? + prefix.len();
        let value = upper.get(start..start + 4)?;
        value
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
            .then(|| value.to_ascii_lowercase())
    };
    let name = row["Description"].as_str().unwrap_or("USB device");
    let lower = name.to_ascii_lowercase();
    if lower.contains("usb hub") || lower.contains("root hub") {
        return None;
    }
    let busnum = busid.split('-').next()?.parse().ok()?;
    let devnum = busid.split('-').nth(1)?.split('.').last()?.parse().ok()?;
    let blocked = if !row["ClientIPAddress"].is_null() {
        Some("Device is already attached by another USB client".into())
    } else if lower.contains("network") || lower.contains("ethernet") {
        Some("Network adapters must remain available to the host".into())
    } else if storage_online != Some(false)
        && storage_guard_required(safe_nonstorage(instance), disk_descendant)
    {
        Some("USB storage may be mounted or its volume state cannot be verified; safely take USB storage offline before sharing".into())
    } else {
        None
    };
    let device = Device {
        busid: busid.into(),
        vendor: id("VID_")?,
        product: id("PID_")?,
        serial: instance.rsplit('\\').next()?.chars().take(256).collect(),
        name: name.chars().take(256).collect(),
        busnum,
        devnum,
        speed: 5,
        blocked,
    };
    device.valid().then_some(device)
}
pub(super) fn fresh_inventory() -> Result<Vec<Device>> {
    let state = host_state()?;
    let ancestry = disk_ancestry();
    let volumes = ancestry.as_ref().and_then(|_| volume_states());
    let fallback = ancestry.is_none().then(online_usb_storage).flatten();
    Ok(state["Devices"]
        .as_array()
        .context("Invalid Windows USB inventory")?
        .iter()
        .filter_map(|row| {
            parse_device(
                row,
                row["InstanceId"].as_str().and_then(|instance| {
                    if ancestry.is_some() {
                        selected_storage_online(instance, ancestry.as_deref(), volumes.as_deref())
                    } else {
                        fallback
                    }
                }),
                row["InstanceId"]
                    .as_str()
                    .and_then(|instance| has_disk_descendant(instance, ancestry.as_deref())),
            )
        })
        .take(128)
        .collect())
}
pub(super) fn inventory() -> Vec<Device> {
    struct Cache {
        at: Instant,
        devices: Vec<Device>,
        refreshing: bool,
    }
    static CACHE: OnceLock<Arc<Mutex<Cache>>> = OnceLock::new();
    let shared = CACHE
        .get_or_init(|| {
            Arc::new(Mutex::new(Cache {
                at: Instant::now() - Duration::from_secs(60),
                devices: Vec::new(),
                refreshing: false,
            }))
        })
        .clone();
    let mut cache = shared.lock().unwrap_or_else(|p| p.into_inner());
    if cache.at.elapsed() >= Duration::from_secs(20) && !cache.refreshing {
        cache.refreshing = true;
        let target = shared.clone();
        std::thread::spawn(move || {
            let result = fresh_inventory();
            let mut cache = target.lock().unwrap_or_else(|p| p.into_inner());
            cache.devices = result.unwrap_or_default();
            cache.at = Instant::now();
            cache.refreshing = false;
        });
    }
    cache.devices.clone()
}
fn source_lease(busid: &str) -> Result<crate::profile::Lease> {
    ensure!(
        porthub_components::usb::valid_busid(busid),
        "Invalid USB source lock identity"
    );
    let root =
        PathBuf::from(std::env::var_os("ProgramData").context("Windows shared state unavailable")?)
            .join("PortHub/usb-source-locks");
    crate::service::directory(&root, true)?;
    crate::profile::Lease::acquire(&root.join(busid))
}
fn controller() -> Result<File> {
    unsafe {
        let set = SetupDiGetClassDevsW(
            &INTERFACE,
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
        );
        ensure!(
            set as isize != -1,
            "Windows USB receive driver is not installed"
        );
        struct List(HDEVINFO);
        impl Drop for List {
            fn drop(&mut self) {
                unsafe {
                    SetupDiDestroyDeviceInfoList(self.0);
                }
            }
        }
        let list = List(set);
        let mut data: SP_DEVICE_INTERFACE_DATA = std::mem::zeroed();
        data.cbSize = std::mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
        ensure!(
            SetupDiEnumDeviceInterfaces(list.0, std::ptr::null(), &INTERFACE, 0, &mut data) != 0,
            "Windows USB receive controller unavailable"
        );
        let mut required = 0;
        SetupDiGetDeviceInterfaceDetailW(
            list.0,
            &data,
            std::ptr::null_mut(),
            0,
            &mut required,
            std::ptr::null_mut(),
        );
        ensure!(
            (8..=32768).contains(&required),
            "Invalid USB receive interface path"
        );
        let mut buffer = vec![0u64; (required as usize + 7) / 8];
        let bytes = buffer.as_mut_ptr().cast::<u8>();
        *(bytes.cast::<u32>()) = if cfg!(target_pointer_width = "64") {
            8
        } else {
            6
        };
        ensure!(
            SetupDiGetDeviceInterfaceDetailW(
                list.0,
                &data,
                bytes.cast(),
                required,
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ) != 0,
            "Cannot query Windows USB receive controller"
        );
        let handle = CreateFileW(
            bytes.add(4).cast(),
            0xc0000000,
            3,
            std::ptr::null(),
            3,
            0x80,
            std::ptr::null_mut(),
        );
        ensure!(
            handle != INVALID_HANDLE_VALUE,
            "Cannot open Windows USB receive controller: {}",
            std::io::Error::last_os_error()
        );
        Ok(File::from_raw_handle(handle))
    }
}
pub(super) fn host_installed() -> bool {
    host().is_ok_and(|path| path.is_file())
}
pub(super) fn receive_installed() -> bool {
    controller().is_ok()
}
pub(super) fn supported() -> bool {
    host_installed() && receive_installed()
}
pub(super) async fn module(source: bool) -> Result<()> {
    crate::service::require_administrator()?;
    if source {
        ensure!(
            host()?.is_file(),
            "Install the signed Windows USB sharing driver"
        );
    } else {
        controller()?;
    }
    Ok(())
}
#[repr(C)]
struct Location {
    port: i32,
    hash: u32,
    busid: [u8; 32],
    service: [u8; 32],
    host: [u8; 1025],
}
#[repr(C)]
struct Plugin {
    size: u32,
    location: Location,
    serial: [u8; 16],
    events: u8,
}
fn fill(target: &mut [u8], value: &str) -> Result<()> {
    ensure!(
        value.len() < target.len() && !value.contains('\0'),
        "Invalid USB kernel parameter"
    );
    target[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}
fn plug(driver: File, port: u16, busid: &str) -> Result<Port> {
    unsafe {
        let mut request: Plugin = std::mem::zeroed();
        request.size = std::mem::size_of::<Plugin>() as u32;
        fill(&mut request.location.busid, busid)?;
        fill(&mut request.location.service, &port.to_string())?;
        fill(&mut request.location.host, "127.0.0.1")?;
        let mut returned = 0;
        let pointer = (&mut request as *mut Plugin).cast();
        let ok = DeviceIoControl(
            driver.as_raw_handle(),
            0x0022e018,
            pointer,
            request.size,
            pointer,
            8,
            &mut returned,
            std::ptr::null_mut(),
        );
        ensure!(
            ok != 0 && returned == 8 && request.location.port > 0,
            "Windows USB attachment failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(Port {
            driver,
            port: request.location.port,
        })
    }
}
struct Port {
    driver: File,
    port: i32,
}
impl Drop for Port {
    fn drop(&mut self) {
        unsafe {
            let mut data = [8u32, self.port as u32];
            let mut returned = 0;
            DeviceIoControl(
                self.driver.as_raw_handle(),
                0x0022e004,
                data.as_mut_ptr().cast(),
                8,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            );
        }
    }
}
struct AttachState {
    cancelled: bool,
    port: Option<Port>,
}
struct Export {
    path: PathBuf,
    guid: Option<String>,
    lease: Option<crate::profile::Lease>,
    instance: String,
}
fn cleanup_export(path: &Path, guid: &str) -> Result<()> {
    let journal: Value = serde_json::from_slice(&crate::profile::read_private(path)?)?;
    ensure!(
        journal["guid"].as_str() == Some(guid),
        "USB ownership journal changed"
    );
    let instance = journal["instance"]
        .as_str()
        .context("USB ownership identity unavailable")?;
    release_binding(guid, instance)?;
    std::fs::remove_file(path)?;
    Ok(())
}
fn release_binding(guid: &str, instance: &str) -> Result<()> {
    let state = host_state()?;
    let rows = state["Devices"]
        .as_array()
        .context("USB recovery inventory unavailable")?;
    if let Some(row) = rows
        .iter()
        .find(|row| row["PersistedGuid"].as_str() == Some(guid))
    {
        ensure!(
            row["InstanceId"].as_str() == Some(instance),
            "USB binding identity changed"
        );
        ensure!(
            host_output(&["unbind", "--guid", guid])?.status.success(),
            "Cannot release owned USB binding"
        );
        let after = host_state()?;
        ensure!(
            !after["Devices"]
                .as_array()
                .context("USB recovery verification unavailable")?
                .iter()
                .any(|r| r["PersistedGuid"].as_str() == Some(guid)),
            "USB binding remains active"
        );
    }
    Ok(())
}
impl Drop for Export {
    fn drop(&mut self) {
        let path = self.path.clone();
        let guid = self.guid.take();
        let lease = self.lease.take();
        let instance = self.instance.clone();
        std::thread::spawn(move || {
            let _lease = lease;
            if let Some(guid) = guid {
                let cleanup = if path.exists() {
                    cleanup_export(&path, &guid)
                } else {
                    release_binding(&guid, &instance)
                };
                if let Err(error) = cleanup {
                    tracing::warn!(%error,"Owned USB binding cleanup deferred");
                }
            }
        });
    }
}
enum Kind {
    Source(Export),
    Destination {
        state: Arc<Mutex<AttachState>>,
        task: JoinHandle<Result<()>>,
    },
}
pub(super) struct Handoff {
    kind: Kind,
}
impl Handoff {
    pub async fn failed(&mut self) -> Result<()> {
        match &mut self.kind {
            Kind::Source(_) => std::future::pending().await,
            Kind::Destination { task, .. } => {
                (&mut *task).await??;
                std::future::pending().await
            }
        }
    }
}
impl Drop for Handoff {
    fn drop(&mut self) {
        if let Kind::Destination { state, task } = &mut self.kind {
            let mut state = state.lock().unwrap_or_else(|p| p.into_inner());
            state.cancelled = true;
            state.port.take();
            task.abort();
        }
    }
}
pub(super) fn recover(profile: &Path) {
    let profile = profile.to_owned();
    std::thread::spawn(move || {
        let Some(parent) = profile.parent() else {
            return;
        };
        let prefix = crate::profile::sibling(&profile, ".usb-windows-");
        let Some(prefix) = prefix.file_name().and_then(|p| p.to_str()) else {
            return;
        };
        let Ok(files) = std::fs::read_dir(parent) else {
            return;
        };
        for file in files.flatten().take(256) {
            let name = file.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(busid) = name
                .strip_prefix(prefix)
                .and_then(|n| n.strip_suffix(".json"))
            else {
                continue;
            };
            let Ok(_lease) = source_lease(busid) else {
                continue;
            };
            if let Ok(bytes) = crate::profile::read_private(&file.path()) {
                if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(guid) = value["guid"]
                        .as_str()
                        .filter(|g| uuid::Uuid::parse_str(g).is_ok())
                    {
                        let _ = cleanup_export(&file.path(), guid);
                    }
                }
            }
        }
    });
}
pub(super) async fn source(
    profile: &Path,
    selected: &Device,
) -> Result<(Handoff, TcpStream, Device, Vec<u8>)> {
    let lease = source_lease(&selected.busid)?;
    let current = tokio::task::spawn_blocking(fresh_inventory)
        .await??
        .into_iter()
        .find(|d| d.same_device(selected))
        .context("Selected Windows USB device was unplugged or changed")?;
    ensure!(
        current.blocked.is_none(),
        "{}",
        current
            .blocked
            .as_deref()
            .unwrap_or("USB device unavailable")
    );
    ensure!(
        current.busid == selected.busid,
        "Selected USB device moved; refresh device inventory"
    );
    let state = tokio::task::spawn_blocking(host_state).await??;
    let row = state["Devices"]
        .as_array()
        .context("USB inventory unavailable")?
        .iter()
        .find(|row| row["BusId"] == current.busid)
        .context("USB device disappeared")?;
    let was_bound = row["PersistedGuid"].as_str().is_some();
    let journal = crate::profile::sibling(profile, &format!(".usb-windows-{}.json", current.busid));
    let mut export = Export {
        path: journal.clone(),
        guid: None,
        lease: Some(lease),
        instance: row["InstanceId"]
            .as_str()
            .context("USB physical identity unavailable")?
            .into(),
    };
    if journal.try_exists()? {
        let journal = journal.clone();
        tokio::task::spawn_blocking(move || {
            let value: Value = serde_json::from_slice(&crate::profile::read_private(&journal)?)?;
            let guid = value["guid"]
                .as_str()
                .context("Invalid USB recovery identity")?;
            cleanup_export(&journal, guid)
        })
        .await??;
        anyhow::bail!("Recovered previous USB binding; retry after device inventory refresh");
    }
    let ancestry = tokio::task::spawn_blocking(disk_ancestry).await?;
    if storage_guard_required(
        safe_nonstorage(&export.instance),
        has_disk_descendant(&export.instance, ancestry.as_deref()),
    ) {
        ensure!(
            {
                let instance = export.instance.clone();
                tokio::task::spawn_blocking(move || {
                    if let Some(disks) = ancestry {
                        selected_storage_online(&instance, Some(&disks), volume_states().as_deref())
                    } else {
                        online_usb_storage()
                    }
                })
                .await?
            } == Some(false),
            "USB volume state changed; safely take USB storage offline before sharing"
        );
    }
    if !was_bound {
        host_command(&["bind", "--busid", &current.busid]).await?;
        let state = tokio::task::spawn_blocking(host_state).await??;
        let guid = state["Devices"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["BusId"] == current.busid))
            .and_then(|row| row["PersistedGuid"].as_str())
            .context("Windows USB binding identity unavailable")?
            .to_owned();
        ensure!(
            uuid::Uuid::parse_str(&guid).is_ok(),
            "Invalid Windows USB driver binding identity"
        );
        export.guid = Some(guid.clone());
        crate::profile::write_private(
            &journal,
            &serde_json::to_vec(
                &serde_json::json!({"guid":guid,"device":current,"instance":row["InstanceId"]}),
            )?,
            true,
        )?;
    }
    let mut stream =
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect("127.0.0.1:3240"))
            .await??;
    stream.set_nodelay(true)?;
    let (actual, wire) = tokio::time::timeout(
        Duration::from_secs(12),
        super::protocol::import(&mut stream, &current),
    )
    .await??;
    Ok((
        Handoff {
            kind: Kind::Source(export),
        },
        stream,
        actual,
        wire,
    ))
}
pub(super) async fn destination(device: &Device, wire: &[u8]) -> Result<(Handoff, TcpStream)> {
    super::protocol::validate(wire, device)?;
    let driver = controller()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let capability = format!("1-{:028}", uuid::Uuid::new_v4().as_u128() % 10u128.pow(28));
    let secret = capability.clone();
    let state = Arc::new(Mutex::new(AttachState {
        cancelled: false,
        port: None,
    }));
    let shared = state.clone();
    let task = tokio::spawn(async move {
        let attached = tokio::task::spawn_blocking(move || plug(driver, port, &secret)).await??;
        let mut state = shared.lock().unwrap_or_else(|p| p.into_inner());
        if !state.cancelled {
            state.port = Some(attached);
        }
        Ok(())
    });
    let guard = Handoff {
        kind: Kind::Destination { state, task },
    };
    let stream = tokio::time::timeout(Duration::from_secs(15), async {
        for _ in 0..8 {
            let (mut stream, address) = listener.accept().await?;
            ensure!(
                address.ip().is_loopback(),
                "USB kernel connection must be local"
            );
            if tokio::time::timeout(
                Duration::from_secs(2),
                super::protocol::accept_import(&mut stream, &capability, wire, device),
            )
            .await
            .is_ok_and(|r| r.is_ok())
            {
                stream.set_nodelay(true)?;
                return Ok::<_, anyhow::Error>(stream);
            }
        }
        anyhow::bail!("Windows USB kernel did not authenticate its local connection")
    })
    .await??;
    Ok((guard, stream))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn disk_ancestry_separates_serial_devices_from_unrelated_mounted_storage() {
        let disk_usb = "USB\\VID_0781&PID_5583\\disk";
        let serial_usb = "USB\\VID_10C4&PID_EA60\\0001";
        let ancestry = vec![DiskNode {
            ancestors: vec![
                "USBSTOR\\Disk&Ven_SanDisk\\disk".into(),
                disk_usb.into(),
                "USB\\ROOT_HUB30\\root".into(),
            ],
            number: Some(1),
            offline: false,
            indirect: false,
        }];
        assert_eq!(
            has_disk_descendant(serial_usb, Some(&ancestry)),
            Some(false)
        );
        assert!(!storage_guard_required(
            false,
            has_disk_descendant(serial_usb, Some(&ancestry))
        ));
        assert!(storage_guard_required(
            false,
            has_disk_descendant(disk_usb, Some(&ancestry))
        ));
        assert!(
            storage_guard_required(true, Some(true)),
            "Disk ancestry overrides registry classification"
        );
        assert!(
            storage_guard_required(false, None),
            "Incomplete native enumeration cannot grant capture"
        );
        assert_eq!(has_disk_descendant(serial_usb, None), None);
        assert_eq!(has_disk_descendant("", Some(&ancestry)), None);
        assert_eq!(
            has_disk_descendant(&disk_usb.to_lowercase(), Some(&ancestry)),
            Some(true)
        );
        let row = serde_json::json!({"BusId":"5-1","InstanceId":serial_usb,"Description":"CP2102 USB to UART Bridge Controller","ClientIPAddress":null});
        assert!(parse_device(&row, Some(true), Some(false))
            .unwrap()
            .blocked
            .is_none());
        assert!(parse_device(&row, None, None).unwrap().blocked.is_some());
    }
    #[test]
    fn storage_guard_checks_only_selected_disk_volumes() {
        let disks = [
            DiskNode {
                ancestors: vec!["USB\\selected".into()],
                number: Some(1),
                offline: false,
                indirect: false,
            },
            DiskNode {
                ancestors: vec!["USB\\other".into()],
                number: Some(2),
                offline: false,
                indirect: false,
            },
        ];
        let volumes = [
            VolumeState {
                disks: Some(vec![1]),
                offline: true,
                mounted: false,
            },
            VolumeState {
                disks: Some(vec![2]),
                offline: false,
                mounted: true,
            },
        ];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&volumes)),
            Some(false)
        );
        assert_eq!(
            selected_storage_online("USB\\other", Some(&disks), Some(&volumes)),
            Some(true)
        );
        assert_eq!(
            selected_storage_online("USB\\serial", Some(&disks), None),
            Some(false)
        );
    }
    #[test]
    fn locked_or_unknown_storage_never_grants_capture() {
        let disks = [DiskNode {
            ancestors: vec!["USB\\selected".into()],
            number: Some(1),
            offline: false,
            indirect: false,
        }];
        let locked = [VolumeState {
            disks: Some(vec![1]),
            offline: false,
            mounted: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&locked)),
            None
        );
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), None),
            None
        );
        assert_eq!(
            selected_storage_online("USB\\selected", None, Some(&locked)),
            None
        );
        let unmapped = [VolumeState {
            disks: None,
            offline: true,
            mounted: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&unmapped)),
            None
        );
        let removed = [DiskNode {
            ancestors: vec!["USB\\selected".into()],
            number: None,
            offline: false,
            indirect: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&removed), Some(&locked)),
            None
        );
        assert_eq!(
            selected_storage_online("", Some(&disks), Some(&locked)),
            None
        );
    }
    #[test]
    fn offline_disk_and_complete_empty_volume_map_are_positive_evidence() {
        let offline = [DiskNode {
            ancestors: vec!["USB\\selected".into()],
            number: Some(1),
            offline: true,
            indirect: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&offline), None),
            Some(false)
        );
        let raw = [DiskNode {
            ancestors: vec!["USB\\selected".into()],
            number: Some(1),
            offline: false,
            indirect: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&raw), Some(&[])),
            Some(false)
        );
        let unknown = [VolumeState {
            disks: None,
            offline: false,
            mounted: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&raw), Some(&unknown)),
            None
        );
    }
    #[test]
    fn spanned_and_multilun_volumes_check_every_selected_extent() {
        let disks = [
            DiskNode {
                ancestors: vec!["USB\\selected".into()],
                number: Some(1),
                offline: true,
                indirect: false,
            },
            DiskNode {
                ancestors: vec!["USB\\selected".into()],
                number: Some(2),
                offline: false,
                indirect: false,
            },
        ];
        let active = [VolumeState {
            disks: Some(vec![9, 2]),
            offline: false,
            mounted: true,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&active)),
            Some(true)
        );
        let locked = [VolumeState {
            disks: Some(vec![9, 2]),
            offline: false,
            mounted: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&locked)),
            None
        );
        let offline = [VolumeState {
            disks: Some(vec![9, 2]),
            offline: true,
            mounted: false,
        }];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&offline)),
            Some(false)
        );
    }
    #[test]
    fn volume_extent_parser_requires_complete_bounded_native_records() {
        let stride = std::mem::size_of::<DiskExtent>();
        let start = std::mem::offset_of!(DiskExtents, extents);
        let mut bytes = vec![0u8; start + stride * 2];
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        for (index, disk) in [1u32, 2].into_iter().enumerate() {
            let position = start + stride * index;
            bytes[position..position + 4].copy_from_slice(&disk.to_le_bytes());
            bytes[position + 16..position + 24].copy_from_slice(&4096i64.to_le_bytes());
        }
        assert_eq!(extent_numbers(&bytes), Some(vec![1, 2]));
        assert!(extent_numbers(&bytes[..bytes.len() - 1]).is_none());
        bytes[..4].copy_from_slice(&257u32.to_le_bytes());
        assert!(extent_numbers(&bytes).is_none());
        bytes[..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(extent_numbers(&bytes).is_none());
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[start + 8..start + 16].copy_from_slice(&(-1i64).to_le_bytes());
        assert!(extent_numbers(&bytes).is_none());
    }
    #[test]
    fn indirect_pool_or_virtual_disks_prevent_false_safe_empty_extent_proof() {
        let selected = DiskNode {
            ancestors: vec!["USB\\selected".into()],
            number: Some(1),
            offline: false,
            indirect: false,
        };
        let virtual_disk = DiskNode {
            ancestors: vec!["ROOT\\space".into()],
            number: Some(2),
            offline: false,
            indirect: true,
        };
        let mounted_virtual = [VolumeState {
            disks: Some(vec![2]),
            mounted: true,
            offline: false,
        }];
        let mut disks = [selected, virtual_disk];
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&mounted_virtual)),
            None
        );
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), Some(&[])),
            None
        );
        disks[0].offline = true;
        assert_eq!(
            selected_storage_online("USB\\selected", Some(&disks), None),
            Some(false)
        );
        for bus in [
            None,
            Some(0),
            Some(1),
            Some(8),
            Some(14),
            Some(15),
            Some(16),
            Some(255),
        ] {
            assert!(indirect_storage_bus(bus));
        }
        for bus in [7, 11, 17] {
            assert!(!indirect_storage_bus(Some(bus)));
        }
    }
    #[test]
    fn release_driver_abi_is_fixed() {
        assert_eq!(std::mem::size_of::<Location>(), 1100);
        assert_eq!(std::mem::size_of::<Plugin>(), 1124);
        assert_eq!(std::mem::offset_of!(Plugin, location), 4);
        assert_eq!(std::mem::offset_of!(Plugin, serial), 1104);
    }
    #[test]
    fn inventory_hides_hubs_and_blocks_online_storage() {
        let row = serde_json::json!({"BusId":"1-14","InstanceId":"USB\\VID_04E8&PID_4001\\stable","Description":"USB Attached SCSI (UAS) Mass Storage Device","ClientIPAddress":null});
        assert!(parse_device(&row, Some(true), None)
            .unwrap()
            .blocked
            .is_some());
        assert!(parse_device(&row, Some(false), None)
            .unwrap()
            .blocked
            .is_none());
        let mut hub = row;
        hub["Description"] = "Generic USB Hub".into();
        assert!(parse_device(&hub, Some(false), None).is_none());
    }
    #[test]
    fn storage_guard_does_not_trust_friendly_names_or_unknown_volume_state() {
        let row = serde_json::json!({"BusId":"1-14","InstanceId":"USB\\VID_04E8&PID_4001\\porthub-test-nonexistent","Description":"Samsung Portable SSD T7","ClientIPAddress":null});
        assert!(parse_device(&row, Some(true), None)
            .unwrap()
            .blocked
            .is_some());
        assert!(parse_device(&row, None, None).unwrap().blocked.is_some());
        assert!(parse_device(&row, Some(false), None)
            .unwrap()
            .blocked
            .is_none());
    }
    #[test]
    fn serial_exception_requires_native_driver_identity() {
        let ports = "{4d36e978-e325-11ce-bfc1-08002be10318}";
        assert!(proven_serial("silabser", ports));
        assert!(proven_serial("usbser", ports));
        assert!(proven_serial("FTDIBUS", ""));
        assert!(!proven_serial(
            "usbser",
            "{4d36e972-e325-11ce-bfc1-08002be10318}"
        ));
        assert!(!proven_serial("rndismp", ports));
        assert!(!proven_serial("USBSTOR", ports));
    }
}
