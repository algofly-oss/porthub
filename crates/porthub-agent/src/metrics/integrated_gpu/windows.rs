//! Match physical DXGI adapters to WDDM counter LUIDs. The LUID is runtime-only;
//! the reported identity uses the OS PCI device identity and survives reboots.
use super::*;
use std::{collections::HashMap, ffi::c_void};
use windows_sys::core::GUID;
pub(super) struct Adapter {
    pub gpu: Gpu,
    pub luid: Option<u64>,
    pub dedicated_capacity: Option<u64>,
}
#[repr(C)]
struct Display {
    size: u32,
    name: [u16; 32],
    description: [u16; 128],
    flags: u32,
    id: [u16; 128],
    key: [u16; 128],
}
#[link(name = "user32")]
unsafe extern "system" {
    fn EnumDisplayDevicesW(
        device: *const u16,
        index: u32,
        display: *mut Display,
        flags: u32,
    ) -> i32;
}
#[link(name = "dxgi")]
unsafe extern "system" {
    fn CreateDXGIFactory1(iid: *const GUID, factory: *mut *mut c_void) -> i32;
}
#[repr(C)]
struct Luid {
    low: u32,
    high: i32,
}
#[repr(C)]
struct Description {
    name: [u16; 128],
    vendor: u32,
    device: u32,
    subsystem: u32,
    revision: u32,
    video: usize,
    system: usize,
    shared: usize,
    luid: Luid,
    flags: u32,
}
struct Com(*mut c_void);
impl Com {
    unsafe fn method(&self, index: usize) -> *const c_void {
        let table = *(self.0 as *const *const *const c_void);
        *table.add(index)
    }
}
impl Drop for Com {
    fn drop(&mut self) {
        unsafe {
            let release: unsafe extern "system" fn(*mut c_void) -> u32 =
                std::mem::transmute(self.method(2));
            release(self.0);
        }
    }
}
fn wide(data: &[u16]) -> String {
    String::from_utf16_lossy(data).trim_matches('\0').to_owned()
}
fn display_devices() -> Vec<Gpu> {
    let mut rows = Vec::new();
    for index in 0..32 {
        let mut data: Display = unsafe { std::mem::zeroed() };
        data.size = std::mem::size_of::<Display>() as u32;
        if unsafe { EnumDisplayDevicesW(std::ptr::null(), index, &mut data, 0) } == 0 {
            break;
        }
        let name = wide(&data.description);
        if data.flags & 8 != 0
            || name.is_empty()
            || name.to_lowercase().contains("remote")
            || name.to_lowercase().contains("basic render")
        {
            continue;
        }
        let id = wide(&data.id);
        rows.push(unknown(
            format!(
                "windows:{}",
                if id.is_empty() { wide(&data.name) } else { id }
            ),
            name,
        ));
    }
    rows
}
pub(super) fn inventory() -> Vec<Adapter> {
    let legacy = display_devices();
    let iid = GUID {
        data1: 0x770aae78,
        data2: 0xf26f,
        data3: 0x4dba,
        data4: [0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87],
    };
    let mut factory = std::ptr::null_mut();
    if unsafe { CreateDXGIFactory1(&iid, &mut factory) } < 0 || factory.is_null() {
        return legacy
            .into_iter()
            .map(|gpu| Adapter {
                gpu,
                luid: None,
                dedicated_capacity: None,
            })
            .collect();
    }
    let factory = Com(factory);
    let core = Core::new();
    let mut rows = Vec::new();
    let mut ids = HashMap::<String, usize>::new();
    for index in 0..16 {
        let mut adapter = std::ptr::null_mut();
        let enumerate: unsafe extern "system" fn(*mut c_void, u32, *mut *mut c_void) -> i32 =
            unsafe { std::mem::transmute(factory.method(12)) };
        if unsafe { enumerate(factory.0, index, &mut adapter) } < 0 || adapter.is_null() {
            break;
        }
        let adapter = Com(adapter);
        let mut description: Description = unsafe { std::mem::zeroed() };
        let describe: unsafe extern "system" fn(*mut c_void, *mut Description) -> i32 =
            unsafe { std::mem::transmute(adapter.method(10)) };
        if unsafe { describe(adapter.0, &mut description) } < 0 || description.flags & 3 != 0 {
            continue;
        }
        let name = wide(&description.name);
        let used = ids.entry(name.clone()).or_default();
        let id = legacy
            .iter()
            .filter(|gpu| gpu.name == name)
            .nth(*used)
            .and_then(|gpu| gpu.id.clone())
            .unwrap_or_else(|| {
                format!(
                    "windows-pci:{:04x}:{:04x}:{:08x}:{index}",
                    description.vendor, description.device, description.subsystem
                )
            });
        *used += 1;
        let mut gpu = unknown(id, name);
        let properties = core
            .as_ref()
            .and_then(|core| core.properties(&description.luid));
        // DXCore uses64-bit capacities even for a32-bit collector. DXGI SIZE_T
        // remains the compatible fallback on older Windows versions.
        gpu.shared_memory_capacity = properties
            .as_ref()
            .and_then(|p| p.shared)
            .or(Some(description.shared as u64))
            .filter(|n| *n > 0 && *n <= i64::MAX as u64);
        gpu.integrated = properties.as_ref().and_then(|p| p.integrated);
        let dedicated_capacity = properties
            .as_ref()
            .and_then(|p| p.dedicated)
            .or_else(|| (description.video as u64).checked_add(description.system as u64))
            .filter(|n| *n <= i64::MAX as u64);
        rows.push(Adapter {
            gpu,
            dedicated_capacity,
            luid: Some(((description.luid.high as u32 as u64) << 32) | description.luid.low as u64),
        });
    }
    if rows.is_empty() {
        legacy
            .into_iter()
            .map(|gpu| Adapter {
                gpu,
                luid: None,
                dedicated_capacity: None,
            })
            .collect()
    } else {
        rows
    }
}

// Optional DXCore metadata avoids guessing integrated-vs-discrete from vendor,
// reserved-memory size or names. No D3D device/context or GPU workload is created.
// https://learn.microsoft.com/windows/win32/api/dxcore_interface/ne-dxcore_interface-dxcoreadapterproperty
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryExW(name: *const u16, file: isize, flags: u32) -> isize;
    fn GetProcAddress(module: isize, name: *const u8) -> *const c_void;
    fn FreeLibrary(module: isize) -> i32;
}
struct Library(isize);
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}
struct Properties {
    integrated: Option<bool>,
    shared: Option<u64>,
    dedicated: Option<u64>,
}
struct Core {
    factory: Com,
    _library: Library,
}
impl Core {
    fn new() -> Option<Self> {
        let name = "dxcore.dll\0".encode_utf16().collect::<Vec<_>>();
        // System32-only loading also permits older Windows versions to omit DXCore.
        let handle = unsafe { LoadLibraryExW(name.as_ptr(), 0, 0x800) };
        if handle == 0 {
            return None;
        }
        let library = Library(handle);
        let function =
            unsafe { GetProcAddress(library.0, b"DXCoreCreateAdapterFactory\0".as_ptr()) };
        if function.is_null() {
            return None;
        }
        let create: unsafe extern "system" fn(*const GUID, *mut *mut c_void) -> i32 =
            unsafe { std::mem::transmute(function) };
        let iid = GUID {
            data1: 0x78ee5945,
            data2: 0xc36e,
            data3: 0x4b13,
            data4: [0xa6, 0x69, 0x00, 0x5d, 0xd1, 0x1c, 0x0f, 0x06],
        };
        let mut factory = std::ptr::null_mut();
        if unsafe { create(&iid, &mut factory) } < 0 || factory.is_null() {
            return None;
        }
        Some(Self {
            factory: Com(factory),
            _library: library,
        })
    }
    fn properties(&self, luid: &Luid) -> Option<Properties> {
        let iid = GUID {
            data1: 0xf0db4c7f,
            data2: 0xfe5a,
            data3: 0x42a2,
            data4: [0xbd, 0x62, 0xf2, 0xa6, 0xcf, 0x6f, 0xc8, 0x3e],
        };
        let lookup: unsafe extern "system" fn(
            *mut c_void,
            *const Luid,
            *const GUID,
            *mut *mut c_void,
        ) -> i32 = unsafe { std::mem::transmute(self.factory.method(4)) };
        let mut adapter = std::ptr::null_mut();
        if unsafe { lookup(self.factory.0, luid, &iid, &mut adapter) } < 0 || adapter.is_null() {
            return None;
        }
        let adapter = Com(adapter);
        let supports: unsafe extern "system" fn(*mut c_void, u32) -> bool =
            unsafe { std::mem::transmute(adapter.method(5)) };
        let property: unsafe extern "system" fn(*mut c_void, u32, usize, *mut c_void) -> i32 =
            unsafe { std::mem::transmute(adapter.method(6)) };
        let get_u64 = |kind| {
            if !unsafe { supports(adapter.0, kind) } {
                return None;
            }
            let mut value = 0u64;
            (unsafe { property(adapter.0, kind, 8, (&mut value as *mut u64).cast()) } >= 0)
                .then_some(value)
        };
        let integrated = if unsafe { supports(adapter.0, 12) } {
            let mut value = 0u8;
            if unsafe { property(adapter.0, 12, 1, (&mut value as *mut u8).cast()) } >= 0
                && value <= 1
            {
                Some(value != 0)
            } else {
                None
            }
        } else {
            None
        };
        Some(Properties {
            integrated,
            shared: get_u64(9),
            dedicated: get_u64(7)
                .zip(get_u64(8))
                .and_then(|(a, b)| a.checked_add(b)),
        })
    }
}
