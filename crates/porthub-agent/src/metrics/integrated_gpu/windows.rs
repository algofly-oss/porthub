//! Match physical DXGI adapters to WDDM counter LUIDs. The LUID is runtime-only;
//! the reported identity uses the OS PCI device identity and survives reboots.
use super::*;
use std::{collections::HashMap, ffi::c_void};
use windows_sys::core::GUID;
pub(super) struct Adapter {
    pub gpu: Gpu,
    pub luid: Option<u64>,
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
            .map(|gpu| Adapter { gpu, luid: None })
            .collect();
    }
    let factory = Com(factory);
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
        rows.push(Adapter {
            gpu: unknown(id, name),
            luid: Some(((description.luid.high as u32 as u64) << 32) | description.luid.low as u64),
        });
    }
    if rows.is_empty() {
        legacy
            .into_iter()
            .map(|gpu| Adapter { gpu, luid: None })
            .collect()
    } else {
        rows
    }
}
