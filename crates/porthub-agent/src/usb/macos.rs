//! Native macOS USB export. Root capture uses libusb's public Darwin IOKit
//! implementation; no virtual host controller, signing entitlement or daemon is
//! installed. Imported virtual USB controllers remain unsupported on macOS.
use super::{protocol, userspace};
use anyhow::{ensure, Context, Result};
use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    number::CFNumber,
    string::CFString,
};
use porthub_components::usb::Device;
use rusb::{DeviceHandle, GlobalContext, TransferType, UsbContext};
use std::{
    collections::{HashMap, HashSet},
    ffi::{c_char, c_void, CStr},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOServiceMatching(name: *const c_char) -> *mut c_void;
    fn IOServiceGetMatchingServices(port: u32, matching: *mut c_void, iterator: *mut u32) -> i32;
    fn IOIteratorNext(iterator: u32) -> u32;
    fn IOObjectRelease(object: u32) -> i32;
    fn IOObjectConformsTo(object: u32, class: *const c_char) -> bool;
    fn IORegistryEntryCreateCFProperty(
        entry: u32,
        key: *const c_void,
        allocator: *const c_void,
        options: u32,
    ) -> *const c_void;
    fn IORegistryEntryCreateIterator(
        entry: u32,
        plane: *const c_char,
        options: u32,
        iterator: *mut u32,
    ) -> i32;
}
struct Object(u32);
impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            IOObjectRelease(self.0);
        }
    }
}
fn property(entry: u32, key: &str) -> Option<CFType> {
    let key = CFString::new(key);
    let value = unsafe {
        IORegistryEntryCreateCFProperty(
            entry,
            key.as_concrete_TypeRef().cast(),
            std::ptr::null(),
            0,
        )
    };
    (!value.is_null()).then(|| unsafe { CFType::wrap_under_create_rule(value.cast()) })
}
fn number(entry: u32, key: &str) -> Option<i64> {
    property(entry, key)?.downcast::<CFNumber>()?.to_i64()
}
fn string(entry: u32, key: &str) -> String {
    property(entry, key)
        .and_then(|v| v.downcast::<CFString>())
        .map(|v| v.to_string())
        .unwrap_or_default()
}
#[derive(Default)]
struct Metadata {
    name: String,
    serial: String,
    builtin: bool,
    media: HashSet<String>,
    network: bool,
}
fn metadata() -> Result<HashMap<(u8, u8, u16, u16), Metadata>> {
    let mut iterator = 0;
    ensure!(
        unsafe {
            IOServiceGetMatchingServices(
                0,
                IOServiceMatching(b"IOUSBHostDevice\0".as_ptr().cast()),
                &mut iterator,
            )
        } == 0,
        "Cannot inspect native USB identity"
    );
    let iterator = Object(iterator);
    let mut entries = HashMap::new();
    loop {
        let entry = unsafe { IOIteratorNext(iterator.0) };
        if entry == 0 {
            break;
        }
        let entry = Object(entry);
        let Some(location) = number(entry.0, "locationID") else {
            continue;
        };
        let Some(address) = number(entry.0, "USB Address") else {
            continue;
        };
        let Some(vendor) = number(entry.0, "idVendor") else {
            continue;
        };
        let Some(product) = number(entry.0, "idProduct") else {
            continue;
        };
        let product_name = string(entry.0, "USB Product Name");
        let manufacturer = string(entry.0, "USB Vendor Name");
        let builtin = property(entry.0, "built-in").is_some_and(|v| {
            v.downcast::<CFBoolean>().is_some_and(|b| b.into())
                || v.downcast::<CFData>()
                    .is_some_and(|d| d.bytes().first().copied().unwrap_or(0) != 0)
        }) || product_name.to_lowercase().contains("internal");
        let mut meta = Metadata {
            name: format!("{manufacturer} {product_name}")
                .trim()
                .chars()
                .take(120)
                .collect(),
            serial: string(entry.0, "USB Serial Number")
                .chars()
                .take(256)
                .collect(),
            builtin,
            media: HashSet::new(),
            network: false,
        };
        let mut children = 0;
        if unsafe {
            IORegistryEntryCreateIterator(entry.0, b"IOService\0".as_ptr().cast(), 1, &mut children)
        } == 0
        {
            let children = Object(children);
            loop {
                let child = unsafe { IOIteratorNext(children.0) };
                if child == 0 {
                    break;
                }
                let child = Object(child);
                if unsafe { IOObjectConformsTo(child.0, b"IONetworkInterface\0".as_ptr().cast()) } {
                    meta.network = true;
                }
                if unsafe { IOObjectConformsTo(child.0, b"IOMedia\0".as_ptr().cast()) } {
                    let name = string(child.0, "BSD Name");
                    if !name.is_empty() {
                        meta.media.insert(name);
                    }
                }
            }
        }
        entries.insert(
            (
                (location as u32 >> 24) as u8,
                address as u8,
                vendor as u16,
                product as u16,
            ),
            meta,
        );
    }
    Ok(entries)
}
fn mounts() -> Result<HashSet<String>> {
    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    ensure!(count >= 0, "Cannot inspect mounted drives");
    let mut data: Vec<libc::statfs> = Vec::with_capacity(count as usize + 8);
    data.resize_with(count as usize + 8, || unsafe { std::mem::zeroed() });
    let found = unsafe {
        libc::getfsstat(
            data.as_mut_ptr(),
            (data.len() * std::mem::size_of::<libc::statfs>()) as i32,
            libc::MNT_NOWAIT,
        )
    };
    ensure!(found >= 0, "Cannot inspect mounted drives");
    Ok(data
        .iter()
        .take(found as usize)
        .filter_map(|v| {
            unsafe { CStr::from_ptr(v.f_mntfromname.as_ptr()) }
                .to_str()
                .ok()
                .and_then(|name| name.strip_prefix("/dev/"))
                .map(str::to_owned)
        })
        .collect())
}
fn speed(speed: rusb::Speed) -> Option<u32> {
    match speed {
        rusb::Speed::Low => Some(1),
        rusb::Speed::Full => Some(2),
        rusb::Speed::High => Some(3),
        rusb::Speed::Super => Some(5),
        rusb::Speed::SuperPlus => Some(6),
        _ => None,
    }
}
fn native_id(device: &rusb::Device<GlobalContext>) -> Result<(String, u16, u16)> {
    let bus = device.bus_number() as u16 + 1;
    let address = device.address() as u16;
    let mut ports = device.port_numbers().unwrap_or_default();
    if ports.is_empty() {
        ports.push(device.address());
    }
    Ok((
        format!(
            "{bus}-{}",
            ports
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(".")
        ),
        bus,
        address,
    ))
}
pub(super) fn inventory() -> Vec<Device> {
    let Ok(metadata) = metadata() else {
        return Vec::new();
    };
    let mounted = mounts().ok();
    let Ok(devices) = rusb::devices() else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for native in devices.iter().take(128) {
        let Ok(descriptor) = native.device_descriptor() else {
            continue;
        };
        if descriptor.class_code() == 9 {
            continue;
        }
        let Some(speed) = speed(native.speed()) else {
            continue;
        };
        let Ok((busid, busnum, devnum)) = native_id(&native) else {
            continue;
        };
        if devnum == 0 {
            continue;
        }
        let key = (
            native.bus_number(),
            native.address(),
            descriptor.vendor_id(),
            descriptor.product_id(),
        );
        let meta = metadata.get(&key);
        let config = native.active_config_descriptor().ok();
        let mut blocked = if meta.is_none() {
            Some("Native USB identity unavailable".into())
        } else {
            None
        };
        if meta.is_some_and(|m| m.builtin) {
            blocked = Some("Built-in device".into());
        }
        if let Some(config) = &config {
            if config.interfaces().any(|i| {
                i.descriptors().any(|a| {
                    a.endpoint_descriptors()
                        .any(|e| e.transfer_type() == TransferType::Isochronous)
                })
            }) {
                blocked = Some("Isochronous USB export is not yet supported on macOS".into());
            }
        } else {
            blocked = Some("USB configuration unavailable".into());
        }
        if meta.is_some_and(|m| m.network) {
            blocked = Some("Network adapters cannot be captured".into());
        }
        if (mounted.is_none() && meta.is_some_and(|m| !m.media.is_empty()))
            || meta.is_some_and(|m| {
                m.media
                    .iter()
                    .any(|name| mounted.as_ref().is_some_and(|set| set.contains(name)))
            })
        {
            blocked = Some("Mounted storage device; unmount it on this Mac first".into());
        }
        let device = Device {
            busid,
            vendor: format!("{:04x}", descriptor.vendor_id()),
            product: format!("{:04x}", descriptor.product_id()),
            serial: meta.map(|m| m.serial.clone()).unwrap_or_default(),
            name: meta
                .map(|m| m.name.clone())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| {
                    format!(
                        "USB {:04x}:{:04x}",
                        descriptor.vendor_id(),
                        descriptor.product_id()
                    )
                }),
            busnum,
            devnum,
            speed,
            blocked,
        };
        if device.valid() {
            result.push(device);
        }
    }
    result.sort_by(|a, b| a.busid.cmp(&b.busid));
    result
}
struct Native {
    handle: DeviceHandle<GlobalContext>,
    interfaces: Vec<u8>,
    endpoints: Mutex<HashMap<u8, (TransferType, u16)>>,
    configuration: u8,
    captured: bool,
}
impl Drop for Native {
    fn drop(&mut self) {
        for interface in self.interfaces.iter().rev() {
            let _ = self.handle.release_interface(*interface);
        }
        if self.captured {
            // Capture belongs to the whole device. Restore even when the first
            // interface claim failed and libusb recorded no claimed interface.
            if let Err(error) = self.handle.attach_kernel_driver(0) {
                tracing::warn!(%error,"Cannot restore native macOS USB device ownership");
            }
        }
    }
}
fn error(error: rusb::Error) -> i32 {
    match error {
        rusb::Error::Timeout => -110,
        rusb::Error::NoDevice => -19,
        rusb::Error::Pipe => -32,
        rusb::Error::Overflow => -75,
        rusb::Error::InvalidParam => -22,
        rusb::Error::Busy => -16,
        rusb::Error::Interrupted => -104,
        rusb::Error::NotSupported => -95,
        _ => -5,
    }
}
impl userspace::DeviceIo for Native {
    fn execute(
        &self,
        r: &userspace::Transfer,
        cancelled: &AtomicBool,
    ) -> std::result::Result<userspace::Completion, i32> {
        if cancelled.load(Ordering::Acquire) {
            return Err(-104);
        }
        let timeout = Duration::from_secs(1);
        let mut bytes = if r.input {
            vec![0; r.length]
        } else {
            Vec::new()
        };
        let actual = if r.endpoint == 0 {
            let request_type = r.setup[0];
            let request = r.setup[1];
            let value = u16::from_le_bytes([r.setup[2], r.setup[3]]);
            let index = u16::from_le_bytes([r.setup[4], r.setup[5]]);
            let length = u16::from_le_bytes([r.setup[6], r.setup[7]]) as usize;
            if request_type & 0x80 != if r.input { 0x80 } else { 0 } || length != r.length {
                return Err(-22);
            }
            if !r.input && request_type == 0 && request == 5 {
                0
            }
            // A remote address never changes the physical host's address.
            else if !r.input && request_type == 0 && request == 9 {
                if value != self.configuration as u16 {
                    return Err(-95);
                }
                0
            } else if !r.input && request_type == 1 && request == 11 {
                if value != 0 || index > 255 {
                    return Err(-95);
                }
                self.handle
                    .set_alternate_setting(index as u8, value as u8)
                    .map_err(error)?;
                0
            } else if r.input {
                self.handle
                    .read_control(request_type, request, value, index, &mut bytes, timeout)
                    .map_err(error)?
            } else {
                self.handle
                    .write_control(request_type, request, value, index, &r.data, timeout)
                    .map_err(error)?
            }
        } else {
            let address = r.endpoint | if r.input { 0x80 } else { 0 };
            let endpoint = self
                .endpoints
                .lock()
                .map_err(|_| -5)?
                .get(&address)
                .copied()
                .ok_or(-22)?;
            let actual = match (endpoint.0, r.input) {
                (TransferType::Bulk, true) => loop {
                    if cancelled.load(Ordering::Acquire) {
                        break Err(rusb::Error::Interrupted);
                    }
                    match self
                        .handle
                        .read_bulk(address, &mut bytes, Duration::from_millis(250))
                    {
                        Err(rusb::Error::Timeout) => continue,
                        result => break result,
                    }
                },
                (TransferType::Bulk, false) => self.handle.write_bulk(address, &r.data, timeout),
                (TransferType::Interrupt, true) => loop {
                    if cancelled.load(Ordering::Acquire) {
                        break Err(rusb::Error::Interrupted);
                    }
                    match self.handle.read_interrupt(
                        address,
                        &mut bytes,
                        Duration::from_millis(250),
                    ) {
                        Err(rusb::Error::Timeout) => continue,
                        result => break result,
                    }
                },
                (TransferType::Interrupt, false) => {
                    self.handle.write_interrupt(address, &r.data, timeout)
                }
                _ => return Err(-95),
            }
            .map_err(error)?;
            if !r.input
                && r.flags & 0x40 != 0
                && endpoint.0 == TransferType::Bulk
                && actual > 0
                && actual % endpoint.1 as usize == 0
            {
                self.handle
                    .write_bulk(address, &[], timeout)
                    .map_err(error)?;
            }
            actual
        };
        if r.input {
            bytes.truncate(actual);
        } else {
            bytes.clear();
        }
        Ok(userspace::Completion {
            actual,
            data: bytes,
        })
    }
}
pub(super) struct Handoff {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Drop for Handoff {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}
pub(super) async fn prepare(source: bool) -> Result<()> {
    ensure!(source,"Receiving USB on macOS requires Apple's approved virtual host-controller entitlement; this Mac can export devices only");
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "macOS USB capture requires the system agent"
    );
    Ok(())
}
pub(super) async fn source(
    _profile: &Path,
    selected: &Device,
) -> Result<(Handoff, tokio::net::TcpStream, Device, Vec<u8>)> {
    prepare(true).await?;
    let current = inventory()
        .into_iter()
        .find(|d| d.same_device(selected))
        .context("Selected USB device is unplugged or changed")?;
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
    let devices = rusb::devices()?;
    let native = devices
        .iter()
        .find(|d| native_id(d).is_ok_and(|(id, _, _)| id == current.busid))
        .context("Selected USB device disappeared")?;
    let descriptor = native.device_descriptor()?;
    let config = native.active_config_descriptor()?;
    let handle = native.open().context("Cannot open selected USB device")?;
    // libusb's Darwin automatic detach can capture the device before a failed
    // claim, then leak that capture because no interface was marked claimed.
    // One explicit capture paired with Native::drop restores all failure paths.
    handle.set_auto_detach_kernel_driver(false)?;
    handle
        .detach_kernel_driver(0)
        .context("Cannot capture the selected macOS USB device")?;
    let mut io = Native {
        handle,
        interfaces: Vec::new(),
        endpoints: Mutex::new(HashMap::new()),
        configuration: config.number(),
        captured: true,
    };
    for interface in config.interfaces() {
        let number = interface.number();
        io.handle.claim_interface(number).context(
            "Cannot open the selected USB interface; macOS denied native interface access",
        )?;
        io.interfaces.push(number);
        let alternate = interface
            .descriptors()
            .find(|d| d.setting_number() == 0)
            .context("USB alternate setting unavailable")?;
        for endpoint in alternate.endpoint_descriptors() {
            ensure!(
                endpoint.max_packet_size() > 0,
                "Invalid USB endpoint packet size"
            );
            ensure!(
                endpoint.transfer_type() != TransferType::Isochronous,
                "Isochronous macOS USB export is unsupported"
            );
            io.endpoints.get_mut().unwrap().insert(
                endpoint.address(),
                (endpoint.transfer_type(), endpoint.max_packet_size()),
            );
        }
    }
    let mut wire = protocol::legacy_device(&current)?;
    let version = descriptor.device_version();
    wire[304..306].copy_from_slice(
        &(((version.major() as u16) << 8)
            | ((version.minor() as u16) << 4)
            | version.sub_minor() as u16)
            .to_be_bytes(),
    );
    wire[306] = descriptor.class_code();
    wire[307] = descriptor.sub_class_code();
    wire[308] = descriptor.protocol_code();
    wire[309] = config.number();
    wire[310] = descriptor.num_configurations();
    wire[311] = config.num_interfaces();
    protocol::validate(&wire, &current)?;
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let kernel = std::net::TcpStream::connect(listener.local_addr()?)?;
    let (proxy, peer) = listener.accept()?;
    ensure!(
        peer == kernel.local_addr()?,
        "USB loopback socket ownership mismatch"
    );
    kernel.set_nodelay(true)?;
    proxy.set_nodelay(true)?;
    kernel.set_nonblocking(true)?;
    proxy.set_nonblocking(true)?;
    let kernel = tokio::net::TcpStream::from_std(kernel)?;
    let stream = tokio::net::TcpStream::from_std(proxy)?;
    let cancel = CancellationToken::new();
    let task = tokio::spawn(userspace::serve(
        kernel,
        Arc::new(io),
        ((current.busnum as u32) << 16) | current.devnum as u32,
        cancel.clone(),
    ));
    Ok((Handoff { cancel, task }, stream, current, wire))
}
