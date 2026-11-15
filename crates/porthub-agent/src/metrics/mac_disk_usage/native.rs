//! Bounded native macOS filesystem metadata; no volume contents or SMART access.
use super::*;
use core_foundation::{
    array::CFArray,
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::CFDictionary,
    number::CFNumber,
    propertylist,
    string::CFString,
};
use serde_json::{json, Value};
use std::{
    ffi::{c_char, c_void, CString},
    time::{Duration, Instant},
};
fn convert(value: &CFType, depth: usize) -> Value {
    if depth > 12 {
        return Value::Null;
    }
    if let Some(value) = value.downcast::<CFString>() {
        return json!(value.to_string());
    }
    if let Some(value) = value.downcast::<CFBoolean>() {
        return json!(bool::from(value));
    }
    if let Some(value) = value.downcast::<CFNumber>() {
        return value.to_i64().map(|v| json!(v)).unwrap_or(Value::Null);
    }
    if let Some(value) = value.downcast::<CFArray>() {
        return Value::Array(
            value
                .iter()
                .take(1024)
                .map(|v| convert(&unsafe { CFType::wrap_under_get_rule(*v) }, depth + 1))
                .collect(),
        );
    }
    if let Some(value) = value.downcast::<CFDictionary>() {
        let (keys, values) = value.get_keys_and_values();
        let mut out = serde_json::Map::new();
        for (key, value) in keys.into_iter().zip(values).take(1024) {
            let key = unsafe { CFType::wrap_under_get_rule(key) };
            if let Some(key) = key.downcast::<CFString>() {
                out.insert(
                    key.to_string(),
                    convert(&unsafe { CFType::wrap_under_get_rule(value) }, depth + 1),
                );
            }
        }
        return Value::Object(out);
    }
    Value::Null
}
fn plist(args: &[&str]) -> Result<Value, String> {
    use std::{
        io::Read,
        process::{Command, Stdio},
    };
    let mut child = Command::new("/usr/sbin/diskutil")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Native storage inventory is unavailable")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Native storage output unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(262145).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(3);
    let success = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| "Native storage output unavailable")?
        .map_err(|_| "Native storage output unavailable")?;
    if !success || bytes.len() > 262144 {
        return Err("Native storage query timed out or exceeded its limit".into());
    }
    let (raw, _) = propertylist::create_with_data(CFData::from_buffer(&bytes), 0)
        .map_err(|_| "Invalid native storage inventory")?;
    let root = unsafe { CFType::wrap_under_create_rule(raw) };
    Ok(convert(&root, 0))
}
#[link(name = "IOKit", kind = "framework")]
extern "C" {
    fn IOBSDNameMatching(port: u32, options: u32, name: *const c_char) -> *mut c_void;
    fn IOServiceGetMatchingService(port: u32, matching: *mut c_void) -> u32;
    fn IOObjectRelease(object: u32) -> i32;
    fn IOObjectConformsTo(object: u32, class: *const c_char) -> bool;
    fn IORegistryEntryGetChildIterator(entry: u32, plane: *const c_char, iterator: *mut u32)
        -> i32;
    fn IOIteratorNext(iterator: u32) -> u32;
    fn IORegistryEntryGetName(entry: u32, name: *mut c_char) -> i32;
    fn IORegistryEntryGetRegistryEntryID(entry: u32, id: *mut u64) -> i32;
    fn IORegistryEntryCreateCFProperty(
        entry: u32,
        key: *const c_void,
        allocator: *const c_void,
        options: u32,
    ) -> *const c_void;
}
struct Object(u32);
impl Drop for Object {
    fn drop(&mut self) {
        unsafe {
            IOObjectRelease(self.0);
        }
    }
}
fn string(entry: u32, key: &str) -> Option<String> {
    let key = CFString::new(key);
    let raw = unsafe {
        IORegistryEntryCreateCFProperty(
            entry,
            key.as_concrete_TypeRef().cast(),
            std::ptr::null(),
            0,
        )
    };
    if raw.is_null() {
        return None;
    }
    let value = unsafe { CFType::wrap_under_create_rule(raw.cast()) };
    value.downcast::<CFString>().map(|value| value.to_string())
}
fn identify(bsd: &str, partitions: &[String]) -> (String, String) {
    use sha2::{Digest, Sha256};
    let mut identity = None;
    let mut display = "Physical drive".to_owned();
    let mut instance = 0u64;
    if let Ok(name) = CString::new(bsd) {
        let dictionary = unsafe { IOBSDNameMatching(0, 0, name.as_ptr()) };
        if !dictionary.is_null() {
            let entry = unsafe { IOServiceGetMatchingService(0, dictionary) };
            if entry != 0 {
                let object = Object(entry);
                let mut buffer = [0i8; 128];
                if unsafe { IORegistryEntryGetName(object.0, buffer.as_mut_ptr()) } == 0 {
                    let bytes = buffer
                        .iter()
                        .take_while(|v| **v != 0)
                        .map(|v| *v as u8)
                        .collect::<Vec<_>>();
                    if let Ok(value) = String::from_utf8(bytes) {
                        if !value.is_empty() {
                            display = value;
                        }
                    }
                }
                unsafe {
                    IORegistryEntryGetRegistryEntryID(object.0, &mut instance);
                }
                let mut iterator = 0;
                if unsafe {
                    IORegistryEntryGetChildIterator(
                        object.0,
                        b"IOService\0".as_ptr().cast(),
                        &mut iterator,
                    )
                } == 0
                    && iterator != 0
                {
                    let iterator = Object(iterator);
                    for _ in 0..128 {
                        let child = unsafe { IOIteratorNext(iterator.0) };
                        if child == 0 {
                            break;
                        }
                        let child = Object(child);
                        if unsafe {
                            IOObjectConformsTo(child.0, b"IOGUIDPartitionScheme\0".as_ptr().cast())
                        } {
                            identity = string(child.0, "UUID")
                                .filter(|v| !v.is_empty())
                                .map(|uuid| format!("partition-table:{uuid}"));
                        }
                    }
                }
            }
        }
    }
    let raw = identity.unwrap_or_else(|| {
        if !partitions.is_empty() {
            format!("partition-uuids:{}", partitions.join(":"))
        } else if instance != 0 {
            format!("native-media-instance:{instance}")
        } else {
            format!("native-bsd:{bsd}")
        }
    });
    (
        format!("mac-physical:{:x}", Sha256::digest(raw.as_bytes())),
        display,
    )
}
pub(super) fn snapshot() -> Option<Snapshot> {
    let physical = plist(&["list", "-plist", "physical"]).ok()?;
    let apfs = plist(&["apfs", "list", "-plist"]).ok();
    parse(&physical, apfs.as_ref(), identify)
}
fn text(bytes: &[c_char]) -> String {
    let bytes = bytes
        .iter()
        .take_while(|v| **v != 0)
        .map(|v| *v as u8)
        .collect::<Vec<_>>();
    String::from_utf8_lossy(&bytes).into_owned()
}
pub(super) fn mounts() -> Option<Vec<Mount>> {
    unsafe {
        let count = libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT);
        if count <= 0 || count > 1008 {
            return None;
        }
        let capacity = count as usize + 16;
        let mut rows: Vec<libc::statfs> = (0..capacity).map(|_| std::mem::zeroed()).collect();
        let count = libc::getfsstat(
            rows.as_mut_ptr(),
            (rows.len() * std::mem::size_of::<libc::statfs>()) as i32,
            libc::MNT_NOWAIT,
        );
        if count < 0 || count as usize >= capacity {
            return None;
        }
        let mut mounts = Vec::new();
        for row in rows.into_iter().take(count as usize) {
            let source = text(&row.f_mntfromname);
            let Some(source) = source.strip_prefix("/dev/").filter(|v| bsd(v)) else {
                continue;
            };
            let total = row.f_blocks.checked_mul(row.f_bsize as u64)?;
            let free = row.f_bavail.checked_mul(row.f_bsize as u64)?;
            if total > i64::MAX as u64 || free > total {
                return None;
            }
            mounts.push(Mount {
                bsd: source.into(),
                used: total - free,
                total,
            });
        }
        Some(mounts)
    }
}
