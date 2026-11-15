//! Apple storage drivers expose an OS SMART assessment through diskutil. The
//! property list is decoded with native CoreFoundation; missing detailed wear,
//! counters and self-test support remain unavailable rather than invented.
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
fn info(path: &Path) -> Result<Value, String> {
    let id = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Invalid native drive identity")?;
    if !id
        .strip_prefix("disk")
        .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("Invalid physical drive identity".into());
    }
    plist(&["info", "-plist", id])
}
pub(super) fn inventory() -> Vec<Device> {
    let Ok(list) = plist(&["list", "-plist", "physical"]) else {
        return Vec::new();
    };
    list["AllDisksAndPartitions"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_DRIVES)
        .filter_map(|row| {
            let path = Path::new("/dev").join(row["DeviceIdentifier"].as_str()?);
            let data = info(&path).ok()?;
            let name = data["MediaName"].as_str().unwrap_or("Physical drive");
            let serial = data["SerialNumber"]
                .as_str()
                .or_else(|| data["DeviceTreePath"].as_str())
                .unwrap_or("");
            let capacity = data["IOKitSize"]
                .as_u64()
                .or_else(|| data["TotalSize"].as_u64())
                .or_else(|| row["Size"].as_u64())?;
            Some(Device::new(path, name, serial, "os_smart", capacity))
        })
        .collect()
}
pub(super) fn probe(device: &Device) -> Result<Reading, String> {
    let data = info(&device.path)?;
    match data["SMARTStatus"].as_str() {
        Some("Verified") => Ok(Reading {
            self_test: "unsupported".into(),
            ..Default::default()
        }),
        Some("Failing") | Some("Failure") => Ok(Reading {
            critical: true,
            self_test: "unsupported".into(),
            reasons: vec!["The native storage driver reports SMART failure".into()],
            ..Default::default()
        }),
        _ => Err("The native storage driver does not provide SMART health".into()),
    }
}
pub(super) fn short_test(_: &Device, _: &Reading) -> Result<(), String> {
    Err("The native Apple storage driver does not expose short self-tests".into())
}
