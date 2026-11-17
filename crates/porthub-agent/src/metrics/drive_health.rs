//! Bounded physical-drive inventory and native SMART checks. No filesystem data
//! is read or written, no repairs are attempted, and short tests run only idle.
use porthub_components::metrics::{DriveHealth, DriveStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const PROBE_INTERVAL: Duration = Duration::from_secs(30 * 60);
const INVENTORY_INTERVAL: Duration = Duration::from_secs(60);
const WEEK: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_DRIVES: usize = 64;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", test))]
mod macos_reading;
#[cfg(windows)]
mod windows;
#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;
#[cfg(windows)]
use windows as platform;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::*;
    pub(super) fn inventory() -> Vec<Device> {
        Vec::new()
    }
    pub(super) fn probe(_: &Device) -> Result<Reading, String> {
        Err("Native SMART access is unavailable on this platform".into())
    }
    pub(super) fn short_test(_: &Device, _: &Reading, _: &dyn Fn() -> bool) -> Result<(), String> {
        Err("Native short self-test unavailable".into())
    }
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}
fn text(value: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in value.trim().chars().filter(|c| !c.is_control()) {
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(ch);
    }
    out
}
#[derive(Clone)]
struct Device {
    path: PathBuf,
    id: String,
    name: String,
    model: String,
    serial: String,
    #[cfg(target_os = "linux")]
    native: Option<std::sync::Arc<platform::Binding>>,
    protocol: String,
    capacity: u64,
    busy_counter: Option<u64>,
    asleep: bool,
    in_use: bool,
}
impl Device {
    fn new(path: PathBuf, model: &str, serial: &str, protocol: &str, capacity: u64) -> Self {
        // A path is only the fallback for devices that expose no serial/WWN.
        let identity = if serial.trim().is_empty() {
            format!("{}:{}:{}", path.display(), model, capacity)
        } else {
            format!("{}:{}:{}", protocol, model, serial.trim())
        };
        Self {
            path,
            id: format!("{:x}", Sha256::digest(identity.as_bytes())),
            name: text(model, 120),
            model: model.trim().to_owned(),
            serial: serial.trim().to_owned(),
            #[cfg(target_os = "linux")]
            native: None,
            protocol: protocol.into(),
            capacity: capacity.min(i64::MAX as u64),
            busy_counter: None,
            asleep: false,
            in_use: false,
        }
    }
    fn same_identity(&self, other: &Self) -> bool {
        self.id == other.id
            && self.path == other.path
            && self.model == other.model
            && self.serial == other.serial
            && self.capacity == other.capacity
            && self.protocol == other.protocol
    }
    fn same_observation(&self, other: &Self) -> bool {
        if !self.same_identity(other) {
            return false;
        }
        #[cfg(target_os = "linux")]
        if self.native.as_deref() != other.native.as_deref() {
            return false;
        }
        true
    }
    fn complete_test_identity(&self) -> bool {
        !self.serial.is_empty() && !self.model.is_empty() && self.capacity > 0
    }
    fn empty(&self, at: i64) -> DriveHealth {
        DriveHealth {
            id: self.id.clone(),
            name: if self.name.is_empty() {
                "Drive".into()
            } else {
                self.name.clone()
            },
            protocol: self.protocol.clone(),
            capacity: self.capacity,
            present: true,
            status: DriveStatus::Unavailable,
            observed_at: at,
            checked_at: None,
            temperature: None,
            percentage_used: None,
            available_spare: None,
            spare_threshold: None,
            power_on_hours: None,
            power_cycles: None,
            unsafe_shutdowns: None,
            media_errors: None,
            reallocated_sectors: None,
            pending_sectors: None,
            uncorrectable_sectors: None,
            reported_uncorrectable_errors: None,
            lifetime_read_bytes: None,
            lifetime_written_bytes: None,
            short_test_supported: false,
            self_test: "unsupported".into(),
            last_test_started: None,
            next_test_at: None,
            reasons: Vec::new(),
        }
    }
}
#[derive(Clone, Default)]
struct Reading {
    temperature: Option<f32>,
    percentage_used: Option<u8>,
    available_spare: Option<u8>,
    spare_threshold: Option<u8>,
    power_on_hours: Option<u64>,
    power_cycles: Option<u64>,
    unsafe_shutdowns: Option<u64>,
    media_errors: Option<u64>,
    reallocated_sectors: Option<u64>,
    pending_sectors: Option<u64>,
    uncorrectable_sectors: Option<u64>,
    reported_uncorrectable_errors: Option<u64>,
    lifetime_read_bytes: Option<u64>,
    lifetime_written_bytes: Option<u64>,
    short_test_supported: bool,
    self_test: String,
    reasons: Vec<String>,
    critical: bool,
}
impl Reading {
    fn apply(&self, device: &Device, at: i64) -> DriveHealth {
        let mut out = device.empty(at);
        out.checked_at = Some(at);
        out.temperature = self.temperature;
        out.percentage_used = self.percentage_used;
        out.available_spare = self.available_spare;
        out.spare_threshold = self.spare_threshold;
        out.power_on_hours = self.power_on_hours;
        out.power_cycles = self.power_cycles;
        out.unsafe_shutdowns = self.unsafe_shutdowns;
        out.media_errors = self.media_errors;
        out.reallocated_sectors = self.reallocated_sectors;
        out.pending_sectors = self.pending_sectors;
        out.uncorrectable_sectors = self.uncorrectable_sectors;
        out.reported_uncorrectable_errors = self.reported_uncorrectable_errors;
        out.lifetime_read_bytes = self.lifetime_read_bytes;
        out.lifetime_written_bytes = self.lifetime_written_bytes;
        out.short_test_supported = self.short_test_supported;
        out.self_test = if self.self_test.is_empty() {
            "not_run".into()
        } else {
            self.self_test.clone()
        };
        out.reasons = self.reasons.iter().take(8).map(|s| text(s, 160)).collect();
        out.status = if self.critical || self.self_test == "failed" {
            DriveStatus::Critical
        } else if !out.reasons.is_empty() {
            DriveStatus::Warning
        } else {
            DriveStatus::Healthy
        };
        out
    }
}
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Schedule {
    #[serde(default)]
    started: BTreeMap<String, i64>,
    #[serde(default)]
    reserved: BTreeMap<String, i64>,
}
impl Schedule {
    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 16384 {
            return Err("Short-test schedule exceeds bound".into());
        }
        let schedule: Self =
            serde_json::from_slice(bytes).map_err(|_| "Invalid short-test schedule")?;
        if schedule.started.len() + schedule.reserved.len() > 128
            || schedule
                .started
                .iter()
                .chain(&schedule.reserved)
                .any(|(id, at)| {
                    id.len() != 64
                        || !id
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        || *at <= 0
                })
        {
            return Err("Invalid short-test schedule entries".into());
        }
        Ok(schedule)
    }
    fn load(path: &Path) -> Result<Self, String> {
        match crate::profile::read_private(path) {
            Ok(bytes) => Self::decode(&bytes),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                Ok(Self::default())
            }
            Err(_) => Err("Short-test schedule cannot be read securely".into()),
        }
    }
    fn last_attempt(&self, id: &str) -> Option<i64> {
        self.started
            .get(id)
            .into_iter()
            .chain(self.reserved.get(id))
            .copied()
            .max()
    }
    fn encode(&self) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(self).map_err(|_| "Cannot encode short-test schedule")?;
        Self::decode(&bytes)?;
        Ok(bytes)
    }
}
fn idle_for_test(cpu: f32, current: Option<u64>, previous: Option<u64>) -> bool {
    (0.0..35.0).contains(&cpu)
        && current
            .zip(previous)
            .and_then(|(new, old)| new.checked_sub(old))
            .is_some_and(|delta| delta <= 4 * 1024 * 1024)
}
// Shared production transaction: persistence failure cannot invoke the mutating
// backend. Retain a durable reservation even when policy revokes/start fails.
fn reserve_and_start(
    schedule: &mut Schedule,
    id: &str,
    at: i64,
    mut persist: impl FnMut(&[u8]) -> Result<(), String>,
    allowed: impl FnOnce() -> bool,
    start: impl FnOnce() -> Result<(), String>,
) -> Result<bool, String> {
    if at <= 0
        || schedule
            .last_attempt(id)
            .is_some_and(|last| at < last.saturating_add(WEEK))
    {
        return Ok(false);
    }
    let mut next = schedule.clone();
    // Old completed cooldowns need not grow the bounded hardware-history file.
    next.started
        .retain(|_, last| last.saturating_add(WEEK) > at);
    next.reserved
        .retain(|_, last| last.saturating_add(WEEK) > at);
    next.reserved.insert(id.to_owned(), at);
    persist(&next.encode()?)?;
    *schedule = next;
    if !allowed() {
        return Err("Short self-tests disabled locally".into());
    }
    start()?;
    schedule.started.insert(id.to_owned(), at);
    // The PRE-start reservation already protects restart cooldown if this later
    // informational completion write fails. Never erase it on failure.
    if persist(&schedule.encode()?).is_err() {
        tracing::warn!(
            "Short-test start recorded by durable reservation; completion metadata unavailable"
        );
    }
    Ok(true)
}
fn scheduled_short_test(
    path: &Path,
    device: &Device,
    reading: &Reading,
    at: i64,
) -> Result<bool, String> {
    let schedule_path = crate::profile::sibling(path, ".drive-health-schedule.json");
    let lock = crate::profile::sibling(path, ".drive-health-schedule.lock");
    let _lease =
        crate::profile::Lease::acquire(&lock).map_err(|_| "Short-test scheduler already owned")?;
    let mut schedule = Schedule::load(&schedule_path)?;
    let allowed = || {
        use crate::features::{enabled, Feature};
        enabled(path, Feature::Metrics)
            && enabled(path, Feature::DriveHealth)
            && enabled(path, Feature::DriveTests)
    };
    reserve_and_start(
        &mut schedule,
        &device.id,
        at,
        |bytes| {
            crate::profile::write_private(&schedule_path, bytes, true)
                .map_err(|_| "Cannot persist short-test reservation".into())
        },
        &allowed,
        || platform::short_test(device, reading, &allowed),
    )
}
struct Entry {
    device: Device,
    snapshot: DriveHealth,
    due: Instant,
    last_counter: Option<u64>,
}
pub(super) struct Collector {
    entries: BTreeMap<String, Entry>,
    inventory_due: Instant,
    schedule: Schedule,
    schedule_valid: bool,
    schedule_path: PathBuf,
    profile: PathBuf,
    next_test: Instant,
}
impl Collector {
    pub fn new(profile: &Path) -> Self {
        let schedule_path = crate::profile::sibling(profile, ".drive-health-schedule.json");
        // Corrupt/inaccessible state blocks tests; never silently reset a clock.
        let loaded = Schedule::load(&schedule_path);
        let schedule_valid = loaded.is_ok();
        let schedule = loaded.unwrap_or_default();
        Self {
            entries: BTreeMap::new(),
            inventory_due: Instant::now(),
            schedule,
            schedule_valid,
            schedule_path,
            profile: profile.to_owned(),
            next_test: Instant::now(),
        }
    }
    /// Called from the existing metrics worker. At most one device is probed per
    /// tick; native IO runs off the async runtime. Linux command timeouts are
    /// explicit; synchronous Windows storage IO still depends on driver completion.
    pub async fn sample(&mut self, cpu: f32, tests_enabled: bool) -> Vec<DriveHealth> {
        let instant = Instant::now();
        let at = now();
        if instant >= self.inventory_due {
            let devices = tokio::task::spawn_blocking(platform::inventory)
                .await
                .unwrap_or_default();
            self.reconcile(devices, at, instant);
            self.inventory_due = instant + INVENTORY_INTERVAL;
        }
        let due = self
            .entries
            .iter()
            .find(|(_, e)| e.snapshot.present && e.due <= instant)
            .map(|(id, _)| id.clone());
        if let Some(id) = due {
            if let Some(entry) = self.entries.get_mut(&id) {
                entry.due = instant + PROBE_INTERVAL;
                let device = entry.device.clone();
                if device.in_use {
                    entry.snapshot = device.empty(at);
                    entry.snapshot.reasons.push(
                        "USB device is forwarded; inspect SMART on its receiving host".into(),
                    );
                } else if device.asleep {
                    entry.snapshot.observed_at = at;
                    if !matches!(
                        entry.snapshot.status,
                        DriveStatus::Critical | DriveStatus::Warning
                    ) {
                        entry.snapshot.status = DriveStatus::Sleeping;
                    }
                    entry.snapshot.reasons.truncate(7);
                    entry
                        .snapshot
                        .reasons
                        .push("Drive is sleeping; checks resume when it wakes".into());
                } else {
                    let probed =
                        tokio::task::spawn_blocking(move || platform::probe(&device)).await;
                    match probed {
                        Ok(Ok(reading)) => {
                            let started = self
                                .schedule
                                .started
                                .get(&id)
                                .copied()
                                .filter(|value| *value > 0);
                            let first_due = self
                                .schedule
                                .last_attempt(&id)
                                .unwrap_or(0)
                                .saturating_add(WEEK);
                            let idle =
                                idle_for_test(cpu, entry.device.busy_counter, entry.last_counter);
                            entry.snapshot = reading.apply(&entry.device, at);
                            entry.snapshot.last_test_started = started;
                            if reading.short_test_supported {
                                if !self.schedule_valid {
                                    entry.snapshot.reasons.push(
                                        "Short tests blocked by invalid or inaccessible schedule"
                                            .into(),
                                    );
                                }
                                entry.snapshot.next_test_at = Some(first_due.max(at));
                                if tests_enabled
                                    && self.schedule_valid
                                    && at >= first_due
                                    && instant >= self.next_test
                                    && reading.self_test != "running"
                                {
                                    if !idle {
                                        entry.snapshot.self_test = "deferred".into();
                                        entry.snapshot.next_test_at = Some(at + 30 * 60 * 1000);
                                        entry.due = instant + Duration::from_secs(30 * 60);
                                    } else {
                                        let device = entry.device.clone();
                                        let profile = self.profile.clone();
                                        let result = tokio::task::spawn_blocking(move || {
                                            scheduled_short_test(&profile, &device, &reading, at)
                                        })
                                        .await;
                                        // Reload exact durable state even on failed/revoked start.
                                        match Schedule::load(&self.schedule_path) {
                                            Ok(schedule) => self.schedule = schedule,
                                            Err(_) => self.schedule_valid = false,
                                        }
                                        if matches!(result, Ok(Ok(true))) {
                                            entry.snapshot.last_test_started = Some(at);
                                            entry.snapshot.next_test_at =
                                                Some(at.saturating_add(WEEK));
                                            entry.snapshot.self_test = "running".into();
                                            entry.due = instant + Duration::from_secs(120);
                                            self.next_test = instant + Duration::from_secs(10 * 60);
                                        } else {
                                            entry.snapshot.self_test = "deferred".into();
                                            entry.snapshot.reasons.push("Short test deferred; identity, policy or durable schedule unavailable".into());
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Err(reason)) if reason.contains("standby") => {
                            if !matches!(
                                entry.snapshot.status,
                                DriveStatus::Critical | DriveStatus::Warning
                            ) {
                                entry.snapshot.status = DriveStatus::Sleeping;
                            }
                            entry.snapshot.observed_at = at;
                            entry.snapshot.reasons =
                                vec!["Drive is sleeping; checks resume when it wakes".into()];
                        }
                        _ => {
                            entry.snapshot = entry.device.empty(at);
                            entry.snapshot.checked_at = Some(at);
                            entry.snapshot.reasons.push("SMART is unsupported, unavailable, or requires native device permission".into());
                        }
                    }
                }
            }
        }
        self.entries
            .values()
            .take(MAX_DRIVES)
            .map(|e| e.snapshot.clone())
            .collect()
    }
    fn reconcile(&mut self, devices: Vec<Device>, at: i64, instant: Instant) {
        let mut present = HashSet::new();
        for device in devices.into_iter().take(MAX_DRIVES) {
            present.insert(device.id.clone());
            if let Some(entry) = self.entries.get_mut(&device.id) {
                // Compare BEFORE replacing the cached witness. Stable hardware IDs
                // do not authorize reusing old health after a move/replug/resize.
                let changed = !entry.device.same_observation(&device);
                entry.last_counter = if changed {
                    None
                } else {
                    entry.device.busy_counter
                };
                entry.device = device;
                if changed || !entry.snapshot.present {
                    entry.snapshot = entry.device.empty(at);
                    entry.due = instant;
                } else if entry.snapshot.status == DriveStatus::Sleeping && !entry.device.asleep {
                    entry.due = instant;
                }
            } else {
                self.entries.insert(
                    device.id.clone(),
                    Entry {
                        snapshot: device.empty(at),
                        device,
                        due: instant,
                        last_counter: None,
                    },
                );
            }
        }
        for (id, entry) in &mut self.entries {
            if !present.contains(id) && entry.snapshot.present {
                entry.snapshot.present = false;
                entry.snapshot.status = DriveStatus::Removed;
                entry.snapshot.observed_at = at;
                entry.snapshot.reasons = vec!["Drive removed from this machine".into()];
                entry.snapshot.next_test_at = None;
                #[cfg(target_os = "linux")]
                {
                    entry.device.native = None;
                }
            }
        }
        // Keep a bounded set of recent removed-drive tombstones. Historical snapshots
        // remain on the gateway after their local tombstone has aged out.
        while self.entries.len() > MAX_DRIVES {
            let id = self
                .entries
                .iter()
                .filter(|(_, e)| !e.snapshot.present)
                .min_by_key(|(_, e)| e.snapshot.observed_at)
                .map(|(id, _)| id.clone());
            if let Some(id) = id {
                self.entries.remove(&id);
            } else {
                break;
            }
        }
    }
}
/// SMART device operations have a separate task and cache: slow storage or a
/// missing native utility must never suppress ordinary CPU/RAM/disk telemetry.
pub(super) struct Worker {
    snapshots: tokio::sync::watch::Receiver<Vec<DriveHealth>>,
    cpu: tokio::sync::watch::Sender<f32>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Worker {
    pub fn start(path: PathBuf, cancel: tokio_util::sync::CancellationToken) -> Self {
        let (snapshots, receiver) = tokio::sync::watch::channel(Vec::new());
        let (cpu, cpu_reader) = tokio::sync::watch::channel(100.);
        let task = tokio::spawn(async move {
            let mut policy = crate::features::subscribe(&path);
            let mut collector = Collector::new(&path);
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {_=cancel.cancelled()=>break,_=tick.tick()=>{},changed=policy.changed()=>if changed.is_err(){break;}}
                let enabled = policy.borrow().enabled(crate::features::Feature::Metrics)
                    && policy
                        .borrow()
                        .enabled(crate::features::Feature::DriveHealth);
                if !enabled {
                    snapshots.send_replace(Vec::new());
                    continue;
                }
                let usage = *cpu_reader.borrow();
                let tests = policy
                    .borrow()
                    .enabled(crate::features::Feature::DriveTests);
                let readings = tokio::select! {_=cancel.cancelled()=>break,readings=collector.sample(usage,tests)=>readings};
                if crate::features::enabled(&path, crate::features::Feature::Metrics)
                    && crate::features::enabled(&path, crate::features::Feature::DriveHealth)
                {
                    snapshots.send_replace(readings);
                }
            }
        });
        Self {
            snapshots: receiver,
            cpu,
            task,
        }
    }
    pub fn cpu(&self, value: f32) {
        self.cpu.send_replace(value);
    }
    pub fn snapshot(&self) -> Vec<DriveHealth> {
        self.snapshots
            .borrow()
            .iter()
            .filter(|s| s.valid())
            .cloned()
            .collect()
    }
}
fn counter(data: &[u8]) -> u64 {
    if data.iter().skip(8).any(|b| *b != 0) {
        i64::MAX as u64
    } else {
        let mut bytes = [0; 8];
        for (a, b) in bytes.iter_mut().zip(data) {
            *a = *b;
        }
        u64::from_le_bytes(bytes).min(i64::MAX as u64)
    }
}
fn nvme_bytes(data: &[u8]) -> Option<u64> {
    let units = u128::from_le_bytes(data.try_into().ok()?);
    let bytes = units.checked_mul(512_000)?;
    (units > 0 && bytes <= i64::MAX as u128).then_some(bytes as u64)
}
fn valid_ata_sector(data: &[u8]) -> bool {
    data.len() == 512
        && data.iter().any(|b| *b != 0)
        && data.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0
}
fn nvme(data: &[u8]) -> Result<Reading, String> {
    if data.len() < 512 || data.iter().all(|b| *b == 0) {
        return Err("Incomplete NVMe health log".into());
    }
    let kelvin = u16::from_le_bytes([data[1], data[2]]);
    let mut reading = Reading {
        temperature: (kelvin > 0)
            .then_some(kelvin as f32 - 273.15)
            .filter(|v| (-40.0..=150.0).contains(v)),
        percentage_used: Some(data[5]),
        available_spare: (data[3] <= 100).then_some(data[3]),
        spare_threshold: (data[4] <= 100).then_some(data[4]),
        power_on_hours: Some(counter(&data[128..144])),
        power_cycles: Some(counter(&data[112..128])),
        unsafe_shutdowns: Some(counter(&data[144..160])),
        media_errors: Some(counter(&data[160..176])),
        lifetime_read_bytes: nvme_bytes(&data[32..48]),
        lifetime_written_bytes: nvme_bytes(&data[48..64]),
        ..Default::default()
    };
    if data[0] & 0xfd != 0 {
        reading.critical = true;
        reading
            .reasons
            .push(format!("NVMe critical warning flags: 0x{:02x}", data[0]));
    }
    if data[0] & 2 != 0 || reading.temperature.is_some_and(|v| v >= 70.) {
        reading.reasons.push("Drive temperature is elevated".into());
    }
    if data[5] >= 100 {
        reading.critical = true;
        reading
            .reasons
            .push("Rated SSD endurance has been used".into());
    } else if data[5] >= 90 {
        reading
            .reasons
            .push("SSD is nearing its rated endurance".into());
    }
    if reading
        .available_spare
        .zip(reading.spare_threshold)
        .is_some_and(|(spare, threshold)| spare < threshold)
    {
        reading.critical = true;
        reading
            .reasons
            .push("Available spare is below the drive threshold".into());
    }
    if reading.media_errors.is_some_and(|n| n > 0) {
        reading
            .reasons
            .push("Media or data-integrity errors recorded".into());
    }
    Ok(reading)
}
fn ata(data: &[u8], thresholds: Option<&[u8]>, log: Option<&[u8]>) -> Result<Reading, String> {
    if data.len() != 512
        || data.iter().all(|b| *b == 0)
        || data.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) != 0
    {
        return Err("Incomplete or corrupt ATA SMART data".into());
    }
    if !data[2..362].chunks_exact(12).any(|a| a[0] != 0 && a[3] > 0) {
        return Err("ATA bridge returned no usable SMART attributes".into());
    }
    let mut out = Reading {
        short_test_supported: data[367] & 0x10 != 0,
        self_test: if data[363] >> 4 == 15 {
            "running".into()
        } else {
            "not_run".into()
        },
        ..Default::default()
    };
    for attr in data[2..362].chunks_exact(12) {
        let id = attr[0];
        if id == 0 {
            continue;
        }
        let raw = counter(&attr[5..11]);
        match id {
            5 => out.reallocated_sectors = Some(raw),
            9 => out.power_on_hours = Some(raw),
            12 => out.power_cycles = Some(raw),
            194 | 190 => {
                let temp = attr[5] as f32;
                if temp <= 150. {
                    out.temperature = Some(temp);
                }
            }
            187 => out.reported_uncorrectable_errors = Some(raw),
            197 => out.pending_sectors = Some(raw),
            198 => out.uncorrectable_sectors = Some(raw),
            _ => {}
        }
        if let Some(limit) = thresholds
            .filter(|t| valid_ata_sector(t))
            .and_then(|t| t[2..362].chunks_exact(12).find(|a| a[0] == id))
            .map(|t| t[1])
            .filter(|n| *n > 0)
        {
            if attr[3] <= limit {
                out.critical = true;
                out.reasons
                    .push(format!("SMART attribute {id} crossed its drive threshold"));
            }
        }
    }
    for (value, label) in [
        (
            out.reported_uncorrectable_errors,
            "Historical uncorrectable command errors recorded; inspect changes over time",
        ),
        (out.reallocated_sectors, "Reallocated sectors recorded"),
        (out.pending_sectors, "Pending sectors need attention"),
        (out.uncorrectable_sectors, "Uncorrectable sectors recorded"),
    ] {
        if value.is_some_and(|v| v > 0) {
            out.reasons.push(label.into());
        }
    }
    if out.temperature.is_some_and(|v| v >= 60.) {
        out.reasons.push("Drive temperature is elevated".into());
    }
    if let Some(log) = log.filter(|b| valid_ata_sector(b) && out.self_test != "running") {
        let index = log[508] as usize;
        if (1..=21).contains(&index) {
            let status = log[2 + (index - 1) * 24 + 1] >> 4;
            out.self_test = match status {
                0 => "passed",
                1 | 2 => "aborted",
                15 => "running",
                _ => "failed",
            }
            .into();
        }
    }
    out.reasons.truncate(8);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn device(serial: &str) -> Device {
        Device::new("/dev/fixture".into(), "Fixture drive", serial, "nvme", 1024)
    }
    #[test]
    fn nvme_endurance_media_and_spare_are_not_silently_healthy() {
        let mut bytes = [0; 512];
        bytes[1..3].copy_from_slice(&310u16.to_le_bytes());
        bytes[3] = 100;
        bytes[4] = 10;
        bytes[5] = 3;
        let healthy = nvme(&bytes).unwrap().apply(&device("serial-a"), 1);
        assert_eq!(healthy.status, DriveStatus::Healthy);
        assert!(healthy.valid());
        bytes[5] = 92;
        let warning = nvme(&bytes).unwrap().apply(&device("serial-a"), 1);
        assert_eq!(warning.status, DriveStatus::Warning);
        bytes[3] = 5;
        let critical = nvme(&bytes).unwrap().apply(&device("serial-a"), 1);
        assert_eq!(critical.status, DriveStatus::Critical);
        bytes[3] = 100;
        bytes[5] = 3;
        bytes[160] = 1;
        let media = nvme(&bytes).unwrap().apply(&device("serial-a"), 1);
        assert_eq!(media.media_errors, Some(1));
        assert_eq!(media.status, DriveStatus::Warning);
        assert!(nvme(&[0; 512]).is_err());
        assert!(nvme(&[1; 32]).is_err());
    }
    fn checksum(bytes: &mut [u8; 512]) {
        bytes[511] = 0;
        bytes[511] = 0u8.wrapping_sub(bytes.iter().fold(0u8, |s, b| s.wrapping_add(*b)));
    }
    #[test]
    fn ata_checks_thresholds_pending_sectors_and_selftest_results() {
        let mut data = [0; 512];
        data[0] = 1;
        data[2] = 197;
        data[5] = 100;
        data[7] = 2;
        data[367] = 0x10;
        checksum(&mut data);
        let warning = ata(&data, None, None).unwrap().apply(&device("ata-a"), 1);
        assert_eq!(warning.pending_sectors, Some(2));
        assert_eq!(warning.status, DriveStatus::Warning);
        assert!(warning.short_test_supported);
        let mut limits = [0; 512];
        limits[2] = 197;
        limits[3] = 110;
        let mut log = [0; 512];
        log[508] = 1;
        log[3] = 0x70;
        checksum(&mut limits);
        checksum(&mut log);
        let failed = ata(&data, Some(&limits), Some(&log))
            .unwrap()
            .apply(&device("ata-a"), 1);
        assert_eq!(failed.status, DriveStatus::Critical);
        assert_eq!(failed.self_test, "failed");
        data[20] = 1;
        assert!(ata(&data, None, None).is_err());
    }
    #[test]
    fn historical_reported_errors_are_warning_not_failed_sectors() {
        let mut data = [0; 512];
        data[0] = 1;
        data[2] = 187;
        data[5] = 98;
        data[7] = 2;
        checksum(&mut data);
        let reading = ata(&data, None, None).unwrap().apply(&device("ata"), 1);
        assert_eq!(reading.reported_uncorrectable_errors, Some(2));
        assert_eq!(reading.uncorrectable_sectors, None);
        assert_eq!(reading.status, DriveStatus::Warning);
        let mut corrupt = [0; 512];
        corrupt[2] = 187;
        corrupt[3] = 99;
        assert!(!ata(&data, Some(&corrupt), Some(&corrupt)).unwrap().critical);
        checksum(&mut corrupt);
        assert!(ata(&data, Some(&corrupt), None).unwrap().critical);
    }
    #[test]
    fn empty_attribute_pages_and_corrupt_optional_blocks_are_not_health_evidence() {
        let mut data = [0; 512];
        data[0] = 1;
        checksum(&mut data);
        assert!(ata(&data, None, None).is_err());
        data[2] = 9;
        data[5] = 100;
        data[7] = 1;
        checksum(&mut data);
        let mut log = [0; 512];
        log[508] = 1;
        log[3] = 0x70;
        assert_eq!(ata(&data, None, Some(&log)).unwrap().self_test, "not_run");
    }
    #[test]
    fn invalid_nvme_spare_values_do_not_invent_a_threshold_failure() {
        let mut data = [0; 512];
        data[1..3].copy_from_slice(&300u16.to_le_bytes());
        data[3] = 100;
        data[4] = 255;
        let reading = nvme(&data).unwrap();
        assert_eq!(reading.spare_threshold, None);
        assert!(!reading.critical);
        data[3] = 255;
        data[4] = 10;
        assert_eq!(nvme(&data).unwrap().available_spare, None);
    }
    #[test]
    fn lifetime_nvme_bytes_are_approximate_bounded_and_zero_is_not_reported() {
        assert_eq!(nvme_bytes(&0u128.to_le_bytes()), None);
        assert_eq!(
            nvme_bytes(&43767976u128.to_le_bytes()),
            Some(22409203712000)
        );
        assert_eq!(nvme_bytes(&u128::MAX.to_le_bytes()), None);
        assert_eq!(nvme_bytes(&(i64::MAX as u128).to_le_bytes()), None);
    }
    #[test]
    fn hotplug_keeps_hardware_identity_and_marks_removed_drive_unknown() {
        let root = tempfile::tempdir().unwrap();
        let mut collector = Collector::new(&root.path().join("profile.json"));
        let at = now();
        let instant = Instant::now();
        let first = device("serial-a");
        let id = first.id.clone();
        collector.reconcile(vec![first], at, instant);
        assert!(collector.entries[&id].snapshot.present);
        collector.reconcile(Vec::new(), at + 1, instant);
        let removed = &collector.entries[&id].snapshot;
        assert!(!removed.present);
        assert_eq!(removed.status, DriveStatus::Removed);
        assert!(removed.valid());
        let mut replugged = device("serial-a");
        replugged.path = "/dev/new-bus-name".into();
        collector.reconcile(vec![replugged], at + 2, instant);
        assert_eq!(collector.entries.len(), 1);
        assert!(collector.entries[&id].snapshot.present);
        assert_eq!(
            collector.entries[&id].snapshot.status,
            DriveStatus::Unavailable
        );
        collector.reconcile(vec![device("replacement-serial")], at + 3, instant);
        assert_eq!(collector.entries.len(), 2);
        assert_eq!(collector.entries[&id].snapshot.status, DriveStatus::Removed);
    }
    #[test]
    fn large_nvme_counters_stay_bson_safe() {
        assert_eq!(counter(&[255; 16]), i64::MAX as u64);
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires native root device access; reads only, never starts a self-test"]
    fn native_readonly_physical_drives() {
        for drive in platform::inventory() {
            if drive.in_use || drive.path == Path::new("/dev/sdb") {
                continue;
            }
            let result = platform::probe(&drive);
            match result {
                Ok(reading) => {
                    let snapshot = reading.apply(&drive, now());
                    assert!(snapshot.valid());
                    println!(
                        "{} {} {} {:?} temperature={:?} wear={:?}",
                        drive.path.display(),
                        drive.name,
                        drive.protocol,
                        snapshot.status,
                        snapshot.temperature,
                        snapshot.percentage_used
                    );
                }
                Err(reason) => println!("{} unavailable: {reason}", drive.path.display()),
            }
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod readonly_hardware_diagnostics {
    use super::*;
    #[test]
    #[ignore = "Explicit read-only hardware health diagnostic; never starts self-tests"]
    fn physical_drive_health_without_self_tests() {
        assert_eq!(
            std::env::var("PORTHUB_SMART_READONLY_PROBE").as_deref(),
            Ok("1"),
            "Explicit read-only probe opt-in required"
        );
        for device in platform::inventory() {
            let at = now();
            let snapshot = if device.in_use {
                let mut value = device.empty(at);
                value
                    .reasons
                    .push("Device currently forwarded; source SMART skipped".into());
                value
            } else if device.asleep {
                let mut value = device.empty(at);
                value.status = DriveStatus::Sleeping;
                value
                    .reasons
                    .push("Drive sleeping; read-only probe did not wake it".into());
                value
            } else {
                match platform::probe(&device) {
                    Ok(reading) => reading.apply(&device, at),
                    Err(error) => {
                        let mut value = device.empty(at);
                        value.reasons.push(error);
                        value
                    }
                }
            };
            println!(
                "{}",
                serde_json::json!({"device":device.path,"health":snapshot})
            );
        }
    }
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    fn id() -> String {
        "a".repeat(64)
    }
    #[test]
    fn reservation_is_durable_before_start_and_survives_restart_and_failed_start() {
        let mut schedule = Schedule::default();
        let bytes = std::cell::RefCell::new(Vec::new());
        let calls = AtomicUsize::new(0);
        let at = WEEK * 2;
        assert!(reserve_and_start(
            &mut schedule,
            &id(),
            at,
            |value| {
                *bytes.borrow_mut() = value.to_vec();
                Ok(())
            },
            || true,
            || {
                let stored = Schedule::decode(&bytes.borrow()).unwrap();
                assert_eq!(stored.reserved.get(&id()), Some(&at));
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        )
        .unwrap());
        let mut restarted = Schedule::decode(&bytes.borrow()).unwrap();
        assert!(!reserve_and_start(
            &mut restarted,
            &id(),
            at + WEEK - 1,
            |_| panic!("early persistence"),
            || true,
            || panic!("early native test")
        )
        .unwrap());
        assert!(reserve_and_start(
            &mut restarted,
            &id(),
            at + WEEK,
            |value| {
                *bytes.borrow_mut() = value.to_vec();
                Ok(())
            },
            || true,
            || Err("native reject".into())
        )
        .is_err());
        let mut restarted = Schedule::decode(&bytes.borrow()).unwrap();
        assert!(!reserve_and_start(
            &mut restarted,
            &id(),
            at + WEEK + 1,
            |_| panic!(),
            || true,
            || panic!()
        )
        .unwrap());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn failed_reservation_or_revoked_policy_never_calls_native_backend() {
        let mut schedule = Schedule::default();
        let at = WEEK * 2;
        assert!(reserve_and_start(
            &mut schedule,
            &id(),
            at,
            |_| Err("disk unavailable".into()),
            || true,
            || panic!("test before durable write")
        )
        .is_err());
        assert!(schedule.last_attempt(&id()).is_none());
        let mut stored = Vec::new();
        assert!(reserve_and_start(
            &mut schedule,
            &id(),
            at,
            |b| {
                stored = b.to_vec();
                Ok(())
            },
            || false,
            || panic!("revoked test started")
        )
        .is_err());
        assert_eq!(
            Schedule::decode(&stored).unwrap().last_attempt(&id()),
            Some(at)
        );
    }
    #[test]
    fn post_start_completion_write_failure_keeps_persisted_reservation() {
        let mut schedule = Schedule::default();
        let mut stored = Vec::new();
        let mut writes = 0;
        let at = WEEK * 2;
        assert!(reserve_and_start(
            &mut schedule,
            &id(),
            at,
            |b| {
                writes += 1;
                if writes == 1 {
                    stored = b.to_vec();
                    Ok(())
                } else {
                    Err("metadata write unavailable".into())
                }
            },
            || true,
            || Ok(())
        )
        .unwrap());
        let mut restarted = Schedule::decode(&stored).unwrap();
        assert!(!reserve_and_start(
            &mut restarted,
            &id(),
            at + 1,
            |_| panic!(),
            || true,
            || panic!()
        )
        .unwrap());
    }
    #[test]
    fn corrupt_oversized_unknown_and_future_schedule_do_not_reset_weekly_clock() {
        for bytes in [
            b"not json".to_vec(),
            vec![b' '; 16385],
            br#"{"started":{},"unknown":1}"#.to_vec(),
            br#"{"started":{"a":-1}}"#.to_vec(),
        ] {
            assert!(Schedule::decode(&bytes).is_err());
        }
        let mut schedule = Schedule::default();
        schedule.started.insert(id(), WEEK * 4);
        assert!(!reserve_and_start(
            &mut schedule,
            &id(),
            WEEK * 2,
            |_| panic!(),
            || true,
            || panic!()
        )
        .unwrap());
        let path =
            std::env::temp_dir().join(format!("porthub-smart-schedule-{}", uuid::Uuid::new_v4()));
        std::fs::write(&path, b"broken").unwrap();
        assert!(Schedule::load(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn only_known_idle_counters_and_low_finite_cpu_admit_tests() {
        assert!(idle_for_test(1., Some(9), Some(9)));
        assert!(idle_for_test(34., Some(4 * 1024 * 1024), Some(0)));
        for (cpu, current, old) in [
            (35., Some(0), Some(0)),
            (f32::NAN, Some(0), Some(0)),
            (1., None, Some(0)),
            (1., Some(0), None),
            (1., Some(0), Some(1)),
            (1., Some(4 * 1024 * 1024 + 1), Some(0)),
        ] {
            assert!(!idle_for_test(cpu, current, old));
        }
    }
    fn assert_cache_invalidated(old: Device, fresh: Device) {
        assert_eq!(
            old.id, fresh.id,
            "Fixture must retain hardware history identity"
        );
        let mut collector = Collector::new(Path::new("/nonexistent/readonly-fixture-profile"));
        let instant = Instant::now();
        let at = WEEK * 2;
        collector.reconcile(vec![old.clone()], at, instant);
        let entry = collector.entries.get_mut(&old.id).unwrap();
        entry.snapshot = Reading::default().apply(&old, at);
        entry.due = instant + PROBE_INTERVAL;
        entry.last_counter = Some(9);
        collector.reconcile(vec![fresh.clone()], at + 1, instant);
        let entry = &collector.entries[&old.id];
        assert_eq!(entry.device.id, old.id);
        assert!(entry.snapshot.present);
        assert_eq!(entry.snapshot.status, DriveStatus::Unavailable);
        assert_eq!(entry.snapshot.checked_at, None);
        assert_eq!(entry.snapshot.capacity, fresh.capacity);
        assert!(entry.due <= instant);
        assert_eq!(entry.last_counter, None);
    }
    #[test]
    fn collector_invalidates_old_health_immediately_when_same_id_moves_or_capacity_changes() {
        let old = Device::new("/dev/old".into(), "model", "stable-serial", "ata", 1024);
        assert_cache_invalidated(
            old.clone(),
            Device::new("/dev/new".into(), "model", "stable-serial", "ata", 1024),
        );
        assert_cache_invalidated(
            old,
            Device::new("/dev/old".into(), "model", "stable-serial", "ata", 2048),
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn collector_invalidates_reused_serialless_node_when_kernel_generation_changes() {
        let mut old = Device::new("/dev/same".into(), "model", "", "ata", 1024);
        old.native = Some(linux::Binding::test_generation(1));
        let mut fresh = old.clone();
        fresh.native = Some(linux::Binding::test_generation(2));
        assert_cache_invalidated(old, fresh);
    }
    #[test]
    fn mutation_requires_complete_serial_model_capacity_identity_but_read_identity_can_be_compared()
    {
        let valid = Device::new("/dev/fixture".into(), "model", "serial", "ata", 1024);
        assert!(valid.complete_test_identity());
        for candidate in [
            Device::new(valid.path.clone(), "model", "", "ata", 1024),
            Device::new(valid.path.clone(), "", "serial", "ata", 1024),
            Device::new(valid.path.clone(), "model", "serial", "ata", 0),
        ] {
            assert!(!candidate.complete_test_identity());
            assert!(candidate.same_identity(&candidate.clone()));
        }
    }
    #[test]
    fn hotplug_reused_path_does_not_retain_old_serial_model_capacity_or_protocol_authority() {
        let old = Device::new("/dev/fixture".into(), "model", "serial", "ata", 1024);
        for changed in [
            Device::new(old.path.clone(), "other", "serial", "ata", 1024),
            Device::new(old.path.clone(), "model", "newserial", "ata", 1024),
            Device::new(old.path.clone(), "model", "serial", "ata", 2048),
            Device::new(old.path.clone(), "model", "serial", "nvme", 1024),
        ] {
            assert!(!old.same_identity(&changed));
        }
        assert!(old.same_identity(&Device::new(
            old.path.clone(),
            "model",
            "serial",
            "ata",
            1024
        )));
    }
}
