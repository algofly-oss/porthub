//! Driver-provided WDDM engine counters. Per-process values are aggregated by
//! engine and the busiest engine is used, matching Windows' GPU usage model.
//! Process IDs and counter instance strings never leave this module.
#[cfg(any(windows, test))]
use std::collections::HashMap;
#[cfg(any(windows, test))]
fn aggregate(values: impl Iterator<Item = (String, f64)>) -> HashMap<u64, f32> {
    let mut engines = HashMap::<(u64, String), f64>::new();
    for (name, value) in values {
        if !value.is_finite() || value < 0. {
            continue;
        }
        let Some(start) = name.find("luid_") else {
            continue;
        };
        let Some(end) = name.find("_engtype_").filter(|n| *n > start) else {
            continue;
        };
        let parts = name[start + 5..end].split('_').collect::<Vec<_>>();
        if parts.len() < 2 {
            continue;
        }
        let hex =
            |part: &str| u32::from_str_radix(part.strip_prefix("0x").unwrap_or(part), 16).ok();
        let Some(luid) = hex(parts[0])
            .zip(hex(parts[1]))
            .map(|(high, low)| ((high as u64) << 32) | low as u64)
        else {
            continue;
        };
        *engines.entry((luid, name[start..end].into())).or_default() += value;
    }
    let mut adapters = HashMap::<u64, f32>::new();
    for ((luid, _), value) in engines {
        let entry = adapters.entry(luid).or_insert(0.);
        *entry = entry.max(value.clamp(0., 100.) as f32);
    }
    adapters
}

#[cfg(any(windows, test))]
#[derive(Default)]
pub(super) struct MemoryReadings {
    pub shared: HashMap<u64, u64>,
    pub dedicated: HashMap<u64, u64>,
}
/// Adapter counters are GLOBAL VidMm measurements, not per-process totals.
/// Never sum GPU Process Memory counters: cross-process surfaces repeat there.
#[cfg(any(windows, test))]
fn memory(values: impl Iterator<Item = (String, f64)>) -> HashMap<u64, u64> {
    use std::collections::HashSet;
    let mut rows = HashMap::<u64, HashMap<u32, u64>>::new();
    let mut invalid = HashSet::new();
    for (name, value) in values {
        let parts = name.split('_').collect::<Vec<_>>();
        if parts.len() != 5 || parts[0] != "luid" || parts[3] != "phys" {
            continue;
        }
        let hex = |s: &str| {
            u32::from_str_radix(
                s.strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s),
                16,
            )
            .ok()
        };
        let Some((high, low)) = hex(parts[1]).zip(hex(parts[2])) else {
            continue;
        };
        let luid = ((high as u64) << 32) | low as u64;
        if parts[4].is_empty() || !parts[4].bytes().all(|b| b.is_ascii_digit()) {
            invalid.insert(luid);
            continue;
        }
        let Ok(physical) = parts[4].parse::<u32>() else {
            invalid.insert(luid);
            continue;
        };
        if !value.is_finite() || value < 0. || value >= i64::MAX as f64 || value.fract() != 0. {
            invalid.insert(luid);
            continue;
        }
        if rows
            .entry(luid)
            .or_default()
            .insert(physical, value as u64)
            .is_some()
        {
            invalid.insert(luid);
        }
    }
    rows.into_iter()
        .filter_map(|(luid, values)| {
            if invalid.contains(&luid) {
                return None;
            }
            values
                .values()
                .try_fold(0u64, |sum, value| {
                    sum.checked_add(*value).filter(|n| *n <= i64::MAX as u64)
                })
                .map(|sum| (luid, sum))
        })
        .collect()
}
#[cfg(windows)]
pub(super) struct Counter {
    query: isize,
    counter: Option<isize>,
    shared: Option<isize>,
    dedicated: Option<isize>,
    memory: MemoryReadings,
    warm: bool,
}
#[cfg(windows)]
#[link(name = "pdh")]
unsafe extern "system" {
    fn PdhOpenQueryW(source: *const u16, user: usize, query: *mut isize) -> i32;
    fn PdhAddEnglishCounterW(
        query: isize,
        path: *const u16,
        user: usize,
        counter: *mut isize,
    ) -> i32;
    fn PdhCollectQueryData(query: isize) -> i32;
    fn PdhGetFormattedCounterArrayW(
        counter: isize,
        format: u32,
        size: *mut u32,
        count: *mut u32,
        items: *mut Item,
    ) -> i32;
    fn PdhCloseQuery(query: isize) -> i32;
}
#[cfg(windows)]
#[repr(C)]
struct Value {
    status: u32,
    value: f64,
}
#[cfg(windows)]
#[repr(C)]
struct Item {
    name: *mut u16,
    value: Value,
}
#[cfg(windows)]
impl Drop for Counter {
    fn drop(&mut self) {
        unsafe {
            PdhCloseQuery(self.query);
        }
    }
}
#[cfg(windows)]
fn values(counter: isize) -> Option<Vec<(String, f64)>> {
    let mut bytes = 0;
    let mut count = 0;
    let status = unsafe {
        PdhGetFormattedCounterArrayW(
            counter,
            0x200 | 0x8000,
            &mut bytes,
            &mut count,
            std::ptr::null_mut(),
        )
    };
    if status as u32 != 0x800007d2 || bytes == 0 || bytes > 262144 {
        return None;
    }
    let allocated = bytes as usize;
    let mut buffer = vec![0u64; (allocated + 7) / 8];
    if unsafe {
        PdhGetFormattedCounterArrayW(
            counter,
            0x200 | 0x8000,
            &mut bytes,
            &mut count,
            buffer.as_mut_ptr().cast(),
        )
    } != 0
        || bytes as usize > allocated
        || count > 4096
        || count as usize * std::mem::size_of::<Item>() > bytes as usize
    {
        return None;
    }
    let start = buffer.as_ptr() as usize;
    let end = start + bytes as usize;
    let mut values = Vec::new();
    for index in 0..count as usize {
        let item = unsafe { &*buffer.as_ptr().cast::<Item>().add(index) };
        if item.name.is_null() {
            continue;
        }
        let pointer = item.name as usize;
        if pointer < start || pointer >= end || pointer % 2 != 0 {
            continue;
        }
        let available = ((end - pointer) / 2).min(1024);
        let characters = unsafe { std::slice::from_raw_parts(item.name, available) };
        let Some(length) = characters.iter().position(|c| *c == 0) else {
            continue;
        };
        values.push((
            String::from_utf16_lossy(&characters[..length]),
            if item.value.status <= 1 {
                item.value.value
            } else {
                f64::NAN
            },
        ));
    }
    Some(values)
}
#[cfg(windows)]
impl Counter {
    pub fn new() -> Option<Self> {
        let mut query = 0;
        if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let add = |path: &str| {
            let path = path.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
            let mut counter = 0;
            (unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } == 0)
                .then_some(counter)
        };
        let counter = add(r"\GPU Engine(*)\Utilization Percentage");
        let shared = add(r"\GPU Adapter Memory(*)\Shared Usage");
        let dedicated = add(r"\GPU Adapter Memory(*)\Dedicated Usage");
        if (counter.is_none() && shared.is_none() && dedicated.is_none())
            || unsafe { PdhCollectQueryData(query) } != 0
        {
            unsafe {
                PdhCloseQuery(query);
            }
            return None;
        }
        Some(Self {
            query,
            counter,
            shared,
            dedicated,
            memory: MemoryReadings::default(),
            warm: false,
        })
    }
    pub fn memory(&self) -> &MemoryReadings {
        &self.memory
    }
    pub fn sample(&mut self) -> Option<HashMap<u64, f32>> {
        self.memory = MemoryReadings::default();
        if !self.warm {
            self.warm = true;
            return None;
        }
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return None;
        }
        self.memory.shared = self
            .shared
            .and_then(values)
            .map(|v| memory(v.into_iter()))
            .unwrap_or_default();
        self.memory.dedicated = self
            .dedicated
            .and_then(values)
            .map(|v| memory(v.into_iter()))
            .unwrap_or_default();
        let readings = aggregate(self.counter.and_then(values)?.into_iter());
        (!readings.is_empty()).then_some(readings)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adapter_memory_uses_global_physical_instances_and_preserves_real_zero() {
        let rows = memory(
            [
                ("luid_0x00000000_0x00016019_phys_0", 248737792.),
                ("luid_0x00000000_0x00016019_phys_1", 4096.),
                ("luid_0x00000000_0x00000002_phys_0", 0.),
                ("pid_12_luid_0x00000000_0x00016019_phys_0", 999999999.),
                ("_Total", 999999999.),
            ]
            .into_iter()
            .map(|(s, v)| (s.into(), v)),
        );
        assert_eq!(rows.get(&0x16019), Some(&248741888));
        assert_eq!(rows.get(&2), Some(&0));
        assert_eq!(rows.len(), 2);
        assert!(memory(std::iter::empty()).is_empty());
    }
    #[test]
    fn invalid_or_duplicate_partition_never_yields_partial_or_fabricated_usage() {
        for invalid in [f64::NAN, f64::INFINITY, -1., 1.5, i64::MAX as f64] {
            assert!(memory(
                [
                    (String::from("luid_0x0_0x1_phys_0"), 4096.),
                    (String::from("luid_0x0_0x1_phys_1"), invalid)
                ]
                .into_iter()
            )
            .is_empty());
        }
        assert!(memory(
            [
                (String::from("luid_0x0_0x1_phys_0"), 4096.),
                (String::from("luid_0x0_0x1_phys_0"), 4096.)
            ]
            .into_iter()
        )
        .is_empty());
        assert!(memory(
            [
                (String::from("luid_0x0_0x1_phys_0"), 2f64.powi(62)),
                (String::from("luid_0x0_0x1_phys_1"), 2f64.powi(62))
            ]
            .into_iter()
        )
        .is_empty());
    }
    #[test]
    fn engines_sum_processes_but_do_not_sum_parallel_engine_percentages() {
        let values = [
            ("pid_1_luid_0x0_0x7_phys_0_eng_0_engtype_3D", 30.),
            ("pid_2_luid_0x0_0x7_phys_0_eng_0_engtype_3D", 25.),
            ("pid_1_luid_0x0_0x7_phys_0_eng_1_engtype_Copy", 40.),
        ];
        let readings = aggregate(values.into_iter().map(|(n, v)| (n.into(), v)));
        assert_eq!(readings.get(&7), Some(&55.));
        assert!(aggregate(std::iter::empty()).is_empty());
        let readings = aggregate(
            [
                ("pid_1_luid_0x0_0xa_phys_0_eng_0_engtype_3D".into(), 20.),
                ("pid_2_luid_0x0_0xb_phys_0_eng_0_engtype_3D".into(), 90.),
            ]
            .into_iter(),
        );
        assert_eq!(readings.get(&10), Some(&20.));
        assert_eq!(readings.get(&11), Some(&90.));
    }
}
