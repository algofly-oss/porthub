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

#[cfg(windows)]
pub(super) struct Counter {
    query: isize,
    counter: isize,
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
impl Counter {
    pub fn new() -> Option<Self> {
        let mut query = 0;
        let mut counter = 0;
        if unsafe { PdhOpenQueryW(std::ptr::null(), 0, &mut query) } != 0 {
            return None;
        }
        let path = "\\GPU Engine(*)\\Utilization Percentage\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        if unsafe { PdhAddEnglishCounterW(query, path.as_ptr(), 0, &mut counter) } != 0
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
            warm: false,
        })
    }
    pub fn sample(&mut self) -> Option<HashMap<u64, f32>> {
        if !self.warm {
            self.warm = true;
            return None;
        }
        if unsafe { PdhCollectQueryData(self.query) } != 0 {
            return None;
        }
        let mut bytes = 0u32;
        let mut count = 0u32;
        let status = unsafe {
            PdhGetFormattedCounterArrayW(
                self.counter,
                0x200 | 0x8000,
                &mut bytes,
                &mut count,
                std::ptr::null_mut(),
            )
        };
        if status as u32 != 0x800007d2 || bytes == 0 || bytes > 262144 {
            return None;
        }
        let mut buffer = vec![0u64; (bytes as usize + 7) / 8];
        if unsafe {
            PdhGetFormattedCounterArrayW(
                self.counter,
                0x200 | 0x8000,
                &mut bytes,
                &mut count,
                buffer.as_mut_ptr().cast(),
            )
        } != 0
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
            if item.value.status > 1 || item.name.is_null() {
                continue;
            }
            let pointer = item.name as usize;
            if pointer < start || pointer >= end || pointer % 2 != 0 {
                continue;
            }
            let available = ((end - pointer) / 2).min(1024);
            let characters = unsafe { std::slice::from_raw_parts(item.name, available) };
            let length = characters.iter().position(|c| *c == 0).unwrap_or(available);
            values.push((
                String::from_utf16_lossy(&characters[..length]),
                item.value.value,
            ));
        }
        let readings = aggregate(values.into_iter());
        (!readings.is_empty()).then_some(readings)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
