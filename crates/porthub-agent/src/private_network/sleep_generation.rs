//! Host sleep evidence for in-process TCP continuation. A failed read or
//! unknown platform cannot confirm continuity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Generation([i64; 6]);

impl Generation {
    #[cfg(target_os = "linux")]
    pub(super) fn read() -> Option<Self> {
        let count = std::fs::read_to_string("/sys/power/suspend_stats/success")
            .ok()?
            .trim()
            .parse()
            .ok()?;
        Some(Self([count, 0, 0, 0, 0, 0]))
    }

    #[cfg(target_os = "macos")]
    pub(super) fn read() -> Option<Self> {
        fn sample(name: &std::ffi::CStr) -> Option<[i64; 2]> {
            let mut time = std::mem::MaybeUninit::<libc::timeval>::uninit();
            let mut size = std::mem::size_of::<libc::timeval>();
            let result = unsafe {
                libc::sysctlbyname(
                    name.as_ptr(),
                    time.as_mut_ptr().cast(),
                    &mut size,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if result != 0 || size != std::mem::size_of::<libc::timeval>() {
                return None;
            }
            let time = unsafe { time.assume_init() };
            (time.tv_sec >= 0 && (0..1_000_000).contains(&time.tv_usec))
                .then_some([time.tv_sec, i64::from(time.tv_usec)])
        }
        let [boot_s, boot_us] = sample(c"kern.boottime")?;
        let [sleep_s, sleep_us] = sample(c"kern.sleeptime")?;
        let [wake_s, wake_us] = sample(c"kern.waketime")?;
        Some(Self([boot_s, boot_us, sleep_s, sleep_us, wake_s, wake_us]))
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub(super) fn read() -> Option<Self> {
        None
    }
}
