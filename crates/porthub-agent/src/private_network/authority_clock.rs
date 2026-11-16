//! Experimental request-start authority window. Not yet a readiness contract:
//! every queued/native/data-plane consumer must retain and validate the witness.
use anyhow::{ensure, Result};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

pub(crate) const REQUEST_VALIDITY: Duration = Duration::from_secs(15);

pub(crate) trait SuspendClock: Send + Sync {
    fn elapsed_since_boot(&self) -> Result<Duration>;
}

pub(crate) struct NativeClock;
impl SuspendClock for NativeClock {
    fn elapsed_since_boot(&self) -> Result<Duration> {
        native_now()
    }
}

// CLOCK_BOOTTIME includes suspend; CLOCK_MONOTONIC/std::Instant alone does not.
// https://www.kernel.org/doc/html/v4.19/core-api/timekeeping.html
#[cfg(target_os = "linux")]
fn native_now() -> Result<Duration> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, value.as_mut_ptr()) } == 0,
        "suspend-inclusive authority clock unavailable"
    );
    let value = unsafe { value.assume_init() };
    ensure!(
        value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "invalid authority clock"
    );
    Ok(Duration::new(
        value.tv_sec.try_into()?,
        value.tv_nsec.try_into()?,
    ))
}

// https://developer.apple.com/documentation/kernel/1646199-mach_continuous_time
#[cfg(target_os = "macos")]
fn native_now() -> Result<Duration> {
    #[repr(C)]
    struct Timebase {
        numer: u32,
        denom: u32,
    }
    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut Timebase) -> i32;
    }
    let mut base = Timebase { numer: 0, denom: 0 };
    ensure!(
        unsafe { mach_timebase_info(&mut base) } == 0 && base.numer > 0 && base.denom > 0,
        "suspend-inclusive authority clock unavailable"
    );
    let nanos = u128::from(unsafe { mach_continuous_time() }) * u128::from(base.numer)
        / u128::from(base.denom);
    Ok(Duration::new(
        (nanos / 1_000_000_000).try_into()?,
        (nanos % 1_000_000_000).try_into()?,
    ))
}

// Biased interrupt time includes sleep/hibernate. No global timer/power changes.
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time
#[cfg(windows)]
fn native_now() -> Result<Duration> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn QueryInterruptTimePrecise(value: *mut u64);
    }
    let mut ticks = 0;
    unsafe { QueryInterruptTimePrecise(&mut ticks) };
    Ok(Duration::new(
        ticks / 10_000_000,
        ((ticks % 10_000_000) * 100) as u32,
    ))
}

#[derive(Clone)]
pub(crate) struct RequestWindow {
    clock: Arc<dyn SuspendClock>,
    boot_start: Duration,
    awake_start: Instant,
}
impl RequestWindow {
    pub(crate) fn start(clock: Arc<dyn SuspendClock>) -> Result<Self> {
        let boot_start = clock.elapsed_since_boot()?;
        Ok(Self {
            clock,
            boot_start,
            awake_start: Instant::now(),
        })
    }
    pub(crate) fn check(&self, server_expiry: SystemTime) -> Result<()> {
        let now = self.clock.elapsed_since_boot()?;
        let elapsed = now
            .checked_sub(self.boot_start)
            .ok_or_else(|| anyhow::anyhow!("authority clock regressed"))?;
        ensure!(
            elapsed < REQUEST_VALIDITY && self.awake_start.elapsed() < REQUEST_VALIDITY,
            "logical authority request expired"
        );
        ensure!(
            SystemTime::now() < server_expiry,
            "server authority expired"
        );
        Ok(())
    }
}

/// The closure is invoked only AFTER the immutable logical-request witness is
/// created. All internal transport retries share that same start. The returned
/// witness must travel with the response through installation and forwarding.
pub(crate) async fn request<T, F, Fut>(
    clock: Arc<dyn SuspendClock>,
    operation: F,
) -> Result<(T, RequestWindow)>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<(T, SystemTime)>>,
{
    let window = RequestWindow::start(clock)?;
    let (response, expiry) = operation().await?;
    window.check(expiry)?;
    Ok((response, window))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    struct Clock(AtomicU64);
    impl SuspendClock for Clock {
        fn elapsed_since_boot(&self) -> Result<Duration> {
            let n = self.0.load(Ordering::SeqCst);
            ensure!(n != u64::MAX, "clock failed");
            Ok(Duration::from_millis(n))
        }
    }
    fn expiry() -> SystemTime {
        SystemTime::now() + Duration::from_secs(60)
    }
    #[tokio::test]
    async fn actual_delayed_operation_and_retry_cannot_mint_fresh_authority() {
        let clock = Arc::new(Clock(AtomicU64::new(100)));
        let operation_clock = clock.clone();
        let task = tokio::spawn(request(clock, move || async move {
            // Actual async operation/retry boundary; awake time need not advance
            // when the suspend-inclusive clock advances across simulated sleep.
            tokio::task::yield_now().await;
            operation_clock.0.store(8100, Ordering::SeqCst);
            tokio::task::yield_now().await;
            operation_clock.0.store(15100, Ordering::SeqCst);
            Ok(((), expiry()))
        }));
        assert!(task.await.unwrap().is_err());
    }
    #[tokio::test]
    async fn queued_install_keeps_original_witness_across_simulated_suspend() {
        let clock = Arc::new(Clock(AtomicU64::new(100)));
        let (_, window) = request(clock.clone(), || async { Ok(((), expiry())) })
            .await
            .unwrap();
        clock.0.store(15099, Ordering::SeqCst);
        assert!(window.check(expiry()).is_ok());
        clock.0.store(15100, Ordering::SeqCst);
        assert!(window.check(expiry()).is_err());
        // Re-emitting cached authority or cloning it cannot refresh the start.
        assert!(window.clone().check(expiry()).is_err());
    }
    #[test]
    fn regression_failure_and_utc_expiry_fail_closed() {
        let clock = Arc::new(Clock(AtomicU64::new(100)));
        let window = RequestWindow::start(clock.clone()).unwrap();
        clock.0.store(99, Ordering::SeqCst);
        assert!(window.check(expiry()).is_err());
        clock.0.store(u64::MAX, Ordering::SeqCst);
        assert!(window.check(expiry()).is_err());
        clock.0.store(100, Ordering::SeqCst);
        assert!(window.check(SystemTime::UNIX_EPOCH).is_err());
    }
    #[test]
    fn actual_native_clock_advances_without_configuration_changes() {
        let before = NativeClock.elapsed_since_boot().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        assert!(NativeClock.elapsed_since_boot().unwrap() > before);
    }
}
