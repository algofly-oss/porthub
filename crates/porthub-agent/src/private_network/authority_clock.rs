//! Experimental request-start authority window. Not yet a readiness contract:
//! every queued/native/data-plane consumer must retain and validate the witness.
use anyhow::{ensure, Result};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

pub(crate) const REQUEST_VALIDITY: Duration = Duration::from_secs(15);

/// The machine slept through an entire authority window while this request was live.
#[derive(Debug)]
pub(crate) struct ExpiredDuringSuspend;

impl std::fmt::Display for ExpiredDuringSuspend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("logical authority request expired during system sleep")
    }
}
impl std::error::Error for ExpiredDuringSuspend {}

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
    domain: Option<super::authority_event::Domain>,
    boot_start: Duration,
    awake_start: Instant,
    wall_start: SystemTime,
    relative_deadlines: bool,
}
impl RequestWindow {
    pub(crate) fn start(clock: Arc<dyn SuspendClock>) -> Result<Self> {
        Self::start_in(clock, None)
    }
    pub(crate) fn start_in(
        clock: Arc<dyn SuspendClock>,
        domain: Option<super::authority_event::Domain>,
    ) -> Result<Self> {
        ensure!(
            domain.as_ref().is_none_or(|d| d.valid()),
            "profile authority owner stopped"
        );
        let boot_start = clock.elapsed_since_boot()?;
        Ok(Self {
            clock,
            domain,
            boot_start,
            awake_start: Instant::now(),
            wall_start: SystemTime::now(),
            relative_deadlines: false,
        })
    }
    pub(crate) fn use_relative_deadlines(&mut self) {
        self.relative_deadlines = true;
    }
    pub(crate) fn local_expiry(&self, server_now: chrono::DateTime<chrono::Utc>, expiry: chrono::DateTime<chrono::Utc>) -> Result<chrono::DateTime<chrono::Utc>> {
        let ttl = (expiry - server_now).to_std()?;
        ensure!(!ttl.is_zero() && ttl <= REQUEST_VALIDITY, "invalid server authority lifetime");
        Ok(self.wall_start.checked_add(ttl).ok_or_else(|| anyhow::anyhow!("invalid local authority deadline"))?.into())
    }
    pub(crate) fn check(&self, server_expiry: SystemTime) -> Result<()> {
        self.remaining(server_expiry).map(|_| ())
    }
    pub(crate) fn remaining(&self, server_expiry: SystemTime) -> Result<Duration> {
        let limit = if self.relative_deadlines {
            server_expiry.duration_since(self.wall_start)?.min(REQUEST_VALIDITY)
        } else { REQUEST_VALIDITY };
        let local = self.remaining_within(limit)?;
        let server = server_expiry
            .duration_since(SystemTime::now())
            .ok()
            .filter(|n| !n.is_zero())
            .ok_or_else(|| anyhow::anyhow!("server authority expired"))?;
        Ok(local.min(server))
    }
    /// Shorten this ORIGINAL start; never begin a new clock for received TTL.
    pub(crate) fn remaining_within(&self, limit: Duration) -> Result<Duration> {
        ensure!(
            !limit.is_zero() && limit <= REQUEST_VALIDITY,
            "invalid bounded authority duration"
        );
        ensure!(
            self.domain.as_ref().is_none_or(|d| d.valid()),
            "profile authority owner stopped"
        );
        let elapsed = self
            .clock
            .elapsed_since_boot()?
            .checked_sub(self.boot_start)
            .ok_or_else(|| anyhow::anyhow!("authority clock regressed"))?;
        let awake_elapsed = self.awake_start.elapsed();
        if awake_elapsed < limit && elapsed.saturating_sub(awake_elapsed) >= REQUEST_VALIDITY {
            return Err(ExpiredDuringSuspend.into());
        }
        let boot = limit
            .checked_sub(elapsed)
            .filter(|n| !n.is_zero())
            .ok_or_else(|| anyhow::anyhow!("logical authority request expired"))?;
        let awake = limit
            .checked_sub(awake_elapsed)
            .filter(|n| !n.is_zero())
            .ok_or_else(|| anyhow::anyhow!("logical authority request expired"))?;
        Ok(boot.min(awake))
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
    #[tokio::test]
    async fn supervisor_reacquires_after_sleep_and_backs_off_on_ordinary_failure() {
        let (_config, receiver) = tokio::sync::watch::channel(Some(std::path::PathBuf::from("fixture")));
        let cancel = tokio_util::sync::CancellationToken::new();
        let (events, mut attempts) = tokio::sync::mpsc::unbounded_channel();
        let mut first = true;
        let task = tokio::spawn(crate::unified::supervise(receiver, cancel.clone(), move |_, _| {
            let resumed = std::mem::take(&mut first);
            let events = events.clone();
            async move {
                events.send(()).unwrap();
                let clock = Arc::new(Clock(AtomicU64::new(0)));
                let window = RequestWindow::start(clock.clone())?;
                if resumed {
                    clock.0.store(60_000, Ordering::SeqCst);
                    return window.check(expiry());
                }
                window.check(SystemTime::UNIX_EPOCH)
            }
        }));
        attempts.recv().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), attempts.recv()).await.unwrap().unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(80), attempts.recv()).await.is_err());
        cancel.cancel();
        task.await.unwrap();
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
    fn shortened_received_limit_uses_precredit_start_and_cannot_refresh() {
        let clock = Arc::new(Clock(AtomicU64::new(100)));
        let original = RequestWindow::start(clock.clone()).unwrap();
        clock.0.store(350, Ordering::SeqCst);
        let limit = Duration::from_millis(500);
        assert!(original.remaining_within(limit).unwrap() <= Duration::from_millis(250));
        clock.0.store(600, Ordering::SeqCst);
        assert!(original.remaining_within(limit).is_err());
        assert!(original.clone().remaining_within(limit).is_err());
        assert!(original.remaining_within(Duration::ZERO).is_err());
        assert!(original.remaining_within(Duration::from_secs(16)).is_err());
    }
    #[test]
    fn clock_skew_preserves_short_leases_and_charges_transit_and_suspend() {
        for skew in [-22, 22] {
            let clock = Arc::new(Clock(AtomicU64::new(0)));
            let mut window = RequestWindow::start(clock.clone()).unwrap();
            window.use_relative_deadlines();
            let server = chrono::Utc::now() + chrono::Duration::seconds(skew);
            assert!(window.local_expiry(server, server).is_err());
            assert!(window.local_expiry(server, server - chrono::Duration::seconds(1)).is_err());
            assert!(window.local_expiry(server, server + chrono::Duration::seconds(16)).is_err());
            let expiry = window.local_expiry(server, server + chrono::Duration::seconds(4)).unwrap();
            clock.0.store(3000, Ordering::SeqCst);
            let remaining = window.remaining(expiry.into()).unwrap();
            assert!(remaining > Duration::ZERO && remaining <= Duration::from_secs(1));
            clock.0.store(4000, Ordering::SeqCst);
            assert!(window.check(expiry.into()).is_err());
        }
    }
    #[test]
    fn actual_native_clock_advances_without_configuration_changes() {
        let before = NativeClock.elapsed_since_boot().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        assert!(NativeClock.elapsed_since_boot().unwrap() > before);
    }
}
