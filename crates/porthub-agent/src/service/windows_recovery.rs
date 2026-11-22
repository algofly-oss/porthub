//! Bounded SCM recovery, separate from service start/stop ownership.
use anyhow::{ensure, Result};
use std::time::Duration;

pub(super) const RESET_AFTER: Duration = Duration::from_secs(3600);
// SCM repeats the final action after the list is exhausted: it must be None.
pub(super) const RESTART_DELAYS: [Option<Duration>; 4] = [
    Some(Duration::from_secs(5)),
    Some(Duration::from_secs(30)),
    Some(Duration::from_secs(120)),
    None,
];

/// Explicit STOP/SHUTDOWN remains a clean SCM stop even if teardown logs an
/// error. Unexpected failures must remain nonzero for SCM recovery to apply.
pub(super) fn exit_code(failed: bool, deliberate_stop: bool) -> u32 {
    u32::from(failed && !deliberate_stop)
}

trait Recovery {
    fn matches(&self) -> Result<bool>;
    fn configure(&self) -> Result<()>;
}

fn ensure_recovery(service: &impl Recovery) -> Result<()> {
    if !service.matches()? {
        service.configure()?;
        ensure!(
            service.matches()?,
            "Windows service recovery did not persist"
        );
    }
    Ok(())
}

#[cfg(windows)]
pub(super) mod native;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Store {
        matches: Cell<bool>,
        writes: Cell<usize>,
        fail: bool,
        ignore_write: bool,
    }
    impl Recovery for Store {
        fn matches(&self) -> Result<bool> {
            Ok(self.matches.get())
        }
        fn configure(&self) -> Result<()> {
            self.writes.set(self.writes.get() + 1);
            ensure!(!self.fail, "native recovery configuration failed");
            if !self.ignore_write {
                self.matches.set(true);
            }
            Ok(())
        }
    }
    #[test]
    fn missing_recovery_is_reconciled_and_repeated_reconcile_is_read_only() -> Result<()> {
        let store = Store {
            matches: Cell::new(false),
            writes: Cell::new(0),
            fail: false,
            ignore_write: false,
        };
        ensure_recovery(&store)?;
        ensure_recovery(&store)?;
        assert_eq!(store.writes.get(), 1);
        Ok(())
    }
    #[test]
    fn native_failure_or_missing_readback_is_not_success() {
        for (fail, ignore_write) in [(true, false), (false, true)] {
            let store = Store {
                matches: Cell::new(false),
                writes: Cell::new(0),
                fail,
                ignore_write,
            };
            assert!(ensure_recovery(&store).is_err());
            assert!(!store.matches.get());
        }
    }
    #[test]
    fn recovery_is_bounded_and_never_reboots_or_runs_a_command() {
        assert_eq!(
            RESTART_DELAYS,
            [
                Some(Duration::from_secs(5)),
                Some(Duration::from_secs(30)),
                Some(Duration::from_secs(120)),
                None
            ]
        );
        assert_eq!(RESET_AFTER, Duration::from_secs(3600));
        assert!(RESTART_DELAYS.last().unwrap().is_none());
    }
    #[test]
    fn deliberate_stop_does_not_recover_even_when_cleanup_failed() {
        assert_eq!(exit_code(true, false), 1);
        assert_eq!(exit_code(false, false), 0);
        assert_eq!(exit_code(false, true), 0);
        assert_eq!(exit_code(true, true), 0);
    }
}
