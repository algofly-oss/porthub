//! Shared bounded frame-event loop. Stream ticks/corruption never extend time
//! since the last valid image; a slow native request remains supervisor-bounded.
use anyhow::{ensure, Result};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
pub enum Poll<T> {
    Timeout,
    Event(Option<T>),
}
pub trait Events<T> {
    fn request(&mut self) -> Result<()>;
    fn poll(&mut self, wait: Duration) -> Result<Poll<T>>;
}
pub fn run<T, U>(
    events: &mut impl Events<T>,
    cancel: &AtomicBool,
    mut decode: impl FnMut(T) -> Result<Option<U>>,
    mut emit: impl FnMut(U) -> Result<()>,
    mut now: impl FnMut() -> Duration,
) -> Result<()> {
    const DEADLINE: Duration = Duration::from_secs(5);
    let mut last = now();
    if cancel.load(Ordering::Acquire) {
        return Ok(());
    }
    events.request()?;
    while !cancel.load(Ordering::Acquire) {
        ensure!(
            now().saturating_sub(last) < DEADLINE,
            "Camera valid-frame deadline exceeded"
        );
        match events.poll(Duration::from_millis(50))? {
            Poll::Timeout => {}
            Poll::Event(frame) => {
                if let Some(frame) = frame {
                    if let Some(image) = decode(frame)? {
                        ensure!(
                            now().saturating_sub(last) < DEADLINE,
                            "Camera valid-frame deadline exceeded during processing"
                        );
                        if cancel.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        emit(image)?;
                        last = now();
                    }
                }
                ensure!(
                    now().saturating_sub(last) < DEADLINE,
                    "Camera valid-frame deadline exceeded"
                );
                if !cancel.load(Ordering::Acquire) {
                    events.request()?;
                }
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    struct Fake<'a> {
        clock: &'a Cell<Duration>,
        calls: usize,
        empty: bool,
    }
    impl Events<u8> for Fake<'_> {
        fn request(&mut self) -> Result<()> {
            Ok(())
        }
        fn poll(&mut self, _: Duration) -> Result<Poll<u8>> {
            self.calls += 1;
            ensure!(self.calls <= 600, "Fake exceeded deadline budget");
            self.clock.set(self.clock.get() + Duration::from_millis(10));
            Ok(Poll::Event(if self.empty { None } else { Some(1) }))
        }
    }
    #[test]
    fn continuous_ticks_and_corrupt_frames_timeout_without_extending_deadline() {
        for empty in [true, false] {
            let clock = Cell::new(Duration::ZERO);
            let mut events = Fake {
                clock: &clock,
                calls: 0,
                empty,
            };
            let error = run(
                &mut events,
                &AtomicBool::new(false),
                |_| Ok::<_, anyhow::Error>(None::<()>),
                |_| panic!("Invalid frame cannot publish"),
                || clock.get(),
            )
            .unwrap_err();
            assert!(error.to_string().contains("valid-frame deadline"));
            assert_eq!(clock.get(), Duration::from_secs(5));
            assert!(events.calls <= 500);
        }
    }
    #[test]
    fn processing_late_first_frame_cannot_publish_ready() {
        let clock = Cell::new(Duration::ZERO);
        let mut events = Fake {
            clock: &clock,
            calls: 0,
            empty: false,
        };
        assert!(run(
            &mut events,
            &AtomicBool::new(false),
            |_| {
                clock.set(Duration::from_secs(6));
                Ok(Some(()))
            },
            |_| panic!("Late frame cannot publish"),
            || clock.get()
        )
        .is_err());
    }
    #[test]
    fn valid_frames_reset_deadline_and_precancel_never_requests() {
        let clock = Cell::new(Duration::ZERO);
        let cancel = AtomicBool::new(false);
        let mut events = Fake {
            clock: &clock,
            calls: 0,
            empty: false,
        };
        let mut frames = 0;
        run(
            &mut events,
            &cancel,
            |x| Ok(Some(x)),
            |_| {
                frames += 1;
                if frames == 2 {
                    cancel.store(true, Ordering::Release);
                }
                Ok(())
            },
            || clock.get(),
        )
        .unwrap();
        assert_eq!(frames, 2);
        let mut events = Fake {
            clock: &clock,
            calls: 0,
            empty: false,
        };
        run(
            &mut events,
            &AtomicBool::new(true),
            |x| Ok(Some(x)),
            |_| Ok(()),
            || clock.get(),
        )
        .unwrap();
        assert_eq!(events.calls, 0);
    }
}
