//! Coalesce native route notifications without postponing the first audit.
use std::time::Duration;
use tokio::time::Instant;
#[derive(Default)]
pub(crate) struct Debounce(Option<Instant>);
impl Debounce {
    pub(crate) fn notify(&mut self, now: Instant) {
        self.0.get_or_insert(now + Duration::from_millis(250));
    }
    pub(crate) fn deadline(&self) -> Option<Instant> {
        self.0
    }
    pub(crate) async fn wait(&self) {
        match self.deadline() {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    }
    pub(crate) fn clear(&mut self) {
        self.0 = None;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sustained_native_notifications_cannot_postpone_first_route_audit() {
        let start = Instant::now();
        let mut debounce = Debounce::default();
        assert_eq!(debounce.deadline(), None);
        for millis in (0..1000).step_by(10) {
            debounce.notify(start + Duration::from_millis(millis));
            assert_eq!(
                debounce.deadline(),
                Some(start + Duration::from_millis(250))
            );
        }
        debounce.clear();
        assert_eq!(debounce.deadline(), None);
        debounce.notify(start + Duration::from_secs(2));
        assert_eq!(
            debounce.deadline(),
            Some(start + Duration::from_millis(2250))
        );
    }
    #[test]
    fn periodic_resync_and_native_event_share_one_bounded_audit() {
        let start = Instant::now();
        let mut debounce = Debounce::default();
        debounce.notify(start);
        debounce.notify(start + Duration::from_millis(249));
        assert_eq!(
            debounce.deadline(),
            Some(start + Duration::from_millis(250))
        );
        debounce.clear();
        debounce.notify(start + Duration::from_millis(251));
        assert_eq!(
            debounce.deadline(),
            Some(start + Duration::from_millis(501))
        );
    }
}

#[cfg(test)]
mod scheduling_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn select_recreation_under_continuous_events_still_refreshes_at_first_deadline() {
        let start = Instant::now();
        let mut changed = Debounce::default();
        let mut events = tokio::time::interval(Duration::from_millis(10));
        let mut notifications = 0;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                tokio::select! {
                    _ = events.tick() => { changed.notify(Instant::now()); notifications += 1; },
                    _ = changed.wait() => { changed.clear(); break; },
                }
            }
        })
        .await
        .expect("continuous native notifications starved refresh");
        assert!(notifications >= 20);
        assert_eq!(Instant::now() - start, Duration::from_millis(250));
    }
    #[tokio::test(start_paused = true)]
    async fn output_close_interrupts_pending_debounce_without_waiting_for_refresh() {
        let mut changed = Debounce::default();
        changed.notify(Instant::now());
        let (output, receiver) = tokio::sync::watch::channel(());
        let start = Instant::now();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            drop(receiver);
        });
        tokio::select! {
            _ = output.closed() => {},
            _ = changed.wait() => panic!("output closure waited for debounce"),
        }
        assert_eq!(Instant::now() - start, Duration::from_millis(10));
    }
    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_idle_or_pending_debounce() {
        for pending in [false, true] {
            let mut changed = Debounce::default();
            if pending {
                changed.notify(Instant::now());
            }
            let start = Instant::now();
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                _ = changed.wait() => panic!("cancellation waited for debounce"),
            }
            assert_eq!(Instant::now() - start, Duration::from_millis(10));
        }
    }
}
