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

/// Per-watcher native evidence; never linked into production builds.
#[cfg(test)]
pub(crate) mod witness {
    use std::sync::Mutex;
    #[cfg(any(windows,target_os="macos"))]
    use route_manager::{Route, RouteChange};
    use super::*;
    pub(crate) struct Witness {
        expected: Key,
        state: Mutex<State>,
    }
    #[derive(Clone, PartialEq, Eq)]
    pub(crate) struct Key { address: std::net::IpAddr, prefix: u8, index: Option<u32>, gateway: Option<std::net::IpAddr>, metric: Option<u32> }
    impl Key {
        #[cfg(any(windows,target_os="macos"))]
        pub(crate) fn route(route:&Route)->Self {
            Self { address:route.destination(),prefix:route.prefix(),index:route.if_index(),gateway:route.gateway().filter(|ip| !ip.is_unspecified()),
                #[cfg(windows)] metric:route.metric(), #[cfg(not(windows))] metric:None }
        }
    }
    #[derive(Default)]
    struct State { ready: bool, matched: Option<Instant>, completed: bool }
    impl Witness {
        pub(crate) fn new(expected: Key) -> Self { Self { expected, state: Mutex::new(State::default()) } }
        pub(crate) fn ready(&self) { self.state.lock().unwrap().ready = true; }
        pub(crate) fn is_ready(&self) -> bool { self.state.lock().unwrap().ready }
        #[cfg(any(windows,target_os="macos"))]
        pub(crate) fn event(&self, event: &RouteChange) {
            if let RouteChange::Add(route)=event { self.admit(&Key::route(route),true); }
        }
        fn admit(&self, key:&Key, added:bool) {
            if added && *key==self.expected {
                let mut state = self.state.lock().unwrap();
                if state.ready { state.matched.get_or_insert(Instant::now()); }
            }
        }
        // Called only after a successful fresh current() and real publication.
        pub(crate) fn published(&self) {
            let mut state = self.state.lock().unwrap();
            if let Some(at) = state.matched {
                if Instant::now().duration_since(at) <= Duration::from_secs(4) { state.completed = true; }
            }
        }
        pub(crate) fn completed(&self) -> bool { self.state.lock().unwrap().completed }
    }
    #[cfg(windows)]
    #[test]
    fn actual_on_link_add_accepts_native_zero_gateway_but_not_foreign_identity() {
        use std::net::{IpAddr, Ipv4Addr};
        let requested=Route::new("10.254.254.0".parse().unwrap(),25).with_if_index(19).with_metric(77);
        let native=requested.clone().with_gateway(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let witness=Witness::new(Key::route(&requested));witness.ready();
        witness.event(&RouteChange::Add(native));witness.published();assert!(witness.completed());
        let mut foreign=vec![requested.clone().with_gateway("10.254.252.1".parse().unwrap()),requested.clone().with_if_index(20),Route::new(requested.destination(),24).with_if_index(19).with_metric(77)];
        if !cfg!(target_os="macos") {foreign.push(requested.clone().with_metric(78));}
        for route in foreign {let witness=Witness::new(Key::route(&requested));witness.ready();witness.event(&RouteChange::Add(route));witness.published();assert!(!witness.completed());}
        let witness=Witness::new(Key::route(&requested));witness.ready();witness.event(&RouteChange::Delete(requested));witness.published();assert!(!witness.completed());
    }
    #[tokio::test(start_paused = true)]
    async fn late_refresh_cannot_satisfy_native_deadline() {
        let route=Key { address:"10.254.254.0".parse().unwrap(),prefix:25,index:Some(19),gateway:None,metric:Some(77) };
        let witness=Witness::new(route.clone()); witness.ready();
        witness.admit(&route,true);
        tokio::time::sleep(Duration::from_millis(4001)).await;
        witness.published(); assert!(!witness.completed());
    }
    #[test]
    fn initial_periodic_and_foreign_publications_cannot_prove_native_refresh() {
        let route=Key { address:"10.254.254.0".parse().unwrap(),prefix:25,index:Some(19),gateway:None,metric:Some(77) };
        let witness=Witness::new(route.clone());
        witness.published(); assert!(!witness.completed());
        witness.admit(&route,true); witness.ready();
        witness.published(); assert!(!witness.completed());
        witness.admit(&route,false);
        witness.admit(&Key { index:Some(20),..route.clone() },true);
        witness.published(); assert!(!witness.completed());
        witness.admit(&route,true); assert!(!witness.completed());
        witness.published(); assert!(witness.completed());
    }
}
