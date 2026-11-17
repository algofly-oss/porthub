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
        born: Instant,
    }
    #[derive(Clone, PartialEq, Eq, serde::Serialize)]
    pub(crate) struct Key { address: std::net::IpAddr, prefix: u8, index: Option<u32>, gateway: Option<std::net::IpAddr>, metric: Option<u32> }
    impl Key {
        #[cfg(any(windows,target_os="macos"))]
        fn raw(route:&Route)->Self {
            Self { address:route.destination(),prefix:route.prefix(),index:route.if_index(),gateway:route.gateway(),
                #[cfg(windows)] metric:route.metric(), #[cfg(not(windows))] metric:None }
        }
        #[cfg(any(windows,target_os="macos"))]
        pub(crate) fn route(route:&Route)->Self { let mut key=Self::raw(route);key.gateway=key.gateway.filter(|ip|!ip.is_unspecified());key }

    }
    #[derive(serde::Serialize)]
    struct Event { kind:u8, at_ms:u64, key:Key, identity_matches:bool }
    #[derive(serde::Serialize)]
    struct Phase { kind:u8, at_ms:u64, revision:Option<u64> }
    #[derive(Default)]
    struct State { ready: bool, matched: Option<Instant>, completed: bool,
        events:Vec<Event>, phases:Vec<Phase>, events_dropped:u32, phases_dropped:u32,
        refresh_started:u32, refresh_ok:u32, refresh_failed:u32, refresh_timed_out:u32,
        last_errno:Option<i32>, listener_errors:u32, readback_keys:Vec<Key>, readback_matches:bool, readback_errors:u32 }

    impl Witness {
        pub(crate) fn new(expected: Key) -> Self { Self { expected, state: Mutex::new(State::default()), born:Instant::now() } }
        pub(crate) fn ready(&self) { self.state.lock().unwrap().ready = true;self.phase(1,None); }
        pub(crate) fn is_ready(&self) -> bool { self.state.lock().unwrap().ready }
        #[cfg(any(windows,target_os="macos"))]
        pub(crate) fn event(&self, event: &RouteChange) {
            let (kind,route)=match event {RouteChange::Add(r)=>(1,r),RouteChange::Delete(r)=>(2,r),RouteChange::Change(r)=>(3,r)};
            self.record_event(kind,Key::raw(route));
            // NotifyRouteChange2 supplies only route identity, not Metric.
            // Complete proof requires a separate fresh full native readback.
            if kind==1 && self.callback_matches(&Key::route(route)) {
                let mut state=self.state.lock().unwrap();if state.ready {state.matched.get_or_insert(Instant::now());}
            }

        }
        fn phase(&self,kind:u8,revision:Option<u64>){
            let mut state=self.state.lock().unwrap_or_else(|p|p.into_inner());
            if state.phases.len()<16 {state.phases.push(Phase{kind,at_ms:self.born.elapsed().as_millis().min(u64::MAX as u128)as u64,revision});}
            else {state.phases_dropped=state.phases_dropped.saturating_add(1);}
        }
        fn record_event(&self,kind:u8,key:Key){
            // Never retain unrelated route identities, even in diagnostic builds.
            if !((key.address==self.expected.address&&key.prefix==self.expected.prefix)||(self.expected.index.is_some()&&key.index==self.expected.index)){return;}
            let mut canonical=key.clone();canonical.gateway=canonical.gateway.filter(|ip|!ip.is_unspecified());
            let matches=kind==1&&self.callback_matches(&canonical);
            let mut state=self.state.lock().unwrap_or_else(|p|p.into_inner());
            if state.events.len()<8 {state.events.push(Event{kind,at_ms:self.born.elapsed().as_millis().min(u64::MAX as u128)as u64,key,identity_matches:matches});}
            else {state.events_dropped=state.events_dropped.saturating_add(1);}
        }
        fn callback_matches(&self,key:&Key)->bool {
            let mut identity=key.clone();identity.metric=self.expected.metric;
            identity==self.expected
        }
        #[cfg(any(windows,target_os="macos"))]
        pub(crate) fn published_native(&self,rows:&[Route]) {
            let mut retained=Vec::new();let mut found=false;
            for route in rows {let key=Key::raw(route);
                if key.address==self.expected.address&&key.prefix==self.expected.prefix {
                    if retained.len()<8 {retained.push(key);}
                }
                if Key::route(route)==self.expected {found=true;}
            }
            {let mut state=self.state.lock().unwrap();state.readback_keys=retained;state.readback_matches=found;}
            self.phase(if found{8}else{9},None);
            if found {self.published();}
        }
        pub(crate) fn readback_failed(&self,errno:Option<i32>){let mut state=self.state.lock().unwrap();state.readback_errors=state.readback_errors.saturating_add(1);state.last_errno=errno;}
        pub(crate) fn add_started(&self){self.phase(2,None);}
        pub(crate) fn add_acknowledged(&self){self.phase(3,None);}
        pub(crate) fn listener_error(&self,errno:Option<i32>){let mut state=self.state.lock().unwrap_or_else(|p|p.into_inner());state.listener_errors=state.listener_errors.saturating_add(1);state.last_errno=errno;}
        pub(crate) fn refresh_started(&self,revision:Option<u64>){self.state.lock().unwrap().refresh_started+=1;self.phase(4,revision);}
        pub(crate) fn refreshed(&self,success:bool,timed_out:bool,errno:Option<i32>,revision:Option<u64>){
            {let mut s=self.state.lock().unwrap();if success{s.refresh_ok+=1;}else{s.refresh_failed+=1;}if timed_out{s.refresh_timed_out+=1;}s.last_errno=errno;}
            self.phase(if success{5}else{6},revision);
        }
        pub(crate) fn diagnostic(&self,revision:u64)->String {
            let s=self.state.lock().unwrap_or_else(|p|p.into_inner());
            // Fixed enums: event 1 Add/2 Delete/3 Change; phase 1 ready,
            // 2 Add-start/3 Add-ACK/4 refresh-start/5 success/6 failure/7 published/8 readback-match/9 mismatch.
            serde_json::to_string(&serde_json::json!({"expected":self.expected,"ready":s.ready,"matched":s.matched.is_some(),"completed":s.completed,"revision":revision,"events":s.events,"phases":s.phases,"events_dropped":s.events_dropped,"phases_dropped":s.phases_dropped,"refresh_started":s.refresh_started,"refresh_ok":s.refresh_ok,"refresh_failed":s.refresh_failed,"refresh_timed_out":s.refresh_timed_out,"last_errno":s.last_errno,"listener_errors":s.listener_errors,"readback_keys":s.readback_keys,"readback_matches":s.readback_matches,"readback_errors":s.readback_errors})).unwrap_or_else(|_|"{\"diagnostic_unavailable\":true}".into())
        }
        fn admit(&self, key:&Key, added:bool) {
            if added && *key==self.expected {
                let mut state = self.state.lock().unwrap();
                if state.ready { state.matched.get_or_insert(Instant::now()); }
            }
        }
        // Called only after a successful fresh current() and real publication.
        pub(crate) fn published(&self) {
            self.phase(7,None);
            let mut state = self.state.lock().unwrap();
            if let Some(at) = state.matched {
                if Instant::now().duration_since(at) <= Duration::from_secs(4) { state.completed = true; }
            }
        }
        pub(crate) fn completed(&self) -> bool { self.state.lock().unwrap().completed }
    }
    #[test]
    fn diagnostic_is_per_instance_bounded_and_excludes_unrelated_routes() {
        let key=Key{address:"10.254.254.0".parse().unwrap(),prefix:25,index:Some(19),gateway:None,metric:Some(77)};
        let w=Witness::new(key.clone());w.ready();w.add_started();w.add_acknowledged();
        w.record_event(1,Key{address:"192.0.2.123".parse().unwrap(),index:Some(50),..key.clone()});
        for _ in 0..30 {w.record_event(1,key.clone());w.refresh_started(Some(1));w.refreshed(false,true,Some(5),Some(2));}
        let json=w.diagnostic(2);assert!(!json.contains("192.0.2.123"));assert!(json.len()<8192);
        let value:serde_json::Value=serde_json::from_str(&json).unwrap();assert_eq!(value["events"].as_array().unwrap().len(),8);assert_eq!(value["events_dropped"],22);assert_eq!(value["refresh_failed"],30);assert_eq!(value["refresh_timed_out"],30);assert_eq!(value["last_errno"],5);assert!(!w.completed());
        let other:serde_json::Value=serde_json::from_str(&Witness::new(key).diagnostic(0)).unwrap();assert_eq!(other["events"].as_array().unwrap().len(),0);assert_eq!(other["refresh_failed"],0);
    }
    #[cfg(windows)]
    #[test]
    fn actual_on_link_add_accepts_native_zero_gateway_but_not_foreign_identity() {
        use std::net::{IpAddr, Ipv4Addr};
        let requested=Route::new("10.254.254.0".parse().unwrap(),25).with_if_index(19).with_metric(77);
        let partial=requested.clone().with_gateway(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).with_metric(0);
        let witness=Witness::new(Key::route(&requested));witness.ready();
        witness.event(&RouteChange::Add(partial.clone()));assert!(!witness.completed());
        witness.published_native(&[requested.clone()]);assert!(witness.completed());
        for route in [partial.clone().with_gateway("10.254.252.1".parse().unwrap()),partial.clone().with_if_index(20),Route::new(requested.destination(),24).with_if_index(19)] {
            let witness=Witness::new(Key::route(&requested));witness.ready();witness.event(&RouteChange::Add(route));witness.published_native(&[requested.clone()]);assert!(!witness.completed());
        }
        let witness=Witness::new(Key::route(&requested));witness.ready();witness.event(&RouteChange::Add(partial.clone()));witness.published_native(&[requested.clone().with_metric(78)]);assert!(!witness.completed());
        let witness=Witness::new(Key::route(&requested));witness.ready();witness.event(&RouteChange::Add(partial));witness.published_native(&[]);assert!(!witness.completed());
        let witness=Witness::new(Key::route(&requested));witness.ready();witness.event(&RouteChange::Delete(requested.clone()));witness.published_native(&[requested]);assert!(!witness.completed());
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
