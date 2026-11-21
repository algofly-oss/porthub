//! One service owns independently supervised public and private modules.
//! Private failures must not restart established public forwarding streams.
use anyhow::Result;
use std::{
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

/// Fixed diagnostic labels only: never format profile paths or underlying errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PrivateStage {
    Profile, Lease, Control, Strategy, Identity, TorPreferences,
    Controller, NativeOwner, LegacyAdmission, DnsListener, DnsRegistration, Background,
}
impl std::fmt::Display for PrivateStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}
impl std::error::Error for PrivateStage {}
impl PrivateStage {
    fn label(self) -> &'static str {
        match self {
            Self::Profile=>"profile-load",Self::Lease=>"profile-lease",
            Self::Control=>"private-control",Self::Strategy=>"path-settings",
            Self::Identity=>"transport-identity",Self::TorPreferences=>"tor-settings",
            Self::Controller=>"private-controller",Self::NativeOwner=>"native-owner",
            Self::LegacyAdmission=>"legacy-native-admission",Self::DnsListener=>"dns-listener",
            Self::DnsRegistration=>"dns-registration",Self::Background=>"background-task",
        }
    }
    pub(crate) async fn run<T>(self, task: impl Future<Output=Result<T>>) -> Result<T> {
        use anyhow::Context;
        task.await.context(self)
    }
}
pub(crate) fn private_failure_stage(error: &anyhow::Error) -> &'static str {
    error.downcast_ref::<PrivateStage>().map_or("runtime",|stage|stage.label())
}

fn same_configuration_path(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        let normalize = |path: &Path| path.to_string_lossy().trim_start_matches(r"\\?\").replace('/', r"\").to_lowercase();
        normalize(left) == normalize(right)
    }
    #[cfg(not(windows))]
    { left == right }
}

/// Pair by enrolled authority and machine identity, never email, IP, or a
/// fallback URL shared by otherwise unrelated registrations.
pub(crate) fn matches(
    public: &crate::profile::Profile,
    private: &crate::private_profile::Profile,
) -> bool {
    public.server == private.server
        && !private.workspace.is_empty()
        && private.peer_id == format!("{}:{}", private.workspace, public.machine_id)
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    pub format_version: u32,
    pub private_profile: PathBuf,
    pub enabled: bool,
}

pub(crate) fn configuration_path(public_path: &Path) -> PathBuf {
    crate::profile::sibling(public_path, ".private-module.json")
}

pub(crate) fn load(
    public_path: &Path,
    public: &crate::profile::Profile,
) -> Result<Option<Configuration>> {
    let path = configuration_path(public_path);
    if !path.try_exists()? {
        return Ok(None);
    }
    let configuration: Configuration =
        serde_json::from_slice(&crate::profile::read_private(&path)?)?;
    anyhow::ensure!(
        configuration.format_version == 1,
        "unsupported private module configuration"
    );
    let private = crate::private_profile::Profile::load(&configuration.private_profile)?;
    let id = crate::service::RegistrationProfile::Private(private.clone()).identity();
    anyhow::ensure!(
        matches(public, &private)
            && configuration.private_profile
                == public_path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("registration directory missing"))?
                    .join(format!("{id}.json")),
        "private module does not belong to this registration"
    );
    Ok(Some(configuration))
}

pub(crate) fn save(
    public_path: &Path,
    public: &crate::profile::Profile,
    configuration: &Configuration,
) -> Result<()> {
    let private = crate::private_profile::Profile::load(&configuration.private_profile)?;
    let id = crate::service::RegistrationProfile::Private(private.clone()).identity();
    anyhow::ensure!(
        configuration.format_version == 1
            && matches(public, &private)
            && Some(configuration.private_profile.as_path())
                == public_path
                    .parent()
                    .map(|root| root.join(format!("{id}.json")))
                    .as_deref(),
        "private module does not belong to this registration"
    );
    crate::profile::write_private(
        &configuration_path(public_path),
        &serde_json::to_vec(configuration)?,
        true,
    )
}

/// Apply local policy independently from parsing a possibly broken module.
fn refresh_configuration(
    path:&Path, public:&crate::profile::Profile, logs:&crate::logs::Buffer,
    enabled:bool, updates:&watch::Sender<Option<PathBuf>>,
) {
    // Opt-out is authoritative even when the module or its profile cannot be
    // parsed. Never keep an already-running worker merely because load failed.
    if !enabled {
        updates.send_if_modified(|current|current.take().is_some());
        return;
    }
    match load(path,public) {
        Ok(value)=>{
            if let Some(value)=&value {
                if let Ok(private)=crate::private_profile::Profile::load(&value.private_profile){logs.include_private(&private);}
            }
            let selected=value.filter(|value|value.enabled&&enabled).map(|value|value.private_profile);
            updates.send_if_modified(|current|{if *current==selected{false}else{*current=selected;true}});
        },
        Err(_)=>tracing::warn!("private module change rejected; retaining the current configuration"),
    }
}

pub(crate) struct Controller {
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Controller {
    pub(crate) fn start(
        public_path: &Path,
        public: &crate::profile::Profile,
        logs: crate::logs::Buffer,
    ) -> Result<Self> {
        use notify::Watcher;
        // FSEvents reports canonical paths (for example /private/var instead
        // of /var). Match the watched path in the same spelling on macOS.
        #[cfg(target_os = "macos")]
        let wanted = configuration_path(&std::fs::canonicalize(public_path)?);
        #[cfg(not(target_os = "macos"))]
        let wanted = configuration_path(public_path);
        let (changes, mut changed) = tokio::sync::mpsc::channel(1);
        let notifications = changes.clone();
        let target = wanted.clone();
        let mut watcher = (|| -> Result<porthub_transfer::notifications::FileWatcher> {
            let mut watcher = porthub_transfer::notifications::watcher(
                move |event: notify::Result<notify::Event>| match event {
                    Ok(event)
                        if event.paths.iter().any(|path| same_configuration_path(path, &target))
                            && matches!(
                                event.kind,
                                notify::EventKind::Create(_)
                                    | notify::EventKind::Modify(_)
                                    | notify::EventKind::Remove(_)
                            ) =>
                    {
                        let _ = notifications.try_send(false);
                    }
                    Err(_) => {
                        let _ = notifications.try_send(true);
                    }
                    _ => {}
                },
            )?;
            watcher.watch(
                wanted
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("module directory missing"))?,
                notify::RecursiveMode::NonRecursive,
            )?;
            Ok(watcher)
        })()
        .ok();
        let configuration = load(public_path, public).unwrap_or_else(|_| {
            tracing::warn!(
                "private module configuration rejected; waiting for a valid replacement"
            );
            None
        });
        if let Some(config) = &configuration {
            if let Ok(private) = crate::private_profile::Profile::load(&config.private_profile) {
                logs.include_private(&private);
            }
        }
        let selected = configuration
            .filter(|config| config.enabled && crate::features::enabled(public_path,crate::features::Feature::PrivateNetwork))
            .map(|config| config.private_profile);
        let (configuration, receiver) = watch::channel(selected);
        let cancel = CancellationToken::new();
        let supervisor = tokio::spawn(supervise(receiver, cancel.clone(), move |path, cancel| {
            crate::private_network::runtime::run_embedded(path, cancel)
        }));
        let path = public_path.to_owned();
        let public = public.clone();
        let stop = cancel.clone();
        let updates = configuration.clone();
        let task = tokio::spawn(async move {
            let _keepalive = changes;
            let mut policy=crate::features::subscribe(&path);
            let mut fallback = tokio::time::interval(Duration::from_secs(60));
            fallback.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = policy.changed() => {},
                    event = changed.recv() => {
                        if event == Some(true) { watcher = None; }
                        if event.is_none() { break; }
                    },
                    _ = fallback.tick(), if watcher.is_none() => {},
                }
                refresh_configuration(&path,&public,&logs,
                    crate::features::enabled(&path,crate::features::Feature::PrivateNetwork),&updates);

            }
            stop.cancel();
            let _ = supervisor.await;
        });
        Ok(Self { cancel, task })
    }
    pub(crate) async fn stop(&mut self) {
        self.cancel.cancel();
        let _ = (&mut self.task).await;
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct Worker {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Worker {
    async fn shutdown(mut self) {
        self.stop.cancel();
        if tokio::time::timeout(Duration::from_secs(30), &mut self.task)
            .await
            .is_err()
        {
            tracing::warn!("private module shutdown exceeded its deadline");
            self.task.abort();
            let _ = (&mut self.task).await;
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}

// The active timer bounds retries even if the platform clock becomes unavailable.
async fn wait_retry_clock(delay: Duration, clock: impl Fn() -> Option<Duration>) {
    let active_deadline = tokio::time::Instant::now() + delay;
    let Some(deadline) = clock().and_then(|start| start.checked_add(delay)) else {
        tokio::time::sleep_until(active_deadline).await;
        return;
    };
    loop {
        let Some(now) = clock() else {
            tokio::time::sleep_until(active_deadline).await;
            return;
        };
        let remaining = deadline.saturating_sub(now);
        if remaining.is_zero() || tokio::time::Instant::now() >= active_deadline {
            return;
        }
        // A short remaining active-time sleep
        // lets the first wake observe a retry deadline that passed in suspend.
        let check = tokio::time::Instant::now() + remaining.min(Duration::from_secs(1));
        tokio::time::sleep_until(check.min(active_deadline)).await;
    }
}

#[cfg(target_os = "linux")]
fn linux_retry_timer(delay: Duration) -> std::io::Result<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>> {
    use std::{io, os::fd::{AsRawFd, FromRawFd, OwnedFd}};
    // CLOCK_BOOTTIME counts suspend. This non-alarm timer cannot wake the host.
    let raw = unsafe { libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_CLOEXEC | libc::TFD_NONBLOCK) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    let timer = libc::itimerspec {
        it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
        it_value: libc::timespec {
            tv_sec: delay.as_secs().try_into().map_err(|_| io::Error::other("retry delay out of range"))?,
            tv_nsec: delay.subsec_nanos() as _,
        },
    };
    if unsafe { libc::timerfd_settime(fd.as_raw_fd(), 0, &timer, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    tokio::io::unix::AsyncFd::new(fd)
}

pub(crate) async fn suspend_aware_delay(delay: Duration) {
    #[cfg(target_os = "macos")]
    if let Ok(queue) = crate::macos_kqueue::continuous_timer(delay) {
        // Retry and relay heartbeat deadlines should fire on the first wake after expiry.
        // The Tokio deadline also covers an unavailable or failed kernel timer.
        tokio::select! {
            Ok(_) = crate::macos_kqueue::next_flags(&queue) => {},
            _ = tokio::time::sleep(delay) => {},
        }
        return;
    }
    #[cfg(target_os = "linux")]
    if !delay.is_zero() {
        if let Ok(timer) = linux_retry_timer(delay) {
            tokio::select! {
                Ok(_) = timer.readable() => {},
                _ = tokio::time::sleep(delay) => {},
            }
            return;
        }
    }
    #[cfg(feature = "private-sparse")]
    {
        use crate::private_network::{NativeClock, SuspendClock};
        wait_retry_clock(delay, || NativeClock.elapsed_since_boot().ok()).await;
    }
    #[cfg(not(feature = "private-sparse"))]
    wait_retry_clock(delay, || {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()
    }).await;
}

/// Watch-based supervision: no idle polling, one worker at a time, bounded
/// retry on failure, and graceful cleanup before replacing a private runtime.
pub(crate) async fn supervise<F, Fut>(
    mut configuration: watch::Receiver<Option<PathBuf>>,
    cancel: CancellationToken,
    mut start: F,
) where
    F: FnMut(PathBuf, CancellationToken) -> Fut,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let mut retry = Duration::from_secs(5);
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let selected = configuration.borrow_and_update().clone();
        let Some(path) = selected.clone() else {
            tokio::select! {
                _ = cancel.cancelled() => return,
                changed = configuration.changed() => if changed.is_err() { return; },
            }
            retry = Duration::from_secs(5);
            continue;
        };
        let stop = cancel.child_token();
        let mut worker = Worker {
            task: tokio::spawn(start(path, stop.clone())),
            stop,
        };
        let began = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = cancel.cancelled() => { worker.shutdown().await; return; },
                changed = configuration.changed() => {
                    if changed.is_err() { worker.shutdown().await; return; }
                    if *configuration.borrow_and_update() == selected { continue; }
                    worker.shutdown().await;
                    retry = Duration::from_secs(5);
                    break;
                },
                result = &mut worker.task => {
                    // Panics and unexpected clean exits receive the same
                    // backoff; neither escapes into the public runtime.
                    worker.stop.cancel();
                    #[cfg(feature = "private-sparse")]
                    if matches!(&result, Ok(Err(error)) if error.is::<crate::private_network::ExpiredDuringSuspend>()) {
                        tracing::info!("private lease expired during sleep; requesting a fresh lease");
                        retry = Duration::from_secs(5);
                        break;
                    }
                    let reason = match &result {
                        Ok(Err(error)) => private_failure_reason(error),
                        Ok(Ok(())) => "private worker exited unexpectedly",
                        Err(_) => "private worker terminated unexpectedly",
                    };
                    let stage = match &result { Ok(Err(error))=>private_failure_stage(error), _=>"worker" };
                    tracing::warn!(reason, stage, "private module stopped; retry scheduled");
                    if began.elapsed() >= Duration::from_secs(60) { retry = Duration::from_secs(5); }
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        changed = configuration.changed() => {
                            if changed.is_err() { return; }
                            retry = Duration::from_secs(5);
                        },
                        _ = suspend_aware_delay(retry) => retry = (retry * 2).min(Duration::from_secs(60)),
                    }
                    break;
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[tokio::test(start_paused = true)]
    async fn stopped_private_retry_observes_suspend_within_one_second_of_wake() {
        use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
        let boot = Arc::new(AtomicU64::new(100));
        let clock = boot.clone();
        let retry = tokio::spawn(super::wait_retry_clock(Duration::from_secs(60), move || {
            Some(Duration::from_secs(clock.load(Ordering::SeqCst)))
        }));
        tokio::task::yield_now().await;
        assert!(!retry.is_finished());
        boot.store(185, Ordering::SeqCst);
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(retry.is_finished());
        retry.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stopped_private_retry_keeps_active_deadline_when_clock_stops() {
        let before = tokio::time::Instant::now();
        super::wait_retry_clock(Duration::from_secs(5), || Some(Duration::ZERO)).await;
        assert_eq!(before.elapsed(), Duration::from_secs(5));
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn stopped_private_retry_kernel_timer_expires_once() -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let timer = super::linux_retry_timer(Duration::from_millis(30))?;
        let _ready = tokio::time::timeout(Duration::from_secs(2), timer.readable()).await??;
        let mut expirations = 0u64;
        let count = unsafe {
            libc::read(timer.get_ref().as_raw_fd(), (&mut expirations as *mut u64).cast(),
                       std::mem::size_of::<u64>())
        };
        assert_eq!(count, 8);
        assert_eq!(expirations, 1);
        Ok(())
    }

    fn profiles() -> (crate::profile::Profile, crate::private_profile::Profile) {
        let public: crate::profile::Profile = serde_json::from_value(serde_json::json!({
            "server":"https://gateway.example", "machine_id":"0123456789abcdef01234567", "token":"public-secret"
        })).unwrap();
        let private = crate::private_profile::Profile {
            server: public.server.clone(),
            workspace: "abcdef0123456789abcdef01".into(),
            peer_id: format!("abcdef0123456789abcdef01:{}", public.machine_id),
            token: "private-secret-0123456789012345678901".into(),
            account_email: None,
            fallback_servers: vec![],
            allow_insecure_http_for_tests: false,
        };
        (public, private)
    }

    #[test]
    fn module_binding_rejects_other_gateways_machines_and_external_profile_paths() -> Result<()> {
        let (mut public, mut private) = profiles();
        assert!(matches(&public, &private));
        private.server = "https://other.example".into();
        public.fallback_servers.push(private.server.clone());
        assert!(!matches(&public, &private));
        private.server = public.server.clone();
        private.peer_id = "abcdef0123456789abcdef01:ffffffffffffffffffffffff".into();
        assert!(!matches(&public, &private));
        let (public, private) = profiles();
        let mut directory = tempfile::Builder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            directory.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let root = directory.tempdir()?;
        let public_path = root.path().join("public.json");
        let id = crate::service::RegistrationProfile::Private(private.clone()).identity();
        let private_path = root.path().join(format!("{id}.json"));
        crate::profile::write_private(&private_path, &serde_json::to_vec(&private)?, false)?;
        let configuration = Configuration {
            format_version: 1,
            private_profile: private_path.clone(),
            enabled: false,
        };
        save(&public_path, &public, &configuration)?;
        assert!(!load(&public_path, &public)?.unwrap().enabled);
        let external = root.path().join("elsewhere.json");
        crate::profile::write_private(&external, &serde_json::to_vec(&private)?, false)?;
        assert!(save(
            &public_path,
            &public,
            &Configuration {
                private_profile: external,
                ..configuration.clone()
            }
        )
        .is_err());
        let mut other = public.clone();
        other.machine_id = "ffffffffffffffffffffffff".into();
        assert!(load(&public_path, &other).is_err());
        assert_eq!(
            load(&public_path, &public)?.unwrap().private_profile,
            private_path
        );
        Ok(())
    }

    #[test]
    fn shared_log_buffer_redacts_both_credentials() {
        let (public, private) = profiles();
        let logs = crate::logs::Buffer::default();
        logs.configure(&public);
        logs.include_private(&private);
        use std::io::Write;
        use tracing_subscriber::fmt::MakeWriter;
        write!(logs.make_writer(), "{} {}", public.token, private.token).unwrap();
        let output = logs.batch(None, 100, 100).lines.join("\n");
        assert!(!output.contains(&public.token));
        assert!(!output.contains(&private.token));
        assert!(output.contains("[redacted]"));
    }

    #[tokio::test]
    async fn local_disable_cancels_running_worker_even_when_module_configuration_is_broken()->Result<()> {
        let(public,private)=profiles();let mut directory=tempfile::Builder::new();
        #[cfg(unix)]{use std::os::unix::fs::PermissionsExt;directory.permissions(std::fs::Permissions::from_mode(0o700));}
        let root=directory.tempdir()?;let public_path=root.path().join("public.json");
        let id=crate::service::RegistrationProfile::Private(private.clone()).identity();let private_path=root.path().join(format!("{id}.json"));
        crate::profile::write_private(&private_path,&serde_json::to_vec(&private)?,false)?;
        save(&public_path,&public,&Configuration{format_version:1,private_profile:private_path.clone(),enabled:true})?;
        let logs=crate::logs::Buffer::default();let(updates,receiver)=watch::channel(None);let stop=CancellationToken::new();
        let(events,mut observed)=tokio::sync::mpsc::unbounded_channel();
        let task=tokio::spawn(supervise(receiver,stop.clone(),move|_,cancel|{let events=events.clone();async move{
            events.send("started").unwrap();cancel.cancelled().await;events.send("stopped").unwrap();Ok(())
        }}));
        refresh_configuration(&public_path,&public,&logs,true,&updates);
        assert_eq!(observed.recv().await,Some("started"));
        crate::profile::write_private(&configuration_path(&public_path),b"{broken",true)?;
        refresh_configuration(&public_path,&public,&logs,true,&updates);
        assert_eq!(*updates.borrow(),Some(private_path)); // Enabled-on-error retains the running worker.
        assert!(observed.try_recv().is_err());
        refresh_configuration(&public_path,&public,&logs,false,&updates);
        let parked=updates.borrow().is_none();
        let stopped=tokio::time::timeout(Duration::from_secs(1),observed.recv()).await;
        stop.cancel();task.await?;
        assert!(parked,"local opt-out must override a malformed module/profile");
        assert_eq!(stopped.ok().flatten(),Some("stopped"),"opt-out must cancel the actual supervised worker");
        Ok(())
    }

    #[tokio::test]
    async fn replacement_and_shutdown_clean_up_before_starting_another_worker() {
        let (config, receiver) = watch::channel(None);
        let stop = CancellationToken::new();
        let alive = Arc::new(AtomicUsize::new(0));
        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(supervise(receiver, stop.clone(), {
            let alive = alive.clone();
            move |path, cancel| {
                let alive = alive.clone();
                let events = events.clone();
                async move {
                    assert_eq!(alive.fetch_add(1, Ordering::SeqCst), 0);
                    events.send(path).unwrap();
                    cancel.cancelled().await;
                    alive.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                }
            }
        }));
        config.send(Some("first".into())).unwrap();
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("first"));
        config.send(Some("second".into())).unwrap();
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("second"));
        config.send(None).unwrap();
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(alive.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(start_paused=true)]
    async fn address_change_recreates_private_resources_after_cleanup_without_configuration_change(){
        use crate::private_network::address_lifecycle::Binding;
        let first:std::net::Ipv4Addr="10.203.0.2".parse().unwrap();
        let next:std::net::Ipv4Addr="10.204.0.2".parse().unwrap();
        let (_configuration,configured)=watch::channel(Some(PathBuf::from("unchanged-registration")));
        let (address,observations)=watch::channel(first);
        let (events,mut observed)=tokio::sync::mpsc::unbounded_channel();
        let live=Arc::new(AtomicUsize::new(0));let stop=CancellationToken::new();
        struct Resources{address:std::net::Ipv4Addr,live:Arc<AtomicUsize>,events:tokio::sync::mpsc::UnboundedSender<(&'static str,std::net::Ipv4Addr)>}
        impl Drop for Resources{fn drop(&mut self){assert_eq!(self.live.fetch_sub(1,Ordering::SeqCst),1);let _=self.events.send(("closed",self.address));}}
        let task=tokio::spawn(supervise(configured,stop.clone(),move|_,cancel|{
            let mut observations=observations.clone();let live=live.clone();let events=events.clone();
            async move{
                let current=*observations.borrow_and_update();let mut binding=Binding::default();binding.configured(current)?;
                assert_eq!(live.fetch_add(1,Ordering::SeqCst),0);
                let _resources=Resources{address:current,live,events:events.clone()};events.send(("opened",current)).unwrap();
                loop {tokio::select!{_=cancel.cancelled()=>return Ok(()),changed=observations.changed()=>{changed?;binding.check(*observations.borrow_and_update())?;}}}
            }
        }));
        assert_eq!(observed.recv().await.unwrap(),("opened",first));
        address.send(next).unwrap();
        assert_eq!(observed.recv().await.unwrap(),("closed",first));
        // Same registration/configuration; the ordinary bounded failure backoff restarts only this worker.
        assert_eq!(tokio::time::timeout(Duration::from_secs(6),observed.recv()).await.unwrap().unwrap(),("opened",next));
        stop.cancel();task.await.unwrap();
        assert_eq!(observed.recv().await.unwrap(),("closed",next));
    }

    #[tokio::test]
    async fn failed_private_worker_does_not_spin_or_terminate_supervision() {
        let (config, receiver) = watch::channel(Some(PathBuf::from("broken")));
        let stop = CancellationToken::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let (events, mut observed) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(supervise(receiver, stop.clone(), {
            let attempts = attempts.clone();
            move |path, cancel| {
                let attempts = attempts.clone();
                let events = events.clone();
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    events.send(path.clone()).unwrap();
                    if path == PathBuf::from("broken") {
                        anyhow::bail!("injected failure");
                    }
                    cancel.cancelled().await;
                    Ok(())
                }
            }
        }));
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("broken"));
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!task.is_finished());
        config.send(Some("recovered".into())).unwrap();
        assert_eq!(observed.recv().await.unwrap(), PathBuf::from("recovered"));
        stop.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
}

pub(crate) fn private_failure_reason(error: &anyhow::Error) -> &'static str {
    #[cfg(feature = "private-sparse")]
    {
        if error.is::<crate::private_network::ExpiredDuringSuspend>() {
            return "private authority request expired during system sleep";
        }
        if crate::private_network::logical_request_expired(error) {
            return "private authority request exceeded its validity window";
        }
    }
    if crate::private_network::native_route_conflict(error) {
        return "native private route conflicts with an existing network";
    }
    // Only exact local error contexts select these fixed output strings. Nested paths,
    // credentials and arbitrary OS messages never become part of the persisted report.
    for cause in error.chain() {
        let reason = match cause.to_string().as_str() {
            "macOS utun read failed" => "macOS private tunnel packet read failed",
            "macOS utun write failed" | "short private packet write" => "private tunnel packet write failed",
            "owned local packet write exceeded bound" => "local private tunnel packet write timed out",
            "private authority retired" => "private authorization generation was retired",
            "authority clock regressed" => "suspend-inclusive authority clock moved backwards",
            "suspend-inclusive authority clock unavailable" | "invalid authority clock" => "suspend-inclusive authority clock unavailable",
            "native active assignment invalid" | "native quarantine identity/limits changed; repair required" => "native source ownership journal is invalid",
            "previous native source shutdown is not acknowledged" => "previous native source retirement is unconfirmed",
            "native packet source retired or replaced" => "native packet source ownership changed",
            "native packet owner cancelled" => "native packet owner was cancelled",
            "private background task panicked" => "private background task panicked",
            "private background task was cancelled" => "private background task was cancelled",
            "private background task stopped" => "private background task exited unexpectedly",
            "macOS native route preflight failed" => "macOS native route inventory failed",
            "macOS private source preflight failed" => "macOS private source preflight failed",
            "macOS private source verification failed" => "macOS private source verification failed",
            "cannot create macOS private utun device" => "macOS private tunnel device creation failed",
            "cannot identify macOS private utun device" | "cannot find macOS private utun interface" => "macOS private tunnel identity verification failed",
            "cannot add macOS private host route" | "cannot remove macOS private host route" => "macOS private host route update failed",
            "this machine profile is already running" if error.downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.raw_os_error().is_some() && io.raw_os_error()==fs2::lock_contended_error().raw_os_error()) =>
                "private worker lock is held by another owner",
            _ => continue,
        };
        return reason;
    }
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("native source quarantined") || text.contains("native source address quarantined") || text.contains("retained source") { "native source quarantined; safe address repair required" }
    else if text.contains("private address changed") { "private address changed; rebuilding the private tunnel" }
    else if text.contains("lease expired") || text.contains("server authority expired") { "private policy expired; check clock synchronization and gateway connectivity" }
    else if text.contains("resolve1") || text.contains("systemd-resolved") { "private DNS unavailable; check systemd-resolved installation and service state" }
    else if text.contains("dns setup") || text.contains("nsswitch") || text.contains("authselect") { "private DNS setup failed; check privileged enrollment and administrator DNS configuration restrictions" }
    else if text.contains("tun device") { "private TUN unavailable; check device access and network privileges" }
    else if text.contains("rejected this enrollment") { "private enrollment rejected; check registration and administrator access policy" }
    else { "private startup failed; run porthub diagnose with the registration profile" }
}

#[cfg(all(test,windows))]
#[test]
fn windows_module_notifications_match_long_path_and_case_variants() {
    let expected=Path::new(r"C:\ProgramData\PortHub\native\owner.json.private-module.json");
    assert!(same_configuration_path(expected,Path::new(r"\\?\c:\programdata\PORT hub\native\owner.json.private-module.json"))==false);
    assert!(same_configuration_path(expected,Path::new(r"\\?\c:\programdata\PORTHUB\native\owner.json.private-module.json")));
    assert!(!same_configuration_path(expected,Path::new(r"C:\ProgramData\PortHub\native\another.json.private-module.json")));
}

#[cfg(test)]
#[test]
fn private_stage_diagnostic_is_typed_and_never_echoes_error_text() {
    use anyhow::Context;
    let error=Err::<(),_>(anyhow::anyhow!("secret-profile/private-controller")).context(PrivateStage::NativeOwner).unwrap_err();
    assert_eq!(private_failure_stage(&error),"native-owner");
    assert_eq!(private_failure_stage(&anyhow::anyhow!("native-owner secret")),"runtime");
    assert_eq!(private_failure_reason(&anyhow::anyhow!("native source address quarantined; a safe new private address allocation is required")),"native source quarantined; safe address repair required");
}

#[cfg(test)]
#[test]
fn expired_gateway_authority_reports_clock_and_connectivity_checks() {
    let error = anyhow::anyhow!("server authority expired").context("private-controller");
    assert_eq!(
        private_failure_reason(&error),
        "private policy expired; check clock synchronization and gateway connectivity"
    );
}
