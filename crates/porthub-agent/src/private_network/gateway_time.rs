//! One instance per provisioned gateway identity. Called on certificate-time
//! recovery only. Routine control sync already carries the gateway's time.
use super::{NativeClock, SuspendClock};
use anyhow::{ensure, Result};
use std::time::Duration;
use tokio::sync::Mutex;

const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockSample {
    utc: Duration,
    observed: Duration,
}

impl ClockSample {
    pub(super) fn from_sync(utc: chrono::DateTime<chrono::Utc>) -> Option<Self> {
        let received = Duration::from_secs(utc.timestamp().try_into().ok()?);
        if std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .is_ok_and(|wall| wall.abs_diff(received) < Duration::from_secs(60))
        {
            return None;
        }
        Some(Self {
            utc: received,
            observed: NativeClock.elapsed_since_boot().ok()?,
        })
    }

    fn utc_at(&self, now: Duration) -> Option<Duration> {
        let age = now.checked_sub(self.observed)?;
        (age < MAX_AGE).then(|| self.utc.checked_add(age)).flatten()
    }

    fn validation_time(
        &self,
        elapsed: Option<Duration>,
        wall: std::time::SystemTime,
    ) -> Option<Duration> {
        // Unattended systems may regain working time synchronization during an outage.
        // After the sample expires, ordinary certificate validation can use that clock.
        elapsed.and_then(|now| self.utc_at(now))
            .or_else(|| wall.duration_since(std::time::UNIX_EPOCH).ok())
    }
}

impl rustls::time_provider::TimeProvider for ClockSample {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        self.validation_time(NativeClock.elapsed_since_boot().ok(), std::time::SystemTime::now())
            .map(rustls::pki_types::UnixTime::since_unix_epoch)
    }
}

#[derive(Default)]
struct State {
    sample: Option<ClockSample>,
    next_attempt: Duration,
    failures: u32,
}

impl State {
    fn cached(&self, now: Duration) -> Option<Duration> {
        self.sample?.utc_at(now)
    }

    fn begin(&mut self, now: Duration, jitter: u8) -> Result<()> {
        ensure!(now >= self.next_attempt, "gateway clock retry deferred");
        let delay = (30u64 << self.failures.min(6)).min(1800);
        self.next_attempt = now + Duration::from_secs(delay + delay * u64::from(jitter) / 512);
        self.failures = self.failures.saturating_add(1);
        Ok(())
    }
}

// The bootstrap handshake proves possession of an enrolled key and never
// resumes a TLS ticket. No calendar date is needed before we obtain UTC.
#[derive(Debug)]
struct BootstrapClock;

impl rustls::time_provider::TimeProvider for BootstrapClock {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        Some(rustls::pki_types::UnixTime::since_unix_epoch(
            NativeClock.elapsed_since_boot().ok()?,
        ))
    }
}

pub(crate) struct GatewayTime {
    endpoint: reqwest::Url,
    bootstrap_tls: rustls::ClientConfig,
    outbound: crate::outbound::Settings,
    state: Mutex<State>,
    updates: tokio::sync::watch::Sender<Option<ClockSample>>,
}

impl GatewayTime {
    // Origin and SPKI must come from the same trusted enrollment record.
    pub(crate) fn new(origin: &str, pin: &str) -> Result<Self> {
        let url = reqwest::Url::parse(&crate::profile::base(origin, false)?)?;
        ensure!(url.path() == "/", "expected direct gateway origin");
        let mut bootstrap = porthub_identity::pinned_client_config(pin)?;
        bootstrap.time_provider = std::sync::Arc::new(BootstrapClock);
        bootstrap.resumption = rustls::client::Resumption::disabled();
        Ok(Self {
            endpoint: url.join("api/gateway/clock")?,
            bootstrap_tls: bootstrap,
            outbound: crate::outbound::Settings::from_env()?,
            state: Mutex::new(State::default()),
            updates: tokio::sync::watch::channel(None).0,
        })
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<ClockSample>> {
        self.updates.subscribe()
    }

    pub(crate) async fn tls_config(
        &self,
        roots: rustls::RootCertStore,
    ) -> Result<rustls::ClientConfig> {
        self.recover().await?;
        let sample = self
            .state
            .lock()
            .await
            .sample
            .ok_or_else(|| anyhow::anyhow!("missing verified clock"))?;
        Ok(rustls::ClientConfig::builder_with_details(
            std::sync::Arc::new(rustls::crypto::ring::default_provider()),
            std::sync::Arc::new(sample),
        )
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth())
    }

    async fn request_time(&self, nonce: &str, attempt: u32) -> Result<reqwest::Response> {
        let mut client = reqwest::Client::builder()
            .use_preconfigured_tls(self.bootstrap_tls.clone())
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy();
        if self.outbound.interface.is_some() || self.outbound.source.is_some() {
            let host = self
                .endpoint
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("missing clock host"))?
                .trim_matches(['[', ']']);
            let port = self
                .endpoint
                .port_or_known_default()
                .ok_or_else(|| anyhow::anyhow!("missing clock port"))?;
            let destinations: Vec<_> = tokio::net::lookup_host((host, port))
                .await?
                .take(16)
                .collect();
            let routes = crate::outbound::discover(&self.outbound, &destinations).await?;
            let routes =
                crate::outbound::Selection::default().order(&routes, std::time::Instant::now());
            ensure!(
                !routes.is_empty(),
                "no permitted route to the gateway clock"
            );
            let route = &routes[attempt as usize % routes.len()];
            client = client
                .local_address(route.source)
                .resolve_to_addrs(host, &[route.destination]);
            #[cfg(target_os = "macos")]
            {
                client = client.interface(&route.interface);
            }
        }
        Ok(client
            .build()?
            .post(self.endpoint.clone())
            .header("porthub-clock-nonce", nonce)
            .send()
            .await?)
    }

    pub(crate) async fn recover(&self) -> Result<Duration> {
        let mut state = self.state.lock().await;
        let start = NativeClock.elapsed_since_boot()?;
        if let Some(cached) = state.cached(start) {
            return Ok(cached);
        }
        let challenge = uuid::Uuid::new_v4();
        let attempt = state.failures;
        state.begin(start, challenge.as_bytes()[0])?;
        let nonce = challenge.simple().to_string();
        let reply =
            tokio::time::timeout(Duration::from_secs(5), self.request_time(&nonce, attempt))
                .await??;
        ensure!(
            reply.status() == reqwest::StatusCode::NO_CONTENT,
            "gateway clock unavailable"
        );
        ensure!(
            reply
                .headers()
                .get("porthub-clock-nonce")
                .is_some_and(|v| v.as_bytes() == nonce.as_bytes()),
            "stale gateway clock response"
        );
        let elapsed = NativeClock.elapsed_since_boot()?;
        ensure!(
            elapsed
                .checked_sub(start)
                .is_some_and(|n| n <= Duration::from_secs(5)),
            "late gateway clock response"
        );
        let seconds: u64 = reply
            .headers()
            .get("porthub-clock-unix-seconds")
            .ok_or_else(|| anyhow::anyhow!("missing gateway time"))?
            .to_str()?
            .parse()?;
        let utc = Duration::from_secs(seconds);
        state.sample = Some(ClockSample {
            utc,
            observed: elapsed,
        });
        self.updates.send_replace(state.sample);
        state.failures = 0;
        Ok(utc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_sample_returns_to_the_system_clock_for_certificate_validation() {
        use std::time::UNIX_EPOCH;
        let sample = ClockSample {
            utc: Duration::from_secs(1_900_000_000),
            observed: Duration::from_secs(300),
        };
        let wall = sample.utc + MAX_AGE + Duration::from_secs(20);
        assert_eq!(sample.validation_time(Some(sample.observed), UNIX_EPOCH + wall), Some(sample.utc));
        assert_eq!(sample.validation_time(Some(sample.observed + MAX_AGE), UNIX_EPOCH + wall), Some(wall));
        assert_eq!(sample.validation_time(Some(sample.observed + MAX_AGE), UNIX_EPOCH - Duration::from_secs(1)), None);
        assert_eq!(sample.utc_at(sample.observed + MAX_AGE), None);
    }

    #[test]
    fn failed_recovery_backs_off_and_valid_time_advances_locally() {
        let mut state = State::default();
        let start = Duration::from_secs(42);
        state.begin(start, 128).unwrap();
        assert!(state.begin(start + Duration::from_secs(29), 0).is_err());
        let next = state.next_attempt;
        state.begin(next, 0).unwrap();
        assert_eq!(state.next_attempt - next, Duration::from_secs(60));
        let utc = Duration::from_secs(1_900_000_000);
        state.sample = Some(ClockSample {
            utc,
            observed: start,
        });
        assert_eq!(
            state.cached(start + Duration::from_secs(864)),
            Some(utc + Duration::from_secs(864))
        );
        assert!(state.cached(Duration::ZERO).is_none());
        assert!(state.cached(start + MAX_AGE).is_none());
    }
}

#[cfg(all(test, unix))]
#[tokio::test]
async fn concurrent_recovery_shares_one_pinned_request() -> Result<()> {
    use axum::{
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    // The parent fixture serves the pinned endpoint using its actual clock.
    // A new process models a cold agent restart with no previous sample.
    if let Ok(origin) = std::env::var("PORTHUB_TEST_CLOCK_CHILD_ORIGIN") {
        let pin = std::env::var("PORTHUB_TEST_CLOCK_CHILD_PIN")?;
        let real_epoch: i64 = std::env::var("PORTHUB_TEST_REAL_EPOCH")?.parse()?;
        let offset: i64 = std::env::var("FIXTURE_UTC_OFFSET")?.parse()?;
        let wall_epoch =
            chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now()).timestamp();
        assert!((wall_epoch - real_epoch - offset).abs() < 10);
        let der = STANDARD.decode(std::env::var("PORTHUB_TEST_CLOCK_CHILD_CERT")?)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(rustls::pki_types::CertificateDer::from(der))?;
        let p: crate::private_profile::Profile = serde_json::from_value(serde_json::json!({
            "server":origin,"workspace":"000000000000000000000001","peer_id":"000000000000000000000001:000000000000000000000002","token":"x".repeat(32)
        }))?;
        let mut ctl = crate::control::Control::new_private(&p)?;
        ctl.use_fixture_roots(roots.clone())?;
        ctl.set_clock_origin(&super::relay::PinnedRelay {
            url: origin.clone(),
            spki_sha256: pin.clone(),
        })?;
        for _ in 0..2 {
            assert_eq!(
                ctl.request(reqwest::Method::GET, "probe", None, &[])
                    .await?
                    .status,
                reqwest::StatusCode::NO_CONTENT
            );
        }
        // An open keep-alive connection must not mask an identity rotation.
        ctl.set_clock_origin(&super::relay::PinnedRelay {
            url: origin.clone(),
            spki_sha256: "ab".repeat(32),
        })?;
        assert!(ctl
            .request(reqwest::Method::GET, "probe", None, &[])
            .await
            .is_err());
        let public = serde_json::from_value(serde_json::json!({
            "server": origin, "machine_id": "000000000000000000000002", "token": "x".repeat(32)
        }))?;
        let directory = tempfile::tempdir()?;
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let host_path = directory.path().join("public.json");
        let mut host = crate::control::Control::new(public)?;
        host.use_fixture_roots(roots.clone())?;
        host.use_registration_clock(&host_path);
        let mut component_clock = host.component_clock().unwrap();
        assert!(host.request(reqwest::Method::GET,"probe",None,&[]).await.is_err());
        let identity = crate::service::RegistrationProfile::Private(p.clone()).identity();
        let private_path = directory.path().join(format!("{identity}.json"));
        crate::profile::write_private(&private_path,&serde_json::to_vec(&p)?,false)?;
        crate::unified::save(&host_path,host.profile(),&crate::unified::Configuration{
            format_version:1,private_profile:private_path.clone(),enabled:true,
        })?;
        super::clock_identity::remember(&private_path,&p,&super::relay::PinnedRelay {
            url: origin.clone(), spki_sha256: pin.clone(),
        })?;
        assert_eq!(
            host.request(reqwest::Method::GET, "probe", None, &[])
                .await?
                .status,
            StatusCode::NO_CONTENT
        );
        assert!(component_clock.has_changed()?);
        assert!(component_clock.borrow_and_update().is_some());
        let recovered = GatewayTime::new(&origin, &pin)?;
        let cfg = recovered.tls_config(roots).await?;
        let now = cfg.time_provider.current_time().unwrap().as_secs();
        let expected: u64 = std::env::var("PORTHUB_TEST_GATEWAY_EPOCH")?.parse()?;
        assert!((expected..expected + 5).contains(&now));
        let client = reqwest::Client::builder()
            .no_proxy()
            .use_preconfigured_tls(cfg)
            .build()?;
        assert_eq!(
            client.get(&origin).send().await?.status(),
            StatusCode::NOT_FOUND
        );
        return Ok(());
    }
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])?;
    params.not_before = rcgen::date_time_ymd(2030, 1, 1);
    params.not_after = rcgen::date_time_ymd(2031, 1, 1);
    let cert = params.self_signed(&key)?;
    let pin = porthub_identity::origin::Metadata::from_certificate(cert.der(), 443)?.spki_sha256;
    let tls = axum_server::tls_rustls::RustlsConfig::from_der(
        vec![cert.der().to_vec()],
        key.serialize_der(),
    )
    .await?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let origin = format!("https://{}", listener.local_addr()?);
    listener.set_nonblocking(true)?;
    let requests = Arc::new(AtomicUsize::new(0));
    let hits = requests.clone();
    let gateway_epoch = Arc::new(std::sync::atomic::AtomicU64::new(1900000000));
    let simulated_utc = gateway_epoch.clone();
    let router = axum::Router::new()
        .route(
            "/api/probe",
            axum::routing::get(|| async { StatusCode::NO_CONTENT }),
        )
        .route(
            "/api/gateway/clock",
            axum::routing::post(move |headers: HeaderMap| {
                let hits = hits.clone();
                let seconds = simulated_utc.load(Ordering::SeqCst);
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let mut res = StatusCode::NO_CONTENT.into_response();
                    res.headers_mut().insert(
                        "porthub-clock-nonce",
                        headers["porthub-clock-nonce"].clone(),
                    );
                    res.headers_mut()
                        .insert("porthub-clock-unix-seconds", seconds.into());
                    res
                }
            }),
        );
    let handle = axum_server::Handle::new();
    let shutdown = handle.clone();
    let task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(listener, tls)?
            .handle(handle)
            .serve(router.into_make_service())
            .await
    });
    let clock = Arc::new(GatewayTime::new(&origin, &pin)?);
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let clock = clock.clone();
        callers.spawn(async move { clock.recover().await });
    }
    while let Some(answer) = callers.join_next().await {
        assert!((1900000000..1900000005).contains(&answer??.as_secs()));
    }
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone())?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .use_preconfigured_tls(clock.tls_config(roots).await?)
        .build()?;
    assert_eq!(
        client.get(&origin).send().await?.status(),
        StatusCode::NOT_FOUND
    );
    let untrusted = reqwest::Client::builder()
        .no_proxy()
        .use_preconfigured_tls(clock.tls_config(rustls::RootCertStore::empty()).await?)
        .build()?;
    assert!(untrusted.get(&origin).send().await.is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let mut restricted = GatewayTime::new(&origin, &pin)?;
    restricted.outbound.interface = Some("porthub-missing-clock-interface".into());
    assert!(restricted.recover().await.is_err());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    let wrong = GatewayTime::new(&origin, &"ab".repeat(32))?;
    assert!(wrong.recover().await.is_err());
    assert!(wrong
        .recover()
        .await
        .unwrap_err()
        .to_string()
        .contains("deferred"));
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    #[cfg(target_os = "linux")]
    if let Some(shim) = std::env::var_os("PORTHUB_TEST_REALTIME_SHIM") {
        for offset in ["-3155760000", "3155760000"] {
            // Simulate a day offline with the gateway continuing to advance.
            let expected = gateway_epoch.fetch_add(86400, Ordering::SeqCst) + 86400;
            let result = tokio::process::Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "private_network::gateway_time::concurrent_recovery_shares_one_pinned_request",
                ])
                .env("PORTHUB_TEST_CLOCK_CHILD_ORIGIN", &origin)
                .env("PORTHUB_TEST_GATEWAY_EPOCH", expected.to_string())
                .env("PORTHUB_TEST_CLOCK_CHILD_PIN", &pin)
                .env("PORTHUB_TEST_CLOCK_CHILD_CERT", STANDARD.encode(cert.der()))
                .env(
                    "PORTHUB_TEST_REAL_EPOCH",
                    chrono::Utc::now().timestamp().to_string(),
                )
                .env("LD_PRELOAD", &shim)
                .env("FIXTURE_UTC_OFFSET", offset)
                .output()
                .await?;
            ensure!(
                result.status.success(),
                "clock child {offset} failed: {}",
                String::from_utf8_lossy(&result.stdout)
            );
        }
        assert_eq!(requests.load(Ordering::SeqCst), 7);
    }
    shutdown.graceful_shutdown(Some(Duration::from_secs(1)));
    task.await??;
    Ok(())
}
