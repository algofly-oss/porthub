//! One bounded, service-owned reporter per registered profile. Reporting errors
//! never enter terminal transport, repair or reconnection decisions. An idle
//! reporter remains dormant until service cancellation, preventing a new host
//! from racing worker shutdown; unchanged snapshots cause no HTTP requests.
use crate::{
    control::{Control, Failure},
    terminal_telemetry,
};
use serde::Deserialize;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

const INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
static WORKERS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
fn workers() -> &'static Mutex<HashSet<PathBuf>> {
    WORKERS.get_or_init(Default::default)
}
struct Permit(PathBuf);
impl Drop for Permit {
    fn drop(&mut self) {
        workers()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.0);
    }
}
/// Called only after the authenticated gateway advertises ingestion support and
/// accepts a host. The shared broker token outlives each individual host socket.
pub(crate) fn start(profile: &Path, control: Arc<Control>, cancel: CancellationToken) -> bool {
    if cancel.is_cancelled() || !terminal_telemetry::snapshot(profile).valid() {
        return false;
    }
    let mut active = workers().lock().unwrap_or_else(|error| error.into_inner());
    if active.len() >= 128 || !active.insert(profile.into()) {
        return false;
    }
    let permit = Permit(profile.into());
    tokio::spawn(async move {
        let _permit = permit;
        run(&_permit.0, &control, cancel, INTERVAL).await;
    });
    true
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Ack {
    #[serde(rename = "accepted")]
    _accepted: bool,
    revision: u64,
}
async fn send(
    control: &Control,
    summary: &porthub_terminal::traffic_report::Summary,
) -> Result<(), Failure> {
    let body = serde_json::json!({"machine_id":control.profile().machine_id,"token":control.profile().token,"summary":summary});
    let reply = tokio::time::timeout(
        Duration::from_secs(8),
        control.request(
            reqwest::Method::POST,
            "machines/client/terminal-traffic",
            Some(body),
            &[],
        ),
    )
    .await
    .map_err(|_| Failure::Unavailable)??;
    if reply.bytes.len() > 4096 {
        return Err(Failure::InvalidResponse);
    }
    let ack: Ack = serde_json::from_slice(&reply.bytes).map_err(|_| Failure::InvalidResponse)?;
    // A lost acknowledgement can make a successful retry an idempotent no-op.
    // Both forms must acknowledge at least the submitted cumulative revision.
    if ack.revision < summary.revision
        || ack.revision > porthub_terminal::traffic_report::MAX_COUNTER
    {
        return Err(Failure::InvalidResponse);
    }
    Ok(())
}
fn should_upload(
    current: &porthub_terminal::traffic_report::Summary,
    previous: &porthub_terminal::traffic_report::Summary,
    elapsed: Duration,
) -> bool {
    current.instance != previous.instance
        || current.values() != previous.values()
        || current.active_sessions != previous.active_sessions
        || current.active_participants != previous.active_participants
        || current.active_reporting_sessions != previous.active_reporting_sessions
        || current.reported_sessions != previous.reported_sessions
        || (current.active_sessions > 0
            && current.revision > previous.revision
            && elapsed >= HEARTBEAT)
}
async fn run(profile: &Path, control: &Control, cancel: CancellationToken, interval: Duration) {
    let mut acknowledged = None;
    let mut last_success = Instant::now();
    let mut delay = Duration::ZERO;
    let mut backoff = interval;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(delay) => {},
        }
        let summary = terminal_telemetry::snapshot(profile);
        if !summary.valid() {
            break;
        }
        if acknowledged
            .as_ref()
            .is_none_or(|previous| should_upload(&summary, previous, last_success.elapsed()))
        {
            let outcome = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = send(control, &summary) => result,
            };
            match outcome {
                Ok(()) => {
                    acknowledged = Some(summary);
                    last_success = Instant::now();
                    backoff = interval;
                }
                Err(Failure::Rejected(code))
                    if matches!(code, 400 | 401 | 403 | 409 | 410 | 422) =>
                {
                    break
                }
                Err(_) => {
                    delay = backoff;
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            }
        }
        delay = interval;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{ensure, Result};
    use serde_json::Value;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
    };
    async fn fixture() -> Result<(tempfile::TempDir, PathBuf, Arc<Control>, TcpListener)> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("public.json");
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let profile = serde_json::from_value(
            serde_json::json!({"server":format!("http://{}",listener.local_addr()?),"machine_id":"0123456789abcdef01234567","token":"privileged-fixture-token","allow_insecure_http_for_tests":true}),
        )?;
        Ok((directory, path, Arc::new(Control::new(profile)?), listener))
    }
    async fn request(listener: &TcpListener) -> Result<(BufReader<TcpStream>, Value)> {
        let (socket, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
        let mut reader = BufReader::new(socket);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        ensure!(line == "POST /api/machines/client/terminal-traffic HTTP/1.1\r\n");
        let mut length = 0;
        loop {
            line.clear();
            ensure!(reader.read_line(&mut line).await? > 0 && line.len() <= 8192);
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = value.trim().parse::<usize>()?;
            }
        }
        ensure!((1..=8192).contains(&length));
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        let value: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value["machine_id"] == "0123456789abcdef01234567"
                && value["token"] == "privileged-fixture-token"
        );
        ensure!(value.as_object().unwrap().len() == 3);
        ensure!(!value.to_string().contains("terminal_local_traffic"));
        Ok((reader, value))
    }
    async fn reply(reader: &mut BufReader<TcpStream>, status: &str, body: Value) -> Result<()> {
        let body = body.to_string();
        reader
            .get_mut()
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await?;
        reader.get_mut().shutdown().await?;
        Ok(())
    }
    async fn released(path: &Path) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(1), async {
            while workers().lock().unwrap().contains(path) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        Ok(())
    }
    #[test]
    fn empty_host_samples_are_coalesced_but_measurements_and_closed_gauges_are_prompt() {
        use porthub_terminal::traffic_report::Summary;
        let previous = Summary {
            instance: "a".repeat(32),
            revision: 1,
            active_sessions: 1,
            ..Default::default()
        };
        let mut next = previous.clone();
        next.revision = 2;
        next.observed_at = Some(1);
        assert!(!should_upload(&next, &previous, Duration::from_secs(29)));
        assert!(should_upload(&next, &previous, HEARTBEAT));
        next.counters.input_bytes = 1;
        assert!(should_upload(&next, &previous, Duration::ZERO));
        next.counters.input_bytes = 0;
        next.active_sessions = 0;
        assert!(should_upload(&next, &previous, Duration::ZERO));
        assert!(!should_upload(&next, &next, Duration::from_secs(86400)));
    }
    #[tokio::test]
    async fn retry_is_idempotent_and_latest_closed_gauges_are_uploaded_without_idle_polling(
    ) -> Result<()> {
        let (_directory, path, control, listener) = fixture().await?;
        let lease = terminal_telemetry::Lease::open(&path, 2)?;
        let cancel = CancellationToken::new();
        let job = {
            let path = path.clone();
            let control = control.clone();
            let cancel = cancel.clone();
            tokio::spawn(
                async move { run(&path, &control, cancel, Duration::from_millis(25)).await },
            )
        };
        let (socket, first) = request(&listener).await?;
        drop(socket); // The gateway committed the report but its reply was lost.
        let (mut socket, retry) = request(&listener).await?;
        ensure!(
            first == retry,
            "unchanged cumulative retries must be identical"
        );
        reply(
            &mut socket,
            "200 OK",
            serde_json::json!({"accepted":false,"revision":retry["summary"]["revision"]}),
        )
        .await?;
        drop(lease);
        let (mut socket, last) = request(&listener).await?;
        ensure!(last["summary"]["active_sessions"] == 0);
        ensure!(
            last["summary"]["revision"].as_u64().unwrap()
                > first["summary"]["revision"].as_u64().unwrap()
        );
        reply(
            &mut socket,
            "200 OK",
            serde_json::json!({"accepted":true,"revision":last["summary"]["revision"]}),
        )
        .await?;
        ensure!(
            tokio::time::timeout(Duration::from_millis(120), listener.accept())
                .await
                .is_err(),
            "idle reporters must not keep sending unchanged counters"
        );
        // A new host reuses the same reporter and service-instance baseline.
        let next = terminal_telemetry::Lease::open(&path, 2)?;
        let (mut socket, resumed) = request(&listener).await?;
        ensure!(
            resumed["summary"]["active_sessions"] == 1
                && resumed["summary"]["instance"] == first["summary"]["instance"]
        );
        reply(
            &mut socket,
            "200 OK",
            serde_json::json!({"accepted":true,"revision":resumed["summary"]["revision"]}),
        )
        .await?;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), job).await??;
        drop(next);
        Ok(())
    }
    #[tokio::test]
    async fn one_worker_per_profile_is_cancelled_even_while_http_is_stuck() -> Result<()> {
        let (_directory, path, control, listener) = fixture().await?;
        let lease = terminal_telemetry::Lease::open(&path, 2)?;
        let cancel = CancellationToken::new();
        ensure!(start(&path, control.clone(), cancel.clone()));
        ensure!(!start(&path, control.clone(), cancel.clone()));
        let (_socket, _) = request(&listener).await?; // Hold the response open.
        cancel.cancel();
        released(&path).await?;
        ensure!(
            terminal_telemetry::snapshot(&path).active_sessions == 1,
            "reporter cancellation must not close a terminal host"
        );
        ensure!(!start(&path, control.clone(), cancel));
        let next = CancellationToken::new();
        ensure!(
            start(&path, control, next.clone()),
            "cancelled workers must release their profile slot"
        );
        next.cancel();
        released(&path).await?;
        drop(lease);
        Ok(())
    }
    #[tokio::test]
    async fn disabled_machine_response_stops_reporting_without_stopping_the_host() -> Result<()> {
        let (_directory, path, control, listener) = fixture().await?;
        let lease = terminal_telemetry::Lease::open(&path, 1)?;
        ensure!(start(&path, control, CancellationToken::new()));
        let (mut socket, _) = request(&listener).await?;
        reply(
            &mut socket,
            "403 Forbidden",
            serde_json::json!({"detail":"Machine disabled"}),
        )
        .await?;
        released(&path).await?;
        ensure!(terminal_telemetry::snapshot(&path).active_sessions == 1);
        drop(lease);
        Ok(())
    }
}
