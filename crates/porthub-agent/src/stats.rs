//! Local, authenticated agent telemetry. Reading statistics never opens an
//! application socket, sends an API request or triggers a health repair.
use anyhow::{ensure, Result};
use clap::Args;
use porthub_tunnel::ServiceHealthHandle;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, OnceLock},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Registry {
    current: HashMap<String, ServiceHealthHandle>,
    retired: Vec<(String, ServiceHealthHandle)>,
    sent: u64,
    received: u64,
}
static SERVICES: OnceLock<Mutex<Registry>> = OnceLock::new();
fn registry() -> &'static Mutex<Registry> {
    SERVICES.get_or_init(Default::default)
}
pub(crate) fn configure(handles: HashMap<String, ServiceHealthHandle>) {
    let mut registry = registry().lock().unwrap_or_else(|error| error.into_inner());
    let old = std::mem::replace(&mut registry.current, handles);
    for (name, handle) in old {
        if !registry
            .current
            .get(&name)
            .is_some_and(|next| next.same_instance(&handle))
        {
            registry.retired.push((name, handle));
        }
    }
    archive(&mut registry);
}
fn archive(registry: &mut Registry) {
    for (name, handle) in std::mem::take(&mut registry.retired) {
        let traffic = handle.traffic();
        if traffic.active_channels == 0 && handle.traffic_finished() {
            registry.sent = registry.sent.saturating_add(traffic.sent_bytes);
            registry.received = registry.received.saturating_add(traffic.received_bytes);
        } else {
            registry.retired.push((name, handle));
        }
    }
}

fn snapshot(profile: &Path, machine: &str) -> Result<Value> {
    let mut registry = registry().lock().unwrap_or_else(|error| error.into_inner());
    archive(&mut registry);
    let mut sent = registry.sent;
    let mut received = registry.received;
    let mut active = 0u64;
    let mut rows = Vec::new();
    for (name, handle) in registry
        .current
        .iter()
        .chain(registry.retired.iter().map(|(name, handle)| (name, handle)))
    {
        let traffic = handle.traffic();
        sent = sent.saturating_add(traffic.sent_bytes);
        received = received.saturating_add(traffic.received_bytes);
        active = active.saturating_add(traffic.active_channels);
        rows.push(json!({"name":clean(name,64),"health":handle.observe(),"traffic":traffic}));
    }
    let total_services = rows.len();
    rows.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    rows.truncate(50);
    drop(registry);
    let status = crate::profile::read_private(&crate::profile::sibling(profile, ".status.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<crate::runtime::Status>(&bytes).ok());
    let status = status.filter(|status| status.pid == std::process::id());
    let pid = sysinfo::Pid::from_u32(std::process::id());
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[pid]),
        true,
        sysinfo::ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_disk_usage(),
    );
    let process=system.process(pid).map(|process|json!({"pid":std::process::id(),"start_time":process.start_time(),"uptime_seconds":process.run_time(),
        "cpu_millis":process.accumulated_cpu_time(),"rss_bytes":process.memory(),"virtual_bytes":process.virtual_memory(),
        "disk_read_bytes":process.disk_usage().total_read_bytes,"disk_written_bytes":process.disk_usage().total_written_bytes}));
    #[cfg(target_os = "linux")]
    let descriptors = std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|files| files.count());
    #[cfg(not(target_os = "linux"))]
    let descriptors: Option<usize> = None;
    Ok(
        json!({"schema_version":1,"machine_id":machine,"agent_version":crate::VERSION,"observed_at":porthub_terminal::protocol::now(),
        "state":status.as_ref().map(|status|status.state.as_str()).unwrap_or("running"),"route":status.as_ref().map(|status|status.route.as_str()).unwrap_or(""),
        "private_status":status.as_ref().and_then(|status|status.private_status.as_ref()),"process":process,"open_descriptors":descriptors,
        "traffic":{"sent_bytes":sent,"received_bytes":received,"active_channels":active,"scope":"public tunnel application payload"},
        "terminal":{"measurements":crate::terminal_telemetry::snapshot(profile),
            "payload_scope":"guest PTY bytes; output includes redraws; delivery not implied",
            "udp_scope":"host RTC UDP observations; external candidate discovery excluded",
            "relay_scope":"gateway terminal payload; control and TLS/WebSocket framing excluded"},
        "services":rows,"service_count":total_services,"services_truncated":total_services>50}),
    )
}

pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    mut local: BufReader<S>,
    control: &crate::control::Control,
    profile: &Path,
    request: Value,
    cancel: CancellationToken,
) -> Result<()> {
    ensure!(
        request
            .as_object()
            .is_some_and(|object| object.len() == 1
                && object.get("operation") == Some(&json!("agent_stats"))),
        "invalid statistics request"
    );
    let profile = profile.to_owned();
    let machine = control.profile().machine_id.clone();
    let data = tokio::select! {_=cancel.cancelled()=>return Ok(()),data=tokio::task::spawn_blocking(move||snapshot(&profile,&machine))=>data??};
    let mut bytes = serde_json::to_vec(&data)?;
    ensure!(bytes.len() < 32768, "statistics snapshot exceeds limit");
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(2), local.get_mut().write_all(&bytes)).await??;
    Ok(())
}

#[derive(Args, Clone)]
pub struct Options {
    /// Limit statistics to a registration ID from porthub ls.
    #[arg(long)]
    registration: Option<String>,
    #[arg(long)]
    user: bool,
    /// One snapshot, without an interactive screen.
    #[arg(long, alias = "no-stream")]
    once: bool,
    /// Machine-readable snapshots; streaming mode emits newline-delimited JSON.
    #[arg(long)]
    json: bool,
    /// Refresh interval in seconds.
    #[arg(long,default_value_t=1.0,value_parser=interval)]
    interval: f64,
}
fn interval(value: &str) -> Result<f64, String> {
    let value = value
        .parse::<f64>()
        .map_err(|_| "interval must be a number".to_owned())?;
    if value.is_finite() && (0.2..=60.0).contains(&value) {
        Ok(value)
    } else {
        Err("interval must be between 0.2 and 60 seconds".into())
    }
}

async fn collect(options: &Options) -> Result<Vec<Value>> {
    let layout = if options.user {
        crate::service::Layout::user()?
    } else {
        crate::service::Layout::system()?
    };
    let records = if let Some(id) = &options.registration {
        vec![crate::service::readable::select(
            &layout,
            Some(id),
            Some(false),
        )?]
    } else {
        crate::service::readable::list(&layout)?
            .into_iter()
            .filter(|record| !record.private)
            .collect()
    };
    ensure!(
        records.len() <= 128,
        "more than 128 registrations; select one with --registration"
    );
    let mut rows = Vec::new();
    for batch in records.chunks(8) {
        let mut tasks = tokio::task::JoinSet::new();
        for record in batch {
            let layout = layout.clone();
            let id = record.id.clone();
            let machine = record.machine_id.clone();
            let state = record.state.clone();
            tasks.spawn(async move {
                let response=tokio::time::timeout(Duration::from_secs(2),async {
                    let mut stream=crate::exposure_broker::connect_stream(&layout,&id).await?;
                    stream.write_all(b"{\"operation\":\"agent_stats\"}\n").await?;
                    let mut reader=BufReader::new(stream);let mut partial=Vec::new();
                    let bytes=crate::terminal_transport::frame(&mut reader,&mut partial).await?;
                    let row:Value=serde_json::from_slice(&bytes)?;
                    ensure!(row["schema_version"]==1 && row["machine_id"].as_str()==Some(machine.as_str())
                        && row["process"]["pid"].as_u64().is_some_and(|pid|pid>0),"invalid agent statistics response");
                    Ok::<Value,anyhow::Error>(row)
                }).await;
                let mut row=match response{Ok(Ok(row))=>row,_=>json!({"state":state,"machine_id":machine,"unavailable":true,"detail":"Agent statistics unavailable; start or update this registration"})};
                row["registration"]=json!(id);row
            });
        }
        while let Some(row) = tasks.join_next().await {
            rows.push(row?);
        }
    }
    Ok(rows)
}

fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect()
}
struct DashboardSource(Options);
#[async_trait::async_trait]
impl porthub_components::rpc::Handler for DashboardSource {
    type Operation = porthub_components::protocol::stats::Operation;
    type Value = porthub_components::protocol::stats::Value;
    fn connection_limit(&self) -> usize {
        2
    }
    fn exit_when_idle(&self) -> bool {
        false
    }
    async fn handle(
        &self,
        _operation: Self::Operation,
        cancel: CancellationToken,
    ) -> std::result::Result<
        porthub_components::rpc::Reply<Self::Value>,
        porthub_components::rpc::Failure,
    > {
        use porthub_components::{
            ipc,
            protocol::stats::Row,
            rpc::{ErrorCode, Failure, Reply},
        };
        let rows = tokio::select! {biased; _=cancel.cancelled()=>return Err(Failure {code:ErrorCode::Unavailable,detail:"Statistics request cancelled".into()}),
        result=collect(&self.0)=>result.map_err(|_| Failure {code:ErrorCode::Unavailable,detail:"Cannot collect scoped agent statistics".into()})?};
        if rows.iter().any(|row| {
            serde_json::to_vec(row).map_or(true, |bytes| {
                bytes.len() > porthub_components::protocol::stats::MAX_ROW
            })
        }) {
            return Err(Failure {
                code: ErrorCode::Unavailable,
                detail: "Statistics snapshot limit exceeded".into(),
            });
        }
        let count = rows.len();
        let (caller, mut output) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            for row in rows {
                let frame = Row { data: row };
                let result = tokio::select! {biased; _=cancel.cancelled()=>break,
                result=ipc::write(&mut output,&frame,Duration::from_secs(5))=>result};
                if result.is_err() {
                    break;
                }
            }
        });
        Ok(Reply::Stream {
            value: Self::Value::Snapshot { rows: count },
            remote: Box::new(caller),
        })
    }
}

pub async fn run(options: Options, cancel: CancellationToken) -> Result<()> {
    use porthub_components::{
        catalog::{Component, PROTOCOL},
        ipc::Hello,
        local::Endpoint,
    };
    let manager = crate::components::manager(None)?;
    if manager.installed(Component::Stats).await?.is_empty() {
        eprintln!("Preparing stats: downloading a verified compatible dashboard if needed...");
    }
    let (artifact, executable) = manager.resolve(Component::Stats, &cancel).await?;
    let invocation = tempfile::tempdir()?;
    let endpoint = Endpoint::for_artifact(invocation.path(), &artifact)?;
    let work = cancel.child_token();
    let _stop = work.clone().drop_guard();
    let hello = Hello {
        component: Component::Stats,
        protocol: PROTOCOL,
        version: artifact.version.clone(),
    };
    let serving = endpoint.clone();
    let lifetime = work.clone();
    let handler = std::sync::Arc::new(DashboardSource(options.clone()));
    let _server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        porthub_components::rpc::serve(serving, hello, handler, lifetime).await
    }));
    let mut arguments: Vec<std::ffi::OsString> = vec![
        "--managed-endpoint".into(),
        endpoint.address().into(),
        "--interval".into(),
        options.interval.to_string().into(),
    ];
    if options.once {
        arguments.push("--once".into());
    }
    if options.json {
        arguments.push("--json".into());
    }
    use std::io::IsTerminal;
    let interactive = !options.json
        && !options.once
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal();
    // Core owns restoration even if the frontend crashes or is force-stopped.
    let _terminal = if interactive {
        Some(crate::terminal_ui::Screen::enter()?)
    } else {
        None
    };
    let mut child = porthub_components::foreground(&executable, &arguments, &cancel).await?;
    let status = tokio::select! {biased; _=cancel.cancelled()=>{let _=child.kill().await;return Ok(());},status=child.wait()=>status?};
    ensure!(
        status.success(),
        "optional statistics dashboard exited unsuccessfully"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_interval_is_bounded_and_rejects_nan_and_infinity() {
        for invalid in ["0", "0.1", "61", "NaN", "inf", "-1"] {
            assert!(interval(invalid).is_err());
        }
        assert_eq!(interval("0.2").unwrap(), 0.2);
        assert_eq!(interval("1").unwrap(), 1.0);
    }
    #[tokio::test]
    async fn broker_reports_only_whitelisted_process_metrics_without_credentials() -> Result<()> {
        let profile: crate::profile::Profile = serde_json::from_value(
            json!({"server":"http://127.0.0.1:9","machine_id":"0123456789abcdef01234567","token":"never-return-this-secret","allow_insecure_http_for_tests":true}),
        )?;
        let control = crate::control::Control::new(profile)?;
        let directory = tempfile::tempdir()?;
        let source = directory.path().join("missing-profile.json");
        let mut terminal = crate::terminal_telemetry::Lease::open(&source, 1)?;
        terminal.participants(1);
        let mut emitter = crate::terminal_telemetry::Emitter::new(terminal.policy())?;
        terminal.record(emitter.report(porthub_terminal::traffic::Snapshot {
            input_bytes: 7,
            direct_udp_sent_bytes: 13,
            ..Default::default()
        })?)?;
        assert_eq!(
            crate::terminal_telemetry::snapshot(&source.with_file_name("other-profile.json"))
                .counters
                .input_bytes,
            0
        );
        let (mut caller, stream) = tokio::io::duplex(65536);
        let request = serve(
            BufReader::new(stream),
            &control,
            &source,
            json!({"operation":"agent_stats"}),
            CancellationToken::new(),
        );
        let response = async {
            use tokio::io::AsyncReadExt;
            let mut bytes = Vec::new();
            caller.read_to_end(&mut bytes).await?;
            let text = std::str::from_utf8(&bytes)?;
            assert!(!text.contains("never-return-this-secret"));
            assert!(!text.contains("environment"));
            let value: Value = serde_json::from_slice(&bytes)?;
            assert_eq!(
                value["terminal"]["measurements"]["counters"]["input_bytes"],
                7
            );
            assert_eq!(
                value["terminal"]["measurements"]["counters"]["direct_udp_sent_bytes"],
                13
            );
            assert_eq!(value["terminal"]["measurements"]["active_participants"], 1);
            assert_eq!(value["schema_version"], 1);
            assert_eq!(value["process"]["pid"], std::process::id());
            assert_eq!(value["machine_id"], "0123456789abcdef01234567");
            Ok::<_, anyhow::Error>(())
        };
        let (sent, received) = tokio::join!(request, response);
        sent?;
        received?;
        let (caller, stream) = tokio::io::duplex(1024);
        drop(caller);
        assert!(serve(
            BufReader::new(stream),
            &control,
            &source,
            json!({"operation":"agent_stats","token":"injected"}),
            CancellationToken::new()
        )
        .await
        .is_err());
        Ok(())
    }
}
