//! Local, authenticated agent telemetry. Reading statistics never opens an
//! application socket, sends an API request or triggers a health repair.
use anyhow::{ensure, Result};
use crate::terminal_ui::{InputReader,Screen};
use clap::Args;
use porthub_tunnel::ServiceHealthHandle;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    io::{IsTerminal, Write},
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
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

fn number(row: &Value, key: &str) -> u64 {
    row[key].as_u64().unwrap_or(0)
}
fn bytes(value: f64) -> String {
    let mut value = value;
    let units = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < units.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", units[unit])
}
fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect()
}

fn render(
    rows: &[Value],
    width: usize,
    height: usize,
    paused: bool,
    selected: usize,
    details: bool,
) -> String {
    let mut lines = vec![
        format!("PortHub stats  {}", if paused { "PAUSED" } else { "LIVE" }),
        "".into(),
    ];
    let upload: f64 = rows
        .iter()
        .filter_map(|row| row["rates"]["sent_per_second"].as_f64())
        .sum();
    let download: f64 = rows
        .iter()
        .filter_map(|row| row["rates"]["received_per_second"].as_f64())
        .sum();
    let memory: u64 = rows
        .iter()
        .map(|row| number(&row["process"], "rss_bytes"))
        .sum();
    lines.push(format!(
        "{} agents   TX {}/s   RX {}/s   RAM {}",
        rows.len(),
        if rows.iter().any(|row| row["rates"].is_object()) {
            bytes(upload)
        } else {
            "—".into()
        },
        if rows.iter().any(|row| row["rates"].is_object()) {
            bytes(download)
        } else {
            "—".into()
        },
        if rows.iter().any(|row| row["process"].is_object()) {
            bytes(memory as f64)
        } else {
            "—".into()
        }
    ));
    lines.push("Public application payload; process resources belong to the agent only.".into());
    lines.push("".into());
    lines.push(format!(
        "  {:<16} {:<11} {:>7} {:>10} {:>10} {:>10}",
        "REGISTRATION", "STATE", "CPU %", "TX /s", "RX /s", "RSS"
    ));
    let visible = height.saturating_sub(if details { 18 } else { 9 }).max(1);
    for (index, row) in rows
        .iter()
        .enumerate()
        .skip(selected.saturating_sub(visible - 1))
        .take(visible)
    {
        let id = clean(row["registration"].as_str().unwrap_or(""), 16);
        let state = if row["unavailable"] == true {
            "unavailable"
        } else {
            row["state"].as_str().unwrap_or("unknown")
        };
        let rate = |key: &str| {
            row["rates"][key]
                .as_f64()
                .map(bytes)
                .unwrap_or_else(|| "—".into())
        };
        let cpu = row["rates"]["cpu_percent"]
            .as_f64()
            .map(|cpu| format!("{cpu:.1}"))
            .unwrap_or_else(|| "—".into());
        lines.push(format!(
            "{} {:<16} {:<11} {:>7} {:>10} {:>10} {:>10}",
            if index == selected { ">" } else { " " },
            id,
            clean(state, 11),
            cpu,
            rate("sent_per_second"),
            rate("received_per_second"),
            row["process"]["rss_bytes"]
                .as_u64()
                .map(|rss| bytes(rss as f64))
                .unwrap_or_else(|| "—".into())
        ));
    }
    if rows.is_empty() {
        lines.push(
            "No registered agents. Use porthub ls, or --user for per-user registrations.".into(),
        );
    }
    if details {
        if let Some(row) = rows.get(selected) {
            lines.push("".into());
            lines.push(format!(
                "Selected agent: {}",
                clean(row["machine_id"].as_str().unwrap_or(""), 40)
            ));
            lines.push(format!(
                "PID {}   Uptime {}s   Version {}   Route {}",
                row["process"]["pid"],
                number(&row["process"], "uptime_seconds"),
                clean(row["agent_version"].as_str().unwrap_or(""), 24),
                clean(row["route"].as_str().unwrap_or(""), 30)
            ));
            lines.push(format!(
                "Channels {}   TX total {}   RX total {}   FDs {}",
                number(&row["traffic"], "active_channels"),
                bytes(number(&row["traffic"], "sent_bytes") as f64),
                bytes(number(&row["traffic"], "received_bytes") as f64),
                row["open_descriptors"]
            ));
            if let Some(services) = row["services"].as_array() {
                for service in services.iter().take(4) {
                    lines.push(format!(
                        "  {}  {}  {} active",
                        clean(service["name"].as_str().unwrap_or(""), 32),
                        service["health"]["state"].as_str().unwrap_or("unknown"),
                        number(&service["traffic"], "active_channels")
                    ));
                }
            }
        }
    }
    lines.push("".into());
    lines.push(
        "q quit | Space pause | ↑/↓ select | Enter details | t traffic | c CPU | m memory | n name"
            .into(),
    );
    lines
        .into_iter()
        .take(height)
        .map(|line| clean(&line, width))
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn update_rates(
    rows: &mut [Value],
    previous: &mut BTreeMap<String, (Instant, Value)>,
    now: Instant,
) {
    for row in rows.iter_mut() {
        let id = row["registration"].as_str().unwrap_or("").to_owned();
        let rates=previous.get(&id).and_then(|(at,old)|{
                            if row["unavailable"]==true || old["unavailable"]==true || row["process"]["pid"]!=old["process"]["pid"] || row["process"]["start_time"]!=old["process"]["start_time"]{return None;}
                            let elapsed=now.duration_since(*at).as_secs_f64().max(0.001);
                            Some(json!({"sent_per_second":number(&row["traffic"],"sent_bytes").saturating_sub(number(&old["traffic"],"sent_bytes")) as f64/elapsed,
                                "received_per_second":number(&row["traffic"],"received_bytes").saturating_sub(number(&old["traffic"],"received_bytes")) as f64/elapsed,
                                "cpu_percent":number(&row["process"],"cpu_millis").saturating_sub(number(&old["process"],"cpu_millis")) as f64/(elapsed*10.0)}))
                        });
        previous.insert(id, (now, row.clone()));
        row["rates"] = rates.unwrap_or(Value::Null);
    }
    previous.retain(|id, _| {
        rows.iter()
            .any(|row| row["registration"].as_str() == Some(id.as_str()))
    });
}

pub async fn run(options: Options, cancel: CancellationToken) -> Result<()> {
    use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers};
    let interactive = !options.json
        && !options.once
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal();
    let _screen = if interactive {
        Some(Screen::enter()?)
    } else {
        None
    };
    let (_input_reader, mut events) = if interactive {
        let (reader, receive) = InputReader::start();
        (Some(reader), Some(receive))
    } else {
        (None, None)
    };
    let mut previous: BTreeMap<String, (Instant, Value)> = BTreeMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs_f64(options.interval));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut rows = Vec::new();
    let mut paused = false;
    let mut selected = 0usize;
    let mut details = true;
    let mut sort = 't';
    let mut pending: Option<tokio_util::task::AbortOnDropHandle<Result<Vec<Value>>>> = None;
    loop {
        let mut preserve = rows
            .get(selected)
            .and_then(|row: &Value| row["registration"].as_str())
            .map(str::to_owned);
        tokio::select! {
            _=cancel.cancelled()=>break,
            _=tick.tick()=>{
                if !paused && pending.is_none() {
                    let options=options.clone();
                    pending=Some(tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move{collect(&options).await})));
                }
            }
            result=async{match &mut pending{Some(task)=>task.await,None=>std::future::pending().await}}=>{
                rows=result??;pending=None;
                update_rates(&mut rows,&mut previous,Instant::now());
                if options.json {println!("{}",json!({"agents":rows,"observed_at":porthub_terminal::protocol::now()}));}
                else if !interactive {println!("{}",render(&rows,160,200,false,0,true).replace('\r',""));}
                if options.once || !interactive && !options.json{break;}
            }
            event=async{match &mut events{Some(events)=>events.recv().await,None=>std::future::pending().await}}=>{
                match event {
                    Some(Ok(Event::Key(key))) if key.kind!=KeyEventKind::Release=>match key.code{
                        KeyCode::Char('q')|KeyCode::Esc=>break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL)=>break,
                        KeyCode::Char(' ')=>{paused=!paused;if paused{pending=None;}},
                        KeyCode::Up=>{selected=selected.saturating_sub(1);preserve=None;},KeyCode::Down=>{selected=(selected+1).min(rows.len().saturating_sub(1));preserve=None;},
                        KeyCode::Enter=>details=!details,
                        KeyCode::Char(key @ ('t'|'c'|'m'|'n'))=>sort=key,
                        _=>{},
                    },Some(Err(error))=>return Err(error.into()),_=>{},
                }
            }
        }
        if interactive {
            rows.sort_by(|a, b| {
                let metric = |row: &Value| match sort {
                    'c' => row["rates"]["cpu_percent"].as_f64().unwrap_or(0.0),
                    'm' => number(&row["process"], "rss_bytes") as f64,
                    _ => {
                        row["rates"]["sent_per_second"].as_f64().unwrap_or(0.0)
                            + row["rates"]["received_per_second"].as_f64().unwrap_or(0.0)
                    }
                };
                if sort == 'n' {
                    a["registration"].as_str().cmp(&b["registration"].as_str())
                } else {
                    metric(b).total_cmp(&metric(a)).then_with(||a["registration"].as_str().cmp(&b["registration"].as_str()))
                }
            });
            if let Some(id) = preserve {
                if let Some(index) = rows
                    .iter()
                    .position(|row| row["registration"].as_str() == Some(id.as_str()))
                {
                    selected = index;
                }
            }
            selected = selected.min(rows.len().saturating_sub(1));
            let (width, height) = crossterm::terminal::size()?;
            crossterm::execute!(
                std::io::stdout(),
                crossterm::cursor::MoveTo(0, 0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::All),
                crossterm::style::Print(render(
                    &rows,
                    usize::from(width),
                    usize::from(height),
                    paused,
                    selected,
                    details
                ))
            )?;
            std::io::stdout().flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rates_warm_up_and_reset_on_agent_restart_instead_of_spiking() {
        let first = json!({"registration":"fixture","process":{"pid":12,"start_time":10,"cpu_millis":100},"traffic":{"sent_bytes":100,"received_bytes":200}});
        let second = json!({"registration":"fixture","process":{"pid":12,"start_time":10,"cpu_millis":600},"traffic":{"sent_bytes":1100,"received_bytes":2200}});
        let mut previous = BTreeMap::new();
        let at = Instant::now();
        let mut rows = vec![first];
        update_rates(&mut rows, &mut previous, at);
        assert!(rows[0]["rates"].is_null());
        let mut rows = vec![second];
        update_rates(&mut rows, &mut previous, at + Duration::from_secs(1));
        assert_eq!(rows[0]["rates"]["sent_per_second"], 1000.0);
        assert_eq!(rows[0]["rates"]["received_per_second"], 2000.0);
        assert_eq!(rows[0]["rates"]["cpu_percent"], 50.0);
        rows[0]["process"]["start_time"] = json!(20);
        update_rates(&mut rows, &mut previous, at + Duration::from_secs(2));
        assert!(
            rows[0]["rates"].is_null(),
            "PID reuse must begin a fresh rate baseline"
        );
    }
    #[test]
    fn screen_fits_normal_ssh_terminal_and_scrolls_selected_registration_into_view() {
        let rows=(0..12).map(|index|json!({"registration":format!("agent{index:02}"),"state":"running","process":{"rss_bytes":1048576}})).collect::<Vec<_>>();
        let output = render(&rows, 80, 24, false, 11, true);
        assert!(output.contains("> agent11"));
        assert!(output.contains("RSS"));
        assert!(output.lines().all(|line| line.chars().count() <= 80));
        assert!(output.lines().count() <= 24);
        assert_eq!(clean("safe\u{1b}[31m\nname", 30), "safe[31mname");
    }
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
