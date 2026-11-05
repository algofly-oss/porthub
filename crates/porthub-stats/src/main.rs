use anyhow::{ensure, Context, Result};
use clap::Parser;
use porthub_stats::{Options, Source};
use serde_json::{json, Value};
use std::{collections::BTreeSet, io::Read, path::PathBuf, sync::Arc};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version=option_env!("PORTHUB_COMPONENT_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")), about="Independent live process and snapshot dashboard")]
struct Args {
    /// Monitor a process; without this, show up to 128 processes by memory use.
    #[arg(long, conflicts_with = "input")]
    pid: Option<u32>,
    /// Read {"agents":[...]} snapshots from a file refreshed by another tool.
    #[arg(long)]
    input: Option<PathBuf>,
    #[arg(long, hide=true, conflicts_with_all=["input", "pid"])]
    managed_endpoint: Option<String>,
    #[arg(long, hide=true, conflicts_with_all=["managed_endpoint", "input", "pid"])]
    managed_input: Option<PathBuf>,
    #[arg(long)]
    once: bool,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value="1", value_parser=interval)]
    interval: f64,
}
fn interval(value: &str) -> Result<f64, String> {
    match value.parse::<f64>() {
        Ok(value) if value.is_finite() && (0.2..=60.0).contains(&value) => Ok(value),
        _ => Err("interval must be between 0.2 and 60 seconds".into()),
    }
}
struct ManagedSource(String);
#[async_trait::async_trait]
impl Source for ManagedSource {
    async fn collect(&self) -> Result<Vec<Value>> {
        use porthub_components::{
            catalog::{Component, PROTOCOL},
            ipc::{self, Hello},
            local::Endpoint,
            protocol::stats::{Operation, Row, Value as Response},
            rpc::Client,
        };
        use std::time::Duration;
        let endpoint = Endpoint::parse(Component::Stats, &self.0)?;
        let expected = Hello {
            component: Component::Stats,
            protocol: PROTOCOL,
            version: option_env!("PORTHUB_COMPONENT_VERSION")
                .unwrap_or(env!("CARGO_PKG_VERSION"))
                .parse()?,
        };
        let mut retries = 0;
        let client = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match Client::connect_expected(&endpoint, &expected).await {
                    Ok(client) => break Ok(client),
                    Err(error) if retries >= 20 => break Err(error),
                    Err(_) => {
                        retries += 1;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        })
        .await
        .context("managed statistics broker startup timed out")??;
        let (Response::Snapshot { rows }, mut stream) = client
            .upgrade::<_, Response>(Operation::Collect, Duration::from_secs(40))
            .await?;
        ensure!(rows <= 128, "managed snapshot has too many rows");
        let mut result = Vec::with_capacity(rows);
        for _ in 0..rows {
            let row: Row = ipc::read(&mut stream, Duration::from_secs(5)).await?;
            ensure!(
                serde_json::to_vec(&row.data)?.len()
                    <= porthub_components::protocol::stats::MAX_ROW,
                "managed snapshot row exceeds limit"
            );
            result.push(row.data);
        }
        Ok(result)
    }
}
struct FileSource {
    path: PathBuf,
    managed: bool,
    sequence: std::sync::atomic::AtomicU64,
}
impl FileSource {
    fn new(path: PathBuf, managed: bool) -> Self {
        Self {
            path,
            managed,
            sequence: std::sync::atomic::AtomicU64::new(0),
        }
    }
}
#[async_trait::async_trait]
impl Source for FileSource {
    async fn collect(&self) -> Result<Vec<Value>> {
        let path = self.path.clone();
        let managed = self.managed;
        let previous = self.sequence.load(std::sync::atomic::Ordering::Relaxed);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(40);
        loop {
            let path = path.clone();
            let value = tokio::task::spawn_blocking(move || {
                let row_limit = if managed {
                    porthub_components::protocol::stats::MAX_ROW
                } else {
                    32768
                };
                let limit = 128 * row_limit + 1024;
                let mut bytes = Vec::new();
                std::fs::File::open(path)?
                    .take(limit as u64 + 1)
                    .read_to_end(&mut bytes)?;
                ensure!(bytes.len() <= limit, "snapshot input exceeds limit");
                let value: Value = serde_json::from_slice(&bytes)?;
                if managed && value["pending"] == true {
                    return Ok(None);
                }
                ensure!(
                    !managed || value["unavailable"] != true,
                    "Cannot collect scoped agent statistics"
                );
                let sequence = if managed {
                    value["sequence"]
                        .as_u64()
                        .filter(|sequence| *sequence > 0)
                        .context("invalid scoped snapshot sequence")?
                } else {
                    0
                };
                if managed && sequence == previous {
                    return Ok(None);
                }
                let rows = value["agents"]
                    .as_array()
                    .context("snapshot requires an agents array")?;
                ensure!(rows.len() <= 128, "snapshot has too many rows");
                let mut seen = BTreeSet::new();
                for row in rows {
                    let id = row["registration"]
                        .as_str()
                        .context("snapshot row requires registration identity")?;
                    ensure!(
                        !id.is_empty() && id.len() <= 256 && seen.insert(id),
                        "invalid or duplicate snapshot identity"
                    );
                    ensure!(
                        serde_json::to_vec(row)?.len() <= row_limit,
                        "snapshot row exceeds limit"
                    );
                }
                Ok::<_, anyhow::Error>(Some((rows.clone(), sequence)))
            })
            .await??;
            if let Some((rows, sequence)) = value {
                self.sequence
                    .store(sequence, std::sync::atomic::Ordering::Relaxed);
                return Ok(rows);
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "Scoped statistics snapshot did not become available"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
struct LocalSource {
    system: Arc<std::sync::Mutex<sysinfo::System>>,
    pid: Option<u32>,
}
#[async_trait::async_trait]
impl Source for LocalSource {
    async fn collect(&self) -> Result<Vec<Value>> {
        let system = self.system.clone();
        let pid = self.pid;
        tokio::task::spawn_blocking(move || {
            let mut system = system.lock().map_err(|_| anyhow::anyhow!("process sampler unavailable"))?;
            system.refresh_all();
            let mut processes: Vec<_> = system.processes().values()
                .filter(|process| pid.is_none_or(|pid| process.pid().as_u32() == pid)).collect();
            processes.sort_by_key(|process| std::cmp::Reverse(process.memory()));
            Ok(processes.into_iter().take(128).map(|process| json!({
                "registration":format!("{}:{}",process.pid(),process.name().to_string_lossy()),
                "state":"local process","process":{"pid":process.pid().as_u32(),
                "start_time":process.start_time(),"cpu_millis":process.accumulated_cpu_time(),"rss_bytes":process.memory()},
                "traffic":{}})).collect())
        }).await?
    }
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    let manage_terminal = args.managed_endpoint.is_none() && args.managed_input.is_none();
    let source: Arc<dyn Source> = if let Some(endpoint) = args.managed_endpoint {
        Arc::new(ManagedSource(endpoint))
    } else if let Some(path) = args.managed_input {
        Arc::new(FileSource::new(path, true))
    } else {
        match args.input {
            Some(path) => Arc::new(FileSource::new(path, false)),
            None => Arc::new(LocalSource {
                system: Arc::new(std::sync::Mutex::new(sysinfo::System::new())),
                pid: args.pid,
            }),
        }
    };
    let cancel = CancellationToken::new();
    let stopped = cancel.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        stopped.cancel();
    });
    porthub_stats::run(
        Options {
            manage_terminal,
            once: args.once,
            json: args.json,
            interval: args.interval,
        },
        source,
        cancel,
    )
    .await
}
