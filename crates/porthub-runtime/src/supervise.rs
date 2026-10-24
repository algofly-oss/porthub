//! Structured process supervision for core's API, UI and database. Commands are
//! executed directly, without shell interpolation. One bounded task per child.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    time::{Duration, Instant},
};
use tokio::{process::Command, sync::watch, task::JoinSet};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    pub name: String,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub directory: Option<PathBuf>,
    pub after: Option<String>,
    #[serde(default)]
    pub modes: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub process: Vec<Process>,
}
impl Config {
    pub fn parse(source: &str, mode: &str) -> Result<Self> {
        anyhow::ensure!(
            matches!(mode, "prod" | "dev"),
            "PORTHUB_MODE must be prod or dev"
        );
        let mut config: Self = toml::from_str(source).context("parse supervisor configuration")?;
        config
            .process
            .retain(|p| p.modes.is_empty() || p.modes.iter().any(|m| m == mode));
        anyhow::ensure!(
            !config.process.is_empty(),
            "no processes configured for this mode"
        );
        let mut names = HashSet::new();
        for process in &config.process {
            anyhow::ensure!(
                !process.name.is_empty()
                    && process
                        .name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
                "invalid supervised process name"
            );
            anyhow::ensure!(
                names.insert(&process.name),
                "duplicate supervised process name"
            );
            anyhow::ensure!(!process.program.is_empty(), "empty supervised program");
        }
        Ok(config)
    }
}

pub async fn run(config: Config, stop: impl std::future::Future<Output = ()>) -> Result<()> {
    let (cancel, receiver) = watch::channel(false);
    let mut tasks = JoinSet::new();
    for process in config.process {
        tasks.spawn(run_process(process, receiver.clone()));
    }
    tokio::pin!(stop);
    let result = tokio::select! {
        _=&mut stop=>Ok(()),
        result=tasks.join_next()=>match result {
            Some(Ok(result))=>result,
            Some(Err(error))=>Err(error.into()),
            None=>Ok(()),
        }
    };
    let _ = cancel.send(true);
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            tracing::error!(%error,"supervisor task failed during shutdown");
        }
    }
    result
}

async fn stopped(cancel: &mut watch::Receiver<bool>) {
    while !*cancel.borrow_and_update() {
        if cancel.changed().await.is_err() {
            break;
        }
    }
}
async fn wait_ready(address: &str, cancel: &mut watch::Receiver<bool>) -> Result<bool> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let connected = tokio::time::timeout(Duration::from_secs(1), async {
            if let Some(path) = address.strip_prefix("unix:") {
                tokio::net::UnixStream::connect(path).await.map(|_| ())
            } else {
                tokio::net::TcpStream::connect(address).await.map(|_| ())
            }
        });
        tokio::select! {
            _=stopped(cancel)=>return Ok(false),
            result=connected=>if matches!(result,Ok(Ok(()))){return Ok(true)},
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("supervised dependency did not become ready")
        }
        tokio::select! {_=stopped(cancel)=>return Ok(false),_=tokio::time::sleep(Duration::from_millis(500))=>{}}
    }
}
async fn run_process(process: Process, mut cancel: watch::Receiver<bool>) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *cancel.borrow() {
            return Ok(());
        }
        if let Some(after) = &process.after {
            if !wait_ready(after, &mut cancel).await? {
                return Ok(());
            }
        }
        let mut command = Command::new(&process.program);
        command
            .args(&process.args)
            .envs(&process.env)
            .kill_on_drop(true)
            .process_group(0);
        if let Some(directory) = &process.directory {
            command.current_dir(directory);
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("start supervised service {}", process.name))?;
        let pid = child
            .id()
            .and_then(|id| rustix::process::Pid::from_raw(id as i32))
            .context("child PID missing")?;
        let started = Instant::now();
        tracing::info!(service=%process.name,"service started");
        tokio::select! {
            _=stopped(&mut cancel)=>{
                let _=rustix::process::kill_process_group(pid,rustix::process::Signal::TERM);
                if tokio::time::timeout(Duration::from_secs(10),child.wait()).await.is_err() {
                    let _=rustix::process::kill_process_group(pid,rustix::process::Signal::KILL);
                    let _=child.wait().await;
                }
                // Reap/stop subprocesses even if the leader handled TERM first.
                let _=rustix::process::kill_process_group(pid,rustix::process::Signal::KILL);
                return Ok(())
            }
            status=child.wait()=>{
                let _=rustix::process::kill_process_group(pid,rustix::process::Signal::KILL);
                tracing::warn!(service=%process.name,?status,"service exited; restart scheduled");
            }
        }
        if started.elapsed() >= Duration::from_secs(60) {
            backoff = Duration::from_secs(1)
        }
        tokio::select! {_=stopped(&mut cancel)=>return Ok(()),_=tokio::time::sleep(backoff)=>{}}
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}
