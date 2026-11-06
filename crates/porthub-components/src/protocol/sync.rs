use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub path: PathBuf,
    pub url: String,
    pub connections: usize,
    pub contents_only: bool,
    pub force: bool,
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.path.is_absolute() && self.path.as_os_str().len() <= 8192,
            "sync source requires a bounded absolute path"
        );
        ensure!(
            (1..=32).contains(&self.connections) && self.url.len() <= 8192,
            "invalid sync options"
        );
        let url = url::Url::parse(&self.url)?;
        ensure!(
            matches!(url.scheme(), "http" | "https") && url.has_host() && url.fragment().is_none(),
            "sync destination requires an HTTP URL"
        );
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Start { options: Options, detached: bool },
    List { offset: usize, limit: u16 },
    Status { id: String },
    Stop { id: String },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub id: String,
    pub source: PathBuf,
    pub destination: String,
    pub state: String,
    pub completed_runs: u64,
    pub last_success_unix: Option<u64>,
    pub message: String,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Started { id: String },
    Jobs { jobs: Vec<Status>, total: usize },
    Status { job: Status },
    Stopped,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    pub job: Option<Status>,
    pub finished: bool,
    pub failed: bool,
}
