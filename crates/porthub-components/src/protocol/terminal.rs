//! Local runtime provisioning; no enrollment material or terminal guest grants.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    List {
        directory: PathBuf,
        all: bool,
        offset: usize,
    },
    Running {
        directory: PathBuf,
        name: String,
    },
    Stop {
        directory: PathBuf,
        name: String,
    },
    Rename {
        directory: PathBuf,
        name: String,
        new_name: String,
    },
    Install {
        directory: PathBuf,
    },
    Create {
        directory: PathBuf,
        options: CreateOptions,
        reuse: bool,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Workspaces {
        rows: Vec<WorkspaceRow>,
        next: Option<usize>,
    },
    Running {
        running: bool,
    },
    Stopped {
        name: String,
    },
    Workspace {
        job: Job,
    },
    Runtime {
        executable: PathBuf,
        terminfo: PathBuf,
        version: String,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    pub name: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub terminfo: PathBuf,
    pub workspace: PathBuf,
    pub created_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOptions {
    pub name: Option<String>,
    pub cwd: PathBuf,
    pub shell: PathBuf,
    pub environment: Vec<String>,
    pub inherited_environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    pub history_limit: u32,
    pub no_mouse: bool,
    pub prefix: String,
    pub command: Vec<std::ffi::OsString>,
}

/// Credential-free local broker identity, selected by core from installed status.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Broker {
    pub endpoint: PathBuf,
    pub owner: u32,
    pub traffic: bool,
}

/// Invitation is sensitive: core transfers this in a private request file, never argv.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinRequest {
    pub invitation: String,
    pub transport: JoinTransport,
    pub broker: Option<Broker>,
    pub stun_servers: Vec<String>,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinTransport {
    Ssh,
    Relay,
    Auto,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceRow {
    pub id: String,
    pub name: String,
    pub state: WorkspaceState,
    pub shared: bool,
    pub created_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceState {
    Running,
    Ended,
}
