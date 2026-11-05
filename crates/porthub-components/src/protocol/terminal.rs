//! Local runtime provisioning; no enrollment material or terminal guest grants.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Install { directory: PathBuf },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Runtime {
        executable: PathBuf,
        terminfo: PathBuf,
        version: String,
    },
}
