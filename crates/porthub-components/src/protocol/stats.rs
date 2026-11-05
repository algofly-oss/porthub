//! Read-only, bounded snapshot handoff. Enrollment credentials never cross it.
use serde::{Deserialize, Serialize};
pub const MAX_ROW: usize = 48 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Collect,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Snapshot { rows: usize },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub data: serde_json::Value,
}
