use serde::{Deserialize, Serialize};

pub(crate) const MANIFEST_QUERY: &str = "_porthub";
pub(crate) const MANIFEST_VERSION: &str = "1";
pub(crate) const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_MANIFEST_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub version: u8,
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// Slash separated path relative to the requested directory.
    pub path: String,
    /// `file`, `directory`, or `unsupported` (symlink/device/socket, etc.).
    pub kind: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub modified_ns: u128,
}
