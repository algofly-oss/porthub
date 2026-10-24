//! Internal Unix-socket protocol. No machine tokens or origin addresses cross
//! this interface: an acknowledgement identifies exact published file bytes.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub digest: String,
}
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
