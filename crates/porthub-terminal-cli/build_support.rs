//! Early ABI-target preflight; runtime installation still verifies every file.
use std::io::Read;

pub fn validate_target(bytes: &[u8], target: &str) -> Result<(), String> {
    let reader = flate2::read::GzDecoder::new(bytes).take(32 * 1024 * 1024);
    let mut archive = tar::Archive::new(reader);
    for (index, entry) in archive
        .entries()
        .map_err(|_| "invalid runtime archive")?
        .enumerate()
    {
        if index >= 128 {
            return Err("too many runtime entries".into());
        }
        let entry = entry.map_err(|_| "invalid runtime archive entry")?;
        if entry.path().map_err(|_| "invalid runtime path")?.as_ref()
            != std::path::Path::new("manifest.json")
        {
            continue;
        }
        if !entry.header().entry_type().is_file() || entry.size() > 32768 {
            return Err("invalid runtime manifest".into());
        }
        let mut manifest = Vec::new();
        entry
            .take(32769)
            .read_to_end(&mut manifest)
            .map_err(|_| "cannot read runtime manifest")?;
        let manifest: serde_json::Value =
            serde_json::from_slice(&manifest).map_err(|_| "invalid runtime manifest JSON")?;
        if manifest.get("target").and_then(serde_json::Value::as_str) != Some(target) {
            return Err("runtime manifest target differs from Rust target".into());
        }
        return Ok(());
    }
    Err("runtime manifest is missing".into())
}
