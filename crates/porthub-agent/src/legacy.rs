//! Read generated legacy client.env files as data, never as shell programs.
//! Credential staging leaves existing services, configuration and keys intact.
use crate::profile::Profile;
use anyhow::{Context, Result};
use std::{collections::BTreeMap, fs::OpenOptions, io::Read, path::Path};

fn literal(value: &str) -> Result<String> {
    if value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2 {
        let inner = &value[1..value.len() - 1];
        anyhow::ensure!(!inner.contains('\''), "unsupported legacy quoted value");
        return Ok(inner.into());
    }
    let value = if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        &value[1..value.len() - 1]
    } else {
        anyhow::ensure!(
            !value.chars().any(char::is_whitespace),
            "unsupported legacy value whitespace"
        );
        value
    };
    anyhow::ensure!(
        !value.contains(['$', '`', '\\', '"', '\'', ';', '|', '<', '>']),
        "legacy shell expressions cannot be imported"
    );
    Ok(value.into())
}

/// Parse the writer's assignment format. Errors intentionally exclude input
/// lines, values and parser source errors which might contain credentials.
pub(crate) fn assignments(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    anyhow::ensure!(
        bytes.len() <= 65_536,
        "legacy environment exceeds size limit"
    );
    let source = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("legacy environment must be UTF-8"))?;
    let mut values = BTreeMap::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .context("legacy environment must contain literal assignments only")?;
        anyhow::ensure!(
            key.starts_with("PORT_HUB_")
                && key
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
            "invalid legacy environment key"
        );
        anyhow::ensure!(
            !value.chars().any(char::is_control),
            "invalid legacy environment control character"
        );
        let value = literal(value)?;
        anyhow::ensure!(
            values.insert(key, value).is_none(),
            "duplicate legacy environment key"
        );
    }
    Ok(values
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect())
}
pub fn parse(bytes: &[u8], fallback_servers: Vec<String>) -> Result<Profile> {
    parse_with_server(bytes, fallback_servers, None)
}
pub(crate) fn parse_with_server(
    bytes: &[u8],
    fallback_servers: Vec<String>,
    server: Option<&str>,
) -> Result<Profile> {
    let values = assignments(bytes)?;
    let required = |key| -> Result<String> {
        values
            .get(key)
            .filter(|v| !v.is_empty())
            .cloned()
            .context("legacy environment is missing enrollment credentials")
    };
    let api = required("PORT_HUB_API_URL")?;
    let api = api.trim_end_matches('/');
    // The old writer appends /api; the native control plane appends it itself.
    let server = server
        .unwrap_or_else(|| api.strip_suffix("/api").unwrap_or(api))
        .to_owned();
    let mut profile = Profile {
        format_version: 1,
        server,
        machine_id: required("PORT_HUB_MACHINE_ID")?,
        token: required("PORT_HUB_MACHINE_TOKEN")?,
        fallback_servers,
        setup_overrides: BTreeMap::new(),
        allow_insecure_http_for_tests: false,
    };
    if let Some(endpoint) = values.get("PORT_HUB_CONFIG_TOML_URL") {
        let endpoint = url::Url::parse(endpoint)
            .map_err(|_| anyhow::anyhow!("invalid legacy configuration endpoint"))?;
        anyhow::ensure!(
            matches!(endpoint.scheme(), "http" | "https")
                && endpoint.username().is_empty()
                && endpoint.password().is_none(),
            "invalid legacy configuration endpoint"
        );
        for (key, value) in endpoint.query_pairs() {
            if matches!(key.as_ref(), "rathole_server_address" | "service_domain") {
                profile
                    .setup_overrides
                    .entry(key.into_owned())
                    .or_insert_with(|| value.into_owned());
            }
        }
        // public_base_url follows the saved API authority. Never import a
        // discovered origin address into that stable gateway identity.
    }
    // Do not include URL parsing errors: they can contain credential-bearing input.
    profile
        .validate()
        .map_err(|_| anyhow::anyhow!("legacy enrollment failed profile validation"))?;
    Ok(profile)
}

pub fn read(path: &Path, fallbacks: Vec<String>) -> Result<Profile> {
    parse(&read_owned(path, 65_536)?, fallbacks)
}
#[cfg(target_os = "linux")]
pub fn is_generated_cli(path: &Path) -> Result<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.len() > 4 * 1024 * 1024 {
        return Ok(false);
    }
    let bytes = read_owned(path, 4 * 1024 * 1024)?;
    Ok(
        (bytes.starts_with(b"#!/usr/bin/env bash") || bytes.starts_with(b"#!/bin/bash"))
            && bytes
                .windows(24)
                .any(|value| value == b"PORT_HUB_CLIENT_VERSION=")
            && bytes.windows(13).any(|value| value == b"__service-run"),
    )
}
pub(crate) fn read_owned(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path).context("read legacy environment metadata")?;
    anyhow::ensure!(
        before.is_file() && before.len() <= maximum,
        "legacy environment must be a bounded regular file"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        // Older installers created 0644 files. Reading those is permitted,
        // but a writable-by-others or foreign-owned source cannot be trusted.
        anyhow::ensure!(
            (before.uid() == 0 || before.uid() == rustix::process::getuid().as_raw())
                && before.mode() & 0o022 == 0,
            "unsafe legacy environment ownership or permissions"
        );
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).context("open legacy environment")?;
    let after = file.metadata()?;
    anyhow::ensure!(after.is_file(), "legacy environment must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            before.dev() == after.dev()
                && before.ino() == after.ino()
                && before.uid() == after.uid()
                && before.mode() == after.mode(),
            "legacy environment changed during read"
        );
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= maximum,
        "legacy file exceeds size limit"
    );
    Ok(bytes)
}

/// Create a new private profile only. Existing output is never replaced, and
/// no legacy service or shared executable is stopped, overwritten or imported.
pub fn stage(source: &Path, destination: &Path, fallbacks: Vec<String>) -> Result<String> {
    #[cfg(not(unix))]
    {
        let _ = (source, destination, fallbacks);
        anyhow::bail!("native credential protection for this platform is not ready")
    }
    #[cfg(unix)]
    {
        let profile = read(source, fallbacks)?;
        let id = crate::service::identity(&profile);
        profile.save_new(destination)?;
        Ok(id)
    }
}
