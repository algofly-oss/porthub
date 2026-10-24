//! Preserve management of servers started by the previous Go agent. Its private
//! Unix control sockets remain usable after the CLI binary itself is upgraded.
use super::Record;
use anyhow::Result;
use std::path::PathBuf;

#[cfg(unix)]
async fn query(path: &std::path::Path, command: &str) -> Result<String> {
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::UnixStream,
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        let mut stream = UnixStream::connect(path).await?;
        stream.write_all(format!("{command}\n").as_bytes()).await?;
        let mut reply = String::new();
        BufReader::new(stream)
            .take(65536)
            .read_line(&mut reply)
            .await?;
        Ok::<_, anyhow::Error>(reply)
    })
    .await?
}

#[cfg(unix)]
pub async fn list() -> Result<Vec<(PathBuf, Record)>> {
    use serde::Deserialize;
    use std::{
        net::{Ipv4Addr, SocketAddr},
        os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    };
    #[derive(Deserialize)]
    struct Previous {
        pid: u32,
        port: u16,
        bind: String,
        root: PathBuf,
    }
    let uid = rustix::process::getuid().as_raw();
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let directory = base.join(format!("porthub-{uid}"));
    let Ok(metadata) = std::fs::symlink_metadata(&directory) else {
        return Ok(Vec::new());
    };
    if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0 {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(port) = name
            .strip_prefix("http-")
            .and_then(|name| name.strip_suffix(".sock"))
            .and_then(|port| port.parse::<u16>().ok())
        else {
            continue;
        };
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if metadata.uid() != uid || !metadata.file_type().is_socket() {
            continue;
        }
        let Ok(reply) = query(&entry.path(), "info").await else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<Previous>(&reply) else {
            continue;
        };
        if record.port != port {
            continue;
        }
        found.push((
            entry.path(),
            Record {
                pid: record.pid,
                port,
                bind: record.bind.parse().unwrap_or(Ipv4Addr::LOCALHOST.into()),
                root: record.root,
                started_unix: 0,
                control: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                token: String::new(),
            },
        ));
    }
    Ok(found)
}

#[cfg(not(unix))]
pub async fn list() -> Result<Vec<(PathBuf, Record)>> {
    Ok(Vec::new())
}

#[cfg(unix)]
pub async fn stop(port: Option<u16>) -> Result<Vec<u16>> {
    let mut stopped = Vec::new();
    for (path, record) in list().await? {
        if port.is_some_and(|port| port != record.port) {
            continue;
        }
        if query(&path, "stop").await.is_err() {
            continue;
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while query(&path, "info").await.is_ok() {
            anyhow::ensure!(
                tokio::time::Instant::now() < deadline,
                "server on port {} did not stop",
                record.port
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        stopped.push(record.port);
    }
    Ok(stopped)
}

#[cfg(not(unix))]
pub async fn stop(_port: Option<u16>) -> Result<Vec<u16>> {
    Ok(Vec::new())
}
