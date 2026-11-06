//! Tor stream contracts; this module never links a Tor implementation.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    pub directory: PathBuf,
    pub groups: usize,
    pub max_connections: usize,
    /// None uses OS routing for standalone tools. Some(empty) forbids every
    /// source; a managed exit must never silently fall back to OS routing.
    pub sources: Option<Vec<IpAddr>>,
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.directory.is_absolute() && self.directory.as_os_str().len() <= 8192,
            "Tor storage requires a bounded absolute path"
        );
        ensure!(
            (1..=16).contains(&self.groups) && (1..=512).contains(&self.max_connections),
            "invalid Tor capacity"
        );
        ensure!(
            self.sources
                .as_ref()
                .is_none_or(|sources| sources.len() <= 256
                    && sources
                        .iter()
                        .all(|ip| !ip.is_unspecified() && !ip.is_multicast())),
            "invalid Tor underlay sources"
        );
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Configure {
        options: Options,
    },
    Bootstrap {
        options: Options,
    },
    Connect {
        options: Options,
        host: String,
        port: u16,
    },
    Resolve {
        options: Options,
        hostname: String,
    },
    Ready {
        options: Options,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Value {
    Configured,
    Ready { ready: bool },
    Connected,
    Addresses { addresses: Vec<IpAddr> },
}
