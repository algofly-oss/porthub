//! Bundled terminal runtime; no dependency on the PortHub agent or gateway.
use anyhow::{ensure, Result};
use porthub_components::{
    protocol::terminal::{Operation, Value},
    rpc::{ErrorCode, Failure, Handler, Reply},
};
use std::path::Path;
use tokio_util::sync::CancellationToken;
pub const VERSION: &str = match option_env!("PORTHUB_COMPONENT_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
#[cfg(unix)]
static BUNDLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/terminal.bundle.tar.gz"));
pub fn install(directory: &Path) -> Result<Value> {
    ensure!(
        directory.is_absolute(),
        "terminal runtime requires an absolute directory"
    );
    #[cfg(unix)]
    {
        ensure!(
            !BUNDLE.is_empty(),
            "development build has no terminal runtime; compile with PORTHUB_TERMINAL_BUNDLE"
        );
        if !directory.exists() {
            use std::os::unix::fs::DirBuilderExt;
            match std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)
            {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        // Catalog target aliases are unrelated to the embedded runtime's exact
        // build target. A musl bundle carries its musl target in its manifest.
        let runtime =
            porthub_terminal::runtime::install(BUNDLE, directory, env!("PORTHUB_RUST_TARGET"))?;
        Ok(Value::Runtime {
            executable: runtime.executable,
            terminfo: runtime.terminfo,
            version: runtime.version,
        })
    }
    #[cfg(not(unix))]
    {
        anyhow::bail!("terminal hosting requires Unix; use WSL on Windows")
    }
}
pub struct Worker;
#[async_trait::async_trait]
impl Handler for Worker {
    type Operation = Operation;
    type Value = Value;
    fn connection_limit(&self) -> usize {
        4
    }
    async fn handle(
        &self,
        operation: Operation,
        _cancel: CancellationToken,
    ) -> Result<Reply<Value>, Failure> {
        let Operation::Install { directory } = operation;
        tokio::task::spawn_blocking(move || install(&directory)).await
            .map_err(|_| Failure {code:ErrorCode::Internal,detail:"Terminal runtime provisioning task stopped".into()})?
            .map(Reply::Message).map_err(|_| Failure {code:ErrorCode::Unavailable,
                detail:"Terminal runtime unavailable; check platform support, runtime bundle and private directory ownership".into()})
    }
}
