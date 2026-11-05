//! Bundled terminal runtime; no dependency on the PortHub agent or gateway.
use anyhow::{ensure, Result};
use porthub_components::{
    protocol::terminal::{Operation, Value},
    rpc::{ErrorCode, Failure, Handler, Reply},
};
use std::path::Path;
use tokio_util::sync::CancellationToken;
#[cfg(unix)]
pub mod workspace;
#[cfg(unix)]
pub mod owner;
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
        tokio::task::spawn_blocking(move || match operation {
            Operation::Install {directory}=>install(&directory),
            Operation::Create {directory,options,reuse}=>{
                #[cfg(unix)] {workspace::create(&directory,options,reuse).map(|job|Value::Workspace {job})}
                #[cfg(not(unix))] {let _=(directory,options,reuse);anyhow::bail!("terminal hosting requires Unix; use WSL on Windows")}
            }
        }).await.map_err(|_|Failure {code:ErrorCode::Internal,detail:"Terminal operation stopped".into()})?
        .map(Reply::Message).map_err(|error| {
            let message=error.to_string();
            let safe=["workspace name already exists","invalid terminal history limit","terminal working directory does not exist","terminal shell must be an absolute executable path","prefix must be C-a through C-z or F1 through F12","invalid terminal environment variable","name must contain 1–64 letters, numbers, spaces, dots, underscores or hyphens"];
            Failure {code:ErrorCode::Unavailable,detail:if safe.contains(&message.as_str()) {message} else {"Terminal operation unavailable; check workspace name, shell, runtime and private directory ownership".into()}}
        })
    }
}
