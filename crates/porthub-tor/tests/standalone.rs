//! Exercise the shipped standalone CLI and versioned pipe frontend without Tor
//! network access, an installed core, enrollment, or a PortHub server.
use anyhow::{ensure, Result};
use porthub_components::{
    catalog::{Component, PROTOCOL},
    ipc::{self, Hello, Request, Response},
    protocol::tor::{Operation, Options, Value},
    rpc::{ErrorCode, Outcome, SystemOperation, SystemValue},
};
use std::{
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[tokio::test]
async fn independent_cli_and_pipe_frontend_preserve_contract_and_reject_invalid_work() -> Result<()>
{
    let executable = env!("CARGO_BIN_EXE_porthub-tor");
    let version = tokio::process::Command::new(executable)
        .arg("--version")
        .output()
        .await?;
    ensure!(
        version.status.success() && String::from_utf8(version.stdout)?.starts_with("porthub-tor ")
    );
    let help = tokio::process::Command::new(executable)
        .args(["proxy", "--help"])
        .output()
        .await?;
    ensure!(help.status.success() && String::from_utf8(help.stdout)?.contains("--groups"));
    let root = tempfile::tempdir()?;
    let mut child = tokio::process::Command::new(executable)
        .arg("__porthub-stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut input = child.stdin.take().unwrap();
    let mut output = child.stdout.take().unwrap();
    let hello: Hello = ipc::read(&mut output, Duration::from_secs(5)).await?;
    hello.validate(
        Component::Tor,
        &option_env!("PORTHUB_COMPONENT_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .parse()?,
    )?;
    ensure!(hello.protocol == PROTOCOL);
    ipc::write(&mut input, &hello, Duration::from_secs(5)).await?;
    let deadline = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64 + 15000;
    let options = || Options {
        directory: root.path().into(),
        groups: 4,
        max_connections: 64,
        sources: Some(vec![]),
    };
    ipc::write(
        &mut input,
        &Request {
            id: 1,
            deadline_unix_ms: deadline,
            operation: Operation::Ready { options: options() },
        },
        Duration::from_secs(5),
    )
    .await?;
    let response: Response<Outcome<Value>> = ipc::read(&mut output, Duration::from_secs(5)).await?;
    ensure!(
        response.id == 1
            && matches!(
                response.result,
                Outcome::Ok {
                    value: Value::Ready { ready: false },
                    stream: false
                }
            )
    );
    ipc::write(
        &mut input,
        &Request {
            id: 2,
            deadline_unix_ms: deadline,
            operation: Operation::Connect {
                options: options(),
                host: "invalid/secret-destination".into(),
                port: 443,
            },
        },
        Duration::from_secs(5),
    )
    .await?;
    let response: Response<Outcome<Value>> = ipc::read(&mut output, Duration::from_secs(5)).await?;
    ensure!(
        matches!(response.result,Outcome::Error {failure} if matches!(failure.code,ErrorCode::InvalidRequest) && !failure.detail.contains("secret-destination"))
    );
    ipc::write(
        &mut input,
        &Request {
            id: 3,
            deadline_unix_ms: deadline,
            operation: SystemOperation::Ping,
        },
        Duration::from_secs(5),
    )
    .await?;
    let response: Response<Outcome<SystemValue>> =
        ipc::read(&mut output, Duration::from_secs(5)).await?;
    ensure!(
        matches!(response.result,Outcome::Ok {value:SystemValue::Pong {pid},stream:false} if Some(pid)==child.id())
    );
    drop(input);
    // Closing the private input terminates a one-shot invocation. It must not
    // remain alive waiting on an unrelated inherited handle or idle listener.
    tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
    Ok(())
}
