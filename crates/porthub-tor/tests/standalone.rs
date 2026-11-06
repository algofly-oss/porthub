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

#[tokio::test]
async fn multiplex_cli_keeps_one_process_and_exits_after_pipe_owner_closes() -> Result<()> {
    use porthub_components::{multiplex::Carrier, rpc::Client};
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_porthub-tor"))
        .arg("__porthub-multiplex")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    // A local duplex bridge keeps the test independent of OS-specific pipe APIs.
    let (local, remote) = tokio::io::duplex(8192);
    let (mut receive, mut transmit) = tokio::io::split(remote);
    let mut input = input;
    let mut output = output;
    let writing = tokio::spawn(async move { tokio::io::copy(&mut receive, &mut input).await });
    let reading = tokio::spawn(async move { tokio::io::copy(&mut output, &mut transmit).await });
    let carrier = Carrier::connect(local).await?;
    let hello = Hello {
        component: Component::Tor,
        protocol: PROTOCOL,
        version: porthub_tor::VERSION.parse()?,
    };
    let mut first = Client::from_transport(carrier.open().await?, &hello).await?;
    let mut second = Client::from_transport(carrier.open().await?, &hello).await?;
    for connection in [&mut first, &mut second] {
        let response: SystemValue = connection
            .call(SystemOperation::Ping, Duration::from_secs(5))
            .await?;
        ensure!(matches!(response,SystemValue::Pong {pid} if Some(pid)==child.id()));
    }
    let root = tempfile::tempdir()?;
    let options = Options {
        directory: root.path().into(),
        groups: 4,
        max_connections: 64,
        sources: Some(vec![]),
    };
    let response: Value = first
        .call(
            Operation::Configure {
                options: options.clone(),
            },
            Duration::from_secs(5),
        )
        .await?;
    ensure!(matches!(response, Value::Configured));
    drop(first);
    let response: Value = second
        .call(Operation::Ready { options }, Duration::from_secs(5))
        .await?;
    ensure!(matches!(response, Value::Ready { ready: false }));
    drop(second);
    drop(carrier);
    tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
    writing.abort();
    reading.abort();
    Ok(())
}

#[tokio::test]
async fn managed_cli_sessions_coalesce_startup_and_reconnect_with_backoff() -> Result<()> {
    managed_session_fixture(porthub_components::worker::Mode::Cli, false, false).await
}
#[cfg(unix)]
#[tokio::test]
async fn automatic_persistent_session_falls_back_when_worker_cannot_start() -> Result<()> {
    managed_session_fixture(porthub_components::worker::Mode::Auto, true, false).await
}
#[cfg(unix)]
#[tokio::test]
async fn forced_rpc_does_not_invoke_cli_when_worker_cannot_start() -> Result<()> {
    managed_session_fixture(porthub_components::worker::Mode::Rpc, true, false).await
}
#[cfg(unix)]
#[tokio::test]
async fn failed_persistent_cli_startup_backoff_survives_fresh_sessions() -> Result<()> {
    managed_session_fixture(porthub_components::worker::Mode::Cli, false, true).await
}
async fn managed_session_fixture(
    mode: porthub_components::worker::Mode,
    deny_rpc: bool,
    deny_pipe: bool,
) -> Result<()> {
    use porthub_components::{
        catalog::{Artifact, Catalog, CATALOG_ASSET, REPOSITORY, TARGETS},
        rpc::Client,
        store::{Manager, Settings, Sources},
        transport::Transport,
        worker::{ContextOptions, Mode},
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::Write,
        path::Path,
        sync::Arc,
    };
    struct NoNetwork;
    #[async_trait::async_trait]
    impl Transport for NoNetwork {
        async fn fetch(&self, _: &url::Url, _: &Path, _: u64) -> Result<()> {
            anyhow::bail!("fixture has no network")
        }
    }
    let mut temporary = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let root = temporary.tempdir()?;
    porthub_components::store::secure_private_directory(root.path())?;
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => TARGETS[0],
        ("linux", "aarch64") => TARGETS[1],
        ("linux", "x86") => TARGETS[2],
        ("macos", "x86_64") => TARGETS[5],
        ("macos", "aarch64") => TARGETS[6],
        ("windows", "x86_64") => TARGETS[7],
        ("windows", "x86") => TARGETS[8],
        ("windows", "aarch64") => TARGETS[9],
        _ => anyhow::bail!("unsupported native fixture platform"),
    };
    let manager = Manager::new(
        root.path().join("cache"),
        Settings {
            gateway: None,
            sources: Sources::GithubOnly,
            core: "1.11.0".parse()?,
            target: target.into(),
            disabled: BTreeSet::new(),
            pins: BTreeMap::new(),
        },
        Arc::new(NoNetwork),
    )?;
    let mut bytes = std::fs::read(env!("CARGO_BIN_EXE_porthub-tor"))?;
    #[cfg(unix)]
    if deny_rpc || deny_pipe {
        // Fixture-only verified launcher: native worker admission is denied,
        // but the actual shipped helper still serves the multiplexed pipes.
        let executable = env!("CARGO_BIN_EXE_porthub-tor").replace(char::from(39), r#"'"'"'"#);
        bytes=format!("#!/bin/sh\nif [ \"$1\" = __porthub-worker ]; then exit 73; fi\nexec '{executable}' \"$@\"\n").into_bytes();
    }
    #[cfg(unix)]
    if deny_pipe {
        bytes = String::from_utf8(bytes)?
            .replacen(
                "exec '",
                "if [ \"$1\" = __porthub-multiplex ]; then exit 74; fi\nexec '",
                1,
            )
            .into_bytes();
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let artifact: Artifact = serde_json::from_value(
        serde_json::json!({"component":"tor","version":porthub_tor::VERSION,
        "target":target,"core":">=1.11.0, <2.0.0","protocols":[1],"source_revision":"a".repeat(40),
        "build_inputs":"b".repeat(64),"executable":{"size":bytes.len(),"sha256":digest},
        "release":"1.11.0","archive":{"size":1,"sha256":"c".repeat(64)}}),
    )?;
    let binary = manager.cache_root().join(format!(
        "tor-{}-{}{}",
        artifact.version,
        digest,
        if cfg!(windows) { ".exe" } else { "" }
    ));
    std::fs::write(&binary, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755))?;
    }
    let catalog = Catalog {
        schema_version: 1,
        repository: REPOSITORY.into(),
        release: "1.11.0".parse()?,
        artifacts: vec![artifact],
    };
    let mut file = tempfile::NamedTempFile::new_in(manager.cache_root())?;
    file.write_all(&serde_json::to_vec(&catalog)?)?;
    file.persist(manager.cache_root().join(CATALOG_ASSET))?;
    let context = ContextOptions {
        state_directory: root.path().join("state"),
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    let result = manager
        .session_with_mode(Component::Tor, &context, mode, &cancel)
        .await;
    if deny_pipe {
        ensure!(result.is_err(), "broken helper unexpectedly started");
        let path = std::fs::read_dir(manager.cache_root())?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".attempts.json"))
            })
            .ok_or_else(|| anyhow::anyhow!("missing persistent startup backoff"))?;
        let original = std::fs::read(&path)?;
        let second = manager
            .session_with_mode(Component::Tor, &context, mode, &cancel)
            .await;
        ensure!(
            second
                .err()
                .is_some_and(|error| error.to_string().contains("backing off")),
            "fresh session bypassed failed-start backoff"
        );
        ensure!(
            std::fs::read(&path)? == original,
            "backoff attempted another helper launch"
        );
        return Ok(());
    }
    if deny_rpc && matches!(mode, Mode::Rpc) {
        ensure!(result.is_err(), "forced RPC unexpectedly fell back to CLI");
        return Ok(());
    }
    let session = result?;
    async fn pid(mut client: Client) -> Result<u32> {
        match client
            .call(SystemOperation::Ping, Duration::from_secs(5))
            .await?
        {
            SystemValue::Pong { pid } => Ok(pid),
            _ => anyhow::bail!("unexpected ping"),
        }
    }
    let original = pid(session.connect(&cancel).await?).await?;
    let mut connections = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let session = session.clone();
        let cancel = cancel.clone();
        connections.spawn(async move { pid(session.connect(&cancel).await?).await });
    }
    while let Some(result) = connections.join_next().await {
        ensure!(result?? == original, "session spawned an independent pool");
    }
    let mut shutdown = session.connect_existing().await?;
    let _: Result<SystemValue> = shutdown
        .call(SystemOperation::Shutdown, Duration::from_secs(1))
        .await;
    drop(shutdown);
    // Reconnection is safe only before a new operation is dispatched. The
    // first failed-start window is bounded, and a later request gets a new PID.
    let mut reconnected = None;
    for _ in 0..40 {
        if let Ok(client) = session.connect(&cancel).await {
            if let Ok(next) = pid(client).await {
                if next != original {
                    reconnected = Some(next);
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ensure!(
        reconnected.is_some(),
        "persistent CLI did not recover after bounded backoff"
    );
    cancel.cancel();
    drop(session);
    Ok(())
}
