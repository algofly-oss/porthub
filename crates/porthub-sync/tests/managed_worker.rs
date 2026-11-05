use anyhow::{ensure, Result};
use async_trait::async_trait;
use porthub_components::{
    catalog::{Artifact, Blob, Catalog, Component, TARGETS},
    ipc,
    local::Endpoint,
    protocol::sync::{Operation, Options, Progress, Value},
    rpc::{Client, SystemOperation, SystemValue},
    store::{Manager, Settings, Sources},
    transport::Transport,
    worker::ContextOptions,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;
struct Fixture {
    catalog: Vec<u8>,
    executable: Vec<u8>,
    binaries: AtomicUsize,
}
#[async_trait]
impl Transport for Fixture {
    async fn fetch(&self, url: &Url, output: &Path, max: u64) -> Result<()> {
        let bytes = if url.path().ends_with("/catalog") {
            &self.catalog
        } else {
            self.binaries.fetch_add(1, Ordering::SeqCst);
            &self.executable
        };
        ensure!(bytes.len() as u64 <= max, "fixture artifact exceeds limit");
        tokio::fs::write(output, bytes).await?;
        Ok(())
    }
}
struct Cleanup {
    endpoint: Endpoint,
    artifact: Artifact,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let endpoint = self.endpoint.clone();
        let artifact = self.artifact.clone();
        let _ = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                if let Ok(mut client) = Client::connect(&endpoint, &artifact).await {
                    let _: Result<SystemValue> = client
                        .call(SystemOperation::Shutdown, Duration::from_secs(2))
                        .await;
                }
            });
        })
        .join();
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
async fn wait_file(path: &Path, expected: &[u8]) {
    tokio::time::timeout(Duration::from_secs(15), async {
        while !std::fs::read(path).is_ok_and(|bytes| bytes == expected) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn verified_module_download_coalesces_worker_start_and_watch_follows_ipc_lifetime(
) -> Result<()> {
    let root = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let executable = std::fs::read(env!("CARGO_BIN_EXE_porthub-sync"))?;
    let target = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("windows", "aarch64") => "aarch64-pc-windows-msvc",
        ("windows", "x86") => "i686-pc-windows-msvc",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        ("linux", "aarch64") => "aarch64-unknown-linux-gnu",
        _ => TARGETS[0],
    };
    let artifact = Artifact {
        component: Component::Sync,
        version: "0.1.0".parse()?,
        target: target.into(),
        core: ">=1.10.0".parse()?,
        protocols: vec![1],
        source_revision: "a".repeat(40),
        build_inputs: "b".repeat(64),
        executable: Blob {
            size: executable.len() as u64,
            sha256: hash(&executable),
        },
        release: "1.11.0".parse()?,
        archive: Blob {
            size: 1,
            sha256: "c".repeat(64),
        },
    };
    let catalog = Catalog {
        schema_version: 1,
        repository: "algofly-oss/porthub".into(),
        release: "1.11.0".parse()?,
        artifacts: vec![artifact.clone()],
    };
    let fixture = Arc::new(Fixture {
        catalog: serde_json::to_vec(&catalog)?,
        executable,
        binaries: AtomicUsize::new(0),
    });
    let manager = Manager::new(
        root.path().join("components"),
        Settings {
            gateway: Some("https://fixture.test".parse()?),
            sources: Sources::GatewayOnly,
            core: "1.10.1".parse()?,
            target: target.into(),
            disabled: BTreeSet::new(),
            pins: BTreeMap::new(),
        },
        fixture.clone(),
    )?;
    let context = ContextOptions {
        state_directory: root.path().join("state"),
    };
    let cancel = CancellationToken::new();
    manager.refresh(&cancel).await?;
    let (first, second) = tokio::join!(
        manager.worker(Component::Sync, &context, &cancel),
        manager.worker(Component::Sync, &context, &cancel)
    );
    let mut first = first?;
    let mut second = second?;
    let identity = manager
        .cache_root()
        .join(hash(context.state_directory.as_os_str().as_encoded_bytes()));
    let _cleanup = Cleanup {
        endpoint: Endpoint::for_artifact(&identity, &artifact)?,
        artifact: artifact.clone(),
    };
    let SystemValue::Pong { pid: one } = first
        .call(SystemOperation::Ping, Duration::from_secs(2))
        .await?
    else {
        panic!("expected worker PID")
    };
    let SystemValue::Pong { pid: two } = second
        .call(SystemOperation::Ping, Duration::from_secs(2))
        .await?
    else {
        panic!("expected worker PID")
    };
    assert_eq!(one, two);
    assert_ne!(one, std::process::id());
    assert_eq!(fixture.binaries.load(Ordering::SeqCst), 1);
    let source = root.path().join("source");
    let destination = root.path().join("receiver");
    std::fs::create_dir(&source)?;
    std::fs::create_dir(&destination)?;
    std::fs::write(source.join("file"), b"first")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = porthub_transfer::server::router(destination.clone())
        .merge(porthub_transfer::upload::routes(destination.clone())?);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let options = Options {
        path: source.canonicalize()?,
        url: format!("http://{address}/"),
        connections: 4,
        contents_only: true,
        force: false,
    };
    let (started, mut stream) = first
        .upgrade::<_, Value>(
            Operation::Start {
                options,
                detached: false,
            },
            Duration::from_secs(10),
        )
        .await?;
    let Value::Started { id } = started else {
        panic!("expected started job")
    };
    let _: Progress = ipc::read(&mut stream, Duration::from_secs(5)).await?;
    wait_file(&destination.join("file"), b"first").await;
    std::fs::write(source.join("file"), b"second")?;
    wait_file(&destination.join("file"), b"second").await;
    drop(stream);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let jobs: Value = second
                .call(
                    Operation::List {
                        offset: 0,
                        limit: 32,
                    },
                    // The worker's local HTTP status probe is bounded at two
                    // seconds; leave room to return its result after a Windows
                    // loopback connect times out during watch shutdown.
                    Duration::from_secs(4),
                )
                .await
                .unwrap();
            if matches!(jobs, Value::Jobs { jobs, .. } if jobs.iter().all(|job| job.id != id)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    std::fs::write(source.join("file"), b"after disconnect")?;
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert_eq!(std::fs::read(destination.join("file"))?, b"second");
    let _: SystemValue = second
        .call(SystemOperation::Shutdown, Duration::from_secs(2))
        .await?;
    server.abort();
    Ok(())
}
