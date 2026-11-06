use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use porthub_components::{
    catalog::{Artifact, Blob, Catalog, Component, TARGETS},
    ipc,
    local::Endpoint,
    protocol::sync::{Operation, Options, Progress, Value},
    rpc::{Client, SystemOperation, SystemValue},
    store::{Manager, Settings, Sources},
    transport::Transport,
    worker::{ContextOptions, Mode},
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
    newer: Option<Vec<u8>>,
    binaries: AtomicUsize,
}
#[async_trait]
impl Transport for Fixture {
    async fn fetch(&self, url: &Url, output: &Path, max: u64) -> Result<()> {
        let bytes = if url.path().ends_with("/catalog") {
            &self.catalog
        } else {
            self.binaries.fetch_add(1, Ordering::SeqCst);
            if url.path().contains("/sync/0.1.1/") {
                self.newer.as_ref().unwrap_or(&self.executable)
            } else {
                &self.executable
            }
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
    exercise(Mode::Rpc, false, false, None).await
}
#[tokio::test]
async fn verified_cli_fallback_preserves_watch_lifetime() -> Result<()> {
    exercise(Mode::Cli, false, false, None).await
}
#[tokio::test]
async fn unavailable_worker_automatically_uses_verified_cli() -> Result<()> {
    exercise(Mode::Auto, true, false, None).await
}
#[tokio::test]
async fn failed_candidate_recovers_only_in_previously_activated_context() -> Result<()> {
    exercise(Mode::Rpc, false, true, None).await
}
#[tokio::test]
#[ignore = "requires a separately built 0.1.1 sync executable"]
async fn healthy_candidate_stages_without_interrupting_an_active_old_stream() -> Result<()> {
    let path = std::env::var_os("PORTHUB_TEST_UPDATED_SYNC_EXECUTABLE")
        .context("updated sync fixture missing")?;
    exercise(Mode::Rpc, false, false, Some(std::fs::read(path)?)).await
}
async fn exercise(
    mode: Mode,
    blocked: bool,
    failed_update: bool,
    newer: Option<Vec<u8>>,
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
        newer: newer.clone(),
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
    let identity = manager
        .cache_root()
        .join(hash(context.state_directory.as_os_str().as_encoded_bytes()));
    let endpoint = Endpoint::for_artifact(&identity, &artifact)?;
    if blocked {
        let retry_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + 300;
        // A previous failed worker startup is a real transport-unavailable case.
        // Core must still resolve/verify the tool and obey policy before fallback.
        std::fs::write(
            manager.cache_root().join(format!(
                "sync.{}.worker-attempts.json",
                endpoint.startup_key()
            )),
            serde_json::to_vec(
                &serde_json::json!({"count": 1, "last_start": retry_at - 300, "retry_at": retry_at}),
            )?,
        )?;
    }
    let (first, second) = tokio::join!(
        manager.connect(Component::Sync, &context, mode, &cancel),
        manager.connect(Component::Sync, &context, mode, &cancel)
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
    if matches!(mode, Mode::Rpc) {
        assert_eq!(one, two);
    } else {
        assert_ne!(one, two);
    }
    assert_ne!(one, std::process::id());
    assert_eq!(fixture.binaries.load(Ordering::SeqCst), 1);
    if failed_update {
        let pinned = manager.session(Component::Sync, &context, &cancel).await?;
        assert!(
            pinned.newer(&cancel).await?.is_none(),
            "unchanged catalog must not create a candidate worker"
        );
        let mut candidate = artifact.clone();
        candidate.version = "0.1.1".parse()?;
        let mut update = catalog.clone();
        update.release = "1.12.0".parse()?;
        candidate.release = update.release.clone();
        update.artifacts.push(candidate.clone());
        // Same verified fixture bytes deliberately announce 0.1.0, so the
        // candidate passes integrity checks but fails its version handshake.
        std::fs::write(
            manager
                .cache_root()
                .join(porthub_components::catalog::CATALOG_ASSET),
            serde_json::to_vec(&update)?,
        )?;
        let candidate_endpoint = Endpoint::for_artifact(&identity, &candidate)?;
        let retry_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            + 300;
        std::fs::write(
            manager.cache_root().join(format!(
                "sync.{}.worker-attempts.json",
                candidate_endpoint.startup_key()
            )),
            serde_json::to_vec(
                &serde_json::json!({"count":1,"last_start":retry_at-300,"retry_at":retry_at}),
            )?,
        )?;
        let recovered_session = manager.session(Component::Sync, &context, &cancel).await?;
        assert_eq!(recovered_session.artifact().version, artifact.version);
        assert!(
            pinned.newer(&cancel).await?.is_none(),
            "failed candidate must leave the activated session pinned"
        );

        assert_eq!(pinned.artifact().version, artifact.version);
        let mut pinned_client = pinned.connect(&cancel).await?;
        assert!(
            matches!(pinned_client.call::<_, SystemValue>(SystemOperation::Ping, Duration::from_secs(2)).await?,
            SystemValue::Pong { pid } if pid == one)
        );
        let mut recovered = manager
            .connect(Component::Sync, &context, Mode::Cli, &cancel)
            .await?;
        assert!(matches!(
            recovered
                .call::<_, SystemValue>(SystemOperation::Ping, Duration::from_secs(2))
                .await?,
            SystemValue::Pong { .. }
        ));
        let other = ContextOptions {
            state_directory: root.path().join("other-state"),
        };
        assert!(
            manager
                .connect(Component::Sync, &other, Mode::Cli, &cancel)
                .await
                .is_err(),
            "downloaded binaries must not qualify as activated in another context"
        );
        let pinned = Manager::new(
            manager.cache_root().to_path_buf(),
            Settings {
                gateway: Some("https://fixture.test".parse()?),
                sources: Sources::GatewayOnly,
                core: "1.10.1".parse()?,
                target: target.into(),
                disabled: BTreeSet::new(),
                pins: BTreeMap::from([(Component::Sync, candidate.version.clone())]),
            },
            fixture.clone(),
        )?;
        assert!(
            pinned
                .connect(Component::Sync, &context, Mode::Cli, &cancel)
                .await
                .is_err(),
            "an explicit version pin must prevent recovery to a different version"
        );
        drop(recovered);
    }

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
    let mut _candidate_cleanup = None;
    if let Some(bytes) = newer {
        let pinned = manager.session(Component::Sync, &context, &cancel).await?;
        assert!(pinned.newer(&cancel).await?.is_none());
        let mut candidate = artifact.clone();
        candidate.version = "0.1.1".parse()?;
        candidate.executable = Blob {
            size: bytes.len() as u64,
            sha256: hash(&bytes),
        };
        let mut update = catalog.clone();
        update.release = "1.12.0".parse()?;
        candidate.release = update.release.clone();
        update.artifacts.push(candidate.clone());
        std::fs::write(
            manager
                .cache_root()
                .join(porthub_components::catalog::CATALOG_ASSET),
            serde_json::to_vec(&update)?,
        )?;
        let staged = pinned
            .newer(&cancel)
            .await?
            .context("healthy candidate not staged")?;
        assert_eq!(staged.artifact().version, candidate.version);
        _candidate_cleanup = Some(Cleanup {
            endpoint: Endpoint::for_artifact(&identity, &candidate)?,
            artifact: candidate,
        });
        let mut next = staged.connect(&cancel).await?;
        assert!(
            matches!(next.call::<_,SystemValue>(SystemOperation::Ping,Duration::from_secs(2)).await?,
            SystemValue::Pong {pid} if pid != one)
        );
        let mut old = pinned.connect(&cancel).await?;
        assert!(
            matches!(old.call::<_,SystemValue>(SystemOperation::Ping,Duration::from_secs(2)).await?,
            SystemValue::Pong {pid} if pid == one)
        );
        assert_eq!(fixture.binaries.load(Ordering::SeqCst), 2);
        // The original foreground watch stream stays open across candidate startup.
    }

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
