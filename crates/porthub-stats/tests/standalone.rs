use serde_json::Value;
use std::process::Command;
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_porthub-stats"))
}
#[test]
fn independent_process_sampler_and_snapshot_input_need_no_core_or_gateway() {
    let output = command()
        .args(["--once", "--json", "--pid", &std::process::id().to_string()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["agents"][0]["process"]["pid"], std::process::id());
    assert!(value["agents"][0]["process"]["rss_bytes"].as_u64().unwrap() > 0);
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("snapshot.json");
    std::fs::write(&path, r#"{"agents":[{"registration":"fixture","state":"running","process":{"pid":7,"start_time":1}}]}"#).unwrap();
    let output = command()
        .args(["--once", "--json", "--input"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["agents"][0]["registration"], "fixture");
    std::fs::write(
        &path,
        r#"{"agents":[{"registration":"duplicate"},{"registration":"duplicate"}]}"#,
    )
    .unwrap();
    assert!(!command()
        .args(["--once", "--input"])
        .arg(path)
        .output()
        .unwrap()
        .status
        .success());
    let oversized = root.path().join("oversized.json");
    let rows: Vec<_> = (0..129)
        .map(|id| serde_json::json!({"registration":id.to_string()}))
        .collect();
    std::fs::write(
        &oversized,
        serde_json::to_vec(&serde_json::json!({"agents":rows})).unwrap(),
    )
    .unwrap();
    assert!(!command()
        .args(["--once", "--input"])
        .arg(&oversized)
        .output()
        .unwrap()
        .status
        .success());
    assert!(!command()
        .args(["--interval", "NaN"])
        .output()
        .unwrap()
        .status
        .success());
}

struct SnapshotBroker;
#[async_trait::async_trait]
impl porthub_components::rpc::Handler for SnapshotBroker {
    type Operation = porthub_components::protocol::stats::Operation;
    type Value = porthub_components::protocol::stats::Value;
    async fn handle(
        &self,
        _operation: Self::Operation,
        _cancel: tokio_util::sync::CancellationToken,
    ) -> Result<porthub_components::rpc::Reply<Self::Value>, porthub_components::rpc::Failure> {
        use porthub_components::{ipc, protocol::stats::Row, rpc::Reply};
        let (read, mut write) = tokio::io::duplex(65536);
        tokio::spawn(async move {
            for id in 0..3 {
                let row = Row {
                    data: serde_json::json!({"registration":format!("fixture{id}"), "detail":"x".repeat(24000)}),
                };
                if ipc::write(&mut write, &row, std::time::Duration::from_secs(5))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Ok(Reply::Stream {
            value: Self::Value::Snapshot { rows: 3 },
            remote: Box::new(read),
        })
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_frontend_receives_more_than_one_frame_without_core_credentials() {
    use porthub_components::{
        catalog::{Artifact, Blob, Component},
        ipc::Hello,
        local::Endpoint,
    };
    let root = tempfile::tempdir().unwrap();
    let artifact = Artifact {
        component: Component::Stats,
        version: option_env!("PORTHUB_COMPONENT_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .parse()
            .unwrap(),
        target: "x86_64-unknown-linux-gnu".into(),
        core: ">=1.11.0".parse().unwrap(),
        protocols: vec![1],
        source_revision: "a".repeat(40),
        build_inputs: "b".repeat(64),
        executable: Blob {
            size: 1,
            sha256: "c".repeat(64),
        },
        release: "1.11.0".parse().unwrap(),
        archive: Blob {
            size: 1,
            sha256: "d".repeat(64),
        },
    };
    let endpoint = Endpoint::for_artifact(root.path(), &artifact).unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let serving = endpoint.clone();
    let lifetime = cancel.clone();
    let server = tokio::spawn(async move {
        porthub_components::rpc::serve(
            serving,
            Hello {
                component: Component::Stats,
                protocol: 1,
                version: artifact.version,
            },
            std::sync::Arc::new(SnapshotBroker),
            lifetime,
        )
        .await
    });
    let output = tokio::task::spawn_blocking(move || {
        command()
            .args(["--once", "--json", "--managed-endpoint", endpoint.address()])
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    cancel.cancel();
    server.await.unwrap().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.len() > 65536);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["agents"].as_array().unwrap().len(), 3);
    assert_eq!(value["agents"][0]["detail"].as_str().unwrap().len(), 24000);
}
