use anyhow::{ensure, Result};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;
struct Job {
    id: String,
    state: PathBuf,
}
impl Drop for Job {
    fn drop(&mut self) {
        let _ = std::process::Command::new(env!("CARGO_BIN_EXE_porthub-sync"))
            .env("PORTHUB_STATE_DIR", &self.state)
            .args(["stop", &self.id])
            .output();
    }
}
async fn run(state: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_porthub-sync"));
    command
        .kill_on_drop(true)
        .env("PORTHUB_STATE_DIR", state)
        .args(args);
    let output = tokio::time::timeout(Duration::from_secs(20), command.output()).await??;
    ensure!(
        output.status.success(),
        "standalone sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output.stdout)
}
async fn wait_for(path: &Path, contents: &[u8]) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !std::fs::read(path).is_ok_and(|bytes| bytes == contents) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("standalone job did not synchronize the file");
}
#[tokio::test]
async fn standalone_watch_runs_without_core_or_gateway_and_keeps_working_after_launcher_exits(
) -> Result<()> {
    let directory = tempfile::tempdir()?;
    let state = directory.path().join("isolated-state");
    let source = directory.path().join("source");
    let destination = directory.path().join("receiver");
    std::fs::create_dir_all(&source)?;
    std::fs::create_dir_all(&destination)?;
    std::fs::write(source.join("file"), b"initial")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let app = porthub_transfer::server::router(destination.clone())
        .merge(porthub_transfer::upload::routes(destination.clone())?);
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let url = format!("http://{address}/");
    run(
        &state,
        &[
            "watch",
            source.to_str().unwrap(),
            &url,
            "--contents-only",
            "--detach",
        ],
    )
    .await?;
    let list: serde_json::Value = serde_json::from_slice(&run(&state, &["list", "--json"]).await?)?;
    let id = list[0]["id"].as_str().unwrap().to_owned();
    let job = Job {
        id,
        state: state.clone(),
    };
    wait_for(&destination.join("file"), b"initial").await;
    std::fs::write(destination.join("remote-only"), b"keep")?;
    std::fs::write(source.join("file"), b"changed after launcher exited")?;
    wait_for(&destination.join("file"), b"changed after launcher exited").await;
    let status: serde_json::Value =
        serde_json::from_slice(&run(&state, &["status", &job.id, "--json"]).await?)?;
    ensure!(status["id"].as_str() == Some(job.id.as_str()));
    ensure!(std::fs::read(destination.join("remote-only"))? == b"keep");
    run(&state, &["stop", &job.id]).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let list: serde_json::Value =
                serde_json::from_slice(&run(&state, &["list", "--json"]).await.unwrap()).unwrap();
            if list.as_array().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    drop(job);
    server.abort();
    Ok(())
}
