#![cfg(unix)]
use anyhow::{ensure, Context, Result};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct Runner(Child);
impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn cli(config: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_porthub"));
    command
        .env("XDG_CONFIG_HOME", config)
        .env("PORTHUB_STATE_DIR", config.join("runtime"));
    command
}
async fn wait_for(mut check: impl FnMut() -> bool) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(15);
    while !check() {
        ensure!(
            Instant::now() < until,
            "Timed out waiting for mapping state"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}
#[tokio::test]
async fn saved_forward_recovers_after_worker_loss_and_stop_prevents_resurrection() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("porthub/mappings");
    std::fs::create_dir_all(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let remote = TcpListener::bind("127.0.0.1:0").await?;
    let target = remote.local_addr()?.to_string();
    let remote_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = remote.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    let reservation = TcpListener::bind("127.0.0.1:0").await?;
    let local = reservation.local_addr()?;
    drop(reservation);
    let id = "a123456789abcdef0123456789abcdef";
    let config = root.join(format!("{id}.json"));
    porthub_agent::profile::write_private(
        &config,
        &serde_json::to_vec(
            &serde_json::json!({"id":id,"recover":true,"spec":{"kind":"forward","target":target,"bind":"127.0.0.1","port":local.port()}}),
        )?,
        false,
    )?;
    let mut runner = Runner(
        cli(temp.path())
            .arg("mapping-supervisor")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let status = root.join(format!("{id}.status"));
    let pid = || {
        std::fs::read(&status)
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .filter(|j| j["state"] == "running")
            .and_then(|j| j["pid"].as_u64())
            .map(|p| p as u32)
    };
    wait_for(|| pid().is_some()).await?;
    let original_pid = pid().context("Missing worker PID")?;
    let mut stream = TcpStream::connect(local).await?;
    stream.write_all(b"first").await?;
    let mut bytes = [0; 5];
    stream.read_exact(&mut bytes).await?;
    ensure!(&bytes == b"first");
    drop(stream);
    // This PID belongs to the isolated worker just launched by this test.
    ensure!(unsafe { libc::kill(original_pid as i32, libc::SIGTERM) } == 0);
    wait_for(|| pid().is_some_and(|p| p != original_pid)).await?;
    let mut stream = TcpStream::connect(local).await?;
    stream.write_all(b"again").await?;
    stream.read_exact(&mut bytes).await?;
    ensure!(&bytes == b"again");
    drop(stream);
    let output = cli(temp.path())
        .args(["forward", "status", &id[..8]])
        .output()?;
    ensure!(output.status.success() && String::from_utf8_lossy(&output.stdout).contains("running"));
    let output = cli(temp.path())
        .args(["forward", "stop", &id[..8]])
        .output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(!config.exists());
    ensure!(TcpStream::connect(local).await.is_err());
    // A fresh recovery process cannot recreate explicitly stopped mappings.
    runner.0.kill()?;
    runner.0.wait()?;
    let _restarted = Runner(
        cli(temp.path())
            .arg("mapping-supervisor")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    tokio::time::sleep(Duration::from_millis(3500)).await;
    ensure!(TcpStream::connect(local).await.is_err() && !config.exists());
    remote_task.abort();
    Ok(())
}
