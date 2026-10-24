//! Development-only transient-service fixture. Never packaged in agent images.
#[cfg(target_os = "linux")]
async fn run() -> anyhow::Result<()> {
    use anyhow::{ensure, Context};
    use porthub_agent::service::systemd::Systemd;
    use std::{io::Write, os::unix::fs::OpenOptionsExt, path::PathBuf, time::Duration};
    use tokio::io::AsyncWriteExt;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg == "--caller" || arg == "--system-caller")
    {
        ensure!(args.len() == 2, "fixture directory required");
        let controller = if args[0] == "--system-caller" {
            Systemd::connect().await?
        } else {
            Systemd::connect_user().await?
        };
        let child = vec![
            "adopt-legacy".into(),
            "--apply".into(),
            "--legacy-root".into(),
            args[1].clone(),
            "--server".into(),
            "https://gateway.invalid/$PORTHUB_NATIVE_UNSET%q".into(),
        ];
        let unit = controller
            .schedule_adoption(&std::env::current_exe()?, &child)
            .await?;
        println!(
            "{}",
            serde_json::json!({"unit":unit,"caller_pid":std::process::id()})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 6
            && args[0] == "adopt-legacy"
            && args[1] == "--apply"
            && args[2] == "--legacy-root",
        "invalid fixture invocation"
    );
    let root = PathBuf::from(&args[3]);
    ensure!(root.is_absolute(), "fixture needs an absolute directory");
    let listener = tokio::net::UnixListener::bind(root.join("release.sock"))?;
    let proof = serde_json::json!({"pid":std::process::id(),"arguments":args,"cgroup":std::fs::read_to_string("/proc/self/cgroup")?});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("ready.json"))?;
    file.write_all(serde_json::to_string(&proof)?.as_bytes())?;
    file.sync_all()?;
    drop(file);
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
        .await
        .context("fixture release timed out")??;
    stream.write_all(b"done").await?;
    Ok(())
}
#[cfg(target_os = "linux")]
#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    run().await
}
#[cfg(not(target_os = "linux"))]
fn main() {}
