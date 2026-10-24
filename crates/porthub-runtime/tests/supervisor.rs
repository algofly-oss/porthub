#![cfg(unix)]
use porthub_runtime::supervise::Config;
use std::time::Duration;

#[test]
fn configuration_selects_mode_and_rejects_ambiguous_services() {
    let source="[[process]]\nname='api'\nprogram='porthub-api'\n[[process]]\nname='ui'\nprogram='node'\nmodes=['prod']\n[[process]]\nname='ui'\nprogram='next'\nmodes=['dev']\n";
    assert_eq!(
        Config::parse(source, "prod").unwrap().process[1].program,
        "node"
    );
    assert_eq!(
        Config::parse(source, "dev").unwrap().process[1].program,
        "next"
    );
    assert!(Config::parse(source, "other").is_err());
    assert!(Config::parse(
        "[[process]]\nname='api'\nprogram='one'\n[[process]]\nname='api'\nprogram='two'",
        "prod"
    )
    .is_err());
}

#[tokio::test]
async fn failed_child_restarts_and_supervisor_forwards_shutdown() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let events = directory.path().join("events");
    // The shell is only a test fixture. Production processes execute their
    // configured executable/argument vectors directly.
    let script = r#"if [ ! -e "$1" ]; then printf 'first\n' > "$1"; exit 1; fi
printf 'second\n' >> "$1"
trap 'printf "stopped\n" >> "$1"; exit 0' TERM
sleep 300 & wait"#;
    let mut process = toml::value::Table::new();
    process.insert("name".into(), "fixture".into());
    process.insert("program".into(), "/bin/sh".into());
    process.insert(
        "args".into(),
        toml::Value::Array(vec![
            "-c".into(),
            script.into(),
            "porthub-test".into(),
            events.to_string_lossy().to_string().into(),
        ]),
    );
    let mut config = toml::value::Table::new();
    config.insert(
        "process".into(),
        toml::Value::Array(vec![toml::Value::Table(process)]),
    );
    let path = directory.path().join("supervisor.toml");
    tokio::fs::write(&path, toml::to_string(&config)?).await?;
    let mut supervisor = tokio::process::Command::new(env!("CARGO_BIN_EXE_porthub-runtime"))
        .args(["supervise", "--config"])
        .arg(path)
        .env("PORTHUB_MODE", "prod")
        .kill_on_drop(true)
        .spawn()?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tokio::fs::read_to_string(&events)
                .await
                .unwrap_or_default()
                .contains("second")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await?;
    let pid = rustix::process::Pid::from_raw(supervisor.id().unwrap() as i32).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), supervisor.wait())
            .await??
            .success()
    );
    assert_eq!(
        tokio::fs::read_to_string(&events).await?,
        "first\nsecond\nstopped\n"
    );
    Ok(())
}
