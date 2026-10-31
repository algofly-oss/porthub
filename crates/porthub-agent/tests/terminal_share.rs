#![cfg(unix)]
//! Real owner supervisor + bundled tmux + PTYs, using an isolated local broker.
use anyhow::{ensure, Result};
use porthub_terminal::protocol::*;
use std::{
    collections::BTreeMap, os::unix::fs::PermissionsExt, path::PathBuf, process::Command,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an agent binary with bundled terminal runtime"]
async fn sharing_supervisor_reconnects_to_existing_shell_and_explicit_stop_announces_end(
) -> Result<()> {
    let executable = std::env::var_os("PORTHUB_TEST_AGENT_EXECUTABLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_porthub")));
    let directory = tempfile::tempdir()?;
    let data = directory.path().join("data");
    let config = directory.path().join("config");
    let output = Command::new(&executable)
        .args([
            "terminal",
            "sharedtest",
            "--detach",
            "--json",
            "--shell",
            "/bin/sh",
        ])
        .env("XDG_DATA_HOME", &data)
        .output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let job: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let id = job["id"].as_str().unwrap().to_owned();
    struct Cleanup {
        executable: PathBuf,
        data: PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new(&self.executable)
                .args(["terminal", "stop", "sharedtest"])
                .env("XDG_DATA_HOME", &self.data)
                .output();
        }
    }
    let _cleanup = Cleanup {
        executable: executable.clone(),
        data: data.clone(),
    };
    let registration = "a".repeat(64);
    let hello: HostHello = serde_json::from_value(
        serde_json::json!({"id":id,"secret":"b".repeat(64),"write_token":"c".repeat(64),"read_token":"d".repeat(64),
        "options":{"name":"sharedtest","expires_at":0,"idle_timeout":0,"reconnect_timeout":60,"history_limit":100000,"mouse":true,"read_only":false,"size_policy":"smallest"}}),
    )?;
    let path = data.join("porthub/terminal").join(format!("{id}.share"));
    std::fs::write(
        &path,
        serde_json::to_vec(
            &serde_json::json!({"hello":hello,"registration":registration,"user":true,"ready":null,"state":"connecting"}),
        )?,
    )?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let status = config.join("porthub/status");
    std::fs::create_dir_all(&status)?;
    let listener =
        tokio::net::UnixListener::bind(status.join(format!("{}.sock", &registration[..24])))?;
    let mut worker = tokio::process::Command::new(&executable)
        .args(["terminal", "__serve", &id])
        .env("XDG_DATA_HOME", &data)
        .env("XDG_CONFIG_HOME", &config)
        .env_remove("TMUX")
        .env_remove("TMUX_PANE")
        .kill_on_drop(true)
        .spawn()?;
    async fn send(stream: &mut BufReader<tokio::net::UnixStream>, event: HostEvent) -> Result<()> {
        let mut bytes = serde_json::to_vec(&event)?;
        bytes.push(b'\n');
        stream.get_mut().write_all(&bytes).await?;
        Ok(())
    }
    async fn connect(
        listener: &tokio::net::UnixListener,
        expected: &HostHello,
    ) -> Result<BufReader<tokio::net::UnixStream>> {
        let (stream, _) =
            tokio::time::timeout(Duration::from_secs(10), listener.accept()).await??;
        let mut stream = BufReader::new(stream);
        let mut first = String::new();
        stream.read_line(&mut first).await?;
        let request: serde_json::Value = serde_json::from_str(&first)?;
        assert_eq!(request["operation"], "terminal_host");
        let hello: HostHello = serde_json::from_value(request["hello"].clone())?;
        assert_eq!(hello.id, expected.id);
        assert_eq!(hello.secret, expected.secret);
        assert!(request.get("authorization").is_none());
        send(
            &mut stream,
            HostEvent::Ready {
                ssh_host: "example.test".into(),
                ssh_port: 8347,
                public_base: "https://example.test".into(),
            },
        )
        .await?;
        Ok(stream)
    }
    async fn until(
        stream: &mut BufReader<tokio::net::UnixStream>,
        clients: &[u64],
        marker: &str,
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut received: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
            while clients.iter().any(|id| {
                !received
                    .get(id)
                    .is_some_and(|bytes| String::from_utf8_lossy(bytes).contains(marker))
            }) {
                let mut line = String::new();
                ensure!(
                    stream.read_line(&mut line).await? > 0,
                    "sharing supervisor disconnected"
                );
                if let HostOutput::Output { client, data } = serde_json::from_str(&line)? {
                    received
                        .entry(client)
                        .or_default()
                        .extend(decode_data(&data)?);
                }
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
    let mut first = connect(&listener, &hello).await?;
    for (client, read_only) in [(1, false), (2, true)] {
        send(
            &mut first,
            HostEvent::Attach {
                client,
                read_only,
                cols: 100,
                rows: 30,
                term: "xterm-256color".into(),
            },
        )
        .await?;
    }
    until(&mut first, &[1, 2], "PortHub").await?;
    // A real shell sets state, then both viewers see its output.
    send(
        &mut first,
        HostEvent::Input {
            client: 1,
            data: encode_data(b"PORTSTATE=preserved; printf 'INITIAL%s\\n' 'SHARED'\r"),
        },
    )
    .await?;
    until(&mut first, &[1, 2], "INITIALSHARED").await?;
    send(
        &mut first,
        HostEvent::Presence {
            members: vec![
                Participant {
                    id: 1,
                    read_only: false,
                    joined_at: now(),
                    last_active_at: now(),
                },
                Participant {
                    id: 2,
                    read_only: true,
                    joined_at: now(),
                    last_active_at: now(),
                },
            ],
        },
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let listed = tokio::process::Command::new(&executable)
                .args(["terminal", "participants", "sharedtest", "--json"])
                .env("XDG_DATA_HOME", &data)
                .output()
                .await?;
            if listed.status.success() {
                let value: serde_json::Value = serde_json::from_slice(&listed.stdout)?;
                if value["members"]
                    .as_array()
                    .is_some_and(|members| members.len() == 2)
                {
                    assert_eq!(value["members"][1]["read_only"], true);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let removal = tokio::process::Command::new(&executable)
        .args(["terminal", "kick", "sharedtest", "2"])
        .env("XDG_DATA_HOME", &data)
        .output()
        .await?;
    ensure!(
        removal.status.success(),
        "{}",
        String::from_utf8_lossy(&removal.stderr)
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut line = String::new();
            ensure!(
                first.read_line(&mut line).await? > 0,
                "missing removal request"
            );
            if matches!(
                serde_json::from_str::<HostOutput>(&line)?,
                HostOutput::Kick { client: 2 }
            ) {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    send(&mut first, HostEvent::Detach { client: 2 }).await?;
    send(
        &mut first,
        HostEvent::Input {
            client: 1,
            data: encode_data(b"printf 'STILL%s\\n' 'RUNNING'\r"),
        },
    )
    .await?;
    until(&mut first, &[1], "STILLRUNNING").await?;
    drop(first);
    let mut resumed = connect(&listener, &hello).await?;
    send(
        &mut resumed,
        HostEvent::Attach {
            client: 1,
            read_only: false,
            cols: 100,
            rows: 30,
            term: "xterm-256color".into(),
        },
    )
    .await?;
    until(&mut resumed, &[1], "PortHub").await?;
    send(
        &mut resumed,
        HostEvent::Input {
            client: 1,
            data: encode_data(b"printf 'RE%s:%s\\n' 'CONNECTED' \"$PORTSTATE\"\r"),
        },
    )
    .await?;
    until(&mut resumed, &[1], "RECONNECTED:preserved").await?;
    let stopped = Command::new(&executable)
        .args(["terminal", "stop", "sharedtest"])
        .env("XDG_DATA_HOME", &data)
        .output()?;
    assert!(stopped.status.success());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut line = String::new();
            ensure!(
                resumed.read_line(&mut line).await? > 0,
                "missing session-end notification"
            );
            if matches!(serde_json::from_str::<HostOutput>(&line)?, HostOutput::End) {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    assert!(tokio::time::timeout(Duration::from_secs(5), worker.wait())
        .await??
        .success());
    let ended: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(ended["state"], "ended");
    Ok(())
}
