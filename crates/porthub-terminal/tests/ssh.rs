#![cfg(all(feature = "ssh", unix))]
use anyhow::Result;
use porthub_terminal::{hub::Hub, protocol::*};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn ordinary_openssh_joins_shared_terminal_and_read_only_invites_cannot_write() -> Result<()> {
    let root = tempfile::tempdir()?;
    let key = porthub_terminal::ssh::host_key(&root.path().join("host_key"))?;
    let config = porthub_terminal::ssh::config(key);
    let hub = Hub::default();
    let hello = HostHello {
        id: random_token(16),
        secret: random_token(32),
        write_token: random_token(32),
        read_token: random_token(32),
        options: Options {
            name: "SSH pair".into(),
            expires_at: now() + 120,
            session_expires_at: None,
            idle_timeout: 0,
            reconnect_timeout: 60,
            history_limit: DEFAULT_HISTORY,
            mouse: true,
            read_only: false,
            size_policy: SizePolicy::Smallest,
            access: Access::Both,
            max_viewers: 16,
        },
    };
    let mut host = hub.register("fixture-owner", &hello, now())?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let stop = CancellationToken::new();
    let worker_stop = stop.clone();
    let worker_hub = hub.clone();
    let worker = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _=worker_stop.cancelled()=>{tasks.abort_all();break;},
                accepted=listener.accept()=>{let (socket,_)=accepted?;tasks.spawn(porthub_terminal::ssh::serve(socket,config.clone(),worker_hub.clone(),worker_stop.child_token()));}
            }
        }
        Ok::<_, anyhow::Error>(())
    });
    for (token, read_only) in [(&hello.write_token, false), (&hello.read_token, true)] {
        let mut child = Command::new("ssh")
            .args([
                "-F",
                "/dev/null",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "LogLevel=ERROR",
                "-tt",
                "-p",
                &port.to_string(),
                &format!("{token}@127.0.0.1"),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let event = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let event = host.events.recv().await.expect("host channel remains open");
                if matches!(event, HostEvent::Attach { .. }) {
                    break event;
                }
            }
        })
        .await?;
        let HostEvent::Attach {
            client,
            read_only: actual,
            ..
        } = event
        else {
            anyhow::bail!("expected SSH attach");
        };
        assert_eq!(actual, read_only);
        host.session.output(
            host.generation,
            HostOutput::Output {
                client,
                data: encode_data(b"shared-shell-ready\r\n"),
            },
        )?;
        let mut received = vec![0; 128];
        let count = tokio::time::timeout(
            Duration::from_secs(5),
            child.stdout.as_mut().unwrap().read(&mut received),
        )
        .await??;
        assert!(
            String::from_utf8_lossy(&received[..count]).contains("shared-shell-ready"),
            "SSH output count={count}: {:?}",
            String::from_utf8_lossy(&received[..count])
        );
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"echo hello\n")
            .await?;
        let next_input = async {
            loop {
                let event = host.events.recv().await.expect("host channel remains open");
                if let HostEvent::Input { client: id, .. } = event {
                    break id;
                }
            }
        };
        if read_only {
            assert!(tokio::time::timeout(Duration::from_millis(200), next_input)
                .await
                .is_err());
            child.stdin.as_mut().unwrap().write_all(b"\x1b[18~").await?;
            let request = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match host.events.recv().await.unwrap() {
                        HostEvent::History {
                            client: id,
                            request,
                            ..
                        } if id == client => break request,
                        HostEvent::Input { .. } => {
                            panic!("read-only navigation became shell input")
                        }
                        _ => {}
                    }
                }
            })
            .await?;
            host.session.output(
                host.generation,
                HostOutput::History {
                    client,
                    page: HistoryChunk {
                        request,
                        data: encode_data(b"retained-view\n"),
                        done: true,
                        total: 100,
                        before: 0,
                        lines: 1,
                        truncated: false,
                        error: None,
                    },
                },
            )?;
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut output = Vec::new();
                let mut bytes = [0; 4096];
                loop {
                    let count = child.stdout.as_mut().unwrap().read(&mut bytes).await?;
                    anyhow::ensure!(count > 0, "SSH viewer closed");
                    output.extend_from_slice(&bytes[..count]);
                    if String::from_utf8_lossy(&output).contains("retained-view") {
                        break;
                    }
                }
                Ok::<_, anyhow::Error>(())
            })
            .await??;
            child.stdin.as_mut().unwrap().write_all(b"q").await?;
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    match host.events.recv().await.unwrap() {
                        HostEvent::Redraw { client: id } if id == client => break,
                        HostEvent::Input { .. } => {
                            panic!("read-only pager exit became shell input")
                        }
                        _ => {}
                    }
                }
            })
            .await?;
        } else {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), next_input).await?,
                client
            );
        }
        host.session
            .output(host.generation, HostOutput::Closed { client })?;
        tokio::time::timeout(Duration::from_secs(5), child.wait()).await??;
        while host.events.try_recv().is_ok() {}
    }
    hub.end(&hello.id, "test ended");
    stop.cancel();
    worker.await??;
    Ok(())
}
