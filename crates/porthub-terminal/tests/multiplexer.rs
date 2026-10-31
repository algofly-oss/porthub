#![cfg(unix)]
use anyhow::Result;
use porthub_terminal::multiplexer::{create_directory, Start, Workspace};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

fn workspace() -> Result<(tempfile::TempDir, Workspace)> {
    let directory = tempfile::tempdir()?;
    let runtime = if let Ok(bundle) = std::env::var("PORTHUB_TEST_TERMINAL_BUNDLE") {
        let cache = directory.path().join("runtime");
        create_directory(&cache)?;
        let runtime = porthub_terminal::runtime::install(
            &std::fs::read(bundle)?,
            &cache,
            &std::env::var("PORTHUB_TEST_TERMINAL_TARGET").expect("set helper target"),
        )?;
        runtime.executable.parent().unwrap().to_path_buf()
    } else {
        PathBuf::from(
            std::env::var("PORTHUB_TEST_TERMINAL_RUNTIME")
                .expect("set PORTHUB_TEST_TERMINAL_BUNDLE or PORTHUB_TEST_TERMINAL_RUNTIME"),
        )
    };
    let path = directory.path().join("workspace");
    create_directory(&path)?;
    let workspace = Workspace::open(runtime.join("tmux"), runtime.join("terminfo"), path)?;
    Ok((directory, workspace))
}

fn start() -> Start {
    Start {
        cwd: PathBuf::from("/tmp"),
        shell: PathBuf::from("/bin/sh"),
        command: Vec::new(),
        environment: vec![("PORTHUB_SHARED_TEST".into(), "sharedworkspace".into())],
        history_limit: 100_000,
        mouse: true,
        prefix: "C-a".into(),
        cols: 100,
        rows: 30,
    }
}

struct Cleanup(Workspace);
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = self.0.stop();
    }
}

#[test]
#[ignore = "requires extracted bundled runtime in PORTHUB_TEST_TERMINAL_RUNTIME"]
fn detached_workspace_preserves_shared_shell_and_explicit_exit_ends_it() -> Result<()> {
    let (_directory, workspace) = workspace()?;
    let _cleanup = Cleanup(workspace.clone());
    workspace.start(&start())?;
    let observer = workspace.clone();
    drop(workspace);
    assert!(
        observer.is_alive(),
        "dropping owner handle must not destroy the shell"
    );
    let sent = observer
        .command()
        .args([
            "send-keys",
            "-t",
            "%0",
            "printf 'MARKER:%s\\n' \"$PORTHUB_SHARED_TEST\"",
            "Enter",
        ])
        .output()?;
    assert!(
        sent.status.success(),
        "{}",
        String::from_utf8_lossy(&sent.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !observer
        .capture("%0", 100)?
        .contains("MARKER:sharedworkspace")
    {
        assert!(
            Instant::now() < deadline,
            "shared shell output not observed"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let config = observer.command().args(["show-options", "-g"]).output()?;
    let config = String::from_utf8(config.stdout)?;
    assert!(config.contains("history-limit 100000"));
    assert!(config.contains("mouse on"));
    assert!(config.contains("prefix C-a"));
    assert!(config.contains("destroy-unattached off"));
    assert!(observer
        .command()
        .args(["send-keys", "-t", "%0", "exit", "Enter"])
        .status()?
        .success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while observer.is_alive() {
        assert!(
            Instant::now() < deadline,
            "final shell exit must end workspace"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

#[test]
#[ignore = "requires extracted bundled runtime in PORTHUB_TEST_TERMINAL_RUNTIME"]
fn stopping_one_workspace_does_not_affect_another() -> Result<()> {
    let (_first_dir, first) = workspace()?;
    let (_second_dir, second) = workspace()?;
    let _first_cleanup = Cleanup(first.clone());
    let _second_cleanup = Cleanup(second.clone());
    first.start(&start())?;
    second.start(&start())?;
    first.stop()?;
    assert!(!first.is_alive());
    assert!(second.is_alive());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires bundled terminal runtime"]
async fn real_pty_participants_share_output_and_disconnect_preserves_workspace() -> Result<()> {
    use porthub_terminal::{
        protocol::{decode_data, encode_data, HostOutput},
        pty::Client,
    };
    let (_directory, workspace) = workspace()?;
    let _cleanup = Cleanup(workspace.clone());
    workspace.start(&start())?;
    let (output, mut events) = tokio::sync::mpsc::channel(128);
    let writer = Client::attach(
        &workspace,
        1,
        false,
        100,
        30,
        "xterm-256color",
        output.clone(),
    )?;
    let reader = Client::attach(&workspace, 2, true, 100, 30, "xterm-256color", output)?;
    assert!(reader.input(&encode_data(b"exit\r")).is_err());
    let mut received = [Vec::new(), Vec::new()];
    // Wait for both real tmux clients to initialize before sending shell input.
    tokio::time::timeout(Duration::from_secs(5), async {
        while received.iter().any(Vec::is_empty) {
            if let Some(HostOutput::Output { client, data }) = events.recv().await {
                received[client as usize - 1].extend(decode_data(&data)?);
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    writer.input(&encode_data(b"printf 'PORT%s\\n' 'HUBSHARED'\r"))?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while received
            .iter()
            .any(|bytes| !String::from_utf8_lossy(bytes).contains("PORTHUBSHARED"))
        {
            match events.recv().await {
                Some(HostOutput::Output { client, data }) => {
                    received[client as usize - 1].extend(decode_data(&data)?)
                }
                Some(HostOutput::Closed { client }) => {
                    anyhow::bail!("participant {client} closed unexpectedly")
                }
                None => anyhow::bail!("PTY output channel closed"),
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    let clients = workspace
        .command()
        .args(["list-clients", "-F", "#{session_name}"])
        .output()?;
    assert!(clients.status.success());
    assert_eq!(
        String::from_utf8(clients.stdout)?
            .lines()
            .collect::<Vec<_>>(),
        vec!["workspace", "workspace"]
    );
    writer.resize(120, 40)?;
    reader.resize(80, 24)?;
    drop(writer);
    assert!(workspace.is_alive());
    assert!(workspace
        .command()
        .args([
            "send-keys",
            "-c",
            "porthub-owner-command",
            "-t",
            "%0",
            "printf 'AFTER%s\\n' 'DISCONNECT'",
            "Enter"
        ])
        .status()?
        .success());
    let mut after = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !String::from_utf8_lossy(&after).contains("AFTERDISCONNECT") {
            match events.recv().await {
                Some(HostOutput::Output { client: 2, data }) => after.extend(decode_data(&data)?),
                Some(HostOutput::Closed { client: 2 }) | None => {
                    anyhow::bail!("remaining viewer disconnected")
                }
                _ => {}
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    drop(reader);
    assert!(
        workspace.is_alive(),
        "last participant disconnect must not end the shared shell"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires bundled terminal runtime"]
async fn read_only_history_pages_real_scrollback_without_entering_copy_mode() -> Result<()> {
    use porthub_terminal::{host::Attachments, protocol::*};
    let (_directory, workspace) = workspace()?;
    let _cleanup = Cleanup(workspace.clone());
    workspace.start(&start())?;
    let mut attachments = Attachments::new(workspace.clone(), 2)?;
    attachments.apply(HostEvent::Attach {
        client: 7,
        read_only: true,
        cols: 100,
        rows: 30,
        term: "xterm-256color".into(),
    })?;
    let output=workspace.command().args(["send-keys","-c","porthub-history-owner","-t","%0","i=0; while [ $i -lt 250 ]; do printf 'history-line-%s\\n' \"$i\"; i=$((i+1)); done; printf 'history-done\\n'","Enter"]).output()?;
    assert!(output.status.success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !workspace.capture("%0", 1000)?.contains("history-line-249") {
        assert!(
            Instant::now() < deadline,
            "shell history generation timed out"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (recent, total, count, truncated) =
        porthub_terminal::history::page(&workspace, "%0", 0, 32).await?;
    assert!(total > 200 && count == 32 && !truncated);
    let (active, _, _, _) = porthub_terminal::history::page(&workspace, "", 0, 32).await?;
    assert_eq!(
        active, recent,
        "blank pane must capture the active workspace pane"
    );
    let (older, older_total, older_count, _) =
        porthub_terminal::history::page(&workspace, "%0", 32, 32).await?;
    assert_eq!(total, older_total);
    assert_eq!(older_count, 32);
    assert_ne!(recent, older);
    attachments.apply(HostEvent::History {
        client: 7,
        request: 19,
        pane: "%0".into(),
        before: 0,
        lines: 32,
    })?;
    let routed = tokio::time::timeout(Duration::from_secs(5), async {
        let mut bytes = Vec::new();
        loop {
            match attachments.next().await {
                Some(HostOutput::History { client, page }) => {
                    assert_eq!(client, 7);
                    assert_eq!(page.request, 19);
                    assert!(page.error.is_none());
                    page.validate()?;
                    bytes.extend(decode_data(&page.data)?);
                    if page.done {
                        break;
                    }
                }
                Some(_) => {}
                None => anyhow::bail!("attachment router closed"),
            }
        }
        Ok::<_, anyhow::Error>(bytes)
    })
    .await??;
    assert_eq!(routed, recent);
    while tokio::time::timeout(Duration::from_millis(30), attachments.next())
        .await
        .is_ok()
    {}
    attachments.apply(HostEvent::Redraw { client: 7 })?;
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut text = Vec::new();
        loop {
            if let Some(HostOutput::Output { client, data }) = attachments.next().await {
                assert_eq!(client, 7);
                text.extend(decode_data(&data)?);
                if String::from_utf8_lossy(&text).contains("history-done") {
                    break;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;

    let mode = workspace
        .command()
        .args(["display-message", "-p", "-t", "%0", "#{pane_in_mode}"])
        .output()?;
    assert_eq!(
        String::from_utf8_lossy(&mode.stdout).trim(),
        "0",
        "history must not change shared copy mode"
    );
    assert!(
        porthub_terminal::history::page(&workspace, "%0; touch /tmp/unsafe", 0, 32)
            .await
            .is_err()
    );
    let (empty, _, count, _) =
        porthub_terminal::history::page(&workspace, "%0", 200000, 32).await?;
    assert!(empty.is_empty() && count == 0);
    Ok(())
}

#[test]
#[ignore = "requires bundled terminal runtime"]
fn singleton_program_path_is_literal_and_custom_shell_paths_can_contain_spaces() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for custom_shell in [false, true] {
        let (directory, workspace) = workspace()?;
        let _cleanup = Cleanup(workspace.clone());
        let program = directory
            .path()
            .join("program with spaces; touch unexpected; #");
        std::fs::write(
            &program,
            "#!/bin/sh\nprintf 'literal-path-ran\\n'\nexec /bin/sh\n",
        )?;
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))?;
        let mut options = start();
        options.cwd = directory.path().into();
        if custom_shell {
            options.shell = program.clone();
        } else {
            options.command = vec![program.into_os_string()];
        }
        workspace.start(&options)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut ran = false;
        while Instant::now() < deadline {
            if workspace
                .capture("%0", 100)
                .is_ok_and(|text| text.contains("literal-path-ran"))
            {
                ran = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !directory.path().join("unexpected").exists(),
            "program path must never be interpreted as shell syntax"
        );
        assert!(
            ran,
            "the selected program must launch literally; custom_shell={custom_shell}"
        );
        assert!(workspace.is_alive());
    }
    Ok(())
}
