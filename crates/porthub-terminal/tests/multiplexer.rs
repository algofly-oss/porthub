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
        freeze: false, snapshot: None,
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
                    assert_eq!(page.pane.as_deref(), Some("%0"));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires extracted bundled runtime"]
async fn history_stays_on_resolved_pane_during_window_switches_and_rejects_other_sessions(
) -> Result<()> {
    let (_directory, workspace) = workspace()?;
    let _cleanup = Cleanup(workspace.clone());
    workspace.start(&start())?;
    let second = workspace
        .command()
        .args([
            "new-window",
            "-d",
            "-P",
            "-F",
            "#{pane_id}",
            "-t",
            "=workspace:1",
            "/bin/sh",
        ])
        .output()?;
    anyhow::ensure!(second.status.success(), "second window must open");
    let beta = String::from_utf8(second.stdout)?.trim().to_owned();
    for (pane, label, count) in [("%0", "panealpha", 180), (beta.as_str(), "panebeta", 80)] {
        let command = format!(
            r#"i=0; while [ $i -lt {count} ]; do printf '{label}-%03d\n' "$i"; i=$((i+1)); done"#
        );
        let output = workspace
            .command()
            .args(["send-keys", "-t", pane, &command, "Enter"])
            .output()?;
        anyhow::ensure!(output.status.success());
        let deadline = Instant::now() + Duration::from_secs(3);
        while !workspace
            .capture(pane, 1000)?
            .contains(&format!("{label}-{:03}", count - 1))
        {
            anyhow::ensure!(Instant::now() < deadline, "fixture output missing");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let total = |pane: &str| -> Result<u32> {
        Ok(String::from_utf8(
            workspace
                .command()
                .args(["display-message", "-p", "-t", pane, "#{history_size}"])
                .output()?
                .stdout,
        )?
        .trim()
        .parse()?)
    };
    let alpha_total = total("%0")?;
    let beta_total = total(&beta)?;
    anyhow::ensure!(alpha_total != beta_total);
    let switching = workspace.clone();
    let switches = tokio::task::spawn_blocking(move || {
        for index in 0..160 {
            let target = if index % 2 == 0 {
                "=workspace:0"
            } else {
                "=workspace:1"
            };
            let _ = switching
                .command()
                .args(["select-window", "-t", target])
                .output();
        }
    });
    for _ in 0..30 {
        let (bytes, retained, _, _) =
            porthub_terminal::history::page(&workspace, "", 0, 10).await?;
        let text = String::from_utf8(bytes)?;
        if retained == alpha_total {
            anyhow::ensure!(
                text.contains("panealpha") && !text.contains("panebeta"),
                "history metadata and content came from different panes"
            );
        } else {
            anyhow::ensure!(
                retained == beta_total && text.contains("panebeta") && !text.contains("panealpha"),
                "history metadata and content came from different panes"
            );
        }
    }
    switches.await?;
    let other = workspace
        .command()
        .args([
            "new-session",
            "-d",
            "-s",
            "notshared",
            "-P",
            "-F",
            "#{pane_id}",
            "/bin/sh",
        ])
        .output()?;
    anyhow::ensure!(other.status.success());
    let hidden = String::from_utf8(other.stdout)?.trim().to_owned();
    anyhow::ensure!(
        porthub_terminal::history::page(&workspace, &hidden, 0, 10)
            .await
            .is_err(),
        "history must remain within the advertised workspace session"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires the verified bundled terminal runtime"]
async fn frozen_history_survives_output_resize_eviction_and_clear() -> Result<()> {
    use porthub_terminal::history::Snapshot;
    let (_directory, workspace) = workspace()?;
    let _cleanup = Cleanup(workspace.clone());
    let mut options = start();
    options.history_limit = 1000;
    workspace.start(&options)?;
    let empty = Snapshot::capture(&workspace, "").await?;
    assert_eq!(empty.total(), 0, "visible screen is not retained history");
    let generate = |command: &str| -> Result<()> {
        let output = workspace.command().args(["send-keys", "-c", "porthub-history-owner", "-t", "%0", command, "Enter"]).output()?;
        assert!(output.status.success());
        Ok(())
    };
    generate("i=0; while [ $i -lt 220 ]; do printf 'seed-%04d\\n' \"$i\"; i=$((i+1)); done; printf 'SNAPSHOT%s\\n' 'SEEDDONE'")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !workspace.capture("%0", 1500)?.contains("SNAPSHOTSEEDDONE") {
        assert!(Instant::now() < deadline, "seed output did not finish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let frozen = Snapshot::capture(&workspace, "").await?;
    assert_eq!(frozen.pane(), "%0");
    assert!(frozen.total() > 100);
    let saved = frozen.page(0, 512)?.bytes;
    let total = frozen.total();
    let id = frozen.id().to_owned();
    assert!(String::from_utf8_lossy(&saved).contains("seed-"));
    assert!(workspace.command().args(["resize-window", "-t", "=workspace:0", "-x", "40", "-y", "12"]).status()?.success());
    generate("i=0; while [ $i -lt 1500 ]; do printf 'later-%04d\\n' \"$i\"; i=$((i+1)); done; printf 'SNAPSHOT%s\\n' 'FLOODDONE'")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !workspace.capture("%0", 1500)?.contains("SNAPSHOTFLOODDONE") {
        assert!(Instant::now() < deadline, "later output did not finish");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let latest = Snapshot::capture(&workspace, "%0").await?;
    assert!((900..=1000).contains(&latest.total()));
    assert!(!String::from_utf8_lossy(&latest.page(0, 512)?.bytes).contains("seed-"));
    assert_eq!(frozen.page(0, 512)?.bytes, saved);
    assert_eq!(frozen.total(), total);
    assert_eq!(frozen.clone().id(), id);
    assert!(workspace.command().args(["clear-history", "-t", "%0"]).status()?.success());
    assert_eq!(Snapshot::capture(&workspace, "%0").await?.total(), 0);
    assert_eq!(frozen.page(0, 512)?.bytes, saved);
    assert!(workspace.command().args(["new-session", "-d", "-s", "outside", "/bin/sh"]).status()?.success());
    let pane = workspace.command().args(["list-panes", "-t", "outside:", "-F", "#{pane_id}"]).output()?;
    let pane = String::from_utf8(pane.stdout)?;
    assert!(Snapshot::capture(&workspace, pane.trim()).await.is_err(), "other sessions must remain inaccessible");
    Ok(())
}

#[tokio::test]
#[ignore = "requires bundled terminal runtime"]
async fn frozen_history_routes_stable_pages_and_rejects_detached_guest_anchors() -> Result<()> {
    use porthub_terminal::{host::Attachments, protocol::*};
    async fn page(router: &mut Attachments, request: u32, anchor: Option<String>) -> Result<HistoryChunk> {
        router.apply(HostEvent::History {
            client: 7, request, pane: "%0".into(), before: 0, lines: 10,
            freeze: true, snapshot: anchor,
        })?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(HostOutput::History { client: 7, page }) = router.next().await {
                    assert_eq!(page.request, request);
                    assert!(page.done, "small page should fit one frame");
                    page.validate()?;
                    return Ok(page);
                }
            }
        }).await?
    }
    let (_directory, workspace) = workspace()?;
    let _cleanup = Cleanup(workspace.clone());
    workspace.start(&start())?;
    let mut router = Attachments::new(workspace.clone(), 2)?;
    router.apply(HostEvent::Ready {
        direct_transport: false,
        history_snapshots: true, invitations_revoked: false,
        ssh_host: String::new(), ssh_port: 0, public_base: String::new(),
    })?;
    let attach = || HostEvent::Attach {
        client: 7, read_only: true, cols: 100, rows: 30, term: "xterm-256color".into(),
    };
    router.apply(attach())?;
    let send = |command: &str| -> Result<()> {
        let output = workspace.command().args(["send-keys", "-c", "porthub-history-owner", "-t", "%0", command, "Enter"]).output()?;
        anyhow::ensure!(output.status.success(), "history fixture input failed");
        Ok(())
    };
    send("i=0; while [ $i -lt 100 ]; do echo seed-$i; i=$((i+1)); done")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !workspace.capture("%0", 200)?.contains("seed-99") {
        anyhow::ensure!(Instant::now() < deadline, "history fixture timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let frozen = page(&mut router, 1, None).await?;
    assert!(frozen.error.is_none());
    let identity = frozen.snapshot.clone().expect("snapshot identity");
    send("i=0; while [ $i -lt 100 ]; do echo later-$i; i=$((i+1)); done")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !workspace.capture("%0", 200)?.contains("later-99") {
        anyhow::ensure!(Instant::now() < deadline, "later output timed out");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let retained = page(&mut router, 2, Some(identity.clone())).await?;
    assert!(retained.error.is_none());
    assert_eq!(retained.data, frozen.data);
    assert_eq!(retained.total, frozen.total);
    assert_eq!(retained.snapshot, frozen.snapshot);
    router.apply(HostEvent::Detach { client: 7 })?;
    router.apply(attach())?;
    let expired = page(&mut router, 3, Some(identity)).await?;
    assert!(expired.error.is_some(), "reattached guests cannot reuse old cache ownership");
    assert!(expired.data.is_empty());
    Ok(())
}

#[test]
#[ignore = "requires bundled terminal runtime"]
fn private_owner_sidebar_preserves_shared_shell_and_closes_with_its_attachment() -> Result<()> {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    use std::io::{Read, Write};
    use porthub_terminal::owner_view::OwnerView;
    let (directory, shared) = workspace()?;
    let _cleanup = Cleanup(shared.clone());
    shared.start(&start())?;
    for round in 0..2 {
        let path = directory.path().join(format!("view{round}"));
        create_directory(&path)?;
        let view = OwnerView::new(&shared,path)?;
        let mut panel = std::process::Command::new("/bin/sh");
        panel.args(["-c", "printf 'PRIVATE_OWNER_PANEL\\n'; while read line; do printf 'private-control:%s\\n' \"$line\"; done"]);
        let command = view.command(&shared, &panel, 120, 30)?;
        let pty = native_pty_system().openpty(PtySize { rows:30, cols:120, pixel_width:0, pixel_height:0 })?;
        let mut builder = CommandBuilder::new(command.get_program());
        builder.args(command.get_args());
        for (key,value) in command.get_envs() {
            if let Some(value)=value { builder.env(key,value); } else { builder.env_remove(key); }
        }
        builder.env("TERM","xterm-256color");
        let mut child=pty.slave.spawn_command(builder)?;
        drop(pty.slave);
        let mut reader=pty.master.try_clone_reader()?;
        let observed=std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let sink=observed.clone();
        let drain=std::thread::spawn(move || {let mut bytes=[0;8192];while let Ok(count)=reader.read(&mut bytes) {if count==0 {break;} let mut output=sink.lock().unwrap();output.extend_from_slice(&bytes[..count]);if output.len()>262144 {let excess=output.len()-262144;output.drain(..excess);}}});
        let mut writer=pty.master.take_writer()?;
        let wait = |predicate: &dyn Fn() -> bool| -> Result<()> {
            let deadline=Instant::now()+Duration::from_secs(5);
            while !predicate() {
                anyhow::ensure!(Instant::now()<deadline,"private view fixture timed out: {:?}",view.workspace().command().args(["display-message","-p","#{pane_id}:#{window_width}:#{window_zoomed_flag}:#{pane_width}"]).output());
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(())
        };
        wait(&|| view.workspace().capture("%1",20).is_ok_and(|s|s.contains("PRIVATE_OWNER_PANEL")))?;
        assert!(!shared.capture("%0",100)?.contains("PRIVATE_OWNER_PANEL"),"private controls must not enter the shared transcript");
        let panes=shared.command().args(["list-panes","-F","#{pane_id}"]).output()?;
        assert_eq!(String::from_utf8_lossy(&panes.stdout).lines().count(),1,"sidebar must not add shared panes");
        if round==0 {
            writer.write_all(b"printf 'OWNER%s\\n' 'TYPING'\r")?;writer.flush()?;
            wait(&|| shared.capture("%0",100).is_ok_and(|s|s.contains("OWNERTYPING")))?;
            // The private wrapper must not consume the shared prefix or F7.
            writer.write_all(b"\x01%")?;writer.flush()?;
            wait(&|| shared.command().args(["list-panes","-F","#{pane_id}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).lines().count()==2))?;
            assert!(shared.command().args(["kill-pane","-t","%1"]).output()?.status.success());
            writer.write_all(b"i=0; while [ $i -lt 80 ]; do echo scroll-$i; i=$((i+1)); done\r")?;writer.flush()?;
            wait(&|| shared.capture("%0",100).is_ok_and(|s|s.contains("scroll-79")))?;
            writer.write_all(b"\x1b[18~")?;writer.flush()?;
            wait(&|| shared.command().args(["display-message","-p","-t","%0","#{pane_in_mode}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="1"))?;
            writer.write_all(b"\x1b[18~")?;writer.flush()?;
            wait(&|| shared.command().args(["display-message","-p","-t","%0","#{pane_in_mode}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="0"))?;
            writer.write_all(b"\x1b[<64;5;5M")?;writer.flush()?;
            wait(&|| shared.command().args(["display-message","-p","-t","%0","#{pane_in_mode}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="1"))?;
            writer.write_all(b"\x1b[18~")?;writer.flush()?;
            wait(&|| shared.command().args(["display-message","-p","-t","%0","#{pane_in_mode}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="0"))?;
            assert!(shared.command().args(["set-buffer","-w","porthubclipboard"]).output()?.status.success());
            wait(&|| observed.lock().unwrap().windows(b"cG9ydGh1YmNsaXBib2FyZA==".len()).any(|bytes|bytes==b"cG9ydGh1YmNsaXBib2FyZA=="))?;
            assert!(observed.lock().unwrap().windows(5).any(|bytes|bytes==b"\x1b]52;"),"copy request must retain OSC52 framing");
            writer.write_all(b"\x1b[19~")?;writer.flush()?;
            wait(&|| view.workspace().command().args(["display-message","-p","#{pane_id}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="%1"))?;
            writer.write_all(b"owner-only\r")?;writer.flush()?;
            wait(&|| view.workspace().capture("%1",20).is_ok_and(|s|s.contains("private-control:owner-only")))?;
            assert!(!shared.capture("%0",100)?.contains("owner-only"));
            let second_path=directory.path().join("secondowner");create_directory(&second_path)?;
            let second=OwnerView::new(&shared,second_path)?;
            let second_command=second.command(&shared,&panel,120,30)?;
            let second_pty=native_pty_system().openpty(PtySize {rows:30,cols:120,pixel_width:0,pixel_height:0})?;
            let mut second_builder=CommandBuilder::new(second_command.get_program());second_builder.args(second_command.get_args());
            for (key,value) in second_command.get_envs() {if let Some(value)=value {second_builder.env(key,value);}else{second_builder.env_remove(key);}}
            second_builder.env("TERM","xterm-256color");
            let mut second_child=second_pty.slave.spawn_command(second_builder)?;drop(second_pty.slave);
            let mut second_reader=second_pty.master.try_clone_reader()?;
            let second_drain=std::thread::spawn(move||{let mut bytes=[0;8192];while second_reader.read(&mut bytes).is_ok_and(|n|n>0){}});
            let mut second_writer=second_pty.master.take_writer()?;
            wait(&|| second.workspace().capture("%1",20).is_ok_and(|s|s.contains("PRIVATE_OWNER_PANEL")))?;
            assert!(!second.workspace().capture("%1",20)?.contains("owner-only"));
            second_writer.write_all(b"\x1b[19~")?;second_writer.flush()?;
            wait(&|| second.workspace().command().args(["display-message","-p","#{pane_id}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="%1"))?;
            second_writer.write_all(b"second-only\r")?;second_writer.flush()?;
            wait(&|| second.workspace().capture("%1",20).is_ok_and(|s|s.contains("private-control:second-only")))?;
            assert!(!view.workspace().capture("%1",20)?.contains("second-only"));
            assert!(!shared.capture("%0",100)?.contains("second-only"));
            second_child.kill()?;let _=second_child.wait()?;
            wait(&|| !second.workspace().is_alive())?;
            assert!(view.workspace().is_alive() && shared.is_alive(),"one owner disconnect must not affect another");
            drop(second_writer);drop(second_pty.master);drop(second);second_drain.join().unwrap();
            pty.master.resize(PtySize { rows:18, cols:40, pixel_width:0, pixel_height:0 })?;
            wait(&|| view.workspace().command().args(["display-message","-p","#{window_zoomed_flag}:#{pane_id}:#{pane_width}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="1:%0:40"))?;
            writer.write_all(b"\x1b[19~")?;writer.flush()?;
            writer.write_all(b"printf 'NARROW%s\\n' 'OWNER'\r")?;writer.flush()?;
            wait(&|| shared.capture("%0",100).is_ok_and(|s|s.contains("NARROWOWNER")))?;
            pty.master.resize(PtySize { rows:30, cols:120, pixel_width:0, pixel_height:0 })?;
            wait(&|| view.workspace().command().args(["display-message","-p","#{window_zoomed_flag}"]).output().is_ok_and(|o|String::from_utf8_lossy(&o.stdout).trim()=="0"))?;
            child.kill()?;let _=child.wait()?;
            wait(&|| !view.workspace().is_alive())?;
            assert!(shared.is_alive(),"owner terminal closing must preserve the shared shell");
        } else {
            let result=shared.command().args(["send-keys","-t","%0","exit","Enter"]).output()?;
            assert!(result.status.success());
            wait(&|| !shared.is_alive())?;
            wait(&|| !view.workspace().is_alive())?;
            let _=child.wait()?;
        }
        drop(writer);drop(pty.master);drop(view);
        drain.join().unwrap();
    }
    Ok(())
}
