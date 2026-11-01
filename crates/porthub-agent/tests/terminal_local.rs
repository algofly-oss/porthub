#![cfg(unix)]
use anyhow::{ensure, Result};
use std::{
    path::PathBuf,
    process::{Command, Output},
};

#[test]
#[ignore = "requires an agent binary with bundled terminal runtime"]
fn local_cli_needs_no_registration_and_preserves_independent_background_workspaces() -> Result<()> {
    let executable = std::env::var_os("PORTHUB_TEST_AGENT_EXECUTABLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_porthub")));
    let directory = tempfile::tempdir()?;
    let call = |args: &[&str]| -> Result<Output> {
        let output = Command::new(&executable)
            .args(args)
            .env("XDG_DATA_HOME", directory.path())
            .env("SHELL", "/bin/sh")
            .env_remove("TMUX")
            .env_remove("TMUX_PANE")
            .output()?;
        ensure!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    };
    let guide = String::from_utf8(call(&["terminal"])?.stdout)?;
    assert!(guide.contains("porthub terminal share NAME --detach"));
    assert!(guide.contains("porthub terminal url NAME"));
    assert!(guide.contains("porthub terminal share --help"));
    assert!(!directory.path().join("porthub/terminal").exists(), "opening the guide must not create a workspace");
    for command in ["new", "share", "join", "invite", "url", "ls", "attach"] {
        assert!(String::from_utf8(call(&["terminal", command, "--help"])?.stdout)?.contains("Usage:"));
    }
    let first: serde_json::Value = serde_json::from_slice(
        &call(&[
            "terminal", "new", "--detach", "--json",
        ])?
        .stdout,
    )?;
    let name = first["name"].as_str().unwrap();
    let first_id = first["id"].as_str().unwrap();
    struct Cleanup {
        executable: PathBuf,
        data: PathBuf,
        names: Vec<String>,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for name in &self.names {
                let _ = Command::new(&self.executable)
                    .args(["terminal", "stop", name])
                    .env("XDG_DATA_HOME", &self.data)
                    .output();
            }
        }
    }
    let mut cleanup = Cleanup {
        executable: executable.clone(),
        data: directory.path().into(),
        names: vec![name.into()],
    };
    if std::path::Path::new("/bin/bash").is_file() {
        assert_eq!(
            String::from_utf8(call(&["terminal", "tmux", name, "--", "show-options", "-gv", "default-shell"])?.stdout)?.trim(),
            "/bin/bash",
            "new workspaces must prefer Bash even when the launching environment uses sh"
        );
    }
    assert!(name.bytes().all(|byte| byte.is_ascii_lowercase()));
    assert_eq!(first["shared"], false);
    let socket = String::from_utf8(
        call(&[
            "terminal",
            "tmux",
            name,
            "--",
            "display-message",
            "-p",
            "#{socket_path}",
        ])?
        .stdout,
    )?;
    let attached = Command::new(&executable)
        .args(["terminal", "attach", name])
        .env("XDG_DATA_HOME", directory.path())
        .env_remove("TMUX")
        .env_remove("TMUX_PANE")
        .env("PORTHUB_TERMINAL_SOCKET", socket.trim())
        .output()?;
    ensure!(
        attached.status.success(),
        "{}",
        String::from_utf8_lossy(&attached.stderr)
    );
    assert!(
        String::from_utf8(attached.stdout)?.contains(&format!("Already attached to {name}")),
        "own workspace must not recursively attach when ordinary TMUX variables are absent"
    );
    let second: serde_json::Value = serde_json::from_slice(
        &call(&[
            "terminal",
            "secondworkspace",
            "--detach",
            "--json",
            "--shell",
            "/bin/sh",
        ])?
        .stdout,
    )?;
    cleanup.names.push("secondworkspace".into());
    assert_eq!(
        String::from_utf8(call(&["terminal", "tmux", "secondworkspace", "--", "show-options", "-gv", "default-shell"])?.stdout)?.trim(),
        "/bin/sh",
        "an explicit --shell must override the Bash default"
    );
    assert_ne!(second["id"], first["id"]);
    let other_socket = format!(
        "/tmp/porthub-terminal-{}/{}/tmux.sock",
        unsafe { libc::geteuid() },
        second["id"].as_str().unwrap()
    );
    let escaped = Command::new(&executable)
        .args([
            "terminal",
            "tmux",
            name,
            "--",
            "-S",
            &other_socket,
            "kill-server",
        ])
        .env("XDG_DATA_HOME", directory.path())
        .output()?;
    assert!(
        !escaped.status.success(),
        "advanced commands cannot override the selected workspace socket"
    );
    call(&["terminal", "tmux", "secondworkspace", "--", "has-session"])?;

    let reopened: serde_json::Value = serde_json::from_slice(
        &call(&["terminal", "secondworkspace", "--detach", "--json"])?.stdout,
    )?;
    assert_eq!(
        reopened["id"], second["id"],
        "opening a running name must reuse its workspace"
    );
    let duplicate = Command::new(&executable)
        .args(["terminal", "new", "--detach", "--name", name])
        .env("XDG_DATA_HOME", directory.path())
        .output()?;
    assert!(!duplicate.status.success());
    call(&[
        "terminal",
        "tmux",
        name,
        "--",
        "send-keys",
        "-t",
        "%0",
        "printf 'LOCAL%s\\n' 'RUNNING'",
        "Enter",
    ])?;
    let mut captured = String::new();
    for _ in 0..100 {
        captured = String::from_utf8(
            call(&[
                "terminal",
                "tmux",
                name,
                "--",
                "capture-pane",
                "-p",
                "-t",
                "%0",
            ])?
            .stdout,
        )?;
        if captured.contains("LOCALRUNNING") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(captured.contains("LOCALRUNNING"));
    call(&["terminal", "rename", name, "renamedworkspace"])?;
    cleanup.names[0] = "renamedworkspace".into();
    // Simulate invocation from inside this same private tmux server. Attach
    // recognizes the workspace and returns, rather than recursively attaching.
    let socket = format!(
        "/tmp/porthub-terminal-{}/{first_id}/tmux.sock,1,0",
        unsafe { libc::geteuid() }
    );
    let attached = Command::new(&executable)
        .args(["terminal", "renamedworkspace"])
        .env("XDG_DATA_HOME", directory.path())
        .env("TMUX", socket)
        .output()?;
    assert!(attached.status.success());
    assert!(String::from_utf8(attached.stdout)?.contains("Already attached"));
    call(&["terminal", "stop", "renamedworkspace"])?;
    let active: Vec<serde_json::Value> =
        serde_json::from_slice(&call(&["terminal", "ls", "--json"])?.stdout)?;
    assert!(!active.iter().any(|row| row["name"] == "renamedworkspace"));
    assert!(active.iter().any(|row| row["name"] == "secondworkspace"));
    let rows: Vec<serde_json::Value> =
        serde_json::from_slice(&call(&["terminal", "list", "--all", "--json"])?.stdout)?;
    assert_eq!(
        rows.iter()
            .find(|row| row["name"] == "renamedworkspace")
            .unwrap()["state"],
        "ended"
    );
    assert_eq!(
        rows.iter()
            .find(|row| row["name"] == "secondworkspace")
            .unwrap()["state"],
        "running"
    );
    let recreated: serde_json::Value = serde_json::from_slice(
        &call(&[
            "terminal",
            "renamedworkspace",
            "--detach",
            "--json",
            "--shell",
            "/bin/sh",
        ])?
        .stdout,
    )?;
    assert_ne!(
        recreated["id"], first["id"],
        "opening an ended name must create a fresh identity"
    );
    Ok(())
}
