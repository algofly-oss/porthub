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
    let first: serde_json::Value = serde_json::from_slice(
        &call(&[
            "terminal", "new", "--detach", "--json", "--shell", "/bin/sh",
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
    assert!(name.bytes().all(|byte| byte.is_ascii_lowercase()));
    assert_eq!(first["shared"], false);
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
    assert_ne!(second["id"], first["id"]);
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
    let rows: Vec<serde_json::Value> =
        serde_json::from_slice(&call(&["terminal", "list", "--json"])?.stdout)?;
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
