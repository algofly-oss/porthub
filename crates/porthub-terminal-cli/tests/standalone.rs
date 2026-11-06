use std::process::Command;
fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_porthub-terminal"))
}
#[test]
fn independent_cli_exposes_local_tmux_without_core_or_gateway() {
    let help = command().arg("--help").output().unwrap();
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("tmux") && text.contains("runtime") && text.contains("new"));
    #[cfg(unix)]
    assert!(text.contains("attach"));
    assert!(command()
        .arg("--version")
        .output()
        .unwrap()
        .status
        .success());
    assert!(!command()
        .args(["runtime", "--directory", "relative"])
        .output()
        .unwrap()
        .status
        .success());
}
#[cfg(unix)]
#[test]
fn bundled_runtime_creates_lists_and_kills_an_isolated_workspace() {
    if option_env!("PORTHUB_TERMINAL_BUNDLE").is_none() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let runtime = root.path().join("runtime");
    let socket = root.path().join("tmux.sock");
    struct Stop<'a>(&'a std::path::Path, &'a std::path::Path);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            let _ = command()
                .arg("tmux")
                .arg("--directory")
                .arg(self.0)
                .arg("--")
                .arg("-S")
                .arg(self.1)
                .arg("kill-server")
                .output();
        }
    }
    let _stop = Stop(&runtime, &socket);
    let version = command()
        .arg("tmux")
        .arg("--directory")
        .arg(&runtime)
        .args(["--", "-V"])
        .output()
        .unwrap();
    assert!(
        version.status.success(),
        "{}",
        String::from_utf8_lossy(&version.stderr)
    );
    assert!(String::from_utf8_lossy(&version.stdout).contains("tmux "));
    let created = command()
        .env("SHELL", "/bin/sh")
        .arg("tmux")
        .arg("--directory")
        .arg(&runtime)
        .arg("--")
        .arg("-S")
        .arg(&socket)
        .args([
            "-f",
            "/dev/null",
            "new-session",
            "-d",
            "-s",
            "fixture",
            "sleep 60",
        ])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let listed = command()
        .arg("tmux")
        .arg("--directory")
        .arg(&runtime)
        .arg("--")
        .arg("-S")
        .arg(&socket)
        .arg("list-sessions")
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert!(String::from_utf8_lossy(&listed.stdout).contains("fixture"));
}

#[cfg(unix)]
#[test]
fn independent_workspace_creation_preserves_caller_environment_and_reuses_registry_directory() {
    if option_env!("PORTHUB_TERMINAL_BUNDLE").is_none() {
        return;
    }
    use porthub_components::protocol::terminal::Job;
    use porthub_terminal::multiplexer::Workspace;
    let root = tempfile::tempdir().unwrap();
    let registry = root.path().join("workspaces");
    struct Stop(Job);
    impl Drop for Stop {
        fn drop(&mut self) {
            if let Ok(workspace) = Workspace::open(
                self.0.executable.clone(),
                self.0.terminfo.clone(),
                self.0.workspace.clone(),
            ) {
                let _ = workspace.stop();
            }
        }
    }
    let mut running = vec![];
    for index in 0..2 {
        let output = root.path().join(format!("caller-{index}.txt"));
        let value = format!("independent-{index}");
        let result = command()
            .current_dir(root.path())
            .env("PORTHUB_WORKSPACE_FIXTURE", &value)
            .args(["new", "--directory"])
            .arg(&registry)
            .arg("--name")
            .arg(format!("work-{index}"))
            .args([
                "--",
                "/bin/sh",
                "-c",
                "printf '%s' \"$PORTHUB_WORKSPACE_FIXTURE\" > \"$1\"; sleep 30",
                "fixture",
            ])
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let job: Job = serde_json::from_slice(&result.stdout).unwrap();
        assert!(registry.join(format!("{}.json", job.id)).is_file());
        running.push(Stop(job));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !output.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(std::fs::read_to_string(output).unwrap(), value);
    }
}

#[cfg(unix)]
#[test]
fn managed_join_rejects_invalid_or_public_requests_without_echoing_invitation() {
    use std::{io::Write, os::unix::fs::PermissionsExt};
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let request = root.path().join("join.json");
    let marker = "sensitive-invitation-must-not-be-printed";
    let mut file = tempfile::NamedTempFile::new_in(root.path()).unwrap();
    file.write_all(serde_json::to_string(&serde_json::json!({"invitation":format!("https://example.invalid/#{marker}"),"transport":"ssh","broker":null,"stun_servers":[]})).unwrap().as_bytes()).unwrap();
    file.persist(&request).unwrap();
    let result = command()
        .args(["__porthub-join", "--request"])
        .arg(&request)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(marker));
    assert!(!String::from_utf8_lossy(&result.stdout).contains(marker));
    std::fs::set_permissions(&request, std::fs::Permissions::from_mode(0o644)).unwrap();
    let result = command()
        .args(["__porthub-join", "--request"])
        .arg(&request)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains(marker));
}
