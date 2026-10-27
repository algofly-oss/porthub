use std::{
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command(state: &Path) -> Command {
    let mut command = Command::new(
        std::env::var_os("PORTHUB_TEST_AGENT_EXECUTABLE")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_porthub").into()),
    );
    command
        .env("PORTHUB_STATE_DIR", state)
        .env("XDG_RUNTIME_DIR", state)
        .stdin(Stdio::null());
    command
}
fn start(state: &Path, root: &Path) -> Running {
    Running(
        command(state)
            .args(["http.server", "0"])
            .arg(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
fn wait_until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "server did not reach expected state"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn records(state: &Path) -> Vec<(PathBuf, serde_json::Value)> {
    let Ok(entries) = std::fs::read_dir(state.join("http-servers")) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            // Atomic publication can briefly leave a complete temporary file
            // beside its final record; only published registrations count.
            if entry.path().extension().is_none_or(|value| value != "json") {
                return None;
            }
            let bytes = std::fs::read(entry.path()).ok()?;
            Some((entry.path(), serde_json::from_slice(&bytes).ok()?))
        })
        .collect()
}

#[test]
fn multiple_servers_can_be_managed_from_independent_cli_processes() {
    let state = tempfile::tempdir().unwrap();
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let mut first = start(state.path(), first_root.path());
    let mut second = start(state.path(), second_root.path());
    // Servers publish canonical roots, including macOS /private/var aliases
    // and Windows extended-length paths. Keep the input aliases above.
    let first_path = first_root.path().canonicalize().unwrap();
    let second_path = second_root.path().canonicalize().unwrap();
    wait_until(|| records(state.path()).len() == 2);
    let items = records(state.path());
    let first_record = items
        .iter()
        .find(|(_, value)| value["root"] == first_path.to_string_lossy().as_ref())
        .unwrap()
        .clone();
    let port = first_record.1["port"].as_u64().unwrap() as u16;
    let list = command(state.path())
        .args(["http.server", "list"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let output = String::from_utf8(list.stdout).unwrap();
    assert!(output.contains(first_path.to_str().unwrap()));
    assert!(output.contains(second_path.to_str().unwrap()));
    let stopped = command(state.path())
        .args(["http.server", "stop", &port.to_string()])
        .output()
        .unwrap();
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    wait_until(|| first.0.try_wait().unwrap().is_some());
    assert!(
        second.0.try_wait().unwrap().is_none(),
        "stopping one port stopped another server"
    );
    // Reused ports and stale records must not let stop signal unrelated owners.
    let unrelated = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).unwrap();
    std::fs::write(
        &first_record.0,
        serde_json::to_vec(&first_record.1).unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&first_record.0, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let stale = command(state.path())
        .args(["http.server", "stop", &port.to_string()])
        .output()
        .unwrap();
    assert!(!stale.status.success());
    assert_eq!(unrelated.local_addr().unwrap().port(), port);
    let all = command(state.path())
        .args(["http.server", "stop", "--all"])
        .output()
        .unwrap();
    assert!(all.status.success());
    wait_until(|| second.0.try_wait().unwrap().is_some());
    assert_eq!(unrelated.local_addr().unwrap().port(), port);
}

#[cfg(unix)]
#[test]
fn upgraded_cli_can_manage_the_previous_go_control_socket_protocol() {
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixListener,
        },
    };
    let state = tempfile::tempdir().unwrap();
    let uid = std::fs::metadata(state.path()).unwrap().uid();
    let directory = state.path().join(format!("porthub-{uid}"));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.join("http-45555.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let root = state.path().join("old-server");
    let expected = root.clone();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            match request.trim() {
                "info" => {
                    let value = serde_json::json!({"pid":std::process::id(),"port":45555,"bind":"0.0.0.0","root":root,"started":"2026-10-23T00:00:00Z"});
                    writeln!(stream, "{value}").unwrap();
                }
                "stop" => {
                    writeln!(stream, "stopping").unwrap();
                    break;
                }
                _ => panic!("unexpected legacy control command"),
            }
        }
    });
    let list = command(state.path())
        .args(["http.server", "list"])
        .output()
        .unwrap();
    assert!(list.status.success());
    assert!(String::from_utf8(list.stdout)
        .unwrap()
        .contains(expected.to_str().unwrap()));
    let stop = command(state.path())
        .args(["http.server", "stop", "45555"])
        .output()
        .unwrap();
    assert!(
        stop.status.success(),
        "{}",
        String::from_utf8_lossy(&stop.stderr)
    );
    handle.join().unwrap();
}

#[tokio::test]
async fn detached_server_and_receiver_survive_the_launcher_and_stop_independently() {
    let state = tempfile::tempdir().unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("served.txt"), b"served by detached process").unwrap();
    let client = reqwest::Client::new();
    let mut ports = Vec::new();
    for tool in ["http.server", "http.receive"] {
        let output = command(state.path()).args([tool, "0"]).arg(root.path()).arg("-d").output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let items = records(state.path());
        let record = items.iter().find(|(_, value)| !ports.contains(&(value["port"].as_u64().unwrap() as u16))).unwrap();
        let port = record.1["port"].as_u64().unwrap() as u16;
        ports.push(port);
        let response = client.get(format!("http://127.0.0.1:{port}/served.txt")).send().await.unwrap();
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"served by detached process");
        if tool == "http.receive" {
            let response = client.put(format!("http://127.0.0.1:{port}/.porthub/raw/nested/uploaded.txt"))
                .body("uploaded through detached receiver").send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::CREATED);
            assert_eq!(std::fs::read(root.path().join("nested/uploaded.txt")).unwrap(), b"uploaded through detached receiver");
        }
    }
    for (index, port) in ports.iter().enumerate() {
        let output = command(state.path()).args(["http.server", "stop", &port.to_string()]).output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        if index == 0 {
            assert!(client.get(format!("http://127.0.0.1:{}/served.txt", ports[1])).send().await.unwrap().status().is_success());
        }
    }
    wait_until(|| records(state.path()).is_empty());
}
