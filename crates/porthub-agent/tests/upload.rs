use std::{
    net::{Ipv4Addr, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn cli(state: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_porthub"));
    cmd.env("PORTHUB_STATE_DIR", state)
        .env("XDG_RUNTIME_DIR", state)
        .stdin(Stdio::null());
    cmd
}

async fn ready(url: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if reqwest::get(url).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("receiver did not start");
}

#[tokio::test]
async fn receiver_accepts_standard_http_uploads_and_porthub_parallel_push() {
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let child = cli(state.path())
        .args(["http.receive", &port.to_string()])
        .arg(root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut server = Server(child);
    let base = format!("http://127.0.0.1:{port}/");
    ready(&base).await;
    #[cfg(unix)]
    {
        assert_eq!(unsafe { libc::kill(server.0.id() as i32, libc::SIGHUP) }, 0);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            reqwest::get(&base).await.is_ok(),
            "receiver stopped on terminal hangup"
        );
    }

    let curl_style = vec![0x5au8; 256 * 1024];
    let response = reqwest::Client::new()
        .put(format!("{base}.porthub/raw/curl.bin"))
        .body(curl_style.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(
        std::fs::read(root.path().join("curl.bin")).unwrap(),
        curl_style
    );
    let wget_style = b"raw POST upload";
    let response = reqwest::Client::new()
        .post(format!("{base}.porthub/raw/post.txt"))
        .body(wget_style.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(
        std::fs::read(root.path().join("post.txt")).unwrap(),
        wget_style
    );

    let source = state.path().join("large.bin");
    let data: Vec<u8> = (0..(18 * 1024 * 1024)).map(|n| (n % 251) as u8).collect();
    std::fs::write(&source, &data).unwrap();
    let output = cli(state.path())
        .args(["push"])
        .arg(&source)
        .arg(&base)
        .arg("--connections")
        .arg("4")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read(root.path().join("large.bin")).unwrap(), data);

    let tree = state.path().join("tree");
    std::fs::create_dir_all(tree.join("nested")).unwrap();
    std::fs::write(tree.join("one.txt"), b"first file").unwrap();
    std::fs::write(tree.join("nested/two.txt"), b"second file").unwrap();
    let output = cli(state.path())
        .args(["push"])
        .arg(&tree)
        .arg(&base)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(root.path().join("tree/one.txt")).unwrap(),
        b"first file"
    );
    assert_eq!(
        std::fs::read(root.path().join("tree/nested/two.txt")).unwrap(),
        b"second file"
    );
    let metadata = reqwest::Client::new()
        .head(format!("{base}tree/one.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(metadata.status(), reqwest::StatusCode::OK);
    assert!(metadata.headers().contains_key("x-porthub-modified-unix"));
    let output = cli(state.path())
        .args(["push"])
        .arg(&tree)
        .arg(&base)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("sent 0, skipped 2"),
        "stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let output = cli(state.path())
        .args(["push", "--force"])
        .arg(&tree)
        .arg(&base)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("sent 2, skipped 0"));

    let stopped = cli(state.path())
        .args(["http.receive", "stop", &port.to_string()])
        .output()
        .unwrap();
    assert!(
        stopped.status.success(),
        "{}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    let _ = server.0.wait();
}
