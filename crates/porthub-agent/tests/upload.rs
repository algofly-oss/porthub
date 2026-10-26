use std::{
    net::{Ipv4Addr, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        eprintln!("transfer test: stopping server process {}", self.0.id());
        let _ = self.0.kill();
        let _ = self.0.wait();
        eprintln!("transfer test: server process stopped");
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

struct SyncJob {
    state: std::path::PathBuf,
    id: String,
}
impl Drop for SyncJob {
    fn drop(&mut self) {
        eprintln!("watch lifecycle: cleaning up sync job {}", self.id);
        let _ = cli(&self.state)
            .args(["sync", "stop", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
async fn uploaded(path: &Path, expected: &[u8]) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if std::fs::read(path).is_ok_and(|bytes| bytes == expected) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("watch upload did not arrive");
}

#[tokio::test]
async fn detached_watch_is_managed_after_launcher_exits_and_foreground_stops_cleanly() {
    let state = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let source = state.path().join("data");
    std::fs::create_dir_all(source.join("empty/deep")).unwrap();
    std::fs::write(source.join("one"), b"initial").unwrap();
    let socket = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let receiver = cli(state.path())
        .args(["http.receive", &port.to_string()])
        .arg(root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let _receiver = Server(receiver);
    let base = format!("http://127.0.0.1:{port}/");
    ready(&base).await;
    eprintln!("watch lifecycle: receiver ready");
    eprintln!("watch lifecycle: starting detached launcher");
    let output = cli(state.path())
        .arg("push")
        .arg(&source)
        .arg(format!("{base}backups/luna/projects/"))
        .args(["-w", "-d"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("watch lifecycle: detached launcher returned");
    let text = String::from_utf8(output.stdout).unwrap();
    let id = text
        .lines()
        .next()
        .unwrap()
        .strip_prefix("Sync started in background: ")
        .unwrap()
        .to_owned();
    let job = SyncJob {
        state: state.path().to_owned(),
        id,
    };
    let target = root.path().join("backups/luna/projects/data");
    uploaded(&target.join("one"), b"initial").await;
    eprintln!("watch lifecycle: initial sync finished");
    assert!(target.join("empty/deep").is_dir());
    std::fs::write(source.join("one"), b"changed").unwrap();
    uploaded(&target.join("one"), b"changed").await;
    eprintln!("watch lifecycle: edit synced");
    eprintln!("watch lifecycle: querying status");
    let status = cli(state.path())
        .args(["sync", "status", &job.id])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("backups/luna/projects/"));
    eprintln!("watch lifecycle: querying list");
    let list = cli(state.path()).args(["sync", "list"]).output().unwrap();
    assert!(String::from_utf8_lossy(&list.stdout).contains(&job.id));
    eprintln!("watch lifecycle: stopping detached job");
    let stopped = cli(state.path())
        .args(["sync", "stop", &job.id])
        .output()
        .unwrap();
    assert!(stopped.status.success());
    let record = state
        .path()
        .join("sync-jobs")
        .join(format!("{}.json", job.id));
    tokio::time::timeout(Duration::from_secs(3), async {
        while record.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    std::fs::write(source.join("one"), b"stopped").unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(std::fs::read(target.join("one")).unwrap(), b"changed");
    eprintln!("watch lifecycle: starting foreground job");
    let child = cli(state.path())
        .arg("push")
        .arg(&source)
        .arg(format!("{base}foreground/"))
        .arg("-w")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut foreground = Server(child);
    uploaded(&root.path().join("foreground/data/one"), b"stopped").await;
    eprintln!("watch lifecycle: foreground synced");
    assert!(
        foreground.0.try_wait().unwrap().is_none(),
        "foreground returned early"
    );
    #[cfg(unix)]
    {
        assert_eq!(
            unsafe { libc::kill(foreground.0.id() as i32, libc::SIGINT) },
            0
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(exit) = foreground.0.try_wait().unwrap() {
                    assert!(exit.success());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
}
