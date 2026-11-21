use anyhow::{Context, Result};
use porthub_forward_ssh::{serve, Authority, Grant, Master, Registry};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::mpsc,
};
use tokio_util::sync::CancellationToken;
const OWNER: &str = "10ab00000000000000000000";
const ENTRY: &str = "10ab00000000000000000001";
const IMPORT: &str = "host-10ab00000000000000000002";
struct Auth {
    active: AtomicBool,
    key: String,
    grant: Arc<Grant>,
}
#[porthub_forward_ssh::async_trait]
impl Authority for Auth {
    async fn authorize(&self, id: &str, key: &str) -> Result<Option<Arc<Grant>>> {
        Ok(
            (self.active.load(Ordering::SeqCst) && id == ENTRY && key == self.key)
                .then(|| self.grant.clone()),
        )
    }
}
struct Fixture {
    ssh: u16,
    ingress: u16,
    stop: CancellationToken,
    registry: Registry,
    auth: Arc<Auth>,
}
impl Fixture {
    async fn new(root: &Path) -> Result<Self> {
        let master = Arc::new(Master::open(&root.join("master"))?);
        let (pem, key) = master.credentials(OWNER, ENTRY)?;
        let mut tmp = tempfile::NamedTempFile::new_in(root)?;
        std::io::Write::write_all(&mut tmp, pem.as_bytes())?;
        tmp.persist(root.join("identity"))?;
        let local = HashMap::from([((IMPORT.to_owned(), 22001), "saved-local".to_owned())]);
        let (tx, mut rx) = mpsc::channel(4);
        let grant = Grant::new(local, HashSet::from([22002]), tx)?;
        let auth = Arc::new(Auth {
            active: true.into(),
            key,
            grant: grant.clone(),
        });
        let stop = CancellationToken::new();
        let registry = Registry::default();
        let ssh = TcpListener::bind("127.0.0.1:0").await?;
        let port = ssh.local_addr()?.port();
        let forward = TcpListener::bind("127.0.0.1:0").await?;
        let ingress = forward.local_addr()?.port();
        let (halt, a, r, k) = (stop.clone(), auth.clone(), registry.clone(), master.clone());
        tokio::spawn(async move {
            loop {
                tokio::select! {_=halt.cancelled()=>break,v=ssh.accept()=>{let Ok((s,_))=v else{break};let (k,r,a,halt)=(k.clone(),r.clone(),a.clone(),halt.clone());tokio::spawn(async move{let _=serve(s,&k,r,a,halt).await;});}}
            }
        });
        let halt = stop.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {_=halt.cancelled()=>break,v=forward.accept()=>{let Ok((s,_))=v else{break};let g=grant.clone();tokio::spawn(async move{let _=g.forward(22002,s).await;});},v=rx.recv()=>{let Some(job)=v else{break};assert_eq!(job.service,"saved-local");let (s,mut echo)=tokio::io::duplex(4096);if job.stream.send(s).is_ok(){tokio::spawn(async move{let (mut r,mut w)=tokio::io::split(&mut echo);let _=tokio::io::copy(&mut r,&mut w).await;});}}}
            }
        });
        let data = serde_json::json!({"host":"127.0.0.1","port":port,"id":ENTRY,"username":format!("pf-{ENTRY}"),"machine_id":&IMPORT[5..],"import_host":IMPORT,"import_port":22001,"remote_port":22002,"ingress_port":ingress,"identity":root.join("identity"),"host_public_key":master.host_public_key()?,"client_public_key":auth.key,"fingerprint":master.host_fingerprint()});
        let mut f = tempfile::NamedTempFile::new_in(root)?;
        std::io::Write::write_all(&mut f, &serde_json::to_vec(&data)?)?;
        f.persist(root.join("ready.json"))?;
        Ok(Self {
            ssh: port,
            ingress,
            stop,
            registry,
            auth,
        })
    }
    fn revoke(&self) {
        self.auth.active.store(false, Ordering::SeqCst);
        self.registry.revoke(ENTRY);
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel()
    }
}
#[tokio::test]
#[ignore = "explicit loopback-only interactive test fixture"]
async fn saved_entry_loopback_fixture() -> Result<()> {
    let dir = PathBuf::from(std::env::var("PORTHUB_SSH_FIXTURE_DIR")?);
    anyhow::ensure!(
        dir.read_dir()?.next().is_none(),
        "fixture requires empty private directory"
    );
    let f = Fixture::new(&dir).await?;
    tokio::time::timeout(Duration::from_secs(300), async {
        while !dir.join("stop").exists() {
            if dir.join("revoke").exists() {
                f.revoke();
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn openssh_enforces_saved_mappings_and_live_revocation() -> Result<()> {
    use std::process::Stdio;
    use tokio::{
        net::TcpStream,
        process::Command,
        time::{sleep, timeout},
    };
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path();
    let f = Fixture::new(dir).await?;
    let master = Master::open(&dir.join("master"))?;
    let hosts = dir.join("known_hosts");
    std::fs::write(
        &hosts,
        format!("[127.0.0.1]:{} {}\n", f.ssh, master.host_public_key()?),
    )?;
    let command = || {
        let mut c = Command::new("ssh");
        c.current_dir("/")
            .env("HOME", dir)
            .env("SSH_ASKPASS", "/bin/false")
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env_remove("SSH_AUTH_SOCK")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .kill_on_drop(true)
            .args([
                "-F",
                "/dev/null",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ConnectTimeout=3",
                "-o",
            ])
            .arg(format!("UserKnownHostsFile={}", hosts.display()))
            .args(["-p", &f.ssh.to_string(), "-i"])
            .arg(dir.join("identity"));
        c
    };
    let dest = format!("pf-{ENTRY}@127.0.0.1");
    let echo = TcpListener::bind("127.0.0.1:0").await?;
    let echoport = echo.local_addr()?.port();
    let local = TcpListener::bind("127.0.0.1:0").await?;
    let localport = local.local_addr()?.port();
    drop(local);
    let echo_job = tokio::spawn(async move {
        let (mut s, _) = echo.accept().await?;
        let (r, w) = s.split();
        let (mut r, mut w) = (r, w);
        tokio::io::copy(&mut r, &mut w).await?;
        Ok::<(), anyhow::Error>(())
    });
    let mut ssh = command()
        .args([
            "-N",
            "-R",
            &format!("127.0.0.1:22002:127.0.0.1:{echoport}"),
            "-L",
            &format!("127.0.0.1:{localport}:{IMPORT}:22001"),
            &dest,
        ])
        .spawn()?;
    timeout(Duration::from_secs(7), async {
        while !f.auth.grant.is_listening(22002) {
            sleep(Duration::from_millis(15)).await;
        }
    })
    .await?;
    let mut imported = TcpStream::connect(("127.0.0.1", localport)).await?;
    let mut exported = TcpStream::connect(("127.0.0.1", f.ingress)).await?;
    for s in [&mut imported, &mut exported] {
        s.write_all(b"porthub").await?;
        let mut out = [0; 7];
        timeout(Duration::from_secs(3), s.read_exact(&mut out)).await??;
        assert_eq!(out, *b"porthub");
    }
    for args in [
        vec!["-T", &dest, "echo unauthorized"],
        vec!["-W", "127.0.0.1:22", &dest],
        vec!["-N", "-R", "127.0.0.1:22223:127.0.0.1:22", &dest],
        vec!["-N", "-R", "0.0.0.0:22002:127.0.0.1:22", &dest],
    ] {
        assert!(
            !timeout(Duration::from_secs(6), command().args(args).status())
                .await??
                .success()
        );
    }
    f.revoke();
    timeout(Duration::from_secs(5), ssh.wait()).await??;
    for mut chan in [imported, exported] {
        let mut buf = [0; 16];
        assert!(
            !matches!(timeout(Duration::from_secs(2),chan.read(&mut buf)).await,Ok(Ok(n)) if n>0)
        );
    }
    assert!(f.registry.get(ENTRY).is_none());
    assert!(!f.auth.grant.is_listening(22002));
    assert!(!timeout(
        Duration::from_secs(6),
        command()
            .args(["-W", &format!("{IMPORT}:22001"), &dest])
            .status()
    )
    .await??
    .success());
    echo_job.abort();
    Ok(())
}

#[test]
fn private_master_creation_is_atomic_and_domain_separated() -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir()?;
    let path = tmp.path().join("keys/master");
    let results = std::thread::scope(|g| {
        let mut jobs = Vec::new();
        for _ in 0..8 {
            jobs.push(g.spawn(|| Master::open(&path).map(|k| k.host_fingerprint())));
        }
        jobs.into_iter()
            .map(|j| j.join().unwrap())
            .collect::<Result<Vec<_>>>()
    })?;
    assert!(results.windows(2).all(|w| w[0] == w[1]));
    let k = Master::open(&path)?;
    let (_, pub1) = k.credentials(OWNER, ENTRY)?;
    assert_ne!(pub1, k.host_public_key()?);
    assert_ne!(pub1, k.credentials(ENTRY, OWNER)?.1);
    assert_eq!(pub1, Master::open(&path)?.credentials(OWNER, ENTRY)?.1);
    #[cfg(unix)]
    {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        assert!(Master::open(&path).is_err());
    }
    Ok(())
}
