//! Explicit network opt-in. Run this test alone with one test thread and two
//! independently compiled Tor helper versions supplied through environment paths.
use super::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use porthub_components::catalog::{Artifact, Blob, Catalog, CATALOG_ASSET, REPOSITORY};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, io::Write, os::unix::fs::PermissionsExt, path::PathBuf};

struct Environment(Vec<(OsString, Option<OsString>)>);
impl Environment {
    fn set(&mut self, key: &str, value: impl AsRef<std::ffi::OsStr>) {
        self.0.push((key.into(), std::env::var_os(key)));
        std::env::set_var(key, value);
    }
}
impl Drop for Environment {
    fn drop(&mut self) {
        for (key, value) in self.0.drain(..).rev() {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
fn seed(root: &Path, key: &str, target: &str) -> Result<Artifact> {
    let executable =
        PathBuf::from(std::env::var_os(key).context("provide both Tor helper executable paths")?);
    let output = std::process::Command::new(&executable)
        .arg("--version")
        .output()?;
    ensure!(output.status.success(), "cannot inspect Tor helper version");
    let version = std::str::from_utf8(&output.stdout)?
        .split_whitespace()
        .last()
        .context("missing helper version")?
        .parse()?;
    let bytes = std::fs::read(&executable)?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let destination = root.join(format!("tor-{version}-{digest}"));
    std::fs::write(&destination, &bytes)?;
    std::fs::set_permissions(destination, std::fs::Permissions::from_mode(0o755))?;
    Ok(Artifact {
        component: Component::Tor,
        version,
        target: target.into(),
        core: ">=1.11.0, <2.0.0".parse()?,
        protocols: vec![1],
        source_revision: "a".repeat(40),
        build_inputs: "b".repeat(64),
        executable: Blob {
            size: bytes.len() as u64,
            sha256: digest,
        },
        release: "1.11.0".parse()?,
        archive: Blob {
            size: 1,
            sha256: "c".repeat(64),
        },
    })
}
fn catalog(root: &Path, artifacts: Vec<Artifact>, version: &str) -> Result<()> {
    let catalog = Catalog {
        schema_version: 1,
        repository: REPOSITORY.into(),
        release: version.parse()?,
        artifacts,
    };
    catalog.validate()?;
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    temporary.write_all(&serde_json::to_vec(&catalog)?)?;
    temporary
        .persist(root.join(CATALOG_ASSET))
        .map_err(|error| error.error)?;
    Ok(())
}
async fn https(
    pool: &TorPool,
    host: &str,
) -> Result<(
    hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    tokio::task::JoinHandle<Result<(), hyper::Error>>,
)> {
    let stream = pool.connect(Destination::new(host.into(), 443)?).await?;
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls));
    let stream = tokio::time::timeout(
        Duration::from_secs(60),
        connector.connect(host.to_owned().try_into()?, stream),
    )
    .await??;
    let (sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(32768)
        .handshake(hyper_util::rt::TokioIo::new(stream))
        .await?;
    Ok((sender, tokio::spawn(connection)))
}
async fn verify(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    host: &str,
    path: &str,
    tor: bool,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(60), sender.ready()).await??;
    let request = hyper::Request::builder()
        .uri(path)
        .header("host", host)
        .body(Empty::new())?;
    let response =
        tokio::time::timeout(Duration::from_secs(60), sender.send_request(request)).await??;
    ensure!(
        response.status().is_success(),
        "Tor verification endpoint returned a failure"
    );
    let bytes = tokio::time::timeout(
        Duration::from_secs(30),
        Limited::new(response.into_body(), 16384).collect(),
    )
    .await?
    .map_err(|error| anyhow::anyhow!(error.to_string()))?
    .to_bytes();
    if tor {
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value["IsTor"] == true,
            "verification endpoint did not identify a Tor exit"
        );
    } else {
        ensure!(
            !bytes.is_empty(),
            "keepalive verification returned an empty body"
        );
    }
    Ok(())
}
#[tokio::test]
#[ignore = "explicit network opt-in: real managed Tor upgrade and verified HTTPS; run alone with --test-threads=1"]
async fn managed_upgrade_preserves_old_https_connection_and_revokes_new_flows() -> Result<()> {
    let root = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()?;
    let cache = root.path().join("components");
    std::fs::create_dir(&cache)?;
    std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700))?;
    let mut environment = Environment(vec![]);
    environment.set("PORTHUB_COMPONENT_CACHE", &cache);
    environment.set("PORTHUB_COMPONENT_SHARED_CACHE", "off");
    environment.set("PORTHUB_COMPONENT_SOURCE", "github");
    environment.set("PORTHUB_STATE_DIR", root.path().join("state"));
    let manager = crate::components::manager(None)?;
    let target = manager
        .cached_catalog()?
        .map(|catalog| catalog.artifacts[0].target.clone());
    ensure!(target.is_none(), "fixture cache must start empty");
    ensure!(
        std::env::consts::OS == "linux",
        "use a native Linux test platform"
    );
    let target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => anyhow::bail!("use a native Linux test platform"),
    };
    let old = seed(&cache, "PORTHUB_TEST_OLD_TOR_EXECUTABLE", target)?;
    let new = seed(&cache, "PORTHUB_TEST_NEW_TOR_EXECUTABLE", target)?;
    ensure!(
        new.version > old.version,
        "candidate helper must have a newer version"
    );
    catalog(&cache, vec![old.clone()], "1.11.0")?;
    let route = std::net::UdpSocket::bind("0.0.0.0:0")?;
    // A UDP connect chooses the OS-routed source without sending a packet.
    route.connect("1.1.1.1:53")?;
    let (sources, receiver) = watch::channel(vec![route.local_addr()?.ip()]);
    let pool = TorPool::new(&root.path().join("tor"), 4, 16)?.with_underlay(receiver);
    tokio::time::timeout(Duration::from_secs(300), pool.bootstrap()).await??;
    let (mut exit, exit_driver) = https(&pool, "check.torproject.org").await?;
    let exit_driver = tokio_util::task::AbortOnDropHandle::new(exit_driver);
    verify(&mut exit, "check.torproject.org", "/api/ip", true).await?;
    drop(exit);
    drop(exit_driver);
    let (mut original, original_driver) = https(&pool, "porthub.algofly.in").await?;
    let original_driver = tokio_util::task::AbortOnDropHandle::new(original_driver);
    verify(&mut original, "porthub.algofly.in", "/healthz", false).await?;
    catalog(&cache, vec![old.clone(), new.clone()], "1.11.1")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(360);
    loop {
        ensure!(
            !original_driver.is_finished(),
            "old HTTPS connection ended before handover"
        );
        if pool
            .session
            .get()
            .is_some_and(|sessions| sessions.current().artifact().version == new.version)
        {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "managed helper candidate did not activate"
        );
        // Reuse the very same HTTP connection; there is no reconnect adapter.
        verify(&mut original, "porthub.algofly.in", "/healthz", false).await?;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    verify(&mut original, "porthub.algofly.in", "/healthz", false).await?;
    ensure!(
        pool.session.get().unwrap().live().len() >= 2,
        "old stream lost its generation lease"
    );
    let (mut replacement, replacement_driver) = https(&pool, "check.torproject.org").await?;
    let replacement_driver = tokio_util::task::AbortOnDropHandle::new(replacement_driver);
    verify(&mut replacement, "check.torproject.org", "/api/ip", true).await?;
    let original_sources = sources.send_replace(vec![]);
    ensure!(!pool.ready(), "revoked source still reports ready");
    ensure!(
        tokio::time::timeout(
            Duration::from_secs(1),
            pool.connect(Destination::new("example.invalid".into(), 443)?)
        )
        .await?
        .is_err(),
        "revoked pool opened a new flow"
    );
    ensure!(
        pool.resolve("example.invalid").await.is_err(),
        "revoked pool resolved a destination"
    );
    sources.send_replace(original_sources);
    tokio::time::timeout(Duration::from_secs(240), pool.bootstrap()).await??;
    let (mut recovered, recovered_driver) = https(&pool, "check.torproject.org").await?;
    let recovered_driver = tokio_util::task::AbortOnDropHandle::new(recovered_driver);
    verify(&mut recovered, "check.torproject.org", "/api/ip", true).await?;
    drop(recovered);
    drop(recovered_driver);
    drop(original);
    drop(original_driver);
    drop(replacement);
    drop(replacement_driver);
    drop(pool);
    tokio::time::sleep(Duration::from_secs(2)).await;
    eprintln!("PASS managed Tor upgrade: old HTTPS connection preserved, new generation verified, revoked connections and DNS denied");
    Ok(())
}
