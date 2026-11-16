use anyhow::Result;
use async_trait::async_trait;
use porthub_components::{
    catalog::{Blob, Catalog, REPOSITORY},
    media_store::{self, Artifact, Manifest},
    store::{Settings, Sources},
    transport::Transport,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;
use url::Url;
fn blob(bytes: &[u8]) -> Blob {
    Blob {
        size: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}
fn fixture() -> (Manifest, Vec<u8>) {
    let binary = b"verified media helper";
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o755);
    header.set_size(binary.len() as u64);
    header.set_cksum();
    tar.append_data(
        &mut header,
        "media-helper/0.1.0/porthub-media-helper",
        binary.as_slice(),
    )
    .unwrap();
    let archive = tar.into_inner().unwrap().finish().unwrap();
    (
        Manifest {
            schema_version: 1,
            namespace: media_store::NAMESPACE.into(),
            repository: REPOSITORY.into(),
            release: "1.11.29".parse().unwrap(),
            artifacts: vec![Artifact {
                version: "0.1.0".parse().unwrap(),
                target: "x86_64-unknown-linux-gnu".into(),
                core: ">=1.11.29, <2".parse().unwrap(),
                protocol: 1,
                source_revision: "a".repeat(40),
                build_inputs: "b".repeat(64),
                executable: blob(binary),
                archive: blob(&archive),
            }],
        },
        archive,
    )
}
#[derive(Default)]
struct Fetch(Mutex<BTreeMap<String, Vec<u8>>>);
#[async_trait]
impl Transport for Fetch {
    async fn fetch(&self, url: &Url, path: &Path, limit: u64) -> Result<()> {
        let map = self.0.lock().unwrap();
        let bytes = map
            .get(url.path())
            .ok_or_else(|| anyhow::anyhow!("Missing fixture"))?;
        anyhow::ensure!(bytes.len() as u64 <= limit);
        std::fs::write(path, bytes)?;
        Ok(())
    }
}
fn settings() -> Settings {
    Settings {
        gateway: Some(Url::parse("https://porthub.invalid/").unwrap()),
        sources: Sources::GatewayOnly,
        core: "1.11.29".parse().unwrap(),
        target: "x86_64-unknown-linux-gnu".into(),
        disabled: BTreeSet::new(),
        pins: BTreeMap::new(),
    }
}
#[test]
fn namespaced_manifest_cannot_mutate_legacy_catalog_or_publish_unsupported_backends() {
    let (mut media, _) = fixture();
    let bytes = serde_json::to_vec(&media).unwrap();
    assert!(Manifest::parse(&bytes).is_ok());
    assert!(Catalog::parse(&bytes).is_err());
    assert_eq!(
        porthub_components::catalog::CATALOG_ASSET,
        "porthub-components.json"
    );
    assert!(porthub_components::catalog::Component::ALL
        .iter()
        .all(|c| c.name() != "media-helper"));
    for mutate in [0, 1, 2, 3] {
        let mut value = media.clone();
        match mutate {
            0 => value.namespace = "legacy".into(),
            1 => value.repository = "attacker/helper".into(),
            2 => value.artifacts[0].target = "aarch64-apple-darwin".into(),
            _ => value.artifacts[0].protocol = 0,
        };
        assert!(value.validate().is_err());
    }
    let old = media.clone();
    media.release = "1.11.28".parse().unwrap();
    assert!(media.successor(&old).is_err());
    media = old.clone();
    media.artifacts[0].executable.sha256 = "c".repeat(64);
    assert!(media.successor(&old).is_err());
}
#[tokio::test]
async fn approved_source_and_digest_required_before_executable_publication() -> Result<()> {
    let root = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    let (manifest, archive) = fixture();
    let transport = Arc::new(Fetch::default());
    let asset = serde_json::to_vec(&manifest)?;
    transport
        .0
        .lock()
        .unwrap()
        .insert("/api/downloads/media/catalog".into(), asset);
    let artifact = &manifest.artifacts[0];
    let url = format!(
        "/api/downloads/media/{}/{}/{}",
        artifact.version, artifact.target, artifact.executable.sha256
    );
    transport
        .0
        .lock()
        .unwrap()
        .insert(url.clone(), archive.clone());
    let manager = media_store::Manager::new(root.path().to_owned(), settings(), transport.clone())?;
    let cancel = CancellationToken::new();
    assert!(
        manager.ensure(&manifest, &cancel).await.is_err(),
        "Caller-supplied manifest cannot bootstrap trust"
    );
    let approved = manager.refresh(&cancel).await?;
    let path = manager.ensure(&approved, &cancel).await?;
    assert!(porthub_components::store::verified(
        &path,
        &artifact.executable
    )?);
    assert!(
        !root.path().join("porthub-components.json").exists(),
        "Legacy catalog must remain untouched"
    );
    // Tamper cached executable and downloaded archive: neither may be executed/published.
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)?
        .write_all(b"changed")?;
    transport
        .0
        .lock()
        .unwrap()
        .insert(url, vec![0; archive.len()]);
    assert!(manager.ensure(&approved, &cancel).await.is_err());
    let mut changed = manifest.clone();
    changed.repository = "evil/helper".into();
    transport.0.lock().unwrap().insert(
        "/api/downloads/media/catalog".into(),
        serde_json::to_vec(&changed)?,
    );
    assert!(manager.refresh(&cancel).await.is_err());
    Ok(())
}
