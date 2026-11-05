use anyhow::Result;
use async_trait::async_trait;
use porthub_components::{
    catalog::*,
    store::{Manager, Settings, Sources},
    transport::{AccessDenied, Transport},
};
use semver::Version;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, Mutex},
};
use tokio_util::sync::CancellationToken;
use url::Url;

fn private_temp() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    directory
}
fn blob(bytes: &[u8]) -> Blob {
    Blob {
        size: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}
fn artifact(component: Component, version: &str, bytes: &[u8]) -> Artifact {
    Artifact {
        component,
        version: version.parse().unwrap(),
        target: TARGETS[0].into(),
        core: ">=1.10.0, <2.0.0".parse().unwrap(),
        protocols: vec![1],
        source_revision: "a".repeat(40),
        build_inputs: "b".repeat(64),
        executable: blob(bytes),
        release: "1.11.0".parse().unwrap(),
        archive: blob(b"placeholder"),
    }
}
fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, name, *bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}
fn fixture() -> (Catalog, Vec<u8>, Vec<u8>) {
    let executable = b"verified independent tool".to_vec();
    let mut a = artifact(Component::Sync, "1.0.0", &executable);
    let archive = archive(&[(&a.member(), &executable)]);
    a.archive = blob(&archive);
    (
        Catalog {
            schema_version: 1,
            repository: REPOSITORY.into(),
            release: "1.11.0".parse().unwrap(),
            artifacts: vec![a],
        },
        archive,
        executable,
    )
}
#[derive(Default)]
struct Mock {
    payloads: Mutex<BTreeMap<String, Vec<u8>>>,
    calls: Mutex<Vec<String>>,
    deny_gateway: bool,
}
#[async_trait]
impl Transport for Mock {
    async fn fetch(&self, url: &Url, output: &Path, limit: u64) -> Result<()> {
        self.calls.lock().unwrap().push(url.to_string());
        if self.deny_gateway && url.host_str() == Some("gateway.test") {
            return Err(AccessDenied.into());
        }
        let payload = self
            .payloads
            .lock()
            .unwrap()
            .get(url.as_str())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("network unavailable"))?;
        anyhow::ensure!(payload.len() as u64 <= limit, "size limit");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        tokio::fs::write(output, payload).await?;
        Ok(())
    }
}
fn settings() -> Settings {
    Settings {
        gateway: Some(Url::parse("https://gateway.test/prefix").unwrap()),
        sources: Sources::GatewayThenGithub,
        core: "1.10.1".parse().unwrap(),
        target: TARGETS[0].into(),
        disabled: BTreeSet::new(),
        pins: BTreeMap::new(),
    }
}
fn manager(root: &Path, transport: Arc<Mock>) -> Manager {
    Manager::new(root.join("components"), settings(), transport).unwrap()
}
fn github_catalog() -> String {
    format!("https://github.com/{REPOSITORY}/releases/latest/download/{CATALOG_ASSET}")
}
fn add(mock: &Mock, url: String, payload: Vec<u8>) {
    mock.payloads.lock().unwrap().insert(url, payload);
}

#[test]
fn latest_means_latest_compatible_not_latest_published() {
    let (mut catalog, _, _) = fixture();
    let mut next = catalog.artifacts[0].clone();
    next.version = "1.1.0".parse().unwrap();
    catalog.artifacts.push(next.clone());
    next.version = "2.0.0".parse().unwrap();
    next.core = ">=2.0.0".parse().unwrap();
    catalog.artifacts.push(next.clone());
    next.version = "3.0.0".parse().unwrap();
    next.core = ">=1.0.0".parse().unwrap();
    next.protocols = vec![2];
    catalog.artifacts.push(next);
    catalog.validate().unwrap();
    let core = "1.10.1".parse().unwrap();
    assert_eq!(
        catalog
            .select(Component::Sync, &core, TARGETS[0], None)
            .unwrap()
            .version,
        Version::parse("1.1.0").unwrap()
    );
    assert!(catalog
        .select(Component::Sync, &core, TARGETS[1], None)
        .is_none());
    assert!(catalog
        .select(
            Component::Sync,
            &core,
            TARGETS[0],
            Some(&Version::parse("2.0.0").unwrap())
        )
        .is_none());
    assert_eq!(
        catalog
            .select(
                Component::Sync,
                &core,
                TARGETS[0],
                Some(&Version::parse("1.0.0").unwrap())
            )
            .unwrap()
            .version,
        Version::parse("1.0.0").unwrap()
    );
}
#[test]
fn catalog_rejects_ambiguous_metadata_and_untrusted_repository() {
    let (catalog, _, _) = fixture();
    let mut bad = catalog.clone();
    bad.artifacts.push(bad.artifacts[0].clone());
    assert!(bad.validate().is_err());
    let mut bad = catalog.clone();
    bad.repository = "attacker/tool".into();
    assert!(bad.validate().is_err());
    let mut bad = catalog.clone();
    bad.artifacts[0].version = "1.0.0-rc.1".parse().unwrap();
    assert!(bad.validate().is_err());
    let mut bad = catalog.clone();
    bad.artifacts[0].target = "../../tmp/evil".into();
    assert!(bad.validate().is_err());
    let mut bad = catalog.clone();
    bad.artifacts[0].executable.size = MAX_EXECUTABLE + 1;
    assert!(bad.validate().is_err());
    let mut bad = catalog.clone();
    bad.artifacts[0].executable.sha256 = "G".repeat(64);
    assert!(bad.validate().is_err());
    let mut bytes = serde_json::to_value(&catalog).unwrap();
    bytes["artifacts"][0]["url"] = "https://attacker.test/tool".into();
    assert!(Catalog::parse(&serde_json::to_vec(&bytes).unwrap()).is_err());
}
#[tokio::test]
async fn gateway_first_offline_cache_and_corrupt_cache_recovery() {
    let root = private_temp();
    let mock = Arc::new(Mock::default());
    let manager = manager(root.path(), mock.clone());
    let (catalog, _, executable) = fixture();
    let a = &catalog.artifacts[0];
    let cancel = CancellationToken::new();
    add(
        &mock,
        "https://gateway.test/prefix/api/downloads/components/catalog".into(),
        serde_json::to_vec(&catalog).unwrap(),
    );
    add(
        &mock,
        format!("https://gateway.test/prefix/{}", a.gateway_path()),
        executable.clone(),
    );
    let fetched = manager.refresh(&cancel).await.unwrap();
    let path = manager
        .ensure(&fetched, Component::Sync, &cancel)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), executable);
    assert!(!mock
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|u| u.contains("github.com")));
    mock.payloads.lock().unwrap().clear();
    let offline = manager.refresh(&cancel).await.unwrap();
    let calls = mock.calls.lock().unwrap().len();
    assert_eq!(
        manager
            .ensure(&offline, Component::Sync, &cancel)
            .await
            .unwrap(),
        path
    );
    assert_eq!(mock.calls.lock().unwrap().len(), calls);
    std::fs::write(&path, b"bad").unwrap();
    assert!(manager
        .ensure(&offline, Component::Sync, &cancel)
        .await
        .is_err());
    add(
        &mock,
        format!("https://gateway.test/prefix/{}", a.gateway_path()),
        executable.clone(),
    );
    manager
        .ensure(&offline, Component::Sync, &cancel)
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), executable);
}
#[tokio::test]
async fn github_fallback_verifies_archive_and_individual_executable() {
    let root = private_temp();
    let mock = Arc::new(Mock::default());
    let manager = manager(root.path(), mock.clone());
    let (catalog, archive, executable) = fixture();
    let cancel = CancellationToken::new();
    add(
        &mock,
        github_catalog(),
        serde_json::to_vec(&catalog).unwrap(),
    );
    add(&mock, catalog.artifacts[0].github_url(), archive);
    let catalog = manager.refresh(&cancel).await.unwrap();
    let path = manager
        .ensure(&catalog, Component::Sync, &cancel)
        .await
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), executable);
    let calls = mock.calls.lock().unwrap();
    assert!(calls[0].contains("gateway.test"));
    assert!(calls[1].contains("github.com"));
}
#[tokio::test]
async fn administrator_restrictions_and_denials_do_not_fall_back() {
    let root = private_temp();
    let mock = Arc::new(Mock {
        deny_gateway: true,
        ..Default::default()
    });
    let (catalog, _, _) = fixture();
    add(
        &mock,
        github_catalog(),
        serde_json::to_vec(&catalog).unwrap(),
    );
    let cancel = CancellationToken::new();
    let manager = manager(root.path(), mock.clone());
    assert!(manager
        .refresh(&cancel)
        .await
        .unwrap_err()
        .is::<AccessDenied>());
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    let mut config = settings();
    config.disabled.insert(Component::Sync);
    let manager = Manager::new(root.path().join("restricted"), config, mock.clone()).unwrap();
    assert!(manager
        .ensure(&catalog, Component::Sync, &cancel)
        .await
        .is_err());
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    let mock = Arc::new(Mock::default());
    let mut config = settings();
    config.sources = Sources::GatewayOnly;
    let manager = Manager::new(root.path().join("gateway-only"), config, mock.clone()).unwrap();
    assert!(manager.refresh(&cancel).await.is_err());
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
    assert!(mock.calls.lock().unwrap()[0].contains("gateway.test"));
}
#[tokio::test]
async fn concurrent_commands_share_one_verified_download() {
    let root = private_temp();
    let mock = Arc::new(Mock::default());
    let manager = manager(root.path(), mock.clone());
    let (catalog, _, executable) = fixture();
    add(
        &mock,
        format!(
            "https://gateway.test/prefix/{}",
            catalog.artifacts[0].gateway_path()
        ),
        executable,
    );
    let cancel = CancellationToken::new();
    let (a, b) = tokio::join!(
        manager.ensure(&catalog, Component::Sync, &cancel),
        manager.ensure(&catalog, Component::Sync, &cancel)
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn tampered_gateway_bytes_are_not_executed_or_hidden_by_fallback() {
    let root = private_temp();
    let mock = Arc::new(Mock::default());
    let manager = manager(root.path(), mock.clone());
    let (catalog, archive, executable) = fixture();
    add(
        &mock,
        format!(
            "https://gateway.test/prefix/{}",
            catalog.artifacts[0].gateway_path()
        ),
        vec![b'x'; executable.len()],
    );
    add(&mock, catalog.artifacts[0].github_url(), archive);
    assert!(manager
        .ensure(&catalog, Component::Sync, &CancellationToken::new())
        .await
        .unwrap_err()
        .to_string()
        .contains("checksum"));
    assert_eq!(mock.calls.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn unexpected_archive_members_and_links_are_rejected() {
    for link in [false, true] {
        let root = private_temp();
        let mock = Arc::new(Mock::default());
        let manager = manager(root.path(), mock.clone());
        let (mut catalog, _, executable) = fixture();
        let member = catalog.artifacts[0].member();
        let bytes = if link {
            let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut builder = tar::Builder::new(encoder);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o755);
            header.set_link_name("/etc/passwd").unwrap();
            header.set_cksum();
            builder.append_data(&mut header, &member, &[][..]).unwrap();
            builder.into_inner().unwrap().finish().unwrap()
        } else {
            archive(&[(&member, &executable), ("unexpected-executable", b"bad")])
        };
        catalog.artifacts[0].archive = blob(&bytes);
        add(&mock, catalog.artifacts[0].github_url(), bytes);
        assert!(manager
            .ensure(&catalog, Component::Sync, &CancellationToken::new())
            .await
            .is_err());
        let files: Vec<_> = std::fs::read_dir(root.path().join("components"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(files, [std::ffi::OsString::from("sync.lock")]);
    }
}
#[tokio::test]
async fn catalog_downgrades_and_same_release_mutation_are_rejected() {
    let root = private_temp();
    let mock = Arc::new(Mock::default());
    let manager = manager(root.path(), mock.clone());
    let (catalog, _, _) = fixture();
    let url = "https://gateway.test/prefix/api/downloads/components/catalog".to_owned();
    let cancel = CancellationToken::new();
    add(&mock, url.clone(), serde_json::to_vec(&catalog).unwrap());
    manager.refresh(&cancel).await.unwrap();
    let mut changed = catalog.clone();
    changed.artifacts[0].core = ">=1.0.0".parse().unwrap();
    add(&mock, url.clone(), serde_json::to_vec(&changed).unwrap());
    assert!(manager.refresh(&cancel).await.is_err());
    changed = catalog.clone();
    changed.release = "1.10.0".parse().unwrap();
    changed.artifacts[0].release = changed.release.clone();
    add(&mock, url, serde_json::to_vec(&changed).unwrap());
    assert!(manager.refresh(&cancel).await.is_err());
    assert_eq!(
        manager.cached_catalog().unwrap().unwrap().release,
        catalog.release
    );
}
#[tokio::test]
async fn cancelled_download_leaves_no_executable_or_temporary_files() {
    let root = private_temp();
    let mock = Arc::new(Mock::default());
    let manager = manager(root.path(), mock.clone());
    let (catalog, _, _) = fixture();
    let cancel = CancellationToken::new();
    cancel.cancel();
    assert!(manager
        .ensure(&catalog, Component::Sync, &cancel)
        .await
        .is_err());
    assert!(std::fs::read_dir(root.path().join("components"))
        .unwrap()
        .all(|entry| entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|ext| ext == "lock")));
}
#[cfg(unix)]
#[test]
fn caches_cannot_follow_symlinks_or_use_writable_ancestors() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = private_temp();
    let mock = Arc::new(Mock::default());
    let actual = root.path().join("actual");
    std::fs::create_dir(&actual).unwrap();
    std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.path().join("link");
    symlink(&actual, &link).unwrap();
    assert!(Manager::new(link.join("cache"), settings(), mock.clone()).is_err());
    std::fs::set_permissions(&actual, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(Manager::new(actual.join("cache"), settings(), mock).is_err());
}
