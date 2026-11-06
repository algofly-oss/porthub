use porthub_components::{
    catalog::{Artifact, Blob, Component, PROTOCOL, TARGETS},
    ipc::{self, Hello},
    local::{Endpoint, Listener},
};
use std::time::Duration;
fn artifact() -> Artifact {
    Artifact {
        component: Component::Sync,
        version: "0.1.0".parse().unwrap(),
        target: TARGETS[0].into(),
        core: ">=1.10.0".parse().unwrap(),
        protocols: vec![PROTOCOL],
        source_revision: "a".repeat(40),
        build_inputs: "b".repeat(64),
        executable: Blob {
            size: 1,
            sha256: "c".repeat(64),
        },
        release: "1.11.0".parse().unwrap(),
        archive: Blob {
            size: 1,
            sha256: "d".repeat(64),
        },
    }
}
#[tokio::test]
async fn local_transport_checks_ownership_and_carries_versioned_frames() {
    let root = tempfile::tempdir().unwrap();
    let artifact = artifact();
    let endpoint = Endpoint::for_artifact(root.path(), &artifact).unwrap();
    let parsed = Endpoint::parse(Component::Sync, endpoint.address()).unwrap();
    let mut listener = Listener::bind(endpoint.clone()).await.unwrap();
    assert!(Listener::bind(endpoint.clone()).await.is_err());
    let version = artifact.version.clone();
    let serving = tokio::spawn(async move {
        let hello = Hello {
            protocol: PROTOCOL,
            component: Component::Sync,
            version,
        };
        loop {
            let Ok(mut stream) = listener.accept().await else {
                continue;
            };
            // A duplicate Unix bind probes the live listener and closes. Worker
            // servers treat that failed handshake as an ordinary closed client.
            if ipc::write(&mut stream, &hello, Duration::from_secs(2))
                .await
                .is_err()
            {
                continue;
            }
            if let Ok(reply) = ipc::read::<Hello>(&mut stream, Duration::from_secs(2)).await {
                reply.validate(Component::Sync, &hello.version).unwrap();
                break;
            }
        }
    });
    let mut client = parsed.connect().await.unwrap();
    let hello: Hello = ipc::read(&mut client, Duration::from_secs(2))
        .await
        .unwrap();
    hello.validate(Component::Sync, &artifact.version).unwrap();
    ipc::write(&mut client, &hello, Duration::from_secs(2))
        .await
        .unwrap();
    serving.await.unwrap();
    #[cfg(unix)]
    assert!(!std::path::Path::new(endpoint.address()).exists());
    assert!(Endpoint::parse(Component::Sync, "/tmp/untrusted-worker").is_err());
}
#[cfg(unix)]
#[tokio::test]
async fn stale_socket_recovery_never_removes_regular_files_or_live_listeners() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let endpoint = Endpoint::for_artifact(root.path(), &artifact()).unwrap();
    std::fs::write(endpoint.address(), b"unrelated file").unwrap();
    assert!(Listener::bind(endpoint.clone()).await.is_err());
    assert_eq!(
        std::fs::read(endpoint.address()).unwrap(),
        b"unrelated file"
    );
    std::fs::remove_file(endpoint.address()).unwrap();
    let stale = std::os::unix::net::UnixListener::bind(endpoint.address()).unwrap();
    drop(stale);
    std::fs::set_permissions(endpoint.address(), std::fs::Permissions::from_mode(0o600)).unwrap();
    let listener = Listener::bind(endpoint.clone()).await.unwrap();
    drop(listener);
    assert!(!std::path::Path::new(endpoint.address()).exists());
}

#[test]
fn startup_backoff_is_scoped_to_artifact_and_context() {
    let root = tempfile::tempdir().unwrap();
    let original = artifact();
    let endpoint = Endpoint::for_artifact(&root.path().join("context-a"), &original).unwrap();
    let key = endpoint.startup_key();
    assert_eq!(key.len(), 64);
    assert_eq!(
        key,
        Endpoint::parse(Component::Sync, endpoint.address())
            .unwrap()
            .startup_key()
    );
    let mut newer = original.clone();
    newer.version = "0.1.1".parse().unwrap();
    assert_ne!(
        key,
        Endpoint::for_artifact(&root.path().join("context-a"), &newer)
            .unwrap()
            .startup_key()
    );
    let mut changed = original.clone();
    changed.executable.sha256 = "e".repeat(64);
    assert_ne!(
        key,
        Endpoint::for_artifact(&root.path().join("context-a"), &changed)
            .unwrap()
            .startup_key()
    );
    assert_ne!(
        key,
        Endpoint::for_artifact(&root.path().join("context-b"), &original)
            .unwrap()
            .startup_key()
    );
    let mut repacked = original.clone();
    repacked.release = "1.12.0".parse().unwrap();
    repacked.archive.sha256 = "f".repeat(64);
    assert_eq!(
        key,
        Endpoint::for_artifact(&root.path().join("context-a"), &repacked)
            .unwrap()
            .startup_key()
    );
}
