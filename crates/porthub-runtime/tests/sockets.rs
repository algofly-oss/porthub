#![cfg(unix)]
use porthub_runtime::socket;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn socket_has_restricted_permissions_and_one_owner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("api.sock");
    let (listener, lease) = socket::bind(&path).await.unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o660
    );
    assert!(socket::bind(&path).await.is_err());
    drop(listener);
    drop(lease);
    assert!(!path.exists());
    let _replacement = socket::bind(&path).await.unwrap();
}

#[tokio::test]
async fn recovers_stale_socket_without_replacing_files_or_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("api.sock");
    drop(tokio::net::UnixListener::bind(&path).unwrap());
    let (listener, lease) = socket::bind(&path).await.unwrap();
    drop(listener);
    drop(lease);
    std::fs::write(&path, "keep this file").unwrap();
    assert!(socket::bind(&path).await.is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep this file");
    std::fs::remove_file(&path).unwrap();
    let target = directory.path().join("target");
    std::fs::write(&target, "keep target").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(socket::bind(&path).await.is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep target");
}
