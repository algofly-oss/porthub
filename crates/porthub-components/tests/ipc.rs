use porthub_components::{
    catalog::{Component, PROTOCOL},
    ipc::{self, Hello, MAX_FRAME},
};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
#[tokio::test]
async fn worker_handshake_and_typed_frames_round_trip() {
    let (mut client, mut worker) = tokio::io::duplex(1024);
    let version = "1.2.0".parse().unwrap();
    let hello = Hello {
        component: Component::Sync,
        protocol: PROTOCOL,
        version,
    };
    ipc::write(&mut worker, &hello, Duration::from_secs(1))
        .await
        .unwrap();
    let received: Hello = ipc::read(&mut client, Duration::from_secs(1))
        .await
        .unwrap();
    received.validate(Component::Sync, &hello.version).unwrap();
    assert!(received.validate(Component::Tor, &hello.version).is_err());
    assert!(received
        .validate(Component::Sync, &"1.3.0".parse().unwrap())
        .is_err());
    let wrong = Hello {
        protocol: PROTOCOL + 1,
        ..received
    };
    assert!(wrong.validate(Component::Sync, &hello.version).is_err());
}
#[tokio::test]
async fn oversized_partial_and_stalled_frames_are_bounded() {
    let (mut client, mut worker) = tokio::io::duplex(1024);
    worker.write_u32(MAX_FRAME as u32 + 1).await.unwrap();
    assert!(ipc::read::<Hello>(&mut client, Duration::from_millis(20))
        .await
        .is_err());
    let (mut client, mut worker) = tokio::io::duplex(1024);
    worker.write_u32(32).await.unwrap();
    worker.write_all(b"{\"").await.unwrap();
    drop(worker);
    assert!(ipc::read::<Hello>(&mut client, Duration::from_millis(20))
        .await
        .is_err());
    let (mut client, _worker) = tokio::io::duplex(1024);
    assert!(ipc::read::<Hello>(&mut client, Duration::from_millis(20))
        .await
        .is_err());
    assert!(ipc::write(
        &mut client,
        &"x".repeat(MAX_FRAME),
        Duration::from_millis(20)
    )
    .await
    .is_err());
}
