//! No TUN, service, files, native device, or user input: real control HTTP rejection lifecycle.
use anyhow::Result;
use axum::{http::StatusCode, routing::post, Router};
use porthub_agent::{
    private_network::{controller, sparse},
    private_profile::Profile,
};
use porthub_mesh::Identity;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn authenticated_private_rejection_cancels_whole_controller_authority_immediately(
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/api/access/private/sync",
                post(|| async { StatusCode::FORBIDDEN }),
            ),
        )
        .await
    });
    let workspace = "a".repeat(24);
    let peer = format!("{}:{}", workspace, "b".repeat(24));
    let profile = Profile {
        server: format!("http://{address}"),
        peer_id: peer,
        token: "fixture-credential-0123456789abcdef0123456789".into(),
        workspace,
        account_email: None,
        fallback_servers: vec![],
        allow_insecure_http_for_tests: true,
    };
    let (_interfaces, interfaces) = watch::channel(vec![]);
    let (events, mut receive) = mpsc::channel(8);
    let (relay, _) = watch::channel(None);
    let (handle, control) = sparse::channel();
    // Begin with still-unexpired installed authority: rejection must retire it now,
    // rather than merely prevent an initially empty controller from connecting.
    let epoch="a".repeat(64);
    let local=serde_json::json!({"id":profile.peer_id,"ip":"10.203.0.1","fingerprint":"local","instance":"instance-0123456789","hostname":"a.phub"});
    let remote=serde_json::json!({"id":"other","ip":"10.203.0.2","fingerprint":"remote","instance":"remote-instance","hostname":"other.phub"});
    let expires=chrono::Utc::now()+chrono::Duration::seconds(15);
    let base=serde_json::from_value(serde_json::json!({"workspace":profile.workspace,"self":profile.peer_id,"revision":1,"expires_at":expires,"sparse":{"protocol":1,"epoch":epoch},"peers":[local],"grants":[]}))?;
    handle.update_base(&base);
    let lookup=porthub_network::policy::Lookup{kind:"peer".into(),value:"other".into()};
    let lease=serde_json::from_value(serde_json::json!({"workspace":profile.workspace,"self":profile.peer_id,"epoch":epoch,"revision":1,"expires_at":expires,"local":local,"peer":remote,"grants":[{"source":profile.peer_id,"destination":"other","protocol":"any","ports":[]}]}))?;
    handle.installed(&lookup,lease);
    assert_eq!(handle.peers().len(),1);
    assert!(handle.dns_ttl("10.203.0.2".parse()?).is_some());
    let cancel = CancellationToken::new();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        controller::run_watched_sparse(
            profile,
            interfaces,
            Default::default(),
            events,
            relay,
            controller::LocalIdentity {
                traffic: None,
                instance: "instance-0123456789".into(),
                certificate: Identity::new()?,
            },
            cancel.clone(),
            Some(control),
        ),
    )
    .await;
    server.abort();
    let _ = server.await;
    let error = result?.err(); // A rejected result must be an error, never an acknowledged clean run.
    assert!(error.is_some_and(|e| e.to_string().contains("rejected this enrollment")));
    assert!(cancel.is_cancelled());
    assert!(handle.revoked());
    assert!(handle.peers().is_empty());
    assert!(!handle.request_peer("other"));
    assert!(receive.try_recv().is_err());
    Ok(())
}
