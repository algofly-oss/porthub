use anyhow::{ensure, Result};
use std::time::Duration;
mod support;
use support::Case;

#[tokio::test]
#[ignore = "requires built static UI, isolated MongoDB and Playwright"]
async fn browser_boards_and_transfers() -> Result<()> {
    let root = std::env::var("PORTHUB_TEST_BOARD_UI_ROOT")?;
    let case = Case::new(porthub_api::config::Config {
        ui_root: root,
        pairdrop_upstream: std::env::var("PORTHUB_TEST_PAIRDROP_UPSTREAM").unwrap_or_default(),
        ..Default::default()
    })
    .await?;
    let result: Result<()> = async {
        let (_, cookie) = case.user("board-browser@example.invalid", "user").await?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        let router = case.router.clone();
        let server = tokio::spawn(async move { axum::serve(listener, router).await });
        let project = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let output = tokio::time::timeout(
            Duration::from_secs(240),
            tokio::process::Command::new("node")
                .arg(
                    project.join("ui/tests").join(
                        std::env::var("PORTHUB_TEST_UI_SCRIPT")
                            .unwrap_or_else(|_| "boards-live.cjs".into()),
                    ),
                )
                .env("PORTHUB_TEST_UI_URL", base)
                .env("PORTHUB_TEST_BOARD_COOKIE", cookie)
                .kill_on_drop(true)
                .output(),
        )
        .await;
        case.app.file_relay.close();
        case.app.realtime.close().await;
        server.abort();
        let output = output??;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        ensure!(
            output.status.success(),
            "Browser verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    .await;
    case.db.drop().await?;
    result
}
