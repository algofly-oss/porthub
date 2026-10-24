use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use porthub_api::static_ui::StaticUi;

#[tokio::test]
async fn exported_ui_supports_clean_urls_head_assets_and_real_404s() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    tokio::fs::create_dir_all(directory.path().join("_next/static")).await?;
    tokio::fs::create_dir_all(directory.path().join("account")).await?;
    tokio::fs::write(directory.path().join("index.html"), b"index page").await?;
    tokio::fs::write(directory.path().join("home.html"), b"exported home").await?;
    tokio::fs::write(
        directory.path().join("account/signin.html"),
        b"exported signin",
    )
    .await?;
    tokio::fs::write(directory.path().join("404.html"), b"exported missing page").await?;
    tokio::fs::write(
        directory.path().join("_next/static/app-123.js"),
        b"console.log('static asset')",
    )
    .await?;
    let ui = StaticUi::new(directory.path())?;
    for (path, expected) in [
        ("/", b"index page".as_slice()),
        ("/home?view=machines", b"exported home"),
        ("/home/", b"exported home"),
        ("/account/signin", b"exported signin"),
    ] {
        let response = ui
            .serve(Request::builder().uri(path).body(Body::empty())?)
            .await;
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-cache");
        assert_eq!(to_bytes(response.into_body(), 4096).await?, expected);
    }
    let response = ui
        .serve(
            Request::builder()
                .method("HEAD")
                .uri("/home")
                .body(Body::empty())?,
        )
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-length"], "13");
    assert!(to_bytes(response.into_body(), 4096).await?.is_empty());
    let response = ui
        .serve(
            Request::builder()
                .uri("/_next/static/app-123.js")
                .body(Body::empty())?,
        )
        .await;
    assert_eq!(
        response.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    let response = ui
        .serve(
            Request::builder()
                .uri("/does-not-exist")
                .body(Body::empty())?,
        )
        .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        to_bytes(response.into_body(), 4096).await?,
        b"exported missing page"[..]
    );
    for path in [
        "/%2e%2e/secret",
        "/account/%2e%2e/secret",
        "/account%5csecret",
    ] {
        assert_eq!(
            ui.serve(Request::builder().uri(path).body(Body::empty())?)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir()?;
        std::fs::write(outside.path().join("secret.html"), b"private")?;
        std::os::unix::fs::symlink(outside.path(), directory.path().join("escape"))?;
        assert_eq!(
            ui.serve(
                Request::builder()
                    .uri("/escape/secret.html")
                    .body(Body::empty())?
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ui.serve(
                Request::builder()
                    .uri("/escape/secret")
                    .body(Body::empty())?
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    Ok(())
}
