use anyhow::Result;
use axum::http::StatusCode;
use porthub_transfer::upload;
use std::path::PathBuf;

struct Http {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Http {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn http(router: axum::Router) -> Result<Http> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(Http { url, task })
}

#[tokio::test]
async fn raw_receiver_accepts_standard_put_and_post_uploads() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let receiver = http(upload::routes(PathBuf::from(directory.path()))?).await?;
    let client = reqwest::Client::new();

    let put_body = b"uploaded with HTTP PUT";
    let put = client
        .put(format!("{}/.porthub/raw/put.bin", receiver.url))
        .body(put_body.as_slice())
        .send()
        .await?;
    assert_eq!(put.status(), StatusCode::CREATED);
    assert_eq!(
        tokio::fs::read(directory.path().join("put.bin")).await?,
        put_body
    );

    let post_body = b"uploaded with HTTP POST";
    let post = client
        .post(format!("{}/.porthub/raw/nested/post.bin", receiver.url))
        .header("content-type", "application/octet-stream")
        .body(post_body.as_slice())
        .send()
        .await?;
    assert_eq!(post.status(), StatusCode::CREATED);
    assert_eq!(
        tokio::fs::read(directory.path().join("nested/post.bin")).await?,
        post_body
    );

    Ok(())
}
