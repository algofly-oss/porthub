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

#[tokio::test]
async fn nested_destination_syncs_empty_directories_and_same_second_edits() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let root = source.path().join("data");
    std::fs::create_dir_all(root.join("empty/deep"))?;
    let file = root.join("test.txt");
    std::fs::write(&file, b"first")?;
    filetime::set_file_mtime(
        &file,
        filetime::FileTime::from_unix_time(1_700_000_000, 100),
    )?;
    let receiver = http(
        porthub_transfer::server::router(std::fs::canonicalize(destination.path())?)
            .merge(upload::routes(destination.path().to_owned())?),
    )
    .await?;
    let url = format!("{}/backups/luna/projects/", receiver.url);
    upload::put_path(root.clone(), url.clone(), 16, false, false).await?;
    let target = destination.path().join("backups/luna/projects/data");
    assert_eq!(std::fs::read(target.join("test.txt"))?, b"first");
    assert!(target.join("empty/deep").is_dir());
    let skipped = upload::put_path(root.clone(), url.clone(), 16, false, false).await?;
    assert!(skipped.contains("sent 0, skipped 1"), "{skipped}");
    std::fs::write(&file, b"other")?;
    filetime::set_file_mtime(
        &file,
        filetime::FileTime::from_unix_time(1_700_000_000, 900),
    )?;
    upload::put_path(root.clone(), url.clone(), 16, false, false).await?;
    assert_eq!(std::fs::read(target.join("test.txt"))?, b"other");
    let contents_url = format!("{}/contents/one/two/", receiver.url);
    upload::put_path(root, contents_url, 1, true, false).await?;
    assert_eq!(
        std::fs::read(destination.path().join("contents/one/two/test.txt"))?,
        b"other"
    );
    Ok(())
}

#[cfg(feature = "sync")]
#[tokio::test]
async fn watch_syncs_changes_recovers_offline_and_stops_without_deleting_remote_files() -> Result<()>
{
    use porthub_transfer::sync;
    use std::time::Duration;
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let root = source.path().join("data");
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("file"), b"initial")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    drop(listener);
    let cancel = tokio_util::sync::CancellationToken::new();
    let options = sync::Options {
        path: root.clone(),
        url: format!("http://{address}/nested/path/"),
        connections: 16,
        contents_only: false,
        force: false,
    };
    let task = tokio::spawn(sync::watch(options, cancel.clone()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let app = porthub_transfer::server::router(std::fs::canonicalize(destination.path())?)
        .merge(upload::routes(destination.path().to_owned())?);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let target = destination.path().join("nested/path/data/file");
    async fn wait_for(path: &std::path::Path, expected: &[u8]) {
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if std::fs::read(path).is_ok_and(|v| v == expected) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("file did not synchronize");
    }
    wait_for(&target, b"initial").await;
    std::fs::write(target.with_file_name("remote-only"), b"keep")?;
    std::fs::write(root.join("file"), b"updated")?;
    wait_for(&target, b"updated").await;
    std::fs::create_dir_all(root.join("new/subdir"))?;
    std::fs::write(root.join("new/subdir/file"), b"created")?;
    wait_for(
        &target.with_file_name("new").join("subdir/file"),
        b"created",
    )
    .await;
    std::fs::rename(root.join("file"), root.join("renamed"))?;
    wait_for(&target.with_file_name("renamed"), b"updated").await;
    assert!(target.with_file_name("remote-only").exists());
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    server.abort();
    assert!(target.exists());
    Ok(())
}

#[tokio::test]
async fn incremental_selection_does_not_scan_or_request_untouched_files() -> Result<()> {
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    let tree = source.path().join("data");
    std::fs::create_dir_all(tree.join("untouched"))?;
    std::fs::write(tree.join("changed"), b"updated")?;
    std::fs::write(tree.join("untouched/file"), b"do not send")?;
    let tree = std::fs::canonicalize(tree)?;
    let receiver = http(
        porthub_transfer::server::router(std::fs::canonicalize(destination.path())?)
            .merge(upload::routes(destination.path().to_owned())?),
    )
    .await?;
    upload::put_changed_paths(
        tree.clone(),
        format!("{}/nested/", receiver.url),
        16,
        false,
        false,
        vec![tree.join("changed"), tree.join("deleted")],
    )
    .await?;
    assert_eq!(
        std::fs::read(destination.path().join("nested/data/changed"))?,
        b"updated"
    );
    assert!(!destination.path().join("nested/data/untouched").exists());
    #[cfg(unix)]
    {
        let outside = tempfile::tempdir()?;
        std::fs::write(outside.path().join("secret"), b"secret")?;
        std::os::unix::fs::symlink(outside.path(), tree.join("linked"))?;
        assert!(upload::put_changed_paths(
            tree.clone(),
            receiver.url.clone(),
            1,
            false,
            false,
            vec![tree.join("linked/secret")]
        )
        .await
        .is_err());
        assert!(!destination.path().join("data/linked/secret").exists());
    }
    Ok(())
}

#[tokio::test]
async fn corrupt_batched_tail_retains_verified_checkpoint_for_legacy_resume() -> Result<()> {
    use sha2::{Digest, Sha256};
    let directory = tempfile::tempdir()?;
    let receiver = http(upload::routes(directory.path().to_owned())?).await?;
    let client = reqwest::Client::new();
    let id = format!("{:064x}", rand::random::<u128>());
    let api = format!("{}/.porthub/uploads/{id}", receiver.url);
    let first = vec![42u8; 8 * 1024 * 1024];
    let tail = b"last";
    client
        .put(&api)
        .json(&serde_json::json!({
            "name":"batch.bin","size":first.len()+tail.len(),"chunk_size":first.len(),"chunks":2
        }))
        .send()
        .await?
        .error_for_status()?;
    let first_hash = format!("{:x}", Sha256::digest(&first));
    let tail_hash = format!("{:x}", Sha256::digest(tail));
    let mut contents = first;
    contents.extend_from_slice(b"oops");
    let rejected = client
        .put(format!("{api}/chunks/0"))
        .header(
            "x-porthub-chunk-sha256",
            format!("{first_hash},{tail_hash}"),
        )
        .body(contents.clone())
        .send()
        .await?;
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let status = client.get(&api).send().await?.error_for_status()?;
    assert_eq!(status.headers()["x-porthub-chunk-batch"], "4");
    assert_eq!(
        status.json::<serde_json::Value>().await?["missing"],
        serde_json::json!([1])
    );
    client
        .put(format!("{api}/chunks/1"))
        .header("x-porthub-chunk-sha256", tail_hash)
        .body(tail.as_slice())
        .send()
        .await?
        .error_for_status()?;
    let last = contents.len() - tail.len();
    contents[last..].copy_from_slice(tail);
    let result = client
        .post(format!("{api}/commit"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    assert_eq!(result, format!("{:x}", Sha256::digest(&contents)));
    assert_eq!(
        tokio::fs::read(directory.path().join("batch.bin")).await?,
        contents
    );
    Ok(())
}

#[tokio::test]
async fn single_connection_groups_checkpoints_only_when_receiver_advertises_support() -> Result<()>
{
    use axum::{
        extract::Request,
        middleware::{self, Next},
    };
    use std::sync::{Arc, Mutex};
    const CHUNK: usize = 8 * 1024 * 1024;
    let input = tempfile::tempdir()?;
    let file = input.path().join("three-parts.bin");
    let contents = vec![77; 2 * CHUNK + 100];
    std::fs::write(&file, &contents)?;
    for (advertise, expected) in [(true, vec![3]), (false, vec![1, 1, 1])] {
        let directory = tempfile::tempdir()?;
        let counts = Arc::new(Mutex::new(Vec::new()));
        let capture = counts.clone();
        let router = upload::routes(directory.path().to_owned())?.layer(middleware::from_fn(
            move |req: Request, next: Next| {
                let capture = capture.clone();
                async move {
                    if let Some(value) = req.headers().get("x-porthub-chunk-sha256") {
                        capture
                            .lock()
                            .unwrap()
                            .push(value.to_str().unwrap().split(',').count());
                    }
                    let mut response = next.run(req).await;
                    if !advertise {
                        response.headers_mut().remove("x-porthub-chunk-batch");
                    }
                    response
                }
            },
        ));
        let receiver = http(router).await?;
        upload::put_path(file.clone(), receiver.url.clone(), 1, false, true).await?;
        assert_eq!(*counts.lock().unwrap(), expected);
        assert_eq!(
            std::fs::read(directory.path().join("three-parts.bin"))?,
            contents
        );
    }
    Ok(())
}
