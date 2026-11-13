use anyhow::{ensure, Result};
use futures_util::future::try_join_all;
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, BufReader};
#[cfg(unix)]
struct SenderGroup(Option<u32>);
#[cfg(unix)]
impl Drop for SenderGroup {
    fn drop(&mut self) {
        if let Some(pid) = self.0 {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
        }
    }
}
mod support;
use support::Case;

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires isolated MongoDB and curl/wget via PORTHUB_TEST_MONGO_URI"]
async fn anonymous_senders_support_parallel_ranges_multiple_downloaders_and_stop_without_storage(
) -> Result<()> {
    let case = Case::new(Default::default()).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    let router = case.router.clone();
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result: Result<()> = async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(45))
            .build()?;
        let source: Vec<u8> = (0..10 * 1024 * 1024 + 123)
            .map(|i| ((i * 31 + i / 17) % 251) as u8)
            .collect();
        let tmp = tempfile::tempdir()?;
        let file = tmp.path().join("source image's file.bin");
        tokio::fs::write(&file, &source).await?;
        let script = tmp.path().join("sender.sh");
        tokio::fs::write(&script, include_bytes!("../src/transfer_sender.sh")).await?;
        for tool in ["curl", "wget"] {
            let client_temp = tmp.path().join(format!("client-{tool}"));
            tokio::fs::create_dir(&client_temp).await?;
            let mut sender = tokio::process::Command::new("bash")
                .arg(&script)
                .arg(&file)
                .arg(&base)
                .arg(tool)
                .env("TMPDIR", &client_temp)
                .process_group(0)
                .kill_on_drop(true)
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            let pid = sender.id().unwrap();
            let mut group = SenderGroup(Some(pid));
            let mut stdout = BufReader::new(sender.stdout.take().unwrap()).lines();
            let line = tokio::time::timeout(Duration::from_secs(10), stdout.next_line())
                .await??
                .unwrap();
            let url = line.strip_prefix("Download: ").unwrap().to_owned();
            let response = client.head(&url).send().await?;
            ensure!(response.status() == 200 && response.headers()["accept-ranges"] == "bytes");
            ensure!(
                response.headers()["content-length"]
                    .to_str()?
                    .parse::<usize>()?
                    == source.len()
            );
            ensure!(response.headers()["cache-control"] == "no-store, no-transform");
            let read = |start: usize, end: usize| {
                let client = client.clone();
                let url = url.clone();
                let expected = source[start..=end].to_vec();
                async move {
                    let response = client
                        .get(url)
                        .header("range", format!("bytes={start}-{end}"))
                        .send()
                        .await?;
                    ensure!(response.status() == 206);
                    ensure!(response.bytes().await?.as_ref() == expected.as_slice());
                    Ok::<_, anyhow::Error>(())
                }
            };
            // Four simultaneous range connections plus a separate full-file downloader.
            let end = source.len() - 1;
            let part = source.len() / 4;
            let all = try_join_all(
                (0..4).map(|i| read(i * part, if i == 3 { end } else { (i + 1) * part - 1 })),
            );
            let full = async {
                let response = client.get(&url).send().await?;
                ensure!(response.status() == 200);
                ensure!(response.bytes().await?.as_ref() == source.as_slice());
                Ok::<_, anyhow::Error>(())
            };
            let (a, b) = tokio::join!(all, full);
            a?;
            b?;
            read(1000, source.len() - 1).await?;
            let suffix = client
                .get(&url)
                .header("range", "bytes=-123")
                .send()
                .await?;
            ensure!(
                suffix.status() == 206
                    && suffix.bytes().await?.as_ref() == &source[source.len() - 123..]
            );
            let invalid = client
                .get(&url)
                .header("range", format!("bytes={}-", source.len()))
                .send()
                .await?;
            ensure!(invalid.status() == 416);
            let output = tmp.path().join(format!("download-{tool}.bin"));
            let status = if tool == "curl" {
                tokio::process::Command::new("curl")
                    .args(["-fsS", "--max-time", "30", "-o"])
                    .arg(&output)
                    .arg("--")
                    .arg(&url)
                    .status()
                    .await?
            } else {
                tokio::process::Command::new("wget")
                    .args(["-q", "--timeout=30", "-O"])
                    .arg(&output)
                    .arg("--")
                    .arg(&url)
                    .status()
                    .await?
            };
            ensure!(status.success() && tokio::fs::read(output).await? == source);
            // Sender cleanup revokes the anonymous link and its waiting requests.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGTERM);
            }
            tokio::time::timeout(Duration::from_secs(8), sender.wait()).await??;
            group.0 = None;
            ensure!(client.head(&url).send().await?.status() == 404);
            ensure!(
                tokio::fs::read_dir(&client_temp)
                    .await?
                    .next_entry()
                    .await?
                    .is_none(),
                "Client chunk files are cleaned up"
            );
        }
        ensure!(
            case.db.list_collection_names().await?.is_empty(),
            "The relay must not persist file content or sessions in MongoDB"
        );
        Ok(())
    }
    .await;
    case.app.file_relay.close();
    server.abort();
    case.db.drop().await?;
    result
}

#[tokio::test]
#[ignore = "requires isolated MongoDB via PORTHUB_TEST_MONGO_URI"]
async fn interrupted_sender_chunks_resume_without_duplicating_download_bytes() -> Result<()> {
    use futures_util::StreamExt;
    use tokio::io::AsyncWriteExt;
    let case = Case::new(Default::default()).await?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let base = format!("http://{addr}");
    let router = case.router.clone();
    let server = tokio::spawn(async move { axum::serve(listener, router).await });
    let result:Result<()>=async{
  let client=reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
  let payload:Vec<u8>=(0..100_000).map(|n|(n%251)as u8).collect();
  let response=client.post(format!("{base}/api/transfers")).header("x-transfer-name","partial.bin").header("x-transfer-size",payload.len()).send().await?;
  ensure!(response.status()==201);let body=response.text().await?;let values:Vec<_>=body.split_whitespace().collect();let(id,key)=(values[0],values[1]);
  let url=format!("{base}/api/transfers/{id}");
  let(first_tx,first_rx)=tokio::sync::oneshot::channel();let download_client=client.clone();let download_url=url.clone();
  let download=tokio::spawn(async move{
   let mut stream=download_client.get(download_url).send().await?.error_for_status()?.bytes_stream();
   let first=stream.next().await.ok_or_else(||anyhow::anyhow!("No streamed data"))??;let mut bytes=first.to_vec();let _=first_tx.send(first);
   while let Some(part)=stream.next().await{bytes.extend_from_slice(&part?);}Ok::<_,anyhow::Error>(bytes)
  });
  let job=client.get(format!("{url}/next")).header("x-transfer-key",key).send().await?.text().await?;let job:Vec<_>=job.split_whitespace().collect();
  ensure!(job[1]=="0");
  let mut interrupted=tokio::net::TcpStream::connect(addr).await?;
  interrupted.write_all(format!("PUT /api/transfers/{id}/chunks/{} HTTP/1.1\r\nHost: {addr}\r\nX-Transfer-Key: {key}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",job[0],job[2]).as_bytes()).await?;
  interrupted.write_all(&payload[..1024]).await?;
  let first=tokio::time::timeout(Duration::from_secs(5),first_rx).await??;ensure!(first.as_ref()==&payload[..1024]);
  interrupted.shutdown().await?;
  let retry=client.get(format!("{url}/next")).header("x-transfer-key",key).send().await?.text().await?;let retry:Vec<_>=retry.split_whitespace().collect();
  ensure!(retry[1]=="1024","The next request starts after bytes already streamed");
  let uploaded=client.put(format!("{url}/chunks/{}",retry[0])).header("x-transfer-key",key).body(payload[1024..].to_vec()).send().await?;ensure!(uploaded.status()==204);
  let bytes=tokio::time::timeout(Duration::from_secs(5),download).await???;ensure!(bytes==payload,"Resuming a partial upstream chunk must not duplicate or skip bytes");
  ensure!(client.delete(&url).header("x-transfer-key","wrong").send().await?.status()==404);
  ensure!(client.delete(&url).header("x-transfer-key",key).send().await?.status()==204);
  Ok(())
 }.await;
    case.app.file_relay.close();
    server.abort();
    case.db.drop().await?;
    result
}
